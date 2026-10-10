package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// TCP flag bits.
const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagPSH = 0x08
	flagACK = 0x10
)

// Capture reads SYN/ACK/RST packets on the honeypot ports via AF_PACKET.
//
// It exists for two reasons TCP_INFO cannot cover:
//
//  1. Stateless scanners never complete the handshake, so accept() never
//     returns and TCP_INFO never sees them — yet they are the scanners we most
//     want. A RST usually comes back anyway, and SYN-ACK -> RST is a full round
//     trip we can time.
//
//     Note where that RST comes from: zmap writes probes at the Ethernet layer,
//     bypassing the host's TCP stack, so our SYN-ACK arrives at the scanning
//     host with no matching socket and *its kernel* emits the RST. zmap itself
//     sends nothing. That has a consequence — the RST is not guaranteed. A
//     scanner operator can suppress it (zmap's own docs suggest dropping
//     outbound RSTs), and a stateful firewall on their side can swallow the
//     SYN-ACK so no RST is ever generated. When that happens the flow yields no
//     RTT at all and we simply do not measure that scanner.
//
//     When the RST does arrive its timing is clean: the kernel replies from
//     softirq context with no application in the path, arguably a tighter
//     measurement than an application-mediated ACK.
//
//  2. TTL, IP-ID, window and TCP options are not exposed by any socket option,
//     and they are the passive fingerprint we want.
//
// Timestamps come from the kernel via SO_TIMESTAMPNS, not from time.Now() at
// read, so a busy VM scheduling us late does not inflate the measurement.
type Capture struct {
	fd      int
	ft      *FlowTable
	iface   string
	linkHdr int
	ports   map[uint16]bool
}

// interfaceIndex resolves an interface name to its index.
//
// net.InterfaceByName goes through netlink, which a seccomp sandbox can refuse:
// under a systemd unit whose RestrictAddressFamilies omits AF_NETLINK the call
// fails with "address family not supported by protocol". sysfs gives the same
// answer with an ordinary file read and no socket at all, so fall back to it
// rather than losing capture to a hardening setting.
func interfaceIndex(name string) (int, error) {
	if name == "" || strings.ContainsAny(name, "/\x00") {
		return 0, fmt.Errorf("invalid interface name %q", name)
	}
	ifi, nlErr := net.InterfaceByName(name)
	if nlErr == nil {
		return ifi.Index, nil
	}
	b, fsErr := os.ReadFile("/sys/class/net/" + name + "/ifindex")
	if fsErr != nil {
		return 0, fmt.Errorf("interface %q: netlink: %v; sysfs: %v", name, nlErr, fsErr)
	}
	idx, convErr := strconv.Atoi(strings.TrimSpace(string(b)))
	if convErr != nil || idx <= 0 {
		return 0, fmt.Errorf("interface %q: unparseable sysfs ifindex %q", name, b)
	}
	log.Printf("interface %q: netlink unavailable (%v); using sysfs ifindex %d", name, nlErr, idx)
	return idx, nil
}

func NewCapture(iface string, ports []int, ft *FlowTable) (*Capture, error) {
	ifIndex, err := interfaceIndex(iface)
	if err != nil {
		return nil, err
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("socket(AF_PACKET): %w (need CAP_NET_RAW)", err)
	}

	// Attach the filter before binding so unfiltered packets never queue.
	filter, err := buildPortFilter(ports)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := attachFilter(fd, filter); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("attach BPF: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("SO_TIMESTAMPNS: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifIndex,
	}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("bind %s: %w", iface, err)
	}

	pm := make(map[uint16]bool, len(ports))
	for _, p := range ports {
		pm[uint16(p)] = true
	}
	return &Capture{fd: fd, ft: ft, iface: iface, linkHdr: 14, ports: pm}, nil
}

func attachFilter(fd int, filter []bpf.RawInstruction) error {
	prog := make([]unix.SockFilter, len(filter))
	for i, ins := range filter {
		prog[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER,
		&unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]})
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func (c *Capture) Close() error { return unix.Close(c.fd) }

// Run reads packets until the socket is closed.
func (c *Capture) Run() {
	buf := make([]byte, 256) // headers only; the BPF snaplen keeps this cheap
	oob := make([]byte, 128)
	for {
		n, oobn, _, from, err := unix.Recvmsg(c.fd, buf, oob, 0)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return // socket closed on shutdown
		}
		ts := cmsgTimestamp(oob[:oobn])
		if ts.IsZero() {
			ts = time.Now()
		}
		ll, ok := from.(*unix.SockaddrLinklayer)
		if !ok {
			continue
		}
		c.handle(buf[:n], ts, ll.Pkttype == unix.PACKET_OUTGOING)
	}
}

// cmsgTimestamp extracts the kernel's SCM_TIMESTAMPNS receive timestamp.
func cmsgTimestamp(oob []byte) time.Time {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return time.Time{}
	}
	for _, m := range msgs {
		if m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_TIMESTAMPNS {
			if len(m.Data) >= 16 {
				sec := int64(binary.LittleEndian.Uint64(m.Data[0:8]))
				nsec := int64(binary.LittleEndian.Uint64(m.Data[8:16]))
				return time.Unix(sec, nsec)
			}
		}
	}
	return time.Time{}
}

func (c *Capture) handle(pkt []byte, ts time.Time, outgoing bool) {
	if len(pkt) < c.linkHdr+20 {
		return
	}
	ip := pkt[c.linkHdr:]

	// ttl carries the IPv4 TTL or the IPv6 hop limit; they are the same field
	// under different names and serve the same purpose here, estimating hop
	// count. ipID has no IPv6 equivalent outside a fragment header, so it stays
	// zero there and is simply absent from the record.
	var (
		ttl          uint8
		ipID         uint16
		srcIP, dstIP netip.Addr
		tcp          []byte
		segLen       int // TCP header + payload, per the IP header
	)
	switch ip[0] >> 4 {
	case 4:
		ihl := int(ip[0]&0x0f) * 4
		if ihl < 20 || len(ip) < ihl+20 {
			return
		}
		ttl = ip[8]
		ipID = binary.BigEndian.Uint16(ip[4:6])
		srcIP, _ = netip.AddrFromSlice(ip[12:16])
		dstIP, _ = netip.AddrFromSlice(ip[16:20])
		tcp = ip[ihl:]
		// From the IP header, not len(tcp): a snaplen-truncated capture would
		// otherwise report a short payload and silently mis-key the banner ACK.
		segLen = int(binary.BigEndian.Uint16(ip[2:4])) - ihl
	case 6:
		// Fixed 40-byte header, so the TCP header always starts at 40. The BPF
		// filter has already required Next Header to be TCP, which means there
		// is no extension-header chain to walk -- a packet carrying one never
		// reaches us. See buildPortFilter.
		if len(ip) < 40+20 || ip[6] != 6 {
			return
		}
		ttl = ip[7]
		srcIP, _ = netip.AddrFromSlice(ip[8:24])
		dstIP, _ = netip.AddrFromSlice(ip[24:40])
		tcp = ip[40:]
		segLen = int(binary.BigEndian.Uint16(ip[4:6]))
	default:
		return
	}
	// A v4-mapped form would key the same host two ways in the flow table; the
	// listener path unmaps for the same reason.
	srcIP, dstIP = srcIP.Unmap(), dstIP.Unmap()
	sport := binary.BigEndian.Uint16(tcp[0:2])
	dport := binary.BigEndian.Uint16(tcp[2:4])
	seq := binary.BigEndian.Uint32(tcp[4:8])
	ackSeq := binary.BigEndian.Uint32(tcp[8:12])
	dataOff := int(tcp[12]>>4) * 4
	flags := tcp[13]
	window := binary.BigEndian.Uint16(tcp[14:16])

	var opts []byte
	if dataOff >= 20 && len(tcp) >= dataOff {
		opts = tcp[20:dataOff]
	}

	if outgoing {
		if !c.ports[sport] {
			return
		}
		pk := flowKey{src: dstIP, srcPort: dport, dstPort: sport}
		switch {
		case flags&flagSYN != 0 && flags&flagACK != 0:
			// Our SYN-ACK. The peer is the destination; key the flow by the peer.
			c.ft.NoteSynAck(pk, seq, ackSeq, ts)
		case flags&flagSYN == 0 && segLen > dataOff:
			// Our banner. Payload on an established flow means the listener
			// wrote it, and the ACK for it is a second round trip. Record what a
			// reply must acknowledge: everything we have sent through this segment.
			c.ft.NoteBannerTx(pk, seq+uint32(segLen-dataOff), ts)
		}
		return
	}

	// Inbound: the peer is the source.
	if !c.ports[dport] {
		return
	}
	k := flowKey{src: srcIP, srcPort: sport, dstPort: dport}

	switch {
	case flags&flagSYN != 0 && flags&flagACK == 0:
		// Client SYN — the fingerprint packet.
		c.ft.NoteFingerprint(k, ttl, ipID, window, formatTCPOpts(opts), ts)

	case flags&flagRST != 0:
		// Stateless scanner tearing down after our SYN-ACK. SYN-ACK -> RST is a
		// full round trip. Note the reset regardless of whether we can time it;
		// that the peer reset is true either way.
		c.ft.NoteReset(k, ts)
		if t0, sseq, sack, ok := c.ft.SynAck(k); ok {
			// RFC 9293 §3.10.7.1: a RST answering an ACK-bearing segment carries
			// SEG.SEQ = SEG.ACK of that segment and no ACK flag. Stacks that set
			// the ACK flag instead must acknowledge our sequence number.
			valid := seq == sack
			if flags&flagACK != 0 {
				valid = ackSeq == sseq+1
			}
			if valid {
				c.ft.AddPcapSample(k, ts.Sub(t0).Seconds()*1000, "pcap_synack_rst", ts)
			} else {
				c.ft.NoteUnsolicited(k, true)
			}
		}

	case flags&flagACK != 0 && flags&flagSYN == 0 && flags&flagFIN == 0:
		// Handshake-completing ACK: SYN-ACK -> ACK, the primary measurement.
		//
		// The acknowledgement number must be checked. Some scanners pipeline a
		// bare ACK immediately behind their SYN rather than waiting for us, and
		// on the 3-tuple alone that is indistinguishable from a reply -- it is
		// timed as a round trip and yields microseconds, which is really the
		// sender's own inter-packet gap. The kernel applies exactly this test
		// before establishing the connection, which is why TCP_INFO never showed
		// these and only the capture did.
		t0, sseq, _, ok := c.ft.SynAck(k)
		if !ok {
			return // never saw our SYN-ACK; nothing to measure against
		}
		if ackSeq != sseq+1 {
			// Not the handshake ACK -- but it may be the ACK for our banner,
			// which acknowledges past sseq+1 by exactly the banner's length.
			// Checking this BEFORE calling it unsolicited is the whole point:
			// a configured banner used to land here and be discarded, so the
			// second round trip it exists to elicit was never measured.
			if bt, endSeq, ok := c.ft.BannerTx(k); ok && ackSeq == endSeq {
				c.ft.AddBannerSample(k, ts.Sub(bt).Seconds()*1000, ts)
				return
			}
			c.ft.NoteUnsolicited(k, false)
			return
		}
		c.ft.AddPcapSample(k, ts.Sub(t0).Seconds()*1000, "pcap_synack_ack", ts)
		c.ft.NoteHandshakeDone(k, ts)
	}
}

// formatTCPOpts renders the TCP option layout as a stable fingerprint string,
// e.g. "mss1460,sack,ts,nop,wscale7". Order is preserved because stacks and
// scan tools differ in the order they emit options, which is half the signal.
func formatTCPOpts(opts []byte) string {
	var parts []string
	for i := 0; i < len(opts); {
		kind := opts[i]
		switch kind {
		case 0: // EOL
			i = len(opts)
		case 1: // NOP
			parts = append(parts, "nop")
			i++
		default:
			if i+1 >= len(opts) {
				i = len(opts)
				break
			}
			l := int(opts[i+1])
			if l < 2 || i+l > len(opts) {
				i = len(opts)
				break
			}
			switch kind {
			case 2:
				if l == 4 {
					parts = append(parts, "mss"+strconv.Itoa(int(binary.BigEndian.Uint16(opts[i+2:i+4]))))
				}
			case 3:
				if l == 3 {
					parts = append(parts, "wscale"+strconv.Itoa(int(opts[i+2])))
				}
			case 4:
				parts = append(parts, "sack")
			case 5:
				parts = append(parts, "sackblk")
			case 8:
				parts = append(parts, "ts")
			default:
				parts = append(parts, "opt"+strconv.Itoa(int(kind)))
			}
			i += l
		}
	}
	return strings.Join(parts, ",")
}

func logCaptureUnavailable(err error) {
	log.Printf("capture disabled: %v", err)
	log.Printf("  -> RTT will come from TCP_INFO only; stateless scanners that RST")
	log.Printf("     instead of completing the handshake will not be measured,")
	log.Printf("     and TTL/IP-ID/TCP-option fingerprints will be absent.")
}
