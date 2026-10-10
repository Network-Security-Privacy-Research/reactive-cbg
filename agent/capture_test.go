package main

import (
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// seg describes one frame for the capture path to parse. It is a struct rather
// than a parameter list because the sequence numbers matter now: a reply is
// only timed if it acknowledges what we sent, so tests have to be explicit
// about seq/ack rather than letting them default to zero.
type seg struct {
	src, dst     string
	sport, dport uint16
	flags, ttl   uint8
	ipID, window uint16
	seq, ack     uint32
	opts         []byte
	payload      int // bytes of TCP payload, for banner segments
}

// build assembles an Ethernet+IP+TCP frame with the fields capture reads. The
// IP version follows the addresses, so a test states its intent by the address
// it uses rather than by a flag.
func build(s seg) []byte {
	if netip.MustParseAddr(s.src).Is6() {
		return build6(s)
	}
	opts := s.opts
	for len(opts)%4 != 0 {
		opts = append(opts, 0)
	}
	dataOff := 20 + len(opts)
	p := make([]byte, 14+20+dataOff+s.payload)
	binary.BigEndian.PutUint16(p[12:14], 0x0800)

	ip := p[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+dataOff+s.payload))
	binary.BigEndian.PutUint16(ip[4:6], s.ipID)
	ip[8] = s.ttl
	ip[9] = 6
	copy(ip[12:16], netip.MustParseAddr(s.src).AsSlice())
	copy(ip[16:20], netip.MustParseAddr(s.dst).AsSlice())

	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], s.sport)
	binary.BigEndian.PutUint16(tcp[2:4], s.dport)
	binary.BigEndian.PutUint32(tcp[4:8], s.seq)
	binary.BigEndian.PutUint32(tcp[8:12], s.ack)
	tcp[12] = byte(dataOff/4) << 4
	tcp[13] = s.flags
	binary.BigEndian.PutUint16(tcp[14:16], s.window)
	copy(tcp[20:], opts)
	return p
}

// build6 is the IPv6 counterpart: a fixed 40-byte header, hop limit where IPv4
// has TTL, and no identification field at all.
func build6(s seg) []byte {
	opts := s.opts
	for len(opts)%4 != 0 {
		opts = append(opts, 0)
	}
	dataOff := 20 + len(opts)
	p := make([]byte, 14+40+dataOff+s.payload)
	binary.BigEndian.PutUint16(p[12:14], 0x86DD)

	ip := p[14:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(dataOff+s.payload))
	ip[6] = 6 // next header: TCP
	ip[7] = s.ttl
	copy(ip[8:24], netip.MustParseAddr(s.src).AsSlice())
	copy(ip[24:40], netip.MustParseAddr(s.dst).AsSlice())

	tcp := ip[40:]
	binary.BigEndian.PutUint16(tcp[0:2], s.sport)
	binary.BigEndian.PutUint16(tcp[2:4], s.dport)
	binary.BigEndian.PutUint32(tcp[4:8], s.seq)
	binary.BigEndian.PutUint32(tcp[8:12], s.ack)
	tcp[12] = byte(dataOff/4) << 4
	tcp[13] = s.flags
	binary.BigEndian.PutUint16(tcp[14:16], s.window)
	copy(tcp[20:], opts)
	return p
}

func newTestRig(t *testing.T, ports []int) (*Capture, *FlowTable, string) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "measurements.jsonl")
	w, err := NewWriter(logPath, 8, 2, false)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	t.Cleanup(func() { w.Close() })

	ft := NewFlowTable("node-test", w, time.Second)
	pm := make(map[uint16]bool)
	for _, p := range ports {
		pm[uint16(p)] = true
	}
	return &Capture{ft: ft, linkHdr: 14, ports: pm}, ft, logPath
}

func readRecords(t *testing.T, path string) []Record {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var out []Record
	dec := json.NewDecoder(bytesReader(b))
	for dec.More() {
		var r Record
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("decode: %v", err)
		}
		out = append(out, r)
	}
	return out
}

// Sequence numbers shared by the tests: the peer's ISN and ours.
const (
	peerISN = 0x11110000
	ourISN  = 0x22220000
)

// TestStatelessScannerIsMeasured covers the case TCP_INFO cannot reach: a
// zmap/masscan-style scanner that sends SYN, takes our SYN-ACK and replies RST
// without ever completing the handshake. accept() never fires for these, so the
// SYN-ACK -> RST round trip is the only RTT available.
func TestStatelessScannerIsMeasured(t *testing.T) {
	cap, ft, logPath := newTestRig(t, []int{443})
	const scanner, node = "203.0.113.45", "198.51.100.7"

	// masscan-ish SYN: small window, MSS only, low TTL from a long path.
	synOpts := []byte{2, 4, 0x05, 0xb4}
	t0 := time.Date(2026, 8, 7, 14, 3, 11, 0, time.UTC)

	cap.handle(build(seg{src: scanner, dst: node, sport: 41682, dport: 443,
		flags: flagSYN, ttl: 49, ipID: 54321, window: 1024, seq: peerISN, opts: synOpts}), t0, false)
	cap.handle(build(seg{src: node, dst: scanner, sport: 443, dport: 41682,
		flags: flagSYN | flagACK, ttl: 64, ipID: 1, window: 65535,
		seq: ourISN, ack: peerISN + 1}), t0.Add(time.Millisecond), true)
	// The scanning host's kernel resets 38.07 ms later. Per RFC 9293 the bare
	// RST carries the sequence number our SYN-ACK acknowledged.
	cap.handle(build(seg{src: scanner, dst: node, sport: 41682, dport: 443,
		flags: flagRST, ttl: 49, ipID: 54322, seq: peerISN + 1}),
		t0.Add(time.Millisecond+38070*time.Microsecond), false)

	ft.Reap(t0.Add(time.Minute), true)

	recs := readRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	if r.CaptureMethod != "pcap_synack_rst" {
		t.Errorf("capture_method = %q, want pcap_synack_rst", r.CaptureMethod)
	}
	if got := r.RTTMinMS; got < 38.0 || got > 38.2 {
		t.Errorf("rtt_min_ms = %v, want ~38.07", got)
	}
	if r.Flags.HandshakeDone {
		t.Error("handshake_done should be false: the scanner never completed it")
	}
	if !r.Flags.ResetByPeer {
		t.Error("reset_by_peer should be true")
	}
	if r.TTLObserved != 49 || r.IPID != 54321 || r.WindowSize != 1024 {
		t.Errorf("fingerprint not captured: ttl=%d ipid=%d win=%d",
			r.TTLObserved, r.IPID, r.WindowSize)
	}
	if r.SrcIP != scanner {
		t.Errorf("src_ip = %q, want %q", r.SrcIP, scanner)
	}
	t.Logf("stateless scanner record:\n%s", mustJSON(t, r))
}

// TestCompletedHandshakeMergesBothSources checks that when a scanner does
// complete the handshake, the TCP_INFO sample and the capture sample land in
// the same record and the minimum wins.
func TestCompletedHandshakeMergesBothSources(t *testing.T) {
	cap, ft, logPath := newTestRig(t, []int{8443})
	const client, node = "203.0.113.99", "198.51.100.7"

	linuxOpts := []byte{2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 7}
	t0 := time.Date(2026, 8, 7, 14, 5, 0, 0, time.UTC)
	k := flowKey{src: netip.MustParseAddr(client), srcPort: 51234, dstPort: 8443}

	cap.handle(build(seg{src: client, dst: node, sport: 51234, dport: 8443,
		flags: flagSYN, ttl: 55, ipID: 4242, window: 64240, seq: peerISN, opts: linuxOpts}), t0, false)
	cap.handle(build(seg{src: node, dst: client, sport: 8443, dport: 51234,
		flags: flagSYN | flagACK, ttl: 64, ipID: 2, window: 65535,
		seq: ourISN, ack: peerISN + 1}), t0.Add(time.Millisecond), true)
	// Capture sees the completing ACK at 39.90 ms; it acknowledges our SYN-ACK.
	cap.handle(build(seg{src: client, dst: node, sport: 51234, dport: 8443,
		flags: flagACK, ttl: 55, ipID: 4243, window: 64240,
		seq: peerISN + 1, ack: ourISN + 1}),
		t0.Add(time.Millisecond+39900*time.Microsecond), false)
	// The listener independently reports the kernel's tighter 38.07 ms.
	ft.AddSample(k, 38.07, "tcp_info", t0.Add(42*time.Millisecond))

	ft.Reap(t0.Add(time.Minute), true)

	recs := readRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	if len(r.RTTSamplesMS) != 2 {
		t.Fatalf("rtt_samples_ms = %v, want 2 samples", r.RTTSamplesMS)
	}
	if r.CaptureMethod != "tcp_info" {
		t.Errorf("capture_method = %q; the minimum sample came from TCP_INFO", r.CaptureMethod)
	}
	if got := r.RTTMinMS; got < 38.0 || got > 38.1 {
		t.Errorf("rtt_min_ms = %v, want 38.07 (the minimum of both sources)", got)
	}
	if !r.Flags.HandshakeDone {
		t.Error("handshake_done should be true")
	}
	if r.TCPOptsFP != "mss1460,sack,ts,nop,wscale7" {
		t.Errorf("tcp_opts_fp = %q", r.TCPOptsFP)
	}
	t.Logf("completed-handshake record:\n%s", mustJSON(t, r))
}

// TestUnmeasuredFlowIsNotLogged: a SYN that never produces a round trip (no
// SYN-ACK reply, or the peer vanishes) carries no RTT and is not worth a line.
func TestUnmeasuredFlowIsNotLogged(t *testing.T) {
	cap, ft, logPath := newTestRig(t, []int{3389})
	t0 := time.Now()
	cap.handle(build(seg{src: "203.0.113.1", dst: "198.51.100.7", sport: 40000, dport: 3389,
		flags: flagSYN, ttl: 60, ipID: 1, window: 512, seq: peerISN}), t0, false)
	ft.Reap(t0.Add(time.Minute), true)

	if b, err := os.ReadFile(logPath); err == nil && len(b) > 0 {
		t.Errorf("expected no records, got: %s", b)
	}
	// It must still be counted: this is the coverage denominator, and a scanner
	// whose kernel RST was suppressed lands here rather than vanishing.
	if _, emitted, _, unmeasured := ft.Stats(); emitted != 0 || unmeasured != 1 {
		t.Errorf("emitted=%d unmeasured=%d, want 0 and 1", emitted, unmeasured)
	}
}

// TestLaterAcksDoNotUnderstateRTT: only the handshake-completing ACK is a round
// trip. Subsequent data ACKs arrive sooner and would corrupt the minimum.
func TestLaterAcksDoNotUnderstateRTT(t *testing.T) {
	cap, ft, logPath := newTestRig(t, []int{80})
	const client, node = "203.0.113.7", "198.51.100.7"
	t0 := time.Now()

	cap.handle(build(seg{src: client, dst: node, sport: 33333, dport: 80,
		flags: flagSYN, ttl: 58, ipID: 7, window: 29200, seq: peerISN}), t0, false)
	cap.handle(build(seg{src: node, dst: client, sport: 80, dport: 33333,
		flags: flagSYN | flagACK, ttl: 64, ipID: 3, window: 65535,
		seq: ourISN, ack: peerISN + 1}), t0.Add(time.Millisecond), true)
	cap.handle(build(seg{src: client, dst: node, sport: 33333, dport: 80,
		flags: flagACK, ttl: 58, ipID: 8, window: 29200,
		seq: peerISN + 1, ack: ourISN + 1}), t0.Add(51*time.Millisecond), false)
	// A data ACK 2 ms later must not be taken as a second, faster round trip.
	cap.handle(build(seg{src: client, dst: node, sport: 33333, dport: 80,
		flags: flagACK | 0x08, ttl: 58, ipID: 9, window: 29200,
		seq: peerISN + 1, ack: ourISN + 1}), t0.Add(53*time.Millisecond), false)

	ft.Reap(t0.Add(time.Minute), true)
	recs := readRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if n := len(recs[0].RTTSamplesMS); n != 1 {
		t.Errorf("got %d capture samples (%v), want exactly 1", n, recs[0].RTTSamplesMS)
	}
	if got := recs[0].RTTMinMS; got < 49.9 || got > 50.1 {
		t.Errorf("rtt_min_ms = %v, want ~50 (SYN-ACK -> completing ACK)", got)
	}
}

// TestPipelinedAckIsNotTimed is the regression test for the measurement fault
// that produced sub-millisecond RTTs from hosts on other continents.
//
// Some scanners send a bare ACK straight after their SYN instead of waiting for
// our SYN-ACK. It arrives microseconds after we transmit, and on the 3-tuple
// alone it is indistinguishable from a reply, so it used to be timed as a round
// trip -- reporting the sender's own inter-packet gap as the RTT. One such host
// was recorded at 10-24 us by thirteen nodes on five continents at once, while
// the RST path put it at 27-338 ms from those same nodes.
//
// It cannot acknowledge a sequence number it never saw, which is what makes it
// detectable. The peer's kernel applies the same test, which is why a flow like
// this never establishes and TCP_INFO never reported one.
func TestPipelinedAckIsNotTimed(t *testing.T) {
	cap, ft, logPath := newTestRig(t, []int{80})
	const scanner, node = "203.0.113.200", "198.51.100.7"
	t0 := time.Now()

	// Crafted SYN: no TCP options at all, randomized window.
	cap.handle(build(seg{src: scanner, dst: node, sport: 417, dport: 80,
		flags: flagSYN, ttl: 241, ipID: 5, window: 32658, seq: peerISN}), t0, false)
	cap.handle(build(seg{src: node, dst: scanner, sport: 80, dport: 417,
		flags: flagSYN | flagACK, ttl: 64, ipID: 4, window: 65535,
		seq: ourISN, ack: peerISN + 1}), t0.Add(40*time.Microsecond), true)
	// The pipelined ACK, sent with the SYN and so acknowledging nothing of ours,
	// lands 14 us after our SYN-ACK went out.
	cap.handle(build(seg{src: scanner, dst: node, sport: 417, dport: 80,
		flags: flagACK, ttl: 241, ipID: 6, window: 32658,
		seq: peerISN + 1, ack: 0}), t0.Add(54*time.Microsecond), false)

	ft.Reap(t0.Add(time.Minute), true)

	if b, err := os.ReadFile(logPath); err == nil && len(b) > 0 {
		t.Errorf("a pipelined ACK must not yield an RTT, got: %s", b)
	}
	if ack, _ := ft.ValidationStats(); ack != 1 {
		t.Errorf("unsolicited ACK count = %d, want 1", ack)
	}
	// The flow still counts toward the coverage denominator: we saw the scanner
	// and could not measure it.
	if _, emitted, _, unmeasured := ft.Stats(); emitted != 0 || unmeasured != 1 {
		t.Errorf("emitted=%d unmeasured=%d, want 0 and 1", emitted, unmeasured)
	}
}

// TestInjectedRstIsNotTimed: a RST that does not carry the sequence number we
// acknowledged did not come from the peer in reply to us -- an on-path injector
// is the usual explanation -- so it is not a round trip to that peer. The reset
// is still recorded; only the timing is refused.
func TestInjectedRstIsNotTimed(t *testing.T) {
	cap, ft, logPath := newTestRig(t, []int{80})
	const peer, node = "203.0.113.31", "198.51.100.7"
	t0 := time.Now()

	cap.handle(build(seg{src: peer, dst: node, sport: 49395, dport: 80,
		flags: flagSYN, ttl: 47, ipID: 11, window: 64240, seq: peerISN}), t0, false)
	cap.handle(build(seg{src: node, dst: peer, sport: 80, dport: 49395,
		flags: flagSYN | flagACK, ttl: 64, ipID: 5, window: 65535,
		seq: ourISN, ack: peerISN + 1}), t0.Add(time.Millisecond), true)
	// 23 us later, from a peer that is 77 ms away: not the peer.
	cap.handle(build(seg{src: peer, dst: node, sport: 49395, dport: 80,
		flags: flagRST, ttl: 47, ipID: 12, seq: 0}),
		t0.Add(time.Millisecond+23*time.Microsecond), false)

	ft.Reap(t0.Add(time.Minute), true)

	if b, err := os.ReadFile(logPath); err == nil && len(b) > 0 {
		t.Errorf("an unsolicited RST must not yield an RTT, got: %s", b)
	}
	if _, rst := ft.ValidationStats(); rst != 1 {
		t.Errorf("unsolicited RST count = %d, want 1", rst)
	}
}

// TestRstWithAckFlagIsAccepted: some stacks answer with RST|ACK rather than a
// bare RST. That is a genuine reply and must still be timed.
func TestRstWithAckFlagIsAccepted(t *testing.T) {
	cap, ft, logPath := newTestRig(t, []int{23})
	const scanner, node = "203.0.113.77", "198.51.100.7"
	t0 := time.Now()

	cap.handle(build(seg{src: scanner, dst: node, sport: 5555, dport: 23,
		flags: flagSYN, ttl: 52, ipID: 21, window: 1024, seq: peerISN}), t0, false)
	cap.handle(build(seg{src: node, dst: scanner, sport: 23, dport: 5555,
		flags: flagSYN | flagACK, ttl: 64, ipID: 6, window: 65535,
		seq: ourISN, ack: peerISN + 1}), t0.Add(time.Millisecond), true)
	cap.handle(build(seg{src: scanner, dst: node, sport: 5555, dport: 23,
		flags: flagRST | flagACK, ttl: 52, ipID: 22,
		seq: peerISN + 1, ack: ourISN + 1}), t0.Add(61*time.Millisecond), false)

	ft.Reap(t0.Add(time.Minute), true)
	recs := readRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if got := recs[0].RTTMinMS; got < 59.9 || got > 60.1 {
		t.Errorf("rtt_min_ms = %v, want ~60", got)
	}
}

// TestIPv6HandshakeIsMeasured: IPv6 traffic used to reach the flow table only
// via TCP_INFO, because the filter accepted ethertype 0x0800 alone. Every v6
// record therefore had no fingerprint and no RST-path coverage -- and v6 grew
// from 3.5% to 14.5% of the corpus once our addresses were published, so the
// gap stopped being a rounding error.
func TestIPv6HandshakeIsMeasured(t *testing.T) {
	cap, ft, logPath := newTestRig(t, []int{80})
	const client, node = "2a01:7e01::2000:fff:feaf:ae7b", "2001:db8::1"
	linuxOpts := []byte{2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 7}
	t0 := time.Now()

	cap.handle(build(seg{src: client, dst: node, sport: 51234, dport: 80,
		flags: flagSYN, ttl: 57, window: 64800, seq: peerISN, opts: linuxOpts}), t0, false)
	cap.handle(build(seg{src: node, dst: client, sport: 80, dport: 51234,
		flags: flagSYN | flagACK, ttl: 64, window: 65535,
		seq: ourISN, ack: peerISN + 1}), t0.Add(time.Millisecond), true)
	cap.handle(build(seg{src: client, dst: node, sport: 51234, dport: 80,
		flags: flagACK, ttl: 57, window: 64800,
		seq: peerISN + 1, ack: ourISN + 1}), t0.Add(88*time.Millisecond), false)

	ft.Reap(t0.Add(time.Minute), true)
	recs := readRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	if r.SrcIP != client {
		t.Errorf("src_ip = %q, want %q", r.SrcIP, client)
	}
	if got := r.RTTMinMS; got < 86.9 || got > 87.1 {
		t.Errorf("rtt_min_ms = %v, want ~87", got)
	}
	if r.CaptureMethod != "pcap_synack_ack" {
		t.Errorf("capture_method = %q", r.CaptureMethod)
	}
	// The fingerprint is the whole point of capturing v6 at all.
	if r.TCPOptsFP != "mss1460,sack,ts,nop,wscale7" {
		t.Errorf("tcp_opts_fp = %q, want the client's option layout", r.TCPOptsFP)
	}
	if r.TTLObserved != 57 {
		t.Errorf("ttl_observed = %d, want 57 (the hop limit)", r.TTLObserved)
	}
	// IPv6 has no identification field outside a fragment header.
	if r.IPID != 0 {
		t.Errorf("ip_id = %d, want 0: IPv6 has no such field", r.IPID)
	}
	if !r.Flags.HandshakeDone {
		t.Error("handshake_done should be true")
	}
	t.Logf("IPv6 record:\n%s", mustJSON(t, r))
}

// TestIPv6StatelessScannerIsMeasured: the RST path matters more on v6 than v4,
// since a scanner working from a published hitlist is the normal case there.
func TestIPv6StatelessScannerIsMeasured(t *testing.T) {
	cap, ft, logPath := newTestRig(t, []int{3128})
	const scanner, node = "2604:a880:400:d1:0:4:a541:3001", "2001:db8::1"
	t0 := time.Now()

	cap.handle(build(seg{src: scanner, dst: node, sport: 40001, dport: 3128,
		flags: flagSYN, ttl: 52, window: 1024, seq: peerISN,
		opts: []byte{2, 4, 0x05, 0xb4}}), t0, false)
	cap.handle(build(seg{src: node, dst: scanner, sport: 3128, dport: 40001,
		flags: flagSYN | flagACK, ttl: 64, window: 65535,
		seq: ourISN, ack: peerISN + 1}), t0.Add(time.Millisecond), true)
	cap.handle(build(seg{src: scanner, dst: node, sport: 40001, dport: 3128,
		flags: flagRST, ttl: 52, seq: peerISN + 1}), t0.Add(121*time.Millisecond), false)

	ft.Reap(t0.Add(time.Minute), true)
	recs := readRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0].CaptureMethod != "pcap_synack_rst" {
		t.Errorf("capture_method = %q, want pcap_synack_rst", recs[0].CaptureMethod)
	}
	if got := recs[0].RTTMinMS; got < 119.9 || got > 120.1 {
		t.Errorf("rtt_min_ms = %v, want ~120", got)
	}
	if !recs[0].Flags.ResetByPeer {
		t.Error("reset_by_peer should be true")
	}
}

// TestIPv6PipelinedAckIsNotTimed: the sequence check must apply on v6 too.
func TestIPv6PipelinedAckIsNotTimed(t *testing.T) {
	cap, ft, logPath := newTestRig(t, []int{80})
	const scanner, node = "2600:3c02::2000:ddff:fe55:c9e0", "2001:db8::1"
	t0 := time.Now()

	cap.handle(build(seg{src: scanner, dst: node, sport: 417, dport: 80,
		flags: flagSYN, ttl: 241, window: 32658, seq: peerISN}), t0, false)
	cap.handle(build(seg{src: node, dst: scanner, sport: 80, dport: 417,
		flags: flagSYN | flagACK, ttl: 64, window: 65535,
		seq: ourISN, ack: peerISN + 1}), t0.Add(40*time.Microsecond), true)
	cap.handle(build(seg{src: scanner, dst: node, sport: 417, dport: 80,
		flags: flagACK, ttl: 241, window: 32658,
		seq: peerISN + 1, ack: 0}), t0.Add(54*time.Microsecond), false)

	ft.Reap(t0.Add(time.Minute), true)
	if b, err := os.ReadFile(logPath); err == nil && len(b) > 0 {
		t.Errorf("a pipelined ACK must not yield an RTT on v6 either, got: %s", b)
	}
	if ack, _ := ft.ValidationStats(); ack != 1 {
		t.Errorf("unsolicited ACK count = %d, want 1", ack)
	}
}

// TestBannerACKIsMeasured covers the banner-ACK enhancement end to end.
//
// This is a regression test for a silent failure, not a new feature: the config
// knob and the listener's write already existed, but the capture required an
// inbound ACK to carry exactly synackSeq+1. The ACK for a banner acknowledges
// past that by the banner's length, so it was classified as unsolicited and
// dropped. A node with a banner configured therefore paid the exposure cost and
// measured nothing extra at all.
//
// The second sample must also be timed from the BANNER, not from the SYN-ACK.
// Timing it from the SYN-ACK would fold in however long the listener took to
// accept and write, which is our own scheduling delay and not a round trip.
func TestBannerACKIsMeasured(t *testing.T) {
	cap, ft, logPath := newTestRig(t, []int{8443})
	const client, node = "203.0.113.77", "198.51.100.7"
	const bannerLen = 24

	t0 := time.Date(2026, 8, 27, 9, 0, 0, 0, time.UTC)

	cap.handle(build(seg{src: client, dst: node, sport: 40001, dport: 8443,
		flags: flagSYN, ttl: 55, ipID: 1, window: 64240, seq: peerISN}), t0, false)
	cap.handle(build(seg{src: node, dst: client, sport: 8443, dport: 40001,
		flags: flagSYN | flagACK, ttl: 64, ipID: 2, window: 65535,
		seq: ourISN, ack: peerISN + 1}), t0.Add(time.Millisecond), true)
	// Handshake ACK at 50 ms after our SYN-ACK.
	cap.handle(build(seg{src: client, dst: node, sport: 40001, dport: 8443,
		flags: flagACK, ttl: 55, ipID: 3, window: 64240,
		seq: peerISN + 1, ack: ourISN + 1}), t0.Add(51*time.Millisecond), false)

	// Our banner goes out 5 ms later, carrying bannerLen bytes.
	bannerTX := t0.Add(56 * time.Millisecond)
	cap.handle(build(seg{src: node, dst: client, sport: 8443, dport: 40001,
		flags: flagACK | flagPSH, ttl: 64, ipID: 4, window: 65535,
		seq: ourISN + 1, ack: peerISN + 1, payload: bannerLen}), bannerTX, true)

	// Its ACK arrives 30 ms after the banner, acknowledging ourISN+1+bannerLen.
	cap.handle(build(seg{src: client, dst: node, sport: 40001, dport: 8443,
		flags: flagACK, ttl: 55, ipID: 5, window: 64240,
		seq: peerISN + 1, ack: ourISN + 1 + bannerLen}),
		bannerTX.Add(30*time.Millisecond), false)

	ft.Reap(t0.Add(time.Minute), true)

	recs := readRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	if len(r.RTTSamplesMS) != 2 {
		t.Fatalf("rtt_samples_ms = %v, want 2 (handshake + banner ACK)", r.RTTSamplesMS)
	}
	// 30 ms from the banner, NOT 85 ms from the SYN-ACK.
	var banner float64
	for _, v := range r.RTTSamplesMS {
		if v < 40 {
			banner = v
		}
	}
	if banner < 29.9 || banner > 30.1 {
		t.Errorf("banner sample = %v ms, want 30 (timed from the banner, not the SYN-ACK)", banner)
	}
	if got := r.RTTMinMS; got < 29.9 || got > 30.1 {
		t.Errorf("rtt_min_ms = %v, want 30", got)
	}
	if r.CaptureMethod != "pcap_banner_ack" {
		t.Errorf("capture_method = %q, want pcap_banner_ack", r.CaptureMethod)
	}
}

// TestUnsolicitedACKStillCountedWithoutBanner guards the other side of that
// branch: with no banner sent, a mismatched ACK must still be unsolicited
// rather than quietly matching some stale banner state.
func TestUnsolicitedACKStillCountedWithoutBanner(t *testing.T) {
	cap, ft, logPath := newTestRig(t, []int{8443})
	const client, node = "203.0.113.78", "198.51.100.7"

	t0 := time.Date(2026, 8, 27, 9, 30, 0, 0, time.UTC)
	cap.handle(build(seg{src: client, dst: node, sport: 40002, dport: 8443,
		flags: flagSYN, ttl: 55, ipID: 1, window: 64240, seq: peerISN}), t0, false)
	cap.handle(build(seg{src: node, dst: client, sport: 8443, dport: 40002,
		flags: flagSYN | flagACK, ttl: 64, ipID: 2, window: 65535,
		seq: ourISN, ack: peerISN + 1}), t0.Add(time.Millisecond), true)
	// An ACK acknowledging a number we never sent.
	cap.handle(build(seg{src: client, dst: node, sport: 40002, dport: 8443,
		flags: flagACK, ttl: 55, ipID: 3, window: 64240,
		seq: peerISN + 1, ack: ourISN + 999}), t0.Add(20*time.Millisecond), false)

	ft.Reap(t0.Add(time.Minute), true)
	for _, r := range readRecords(t, logPath) {
		for _, v := range r.RTTSamplesMS {
			t.Errorf("unsolicited ACK produced a sample of %v ms; want none", v)
		}
	}
}
