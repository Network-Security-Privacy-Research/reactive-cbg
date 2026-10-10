package main

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
)

// synthPacket builds an Ethernet+IPv4+TCP frame for filter testing.
func synthPacket(sport, dport uint16, proto uint8, ethType uint16, fragOff uint16) []byte {
	p := make([]byte, 14+20+20)
	binary.BigEndian.PutUint16(p[12:14], ethType)
	ip := p[14:]
	ip[0] = 0x45 // v4, IHL=5
	binary.BigEndian.PutUint16(ip[2:4], 40)
	binary.BigEndian.PutUint16(ip[6:8], fragOff)
	ip[9] = proto
	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	tcp[12] = 5 << 4
	return p
}

// synth6Packet builds an Ethernet+IPv6+TCP frame. nextHdr is the Next Header
// field, so passing something other than 6 models a packet whose first header
// is an extension header rather than TCP.
func synth6Packet(sport, dport uint16, nextHdr uint8) []byte {
	p := make([]byte, 14+40+20)
	binary.BigEndian.PutUint16(p[12:14], 0x86DD)
	ip := p[14:]
	ip[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(ip[4:6], 20)
	ip[6] = nextHdr
	ip[7] = 64 // hop limit
	tcp := ip[40:]
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	tcp[12] = 5 << 4
	return p
}

// TestPortFilter exercises the hand-computed relative jump offsets in
// buildPortFilter against a reference BPF VM. Getting these wrong silently
// passes or drops the wrong traffic, so they are worth pinning down.
func TestPortFilter(t *testing.T) {
	ports := []int{80, 443, 3389, 8443}
	raw, err := buildPortFilter(ports)
	if err != nil {
		t.Fatalf("buildPortFilter: %v", err)
	}
	ins, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatalf("disassemble produced unknown instructions")
	}
	vm, err := bpf.NewVM(ins)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}

	const (
		ipv4 = 0x0800
		ipv6 = 0x86DD
		tcp  = 6
		udp  = 17
	)
	cases := []struct {
		name   string
		pkt    []byte
		accept bool
	}{
		{"inbound to honeypot 443", synthPacket(51234, 443, tcp, ipv4, 0), true},
		{"inbound to honeypot 3389", synthPacket(41682, 3389, tcp, ipv4, 0), true},
		{"outbound from honeypot 80", synthPacket(80, 51234, tcp, ipv4, 0), true},
		{"outbound from honeypot 8443", synthPacket(8443, 33333, tcp, ipv4, 0), true},
		{"ssh must not be captured", synthPacket(22, 51234, tcp, ipv4, 0), false},
		{"rsync to ssh must not be captured", synthPacket(51234, 22, tcp, ipv4, 0), false},
		{"udp must not be captured", synthPacket(51234, 443, udp, ipv4, 0), false},
		{"dns tcp on 53 not in port set", synthPacket(53, 51234, tcp, ipv4, 0), false},
		{"non-first fragment dropped", synthPacket(51234, 443, tcp, ipv4, 0x0001), false},

		// IPv6 goes through a separate prologue that rejoins the same port
		// block, so every port decision has to be re-proven for it.
		{"v6 inbound to honeypot 443", synth6Packet(51234, 443, tcp), true},
		{"v6 inbound to honeypot 3389", synth6Packet(41682, 3389, tcp), true},
		{"v6 outbound from honeypot 80", synth6Packet(80, 51234, tcp), true},
		{"v6 ssh must not be captured", synth6Packet(22, 51234, tcp), false},
		{"v6 rsync to ssh must not be captured", synth6Packet(51234, 22, tcp), false},
		{"v6 udp must not be captured", synth6Packet(443, 51234, udp), false},
		{"v6 hop-by-hop ext header dropped", synth6Packet(51234, 443, 0), false},
		{"v6 routing ext header dropped", synth6Packet(51234, 443, 43), false},
		{"truncated ipv6 header", synth6Packet(51234, 443, tcp)[:40], false},
	}
	_ = ipv6
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n, err := vm.Run(c.pkt)
			if err != nil {
				t.Fatalf("vm.Run: %v", err)
			}
			got := n > 0
			if got != c.accept {
				t.Errorf("accept=%v, want %v (ret=%d)", got, c.accept, n)
			}
		})
	}
}

// The safety-critical case: whatever the configured port set, the filter must
// not pull the host's own management or service traffic into the capture path.
// SSH matters everywhere -- capturing the session you are administering the box
// over is both a privacy problem and a feedback loop -- and a port the host uses
// for something else must stay out even when it looks superficially similar to
// one we listen on.
func TestPortFilterExcludesUnconfiguredPorts(t *testing.T) {
	raw, err := buildPortFilter([]int{8080})
	if err != nil {
		t.Fatal(err)
	}
	ins, _ := bpf.Disassemble(raw)
	vm, err := bpf.NewVM(ins)
	if err != nil {
		t.Fatal(err)
	}
	// An assortment of ports a host might legitimately be using for its own
	// purposes. Only 8080 is in the configured set, so none of these may pass.
	for _, p := range []uint16{22, 53, 953, 9050, 25, 587, 3000} {
		n, err := vm.Run(synthPacket(p, 40000, 6, 0x0800, 0))
		if err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			t.Errorf("port %d was captured but is not in the configured set", p)
		}
	}
}

func TestFormatTCPOpts(t *testing.T) {
	// MSS 1460, SACK-permitted, timestamps, NOP, window scale 7 — the classic
	// Linux client layout.
	opts := []byte{
		2, 4, 0x05, 0xb4, // MSS 1460
		4, 2, // SACK permitted
		8, 10, 0, 0, 0, 0, 0, 0, 0, 0, // timestamps
		1,       // NOP
		3, 3, 7, // window scale 7
	}
	if got, want := formatTCPOpts(opts), "mss1460,sack,ts,nop,wscale7"; got != want {
		t.Errorf("formatTCPOpts = %q, want %q", got, want)
	}
}

func TestFormatTCPOptsMalformed(t *testing.T) {
	// Truncated and zero-length options must not panic or loop forever; scan
	// tools emit deliberately odd option layouts.
	for _, in := range [][]byte{
		{2, 4, 0x05},       // truncated MSS
		{2, 0},             // illegal length 0
		{8},                // kind with no length byte
		{1, 1, 1, 0, 3, 3}, // NOPs then EOL then trailing junk
		{},
	} {
		_ = formatTCPOpts(in)
	}
}
