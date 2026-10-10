package main

import (
	"fmt"

	"golang.org/x/net/bpf"
)

// buildPortFilter assembles a classic-BPF program accepting IPv4 and IPv6 TCP
// packets whose source or destination port is in ports.
//
// Filtering in the kernel matters here: a vantage point is often a 1 vCPU box
// with under 1 GB of RAM that has other work to do. Restricting to the honeypot
// ports keeps this capture to a trickle and, importantly, means we never copy
// SSH or bulk transfer traffic into userspace.
//
// The two families need different prologues -- IPv4's header is variable length
// and carries a fragment field, IPv6's is a fixed 40 bytes and does not -- but
// they converge on one shared port-comparison block. The trick is the X
// register: IPv4 loads it from the IHL nibble, IPv6 just sets it to 40, and
// from there "the TCP header begins at 14+X" is true for both.
//
// IPv6 extension headers are not walked. Classic BPF cannot loop, so only the
// first Next Header is examined and a packet carrying a hop-by-hop or routing
// header is dropped rather than measured. That is the same limitation tcpdump's
// "ip6 and tcp" has, and scanner SYN/ACK/RST essentially never carry them.
//
// Layout (indices are absolute, jumps are relative):
//
//	 0  load ethertype
//	 1  == 0x86DD (IPv6)      -> v6 prologue (9)
//	 2  != 0x0800 (IPv4)      -> drop
//	 3  load IPv4 protocol
//	 4  != 6 (TCP)            -> drop
//	 5  load flags+frag offset
//	 6  fragment (non-first)  -> drop   (no usable TCP header)
//	 7  X = IPv4 header length
//	 8  goto ports (12)
//	 9  load IPv6 next header
//	10  != 6 (TCP)            -> drop   (or an extension header; see above)
//	11  X = 40                          (IPv6 header is fixed length)
//	12  load source port at 14+X
//	13..    == port_i         -> accept
//	    load destination port at 16+X
//	...     == port_i         -> accept
//	    drop
//	    accept
func buildPortFilter(ports []int) ([]bpf.RawInstruction, error) {
	n := len(ports)
	if n == 0 {
		return nil, fmt.Errorf("no ports to filter")
	}
	const (
		v6Idx   = 9  // first instruction of the IPv6 prologue
		portIdx = 12 // first instruction of the shared port block
	)
	dropIdx := portIdx + 2 + 2*n
	acceptIdx := dropIdx + 1
	if acceptIdx > 255 {
		return nil, fmt.Errorf("too many ports for a byte-relative jump (%d)", n)
	}

	ins := make([]bpf.Instruction, 0, acceptIdx+1)
	ins = append(ins,
		// 0-2: split on ethertype.
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0x86DD, SkipTrue: uint8(v6Idx - 2)},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 0x0800, SkipTrue: uint8(dropIdx - 3)},
		// 3-8: IPv4 prologue. Offsets are 14 + the field's offset in the header.
		bpf.LoadAbsolute{Off: 23, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 6, SkipTrue: uint8(dropIdx - 5)},
		bpf.LoadAbsolute{Off: 20, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: uint8(dropIdx - 7)},
		bpf.LoadMemShift{Off: 14},
		bpf.Jump{Skip: uint32(portIdx - 9)},
		// 9-11: IPv6 prologue. Next Header sits at 14+6; the header is fixed at
		// 40 bytes, so X is a constant rather than something to derive.
		bpf.LoadAbsolute{Off: 20, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 6, SkipTrue: uint8(dropIdx - 11)},
		bpf.LoadConstant{Dst: bpf.RegX, Val: 40},
		// 12+: shared by both families.
		bpf.LoadIndirect{Off: 14, Size: 2}, // source port
	)
	for i, p := range ports {
		idx := portIdx + 1 + i
		ins = append(ins, bpf.JumpIf{
			Cond: bpf.JumpEqual, Val: uint32(uint16(p)),
			SkipTrue: uint8(acceptIdx - idx - 1),
		})
	}
	ins = append(ins, bpf.LoadIndirect{Off: 16, Size: 2}) // destination port
	for i, p := range ports {
		idx := portIdx + 2 + n + i
		ins = append(ins, bpf.JumpIf{
			Cond: bpf.JumpEqual, Val: uint32(uint16(p)),
			SkipTrue: uint8(acceptIdx - idx - 1),
		})
	}
	ins = append(ins,
		bpf.RetConstant{Val: 0},      // drop
		bpf.RetConstant{Val: 262144}, // accept (snaplen; headers are all we read)
	)
	return bpf.Assemble(ins)
}
