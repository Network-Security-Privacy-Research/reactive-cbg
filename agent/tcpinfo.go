package main

import (
	"encoding/binary"
	"net"

	"golang.org/x/sys/unix"
)

// Byte offsets into struct tcp_info (include/uapi/linux/tcp.h). Parsed by
// offset rather than via a Go struct so the agent does not break as the kernel
// appends fields; every node in the fleet runs >= 5.15, well past the 4.10 that
// introduced tcpi_min_rtt.
const (
	offTCPIRtt    = 68  // __u32 tcpi_rtt     — smoothed RTT, microseconds
	offTCPIRttvar = 72  // __u32 tcpi_rttvar
	offTCPIMinRtt = 148 // __u32 tcpi_min_rtt — minimum RTT seen, microseconds
	tcpInfoLen    = 232
)

// TCPInfo holds the handshake RTT as measured by the kernel.
type TCPInfo struct {
	RTTus    uint32
	RTTVarus uint32
	MinRTTus uint32
}

// ReadTCPInfo pulls TCP_INFO from an accepted connection.
//
// Called immediately after Accept, tcpi_rtt is the SYN-ACK -> ACK round trip:
// the kernel seeds srtt from tcp_synack_rtt_meas() when the handshake-completing
// ACK arrives. This is exactly the measurement we want, taken in the kernel
// rather than in userspace, so VM scheduling jitter does not enter the number.
// tcpi_min_rtt gives the running minimum for free.
func ReadTCPInfo(c *net.TCPConn) (TCPInfo, error) {
	var ti TCPInfo
	raw, err := c.SyscallConn()
	if err != nil {
		return ti, err
	}
	var inner error
	buf := make([]byte, tcpInfoLen)
	err = raw.Control(func(fd uintptr) {
		var n uint32 = uint32(len(buf))
		inner = getsockoptBytes(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO, buf, &n)
	})
	if err != nil {
		return ti, err
	}
	if inner != nil {
		return ti, inner
	}
	ti.RTTus = binary.LittleEndian.Uint32(buf[offTCPIRtt:])
	ti.RTTVarus = binary.LittleEndian.Uint32(buf[offTCPIRttvar:])
	ti.MinRTTus = binary.LittleEndian.Uint32(buf[offTCPIMinRtt:])
	return ti, nil
}

func getsockoptBytes(fd, level, opt int, b []byte, n *uint32) error {
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(opt),
		uintptr(ptrOf(b)), uintptr(ptrOfU32(n)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}
