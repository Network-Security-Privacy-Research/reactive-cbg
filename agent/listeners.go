package main

import (
	"log"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Listeners accept connections on the honeypot ports so the handshake actually
// completes, then read the kernel's own handshake RTT from TCP_INFO.
//
// The connection is closed immediately after (optionally following a small
// banner). We are not a service; we exist to make the handshake happen and to
// time it.
type Listeners struct {
	cfg    Config
	ft     *FlowTable
	ls     []net.Listener
	wg     sync.WaitGroup
	closed chan struct{}
	once   sync.Once
}

func NewListeners(cfg Config, ft *FlowTable) (*Listeners, error) {
	l := &Listeners{cfg: cfg, ft: ft, closed: make(chan struct{})}
	for _, p := range cfg.ListenPorts {
		ln, err := net.Listen("tcp", net.JoinHostPort("", itoa(p)))
		if err != nil {
			// A port already in use is expected on some nodes (inventory tracks
			// this per node). Skip it rather than refusing to start.
			log.Printf("port %d: %v (skipping)", p, err)
			continue
		}
		l.ls = append(l.ls, ln)
		log.Printf("listening on :%d", p)
	}
	if len(l.ls) == 0 {
		return nil, errNoPorts
	}
	return l, nil
}

func (l *Listeners) Run() {
	for _, ln := range l.ls {
		l.wg.Add(1)
		go l.acceptLoop(ln)
	}
}

func (l *Listeners) acceptLoop(ln net.Listener) {
	defer l.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-l.closed:
				return
			default:
			}
			// Transient accept errors (fd exhaustion under a scan burst) should
			// not kill the listener.
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go l.serve(c)
	}
}

func (l *Listeners) serve(c net.Conn) {
	defer c.Close()
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return
	}
	now := time.Now()

	// Read TCP_INFO immediately: at this instant tcpi_rtt is the SYN-ACK -> ACK
	// round trip and nothing else has happened on the socket yet.
	ti, err := ReadTCPInfo(tc)
	if err != nil {
		return
	}

	ap, err := netip.ParseAddrPort(c.RemoteAddr().String())
	if err != nil {
		return
	}
	lp, err := netip.ParseAddrPort(c.LocalAddr().String())
	if err != nil {
		return
	}
	k := flowKey{src: ap.Addr().Unmap(), srcPort: ap.Port(), dstPort: lp.Port()}

	// Prefer tcpi_min_rtt (the kernel's running minimum) and fall back to the
	// smoothed value on the rare kernel that leaves it zero.
	us := ti.MinRTTus
	if us == 0 {
		us = ti.RTTus
	}
	l.ft.AddSample(k, float64(us)/1000.0, "tcp_info", now)
	l.ft.NoteHandshakeDone(k, now)

	if l.cfg.Banner != "" {
		// A banner elicits a data ACK, giving a second independent RTT sample
		// that the capture picks up.
		c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		c.Write([]byte(l.cfg.Banner))
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		var scratch [64]byte
		c.Read(scratch[:])
	}
}

func (l *Listeners) Close() {
	l.once.Do(func() {
		close(l.closed)
		for _, ln := range l.ls {
			ln.Close()
		}
	})
	l.wg.Wait()
}
