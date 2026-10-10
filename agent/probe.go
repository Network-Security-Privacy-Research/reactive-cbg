package main

// Active back-probe module.
//
// WHY THIS EXISTS. The passive method's contribution is largest exactly where
// conventional active geolocation cannot go: a scanner that answers nothing we
// send cannot be multilaterated by anyone probing it, but it still has to
// complete a handshake with us to scan us, and that handshake is a clean RTT.
// To claim that, we have to measure how much of the scanner population is
// actually unprobeable rather than assume it.
//
// WHY IT RUNS ON THE NODE. The probe has to leave from the box that saw the
// connection, moments after it saw it. A central prober would need each node to
// tell it "this IP just appeared, probe it now", which would need an always-on
// streaming collector. Doing it locally also removes the
// confound that would otherwise wreck the result: a host that is scanning us
// right now is provably alive, so if it ignores our probe that is filtering,
// not an address that went dark between the sighting and the sweep.
//
// Every guardrail in this module is mandatory:
// rate limits, a do-not-probe list, no RFC1918/bogons/reserved space, a total
// volume cap, an audit log of every probe, and a kill switch. It stays off
// unless active_probe_enabled is explicitly set, and it is per-node so a single
// provider complaint is one config edit.
//
// The probe is never allowed to disturb the measurement it came from: work is
// handed to a bounded queue and dropped if the queue is full, so the reaper
// that writes measurement records never blocks on the network.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// ProbeResult is one line of the probe audit log. Every probe writes one,
// including the ones that were refused, so the log is a complete record of what
// this node sent and why.
type ProbeResult struct {
	TS       time.Time `json:"ts"`
	NodeID   string    `json:"node_id"`
	Target   string    `json:"target"`
	SkipRule string    `json:"skip_rule,omitempty"` // set when nothing was sent

	// Lag between seeing the target's traffic and probing it. The whole point
	// of probing from the node is to keep this small: a target still scanning
	// us is provably alive, so a non-response is filtering rather than churn.
	LagMS int64 `json:"lag_ms"`

	// The passive measurement that triggered this, for direct comparison.
	PassiveRTTMS float64 `json:"passive_rtt_ms"`

	ICMP *ProbeAttempt  `json:"icmp,omitempty"`
	TCP  []ProbeAttempt `json:"tcp,omitempty"`

	// Responsive means at least one probe produced a timing, i.e. conventional
	// active geolocation would have had something to work with.
	Responsive  bool    `json:"responsive"`
	ActiveMinMS float64 `json:"active_min_ms,omitempty"`
}

// ProbeAttempt is a single probe and its outcome.
type ProbeAttempt struct {
	Kind string `json:"kind"`           // "icmp" | "tcp"
	Port int    `json:"port,omitempty"` // tcp only
	// Result is one of: reply, synack, rst, prohibited, timeout, unreachable,
	// error. Only reply, synack and rst are answers from the target itself --
	// see hostAnswered.
	Result string  `json:"result"`
	RTTMS  float64 `json:"rtt_ms,omitempty"`
	Err    string  `json:"err,omitempty"`
}

// hostAnswered reports whether a result is a response from the TARGET, as
// opposed to from something on the path to it.
//
// The distinction decides two different things and they disagree. "prohibited"
// -- an ICMP administratively-prohibited error, which Linux surfaces as EACCES
// on connect -- is a real returned packet with a real round-trip time, so it
// proves the path works. But it is emitted by whatever filtering device chose
// to refuse, which may sit well short of the target. Its RTT is therefore an
// upper bound on the distance to the FILTER, not to the host, and using it as
// a CBG constraint would make the disk too small and could falsify a
// geolocation claim that is actually true.
//
// So a prohibited reply is recorded, with its timing, and deliberately does
// not count as the host being reachable.
func hostAnswered(result string) bool {
	switch result {
	case "reply", "synack", "rst":
		return true
	}
	return false
}

// probeJob is queued by the flow reaper and executed by a worker.
type probeJob struct {
	target     netip.Addr
	seenAt     time.Time
	passiveRTT float64
}

// Prober owns the active probing lifecycle for one node.
type Prober struct {
	cfg    ProbeConfig
	nodeID string
	out    *Writer

	jobs chan probeJob
	wg   sync.WaitGroup
	quit chan struct{}

	// Rate limiting is a token bucket refilled continuously, plus a hard total
	// for the day. The bucket smooths bursts; the daily cap is the number a
	// provider would actually ask about.
	mu         sync.Mutex
	tokens     float64
	lastRefill time.Time
	dayStamp   int
	sentToday  int

	// recent suppresses re-probing an address we already probed. Without it a
	// single aggressive scanner would be probed thousands of times: our corpus
	// averages ~36 connections per source, and one /24 sent 447k packets.
	recent map[netip.Addr]time.Time

	// Counters for the periodic stats line.
	nSent, nSkipped, nDropped, nResponsive atomic.Uint64

	killed atomic.Bool
}

// blockedNets are ranges we must never send to regardless of configuration.
// A scanner's source address is attacker-controlled input, so
// this is not hypothetical: spoofed or bogon sources would otherwise turn the
// fleet into a reflector aimed at whatever the spoofer chose.
var blockedNets []netip.Prefix

func init() {
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
		"2001:db8::/32", "64:ff9b::/96", "100::/64",
	} {
		blockedNets = append(blockedNets, netip.MustParsePrefix(s))
	}
}

func NewProber(cfg ProbeConfig, nodeID string, out *Writer) (*Prober, error) {
	if len(cfg.TCPPorts) == 0 && !cfg.ICMP {
		return nil, errors.New("active probing enabled but no TCP ports and no ICMP")
	}
	p := &Prober{
		cfg:        cfg,
		nodeID:     nodeID,
		out:        out,
		jobs:       make(chan probeJob, cfg.QueueDepth),
		quit:       make(chan struct{}),
		tokens:     cfg.RatePerSec,
		lastRefill: time.Now(),
		recent:     make(map[netip.Addr]time.Time),
	}
	for i := 0; i < cfg.Workers; i++ {
		p.wg.Add(1)
		go p.worker()
	}
	p.wg.Add(1)
	go p.housekeeping()
	return p, nil
}

// Submit queues a target. It never blocks: if the queue is full the job is
// dropped, because the caller is the reaper that writes measurement records and
// the passive measurement is worth more than any individual probe.
func (p *Prober) Submit(target netip.Addr, seenAt time.Time, passiveRTT float64) {
	select {
	case p.jobs <- probeJob{target: target, seenAt: seenAt, passiveRTT: passiveRTT}:
	default:
		p.nDropped.Add(1)
	}
}

func (p *Prober) Close() {
	close(p.quit)
	close(p.jobs)
	p.wg.Wait()
}

// housekeeping polls the kill switch and expires the cooldown map.
func (p *Prober) housekeeping() {
	defer p.wg.Done()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-p.quit:
			return
		case <-t.C:
			if p.cfg.KillSwitchPath != "" {
				_, err := os.Stat(p.cfg.KillSwitchPath)
				now := err == nil
				if now != p.killed.Swap(now) {
					if now {
						log.Printf("PROBE KILL SWITCH present at %s: active probing stopped",
							p.cfg.KillSwitchPath)
					} else {
						log.Printf("probe kill switch cleared; active probing resumed")
					}
				}
			}
			cutoff := time.Now().Add(-p.cfg.cooldown())
			p.mu.Lock()
			for a, t := range p.recent {
				if t.Before(cutoff) {
					delete(p.recent, a)
				}
			}
			p.mu.Unlock()
		}
	}
}

// admit applies every guardrail and returns "" if the probe may proceed, or the
// name of the rule that refused it.
func (p *Prober) admit(target netip.Addr, now time.Time) string {
	if p.killed.Load() {
		return "kill_switch"
	}
	if !target.IsValid() || target.IsUnspecified() || target.IsLoopback() ||
		target.IsMulticast() || target.IsLinkLocalUnicast() ||
		target.IsLinkLocalMulticast() || target.IsInterfaceLocalMulticast() {
		return "reserved_address"
	}
	t := target.Unmap()
	for _, n := range blockedNets {
		if n.Addr().Is4() == t.Is4() && n.Contains(t) {
			return "bogon"
		}
	}
	for _, n := range p.cfg.doNotProbe {
		if n.Addr().Is4() == t.Is4() && n.Contains(t) {
			return "do_not_probe_list"
		}
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Daily cap, reset on UTC day change.
	day := now.UTC().YearDay()
	if day != p.dayStamp {
		p.dayStamp, p.sentToday = day, 0
	}
	if p.cfg.DailyCap > 0 && p.sentToday >= p.cfg.DailyCap {
		return "daily_cap"
	}

	if last, ok := p.recent[target]; ok && now.Sub(last) < p.cfg.cooldown() {
		return "cooldown"
	}

	// Token bucket.
	elapsed := now.Sub(p.lastRefill).Seconds()
	p.lastRefill = now
	p.tokens += elapsed * p.cfg.RatePerSec
	if depth := p.cfg.RatePerSec * p.cfg.BurstSeconds; p.tokens > depth {
		p.tokens = depth
	}
	if p.tokens < 1 {
		return "rate_limit"
	}
	p.tokens--

	p.recent[target] = now
	p.sentToday++
	return ""
}

func (p *Prober) worker() {
	defer p.wg.Done()
	for j := range p.jobs {
		p.run(j)
	}
}

func (p *Prober) run(j probeJob) {
	now := time.Now()
	res := ProbeResult{
		TS: now.UTC(), NodeID: p.nodeID, Target: j.target.String(),
		LagMS: now.Sub(j.seenAt).Milliseconds(), PassiveRTTMS: j.passiveRTT,
	}
	if rule := p.admit(j.target, now); rule != "" {
		// Skips are logged too. A silent skip would make the denominator
		// unknowable, and "responsive" only means something against a known
		// count of probes actually sent.
		res.SkipRule = rule
		p.nSkipped.Add(1)
		p.emit(&res)
		return
	}
	p.nSent.Add(1)

	// Only the target's own answers feed active_min_ms and responsive. A
	// timing from a filtering device on the path is recorded but excluded.
	best := 0.0
	consider := func(a ProbeAttempt) {
		if hostAnswered(a.Result) && a.RTTMS > 0 && (best == 0 || a.RTTMS < best) {
			best = a.RTTMS
		}
	}
	if p.cfg.ICMP {
		a := p.probeICMP(j.target)
		res.ICMP = &a
		consider(a)
	}
	for _, port := range p.cfg.TCPPorts {
		a := p.probeTCP(j.target, port)
		res.TCP = append(res.TCP, a)
		consider(a)
	}
	res.ActiveMinMS = best
	res.Responsive = best > 0
	if res.Responsive {
		p.nResponsive.Add(1)
	}
	p.emit(&res)
}

func (p *Prober) emit(r *ProbeResult) {
	b, err := json.Marshal(r)
	if err != nil {
		return
	}
	if err := p.out.WriteRaw(append(b, '\n')); err != nil {
		log.Printf("probe log write: %v", err)
	}
}

// probeTCP sends one connect() and times the answer.
//
// A refusal is as good as an acceptance here, and better for our purposes: the
// RST comes from the target's kernel with no service involved, which is the
// probe primitive. connect() rather than a hand-rolled SYN because the kernel
// already does the retransmit and teardown correctly, and the extra cost on an
// open port is a single connection we close immediately -- orders of magnitude
// less than the scan that prompted it.
func (p *Prober) probeTCP(target netip.Addr, port int) ProbeAttempt {
	a := ProbeAttempt{Kind: "tcp", Port: port}
	addr := net.JoinHostPort(target.String(), fmt.Sprint(port))
	d := net.Dialer{Timeout: p.cfg.timeout()}
	t0 := time.Now()
	c, err := d.Dial("tcp", addr)
	el := float64(time.Since(t0).Microseconds()) / 1000.0
	if err == nil {
		c.Close()
		a.Result, a.RTTMS = "synack", el
		return a
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		// SYN -> RST: a clean round trip.
		a.Result, a.RTTMS = "rst", el
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		// An ICMP administratively-prohibited error came back. Common on
		// residential IPv6, where the CPE or ISP refuses unsolicited inbound
		// rather than dropping it. Timed, because it confirms the path, but
		// see hostAnswered: the sender is the filter, not the target.
		a.Result, a.RTTMS = "prohibited", el
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH),
		errors.Is(err, syscall.ECONNRESET):
		a.Result, a.Err = "unreachable", err.Error()
	case isTimeout(err):
		a.Result = "timeout"
	default:
		a.Result, a.Err = "error", err.Error()
	}
	return a
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// probeICMP sends one echo request and waits for the matching reply.
//
// A fresh socket per probe rather than one shared listener with a demultiplexer:
// at the rates this module runs (single-digit probes per second, capped) the
// socket churn is irrelevant, and it keeps reply matching trivially correct
// instead of depending on an ID/sequence table that could mismatch replies
// between concurrent targets.
func (p *Prober) probeICMP(target netip.Addr) ProbeAttempt {
	a := ProbeAttempt{Kind: "icmp"}
	v6 := !target.Unmap().Is4()
	network, proto, typ := "ip4:icmp", 1, icmp.Type(ipv4.ICMPTypeEcho)
	if v6 {
		network, proto, typ = "ip6:ipv6-icmp", 58, icmp.Type(ipv6.ICMPTypeEchoRequest)
	}
	conn, err := icmp.ListenPacket(network, "")
	if err != nil {
		a.Result, a.Err = "error", err.Error()
		return a
	}
	defer conn.Close()

	id := os.Getpid() & 0xffff
	msg := icmp.Message{Type: typ, Code: 0,
		Body: &icmp.Echo{ID: id, Seq: 1, Data: []byte("rcbg")}}
	wb, err := msg.Marshal(nil)
	if err != nil {
		a.Result, a.Err = "error", err.Error()
		return a
	}
	dst := &net.IPAddr{IP: net.IP(target.Unmap().AsSlice())}
	deadline := time.Now().Add(p.cfg.timeout())
	_ = conn.SetDeadline(deadline)

	t0 := time.Now()
	if _, err := conn.WriteTo(wb, dst); err != nil {
		a.Result, a.Err = "error", err.Error()
		return a
	}

	rb := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			if isTimeout(err) {
				a.Result = "timeout"
			} else {
				a.Result, a.Err = "error", err.Error()
			}
			return a
		}
		// The raw socket sees every ICMP arriving at the host, not just ours.
		// Match on peer, type and echo id before believing a reply, or a
		// concurrent probe's answer would be credited to this one.
		pa, ok := peer.(*net.IPAddr)
		if !ok || !pa.IP.Equal(dst.IP) {
			continue
		}
		m, err := icmp.ParseMessage(proto, rb[:n])
		if err != nil {
			continue
		}
		isReply := m.Type == ipv4.ICMPTypeEchoReply || m.Type == ipv6.ICMPTypeEchoReply
		if !isReply {
			continue
		}
		if e, ok := m.Body.(*icmp.Echo); !ok || e.ID != id || e.Seq != 1 {
			continue
		}
		a.Result = "reply"
		a.RTTMS = float64(time.Since(t0).Microseconds()) / 1000.0
		return a
	}
}

// Stats reports probe counters for the periodic log line.
func (p *Prober) Stats() (sent, skipped, dropped, responsive uint64) {
	return p.nSent.Load(), p.nSkipped.Load(), p.nDropped.Load(), p.nResponsive.Load()
}
