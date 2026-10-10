package main

import (
	"net/netip"
	"sync"
	"time"
)

// flowKey identifies one inbound connection attempt.
type flowKey struct {
	src     netip.Addr
	srcPort uint16
	dstPort uint16
}

// sample is one RTT observation with the method that produced it.
type sample struct {
	ms     float64
	method string
}

// flow accumulates everything learned about a single connection attempt from
// both the listener (TCP_INFO) and the capture (packet timings + fingerprint),
// and is emitted as one Record once idle.
type flow struct {
	key       flowKey
	firstSeen time.Time
	lastSeen  time.Time

	synackTX  time.Time // when our SYN-ACK went out (from capture)
	synackSeq uint32    // its sequence number; a reply must acknowledge seq+1
	synackAck uint32    // what it acknowledged, i.e. the peer's ISN+1
	hasSynack bool

	samples []sample

	ttl    uint8
	ipID   uint16
	window uint16
	optsFP string
	hasFP  bool

	// The banner-elicited data ACK, when a banner is configured. This is a
	// SECOND round trip on the same flow: banner out, its ACK back. It needs
	// its own reference point and its own dedup flag -- the SYN-ACK time is
	// the wrong t0 for it, and pcapSampled is already spent by the handshake.
	bannerTX      time.Time // when our banner segment went out
	bannerEndSeq  uint32    // seq + payload length; the ACK must carry exactly this
	hasBanner     bool
	bannerSampled bool

	handshakeDone bool
	resetByPeer   bool
	pcapSampled   bool
}

// FlowTable collects flows and emits them after an idle period.
type FlowTable struct {
	mu         sync.Mutex
	flows      map[flowKey]*flow
	flushAfter time.Duration
	nodeID     string
	out        *Writer
	dropped    uint64
	emitted    uint64
	unmeasured uint64
	maxFlows   int

	// Packets that arrived on a flow but acknowledged nothing we sent.
	unsolicitedACK uint64
	unsolicitedRST uint64

	// Optional active back-probe; nil in the passive phase.
	// Hooked here because emitting a record is the exact moment we know both
	// the source address and that it just talked to us -- probing then keeps
	// the lag to seconds, which is what separates "this host filters probes"
	// from "this address went dark since we saw it".
	prober *Prober
}

// SetProber attaches the active module. Must be called before Run.
func (ft *FlowTable) SetProber(p *Prober) { ft.prober = p }

func NewFlowTable(nodeID string, out *Writer, flushAfter time.Duration) *FlowTable {
	return &FlowTable{
		flows:      make(map[flowKey]*flow),
		flushAfter: flushAfter,
		nodeID:     nodeID,
		out:        out,
		maxFlows:   200000, // bounded so a SYN flood cannot exhaust memory
	}
}

func (ft *FlowTable) get(k flowKey, now time.Time) *flow {
	f, ok := ft.flows[k]
	if !ok {
		if len(ft.flows) >= ft.maxFlows {
			ft.dropped++
			return nil
		}
		f = &flow{key: k, firstSeen: now}
		ft.flows[k] = f
	}
	f.lastSeen = now
	return f
}

// AddSample records an RTT observation for a flow.
func (ft *FlowTable) AddSample(k flowKey, ms float64, method string, now time.Time) {
	if ms <= 0 || ms > 10000 {
		return // implausible; discard rather than poison the minimum
	}
	ft.mu.Lock()
	defer ft.mu.Unlock()
	if f := ft.get(k, now); f != nil {
		f.samples = append(f.samples, sample{ms: ms, method: method})
	}
}

// AddPcapSample records the first capture-derived RTT for a flow. Only the
// first is kept: later ACKs in the same connection are data ACKs, not handshake
// round trips, and would understate the RTT.
func (ft *FlowTable) AddPcapSample(k flowKey, ms float64, method string, now time.Time) {
	if ms <= 0 || ms > 10000 {
		return
	}
	ft.mu.Lock()
	defer ft.mu.Unlock()
	f := ft.get(k, now)
	if f == nil || f.pcapSampled {
		return
	}
	f.pcapSampled = true
	f.samples = append(f.samples, sample{ms: ms, method: method})
}

// NoteSynAck records the transmit time of our SYN-ACK, the reference point for
// the capture-derived RTT, together with the sequence numbers a genuine reply
// must carry. Retransmissions reuse the same numbers, so keeping the first is
// still correct.
func (ft *FlowTable) NoteSynAck(k flowKey, seq, ack uint32, t time.Time) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	if f := ft.get(k, t); f != nil && !f.hasSynack {
		f.synackTX, f.synackSeq, f.synackAck, f.hasSynack = t, seq, ack, true
	}
}

// NoteBannerTx records our banner segment: when it left and the acknowledgement
// number a reply to it must carry. Only the first data segment on a flow is
// kept, so a retransmitted banner still measures against the original send --
// the same reasoning as NoteSynAck.
func (ft *FlowTable) NoteBannerTx(k flowKey, endSeq uint32, t time.Time) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	if f := ft.get(k, t); f != nil && !f.hasBanner {
		f.bannerTX, f.bannerEndSeq, f.hasBanner = t, endSeq, true
	}
}

// BannerTx returns our banner's transmit time and the ack number a reply to it
// must carry.
func (ft *FlowTable) BannerTx(k flowKey) (t time.Time, endSeq uint32, ok bool) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	if f, found := ft.flows[k]; found && f.hasBanner {
		return f.bannerTX, f.bannerEndSeq, true
	}
	return time.Time{}, 0, false
}

// AddBannerSample records the banner -> data-ACK round trip. Deliberately not
// routed through AddPcapSample: that path is guarded by pcapSampled, which the
// handshake has already consumed, and dropping this sample is exactly the bug
// that made a configured banner measure nothing at all.
func (ft *FlowTable) AddBannerSample(k flowKey, ms float64, now time.Time) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	f := ft.get(k, now)
	if f == nil || f.bannerSampled {
		return
	}
	f.bannerSampled = true
	f.samples = append(f.samples, sample{ms: ms, method: "pcap_banner_ack"})
}

// SynAck returns our SYN-ACK's transmit time and sequence numbers for a flow.
func (ft *FlowTable) SynAck(k flowKey) (t time.Time, seq, ack uint32, ok bool) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	if f, found := ft.flows[k]; found && f.hasSynack {
		return f.synackTX, f.synackSeq, f.synackAck, true
	}
	return time.Time{}, 0, 0, false
}

// NoteUnsolicited counts an inbound ACK or RST that arrived on a live flow but
// did not acknowledge our SYN-ACK. Such a packet was not sent in reply to us --
// typically a scanner pipelining it behind its SYN without waiting -- so timing
// it measures the sender's own inter-packet gap rather than a round trip.
//
// Only packets that cost us a measurement are counted. A flow that already has
// its sample sees plenty of these -- duplicate ACKs, the client's answer to the
// FIN we send on close -- and counting those buries the signal the number
// exists to carry: the first rollout reported 90,765 refusals fleet-wide, of
// which almost none had prevented anything being measured.
func (ft *FlowTable) NoteUnsolicited(k flowKey, rst bool) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	if f, ok := ft.flows[k]; ok && f.pcapSampled {
		return
	}
	if rst {
		ft.unsolicitedRST++
	} else {
		ft.unsolicitedACK++
	}
}

// ValidationStats reports packets rejected as not acknowledging our SYN-ACK.
// Worth watching after a rollout: a sudden rise in rejected RSTs would mean the
// check is discarding legitimate stateless-scanner measurements.
func (ft *FlowTable) ValidationStats() (ack, rst uint64) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return ft.unsolicitedACK, ft.unsolicitedRST
}

// NoteFingerprint records the passive fingerprint carried by the client's SYN.
func (ft *FlowTable) NoteFingerprint(k flowKey, ttl uint8, ipID, window uint16, optsFP string, t time.Time) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	if f := ft.get(k, t); f != nil && !f.hasFP {
		f.ttl, f.ipID, f.window, f.optsFP, f.hasFP = ttl, ipID, window, optsFP, true
	}
}

func (ft *FlowTable) NoteHandshakeDone(k flowKey, t time.Time) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	if f := ft.get(k, t); f != nil {
		f.handshakeDone = true
	}
}

func (ft *FlowTable) NoteReset(k flowKey, t time.Time) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	if f := ft.get(k, t); f != nil {
		f.resetByPeer = true
	}
}

// Reap emits and removes flows idle longer than flushAfter. Passing a zero
// deadline flushes everything (shutdown).
func (ft *FlowTable) Reap(now time.Time, all bool) int {
	ft.mu.Lock()
	var ready []*flow
	for k, f := range ft.flows {
		if all || now.Sub(f.lastSeen) >= ft.flushAfter {
			ready = append(ready, f)
			delete(ft.flows, k)
		}
	}
	ft.mu.Unlock()

	n, unmeasured := 0, 0
	for _, f := range ready {
		if len(f.samples) == 0 {
			// No round trip was observable: the peer took our SYN-ACK and sent
			// neither an ACK nor a RST. Not worth a log line, but it must be
			// counted — this is the denominator for how much of the scanner
			// population we can actually measure, and a scanner that suppresses
			// its kernel's RST lands here rather than being merely absent.
			unmeasured++
			continue
		}
		rec := f.record(ft.nodeID)
		if err := ft.out.Write(rec); err == nil {
			n++
		}
		if ft.prober != nil {
			// Submit never blocks; a full queue drops the probe rather than
			// stalling the reaper. The passive measurement is the asset.
			ft.prober.Submit(f.key.src, f.lastSeen, rec.RTTMinMS)
		}
	}
	ft.mu.Lock()
	ft.emitted += uint64(n)
	ft.unmeasured += uint64(unmeasured)
	ft.mu.Unlock()
	return n
}

func (f *flow) record(nodeID string) *Record {
	r := &Record{
		TS:      f.firstSeen.UTC(),
		NodeID:  nodeID,
		SrcIP:   f.key.src.String(),
		SrcPort: f.key.srcPort,
		DstPort: f.key.dstPort,
		Proto:   "tcp",
	}
	// Minimum across every sample — never a single sample.
	best := f.samples[0]
	for _, s := range f.samples {
		r.RTTSamplesMS = append(r.RTTSamplesMS, s.ms)
		if s.ms < best.ms {
			best = s
		}
	}
	r.RTTMinMS = best.ms
	r.CaptureMethod = best.method
	r.TTLObserved = f.ttl
	r.IPID = f.ipID
	r.WindowSize = f.window
	r.TCPOptsFP = f.optsFP
	r.Flags.HandshakeDone = f.handshakeDone
	r.Flags.ResetByPeer = f.resetByPeer
	// v1 rule: any unsolicited inbound to a honeypot port is a
	// candidate scan. Refinement happens centrally, not here.
	r.Flags.ScanCandidate = true
	return r
}

// Stats reports flow-table counters. unmeasured counts flows that produced no
// RTT at all; together with emitted it gives the measurable fraction of the
// scanner population seen by this node.
func (ft *FlowTable) Stats() (open int, emitted, dropped, unmeasured uint64) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return len(ft.flows), ft.emitted, ft.dropped, ft.unmeasured
}
