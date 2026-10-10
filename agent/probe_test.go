package main

import (
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"
)

// testProber builds a Prober without starting workers, so admit() can be
// exercised deterministically.
func testProber(t *testing.T, mut func(*ProbeConfig)) *Prober {
	t.Helper()
	cfg := defaultProbeConfig()
	cfg.KillSwitchPath = ""
	if mut != nil {
		mut(&cfg)
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return &Prober{
		cfg: cfg, nodeID: "test",
		tokens: cfg.RatePerSec, lastRefill: time.Now(),
		recent: make(map[netip.Addr]time.Time),
	}
}

// A scanner's source address is attacker-controlled, so the address filter is
// the guardrail most likely to be actually attacked: a spoofed source would
// otherwise aim the fleet at a third party.
func TestAdmitRejectsReservedAndBogonSpace(t *testing.T) {
	p := testProber(t, nil)
	now := time.Now()
	for _, addr := range []string{
		"10.0.0.1", "192.168.1.1", "172.16.5.5", "127.0.0.1", "0.0.0.0",
		"169.254.1.1", "100.64.0.1", "224.0.0.1", "239.1.2.3", "240.0.0.1",
		"255.255.255.255", "192.0.2.5", "198.51.100.5", "203.0.113.5",
		"198.18.0.1", "192.88.99.1",
		"::1", "fe80::1", "fc00::1", "ff02::1", "2001:db8::1",
	} {
		a := netip.MustParseAddr(addr)
		if rule := p.admit(a, now); rule == "" {
			t.Errorf("admit(%s) allowed a probe; must be refused", addr)
		}
	}
}

func TestAdmitAllowsOrdinaryPublicAddresses(t *testing.T) {
	p := testProber(t, func(c *ProbeConfig) { c.RatePerSec = 5 })
	now := time.Now()
	for _, addr := range []string{"8.8.8.8", "199.45.155.81", "2606:4700::1111"} {
		if rule := p.admit(netip.MustParseAddr(addr), now); rule != "" {
			t.Errorf("admit(%s) refused with %q; expected allow", addr, rule)
		}
	}
}

// An IPv4-mapped IPv6 form of a private address must not slip past the v4
// bogon list.
func TestAdmitUnmapsBeforeMatching(t *testing.T) {
	p := testProber(t, nil)
	a := netip.MustParseAddr("::ffff:10.1.2.3")
	if rule := p.admit(a, time.Now()); rule != "bogon" {
		t.Errorf("mapped RFC1918 address got %q; want bogon", rule)
	}
}

func TestAdmitHonoursDoNotProbeList(t *testing.T) {
	p := testProber(t, func(c *ProbeConfig) {
		c.DoNotProbe = []string{"203.0.114.0/24", "2001:4860::/32"}
	})
	now := time.Now()
	if rule := p.admit(netip.MustParseAddr("203.0.114.9"), now); rule != "do_not_probe_list" {
		t.Errorf("listed v4 prefix got %q; want do_not_probe_list", rule)
	}
	if rule := p.admit(netip.MustParseAddr("2001:4860::8888"), now); rule != "do_not_probe_list" {
		t.Errorf("listed v6 prefix got %q; want do_not_probe_list", rule)
	}
	if rule := p.admit(netip.MustParseAddr("203.0.115.9"), now); rule != "" {
		t.Errorf("unlisted neighbor got %q; want allow", rule)
	}
}

// Our corpus averages ~36 connections per source and one /24 sent 447k packets,
// so without a cooldown a single scanner would be probed thousands of times.
func TestAdmitCooldownSuppressesRepeatProbes(t *testing.T) {
	p := testProber(t, func(c *ProbeConfig) {
		c.RatePerSec = 5
		c.CooldownHours = 1
	})
	a := netip.MustParseAddr("198.51.101.7")
	now := time.Now()
	if rule := p.admit(a, now); rule != "" {
		t.Fatalf("first probe refused: %q", rule)
	}
	if rule := p.admit(a, now.Add(time.Minute)); rule != "cooldown" {
		t.Errorf("repeat within cooldown got %q; want cooldown", rule)
	}
	if rule := p.admit(a, now.Add(2*time.Hour)); rule != "" {
		t.Errorf("probe after cooldown got %q; want allow", rule)
	}
}

func TestAdmitRateLimits(t *testing.T) {
	p := testProber(t, func(c *ProbeConfig) { c.RatePerSec = 2 })
	now := time.Now()
	allowed := 0
	// Same instant, so no tokens are refilled: the bucket starts with one
	// second's worth and must not exceed it.
	for i := range 20 {
		a := netip.AddrFrom4([4]byte{198, 51, 102, byte(i)})
		if p.admit(a, now) == "" {
			allowed++
		}
	}
	if allowed != 2 {
		t.Errorf("allowed %d probes in one instant; want 2 (rate_per_sec)", allowed)
	}
	// A second later exactly one more second of tokens is available.
	allowed = 0
	for i := range 20 {
		a := netip.AddrFrom4([4]byte{198, 51, 103, byte(i)})
		if p.admit(a, now.Add(time.Second)) == "" {
			allowed++
		}
	}
	if allowed != 2 {
		t.Errorf("allowed %d probes after 1s; want 2", allowed)
	}
}

func TestAdmitDailyCap(t *testing.T) {
	p := testProber(t, func(c *ProbeConfig) {
		c.RatePerSec = 5
		c.DailyCap = 3
	})
	base := time.Now()
	allowed := 0
	for i := range 10 {
		// Advance a second each time so the rate limiter never bites and the
		// cap is unambiguously what stopped us.
		a := netip.AddrFrom4([4]byte{198, 51, 104, byte(i)})
		if p.admit(a, base.Add(time.Duration(i)*time.Second)) == "" {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("allowed %d probes; want 3 (daily_cap)", allowed)
	}
	// The cap resets on a UTC day change rather than accumulating forever.
	next := base.Add(25 * time.Hour)
	if rule := p.admit(netip.MustParseAddr("198.51.105.1"), next); rule != "" {
		t.Errorf("probe on the next day got %q; want allow", rule)
	}
}

func TestKillSwitchStopsEverything(t *testing.T) {
	p := testProber(t, func(c *ProbeConfig) { c.RatePerSec = 5 })
	p.killed.Store(true)
	if rule := p.admit(netip.MustParseAddr("8.8.8.8"), time.Now()); rule != "kill_switch" {
		t.Errorf("got %q while killed; want kill_switch", rule)
	}
}

// A refused probe must still consume nothing: if the kill switch or the bogon
// filter also burned a token or a cooldown slot, clearing the switch would
// leave the limiter in a misleading state.
func TestRefusedProbesDoNotConsumeBudget(t *testing.T) {
	p := testProber(t, func(c *ProbeConfig) { c.RatePerSec = 2 })
	now := time.Now()
	for range 50 {
		p.admit(netip.MustParseAddr("10.0.0.1"), now) // bogon, refused
	}
	allowed := 0
	for i := range 10 {
		a := netip.AddrFrom4([4]byte{198, 51, 106, byte(i)})
		if p.admit(a, now) == "" {
			allowed++
		}
	}
	if allowed != 2 {
		t.Errorf("allowed %d after 50 refusals; want 2 (refusals must not spend tokens)", allowed)
	}
}

func TestSubmitNeverBlocksWhenQueueIsFull(t *testing.T) {
	// No workers drain this queue, so it fills immediately. Submit is called
	// from the reaper that writes measurement records; if it could block, a
	// slow probe would stall the passive measurement that is the whole asset.
	p := &Prober{jobs: make(chan probeJob, 2)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 100 {
			p.Submit(netip.AddrFrom4([4]byte{1, 2, 3, byte(i)}), time.Now(), 1.0)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Submit blocked on a full queue")
	}
	if got := p.nDropped.Load(); got != 98 {
		t.Errorf("dropped %d; want 98", got)
	}
}

// The probe primitive: a SYN to a closed port gets a RST from the target's kernel
// with no service involved, and the round trip is clean. Verified against a
// loopback port we just released, so the test sends nothing off-box.
func TestProbeTCPTimesARefusal(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close() // nothing is listening now, so the kernel answers RST

	p := testProber(t, nil)
	a := p.probeTCP(netip.MustParseAddr("127.0.0.1"), port)
	if a.Result != "rst" {
		t.Fatalf("result %q (err=%q); want rst", a.Result, a.Err)
	}
	if a.RTTMS <= 0 {
		t.Errorf("refusal produced no timing (%v ms)", a.RTTMS)
	}
	if a.Kind != "tcp" || a.Port != port {
		t.Errorf("attempt mislabeled: %+v", a)
	}
}

func TestProbeTCPTimesAnAccept(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port

	p := testProber(t, nil)
	a := p.probeTCP(netip.MustParseAddr("127.0.0.1"), port)
	if a.Result != "synack" {
		t.Fatalf("result %q (err=%q); want synack", a.Result, a.Err)
	}
	if a.RTTMS <= 0 {
		t.Errorf("accept produced no timing (%v ms)", a.RTTMS)
	}
}

// A target that silently drops must read as a timeout, not an error: it is the
// unresponsive population that the whole exercise is trying to count, so
// misclassifying it would corrupt the headline number.
func TestProbeTCPUnansweredReadsAsTimeout(t *testing.T) {
	p := testProber(t, func(c *ProbeConfig) { c.TimeoutMS = 200 })
	// 198.18.0.0/15 is benchmark space (RFC 2544); admit() refuses it, but
	// probeTCP is being called directly and nothing routes there, so the
	// connect attempt goes nowhere and expires.
	a := p.probeTCP(netip.MustParseAddr("198.18.37.211"), 9)
	if a.Result != "timeout" && a.Result != "unreachable" {
		t.Fatalf("result %q (err=%q); want timeout or unreachable", a.Result, a.Err)
	}
	if a.RTTMS != 0 {
		t.Errorf("a non-answer must carry no RTT; got %v", a.RTTMS)
	}
}

// Every probe must be audit-logged. A refusal has to appear there too:
// "responsive" is only meaningful against a known count of probes sent, so a
// silent skip would make the denominator unknowable.
func TestRunAuditsRefusedProbes(t *testing.T) {
	dir := t.TempDir()
	w, err := NewWriter(dir+"/probes.jsonl", 8, 1, false)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	defer w.Close()

	p := testProber(t, nil)
	p.out = w
	p.run(probeJob{
		target:     netip.MustParseAddr("10.11.12.13"), // bogon: must be refused
		seenAt:     time.Now().Add(-1500 * time.Millisecond),
		passiveRTT: 4.25,
	})

	b, err := os.ReadFile(dir + "/probes.jsonl")
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	var got ProbeResult
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("audit line is not valid JSON: %v (%q)", err, b)
	}
	if got.SkipRule != "bogon" {
		t.Errorf("skip_rule = %q; want bogon", got.SkipRule)
	}
	if got.Responsive {
		t.Error("a refused probe must not be counted responsive")
	}
	if len(got.TCP) != 0 || got.ICMP != nil {
		t.Error("a refused probe must record no attempts: nothing was sent")
	}
	if got.PassiveRTTMS != 4.25 {
		t.Errorf("passive_rtt_ms = %v; want 4.25", got.PassiveRTTMS)
	}
	if got.LagMS < 1000 {
		t.Errorf("lag_ms = %d; want the real gap since the sighting", got.LagMS)
	}
	if n := p.nSkipped.Load(); n != 1 {
		t.Errorf("skipped counter = %d; want 1", n)
	}
	if n := p.nSent.Load(); n != 0 {
		t.Errorf("sent counter = %d; want 0 (nothing left the box)", n)
	}
}

func TestProbeConfigValidateRejectsUnsafeSettings(t *testing.T) {
	cases := map[string]func(*ProbeConfig){
		"rate above ceiling":   func(c *ProbeConfig) { c.RatePerSec = maxProbeRatePerSec + 1 },
		"rate zero":            func(c *ProbeConfig) { c.RatePerSec = 0 },
		"cap above ceiling":    func(c *ProbeConfig) { c.DailyCap = maxProbeDailyCap + 1 },
		"cap zero":             func(c *ProbeConfig) { c.DailyCap = 0 },
		"no cooldown":          func(c *ProbeConfig) { c.CooldownHours = 0 },
		"port too high":        func(c *ProbeConfig) { c.TCPPorts = []int{65536} },
		"bad port":             func(c *ProbeConfig) { c.TCPPorts = []int{0} },
		"nothing to send":      func(c *ProbeConfig) { c.TCPPorts = nil; c.ICMP = false },
		"no audit log":         func(c *ProbeConfig) { c.LogPath = "" },
		"absurd timeout":       func(c *ProbeConfig) { c.TimeoutMS = 60000 },
		"bad do_not_probe":     func(c *ProbeConfig) { c.DoNotProbe = []string{"not-a-cidr"} },
		"timeout far too tiny": func(c *ProbeConfig) { c.TimeoutMS = 1 },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := defaultProbeConfig()
			mut(&c)
			if err := c.validate(); err == nil {
				t.Errorf("validate accepted an unsafe config (%s)", name)
			}
		})
	}
}

func TestProbeConfigDefaultsAreValidAndConservative(t *testing.T) {
	c := defaultProbeConfig()
	if err := c.validate(); err != nil {
		t.Fatalf("defaults do not validate: %v", err)
	}
	if c.RatePerSec > maxProbeRatePerSec || c.DailyCap > maxProbeDailyCap {
		t.Error("defaults exceed the hard ceilings")
	}
	if c.KillSwitchPath == "" {
		t.Error("defaults must configure a kill switch")
	}
	if c.CooldownHours < 1 {
		t.Error("default cooldown is too short to prevent repeat probing")
	}
}

// The passive phase must be exactly as it was: a config that does not opt in
// gets no prober at all, and the details are ignored even if present.
func TestActiveProbeOffByDefault(t *testing.T) {
	if defaultConfig().ActiveProbeEnabled {
		t.Fatal("active probing must default to false")
	}
}

// An ICMP administratively-prohibited reply is a real returned packet with a
// real round trip, but it comes from whatever device chose to refuse, which may
// sit far short of the target. Treating it as the host answering would put a
// too-small disk around the wrong machine and could falsify a geolocation claim
// that is actually correct. It must be recorded and must not count.
func TestProhibitedIsRecordedButNotAHostAnswer(t *testing.T) {
	for _, r := range []string{"reply", "synack", "rst"} {
		if !hostAnswered(r) {
			t.Errorf("%q should count as the host answering", r)
		}
	}
	for _, r := range []string{"prohibited", "timeout", "unreachable", "error", ""} {
		if hostAnswered(r) {
			t.Errorf("%q must NOT count as the host answering", r)
		}
	}
}

// The whole point of separating them: a prohibited reply carries a timing, and
// that timing must stay out of active_min_ms.
func TestProhibitedTimingExcludedFromActiveMin(t *testing.T) {
	best := 0.0
	consider := func(a ProbeAttempt) {
		if hostAnswered(a.Result) && a.RTTMS > 0 && (best == 0 || a.RTTMS < best) {
			best = a.RTTMS
		}
	}
	// A filter answering in 16 ms alongside the real host at 99 ms: the fast
	// one is the wrong machine and must not become the constraint.
	consider(ProbeAttempt{Kind: "tcp", Port: 80, Result: "prohibited", RTTMS: 16.1})
	consider(ProbeAttempt{Kind: "icmp", Result: "reply", RTTMS: 99.5})
	if best != 99.5 {
		t.Errorf("active_min_ms = %v; want 99.5 (the prohibited 16.1 ms is the filter)", best)
	}
	// Prohibited alone leaves nothing usable.
	best = 0
	consider(ProbeAttempt{Kind: "tcp", Port: 443, Result: "prohibited", RTTMS: 16.1})
	if best != 0 {
		t.Errorf("a prohibited-only probe must yield no usable RTT; got %v", best)
	}
}

// TestAdmitBurstIsBoundedByBucketDepth: arrivals are bursty in a way the
// sustained rate is not -- measured over 12,013 busy node-seconds the median
// was 1 probe-eligible arrival and the 99.9th percentile was 41 -- so a bucket
// holding only one second's worth threw away roughly a tenth of all probe
// opportunities while the fleet sat under 20% of its daily cap. Depth is what
// absorbs that, and it must still be bounded.
func TestAdmitBurstIsBoundedByBucketDepth(t *testing.T) {
	p := testProber(t, func(c *ProbeConfig) { c.RatePerSec = 2; c.BurstSeconds = 20 })
	base := time.Now()
	p.lastRefill, p.tokens = base, 0

	// Idle far longer than the bucket can bank, then a burst in one instant.
	now := base.Add(10 * time.Minute)
	allowed := 0
	for i := range 200 {
		a := netip.AddrFrom4([4]byte{198, 51, byte(102 + i/256), byte(i % 256)})
		if p.admit(a, now) == "" {
			allowed++
		}
	}
	if want := 40; allowed != want {
		t.Errorf("burst admitted %d probes; want %d (rate 2/s x 20 s of depth)", allowed, want)
	}
}

// TestSustainedRateIsUnchangedByBurstDepth is the safety-critical property: a
// deeper bucket may let a burst borrow against future capacity, but it must not
// raise the long-run rate. That is what a provider would notice, and what
// we must bound.
func TestSustainedRateIsUnchangedByBurstDepth(t *testing.T) {
	const rate, secs = 2.0, 300
	for _, burst := range []float64{1, 20, 60} {
		p := testProber(t, func(c *ProbeConfig) { c.RatePerSec = rate; c.BurstSeconds = burst })
		base := time.Now()
		p.lastRefill, p.tokens = base, 0
		allowed, n := 0, 0
		// Offer far more than the limiter can pass, every second, for 5 minutes.
		for s := range secs {
			now := base.Add(time.Duration(s) * time.Second)
			for range 50 {
				n++
				// Distinct each time, so the cooldown never masks the limiter.
				a := netip.AddrFrom4([4]byte{203, byte(n >> 16), byte(n >> 8), byte(n)})
				if p.admit(a, now) == "" {
					allowed++
				}
			}
		}
		ceiling := int(rate*secs) + int(rate*burst)
		if allowed > ceiling {
			t.Errorf("burst_seconds=%g: %d probes in %ds exceeds the ceiling %d",
				burst, allowed, secs, ceiling)
		}
		if got := float64(allowed) / secs; got > rate*1.05 {
			t.Errorf("burst_seconds=%g: sustained %.2f/s exceeds rate_per_sec %.2f",
				burst, got, rate)
		}
	}
}

// A config written before burst_seconds existed must keep its old behavior
// rather than silently acquiring a bucket that never fills.
func TestMissingBurstSecondsDefaultsToOneSecond(t *testing.T) {
	c := defaultProbeConfig()
	c.KillSwitchPath = ""
	c.BurstSeconds = 0 // as an older TOML would leave it
	if err := c.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if c.BurstSeconds != 1 {
		t.Errorf("BurstSeconds = %g, want 1 (the pre-existing behavior)", c.BurstSeconds)
	}
}

func TestBurstSecondsIsBounded(t *testing.T) {
	c := defaultProbeConfig()
	c.KillSwitchPath = ""
	c.BurstSeconds = maxProbeBurstSeconds + 1
	if err := c.validate(); err == nil {
		t.Error("validate accepted burst_seconds above the maximum")
	}
}
