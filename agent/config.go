package main

import (
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// Ceilings on the active module, enforced regardless of what the config says.
// At 5/s a node sends less than one packet per scanner it
// already answered; the daily cap is the number a provider would ask about.
const (
	maxProbeRatePerSec = 5.0
	maxProbeDailyCap   = 50000
	// A minute's worth of tokens is the most we will hold. Beyond that a long
	// quiet spell would bank enough credit for a burst that looks like a scan
	// in its own right, whatever the average says.
	maxProbeBurstSeconds = 60.0
)

// Config is the per-node agent configuration.
type Config struct {
	// node_id is the join key. Position deliberately lives centrally, not
	// here: the agent has no use for it, and a copy on the box would go stale
	// every time a landmark is refined. Older configs may still carry
	// lat/lon/calibrated; unknown keys are ignored.
	NodeID string `toml:"node_id"`

	ListenPorts []int `toml:"listen_ports"`
	// Ports this host must not hand to a honeypot listener, because something
	// else on the box needs them. Empty by default: only the operator knows
	// what a given host already runs, and hard-coding a guess here would be
	// wrong for most of them. Put the ports your own services use in it and
	// the agent refuses to start rather than fighting them for a bind.
	//
	// 22 is the usual first entry. Add whatever else this host answers on, and
	// keep entries for services that are merely stopped right now -- the
	// installer's own check only sees what is bound at the moment it runs, so
	// this list is what protects a port across a restart. A config that says
	// out loud what the box is for is easier to audit than one that does not.
	NeverBind []int  `toml:"never_bind"`
	LogPath   string `toml:"log_path"`
	LogMaxMB  int    `toml:"log_max_mb"`
	LogKeep   int    `toml:"log_keep"`
	// Gzip rotated logs. Rotated files are never appended to, so this is free,
	// and it buys roughly an order of magnitude more history before a burst
	// pushes records out of the retention window.
	LogCompress bool `toml:"log_compress"`

	// Master switch for the active back-probe module. Defaults
	// to false and every node ships with it false; turning it on is a
	// deliberate per-node act so a provider complaint is one config edit.
	ActiveProbeEnabled bool `toml:"active_probe_enabled"`

	// Details of the active module. Ignored entirely unless the master switch
	// above is on.
	ActiveProbe ProbeConfig `toml:"active_probe"`

	// Packet capture supplements TCP_INFO: it is the only way to measure
	// stateless scanners (zmap/masscan) that RST instead of completing the
	// handshake, and the only source of TTL / IP-ID / TCP-option fingerprints.
	CaptureEnabled bool   `toml:"capture_enabled"`
	CaptureIface   string `toml:"capture_iface"`

	// Emit a flow record once it has been idle this long (seconds).
	FlushAfterSec int `toml:"flush_after_sec"`

	// Optional banner sent on accept to elicit a data ACK (a second RTT
	// sample). Empty disables it.
	Banner string `toml:"banner"`
}

// ProbeConfig configures the active back-probe module. The guardrails are
// not optional, so the fields that enforce them
// (rate_per_sec, daily_cap, timeout_ms) are clamped to sane values rather than
// trusted, and a config that tried to disable them cannot.
type ProbeConfig struct {
	// TCP ports to probe. The probe primitive is a single SYN: a closed port
	// answering RST is a clean RTT and needs no service on the target.
	TCPPorts []int `toml:"tcp_ports"`
	ICMP     bool  `toml:"icmp"`

	RatePerSec float64 `toml:"rate_per_sec"`
	// How many seconds' worth of tokens the bucket may hold. This governs
	// burst tolerance only: the refill rate still bounds the sustained probe
	// rate, so a deeper bucket cannot raise the long-run average above
	// rate_per_sec, and daily_cap bounds the total either way.
	BurstSeconds  float64 `toml:"burst_seconds"`
	DailyCap      int     `toml:"daily_cap"`
	CooldownHours float64 `toml:"cooldown_hours"`
	TimeoutMS     int     `toml:"timeout_ms"`
	Workers       int     `toml:"workers"`
	QueueDepth    int     `toml:"queue_depth"`

	// Separate from the measurement log so the probe record -- what we sent,
	// where, and when -- can be produced on request without the rest.
	LogPath  string `toml:"log_path"`
	LogMaxMB int    `toml:"log_max_mb"`
	LogKeep  int    `toml:"log_keep"`

	// Touch this file to stop probing fleet-wide within seconds, with no
	// restart and no config edit. The module must be trivially killable.
	KillSwitchPath string `toml:"kill_switch_path"`

	// Operator do-not-probe list, as CIDRs, on top of the built-in bogon set.
	DoNotProbe []string `toml:"do_not_probe"`

	doNotProbe []netip.Prefix
}

func (p ProbeConfig) cooldown() time.Duration {
	return time.Duration(p.CooldownHours * float64(time.Hour))
}

func (p ProbeConfig) timeout() time.Duration {
	return time.Duration(p.TimeoutMS) * time.Millisecond
}

func defaultProbeConfig() ProbeConfig {
	return ProbeConfig{
		// Two ports, not eight. Every extra port multiplies the packets we
		// send per target for a steeply diminishing chance of an answer.
		TCPPorts: []int{80, 443},
		ICMP:     true,
		// Deliberately slow. The queue drops what it cannot keep up with, and
		// a probe we skipped costs one row of a 19k-row table; a provider
		// complaint costs a node.
		RatePerSec:     2,
		BurstSeconds:   20,
		DailyCap:       20000,
		CooldownHours:  24,
		TimeoutMS:      2000,
		Workers:        8,
		QueueDepth:     1024,
		LogPath:        "/var/lib/rcbg/probes.jsonl",
		LogMaxMB:       128,
		LogKeep:        3,
		KillSwitchPath: "/var/lib/rcbg/STOP-PROBING",
	}
}

// validate clamps the guardrails and parses the do-not-probe list. The limits
// are enforced here rather than trusted from the file: a typo that sent
// rate_per_sec to 10000 would look like a config mistake and read like a
// denial-of-service attempt from whoever received it.
func (p *ProbeConfig) validate() error {
	if len(p.TCPPorts) == 0 && !p.ICMP {
		return fmt.Errorf("no tcp_ports and icmp=false: nothing to send")
	}
	for _, port := range p.TCPPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid tcp probe port %d", port)
		}
	}
	if p.RatePerSec <= 0 || p.RatePerSec > maxProbeRatePerSec {
		return fmt.Errorf("rate_per_sec must be in (0, %g]; got %g",
			maxProbeRatePerSec, p.RatePerSec)
	}
	// Zero means an unset key rather than a deliberate choice: the burst was
	// fixed at one second's worth before this was configurable, so fall back
	// to that rather than to a bucket that can never fill.
	if p.BurstSeconds == 0 {
		p.BurstSeconds = 1
	}
	if p.BurstSeconds < 1 || p.BurstSeconds > maxProbeBurstSeconds {
		return fmt.Errorf("burst_seconds must be in [1, %g]; got %g",
			maxProbeBurstSeconds, p.BurstSeconds)
	}
	if p.DailyCap <= 0 || p.DailyCap > maxProbeDailyCap {
		return fmt.Errorf("daily_cap must be in (0, %d]; got %d",
			maxProbeDailyCap, p.DailyCap)
	}
	if p.CooldownHours <= 0 {
		return fmt.Errorf("cooldown_hours must be > 0: without it one scanner is probed thousands of times")
	}
	if p.TimeoutMS < 100 || p.TimeoutMS > 30000 {
		return fmt.Errorf("timeout_ms must be in [100, 30000]; got %d", p.TimeoutMS)
	}
	if p.Workers < 1 {
		p.Workers = 1
	}
	if p.QueueDepth < 1 {
		p.QueueDepth = 1
	}
	if p.LogPath == "" {
		return fmt.Errorf("log_path is required: every probe must be audit-logged")
	}
	if p.LogMaxMB <= 0 {
		p.LogMaxMB = 128
	}
	p.doNotProbe = nil
	for _, s := range p.DoNotProbe {
		n, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("do_not_probe %q: %w", s, err)
		}
		p.doNotProbe = append(p.doNotProbe, n.Masked())
	}
	return nil
}

func defaultConfig() Config {
	return Config{
		LogPath:        "/var/lib/rcbg/measurements.jsonl",
		LogMaxMB:       512,
		LogKeep:        3,
		FlushAfterSec:  10,
		CaptureEnabled: true,
		LogCompress:    true,
		ActiveProbe:    defaultProbeConfig(),
	}
}

func LoadConfig(path string) (Config, error) {
	c := defaultConfig()
	b, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("read config: %w", err)
	}
	if err := toml.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("parse config: %w", err)
	}
	if c.NodeID == "" {
		return c, fmt.Errorf("node_id is required")
	}
	if len(c.ListenPorts) == 0 {
		return c, fmt.Errorf("listen_ports is empty")
	}
	// Never take a port the host needs for something else. The agent must not
	// be the reason a service on this box stops answering, and the operator is
	// the only one who knows which ports those are -- hence never_bind rather
	// than a built-in list.
	blocked := make(map[int]bool, len(c.NeverBind))
	for _, p := range c.NeverBind {
		blocked[p] = true
	}
	for _, p := range c.ListenPorts {
		if p < 1 || p > 65535 {
			return c, fmt.Errorf("invalid listen port %d", p)
		}
		if blocked[p] {
			return c, fmt.Errorf("refusing to bind port %d: listed in never_bind", p)
		}
	}
	if c.ActiveProbeEnabled {
		if err := c.ActiveProbe.validate(); err != nil {
			return c, fmt.Errorf("active_probe: %w", err)
		}
	}
	if c.LogMaxMB <= 0 {
		c.LogMaxMB = 512
	}
	if c.FlushAfterSec <= 0 {
		c.FlushAfterSec = 10
	}
	return c, nil
}
