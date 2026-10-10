// Command rcbg-agent is the R-CBG passive node agent.
//
// It presents TCP listeners on commonly-scanned ports and measures the RTT of
// every unsolicited connection that arrives, from two independent sources:
//
//   - TCP_INFO on accept — the kernel's own SYN-ACK -> ACK measurement, for
//     scanners that complete the handshake.
//   - AF_PACKET capture — SYN-ACK -> RST timing for stateless scanners that
//     never complete it, plus the TTL / IP-ID / TCP-option fingerprint. The RST
//     is emitted by the scanning host's kernel rather than by the scan tool, so
//     it can be absent if that host suppresses or filters it; see capture.go.
//
// PASSIVE PHASE: this binary sends no unsolicited packets. It only ever
// responds to inbound connections. There is no active probe code compiled in.
package main

import (
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

var errNoPorts = errors.New("no listen ports could be bound")

func itoa(i int) string { return strconv.Itoa(i) }

func main() {
	cfgPath := flag.String("config", "/etc/rcbg/agent.toml", "path to agent config")
	dryRun := flag.Bool("check", false, "validate config and exit")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetPrefix("rcbg-agent: ")

	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *dryRun {
		log.Printf("config OK: node_id=%s ports=%v log=%s capture=%v iface=%s",
			cfg.NodeID, cfg.ListenPorts, cfg.LogPath, cfg.CaptureEnabled, cfg.CaptureIface)
		// Say this plainly either way. -check is the last look before a config
		// reaches a node, and whether the box will send unsolicited packets is
		// the one thing worth being certain of at that moment.
		if cfg.ActiveProbeEnabled {
			log.Printf("ACTIVE PROBE: ON  tcp=%v icmp=%v rate=%.1f/s cap=%d/day "+
				"cooldown=%.1fh do_not_probe=%d prefixes kill_switch=%s",
				cfg.ActiveProbe.TCPPorts, cfg.ActiveProbe.ICMP,
				cfg.ActiveProbe.RatePerSec, cfg.ActiveProbe.DailyCap,
				cfg.ActiveProbe.CooldownHours, len(cfg.ActiveProbe.DoNotProbe),
				cfg.ActiveProbe.KillSwitchPath)
		} else {
			log.Printf("ACTIVE PROBE: off (this node sends no unsolicited packets)")
		}
		return
	}

	w, err := NewWriter(cfg.LogPath, cfg.LogMaxMB, cfg.LogKeep, cfg.LogCompress)
	if err != nil {
		log.Fatalf("log: %v", err)
	}
	defer w.Close()

	ft := NewFlowTable(cfg.NodeID, w, time.Duration(cfg.FlushAfterSec)*time.Second)

	var prober *Prober
	if cfg.ActiveProbeEnabled {
		pw, err := NewWriter(cfg.ActiveProbe.LogPath, cfg.ActiveProbe.LogMaxMB,
			cfg.ActiveProbe.LogKeep, false)
		if err != nil {
			log.Fatalf("probe log: %v", err)
		}
		defer pw.Close()
		prober, err = NewProber(cfg.ActiveProbe, cfg.NodeID, pw)
		if err != nil {
			log.Fatalf("active probe: %v", err)
		}
		ft.SetProber(prober)
		// Loud on purpose. This is the only mode in which the agent sends
		// unsolicited packets, and it should be obvious in the journal which
		// nodes are doing it and under what limits.
		log.Printf("ACTIVE PROBING ENABLED: tcp=%v icmp=%v rate=%.1f/s cap=%d/day "+
			"cooldown=%.1fh kill_switch=%s log=%s",
			cfg.ActiveProbe.TCPPorts, cfg.ActiveProbe.ICMP, cfg.ActiveProbe.RatePerSec,
			cfg.ActiveProbe.DailyCap, cfg.ActiveProbe.CooldownHours,
			cfg.ActiveProbe.KillSwitchPath, cfg.ActiveProbe.LogPath)
	}

	ls, err := NewListeners(cfg, ft)
	if err != nil {
		log.Fatalf("listeners: %v", err)
	}
	ls.Run()

	var cap *Capture
	if cfg.CaptureEnabled {
		cap, err = NewCapture(cfg.CaptureIface, cfg.ListenPorts, ft)
		if err != nil {
			logCaptureUnavailable(err)
		} else {
			go cap.Run()
			log.Printf("capturing on %s for ports %v", cfg.CaptureIface, cfg.ListenPorts)
		}
	}

	log.Printf("node=%s started", cfg.NodeID)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	reap := time.NewTicker(time.Second)
	defer reap.Stop()
	stats := time.NewTicker(10 * time.Minute)
	defer stats.Stop()

	for {
		select {
		case <-reap.C:
			ft.Reap(time.Now(), false)
		case <-stats.C:
			open, emitted, dropped, unmeasured := ft.Stats()
			uack, urst := ft.ValidationStats()
			// unsolicited_* are packets that arrived on a flow without
			// acknowledging our SYN-ACK, so they were not timed. A high
			// unsolicited_rst would mean the check is refusing legitimate
			// stateless-scanner measurements and should be revisited.
			log.Printf("stats: open_flows=%d emitted=%d unmeasured=%d dropped=%d "+
				"unsolicited_ack=%d unsolicited_rst=%d",
				open, emitted, unmeasured, dropped, uack, urst)
			if prober != nil {
				sent, skipped, pdropped, responsive := prober.Stats()
				log.Printf("probe: sent=%d responsive=%d skipped=%d queue_dropped=%d",
					sent, responsive, skipped, pdropped)
			}
		case <-stop:
			log.Printf("shutting down")
			ls.Close()
			if cap != nil {
				cap.Close()
			}
			if prober != nil {
				// Before the final Reap, so the flush cannot queue probes into
				// a closed channel.
				prober.Close()
				ft.SetProber(nil)
			}
			n := ft.Reap(time.Now(), true)
			open, emitted, dropped, unmeasured := ft.Stats()
			log.Printf("flushed %d flow(s); total emitted=%d unmeasured=%d dropped=%d open=%d",
				n, emitted, unmeasured, dropped, open)
			return
		}
	}
}
