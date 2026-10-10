#!/usr/bin/env python3
"""Compare what the agent recorded against an independently known RTT.

Reads measurement JSONL on stdin. Lives in its own file rather than a heredoc
inside verify-node.sh: `ssh ... | python3 - args <<'PY'` gives python its
program on stdin *and* tries to pipe data there, and the heredoc wins, so the
piped records are never read.

Usage: analyze-verify.py <ping_min_ms> <src_ip> [since_iso8601] < records.jsonl
"""
from __future__ import annotations

import collections
import json
import statistics
import sys


def main() -> int:
    ping_min = float(sys.argv[1])
    myip = sys.argv[2] if len(sys.argv) > 2 else ""
    # The log accumulates across runs. Comparing a minimum taken over hours
    # against a ping taken just now measures path drift, not agent accuracy.
    since = sys.argv[3] if len(sys.argv) > 3 else ""

    all_rows, rows = [], []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        all_rows.append(r)
        if myip and r.get("src_ip") != myip:
            continue
        if since and r.get("ts", "") < since:
            continue
        rows.append(r)

    if not all_rows:
        print("    log is empty: no measurements recorded at all")
        return 1
    if not rows:
        others = collections.Counter(r["src_ip"] for r in all_rows)
        print(f"    no records from {myip} since {since or 'start of log'}, "
              f"but {len(all_rows)} total in the log:")
        for ip, n in others.most_common(5):
            print(f"      {ip}  {n}")
        return 1

    by_method: dict[str, list[float]] = {}
    for r in rows:
        by_method.setdefault(r["capture_method"], []).append(r["rtt_min_ms"])

    print(f"    {len(rows)} record(s) from {myip} in this run"
          f"   ({len(all_rows)} total in log)")
    print()
    print(f"    {'method':<20}{'n':>4}{'min':>10}{'median':>10}{'vs ping':>12}")
    for m, v in sorted(by_method.items()):
        print(f"    {m:<20}{len(v):>4}{min(v):>10.3f}"
              f"{statistics.median(v):>10.3f}{min(v) - ping_min:>+12.3f}")
    print()
    print(f"    ping min = {ping_min:.3f} ms")

    overall = min(r["rtt_min_ms"] for r in rows)
    delta = overall - ping_min
    # Tolerance scales with distance: a few ms of scheduling and path asymmetry
    # matters much less on a 250 ms path than a 5 ms one.
    tol = max(2.0, 0.10 * ping_min)
    verdict = "PASS" if abs(delta) <= tol else "SUSPECT"
    print(f"    overall min = {overall:.3f} ms   delta = {delta:+.3f} ms "
          f"(tolerance +/-{tol:.1f})   [{verdict}]")

    ports = collections.Counter(r["dst_port"] for r in rows)
    print(f"    ports covered: {dict(sorted(ports.items()))}")

    fp = [r for r in rows if r.get("ttl_observed")]
    print()
    if fp:
        s = fp[0]
        print(f"    capture is running: ttl={s['ttl_observed']} "
              f"opts={s.get('tcp_opts_fp', '-')} win={s.get('window_size', '-')} "
              f"({len(fp)}/{len(rows)} records fingerprinted)")
    else:
        print("    WARNING: no fingerprint fields on any record.")
        print("    The AF_PACKET capture is not delivering packets, so:")
        print("      - stateless scanners that never complete the handshake")
        print("        are being missed entirely")
        print("      - TTL / IP-ID / TCP-option fingerprints are absent")
        print("    Check: journalctl -u rcbg-agent | grep -i capture")
        return 2

    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
