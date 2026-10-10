# R-CBG node agent

Measurement agent for "Reactive Constraint-Based Geolocation of Internet
Hosts". It listens on a set of TCP ports and records the round-trip time of
handshakes that remote hosts initiate. It sends unsolicited probes only if
active probing is enabled in the config.

## Layout

```
agent/                    Go source and tests
  rcbg-agent.service      systemd unit
deploy/
  agent.toml.example      documented config template
  deploy-node.sh          build, install, and verify one node over SSH
  remote-install.sh       runs on the node (staged by deploy-node.sh)
  verify-node.sh          post-install health check
  provision-nopasswd.sh   optional passwordless sudo for unattended redeploys
  rendered/               per-node configs go here
```

## Requirements

Node dependencies: Linux 4.10 or newer, systemd, root for install. The agent
runs as an unprivileged `rcbg` user with `CAP_NET_RAW` and
`CAP_NET_BIND_SERVICE`, and writes to `/var/lib/rcbg`.

Build dependencies: Go 1.25+ (package dependencies: BurntSushi/toml,
golang.org/x/net, golang.org/x/sys). 

## Build

```sh
cd agent && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o bin/rcbg-agent .
go test ./...
```

Add `GOOS=linux GOARCH=arm64` for arm64.

## Deploy

Build first (see above) so that `agent/bin/rcbg-agent` exists. Then:

```sh
cp deploy/agent.toml.example deploy/rendered/mynode.toml
$EDITOR deploy/rendered/mynode.toml          # set node_id and capture_iface
agent/bin/rcbg-agent -config deploy/rendered/mynode.toml -check
deploy/deploy-node.sh mynode                 # mynode is an SSH host/alias
```

`capture_iface` must be the default-route interface. 

`listen_ports` must not include any ports the host already binds to. 

## Output

One JSON object per line in `/var/lib/rcbg/measurements.jsonl`, rotated at
`log_max_mb` and keeping `log_keep` files. Pull logs on a cadence shorter than
the retention window.

```json
{
  "ts": "2026-10-10T14:03:11.284Z",
  "node_id": "mynode",
  "src_ip": "<example source ip>",
  "src_port": 51234,
  "dst_port": 443,
  "proto": "tcp",
  "rtt_samples_ms": [41.2, 41.9],
  "rtt_min_ms": 41.2,
  "capture_method": "pcap_synack_ack",
  "ttl_observed": 52,
  "tcp_opts_fp": "...",
  "ip_id": 12345,
  "window_size": 65535,
  "flags": {
    "scan_candidate": true,
    "handshake_done": true,
    "reset_by_peer": false
  }
}
```

`capture_method` is `tcp_info` (kernel-reported, completed handshake),
`pcap_synack_ack`, or `pcap_synack_rst` (timed from packet capture; the RST
variant is a stateless scanner).

Active probe results, if enabled, go to `/var/lib/rcbg/probes.jsonl` with the
same rotation. `touch /var/lib/rcbg/STOP-PROBING` halts probing immediately.

## Citation

If you use this agent or its measurements, please cite:

> Spencer Ye, Chase Kanipe, Peter Ryan, and Erik Rye. Reactive
> Constraint-Based Geolocation of Internet Hosts. NewGeo '26.
> arXiv:2610.05545.

```bibtex
@inproceedings{ye2026reactive,
  title         = {Reactive Constraint-Based Geolocation of Internet Hosts},
  author        = {Ye, Spencer and Kanipe, Chase and Ryan, Peter and Rye, Erik},
  year          = {2026},
  booktitle     = "{Proceedings of the New Directions in IP Geolocation Workshop 2026 (NewGeo 2026) }"
```

## License

MIT.
