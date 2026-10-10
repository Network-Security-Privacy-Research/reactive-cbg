#!/usr/bin/env bash
# R-CBG Phase 1 — deploy the agent to a single node.
#
# Deliberately one node at a time: test on ONE node and confirm
# you can still reconnect before rolling to the rest.
#
# Idempotent:
#   * an existing /etc/rcbg/agent.toml is never clobbered (pass --force-config)
#   * no firewall rule is ever added, removed or flushed (Phase 0 confirmed
#     inbound TCP is already unfiltered on these nodes)
#   * nothing the host was already running is stopped, reconfigured or rebound;
#     what is listening is snapshotted before and after and compared
#
# Requires sudo on the node. sudo asks for a password on this fleet, so the
# remote half runs under `ssh -t`.
#
# Usage: deploy/deploy-node.sh <alias> [--force-config] [--no-start]

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALIAS="${1:-}"
shift || true
FORCE_CONFIG=0
NO_START=0
for a in "$@"; do
  case "$a" in
    --force-config) FORCE_CONFIG=1 ;;
    --no-start)     NO_START=1 ;;
    *) echo "unknown flag: $a" >&2; exit 2 ;;
  esac
done

if [ -z "$ALIAS" ]; then
  echo "usage: $0 <alias> [--force-config] [--no-start]" >&2
  exit 2
fi

# The remote install needs sudo, and sudo on this fleet wants a password, so
# `ssh -t` needs a real TTY on this side. Fail before staging anything rather
# than halfway through.
if { [ ! -t 0 ] || [ ! -t 1 ]; } && [ -z "${RCBG_NO_TTY_OK:-}" ]; then
  cat >&2 <<'MSG'
error: no TTY available, but the remote sudo needs one to prompt.

Run this from an interactive terminal. Agent harnesses and CI runners generally
do not allocate a TTY -- use a normal shell instead.

If you have provisioned passwordless sudo on the node, re-run with
RCBG_NO_TTY_OK=1 to skip this check.
MSG
  exit 1
fi

BIN="$REPO/agent/bin/rcbg-agent"
CFG="$REPO/deploy/rendered/$ALIAS.toml"
UNIT="$REPO/agent/rcbg-agent.service"

[ -f "$CFG" ] || { echo "no rendered config for $ALIAS; run deploy/render-configs.py" >&2; exit 1; }

echo "==> building static binary"
( cd "$REPO/agent" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o bin/rcbg-agent . )

echo "==> staging to $ALIAS"
ssh "$ALIAS" 'mkdir -p ~/.rcbg-stage'
scp -q "$BIN" "$ALIAS:~/.rcbg-stage/rcbg-agent"
scp -q "$CFG" "$ALIAS:~/.rcbg-stage/agent.toml"
scp -q "$UNIT" "$ALIAS:~/.rcbg-stage/rcbg-agent.service"
scp -q "$REPO/deploy/remote-install.sh" "$ALIAS:~/.rcbg-stage/remote-install.sh"

# Snapshot what this host is already serving, so we can prove afterwards that
# installing the agent did not take any of it away.
#
# Deliberately NOT a list of service names. An earlier version named the
# daemons it expected to find, because every host it ran on happened to run
# them -- and it warned that a node "may already be unhealthy" when it found
# none, which is nonsense advice on a host that was never running them. The
# kernel already knows what is listening; ask it instead of guessing.
listening() {
  ssh -o BatchMode=yes "$1" '
    # proto/port, taking the port as whatever follows the last colon so that
    # 0.0.0.0:22, [::]:22 and 127.0.0.53%lo:53 all reduce correctly.
    { ss -Hltn 2>/dev/null | awk "{n=split(\$4,a,\":\"); print \"tcp/\" a[n]}"
      ss -Hlun 2>/dev/null | awk "{n=split(\$4,a,\":\"); print \"udp/\" a[n]}"
    } | sort -u | paste -sd, -
  ' 2>/dev/null || echo "unknown"
}

SERVING_BEFORE="$(listening "$ALIAS")"
echo "==> listening before deploy: ${SERVING_BEFORE:-<nothing>}"

echo "==> installing (sudo password may be requested)"
# NOTE: the installer is run from a staged file, not piped in via a heredoc.
# `ssh -t host bash -s <<EOF` puts the heredoc on ssh's stdin, which stops ssh
# allocating a TTY and leaves sudo with nowhere to prompt.
ssh -t "$ALIAS" "FORCE_CONFIG=$FORCE_CONFIG NO_START=$NO_START bash ~/.rcbg-stage/remote-install.sh"

echo
echo "==> post-install checks on $ALIAS"

SERVING_AFTER="$(listening "$ALIAS")"
# The agent ADDS listeners, so growth is expected and fine. What matters is
# whether anything that was answering before has stopped.
LOST=$(comm -23 \
  <(printf '%s' "$SERVING_BEFORE" | tr ',' '\n' | sort -u) \
  <(printf '%s' "$SERVING_AFTER"  | tr ',' '\n' | sort -u) | paste -sd, -)
if [ -n "$LOST" ]; then
  echo >&2
  echo "*** SOMETHING STOPPED LISTENING ***" >&2
  echo "    gone since before the deploy: $LOST" >&2
  echo "    Stop and investigate. Disable the agent with:" >&2
  echo "      ssh $ALIAS 'sudo systemctl disable --now rcbg-agent'" >&2
  exit 1
fi
echo "-- nothing that was listening before stopped."

ssh -o BatchMode=yes "$ALIAS" '
  echo "-- listening TCP ports --"
  ss -Hltn | awk "{print \$4}" | sed "s/.*[:.]//" | sort -un | paste -sd, -
  echo "-- agent --"
  printf "   state:  %s\n" "$(systemctl is-active rcbg-agent 2>/dev/null)"
  printf "   memory: %s\n" "$(systemctl show -p MemoryCurrent --value rcbg-agent 2>/dev/null)"
  echo "-- recent agent log --"
  journalctl -u rcbg-agent -n 12 --no-pager 2>/dev/null | sed "s/^/   /" || true
' || true

echo
echo "Deployed to $ALIAS. Confirm you can still SSH in a fresh session before rolling further."
