#!/usr/bin/env bash
# Runs ON the node, staged there by deploy/deploy-node.sh.
#
# This lives in its own file rather than a heredoc piped to `bash -s` for a
# specific reason: `ssh -t host bash -s <<EOF` hands the heredoc to ssh's stdin,
# so ssh cannot allocate a TTY and sudo has nowhere to prompt for a password.
# Staging the script and running `ssh -t host bash <script>` leaves stdin
# attached to the terminal, which is what sudo needs.
#
# Env: FORCE_CONFIG=0|1  NO_START=0|1

set -euo pipefail
S="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Refuse to take a port something on this host is already using. The agent's
# own never_bind list catches ports the operator KNOWS about; this catches the
# ones they forgot, by asking the kernel instead of a config file. Checked here
# rather than centrally because only the node knows what it is running.
want=$(awk -F'[][]' '/^listen_ports/{print $2}' "$S/agent.toml" \
         | tr ',' '\n' | tr -d ' ' | grep -E '^[0-9]+$' | sort -un)
bound=$(ss -Hltn 2>/dev/null | awk '{print $4}' | sed 's/.*[:.]//' | sort -un)
clash=$(comm -12 <(echo "$want") <(echo "$bound"))
if [ -n "$clash" ]; then
  echo "REFUSING: these listen_ports are already bound on this host:" >&2
  echo "$clash" | paste -sd, - | sed 's/^/  /' >&2
  echo "Remove them from listen_ports, or add them to never_bind, and re-run." >&2
  echo "Nothing has been installed." >&2
  exit 1
fi

sudo install -d -m 0755 /etc/rcbg
sudo install -d -m 0755 /var/lib/rcbg

# Dedicated unprivileged service account; capabilities come from the unit.
if ! id rcbg >/dev/null 2>&1; then
  sudo useradd --system --no-create-home --shell /usr/sbin/nologin rcbg
  echo "created user rcbg"
fi
sudo chown rcbg:rcbg /var/lib/rcbg

sudo install -m 0755 "$S/rcbg-agent" /usr/local/bin/rcbg-agent

if [ -f /etc/rcbg/agent.toml ] && [ "${FORCE_CONFIG:-0}" != "1" ]; then
  echo "keeping existing /etc/rcbg/agent.toml (pass --force-config to replace)"
else
  if [ -f /etc/rcbg/agent.toml ]; then
    sudo cp -a /etc/rcbg/agent.toml "/etc/rcbg/agent.toml.bak.$(date +%s)"
    echo "backed up previous config"
  fi
  sudo install -m 0644 "$S/agent.toml" /etc/rcbg/agent.toml
fi

# Validate before we let systemd near it.
sudo /usr/local/bin/rcbg-agent -config /etc/rcbg/agent.toml -check

sudo install -m 0644 "$S/rcbg-agent.service" /etc/systemd/system/rcbg-agent.service
sudo systemctl daemon-reload

if [ "${NO_START:-0}" = "1" ]; then
  echo "installed but not started (--no-start)"
else
  # `enable --now` starts a stopped unit but does NOT restart a running one, so
  # a redeploy would leave the old binary and old unit settings in effect.
  sudo systemctl enable rcbg-agent
  sudo systemctl restart rcbg-agent
  sleep 2
  sudo systemctl --no-pager --full status rcbg-agent | head -20

  # Surface the capture state directly: it degrades to TCP_INFO-only rather than
  # failing loudly, and that is easy to miss.
  echo
  if sudo journalctl -u rcbg-agent -n 40 --no-pager | grep -q "capture disabled"; then
    echo "!! CAPTURE IS DISABLED -- stateless scanners will not be measured:"
    sudo journalctl -u rcbg-agent -n 40 --no-pager | grep -A3 "capture disabled" | sed 's/^/   /'
  else
    sudo journalctl -u rcbg-agent -n 40 --no-pager | grep -i "capturing on" | sed 's/^/   /'
  fi
fi

cd /
rm -rf "$S"
