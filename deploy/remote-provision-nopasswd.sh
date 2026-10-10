#!/usr/bin/env bash
# Runs ON the node, staged there by deploy/provision-nopasswd.sh.
#
# Installs /etc/sudoers.d/rcbg-deploy so the rollout can run unattended.
#
# The dangerous failure here is a malformed sudoers file, which breaks sudo
# entirely on a box you then cannot repair without console access. Guards:
#   * the candidate is written to a temp file and validated with `visudo -cf`
#     BEFORE it is placed in /etc/sudoers.d/
#   * `visudo -c` then re-validates the whole configuration
#   * if the post-install check fails the file is removed again immediately,
#     while we still hold an authenticated sudo timestamp
#
# Env: MODE=scoped|all  ACTION=install|revoke

set -euo pipefail

DEST=/etc/sudoers.d/rcbg-deploy   # no dot in the name: sudo skips those
ME="$(id -un)"
MODE="${MODE:-scoped}"
ACTION="${ACTION:-install}"

if [ "$ACTION" = "revoke" ]; then
  if sudo test -f "$DEST"; then
    sudo rm -f "$DEST"
    echo "removed $DEST"
  else
    echo "$DEST not present"
  fi
  sudo visudo -c >/dev/null && echo "sudoers still valid"
  exit 0
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

if [ "$MODE" = "all" ]; then
  cat > "$TMP" <<EOF
# Installed by rcbg deploy/provision-nopasswd.sh
# Grants $ME unrestricted passwordless root for automated R-CBG deployment.
$ME ALL=(ALL) NOPASSWD: ALL
EOF
else
  # Resolve absolute paths on THIS host: they differ across the fleet
  # (/bin vs /usr/bin) and sudoers requires absolute paths.
  CMDS=()
  ID_PATH=""
  for c in install systemctl useradd journalctl chown cp rm id; do
    p="$(command -v "$c" 2>/dev/null || true)"
    [ -n "$p" ] && CMDS+=("$p")
    [ "$c" = id ] && ID_PATH="$p"
  done
  if [ -z "$ID_PATH" ]; then
    echo "REFUSING: no id(1) on this host, so the grant cannot be verified" >&2
    exit 1
  fi
  # The agent binary is run under sudo for its -check config validation.
  CMDS+=("/usr/local/bin/rcbg-agent")

  JOINED="$(printf '%s, ' "${CMDS[@]}")"
  JOINED="${JOINED%, }"

  cat > "$TMP" <<EOF
# Installed by rcbg deploy/provision-nopasswd.sh
#
# Scoped to the commands deploy/remote-install.sh needs. Note honestly that
# this is NOT a security boundary: passwordless \`install\` can write any file
# anywhere as root, and \`systemctl\` can run any unit. It limits accidental
# damage and makes the grant auditable, nothing more.
#
# Remove with: deploy/provision-nopasswd.sh --revoke <alias>
$ME ALL=(root) NOPASSWD: $JOINED
EOF
fi

# Validate the candidate BEFORE it can affect anything.
if ! sudo visudo -cf "$TMP"; then
  echo "REFUSING: candidate sudoers file failed validation; nothing installed" >&2
  exit 1
fi

# Baseline the EXISTING configuration before adding to it.
#
# `visudo -c` checks every file in /etc/sudoers.d, and some nodes ship with an
# unrelated broken one -- cloud-init's /etc/sudoers.d/ubuntu with the wrong
# mode is common. That makes the check fail for reasons that have nothing to
# do with this script, and a bare pass/fail test then blames our drop-in and
# rolls back a working grant. sudo itself just skips offending files, so the
# node's sudo keeps working and the problem is invisible until now.
BASE_ERR="$(sudo visudo -c 2>&1 | grep -v ': parsed OK$' || true)"
if [ -n "$BASE_ERR" ]; then
  echo "NOTE: this node's sudoers was ALREADY invalid before this script ran:" >&2
  printf '      %s\n' "$BASE_ERR" >&2
  echo "      Not caused by rcbg, and sudo still works (it ignores those files)." >&2
  echo "      Worth fixing separately; proceeding." >&2
fi

sudo install -m 0440 -o root -g root "$TMP" "$DEST"

# Re-validate, comparing against the baseline rather than demanding a clean
# result. The only question that matters is whether WE broke something.
POST_ERR="$(sudo visudo -c 2>&1 | grep -v ': parsed OK$' || true)"
if [ "$POST_ERR" != "$BASE_ERR" ]; then
  echo "sudoers validation CHANGED after installing $DEST; rolling back" >&2
  echo "  before: ${BASE_ERR:-<clean>}" >&2
  echo "  after:  ${POST_ERR:-<clean>}" >&2
  sudo rm -f "$DEST"
  exit 1
fi

# Confirm it actually works. Done in a fresh session (-K drops the cached
# timestamp) so we are testing the new rule, not the password just typed.
#
# The test command must be one the grant actually covers. Testing with `true`
# fails in scoped mode no matter how well the install went, because `true` is
# not on the command list -- sudo is then behaving correctly and the script
# rolls back a perfectly good grant. Use id(1), which is on the list and is
# read-only. In unrestricted mode anything works.
if [ "$MODE" = "all" ]; then
  VERIFY=(true)
else
  VERIFY=("$ID_PATH" -u)
fi
sudo -K
if sudo -n "${VERIFY[@]}" >/dev/null 2>&1; then
  echo "OK: passwordless sudo active for $ME (mode=$MODE)"
  if [ "$MODE" != "all" ]; then
    echo "    commands: $JOINED"
  fi
else
  echo "verification FAILED: 'sudo -n ${VERIFY[*]}' still requires a password." >&2
  echo "  Most likely /etc/sudoers lacks '#includedir /etc/sudoers.d', or a" >&2
  echo "  later drop-in overrides this one. Rolling back." >&2
  # We just dropped our timestamp, so this prompts -- but the operator is at
  # the terminal and a broken grant is worse than one more prompt.
  sudo rm -f "$DEST" || true
  exit 1
fi
