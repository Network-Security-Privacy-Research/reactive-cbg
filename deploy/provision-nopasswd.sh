#!/usr/bin/env bash
# Provision passwordless sudo across the fleet so the R-CBG rollout can run
# unattended. One interactive password per node, once.
#
# Read this before running it:
#
#   Anything that can automate this deploy is equivalent to root. A
#   command-scoped sudoers entry still includes `install`, which writes any
#   file anywhere as root, and `systemctl`, which runs any unit. Scoping
#   reduces ACCIDENTAL damage and makes the grant auditable; it is not a
#   security boundary. Choose --all if you would rather be honest about that.
#
# Safety: the sudoers drop-in is validated with `visudo -cf` before it is
# installed, `visudo -c` re-checks afterwards, and the grant is verified with a
# cleared sudo timestamp -- rolling back on any failure. A malformed sudoers
# file breaks sudo entirely on that host, so this path is deliberately paranoid.
#
# Usage:
#   deploy/provision-nopasswd.sh mynode                # one node (do this first)
#   deploy/provision-nopasswd.sh --all-nodes          # every node in nodes.txt
#   deploy/provision-nopasswd.sh --mode all mynode     # unrestricted NOPASSWD
#   deploy/provision-nopasswd.sh --revoke mynode       # remove the grant
#   deploy/provision-nopasswd.sh --check              # report current state
#
# Each node needs an interactive sudo password, so this requires a real
# terminal. Nodes are done one at a time, never in parallel.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODES="$REPO/deploy/nodes.txt"
HELPER="$REPO/deploy/remote-provision-nopasswd.sh"

MODE=scoped
ACTION=install
ALL_NODES=0
CHECK_ONLY=0
targets=()

while [ $# -gt 0 ]; do
  case "$1" in
    --mode)      MODE="${2:-scoped}"; shift 2 ;;
    --revoke)    ACTION=revoke; shift ;;
    --all-nodes) ALL_NODES=1; shift ;;
    --check)     CHECK_ONLY=1; shift ;;
    -h|--help)   sed -n '2,30p' "$0"; exit 0 ;;
    -*)          echo "unknown flag: $1" >&2; exit 2 ;;
    *)           targets+=("$1"); shift ;;
  esac
done

case "$MODE" in scoped|all) ;; *) echo "--mode must be scoped or all" >&2; exit 2 ;; esac

if [ "$ALL_NODES" = "1" ]; then
  mapfile -t targets < <(grep -v '^\s*#' "$NODES" | awk 'NF{print $1}')
fi
if [ ${#targets[@]} -eq 0 ]; then
  echo "no nodes given; pass aliases or --all-nodes" >&2
  exit 2
fi

# --check needs no privilege and no terminal.
if [ "$CHECK_ONLY" = "1" ]; then
  printf '%-18s %s\n' NODE STATE
  for a in "${targets[@]}"; do
    s=$(ssh -o BatchMode=yes -o ConnectTimeout=8 "$a" \
        'sudo -n id -u >/dev/null 2>&1 && echo passwordless || echo "password-required"' 2>/dev/null \
        || echo unreachable)
    printf '%-18s %s\n' "$a" "$s"
  done
  exit 0
fi

if { [ ! -t 0 ] || [ ! -t 1 ]; }; then
  echo "error: this needs a real terminal -- each node prompts for its sudo" >&2
  echo "password once. Agent harnesses and CI runners rarely give you a TTY." >&2
  exit 1
fi

echo "action=$ACTION mode=$MODE nodes=${#targets[@]}"
if [ "$ACTION" = "install" ] && [ "$MODE" = "all" ]; then
  echo
  echo "WARNING: --mode all grants unrestricted passwordless root to your login"
  echo "         user on ${#targets[@]} host(s)."
fi
echo
read -r -p "Continue? [y/N] " reply
case "$reply" in y|Y|yes|YES) ;; *) echo "aborted"; exit 1 ;; esac

ok=(); failed=()
for a in "${targets[@]}"; do
  echo
  echo "======== $a ========"
  if ! ssh -o BatchMode=yes -o ConnectTimeout=10 "$a" true 2>/dev/null; then
    echo "unreachable, skipping"
    failed+=("$a")
    continue
  fi
  ssh -o BatchMode=yes "$a" 'mkdir -p ~/.rcbg-stage'
  scp -q "$HELPER" "$a:~/.rcbg-stage/provision.sh"
  # Staged file, not a stdin heredoc: a heredoc occupies ssh's stdin and stops
  # it allocating the TTY that sudo needs to prompt.
  if ssh -t "$a" "MODE=$MODE ACTION=$ACTION bash ~/.rcbg-stage/provision.sh"; then
    ok+=("$a")
  else
    echo "FAILED on $a"
    failed+=("$a")
  fi
  ssh -o BatchMode=yes "$a" 'rm -f ~/.rcbg-stage/provision.sh' 2>/dev/null
done

echo
echo "======== summary ========"
echo "ok      (${#ok[@]}): ${ok[*]:-none}"
echo "failed  (${#failed[@]}): ${failed[*]:-none}"
echo
echo "Verify with: deploy/provision-nopasswd.sh --check --all-nodes"
if [ "$ACTION" = "install" ] && [ ${#ok[@]} -gt 0 ]; then
  echo "Then roll out unattended with:"
  echo "  RCBG_NO_TTY_OK=1 deploy/deploy-node.sh <alias>"
fi
