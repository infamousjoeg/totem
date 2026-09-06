#!/usr/bin/env bash
#
# verify.sh - run the full verification in an ISOLATED COPY of the working
# tree, never in the working tree itself.
#
# WHY THIS EXISTS. Several agents share one working directory, so a full-tree
# run there compiles whatever anyone has half-written on disk at that moment. A
# green result from the shared tree is a statement about the directory at that
# instant rather than about my code, and a red one is a coin flip between my bug
# and someone else's half-saved file. Both directions are worthless, and the red
# direction has already cost several people real time chasing failures that were
# never in the code.
#
# It matters most for MUTATION TESTING, which is deliberately writing
# known-broken code and then removing it, over and over. That is the single
# worst thing to do in a shared tree: every cycle is a window in which somebody
# else's verification compiles a defect that was planted on purpose and is about
# to be removed. Run mutations against a copy made by this script.
#
# It copies the WORKING TREE rather than cloning HEAD, deliberately.
# Uncommitted changes are the thing under test, so a clone of HEAD would verify
# bytes nobody is asking about and report green about the wrong thing.
#
# Usage:
#   scripts/verify.sh                      # everything
#   scripts/verify.sh ./internal/server/   # one package, same checks
#
# Environment:
#   TOTEM_VERIFY_DIR   where to put the copy (default: a fresh mktemp -d)
#   TOTEM_VERIFY_KEEP  set to 1 to keep the copy even when everything passes
#
# The copy is kept on failure so the failing state can be inspected, and its
# path is printed.

set -euo pipefail

repo_root() {
	local here
	here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
	printf '%s' "$here"
}

SRC="$(repo_root)"
DST="${TOTEM_VERIFY_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/totem-verify.XXXXXX")}"

# A scratch verifier that leaks into the shared tree is worse than none: it
# would compile deliberate defects in the one place this exists to protect. So
# refuse rather than trusting the caller to have passed a sane directory.
case "$DST" in
"$SRC" | "$SRC"/*)
	echo "verify.sh: refusing to verify into $DST, which is inside the working tree at $SRC." >&2
	echo "  The whole point is that the copy is somewhere the shared tree cannot see." >&2
	exit 2
	;;
esac

command -v rsync >/dev/null 2>&1 || {
	echo "verify.sh: rsync is required to copy the working tree." >&2
	exit 2
}

cleanup() {
	local status=$?
	if [ "$status" -eq 0 ] && [ "${TOTEM_VERIFY_KEEP:-0}" != "1" ]; then
		rm -rf "$DST"
	else
		echo "verify.sh: the copy is at $DST" >&2
	fi
	return "$status"
}
trap cleanup EXIT

mkdir -p "$DST"
# --delete makes the copy an exact MIRROR, which matters whenever $DST is
# reused. Without it rsync merges, so a file deleted in the working tree
# survives in the copy and a file planted in the copy is silently overwritten
# by the pristine one. Either way the run verifies bytes that are not the ones
# under test and reports green about the wrong thing, which is the exact failure
# this script exists to prevent, produced by the script.
#
# .git is excluded because nothing here reads history and copying it is slow.
rsync -a --delete --exclude '.git' "$SRC/" "$DST/"

cd "$DST"
echo "=== verifying an isolated copy of $SRC at $DST ==="

if [ -n "$(gofmt -l .)" ]; then
	echo "FAIL: gofmt" >&2
	gofmt -l . >&2
	exit 1
fi
go build ./...
go vet ./...
GOOS=linux go vet ./...
go test -race -count=1 "${@:-./...}"

echo "=== verified ==="
