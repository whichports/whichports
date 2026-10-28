#!/bin/sh
# Build the release binary from the commit, never from the working tree.
#
#     PKG_VERSION=0.1.10 sh ops/release-build.sh dist/whichports-agent
#
# `make agent` builds from whatever is on disk, which is right for development
# and wrong for a release: the Go toolchain stamps vcs.modified=true into the
# binary whenever `git status --porcelain` prints anything, untracked scratch
# included, and the fleet ended up running a 0.1.8 that no commit describes
# (docs/RECORD.md 4.111). ops/require-reproducible-binary.sh has the reading of
# the toolchain's source behind that.
#
# So the release build checks out HEAD into a fresh, detached git worktree in a
# temporary directory, builds there, copies the binary out, and removes the
# worktree. A fresh worktree holds exactly the tracked files of the commit and
# nothing else, so the toolchain sees a clean status and stamps the commit. The
# result is then read back and refused unless it says so, which is the guard
# and not this script: building in a worktree is how the guard is satisfied,
# reading the binary is how it is enforced.
#
# Nothing here decides the version or the commit. The Makefile passes the
# version it derives from the tag, and the commit is HEAD of the checkout this
# runs in, which require-clean-main.sh has already checked is main and pushed.
set -eu
cd "$(dirname "$0")/.."

OUT="${1:?usage: release-build.sh <output path>}"
VERSION="${PKG_VERSION:?set PKG_VERSION, the Makefile does}"

ROOT="$(git rev-parse --show-toplevel)"
COMMIT="$(git rev-parse HEAD)"
# The agent's directory relative to the repository root, so the same script
# builds a repository where the agent is the root and one where it is agent/.
HERE="$(pwd)"
SUB="${HERE#"$ROOT"}"

WORKTREE="$(mktemp -d "${TMPDIR:-/tmp}/whichports-release.XXXXXX")"
cleanup() {
  git -C "$ROOT" worktree remove --force "$WORKTREE" >/dev/null 2>&1 || true
  rm -rf "$WORKTREE"
}
trap cleanup EXIT INT TERM

git -C "$ROOT" worktree add --detach --quiet "$WORKTREE" "$COMMIT"

mkdir -p "$(dirname "$OUT")"
case "$OUT" in
  /*) ABS_OUT="$OUT" ;;
  *)  ABS_OUT="$HERE/$OUT" ;;
esac
(
  cd "$WORKTREE$SUB"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
    -ldflags "-X main.version=$VERSION" -o "$ABS_OUT" ./cmd/agent
)

sh ops/require-reproducible-binary.sh "$OUT" "$COMMIT"
echo "built $OUT as version $VERSION"
