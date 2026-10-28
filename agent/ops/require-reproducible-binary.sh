#!/bin/sh
# Refuse a release binary that does not name the commit it was built from.
#
#     sh ops/require-reproducible-binary.sh dist/whichports-agent <commit> <version>
#
# The page promises the agent's source is readable, and that promise is what
# carries "install this as root". A binary that says vcs.modified=true was built
# from a tree that differs from every commit, so nobody can check out what the
# fleet runs. docs/RECORD.md 4.111 found the whole fleet on exactly such a
# build, 0.1.8, and 4.63 before it had to trace 0.1.6 by hand.
#
# Why the publish guard did not catch it: require-clean-main.sh deliberately
# ignores untracked files, because rejecting them made a clean publish
# impossible on a machine with scratch worktrees. The Go toolchain does not
# ignore them. Its vcs.modified is `len(git status --porcelain) > 0`
# (cmd/go/internal/vcs/vcs.go, gitStatus, read in go1.27.1), and an untracked
# file is a line of that output. So every build on a machine with any untracked
# file anywhere in the repository was stamped modified, whether or not a tracked
# file had changed. The two guards disagreed about what dirty means and the
# toolchain's meaning is the one the binary carries.
#
# This script does not decide what dirty means at all. It reads what the
# toolchain wrote into the binary and refuses unless both fields say the
# binary is the commit: vcs.modified=false and vcs.revision is the commit asked
# for. ops/release-build.sh is what makes those true, by building from a fresh
# worktree of the commit where no untracked file can exist.
#
# The injected package version is deliberately not checked here, because it
# cannot be read back: with -trimpath the toolchain records no -ldflags in the
# build information at all (cmd/go/internal/load/pkg.go, "only include ldflags
# if -trimpath is not set", go.dev/issue/52372, read in go1.27.1). The Makefile
# hands one PKG_VERSION to both the build and nfpm, so the binary and the
# package agree by construction, and `whichports-agent --version` on a host is
# where the value is read.
#
# It also refuses a binary built with a build tag. Until 2026-10-12 the
# package reader and the apt lists reader stood behind one and this script
# refused a binary that held either (docs/RECORD.md 4.369 and 4.385). Every
# release holds both since the security data check shipped, so those two
# refusals are gone and the one of a tag stays: no build command passes one.
set -eu

BINARY="${1:?usage: require-reproducible-binary.sh <binary> <commit>}"
COMMIT="${2:?usage: require-reproducible-binary.sh <binary> <commit>}"

[ -f "$BINARY" ] || { echo "no binary at $BINARY" >&2; exit 1; }

# `go version -m` reads the build information the toolchain embedded, the same
# bytes `whichports-agent --version` prints on the box.
INFO="$(go version -m "$BINARY")" || { echo "go version -m could not read $BINARY" >&2; exit 1; }

field() {
  printf '%s\n' "$INFO" | awk -v key="$1" '$1 == "build" && index($2, key "=") == 1 { sub(key "=", "", $2); print $2; exit }'
}

fail=0
modified="$(field vcs.modified)"
revision="$(field vcs.revision)"

if [ "$modified" != "false" ]; then
  echo "REFUSED: the binary says vcs.modified=${modified:-unset}. It was built from a tree" >&2
  echo "that differs from every commit, so nobody can check out what it runs." >&2
  echo "Build with ops/release-build.sh, which builds from a fresh worktree of the commit." >&2
  fail=1
fi
if [ "$revision" != "$COMMIT" ]; then
  echo "REFUSED: the binary says vcs.revision=${revision:-unset} and the release is $COMMIT." >&2
  fail=1
fi

# A release is built with no build tag. The toolchain records the tags a
# binary was built with, also under -trimpath: `go version -m` printed a
# `build -tags=` line for such a build (go1.27.1, 2026-10-06). So a tagged
# binary is refused by reading it.
tags="$(field -tags)"
if [ -n "$tags" ]; then
  echo "REFUSED: the binary says -tags=$tags. A release is built with no build tag." >&2
  fail=1
fi

if [ "$fail" != "0" ]; then
  exit 1
fi
echo "the binary is commit $COMMIT, vcs.modified=false"
