#!/bin/sh
# Guard for publish.sh. It refuses to publish unless we are on main with no
# uncommitted changes to *tracked* files. It lives in its own script, rather
# than inline in publish.sh, so it can be tested on its own against real
# repositories in each state that matters (require_clean_main_test.go).
#
# Why it checks tracked files only, and not a pristine tree:
#
# publish.sh tags the current commit and then builds and ships packages from the
# working tree. The failure that must be caught is an uncommitted change to a
# tracked file, because that change goes into the built package but is not in the
# commit the tag points at, so the release and its tag would disagree.
#
# An untracked file changes neither the current commit nor any tracked source, so
# it cannot cause that disagreement. In this repo the common untracked things are
# a git worktree in a scratch folder, build scratch, an editor swap file, a
# stray .log. The earlier check rejected all of those, which made a clean publish
# effectively impossible and pushed the operator toward committing straight to
# main just to silence it (docs/RECORD.md, 2026-08-15). --untracked-files=no
# reports staged and unstaged changes to tracked files and stays silent about
# untracked ones, which is exactly the line we want.
#
# The narrow residual: a brand new untracked source file dropped into a package
# the build compiles would be built in without being committed. That needs a
# tracked file to reference it to matter, and referencing it edits a tracked
# file, which this catches. It is a far smaller hazard than the pristine check,
# which caused real damage by being unusable.
set -eu

branch="$(git rev-parse --abbrev-ref HEAD)"
if [ "$branch" != "main" ]; then
  echo "on branch $branch - publish from main" >&2
  exit 1
fi

# --untracked-files=no: only staged and unstaged changes to tracked files, never
# untracked scratch. The offending paths are printed so the operator sees exactly
# what to commit or stash, not a bare "not clean".
dirty="$(git status --porcelain --untracked-files=no)"
if [ -n "$dirty" ]; then
  echo "tracked files have uncommitted changes - commit or stash before publishing:" >&2
  echo "$dirty" >&2
  exit 1
fi

# The commit has to be one origin already has.
#
# publish.sh tags the current commit and pushes the tag. If local main carries
# commits origin/main does not, that tag lands on a commit nobody else can
# fetch. docs/RECORD.md 4.49 recorded exactly that happening, two local-only
# commits and a phantom v0.1.6 tag pushed to origin pointing at an orphan, and
# 4.57 recorded the consequence still live: a 0.1.6 package at
# get.whichports.com that no tag and no commit on main accounts for, on a
# product whose page promises the source is readable.
#
# The check above passed the whole time. It read the branch name and the
# working tree, which are both about this machine, and never asked whether
# anybody else could see what was about to be tagged.
#
# Fetch first rather than trusting a stale remote-tracking ref, because the
# thing being guarded against is precisely a local view that has drifted. A
# fetch failure refuses rather than proceeding: no network is not evidence of
# agreement.
if ! git remote get-url origin >/dev/null 2>&1; then
  echo "no origin remote, so there is nothing to check this commit against." >&2
  echo "publish.sh pushes a tag, and a tag on a commit origin does not have is" >&2
  echo "unreachable for everybody else (docs/RECORD.md 4.57)." >&2
  exit 1
fi

if ! git fetch --quiet origin main 2>/dev/null; then
  echo "could not fetch origin/main, so this commit cannot be checked against it." >&2
  echo "not being able to look is not the same as having looked." >&2
  exit 1
fi

ahead="$(git rev-list --count origin/main..HEAD)"
behind="$(git rev-list --count HEAD..origin/main)"
if [ "$ahead" != "0" ] || [ "$behind" != "0" ]; then
  echo "main here and origin/main disagree: $ahead commit(s) ahead, $behind behind." >&2
  if [ "$ahead" != "0" ]; then
    echo "" >&2
    echo "publish.sh would tag a commit origin does not have, and that tag would" >&2
    echo "point at nothing anybody else can fetch. That is how the 0.1.6 now live" >&2
    echo "at get.whichports.com came to have no commit behind it (RECORD 4.57)." >&2
    echo "" >&2
    echo "Push first, or reset to origin/main if the local commits were a mistake:" >&2
    git --no-pager log --oneline origin/main..HEAD >&2
  fi
  if [ "$behind" != "0" ]; then
    echo "" >&2
    echo "Pull first. Publishing from behind ships an older tree as a newer version." >&2
  fi
  exit 1
fi
