#!/bin/sh
# Guard for publish.sh: the release it is about to publish must already be in
# the public repository, under the same tag, as the export of this commit.
# It lives in its own script, like require-clean-main.sh, so it can be tested
# on its own against real repositories (require_public_release_test.go).
#
#   sh ops/require-public-release.sh <the public repository's clone> <tag>
#
# Why. publish.sh puts selfhost.sh on get.whichports.com: selfhost/install.sh
# with a release tag and that tag's commit filled in by
# selfhost/release_installer.py. On a server the installer clones the public
# repository and builds nothing unless the tag there names that very commit.
# The public repository has a history of its own, one commit per update made
# by export/export.py, so the commit has to be read from the public
# repository and never from this one. A copy stamped from here would stop on
# every server that ran it.
#
# The public repository is updated by hand, with export/export.py --into and a
# push, after a look at what goes (export/README.md). This guard only reads:
# it never commits, tags or pushes. publish.sh runs it before it tags
# anything here, so a refusal leaves every repository as it was.
set -eu

public="$1"
tag="$2"

refuse() {
  for line in "$@"; do
    echo "$line" >&2
  done
  exit 1
}

if ! top="$(git -C "$public" rev-parse --show-toplevel 2>/dev/null)"; then
  refuse "no clone of the public repository at $public." \
         "WHICHPORTS_PUBLIC names the folder that holds it."
fi
if [ "$top" = "$(git rev-parse --show-toplevel)" ]; then
  refuse "$public is this repository, and not a clone of the public one." \
         "WHICHPORTS_PUBLIC names the folder that holds the public one."
fi

# The commit the tag names in the clone. ^{commit} reads through an annotated
# tag to its commit, as the installer does.
if ! commit="$(git -C "$public" rev-parse --verify --quiet "refs/tags/$tag^{commit}")"; then
  refuse "the public repository's clone at $public has no tag $tag." \
         "Make the release there first, from this repository's root:" \
         "  python3 export/export.py --into $public --subject \"whichports $tag\"" \
         "  git -C $public tag $tag" \
         "  git -C $public push origin main $tag" \
         "export/README.md says what to read before the push."
fi

# The commit the tag names in the public repository itself, which is where
# the installer clones from. ls-remote lists an annotated tag twice, the tag
# object and, with ^{} after the name, the commit it names, so that line is
# taken when it is there. Not being able to look is not the same as having
# looked, so a failed read refuses.
if ! lines="$(git -C "$public" ls-remote origin "refs/tags/$tag" "refs/tags/$tag^{}" 2>/dev/null)"; then
  refuse "could not read the public repository's tags from the clone at $public."
fi
remote="$(printf '%s\n' "$lines" | awk -v plain="refs/tags/$tag" -v peeled="refs/tags/$tag^{}" '
  $2 == peeled { named = $1 }
  $2 == plain && light == "" { light = $1 }
  END { if (named != "") print named; else print light }')"
if [ -z "$remote" ]; then
  refuse "$tag is in the clone at $public and not in the public repository." \
         "Send it there: git -C $public push origin main $tag"
fi
if [ "$remote" != "$commit" ]; then
  refuse "$tag names commit $commit in the clone at $public, and $remote in the public repository." \
         "The installer clones the public repository's, so the two must agree."
fi

# The release there is this commit's: the agent the packages hold, the
# installer and the stack's files, and the control plane the stack runs. The
# export copies these three folders file for file, so git names each with
# the same id on both sides when nothing in it differs.
for path in agent selfhost controlplane/app; do
  ours="$(git rev-parse --verify --quiet "HEAD:$path")" || ours=""
  theirs="$(git -C "$public" rev-parse --verify --quiet "$commit:$path")" || theirs=""
  if [ -z "$ours" ] || [ "$ours" != "$theirs" ]; then
    refuse "at $tag the public repository's $path/ is not this commit's." \
           "The release there is the export of another commit."
  fi
done

echo "  the public repository has $tag at $commit, with this commit's agent/, selfhost/ and controlplane/app/"
