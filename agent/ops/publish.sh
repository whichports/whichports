#!/bin/sh
# One-command publish for get.whichports.com, run from the Mac:
#
#   git pull && cd agent && bash ops/publish.sh
#
# Versioning is automatic: if the current commit already carries a v* tag it
# republishes that version, otherwise it bumps the patch number, tags, and
# pushes the tag as part of publishing. Tag by hand only to jump a minor or
# major.
#
# The signing passphrase comes from the macOS keychain when stored there, so
# the normal run prompts for nothing. Store it once with:
#
#   security add-generic-password -s whichports-signing -a hello@whichports.com -w
#
# Without a keychain entry the script asks, once per run: the passphrase is
# what keeps a stolen laptop from signing packages the fleet trusts, so it is
# needed at every signing, and the keychain is the thing that remembers it.
#
# The tree it sends also holds selfhost.sh, the self-hosted installer, stamped
# with this release's tag and the commit that tag names in the public
# repository. So the release has to be there first, exported, tagged and
# pushed by hand. ops/require-public-release.sh checks that
# before anything is tagged here, and says the three commands when it is not.
set -eu
cd "$(dirname "$0")/.."

KEY_ID="hello@whichports.com"
# Where the repository tree goes, as an ssh alias and never as an address.
# The alias is an entry in ~/.ssh/config, a Host with its HostName and User,
# for the machine that serves get.whichports.com. WHICHPORTS_HOST names
# another one for a single run. An override that is set and empty falls back
# to the alias, so the rsync below is never handed a destination with no host.
HOST="${WHICHPORTS_HOST:-whichports}"
DEST="$HOST:/srv/get.whichports.com/"
BASE="https://get.whichports.com"
# The owner's clone of the public repository, the one the export's updates go
# into (docs/record 4.400, made new on 28 October as 4.471 says). WHICHPORTS_PUBLIC names another for a single run,
# and one set and empty falls back to it.
PUBLIC="${WHICHPORTS_PUBLIC:-$HOME/whichports-public}"

command -v docker >/dev/null 2>&1 || { echo "docker not found (repo metadata builds in a container)" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "docker daemon not running - start Docker Desktop first" >&2; exit 1; }
command -v nfpm >/dev/null 2>&1 || { echo "nfpm not found: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 not found (it stamps the self-hosted installer)" >&2; exit 1; }

# Publish only a committed state: the tag below points at the current commit, so
# the tree must be on main with no uncommitted changes to tracked files. The
# guard is its own script so it can be tested against real repositories, and so
# it stays out of the way of untracked scratch like a git worktree in a scratch folder,
# which was making a clean publish impossible (docs/RECORD.md, 2026-08-15).
sh ops/require-clean-main.sh

NEW_TAG=no
if TAG="$(git describe --tags --exact-match --match 'v*' 2>/dev/null)"; then
  echo "current commit is already $TAG - republishing that version"
else
  LAST="$(git describe --tags --abbrev=0 --match 'v*' 2>/dev/null || echo v0.0.0)"
  BASEVER="${LAST#v}"
  MAJ="${BASEVER%%.*}"; REST="${BASEVER#*.}"
  MIN="${REST%%.*}"; PATCH="${REST#*.}"
  TAG="v$MAJ.$MIN.$((PATCH + 1))"
  NEW_TAG=yes
fi

# The release must be in the public repository under the same tag, as this
# commit's export, before this commit is tagged: a refusal here leaves no tag
# behind and builds nothing.
echo "* checking the public repository has $TAG"
sh ops/require-public-release.sh "$PUBLIC" "$TAG"

if [ "$NEW_TAG" = yes ]; then
  echo "tagging $TAG (previous was $LAST)"
  git tag "$TAG"
  git push origin "$TAG"
fi
VERSION="${TAG#v}"
echo "publishing version $VERSION"

# Passphrase: keychain first, prompt as the fallback.
PASS="$(security find-generic-password -s whichports-signing -w 2>/dev/null || true)"
if [ -z "$PASS" ]; then
  printf "signing key passphrase (%s): " "$KEY_ID"
  stty -echo
  read -r PASS
  stty echo
  printf "\n"
  echo "tip: store it once so this prompt disappears:"
  echo "  security add-generic-password -s whichports-signing -a $KEY_ID -w"
fi

TMPKEY="$(mktemp)"
trap 'rm -f "$TMPKEY"' EXIT INT TERM
gpg --batch --pinentry-mode loopback --passphrase "$PASS" \
    --armor --export-secret-keys "$KEY_ID" > "$TMPKEY" || {
  echo "key export failed - wrong passphrase?" >&2; exit 1; }

echo "* building signed packages"
SIGNING_KEY_FILE="$TMPKEY" NFPM_PASSPHRASE="$PASS" make package-signed

echo "* building signed repository tree"
SIGNING_KEY_FILE="$TMPKEY" REPO_GPG_PASSPHRASE="$PASS" make repo

# The self-hosted installer, served as $BASE/selfhost.sh: the tag's own
# install.sh, read in the public repository's clone, with the tag and its
# commit there filled in. `make repo` empties the tree first, so it is
# written after it, and the rights below are given to it with the rest.
echo "* stamping the self-hosted installer with $TAG"
python3 ../selfhost/release_installer.py --repository "$PUBLIC" "$TAG" > dist-repo/selfhost.sh

# The web server on the box reads the tree as a user of its own, so every
# folder must be 755 and every file 644, whatever the umask of the terminal
# this runs in. `make repo` makes dist-repo with mkdir, which takes the umask:
# on 13 October a umask of 077 made it 700, `rsync -a` below copied that onto
# /srv/get.whichports.com, and every path answered 403 (docs/RECORD.md 4.456,
# 4.460). Nothing in the tree is run on the box, so no file keeps an x bit.
echo "* giving the tree the rights the site needs"
find dist-repo -type d -exec chmod 755 {} +
find dist-repo -type f -exec chmod 644 {} +

echo "* publishing to $DEST"
rsync -a --delete dist-repo/ "$DEST"

# One request for each path the installer and a reader ask for, and a path
# that fails is named with what its code means here. Caddy's file server
# answers 403 when it may not open a file or a folder (`fs.ErrPermission` in
# caddy's modules/caddyhttp/fileserver/staticfiles.go, read 2026-10-14),
# which is what the folder's rights did on 13 October.
live_check() {
  failed=0
  for path in / /whichports-signing-public.asc /deb/dists/stable/InRelease /rpm/repodata/repomd.xml /selfhost.sh; do
    code="$(curl -sS -o /dev/null -w '%{http_code}' "$BASE$path" 2>/dev/null)" || code=""
    case "$code" in
      200) echo "  ok  $BASE$path" ;;
      403) echo "  403 $BASE$path: the web server may not read it. On the box every folder of the tree must be 755 and every file 644: ls -ld /srv/get.whichports.com" >&2
           failed=1 ;;
      404) echo "  404 $BASE$path: not in the tree that was sent" >&2
           failed=1 ;;
      ""|000) echo "  no answer from $BASE$path" >&2
           failed=1 ;;
      *) echo "  $code $BASE$path" >&2
           failed=1 ;;
    esac
  done
  return "$failed"
}

echo "* verifying the live site"
live_check || { echo "the live site does not serve the tree, see the lines above" >&2; exit 1; }
echo
echo "live: $TAG. Install anywhere with:  curl -fsSL $BASE | sh"
