#!/bin/sh
# Build the signed apt + rpm repository tree for get.whichports.com from
# already-signed packages. Runs INSIDE the repo-builder container
# (packaging/repo/Dockerfile); `make repo` wires the mounts and env. POSIX
# sh. The pattern is the repo builder of an earlier project of the author's,
# reviewed and rewritten.
#
# The private key is mounted read-only into this LOCAL, throwaway container
# and imported into an ephemeral keyring that dies with the container. It is
# never written into the output tree and never reaches the server: the server
# only serves the already-signed files this script produces.
#
# Inputs (env):
#   PKG_DIR   dir of signed *.deb and *.rpm (mounted read-only)
#   OUT_DIR   output dir for the repo tree (mounted read-write)
#   KEY_FILE  armored private signing key (mounted read-only)
#   KEY_ID    uid to sign with (hello@whichports.com)
#   KEY_PASS  passphrase (empty allowed for a test key)
#   SUITE (stable), COMPONENT (main), ARCH (amd64), ORIGIN/LABEL (whichports)
set -eu

: "${PKG_DIR:?set PKG_DIR}"
: "${OUT_DIR:?set OUT_DIR}"
: "${KEY_FILE:?set KEY_FILE}"
: "${KEY_ID:?set KEY_ID}"
KEY_PASS="${KEY_PASS:-}"
SUITE="${SUITE:-stable}"
COMPONENT="${COMPONENT:-main}"
ARCH="${ARCH:-amd64}"
ORIGIN="${ORIGIN:-whichports}"
LABEL="${LABEL:-whichports}"

GNUPGHOME=/tmp/gnupg
export GNUPGHOME
rm -rf "$GNUPGHOME"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"
gpg --batch --pinentry-mode loopback --passphrase "$KEY_PASS" --import "$KEY_FILE"

gpg_detach() {
  gpg --batch --yes --pinentry-mode loopback --passphrase "$KEY_PASS" \
      --local-user "$KEY_ID" --detach-sign --armor -o "$2" "$1"
}
gpg_clear() {
  gpg --batch --yes --pinentry-mode loopback --passphrase "$KEY_PASS" \
      --local-user "$KEY_ID" --clearsign -o "$2" "$1"
}

# ---------------------------------------------------------------- rpm ----
# createrepo_c builds repodata/; repomd.xml gets a detached signature so
# dnf's repo_gpgcheck verifies the metadata, and the packages themselves are
# already signed (gpgcheck).
RPMOUT="$OUT_DIR/rpm"
rm -rf "$RPMOUT"
mkdir -p "$RPMOUT"
cp "$PKG_DIR"/*.rpm "$RPMOUT"/
createrepo_c --quiet "$RPMOUT"
gpg_detach "$RPMOUT/repodata/repomd.xml" "$RPMOUT/repodata/repomd.xml.asc"

# ---------------------------------------------------------------- deb ----
# dists/ + pool/ so a "deb URL stable main" line works; Filename paths are
# relative to the deb root under the base URL.
DEBOUT="$OUT_DIR/deb"
rm -rf "$DEBOUT"
POOL="$DEBOUT/pool/$COMPONENT"
BINDIR="$DEBOUT/dists/$SUITE/$COMPONENT/binary-$ARCH"
mkdir -p "$POOL" "$BINDIR"
cp "$PKG_DIR"/*.deb "$POOL"/

cd "$DEBOUT"
dpkg-scanpackages --multiversion pool /dev/null > "$BINDIR/Packages" 2>/dev/null
gzip -9c "$BINDIR/Packages" > "$BINDIR/Packages.gz"
apt-ftparchive \
  -o "APT::FTPArchive::Release::Origin=$ORIGIN" \
  -o "APT::FTPArchive::Release::Label=$LABEL" \
  -o "APT::FTPArchive::Release::Suite=$SUITE" \
  -o "APT::FTPArchive::Release::Codename=$SUITE" \
  -o "APT::FTPArchive::Release::Components=$COMPONENT" \
  -o "APT::FTPArchive::Release::Architectures=$ARCH" \
  release "dists/$SUITE" > "dists/$SUITE/Release"
# InRelease for modern apt, Release.gpg for older.
gpg_clear  "dists/$SUITE/Release" "dists/$SUITE/InRelease"
gpg_detach "dists/$SUITE/Release" "dists/$SUITE/Release.gpg"

# ------------------------------------------------------- top of tree ----
# The public key for operators to import, and the installer; the Caddy site
# rewrites / to /install.sh so `curl -fsSL https://get.whichports.com | sh`
# works.
gpg --armor --export "$KEY_ID" > "$OUT_DIR/whichports-signing-public.asc"
cp /usr/local/share/whichports/install.sh "$OUT_DIR/install.sh"

echo "signed repository tree written to $OUT_DIR"
