# The hosted repository, get.whichports.com

The signed apt and dnf repository the installer at the site root configures.
Decision and DNS by the owner, 2026-08-13. The build runs locally in a throwaway
container; the server only ever serves already-signed files.

## Publishing (the owner, from the Mac)

One command does it, version bump and tag included, once the release is in
the public repository (below):

```sh
git pull && cd agent && bash ops/publish.sh
```

The script republishes the current tag if the commit carries one, otherwise
bumps the patch version, tags and pushes. The signing passphrase comes from
the macOS keychain (store once:
`security add-generic-password -s whichports-signing -a hello@whichports.com -w`);
without the keychain entry it prompts. The make targets underneath
(`package-signed`, `repo`) still work standalone for debugging, key handling
in ../signing/README.md. The tree lands in `/srv/get.whichports.com` on the
prod box, owned by deploy, served read-only.

The tree also holds `selfhost.sh`, the self-hosted installer that
`selfhost/README.md` gives as its one line. It is `selfhost/install.sh` with
the release's tag and the commit that tag names in the public repository
filled in by `selfhost/release_installer.py`, because on a server it clones
the public repository and builds that commit and nothing else. So the release
is in the public repository first: this commit exported into the owner's
clone of it, tagged with the same version, and pushed. Before anything is
tagged, `ops/require-public-release.sh` checks the clone and the public
repository agree on the tag and hold this commit's `agent/`, `selfhost/` and
`controlplane/app/`, and when they do not it says the commands that make the
release. The clone is `~/whichports-public`, or the folder
`WHICHPORTS_PUBLIC` names.

## Serving it (Caddy on the prod box, one-time)

Add to the Caddyfile and reload. DNS: point get.whichports.com at the box as
DNS-only (grey cloud), so Caddy issues its own certificate, the same way the
rest of the box works.

```
get.whichports.com {
	root * /srv/get.whichports.com
	rewrite / /install.sh
	header /install.sh Content-Type text/plain
	file_server
}
```

After the first publish, verify from any machine:

```sh
curl -fsSL https://get.whichports.com | head -5
curl -fsSL https://get.whichports.com/whichports-signing-public.asc | gpg --show-keys
```

## What an operator ends up running

```sh
curl -fsSL https://get.whichports.com | sh
systemctl enable --now whichports-agent.timer
```

apt verifies the InRelease signature against the signed-by key, dnf verifies
both packages (gpgcheck) and metadata (repo_gpgcheck). A tampered mirror or a
truncated download fails their checks, not ours.
