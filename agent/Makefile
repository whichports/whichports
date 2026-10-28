# Build and packaging for the agent. The Go toolchain is the only hard
# requirement; nfpm (a single Go binary) arrives via go install when packaging.
#
# Version comes from the latest v* git tag, the leading v stripped, falling
# back to 0.0.0-dev for untagged development builds.
PKG_VERSION ?= $(shell git describe --tags --abbrev=0 --match 'v*' 2>/dev/null | sed 's/^v//' || true)
ifeq ($(strip $(PKG_VERSION)),)
PKG_VERSION := 0.0.0-dev
endif

.PHONY: agent release-agent package package-signed clean

## agent: the static Linux binary the page promises, into dist/.
## The -X injects the same PKG_VERSION nfpm stamps on the packages, so
## `whichports-agent --version` and the package manager always name one
## version. The commit, time and clean state come from the toolchain's own
## vcs stamping, nothing to inject for those.
agent:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-X main.version=$(PKG_VERSION)" -o dist/whichports-agent ./cmd/agent

## release-agent: the same binary, built from the commit rather than from the
## working tree, and refused unless it says so. The toolchain stamps
## vcs.modified=true whenever `git status --porcelain` prints anything, untracked
## scratch included, which is how the fleet came to run a 0.1.8 no commit
## describes (docs/RECORD.md 4.111). ops/release-build.sh builds in a fresh
## worktree of HEAD and ops/require-reproducible-binary.sh reads the result back.
release-agent:
	PKG_VERSION=$(PKG_VERSION) sh ops/release-build.sh dist/whichports-agent

## package: UNSIGNED .deb + .rpm for development and hands-on testing.
package: agent
	@command -v nfpm >/dev/null 2>&1 || { echo 'nfpm not found: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest (then add $$(go env GOPATH)/bin to PATH)'; exit 1; }
	PKG_VERSION=$(PKG_VERSION) nfpm package --config packaging/nfpm.yaml --packager deb --target dist/
	PKG_VERSION=$(PKG_VERSION) nfpm package --config packaging/nfpm.yaml --packager rpm --target dist/
	@echo "built packages (version $(PKG_VERSION)) into dist/:"
	@ls -1 dist/*.deb dist/*.rpm

## package-signed: GPG-signed release packages. The private key lives only on
## the signer's machine and in the password manager, never in this repo and
## never on any server (packaging/signing/README.md):
##   SIGNING_KEY_FILE=/path/to/private.asc NFPM_PASSPHRASE=... make package-signed
package-signed: release-agent
	@command -v nfpm >/dev/null 2>&1 || { echo 'nfpm not found: go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest'; exit 1; }
	@[ -n "$$SIGNING_KEY_FILE" ] || { echo 'set SIGNING_KEY_FILE (see packaging/signing/README.md)'; exit 1; }
	@[ -f "$$SIGNING_KEY_FILE" ] || { echo "SIGNING_KEY_FILE not found: $$SIGNING_KEY_FILE"; exit 1; }
	SIGNING_KEY_FILE="$$SIGNING_KEY_FILE" PKG_VERSION=$(PKG_VERSION) nfpm package --config packaging/nfpm.yaml --packager deb --target dist/
	SIGNING_KEY_FILE="$$SIGNING_KEY_FILE" PKG_VERSION=$(PKG_VERSION) nfpm package --config packaging/nfpm.yaml --packager rpm --target dist/
	@echo "built SIGNED packages (version $(PKG_VERSION)) into dist/:"
	@ls -1 dist/*.deb dist/*.rpm

clean:
	rm -rf dist

REPO_OUT ?= dist-repo
REPO_KEY_ID ?= hello@whichports.com
# Where the signed packages come from. dist/ is where package-signed writes, so
# a release publish never sets this. The clean-box install test (ops/cleanbox)
# points it at a throwaway directory of fixture packages, which is how it builds
# a real signed repository without disturbing dist/.
REPO_PKG_DIR ?= dist

## repo: build the SIGNED apt + dnf repository tree into dist-repo/ from the
## signed packages in dist/ (run `make package-signed` first). Metadata is
## generated and signed inside a throwaway container; publish per
## packaging/repo/README.md.
.PHONY: repo
repo:
	@command -v docker >/dev/null 2>&1 || { echo 'docker not found (the repo builder runs in a container)'; exit 1; }
	@[ -n "$$SIGNING_KEY_FILE" ] || { echo 'set SIGNING_KEY_FILE (see packaging/signing/README.md)'; exit 1; }
	@[ -f "$$SIGNING_KEY_FILE" ] || { echo "SIGNING_KEY_FILE not found: $$SIGNING_KEY_FILE"; exit 1; }
	@ls $(REPO_PKG_DIR)/*.deb $(REPO_PKG_DIR)/*.rpm >/dev/null 2>&1 || { echo 'no packages in $(REPO_PKG_DIR)/ - run: make package-signed'; exit 1; }
	docker build -q -t whichports-repo-builder -f packaging/repo/Dockerfile packaging >/dev/null
	rm -rf $(REPO_OUT) && mkdir -p $(REPO_OUT)
	docker run --rm \
	  -e PKG_DIR=/pkg -e OUT_DIR=/out -e KEY_FILE=/key.asc \
	  -e KEY_ID="$(REPO_KEY_ID)" -e KEY_PASS="$$REPO_GPG_PASSPHRASE" \
	  -v "$(abspath $(REPO_PKG_DIR))":/pkg:ro \
	  -v "$(abspath $(REPO_OUT))":/out \
	  -v "$$SIGNING_KEY_FILE":/key.asc:ro \
	  whichports-repo-builder
	@echo "repo tree in $(REPO_OUT)/ - publish per packaging/repo/README.md"
