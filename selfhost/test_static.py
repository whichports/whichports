"""The rules of the Compose files, checked without Docker on every gate run.

The full up, answer and down is selfhost/smoke.py, which needs Docker and the
network and runs before every commit that touches this directory, a
Dockerfile, a Compose file, uv.lock or the worker (decided 2026-10-01,
docs/record 4.226). This half is what a laptop with Docker stopped can still
prove.

These read the files as text, line by line, because the gate's interpreter
has no YAML parser, and a dependency is not added for one test.
`docker compose config` is the parser, and smoke.py runs it.
"""
import ast
import re
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
COMPOSE_FILES = sorted(HERE.rglob("compose*.yaml"))
DOCKERFILES = sorted(p for p in HERE.rglob("Dockerfile*")
                     if not p.name.endswith(".dockerignore"))
PRODUCT_COMPOSE = HERE / "compose.yaml"
ENV_EXAMPLE = HERE / "env.example"
DOCKERFILE = HERE / "Dockerfile"

# Images the stack builds itself carry this tag and no digest.
LOCAL_TAG = ":local"


def code_lines(path: Path):
    """Each line with its comment removed. A `#` inside a quoted string is
    not a comment, and no line in these files has one, which is asserted."""
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.split(" #", 1)[0] if not raw.lstrip().startswith("#") else ""
        yield number, line.rstrip()


def test_the_files_exist():
    assert PRODUCT_COMPOSE in COMPOSE_FILES
    assert DOCKERFILE in DOCKERFILES
    assert ENV_EXAMPLE.is_file()


# ---------------------------------------------------------- base images

FROM_RE = re.compile(r"^FROM\s+(\S+)", re.IGNORECASE)
COPY_FROM_RE = re.compile(r"--from=(\S+)")
PINNED_RE = re.compile(r"^[a-z0-9./-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$")


def base_images(path: Path):
    stages = set()
    for number, line in code_lines(path):
        match = FROM_RE.match(line.strip())
        if match:
            image = match.group(1)
            if image not in stages:
                yield number, image
            alias = re.search(r"\bAS\s+(\S+)", line, re.IGNORECASE)
            if alias:
                stages.add(alias.group(1))
        for image in COPY_FROM_RE.findall(line):
            if image not in stages:
                yield number, image


@pytest.mark.parametrize("dockerfile", DOCKERFILES, ids=lambda p: str(p.relative_to(HERE)))
def test_every_base_image_is_a_version_pinned_by_digest(dockerfile):
    """A tag can move under us and a digest cannot. The version stays beside
    it so a person can read what it is."""
    found = list(base_images(dockerfile))
    assert found, f"{dockerfile} names no base image"
    for number, image in found:
        if image.endswith(LOCAL_TAG):
            # Built by this repository's own Dockerfile, whose bases are
            # held to the same rule.
            continue
        assert PINNED_RE.match(image), \
            f"{dockerfile.name}:{number}: {image} is not name:version@sha256:digest"


@pytest.mark.parametrize("compose", COMPOSE_FILES, ids=lambda p: str(p.relative_to(HERE)))
def test_every_pulled_image_is_pinned_by_digest(compose):
    for number, line in code_lines(compose):
        match = re.match(r"^\s*image:\s*(\S+)", line)
        if not match:
            continue
        image = match.group(1)
        if image.endswith(LOCAL_TAG):
            continue
        assert PINNED_RE.match(image), \
            f"{compose.name}:{number}: {image} is pulled and not pinned"


def test_every_base_image_is_justified_in_the_readme():
    """Every dependency gets a paragraph saying why it is worth having, and
    a base image is a dependency."""
    readme = (HERE / "README.md").read_text()
    names = set()
    for dockerfile in DOCKERFILES:
        for _number, image in base_images(dockerfile):
            if image.endswith(LOCAL_TAG):
                continue
            names.add(image.split("@")[0].rsplit(":", 1)[0].split("/")[-1])
    for name in sorted(names):
        assert f"`{name}`" in readme, \
            f"selfhost/README.md does not justify the base image {name}"


# ------------------------------------------------------- the docker socket

@pytest.mark.parametrize("path", COMPOSE_FILES + DOCKERFILES,
                         ids=lambda p: str(p.relative_to(HERE)))
def test_no_container_is_given_the_docker_socket(path):
    """Whoever holds the socket is root on the machine (docs/RECORD.md 4.222)."""
    text = path.read_text()
    assert "docker.sock" not in text
    assert "/var/run/docker" not in text
    assert "/run/docker" not in text


# ------------------------------------------------------------ the ingest

def ports_entries(path: Path):
    """Every item of every `ports:` list, as text, with its line number."""
    lines = list(code_lines(path))
    for index, (number, line) in enumerate(lines):
        match = re.match(r"^(\s*)ports:\s*(.*)$", line)
        if not match:
            continue
        indent, inline = len(match.group(1)), match.group(2).strip()
        if inline:
            yield number, inline
            continue
        for later_number, later in lines[index + 1:]:
            if not later.strip():
                continue
            if len(later) - len(later.lstrip()) <= indent:
                break
            yield later_number, later.strip().lstrip("-").strip()


@pytest.mark.parametrize("compose", COMPOSE_FILES, ids=lambda p: str(p.relative_to(HERE)))
def test_8410_is_never_published(compose):
    for number, entry in ports_entries(compose):
        assert "8410" not in entry, \
            f"{compose.name}:{number} publishes the ingest's own port"


def test_the_controlplane_runs_the_ingest_unit_itself():
    """Its command is the unit's ExecStart, so the bind and
    --no-proxy-headers come from the file prod installs."""
    text = PRODUCT_COMPOSE.read_text()
    assert '"selfhost/worker.py", "exec", "whichports-ingest.service"' in text


def test_the_product_publishes_no_port_at_all():
    """Nothing goes through Docker's port publishing, which would put it
    past the machine's own firewall rules."""
    assert list(ports_entries(PRODUCT_COMPOSE)) == []
    for _number, line in code_lines(PRODUCT_COMPOSE):
        assert not re.match(r"^\s*(ports|expose):", line)


def test_only_the_control_plane_and_caddy_are_on_the_machines_network():
    """They need each other on loopback, the shape the proof rule checks
    (controlplane/app/ingest.py). The worker needs nothing of the kind and
    stays on the default bridge with nothing published."""
    text = PRODUCT_COMPOSE.read_text()
    assert "network_mode: host" in service_block(text, "controlplane")
    assert "network_mode: host" in service_block(text, "caddy")
    assert "network_mode" not in service_block(text, "worker")
    assert text.count("network_mode:") == 2
    assert "network_mode: service:" not in text


def test_caddy_is_optional_and_on_in_the_example():
    caddy = service_block(PRODUCT_COMPOSE.read_text(), "caddy")
    assert 'profiles: ["caddy"]' in caddy
    assert "COMPOSE_PROFILES=caddy" in ENV_EXAMPLE.read_text().splitlines()


def test_the_two_ports_are_settable_and_default_to_the_boxs():
    text = PRODUCT_COMPOSE.read_text()
    for name, default in (("WHICHPORTS_HTTPS_PORT", "443"),
                          ("WHICHPORTS_INGEST_PORT", "8410")):
        assert f"${{{name}:-{default}}}" in text
        assert f"{name}={default}" in ENV_EXAMPLE.read_text().splitlines()
    caddyfile = (HERE / "Caddyfile").read_text()
    assert "https_port {$WHICHPORTS_HTTPS_PORT:443}" in caddyfile
    assert caddyfile.count(
        "reverse_proxy 127.0.0.1:{$WHICHPORTS_INGEST_PORT:8410}") == 2
    assert "reverse_proxy" not in caddyfile.replace(
        "reverse_proxy 127.0.0.1:{$WHICHPORTS_INGEST_PORT:8410}", "")


def test_443_is_said_to_be_required_and_a_proxy_that_ends_tls_is_out_of_the_one_line():
    """TLS-ALPN-01 "is performed via TLS on port 443" (Let's Encrypt's page
    on challenge types, read 2026-10-20), so a Caddy moved off 443 gets no
    certificate unless 443 is forwarded to it unchanged."""
    example = ENV_EXAMPLE.read_text()
    assert example.splitlines().count("WHICHPORTS_HTTPS_PORT=443") == 1
    flat = " ".join(example.replace("#", " ").split())
    assert "Caddy must have port 443 from the internet" in flat
    assert "letsencrypt.org/docs/challenge-types" in flat
    readme = " ".join((HERE / "README.md").read_text().split())
    assert "Caddy must have port 443 from the internet" in readme
    assert ("A server behind a proxy or load balancer that ends TLS is not for the"
            " one-line install: install by hand, with Your own proxy.") in readme
    caddyfile = (HERE / "Caddyfile").read_text()
    assert "letsencrypt.org/docs/challenge-types" in caddyfile


UBUNTU_PACKAGES = "docker.io docker-compose-v2 docker-buildx git"
BUILDX = ("On Ubuntu 26.04 name `docker-buildx` too, which Compose builds with:"
          " without it, Compose warns that buildx is not installed and builds"
          " all the same.")


def test_the_ubuntu_line_names_buildx_wherever_it_is_given():
    """Measured 2026-10-20 on plain Ubuntu 26.04 with its own docker.io and
    docker-compose-v2: Compose warns it is configured to build using Bake but
    buildx is not installed, and with docker-buildx 0.30.1-0ubuntu1 from
    universe it does not. Debian 13's own line already brings docker-buildx
    0.13.1+ds1-3, and no warning shows, so its line stays as it is."""
    readme = (HERE / "README.md").read_text()
    assert f"\nsudo apt install {UBUNTU_PACKAGES}\n" in readme
    assert "\nsudo apt install docker.io docker-cli docker-compose git\n" in readme
    assert BUILDX in " ".join(readme.split())
    assert f"sudo apt install {UBUNTU_PACKAGES}." in (HERE / "install.sh").read_text()
    assert f'"apt-get install -y {UBUNTU_PACKAGES}"' in (HERE / "prove_install.py").read_text()


def test_nothing_listens_on_80_and_no_setting_names_it():
    """Caddy gets its certificate on 443 alone since 16 October 2026 (the
    shorter install, docs/record 4.461), so port 80 has no setting left and
    the Caddyfile names no HTTP port. selfhost/smoke.py reads the sockets
    the real Caddy opens."""
    caddyfile = (HERE / "Caddyfile").read_text()
    for path in (PRODUCT_COMPOSE, ENV_EXAMPLE, HERE / "Caddyfile"):
        assert "WHICHPORTS_HTTP_PORT" not in path.read_text(), path.name
    settings = [line.strip() for line in caddyfile.splitlines()
                if not line.strip().startswith("#")]
    assert not [line for line in settings if line.startswith("http_port")]


def global_options(caddyfile: str) -> str:
    """The global block, the first one in the file, without its comments."""
    lines = [line for line in caddyfile.splitlines()
             if not line.strip().startswith("#")]
    text = "\n".join(lines)
    start = text.index("{\n")
    return text[start:text.index("\n}\n", start)]


def test_caddy_gets_its_certificate_on_443_with_tls_alpn_and_redirects_nothing():
    """Caddy's automatic HTTPS page (read 2026-10-16): the HTTP challenge
    needs port 80, the TLS-ALPN challenge needs 443, both are on by default,
    and the redirect to https:// uses port 80. With 80 closed the HTTP
    challenge can only fail, so it is off, and the redirect with it. The
    TLS-ALPN challenge stays on: it is the one that works."""
    block = global_options((HERE / "Caddyfile").read_text())
    assert "\tauto_https disable_redirects" in block
    issuer = re.search(r"\tcert_issuer acme \{(.*?)\n\t\}", block, re.S)
    assert issuer, "no acme issuer in the global options"
    assert [line.strip() for line in issuer.group(1).splitlines()
            if line.strip()] == ["disable_http_challenge"]
    assert block.count("cert_issuer") == 1
    assert "disable_tlsalpn_challenge" not in block
    assert "auto_https off" not in block and "disable_certs" not in block


def test_the_year_of_caching_is_only_for_a_font_that_was_served():
    """Without the condition Caddy sets the header on every answer under
    /fonts/, a 404 included (docs/record 4.193). The smoke test asks the
    real Caddy. This holds the line itself."""
    caddyfile = (HERE / "Caddyfile").read_text()
    block = re.search(r"header /fonts/\* \{(.*?)\n\t\t\}", caddyfile, re.S)
    assert block, "the fonts' header is no longer a block with a condition"
    assert 'Cache-Control "public, max-age=31536000, immutable"' in block.group(1)
    assert "match status 2xx 304" in block.group(1)
    assert caddyfile.count("immutable") == 1


def test_caddy_opens_nothing_but_its_two_tcp_ports():
    caddyfile = (HERE / "Caddyfile").read_text()
    assert "\tadmin off" in caddyfile
    assert "protocols h1 h2" in caddyfile


# -------------------------------------------------------------- sandbox

def service_block(text: str, name: str) -> str:
    start = text.index(f"\n  {name}:")
    following = re.search(r"\n  [a-z]", text[start + 3:])
    end = start + 3 + following.start() if following else len(text)
    return text[start:end]


def test_both_python_containers_carry_the_sandbox():
    text = PRODUCT_COMPOSE.read_text()
    anchor = text[text.index("x-controlplane:"):text.index("\nservices:")]
    for line in ("read_only: true", "- /tmp", "- ALL",
                 "- no-new-privileges:true", "init: true"):
        assert line in anchor, f"the shared block lost {line!r}"
    for name in ("controlplane", "worker"):
        assert "<<: *controlplane" in service_block(text, name)


# ------------------------------------------------------------- the build

def services_of(text: str) -> dict:
    """Each service of a Compose file, by name: the image it runs and
    whether it builds that image, with what it takes from a shared block
    (`<<: *name`) counted as its own."""
    shared = {}
    for match in re.finditer(r"(?m)^x-[a-z-]+: &([a-z-]+)\n((?:[ #].*\n|\n)*)", text):
        shared[match.group(1)] = match.group(2)
    section = text[text.index("\nservices:"):]
    following = re.search(r"\n[a-z]", section[1:])
    section = section[:following.start() + 1] if following else section
    out = {}
    for name in re.findall(r"(?m)^  ([a-z][a-z0-9-]*):$", section):
        own = service_block(section, name)
        merged = re.search(r"<<: \*([a-z-]+)", own)
        lines = own + (shared[merged.group(1)] if merged else "")
        image = re.search(r"(?m)^ +image: *(\S+)", lines)
        out[name] = (image.group(1) if image else "",
                     re.search(r"(?m)^ +build:", lines) is not None)
    return out


def test_each_image_the_stack_builds_is_built_by_one_service():
    """Two services that build one image build it twice at once under one
    `up --build`, and the image store refuses the second to finish. A new
    Ubuntu 26.04 install did, on 2026-10-26, with Compose 2.40.3, buildx
    0.30.1 and the containerd image store: "image whichports-controlplane:local
    already exists", exit 1, nothing started, and the same line worked when
    run again. So the control plane builds the image and the worker runs it."""
    services = services_of(PRODUCT_COMPOSE.read_text())
    assert set(services) == {"controlplane", "worker", "caddy"}
    builders = {}
    for name, (image, builds) in services.items():
        assert image.endswith(LOCAL_TAG), f"{name} runs {image!r}"
        if builds:
            builders.setdefault(image, []).append(name)
    assert builders == {"whichports-controlplane:local": ["controlplane"],
                        "whichports-caddy:local": ["caddy"]}
    assert services["worker"] == ("whichports-controlplane:local", False)


def test_the_worker_never_pulls_the_image_the_control_plane_builds():
    """No registry has it. Without this line a first `up --build` asked
    Docker Hub for it before the control plane had built it, and printed
    "worker Error pull access denied for whichports-controlplane" into a
    build that went on to succeed (Compose 2.40.3, 2026-10-26)."""
    worker = service_block(PRODUCT_COMPOSE.read_text(), "worker")
    assert "\n    pull_policy: never\n" in worker


@pytest.mark.parametrize("compose", COMPOSE_FILES, ids=lambda p: str(p.relative_to(HERE)))
def test_no_compose_file_builds_one_image_in_two_services(compose):
    """The race above, in every Compose file here: the end to end test's two
    target servers each carried a build of one image until 2026-10-27. A
    service that runs an image another service of its file builds never
    pulls it."""
    text = compose.read_text()
    services = services_of(text)
    builders = {}
    for name, (image, builds) in services.items():
        if builds:
            builders.setdefault(image, []).append(name)
    assert all(len(names) == 1 for names in builders.values()), builders
    section = text[text.index("\nservices:"):]
    for name, (image, builds) in services.items():
        if image in builders and not builds:
            assert "\n    pull_policy: never\n" in service_block(section, name), name


def test_caddy_carries_the_sandbox_and_the_one_capability_in_the_stack():
    text = PRODUCT_COMPOSE.read_text()
    caddy = service_block(text, "caddy")
    for line in ("read_only: true", "- /tmp", "- ALL", "- NET_BIND_SERVICE",
                 "init: true"):
        assert line in caddy
    assert text.count("cap_add:") == 1, "one capability, on one service"
    added = caddy[caddy.index("cap_add:"):].splitlines()[1:3]
    assert added[0].strip() == "- NET_BIND_SERVICE"
    assert not added[1].strip().startswith("- "), "exactly one"
    assert "privileged: true" not in caddy


def test_caddy_has_a_health_check_on_its_own_port():
    """Without one, compose up --wait reads a Caddy that exits at once and
    restarts as up (Compose 5.6.0, 2026-10-20). The check connects to the
    port Caddy listens on, from inside its container, with busybox's nc,
    which the pinned image has (measured 2026-10-20)."""
    caddy = service_block(PRODUCT_COMPOSE.read_text(), "caddy")
    assert "healthcheck:" in caddy
    assert ('test: ["CMD", "nc", "-z", "-w", "3", "127.0.0.1",'
            ' "${WHICHPORTS_HTTPS_PORT:-443}"]') in caddy


def test_caddy_runs_unprivileged_and_the_image_keeps_no_setuid_file():
    """Measured 2026-10-01 on the host network: as uid 10001 Caddy binds 80
    through its file capability only while no-new-privileges is off. So the
    flag is absent on this one service, on purpose, and the image closes the
    other way up instead."""
    caddy = service_block(PRODUCT_COMPOSE.read_text(), "caddy")
    assert "no-new-privileges" not in "\n".join(
        l for l in caddy.splitlines() if not l.strip().startswith("#"))
    text = DOCKERFILE.read_text()
    stage = text[text.index(" AS caddy"):text.index(" AS controlplane")]
    assert "USER whichports" in stage
    assert "-u 10001" in stage
    assert "-perm /6000 -exec chmod a-s {} +" in stage


@pytest.mark.parametrize("compose", COMPOSE_FILES, ids=lambda p: str(p.relative_to(HERE)))
def test_nothing_is_privileged(compose):
    for _number, line in code_lines(compose):
        assert "privileged: true" not in line
        assert "SYS_ADMIN" not in line
        assert "pid: host" not in line


# ------------------------------------------------------------- secrets

SECRET_NAMES = re.compile(r"(PASSWORD|SECRET|TOKEN|_KEY$|KEY_|INVITE)")


def test_the_example_env_holds_no_secret():
    for number, raw in enumerate(ENV_EXAMPLE.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        assert sep, f"env.example:{number} is not KEY=VALUE"
        if SECRET_NAMES.search(key):
            assert value == "", f"env.example:{number} gives {key} a value"


def test_the_example_env_has_the_invite_line_once_and_empty_beside_the_three():
    """The installer writes the invite into this line and nothing else, and
    app/invite.py refuses it set beside any of the three. Left empty here,
    a copy of this file is an instance with no probers."""
    sys.path.insert(0, str(HERE.parent / "controlplane"))
    from app import invite
    lines = ENV_EXAMPLE.read_text().splitlines()
    assert lines.count(f"{invite.INVITE_ENV}=") == 1
    assert [line for line in lines if line.startswith(invite.INVITE_ENV)] == [
        f"{invite.INVITE_ENV}="]
    for name in (invite.PROBER_API_ENV, invite.PROBER_API_KEY_ENV,
                 invite.PROBER_PROOF_KEY_ENV):
        assert lines.count(f"{name}=") == 1
    assert lines.count("WHICHPORTS_DOMAIN=whichports.example.com") == 1


@pytest.mark.parametrize("path", [PRODUCT_COMPOSE, DOCKERFILE, ENV_EXAMPLE],
                         ids=lambda p: p.name)
def test_the_test_only_trust_never_reaches_the_product(path):
    """SSL_CERT_FILE makes Python and Go trust another certificate authority.
    The end to end test needs it to trust its own, and it lives in that
    test's compose file and nowhere a tester's instance reads."""
    assert "SSL_CERT_FILE" not in path.read_text()


def test_the_dockerignore_is_an_allowlist():
    ignore = (HERE / "Dockerfile.dockerignore").read_text().splitlines()
    first = next(l for l in ignore if l.strip() and not l.startswith("#"))
    assert first == "*"
    for line in ignore:
        if line.startswith("!"):
            assert ".env" not in line and ".db" not in line


def test_the_env_file_stays_out_of_git():
    gitignore = (HERE.parent / ".gitignore").read_text().splitlines()
    assert ".env" in gitignore


# ------------------------------------------------------- the package set

def test_the_image_installs_the_lock_without_reflex_and_resolves_nothing():
    text = DOCKERFILE.read_text()
    joined = re.sub(r"\\\n\s*", "", text)
    assert ("uv export --frozen --no-dev --prune reflex --no-emit-project"
            in joined)
    assert "--require-hashes --no-deps --only-binary :all:" in joined
    assert "pip install" not in joined.replace("uv pip install", "")


def test_the_python_is_the_gates():
    """Decided 2026-10-01 (docs/record 4.226): an instance runs the
    interpreter the gate tested, until gate, prod and image move to 3.14
    together. The gate runs this file, so the comparison is with the
    interpreter running it, and a gate that moves to a new Python fails here
    until the Dockerfile follows."""
    running = "{}.{}.{}".format(*sys.version_info[:3])
    pythons = [image for _number, image in base_images(DOCKERFILE)
               if image.startswith("python:")]
    assert pythons
    for image in pythons:
        assert image.startswith(f"python:{running}-"), \
            f"the gate runs Python {running} and the image is {image}"


# ------------------------------------------------------- the test rig

E2E = HERE / "e2e"


def test_the_test_vantage_carries_the_closed_set_the_real_one_does():
    """A real prober box gets the six modules `VANTAGE_MODULES` names in
    controlplane/app/probe_runner.py, and the control plane's suite checks
    that set is closed. The test vantage copies the same six, by name. The
    constant is read as text, because this suite does not import the app."""
    runner = HERE.parent / "controlplane" / "app" / "probe_runner.py"
    assigned = [node.value for node in ast.parse(runner.read_text()).body
                if isinstance(node, ast.Assign)
                and getattr(node.targets[0], "id", "") == "VANTAGE_MODULES"]
    modules = list(ast.literal_eval(assigned[0]))
    assert len(modules) == 6
    line = next(l for l in (E2E / "Dockerfile").read_text().splitlines()
                if l.startswith("COPY controlplane/app/"))
    copied = [word.rsplit("/", 1)[1] for word in line.split()[1:-1]]
    assert sorted(copied) == sorted(modules)
    assert line.split()[-1] == "/opt/whichports/app/"


def test_the_test_network_is_internal_and_numbered_from_the_two_ranges():
    text = (E2E / "compose.yaml").read_text()
    assert "    internal: true" in text
    assert "- subnet: 192.88.99.0/24" in text
    assert "- subnet: 2001:20:0:1::/64" in text
    assert "ports:" not in "\n".join(l for _n, l in code_lines(E2E / "compose.yaml"))


def test_production_code_knows_nothing_of_the_test_ranges():
    """The rule that decides what may be probed is not taught about the
    ranges the test borrows (docs/record 4.227)."""
    for tree in ("controlplane/app", "agent/internal", "agent/cmd"):
        for path in (HERE.parent / tree).rglob("*"):
            if path.suffix not in (".py", ".go") or "_test" in path.name:
                continue
            text = path.read_text(errors="replace")
            assert "192.88.99." not in text, path
            assert "2001:20:" not in text, path


def test_no_key_is_baked_into_a_test_image():
    text = (E2E / "Dockerfile").read_text()
    assert "rm -f /etc/ssh/ssh_host_*" in text
    assert "ssh-keygen" not in text
    assert "whp" not in text.replace("whichports", "")


def _copied_from_the_tree(dockerfile: Path) -> list:
    """Every path a Dockerfile copies out of the build's tree, its COPY
    lines read as text. A COPY from another stage or image is not one."""
    sources = []
    for _number, line in code_lines(dockerfile):
        words = line.split()
        if not words or words[0] != "COPY" or any(w.startswith("--from") for w in words):
            continue
        sources += [w for w in words[1:-1] if not w.startswith("--")]
    return sources


def _inside(path: str, tree) -> bool:
    return any(path == top or path.startswith(top.rstrip("/") + "/") for top in tree)


def _tree_of(script: Path) -> tuple:
    """The `TREE` a script assigns, read as text like `VANTAGE_MODULES`
    above, because importing either script would run its imports."""
    assigned = [node.value for node in ast.parse(script.read_text()).body
                if isinstance(node, ast.Assign)
                and getattr(node.targets[0], "id", "") == "TREE"]
    assert len(assigned) == 1, script
    return tuple(ast.literal_eval(assigned[0]))


def test_the_smoke_and_the_e2e_copy_every_file_the_images_build_from():
    """smoke.py and e2e/run.py build the images from a clean copy of the
    paths each names, so a path a Dockerfile copies that neither names fails
    the build. On 2026-10-24 the e2e named its own list without the two
    ops/cve unit files the product image copies since that day, and
    stopped at its build."""
    smoke_tree = _tree_of(HERE / "smoke.py")
    e2e_tree = _tree_of(E2E / "run.py")
    for path in _copied_from_the_tree(DOCKERFILE):
        assert _inside(path, smoke_tree), (path, "smoke.py")
        assert _inside(path, e2e_tree), (path, "e2e/run.py")
    for path in _copied_from_the_tree(E2E / "Dockerfile"):
        assert _inside(path, e2e_tree), (path, "e2e/run.py")
    assert set(smoke_tree) <= set(e2e_tree)


# ------------------------------------------------------ the CVE check's data

CVE_UNITS = HERE.parent / "ops" / "cve"


def test_the_cve_folder_is_one_path_for_the_unit_the_setting_the_volume_and_the_image():
    """The box's own unit writes /var/lib/whichports-cve. In the bundle that
    is a volume of its own, written by the worker and read only by the
    control plane, and the setting both read it through names the same
    path. The image makes the mount point for its user and carries the two
    unit files where the worker looks for them."""
    folder = "/var/lib/whichports-cve"
    unit = (CVE_UNITS / "whichports-cve.service").read_text()
    assert f"--out {folder}" in " ".join(unit.replace("\\\n", " ").split())
    compose = PRODUCT_COMPOSE.read_text()
    anchor = compose[compose.index("x-controlplane:"):compose.index("\nservices:")]
    assert f"WHICHPORTS_CVE_DIR: {folder}" in anchor
    assert f"- cve:{folder}:ro" in service_block(compose, "controlplane")
    worker_block = service_block(compose, "worker")
    assert f"- cve:{folder}\n" in worker_block and ":ro" not in worker_block
    assert "\n  cve:\n" in compose[compose.index("\nvolumes:"):]
    dockerfile = (HERE / "Dockerfile").read_text()
    made = dockerfile[dockerfile.index("install -d -o whichports -g whichports -m 0700"):]
    assert folder in made.split("\nCOPY")[0]
    sys.path.insert(0, str(HERE))
    try:
        import worker
    finally:
        sys.path.remove(str(HERE))
    assert ("COPY ops/cve/whichports-cve.service ops/cve/whichports-cve.timer "
            f"{worker.DEFAULT_CVE_UNIT_DIR}/") in dockerfile
    ignore = (HERE / "Dockerfile.dockerignore").read_text()
    # The two files and nothing else of ops/ are let into the build.
    let_in = [line.strip() for line in ignore.splitlines() if line.strip().startswith("!ops")]
    assert let_in == ["!ops/cve/whichports-cve.service", "!ops/cve/whichports-cve.timer"]


def test_the_readme_names_the_two_hosts_the_cve_build_asks_and_its_time():
    fetch = (HERE.parent / "controlplane" / "app" / "cvefetch.py").read_text()
    hosts = re.search(r"^VENDOR_HOSTS = \(([^)]*)\)", fetch, re.M).group(1)
    names = re.findall(r'"([^"]+)"', hosts)
    assert names == ["security-tracker.debian.org", "security-metadata.canonical.com"]
    readme = " ".join((HERE / "README.md").read_text().split())
    for name in names:
        assert name in readme, name
    timer = (CVE_UNITS / "whichports-cve.timer").read_text()
    clock = re.search(r"^OnCalendar=\*-\*-\* (\d\d:\d\d):00 UTC$", timer, re.M).group(1)
    assert f"Once a day at {clock} UTC the worker downloads" in readme
    assert f"the CVE check's security data daily at {clock} UTC" in readme
    assert "Nothing about your servers or their packages is in those requests." in readme


# ------------------------------------------------- what the README promises

def test_what_the_readme_says_we_keep_is_what_the_code_keeps():
    """The README states the retention itself, because a public README
    cannot point at a private document. The numbers live in the control
    plane, and this holds the sentence to them."""
    readme = (HERE / "README.md").read_text()
    sys.path.insert(0, str(HERE.parent / "controlplane"))
    from app import authz, proberapi
    assert "never longer than fifteen minutes" in readme
    assert proberapi.BATCH_TTL_SECONDS == 15 * 60
    assert "for thirty days" in readme
    assert proberapi.LOG_RETENTION_SECONDS == 30 * 24 * 60 * 60
    assert "for the hour those counts are used in" in readme
    assert proberapi.PACE_WINDOW_SECONDS == 60 * 60
    # Our side holds what an instance's agents prove by presence, which
    # lapses in an hour since 2026-10-20, not in an agent report's week.
    assert "lapses an hour after" in readme
    assert authz.HOUR_TTL_SECONDS == 60 * 60
    # A proof by DNS TXT or a token file, which an instance makes on our side
    # too since 2026-10-24, lasts thirty days and is read every day.
    flat = " ".join(readme.split())
    assert "One by DNS TXT or a token file lasts thirty days and is read again every day." in flat
    assert authz.PUBLISHED_TTL_SECONDS == 30 * 24 * 60 * 60
    assert authz.RENEWAL_EVERY_SECONDS == 24 * 60 * 60
    # A challenge that proved nothing goes once its day is over, since
    # 2026-10-27, by the sweep the five minute timer runs.
    assert ("One that never proved its address is deleted within five minutes"
            " of its 24 hours") in flat
    assert authz.CHALLENGE_TTL_SECONDS == 24 * 60 * 60
    sweep = (HERE.parent / "controlplane" / "app" / "sweep_cli.py").read_text()
    assert "authz.forget_unproved_challenges(con, now=now)" in sweep
    assert "No port and no result" in readme
    columns = proberapi.SCHEMA.split("prober_api_log")[1].split(");")[0]
    assert "port" not in columns and "state" not in columns


def test_what_the_readme_says_of_a_feedback_message_is_what_the_wire_carries():
    """The README says what leaves an instance when somebody sends a
    message from the Feedback window, and what our side keeps of it. Both
    are held here to the wire's own fields and to the table's own columns,
    so a sixth field or a column for an address cannot arrive without the
    sentence (docs/record 4.425, 4.441)."""
    readme = " ".join((HERE / "README.md").read_text().split())
    sys.path.insert(0, str(HERE.parent / "controlplane"))
    from app import feedback
    # What leaves: the words, and beside them three things. The fifth field
    # is the number of the body's own shape.
    assert ("It is the words as the window shows them, and beside them the"
            " kind, the screen and the version.") in readme
    assert feedback.FIELDS == ("version", "kind", "words", "screen", "instance_version")
    assert "nothing is added to them" in readme
    # It goes with the instance's API key, and the other key is refused.
    assert "It goes with your instance's API key" in readme
    routes = (HERE.parent / "controlplane" / "app" / "feedback_routes.py").read_text()
    assert "instances.KIND_API" in routes and "KIND_PROOF" not in routes
    # What our side keeps: who sent it is an instance, never a person, and
    # no address is written.
    assert ("its words with the kind, the screen and the version, which instance"
            " sent it and when it arrived, until we delete it. No address, and no"
            " name or account of the person who wrote it") in readme
    table = feedback.SCHEMA.split("CREATE TABLE IF NOT EXISTS feedback (")[1].split(");")[0]
    columns = [line.split()[0] for line in table.splitlines()
               if line.strip() and line.split()[0].isidentifier()
               and line.split()[0] not in ("CHECK",)]
    assert columns == ["id", "instance_id", "workspace_id", "kind", "words", "screen",
                       "instance_version", "received_at", "done_at"]
    # An instance with no prober lines keeps the message itself.
    assert ("On an instance with no prober lines in `.env` the message is kept"
            " in its own database and nothing is sent.") in readme


def test_the_snapshots_the_readme_names_are_the_boxs_fourteen_without_batches_and_the_count():
    """Every line of "What our side keeps" has its own time, fifteen
    minutes, an hour, thirty days. All of them are rows of one database,
    and the box copies that database every night and keeps fourteen copies.
    So a row we delete is still in a snapshot for fourteen nights
    (docs/record 4.442). Two tables are the exception: a night's copy is
    emptied of the queued batches and of the hour's count before it is
    checked and zipped (docs/record 4.444). The README says both, and this
    holds each half to the code."""
    readme = " ".join((HERE / "README.md").read_text().split())
    assert ("A batch with its answer and the hour's counts are not in a"
            " snapshot: each night's copy of the database is emptied of both before"
            " it is kept. Everything else in this list is also in those nightly"
            " snapshots, fourteen of them, so a thing we delete is gone from our"
            " server fourteen nights later. Two more machines of ours each fetch the"
            " newest snapshot every night and keep fourteen copies. A copy there is"
            " gone fourteen nights after its snapshot was made, as on our server, and"
            " later than that when our server made no new snapshot or that machine"
            " was off. A snapshot we copy off the server by hand is kept until we"
            " delete that copy.") in readme
    control_plane = HERE.parent / "controlplane"
    unit = (control_plane / "ops" / "whichports-backup.service").read_text()
    assert "--keep 14" in unit
    # Nightly: one calendar time a day, and no other timer starts the backup.
    timer = (control_plane / "ops" / "whichports-backup.timer").read_text()
    assert timer.count("OnCalendar=") == 1 and "OnCalendar=*-*-* " in timer
    # The copy is SQLite's own backup of the whole file.
    sys.path.insert(0, str(control_plane))
    from app import backup, instancesignup, proberapi
    source = (control_plane / "app" / "backup.py").read_text()
    assert "source.backup(dest)" in source
    # The tables that are taken out, by their names in the prober API's and
    # the open signup's own schemas, and the abuse log is not one of them.
    assert backup.LEFT_OUT_OF_A_SNAPSHOT == ("prober_api_batches", "prober_api_charges",
                                             "prober_api_proof_uses", "instance_signups",
                                             "instance_signup_claims")
    schemas = proberapi.SCHEMA + instancesignup.SCHEMA
    for table in backup.LEFT_OUT_OF_A_SNAPSHOT + ("prober_api_log",):
        assert f"CREATE TABLE IF NOT EXISTS {table} (" in schemas
    # Emptied before it is checked and before it is kept: the order in `run`.
    run = source.split("def run(")[1].split("def main(")[0]
    assert (run.index("snapshot(db_path, work)") < run.index("leave_batches_out(work)")
            < run.index("verify(work)") < run.index("compress(work, final)"))


# ------------------------------- what the README tells a stranger to expect
#
# Added after a read of the README as somebody on a fresh server would follow
# it (2026-10-02). Each sentence is held to the place the fact lives, so the
# README cannot keep saying it after the code stops doing it.

def test_the_password_rule_in_the_readme_is_the_one_the_code_holds():
    sys.path.insert(0, str(HERE.parent / "controlplane"))
    from app import accounts
    readme = (HERE / "README.md").read_text()
    assert accounts.PASSWORD_MIN_CHARS == 12
    assert [key for key, _words, _test in accounts.PASSWORD_RULES] == [
        "length", "digit", "special"]
    assert ("at least 12 characters, with a number and a\nspecial character"
            in readme)


def test_the_private_address_setting_in_the_readme_is_the_one_the_code_holds():
    """The setting's name, the value that turns it on and the five networks
    it lets through, each from `app/outbound.py`. And the example file names
    it only as a comment, so a copy of it is an instance with the setting
    off (docs/record 4.336)."""
    sys.path.insert(0, str(HERE.parent / "controlplane"))
    from app import outbound
    readme = (HERE / "README.md").read_text()
    assert f"`{outbound.SETTING}={outbound.ON}`" in readme
    assert f"| `{outbound.SETTING}` |" in readme
    for network in outbound.LET_THROUGH_WITH_THE_SETTING:
        assert f"`{network}`" in readme, network
    named = set(re.findall(r"`([0-9a-f:.]+/\d+)`", readme))
    assert named == {str(n) for n in outbound.LET_THROUGH_WITH_THE_SETTING}
    # What turning it on means is said, and not only how.
    assert "anybody\nwho may add a channel on your instance" in readme
    example = ENV_EXAMPLE.read_text().splitlines()
    assert f"# {outbound.SETTING}={outbound.ON}" in example
    assert not [line for line in example if line.startswith(outbound.SETTING)]


def test_the_readme_names_every_place_the_build_downloads_from():
    """The registries of the base images and of the locked packages, read
    from the Dockerfile and the lock file."""
    readme = (HERE / "README.md").read_text()
    images = re.findall(r"^(?:FROM|COPY --from=)\s*([^\s@:]+)[:@]",
                        (HERE / "Dockerfile").read_text(), re.M)
    registries = set()
    for image in images:
        if image in ("build", "assets", "caddy-base"):
            continue  # an earlier stage of this Dockerfile, not a download
        first = image.split("/")[0]
        # A name with no registry in front is Docker Hub's.
        registries.add(first if "." in first else "Docker Hub")
    assert registries == {"Docker Hub", "ghcr.io"}, registries
    lock = (HERE.parent / "controlplane" / "uv.lock").read_text()
    hosts = set(re.findall(r'(?:registry|url) = "https://([^/"]+)', lock))
    assert hosts == {"pypi.org", "files.pythonhosted.org"}, hosts
    for place in registries | hosts:
        assert place in readme, f"the README does not name {place}"


def test_the_certificate_authority_the_readme_names_is_the_caddyfiles():
    """One issuer is named in the Caddyfile, `acme` with its default
    directory, which is Let's Encrypt. Naming it replaces Caddy's default
    list, and in the pinned 2.11.4 that list holds ZeroSSL only when an
    email is set, which this file never did (DefaultIssuers, read in
    Caddy's source at v2.11.4 on 2026-10-16). So the README names Let's
    Encrypt alone."""
    readme = (HERE / "README.md").read_text()
    caddyfile = (HERE / "Caddyfile").read_text()
    assert "Let's Encrypt" in readme and "Let's Encrypt" in caddyfile
    assert "ZeroSSL" not in readme
    block = global_options(caddyfile)
    assert re.search(r"cert_issuer acme \{", block)
    assert "acme_ca" not in block and "\temail" not in block


@pytest.mark.parametrize("command,argv", [
    ("docker compose exec worker ls /var/backups/whichports",
     '"exec", "-T", "worker", "ls",\n                              "/var/backups/whichports"'),
    ("docker compose exec controlplane python -m app.users_cli passwd you@example.com",
     '"app.users_cli", "passwd", ACCOUNT'),
    ("docker compose down\n", '"--profile", "caddy", "down", "--remove-orphans"'),
    ("docker compose down -v\n", '"--profile", "caddy", "down", "-v"'),
    ("docker compose logs -f caddy", '"logs"'),
    ("docker compose exec worker python selfhost/worker.py once whichports-cve.service",
     '"once", "whichports-cve.service"'),
])
def test_a_command_the_readme_gives_a_stranger_is_one_the_smoke_test_runs(
        command, argv):
    assert command in (HERE / "README.md").read_text()
    assert argv in (HERE / "smoke.py").read_text()


def test_the_sudo_form_puts_the_commit_after_sudo():
    """In front of `sudo` the variable is dropped, the build succeeds and the
    dashboard names no commit (measured on a server, docs/record 4.333)."""
    readme = (HERE / "README.md").read_text()
    assert "\nsudo WHICHPORTS_COMMIT=$(git rev-parse --short=12 HEAD) docker compose up" in readme
    assert "WHICHPORTS_COMMIT=$(git rev-parse --short=12 HEAD) sudo" not in readme


def test_the_restore_onto_a_new_server_is_in_the_order_that_was_run():
    """Install, stop, restore from standard input, start, and no account
    made first (run on a server, docs/record 4.349)."""
    readme = (HERE / "README.md").read_text()
    block = readme[readme.index("On a new server"):readme.index("## Settings")]
    steps = ["docker compose up -d --build", "docker compose stop",
             "selfhost/restore.py - <", "docker compose up -d\n```"]
    places = [block.index(step) for step in steps]
    assert places == sorted(places)
    assert "make no\naccount" in block or "make no account" in block


def test_the_caddy_volumes_the_readme_removes_by_name_are_the_compose_files():
    """With the Caddy profile off, `down -v` leaves Caddy's two volumes
    (measured on a server, docs/record 4.374), so the README names them."""
    compose = (HERE / "compose.yaml").read_text()
    project = re.search(r"(?m)^name: (\S+)$", compose).group(1)
    readme = (HERE / "README.md").read_text()
    for volume in ("caddy_data", "caddy_config"):
        assert re.search(rf"(?m)^  {volume}:", compose), volume
        assert f"{project}_{volume}" in readme
    assert f"docker volume rm {project}_caddy_data {project}_caddy_config" in readme


def test_the_env_file_is_closed_to_others_in_the_install_steps():
    readme = (HERE / "README.md").read_text()
    assert "cp env.example .env\nchmod 600 .env\n" in readme


def test_the_readme_asks_for_an_aaaa_record_only_where_the_address_exists():
    """It used to say the A and AAAA records must point at the server, which
    told a server with no IPv6 to publish a record for an address it does
    not hold."""
    readme = " ".join((HERE / "README.md").read_text().split())
    assert "A and AAAA records point at the server" not in readme
    assert ("an AAAA record only if the server has that IPv6 address"
            in readme)


# ------------------------------------- taking an instance off, agents and all
#
# Taking the stack down does not take the agents off the servers, and an
# agent proves its server's addresses to our API with the instance's proof
# key, not through the instance. In the second big test, after `down -v`,
# the instance's agents went on reporting their presence and our side held
# their proofs until the instance was revoked (27 October). So the section
# says to take the agents off first and to ask us to end the keys.

def taking_it_off():
    readme = (HERE / "README.md").read_text()
    start = readme.index("## Taking it off the server")
    return readme[start:readme.index("\n## ", start + 1)]


def test_taking_it_off_takes_the_agents_off_before_the_stack():
    section = taking_it_off()
    assert "sudo whichports-uninstall\n" in section
    assert section.index("sudo whichports-uninstall") < section.index("docker compose down -v\n")
    # The command is the one the agent package installs.
    nfpm = (HERE.parent / "agent" / "packaging" / "nfpm.yaml").read_text()
    assert 'dst: "/usr/bin/whichports-uninstall"' in nfpm
    flat = " ".join(section.split())
    assert "go on doing so after the stack is gone" in flat


def test_taking_it_off_asks_us_to_end_the_keys_and_says_what_that_ends():
    flat = " ".join(taking_it_off().split())
    landing = (HERE.parent / "site" / "landing" / "build.py").read_text()
    assert "hello@whichports.com" in flat and "hello@whichports.com" in landing
    # What ending an instance does, as the command our side runs says it.
    sys.path.insert(0, str(HERE.parent / "controlplane"))
    import app.instances_cli as instances_cli
    assert "`revoke` ends both keys and every proof the instance made, at once." in \
        " ".join(instances_cli.__doc__.split())
    assert "both its keys and every proof it made end at once" in flat
    assert flat.index("whichports-uninstall") < flat.index("hello@whichports.com")
