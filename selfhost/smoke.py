"""The Compose stack from a clean tree: up, answering, and down again.

    python3 selfhost/smoke.py            the working tree, as it would be committed
    python3 selfhost/smoke.py --head     the last commit, exactly

Runs before every commit that touches selfhost/, a Dockerfile, a Compose file,
uv.lock or the worker, and a red run means no commit, the same as the gate
(decided 2026-10-01, docs/record 4.226). It needs
Docker running, git, Python and the network to pull the pinned base images,
which is why it is not inside the gate. Nothing else has to be installed. selfhost/test_static.py is the half the gate runs.

What a pass means, in the order it is checked:

  1. The Compose file parses, with Caddy and without it.
  2. The images build from a tree holding only what git would have.
  3. The stack comes up healthy on ports nothing else uses, Caddy by its
     own health check too.
  4. No container holds the Docker socket and none publishes a port. Every
     container is read-only, unprivileged, and drops every capability but
     Caddy's one. The Python ones cannot gain privileges, and Caddy's image
     holds no setuid file.
  5. The sockets the stack opened on the machine are the ingest on 127.0.0.1
     and Caddy's one port, its stand-in for 443, and nothing else: nothing
     listens on an HTTP port.
  6. The image holds exactly the packages `uv export --prune reflex` lists.
  7. Caddy answers over TLS with a certificate from its own authority:
     /healthz, /login, the fonts, /metrics closed, and the beta signup
     route of our own landing page answering 404. A font that is there is
     cacheable for a year, also on a 304, and a font that is not there is
     answered 404 without that year.
  8. An account is made, signs in, and the dashboard renders with the commit
     in its footer. Add server prints a command that enrols to this instance.
     A new password set from the command line replaces the old one.
  9. Without the three prober lines the worker schedules the sweep, the
     backup and the scan path, and says in one line that the two probing
     passes are not scheduled. A second worker with the three lines set
     schedules all five and takes our prober list, and so does a third with
     the invite line alone. A write to the scan
     trigger starts a drain within seconds, and a sweep and a backup run on
     demand. A webhook
     at a private address is refused without
     WHICHPORTS_ALERTS_TO_PRIVATE_ADDRESSES and delivered with it, and a
     loopback address is refused at the door both ways.
 10. The snapshots copy off the machine and the copy opens as a database.
     A restore from that copy, and one by name from the volume: a server
     added after the backup is gone after each, and the session from before
     still opens the dashboard.
 11. The ingest is killed, the runtime restarts it, and Caddy serves it
     again. Then the control plane is recreated, the upgrade path, the same.
 12. Without Caddy, your own proxy's case: the only socket is the ingest on
     127.0.0.1, and it answers there.
 13. A malformed WHICHPORTS_BASE_URL stops the control plane at start with
     one line naming the setting, so does an invite line cut short, and a
     port that is taken stops the ingest and Caddy at start, each naming the
     address.
 14. Down keeps the five volumes. Down with its volumes deletes them, and
     nothing of the project is left.

**Its requests are made from a container on the machine's own network**, not
from the machine itself. The stack listens there (compose.yaml), and on Docker
Desktop that network belongs to Docker's virtual machine, which a Mac cannot
reach without a setting this script will not change for anyone. On a Linux
server it is the server's own network, so the same script works on both.

Every command is an argv array, never a shell string. Nothing here reads or
writes a secret: the account's password is made up for the run.
"""
import argparse
import datetime
import gzip
import json
import os
import random
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# What the build reads. Everything else in the repository stays out. Of ops,
# only the CVE build's two unit files, which the image carries.
TREE = ("controlplane", "site", "selfhost", "ops/cve/whichports-cve.service",
        "ops/cve/whichports-cve.timer")
IMAGE = "whichports-controlplane:local"
PYTHON = "/srv/controlplane/.venv/bin/python"
PASSWORD = "smoke-only-" + os.urandom(6).hex()
ACCOUNT = "smoke@example.com"
ALWAYS = ("whichports-sweep.timer", "whichports-backup.timer",
          "whichports-cve.timer", "whichports-scan.path")
# Scheduled only on an instance that uses our prober API (docs/record 4.333).
PROBING = ("whichports-probe-fast.timer", "whichports-probe.timer")
# Made up for the run. The second worker is removed seconds after it starts,
# long before its first job, so nothing is ever sent to this name.
PROBER_LINES = {"WHICHPORTS_PROBER_API": "https://prober.invalid",
                "WHICHPORTS_PROBER_API_KEY": "smoke-only",
                "WHICHPORTS_PROBER_PROOF_KEY": "smoke-only"}
# The same as one invite line (controlplane/app/invite.py), with keys of the
# right shape that were never issued.
INVITE_LINE = {"WHICHPORTS_PROBER_INVITE": "whpinvite1_prober.invalid_whpi_"
               + "0" * 64 + "_whpp_" + "0" * 64}

failures = []


def say(ok: bool, what: str) -> bool:
    print(f"  {'ok  ' if ok else 'FAIL'} {what}", flush=True)
    if not ok:
        failures.append(what)
    return ok


def run(argv, *, cwd=None, check=True, timeout=600, input=None, env=None):
    # Text in and out, except when the input is bytes: a snapshot is binary.
    binary = isinstance(input, bytes)
    done = subprocess.run(argv, cwd=cwd, capture_output=True, text=not binary,
                          timeout=timeout, input=input, env=env)
    if binary:
        done.stdout = done.stdout.decode("utf-8", "replace")
        done.stderr = done.stderr.decode("utf-8", "replace")
    if check and done.returncode != 0:
        raise RuntimeError(f"{' '.join(argv[:8])} ... exited"
                           f" {done.returncode}:\n{done.stderr[-2000:]}")
    return done


# ---------------------------------------------------------------- the tree

def clean_tree(destination: Path, head: bool) -> str:
    """Copy what a checkout would hold into `destination`. Returns the commit
    stamp for the footer: the commit, plus " +local changes" when the working
    tree differs from it."""
    commit = run(["git", "rev-parse", "--short=12", "HEAD"], cwd=REPO).stdout.strip()
    if head:
        # Bytes, not text: a tar stream is binary.
        data = subprocess.run(["git", "archive", "--format=tar", "HEAD", *TREE],
                              cwd=REPO, capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", str(destination)], input=data,
                       check=True)
        return commit
    listed = run(["git", "ls-files", "--cached", "--others",
                  "--exclude-standard", "-z", "--", *TREE], cwd=REPO).stdout
    for name in filter(None, listed.split("\0")):
        source = REPO / name
        if not source.is_file():
            continue  # deleted in the working tree
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    dirty = run(["git", "status", "--porcelain", "--", *TREE], cwd=REPO).stdout
    return f"{commit} +local changes" if dirty.strip() else commit


# ------------------------------------------- on the machine's own network
#
# One small program, run in a throwaway container on the host network. It
# does what the argument says and prints one JSON document.

REMOTE = r'''
import ipaddress, json, os, ssl, sys
import urllib.error, urllib.request

args = json.loads(os.environ["SMOKE_ARGS"])


def listeners():
    """Every TCP socket in LISTEN on this network, as [address, port]."""
    found = []
    for name in ("/proc/net/tcp", "/proc/net/tcp6"):
        with open(name) as handle:
            next(handle)
            for line in handle:
                fields = line.split()
                if fields[3] != "0A":
                    continue
                raw, port = fields[1].rsplit(":", 1)
                data = bytes.fromhex(raw)
                # The kernel prints each 32 bit word in host byte order.
                words = b"".join(data[i:i + 4][::-1] for i in range(0, len(data), 4))
                found.append([str(ipaddress.ip_address(words)), int(port, 16)])
    return sorted(found)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def http():
    handlers = [NoRedirect()]
    if args.get("root"):
        handlers.append(urllib.request.HTTPSHandler(
            context=ssl.create_default_context(cadata=args["root"])))
    opener = urllib.request.build_opener(*handlers)
    results = []
    carried = dict(args.get("cookies") or {})
    for step in args["steps"]:
        headers = dict(step.get("headers") or {})
        if carried:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in carried.items())
        data = step.get("data")
        request = urllib.request.Request(
            args["base"] + step["path"],
            data=data.encode() if data is not None else None, headers=headers)
        try:
            with opener.open(request, timeout=30) as response:
                status, body, reply = response.status, response.read(), response.headers
        except urllib.error.HTTPError as exc:
            status, body, reply = exc.code, exc.read(), exc.headers
        except (urllib.error.URLError, OSError) as exc:
            results.append({"status": 0, "body": str(exc)})
            continue
        for value in reply.get_all("Set-Cookie") or []:
            name, _, rest = value.partition("=")
            carried[name.strip()] = rest.split(";", 1)[0]
        results.append({"status": status,
                        "body": body.decode("utf-8", "replace"),
                        "cache": reply.get("Cache-Control") or "",
                        "etag": reply.get("Etag") or ""})
    return {"results": results, "cookies": carried}


print(json.dumps(listeners() if args["do"] == "listeners" else http()))
'''


def remote(arguments: dict):
    done = run(["docker", "run", "--rm", "-i", "--network", "host",
                "-e", "SMOKE_ARGS=" + json.dumps(arguments),
                "--entrypoint", PYTHON, IMAGE, "-"], input=REMOTE, timeout=120)
    return json.loads(done.stdout)


def listeners() -> set:
    return {(address, port) for address, port in remote({"do": "listeners"})}


class Browser:
    """Requests from the machine's own network, with one cookie jar."""

    def __init__(self, base: str, root: str = ""):
        self.base, self.root, self.cookies = base, root, {}

    def ask(self, *steps):
        answer = remote({"do": "http", "base": self.base, "root": self.root,
                         "steps": list(steps), "cookies": self.cookies})
        self.cookies = answer["cookies"]
        return [(r["status"], r["body"]) for r in answer["results"]]

    def get(self, path):
        return self.ask({"path": path})[0]

    def caching_of(self, path, headers=None):
        """The status, the Cache-Control header and the Etag of one answer."""
        answer = remote({"do": "http", "base": self.base, "root": self.root,
                         "steps": [{"path": path, "headers": headers or {}}],
                         "cookies": self.cookies})["results"][0]
        return answer["status"], answer.get("cache", ""), answer.get("etag", "")


A_YEAR = "max-age=31536000"


def check_font_caching(browser: Browser) -> None:
    """A font that was served may be kept for a year. A font that was not
    there must not be: a browser would keep the 404 as long (docs/record
    4.193, measured on our own Caddy with the same line)."""
    status, cache, etag = browser.caching_of("/fonts/WorkSans-400.woff2")
    say(status == 200 and A_YEAR in cache and "immutable" in cache,
        f"a font that is there is cacheable for a year: {status}, {cache!r}")
    status, cache, _ = browser.caching_of("/fonts/no-such-font.woff2")
    say(status == 404 and A_YEAR not in cache and "immutable" not in cache,
        f"a font that is not there is not: {status}, Cache-Control {cache!r}")
    status, cache, _ = browser.caching_of("/fonts/WorkSans-400.woff2",
                                          {"If-None-Match": etag})
    say(bool(etag) and status == 304 and A_YEAR in cache,
        f"asked again with its Etag it answers 304 and keeps the year:"
        f" {status}, {cache!r}")


def sign_in(browser: Browser, password: str | None = None) -> bool:
    status, page = browser.get("/login")
    csrf = re.search(r'name="csrf" value="([^"]+)"', page)
    if status != 200 or not csrf:
        return False
    from urllib.parse import urlencode
    form = urlencode({"csrf": csrf.group(1), "next": "/", "email": ACCOUNT,
                      "password": PASSWORD if password is None else password})
    status, _ = browser.ask({"path": "/login", "data": form, "headers": {
        "Content-Type": "application/x-www-form-urlencoded"}})[0]
    return status == 303


def add_server(browser: Browser, name: str):
    status, body = browser.ask({"path": "/api/admin/hosts",
                                "data": json.dumps({"name": name}),
                                "headers": {"Content-Type": "application/json"}})[0]
    return status, (json.loads(body) if status == 201 else {})


def wait_for(predicate, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(1)
    return predicate()


# ---------------------------------------------------------------- docker

class Stack:
    def __init__(self, tree: Path, project: str):
        self.tree = tree
        self.project = project

    def compose(self, *args, check=True, timeout=600, input=None):
        argv = ["docker", "compose", "-p", self.project,
                "-f", str(self.tree / "selfhost" / "compose.yaml")]
        return run(argv + list(args), cwd=self.tree, check=check,
                   timeout=timeout, input=input)

    def containers(self) -> list:
        ids = self.compose("ps", "-a", "-q").stdout.split()
        if not ids:
            return []
        return json.loads(run(["docker", "inspect", *ids]).stdout)

    def py(self, service: str, code: str, check=True):
        return self.compose("exec", "-T", service, PYTHON, "-c", code,
                            check=check)

    def host_names(self) -> list:
        out = self.py("worker", "import sqlite3, json; print(json.dumps(sorted("
                      "r[0] for r in sqlite3.connect("
                      "'/var/lib/whichports-controlplane/whichports.db')"
                      ".execute('SELECT name FROM hosts'))))").stdout
        return json.loads(out)


# ---------------------------------------------------------------- checks

def check_config(stack: Stack) -> None:
    for profiles, expected in (("caddy", {"controlplane", "worker", "caddy"}),
                               ("", {"controlplane", "worker"})):
        # The variable in the environment wins over the line in .env, which
        # is the same as removing that line.
        done = run(["docker", "compose", "-p", stack.project, "-f",
                    str(stack.tree / "selfhost" / "compose.yaml"),
                    "config", "--format", "json"], cwd=stack.tree, check=False,
                   env={**os.environ, "COMPOSE_PROFILES": profiles})
        label = "with Caddy" if profiles else "without Caddy"
        if not say(done.returncode == 0, f"compose.yaml parses, {label}"):
            print(done.stderr)
            continue
        services = json.loads(done.stdout)["services"]
        say(set(services) == expected, f"{label}: services {sorted(services)}")
        say(not any(s.get("ports") for s in services.values()),
            f"{label}: no service publishes a port")


def check_hardening(stack: Stack) -> None:
    containers = stack.containers()
    say(len(containers) == 3, f"three containers, found {len(containers)}")
    for c in containers:
        name = c["Config"]["Labels"].get("com.docker.compose.service", "?")
        host = c["HostConfig"]
        mounts = [m.get("Source", "") + " " + m.get("Destination", "")
                  for m in c.get("Mounts", [])]
        say(not any("docker.sock" in m for m in mounts),
            f"{name}: no Docker socket mounted")
        if name in ("controlplane", "worker"):
            cve = [m for m in c.get("Mounts", [])
                   if m.get("Destination") == "/var/lib/whichports-cve"]
            say(len(cve) == 1 and cve[0].get("RW") == (name == "worker"),
                f"{name}: the CVE folder is mounted"
                f" {'writable' if name == 'worker' else 'read only'}")
        say(not (host.get("PortBindings") or {})
            and not any((c["NetworkSettings"].get("Ports") or {}).values()),
            f"{name}: publishes no port")
        on_host = host.get("NetworkMode") == "host"
        say(on_host == (name in ("controlplane", "caddy")),
            f"{name}: network mode {host.get('NetworkMode')}")
        say(host.get("ReadonlyRootfs") is True, f"{name}: read-only root")
        say(host.get("CapDrop") == ["ALL"], f"{name}: every capability dropped")
        added = sorted(a.removeprefix("CAP_") for a in host.get("CapAdd") or [])
        say(added == (["NET_BIND_SERVICE"] if name == "caddy" else []),
            f"{name}: capabilities added {added}")
        say(not host.get("Privileged"), f"{name}: not privileged")
        no_new = "no-new-privileges:true" in (host.get("SecurityOpt") or [])
        say(no_new == (name != "caddy"),
            f"{name}: no-new-privileges {'set' if no_new else 'not set'}")
        uid = stack.compose("exec", "-T", name, "id", "-u").stdout.strip()
        say(uid == "10001", f"{name}: runs as uid {uid}")
    setuid = stack.compose("exec", "-T", "caddy", "find", "/", "-xdev",
                           "-type", "f", "-perm", "/6000", check=False).stdout
    say(not setuid.strip(), "Caddy's image holds no setuid or setgid file")


def check_sockets(before: set, after: set, ports: dict, caddy: bool) -> None:
    opened = after - before
    expected = {("127.0.0.1", ports["ingest"])}
    say(("127.0.0.1", ports["ingest"]) in opened,
        f"the ingest listens on 127.0.0.1:{ports['ingest']}")
    elsewhere = {(a, p) for a, p in opened if p == ports["ingest"]
                 and a != "127.0.0.1"}
    say(not elsewhere, "the ingest listens on no other address")
    if caddy:
        found = {a for a, p in opened if p == ports["https"]}
        say(bool(found) and found <= {"0.0.0.0", "::"},
            f"Caddy listens on {ports['https']}, on {sorted(found)}")
        expected |= {(a, ports["https"]) for a in found}
        say(not {p for _a, p in opened} & {80, 443},
            "Caddy opened no other port: nothing on 80, and 443 itself only"
            " where .env says so")
    say(opened == expected, "the stack opened nothing else"
        + ("" if opened == expected else f": {sorted(opened - expected)}"))


def uv_image(tree: Path) -> str:
    """The uv image the Dockerfile builds with, pin and all, read from the
    Dockerfile so the digest is written in one place."""
    text = (tree / "selfhost" / "Dockerfile").read_text()
    return re.search(r"--from=(ghcr\.io/astral-sh/uv:\S+@sha256:[0-9a-f]{64})",
                     text).group(1)


def check_packages(stack: Stack, tree: Path) -> None:
    # uv runs from the image the build itself uses, so this machine needs
    # Docker and nothing else. A server somebody installs on has no uv.
    export = run(["docker", "run", "--rm", "-v",
                  f"{tree / 'controlplane'}:/src:ro", "-w", "/src",
                  uv_image(tree), "export", "--frozen", "--no-dev", "--prune",
                  "reflex", "--no-emit-project", "--no-header",
                  "--no-annotate", "--no-hashes"]).stdout
    wanted = set()
    for line in export.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        requirement, _, marker = line.partition(";")
        if "win32" in marker:
            continue
        name, _, version = requirement.strip().partition("==")
        wanted.add((re.sub(r"[-_.]+", "-", name.lower()), version.strip()))
    listed = stack.py("controlplane",
                      "import importlib.metadata as m, json; print(json.dumps("
                      "sorted([d.metadata['Name'], d.version] for d in"
                      " m.distributions())))").stdout
    got = {(re.sub(r"[-_.]+", "-", n.lower()), v) for n, v in json.loads(listed)}
    say(got == wanted, f"the image holds exactly the {len(wanted)} packages"
        f" of the export" + ("" if got == wanted else
                              f": extra {sorted(got - wanted)},"
                              f" missing {sorted(wanted - got)}"))


def check_schedule_with_the_prober_lines(stack: Stack) -> None:
    """A second worker, started with the three prober lines, and a third
    with the invite line alone, each removed as soon as it has said what it
    schedules."""
    for label, lines in (("the three prober lines", PROBER_LINES),
                         ("the invite line", INVITE_LINE)):
        name = f"{stack.project}-with-probers"
        settings = [word for key, value in lines.items()
                    for word in ("-e", f"{key}={value}")]
        stack.compose("run", "-d", "--no-deps", "--name", name, *settings, "worker")
        try:
            def said() -> str:
                got = run(["docker", "logs", name], check=False)
                return got.stdout + got.stderr
            wait_for(lambda: "scan: watching" in said(), 20)
            logs = said()
            for unit in ALWAYS + PROBING + ("whichports-vantages-sync.timer",):
                say(f"worker: {unit}:" in logs,
                    f"with {label} the worker schedules {unit}")
            say("not scheduled" not in logs,
                "and says nothing about a pass that is not scheduled")
            say("whpi_" not in logs and "whpp_" not in logs,
                "and names no key")
        finally:
            run(["docker", "rm", "-f", name], check=False)


def check_worker(stack: Stack) -> None:
    logs = stack.compose("logs", "--no-color", "worker").stdout
    for unit in ALWAYS:
        say(f"worker: {unit}:" in logs, f"the worker schedules {unit}")
    told = [line for line in logs.splitlines() if "not scheduled" in line]
    say(len(told) == 1 and all(unit in told[0] for unit in PROBING)
        and "WHICHPORTS_PROBER_API is not set" in told[0],
        "without the prober lines it says in one line that the two probing"
        " passes are not scheduled")
    say(not any(f"worker: {unit}:" in logs for unit in PROBING)
        and " probe-fast: " not in logs and " probe: " not in logs,
        "and no probing pass is scheduled or started")
    say(" cve: first run in 120s" in logs
        and "no extract in /var/lib/whichports-cve yet" in logs,
        "a new install's worker builds the CVE data two minutes after start")
    check_schedule_with_the_prober_lines(stack)
    stack.py("worker", "open('/var/lib/whichports-controlplane/scan-requested',"
             " 'w').write('smoke')")
    say(wait_for(lambda: "scan: started" in stack.compose(
        "logs", "--no-color", "worker").stdout, 10),
        "a write to the scan trigger started a drain")
    for unit in ("whichports-sweep.service", "whichports-backup.service"):
        done = stack.compose("exec", "-T", "worker", "python",
                             "selfhost/worker.py", "once", unit, check=False)
        say(done.returncode == 0, f"{unit} ran on demand, exit {done.returncode}")
    check_cve_build(stack)
    check_private_destinations(stack)


def check_cve_build(stack: Stack) -> None:
    """The new install's own first build, two minutes after the worker
    started, then the control plane reads what it wrote with its own reader,
    through the setting, from its read-only mount. Then the README's command
    for a build by hand, and a restart that has the files and so waits for
    the daily time. It downloads the two vendors' files, so this needs the
    internet, as the stack does."""
    def logs(*since) -> str:
        return stack.compose("logs", "--no-color", *since, "worker").stdout

    wait_for(lambda: " cve: exited " in logs(), 420)
    built = logs()
    for line in built.splitlines():
        if " cve | " in line:
            print(f"       {line.split(' cve | ', 1)[1]}")
    ended = re.search(r" cve: exited (-?\d+) after ([\d.]+)s", built)
    if not say(bool(ended) and ended.group(1) == "0",
               "the new install built the CVE data by itself after start"
               + (f", exit {ended.group(1)}, {float(ended.group(2)):.0f}s" if ended else "")):
        print(built[-3000:])
        return
    peak = stack.compose("exec", "-T", "worker", "cat", "/sys/fs/cgroup/memory.peak",
                         check=False).stdout.strip()
    if peak.isdigit():
        print(f"       the worker container's memory at its peak so far: {int(peak) >> 20} MB")
    read = stack.py("controlplane", (
        "import json, os\n"
        "from app import cvestore, cveextract\n"
        "out = {'dir': str(cvestore.directory())}\n"
        "for d, v in [('debian', k) for k in cveextract.DEBIAN_CODENAMES]"
        " + [('ubuntu', k) for k in cveextract.UBUNTU_ECOSYSTEMS]:\n"
        "    s = cvestore.read(d, v)\n"
        "    out[f'{d} {v}'] = None if s is None else s.header.built\n"
        "print(json.dumps(out))\n"), check=False)
    try:
        found = json.loads(read.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        say(False, f"the control plane read the extracts: {read.stdout} {read.stderr}")
        return
    say(found.pop("dir") == "/var/lib/whichports-cve",
        "the control plane reads the CVE data from /var/lib/whichports-cve")
    say(bool(found) and all(found.values()),
        f"the control plane's own reader reads {len(found)} extracts, each with"
        f" the time it was built: {sorted(found)}")
    wrote = stack.compose("exec", "-T", "controlplane", "touch",
                          "/var/lib/whichports-cve/x", check=False)
    say(wrote.returncode != 0, "and the control plane cannot write there")
    began = time.monotonic()
    done = stack.compose("exec", "-T", "worker", "python", "selfhost/worker.py",
                         "once", "whichports-cve.service", check=False,
                         timeout=1200)
    say(done.returncode == 0, f"the README's command builds it again by hand,"
        f" exit {done.returncode}, {time.monotonic() - began:.0f}s")
    since = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stack.compose("restart", "worker", timeout=120)
    wait_for(lambda: " cve: first run in " in logs("--since", since), 30)
    again = re.search(r" cve: first run in (\d+)s", logs("--since", since))
    say(bool(again) and int(again.group(1)) > 120,
        "a restart with the files there waits for 04:41"
        + (f", first run in {again.group(1)}s" if again else ""))


# A receiver for one webhook: it answers 204 to a POST and says it got one.
RECEIVER = (
    "import http.server\n"
    "class Handler(http.server.BaseHTTPRequestHandler):\n"
    "    def do_POST(self):\n"
    "        self.rfile.read(int(self.headers.get('Content-Length', 0)))\n"
    "        self.send_response(204)\n"
    "        self.end_headers()\n"
    "        print('got a POST', flush=True)\n"
    "http.server.HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()\n")
PRIVATE_SETTING = "WHICHPORTS_ALERTS_TO_PRIVATE_ADDRESSES"


def check_private_destinations(stack: Stack) -> None:
    """A webhook inside the operator's own network (docs/record 4.336).

    The receiver runs on the worker's own Docker network, which is a private
    one, and the test message is sent from the worker, where a real alert is
    sent from. Without the setting it is refused and the operator is told
    which setting allows it. With the setting it arrives."""
    name = f"{stack.project}-receiver"
    stack.compose("run", "-d", "--no-deps", "--name", name, "worker",
                  PYTHON, "-c", RECEIVER)
    cli = ["worker", "python", "-m", "app.channels_cli"]
    try:
        added = stack.compose("exec", "-T", *cli, "add", "--type", "webhook",
                              "--label", "smoke private", "--destination",
                              f"http://{name}:8080/hook", check=False)
        say(added.returncode == 0, "a webhook written as a name is taken at"
            " the door without being looked up")
        off = stack.compose("exec", "-T", *cli, "test", "--label",
                            "smoke private", check=False)
        said = off.stdout + off.stderr
        say(off.returncode != 0 and "inside a private network" in said
            and f"{PRIVATE_SETTING}=yes" in said,
            "without the setting a private address is refused, and the"
            " operator is told the setting")
        on = stack.compose("exec", "-T", "-e", f"{PRIVATE_SETTING}=yes", *cli,
                           "test", "--label", "smoke private", check=False)
        got = run(["docker", "logs", name], check=False)
        say(on.returncode == 0 and (got.stdout + got.stderr).count("got a POST") == 1,
            "with the setting the same webhook is delivered, once")
        for label, extra in (("without", []), ("with", ["-e", f"{PRIVATE_SETTING}=yes"])):
            loop = stack.compose("exec", "-T", *extra, *cli, "add", "--type",
                                 "webhook", "--label", f"smoke loopback {label}",
                                 "--destination", "http://127.0.0.1:9/hook",
                                 check=False)
            say(loop.returncode != 0 and "not an address an alert can be sent to"
                in loop.stdout + loop.stderr,
                f"a loopback address is refused at the door {label} the setting")
    finally:
        run(["docker", "rm", "-f", name], check=False)


def opens_as_a_database(snapshot: Path) -> bool:
    """A backup nobody has opened never counts as one (ops/RUNBOOK.md)."""
    work = snapshot.with_suffix(".opened")
    try:
        with gzip.open(snapshot, "rb") as packed, open(work, "wb") as out:
            shutil.copyfileobj(packed, out)
        con = sqlite3.connect(f"file:{work}?mode=ro", uri=True)
        try:
            return con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        finally:
            con.close()
    except (OSError, EOFError, sqlite3.Error):
        return False


def check_lost_password(stack: Stack, browser: Browser) -> None:
    """The README's answer to a lost password with no mail relay: a new one
    set from the server. The old one stops working and the new one signs in.
    Then it is set back, so the rest of the run signs in as before."""
    other = "smoke-other-" + os.urandom(6).hex()
    done = stack.compose("exec", "-T", "controlplane", "python", "-m",
                         "app.users_cli", "passwd", ACCOUNT,
                         input=other + "\n", check=False)
    say(done.returncode == 0, "a new password is set from the command line")
    say(not sign_in(browser), "the old password no longer signs in")
    say(sign_in(browser, other), "the new one does")
    back = stack.compose("exec", "-T", "controlplane", "python", "-m",
                         "app.users_cli", "passwd", ACCOUNT,
                         input=PASSWORD + "\n", check=False)
    say(back.returncode == 0 and sign_in(browser),
        "and set back, the first one signs in again")


def check_restore(stack: Stack, browser: Browser, workdir: Path) -> None:
    snapshots = stack.compose("exec", "-T", "worker", "ls",
                              "/var/backups/whichports").stdout.split()
    if not say(bool(snapshots), "a snapshot exists to restore"):
        return
    # Off the machine, as the README says to keep a copy, and the restore is
    # from that copy on standard input, so what comes back made the trip.
    pulled = workdir / "pulled"
    stack.compose("cp", "worker:/var/backups/whichports", str(pulled))
    copy = pulled / snapshots[-1]
    say(copy.is_file() and opens_as_a_database(copy),
        "the snapshots copy off the machine, and the copy opens as a database")
    before = stack.host_names()
    status, _ = add_server(browser, "after-the-backup")
    say(status == 201, "a server added after the backup")
    stack.compose("stop")
    done = stack.compose("run", "--rm", "--no-deps", "-T", "worker", "python",
                         "selfhost/restore.py", "-", check=False,
                         input=copy.read_bytes())
    say(done.returncode == 0, "restore from the copy on standard input, exit"
        f" {done.returncode}" + ("" if done.returncode == 0
                                 else f": {done.stderr.strip()}"))
    stack.compose("up", "-d", "--wait", timeout=300)
    say(stack.host_names() == before,
        "after it the servers are the ones in the backup")
    # And once more by name, from the volume, the ordinary case.
    status, _ = add_server(browser, "after-the-backup-again")
    stack.compose("stop")
    done = stack.compose("run", "--rm", "--no-deps", "-T", "worker", "python",
                         "selfhost/restore.py", snapshots[-1], check=False)
    say(done.returncode == 0, f"restore.py exit {done.returncode}"
        + ("" if done.returncode == 0 else f": {done.stderr.strip()}"))
    stack.compose("up", "-d", "--wait", timeout=300)
    say(stack.host_names() == before,
        "after the restore the servers are the ones in the backup")
    left = stack.compose("exec", "-T", "worker", "ls", "-A",
                         "/var/lib/whichports-controlplane").stdout.split()
    say(not [n for n in left if n.startswith(".restore-")],
        "the restore left no work file behind")
    say(wait_for(lambda: browser.get("/")[0] == 200, 30),
        "the session from before the restore opens the dashboard")


def check_restarts(stack: Stack, browser: Browser) -> None:
    def restarts() -> int:
        cid = stack.compose("ps", "-q", "controlplane").stdout.strip()
        return int(run(["docker", "inspect", "-f", "{{.RestartCount}}",
                        cid]).stdout.strip())

    before = restarts()
    stack.py("controlplane",
             "import os, signal\n"
             "for p in os.listdir('/proc'):\n"
             "    if p.isdigit() and int(p) != os.getpid() and 'uvicorn' in"
             " open(f'/proc/{p}/cmdline').read():\n"
             "        os.kill(int(p), signal.SIGKILL)", check=False)
    say(wait_for(lambda: restarts() > before, 30),
        "the ingest was killed and the runtime restarted its container")
    say(wait_for(lambda: browser.get("/healthz")[0] == 200, 60),
        "Caddy serves it again")
    stack.compose("up", "-d", "--force-recreate", "--wait", "controlplane",
                  timeout=300)
    say(wait_for(lambda: browser.get("/healthz")[0] == 200, 60),
        "after recreating the control plane, Caddy serves it again")


def check_own_proxy(stack: Stack, before: set, ports: dict) -> None:
    stack.compose("rm", "-s", "-f", "caddy")
    after = wait_listeners(lambda now: not {p for _a, p in now - before}
                           & {ports["https"]})
    check_sockets(before, after, ports, caddy=False)
    direct = Browser(f"http://127.0.0.1:{ports['ingest']}")
    status, _ = direct.ask({"path": "/login", "headers": {
        "X-Forwarded-For": "192.88.99.7", "X-Forwarded-Proto": "https"}})[0]
    say(status == 200, f"a proxy on the machine reaches the ingest on"
        f" loopback, {status}")


def wait_listeners(settled, seconds: float = 20) -> set:
    deadline = time.monotonic() + seconds
    now = listeners()
    while not settled(now) and time.monotonic() < deadline:
        time.sleep(1)
        now = listeners()
    return now


def check_refusals_at_start(stack: Stack, ports: dict) -> None:
    done = stack.compose("run", "--rm", "--no-deps", "-T",
                         "-e", "WHICHPORTS_BASE_URL=http://whichports.example.com",
                         "controlplane", check=False, timeout=120)
    lines = [l for l in done.stderr.splitlines() if l.startswith("worker:")]
    say(done.returncode == 2 and len(lines) == 1
        and "WHICHPORTS_BASE_URL" in lines[0],
        "a malformed WHICHPORTS_BASE_URL stops the control plane at start in"
        f" one line, exit {done.returncode}")

    cut = INVITE_LINE["WHICHPORTS_PROBER_INVITE"][:-1]
    done = stack.compose("run", "--rm", "--no-deps", "-T",
                         "-e", f"WHICHPORTS_PROBER_INVITE={cut}",
                         "controlplane", check=False, timeout=120)
    lines = [l for l in done.stderr.splitlines() if l.startswith("worker:")]
    say(done.returncode == 2 and len(lines) == 1
        and "WHICHPORTS_PROBER_INVITE" in lines[0] and cut not in done.stderr,
        "an invite line cut short stops the control plane at start in one"
        f" line that does not repeat it, exit {done.returncode}")

    done = stack.compose("run", "--rm", "--no-deps", "-T",
                         "-e", f"{PRIVATE_SETTING}=true",
                         "controlplane", check=False, timeout=120)
    lines = [l for l in done.stderr.splitlines() if l.startswith("worker:")]
    say(done.returncode == 2 and len(lines) == 1
        and PRIVATE_SETTING in lines[0],
        f"a wrong value for {PRIVATE_SETTING} stops the control plane at"
        f" start in one line, exit {done.returncode}")

    # Something else holds a port: the running ingest holds its own.
    done = stack.compose("run", "--rm", "--no-deps", "-T", "controlplane",
                         check=False, timeout=120)
    said = done.stdout + done.stderr
    say(done.returncode != 0 and "address already in use" in said
        and str(ports["ingest"]) in said,
        f"a second ingest on the taken port stops at start and names it,"
        f" exit {done.returncode}")
    done = stack.compose("--profile", "caddy", "run", "--rm", "--no-deps",
                         "-T", "-e", f"WHICHPORTS_HTTPS_PORT={ports['ingest']}",
                         "caddy", check=False, timeout=120)
    said = done.stdout + done.stderr
    say(done.returncode != 0 and "address already in use" in said,
        f"Caddy on a taken port stops at start and names it,"
        f" exit {done.returncode}")


# ------------------------------------------------------------------ main

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--head", action="store_true",
                        help="the last commit rather than the working tree")
    parser.add_argument("--keep", action="store_true",
                        help="leave the stack up for a look, and say how to"
                             " take it down")
    args = parser.parse_args(argv)

    if run(["docker", "info"], check=False, timeout=60).returncode != 0:
        print("smoke: Docker is not running, so nothing was tested")
        return 1
    project = f"wpsmoke{os.getpid()}"
    workdir = Path(tempfile.mkdtemp(prefix="whichports-smoke-"))
    tree = workdir / "tree"
    tree.mkdir()
    stack = Stack(tree, project)
    try:
        stamp = clean_tree(tree, args.head)
        print(f"smoke: {project}, tree at {stamp}")
        env_example = (tree / "selfhost" / "env.example").read_text()
        # A first .env so Compose can parse and build before any port is
        # chosen: choosing one needs the image, to look at the machine's
        # network from inside it.
        (tree / "selfhost" / ".env").write_text(
            re.sub(r"(?m)^WHICHPORTS_DOMAIN=.*$", "WHICHPORTS_DOMAIN=localhost",
                   env_example) + f"WHICHPORTS_COMMIT={stamp}\n")

        print("1. the Compose file")
        check_config(stack)

        print("2. build")
        started = time.monotonic()
        stack.compose("--profile", "caddy", "build", timeout=1800)
        say(True, f"built in {time.monotonic() - started:.0f}s")

        before = listeners()
        taken = {port for _address, port in before}
        free = [p for p in random.sample(range(20000, 60000), 50)
                if p not in taken][:2]
        ports = dict(zip(("https", "ingest"), free))
        env_text = re.sub(r"(?m)^WHICHPORTS_DOMAIN=.*$",
                          "WHICHPORTS_DOMAIN=localhost", env_example)
        for key, name in (("https", "HTTPS"), ("ingest", "INGEST")):
            env_text = re.sub(rf"(?m)^WHICHPORTS_{name}_PORT=.*$",
                              f"WHICHPORTS_{name}_PORT={ports[key]}", env_text)
        (tree / "selfhost" / ".env").write_text(
            env_text + f"WHICHPORTS_COMMIT={stamp}\n")
        print(f"smoke: ports {ports}")

        print("3. up")
        stack.compose("up", "-d", "--wait", timeout=300)
        say(True, "healthy")
        for c in stack.containers():
            name = c["Config"]["Labels"].get("com.docker.compose.service", "?")
            health = (c["State"].get("Health") or {}).get("Status", "none")
            say(health == ("none" if name == "worker" else "healthy"),
                f"{name} reads {health}")

        print("4. hardening")
        check_hardening(stack)

        print("5. the sockets it opened")
        after = wait_listeners(lambda now: {ports["https"], ports["ingest"]}
                               <= {p for _a, p in now})
        check_sockets(before, after, ports, caddy=True)

        print("6. packages")
        check_packages(stack, tree)

        print("7. through Caddy")
        root = stack.compose("exec", "-T", "caddy", "cat",
                             "/data/caddy/pki/authorities/local/root.crt").stdout
        browser = Browser(f"https://localhost:{ports['https']}", root)
        for path, want in (("/healthz", 200), ("/login", 200),
                           ("/fonts/WorkSans-400.woff2", 200),
                           ("/favicon.svg", 200), ("/metrics", 404)):
            status, _ = browser.get(path)
            say(status == want, f"{path} answers {status}, wants {want}")
        check_font_caching(browser)
        # Our own landing page's form posts here. An instance serves the same
        # code and must never take anybody's address (app/betasignup.py).
        status, _ = browser.ask({
            "path": "/api/v1/beta-signup",
            "data": json.dumps({"email": "nobody@example.org"}),
            "headers": {"Content-Type": "application/json"}})[0]
        say(status == 404, f"the beta signup route is off on an instance,"
            f" {status}")

        print("8. an account, the dashboard, Add server")
        made = stack.compose("exec", "-T", "controlplane", "python", "-m",
                             "app.users_cli", "--create-database", "add",
                             ACCOUNT, input=PASSWORD + "\n", check=False)
        say(made.returncode == 0, "an account is made from the command line")
        say(sign_in(browser), "it signs in")
        status, page = browser.get("/")
        say(status == 200, f"the dashboard renders, {status}")
        say(f"built {stamp}," in page, f"its footer names {stamp}")
        status, body = add_server(browser, "smoke-server")
        command = body.get("install_command", "")
        say(status == 201 and " --server=https://localhost " in command
            and "app.whichports.com" not in command
            and command.startswith("curl -fsSL https://get.whichports.com/"),
            "Add server enrols to this instance and installs from ours")
        check_lost_password(stack, browser)

        print("9. the worker")
        check_worker(stack)

        print("10. a restore")
        check_restore(stack, browser, workdir)

        print("11. a crash, and the upgrade path")
        check_restarts(stack, browser)

        print("12. without Caddy")
        check_own_proxy(stack, before, ports)

        print("13. refusals at start")
        check_refusals_at_start(stack, ports)
    except Exception as exc:  # noqa: BLE001, a run that broke is reported, then torn down
        say(False, f"the run stopped: {exc}")
    finally:
        if args.keep:
            print(f"left up. Take it down with:\n  docker compose -p {project}"
                  f" -f {tree}/selfhost/compose.yaml --profile caddy down -v")
        else:
            print("14. down")

            def left(kind, *extra) -> list:
                return run(["docker", kind, "ls", "-q", *extra, "--filter",
                            f"label=com.docker.compose.project={project}"]
                           ).stdout.split()

            # The README's two ways of taking it off the server. Plain down
            # keeps the data, down -v deletes it.
            stack.compose("--profile", "caddy", "down", "--remove-orphans",
                          check=False, timeout=300)
            say(not left("container", "-a") and len(left("volume")) == 5,
                "down removes the containers and keeps the five volumes")
            stack.compose("--profile", "caddy", "down", "-v",
                          "--remove-orphans", check=False, timeout=300)
            say(not left("container", "-a") + left("volume") + left("network"),
                "down -v deletes them, and nothing of the project is left")
            shutil.rmtree(workdir, ignore_errors=True)
    print()
    if failures:
        print(f"SMOKE FAILED, {len(failures)} checks:")
        for what in failures:
            print(f"  {what}")
        return 1
    print("SMOKE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
