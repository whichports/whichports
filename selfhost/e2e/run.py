"""The prober API, end to end, on one machine, with every refusal shown.

    python3 selfhost/e2e/run.py            the working tree
    python3 selfhost/e2e/run.py --head     the last commit
    python3 selfhost/e2e/run.py --keep     leave it up to look at

`docs/PRODUCT.md` 5g says how the API behaves. This runs all of it for real:
a self-hosted instance with ApiTransport set, a second control plane playing
our side with the API routes and the worker, a vantage it drives over ssh, and
two servers each running the agent. `compose.yaml` beside this file says what
each container is and the two things that differ from the product.

What is shown, in order:

  1. Our side issues the instance its two keys, and names its vantage.
  2. The instance's worker takes our vantage list through the API by
     itself, on its own schedule, with nobody running a command.
  3. The agent runs once on each server, as its own user with NET_ADMIN and
     NET_RAW and nothing else. On server A it reports to the instance and
     sends its presence to our API. Server B was enrolled without the proof
     key, so it reports to the instance and proves nothing to us.
  4. A pass on the instance, through the API: server A's ports are measured
     on both families, server B's come back not tested, no_authorization,
     because nobody proved that address to us. Each server also reports
     Docker's own resolver, listening on 127.0.0.11, and from outside that
     port is refused, which is the right answer for a loopback listener.
  5. The abuse-log command names the instance, the vantage and the proof for
     server A's address, and has nothing for server B's.
  6. An unknown key is refused, by the API directly and in a pass.
  7. A revoke on the instance stops the probe of that address at once: the
     next pass does not send it, while the other family is still measured.
  8. A batch is queued while our worker is stopped, the instance is revoked,
     the worker starts, and the batch is never sent: no new ssh session
     reaches the vantage. Every proof the instance made has ended.
  9. The revoked key gets the same refusal as the unknown one, and the agent
     still exits 0, because presence can never fail its run.

**What stands in for what.** No address here is public, and SI-6 proves only
addresses that are. The network is numbered from 192.88.99.0/24 (RFC 7526)
and 2001:20:0:1::/64 (RFC 7343), which `authz.normalise_target` accepts
unchanged and which route to nobody, on a Docker network nothing leaves. The
production rule is not touched and learns nothing about those ranges.

It needs Docker, and Go to build the agent for this machine's Linux. Keys are
made per run, live in the run's temporary directory and its containers, and
are never printed.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import smoke  # noqa: E402  (the clean tree, `say`, `run` and `wait_for`)

say, run, wait_for, failures = smoke.say, smoke.run, smoke.wait_for, smoke.failures

# What the build reads: everything smoke.py copies, the CVE check's two unit
# files the product image carries among them, and the agent, which this run
# builds from source. selfhost/test_static.py holds every path the two
# Dockerfiles copy to this list and smoke.py's to a part of it.
TREE = ("controlplane", "site", "selfhost", "ops/cve/whichports-cve.service",
        "ops/cve/whichports-cve.timer", "agent")

VANTAGE = "probe-e2e"
VANTAGE_V4, VANTAGE_V6 = "192.88.99.30", "2001:20:0:1::30"
A_V4, A_V6 = "192.88.99.40", "2001:20:0:1::40"
B_V4, B_V6 = "192.88.99.50", "2001:20:0:1::50"
DATABASE = "/var/lib/whichports-controlplane/whichports.db"
PASSWORD = "e2e-only-" + os.urandom(6).hex()
PASS = ["python", "selfhost/worker.py", "once", "whichports-probe-fast.service"]
# The agent as its unit starts it: its own user, two ambient capabilities,
# a bounding set of the same two, and no new privileges
# (agent/packaging/systemd/whichports-agent.service).
AS_THE_AGENT = ["setpriv", "--reuid=whichports-agent",
                "--regid=whichports-agent", "--init-groups",
                "--inh-caps=+net_admin,+net_raw",
                "--ambient-caps=+net_admin,+net_raw",
                "--bounding-set=-all,+net_admin,+net_raw", "--no-new-privs"]
NET_ADMIN_AND_NET_RAW = (1 << 12) | (1 << 13)


def mask(text: str) -> str:
    """Whatever a command printed, with every key and credential cut to its
    prefix. Nothing this script prints can be used."""
    return re.sub(r"\b(whp[ipa]?_)[0-9A-Za-z_-]{8,}", r"\1...", text)


def show(text: str) -> None:
    for line in mask(text).strip().splitlines():
        print(f"      | {line}", flush=True)


class Stack:
    def __init__(self, tree: Path, project: str):
        self.tree, self.project = tree, project
        self.file = str(tree / "selfhost" / "e2e" / "compose.yaml")

    def compose(self, *args, check=True, timeout=600, input=None):
        return run(["docker", "compose", "-p", self.project, "-f", self.file,
                    *args], cwd=self.tree, check=check, timeout=timeout,
                   input=input)

    def exec(self, service, *argv, check=True, input=None, user=None,
             env=None, timeout=900):
        extra = []
        if user:
            extra += ["-u", user]
        for key, value in (env or {}).items():
            extra += ["-e", f"{key}={value}"]
        return self.compose("exec", "-T", *extra, service, *argv, check=check,
                            input=input, timeout=timeout)

    def sql(self, service, query, python="python"):
        code = ("import json, sqlite3, sys\n"
                f"con = sqlite3.connect('file:{DATABASE}?mode=ro', uri=True)\n"
                "con.row_factory = sqlite3.Row\n"
                "print(json.dumps([dict(r) for r in con.execute(sys.argv[1])]))")
        return json.loads(self.exec(service, python, "-c", code, query).stdout)

    def write(self, service, path, text, user=None, mode=0o644,
              python="python"):
        code = ("import os, sys\n"
                "open(sys.argv[1], 'w').write(sys.stdin.read())\n"
                "os.chmod(sys.argv[1], int(sys.argv[2]))")
        self.exec(service, python, "-c", code, path, str(mode), input=text,
                  user=user)

    def logs(self, service) -> str:
        return self.compose("logs", "--no-color", service).stdout


def latest_results(stack: Stack) -> list:
    return stack.sql("instance", """
        SELECT h.name AS host, r.target, r.family, r.port, r.state, r.reason,
               pr.vantage
        FROM probe_results r
        JOIN probe_runs pr ON pr.id = r.run_id
        JOIN hosts h ON h.id = pr.host_id
        WHERE pr.id IN (SELECT MAX(id) FROM probe_runs GROUP BY host_id)
        ORDER BY h.name, r.family, r.port""")


def print_results(rows) -> None:
    for r in rows:
        reason = f" {r['reason']}" if r["reason"] else ""
        print(f"      | {r['host']:9} {r['family']} {r['target']:16}"
              f" port {r['port']:<5} {r['state']}{reason}  from {r['vantage']}")


def states(rows, host, family) -> set:
    return {(r["port"], r["state"], r["reason"]) for r in rows
            if r["host"] == host and r["family"] == family}


def measured(rows, host, family) -> bool:
    """80 and 8080 answered, and the one other socket the agent reports,
    Docker's own resolver on 127.0.0.11, refused: it is bound to loopback, so
    from outside nothing is listening there. Measured 2026-10-01: every
    container on a user-defined network has that listener, on a port Docker
    picks."""
    found = states(rows, host, family)
    answered = {(80, "connect_succeeded", None), (8080, "connect_succeeded", None)}
    others = found - answered
    return answered <= found and len(others) == 1 \
        and all(state == "connect_refused" for _port, state, _reason in others)


def refused_unproved(rows, host, family) -> bool:
    found = states(rows, host, family)
    return len(found) == 3 and all(
        (state, reason) == ("not_tested", "no_authorization")
        for _port, state, reason in found)


def ssh_sessions(stack: Stack) -> int:
    return stack.logs("vantage").count("Accepted publickey for prober")


def log_rows(stack: Stack) -> dict:
    return {r["target"]: r["batches"] for r in stack.sql(
        "ours", "SELECT target, SUM(batches) AS batches FROM prober_api_log"
                " GROUP BY target")}


def api(stack: Stack, path: str, key: str | None):
    """One GET to our API from the instance's side, returning (status, body)."""
    code = ("import json, sys, urllib.error, urllib.request\n"
            "headers = {'Authorization': 'Bearer ' + sys.argv[2]}"
            " if len(sys.argv) > 2 else {}\n"
            "request = urllib.request.Request(sys.argv[1], headers=headers)\n"
            "try:\n"
            "    with urllib.request.urlopen(request, timeout=30) as r:\n"
            "        print(json.dumps([r.status, r.read().decode()]))\n"
            "except urllib.error.HTTPError as exc:\n"
            "    print(json.dumps([exc.code, exc.read().decode()]))")
    argv = ["python", "-c", code, "https://ours.internal" + path]
    if key is not None:
        argv.append(key)
    status, body = json.loads(stack.exec("instance-worker", *argv).stdout)
    return status, body


def build_agent(tree: Path) -> None:
    arch = run(["docker", "info", "--format", "{{.Architecture}}"]).stdout.strip()
    goarch = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64",
              "amd64": "amd64"}.get(arch)
    if goarch is None:
        raise RuntimeError(f"Docker runs on {arch}, which this does not build for")
    out = tree / "selfhost" / "e2e" / "build" / "whichports-agent"
    out.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": goarch}
    run(["go", "build", "-trimpath", "-o", str(out), "./cmd/agent"],
        cwd=tree / "agent", env=env, timeout=900)
    say(out.is_file(), f"the agent built from agent/ for linux/{goarch}")


# ------------------------------------------------------------------ steps

def bring_up_our_side(stack: Stack) -> tuple[str, str]:
    stack.compose("up", "-d", "ours", "ours-caddy", "vantage", timeout=300)
    say(wait_for(lambda: stack.exec(
        "ours", "python", "-c",
        "import urllib.request; urllib.request.urlopen("
        "'http://127.0.0.1:8410/healthz', timeout=3)", check=False).returncode == 0,
        60), "our side's ingest answers on its own loopback")
    stack.exec("ours", "python", "-m", "app.users_cli", "--create-database",
               "add", "ops@example.com", input=PASSWORD + "\n")
    added = stack.exec("ours", "python", "-m", "app.vantages_cli", "add",
                       "--name", VANTAGE, "--via", f"prober@{VANTAGE_V4}",
                       "--address", VANTAGE_V4, "--address", VANTAGE_V6)
    show(added.stdout)
    issued = stack.exec("ours", "python", "-m", "app.instances_cli", "add",
                        "--name", "e2e")
    show(issued.stdout)
    api_key = re.search(r"whpi_[0-9a-f]{64}", issued.stdout)
    proof_key = re.search(r"whpp_[0-9a-f]{64}", issued.stdout)
    say(bool(api_key and proof_key),
        "instances_cli add printed an API key and a proof key")
    # Started now that its database exists. The worker refuses to run
    # against a database that is not there, and on the box its unit restarts
    # it until one is.
    stack.compose("up", "-d", "ours-worker", timeout=300)
    return api_key.group(0), proof_key.group(0)


def give_the_worker_its_ssh(stack: Stack) -> None:
    """What the prober's deploy and a first ssh by hand do on the real box:
    the control plane's key in the prober user's authorized_keys, and the
    prober's host key in the control plane's known_hosts."""
    stack.exec("ours-worker", "ssh-keygen", "-q", "-t", "ed25519", "-N", "",
               "-f", "/e2e/home/.ssh/id_ed25519")
    public = stack.exec("ours-worker", "cat",
                        "/e2e/home/.ssh/id_ed25519.pub").stdout
    stack.write("vantage", "/home/prober/.ssh/authorized_keys", public,
                user="prober", mode=0o600, python="python3")
    host_key = stack.exec("vantage", "cat",
                          "/etc/ssh/ssh_host_ed25519_key.pub").stdout.split()
    stack.write("ours-worker", "/e2e/home/.ssh/known_hosts",
                f"{VANTAGE_V4} {host_key[0]} {host_key[1]}\n")
    # The check the deploy script makes: the runner is there and refuses a
    # batch that is not one.
    done = stack.exec("ours-worker", "ssh", "-o", "BatchMode=yes", "-o",
                      "StrictHostKeyChecking=yes", f"prober@{VANTAGE_V4}",
                      "--", "env", "PYTHONPATH=/opt/whichports", "python3",
                      "-m", "app.probe_runner", input="{}", check=False)
    say(done.returncode == 2,
        f"over ssh the runner on the vantage refuses an unusable batch, exit"
        f" {done.returncode}")


def bring_up_the_instance(stack: Stack, api_key: str, proof_key: str) -> None:
    (stack.tree / "selfhost" / "e2e" / "instance.env").write_text(
        "WHICHPORTS_PROBER_API=https://ours.internal\n"
        f"WHICHPORTS_PROBER_API_KEY={api_key}\n"
        f"WHICHPORTS_PROBER_PROOF_KEY={proof_key}\n")
    stack.compose("up", "-d", "instance", "instance-caddy", "instance-worker",
                  "target-a", "target-b", timeout=300)
    roots = []
    for caddy in ("ours-caddy", "instance-caddy"):
        path = "/data/caddy/pki/authorities/local/root.crt"
        wait_for(lambda: stack.exec(caddy, "test", "-s", path,
                                    check=False).returncode == 0, 60)
        roots.append(stack.exec(caddy, "cat", path).stdout)
    stack.write("target-a", "/e2e/roots/roots.pem", "".join(roots),
                python="python3")
    say(len(roots) == 2 and all("BEGIN CERTIFICATE" in r for r in roots),
        "both Caddys made their own authority, and the two roots are what"
        " the test's clients trust")
    stack.exec("instance", "python", "-m", "app.users_cli",
               "--create-database", "add", "you@example.com",
               input=PASSWORD + "\n")


def take_the_vantage_list(stack: Stack) -> None:
    """The product's own scheduler, started as the worker container starts
    it, and left alone until it has taken our prober list. Nobody runs
    `vantages_cli sync-api`. It is stopped again before its first sweep and
    pass, three and four minutes in, so they cannot land in the middle of a
    step below."""
    stack.compose("up", "-d", "instance-scheduler", timeout=300)
    try:
        began = time.monotonic()
        took = wait_for(lambda: "vantages-sync: exited"
                        in stack.logs("instance-scheduler"), 150)
        logs = stack.logs("instance-scheduler")
        show("\n".join(line.split("|", 1)[-1].strip()
                       for line in logs.splitlines() if "vantages" in line))
        say(took and "vantages-sync: exited 0" in logs
            and f"added {VANTAGE}" in logs,
            f"the worker took our prober list unasked,"
            f" {time.monotonic() - began:.0f}s after it started")
    finally:
        stack.compose("rm", "-s", "-f", "instance-scheduler", check=False)
    listed = stack.exec("instance", "python", "-m", "app.vantages_cli", "list")
    say(VANTAGE in listed.stdout, f"the instance's registry names {VANTAGE}")
    again = stack.exec("instance-worker", "python", "selfhost/worker.py",
                       "once", "whichports-vantages-sync.service", check=False)
    say(again.returncode == 0 and "nothing changed" in again.stdout,
        "asked for by name it runs at once, and finds nothing to change")


def run_the_agent(stack: Stack, service: str, credential: str,
                  proof_key: str | None) -> None:
    argv = ["whichports-agent", "enroll", "--server=https://instance.internal",
            f"--credential={credential}"]
    if proof_key:
        argv += ["--prober-server=https://ours.internal",
                 f"--prober-proof-key={proof_key}"]
    enrolled = stack.exec(service, *argv)
    show(enrolled.stdout)
    status = stack.exec(service, *AS_THE_AGENT, "python3", "-c",
                        "import os; print(os.getuid(), open("
                        "'/proc/self/status').read())").stdout
    uid = int(status.split()[0])
    caps = {name: int(value, 16) for name, value in
            re.findall(r"(Cap\w+):\s+([0-9a-f]+)", status)}
    new_privs = re.search(r"NoNewPrivs:\s+(\d)", status)
    say(uid != 0 and all(caps[k] == NET_ADMIN_AND_NET_RAW for k in
                         ("CapEff", "CapPrm", "CapAmb", "CapBnd"))
        and new_privs and new_privs.group(1) == "1",
        f"{service}: the agent's process is uid {uid} with NET_ADMIN and"
        f" NET_RAW only (effective {caps['CapEff']:#x}, bounding"
        f" {caps['CapBnd']:#x}), no new privileges")
    done = stack.exec(service, *AS_THE_AGENT, "/usr/local/bin/whichports-agent",
                      "--mode=oneshot", check=False)
    if done.stdout.strip() or done.stderr.strip():
        show(done.stdout + done.stderr)
    say(done.returncode == 0, f"{service}: whichports-agent --mode=oneshot"
        f" exit {done.returncode}")


def proofs(stack: Stack, service: str) -> list:
    """Every authorisation a registry holds, asked through `app.authz` like
    everything else. No file but that module reads its tables, and a test in
    the control plane's suite holds this script to that too."""
    code = ("import json, sqlite3\n"
            "from app import authz\n"
            f"con = sqlite3.connect('file:{DATABASE}?mode=ro', uri=True)\n"
            "con.row_factory = sqlite3.Row\n"
            "print(json.dumps(sorted(({k: r[k] for k in ('target', 'family',"
            " 'method', 'account', 'revoked_at')} for r in"
            " authz.list_authorizations(con)), key=lambda r: r['target'])))")
    return json.loads(stack.exec(service, "python", "-c", code).stdout)


def print_proofs(rows) -> None:
    for r in rows:
        state = f"revoked {r['revoked_at']}" if r["revoked_at"] else "live"
        print(f"      | {r['target']:18} {r['family']} by {r['method']},"
              f" account {r['account']}, {state}")
    if not rows:
        print("      | none")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--head", action="store_true")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args(argv)
    if run(["docker", "info"], check=False, timeout=60).returncode != 0:
        print("e2e: Docker is not running, so nothing was tested")
        return 1
    if not shutil.which("go"):
        print("e2e: Go is not on PATH, and the agent has to be built")
        return 1

    project = f"wpe2e{os.getpid()}"
    workdir = Path(tempfile.mkdtemp(prefix="whichports-e2e-"))
    tree = workdir / "tree"
    tree.mkdir()
    stack = Stack(tree, project)
    background = None
    try:
        smoke.TREE = TREE
        stamp = smoke.clean_tree(tree, args.head)
        print(f"e2e: {project}, tree at {stamp}")
        (tree / "selfhost" / "e2e" / "instance.env").write_text("")
        (tree / "selfhost" / ".env").write_text(
            "WHICHPORTS_DOMAIN=unused.internal\nCOMPOSE_PROFILES=caddy\n")

        print("0. build")
        build_agent(tree)
        run(["docker", "compose", "-p", project + "build", "-f",
             str(tree / "selfhost" / "compose.yaml"), "--profile", "caddy",
             "build"], cwd=tree, timeout=1800)
        stack.compose("build", timeout=1800)
        say(True, "the product's two images and the three test images built")

        print("1. our side: keys and a vantage")
        api_key, proof_key = bring_up_our_side(stack)
        give_the_worker_its_ssh(stack)

        print("2. the instance's worker takes our vantage list by itself")
        bring_up_the_instance(stack, api_key, proof_key)
        take_the_vantage_list(stack)

        print("3. the agent, on two servers")
        credentials = {}
        for name in ("target-a", "target-b"):
            added = stack.exec("instance", "python", "-m", "app.hosts_cli",
                               "add", name)
            credentials[name] = re.search(r"^\s+(whp_\S+)\s*$", added.stdout,
                                          re.M).group(1)
        run_the_agent(stack, "target-a", credentials["target-a"], proof_key)
        run_the_agent(stack, "target-b", credentials["target-b"], None)
        reported = stack.sql("instance", "SELECT name, last_report_at FROM hosts"
                                         " ORDER BY name")
        say(len(reported) == 2 and all(r["last_report_at"] for r in reported),
            "both servers' reports reached the instance: "
            + ", ".join(r["name"] for r in reported))
        print("    the instance's own registry:")
        on_instance = proofs(stack, "instance")
        print_proofs(on_instance)
        say({r["target"] for r in on_instance} == {A_V4, A_V6, B_V4, B_V6},
            "the instance holds a proof for both addresses of both servers")
        print("    our registry:")
        on_ours = proofs(stack, "ours")
        print_proofs(on_ours)
        say({r["target"] for r in on_ours} == {A_V4, A_V6}
            and all(r["account"] != "default" for r in on_ours),
            "ours holds proofs for server A's two addresses only, under the"
            " instance's own account")

        print("4. a pass on the instance, through the API")
        sessions = ssh_sessions(stack)
        done = stack.exec("instance-worker", *PASS, check=False)
        show(done.stdout + done.stderr)
        rows = latest_results(stack)
        print_results(rows)
        for family in ("v4", "v6"):
            say(measured(rows, "target-a", family),
                f"server A, {family}: 80 and 8080 answered, and Docker's"
                " loopback resolver port refused")
            say(refused_unproved(rows, "target-b", family),
                f"server B, {family}: every port not tested, no_authorization")
        say(all(r["vantage"] == VANTAGE for r in rows),
            f"every row was measured from {VANTAGE}")
        say(ssh_sessions(stack) > sessions,
            "our worker reached the vantage over ssh for it")

        print("5. the abuse-log command, on our side")
        for address, expect in ((A_V4, True), (B_V4, False)):
            logged = stack.exec("ours", "python", "-m", "app.instances_cli",
                                "log", "--address", address)
            show(logged.stdout)
            if expect:
                say(f"from {VANTAGE}" in logged.stdout
                    and "proof  e2e" in logged.stdout,
                    f"{address}: the instance, the vantage and the proof")
            else:
                say("no instance asked for" in logged.stdout,
                    f"{address}: nothing, because no batch could reach it")

        print("6. an unknown key")
        made_up = "whpi_" + os.urandom(32).hex()
        for label, key in (("no key", None), ("a key nobody issued", made_up)):
            status, body = api(stack, "/api/v1/prober/vantages", key)
            say(status == 401 and json.loads(body) == {"error": "unknown_key"},
                f"{label}: {status} {body.strip()}")
        status, _body = api(stack, "/api/v1/prober/vantages", api_key)
        say(status == 200, f"the instance's own key: {status}")
        before = len(stack.sql("instance", "SELECT id FROM probe_runs"))
        done = stack.exec("instance-worker", *PASS, check=False,
                          env={"WHICHPORTS_PROBER_API_KEY": made_up})
        show(done.stdout + done.stderr)
        say(done.returncode != 0 and "unknown_key" in done.stdout + done.stderr
            and len(stack.sql("instance", "SELECT id FROM probe_runs")) == before,
            f"a pass with it stops, names the class, and stores nothing,"
            f" exit {done.returncode}")

        print("7. a revoke on the instance")
        logged_before = log_rows(stack)
        revoked = stack.exec("instance", "python", "-m", "app.authz_cli",
                             "revoke", A_V4)
        show(revoked.stdout)
        done = stack.exec("instance-worker", *PASS, check=False)
        rows = latest_results(stack)
        print_results([r for r in rows if r["host"] == "target-a"])
        say(refused_unproved(rows, "target-a", "v4"),
            "server A, v4: not tested, no_authorization, on the very next pass")
        say(measured(rows, "target-a", "v6"), "server A, v6: still measured")
        logged_after = log_rows(stack)
        say(logged_after.get(A_V4) == logged_before.get(A_V4)
            and logged_after.get(A_V6, 0) > logged_before.get(A_V6, 0),
            f"our log: no further batch could reach {A_V4}"
            f" ({logged_before.get(A_V4)} before, {logged_after.get(A_V4)}"
            f" after), {A_V6} went from {logged_before.get(A_V6)} to"
            f" {logged_after.get(A_V6)}")

        print("8. the instance is revoked with a batch waiting")
        stack.compose("stop", "ours-worker")
        sessions = ssh_sessions(stack)
        background = subprocess.Popen(
            ["docker", "compose", "-p", project, "-f", stack.file, "exec",
             "-T", "instance-worker", *PASS], cwd=tree,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        queued = wait_for(lambda: bool(stack.sql(
            "ours", "SELECT id FROM prober_api_batches WHERE started_at IS NULL")),
            60)
        say(queued, "a batch from the instance is queued on our side, our"
            " worker stopped")
        ended = stack.exec("ours", "python", "-m", "app.instances_cli",
                           "revoke", "--name", "e2e")
        show(ended.stdout)
        stack.compose("start", "ours-worker")
        say(wait_for(lambda: "dropped" in stack.logs("ours-worker"), 60),
            "our worker dropped it: " + next(
                (l.split("|", 1)[-1].strip() for l in
                 stack.logs("ours-worker").splitlines() if "dropped" in l),
                "no line"))
        out, _ = background.communicate(timeout=300)
        code, background = background.returncode, None
        show(out)
        say(code != 0 and "unknown_key" in out,
            f"the instance's pass ended on the refusal, exit {code}")
        say(ssh_sessions(stack) == sessions,
            f"no new ssh session reached the vantage ({sessions} before and"
            " after)")
        say(not stack.sql("ours", "SELECT id FROM prober_api_batches"),
            "nothing of the batch is left on our side")
        print("    our registry:")
        on_ours = proofs(stack, "ours")
        print_proofs(on_ours)
        say(on_ours and all(r["revoked_at"] for r in on_ours),
            "every proof the instance made has ended")

        print("9. the revoked key")
        status, body = api(stack, "/api/v1/prober/vantages", api_key)
        say(status == 401 and json.loads(body) == {"error": "unknown_key"},
            f"the same refusal as a key nobody issued: {status} {body.strip()}")
        done = stack.exec("instance-worker", *PASS, check=False)
        say(done.returncode != 0 and "unknown_key" in done.stdout + done.stderr,
            f"a pass with it stops, exit {done.returncode}")
        done = stack.exec("target-a", *AS_THE_AGENT,
                          "/usr/local/bin/whichports-agent", "--mode=oneshot",
                          check=False)
        say(done.returncode == 0, "the agent on server A still runs and"
            f" exits {done.returncode}, with its proof key dead")
        on_ours = proofs(stack, "ours")
        say(all(r["revoked_at"] for r in on_ours),
            "and proved nothing new to us")
    except Exception as exc:  # noqa: BLE001, reported, then torn down
        say(False, f"the run stopped: {mask(str(exc))}")
    finally:
        if background is not None:
            background.kill()
        if args.keep:
            print(f"left up. Take it down with:\n  docker compose -p {project}"
                  f" -f {stack.file} down -v")
        else:
            print("10. down")
            stack.compose("down", "-v", "--remove-orphans", check=False,
                          timeout=300)
            left = [run(["docker", kind, "ls", "-q", *extra, "--filter",
                         f"label=com.docker.compose.project={project}"]).stdout
                    for kind, extra in (("container", ["-a"]), ("volume", []),
                                        ("network", []))]
            say(not "".join(left).strip(), "nothing of the project is left")
            shutil.rmtree(workdir, ignore_errors=True)
    print()
    if failures:
        print(f"E2E FAILED, {len(failures)} checks:")
        for what in failures:
            print(f"  {mask(what)}")
        return 1
    print("E2E PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
