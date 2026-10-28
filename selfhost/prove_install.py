"""The self-hosted installer, run for real in a plain container of one system.

    python3 selfhost/prove_install.py ubuntu:26.04
    python3 selfhost/prove_install.py ubuntu:26.04 debian:13 almalinux:10 fedora:44 ubuntu:24.04

For each image, in this order:

  1. A plain container of that image starts on this machine's own network,
     the way a server's programs share its network, with this machine's
     Docker socket mounted, so the Docker and Compose commands inside it
     drive this machine's Docker engine, the way selfhost/smoke.py drives it
     from outside. It is not privileged and gets no capability. In it: the
     packages selfhost/README.md names for that system, curl and sudo, which
     a server has and the image has not, and a user `tester` who may use sudo
     without a password.
  2. The last commit is put in it as a git repository with a tag, and the
     installer as the publish would serve it: release_installer.stamp with
     that tag and commit. `tester` runs the line on a terminal, piped from
     curl into sudo, as the README gives it, with two differences. The
     repository the script clones: `sudo env WHICHPORTS_REPOSITORY=<that
     repository> sh`, because the public repository is not this commit. And
     curl reads the script from a file, without the line's --proto '=https',
     which refuses file:// (checked here). The questions are answered on the
     terminal and the plan with a yes. The domain ends in `.internal`, so
     Caddy takes its certificate from its own authority and no authority is
     asked. The invite's keys were never issued and its host is
     `prober.invalid`, so the instance asks nobody for our probers.
  3. Before the install, a program holding 443: the line stops before asking.
  4. The install, read back from the stack: the script's exit and its last
     lines, the plan naming the probers' host, the terminal holding no
     password, `.env` in /opt/whichports mode 600 holding the answers, the
     three containers up and Caddy healthy, the sockets on the machine's
     network (443 and the ingest on 127.0.0.1, nothing on 80), a sign-in
     through Caddy with that password, the commit in the dashboard's footer,
     and Add server's line carrying the proof key and not the API key.
  5. The same line again: exit 0, `.env` untouched, no second account.
  6. The line without sudo: it is refused, and nothing changes.
  7. A file of /opt/whichports given to `tester`, then a local edit: each
     stops the line before anything is asked, and is put back.
  8. Caddy stopped, a program holding 443, and the line again: the stack's
     own folder skips the port check, Caddy cannot start, and the line ends
     1 with no "running".
  9. Down with its volumes, and the container removed.

What this does not prove: the system's own Docker engine. The engine is the
one on this machine, whichever system the commands come from. So it proves
the script, the system's shell, its sudo, its git and its Docker and Compose
commands, on this machine's architecture.

Every command here is an argv array, but for the fixed set-up lines a
container's own shell runs. The password is made up for the run.
"""
import argparse
import json
import os
import pty
import re
import secrets
import select
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(HERE))
import release_installer  # noqa: E402

DOMAIN = "proof.whichports.internal"
EMAIL = "proof@example.com"
API_KEY = "whpi_" + "0" * 64
PROOF_KEY = "whpp_" + "1" * 64
INVITE = f"whpinvite1_prober.invalid_{API_KEY}_{PROOF_KEY}"
PROMPTS = ("Go on?", "Your domain", "Your invite", "An email address",
           "A password for it", "The same password again")
IMAGE = "whichports-controlplane:local"
PYTHON = "/srv/controlplane/.venv/bin/python"
INSTALL_DIR = "/opt/whichports"
SELFHOST = f"{INSTALL_DIR}/selfhost"
HOLDER = "whichports-prove-install-holds-443"

# What each system installs, from selfhost/README.md: the distribution's own
# packages where it names them, and Docker's repository where it does not.
# Only Docker's command line and its Compose plugin: the engine is this
# machine's. Then curl and sudo.
APT_DOCKER_REPO = [
    "apt-get install -y ca-certificates curl",
    "install -m 0755 -d /etc/apt/keyrings",
    "curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc",
    'echo "deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu'
    ' $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list',
    "apt-get update",
]
SYSTEMS = {
    "ubuntu:26.04": ["apt-get update",
                     "apt-get install -y docker.io docker-compose-v2 docker-buildx git",
                     "apt-get install -y curl sudo"],
    "debian:13": ["apt-get update",
                  "apt-get install -y docker.io docker-cli docker-compose git",
                  "apt-get install -y curl sudo"],
    "ubuntu:24.04": ["apt-get update", *APT_DOCKER_REPO,
                     "apt-get install -y docker-ce-cli docker-compose-plugin git sudo"],
    "almalinux:10": ["dnf -y install dnf-plugins-core",
                     "dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo",
                     "dnf -y install docker-ce-cli docker-compose-plugin git sudo"],
    "fedora:44": ["dnf -y install dnf5-plugins",
                  "dnf config-manager addrepo --from-repofile=https://download.docker.com/linux/fedora/docker-ce.repo",
                  "dnf -y install docker-ce-cli docker-compose-plugin git sudo"],
}

failures = []


def say(ok: bool, what: str) -> bool:
    print(f"  {'ok  ' if ok else 'FAIL'} {what}", flush=True)
    if not ok:
        failures.append(what)
    return ok


def run(argv, *, check=True, timeout=900, input=None):
    done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                          input=input)
    if check and done.returncode != 0:
        raise RuntimeError(f"{' '.join(argv[:6])} ... exited {done.returncode}:\n"
                           f"{done.stdout[-1500:]}\n{done.stderr[-1500:]}")
    return done


class Box:
    """One container of one system."""

    def __init__(self, image: str):
        self.image = image
        self.name = "whichports-prove-install-" + re.sub(r"[^a-z0-9]", "-", image)

    def sh(self, text: str, *, user="root", check=True, timeout=900):
        """One fixed line of this file's own, run by the container's shell.
        Never a value from outside: the set-up lines above and paths."""
        return run(["docker", "exec", "-u", user, self.name, "sh", "-c", text],
                   check=check, timeout=timeout)

    def start(self) -> None:
        run(["docker", "rm", "-f", self.name], check=False)
        run(["docker", "run", "-d", "--name", self.name, "--network", "host",
             "-v", "/var/run/docker.sock:/var/run/docker.sock",
             "--entrypoint", "sleep", self.image, "infinity"])
        for line in SYSTEMS[self.image]:
            self.sh(("DEBIAN_FRONTEND=noninteractive " if "apt-get" in line else "") + line)
        self.sh("useradd -m -s /bin/sh tester")
        self.sh("mkdir -p /etc/sudoers.d && echo 'tester ALL=(ALL) NOPASSWD: ALL'"
                " > /etc/sudoers.d/tester && chmod 440 /etc/sudoers.d/tester")

    def versions(self) -> str:
        found = self.sh("sh -c 'docker --version; docker compose version --short;"
                        " git --version; sudo --version | head -1; ls -l /bin/sh'",
                        check=False)
        return " | ".join(found.stdout.strip().splitlines())

    def put_the_release(self) -> str:
        """The last commit as a bare repository at /srv/repo.git with a tag,
        and at /srv/selfhost.sh the installer stamped with that tag and its
        commit, as the publish would serve it. Returns the commit."""
        commit = run(["git", "-C", str(REPO), "rev-parse", "HEAD"]).stdout.strip()
        tag = "proof-" + commit[:12]
        with tempfile.TemporaryDirectory() as folder:
            bundle = Path(folder) / "repo.bundle"
            run(["git", "-C", str(REPO), "bundle", "create", str(bundle), "HEAD"])
            run(["docker", "cp", str(bundle), f"{self.name}:/srv/repo.bundle"])
        self.sh("git clone -q --bare /srv/repo.bundle /srv/repo.git")
        run(["docker", "exec", self.name, "git", "-C", "/srv/repo.git", "-c",
             "user.name=proof", "-c", "user.email=proof@example.com",
             "tag", "-a", tag, "-m", "the release under proof", commit])
        script = run(["git", "-C", str(REPO), "show", "HEAD:selfhost/install.sh"]).stdout
        stamped = release_installer.stamp(script, tag, commit)
        run(["docker", "exec", "-i", self.name, "sh", "-c", "cat > /srv/selfhost.sh"],
            input=stamped)
        return commit

    def remove(self) -> None:
        hold(False)
        self.sh(f"test -d {SELFHOST} && docker compose -f {SELFHOST}/compose.yaml"
                " down -v --remove-orphans", check=False, timeout=300)
        run(["docker", "rm", "-f", self.name], check=False)


def hold(on: bool) -> None:
    """A program on this machine's network holding 443, or none."""
    run(["docker", "rm", "-f", HOLDER], check=False)
    if on:
        run(["docker", "run", "-d", "--name", HOLDER, "--network", "host",
             "alpine:latest", "nc", "-lk", "-p", "443", "-e", "/bin/cat"])
        time.sleep(1)


def on_a_terminal(argv, answers, timeout=900) -> tuple:
    """Run argv on a pseudo terminal of this machine, the way a person runs
    the line in ssh, and answer each question as it comes. Returns the exit
    code and everything the terminal showed."""
    pid, master = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    pending, shown, asked = list(answers), b"", 0
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.2)
        if ready:
            try:
                data = os.read(master, 65536)
            except OSError:
                break
            if not data:
                break
            shown += data
        text = shown.decode("utf-8", "replace")
        now = sum(text.count(p) for p in PROMPTS)
        while asked < now:
            asked += 1
            # The echo goes off a moment after the question is shown on the
            # far side. A person types later than that.
            time.sleep(0.3)
            os.write(master, (pending.pop(0) if pending else "\x04").encode() + b"\r")
    else:
        os.kill(pid, 9)
    _, status = os.waitpid(pid, 0)
    os.close(master)
    return os.waitstatus_to_exitcode(status), shown.decode("utf-8", "replace")


def the_line(box: Box, *, sudo=True) -> list:
    """The install line as the README gives it, as `tester` in his home."""
    if sudo:
        line = ("curl -fsSL file:///srv/selfhost.sh | sudo env"
                " WHICHPORTS_REPOSITORY=/srv/repo.git sh")
    else:
        line = "curl -fsSL file:///srv/selfhost.sh | sh"
    return ["docker", "exec", "-it", "-u", "tester", "-w", "/home/tester",
            box.name, "sh", "-c", line]


def show_tail(shown: str) -> None:
    """The script's last lines, up to its own last one: Docker's command
    line on this machine may add a note of its own after the exec ends."""
    lines = [line for line in shown.replace("\r", "").splitlines() if line.strip()]
    ends = [i for i, line in enumerate(lines) if "on that server." in line]
    end = ends[-1] if ends else len(lines) - 1
    for line in lines[max(0, end - 5):end + 1]:
        print(f"       | {line}")


# A small program run on the machine's own network, as selfhost/smoke.py
# does: the sockets there, and a sign-in through Caddy.
CHECK = r'''
import ipaddress, json, os, re, ssl, urllib.error, urllib.parse, urllib.request
args = json.loads(os.environ["PROVE_ARGS"])
found = []
for name in ("/proc/net/tcp", "/proc/net/tcp6"):
    for line in list(open(name))[1:]:
        f = line.split()
        if f[3] == "0A":
            raw, port = f[1].rsplit(":", 1)
            data = bytes.fromhex(raw)
            words = b"".join(data[i:i + 4][::-1] for i in range(0, len(data), 4))
            found.append([str(ipaddress.ip_address(words)), int(port, 16)])
out = {"listening": sorted(found)}
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None
context = ssl.create_default_context(cadata=args["root"])
opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))
base = "https://" + args["domain"]
cookies = {}
def ask(path, data=None, headers=None):
    headers = dict(headers or {})
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    request = urllib.request.Request(base + path, data=data, headers=headers)
    try:
        response = opener.open(request, timeout=30)
    except urllib.error.HTTPError as exc:
        response = exc
    for value in response.headers.get_all("Set-Cookie") or []:
        name, _, rest = value.partition("=")
        cookies[name.strip()] = rest.split(";", 1)[0]
    return response.status, response.read().decode("utf-8", "replace")
status, page = ask("/login")
csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
form = urllib.parse.urlencode({"csrf": csrf, "next": "/", "email": args["email"],
                               "password": args["password"]}).encode()
out["sign_in"] = ask("/login", form, {"Content-Type": "application/x-www-form-urlencoded"})[0]
status, page = ask("/")
footer = re.search(r"built ([0-9a-f]{12})", page)
out["dashboard"] = status
out["footer"] = footer.group(1) if footer else ""
status, body = ask("/api/admin/hosts", json.dumps({"name": "proof-server"}).encode(),
                   {"Content-Type": "application/json"})
out["add_server"] = status
out["install_command"] = json.loads(body).get("install_command", "") if status == 201 else body[:300]
try:
    urllib.request.urlopen("http://" + args["domain"] + "/", timeout=5)
    out["http_80"] = "answered"
except Exception as exc:
    out["http_80"] = type(exc).__name__ + ": " + str(exc)[:80]
print(json.dumps(out))
'''


def compose(box: Box, *args, check=True):
    return run(["docker", "exec", "-u", "root", box.name, "docker", "compose",
                "-f", f"{SELFHOST}/compose.yaml", *args], check=check, timeout=600)


def through_caddy(box: Box, password: str) -> dict:
    root = compose(box, "exec", "-T", "caddy", "cat",
                   "/data/caddy/pki/authorities/local/root.crt").stdout
    return json.loads(run(["docker", "run", "--rm", "--network", "host",
                           "--add-host", f"{DOMAIN}:127.0.0.1",
                           "-e", "PROVE_ARGS=" + json.dumps({
                               "root": root, "domain": DOMAIN, "email": EMAIL,
                               "password": password}),
                           "--entrypoint", PYTHON, IMAGE, "-c", CHECK]).stdout)


def answers(password: str) -> list:
    return [DOMAIN, INVITE, EMAIL, password, password, "yes"]


def refused_before_asking(box: Box, what: str, words: str) -> None:
    code, shown = on_a_terminal(the_line(box), [])
    if not say(code == 2 and words in shown and "Nothing was changed." in shown
               and "Your domain" not in shown, f"{what}: refused before asking, exit {code}"):
        print(shown[-1500:])


def prove(image: str) -> None:
    print(f"\n== {image}", flush=True)
    box = Box(image)
    try:
        box.start()
        print(f"  {box.versions()}")
        commit = box.put_the_release()
        password = "Prove-" + secrets.token_hex(6) + "-1"

        flags = box.sh("curl --proto '=https' --tlsv1.2 -fsS file:///srv/selfhost.sh",
                       user="tester", check=False)
        say(flags.returncode != 0 and "file" in flags.stderr.lower(),
            f"curl with the line's flags refuses file://: {flags.stderr.strip()[:80]}")

        print("  443 held by another program")
        hold(True)
        refused_before_asking(box, "443 held", "Port 443 is held by another program")
        hold(False)

        print("  the line, as tester, through sudo")
        started = time.monotonic()
        code, shown = on_a_terminal(the_line(box), answers(password))
        show_tail(shown)
        say(code == 0, f"the line ended 0 in {time.monotonic() - started:.0f}s, exit {code}")
        say("with our probers at prober.invalid" in shown and "Go on?" in shown,
            "the plan named the probers' host and asked to go on")
        say(password not in shown, "the terminal never showed the password")
        say("whichports is running." in shown, "it said whichports is running")

        env = box.sh(f"stat -c '%a %U' {SELFHOST}/.env").stdout.split()
        say(env == ["600", "root"], f".env is mode 600 and root's: {env}")
        owners = box.sh(f"find {INSTALL_DIR} ! -user root -print | head -3").stdout.strip()
        say(owners == "", f"every file of {INSTALL_DIR} is root's {owners}")
        lines = box.sh("grep -E '^(WHICHPORTS_DOMAIN|WHICHPORTS_HTTPS_PORT|WHICHPORTS_PROBER_[A-Z_]+)='"
                       f" {SELFHOST}/.env").stdout.split()
        say(lines == [f"WHICHPORTS_DOMAIN={DOMAIN}", "WHICHPORTS_HTTPS_PORT=443",
                      f"WHICHPORTS_PROBER_INVITE={INVITE}", "WHICHPORTS_PROBER_API=",
                      "WHICHPORTS_PROBER_API_KEY=", "WHICHPORTS_PROBER_PROOF_KEY="],
            f".env holds the answers and 443: {len(lines)} lines")

        states = [json.loads(line) for line in
                  compose(box, "ps", "--format", "json").stdout.splitlines() if line.strip()]
        said = {s["Service"]: (s["State"], s.get("Health", "")) for s in states}
        say(said == {"controlplane": ("running", "healthy"), "caddy": ("running", "healthy"),
                     "worker": ("running", "")}, f"the stack: {said}")

        checked = through_caddy(box, password)
        ports = sorted({port for _a, port in checked["listening"]})
        say(443 in ports and 80 not in ports,
            f"listening on the machine's network: 443 yes, 80 no ({ports})")
        say(["127.0.0.1", 8410] in checked["listening"]
            and not [a for a, p in checked["listening"] if p == 8410 and a != "127.0.0.1"],
            "the ingest on 127.0.0.1:8410 only")
        say("Connection refused" in checked["http_80"],
            f"http:// gets no answer: {checked['http_80']}")
        say(checked["sign_in"] == 303 and checked["dashboard"] == 200,
            f"signed in through Caddy with that password: {checked['sign_in']}, {checked['dashboard']}")
        say(checked["footer"] == commit[:12],
            f"the footer names {checked['footer']}, the commit is {commit[:12]}")
        command = checked["install_command"]
        say(checked["add_server"] == 201 and f"--prober-proof-key={PROOF_KEY}" in command
            and "--prober-server=https://prober.invalid" in command
            and "whpi_" not in command and "whpinvite1_" not in command,
            "Add server's line carries the proof key, and not the API key or the invite")
        ingest = compose(box, "exec", "-T", "controlplane", "python", "-c",
                         "import os\n"
                         "for p in os.listdir('/proc'):\n"
                         "    if p.isdigit() and p != str(os.getpid())"
                         " and 'uvicorn' in open(f'/proc/{p}/cmdline').read():\n"
                         "        e = open(f'/proc/{p}/environ').read().split('\\0')\n"
                         "        print(sorted(x.split('=')[0] for x in e if 'PROBER' in x))\n"
                         "        break\n").stdout.strip()
        say(ingest == "['WHICHPORTS_PROBER_API', 'WHICHPORTS_PROBER_API_KEY',"
                      " 'WHICHPORTS_PROBER_PROOF_KEY']",
            f"the ingest got the three settings and not the line: {ingest}")
        logs = compose(box, "logs", "--no-color").stdout
        say(password not in logs and API_KEY not in logs,
            "the stack's logs hold neither the password nor the API key")
        left = run(["docker", "exec", box.name, "grep", "-rlF", "-e", password,
                    "/home/tester", "/root", "/tmp", "/var/tmp", "/srv", INSTALL_DIR],
                   check=False).stdout.strip()
        say(left == "", f"no file in the container holds the password {left}")

        print("  the same line again")
        before = box.sh(f"stat -c '%Y %s' {SELFHOST}/.env").stdout
        code, shown = on_a_terminal(the_line(box), answers(password))
        after = box.sh(f"stat -c '%Y %s' {SELFHOST}/.env").stdout
        say(code == 0 and "left as it is" in shown and "is there already" in shown
            and before == after, f"exit {code}, .env and the account left as they were")
        accounts = compose(box, "exec", "-T", "controlplane", "python", "-m",
                           "app.users_cli", "list").stdout.split()
        say(accounts.count(EMAIL) == 1, "one account")

        print("  the line without sudo")
        code, shown = on_a_terminal(the_line(box, sudo=False), [])
        say(code == 2 and "This installer runs as root" in shown and "Nothing was changed." in shown,
            f"refused as tester, nothing changed, exit {code}")

        print("  a file of tester's, then a local edit, in the install folder")
        box.sh(f"chown tester {SELFHOST}/compose.yaml")
        refused_before_asking(box, "a file of tester's", "Not root's, or writable by others:")
        box.sh(f"chown root {SELFHOST}/compose.yaml")
        box.sh(f"echo '# an edit' >> {SELFHOST}/compose.yaml")
        refused_before_asking(box, "a local edit", "git sees these in")
        box.sh(f"git -C {INSTALL_DIR} checkout -- selfhost/compose.yaml")
        clean = box.sh(f"git -C {INSTALL_DIR} status --porcelain").stdout.strip()
        say(clean == "", "put back, git sees nothing")

        print("  Caddy stopped, 443 held, and the line again")
        compose(box, "stop", "caddy")
        hold(True)
        started = time.monotonic()
        code, shown = on_a_terminal(the_line(box), answers(password))
        took = time.monotonic() - started
        hold(False)
        # The script's own last lines: Docker's command line on this
        # machine adds a note of its own after the exec ends.
        script_lines = shown.replace("\r", "").split("What's next")[0].splitlines()
        ended = [line for line in script_lines if line.strip()][-4:]
        if not say(code == 1 and "whichports is running." not in shown
                   and "No account was made." in shown,
                   f"it ended 1 after {took:.0f}s and never said running"):
            print(shown[-2500:])
        for line in ended:
            print(f"       | {line}")
    except Exception as exc:  # noqa: BLE001, a run that broke is reported, then removed
        say(False, f"the run stopped: {exc}")
    finally:
        box.remove()
        left = run(["docker", "ps", "-a", "-q", "--filter", f"name={box.name}"]).stdout.strip()
        volumes = run(["docker", "volume", "ls", "-q", "--filter",
                       "label=com.docker.compose.project=whichports"]).stdout.strip()
        say(not left and not volumes, "the container and the stack's volumes are gone")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("images", nargs="+", choices=sorted(SYSTEMS))
    args = parser.parse_args(argv)
    if run(["docker", "info"], check=False, timeout=60).returncode != 0:
        print("prove_install: Docker is not running, so nothing was tested")
        return 1
    taken = run(["docker", "compose", "ls", "-a", "--format", "json"]).stdout
    if any(p.get("Name") == "whichports" for p in json.loads(taken or "[]")):
        print("prove_install: a stack named whichports is on this Docker already,"
              " and the install would take it over. Nothing was tested.")
        return 1
    for image in args.images:
        prove(image)
    print()
    if failures:
        print(f"PROVE FAILED, {len(failures)} checks:")
        for what in failures:
            print(f"  {what}")
        return 1
    print("PROVE PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
