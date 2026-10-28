"""selfhost/install.sh, run for real with a stand-in for Docker.

The script is piped into a real shell, as `curl ... | sh` does, and answers
its questions on a real pseudo terminal, so the echo, the prompts and the
reading from /dev/tty are the shell's and the terminal's own. git is the real
one, cloning a repository made here. Docker is a stand-in that writes down
every call: its words, its folder, its environment and, for the account, a
hash of what came in on standard input. It checks the password and the mail
address with the control plane's own functions.

Each test runs the script with dash and with bash, the two shells `sh` is
on the systems the README names: dash on Ubuntu and Debian, bash on AlmaLinux
and Fedora. Its PATH holds links to exactly the programs the script may use
and the stand-in, so a script that starts to use another program fails here
first.

The script runs as root and installs to /opt/whichports. Here it runs as the
user running the tests, so two of its constant lines are changed in the text
that is piped, and nothing else: INSTALL_DIR names a folder under the test's
own, ROOT_UID is this user's id, and PROC_NET names a folder holding the
test's own copies of the kernel's tcp and tcp6 tables. Each change must match
its line once. `sleep` is a stand-in that writes down how long it was asked
to wait and returns at once.
Its two release lines are filled in by selfhost/release_installer.py, the way
the copy that is served gets them, with the test repository's tag.

The edge cases come first, the whole install after them. The real run, with
Docker on plain Ubuntu 26.04, is selfhost/prove_install.py.
"""
import fcntl
import hashlib
import json
import os
import re
import select
import shutil
import stat
import subprocess
import sys
import termios
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SCRIPT = HERE / "install.sh"
CONTROLPLANE = REPO / "controlplane"

SHELLS = [name for name in ("dash", "bash") if shutil.which(name)]
assert SHELLS, "neither dash nor bash is on this machine"

# Every program the script may start, besides docker and git.
TOOLS = ("basename", "cat", "chmod", "dirname", "find", "id", "mktemp", "mv",
         "rm", "rmdir", "sed", "stty", "tr")
# Programs the script may start that the tests replace with a stand-in.
STAND_INS = ("docker", "sleep")

# The kernel's tcp tables as /proc/net prints them: a header, then a socket
# a line. 0A is LISTEN, 01 is ESTABLISHED. 01BB is 443, 20D2 is 8410.
TCP_HEADER = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when"
              " retrnsmt   uid  timeout inode\n")


def tcp_line(address_hex: str, port: int, state: str = "0A") -> str:
    return (f"   0: {address_hex}:{port:04X} 00000000:0000 {state} 00000000:00000000"
            " 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n")

API_KEY = "whpi_" + "0123456789abcdef" * 4
PROOF_KEY = "whpp_" + "fedcba9876543210" * 4
INVITE = f"whpinvite1_app.whichports.com_{API_KEY}_{PROOF_KEY}"
DOMAIN = "whichports.example.com"
EMAIL = "you@example.com"
PASSWORD = "a long one, 12+ chars"
COMMIT_RE = re.compile(r"^[0-9a-f]{12}$")
TAG = "v0.0.1-test"

PROMPTS = ("Go on?", "Your domain", "Your invite", "An email address",
           "A password for it", "The same password again")


# ------------------------------------------------------- the stand-in Docker

FAKE_DOCKER = r'''
import hashlib, json, os, sys
from pathlib import Path

scenario = json.loads(Path(os.environ["FAKE_SCENARIO"]).read_text())
state_path = Path(os.environ["FAKE_STATE"])
state = json.loads(state_path.read_text()) if state_path.exists() else {
    "database": False, "accounts": []}
args = sys.argv[1:]
call = {"argv": args, "cwd": os.getcwd(), "env": dict(os.environ)}
# compose -f FILE: the file is written down, and the words after it are the
# call, the way Compose reads them.
if args[:2] == ["compose", "-f"]:
    call["compose_file"] = args[2]
    args = ["compose"] + args[3:]
    call["argv"] = args
if args[:2] == ["compose", "up"] or args[:2] == ["compose", "build"]:
    env_file = Path(call["compose_file"]).parent / ".env"
    call["env_file_mode"] = (oct(env_file.stat().st_mode & 0o777)
                             if env_file.exists() else None)


def done(code, out="", err=""):
    with open(os.environ["FAKE_LOG"], "a") as log:
        log.write(json.dumps(call) + "\n")
    state_path.write_text(json.dumps(state))
    sys.stdout.write(out)
    sys.stderr.write(err)
    sys.exit(code)


CONTAINERS = {"c1": "controlplane", "c2": "worker", "c3": "caddy"}


def states(cid):
    """One container's state as the installer's format prints it. The
    scenario makes one of them not run, not be healthy, or restart."""
    service = CONTAINERS[cid]
    status, health, restarts = "running", ("none" if service == "worker" else "healthy"), 0
    bad = scenario.get("after_up", {}).get(service)
    if bad == "restarting":
        status, health = "restarting", "starting"
    elif bad == "exited":
        status, health = "exited", "unhealthy"
    elif bad == "unhealthy":
        health = "unhealthy"
    elif bad == "restarts":
        state["inspections"] = state.get("inspections", 0) + 1
        restarts = state["inspections"]
    return f"/whichports-{service}-1 {status} {health} {restarts}"


if args[:1] == ["ps"] and "label=com.docker.compose.project=whichports" in args:
    if scenario.get("foreign_project"):
        done(0, "f00\n")
    done(0, "".join(c + "\n" for c in CONTAINERS) if state.get("up") else "")
if args[:1] == ["inspect"] and "com.docker.compose.project.working_dir" in args[2]:
    if args[3] == "f00":
        done(0, scenario["foreign_project"] + "\n")
    done(0, state["workdir"] + "\n")
if args[:1] == ["inspect"] and ".RestartCount" in args[2]:
    done(0, states(args[3]) + "\n")
if args == ["info", "--format", "{{.ServerVersion}}"]:
    refused = ("permission denied while trying to connect to the docker"
               " API at unix:///var/run/docker.sock\n")
    if scenario.get("daemon", True) is False:
        done(1, err=refused)
    if scenario.get("daemon") == "refused but exit 0":
        # Debian 13's docker 26.1.5, measured: an empty line, the refusal
        # on standard error, and exit 0.
        done(0, "\n", refused)
    done(0, "29.8.2\n")
if args[:1] != ["compose"]:
    done(64, err=f"the stand-in knows no such call: {args}\n")
if not scenario.get("compose", True):
    done(1, err="docker: unknown command: docker compose\n")
words = args[1:]
if words == ["version", "--short"]:
    done(0, "2.40.3\n")
if words == ["build"]:
    if scenario.get("build") == "fail":
        done(1, err="failed to solve: process did not complete successfully\n")
    done(0, "built\n")
if words == ["up", "-d", "--wait", "--wait-timeout", "180"]:
    if scenario.get("up") == "unhealthy":
        done(1, err="container whichports-controlplane-1 is unhealthy\n")
    state["up"] = True
    state["workdir"] = str(Path(call["compose_file"]).parent)
    done(0, "Container whichports-controlplane-1  Healthy\n")
if words == ["ps", "-a", "-q"]:
    done(0, "".join(c + "\n" for c in CONTAINERS) if state.get("up") else "")
CLI = ["exec", "-T", "controlplane", "python", "-m", "app.users_cli"]
if words[:6] == CLI:
    rest = words[6:]
    if rest == ["list"]:
        if not state["database"]:
            done(1, err="refusing to work on a database that is not there\n")
        done(0, "".join(f"{a:32} active    workspace: 1\n" for a in state["accounts"]))
    create = rest[:1] == ["--create-database"]
    rest = rest[1:] if create else rest
    if rest[:2] == ["add", "--"] and len(rest) == 3:
        password = sys.stdin.readline().rstrip("\n")
        call["stdin_sha256"] = hashlib.sha256(password.encode()).hexdigest()
        sys.path.insert(0, os.environ["FAKE_CONTROLPLANE"])
        from app import accounts
        email = rest[2]
        if not state["database"] and not create:
            done(1, err="refusing to work on a database that is not there\n")
        state["database"] = True
        try:
            if not accounts.valid_email(accounts.normalize_email(email)):
                raise accounts.AccountError("That does not look like an email address.")
            accounts.check_password_shape(password)
            if accounts.normalize_email(email) in state["accounts"]:
                raise accounts.AccountError("An account with that email already exists.")
        except accounts.AccountError as exc:
            done(1, err=f"could not add {email}: {exc}\n")
        state["accounts"].append(accounts.normalize_email(email))
        done(0, f"account {accounts.normalize_email(email)} created\n")
done(64, err=f"the stand-in knows no such call: {args}\n")
'''


# ------------------------------------------------------------ the fixtures

def git(*args, cwd):
    subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=t@example.com",
                    "-c", "init.defaultBranch=main", *args], cwd=cwd, check=True,
                   capture_output=True)


@pytest.fixture(scope="module")
def repository(tmp_path_factory) -> Path:
    """A repository holding the two files of selfhost/ the script reads and
    the repository's own .gitignore, which keeps .env out of git, as they
    are in this checkout, and one commit."""
    source = tmp_path_factory.mktemp("source")
    (source / "selfhost").mkdir()
    for name in ("compose.yaml", "env.example"):
        shutil.copy(HERE / name, source / "selfhost" / name)
    shutil.copy(REPO / ".gitignore", source / ".gitignore")
    git("init", "-q", cwd=source)
    git("add", ".", cwd=source)
    git("commit", "-q", "-m", "the two files", cwd=source)
    git("tag", "-a", TAG, "-m", "the release", cwd=source)
    return source


def tag_commit(repository: Path, tag: str) -> str:
    return subprocess.run(["git", "-C", str(repository), "rev-parse", f"{tag}^{{commit}}"],
                          capture_output=True, text=True, check=True).stdout.strip()


class World:
    """A home folder to run the script in, a bin folder for its PATH, and
    what the stand-in wrote down."""

    def __init__(self, root: Path, repository: Path, shell: str):
        self.root = root
        self.home = root / "home"
        self.home.mkdir()
        # The stand-in for /opt: the folder the install folder is made in.
        self.opt = root / "opt"
        self.opt.mkdir()
        self.opt.chmod(0o755)
        self.uid = os.getuid()
        # The release the script names: the tag, and its commit unless a
        # test names another.
        self.tag = TAG
        self.commit = None
        self.bin = root / "bin"
        self.bin.mkdir()
        self.shell = shutil.which(shell)
        self.repository = repository
        self.scenario = {}
        self.log = root / "docker-calls.jsonl"
        self.state = root / "docker-state.json"
        for tool in TOOLS + ("git",):
            (self.bin / tool).symlink_to(shutil.which(tool))
        docker = self.bin / "docker"
        docker.write_text(f"#!{sys.executable}\n{FAKE_DOCKER}")
        docker.chmod(0o755)
        self.slept = root / "slept"
        sleep = self.bin / "sleep"
        sleep.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$1\" >> {self.slept}\n")
        sleep.chmod(0o755)
        # The kernel's tables, with nothing listening on 443 or 8410.
        self.proc = root / "proc-net"
        self.proc.mkdir()
        self.listen()

    def listen(self, *lines: str, six: tuple = ()) -> None:
        """What the tcp and tcp6 tables say is listening: an ssh on 22 by
        default, and the lines given."""
        (self.proc / "tcp").write_text(TCP_HEADER + tcp_line("00000000", 22) + "".join(lines))
        (self.proc / "tcp6").write_text(TCP_HEADER + "".join(six))

    def without(self, tool: str) -> None:
        (self.bin / tool).unlink()

    def calls(self) -> list:
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def compose_calls(self) -> list:
        return [c["argv"][1:] for c in self.calls() if c["argv"][:1] == ["compose"]]

    def checkout(self) -> Path:
        return self.opt / "whichports"

    def script(self) -> bytes:
        """The script as served, with its two constants pointed at this
        test: the install folder under the test's own, and this user."""
        text = SCRIPT.read_text()
        for old, new in (("INSTALL_DIR=/opt/whichports\n", f"INSTALL_DIR={self.checkout()}\n"),
                         ("ROOT_UID=0\n", f"ROOT_UID={self.uid}\n"),
                         ("PROC_NET=/proc/net\n", f"PROC_NET={self.proc}\n")):
            assert text.count(old) == 1, old
            text = text.replace(old, new)
        if self.tag is not None:
            commit = self.commit or tag_commit(self.repository, self.tag)
            text = release_installer.stamp(text, self.tag, commit)
        return text.encode()

    def run(self, answers, *, cwd=None, terminal=True, timeout=60):
        scenario = self.root / "scenario.json"
        scenario.write_text(json.dumps(self.scenario))
        env = {"PATH": str(self.bin), "HOME": str(self.home),
               "WHICHPORTS_REPOSITORY": str(self.repository),
               "FAKE_SCENARIO": str(scenario), "FAKE_LOG": str(self.log),
               "FAKE_STATE": str(self.state),
               "FAKE_CONTROLPLANE": str(CONTROLPLANE)}
        return run_on_a_terminal(self.shell, env, cwd or self.home, answers,
                                 terminal=terminal, timeout=timeout,
                                 script=self.script())


@pytest.fixture(params=SHELLS)
def world(request, tmp_path, repository) -> World:
    return World(tmp_path, repository, request.param)


class Ran:
    def __init__(self, code, out, err, tty):
        self.code, self.out, self.err, self.tty = code, out, err, tty

    @property
    def said(self) -> str:
        return self.out + self.err


def run_on_a_terminal(shell, env, cwd, answers, *, terminal, timeout, script) -> Ran:
    """Pipe the script into `shell`, with a pseudo terminal as its
    controlling terminal, and answer each question as it is asked. A
    question asked after the answers have run out gets an end of file, the
    way a person pressing Ctrl-D would."""
    master, slave = os.openpty()

    def take_the_terminal():
        if terminal:
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    process = subprocess.Popen(
        [shell], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, cwd=cwd, env=env, start_new_session=True,
        preexec_fn=take_the_terminal, pass_fds=(slave,))
    os.close(slave)
    process.stdin.write(script)
    process.stdin.close()
    pending = list(answers)
    got = {"tty": b"", "out": b"", "err": b""}
    asked = 0
    streams = {master: "tty", process.stdout.fileno(): "out",
               process.stderr.fileno(): "err"}
    deadline = time.monotonic() + timeout
    while True:
        if time.monotonic() > deadline:
            process.kill()
            process.wait(10)
            raise AssertionError(f"the script did not end within {timeout}s: {got}")
        ready, _, _ = select.select(list(streams), [], [], 0.1)
        for fd in ready:
            try:
                data = os.read(fd, 65536)
            except OSError:
                data = b""
            if data:
                got[streams[fd]] += data
            else:
                del streams[fd]
        text = got["tty"].decode("utf-8", "replace")
        now_asked = sum(text.count(prompt) for prompt in PROMPTS)
        while asked < now_asked:
            asked += 1
            if pending:
                os.write(master, pending.pop(0).encode() + b"\n")
            else:
                os.write(master, b"\x04")
        # Standard output and error close when the shell and every program
        # it started have ended.
        if process.poll() is not None and list(streams) in ([master], []):
            break
    process.wait(10)
    os.close(master)
    out, err, tty = got["out"], got["err"], got["tty"]
    return Ran(process.returncode, out.decode("utf-8", "replace"),
               err.decode("utf-8", "replace"), tty.decode("utf-8", "replace"))


GOOD = [DOMAIN, INVITE, EMAIL, PASSWORD, PASSWORD, "yes"]


def tree(folder: Path) -> dict:
    """Every file under a folder, git's own aside, with its bytes and mode."""
    if not folder.exists():
        return {}
    return {str(p.relative_to(folder)): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode))
            for p in folder.rglob("*") if p.is_file() and ".git" not in p.parts}


def assert_nothing_changed(world: World, ran: Ran, before: dict | None = None):
    assert ran.code == 2, ran.said
    assert "Nothing was changed." in ran.err
    assert tree(world.opt) == (before or {})
    assert not [p for p in world.opt.iterdir() if p.name != "whichports"], "a work folder was left"
    assert not any(c[:1] in (["build"], ["up"], ["exec"]) for c in world.compose_calls())


# ---------------------------------------------- what it needs, before asking

def test_without_a_terminal_it_asks_nothing_and_changes_nothing(world):
    ran = world.run(GOOD, terminal=False)
    assert_nothing_changed(world, ran)
    assert "needs a terminal" in ran.err
    assert ran.tty == ""


def test_without_docker_it_stops_before_asking(world):
    world.without("docker")
    ran = world.run(GOOD)
    assert_nothing_changed(world, ran)
    assert "Docker is not installed" in ran.err
    assert "sudo apt install docker.io docker-compose-v2 docker-buildx git" in ran.err
    assert ran.tty == ""


def test_without_the_compose_plugin_it_stops_before_asking(world):
    world.scenario["compose"] = False
    ran = world.run(GOOD)
    assert_nothing_changed(world, ran)
    assert "Compose plugin is not installed" in ran.err
    assert ran.tty == ""


@pytest.mark.parametrize("daemon", [False, "refused but exit 0"])
def test_when_docker_does_not_answer_it_says_what_docker_said(world, daemon):
    world.scenario["daemon"] = daemon
    ran = world.run(GOOD)
    assert_nothing_changed(world, ran)
    assert "  permission denied while trying to connect" in ran.err
    assert "Check that Docker runs" in ran.err
    assert ran.tty == ""


@pytest.mark.parametrize("held", [
    ("tcp", "00000000", 443), ("tcp", "0100007F", 443), ("tcp6", "0" * 32, 443),
    ("tcp", "0100007F", 8410),
])
def test_a_port_the_stack_needs_held_by_another_program_stops_it_before_asking(world, held):
    table, address, port = held
    if table == "tcp":
        world.listen(tcp_line(address, port))
    else:
        world.listen(six=(tcp_line(address, port),))
    ran = world.run(GOOD)
    assert_nothing_changed(world, ran)
    assert f"Port {port} is held by another program on this server" in ran.err
    assert ran.tty == ""


def test_a_port_that_is_not_listening_or_another_port_does_not_stop_it(world):
    world.listen(tcp_line("0100007F", 443, state="01"), tcp_line("00000000", 4430),
                 tcp_line("00000000", 8080))
    ran = world.run(GOOD)
    assert ran.code == 0, ran.said


def test_a_stack_named_whichports_from_another_folder_stops_it_before_asking(world):
    """Compose names the project whichports wherever it was started, so a
    stack set up by hand elsewhere would be taken over, volumes and all."""
    world.scenario["foreign_project"] = "/home/someone/whichports/selfhost"
    ran = world.run(GOOD)
    assert_nothing_changed(world, ran)
    assert "A stack named whichports is on this server already, from /home/someone/whichports/selfhost" in ran.err
    assert ran.tty == ""


def test_on_a_second_run_its_own_stack_may_hold_its_ports(world):
    install_once(world)
    world.listen(tcp_line("00000000", 443), tcp_line("0100007F", 8410))
    ran = world.run(GOOD)
    assert ran.code == 0, ran.said


@pytest.mark.parametrize("service,bad", [
    ("caddy", "restarting"), ("caddy", "exited"), ("caddy", "restarts"),
    ("controlplane", "unhealthy"), ("worker", "restarts"),
])
def test_a_service_that_does_not_stay_up_after_the_wait_stops_it(world, service, bad):
    """compose up --wait has ended 0 with Caddy restarting over and over
    (Compose 5.6.0, three runs in six, 2026-10-20). So every container's
    own state is read twice, a while apart, before anything says running."""
    world.scenario["after_up"] = {service: bad}
    ran = world.run(GOOD)
    assert ran.code == 1, ran.said
    assert "did not stay up" in ran.err
    assert f"whichports-{service}-1" in ran.err
    assert "No account was made." in ran.err
    assert not [c for c in world.compose_calls() if c[0] == "exec"]
    assert "whichports is running." not in ran.out


def test_it_waits_a_while_and_reads_every_container_twice_before_it_says_running(world):
    ran = world.run(GOOD)
    assert ran.code == 0, ran.said
    assert world.slept.read_text().split() == ["10"]
    inspected = [c["argv"][3] for c in world.calls()
                 if c["argv"][:1] == ["inspect"] and ".RestartCount" in c["argv"][2]]
    assert sorted(inspected) == ["c1", "c1", "c2", "c2", "c3", "c3"]


def test_without_git_it_stops_before_asking(world):
    world.without("git")
    ran = world.run(GOOD)
    assert_nothing_changed(world, ran)
    assert "git is not installed" in ran.err


def test_a_clone_that_fails_stops_it_without_asking_for_a_login(world):
    """A repository that is not there, or one that wants a login, ends the
    clone with git's own words. git is told not to ask at the terminal."""
    world.commit = tag_commit(world.repository, TAG)
    world.repository = world.root / "no-such-repository"
    ran = world.run(GOOD)
    assert_nothing_changed(world, ran)
    assert "The clone failed" in ran.err
    assert not world.checkout().exists()
    assert ran.tty.count("Username") == 0


def test_a_copy_that_names_no_release_installs_nothing(world):
    """The script as it is in the repository: its release lines empty."""
    world.tag = None
    ran = world.run(GOOD)
    assert_nothing_changed(world, ran)
    assert "names no release" in ran.err
    assert ran.tty == ""


def test_a_tag_that_names_another_commit_than_the_installer_is_refused(world):
    """The tag was moved where the repository lives, or another repository
    answers: the clone is removed again and nothing is built."""
    world.commit = "0" * 40
    ran = world.run(GOOD)
    assert_nothing_changed(world, ran)
    assert f"The tag {TAG} in " in ran.err and "and this installer is for commit " + "0" * 40 in ran.err
    assert not world.checkout().exists()


def test_a_tag_the_repository_does_not_have_is_refused(world):
    world.tag, world.commit = "v9.9.9", "0" * 40
    ran = world.run(GOOD)
    assert_nothing_changed(world, ran)
    assert f"The tag v9.9.9 is not in {world.repository}" in ran.err


def test_the_clone_says_nothing_of_gits_own(world):
    """A release tag is an annotated one, and git clone --branch on it
    warns that it is not a commit, then explains a detached HEAD in eleven
    lines, --quiet or not (measured 2026-10-20 on Ubuntu 26.04's git 2.53).
    A person reading the install has no use for either."""
    ran = world.run(GOOD)
    assert ran.code == 0, ran.said
    for words in ("warning:", "is not a commit", "detached HEAD", "advice."):
        assert words not in ran.said, words


def a_later_release(world: World, tmp_path: Path) -> Path:
    """A copy of the test repository with one more commit and its tag."""
    later = tmp_path / "later"
    shutil.copytree(world.repository, later)
    (later / "notes.txt").write_text("later\n")
    git("add", "notes.txt", cwd=later)
    git("commit", "-q", "-m", "later", cwd=later)
    git("tag", "-a", "v0.0.2-test", "-m", "later", cwd=later)
    return later


def test_a_folder_at_another_release_is_refused_and_named(world, tmp_path):
    install_once(world)
    world.repository = a_later_release(world, tmp_path)
    world.tag = "v0.0.2-test"
    before = tree(world.opt)
    ran = world.run(GOOD)
    assert ran.code == 2 and "Nothing was changed." in ran.err, ran.said
    assert f"is at commit {tag_commit(world.repository, TAG)}" in ran.err
    assert "this installer is for v0.0.2-test" in ran.err
    assert tree(world.opt) == before


def test_the_readmes_upgrade_of_a_one_line_install_moves_it_to_the_next_release(world, tmp_path):
    """The README's two git lines for a folder the one line made, run here
    without sudo, then the next release's installer finds it its own."""
    install_once(world)
    later = a_later_release(world, tmp_path)
    readme = (HERE / "README.md").read_text()
    lines = [l for l in readme.splitlines() if l.startswith("sudo git -C /opt/whichports ")]
    assert lines == ["sudo git -C /opt/whichports fetch --tags",
                     "sudo git -C /opt/whichports checkout <the new tag>"], lines
    checkout = world.checkout()
    subprocess.run(["git", "-C", str(checkout), "remote", "set-url", "origin", str(later)], check=True)
    subprocess.run(["git", "-C", str(checkout), "fetch", "-q", "--tags"], check=True)
    subprocess.run(["git", "-C", str(checkout), "-c", "advice.detachedHead=false",
                    "checkout", "-q", "v0.0.2-test"], check=True)
    world.repository, world.tag = later, "v0.0.2-test"
    ran = world.run(GOOD)
    assert ran.code == 0, ran.said
    assert "which an earlier run made, as it is" in ran.out


def test_an_install_folder_that_is_not_a_checkout_stops_it(world):
    (world.checkout()).mkdir()
    (world.checkout() / "notes.txt").write_text("mine")
    before = tree(world.opt)
    ran = world.run(GOOD)
    assert_nothing_changed(world, ran, before)
    assert "is not a whichports checkout" in ran.err


def test_not_as_root_it_stops_before_asking(world):
    world.uid = os.getuid() + 1
    ran = world.run(GOOD)
    assert_nothing_changed(world, ran)
    assert "This installer runs as root" in ran.err and "sudo" in ran.err
    assert ran.tty == ""


def test_an_install_folder_that_is_a_link_stops_it(world):
    elsewhere = world.root / "elsewhere"
    subprocess.run(["git", "clone", "-q", str(world.repository), str(elsewhere)], check=True)
    world.checkout().symlink_to(elsewhere)
    ran = world.run(GOOD)
    assert ran.code == 2 and "Nothing was changed." in ran.err, ran.said
    assert "is a link" in ran.err
    assert not (elsewhere / "selfhost" / ".env").exists()


def install_and_change(world: World, change) -> Ran:
    """Install, change the folder the way another user could, and run the
    line again."""
    install_once(world)
    change(world.checkout())
    before = tree(world.opt)
    calls = len(world.calls())
    ran = world.run(GOOD)
    assert ran.code == 2 and "Nothing was changed." in ran.err, ran.said
    assert tree(world.opt) == before
    assert not [c for c in world.calls()[calls:] if c["argv"][:2] in (
        ["compose", "build"], ["compose", "up"], ["compose", "exec"])]
    return ran


@pytest.mark.parametrize("what,change", [
    ("a folder a group may write", lambda d: (d / "selfhost").chmod(0o775)),
    ("a file anybody may write", lambda d: (d / "selfhost" / "compose.yaml").chmod(0o646)),
    ("the install folder itself", lambda d: d.chmod(0o757)),
])
def test_a_folder_others_may_write_stops_it(world, what, change):
    ran = install_and_change(world, change)
    assert "Not root's, or writable by others:" in ran.err, what
    assert "somebody other than root could have put there" in ran.err


def test_a_parent_folder_others_may_write_stops_it(world):
    install_once(world)
    world.opt.chmod(0o777)
    ran = world.run(GOOD)
    assert ran.code == 2 and "Nothing was changed." in ran.err, ran.said
    assert "Not root's, or writable by others:" in ran.err


def test_a_folder_owned_by_another_user_stops_it(world):
    """Here every file is this user's, so the script is told root is
    another id, and a stand-in id answers with that id: the files then
    belong to somebody other than the script's root."""
    install_once(world)
    world.uid = os.getuid() + 1
    stand_in = world.bin / "id"
    stand_in.unlink()
    stand_in.write_text(f"#!/bin/sh\necho {world.uid}\n")
    stand_in.chmod(0o755)
    before = tree(world.opt)
    ran = world.run(GOOD)
    assert ran.code == 2 and "Nothing was changed." in ran.err, ran.said
    assert "Not root's, or writable by others:" in ran.err
    assert tree(world.opt) == before


@pytest.mark.parametrize("what,change", [
    ("a local edit", lambda d: (d / "selfhost" / "compose.yaml").write_text(
        (d / "selfhost" / "compose.yaml").read_text() + "\n# mine\n")),
    ("a file git does not know", lambda d: (d / "selfhost" / "mine.sh").write_text("true\n")),
    ("a compose override", lambda d: (d / "selfhost" / "compose.override.yaml").write_text(
        "services: {}\n")),
])
def test_a_folder_git_sees_changes_in_stops_it(world, what, change):
    ran = install_and_change(world, change)
    assert "git sees these in" in ran.err, what
    assert "this installer does not build it" in ran.err


# ------------------------------------------- answers of the wrong shape

@pytest.mark.parametrize("wrong,words", [
    ("https://whichports.example.com", "without https://"),
    ("whichports.example.com/", "without https://"),
    ("localhost", "not a domain name"),
    ("203.0.113.9", "not a domain name"),
    ("which_ports.example.com", "not a domain name"),
    ("-whichports.example.com", "not a domain name"),
    ("whichports..example.com", "not a domain name"),
    ("whichports.example.com:443", "not a domain name"),
    ("", "The domain is needed"),
])
def test_a_domain_of_the_wrong_shape_is_refused_and_three_stop_it(world, wrong, words):
    ran = world.run([wrong, wrong, wrong])
    assert_nothing_changed(world, ran)
    assert ran.err.count(words) == 3, ran.err
    assert "Three answers that could not be used" in ran.err
    assert ran.tty.count("Your domain") == 3


def test_a_domain_is_asked_again_and_taken_in_lowercase(world):
    ran = world.run(["https://Which.Example.com", "Which.Example.com"] + GOOD[1:])
    assert ran.code == 0, ran.said
    assert "WHICHPORTS_DOMAIN=which.example.com\n" in (
        world.checkout() / "selfhost" / ".env").read_text()


@pytest.mark.parametrize("wrong", [
    INVITE[:-1],
    INVITE[:-40],
    INVITE[:len("whpinvite1_app.whichports.com")],
    f"whpinvite1_app.whichports.com_{PROOF_KEY}_{API_KEY}",
    INVITE + "0",
    INVITE.replace("0123", "012G", 1),
])
def test_an_invite_line_cut_short_or_changed_is_refused_and_never_repeated(world, wrong):
    ran = world.run([DOMAIN, wrong, wrong, wrong])
    assert_nothing_changed(world, ran)
    assert ran.err.count("That invite line is not whole") == 3, ran.err
    # The line holds two keys: the terminal shows what was typed, the script
    # never says it again.
    for key in (API_KEY[:40], PROOF_KEY[:40], wrong):
        assert key not in ran.out + ran.err


@pytest.mark.parametrize("old", [
    API_KEY, PROOF_KEY, "https://app.whichports.com",
    f"WHICHPORTS_PROBER_API_KEY={API_KEY}",
])
def test_an_invite_of_the_old_three_value_shape_is_named_as_such(world, old):
    ran = world.run([DOMAIN, old, old, old])
    assert_nothing_changed(world, ran)
    assert ran.err.count("an invite of the old shape") == 3, ran.err
    assert API_KEY not in ran.out + ran.err


def test_an_empty_or_strange_invite_is_refused(world):
    ran = world.run([DOMAIN, "", "hello", "whpinvite2_" + INVITE[11:]])
    assert_nothing_changed(world, ran)
    assert "The invite is needed" in ran.err
    assert ran.err.count("That is not an invite line") == 2


@pytest.mark.parametrize("wrong", [
    "you.example.com", "you@", "@example.com", "you@example", "you@@example.com",
    "you@exa mple.com", "",
])
def test_a_mail_address_without_an_at_or_a_dotted_name_is_refused(world, wrong):
    ran = world.run([DOMAIN, INVITE, wrong, wrong, wrong])
    assert_nothing_changed(world, ran)
    assert ran.err.count("That is not an email address.") == 3, ran.err


@pytest.mark.parametrize("wrong,words", [
    ("short1!", "Needs at least 12 characters."),
    ("only letters and spaces", "Needs a number."),
    ("abcdefghijk1", "Needs a special character."),
    ("abcdefghijk", "Needs at least 12 characters, a number, a special character."),
    ("", "Needs at least 12 characters, a number, a special character."),
    ("a1!" * 43, "Use at most 128 characters."),
])
def test_a_password_short_of_the_apps_rule_is_refused_in_the_apps_words(world, wrong, words):
    ran = world.run([DOMAIN, INVITE, EMAIL, wrong, wrong, wrong])
    assert_nothing_changed(world, ran)
    assert ran.err.count("  " + words + "\n") == 3, ran.err
    assert ran.tty.count("The same password again") == 0


def test_two_passwords_that_differ_are_refused(world):
    ran = world.run([DOMAIN, INVITE, EMAIL, PASSWORD, PASSWORD + "x",
                     PASSWORD, "", PASSWORD, "nope"])
    assert_nothing_changed(world, ran)
    assert ran.err.count("The two passwords differ.") == 3


def test_a_wrong_answer_is_asked_again_and_a_right_one_goes_on(world):
    ran = world.run([DOMAIN, API_KEY, INVITE, "you", EMAIL, "short", PASSWORD, PASSWORD, "yes"])
    assert ran.code == 0, ran.said
    assert "an invite of the old shape" in ran.err
    assert "That is not an email address." in ran.err
    assert "Needs" in ran.err


# ------------------------------------------------ an .env already there

def install_once(world: World) -> Ran:
    ran = world.run(GOOD)
    assert ran.code == 0, ran.said
    return ran


def test_an_env_edited_by_hand_stops_it_before_anything_changes(world):
    install_once(world)
    env_file = world.checkout() / "selfhost" / ".env"
    env_file.write_text(env_file.read_text().replace(
        "WHICHPORTS_ALERT_TO=", "WHICHPORTS_ALERT_TO=ops@example.com"))
    os.chmod(env_file, 0o640)
    before = tree(world.opt)
    calls = len(world.calls())
    ran = world.run(GOOD)
    assert ran.code == 2, ran.said
    assert "Nothing was changed." in ran.err
    assert f"{env_file} is there and holds something other than these answers" in ran.err
    assert f"mv '{env_file}' '{env_file}.before'" in ran.err
    assert tree(world.opt) == before, "the .env, its mode and every other file stay"
    assert not [c for c in world.calls()[calls:] if c["argv"][:2] in (
        ["compose", "build"], ["compose", "up"], ["compose", "exec"])]


def test_an_env_written_with_other_answers_stops_it_too(world):
    install_once(world)
    before = tree(world.opt)
    ran = world.run(["other.example.com"] + GOOD[1:])
    assert ran.code == 2 and "Nothing was changed." in ran.err, ran.said
    assert tree(world.opt) == before


def test_a_release_whose_caddy_port_is_not_443_is_refused(world, tmp_path):
    """The certificate's challenge comes to port 443, so the one line never
    installs Caddy on another port."""
    moved = tmp_path / "moved-port"
    shutil.copytree(world.repository, moved)
    example = moved / "selfhost" / "env.example"
    example.write_text(example.read_text().replace(
        "WHICHPORTS_HTTPS_PORT=443\n", "WHICHPORTS_HTTPS_PORT=8443\n"))
    git("commit", "-q", "-am", "a moved port", cwd=moved)
    git("tag", "-f", "-a", TAG, "-m", "moved", cwd=moved)
    world.repository = moved
    ran = world.run(GOOD)
    assert_nothing_changed(world, ran)
    assert "WHICHPORTS_HTTPS_PORT=443" in ran.err


def test_the_plan_and_the_env_say_443(world):
    ran = world.run(GOOD)
    assert ran.code == 0, ran.said
    assert "3. build the images, start the stack on port 443, and wait until it reads healthy" in ran.out
    env = (world.checkout() / "selfhost" / ".env").read_text().splitlines()
    assert env.count("WHICHPORTS_HTTPS_PORT=443") == 1


def test_a_release_from_before_the_invite_line_is_not_guessed_at(world, tmp_path):
    """A repository whose env.example has no invite line: the clone is
    removed again and nothing is left."""
    old = tmp_path / "old-release"
    shutil.copytree(world.repository, old)
    example = old / "selfhost" / "env.example"
    example.write_text(example.read_text().replace("WHICHPORTS_PROBER_INVITE=\n", ""))
    git("commit", "-q", "-am", "an older env.example", cwd=old)
    git("tag", "-f", "-a", TAG, "-m", "moved", cwd=old)
    world.repository = old
    ran = world.run(GOOD)
    assert_nothing_changed(world, ran)
    assert "cannot fill it in" in ran.err
    assert list(world.opt.iterdir()) == []


# ----------------------------------------------- when the stack does not come

def test_a_build_that_fails_stops_it_and_makes_no_account(world):
    world.scenario["build"] = "fail"
    ran = world.run(GOOD)
    assert ran.code == 1, ran.said
    assert "failed to solve" in ran.err
    assert "The build failed" in ran.err
    assert "Nothing was changed." not in ran.err
    assert [c[0] for c in world.compose_calls()] == ["version", "build"]


def test_a_stack_that_never_reads_healthy_stops_it_and_makes_no_account(world):
    world.scenario["up"] = "unhealthy"
    ran = world.run(GOOD)
    assert ran.code == 1, ran.said
    # Compose may give up at once, when a container exits, so the line does
    # not say a time passed that did not.
    assert "The stack did not come up healthy. Compose waits at most 180 seconds, and its own words are above." in ran.err
    assert "docker compose logs controlplane caddy" in ran.err
    assert "No account was made." in ran.err
    assert not [c for c in world.compose_calls() if c[0] == "exec"]


def test_the_control_planes_own_refusal_of_the_password_is_said_and_stops_it(world):
    """Eight characters that are fourteen bytes: the script counts bytes,
    the control plane counts characters, and the control plane decides."""
    password = "éééééé1!"
    ran = world.run([DOMAIN, INVITE, EMAIL, password, password, "yes"])
    assert ran.code == 1, ran.said
    assert "could not add you@example.com: Needs at least 12 characters." in ran.err
    assert "The account was not made" in ran.err
    assert "users_cli add 'you@example.com'" in ran.err


# ------------------------------------------------------------ the password

def test_the_password_is_read_with_the_echo_off_and_the_rest_is_shown(world):
    ran = world.run(GOOD)
    assert ran.code == 0, ran.said
    assert PASSWORD not in ran.tty
    assert DOMAIN in ran.tty and EMAIL in ran.tty


def test_the_password_is_in_no_command_line_no_environment_no_file_and_no_output(world):
    ran = world.run(GOOD)
    assert ran.code == 0, ran.said
    calls = world.calls()
    assert PASSWORD not in json.dumps([{k: v for k, v in c.items()
                                        if k != "stdin_sha256"} for c in calls])
    for path in list(world.opt.rglob("*")) + list(world.home.rglob("*")) + list(world.root.glob("*")):
        if path.is_file():
            assert PASSWORD.encode() not in path.read_bytes(), path
    assert PASSWORD not in ran.out + ran.err + ran.tty
    added = [c for c in calls if "stdin_sha256" in c]
    assert len(added) == 1
    assert added[0]["stdin_sha256"] == hashlib.sha256(PASSWORD.encode()).hexdigest()


# --------------------------------------------------------- the whole install

def test_it_says_what_it_asks_before_it_asks_anything(world):
    ran = world.run(GOOD)
    assert ran.code == 0, ran.said
    intro = ran.out.index("It asks four things: your domain, your invite line, an email address and a password.")
    assert intro < ran.out.index("It will:")
    assert "Docker 29.8.2, Compose 2.40.3." in ran.out
    assert ran.tty.index("Your domain") < ran.tty.index("Go on?")


def test_the_plan_names_what_it_will_do_with_the_answers_and_the_probers_host(world):
    """The invite's host is where the instance sends its batches of ports,
    so it is shown before anything is done, and the person says yes to it."""
    ran = world.run(GOOD)
    assert ran.code == 0, ran.said
    plan = ran.out.index("It will:")
    for step in (f"1. clone {world.repository} at {TAG}, commit {tag_commit(world.repository, TAG)}, into {world.checkout()}",
                 f"2. write {world.checkout()}/selfhost/.env, readable by root only, for {DOMAIN}, with our probers at app.whichports.com",
                 "3. build the images, start the stack on port 443, and wait until it reads healthy",
                 f"4. make the account {EMAIL}"):
        assert plan < ran.out.index(step), step
    assert ran.out.index("4. make the account") < ran.out.index("* cloning")


@pytest.mark.parametrize("answer", ["no", "", "y", "yes please", "YES "])
def test_anything_but_yes_to_the_plan_changes_nothing(world, answer):
    ran = world.run(GOOD[:-1] + [answer])
    if answer.strip() == "YES":
        assert ran.code == 0, ran.said
        return
    assert_nothing_changed(world, ran)
    assert "You did not type yes." in ran.err
    assert not world.calls() or not [c for c in world.compose_calls() if c[0] != "version"]


def test_a_new_install_clones_writes_builds_waits_and_makes_the_account(world):
    ran = world.run(GOOD)
    assert ran.code == 0, ran.said
    checkout = world.checkout()
    env_file = checkout / "selfhost" / ".env"
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    expected = (HERE / "env.example").read_text().replace(
        "WHICHPORTS_DOMAIN=whichports.example.com\n", f"WHICHPORTS_DOMAIN={DOMAIN}\n").replace(
        "WHICHPORTS_PROBER_INVITE=\n", f"WHICHPORTS_PROBER_INVITE={INVITE}\n")
    assert env_file.read_text() == expected
    assert not list((checkout / "selfhost").glob(".env.*")), "no work file left"

    calls = [c for c in world.calls() if c["argv"][:1] == ["compose"]]
    assert [c["argv"][1:] for c in calls] == [
        ["version", "--short"],
        ["build"],
        ["up", "-d", "--wait", "--wait-timeout", "180"],
        ["ps", "-a", "-q"],
        ["ps", "-a", "-q"],
        ["exec", "-T", "controlplane", "python", "-m", "app.users_cli", "list"],
        ["exec", "-T", "controlplane", "python", "-m", "app.users_cli",
         "--create-database", "add", "--", EMAIL],
    ]
    for call in calls[1:]:
        assert call["compose_file"] == str(checkout / "selfhost" / "compose.yaml")
    for call in calls[1:3]:
        assert COMMIT_RE.match(call["env"]["WHICHPORTS_COMMIT"]), call["env"]
        assert call["env_file_mode"] == "0o600", "written closed before the build"
    head = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"], cwd=checkout,
                          capture_output=True, text=True, check=True).stdout.strip()
    assert head == tag_commit(world.repository, TAG)[:12]
    assert calls[1]["env"]["WHICHPORTS_COMMIT"] == head
    assert "account you@example.com created" in ran.out
    assert f"  open      https://{DOMAIN}/" in ran.out
    assert f"  sign in   {EMAIL}" in ran.out
    assert ran.out.rstrip().endswith("run the line it gives you on that server.")
    assert stat.S_IMODE(checkout.stat().st_mode) == 0o755
    assert not [p for p in world.opt.iterdir() if p.name != "whichports"], "no work folder left"


def test_run_twice_it_changes_nothing_the_second_time(world):
    install_once(world)
    env_file = world.checkout() / "selfhost" / ".env"
    before = tree(world.opt)
    written = env_file.stat().st_mtime_ns
    calls = len(world.calls())
    ran = world.run(GOOD)
    assert ran.code == 0, ran.said
    assert "1. use " in ran.out and "which an earlier run made, as it is" in ran.out
    assert "* cloning" not in ran.out
    assert "is there with these answers, left as it is" in ran.out
    assert "* the account you@example.com is there already, left as it is" in ran.out
    assert tree(world.opt) == before
    assert env_file.stat().st_mtime_ns == written
    later = [c["argv"][1:] for c in world.calls()[calls:] if c["argv"][:1] == ["compose"]]
    assert not [c for c in later if "add" in c], "no second account"


def test_another_mail_address_on_a_second_run_makes_no_second_account(world):
    install_once(world)
    ran = world.run([DOMAIN, INVITE, "other@example.com", PASSWORD, PASSWORD, "yes"])
    assert ran.code == 0, ran.said
    assert "this instance has an account already, so none was made for other@example.com" in ran.out
    assert "users_cli add 'other@example.com'" in ran.out
    assert json.loads(world.state.read_text())["accounts"] == [EMAIL]


def test_a_mail_address_in_a_printed_command_is_quoted_for_the_shell(world):
    """The printed command is one a person may paste as root, and an
    address may hold a quote or a dollar sign."""
    install_once(world)
    odd = "o'$(id)@example.com"
    ran = world.run([DOMAIN, INVITE, odd, PASSWORD, PASSWORD, "yes"])
    assert ran.code == 0, ran.said
    assert "users_cli add 'o'\\''$(id)@example.com'" in ran.out, ran.out


def test_a_run_after_a_refused_account_makes_it_without_a_second_database(world):
    """The first account's command makes the database even when it then
    refuses the password, so the next run adds to that database."""
    password = "éééééé1!"
    world.run([DOMAIN, INVITE, EMAIL, password, password, "yes"])
    ran = world.run(GOOD)
    assert ran.code == 0, ran.said
    adds = [c for c in world.compose_calls() if "add" in c]
    assert "--create-database" not in adds[-1]
    assert "account you@example.com created" in ran.out


@pytest.mark.parametrize("where", ["a checkout", "its selfhost folder"])
def test_the_folder_it_is_run_from_is_never_built(world, where):
    """Run from inside a checkout somebody else made, it still installs
    to its own folder, and the checkout it stood in is left as it was."""
    checkout = world.home / "theirs"
    subprocess.run(["git", "clone", "-q", str(world.repository), str(checkout)], check=True)
    cwd = checkout if where == "a checkout" else checkout / "selfhost"
    before = tree(checkout)
    ran = world.run(GOOD, cwd=cwd)
    assert ran.code == 0, ran.said
    assert f"1. clone {world.repository} at {TAG}, commit " in ran.out
    assert (world.checkout() / "selfhost" / ".env").exists()
    assert tree(checkout) == before


def test_no_compose_call_reads_a_file_but_the_releases_own(world):
    install_once(world)
    files = {c.get("compose_file") for c in world.calls()
             if c["argv"][:1] == ["compose"] and c["argv"][1:2] != ["version"]}
    assert files == {str(world.checkout() / "selfhost" / "compose.yaml")}


# ------------------------------------------------------- the script's text

def script_text() -> str:
    return SCRIPT.read_text()


def code_lines() -> list:
    return [line for line in script_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def test_git_is_never_told_a_folder_is_safe():
    """safe.directory would let root read a checkout another user owns. The
    install folder is root's own, so git needs no such word."""
    assert "safe.directory" not in "\n".join(code_lines())


def test_it_never_runs_eval_or_a_shell_on_a_built_string():
    for line in code_lines():
        assert not re.search(r"\beval\b", line), line
        assert not re.search(r"\b(sh|bash|dash)\s+-c\b", line), line
        assert "exec " not in line.replace("compose exec", ""), line
        assert "source " not in line and not line.lstrip().startswith(". "), line


def test_the_password_is_never_exported_or_passed_to_a_program_by_name():
    text = "\n".join(code_lines())
    assert "export" not in text
    uses = [line.strip() for line in code_lines() if "$password" in line]
    assert uses == [
        # Inside password_needs: patterns, which start no program.
        'case $password in *[0-9]*) ;; *) missing="${missing:+$missing, }a number" ;; esac',
        'case $password in *[!A-Za-z0-9]*) ;; *) missing="${missing:+$missing, }a special character" ;; esac',
        'needs=$(password_needs "$password")',
        'if [ "$secret" = "$password" ]; then',
        'if ! printf \'%s\\n\' "$password" | compose exec -T controlplane python -m app.users_cli add -- "$email"; then',
        'if ! printf \'%s\\n\' "$password" | compose exec -T controlplane python -m app.users_cli --create-database add -- "$email"; then',
    ], uses


def test_the_call_is_the_last_line_and_inside_braces():
    lines = script_text().rstrip("\n").splitlines()
    assert lines[-1] == '{ main "$@"; }'
    assert [line for line in code_lines() if re.search(r'\bmain\b', line)] == [
        "main() {", '{ main "$@"; }']


@pytest.mark.parametrize("shell", SHELLS)
def test_a_script_cut_short_at_any_line_runs_nothing(tmp_path, shell):
    """Piped into a shell, a download that stops halfway runs what came.
    Cut after each line, the script must run nothing at all: no program, no
    question, no line printed."""
    lines = script_text().splitlines(keepends=True)
    marker = tmp_path / "ran"
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in TOOLS + ("git",) + STAND_INS:
        stand_in = bin_dir / tool
        stand_in.write_text(f"#!/bin/sh\n: > {marker}\n")
        stand_in.chmod(0o755)
    whole = "".join(lines)
    # After every line, and inside the last line at every character, which
    # is the one cut a function alone does not cover: "main" would run.
    cuts = [len("".join(lines[:n])) for n in range(1, len(lines))]
    cuts += range(cuts[-1] + 1, len(whole.rstrip("\n")))
    for cut in cuts:
        done = subprocess.run([shutil.which(shell)], input=whole[:cut].encode(),
                              capture_output=True, env={"PATH": str(bin_dir)},
                              cwd=tmp_path, timeout=20, start_new_session=True)
        where = f"cut after {whole[:cut][-30:]!r}"
        assert not marker.exists(), f"{where} ran a program"
        assert done.stdout == b"", f"{where} printed {done.stdout!r}"
        assert b"Nothing was changed" not in done.stderr, f"{where} ran main"


def test_the_readme_gives_the_line_this_script_is_served_by():
    readme = (HERE / "README.md").read_text()
    line = "curl --proto '=https' --tlsv1.2 -fsSL https://get.whichports.com/selfhost.sh | sudo sh"
    assert line in script_text()
    assert f"\n{line}\n" in readme


# ------------------------------------- the rules are the control plane's own

def rule(shell: str, tmp_path: Path, function: str, *values) -> list:
    """The script's own function, on each value, as exit codes and output.
    The script is loaded without its last line, so main is not called."""
    lib = tmp_path / "rules.sh"
    if not lib.exists():
        body = script_text().rstrip("\n").splitlines()[:-1]
        lib.write_text("\n".join(body) + '\nfunction=$1\nshift\nfor value in "$@"; do\n'
                       '  if "$function" "$value"; then echo "0"; else echo "1"; fi\n'
                       '  echo "--"\ndone\n')
    done = subprocess.run([shutil.which(shell), str(lib), function, *values],
                          capture_output=True, text=True, timeout=60,
                          env={"PATH": "/usr/bin:/bin"})
    assert done.returncode == 0, done.stderr
    answers = done.stdout.split("--\n")[:-1]
    assert len(answers) == len(values)
    return answers


sys.path.insert(0, str(CONTROLPLANE))
from app import accounts, invite  # noqa: E402

sys.path.insert(0, str(HERE))
import release_installer  # noqa: E402

HOSTS = ["whichports.example.com", "a.b", "x-1.y-2.example", "ours.internal",
         "a" * 63 + ".com", "a" * 64 + ".com", ("a" * 63 + ".") * 3 + "a" * 58 + ".io",
         ("a" * 63 + ".") * 3 + "a" * 59 + ".io", "localhost", "203.0.113.9",
         "app.whichports.123", "app_x.com", "-a.com", "a-.com", "a..com", ".a.com",
         "a.com.", "A.com", "a.com:443", "", "a b.com", "é.com", "xn--e1afmkfd.com",
         "1.2.3.example", "a.b-c", "a.-b"]


@pytest.mark.parametrize("shell", SHELLS)
def test_the_domain_rule_is_the_invites_host_rule(shell, tmp_path):
    got = rule(shell, tmp_path, "name_ok", *HOSTS)
    for host, answer in zip(HOSTS, got):
        assert (answer == "0\n") == invite.host_ok(host), host


@pytest.mark.parametrize("shell", SHELLS)
def test_the_invite_rule_is_the_control_planes(shell, tmp_path):
    lines = [INVITE, INVITE[:-1], INVITE + "0", f"  {INVITE}", INVITE.upper(),
             f"whpinvite1_a.b_{API_KEY}_{PROOF_KEY}",
             f"whpinvite1_a_b.com_{API_KEY}_{PROOF_KEY}",
             f"whpinvite1_app.whichports.com_{PROOF_KEY}_{API_KEY}",
             f"whpinvite1_app.whichports.com_{API_KEY}_{API_KEY}",
             f"whpinvite1_app.whichports.com_{API_KEY}_{PROOF_KEY}_{PROOF_KEY}",
             f"whpinvite1__{API_KEY}_{PROOF_KEY}",
             f"whpinvite1_localhost_{API_KEY}_{PROOF_KEY}",
             "whpinvite2_" + INVITE[11:], API_KEY, PROOF_KEY, "",
             INVITE.replace("_whpp_", "_whpp__"), INVITE.replace("whpi_", "whpi__")]
    got = rule(shell, tmp_path, "invite_ok", *lines)
    for line, answer in zip(lines, got):
        try:
            invite.split(line)
            takes = line == line.strip()  # the script's read takes spaces off first
        except invite.InviteError:
            takes = False
        assert (answer == "0\n") == takes, line


@pytest.mark.parametrize("shell", SHELLS)
def test_the_mail_rule_is_the_control_planes(shell, tmp_path):
    addresses = ["you@example.com", "a@b.c", "you@example", "you@@example.com",
                 "@example.com", "you@", "you@.com", "you@example.", "you.example.com",
                 "y ou@example.com", "you@exa\tmple.com", "-x@example.com",
                 "you+tag@sub.example.com", "a@b..c", "a@.b.c", "a" * 250 + "@b.cd",
                 "a" * 251 + "@b.cd", ""]
    got = rule(shell, tmp_path, "email_ok", *addresses)
    for address, answer in zip(addresses, got):
        assert (answer == "0\n") == accounts.valid_email(address), address


@pytest.mark.parametrize("shell", SHELLS)
def test_the_password_rule_and_its_words_are_the_control_planes(shell, tmp_path):
    passwords = ["", "short1!", "abcdefghijk1", "abcdefghijkl!", "abcdefghijk!1",
                 "only letters and spaces", "123456789012", "!!!!!!!!!!!!",
                 "a long one, 12+ chars", " leading space1", "trailing1   ",
                 "tab\there12345", "a1!" * 42 + "ab", "a1!" * 43, "a" * 129,
                 "back\\slash1xyz", "per%cent1xyzz", "$dollar1xyzz", "'quote1'xyzz"]
    got = rule(shell, tmp_path, "password_needs", *passwords)
    for password, answer in zip(passwords, got):
        try:
            accounts.check_password_shape(password)
            words = ""
        except accounts.AccountError as exc:
            words = str(exc) + "\n"
        assert answer == "0\n" + words or answer == words + "0\n", (password, answer)
