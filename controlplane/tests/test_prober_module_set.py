"""The modules that go to a vantage host still form a closed set.

A vantage host gets exactly `prober.py`, `authz.py`, `ratelimit.py`,
`dnstxt.py`, `probe_runner.py` and `workspace.py`, and deliberately no
`db.py`, no `store.py`, no `ingest.py`, no credential and no database: the
prober is the box that attracts abuse reports and is therefore the one most
likely to be taken, so a compromise of it must not reach the control plane.

The deploy script already checks the set is closed and refuses to deploy when
it is not. **The check was in the wrong place, and it cost five days.** On
2026-08-23 the workspaces change gave `authz.account_for_workspace` a single
reference to `db.DEFAULT_WORKSPACE_ID`. `authz` therefore imported `db`, the
set stopped being closed, and every prober deploy from that day refused. A
deploy is run by hand rather than by CI, so nothing said so: the vantage host
sat nine commits behind, including a fix about how it closes connections to
other people's servers, while the whole suite stayed green
(`docs/RECORD.md` 4.113).

So the same check runs here, on every commit. A module that reaches for the
database now fails a test the day it is written, and the deploy script keeps
its own copy as the last word at the moment it matters.

**This is the import graph and not the whole property.** It does not prove the
set never touches a database, only that it pulls in nothing outside itself.
The `sqlite3` import in `authz.py` is real and is what the control plane's own
authority uses; the prober is handed a snapshot instead and opens nothing. The
test below pins that separately by importing the set in isolation.
"""
import ast
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

from app import probe_runner

REPO = pathlib.Path(__file__).resolve().parents[2]
APP = REPO / "controlplane" / "app"
DEPLOY = REPO / "ops" / "deploy-prober.sh"

# The deploy script is not part of every tree this suite runs in. Where it is
# absent the list and the import graph are still checked, and only the tests
# that run the script itself are skipped.
needs_the_deploy_script = pytest.mark.skipif(
    not DEPLOY.is_file() or shutil.which("bash") is None,
    reason="this tree has no deploy script, or no bash to run it with")


def shipped_modules() -> list[str]:
    """The one list, `probe_runner.VANTAGE_MODULES`. The deploy script reads
    the same constant, and the tests at the end of this file hold it to
    that, because two lists are two things that can disagree."""
    return list(probe_runner.VANTAGE_MODULES)


def package_imports(module: str) -> set[str]:
    """Every module inside the package that `module` imports, at any depth of
    the file. A function-level import counts: it is still a module that has to
    be present on the far end the first time that line runs."""
    tree = ast.parse((APP / module).read_text())
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level:
            for alias in node.names:
                found.add(alias.name)
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("app."):
                    found.add(alias.name.split(".", 1)[1])
    return found


def test_the_list_is_the_six_and_every_one_exists():
    """A list that names nothing passes every check below by accident, and a
    seventh name is a decision somebody takes on purpose, here as well."""
    assert sorted(shipped_modules()) == sorted(
        ["authz.py", "dnstxt.py", "probe_runner.py", "prober.py",
         "ratelimit.py", "workspace.py"])
    for name in shipped_modules():
        assert (APP / name).is_file(), name


def test_the_module_set_is_closed():
    """The check `ops/deploy-prober.sh` does, run on every commit instead of
    at a deploy somebody runs by hand once a week."""
    allowed = {name[:-3] for name in shipped_modules()}
    reaching_out = {}
    for name in sorted(allowed):
        outside = package_imports(name + ".py") - allowed
        if outside:
            reaching_out[name] = sorted(outside)
    assert not reaching_out, (
        f"these modules import something outside the vantage set: {reaching_out}."
        " Either the import does not belong there, or ops/deploy-prober.sh and"
        " ops/RUNBOOK.md widen what runs on the prober deliberately. Widening"
        " it by accident is what this test exists to stop")


@pytest.mark.parametrize("forbidden", ["db", "store", "ingest", "accounts",
                                       "join", "intent", "alerts", "channels",
                                       "notify", "webhook", "hetzner"])
def test_no_shipped_module_reaches_the_control_plane(forbidden):
    """Named one by one as well as by the closed-set check above, so a failure
    says which module arrived rather than only that the set grew. `db` is the
    one that really happened."""
    for name in shipped_modules():
        assert forbidden not in package_imports(name), (
            f"{name} imports {forbidden}, which does not go to a vantage host")


def test_the_shipped_set_imports_cleanly_with_nothing_else_present():
    """The property the graph check only implies: the set can be imported on
    a machine that has this package and nothing configured. Run in a
    subprocess so a module already imported by the rest of the suite cannot
    make a missing one look present."""
    names = ", ".join(name[:-3] for name in sorted(shipped_modules()))
    script = f"from app import {names}\nprint('ok')\n"
    done = subprocess.run([sys.executable, "-c", script], cwd=REPO / "controlplane",
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "ok"


def test_the_prober_never_opens_the_database_itself():
    """`authz.py` imports sqlite3 and that is correct: the control plane's own
    `DatabaseAuthority` uses it. What must stay true is that the prober's own
    entry point does not, because it is handed a snapshot instead.

    Asserted over `probe_runner.py`, which is the whole of what runs on the
    vantage host, rather than over the modules it can reach.
    """
    source = (APP / "probe_runner.py").read_text()
    tree = ast.parse(source)
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        if isinstance(node, ast.ImportFrom) and node.module and not node.level:
            imported.add(node.module)
    assert "sqlite3" not in imported
    assert "DatabaseAuthority" not in source


# ------------------------------------------------- the deploy script itself
#
# Run for real, against an `ssh` and an `scp` that only write down what they
# were asked. The far end is a name under .invalid, which never resolves, so
# a stub that failed to take the place of the real command reaches nothing.

DEST = "prober@vantage.invalid"

SSH_STUB = """#!/bin/sh
echo "ssh $*" >> "$STUB_LOG"
# The script's last step sends an empty batch and expects a refusal.
case "$*" in *app.probe_runner*) cat > /dev/null; exit 2 ;; esac
exit 0
"""

SCP_STUB = """#!/bin/sh
echo "scp $*" >> "$STUB_LOG"
exit 0
"""


def run_deploy(tmp_path, script=DEPLOY):
    """Run a deploy script with the two stubs first on PATH. Returns the
    finished process and the lines the stubs wrote."""
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    for name, body in (("ssh", SSH_STUB), ("scp", SCP_STUB)):
        (stubs / name).write_text(body)
        (stubs / name).chmod(0o755)
    log = tmp_path / "stub.log"
    log.write_text("")
    env = dict(os.environ, PATH=f"{stubs}{os.pathsep}{os.environ['PATH']}",
               STUB_LOG=str(log))
    env.pop("WHICHPORTS_PROBER_DIR", None)
    done = subprocess.run(["bash", str(script), DEST], env=env, cwd=tmp_path,
                          capture_output=True, text=True, timeout=60)
    return done, log.read_text().splitlines()


def tree_of_its_own(tmp_path) -> pathlib.Path:
    """The script and the six modules, copied, so a test can break one."""
    root = tmp_path / "tree"
    (root / "ops").mkdir(parents=True)
    (root / "controlplane" / "app").mkdir(parents=True)
    shutil.copy2(DEPLOY, root / "ops" / DEPLOY.name)
    for name in shipped_modules():
        shutil.copy2(APP / name, root / "controlplane" / "app" / name)
    return root


@needs_the_deploy_script
def test_the_deploy_script_keeps_no_list_of_its_own():
    text = DEPLOY.read_text()
    assert "VANTAGE_MODULES" in text
    code = [line for line in text.splitlines()
            if not line.lstrip().startswith("#")]
    for name in shipped_modules():
        if name == "probe_runner.py":
            continue  # the file it reads the list from, and the final check
        assert not any(name in line for line in code), (
            f"{name} is written out in ops/deploy-prober.sh. The list is"
            " VANTAGE_MODULES and the script reads it")


@needs_the_deploy_script
def test_the_deploy_script_sends_exactly_the_list(tmp_path):
    done, calls = run_deploy(tmp_path)
    assert done.returncode == 0, done.stdout + done.stderr
    sent = [line.split()[-2:] for line in calls if line.startswith("scp ")]
    assert sent == [[f"controlplane/app/{name}",
                     f"{DEST}:/opt/whichports/app/{name}"]
                    for name in shipped_modules()]
    assert "module set closed" in done.stdout
    # Before anything is copied it makes the directory, and after everything
    # it asks the far end to refuse an empty batch. Nothing else is run there.
    remote = [line for line in calls if line.startswith("ssh ")]
    assert len(remote) == 2
    assert "mkdir -p /opt/whichports/app" in remote[0]
    assert remote[1].endswith("python3 -m app.probe_runner")
    assert calls.index(remote[0]) == 0 and calls[-1] == remote[1]


@needs_the_deploy_script
@pytest.mark.parametrize("line", [
    "",                                              # the constant is gone
    "VANTAGE_MODULES = ()",                          # names nothing
    'VANTAGE_MODULES = ["prober.py"]',               # not a tuple
    'VANTAGE_MODULES = ("prober.py", 7)',            # not a string
    'VANTAGE_MODULES = ("../../etc/passwd",)',       # not a bare file name
    'VANTAGE_MODULES = ("prober.py", "db.sqlite")',  # not a module
    'VANTAGE_MODULES = ("prober.py -o x.py",)',      # would be scp options
    "VANTAGE_MODULES = tuple(os.listdir('.'))",      # not a literal
])
def test_a_list_it_cannot_use_sends_nothing(tmp_path, line):
    root = tree_of_its_own(tmp_path)
    runner = root / "controlplane" / "app" / "probe_runner.py"
    kept = [row for row in runner.read_text().splitlines(keepends=True)]
    start = next(i for i, row in enumerate(kept)
                 if row.startswith("VANTAGE_MODULES = ("))
    end = next(i for i in range(start, len(kept)) if kept[i].rstrip().endswith(")"))
    runner.write_text("".join(kept[:start]) + line + "\n"
                      + "".join(kept[end + 1:]))
    done, calls = run_deploy(tmp_path, root / "ops" / DEPLOY.name)
    assert done.returncode != 0
    assert calls == [], "nothing was run on the far end and nothing copied"


@needs_the_deploy_script
def test_a_set_that_is_no_longer_closed_sends_nothing(tmp_path):
    """What really happened on 2026-08-23: `authz` imported `db`."""
    root = tree_of_its_own(tmp_path)
    authz = root / "controlplane" / "app" / "authz.py"
    authz.write_text(authz.read_text() + "\nfrom . import db\n")
    done, calls = run_deploy(tmp_path, root / "ops" / DEPLOY.name)
    assert done.returncode == 1
    assert "authz imports db" in done.stderr
    assert calls == []


@needs_the_deploy_script
def test_a_far_end_that_accepts_an_empty_batch_fails_the_deploy(tmp_path,
                                                                monkeypatch):
    """The last step is a real check and not a formality: a runner that
    answers an unusable batch with success is not the runner."""
    monkeypatch.setattr(sys.modules[__name__], "SSH_STUB",
                        '#!/bin/sh\necho "ssh $*" >> "$STUB_LOG"\n'
                        "cat > /dev/null\nexit 0\n")
    done, _calls = run_deploy(tmp_path)
    assert done.returncode == 1
    assert "accepted an empty batch" in done.stderr
