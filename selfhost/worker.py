"""Run the control plane's systemd timers inside one container.

    python selfhost/worker.py run                        the scheduler, forever
    python selfhost/worker.py once whichports-backup.service   one job, now
    python selfhost/worker.py once whichports-cve.service      the CVE build, now
    python selfhost/worker.py once whichports-vantages-sync.service
    python selfhost/worker.py exec whichports-ingest.service   become that unit

On the production box systemd runs the scheduled jobs beside the ingest
(`ops/RUNBOOK.md`, "What runs there"). A Docker Compose install has no
systemd, so this process does the same work. **It reads the very unit files
the box installs**, from `controlplane/ops`, and runs each one's `ExecStart`
on that unit's own schedule. So a self-hosted instance runs the same commands
at the same cadences as prod by construction, and a change to a timer reaches
both in the same commit. There is no second copy of a cadence anywhere.

One pair of those files lives elsewhere: the CVE check's daily build,
`ops/cve/whichports-cve.service` and its timer, which the box gets from
`ops/cve/install-on-the-box.sh`. The image puts them at `/srv/ops/cve`, the
same place beside the control plane as in a checkout, and this worker runs
them like the others. The build fetches Debian's security tracker file and
Canonical's OSV file and opens no database, so it runs on an instance that
has no account yet. **On an instance whose folder holds no extract, a new
one, the first build comes two minutes after the worker starts**, where the
box got its first from its install. With the files there a restart waits for
04:41 as before, so the daily time is the unit's and nothing else changes.

## What it reads, and what it refuses

It understands the directives those files use today and nothing more. A unit
that says something else stops this worker at start, naming the directive,
rather than being half honoured. `test_worker.py` reads the real units on every
gate run, so a timer change this worker cannot follow fails the gate first.

The timer semantics follow systemd's own manual (systemd.timer(5) and
systemd.path(5), read from systemd's source repository on 2026-10-01):

- `OnBootSec=` counts from when this worker started. The manual: "In
  containers, for the system manager instance, this is mapped to
  OnStartupSec=".
- `OnUnitActiveSec=` counts from when the job last started.
- `RandomizedDelaySec=` adds a fresh random delay between 0 and that value
  before every run.
- "in case the unit to activate is already active at the time the timer
  elapses it is not restarted, but simply left running". So a job never runs
  twice at once, and one that overran starts again when it finishes.
- `OnCalendar=` is only the daily `*-*-* HH:MM:SS` form, in UTC, which is what
  a container's clock reads. A trailing ` UTC`, as the CVE timer writes it,
  says the same and is read the same.
- `Persistent=` "only has an effect on timers configured with OnCalendar=".
  The time of the last run is kept in a stamp file beside the database, the
  way systemd keeps one under /var/lib/systemd/timers, so a stack that was down
  at 03:17 takes its backup when it comes back.
- `PathModified=` fires when the file's size, inode or modification time
  changes. The manual: when the triggered service ends, "monitored paths are
  checked immediately again", so a request that landed during a drain gets a
  drain of its own.

## The one job of its own

Our box drives its probers over ssh and names them by hand
(`vantages_cli add`). A self-hosted instance asks our prober API instead, and
has to take the list of our probers from it, by name, with every one of our
addresses kept out of its own targets (`docs/PRODUCT.md` 5g). No unit on the
box does that, because the box never needs it, so this worker carries it
itself: `python -m app.vantages_cli sync-api`, a minute after it starts and
every fifteen minutes after, and only when the instance is set to use the
API. A prober we add reaches every instance within a quarter of an hour, and
nobody has to know the command exists. It runs ahead of the first probing
pass, which the fast lane's own timer puts four minutes after start.

**Without that setting the two probing timers are not scheduled**, and the
worker says so in one line at start. Every unit is still read and checked,
and `once` still runs a pass that is asked for by name. The scan path stays
as it is.

## The invite line

`.env` may name our probers in one line, `WHICHPORTS_PROBER_INVITE`, as the
installer writes it. Before anything else this worker takes it apart into the
three settings the control plane reads (`take_apart_invite`, with the
control plane's own `app/invite.py`), so the schedule above sees the API as
set, and every job, the ingest included, gets the three and never the line.

## A job that runs too long

`TimeoutStartSec=` is honoured. systemd.service(5), read on 2026-10-14 in
systemd's source repository, says that past it "the service will be
considered failed and will be shut down again", and by default with
SIGTERM. So a job that runs past it gets SIGTERM, and SIGKILL 30 seconds
later if it is still there. Those 30 seconds are this worker's own: systemd
waits the unit's TimeoutStopSec=, whose default is set when systemd is built.

## The sandbox directives

`User=`, `NoNewPrivileges=`, `ProtectSystem=`, `ProtectHome=`, `PrivateTmp=`
and `ReadWritePaths=` are not applied by this process. The container is the
sandbox, and `selfhost/compose.yaml` sets the equivalent of each one beside it:
an unprivileged user, no-new-privileges, a read-only root, a private /tmp, and
the volumes as the only writable paths. `MemoryMax=` is not applied either,
and nothing in the compose file stands in for it: a container has no group of
its own for each job. On the box it keeps a CVE build that grew from taking
the ingest's memory, and here the ingest runs in a container of its own.
`EnvironmentFile=` is the env file
Compose hands every container, and a value from it wins over a unit's own
`Environment=`, which is the order systemd uses.

## What it never does

It never runs a shell. Every command is the unit's own `ExecStart`, split into
an argv array and started directly (SI-4). A line with a `$`, a `%` specifier
or one of systemd's prefix characters is refused rather than interpreted.
"""
import argparse
import importlib.util
import os
import random
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Where the image puts the unit files. In a checkout they are
# controlplane/ops, and the tests pass that path in.
DEFAULT_UNIT_DIR = Path("/srv/controlplane/ops")

# What a self-hosted instance runs from that directory.
TIMERS = (
    "whichports-sweep.timer",
    "whichports-probe-fast.timer",
    "whichports-probe.timer",
    "whichports-backup.timer",
)
PATHS = ("whichports-scan.path",)
# The CVE check's daily build, from its own directory (see the top of this
# file). In a checkout it is ops/cve, and the tests pass that path in.
DEFAULT_CVE_UNIT_DIR = Path("/srv/ops/cve")
CVE_TIMER = "whichports-cve.timer"
# The jobs that open no database, so they run before the first account has
# made one. The CVE build reads the vendors' files and writes its own folder.
NEEDS_NO_DATABASE = {"whichports-cve.service"}
# A new instance's first CVE build, this long after the worker starts, when
# the folder holds no extract. After the prober list's first take at one
# minute.
CVE_FIRST_SECONDS = 120.0
# After a job's TimeoutStartSec= has passed and it was sent SIGTERM, how long
# it has before SIGKILL. This worker's own number, see the top of this file.
LATE_KILL_SECONDS = 30.0

# The two that probe. An instance has no prober of its own: it asks our
# prober API (docs/PRODUCT.md 5g). Without that setting there is nothing to
# probe with, and each pass ended with exit 2 and a line naming a command an
# instance's operator is never given, every ten minutes (measured on a
# server, docs/record 4.333). So without the setting they are not scheduled.
PROBING_TIMERS = (
    "whichports-probe-fast.timer",
    "whichports-probe.timer",
)

# Every other unit in that directory, and why it is not run by this worker.
# test_worker.py holds this list and the directory equal, so a new unit
# cannot be left out by accident.
NOT_SCHEDULED_HERE = {
    "whichports-ingest.service":
        "the controlplane container runs it, through `exec`",
    "whichports-proberapi.service":
        "it drives our probers for self-hosted instances, so only our own"
        " control plane runs it, never an instance",
}

# The worker's own job, which no unit carries: take our prober list from the
# API. The command is the one `app/vantages_cli.py` documents for an
# instance. It borrows the interpreter, the working directory and the
# environment of the fast lane's unit, so nothing about where the control
# plane lives is written twice.
SYNC_SERVICE = "whichports-vantages-sync.service"
SYNC_ARGS = ("-m", "app.vantages_cli", "sync-api")
SYNC_BORROWS_FROM = "whichports-probe-fast.timer"
# A minute after start, so it is done before the first pass at four. Then
# every fifteen minutes, which is one small GET, and the longest a new prober
# of ours goes unnoticed.
SYNC_FIRST_SECONDS = 60.0
SYNC_EVERY_SECONDS = 15 * 60.0
SYNC_JITTER_SECONDS = 60.0
# On a new install the database appears when the first account is made, a
# few minutes in. A sync that found none looks again this soon, so the first
# pass after the account finds the probers named.
SYNC_RETRY_SECONDS = 60.0
# Set means this instance asks our API. The same name `app/dispatch.py` reads.
PROBER_API_ENV = "WHICHPORTS_PROBER_API"

# The one flag of the ingest a self-hosted machine may change: the port, for
# a machine where 8410 is taken. Never the bind address.
INGEST_PORT_ENV = "WHICHPORTS_INGEST_PORT"

# How often the path watch looks at its file. A stat a second is nothing,
# and it keeps Scan now within a second of the click.
PATH_POLL_SECONDS = 1.0

# The directives each section may carry. Anything else stops the worker.
KNOWN = {
    "Unit": {"Description", "After", "Wants"},
    "Install": {"WantedBy"},
    "Timer": {"OnBootSec", "OnUnitActiveSec", "RandomizedDelaySec",
              "OnCalendar", "Persistent"},
    "Path": {"PathModified"},
    "Service": {"Type", "User", "WorkingDirectory", "Environment",
                "EnvironmentFile", "ExecStart", "Restart", "RestartSec",
                "TimeoutStopSec", "TimeoutStartSec", "NoNewPrivileges",
                "ProtectSystem", "ProtectHome", "PrivateTmp", "ReadWritePaths",
                "MemoryMax"},
}

# systemd.time(7) units this worker accepts. Anything finer or coarser is not
# in any unit today and is refused rather than guessed at.
SPAN_UNITS = {
    "s": 1, "sec": 1, "second": 1, "seconds": 1,
    "m": 60, "min": 60, "minute": 60, "minutes": 60,
    "h": 3600, "hr": 3600, "hour": 3600, "hours": 3600,
}
# A number, optional spaces, an optional unit, and that again. systemd.time(7)
# writes "2 h" and "2hours" alike.
SPAN_PART_RE = re.compile(r"(\d+(?:\.\d+)?)\s*([a-z]*)")
SPAN_RE = re.compile(r"(?:\d+(?:\.\d+)?\s*[a-z]*\s*)+")


class UnitError(ValueError):
    """A unit file says something this worker will not guess at."""


class SettingError(ValueError):
    """A setting whose wrong value stops the stack at start."""


# ----------------------------------------------------------------- reading

def read_unit(path: Path) -> dict:
    """{section: [(key, value), ...]} in file order.

    Comments start with # or ;, a line ending in a backslash continues on the
    next one, which is how the backup unit writes its long ExecStart.
    """
    sections = {}
    current = None
    pending = ""
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not pending and (not line or line[0] in "#;"):
            continue
        if line.endswith("\\"):
            pending += line[:-1].strip() + " "
            continue
        line = pending + line
        pending = ""
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            if current not in KNOWN:
                raise UnitError(f"{path.name}: section [{current}] is not one"
                                " this worker understands")
            sections.setdefault(current, [])
            continue
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or current is None:
            raise UnitError(f"{path.name}: cannot read the line {raw!r}")
        if key not in KNOWN[current]:
            raise UnitError(f"{path.name}: [{current}] {key}= is not a"
                            " directive this worker understands, so it will"
                            " not run the unit half honoured")
        sections[current].append((key, value.strip()))
    if pending:
        raise UnitError(f"{path.name}: the last line ends in a backslash")
    return sections


def _one(sections: dict, section: str, key: str, path: Path,
         required: bool = True):
    values = [v for k, v in sections.get(section, []) if k == key]
    if len(values) > 1:
        raise UnitError(f"{path.name}: {key}= appears {len(values)} times")
    if not values:
        if required:
            raise UnitError(f"{path.name}: has no {key}=")
        return None
    return values[0]


def parse_span(text: str) -> float:
    """A systemd time span such as `5min`, `30s`, `1h` or `5m`, in seconds.

    A plain number is seconds, as in systemd.time(7). Several parts add up,
    `1h 30min`.
    """
    if not SPAN_RE.fullmatch(text.strip()) or not text.strip():
        raise UnitError(f"{text!r} is not a time span")
    total = 0.0
    for number, unit in SPAN_PART_RE.findall(text):
        if unit and unit not in SPAN_UNITS:
            raise UnitError(f"{text!r} uses a unit this worker does not read")
        total += float(number) * SPAN_UNITS.get(unit, 1)
    return total


def parse_daily(text: str) -> tuple[int, int, int]:
    """(hour, minute, second) from `*-*-* 03:17:00`, the one OnCalendar= form
    any unit uses, also with ` UTC` after it. Every other calendar expression
    is refused."""
    text = text.strip().removesuffix(" UTC")
    date, _, clock = text.partition(" ")
    if date != "*-*-*" or not clock:
        raise UnitError(f"OnCalendar={text} is not the daily form"
                        " `*-*-* HH:MM:SS` this worker reads")
    pieces = clock.split(":")
    if len(pieces) == 2:
        pieces.append("00")
    try:
        hour, minute, second = (int(p) for p in pieces)
    except ValueError:
        raise UnitError(f"OnCalendar={text} has no readable time") from None
    if len(pieces) != 3 or not (0 <= hour < 24 and 0 <= minute < 60
                                and 0 <= second < 60):
        raise UnitError(f"OnCalendar={text} has no readable time")
    return hour, minute, second


def parse_bool(text: str, path: Path) -> bool:
    lowered = text.lower()
    if lowered in ("yes", "true", "1", "on"):
        return True
    if lowered in ("no", "false", "0", "off"):
        return False
    raise UnitError(f"{path.name}: {text!r} is not a boolean")


@dataclass
class Service:
    name: str
    argv: list
    working_directory: str
    environment: dict = field(default_factory=dict)
    # TimeoutStartSec=, in seconds, or None when the unit sets none.
    timeout: float | None = None

    @property
    def short(self) -> str:
        """`sweep` for whichports-sweep.service, for the log lines."""
        stem = self.name.rsplit(".", 1)[0]
        return stem.removeprefix("whichports-")


def parse_exec_start(line: str, path: Path) -> list:
    """The ExecStart line as an argv array, or UnitError.

    systemd gives `$`, `%` and the prefixes `@-:+!` their own meanings. None
    of the units uses any of them, so meeting one here means the unit changed
    in a way this worker would get wrong, and it stops instead.
    """
    if not line or line[0] in "@-:+!":
        raise UnitError(f"{path.name}: ExecStart= starts with a prefix"
                        " character this worker does not interpret")
    if "$" in line or "%" in line:
        raise UnitError(f"{path.name}: ExecStart= uses $ or a % specifier,"
                        " which this worker does not expand")
    argv = shlex.split(line)
    if not argv or not argv[0].startswith("/"):
        raise UnitError(f"{path.name}: ExecStart= must start with an"
                        " absolute path")
    return argv


def read_service(path: Path, *, oneshot: bool) -> Service:
    sections = read_unit(path)
    kind = _one(sections, "Service", "Type", path, required=False) or "simple"
    if oneshot and kind != "oneshot":
        raise UnitError(f"{path.name}: a scheduled unit must be"
                        f" Type=oneshot, this one is {kind}")
    argv = parse_exec_start(_one(sections, "Service", "ExecStart", path), path)
    environment = {}
    for key, value in sections.get("Service", []):
        if key != "Environment":
            continue
        for assignment in shlex.split(value):
            name, sep, setting = assignment.partition("=")
            if not sep or not name:
                raise UnitError(f"{path.name}: cannot read Environment={value}")
            environment[name] = setting
    directory = _one(sections, "Service", "WorkingDirectory", path,
                     required=False) or "/"
    timeout = _one(sections, "Service", "TimeoutStartSec", path, required=False)
    return Service(name=path.name, argv=argv, working_directory=directory,
                   environment=environment,
                   timeout=parse_span(timeout) if timeout is not None else None)


@dataclass
class TimerJob:
    timer: str
    service: Service
    on_boot: float | None = None
    every: float | None = None
    jitter: float = 0.0
    daily: tuple | None = None
    persistent: bool = False
    # Seconds until another try when the job was not run at all. None for
    # every job read from a unit file, which keeps systemd's own schedule.
    retry_when_not_run: float | None = None
    # Seconds from start to the first run, in place of the schedule's own.
    # Set only for a CVE build with no extract in its folder.
    first_after: float | None = None


@dataclass
class PathJob:
    path_unit: str
    service: Service
    watched: str


def read_timer(unit_dir: Path, name: str) -> TimerJob:
    path = unit_dir / name
    sections = read_unit(path)
    timer = sections.get("Timer", [])
    if not timer:
        raise UnitError(f"{name}: has no [Timer] section")
    service = read_service(unit_dir / name.replace(".timer", ".service"),
                           oneshot=True)
    job = TimerJob(timer=name, service=service)
    on_boot = _one(sections, "Timer", "OnBootSec", path, required=False)
    every = _one(sections, "Timer", "OnUnitActiveSec", path, required=False)
    jitter = _one(sections, "Timer", "RandomizedDelaySec", path,
                  required=False)
    calendar = _one(sections, "Timer", "OnCalendar", path, required=False)
    persistent = _one(sections, "Timer", "Persistent", path, required=False)
    job.on_boot = parse_span(on_boot) if on_boot is not None else None
    job.every = parse_span(every) if every is not None else None
    job.jitter = parse_span(jitter) if jitter is not None else 0.0
    job.daily = parse_daily(calendar) if calendar is not None else None
    job.persistent = parse_bool(persistent, path) if persistent else False
    monotonic = job.on_boot is not None or job.every is not None
    if monotonic and job.daily is not None:
        raise UnitError(f"{name}: mixes OnCalendar= with monotonic timers,"
                        " which no unit does today")
    if not monotonic and job.daily is None:
        raise UnitError(f"{name}: names no time to run")
    if job.every is None and job.daily is None:
        raise UnitError(f"{name}: runs only once after start, which no unit"
                        " does today")
    if job.every is not None and job.on_boot is None:
        # OnUnitActiveSec= counts from the last run, so on its own it never
        # gives a first one.
        raise UnitError(f"{name}: OnUnitActiveSec= without OnBootSec= never"
                        " starts on its own")
    return job


def read_path_unit(unit_dir: Path, name: str) -> PathJob:
    path = unit_dir / name
    sections = read_unit(path)
    watched = _one(sections, "Path", "PathModified", path)
    if not watched.startswith("/"):
        raise UnitError(f"{name}: PathModified= is not an absolute path")
    service = read_service(unit_dir / name.replace(".path", ".service"),
                           oneshot=True)
    return PathJob(path_unit=name, service=service, watched=watched)


def sync_service(timers: list) -> Service:
    """The command that takes our prober list, run where and as the fast
    lane's unit runs."""
    probe = next(job.service for job in timers if job.timer == SYNC_BORROWS_FROM)
    return Service(name=SYNC_SERVICE, argv=[probe.argv[0], *SYNC_ARGS],
                   working_directory=probe.working_directory,
                   environment=dict(probe.environment))


def sync_job(timers: list, environ=None) -> TimerJob | None:
    """The worker's own job on its schedule, or None when this instance does
    not use our prober API and so has no list to take."""
    environ = os.environ if environ is None else environ
    if not environ.get(PROBER_API_ENV, "").strip():
        return None
    return TimerJob(timer=SYNC_SERVICE.replace(".service", ".timer"),
                    service=sync_service(timers), on_boot=SYNC_FIRST_SECONDS,
                    every=SYNC_EVERY_SECONDS, jitter=SYNC_JITTER_SECONDS,
                    retry_when_not_run=SYNC_RETRY_SECONDS)


def scheduled(timers: list, environ=None) -> list:
    """The timers this instance runs on a schedule: all of them when it uses
    our prober API, and without it all but the probing passes."""
    environ = os.environ if environ is None else environ
    if environ.get(PROBER_API_ENV, "").strip():
        return list(timers)
    return [job for job in timers if job.timer not in PROBING_TIMERS]


def read_all(unit_dir: Path) -> tuple[list, list]:
    """Every job this worker runs, read and checked before any of them
    starts, so a unit it cannot follow stops it at start and not at 03:17."""
    timers = [read_timer(unit_dir, name) for name in TIMERS]
    paths = [read_path_unit(unit_dir, name) for name in PATHS]
    return timers, paths


def output_folder(service: Service) -> Path | None:
    """The folder the command writes, the value after its `--out`."""
    argv = service.argv
    if "--out" not in argv[:-1]:
        return None
    return Path(argv[argv.index("--out") + 1])


def holds_an_extract(folder: Path) -> bool:
    """Whether a release's extract is there, `debian-12.tsv.gz` and the like
    (`controlplane/app/cvestore.py`). A half-written `.part` is none."""
    try:
        return any(path.is_file() for path in folder.glob("*.tsv.gz"))
    except OSError:
        return False


def with_first_build(job: TimerJob) -> TimerJob:
    """The CVE job, with its first run CVE_FIRST_SECONDS after start when
    the folder it writes holds no extract yet. With one there it keeps the
    unit's own schedule."""
    folder = output_folder(job.service)
    if folder is not None and not holds_an_extract(folder):
        job.first_after = CVE_FIRST_SECONDS
    return job


def read_cve(cve_dir: Path) -> TimerJob:
    """The CVE check's daily build, read from its own directory. Missing,
    it stops the worker at start, as any unit of the list would."""
    for name in (CVE_TIMER, CVE_TIMER.replace(".timer", ".service")):
        if not (cve_dir / name).is_file():
            raise UnitError(f"{name} is not in {cve_dir}")
    return read_timer(cve_dir, CVE_TIMER)


# ---------------------------------------------------------------- schedule

def next_daily(after: datetime, hour: int, minute: int, second: int) -> datetime:
    """The first HH:MM:SS UTC strictly after `after`."""
    candidate = after.replace(hour=hour, minute=minute, second=second,
                              microsecond=0)
    if candidate <= after:
        candidate += timedelta(days=1)
    return candidate


def previous_daily(before: datetime, hour: int, minute: int,
                   second: int) -> datetime:
    """The last HH:MM:SS UTC at or before `before`."""
    candidate = before.replace(hour=hour, minute=minute, second=second,
                               microsecond=0)
    if candidate > before:
        candidate -= timedelta(days=1)
    return candidate


def first_delay(job: TimerJob, now: datetime, last_run: datetime | None,
                rng: random.Random) -> float:
    """Seconds from the worker's start to the job's first run."""
    if job.first_after is not None:
        return job.first_after
    jitter = rng.uniform(0, job.jitter)
    if job.daily is None:
        return job.on_boot + jitter
    if job.persistent and last_run is not None \
            and previous_daily(now, *job.daily) > last_run:
        # A run was due while the stack was down. Still subject to the
        # random delay, as the manual says.
        return jitter
    return (next_daily(now, *job.daily) - now).total_seconds() + jitter


def next_delay(job: TimerJob, started: float, finished: float,
               now_wall: datetime, rng: random.Random) -> float:
    """Seconds from the end of a run to the next one.

    `started` and `finished` are monotonic clock readings. A monotonic job is
    due `every` after it started, and if it ran longer than that it is due the
    moment it ends, because a timer that elapses during a run leaves the run
    alone rather than starting a second copy.
    """
    jitter = rng.uniform(0, job.jitter)
    if job.daily is None:
        due = started + job.every
        return max(due - finished, 0.0) + jitter
    return (next_daily(now_wall, *job.daily) - now_wall).total_seconds() \
        + jitter


def stamp_path(state_dir: Path, job: TimerJob) -> Path:
    return state_dir / f"stamp-{job.timer}"


def read_stamp(path: Path) -> datetime | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
    except OSError:
        return None


def write_stamp(path: Path, when: datetime) -> None:
    """The last run's time, kept as the file's modification time, which is
    how systemd keeps its own timer stamps."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
        stamp = when.timestamp()
        os.utime(path, (stamp, stamp))
    except OSError as exc:
        log("worker", f"could not write {path}: {exc}")


def file_signature(path: str):
    """What PathModified= watches, as a tuple that changes when the file is
    written: its inode, size and modification time. None when it is absent."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_ino, st.st_size, st.st_mtime_ns)


# ----------------------------------------------------------------- running

# Every job runs on a thread of its own and they all write to one stdout.
# A line is written whole, under this lock, so two of them never run together
# (seen on 2026-10-02: one job's line ended in the start of another's).
_output_lock = threading.Lock()


def write_line(text: str) -> None:
    with _output_lock:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()


def log(name: str, message: str) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    write_line(f"{stamp} {name}: {message}")


def service_environment(service: Service, base=None) -> dict:
    """The unit's Environment= lines, with the container's own environment
    on top, the order systemd uses for EnvironmentFile= over Environment=."""
    environment = dict(service.environment)
    environment.update(os.environ if base is None else base)
    return environment


class Worker:
    def __init__(self, timers, paths, *, state_dir: Path, rng=None,
                 poll_seconds: float = PATH_POLL_SECONDS):
        self.timers = timers
        self.paths = paths
        self.state_dir = state_dir
        self.rng = rng or random.Random()
        self.poll_seconds = poll_seconds
        self.stopping = threading.Event()
        self._running = {}
        self._running_lock = threading.Lock()
        self._said_no_database = set()

    # One job, start to finish. Returns its exit code, or None when it was
    # not started.
    def run_service(self, service: Service):
        if self.stopping.is_set():
            return None
        environment = service_environment(service)
        database = environment.get("WHICHPORTS_DB")
        if database and not os.path.exists(database) \
                and service.name not in NEEDS_NO_DATABASE:
            # Every command refuses a database that is not there, so running
            # it would print the same refusal every few minutes. One line,
            # once, until the first account makes the file.
            if service.name not in self._said_no_database:
                self._said_no_database.add(service.name)
                log(service.short, f"not run, there is no database yet at"
                    f" {database}. Making the first account creates it")
            return None
        self._said_no_database.discard(service.name)
        log(service.short, "started")
        began = time.monotonic()
        try:
            process = subprocess.Popen(
                service.argv, cwd=service.working_directory, env=environment,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                errors="replace")
        except OSError as exc:
            log(service.short, f"could not start {service.argv[0]}: {exc}")
            return None
        with self._running_lock:
            self._running[service.name] = process
        late = None
        if service.timeout is not None:
            late = threading.Timer(service.timeout, self._end_late,
                                   args=(service, process))
            late.daemon = True
            late.start()
        try:
            for line in process.stdout:
                write_line(f"  {service.short} | {line.rstrip()}")
            code = process.wait()
        finally:
            if late is not None:
                late.cancel()
            with self._running_lock:
                self._running.pop(service.name, None)
        log(service.short, f"exited {code} after"
            f" {time.monotonic() - began:.1f}s")
        return code

    def _end_late(self, service: Service, process) -> None:
        """The job ran past its TimeoutStartSec=: SIGTERM, and SIGKILL when
        it is still there LATE_KILL_SECONDS later."""
        log(service.short, f"still running after its TimeoutStartSec of"
            f" {service.timeout:.0f}s, stopping it")
        try:
            process.terminate()
            process.wait(LATE_KILL_SECONDS)
        except subprocess.TimeoutExpired:
            log(service.short, f"still running {LATE_KILL_SECONDS:.0f}s after"
                " SIGTERM, killing it")
            process.kill()
        except OSError:
            pass

    def _timer_loop(self, job: TimerJob) -> None:
        stamp = stamp_path(self.state_dir, job)
        now = datetime.now(timezone.utc)
        delay = first_delay(job, now, read_stamp(stamp), self.rng)
        log(job.service.short, f"first run in {delay:.0f}s")
        while not self.stopping.wait(delay):
            started = time.monotonic()
            if job.persistent:
                write_stamp(stamp, datetime.now(timezone.utc))
            code = self.run_service(job.service)
            finished = time.monotonic()
            if code is None and job.retry_when_not_run is not None:
                delay = job.retry_when_not_run
                continue
            delay = next_delay(job, started, finished,
                               datetime.now(timezone.utc), self.rng)

    def _path_loop(self, job: PathJob) -> None:
        # A file that already exists does not fire at start, the same as a
        # path unit's PathModified=.
        seen = file_signature(job.watched)
        log(job.service.short, f"watching {job.watched}")
        while not self.stopping.wait(self.poll_seconds):
            current = file_signature(job.watched)
            if current == seen or current is None:
                seen = current
                continue
            # Taken before the run, so a write during the run differs at the
            # next look and gets a run of its own.
            seen = current
            self.run_service(job.service)

    def stop(self, *_signal) -> None:
        """Stop scheduling and pass the stop on to whatever is running, the
        way systemd stops a running oneshot when the box shuts down."""
        self.stopping.set()
        with self._running_lock:
            running = list(self._running.values())
        for process in running:
            try:
                process.terminate()
            except OSError:
                pass

    def run(self) -> int:
        threads = [threading.Thread(target=self._timer_loop, args=(job,),
                                    name=job.timer, daemon=True)
                   for job in self.timers]
        threads += [threading.Thread(target=self._path_loop, args=(job,),
                                     name=job.path_unit, daemon=True)
                    for job in self.paths]
        for thread in threads:
            thread.start()
        # Joined with a timeout so the main thread keeps running Python code
        # and the signal handler gets its turn.
        while any(thread.is_alive() for thread in threads):
            for thread in threads:
                thread.join(0.5)
        log("worker", "stopped")
        return 0


# ------------------------------------------------------------ at start

def take_apart_invite(service: Service, environ=None) -> None:
    """Turn the invite line into the three settings the control plane reads.

    `.env` may carry our probers as one line, WHICHPORTS_PROBER_INVITE, the
    way the installer writes it, instead of the three lines
    WHICHPORTS_PROBER_API, WHICHPORTS_PROBER_API_KEY and
    WHICHPORTS_PROBER_PROOF_KEY. This worker starts every process of the
    stack, so it takes the line apart here, once, before any check, schedule
    or job reads the environment, and everything after it reads the three as
    it always did. The line itself is then removed, so no job is handed it.

    The rule is the control plane's own, `app/invite.py`, loaded by its path
    the way `check_settings` loads `app/publicurl.py`. That file says why the
    two keys inside the line stay apart. A line that cannot be taken apart,
    or one set beside any of the three lines, stops the start in one line
    that names the setting and never the value.
    """
    environ = os.environ if environ is None else environ
    module = Path(service.working_directory) / "app" / "invite.py"
    if not module.is_file():
        return
    spec = importlib.util.spec_from_file_location("whichports_invite", module)
    invite = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(invite)
    try:
        three = invite.settings(service_environment(service, environ))
    except invite.InviteError as exc:
        raise SettingError(str(exc)) from None
    if three:
        environ.update(three)
        environ.pop(invite.INVITE_ENV, None)


def check_settings(service: Service) -> None:
    """Refuse to start when a setting is wrong in a way that would otherwise
    surface only at the first click.

    Two settings. WHICHPORTS_BASE_URL: malformed, the Add server window
    refuses and the sweep's mail stops, so the container says so at start, in
    one line, and does not come up (docs/record 4.226). And
    WHICHPORTS_ALERTS_TO_PRIVATE_ADDRESSES, which loosens where an alert may
    be sent and is on only when it reads exactly `yes`: any other value stops
    the start, so a typing error is never taken for on or for off
    (docs/record 4.336).

    The rule is the control plane's own, `app/publicurl.py`, loaded from the
    unit's working directory as a file, so this worker never restates it and
    never puts that directory on its import path. A directory without that
    module is not the control plane, as in this file's tests, and has nothing
    to check.
    """
    module = Path(service.working_directory) / "app" / "publicurl.py"
    if not module.is_file():
        return
    spec = importlib.util.spec_from_file_location("whichports_publicurl",
                                                  module)
    publicurl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(publicurl)
    try:
        publicurl.base(service_environment(service))
    except publicurl.PublicUrlError as exc:
        raise SettingError(str(exc)) from None

    # The same way for the second rule, `app/outbound.py`. A control plane
    # from before that file has no such setting to get wrong.
    module = Path(service.working_directory) / "app" / "outbound.py"
    if not module.is_file():
        return
    spec = importlib.util.spec_from_file_location("whichports_outbound",
                                                  module)
    outbound = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(outbound)
    complaint = outbound.setting_complaint(service_environment(service))
    if complaint:
        raise SettingError(complaint)


# ----------------------------------------------------------------- commands

def command_run(args) -> int:
    timers, paths = read_all(args.units)
    cve = with_first_build(read_cve(args.cve_units))
    take_apart_invite(timers[0].service)
    check_settings(timers[0].service)
    # The sync borrows from the fast lane's unit, so it is built from the
    # whole list, before the probing passes are taken out of the schedule.
    own = sync_job(timers)
    timers = scheduled(timers)
    timers.append(cve)
    if own is not None:
        timers.append(own)
    else:
        log("worker", f"no prober list to take: {PROBER_API_ENV} is not set")
        log("worker", f"{' and '.join(PROBING_TIMERS)} are not scheduled:"
            f" {PROBER_API_ENV} is not set, so there is nothing to probe with")
    for job in timers:
        when = (f"daily at {job.daily[0]:02d}:{job.daily[1]:02d}:"
                f"{job.daily[2]:02d} UTC" if job.daily
                else f"every {job.every:.0f}s")
        log("worker", f"{job.timer}: {' '.join(job.service.argv)}, {when},"
            f" up to {job.jitter:.0f}s later")
    for job in paths:
        log("worker", f"{job.path_unit}: {' '.join(job.service.argv)},"
            f" when {job.watched} is written")
    if cve.first_after is not None:
        log("worker", f"{CVE_TIMER}: no extract in {output_folder(cve.service)}"
            f" yet, so a first build {cve.first_after:.0f}s after start")
    database = os.environ.get("WHICHPORTS_DB") or \
        timers[0].service.environment.get("WHICHPORTS_DB", "")
    state_dir = Path(database).parent / "worker" if database else Path("/tmp")
    worker = Worker(timers, paths, state_dir=state_dir)
    signal.signal(signal.SIGTERM, worker.stop)
    signal.signal(signal.SIGINT, worker.stop)
    return worker.run()


def command_once(args) -> int:
    """Run one scheduled unit now, in the foreground. For a backup on
    demand, or to see a sweep's output without waiting five minutes."""
    allowed = {name.replace(".timer", ".service") for name in TIMERS}
    allowed |= {name.replace(".path", ".service") for name in PATHS}
    allowed.add(SYNC_SERVICE)
    cve_service = CVE_TIMER.replace(".timer", ".service")
    allowed.add(cve_service)
    if args.unit not in allowed:
        print(f"{args.unit} is not a unit this worker schedules. It runs: "
              + ", ".join(sorted(allowed)), file=sys.stderr)
        return 2
    if args.unit == SYNC_SERVICE:
        # Asked for by name, so it runs whether or not the API is set, and
        # the command itself says what is missing.
        timers, _paths = read_all(args.units)
        service = sync_service(timers)
    elif args.unit == cve_service:
        service = read_cve(args.cve_units).service
    else:
        service = read_service(args.units / args.unit, oneshot=True)
    take_apart_invite(service)
    worker = Worker([], [], state_dir=Path("/tmp"))
    signal.signal(signal.SIGTERM, worker.stop)
    code = worker.run_service(service)
    return 1 if code is None else code


def with_port(argv: list, environment: dict, unit: str) -> list:
    """The unit's command with the value after `--port` replaced, when the
    environment moves the ingest off the unit's own port.

    Every other word of the command stays the unit's, the `--host 127.0.0.1`
    included. A port already in use is uvicorn's own start-up failure, which
    names the address, and nothing here falls back to another one.
    """
    wanted = environment.get(INGEST_PORT_ENV, "").strip()
    if not wanted:
        return argv
    if not wanted.isdigit() or not 1 <= int(wanted) <= 65535:
        raise SettingError(f"{INGEST_PORT_ENV} is a port number from 1 to"
                           f" 65535. {wanted!r} is not")
    if "--port" not in argv[:-1]:
        raise UnitError(f"{unit}: has no --port to move")
    at = argv.index("--port")
    return argv[:at + 1] + [wanted] + argv[at + 2:]


def command_exec(args) -> int:
    """Become the unit's ExecStart, so the container's main process is that
    command with that unit's flags, read from the file prod installs."""
    service = read_service(args.units / args.unit, oneshot=False)
    take_apart_invite(service)
    check_settings(service)
    environment = service_environment(service)
    argv = with_port(service.argv, environment, service.name)
    os.chdir(service.working_directory)
    os.execve(argv[0], argv, environment)
    return 1  # not reached, execve replaces this process or raises


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--units", type=Path, default=DEFAULT_UNIT_DIR,
                        help="the directory holding the unit files")
    parser.add_argument("--cve-units", type=Path, default=DEFAULT_CVE_UNIT_DIR,
                        help="the directory holding the CVE build's two unit"
                             " files")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="run every scheduled unit on its schedule")
    p_once = sub.add_parser("once", help="run one scheduled unit now")
    p_once.add_argument("unit")
    p_exec = sub.add_parser("exec", help="become a unit's ExecStart")
    p_exec.add_argument("unit")
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            return command_run(args)
        if args.command == "once":
            return command_once(args)
        return command_exec(args)
    except (UnitError, SettingError) as exc:
        print(f"worker: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
