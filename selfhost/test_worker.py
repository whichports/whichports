"""The Compose worker reads prod's unit files and runs them on their schedule.

Two kinds of test here. The first reads the real files in controlplane/ops on
every gate run, so a unit change this worker cannot follow fails here before
it fails a self-hosted instance. The second drives the scheduler with small
units of its own, against real processes and a real clock.
"""
import os
import random
import signal
import subprocess
import sys
import textwrap
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import worker

REPO = Path(__file__).resolve().parent.parent
OPS = REPO / "controlplane" / "ops"
CVE_UNITS = REPO / "ops" / "cve"


class MaxRandom(random.Random):
    """Always the top of the range, so a jitter's bound is what is tested."""

    def uniform(self, a, b):
        return b


class MinRandom(random.Random):
    def uniform(self, a, b):
        return a


def write(directory: Path, name: str, text: str) -> Path:
    path = directory / name
    path.write_text(textwrap.dedent(text).lstrip())
    return path


def oneshot(directory: Path, name: str, argv: str, extra: str = "") -> None:
    write(directory, name, f"""
        [Service]
        Type=oneshot
        WorkingDirectory={directory}
        ExecStart={argv}
        {extra}
        """)


# ------------------------------------------------------- the real units

def test_every_real_unit_it_runs_reads_cleanly():
    timers, paths = worker.read_all(OPS)
    assert [job.timer for job in timers] == list(worker.TIMERS)
    assert [job.path_unit for job in paths] == list(worker.PATHS)
    for job in timers:
        assert job.every or job.daily, job.timer
        assert job.service.argv[0] == "/srv/controlplane/.venv/bin/python"
        assert job.service.working_directory == "/srv/controlplane"
        # The backup names its database with --db instead.
        assert job.service.environment.get(
            "WHICHPORTS_DB", "/var/lib/whichports-controlplane/whichports.db") \
            == "/var/lib/whichports-controlplane/whichports.db"


def test_the_backup_reads_its_continued_execstart_whole():
    timers, _ = worker.read_all(OPS)
    backup = next(j for j in timers if j.timer == "whichports-backup.timer")
    argv = backup.service.argv
    assert argv[1:4] == ["-m", "app.backup", "--db"]
    assert "--dest" in argv and "--keep" in argv
    assert backup.daily is not None and backup.persistent


def test_the_scan_path_watches_the_trigger_beside_the_database():
    _, paths = worker.read_all(OPS)
    (scan,) = paths
    assert scan.watched == "/var/lib/whichports-controlplane/scan-requested"
    assert scan.service.argv[2:4] == ["app.scan_cli", "drain"]


def test_every_unit_in_the_directory_is_run_here_or_said_not_to_be():
    on_disk = {p.name for p in OPS.iterdir() if p.suffix in
               (".timer", ".path", ".service")}
    scheduled = set(worker.TIMERS) | set(worker.PATHS)
    triggered = {n.rsplit(".", 1)[0] + ".service" for n in scheduled}
    accounted = scheduled | triggered | set(worker.NOT_SCHEDULED_HERE)
    assert on_disk - accounted == set(), \
        "a unit in controlplane/ops that the worker neither runs nor names"
    assert accounted - on_disk == set(), \
        "the worker names a unit that controlplane/ops no longer has"


def test_the_ingest_unit_binds_loopback_and_keeps_proxy_headers_off():
    """The controlplane container runs this line through `exec`. The bind
    stays 127.0.0.1 in every Compose variant, and --no-proxy-headers is what
    the proof rule stands on (ingest.observed_source_address)."""
    service = worker.read_service(OPS / "whichports-ingest.service",
                                  oneshot=False)
    argv = service.argv
    assert argv[argv.index("--host") + 1] == "127.0.0.1"
    assert "--no-proxy-headers" in argv
    assert argv[0] == "/srv/controlplane/.venv/bin/uvicorn"


def test_the_ingest_writes_no_access_log_in_the_container_either():
    """A link a mail carries holds its token in the path, and uvicorn's
    access log writes every path to the container's log. The port is the one
    word `with_port` changes, so the flag survives it."""
    service = worker.read_service(OPS / "whichports-ingest.service",
                                  oneshot=False)
    moved = worker.with_port(service.argv, {worker.INGEST_PORT_ENV: "8411"},
                             "whichports-ingest.service")
    assert "--no-access-log" in service.argv
    assert "--no-access-log" in moved


def test_the_prober_api_worker_is_not_in_any_schedule():
    names = set(worker.TIMERS) | set(worker.PATHS)
    assert not any("proberapi" in name for name in names)


# ------------------------------------------------------------- parsing

def test_the_real_cve_pair_reads_cleanly_from_its_own_directory():
    """The CVE check's daily build, the very unit pair our box installs
    (ops/cve/install-on-the-box.sh): its time, its delay, its catch-up, its
    time limit and its command, read as the worker will run them."""
    job = worker.read_cve(CVE_UNITS)
    assert job.timer == "whichports-cve.timer"
    assert job.daily == (4, 41, 0)
    assert job.jitter == 600.0 and job.persistent
    assert job.service.name == "whichports-cve.service"
    assert job.service.timeout == 900.0
    assert job.service.working_directory == "/srv/controlplane"
    assert job.service.argv == ["/srv/controlplane/.venv/bin/python", "-m",
                                "app.cvesync_cli", "build", "--out",
                                "/var/lib/whichports-cve"]


def cve_job(folder: Path) -> worker.TimerJob:
    service = worker.Service("whichports-cve.service",
                             ["/bin/true", "build", "--out", str(folder)], "/", {})
    return worker.TimerJob(timer="whichports-cve.timer", service=service,
                           jitter=600.0, daily=(4, 41, 0), persistent=True)


def test_a_new_instance_builds_two_minutes_after_start_and_only_then(tmp_path):
    """A new instance has no extract, and every port of it would read `no
    security data` until the next 04:41. So its first build comes two
    minutes after the worker starts. The daily time stays the unit's."""
    folder = tmp_path / "cve"
    now = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)
    job = worker.with_first_build(cve_job(folder))
    assert job.first_after == worker.CVE_FIRST_SECONDS == 120.0
    assert worker.first_delay(job, now, None, MaxRandom()) == 120.0
    # After that first build the next is at 04:41, as the unit says.
    after = worker.next_delay(job, 0.0, 45.0, now, MinRandom())
    assert after == (datetime(2026, 10, 15, 4, 41, tzinfo=timezone.utc) - now).total_seconds()


def test_a_restart_with_the_extracts_there_waits_for_its_time(tmp_path):
    folder = tmp_path / "cve"
    folder.mkdir()
    (folder / "debian-12.tsv.gz").write_bytes(b"x")
    now = datetime(2026, 10, 14, 9, 0, tzinfo=timezone.utc)
    job = worker.with_first_build(cve_job(folder))
    assert job.first_after is None
    assert worker.first_delay(job, now, now, MinRandom()) == \
        (datetime(2026, 10, 15, 4, 41, tzinfo=timezone.utc) - now).total_seconds()


def test_a_half_written_file_alone_is_no_extract(tmp_path):
    folder = tmp_path / "cve"
    folder.mkdir()
    (folder / "debian-12.tsv.gz.part").write_bytes(b"x")
    assert not worker.holds_an_extract(folder)
    assert worker.with_first_build(cve_job(folder)).first_after == 120.0


def test_a_job_whose_command_names_no_folder_keeps_its_schedule(tmp_path):
    service = worker.Service("whichports-cve.service", ["/bin/true", "build"], "/", {})
    job = worker.TimerJob(timer="whichports-cve.timer", service=service,
                          daily=(4, 41, 0))
    assert worker.with_first_build(job).first_after is None
    # And the real unit names the folder the control plane reads.
    real = worker.read_cve(CVE_UNITS)
    assert worker.output_folder(real.service) == Path("/var/lib/whichports-cve")


def test_a_missing_cve_pair_stops_it_at_start(tmp_path):
    with pytest.raises(worker.UnitError, match="whichports-cve.timer is not in"):
        worker.read_cve(tmp_path)
    (tmp_path / "whichports-cve.timer").write_text((CVE_UNITS / "whichports-cve.timer").read_text())
    with pytest.raises(worker.UnitError, match="whichports-cve.service is not in"):
        worker.read_cve(tmp_path)


def test_a_missing_cve_pair_stops_run_with_its_name(tmp_path):
    done = run_cli("--units", str(OPS), "--cve-units", str(tmp_path), "run")
    assert done.returncode == 2
    assert "whichports-cve.timer is not in" in done.stderr


@pytest.mark.parametrize("text,seconds", [
    ("30s", 30), ("60s", 60), ("5min", 300), ("5m", 300), ("1h", 3600),
    ("10min", 600), ("50", 50), ("1h 30min", 5400), ("2 hours", 7200),
])
def test_time_spans(text, seconds):
    assert worker.parse_span(text) == seconds


@pytest.mark.parametrize("text", ["", "5d", "1ms", "abc", "5 min x", "-5s"])
def test_time_spans_it_will_not_guess(text):
    with pytest.raises(worker.UnitError):
        worker.parse_span(text)


def test_daily_calendar():
    assert worker.parse_daily("*-*-* 03:17:00") == (3, 17, 0)
    # The CVE timer writes its zone. The container's clock is UTC already.
    assert worker.parse_daily("*-*-* 04:41:00 UTC") == (4, 41, 0)
    assert worker.parse_daily("*-*-* 23:05") == (23, 5, 0)


@pytest.mark.parametrize("text", ["daily", "Mon *-*-* 03:00:00",
                                  "*-*-01 03:00:00", "*-*-* 25:00:00",
                                  "*-*-* 03:xx:00", "*-*-*",
                                  "*-*-* 04:41:00 Europe/Brussels",
                                  "*-*-* 04:41:00 CET"])
def test_calendars_it_will_not_guess(text):
    with pytest.raises(worker.UnitError):
        worker.parse_daily(text)


def test_an_unknown_directive_stops_it(tmp_path):
    # TimeoutStartSec= was the example here until the CVE unit brought it
    # in, honoured. RuntimeMaxSec= is one no unit uses.
    oneshot(tmp_path, "x.service", "/bin/true", "RuntimeMaxSec=5min")
    with pytest.raises(worker.UnitError, match="RuntimeMaxSec"):
        worker.read_service(tmp_path / "x.service", oneshot=True)


def test_an_unknown_section_stops_it(tmp_path):
    write(tmp_path, "x.socket", "[Socket]\nListenStream=80\n")
    with pytest.raises(worker.UnitError, match="Socket"):
        worker.read_unit(tmp_path / "x.socket")


@pytest.mark.parametrize("line", [
    "-/bin/true", "@/bin/true x", "+/bin/true", "!/bin/true", ":/bin/true",
    "/bin/echo $HOME", "/bin/echo %h", "bin/true", "true",
])
def test_execstart_it_will_not_interpret(tmp_path, line):
    oneshot(tmp_path, "x.service", line)
    with pytest.raises(worker.UnitError):
        worker.read_service(tmp_path / "x.service", oneshot=True)


def test_a_scheduled_unit_must_be_a_oneshot(tmp_path):
    write(tmp_path, "x.service", "[Service]\nExecStart=/bin/true\n")
    with pytest.raises(worker.UnitError, match="oneshot"):
        worker.read_service(tmp_path / "x.service", oneshot=True)
    # The same file is fine to become, which is what the ingest is.
    worker.read_service(tmp_path / "x.service", oneshot=False)


def test_two_execstarts_stop_it(tmp_path):
    oneshot(tmp_path, "x.service", "/bin/true", "ExecStart=/bin/false")
    with pytest.raises(worker.UnitError, match="2 times"):
        worker.read_service(tmp_path / "x.service", oneshot=True)


def test_environment_lines(tmp_path):
    oneshot(tmp_path, "x.service", "/bin/true",
            'Environment=A=1 "B=two words"\nEnvironment=C=3')
    service = worker.read_service(tmp_path / "x.service", oneshot=True)
    assert service.environment == {"A": "1", "B": "two words", "C": "3"}


def test_a_dangling_continuation_stops_it(tmp_path):
    write(tmp_path, "x.service", "[Service]\nExecStart=/bin/true \\\n")
    with pytest.raises(worker.UnitError, match="backslash"):
        worker.read_unit(tmp_path / "x.service")


def test_a_timer_that_never_starts_on_its_own_stops_it(tmp_path):
    oneshot(tmp_path, "x.service", "/bin/true")
    write(tmp_path, "x.timer", "[Timer]\nOnUnitActiveSec=5min\n")
    with pytest.raises(worker.UnitError, match="never"):
        worker.read_timer(tmp_path, "x.timer")


def test_a_timer_that_runs_only_once_stops_it(tmp_path):
    oneshot(tmp_path, "x.service", "/bin/true")
    write(tmp_path, "x.timer", "[Timer]\nOnBootSec=5min\n")
    with pytest.raises(worker.UnitError, match="once"):
        worker.read_timer(tmp_path, "x.timer")


def test_a_missing_service_file_stops_it(tmp_path):
    write(tmp_path, "x.timer", "[Timer]\nOnBootSec=1\nOnUnitActiveSec=1\n")
    with pytest.raises(OSError):
        worker.read_timer(tmp_path, "x.timer")


# ------------------------------------------------------------ schedule

def monotonic_job(on_boot=180, every=300, jitter=30):
    service = worker.Service("x.service", ["/bin/true"], "/")
    return worker.TimerJob("x.timer", service, on_boot=on_boot, every=every,
                           jitter=jitter)


def daily_job(persistent=True, jitter=300):
    service = worker.Service("b.service", ["/bin/true"], "/")
    return worker.TimerJob("b.timer", service, jitter=jitter,
                           daily=(3, 17, 0), persistent=persistent)


NOW = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_first_run_is_on_boot_plus_at_most_the_jitter():
    job = monotonic_job()
    assert worker.first_delay(job, NOW, None, MinRandom()) == 180
    assert worker.first_delay(job, NOW, None, MaxRandom()) == 210


def test_next_run_counts_from_the_last_start():
    job = monotonic_job()
    # Started at 1000, took 20 seconds: due at 1300, so 280 from the end.
    assert worker.next_delay(job, 1000, 1020, NOW, MinRandom()) == 280
    assert worker.next_delay(job, 1000, 1020, NOW, MaxRandom()) == 310


def test_a_run_longer_than_its_interval_is_followed_at_once_not_doubled():
    job = monotonic_job()
    assert worker.next_delay(job, 1000, 1400, NOW, MinRandom()) == 0


def test_daily_waits_for_the_next_0317_utc():
    job = daily_job()
    delay = worker.first_delay(job, NOW, None, MinRandom())
    expected = datetime(2026, 10, 2, 3, 17, tzinfo=timezone.utc) - NOW
    assert delay == expected.total_seconds()


def test_persistent_catches_up_a_run_missed_while_down():
    job = daily_job()
    yesterday_before_0317 = datetime(2026, 9, 30, 2, 0, tzinfo=timezone.utc)
    assert worker.first_delay(job, NOW, yesterday_before_0317,
                              MaxRandom()) == 300


def test_persistent_does_not_repeat_a_run_already_taken_today():
    job = daily_job()
    today_after_0317 = datetime(2026, 10, 1, 3, 20, tzinfo=timezone.utc)
    delay = worker.first_delay(job, NOW, today_after_0317, MinRandom())
    assert delay > 12 * 3600


def test_no_catch_up_without_persistent():
    job = daily_job(persistent=False)
    long_ago = NOW - timedelta(days=30)
    assert worker.first_delay(job, NOW, long_ago, MinRandom()) > 12 * 3600


def test_daily_next_is_tomorrow_after_tonights_run():
    job = daily_job()
    just_after = datetime(2026, 10, 1, 3, 17, 5, tzinfo=timezone.utc)
    delay = worker.next_delay(job, 0, 5, just_after, MinRandom())
    assert delay == (timedelta(days=1) - timedelta(seconds=5)).total_seconds()


def test_stamp_round_trip(tmp_path):
    job = daily_job()
    path = worker.stamp_path(tmp_path / "state", job)
    assert worker.read_stamp(path) is None
    worker.write_stamp(path, NOW)
    assert worker.read_stamp(path) == NOW


def test_file_signature(tmp_path):
    target = tmp_path / "scan-requested"
    assert worker.file_signature(str(target)) is None
    target.write_text("")
    first = worker.file_signature(str(target))
    time.sleep(0.01)
    target.write_text("x")
    assert worker.file_signature(str(target)) != first


# ------------------------------------------------------------- running

def py(code: str) -> list:
    return [sys.executable, "-c", code]


def service(tmp_path, argv, environment=None):
    return worker.Service("t.service", argv, str(tmp_path),
                          environment or {})


def quiet_worker(tmp_path, timers=(), paths=(), **kwargs):
    return worker.Worker(list(timers), list(paths), state_dir=tmp_path,
                         **kwargs)


def test_a_job_runs_and_reports_its_exit_code(tmp_path, capsys):
    w = quiet_worker(tmp_path)
    code = w.run_service(service(tmp_path, py("print('hello'); raise SystemExit(3)")))
    assert code == 3
    out = capsys.readouterr().out
    assert "t | hello" in out and "exited 3" in out


def test_the_container_environment_wins_over_the_unit(tmp_path, monkeypatch):
    monkeypatch.setenv("WHICHPORTS_TEST_VALUE", "from-container")
    out = tmp_path / "seen"
    w = quiet_worker(tmp_path)
    w.run_service(service(
        tmp_path,
        py(f"import os; open({str(out)!r}, 'w').write("
           "os.environ['WHICHPORTS_TEST_VALUE'] + ' ' + os.environ['ONLY_UNIT'])"),
        {"WHICHPORTS_TEST_VALUE": "from-unit", "ONLY_UNIT": "kept"}))
    assert out.read_text() == "from-container kept"


def test_no_database_yet_means_not_run_and_said_once(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("WHICHPORTS_DB", raising=False)
    marker = tmp_path / "ran"
    job = service(tmp_path, py(f"open({str(marker)!r}, 'w')"),
                  {"WHICHPORTS_DB": str(tmp_path / "absent.db")})
    w = quiet_worker(tmp_path)
    assert w.run_service(job) is None
    assert w.run_service(job) is None
    assert not marker.exists()
    assert capsys.readouterr().out.count("no database yet") == 1
    (tmp_path / "absent.db").write_text("")
    assert w.run_service(job) == 0
    assert marker.exists()


def test_a_job_past_its_timeoutstartsec_is_stopped(tmp_path, capsys):
    """systemd.service(5): past TimeoutStartSec= the service "will be shut
    down again", by SIGTERM by default."""
    job = worker.Service("t.service", py("import time; time.sleep(60)"),
                         str(tmp_path), {}, timeout=1.0)
    started = time.monotonic()
    code = quiet_worker(tmp_path).run_service(job)
    assert time.monotonic() - started < 15
    assert code == -signal.SIGTERM
    assert "still running after its TimeoutStartSec of 1s, stopping it" in capsys.readouterr().out


def test_a_job_that_ignores_sigterm_is_killed(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(worker, "LATE_KILL_SECONDS", 1.0)
    job = worker.Service("t.service", py(
        "import signal, sys, time\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "print('ignoring', flush=True)\n"
        "time.sleep(60)"), str(tmp_path), {}, timeout=1.0)
    code = quiet_worker(tmp_path).run_service(job)
    assert code == -signal.SIGKILL
    assert "killing it" in capsys.readouterr().out


def test_a_job_within_its_timeoutstartsec_is_left_alone(tmp_path):
    job = worker.Service("t.service", py("raise SystemExit(4)"), str(tmp_path),
                         {}, timeout=30.0)
    assert quiet_worker(tmp_path).run_service(job) == 4


def test_the_cve_build_runs_with_no_database_and_nothing_else_does(tmp_path, monkeypatch):
    """The build reads the vendors' files and opens no database, so it runs
    on an instance that has no account yet. Any other job still waits."""
    monkeypatch.delenv("WHICHPORTS_DB", raising=False)
    marker = tmp_path / "built"
    absent = {"WHICHPORTS_DB": str(tmp_path / "absent.db")}
    build = worker.Service("whichports-cve.service", py(f"open({str(marker)!r}, 'w')"),
                           str(tmp_path), absent)
    other = worker.Service("whichports-sweep.service", py(f"open({str(marker)!r}, 'w')"),
                           str(tmp_path), absent)
    w = quiet_worker(tmp_path)
    assert w.run_service(other) is None and not marker.exists()
    assert w.run_service(build) == 0 and marker.exists()
    assert worker.NEEDS_NO_DATABASE == {"whichports-cve.service"}


def test_memorymax_is_read_and_a_time_limit_is_kept(tmp_path):
    oneshot(tmp_path, "m.service", "/bin/true", "MemoryMax=1G\nTimeoutStartSec=15min")
    read = worker.read_service(tmp_path / "m.service", oneshot=True)
    assert read.timeout == 900.0


def test_a_command_that_is_not_there_does_not_stop_the_worker(tmp_path, capsys):
    w = quiet_worker(tmp_path)
    assert w.run_service(service(tmp_path, [str(tmp_path / "nope")])) is None
    assert "could not start" in capsys.readouterr().out


def test_it_never_asks_for_a_shell(tmp_path, monkeypatch):
    seen = {}
    real = subprocess.Popen

    def spy(argv, **kwargs):
        seen["argv"], seen["kwargs"] = argv, kwargs
        return real(argv, **kwargs)

    monkeypatch.setattr(worker.subprocess, "Popen", spy)
    quiet_worker(tmp_path).run_service(service(tmp_path, py("pass")))
    assert isinstance(seen["argv"], list)
    assert not seen["kwargs"].get("shell")


def test_the_timer_loop_runs_again_and_stop_ends_a_running_job(tmp_path):
    count = tmp_path / "count"
    job = worker.TimerJob(
        "t.timer",
        service(tmp_path, py(
            f"open({str(count)!r}, 'a').write('x');"
            "import time; time.sleep(30) if len(open("
            f"{str(count)!r}).read()) >= 3 else None")),
        on_boot=0, every=0.05, jitter=0)
    w = quiet_worker(tmp_path, timers=[job])
    thread = threading.Thread(target=w.run)
    thread.start()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and len(count.read_text()
                                              if count.exists() else "") < 3:
        time.sleep(0.02)
    time.sleep(0.2)  # the third run is now in its 30 second sleep
    began = time.monotonic()
    w.stop()
    thread.join(10)
    assert not thread.is_alive()
    assert time.monotonic() - began < 5, "stop waited out the running job"
    assert len(count.read_text()) == 3


def test_the_path_watch_runs_on_a_write_and_again_for_a_write_during_a_run(tmp_path):
    trigger = tmp_path / "scan-requested"
    runs = tmp_path / "runs"
    gate = tmp_path / "gate"
    # Each run records itself, and the first one waits until the test has
    # written the trigger a second time, so that write lands mid-run.
    code = (f"import os, time\n"
            f"open({str(runs)!r}, 'a').write('x')\n"
            f"if len(open({str(runs)!r}).read()) == 1:\n"
            f"    while not os.path.exists({str(gate)!r}): time.sleep(0.01)\n")
    job = worker.PathJob("t.path", service(tmp_path, py(code)), str(trigger))
    w = quiet_worker(tmp_path, paths=[job], poll_seconds=0.02)
    thread = threading.Thread(target=w.run)
    thread.start()
    try:
        time.sleep(0.1)
        trigger.write_text("1")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not runs.exists():
            time.sleep(0.01)
        time.sleep(0.05)
        trigger.write_text("22")
        gate.write_text("")
        while time.monotonic() < deadline and len(runs.read_text()) < 2:
            time.sleep(0.01)
        time.sleep(0.2)
        assert runs.read_text() == "xx"
    finally:
        w.stop()
        thread.join(10)


def test_a_file_that_was_already_there_does_not_fire_at_start(tmp_path):
    trigger = tmp_path / "scan-requested"
    trigger.write_text("old")
    ran = tmp_path / "ran"
    job = worker.PathJob("t.path", service(tmp_path, py(
        f"open({str(ran)!r}, 'w')")), str(trigger))
    w = quiet_worker(tmp_path, paths=[job], poll_seconds=0.02)
    thread = threading.Thread(target=w.run)
    thread.start()
    time.sleep(0.3)
    w.stop()
    thread.join(10)
    assert not ran.exists()


# ------------------------------------------------------------ commands

def run_cli(*args, env=None):
    return subprocess.run([sys.executable, str(Path(worker.__file__)), *args],
                          capture_output=True, text=True, timeout=60,
                          env=env)


def test_once_refuses_a_unit_it_does_not_schedule():
    done = run_cli("--units", str(OPS), "once", "whichports-ingest.service")
    assert done.returncode == 2
    assert "not a unit this worker schedules" in done.stderr


def test_exec_becomes_the_units_command(tmp_path):
    out = tmp_path / "out"
    write(tmp_path, "x.service", f"""
        [Service]
        WorkingDirectory={tmp_path}
        Environment=FROM_UNIT=yes
        ExecStart={sys.executable} -c "import os; open('out', 'w').write(os.getcwd() + ' ' + os.environ['FROM_UNIT'])"
        """)
    done = run_cli("--units", str(tmp_path), "exec", "x.service")
    assert done.returncode == 0, done.stderr
    assert out.read_text() == f"{tmp_path.resolve()} yes" or \
        out.read_text() == f"{tmp_path} yes"


def test_a_unit_it_cannot_follow_stops_run_at_start(tmp_path):
    for name in worker.TIMERS + worker.PATHS:
        (tmp_path / name).write_text((OPS / name).read_text())
        service_name = name.rsplit(".", 1)[0] + ".service"
        (tmp_path / service_name).write_text((OPS / service_name).read_text())
    sweep = tmp_path / "whichports-sweep.timer"
    sweep.write_text(sweep.read_text().replace("[Timer]",
                                               "[Timer]\nAccuracySec=1us"))
    done = run_cli("--units", str(tmp_path), "run")
    assert done.returncode == 2
    assert "AccuracySec" in done.stderr


# ------------------------------------------------------------ at start

def control_plane_dir(tmp_path: Path) -> Path:
    """A working directory holding the control plane's own publicurl.py,
    the one module the start check loads."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "publicurl.py").write_text(
        (REPO / "controlplane" / "app" / "publicurl.py").read_text())
    write(tmp_path, "x.service", f"""
        [Service]
        WorkingDirectory={tmp_path}
        ExecStart={sys.executable} -c "open('started', 'w')"
        """)
    return tmp_path


def env_with(**values):
    environment = {k: v for k, v in os.environ.items()
                   if k != "WHICHPORTS_BASE_URL"}
    environment.update(values)
    return environment


def test_a_malformed_base_url_stops_exec_at_start_in_one_line(tmp_path):
    directory = control_plane_dir(tmp_path)
    done = run_cli("--units", str(directory), "exec", "x.service",
                   env=env_with(WHICHPORTS_BASE_URL="http://x.example.com"))
    assert done.returncode == 2
    assert done.stderr.count("\n") == 1
    assert "WHICHPORTS_BASE_URL" in done.stderr
    assert not (directory / "started").exists()


@pytest.mark.parametrize("value", ["", "https://x.example.com"])
def test_a_good_or_absent_base_url_starts(tmp_path, value):
    directory = control_plane_dir(tmp_path)
    done = run_cli("--units", str(directory), "exec", "x.service",
                   env=env_with(WHICHPORTS_BASE_URL=value))
    assert done.returncode == 0, done.stderr
    assert (directory / "started").exists()


def test_the_check_reads_the_unit_environment_under_the_containers(tmp_path):
    directory = control_plane_dir(tmp_path)
    service = worker.read_service(directory / "x.service", oneshot=False)
    service.environment["WHICHPORTS_BASE_URL"] = "http://from-the-unit"
    with pytest.raises(worker.SettingError):
        worker.check_settings(service)


SETTING = "WHICHPORTS_ALERTS_TO_PRIVATE_ADDRESSES"


def with_the_outbound_rule(directory: Path) -> Path:
    """The control plane's own outbound.py beside its publicurl.py, as the
    image holds both."""
    (directory / "app" / "outbound.py").write_text(
        (REPO / "controlplane" / "app" / "outbound.py").read_text())
    return directory


@pytest.mark.parametrize("value", ["true", "YES", "1", "no"])
def test_a_wrong_value_for_private_addresses_stops_exec_at_start_in_one_line(
        tmp_path, value):
    """The setting loosens where an alert may go, so it is on only when it
    reads exactly yes. Anything else stops the start: never read as on, and
    never passed over as off without a word (docs/record 4.336)."""
    directory = with_the_outbound_rule(control_plane_dir(tmp_path))
    done = run_cli("--units", str(directory), "exec", "x.service",
                   env=env_with(**{SETTING: value}))
    assert done.returncode == 2
    assert done.stderr.count("\n") == 1
    assert SETTING in done.stderr
    assert not (directory / "started").exists()


@pytest.mark.parametrize("value", ["", "yes"])
def test_yes_or_nothing_for_private_addresses_starts(tmp_path, value):
    directory = with_the_outbound_rule(control_plane_dir(tmp_path))
    done = run_cli("--units", str(directory), "exec", "x.service",
                   env=env_with(**{SETTING: value}))
    assert done.returncode == 0, done.stderr
    assert (directory / "started").exists()


def test_the_rule_is_loaded_by_its_path_with_nothing_else_of_the_control_plane(
        tmp_path):
    """The worker never puts the control plane on its import path. The file
    has to load on its own, which is why it imports the probing rule only
    inside the function that calls it."""
    directory = with_the_outbound_rule(control_plane_dir(tmp_path))
    assert sorted(p.name for p in (directory / "app").iterdir()) == [
        "outbound.py", "publicurl.py"]
    service = worker.read_service(directory / "x.service", oneshot=False)
    service.environment[SETTING] = "on"
    with pytest.raises(worker.SettingError, match=SETTING):
        worker.check_settings(service)


def test_a_control_plane_from_before_the_rule_has_nothing_more_to_check(tmp_path):
    directory = control_plane_dir(tmp_path)
    service = worker.read_service(directory / "x.service", oneshot=False)
    service.environment[SETTING] = "on"
    worker.check_settings(service)


def test_no_control_plane_means_nothing_to_check(tmp_path):
    worker.check_settings(worker.Service("x.service", ["/bin/true"],
                                         str(tmp_path)))


# ------------------------------------------------------- the ingest port

INGEST = ["/srv/controlplane/.venv/bin/uvicorn", "app.ingest:app", "--host",
          "127.0.0.1", "--port", "8410", "--no-proxy-headers"]


def test_the_port_stays_the_units_when_nothing_moves_it():
    assert worker.with_port(INGEST, {}, "i.service") == INGEST
    assert worker.with_port(INGEST, {worker.INGEST_PORT_ENV: " "},
                            "i.service") == INGEST


def test_only_the_port_moves_and_never_the_bind():
    moved = worker.with_port(INGEST, {worker.INGEST_PORT_ENV: "8411"},
                             "i.service")
    assert moved == ["/srv/controlplane/.venv/bin/uvicorn", "app.ingest:app",
                     "--host", "127.0.0.1", "--port", "8411",
                     "--no-proxy-headers"]
    assert INGEST[5] == "8410", "the unit's own argv must not be edited"


@pytest.mark.parametrize("value", ["0", "65536", "http", "84 10", "-1",
                                   "8410;id", "0.0.0.0:8410"])
def test_a_port_that_is_not_a_port_stops_it(value):
    with pytest.raises(worker.SettingError, match="WHICHPORTS_INGEST_PORT"):
        worker.with_port(INGEST, {worker.INGEST_PORT_ENV: value}, "i.service")


def test_a_unit_with_no_port_to_move_stops_it():
    with pytest.raises(worker.UnitError, match="no --port"):
        worker.with_port(["/bin/true"], {worker.INGEST_PORT_ENV: "8411"},
                         "x.service")


def test_the_real_ingest_unit_has_the_port_this_moves():
    service = worker.read_service(OPS / "whichports-ingest.service",
                                  oneshot=False)
    moved = worker.with_port(service.argv, {worker.INGEST_PORT_ENV: "9000"},
                             service.name)
    assert moved[moved.index("--port") + 1] == "9000"
    assert moved[moved.index("--host") + 1] == "127.0.0.1"


# ------------------------------------------------- the worker's own job

def test_no_prober_api_means_no_list_to_take():
    timers, _ = worker.read_all(OPS)
    assert worker.sync_job(timers, {}) is None
    assert worker.sync_job(timers, {worker.PROBER_API_ENV: "   "}) is None


def test_with_the_api_set_the_list_is_taken_before_the_first_pass():
    timers, _ = worker.read_all(OPS)
    job = worker.sync_job(timers, {worker.PROBER_API_ENV: "https://ours.example"})
    fast = next(j for j in timers if j.timer == "whichports-probe-fast.timer")
    assert job.service.argv == [fast.service.argv[0], "-m",
                                "app.vantages_cli", "sync-api"]
    assert job.service.working_directory == fast.service.working_directory
    assert job.service.environment == fast.service.environment
    assert job.service.short == "vantages-sync"
    latest_first_sync = worker.first_delay(job, NOW, None, MaxRandom())
    earliest_first_pass = min(worker.first_delay(j, NOW, None, MinRandom())
                              for j in timers if "probe" in j.timer)
    assert latest_first_sync < earliest_first_pass, \
        "the first pass must find our probers already named"
    assert job.every == 15 * 60


def test_the_sync_command_is_the_one_the_control_plane_documents():
    source = (REPO / "controlplane" / "app" / "vantages_cli.py").read_text()
    assert 'sub.add_parser("sync-api"' in source
    assert worker.SYNC_ARGS == ("-m", "app.vantages_cli", "sync-api")


def test_the_api_setting_is_the_name_dispatch_reads():
    source = (REPO / "controlplane" / "app" / "dispatch.py").read_text()
    assert f'PROBER_API_ENV = "{worker.PROBER_API_ENV}"' in source


def test_a_sync_that_found_no_database_looks_again_soon(tmp_path, monkeypatch):
    """A new install has no database until the first account is made. The
    sync must not wait a quarter of an hour after that."""
    monkeypatch.delenv("WHICHPORTS_DB", raising=False)
    database = tmp_path / "later.db"
    ran = tmp_path / "ran"
    job = worker.TimerJob(
        "s.timer", service(tmp_path, py(f"open({str(ran)!r}, 'a').write('x')"),
                           {"WHICHPORTS_DB": str(database)}),
        on_boot=0, every=3600, jitter=0, retry_when_not_run=0.05)
    w = quiet_worker(tmp_path, timers=[job])
    thread = threading.Thread(target=w.run)
    thread.start()
    try:
        time.sleep(0.3)
        assert not ran.exists(), "no database, so it has not run"
        database.write_text("")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not ran.exists():
            time.sleep(0.02)
        assert ran.exists(), "it ran once the database appeared"
        time.sleep(0.4)
        assert ran.read_text() == "x", "and then went back to its schedule"
    finally:
        w.stop()
        thread.join(10)


def test_a_unit_from_a_file_never_retries_early(tmp_path, monkeypatch):
    """Every job read from a unit keeps systemd's schedule: not run means
    wait for the next elapse."""
    monkeypatch.delenv("WHICHPORTS_DB", raising=False)
    timers, _ = worker.read_all(OPS)
    assert all(job.retry_when_not_run is None for job in timers)


# --------------------------- an instance without the prober lines (4.333)

SWEEP_AND_BACKUP = ["whichports-sweep.timer", "whichports-backup.timer"]


def test_without_the_prober_api_no_probing_pass_is_scheduled():
    """Measured on a server, docs/record 4.333: an instance without the
    prober lines has no prober to ask, so every pass ended with exit 2."""
    timers, _ = worker.read_all(OPS)
    for environ in ({}, {worker.PROBER_API_ENV: ""}, {worker.PROBER_API_ENV: "   "}):
        assert [job.timer for job in worker.scheduled(timers, environ)] == \
            SWEEP_AND_BACKUP


def test_with_the_prober_api_every_timer_is_scheduled():
    timers, _ = worker.read_all(OPS)
    kept = worker.scheduled(timers, {worker.PROBER_API_ENV: "https://ours.example"})
    assert [job.timer for job in kept] == list(worker.TIMERS)


def test_the_probing_timers_are_exactly_the_ones_that_run_the_prober():
    """So a third probing timer cannot be added to the box and left running
    on an instance that has nothing to probe with."""
    timers, _ = worker.read_all(OPS)
    run_the_prober = {job.timer for job in timers
                      if "app.prober_cli" in job.service.argv}
    assert run_the_prober == set(worker.PROBING_TIMERS)
    assert set(worker.PROBING_TIMERS) < set(worker.TIMERS)


def test_a_probing_pass_can_still_be_asked_for_by_name():
    """`once` is somebody asking, so it runs and the command says what is
    missing. Only the schedule changed."""
    done = run_cli("--units", str(OPS), "once", "whichports-probe-fast.service",
                   env={k: v for k, v in os.environ.items()
                        if k != worker.PROBER_API_ENV})
    assert "not a unit this worker schedules" not in done.stderr


def lines_until(process, wanted, seconds: float = 30.0) -> list:
    """Read the process's lines until every string in `wanted` has appeared
    in some line, in whatever order, or the time is up.

    **In whatever order.** The worker's main thread announces the schedule,
    and then every job says its own first line from a thread of its own, so
    nothing promises which job speaks first. Until 2026-10-07 this stopped
    reading at the scan's line, and in a gate under load the scan spoke
    before the fast pass: this suite failed twice within the hour that day
    and passed alone every time (docs/record 4.354)."""
    lines = []

    def read():
        for line in process.stdout:
            lines.append(line.rstrip("\n"))

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        seen = list(lines)
        if all(any(want in line for line in seen) for want in wanted):
            break
        time.sleep(0.02)
    return lines


# The first line each job says once it is waiting, by the job's short name.
WAITING = {"sweep": " sweep: first run in ", "backup": " backup: first run in ",
           "scan": " scan: watching ", "probe-fast": " probe-fast: first run in ",
           "probe": " probe: first run in ",
           "vantages-sync": " vantages-sync: first run in ",
           "cve": " cve: first run in "}


def start_lines(tmp_path: Path, jobs, **settings) -> list:
    """What `run` prints with the real units until each of `jobs` has said
    it is waiting. The first job is minutes away, so nothing is started."""
    env = {k: v for k, v in os.environ.items() if k != worker.PROBER_API_ENV}
    env.update(settings, WHICHPORTS_DB=str(tmp_path / "state" / "none.db"),
               PYTHONUNBUFFERED="1")
    process = subprocess.Popen(
        [sys.executable, str(Path(worker.__file__)), "--units", str(OPS),
         "--cve-units", str(CVE_UNITS), "run"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    try:
        lines = lines_until(process, [WAITING[job] for job in jobs])
    finally:
        process.terminate()
        try:
            process.wait(15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(15)
    return list(lines)


SPEAKS_OUT_OF_ORDER = """
import sys, time
print("2026-10-07T12:00:00Z scan: watching /somewhere", flush=True)
time.sleep(0.4)
print("2026-10-07T12:00:00Z probe-fast: first run in 251s", flush=True)
time.sleep(30)
"""


def test_run_schedules_the_cve_build_at_its_units_time(tmp_path):
    lines = start_lines(tmp_path, ["sweep", "backup", "scan", "cve"])
    assert any("worker: whichports-cve.timer: /srv/controlplane/.venv/bin/python -m"
               " app.cvesync_cli build --out /var/lib/whichports-cve, daily at"
               " 04:41:00 UTC, up to 600s later" in line for line in lines), lines


def test_the_helper_waits_for_every_line_it_was_asked_for_in_any_order():
    """A stand-in that speaks the way the worker did in the failing gate:
    the scan first, the fast pass four tenths of a second later."""
    process = subprocess.Popen([sys.executable, "-c", SPEAKS_OUT_OF_ORDER],
                               stdout=subprocess.PIPE, text=True)
    try:
        lines = list(lines_until(process, [WAITING["scan"], WAITING["probe-fast"]]))
    finally:
        process.kill()
        process.wait(15)
    assert any(WAITING["probe-fast"] in line for line in lines), lines


def test_the_helper_gives_up_when_a_line_never_comes_and_says_what_it_has():
    process = subprocess.Popen([sys.executable, "-c", SPEAKS_OUT_OF_ORDER],
                               stdout=subprocess.PIPE, text=True)
    try:
        started = time.monotonic()
        lines = list(lines_until(process, [WAITING["backup"]], seconds=0.8))
        took = time.monotonic() - started
    finally:
        process.kill()
        process.wait(15)
    assert 0.7 < took < 5
    assert any(WAITING["scan"] in line for line in lines)


def test_at_start_without_the_prober_api_it_says_so_in_one_line(tmp_path):
    lines = start_lines(tmp_path, ["sweep", "backup", "scan"])
    said = [line for line in lines if "not scheduled" in line]
    assert len(said) == 1, lines
    assert worker.PROBER_API_ENV in said[0]
    for timer in worker.PROBING_TIMERS:
        assert timer in said[0]
        assert not any(f"worker: {timer}:" in line for line in lines)
    assert not any(" probe-fast: " in line or " probe: " in line for line in lines)
    for timer in SWEEP_AND_BACKUP:
        assert any(f"worker: {timer}:" in line for line in lines), lines
    assert any("worker: whichports-scan.path:" in line for line in lines)


def test_at_start_with_the_prober_api_both_passes_are_scheduled(tmp_path):
    lines = start_lines(tmp_path, ["sweep", "backup", "scan", "probe-fast", "probe",
                                   "vantages-sync"],
                        **{worker.PROBER_API_ENV: "https://ours.example"})
    assert not any("not scheduled" in line for line in lines), lines
    for timer in worker.TIMERS:
        assert any(f"worker: {timer}:" in line for line in lines), lines
    assert any(" probe-fast: first run in " in line for line in lines)
    assert any(" probe: first run in " in line for line in lines)
    assert any("worker: whichports-vantages-sync.timer:" in line for line in lines)


def test_once_accepts_the_sync_by_name():
    done = run_cli("--units", str(OPS), "once", worker.SYNC_SERVICE)
    assert "not a unit this worker schedules" not in done.stderr
    assert done.returncode != 2


def test_lines_from_many_threads_never_run_together(capsys):
    """Each job writes from its own thread. A line must come out whole."""
    def chatter(name):
        for i in range(200):
            worker.log(name, f"line {i} " + "x" * 40)

    threads = [threading.Thread(target=chatter, args=(f"job{n}",))
               for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 8 * 200
    for line in lines:
        assert line.count("Z job") == 1 and line.endswith("x" * 40), line


# ------------------------------------------- the invite as one line (4.461)
#
# selfhost/.env may carry our probers as one line, WHICHPORTS_PROBER_INVITE,
# which the control plane's app/invite.py takes apart. The worker starts every
# process of the stack, so it does that before anything reads the three
# settings, and refuses an invite it cannot take apart the way it refuses a
# malformed address: at start, in one line.

API_KEY = "whpi_" + "0123456789abcdef" * 4
PROOF_KEY = "whpp_" + "fedcba9876543210" * 4
INVITE = f"whpinvite1_ours.example.com_{API_KEY}_{PROOF_KEY}"
INVITE_ENV = "WHICHPORTS_PROBER_INVITE"
THE_THREE = ("WHICHPORTS_PROBER_API", "WHICHPORTS_PROBER_API_KEY",
             "WHICHPORTS_PROBER_PROOF_KEY")


def with_the_invite_rule(directory: Path) -> Path:
    (directory / "app" / "invite.py").write_text(
        (REPO / "controlplane" / "app" / "invite.py").read_text())
    return directory


def env_without_probers(**values):
    environment = {k: v for k, v in env_with().items()
                   if k not in THE_THREE and k != INVITE_ENV}
    environment.update(values)
    return environment


def says_its_settings(directory: Path) -> None:
    """A unit that writes, one per line, the four settings as it got them."""
    names = THE_THREE + (INVITE_ENV,)
    code = ("import os; open('seen', 'w').write('\\n'.join(n + '=' +"
            f" os.environ.get(n, '-') for n in {names!r}))")
    write(directory, "x.service", f"""
        [Service]
        WorkingDirectory={directory}
        ExecStart={sys.executable} -c "{code}"
        """)


def seen(directory: Path) -> dict:
    return dict(line.split("=", 1) for line in
                (directory / "seen").read_text().splitlines())


def test_a_malformed_invite_stops_exec_at_start_in_one_line(tmp_path):
    directory = with_the_invite_rule(control_plane_dir(tmp_path))
    done = run_cli("--units", str(directory), "exec", "x.service",
                   env=env_without_probers(**{INVITE_ENV: INVITE[:-1]}))
    assert done.returncode == 2
    assert done.stderr.count("\n") == 1
    assert INVITE_ENV in done.stderr
    assert API_KEY not in done.stderr and PROOF_KEY[:-1] not in done.stderr
    assert not (directory / "started").exists()


@pytest.mark.parametrize("other", THE_THREE)
def test_the_invite_beside_any_of_the_three_lines_stops_exec_at_start(tmp_path, other):
    directory = with_the_invite_rule(control_plane_dir(tmp_path))
    done = run_cli("--units", str(directory), "exec", "x.service",
                   env=env_without_probers(**{INVITE_ENV: INVITE, other: "x"}))
    assert done.returncode == 2
    assert done.stderr.count("\n") == 1
    assert INVITE_ENV in done.stderr and other in done.stderr
    assert not (directory / "started").exists()


def test_a_malformed_invite_stops_once_and_run_at_start_too(tmp_path):
    directory = with_the_invite_rule(control_plane_dir(tmp_path))
    units = units_working_in(tmp_path / "units", directory)
    for argv in (["once", "whichports-sweep.service"], ["run"]):
        done = run_cli("--units", str(units), "--cve-units", str(units), *argv,
                       env=env_without_probers(**{INVITE_ENV: "whpi_" + "0" * 64}))
        assert done.returncode == 2, (argv, done.stderr)
        assert INVITE_ENV in done.stderr


def test_exec_takes_the_invite_apart_into_the_three_and_passes_the_line_no_further(tmp_path):
    directory = with_the_invite_rule(control_plane_dir(tmp_path))
    says_its_settings(directory)
    done = run_cli("--units", str(directory), "exec", "x.service",
                   env=env_without_probers(**{INVITE_ENV: f"  {INVITE} "}))
    assert done.returncode == 0, done.stderr
    assert seen(directory) == {
        "WHICHPORTS_PROBER_API": "https://ours.example.com",
        "WHICHPORTS_PROBER_API_KEY": API_KEY,
        "WHICHPORTS_PROBER_PROOF_KEY": PROOF_KEY,
        INVITE_ENV: "-",
    }


def test_the_three_lines_alone_reach_the_command_as_they_always_did(tmp_path):
    directory = with_the_invite_rule(control_plane_dir(tmp_path))
    says_its_settings(directory)
    done = run_cli("--units", str(directory), "exec", "x.service",
                   env=env_without_probers(**{
                       "WHICHPORTS_PROBER_API": "https://ours.example.com",
                       "WHICHPORTS_PROBER_API_KEY": API_KEY,
                       "WHICHPORTS_PROBER_PROOF_KEY": PROOF_KEY,
                       INVITE_ENV: ""}))
    assert done.returncode == 0, done.stderr
    assert seen(directory)["WHICHPORTS_PROBER_API_KEY"] == API_KEY


def test_once_takes_the_invite_apart_for_the_job_it_runs(tmp_path):
    directory = with_the_invite_rule(control_plane_dir(tmp_path))
    units = units_working_in(tmp_path / "units", directory)
    code = ("import os; open('seen', 'w').write(os.environ.get("
            "'WHICHPORTS_PROBER_PROOF_KEY', '-'))")
    sweep = units / "whichports-sweep.service"
    sweep.write_text(re_execstart(sweep.read_text(),
                                  f'{sys.executable} -c "{code}"'))
    done = run_cli("--units", str(units), "--cve-units", str(units), "once",
                   "whichports-sweep.service",
                   env=env_without_probers(**{INVITE_ENV: INVITE,
                                              "WHICHPORTS_DB": ""}))
    assert done.returncode == 0, done.stdout + done.stderr
    assert (directory / "seen").read_text() == PROOF_KEY


def test_no_control_plane_means_no_invite_to_take_apart(tmp_path):
    """The same rule as the other start checks: a directory without the
    module is not the control plane, as in most of this file's tests."""
    environ = {INVITE_ENV: "not an invite"}
    worker.take_apart_invite(worker.Service("x.service", ["/bin/true"],
                                            str(tmp_path)), environ)
    assert environ == {INVITE_ENV: "not an invite"}


def units_working_in(folder: Path, control_plane: Path) -> Path:
    """The real units, ops/cve's pair included, with their working
    directory moved to `control_plane`, so the start checks load the
    modules a test put there. Nothing they run is started: the first job
    is minutes away."""
    folder.mkdir()
    for source in list(OPS.glob("whichports-*")) + list(CVE_UNITS.glob("whichports-cve.*")):
        (folder / source.name).write_text(source.read_text().replace(
            "WorkingDirectory=/srv/controlplane",
            f"WorkingDirectory={control_plane}"))
    return folder


def re_execstart(text: str, command: str) -> str:
    """A unit's text with its ExecStart, continuation lines and all, put
    in place by `command`."""
    out, skipping = [], False
    for line in text.splitlines():
        if skipping:
            skipping = line.rstrip().endswith("\\")
            continue
        if line.startswith("ExecStart="):
            out.append(f"ExecStart={command}")
            skipping = line.rstrip().endswith("\\")
            continue
        out.append(line)
    return "\n".join(out) + "\n"


def test_at_start_with_the_invite_alone_both_passes_are_scheduled(tmp_path):
    (tmp_path / "cp").mkdir()
    directory = with_the_invite_rule(control_plane_dir(tmp_path / "cp"))
    units = units_working_in(tmp_path / "units", directory)
    env = env_without_probers(**{INVITE_ENV: INVITE, "PYTHONUNBUFFERED": "1",
                                 "WHICHPORTS_DB": str(tmp_path / "none.db")})
    process = subprocess.Popen(
        [sys.executable, str(Path(worker.__file__)), "--units", str(units),
         "--cve-units", str(units), "run"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    try:
        lines = lines_until(process, [WAITING[job] for job in (
            "sweep", "backup", "scan", "probe-fast", "probe", "vantages-sync")])
    finally:
        process.terminate()
        try:
            process.wait(15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(15)
    assert not any("not scheduled" in line for line in lines), lines
    for timer in worker.TIMERS:
        assert any(f"worker: {timer}:" in line for line in lines), lines
    assert any("worker: whichports-vantages-sync.timer:" in line for line in lines)
    assert not any(API_KEY in line or PROOF_KEY in line for line in lines)
