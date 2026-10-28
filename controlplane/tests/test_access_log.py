"""No link token reaches a log the ingest writes.

    python -m pytest tests/test_access_log.py

A one-time link is a path, /reset/<token> and three like it
(`web_auth._LINK_PATHS`), and the token in it works until it is spent or
expires. uvicorn writes every request line to its access log unless told
not to, the path and the query string included (uvicorn 0.52.2,
`protocols/http/httptools_impl.py`), and under systemd that log is the
journal. A sign-in callback carries a code and a state in its query string,
and `/login/link/<ticket>` carries a ticket, so those went to the same log.

So the ingest's unit starts uvicorn with --no-access-log, and these tests
run the unit's own command line, send it real requests and read every line
the process wrote.
"""
import os
import pathlib
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

CONTROLPLANE = pathlib.Path(__file__).resolve().parents[1]
UNIT = CONTROLPLANE / "ops" / "whichports-ingest.service"

# Made-up secrets, each long and unlike anything else the process prints, so
# finding one in the output can only mean it was logged.
LINK_TOKEN = "linktokenAAAAzzzz0123456789"
TICKET = "ticketBBBByyyy0123456789"
CODE = "codeCCCCxxxx0123456789"
STATE = "stateDDDDwwww0123456789"
SECRETS = (LINK_TOKEN, TICKET, CODE, STATE)


def unit_argv() -> list:
    """The ingest unit's ExecStart, split the way systemd splits a line with
    no quotes in it."""
    lines = [line for line in UNIT.read_text().splitlines()
             if line.startswith("ExecStart=")]
    assert len(lines) == 1, lines
    return lines[0].removeprefix("ExecStart=").split()


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def get(port: int, path: str) -> None:
    """One request. The status does not matter here, only what is logged."""
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}",
                                    timeout=10) as response:
            response.read()
    except urllib.error.HTTPError:
        pass


def wait_until_up(port: int, process) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError("uvicorn stopped before it answered")
        try:
            get(port, "/healthz")
            return
        except OSError:
            time.sleep(0.1)
    raise AssertionError("uvicorn did not answer /healthz within 30 seconds")


def what_the_ingest_writes(argv: list, tmp_path) -> str:
    """Run uvicorn with the unit's words, on a free port and this checkout's
    Python, send the requests that carry secrets, stop it, and return all it
    wrote to stdout and stderr together."""
    assert argv[0].endswith("/uvicorn"), argv
    words = list(argv[1:])
    port = free_port()
    words[words.index("--port") + 1] = str(port)
    environment = dict(os.environ, PYTHONUNBUFFERED="1",
                       WHICHPORTS_DB=str(tmp_path / "cp.db"))
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", *words], cwd=CONTROLPLANE,
        env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True)
    try:
        wait_until_up(port, process)
        get(port, f"/reset/{LINK_TOKEN}")
        get(port, f"/join/{LINK_TOKEN}")
        get(port, f"/login/link/{TICKET}")
        get(port, f"/login/google/callback?code={CODE}&state={STATE}")
    finally:
        process.terminate()
        output, _ = process.communicate(timeout=30)
    return output


def test_the_ingest_unit_turns_the_access_log_off():
    assert "--no-access-log" in unit_argv()


def test_without_the_flag_the_tokens_are_in_the_output(tmp_path):
    """The control: the same run with the flag taken out finds every secret,
    so the test below would see one if it were written."""
    argv = [word for word in unit_argv() if word != "--no-access-log"]
    output = what_the_ingest_writes(argv, tmp_path)
    for secret in SECRETS:
        assert secret in output, secret


def test_no_link_token_ticket_or_code_reaches_the_ingests_output(tmp_path):
    output = what_the_ingest_writes(unit_argv(), tmp_path)
    # The process did run and its output was read.
    assert "Application startup complete" in output
    for secret in SECRETS:
        assert secret not in output, secret
