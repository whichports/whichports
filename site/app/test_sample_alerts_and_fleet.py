"""The sample's Alerts screen and its Fleet tell each server the same way.

    Run from site/: python3 -m pytest app/test_sample_alerts_and_fleet.py

The alert lines were written apart from the Fleet's rows, and a reader who
went from one screen to the other found three servers told differently
(docs/RECORD.md 4.453). media-01 was silent on Alerts and unreviewed on the
Fleet. mail-relay had a reachable port on Alerts and no proof on the Fleet,
and a server without proof is not probed at all. edge-cache-02 was in no
Fleet row. The Fleet's own row for web-02 said one port answers and asked
for a decision on three.

Both are still written by hand. This file reads the two lists against each
other, so a line that names a server names one the Fleet has, in a state
the Fleet shows for it.
"""
import datetime
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402

# The states in which nothing is probed, so no port can have an alert.
NOT_PROBED = ("no proof", "not watched", "paused", "not readable")


def fleet():
    """The sample's Fleet rows by the server's name."""
    return {row.name: row for row in build.sample_fleet_rows()}


def chip_tones(row, line):
    """The tones of the row's chips for the line's port, whichever family
    the chip names. A chip reads `tcp/443` or `tcp/22 v6`."""
    port = f"{line.protocol}/{line.port}"
    return [tone for label, tone in row.chips if label.split(" ")[0] == port]


def open_lines(word):
    return [line for line in build.SAMPLE_OPEN if line.word == word]


def silent_for(word):
    """How long the Fleet says a server has been silent: `silent 3h 12m`."""
    found = re.fullmatch(r"silent (?:(\d+)h ?)?(?:(\d+)m)?", word)
    assert found, word
    return datetime.timedelta(hours=int(found.group(1) or 0), minutes=int(found.group(2) or 0))


# ----------------------------------------------- the reading notices, first

def test_the_chip_reading_takes_a_chip_with_a_family_and_no_other_port():
    row = build.FleetRow("warn", "unreviewed", "x", reach=(2, 3),
                         chips=(("tcp/22 v6", "warn"), ("tcp/2200", "fail")))
    line = build.AlertLine(None, "x", "reachable", "warn", "tcp", 22)
    assert chip_tones(row, line) == ["warn"]
    assert chip_tones(row, build.AlertLine(None, "x", "reachable", "warn", "tcp", 220)) == []


def test_the_silence_reading_takes_hours_and_minutes():
    assert silent_for("silent 3h 12m") == datetime.timedelta(hours=3, minutes=12)
    assert silent_for("silent 40m") == datetime.timedelta(minutes=40)
    assert silent_for("silent 2h") == datetime.timedelta(hours=2)


# ------------------------------------------------- the lines and the rows

def test_every_alert_line_names_a_server_the_fleet_has():
    rows = fleet()
    named = {line.host for line in build.SAMPLE_OPEN + build.SAMPLE_SENT}
    assert named, "no line was read"
    assert sorted(named - set(rows)) == []


def test_no_line_with_a_port_is_about_a_server_nothing_probes():
    rows = fleet()
    with_a_port = [line for line in build.SAMPLE_OPEN + build.SAMPLE_SENT if line.port]
    assert with_a_port, "no line with a port was read"
    wrong = [(line.host, rows[line.host].word) for line in with_a_port
             if line.host in rows and rows[line.host].word in NOT_PROBED]
    assert wrong == []


def test_an_open_silent_line_is_a_server_the_fleet_calls_silent():
    rows = fleet()
    lines = open_lines("silent")
    assert lines, "the sample lost its silent line"
    for line in lines:
        assert rows[line.host].word.startswith("silent"), (line.host, rows[line.host].word)


def test_a_server_the_fleet_calls_silent_has_its_open_line():
    silent = sorted(name for name, row in fleet().items() if row.word.startswith("silent"))
    assert silent, "the sample lost its silent server"
    assert sorted(line.host for line in open_lines("silent")) == silent


def test_the_silent_line_was_raised_when_the_fleets_silence_says():
    """The Fleet says how long the server has been silent, the line says when
    it was raised and after how many minutes. The three give one last report."""
    rows = fleet()
    for line in open_lines("silent"):
        last_report = build.SAMPLE_ALERTS_NOW - silent_for(rows[line.host].word)
        minutes = int(re.search(r"for (\d+) min$", line.why).group(1))
        assert line.when - datetime.timedelta(minutes=minutes) == last_report


def test_an_open_conflict_is_a_red_chip_on_its_servers_row():
    rows = fleet()
    lines = open_lines("conflict")
    assert lines, "the sample lost its conflict line"
    for line in lines:
        assert chip_tones(rows[line.host], line) == ["fail"], line.host


def test_an_open_reachable_port_is_an_amber_chip_on_its_servers_row():
    rows = fleet()
    lines = open_lines("reachable")
    assert lines, "the sample lost its reachable line"
    for line in lines:
        assert chip_tones(rows[line.host], line) == ["warn"], line.host


def test_a_port_that_stopped_answering_asks_nothing_on_its_servers_row():
    rows = fleet()
    lines = open_lines("unreachable")
    assert lines, "the sample lost its unreachable line"
    for line in lines:
        row = rows[line.host]
        assert chip_tones(row, line) == []
        answering, observed = row.reach
        assert answering < observed, "every port answers, so none stopped"


def test_no_server_with_an_open_alert_reads_watched():
    """A live row with an alert still open never reads the green word
    (docs/RECORD.md 4.195), so the sample puts no open line on one."""
    rows = fleet()
    green = [line.host for line in build.SAMPLE_OPEN if rows[line.host].word == build.WATCHED[1]]
    assert green == []


def test_a_sent_line_tells_its_open_alert_the_same_way():
    """One alert, one time and one reason. The silent line read 42 min on
    Open now and 35 min under Sent."""
    told = {(line.host, line.word, line.port): (line.when, line.why) for line in build.SAMPLE_OPEN}
    matched = [line for line in build.SAMPLE_SENT if (line.host, line.word, line.port) in told]
    assert matched, "no sent line was read against an open one"
    for line in matched:
        assert (line.when, line.why) == told[(line.host, line.word, line.port)], line.host


def test_no_fleet_row_asks_about_more_ports_than_answer():
    """An amber chip is a port that answers and nobody has answered for."""
    checked = 0
    for row in fleet().values():
        amber = {label.split(" ")[0] for label, tone in row.chips if tone == "warn"}
        if not amber:
            continue
        checked += 1
        assert len(amber) <= row.reach[0], (row.name, sorted(amber), row.reach)
    assert checked > 2
