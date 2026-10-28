"""A server's Settings, Probing: the list says what it holds.

    Run from site/: python3 -m pytest app/test_settings_your_answers.py

The outside review of 2026-10-06 read "Ports to probe", with Remove on each
port and "Add a port", on a server that has an agent (docs/RECORD.md 4.460).
On such a server the probers take every port the agent reports bound, every
port somebody answered for and every port with a finding from the last day
(docs/PRODUCT.md, Cadence). The list holds only the answers, the ports
declared open or closed, and Remove takes an answer back while a bound port
stays probed. So on a server with an agent the list is headed "Your
answers", the words the page uses for them. On a server with no agent the
answers are what tells the probers which ports to look at, and the heading
stays "Ports to probe".

The sample's list was four ports written by hand, while its Overview has an
answer on one, 443 closed. It is drawn from the sample's one description
(sample_story.py) by the live page's own function.
"""
import pathlib
import re
import sys
from datetime import timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
from test_render_live import (NOW, SSHD, add_address_host_row, add_host,  # noqa: E402,F401
                              db, declare_intent, document)

YOUR_ANSWERS = "Your answers"
PORTS_TO_PROBE = "Ports to probe"


def probing(section):
    return section.split('<div class="hstage h-probing">', 1)[1].split('<div class="hstage ', 1)[0]


def headings(stage):
    return re.findall(r"<h3>([^<]*)", stage)


def rows(stage):
    """Each port row as its port and the line under it."""
    return [(port, " ".join(re.sub(r"<[^>]+>", " ", sub).split()))
            for port, sub in re.findall(
                r'<b class="mono num">([^<]+)</b><small class="dim">(.*?)</small>', stage, re.S)]


def live_section(db, name):
    return rl.render(db, now=NOW).split(f'id="host-{name}"', 1)[1]


# ------------------------------------------------------------ edge cases

def test_a_server_without_an_agent_keeps_ports_to_probe(db):
    add_address_host_row(db, "edge")
    stage = probing(live_section(db, "edge"))
    assert headings(stage) == [PORTS_TO_PROBE]


def test_a_server_with_an_agent_and_no_answer_still_names_the_list(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    stage = probing(live_section(db, "box"))
    assert headings(stage) == [YOUR_ANSWERS]
    assert rows(stage) == []
    assert "Add a port" in stage


def test_the_samples_list_is_the_samples_answers():
    """443 is the one port the sample's Overview has an answer on."""
    page = build.build_sample()
    stage = probing(page[page.index('<div class="wrap view" id="host"'):])
    assert rows(stage) == [("443/tcp", "caddy, declared closed")]
    assert headings(stage) == [YOUR_ANSWERS]


# --------------------------------------------------------- the usual case

def test_a_server_with_an_agent_heads_its_answers_as_answers(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    for family in ("v4", "v6"):
        declare_intent(db, "box", "tcp", 22, family, "open")
    stage = probing(live_section(db, "box"))
    assert headings(stage) == [YOUR_ANSWERS]
    assert PORTS_TO_PROBE not in stage
    assert rows(stage) == [("22/tcp", "sshd, declared open")]
