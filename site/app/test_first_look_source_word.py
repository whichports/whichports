"""A waiting row of the first-look window names where its answer came from
in its row's own Decided-by word.

    Run from site/: python3 -m pytest app/test_first_look_source_word.py

The second big test, 24 October 2026, case F6: on a server with ufw and
Docker, the Overview's rows for 8080 and 8081 read Decided by "rule not
readable", and the first-look window over them listed both with the source
"no rule". host-overview SPEC.md section 8: a row of the window shows where
the answer came from in the words of the Decided by column, and section 6
makes "rule not readable" the word where a rule on the path could not be
fully read, and never "no rule" (docs/RECORD.md 4.301).
"""
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
from test_first_look_order import row  # noqa: E402
from test_render_live import NOW, db, document, probe_result, reporting  # noqa: E402,F401


def source_of(port, **kw):
    (entry,) = rl.first_look_rows([row(port, word="unreviewed", lit="", **kw)])
    return entry[3]


def test_a_waiting_row_takes_its_rows_decided_by_word():
    assert source_of(8080, decided="rule not readable") == "rule not readable"
    assert source_of(8081, decided="no rule") == "no rule"


def _rule(text):
    return {"text": text, "rendered": "partial" if "[" in text else "full", "comment": ""}


def test_on_the_page_the_window_and_the_row_say_one_word(db):
    """The shape of the server measured: ufw's rule written with the
    multiport match, which the agent renders only in part."""
    doc = document(listening=[{"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
                               "port": 8080, "process_name": "docker-proxy", "pid": 8080}])
    doc["nftables"] = {"status": "collected", "tables": [{
        "family": "ip", "name": "filter", "chains": [
            {"name": "INPUT", "hook": "input", "priority": 0, "type": "filter",
             "policy": "drop", "rules": [_rule("counter jump ufw-user-input")]},
            {"name": "ufw-user-input",
             "rules": [_rule("ip protocol tcp [xt match multiport] counter accept")]}]}]}
    reporting(db, "box", doc)
    probe_result(db, "box", 8080, "v4", "connect_succeeded")
    page = rl.render(db, now=NOW)
    host = page.split('id="host-box"', 1)[1]
    row = " ".join(re.sub(r"<[^>]+>", " ", host.split('data-port="8080/tcp"', 1)[1]
                          .split("</label>", 1)[0]).split())
    assert "rule not readable" in row
    window = page[page.index('id="fv-box"'):]
    entry = re.search(r'<div class="fv-r"[^>]*data-port="8080".*?<small>([^<]*)</small></span>'
                      r'<span class="pra">', window, re.S)
    assert entry and entry.group(1) == "rule not readable"
