"""What a card says of a port the prober could not test because the way to
it said no.

    Run from site/: python3 -m pytest app/test_not_tested_reason_words.py

A server whose firewall rejects with "administratively prohibited" answers a
v6 connect with an error the prober's kernel reports as a permission error.
The card read "not tested, local permission denied", which names the
prober's own side for a refusal the server sent (docs/RECORD.md 4.220,
4.454). The prober's reason now names nobody's side, and the card says it in
the prober's own words.
"""
import html
import pathlib
import re
import sqlite3
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402

NOW = trl.NOW
SSHD6 = {"protocol": "tcp", "family": "v6", "bind_address": "::", "port": 22,
         "process_name": "sshd", "pid": 1}


def card_lines(tmp_path, reason):
    """The prober's line on each family's card of port 22, for a v6 result
    that was not tested for `reason`."""
    db = str(tmp_path / "cp.db")
    con = sqlite3.connect(db)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(db, "box", trl.document(listening=[trl.SSHD, SSHD6]))
    trl.probe_result(db, "box", 22, "v4", "connect_succeeded")
    trl.probe_result(db, "box", 22, "v6", "not_tested")
    con = sqlite3.connect(db)
    con.execute("UPDATE probe_results SET reason = ? WHERE family = 'v6'", (reason,))
    con.commit()
    con.close()
    page = rl.render(db, now=NOW)
    section = page[page.index('id="host-box"'):]
    row = section.split('for="pr-box-tcp-22"', 1)[1].split('<input type="checkbox" class="prsel"', 1)[0]
    lines = re.findall(r'<span class="k">prober</span><span class="v">(.*?)</span></div>', row, re.S)
    return [" ".join(html.unescape(re.sub(r"<[^>]+>", " ", line)).split()) for line in lines]


def test_the_reason_the_prober_writes_is_said_in_its_own_words(tmp_path):
    reason = rl.joinbridge.module("prober").REASON_PERMISSION_DENIED
    v4, v6 = card_lines(tmp_path, reason)
    assert v4.startswith("connected from probe1")
    assert v6 == "not tested, permission denied"
    assert "local" not in v6


def test_the_prober_s_own_side_is_still_said_where_it_is_the_prober_s(tmp_path):
    reason = rl.joinbridge.module("prober").REASON_LOCAL_PERMISSION_DENIED
    _v4, v6 = card_lines(tmp_path, reason)
    assert v6 == "not tested, local permission denied"
