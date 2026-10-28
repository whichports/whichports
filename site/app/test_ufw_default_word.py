"""ufw's default for incoming, read where the agent sends it and said in
ufw's own words, the same on every tab (docs/RECORD.md 4.443).

The agent sends `/etc/default/ufw` under `ufw.defaults`, with the file's
words: DROP, ACCEPT, REJECT. The Overview's card and the Evidence tab looked
for the default under `ufw.conf`, where only ufw.conf's own keys are, so on
a real server they never said it. The Rules tab and the Packet path said the
file's word, "drop" or "accept". ufw itself says deny, allow and reject
(`_get_default_policy` in ufw's src/backend.py, read 2026-10-09), and now
all four places say that, from one function.

The document here has the shape of one stored on the box on 2026-10-09:
`defaults` holds the three policies, `conf` holds ENABLED and LOGLEVEL.

    Run from site/: python3 -m pytest app/test_ufw_default_word.py
"""
import html as html_mod
import pathlib
import re
import sqlite3
import sys
from datetime import timedelta

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402

NOW = trl.NOW
UVICORN = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 8410,
           "process_name": "uvicorn", "pid": 4}


def document(incoming):
    """A server with ufw on and one program on 8410 that no rule names.
    `incoming` is the word in /etc/default/ufw, or None for a document that
    carries no defaults at all."""
    doc = trl.document(listening=[UVICORN])
    doc["hostname"] = "box"
    doc["firewalld"] = {"status": "not_present"}
    doc["nftables"] = {"status": "collected", "tables": [
        {"family": "ip", "name": "filter", "chains": [
            {"name": "INPUT", "hook": "input", "priority": 0, "type": "filter",
             "policy": "accept",
             "rules": [{"text": "counter jump ufw-user-input", "rendered": "full"}]},
            {"name": "ufw-user-input",
             "rules": [{"text": "tcp dport 22 counter accept", "rendered": "full"}]}]}]}
    doc["ufw"] = {"status": "collected", "conf": {"ENABLED": "yes", "LOGLEVEL": "low"},
                  "rules": ["allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"], "rules6": [],
                  "sources": {"ufw.conf": {"status": "collected"},
                              "user.rules": {"status": "collected"},
                              "user6.rules": {"status": "collected"}}}
    if incoming is not None:
        doc["ufw"]["defaults"] = {"DEFAULT_INPUT_POLICY": incoming,
                                  "DEFAULT_OUTPUT_POLICY": "ACCEPT",
                                  "DEFAULT_FORWARD_POLICY": "DROP"}
    return doc


def text_of(markup):
    bare = re.sub(r"<[^>]+>", " ", re.sub(r"<svg.*?</svg>", "", markup, flags=re.S))
    return " ".join(html_mod.unescape(bare).split()).replace(" ,", ",")


def four_places(tmp_path, incoming):
    """What each of the four places says about the default for incoming,
    or "" where it says nothing: the Overview's card for 8410, the agent's
    card on Evidence, ufw's block on the Rules tab, ufw's box on the Packet
    path."""
    db = str(tmp_path / "cp.db")
    con = sqlite3.connect(db)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(db, "box", document(incoming))
    trl.probe_result(db, "box", 8410, "v4", "connect_succeeded",
                     measured_at=NOW - timedelta(minutes=5))
    page = rl.render(db, now=NOW)

    def tab(name):
        return page.split(f'id="t-box-{name}"', 1)[1].split('id="t-box-', 1)[0]

    card = tab("overview").split('for="pr-box-tcp-8410"', 1)[1]
    firewall = text_of(re.search(
        r'<span class="k">firewall</span><span class="v">(.*?)</span></div>', card, re.S).group(1))
    agent = tab("evidence").split("<b>The agent, inside</b>", 1)[1].split('<div class="evcard', 1)[0]
    filtering = text_of(re.search(
        r'<span class="evk">filtering</span><span>(.*?)</span></div>', agent, re.S).group(1))
    rules = text_of(tab("rules").split('class="fwh"', 1)[1].split("</div>", 1)[0])
    path = text_of(tab("path"))

    def after(words, marker):
        found = re.search(re.escape(marker) + r" (\S+)", words)
        return found.group(1).rstrip(",") if found else ""

    return {"overview": after(firewall, "ufw default"),
            "evidence": after(filtering, "default incoming"),
            "rules": after(rules, "incoming"),
            "path": after(path, "default incoming"),
            "the card's line": firewall}


@pytest.mark.parametrize("in_the_file,ufw_says", [
    ("DROP", "deny"), ("ACCEPT", "allow"), ("REJECT", "reject")])
def test_every_place_says_the_default_in_ufws_own_word(tmp_path, in_the_file, ufw_says):
    got = four_places(tmp_path, in_the_file)
    assert (got["overview"], got["evidence"], got["rules"], got["path"]) == (ufw_says,) * 4, got


def test_the_card_of_a_port_no_rule_names_says_the_default(tmp_path):
    """The line the sample page draws and the live page never did."""
    assert four_places(tmp_path, "ACCEPT")["the card's line"] == "no rule names 8410, ufw default allow"


def test_a_word_ufw_does_not_write_is_shown_as_it_stands(tmp_path):
    """Never guessed into one of the three."""
    got = four_places(tmp_path, "BANANA")
    assert (got["overview"], got["evidence"], got["rules"], got["path"]) == ("banana",) * 4, got


def test_a_document_with_no_defaults_says_no_default_anywhere(tmp_path):
    got = four_places(tmp_path, None)
    assert (got["overview"], got["evidence"], got["rules"], got["path"]) == ("",) * 4, got
    assert got["the card's line"] == "no rule names 8410"


def test_a_default_under_conf_is_not_read(tmp_path):
    """ufw.conf holds ENABLED and LOGLEVEL. A policy word there is nothing
    an agent sends, and reading it was the fault."""
    db = str(tmp_path / "cp.db")
    con = sqlite3.connect(db)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    doc = document(None)
    doc["ufw"]["conf"]["DEFAULT_INPUT_POLICY"] = "ACCEPT"
    assert rl._ufw_default(doc) == ""
    doc["ufw"]["defaults"] = {"DEFAULT_INPUT_POLICY": "DROP"}
    assert rl._ufw_default(doc) == "deny"


def test_the_words_are_ufws_three():
    assert rl.UFW_POLICY_WORDS == {"accept": "allow", "drop": "deny", "reject": "reject"}
    assert rl.ufw_policy_word("ACCEPT") == "allow"
    assert rl.ufw_policy_word(" Drop ") == "deny"
    assert rl.ufw_policy_word("") == ""
