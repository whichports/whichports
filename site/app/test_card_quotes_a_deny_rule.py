"""A port's card says what the rules say of it, a rule that denies it too.

    Run from site/: python3 -m pytest app/test_card_quotes_a_deny_rule.py

Read on the sample page and on a real ufw server's document on 2026-10-12
(docs/RECORD.md 4.454): the card of a port that a ufw rule denies said
"firewall: no rule names 5432", beside a Rules tab listing "DENY 5432". The
line meant that no rule permits the port and said that no rule names it,
which is a wrong statement of cause.

A rule that names the port and turns the packet away is quoted on the card
the way a permit is, for each address family from that family's own rule.
"no rule names" stands only where none does, and a rule nobody could fully
read is said as not fully readable and never as none.

Two servers: the sample's own, whose 5432 a ufw rule denies on both
families, and `testdata/ufw_ubuntu_2604.json`, the agent's document of a
real Ubuntu server with `ufw deny 5432/tcp`.
"""
import html
import json
import pathlib
import re
import sqlite3
import sys
from datetime import timedelta

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402

NOW = trl.NOW
REAL = pathlib.Path(__file__).resolve().parent / "testdata" / "ufw_ubuntu_2604.json"
REAL_DROP = {"v4": "ip protocol tcp tcp dport 5432 counter drop",
             "v6": "meta l4proto tcp tcp dport 5432 counter drop"}
SAMPLE_DROP = "meta l4proto tcp tcp dport 5432 counter drop"
NO_RULE = "no rule names 5432"


def words(markup):
    bare = re.sub(r"<[^>]+>", " ", re.sub(r"<svg.*?</svg>", "", markup, flags=re.S))
    # a value in its own tag leaves a space before the comma after it
    return " ".join(html.unescape(bare).split()).replace(" ,", ",")


def port_row(section, port):
    """One port's row on the Overview and the cards under it, as markup."""
    found = re.search(r'<label class="pr" for="[^"]*-tcp-%d".*?</label>(.*?)'
                      r'(?=<input type="checkbox" class="prsel"|<div class="agree"|</div>\s*</div>\s*<div class="tab)'
                      % port, section, re.S)
    assert found, f"no row for {port}"
    return found.group(0)


def firewall_lines(row):
    """The firewall line of each family's card, v4 then v6."""
    return [words(line) for line in re.findall(
        r'<span class="k">firewall</span><span class="v">(.*?)</span></div>', row, re.S)]


def decided_by(row):
    return words(re.search(r'<span class="prw">(.*?)</span>', row, re.S).group(1))


def tab(section, name, key):
    return section.split(f'id="t-{name}-{key}"', 1)[1].split(">", 1)[1].split('<div class="tab ', 1)[0]


# ------------------------------------------------------------- the sample

@pytest.fixture(scope="module")
def sample():
    page = build.build_sample()
    return page[page.index('<div class="wrap view" id="host"'):]


def test_the_samples_denied_port_quotes_its_deny_rule_on_both_families(sample):
    lines = firewall_lines(port_row(sample, 5432))
    assert lines == [SAMPLE_DROP, SAMPLE_DROP]


def test_the_sample_no_longer_says_no_rule_names_a_port_a_rule_denies(sample):
    assert NO_RULE not in words(port_row(sample, 5432))


def test_the_samples_denied_port_is_decided_by_your_rule(sample):
    assert decided_by(port_row(sample, 5432)) == "your rule"


def test_a_port_no_rule_names_on_the_same_server_still_says_so(sample):
    """8410 is the sample's port that no rule names, and its line keeps
    ufw's default beside it."""
    assert firewall_lines(port_row(sample, 8410)) == [
        "no rule names 8410, ufw default allow"] * 2


def test_the_samples_three_places_say_the_same_of_the_denied_port(sample):
    """The Overview's card quotes a rule that ends on drop, the Rules tab
    lists ufw's deny for the port, and the Packet path's ufw box names the
    deny. None of the three says no rule."""
    overview = words(port_row(sample, 5432))
    rules = words(tab(sample, "host", "rules"))
    path = words(tab(sample, "host", "path"))
    assert SAMPLE_DROP in overview
    assert re.search(r"deny 5432 tcp/ ?v4 ?\+ ?v6 anywhere", rules, re.I), rules[:400]
    assert "deny 5432, anywhere" in path
    assert "no rule for 5432" not in path


# ------------------------------------------------- the real ufw document

POSTGRES = [{"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 5432,
             "process_name": "postgres", "pid": 5},
            {"protocol": "tcp", "family": "v6", "bind_address": "::", "port": 5432,
             "process_name": "postgres", "pid": 5}]
UVICORN = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 8410,
           "process_name": "uvicorn", "pid": 7}


def real_section(tmp_path, change=None):
    """The real server's page with postgres listening on both families and
    silence from outside on both. `change` may edit the document first."""
    doc = json.loads(REAL.read_text(encoding="utf-8"))
    doc["sockets"] = trl.document(listening=[trl.SSHD, UVICORN] + POSTGRES)["sockets"]
    if change:
        change(doc)
    db = str(tmp_path / "cp.db")
    con = sqlite3.connect(db)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(db, "box", doc)
    for family in ("v4", "v6"):
        trl.probe_result(db, "box", 5432, family, "no_response",
                         measured_at=NOW - timedelta(minutes=5))
    page = rl.render(db, now=NOW)
    return page[page.index('id="host-box"'):]


def test_the_real_servers_denied_port_quotes_each_familys_own_rule(tmp_path):
    """v4 read "18 rules not fully readable" and v6 "no rule names 5432"."""
    lines = firewall_lines(port_row(real_section(tmp_path), 5432))
    assert lines == [REAL_DROP["v4"], REAL_DROP["v6"]]


def test_the_real_servers_denied_port_is_decided_by_your_rule(tmp_path):
    assert decided_by(port_row(real_section(tmp_path), 5432)) == "your rule"


def test_a_deny_on_v4_alone_leaves_v6_saying_what_is_true_of_v6(tmp_path):
    """With ufw's v6 deny taken out of the kernel's v6 chain, no v6 rule
    names the port, and the v6 card says that and not v4's rule."""
    def no_v6_deny(doc):
        for table in doc["nftables"]["tables"]:
            for chain in table["chains"]:
                if chain["name"] == "ufw6-user-input":
                    chain["rules"] = [r for r in chain["rules"] if "5432" not in r["text"]]
    v4, v6 = firewall_lines(port_row(real_section(tmp_path, no_v6_deny), 5432))
    assert v4 == REAL_DROP["v4"]
    assert REAL_DROP["v4"] not in v6 and REAL_DROP["v6"] not in v6
    assert "drop" not in v6


def test_a_deny_nobody_could_fully_read_is_not_fully_readable_and_never_none(tmp_path):
    """The port stands in a set the agent wrote as a bracket: the rule may
    name 5432 and nobody read it."""
    def into_a_set(doc):
        for table in doc["nftables"]["tables"]:
            for chain in table["chains"]:
                if chain["name"] in ("ufw-user-input", "ufw6-user-input"):
                    for r in chain["rules"]:
                        if "5432" in r["text"]:
                            r["text"] = "meta l4proto tcp [lookup @__set0] counter drop"
                            r["rendered"] = "partial"
    for line in firewall_lines(port_row(real_section(tmp_path, into_a_set), 5432)):
        assert "not fully readable" in line
        assert NO_RULE not in line


# ------------------------------------- a family with nothing bound on it
#
# The engine makes no finding for a family nothing listens on and nobody
# probed. Its card said "no rule names 5432" without the rules of that
# family having been asked, on the real document too, whose v6 chain holds
# the deny.

def v4_only_section(tmp_path, change=None):
    """The real server with postgres on v4 alone, and only v4 probed."""
    doc = json.loads(REAL.read_text(encoding="utf-8"))
    doc["sockets"] = trl.document(listening=[trl.SSHD, POSTGRES[0]])["sockets"]
    if change:
        change(doc)
    db = str(tmp_path / "cp.db")
    con = sqlite3.connect(db)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(db, "box", doc)
    trl.probe_result(db, "box", 5432, "v4", "no_response",
                     measured_at=NOW - timedelta(minutes=5))
    page = rl.render(db, now=NOW)
    return page[page.index('id="host-box"'):]


def v6_chain(doc):
    return next(chain for table in doc["nftables"]["tables"] for chain in table["chains"]
                if chain["name"] == "ufw6-user-input")


def test_a_family_with_nothing_bound_quotes_its_own_deny_rule(tmp_path):
    row = port_row(v4_only_section(tmp_path), 5432)
    assert "v6 not tested, nothing is bound" in words(row)
    assert firewall_lines(row) == [REAL_DROP["v4"], REAL_DROP["v6"]]


def test_a_family_with_nothing_bound_and_no_rule_for_the_port_says_none(tmp_path):
    def no_v6_deny(doc):
        v6_chain(doc)["rules"] = [r for r in v6_chain(doc)["rules"] if "5432" not in r["text"]]
    _v4, v6 = firewall_lines(port_row(v4_only_section(tmp_path, no_v6_deny), 5432))
    assert "drop" not in v6
    assert NO_RULE in v6 or "not fully readable" in v6


def test_a_family_with_nothing_bound_and_a_rule_nobody_read_is_not_none(tmp_path):
    def into_a_set(doc):
        for r in v6_chain(doc)["rules"]:
            if "5432" in r["text"]:
                r["text"] = "meta l4proto tcp [lookup @__set0] counter drop"
                r["rendered"] = "partial"
    _v4, v6 = firewall_lines(port_row(v4_only_section(tmp_path, into_a_set), 5432))
    assert "not fully readable" in v6
    assert NO_RULE not in v6


def test_the_real_servers_three_places_say_the_same_of_the_denied_port(tmp_path):
    section = real_section(tmp_path)
    overview = words(port_row(section, 5432))
    rules = words(tab(section, "box", "rules"))
    path = words(tab(section, "box", "path"))
    assert REAL_DROP["v4"] in overview and REAL_DROP["v6"] in overview
    assert NO_RULE not in overview
    assert re.search(r"deny 5432 tcp/ ?v4 ?\+ ?v6 anywhere", rules, re.I), rules[:400]
    assert "deny 5432, anywhere" in path
    assert "no rule for 5432" not in path


def test_the_evidence_tab_names_no_rule_for_the_port_either_way(tmp_path):
    """Evidence holds what each source saw and no line about a rule, so it
    cannot say otherwise. Held so that a rule line added there is read
    against this file."""
    evidence = words(tab(real_section(tmp_path), "box", "evidence"))
    assert "5432" in evidence
    assert NO_RULE not in evidence and "no rule" not in evidence
