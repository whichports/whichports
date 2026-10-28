"""A ufw that is installed and not enabled is not a firewall that is active.

    Run from site/: python3 -m pytest app/test_rules_ufw_not_enabled.py

The first big server test, on a fresh Ubuntu 24.04 server (docs/RECORD.md
4.220): ufw's files were there, `ENABLED=no`, and the kernel held no rule. The
Rules tab said "Firewalls active 1" and drew ufw's "incoming drop" beside the
words not enabled, and the Packet path said "default incoming drop" on every
port. Nothing filtered that server. docs/PRODUCT.md section 2 says zero layers
is the one depth that is called out.

The document below is written from that server's stored section statuses, the
tab as it was drawn that day and the test's notes. The document itself was
not kept.
"""
import html as html_mod
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
from test_render_live import db  # noqa: E402,F401

NOW = trl.NOW
SSH = [{"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 22,
        "owner_uid": 0, "owner_name": "root",
        "cgroup": "/system.slice/ssh.socket", "unit": "ssh.socket"},
       {"protocol": "tcp", "family": "v6", "bind_address": "::", "port": 22,
        "owner_uid": 0, "owner_name": "root",
        "cgroup": "/system.slice/ssh.socket", "unit": "ssh.socket"}]

V4_RULE = "allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"
V6_RULE = "allow tcp 22 ::/0 any ::/0 in"
OTHER_RULE = "allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in"


def document(enabled="no", rules=(), rules6=(), refused=False):
    """A server with ufw's files on it and nothing in the kernel. `enabled`
    is the word in ufw.conf, or None for a conf that did not say."""
    doc = trl.document(listening=SSH)
    doc["hostname"] = "ubuntu-app-01"
    doc["firewalld"] = {"status": "not_present"}
    doc["nftables"] = {"status": "collected", "tables": []}
    doc["containers"] = {"status": "not_present"}
    conf = {"LOGLEVEL": "low"}
    if enabled is not None:
        conf["ENABLED"] = enabled
    rules_read = ({"status": "permission_denied", "cause": "permission"} if refused
                  else {"status": "collected"})
    doc["ufw"] = {"status": "collected", "conf": conf,
                  "defaults": {"DEFAULT_INPUT_POLICY": "DROP",
                               "DEFAULT_OUTPUT_POLICY": "ACCEPT",
                               "DEFAULT_FORWARD_POLICY": "DROP"},
                  "rules": list(rules), "rules6": list(rules6),
                  "sources": {"ufw.conf": {"status": "collected"},
                              "default": {"status": "collected"},
                              "user.rules": rules_read, "user6.rules": rules_read}}
    return doc


def text_of(markup):
    bare = re.sub(r"<[^>]+>", " ", re.sub(r"<svg.*?</svg>", "", markup, flags=re.S))
    return " ".join(html_mod.unescape(bare).split())


def page_of(db, doc):
    trl.reporting(db, "box", doc)
    trl.probe_result(db, "box", 22, "v4", "connect_succeeded")
    return rl.render(db, now=NOW)


def tab(page, name):
    return page.split(f'id="t-box-{name}"', 1)[1].split('id="t-box-', 1)[0]


def strip(rules_tab):
    """The three facts as {label: value}."""
    return dict(re.findall(r'<div class="l">([^<]+)</div><div class="n">([^<]*)</div>',
                           rules_tab))


def ufw_head(rules_tab):
    """The words of ufw's own row on the Rules tab, or "" without one."""
    for head in re.findall(r'<div class="fwh">(.*?)</div>', rules_tab, re.S):
        words = text_of(head)
        if words.startswith("ufw"):
            return words
    return ""


# ------------------------------------------------- the states beside not enabled

def test_a_conf_that_did_not_say_is_not_called_no_firewall(db):
    """Not known to be on, so not counted and no default drawn. Not known to
    be off either, so the page does not say no firewall is active: ufw's own
    row says the file did not say."""
    rules = tab(page_of(db, document(enabled=None)), "rules")
    assert strip(rules)["Firewalls active"] == "0"
    assert build.NO_FIREWALL not in rules
    assert ufw_head(rules) == "ufw did not say"


def test_an_enabled_ufw_whose_rules_were_refused_is_still_a_firewall(db):
    """ufw.conf said yes and the rules files were not readable. The firewall
    is on and counted, its defaults are in effect, and its row says what was
    not read."""
    rules = tab(page_of(db, document(enabled="yes", refused=True)), "rules")
    assert strip(rules)["Firewalls active"] == "1"
    assert build.NO_FIREWALL not in rules
    assert ufw_head(rules) == "ufw not readable incoming deny outgoing allow"


def test_an_enabled_ufw_reads_as_it_did(db):
    page = page_of(db, document(enabled="yes", rules=[V4_RULE], rules6=[V6_RULE]))
    rules = tab(page, "rules")
    assert strip(rules)["Firewalls active"] == "1"
    assert strip(rules)["Rules"] == "1"
    assert build.NO_FIREWALL not in rules
    assert ufw_head(rules) == "ufw active incoming deny outgoing allow"
    assert "default incoming deny" in text_of(tab(page, "path"))
    assert "default incoming deny" in text_of(tab(page, "evidence"))


@pytest.mark.parametrize("enabled,expected", [
    ("yes", True), ("YES", True), (" yes ", True),
    ("no", False), ("", False), (None, False), ("maybe", False)])
def test_ufw_is_enabled_only_when_its_own_file_says_yes(enabled, expected):
    section = document(enabled=enabled)["ufw"]
    assert rl.ufw_enabled(section) is expected
    assert rl.ufw_enabled({}) is False and rl.ufw_enabled(None) is False


# ------------------------------------------------------------ not enabled

def test_a_ufw_that_is_not_enabled_is_not_counted_as_a_firewall(db):
    rules = tab(page_of(db, document()), "rules")
    assert strip(rules)["Firewalls active"] == "0"
    assert strip(rules)["Rules"] == "0"


def test_no_firewall_active_is_called_out_and_ufw_keeps_its_own_row(db):
    """Zero layers is the one depth the product calls out. ufw is still on
    the server, so its row stays, with its own state and nothing else."""
    rules = tab(page_of(db, document()), "rules")
    assert rules.count(build.NO_FIREWALL) == 1
    assert ufw_head(rules) == "ufw not enabled"
    assert rules.index(build.NO_FIREWALL) < rules.index('<div class="fwh">')


def test_a_default_that_is_not_in_effect_is_on_no_tab(db):
    """One function gives every tab ufw's default (docs/RECORD.md 4.443), so
    one function keeps it off all four while ufw is not enabled."""
    page = page_of(db, document())
    assert rl.ufw_defaults(document()["ufw"]) == ()
    assert rl._ufw_default(document()) == ""
    card = tab(page, "overview").split('for="pr-box-tcp-22"', 1)[1]
    firewall = text_of(re.search(
        r'<span class="k">firewall</span><span class="v">(.*?)</span></div>', card, re.S).group(1))
    assert firewall == "no rule names 22"
    evidence = text_of(tab(page, "evidence"))
    assert "ufw present, not enabled" in evidence
    assert "default incoming" not in evidence
    assert "incoming" not in ufw_head(tab(page, "rules"))
    path = text_of(tab(page, "path")).lower()
    assert "default incoming" not in path and "default outgoing" not in path


def test_the_rules_of_a_ufw_that_is_not_enabled_are_listed_and_not_counted(db):
    """The tab lists every rule the server holds. The strip counts the rules
    of firewalls that are active, the way it leaves out firewalld's zones
    that are not in effect (docs/RECORD.md 4.342)."""
    rules = tab(page_of(db, document(rules=[V4_RULE, OTHER_RULE], rules6=[V6_RULE])), "rules")
    assert strip(rules)["Firewalls active"] == "0"
    assert strip(rules)["Rules"] == "0"
    assert rules.count('class="fwr"') == 2
    assert ">22<" in rules and ">443<" in rules
    assert rules.count(build.NO_FIREWALL) == 1
