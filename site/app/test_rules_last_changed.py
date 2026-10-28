""""Rules last changed" on the Rules tab is the newest rule change the page
itself knows of (docs/RECORD.md 4.393, 4.395).

It was the newest date on a rule file and nothing else. So a server whose
kernel rules moved between two reports, which the Changes tab lists, still
read "Rules last changed never" on the tab beside it (measured 2026-10-06),
and before that a file's date of 14 Aug stood beside a rule change of 19 Sep.
And "never" claimed something nobody had watched for.

    Run from site/: python3 -m pytest app/test_rules_last_changed.py
"""
import pathlib
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402

NOW = trl.NOW


def at(day, month=9):
    return datetime(2026, month, day, 9, 30, tzinfo=timezone.utc)


def files(*days):
    return {"rule_files": {"status": "collected", "files": [
        {"path": "/etc/ufw/user.rules", "mtime_unix": int(at(day).timestamp())}
        for day in days]}}


def change(day, kind="rule added", layer="host firewall",
           detail="nftables ip filter: 2 to 3 rules"):
    return build.Change(at(day), layer, "agent", kind, detail=detail)


def test_a_rule_files_date_alone_is_said_as_before():
    assert rl.rules_last_changed(files(2)) == ("2 Sep", "ufw")
    assert rl.rules_last_changed(files(2), []) == ("2 Sep", "ufw")


def test_a_rule_change_seen_after_the_files_date_is_the_newer_one():
    """The measured kind: the file is of the 2nd, the kernel's rules moved on
    the 19th, and the Changes tab says so."""
    assert rl.rules_last_changed(files(2), [change(19)]) == ("19 Sep", "nftables ip filter")


def test_the_files_date_stays_when_it_is_the_newer_one():
    assert rl.rules_last_changed(files(20), [change(19)]) == ("20 Sep", "ufw")


def test_a_rule_change_with_no_rule_file_at_all_is_its_day_and_not_never():
    assert rl.rules_last_changed({}, [change(19)]) == ("19 Sep", "nftables ip filter")


@pytest.mark.parametrize("kind, detail, owner", [
    ("rule removed", "nftables inet firewalld: 9 to 8 rules", "nftables inet firewalld"),
    ("rule added", "nftables ip nat appeared, 4 rules", "nftables ip nat"),
    ("rule removed", "nftables ip raw disappeared, had 1 rule", "nftables ip raw"),
    ("file changed", "/etc/ufw/user6.rules", "ufw"),
])
def test_every_kind_of_rule_change_counts_and_names_whose_it_was(kind, detail, owner):
    assert rl.rules_last_changed({}, [change(7, kind, detail=detail)]) == ("7 Sep", owner)


def test_the_newest_of_several_changes_is_the_one_said():
    changes = [change(5), change(19, "rule removed", detail="nftables ip nat: 4 to 3 rules"),
               change(11)]
    assert rl.rules_last_changed({}, changes) == ("19 Sep", "nftables ip nat")


@pytest.mark.parametrize("layer, kind", [("process", "started"), ("container", "published"),
                                         ("provider", "rule added")])
def test_a_change_that_is_not_the_hosts_rules_does_not_count(layer, kind):
    assert rl.rules_last_changed(files(2), [change(19, kind, layer)]) == ("2 Sep", "ufw")


def test_a_change_with_no_time_does_not_count():
    timeless = build.Change(None, "host firewall", "agent", "rule added",
                            detail="nftables ip filter: 2 to 3 rules")
    assert rl.rules_last_changed(files(2), [timeless]) == ("2 Sep", "ufw")


def test_nothing_known_is_said_as_none_seen_and_never_as_never():
    assert rl.rules_last_changed({}) == (build.NO_RULE_CHANGE_SEEN, "")
    assert rl.rules_last_changed({}, []) == (build.NO_RULE_CHANGE_SEEN, "")
    assert build.NO_RULE_CHANGE_SEEN != "never"


# ----------------------------------------------------------------- on the page

def ufw(rules):
    return {"family": "ip", "name": "filter", "chains": [
        {"name": "INPUT", "hook": "input", "priority": 0, "type": "filter", "policy": "drop",
         "rules": [{"text": "counter jump ufw-user-input", "rendered": "full"}]},
        {"name": "ufw-user-input", "rules": [{"text": t, "rendered": "full"} for t in rules]}]}


def document(rules):
    doc = trl.document(listening=[trl.SSHD])
    doc["hostname"] = "box"
    doc["firewalld"] = {"status": "not_present"}
    doc["nftables"] = {"status": "collected", "tables": [ufw(rules)]}
    return doc


def text_of(html):
    return " ".join(re.sub(r"<[^>]+>", " ", re.sub(r"<svg.*?</svg>", "", html, flags=re.S)).split())


def tab(html, key, after):
    return html.split(f'id="t-box-{key}"', 1)[1].split(f'id="t-box-{after}"', 1)[0]


@pytest.fixture()
def page(tmp_path):
    """One server whose kernel rules grew by one between two reports."""
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    allow = "ip protocol tcp tcp dport %d counter accept"
    trl.add_host(path, "box", [
        (NOW - timedelta(days=6), document([allow % 22])),
        (NOW - timedelta(days=1), document([allow % 22, allow % 8410])),
        (NOW - timedelta(minutes=2), document([allow % 22, allow % 8410]))],
        last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    return rl.render(path, now=NOW)


def test_the_rules_tab_and_the_changes_tab_say_the_same_day(page):
    changes = text_of(tab(page, "changes", "settings"))
    strip = text_of(tab(page, "rules", "evidence").split('class="fw"', 1)[0])
    day = (NOW - timedelta(days=1)).strftime("%-d %b")

    assert f"{day} " in changes and "rule added" in changes.lower()
    assert f"Rules last changed {day} nftables ip filter" in strip
    assert "never" not in strip


def test_a_server_with_no_rule_change_known_does_not_say_never(tmp_path):
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(path, "box", document(["ip protocol tcp tcp dport 22 counter accept"]))
    strip = text_of(tab(rl.render(path, now=NOW), "rules", "evidence").split('class="fw"', 1)[0])

    assert f"Rules last changed {build.NO_RULE_CHANGE_SEEN}" in strip
    assert "never" not in strip


# --------------------------------------- a file's date, only when in effect
#
# The first big server test (docs/RECORD.md 4.220): a server with ufw
# installed and never enabled read the date of ufw's files under Rules last
# changed, and a server with nftables by hand read the date of the image's
# /etc/nftables.conf. A file's date is named for a firewall that is in effect
# on the server and for no other (docs/RECORD.md 4.454).

def dated(path, day):
    return {"path": path, "mtime_unix": int(at(day).timestamp())}


def rule_files(*entries):
    return {"rule_files": {"status": "collected", "files": list(entries)}}


UFW_2_SEP = dated("/etc/ufw/user.rules", 2)
NFT_20_SEP = dated("/etc/nftables.conf", 20)


def test_with_nobody_said_to_be_in_effect_every_file_counts_as_before():
    """The function alone, asked without the list, keeps its old answer."""
    assert rl.rules_last_changed(rule_files(UFW_2_SEP, NFT_20_SEP)) == ("20 Sep", "nftables")


def test_a_file_of_a_firewall_that_is_not_in_effect_is_not_named():
    assert rl.rules_last_changed(rule_files(UFW_2_SEP), (), in_effect=()) == (
        build.NO_RULE_CHANGE_SEEN, "")
    assert rl.rules_last_changed(rule_files(UFW_2_SEP, NFT_20_SEP), (), in_effect=("ufw",)) == (
        "2 Sep", "ufw")


@pytest.mark.parametrize("path,owner", [
    ("/etc/ufw/user.rules", "ufw"), ("/etc/default/ufw", "ufw"),
    ("/etc/firewalld/zones/public.xml", "firewalld"),
    ("/etc/nftables.conf", "nftables"), ("/etc/iptables/rules.v4", "iptables"),
])
def test_a_file_is_named_when_its_own_firewall_is_in_effect(path, owner):
    others = tuple(name for name in ("ufw", "firewalld", "nftables", "iptables") if name != owner)
    assert rl.rules_last_changed(rule_files(dated(path, 7)), (), in_effect=(owner,)) == ("7 Sep", owner)
    assert rl.rules_last_changed(rule_files(dated(path, 7)), (), in_effect=others) == (
        build.NO_RULE_CHANGE_SEEN, "")


def test_a_file_no_firewall_owns_counts_whoever_is_in_effect():
    assert rl.rules_last_changed(rule_files(dated("/etc/other.rules", 7)), (), in_effect=()) == (
        "7 Sep", "")


def test_a_files_change_between_two_reports_follows_the_same_rule():
    moved = change(19, "file changed", detail="/etc/ufw/user.rules")
    assert rl.rules_last_changed({}, [moved], in_effect=()) == (build.NO_RULE_CHANGE_SEEN, "")
    assert rl.rules_last_changed({}, [moved], in_effect=("ufw",)) == ("19 Sep", "ufw")


def test_a_kernel_rule_added_or_removed_counts_whoever_is_in_effect():
    """That change was read in the kernel, which is in effect by being there."""
    assert rl.rules_last_changed({}, [change(19)], in_effect=()) == ("19 Sep", "nftables ip filter")


def a_server(files, ufw_enabled=None, by_hand=(), legacy=()):
    """A server's document with these rule files, ufw as said (None is not
    installed), and rules written straight into the kernel."""
    doc = trl.document(listening=[trl.SSHD])
    doc["hostname"] = "box"
    doc["firewalld"] = {"status": "not_present"}
    doc["containers"] = {"status": "not_present"}
    doc["rule_files"] = {"status": "collected", "files": list(files)}
    doc["ufw"] = {"status": "not_present"}
    tables = []
    if ufw_enabled is not None:
        doc["ufw"] = {"status": "collected", "conf": {"ENABLED": "yes" if ufw_enabled else "no"},
                      "defaults": {"DEFAULT_INPUT_POLICY": "DROP", "DEFAULT_OUTPUT_POLICY": "ACCEPT"},
                      "rules": ["allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"], "rules6": []}
    if ufw_enabled:
        tables.append(ufw(["ip protocol tcp tcp dport 22 counter accept"]))
    if by_hand:
        tables.append({"family": "inet", "name": "filter", "chains": [
            {"name": "input", "hook": "input", "priority": 0, "type": "filter", "policy": "drop",
             "rules": [{"text": t, "rendered": "full"} for t in by_hand]}]})
    doc["nftables"] = {"status": "collected", "tables": tables}
    if legacy:
        doc["iptables"] = {"status": "collected", "tables": [{"name": "filter", "chains": [
            {"name": "INPUT", "builtin": True, "policy": "drop",
             "rules": [{"text": t, "rendered": "full"} for t in legacy]}]}]}
    return doc


def last_changed(doc):
    """The third fact of the Rules tab's strip: its value and the line under it."""
    body = rl.rules_tab_body(doc, "box")
    found = re.search(r'<div class="l">Rules last changed</div><div class="n">([^<]*)</div>'
                      r'<div class="d">([^<]*)</div>', body)
    return found.group(1), found.group(2)


def test_ufw_installed_and_not_enabled_lends_no_date():
    assert last_changed(a_server([UFW_2_SEP], ufw_enabled=False)) == (build.NO_RULE_CHANGE_SEEN, "")


def test_ufw_enabled_lends_its_files_date():
    assert last_changed(a_server([UFW_2_SEP], ufw_enabled=True)) == ("2 Sep", "ufw")


def test_the_images_nftables_conf_is_not_named_on_a_server_with_ufw_alone():
    """The kernel holds ufw's chains and the way into them and nothing else,
    so no rule there is nftables by hand."""
    assert last_changed(a_server([UFW_2_SEP, NFT_20_SEP], ufw_enabled=True)) == ("2 Sep", "ufw")


def test_nftables_conf_is_named_where_rules_stand_in_the_kernel_by_hand():
    doc = a_server([NFT_20_SEP], by_hand=["meta l4proto tcp tcp dport 22 accept"])
    assert last_changed(doc) == ("20 Sep", "nftables")


def test_nftables_conf_is_not_named_over_an_empty_kernel():
    assert last_changed(a_server([NFT_20_SEP])) == (build.NO_RULE_CHANGE_SEEN, "")


def test_a_legacy_rules_file_is_named_where_legacy_rules_stand():
    files = [dated("/etc/iptables/rules.v4", 7)]
    assert last_changed(a_server(files, legacy=["-p icmp accept"])) == ("7 Sep", "iptables")
    assert last_changed(a_server(files)) == (build.NO_RULE_CHANGE_SEEN, "")
