"""The Rules tab's kernel block and a named firewall's own way in.

    Run from site: python3 -m pytest app/test_rules_kernel_named_jump.py

ufw hangs its chains on the kernel's INPUT, FORWARD and OUTPUT with six lines
each, `counter jump ufw-before-input` and five more, once for v4 and once for
v6. Those lines are how ufw's rules are reached at all. The block "In the
kernel, not written by a named firewall" listed all 36 of them on a server
that has nothing but ufw, and the strip counted a second firewall
(docs/RECORD.md 4.453).

`testdata/ufw_ubuntu_2604.json` is the agent's own document in stdout mode on
Ubuntu 26.04.1 with ufw 0.36.2 enabled and three rules, taken on 2026-10-11.
Two things in it are changed: the host name is made up and the one interface
address is left out.

What stays listed is the point of half these tests. Only a line that is the
jump and nothing else is the firewall's own. A jump behind a condition, a jump
with a note on it and a jump into a chain nobody named are somebody's lines.

And a firewall's own line is left out only where that firewall is counted in
a block of its own on the tab. ufw switched off in its file with its lines
still in the kernel keeps all 36 listed, so the page can never say no
firewall over a kernel that holds one.
"""
import copy
import html
import json
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402

REAL = pathlib.Path(__file__).resolve().parent / "testdata" / "ufw_ubuntu_2604.json"
SERVER = "ubuntu-ufw-01"
# Both named firewalls counted, which is the most this block ever leaves out.
BOTH = ("ufw", "docker")


def real_document():
    return json.loads(REAL.read_text(encoding="utf-8"))


def rule(text, comment=""):
    made = {"text": text, "rendered": "full"}
    if comment:
        made["comment"] = comment
    return made


def one_chain(text, comment="", chain="INPUT", table="filter", section="nftables"):
    """A document whose kernel holds one rule, in a chain nobody named."""
    return {section: {"status": "collected", "tables": [
        {"family": "ip", "name": table, "chains": [
            {"name": chain, "type": "filter", "hook": "input", "priority": 0,
             "policy": "accept", "rules": [rule(text, comment)]}]}]}}


def with_a_rule_in_input(doc, text):
    """The real document with one more rule at the end of v4's INPUT."""
    doc = copy.deepcopy(doc)
    for table in doc["nftables"]["tables"]:
        if table["family"] != "ip":
            continue
        for chain in table["chains"]:
            if chain["name"] == "INPUT":
                chain["rules"].append(rule(text))
    return doc


def page_text(markup):
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", markup))).strip()


def fact(markup, label):
    """The number under one of the strip's three labels."""
    found = re.search(rf'<div class="l">{re.escape(label)}</div><div class="n">([^<]*)</div>', markup)
    assert found, f"no fact labelled {label}"
    return found.group(1)


# ------------------------------------------------ what stays listed, first

@pytest.mark.parametrize("text", [
    'iifname "eth0" counter jump ufw-user-input',
    "ip saddr 192.0.2.0/24 counter jump ufw-user-input",
    "tcp dport 8080 counter jump ufw-user-input",
    'iifname "eth0" goto ufw-user-input',
])
def test_a_jump_behind_a_condition_stays_listed(text):
    """Somebody decided which packets take it, so it is their line."""
    block, rows = rl.kernel_leftovers_block(SERVER, one_chain(text), "", BOTH)
    assert rows == 1
    assert html.escape(text) in block


def test_a_bare_jump_with_a_note_on_it_stays_listed():
    """ufw writes no note on its own lines. A note is a person's."""
    doc = one_chain("counter jump ufw-user-input", comment="mine")
    block, rows = rl.kernel_leftovers_block(SERVER, doc, "", BOTH)
    assert rows == 1 and "mine" in block


@pytest.mark.parametrize("text", [
    "counter jump my-own-chain",
    "jump allowlist",
    "goto LOGDROP",
])
def test_a_bare_jump_into_a_chain_nobody_named_stays_listed(text):
    block, rows = rl.kernel_leftovers_block(SERVER, one_chain(text), "", BOTH)
    assert rows == 1 and text in block


@pytest.mark.parametrize("text", [
    "counter accept",
    "tcp dport 22 counter accept",
    "counter drop",
    # the chain's name inside a rule that is not a jump to it
    'counter log prefix "jump ufw-user-input"',
    "counter jump ufw-user-input counter",
])
def test_a_rule_that_is_not_only_the_jump_stays_listed(text):
    block, rows = rl.kernel_leftovers_block(SERVER, one_chain(text), "", BOTH)
    assert rows == 1


def test_a_rule_of_somebodys_beside_ufws_jumps_is_the_only_row():
    """A server with ufw and one rule written by hand in INPUT: the block
    holds that rule alone, numbered 1, and it counts as the second firewall."""
    doc = with_a_rule_in_input(real_document(), "tcp dport 8080 counter accept")
    block, rows = rl.kernel_leftovers_block(SERVER, doc, "", ("ufw",))
    assert rows == 1
    assert "tcp dport 8080 counter accept" in block
    assert "ufw-before-input" not in block and "ufw6-" not in block
    assert build.rules_row_id(SERVER, "kernel", 1) in block
    assert build.rules_row_id(SERVER, "kernel", 2) not in block
    body = rl.rules_tab_body(doc, SERVER)
    assert fact(body, "Firewalls active") == "2"
    assert fact(body, "Rules") == "4"


# ------------------------- a firewall that is not counted keeps its way in

@pytest.mark.parametrize("counted", [(), ("docker",), ("firewalld",), ("",)])
def test_a_way_in_stays_listed_when_its_firewall_is_not_counted(counted):
    doc = one_chain("counter jump ufw-before-input")
    block, rows = rl.kernel_leftovers_block(SERVER, doc, "", counted)
    assert rows == 1 and "ufw-before-input" in block


def test_nobody_counted_is_what_the_block_takes_when_it_is_not_told():
    doc = one_chain("counter jump ufw-before-input")
    assert rl.kernel_leftovers_block(SERVER, doc, "")[1] == 1


def with_ufw_conf(doc, conf):
    doc = copy.deepcopy(doc)
    doc["ufw"]["conf"] = conf
    return doc


@pytest.mark.parametrize("conf", [
    {"ENABLED": "no", "LOGLEVEL": "low"},   # switched off in the file
    {"LOGLEVEL": "low"},                    # the file did not say
    {},
])
def test_ufw_that_is_not_counted_keeps_its_lines_in_the_kernels_list(conf):
    """The file says off, or does not say, and the kernel still holds ufw's
    chains with the way into them. That is a firewall in effect, and the 36
    lines are what shows it."""
    body = rl.rules_tab_body(with_ufw_conf(real_document(), conf), SERVER)
    text = page_text(body)
    assert build.NO_FIREWALL not in text
    assert "In the kernel" in text and "counter jump ufw-before-input" in text
    assert fact(body, "Firewalls active") == "1"
    # ufw's 36 lines, and the policy drop of INPUT and of FORWARD for each
    # family, which are rows since 4.454 where ufw is not counted
    assert fact(body, "Rules") == "40"


def docker_document(containers):
    """Docker's two lines in FORWARD, as a Fedora 44 test server's document
    holds them, and what the agent says of its containers."""
    doc = one_chain("counter jump DOCKER-USER", chain="FORWARD")
    doc["nftables"]["tables"][0]["chains"][0]["rules"].append(rule("counter jump DOCKER-FORWARD"))
    doc["containers"] = containers
    return doc


def test_dockers_way_in_is_left_out_under_dockers_own_block():
    published = {"status": "collected", "docker": [
        {"id": "abc123456789", "name": "web", "image": "web:latest",
         "ports": [{"host_ip": "0.0.0.0", "host_port": 8080,
                    "container_port": 80, "protocol": "tcp"}]}]}
    body = rl.rules_tab_body(docker_document(published), SERVER)
    assert "DOCKER-USER" not in body and "DOCKER-FORWARD" not in body
    assert build.NOTHING_ELSE_IN_KERNEL in page_text(body)
    assert fact(body, "Firewalls active") == "1"


@pytest.mark.parametrize("containers", [
    {"status": "permission_denied", "cause": "permission"},   # as on that server
    {"status": "collected", "docker": []},                    # nothing published
    {"status": "not_present"},
])
def test_dockers_way_in_stays_listed_when_docker_has_no_block(containers):
    body = rl.rules_tab_body(docker_document(containers), SERVER)
    assert "counter jump DOCKER-USER" in body and "counter jump DOCKER-FORWARD" in body
    assert fact(body, "Firewalls active") == "1"


# ------------------------------------------------------ what is not listed

@pytest.mark.parametrize("text", [
    "counter jump ufw-before-input",
    "counter jump ufw6-before-logging-forward",
    "jump ufw-user-input",
    "goto ufw-user-input",
    "counter goto ufw-track-output",
    "counter jump DOCKER-USER",
])
def test_a_bare_jump_into_a_named_firewalls_chain_is_not_listed(text):
    block, rows = rl.kernel_leftovers_block(SERVER, one_chain(text), "", BOTH)
    assert (block, rows) == ("", 0)


@pytest.mark.parametrize("section", ["iptables", "ip6tables"])
def test_the_older_tables_are_read_the_same_way(section):
    """The agent writes a legacy rule that only jumps as `jump <chain>`."""
    doc = one_chain("jump ufw-before-input", section=section)
    assert rl.kernel_leftovers_block(SERVER, doc, "", BOTH) == ("", 0)
    doc = one_chain("-p tcp jump ufw-before-input", section=section)
    assert rl.kernel_leftovers_block(SERVER, doc, "", BOTH)[1] == 1


def test_the_real_document_holds_ufws_thirty_six_lines():
    """The fixture is what this file is about. If it ever stops holding the
    lines, the tests under it pass for nothing."""
    bare = [r["text"] for table in real_document()["nftables"]["tables"]
            for chain in table["chains"] if chain["name"] in ("INPUT", "FORWARD", "OUTPUT")
            for r in chain["rules"]]
    assert len(bare) == 36
    assert all(re.fullmatch(r"counter jump ufw6?-[a-z-]+", text) for text in bare)


def test_a_real_ufw_server_lists_nothing_in_the_kernel():
    assert rl.kernel_leftovers_block(SERVER, real_document(), "", ("ufw",)) == ("", 0)


def test_a_real_ufw_server_has_one_firewall_and_its_three_rules():
    body = rl.rules_tab_body(real_document(), SERVER)
    assert fact(body, "Firewalls active") == "1"
    assert fact(body, "Rules") == "3"
    text = page_text(body)
    assert build.NOTHING_ELSE_IN_KERNEL in text
    assert "In the kernel" not in text
    assert "ufw-before" not in text and "ufw6-" not in text
