"""The Packet path of a port with nothing on its way.

    Run from site/: python3 -m pytest app/test_path_nothing_on_the_way.py

Two things, measured on 2026-10-12 (docs/RECORD.md 4.454):

A port with no tool on its way had no path, and when that was every port
the tab said "No port on this host has a path from outside: nothing is bound
to a network address and no container publishes one." On a server with no
firewall at all that is untrue: ports are bound and answer. The drawing
takes a path with nothing on it, so such a port keeps its path, and the
sentence stands only where it is true.

ufw installed and never enabled stood on every path as a box reading "no
rule for 8410" (docs/RECORD.md 4.220). A ufw whose own file says it is off
filters nothing and gets no box. One whose file does not say keeps it.

Rules written into the kernel by hand have no box of their own, which the
tab's spec lists as not built, and the spec says what a path past them is:
drawn, and a chain belonging to nobody blames nobody. So a server with
nftables by hand keeps its paths too, with what was measured at their end.
"""
import copy
import html
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
import test_rules_kernel_named_jump as jump  # noqa: E402
import test_rules_raw_nftables as raw  # noqa: E402

NOW = trl.NOW
NOTHING_BOUND = "nothing is bound to a network address"


def sock(port, name, pid, address="0.0.0.0"):
    return {"protocol": "tcp", "family": "v6" if ":" in address else "v4",
            "bind_address": address, "port": port, "process_name": name, "pid": pid}


UVICORN = sock(8410, "uvicorn", 7)


def bare_server(listening=(trl.SSHD, UVICORN)):
    """A server with nothing of its own: no ufw, no firewalld, no container
    and an empty kernel."""
    doc = raw.document(rules=())
    doc["sockets"] = trl.document(listening=list(listening))["sockets"]
    return doc


def with_ufw(doc, conf, rules=("allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in",)):
    doc = copy.deepcopy(doc)
    doc["ufw"] = {"status": "collected", "conf": conf,
                  "defaults": {"DEFAULT_INPUT_POLICY": "DROP", "DEFAULT_OUTPUT_POLICY": "ACCEPT"},
                  "rules": list(rules), "rules6": []}
    return doc


def path_tab(tmp_path, doc, answering=(8410,)):
    """The words of the server's Packet path tab on a whole live page, with
    the ports given measured as answering over v4."""
    db = str(tmp_path / "cp.db")
    con = sqlite3.connect(db)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(db, "box", doc)
    for port in answering:
        trl.probe_result(db, "box", port, "v4", "connect_succeeded",
                         measured_at=NOW - timedelta(minutes=5))
    page = rl.render(db, now=NOW)
    section = page[page.index('id="host-box"'):]
    # from the end of the panel's own tag to the next panel's
    tab = section.split('id="t-box-path"', 1)[1].split(">", 1)[1].split('<div class="tab ', 1)[0]
    bare = re.sub(r"<[^>]+>", " ", re.sub(r"<svg.*?</svg>", "", tab, flags=re.S))
    return " ".join(html.unescape(bare).split())


def chips(words):
    """The ports the picker offers, from the tab's words."""
    head = words.split("Path for", 1)[1] if "Path for" in words else ""
    return re.findall(r"(\d+/tcp v[46])", head.split(" tcp/", 1)[0])


# ------------------------------------------- where the old sentence is true

def test_a_server_with_nothing_bound_to_a_network_address_still_says_so(tmp_path):
    doc = bare_server(listening=[sock(5432, "postgres", 5, "127.0.0.1")])
    words = path_tab(tmp_path, doc, answering=())
    assert NOTHING_BOUND in words


# ---------------------------------------- a port with nothing on its way

def test_a_port_on_a_server_with_no_firewall_keeps_its_path(tmp_path):
    words = path_tab(tmp_path, bare_server())
    assert NOTHING_BOUND not in words
    assert chips(words) == ["22/tcp v4", "8410/tcp v4"]
    assert "answered connected from probe1" in words
    assert "reaches uvicorn" in words.lower()
    assert "ufw" not in words


def test_a_port_that_does_not_answer_keeps_its_path_too(tmp_path):
    words = path_tab(tmp_path, bare_server(), answering=())
    assert chips(words) == ["22/tcp v4", "8410/tcp v4"]
    assert NOTHING_BOUND not in words


# ------------------------------------------------- ufw, on the way or not

def test_ufw_whose_file_says_off_stands_on_no_path(tmp_path):
    words = path_tab(tmp_path, with_ufw(bare_server(), {"ENABLED": "no"}))
    assert chips(words) == ["22/tcp v4", "8410/tcp v4"]
    assert "ufw" not in words
    assert "no rule for 8410" not in words


@pytest.mark.parametrize("conf", [{"ENABLED": "yes"}, {}, {"LOGLEVEL": "low"}])
def test_ufw_that_is_on_or_whose_file_does_not_say_keeps_its_box(tmp_path, conf):
    words = path_tab(tmp_path, with_ufw(bare_server(), conf))
    assert chips(words) == ["22/tcp v4", "8410/tcp v4"]
    assert "ufw no rule for 8410" in words


# ------------------------------------------------- rules written by hand

def test_nftables_by_hand_keeps_its_paths_and_blames_nobody(tmp_path):
    """The twelve rules of the first big test, with the policy drop. 8410
    answers and is drawn as reaching its service, 22 was not probed. No box
    is drawn for rules no tool wrote, and nobody is said to end a journey."""
    doc = raw.document()
    doc["sockets"] = bare_server()["sockets"]
    words = path_tab(tmp_path, doc)
    assert chips(words) == ["22/tcp v4", "8410/tcp v4"]
    assert NOTHING_BOUND not in words
    assert "answered connected from probe1" in words
    assert "ends its journey here" not in words


def real_ufw_server(conf=None):
    doc = jump.real_document()
    doc["sockets"] = bare_server()["sockets"]
    if conf is not None:
        doc["ufw"]["conf"] = conf
    return doc


def test_the_real_ufw_server_keeps_its_paths_with_ufws_box(tmp_path):
    words = path_tab(tmp_path, real_ufw_server())
    assert chips(words) == ["22/tcp v4", "8410/tcp v4"]
    assert "ufw no rule for 8410" in words


def test_ufw_switched_off_in_its_file_with_its_chains_still_in_the_kernel(tmp_path):
    """Its file says off, so it has no box. The chains it left in the kernel
    hang on a chain nobody named, which has no box either, and the path is
    drawn with what was measured at its end."""
    words = path_tab(tmp_path, real_ufw_server({"ENABLED": "no"}))
    assert chips(words) == ["22/tcp v4", "8410/tcp v4"]
    assert "ufw" not in words.replace("ubuntu-ufw-01", "")
    assert "host firewall" not in words


# ------------------------------------------------------- the older tables

def test_a_server_on_the_older_iptables_keeps_its_paths_and_counts_its_rules(tmp_path):
    """Those rules are stored by match name and can never be placed on a
    port, which docs/PRODUCT.md 4g answers with a count under the flow. The
    count was promised and never shown, since no port had a path."""
    doc = raw.document(rules=(), legacy=raw.LEGACY_RULES)
    doc["sockets"] = bare_server()["sockets"]
    words = path_tab(tmp_path, doc)
    assert chips(words) == ["22/tcp v4", "8410/tcp v4"]
    assert "4 legacy iptables rules, not placed on a port" in words
    assert NOTHING_BOUND not in words
