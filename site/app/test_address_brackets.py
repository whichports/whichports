"""An IPv6 address with a port is written in brackets on every tab.

    Run from site/: python3 -m pytest app/test_address_brackets.py

RFC 3986 section 3.2.2 writes an IPv6 literal with a port as `[::]:443`.
Written bare, `:::443`, a reader counts colons to find the port. The
Overview's cards took the brackets in their own commit. This holds the Packet
path's end and the Changes tab's agent lines to the same spelling, so one
socket reads one way wherever it appears.
"""
import pathlib
import re
import sys
from datetime import timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import render_live as rl  # noqa: E402
from test_render_live import NOW, add_host, db, document, probe_result, reporting  # noqa: E402

__all__ = ["db"]


def on(address, port, process="caddy", family=None):
    return {"protocol": "tcp", "family": family or ("v6" if ":" in address else "v4"),
            "bind_address": address, "port": port, "process_name": process, "pid": port}


def text_of(html):
    return " ".join(re.sub(r"<[^>]+>", " ", html).split())


def test_the_packet_path_ends_at_a_v6_socket_written_in_brackets(db):
    reporting(db, "box", document(listening=[on("::", 3030)]))
    probe_result(db, "box", 3030, "v6", "connect_succeeded")
    page = rl.render(db, now=NOW).split('id="host-box"', 1)[1]
    assert "[::]:3030" in page
    assert ":::3030" not in page


def test_a_v4_socket_on_the_packet_path_reads_as_it_did(db):
    reporting(db, "box", document(listening=[on("0.0.0.0", 8080)]))
    probe_result(db, "box", 8080, "v4", "connect_succeeded")
    page = rl.render(db, now=NOW).split('id="host-box"', 1)[1]
    assert "0.0.0.0:8080" in page
    assert "[0.0.0.0]" not in page


def test_a_socket_that_started_on_v6_is_written_in_brackets_on_the_changes_tab(db):
    older = document(listening=[on("0.0.0.0", 22, "sshd")])
    newer = document(listening=[on("0.0.0.0", 22, "sshd"), on("::", 443)])
    add_host(db, "box", [(NOW - timedelta(minutes=30), older), (NOW - timedelta(minutes=2), newer)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    page = rl.render(db, now=NOW).split('id="host-box"', 1)[1]
    changes = text_of(page.split('id="t-box-changes"', 1)[1].split('<div class="tab', 1)[0])
    assert "caddy on [::]:443" in changes
    assert ":::443" not in changes


def test_one_address_and_one_port_in_each_family():
    assert rl._address_and_port("::", 443) == "[::]:443"
    assert rl._address_and_port("fe80::1", 22) == "[fe80::1]:22"
    assert rl._address_and_port("192.0.2.7", 22) == "192.0.2.7:22"
