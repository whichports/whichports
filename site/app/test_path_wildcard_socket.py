"""The Packet path offers the v4 path of a port whose only socket is on `::`
(docs/RECORD.md 4.347).

A socket on the IPv6 wildcard may be taking the port's v4 connections too.
Whether it does is IPV6_V6ONLY, which the server's document does not carry,
so on v4 such a socket is neither an owner nor an absence (docs/PRODUCT.md
8a). The Overview has said so since 4.267: its v4 card reads "listens on
[::]:3030" beside the prober's v4 connection. The Packet path had no v4 path
for that port at all, seen on a real server (4.309).

    Run from site/: python3 -m pytest app/test_path_wildcard_socket.py
"""
import pathlib
import re
import sqlite3
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
import test_render_live as h  # noqa: E402


def socket(address, port=3030, protocol="tcp", name="dual", pid=41):
    family = "v6" if ":" in address else "v4"
    return {"protocol": protocol, "family": family, "bind_address": address,
            "port": port, "process_name": name, "pid": pid}


def document(*sockets):
    """A server with ufw, so every path has a firewall to draw, and the
    sockets given."""
    doc = h.document(listening=list(sockets))
    doc["hostname"] = "web-01"
    doc["firewalld"] = {"status": "not_present"}
    doc["nftables"] = {"status": "collected", "tables": []}
    doc["ufw"] = {"status": "collected", "conf": {"ENABLED": "yes"},
                  "defaults": {"DEFAULT_INPUT_POLICY": "DROP"},
                  "rules": ["allow tcp 3030 0.0.0.0/0 any 0.0.0.0/0 in"],
                  "rules6": ["allow tcp 3030 ::/0 any ::/0 in"],
                  "sources": {"ufw.conf": {"status": "collected"},
                              "user.rules": {"status": "collected"},
                              "user6.rules": {"status": "collected"}}}
    return doc


def text_of(html):
    return " ".join(re.sub(r"<[^>]+>", " ", re.sub(r"<svg.*?</svg>", "", html, flags=re.S)).split())


def paths(doc, findings=()):
    """The tab's paths as {"3030/tcp v4": what its walk says}."""
    html = rl.path_tab_body(doc, "web-01", findings=findings)
    if 'class="walk"' not in html:
        return {}
    chips = re.findall(r"<label[^>]*>([^<]+)</label>", html.split('class="walks"')[0])
    walks = [text_of(w) for w in html.split('<div class="walk">')[1:]]
    assert len(chips) == len(walks)
    return dict(zip(chips, walks))


# ------------------------------------------------------------ the measured case

def test_a_port_whose_only_socket_is_on_the_v6_wildcard_has_a_v4_path():
    got = paths(document(socket("::")))

    assert list(got) == ["3030/tcp v4", "3030/tcp v6"]
    # Its end is the socket there is, with its own address, as the
    # Overview's v4 card writes it.
    assert "listening dual [::]:3030" in got["3030/tcp v4"]
    assert "listening dual [::]:3030" in got["3030/tcp v6"]


def test_the_v4_path_is_walked_as_a_v4_packet():
    """The firewall on the way is read for v4: ufw's v4 rule, not its v6
    one."""
    doc = document(socket("::"))
    doc["ufw"]["rules"] = []          # nothing for v4
    got = paths(doc)

    assert "ufw no rule for 3030" in got["3030/tcp v4"]
    assert "ufw allow 3030, anywhere" in got["3030/tcp v6"]


def test_udp_is_no_different():
    got = paths(document(socket("::", protocol="udp")))
    assert list(got) == ["3030/udp v4", "3030/udp v6"]


# ------------------------------------------- what is not the wildcard stays as it was

@pytest.mark.parametrize("address", ["2001:db8::1", "fe80::1", "::ffff:192.0.2.1"])
def test_a_socket_on_one_v6_address_takes_no_v4_connection_and_has_no_v4_path(address):
    got = paths(document(socket(address)))
    assert list(got) == ["3030/tcp v6"]


def test_a_socket_on_v6_loopback_has_no_path_at_all():
    assert paths(document(socket("::1"))) == {}


def test_a_v4_socket_beside_the_wildcard_is_the_end_of_the_v4_path():
    got = paths(document(socket("0.0.0.0", name="four", pid=4), socket("::", name="six", pid=6)))

    assert list(got) == ["3030/tcp v4", "3030/tcp v6"]
    assert "listening four 0.0.0.0:3030" in got["3030/tcp v4"]
    assert "six" not in got["3030/tcp v4"]
    assert "listening six [::]:3030" in got["3030/tcp v6"]


def test_a_v4_socket_on_loopback_beside_the_wildcard_still_has_no_v4_path():
    """The v4 sockets that exist decide, as before: all of them on loopback
    is a port no v4 packet from outside reaches by them. The wildcard is not
    asked when a v4 socket is there."""
    got = paths(document(socket("127.0.0.1"), socket("::")))
    assert list(got) == ["3030/tcp v6"]


def test_a_port_with_only_a_v4_socket_gets_no_v6_path():
    """The ambiguity has one direction. A v4 socket cannot take a v6
    connection."""
    got = paths(document(socket("0.0.0.0")))
    assert list(got) == ["3030/tcp v4"]


@pytest.mark.parametrize("address", [None, "", "not an address", 7])
def test_an_address_that_will_not_read_is_not_the_wildcard(address):
    s = socket("::")
    s["bind_address"] = address
    assert rl.wildcard_v6_sockets({"v6": [s]}) == []


def test_the_wildcard_is_read_as_an_address_and_not_as_text():
    """`::` written the long way is the same address."""
    long_way = socket("::")
    long_way["bind_address"] = "0:0:0:0:0:0:0:0"
    assert rl.wildcard_v6_sockets({"v6": [long_way]}) == [long_way]
    assert rl.wildcard_v6_sockets({"v4": [socket("0.0.0.0")]}) == []


# ---------------------------------------------------------------- on the page

def test_with_the_probers_v4_connection_the_path_reaches_the_socket(tmp_path):
    """The whole page: the server reports one socket on `::`, the prober
    connected over v4, and the v4 path ends at that socket as reached."""
    db = str(tmp_path / "cp.db")
    con = sqlite3.connect(db)
    con.executescript(h.SCHEMA)
    con.commit()
    con.close()
    h.reporting(db, "web-01", document(socket("::")))
    h.probe_result(db, "web-01", 3030, "v4", "connect_succeeded")
    html = rl.render(db, now=h.NOW)
    tab = html.split('id="t-web-01-path"', 1)[1].split('<div class="tab ', 1)[0]
    chips = re.findall(r"<label[^>]*>([^<]+)</label>", tab.split('class="walks"')[0])
    walks = dict(zip(chips, (text_of(w) for w in tab.split('<div class="walk">')[1:])))

    assert "3030/tcp v4" in walks
    assert "reaches dual [::]:3030" in walks["3030/tcp v4"]
