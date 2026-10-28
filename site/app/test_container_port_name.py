"""A container's published port, named the same on the Overview as on the
Services tab.

    Run from site/: python3 -m pytest app/test_container_port_name.py

Docker holds a host socket for a port it publishes: docker-proxy with the
userland proxy on, dockerd itself with it off (both measured on Docker 29.8.2,
docs/RECORD.md 4.246). The agent names a socket by its process or its unit and
otherwise by its owner, and since 0.1.10 it sends no process name, so the
Overview named that port "user root" while the Services tab named the
container (docs/RECORD.md 4.199, and the test fleet's tcp/3050 in 4.210).
"""
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import render_live as rl  # noqa: E402
from test_render_live import NOW, db, document, probe_result, reporting  # noqa: E402

__all__ = ["db"]


def proxy_socket(port, family):
    """The runtime's host socket as the agent sends it: no process name, the
    owning user root."""
    return {"protocol": "tcp", "family": family,
            "bind_address": "0.0.0.0" if family == "v4" else "::", "port": port,
            "process_name": "", "pid": None, "owner_name": "root", "owner_uid": 0}


def container(name, port, families=("v4", "v6")):
    return {"id": "abc123def456", "name": name, "image": "nginx:alpine",
            "ports": [{"host_ip": "0.0.0.0" if fam == "v4" else "::", "host_port": port,
                       "container_port": 80, "protocol": "tcp"} for fam in families]}


def box(db, listening, containers):
    doc = document(listening=listening)
    doc["containers"] = {"status": "collected", "docker": containers}
    reporting(db, "box", doc)


def overview_row_and_cards(db, port):
    html = rl.render(db, now=NOW)
    page = html.split('id="host-box"', 1)[1].split('<div class="wrap view"', 1)[0]
    after = page.split(f'data-port="{port}/tcp"', 1)[1]
    return after.split("</label>", 1)[0], after.split("</label>", 1)[1].split('<div class="pre">', 1)[1]


def service_of(row):
    cell = re.search(r'<span class="prs(?: note)?">(.*?)</span>', row, re.S).group(1)
    return re.sub(r"<small.*", "", cell, flags=re.S)


def card(cards, family):
    for one in cards.split('<div class="prec">')[1:]:
        if f">{family}</i>" in one.split("</div>", 1)[0]:
            return re.sub(r"<[^>]+>", "", one)
    raise AssertionError(f"no {family} card")


def services_names(db):
    html = rl.render(db, now=NOW)
    page = html.split('id="host-box"', 1)[1]
    panel = page.split('id="t-box-services"', 1)[1].split('<div class="tab', 1)[0]
    return re.findall(r'<span class="snm"><b>(.*?)</b>', panel)


def test_a_published_port_is_named_by_its_container_on_the_row(db):
    box(db, [proxy_socket(3050, "v4"), proxy_socket(3050, "v6")], [container("shop", 3050)])
    probe_result(db, "box", 3050, "v4", "connect_succeeded")
    row, _ = overview_row_and_cards(db, 3050)
    assert service_of(row) == "shop"
    assert "user root" not in row


def test_the_card_says_the_container_publishes_it(db):
    box(db, [proxy_socket(3050, "v4"), proxy_socket(3050, "v6")], [container("shop", 3050)])
    probe_result(db, "box", 3050, "v4", "connect_succeeded")
    _, cards = overview_row_and_cards(db, 3050)
    v4 = card(cards, "v4")
    assert "docker container shop publishes it on 0.0.0.0" in v4
    assert "user root" not in v4


def test_the_overview_and_the_services_tab_give_the_port_one_name(db):
    box(db, [proxy_socket(3050, "v4"), proxy_socket(3050, "v6")], [container("shop", 3050)])
    probe_result(db, "box", 3050, "v4", "connect_succeeded")
    row, _ = overview_row_and_cards(db, 3050)
    assert service_of(row) in services_names(db)
    assert "user root" not in services_names(db)


def test_with_the_proxy_off_dockerd_holds_the_socket_and_the_name_is_the_same(db):
    """Docker 29.8.2 with userland-proxy off: dockerd listens on 0.0.0.0 alone,
    and the publication is on 0.0.0.0 alone."""
    socket = dict(proxy_socket(3050, "v4"), process_name="dockerd", pid=13)
    box(db, [socket], [container("shop", 3050, families=("v4",))])
    probe_result(db, "box", 3050, "v4", "connect_succeeded")
    row, _ = overview_row_and_cards(db, 3050)
    assert service_of(row) == "shop"


def test_a_name_you_gave_the_port_still_wins(db):
    """The operator's own name sits first, as it always did for a container's
    port, with what published it beside it."""
    from test_render_live import declare_name
    box(db, [proxy_socket(3050, "v4")], [container("shop", 3050, families=("v4",))])
    declare_name(db, "box", "tcp", 3050, "webshop")
    probe_result(db, "box", 3050, "v4", "connect_succeeded")
    row, _ = overview_row_and_cards(db, 3050)
    assert service_of(row) == "webshop"
    assert "published by docker into container shop" in row


def test_a_port_with_a_socket_and_no_container_reads_as_before(db):
    box(db, [{"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 8080,
              "process_name": "app", "pid": 8080}], [container("shop", 3050)])
    probe_result(db, "box", 8080, "v4", "connect_succeeded")
    row, cards = overview_row_and_cards(db, 8080)
    assert service_of(row) == "app"
    assert "app listens on 0.0.0.0:8080" in card(cards, "v4")


# ------------------------------------- a publication with no host address
#
# The second big test, finding C10 (24 October 2026): rootful Podman, run
# with -p 8095:8095 and no address, holds the publication as HostIp "", and
# the card said "podman container wptest-c10 publishes it on" and stopped.
# With no address the line names the container and says no "on", and the
# Packet path names the port and no address either.

def podman_box(db, port=8095):
    doc = document(listening=[proxy_socket(port, "v4"), proxy_socket(port, "v6")])
    doc["containers"] = {"status": "collected", "podman": [
        {"id": "c10c10c10c10", "name": "wptest-c10", "image": "nginx:alpine",
         "ports": [{"host_ip": "", "host_port": port, "container_port": port, "protocol": "tcp"}]}]}
    reporting(db, "box", doc)
    probe_result(db, "box", port, "v4", "no_response")


def test_a_publication_with_no_host_address_says_the_container_publishes_it_and_no_on(db):
    podman_box(db)
    _, cards = overview_row_and_cards(db, 8095)
    for family in ("v4", "v6"):
        line = " ".join(card(cards, family).split())
        assert "podman container wptest-c10 publishes it" in line, line
        assert "publishes it on" not in line, line


def test_a_publication_with_an_address_still_says_where(db):
    box(db, [proxy_socket(3050, "v4"), proxy_socket(3050, "v6")], [container("shop", 3050)])
    probe_result(db, "box", 3050, "v4", "connect_succeeded")
    _, cards = overview_row_and_cards(db, 3050)
    assert "docker container shop publishes it on 0.0.0.0" in card(cards, "v4")


def test_the_packet_paths_last_gate_names_no_empty_address():
    path = {"sockets": [], "publications": [
        ("podman", {"name": "wptest-c10"}, {"host_ip": "", "host_port": 8095, "container_port": 8095})]}
    note = rl.socket_cell(path)["note"]
    assert "podman publishes port 8095 into container wptest-c10 port 8095" in note
    assert " :8095" not in note and "publishes :" not in note
    path["publications"][0][2]["host_ip"] = "0.0.0.0"
    assert "podman publishes 0.0.0.0:8095 into container wptest-c10 port 8095" in rl.socket_cell(path)["note"]
