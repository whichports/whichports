"""A sockets section that was not read draws no socket and no absence.

    Run from site/: python3 -m pytest app/test_sockets_not_read.py

The page marks a section it cannot read `not_readable`, and nothing derived
from it is counted, diffed or drawn (docs/PRODUCT.md 4e). A section the
agent itself says it did not read is the same fact from the other side
(docs/RECORD.md 4.17). On 2026-10-26 a report whose first socket carried a
number for its owner's name was marked not readable on the Evidence strip,
and still the Overview's rows read "nothing listening" while their cards
said a program listens on 0.0.0.0:22, and the Evidence matrix read
"listening" and named every program. The engine reads the stored document
with its own checks, so the sockets reached the findings the cards and the
matrix draw. Both views now say the sockets were not read, in the words the
page has for it: "sockets not read" on the Overview, "not read" in the
matrix.
"""
import copy
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
from test_host_evidence import rows_of  # noqa: E402
from test_render_live import (  # noqa: E402
    NOW, SSHD, JELLYFIN, db, document, host_section, probe_result, reporting, tab_body)

__all__ = ["db"]

SSH = dict(SSHD, owner_name="root", owner_uid=0)
WEB = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 5000,
       "process_name": "gunicorn", "pid": 9, "owner_name": "app", "owner_uid": 1000}


def sockets():
    """Fresh copies each time, because a test below changes one in place."""
    return copy.deepcopy([SSH, WEB])


def owner_name_a_number():
    """The 26 October shape: one value of the wrong type, so the page
    marks the section not readable, and the engine still reads each socket."""
    doc = document(listening=sockets())
    doc["sockets"]["listening"][0]["owner_name"] = 0
    return doc


def agent_refused():
    doc = document(listening=sockets())
    doc["sockets"] = {"status": "permission_denied", "cause": "permission"}
    return doc


def agent_read_error():
    """A read the agent says failed, with entries in it all the same."""
    doc = document(listening=sockets())
    doc["sockets"]["status"] = "read_error"
    return doc


NOT_READ = [pytest.param(owner_name_a_number, id="not readable"),
            pytest.param(agent_refused, id="permission denied"),
            pytest.param(agent_read_error, id="read error")]


def page(db, doc):  # noqa: F811
    reporting(db, "box", doc)
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    return host_section(rl.render(db, now=NOW), "box")


def overview_rows(section):
    """{port: (the Service cell, the opened row's text)} as drawn."""
    overview = tab_body(section, "box", "overview")
    out = {}
    for m in re.finditer(r'data-port="(\d+)/tcp">(.*?)</label><div class="pre">(.*?)</div></div></div>',
                         overview, re.S):
        service = re.search(r'<span class="prs(?: note)?">(.*?)</span>', m.group(2)).group(1)
        opened = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", m.group(3)))
        out[int(m.group(1))] = (service, opened)
    return out


def agent_lines(opened):
    return re.findall(r"agent (.*?) prober", opened)


# ------------------------------------------------------------ the edges first

@pytest.mark.parametrize("make", NOT_READ)
def test_no_row_says_nothing_listening_and_no_card_names_a_socket(db, make):  # noqa: F811
    rows = overview_rows(page(db, make()))
    assert 22 in rows
    for port, (service, opened) in rows.items():
        assert service == rl.SOCKETS_NOT_READ, (port, service)
        assert "nothing listening" not in service
        assert "listens on" not in opened, (port, opened)
        assert "nothing is bound" not in opened and "nothing bound" not in opened, (port, opened)
        assert "nothing on the host owns it" not in opened, (port, opened)
        assert agent_lines(opened) == [rl.SOCKETS_NOT_READ] * 2, (port, opened)


@pytest.mark.parametrize("make", NOT_READ)
def test_the_matrix_says_not_read_and_names_no_program(db, make):  # noqa: F811
    evidence = tab_body(page(db, make()), "box", "evidence")
    rows = rows_of(evidence)
    assert rows
    for port, family, service, tags, _state in rows:
        assert tags[0] == "not read", (port, family, tags)
        assert service == "&mdash;", (port, family, service)
    for name in ("sshd", "gunicorn", "root"):
        assert f'<span class="msv">{name}</span>' not in evidence


def test_the_unreadable_section_is_still_marked_on_the_strip(db):  # noqa: F811
    """The mark the page already drew stays, and now nothing beside it
    contradicts it."""
    evidence = tab_body(page(db, owner_name_a_number()), "box", "evidence")
    assert "listening sockets · not readable" in evidence


def test_a_container_port_is_still_named_by_its_container(db):  # noqa: F811
    """The containers section is its own section and was read, so what it
    says of a published port still stands when the sockets were not read."""
    doc = document(listening=sockets()[:1], podman=copy.deepcopy([JELLYFIN]))
    doc["sockets"]["listening"][0]["owner_name"] = 0
    rows = overview_rows(page(db, doc))
    service, opened = rows[8096]
    assert service == "jellyfin"
    assert "container jellyfin" in opened
    assert rows[22][0] == rl.SOCKETS_NOT_READ


# ------------------------------------------------------------ and as it was

def test_a_readable_section_still_names_its_sockets_on_both_views(db):  # noqa: F811
    section = page(db, document(listening=sockets()))
    rows = overview_rows(section)
    assert rows[22][0] == "sshd"
    assert "sshd listens on 0.0.0.0:22" in rows[22][1]
    assert rows[5000][0] == "gunicorn"
    matrix = {(p, f): (svc, tags) for p, f, svc, tags, _st in
              rows_of(tab_body(section, "box", "evidence"))}
    assert matrix[(22, "v4")] == ("sshd", ["listening", "open", "not connected"])
    assert matrix[(5000, "v4")][1][0] == "listening"


def test_the_predicate_reads_the_section_and_nothing_else():
    assert rl.sockets_not_read({"sockets": {"status": rl.NOT_READABLE}})
    assert rl.sockets_not_read({"sockets": {"status": "permission_denied"}})
    assert not rl.sockets_not_read({"sockets": {"status": "collected", "listening": []}})
    # No document, or one with no sockets section, is not this fact: an
    # address host has nothing to read and says "no agent" instead.
    assert not rl.sockets_not_read({})
    assert not rl.sockets_not_read(None)
    assert not rl.sockets_not_read({"hostname": "box"})
