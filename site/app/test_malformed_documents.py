"""One malformed stored document must not take the dashboard down.

The ingest validates the envelope and stores the rest verbatim as evidence
(docs/PRODUCT.md 4e), so any enrolled agent, buggy or hostile, can put a
section of any shape into the database, and the renderer draws every host of
a workspace in one process. Two things hold that up. `read_view` replaces a
section of the wrong shape with `not_readable`, and `draw_host_view` draws a
host whose page still raises as a document that could not be read, names it
on stderr with the exception's type, and goes on to the next host.

The sweep below feeds every section, every list and every field of a full
document one wrong shape at a time, with a healthy host beside it, and holds
three things: the page renders, the healthy host is intact, and the guard was
not needed, because a walk that tolerates a shape is better than a backstop
that catches it. The one test that wants the backstop injects a failure the
walk cannot anticipate.
"""
import copy
import sqlite3

import pytest

from app import render_live as rl
import theme
from test_render_live import (NOW, SCHEMA, SSHD, add_host, document, full_document,
                              host_section)


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "cp.db"
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    con.commit()
    con.close()
    return str(path)


def render_with(db, bad_doc):
    """A healthy host and a host carrying `bad_doc`, rendered together.

    Deep copies throughout: `full_document` shares its socket and container
    entries by reference, so a mutation made through one document reaches
    the other and the healthy host reads as marked by its neighbour, which
    is what the first run of this sweep reported 476 times."""
    good = copy.deepcopy(full_document())
    good["hostname"] = "healthy"
    add_host(db, "good", [(NOW, good)], last_report_at=NOW.isoformat())
    add_host(db, "bad", [(NOW, bad_doc)], last_report_at=NOW.isoformat())
    return rl.render(db, now=NOW)


def assert_healthy_host_intact(html):
    section = host_section(html, "good")
    assert "healthy" in section, "the healthy host lost its hostname"
    assert "sshd" in section, "the healthy host lost its services"
    assert "not readable" not in section, "the healthy host was marked by its neighbour"


# --------------------------------------------------------------- the backstop


def test_a_page_that_cannot_be_drawn_is_shown_as_not_readable_and_the_rest_renders(
        db, monkeypatch, capsys):
    """The guard, with a failure the walk cannot anticipate: a builder inside
    the host page raises on one host's document. That host reads as not
    readable on the fleet and on its own page, the other host is untouched,
    and stderr names the host and the exception's type."""
    bad = copy.deepcopy(full_document())
    bad["hostname"] = "bad-host"
    bad["marker"] = "explode"
    original = rl.host_port_rows

    def explode(name, doc, *args, **kwargs):
        if doc.get("marker") == "explode":
            raise RuntimeError("a shape the sweep did not anticipate")
        return original(name, doc, *args, **kwargs)

    monkeypatch.setattr(rl, "host_port_rows", explode)
    html = render_with(db, bad)
    assert_healthy_host_intact(html)

    bad_section = host_section(html, "bad")
    assert "not readable" in bad_section
    assert "bad-host" not in bad_section, "nothing from the undrawable document is shown"
    # The fleet row says the same as the page: the fail tone and the words.
    assert theme.status("fail", "not readable") in html
    err = capsys.readouterr().err
    assert "could not be drawn" in err and "RuntimeError" in err
    assert "explode" not in err, "the document's own text stays out of the journal"


def test_the_backstop_is_not_needed_for_a_healthy_fleet(db, capsys):
    render_with(db, full_document())
    assert "could not be drawn" not in capsys.readouterr().err


# ------------------------------------------------------------------ the sweep


WRONG_FOR = {
    str: ([1], 7, None),
    int: ("x", [1]),
    bool: ("x",),
    list: ("x", 7, [None], ["x"], [{}]),
    dict: ("x", 7, [None]),
    type(None): ("x", [1]),
}


def mutations():
    """Every (section, path, wrong value) the sweep tries: the section itself,
    each field in it, and each field of the first entry of each list in it."""
    base = copy.deepcopy(full_document())
    for section in sorted(k for k in base if k not in ("schema_version", "hostname",
                                                        "collected_at_unix")):
        for wrong in WRONG_FOR[dict]:
            yield section, (), wrong
        for key, value in base[section].items():
            for wrong in WRONG_FOR[type(value)]:
                yield section, (key,), wrong
            if isinstance(value, list) and value and isinstance(value[0], dict):
                for inner, inner_value in value[0].items():
                    for wrong in WRONG_FOR[type(inner_value)]:
                        yield section, (key, 0, inner), wrong
                    if isinstance(inner_value, list) and inner_value and isinstance(inner_value[0], dict):
                        for deep, deep_value in inner_value[0].items():
                            for wrong in WRONG_FOR[type(deep_value)]:
                                yield section, (key, 0, inner, 0, deep), wrong
            if isinstance(value, dict):
                for inner, inner_value in value.items():
                    for wrong in WRONG_FOR[type(inner_value)]:
                        yield section, (key, inner), wrong


def mutate(doc, section, path, wrong):
    if not path:
        doc[section] = wrong
        return
    node = doc[section]
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = wrong


CASES = list(mutations())


def case_id(case):
    section, path, wrong = case
    where = section + "".join(f"[{p!r}]" for p in path)
    return f"{where}={wrong!r}"


@pytest.mark.parametrize("case", CASES, ids=[case_id(c) for c in CASES])
def test_a_wrong_shape_anywhere_renders_the_fleet_and_never_needs_the_backstop(db, capsys, case):
    section, path, wrong = case
    bad = copy.deepcopy(full_document())
    bad["hostname"] = "bad-host"
    mutate(bad, section, path, wrong)
    html = render_with(db, bad)
    assert_healthy_host_intact(html)
    assert 'id="host-bad"' in html, "the bad host has no page at all"
    err = capsys.readouterr().err
    assert "could not be drawn" not in err, (
        f"the walk raised on {case_id(case)} and the backstop had to catch it:\n{err}")
    if not path:
        # A whole section of the wrong shape is named on the host's page, in
        # the words every other status uses, never read as an empty section.
        assert "not readable" in host_section(html, "bad")


def test_the_sweep_covers_every_section_the_page_reads():
    sections = {case[0] for case in CASES}
    for key, _label in rl.SECTION_LABELS:
        assert key in sections or key not in full_document(), key


def test_a_missing_section_is_absence_and_not_a_fault(db, capsys):
    """A section that is not there is what an older agent sends. It is not a
    fault and it is not marked; the page says the layer was not collected."""
    for key in [k for k, _ in rl.SECTION_LABELS]:
        bad = copy.deepcopy(full_document())
        bad.pop(key, None)
        bad["hostname"] = "older"
        add_host(db, f"older-{key}", [(NOW, bad)], last_report_at=NOW.isoformat())
    html = rl.render(db, now=NOW)
    assert "could not be drawn" not in capsys.readouterr().err
    assert "not readable" not in html
