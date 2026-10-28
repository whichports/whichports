"""The mark on a reachable port that should rarely face the internet.

A slim mark in the warn tone beside a state, never a state. It is drawn when
two things are both true: the prober measured the port reachable, and the port
is on the list in controlplane/app/rarelypublic.py, where every entry carries
the sentence from the service's own documentation (`docs/RECORD.md` 4.248).
On the Fleet the port also sits as a chip under Needs a decision while the
server's word stays what it is (`docs/RECORD.md` 4.229).

Most of this file is about when the mark must not appear: a port nobody
measured, a port measured shut, and a port that is not on the list.

    Run from site/: python3 -m pytest app/test_rarely_public_mark.py
"""
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
import theme  # noqa: E402
from test_render_live import db  # noqa: E402,F401  (the empty database fixture)

NOW = trl.NOW
MARK = build.rarely_flag(True)
WORD = "should rarely face the internet"


def sock(port, name, family="v4"):
    return {"protocol": "tcp", "family": family,
            "bind_address": "0.0.0.0" if family == "v4" else "::", "port": port,
            "process_name": name, "pid": port}


def allow(*ports):
    """An nftables table in the shape ufw writes, permitting these ports, so
    each reads `intended` with "your rule" (docs/PRODUCT.md 8d)."""
    return {"status": "collected", "tables": [
        {"family": "ip", "name": "filter", "chains": [
            {"name": "ufw-user-input", "hook": "input", "priority": 0, "type": "filter",
             "rules": [{"text": f"ip protocol tcp tcp dport {p} counter accept",
                        "rendered": "full"} for p in ports]}]}]}


def server(db, name, sockets, permitted=(), answers=(), silent=()):
    """A reporting server, its listening sockets, the ports a rule of its
    operator's permits, and what the prober measured over IPv4."""
    doc = trl.document(listening=sockets)
    if permitted:
        doc["nftables"] = allow(*permitted)
    trl.reporting(db, name, doc)
    for port in answers:
        trl.probe_result(db, name, port, "v4", "connect_succeeded")
    for port in silent:
        trl.probe_result(db, name, port, "v4", "no_response")


def port_row(html, name, port):
    section = trl.host_section(html, name)
    return section.split(f'data-port="{port}/tcp"', 1)[1].split("</label>", 1)[0]


def state_cell(html, name, port):
    return port_row(html, name, port).split('<span class="prst">', 1)[1].split("</span><span class=\"prn\"", 1)[0]


def fleet_row(html, name):
    start = html.index(f'<a class="row" href="/host/{name}"')
    return html[start:html.index("</a>", start)]


def header(html, name):
    return trl.host_section(html, name).split('<div class="acts">')[0]


def drawn(html):
    """The page without its stylesheets and its script, which name the mark's
    class whether or not a mark is drawn: the script draws it back on Restore
    (test_rarely_dismiss.py)."""
    return re.sub(r"(?s)<(style|script)\b.*?</\1>", "", html)


# ------------------------------------------------------------------- the mark

def test_the_mark_is_a_slim_box_with_its_words_as_title_and_text():
    assert MARK == f'<span class="tag-rare" title="{WORD}">{WORD}</span>'
    assert build.rarely_flag(False) == ""


def test_the_mark_is_the_warning_glyph_in_the_warn_tone_and_shows_no_word():
    assert build.MARK_ICONS[".tag-rare"] == "warning"
    assert "warning" in theme.ICONS
    rule = re.search(r"(?m)^\.tag-rare\{[^}]*\}", build.CSS).group(0)
    assert "color:var(--warn)" in rule and "border:1px solid var(--warn)" in rule
    assert "--fail" not in rule and "--ok" not in rule
    # the shared slim rule pushes the words out of the box, so only the glyph shows
    shared = re.search(r"\.tag-alert,\.tag-mute,\.tag-rate,\.tag-rare\{[^}]*\}", build.CSS).group(0)
    assert "text-indent:200%" in shared and "overflow:hidden" in shared
    assert ".tag-rare::before" in build.CSS


def test_the_words_are_the_whole_of_what_the_screen_says():
    """No sentence that explains, and no service named: what runs on the port
    was not measured (the list is keyed on the port number)."""
    assert build.RARELY_WORD == WORD
    for said in ("Redis", "because", "documentation", "exposed", "unsafe", "risk"):
        assert said.lower() not in build.RARELY_WORD.lower()


# ---------------------------------------------------------------- when it shows

def test_a_reachable_port_on_the_list_carries_the_mark_beside_its_state(db):
    server(db, "box", [sock(22, "sshd"), sock(6379, "redis-server")], answers=(22, 6379))
    html = rl.render(db, now=NOW)
    cell = state_cell(html, "box", 6379)
    assert cell == theme.status("warn", "unreviewed") + MARK
    assert MARK not in port_row(html, "box", 22)


def test_the_mark_stays_when_a_rule_of_the_operators_allows_the_port(db):
    """Flagged either way (docs/RECORD.md 4.221): the port reads `intended`,
    by the operator's own rule, and the mark sits beside that word."""
    server(db, "box", [sock(22, "sshd"), sock(6379, "redis-server")],
           permitted=(22, 6379), answers=(22, 6379))
    html = rl.render(db, now=NOW)
    assert state_cell(html, "box", 6379) == theme.status("ok", "intended") + MARK
    assert '<span class="prw">your rule</span>' in port_row(html, "box", 6379)
    assert state_cell(html, "box", 22) == theme.status("ok", "intended")


def test_the_mark_changes_no_state_word(db):
    """Never a state: the same server reads the same words with and without
    a listed port among its ports."""
    server(db, "listed", [sock(6379, "redis-server")], permitted=(6379,), answers=(6379,))
    server(db, "other", [sock(8080, "caddy")], permitted=(8080,), answers=(8080,))
    html = rl.render(db, now=NOW)
    assert theme.status("ok", "intended") in state_cell(html, "listed", 6379)
    assert theme.status("ok", "intended") in state_cell(html, "other", 8080)
    word = re.search(r'data-state="([^"]*)"', fleet_row(html, "listed")).group(1)
    assert word == re.search(r'data-state="([^"]*)"', fleet_row(html, "other")).group(1)


# ---------------------------------------------------------- when it must not

def test_a_listed_port_nobody_probed_carries_no_mark(db):
    """Not tested is not reachable (docs/PRODUCT.md 4b)."""
    server(db, "box", [sock(6379, "redis-server")])
    html = rl.render(db, now=NOW)
    assert "tag-rare" not in trl.host_section(html, "box")
    assert "tag-rare" not in fleet_row(html, "box")


def test_a_listed_port_measured_shut_carries_no_mark(db):
    server(db, "box", [sock(22, "sshd"), sock(6379, "redis-server")],
           answers=(22,), silent=(6379,))
    html = rl.render(db, now=NOW)
    assert "tag-rare" not in trl.host_section(html, "box")
    assert "tag-rare" not in fleet_row(html, "box")
    assert "tcp/6379" not in fleet_row(html, "box")


def test_a_listed_port_that_refused_carries_no_mark(db):
    server(db, "box", [sock(6379, "redis-server")])
    trl.probe_result(db, "box", 6379, "v4", "connect_refused")
    assert "tag-rare" not in drawn(rl.render(db, now=NOW))


def test_a_reachable_port_that_is_not_on_the_list_carries_no_mark(db):
    """PostgreSQL's port was left off the list, because its own documentation
    never says it should not face the internet (docs/RECORD.md 4.248)."""
    server(db, "box", [sock(5432, "postgres"), sock(2376, "dockerd"), sock(443, "caddy")],
           answers=(5432, 2376, 443))
    html = rl.render(db, now=NOW)
    assert "tag-rare" not in drawn(html)


def test_a_server_with_no_ports_at_all_draws_no_mark(db):
    trl.add_host(db, "new", [])
    html = rl.render(db, now=NOW)
    assert "tag-rare" not in drawn(html)


def test_a_document_that_will_not_read_draws_no_mark(db):
    trl.add_raw_report(db, "broken", "not a document")
    html = rl.render(db, now=NOW)
    assert "not readable" in fleet_row(html, "broken")
    assert "tag-rare" not in drawn(html)


# ------------------------------------------------------------------ the Fleet

def test_on_the_fleet_the_port_is_a_chip_and_the_rows_word_stays(db):
    """docs/RECORD.md 4.229: under Needs a decision as a chip, while the
    server's row reads what it read. And the mark sits beside that word."""
    server(db, "sessions", [sock(22, "sshd"), sock(6379, "redis-server")],
           permitted=(22, 6379), answers=(22, 6379))
    server(db, "plain", [sock(22, "sshd")], permitted=(22,), answers=(22,))
    html = rl.render(db, now=NOW)
    listed, plain = fleet_row(html, "sessions"), fleet_row(html, "plain")
    word = re.search(r'data-state="([^"]*)"', plain).group(1)
    assert f'data-state="{word}"' in listed, "the mark changed the server's word"
    assert listed.split('<div class="fsrv">')[0].endswith(MARK + "</div>")
    assert '<div class="fchips"><span class="fpc warn">tcp/6379</span>' in listed
    assert "tag-rare" not in plain and '<div class="fchips"></div>' in plain


def test_a_port_that_is_already_a_chip_for_its_state_is_not_drawn_twice(db):
    server(db, "box", [sock(6379, "redis-server")], answers=(6379,))
    row = fleet_row(rl.render(db, now=NOW), "box")
    assert row.count(">tcp/6379<") == 1
    assert MARK in row


def test_the_chip_names_the_family_when_only_one_of_two_answered(db):
    doc = trl.document(listening=[sock(6379, "redis-server"), sock(6379, "redis-server", "v6")])
    doc["nftables"] = allow(6379)
    trl.reporting(db, "box", doc)
    trl.probe_result(db, "box", 6379, "v4", "connect_succeeded")
    trl.probe_result(db, "box", 6379, "v6", "no_response")
    row = fleet_row(rl.render(db, now=NOW), "box")
    assert '<span class="fpc warn">tcp/6379 v4</span>' in row


def test_the_chip_counts_in_the_needs_a_decision_box_and_leaves_the_rest(db):
    """The boxes are sums of what the rows show, so the box and the table
    cannot disagree (docs/screens/fleet/SPEC.md section 3)."""
    server(db, "box", [sock(22, "sshd"), sock(6379, "redis-server")],
           permitted=(22, 6379), answers=(22, 6379))
    doc = trl.document(listening=[sock(22, "sshd"), sock(6379, "redis-server")])
    doc["nftables"] = allow(22, 6379)
    findings = rl.load(db, now=NOW)[5]["box"]
    reach, chips = rl.fleet_facts(doc, findings)
    assert reach == (2, 2)
    assert chips == (("tcp/6379", "warn"),)
    totals = build.fleet_totals([build.FleetRow("ok", "watched", "box", reach=reach,
                                                chips=chips)])
    assert totals["decision"] == 1 and totals["conflict"] == 0


def test_a_conflict_still_comes_first_among_the_chips(db):
    server(db, "box", [sock(443, "caddy"), sock(6379, "redis-server")],
           permitted=(6379,), answers=(443, 6379))
    trl.declare_intent(db, "box", "tcp", 443, "v4", "closed")
    row = fleet_row(rl.render(db, now=NOW), "box")
    chips = re.findall(r'<span class="fpc (\w+)">([^<]*)</span>', row)
    assert chips == [("fail", "tcp/443"), ("warn", "tcp/6379")]


# --------------------------------------- the Fleet and the page count alike

def fleet_decisions(html, name):
    """How many ports the Fleet puts under Needs a decision for one server:
    its chips that are not a conflict, which has a box of its own."""
    row = fleet_row(html, name)
    return len(re.findall(r'<span class="fpc (?!fail)\w+">', row))


def page_decisions(html, name):
    """The number in the Needs a decision box on the server's own page."""
    strip = trl.host_section(html, name).split('<div class="hstrip">', 1)[1]
    found = re.search(r'<div class="l">Needs a decision</div><div class="n[^"]*">(\d+)</div>', strip)
    return int(found.group(1))


def test_for_any_server_the_fleet_and_its_own_page_count_the_same_ports(db):
    """One number, said in two places (docs/RECORD.md 4.258): the page's box
    counts the set the Fleet counts."""
    # a listed port its operator's rule allows
    server(db, "allowed", [sock(22, "sshd"), sock(6379, "redis-server")],
           permitted=(22, 6379), answers=(22, 6379))
    # a listed port no rule allows: one chip, counted once and not twice
    server(db, "norule", [sock(22, "sshd"), sock(3306, "mariadbd")],
           permitted=(22,), answers=(22, 3306))
    # an ordinary unreviewed port beside an allowed listed one
    server(db, "both", [sock(8080, "caddy"), sock(6379, "redis-server")],
           permitted=(6379,), answers=(8080, 6379))
    # a listed port declared closed and still answering: a conflict, counted by neither
    server(db, "said-no", [sock(22, "sshd"), sock(6379, "redis-server")],
           permitted=(22, 6379), answers=(22, 6379))
    trl.declare_intent(db, "said-no", "tcp", 6379, "v4", "closed")
    # a listed port measured shut, and a server with nothing listed
    server(db, "shut", [sock(22, "sshd"), sock(6379, "redis-server")],
           permitted=(22,), answers=(22,), silent=(6379,))
    server(db, "plain", [sock(22, "sshd")], permitted=(22,), answers=(22,))
    # a server watched from outside only
    trl.add_address_host_row(db, "outside")
    trl.probe_result(db, "outside", 3306, "v4", "connect_succeeded")
    html = rl.render(db, now=NOW)
    expected = {"allowed": 1, "norule": 1, "both": 2, "said-no": 0, "shut": 0,
                "plain": 0, "outside": 1}
    for name, count in expected.items():
        assert fleet_decisions(html, name) == count, (name, "the Fleet")
        assert page_decisions(html, name) == count, (name, "the server's page")


def test_the_pages_box_opens_on_the_listed_port_when_it_is_the_first_it_counts(db):
    server(db, "box", [sock(22, "sshd"), sock(6379, "redis-server")],
           permitted=(22, 6379), answers=(22, 6379))
    strip = trl.host_section(rl.render(db, now=NOW), "box").split('<div class="hstrip">', 1)[1]
    box = strip.split("Needs a decision", 1)[0].rsplit("<div", 2)[1]
    assert 'data-row="pr-box-tcp-6379"' in box


def test_the_answers_on_a_listed_port_the_rule_allows_stay_as_they_were(db):
    """Counting it changes no answer: the row keeps its lit Yes and the other
    two stay behind the opened row."""
    server(db, "box", [sock(6379, "redis-server")], permitted=(6379,), answers=(6379,))
    row = port_row(rl.render(db, now=NOW), "box", 6379)
    assert '<span class="pra settled"' in row
    assert re.search(r'class="ans yes pick', row)


# ----------------------------------------------------- the header and the rest

def test_the_servers_header_carries_the_mark_its_fleet_row_carries(db):
    server(db, "box", [sock(6379, "redis-server")], permitted=(6379,), answers=(6379,))
    server(db, "plain", [sock(22, "sshd")], permitted=(22,), answers=(22,))
    html = rl.render(db, now=NOW)
    assert MARK in header(html, "box")
    assert "tag-rare" not in header(html, "plain")


def test_an_address_only_server_carries_the_mark_on_the_port_number_alone(db):
    """Nothing on the server is read, and nothing needs to be: the list is
    keyed on the port, and the prober measured it."""
    trl.add_address_host_row(db, "outside")
    trl.probe_result(db, "outside", 3306, "v4", "connect_succeeded")
    html = rl.render(db, now=NOW)
    assert MARK in port_row(html, "outside", 3306)
    assert MARK in fleet_row(html, "outside")


def test_every_port_on_the_list_is_marked_when_it_answers(db):
    listed = joinbridge_list()
    sockets = [sock(e.port, "x") for e in listed.ENTRIES]
    server(db, "box", sockets, answers=tuple(e.port for e in listed.ENTRIES))
    html = rl.render(db, now=NOW)
    for e in listed.ENTRIES:
        assert MARK in port_row(html, "box", e.port), e.port


def joinbridge_list():
    return rl.joinbridge.module("rarelypublic")


def test_the_reachable_listed_ports_are_read_from_the_list_and_the_measurement(db):
    server(db, "box", [sock(22, "sshd"), sock(6379, "redis-server"), sock(3306, "mariadbd")],
           answers=(22, 6379), silent=(3306,))
    findings = rl.load(db, now=NOW)[5]["box"]
    assert rl.rarely_reachable(findings) == {"tcp/6379": ["v4"]}
    assert rl.rarely_reachable(()) == {}
