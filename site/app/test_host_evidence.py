"""The Evidence tab: one row per port and family with one word per view as
a neutral tag, three cards, and the document's sections as a strip, per
docs/screens/host-evidence/SPEC.md. It shows and never decides.

    Run from site/app: python3 -m pytest test_host_evidence.py

Its own file, the way test_host_services.py is. The engine's words per
row are still covered by test_render_live.py against evidence_matrix_rows,
which this tab reads; this file covers what the screen makes of them.
"""
import functools
import html as html_mod
import http.server
import json
import pathlib
import re
import sys
import threading
from datetime import timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import build  # noqa: E402
import render_live as rl  # noqa: E402
import theme  # noqa: E402
from test_render_live import (  # noqa: E402
    JELLYFIN, LOOP, NOW, SSHD, SSHD6, add_host, db, declare_intent, declare_name, document,
    host_section, limited_doc, probe_result, refused, tab_body)
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

__all__ = ["db"]


# ------------------------------------------------------------ the fragments

def probed_cell(value):
    """The header's Probed fact as it is drawn: the turning mark, written
    always and shown only while probing (test_probing_mark.py), then the
    value."""
    import theme
    return ('<div class="k">probed</div><div class="v"><span class="pspin" title="probing">'
            + theme.icon("circle-notch", 13) + '</span>' + value + '</div>')


def row(**kw):
    base = dict(protocol="tcp", port=443, family="v4", service="caddy", agent="listening",
                prober="connect succeeded", provider="permits", state="conflict",
                row="pr-box-tcp-443")
    base.update(kw)
    return build.EvidenceRow(**base)


def test_a_row_is_the_port_the_service_three_neutral_tags_and_the_state():
    html = build.evidence_row_html("box", row())
    assert html == (
        '<div class="mr" data-row="pr-box-tcp-443" data-tab="tb-box-overview">'
        '<span class="mp"><b>443</b><small>TCP/<i class="v4">v4</i></small></span>'
        '<span class="msv">caddy</span>'
        '<span class="st nt">listening</span><span class="st nt">open</span>'
        '<span class="st nt">permitted</span>'
        '<span class="mst"><span class="st fail">conflict</span></span></div>')


def test_the_provider_column_is_always_drawn():
    """The owner, 2026-09-06, did not see the provider column at all. It is
    drawn on every page, "not connected" in every cell while no token is
    set, and the third word for a rule that permits from some addresses
    only is the engine's `permits some`."""
    assert '<span class="st nt">permitted</span>' in build.evidence_row_html("box", row())
    assert '<span class="st nt off">not connected</span>' in build.evidence_row_html(
        "box", row(provider="not connected"))
    assert '<span class="st nt">permitted from some</span>' in build.evidence_row_html(
        "box", row(provider="permits some"))
    head = build.evidence_thead_html()
    assert "The provider" in head and head.count("<span>") == 6
    assert 'class="panel mxt"' in build.evidence_table_html("box", [row()])


def test_an_absence_is_the_fainter_tag_and_a_thing_found_is_ink():
    html = build.evidence_row_html("box", row(service="", agent="nothing bound",
                                              prober="no response", provider="no rule",
                                              state="not reachable"))
    assert '<span class="msv off">&mdash;</span>' in html
    assert '<span class="st nt off">nothing bound</span>' in html
    assert '<span class="st nt">no answer</span>' in html
    assert '<span class="st off">not reachable</span>' in html
    for word in build.ABSENT_WORDS:
        assert build.evidence_tag(word) == f'<span class="st nt off">{word}</span>'
    assert build.evidence_tag("listening") == '<span class="st nt">listening</span>'


def test_the_probers_words_are_the_specs_and_the_engines_stay_in_the_data():
    assert build.OUTSIDE_SHOWN == {"connect succeeded": "open", "connect refused": "refused",
                                   "no response": "no answer", "not tested": "not tested"}
    html = build.evidence_row_html("box", row(prober="connect refused"))
    assert ">refused<" in html and "connect refused" not in html


def test_v6_is_told_apart_from_v4_before_reading():
    assert '<i class="v6">v6</i>' in build.evidence_row_html("box", row(family="v6"))
    assert ".mp small i.v6{color:var(--ink);font-weight:600}" in build.CSS
    assert ".mp small i.v4{color:var(--faint)}" in build.CSS


def test_no_state_is_an_empty_cell_and_never_a_sixth_word():
    html = build.evidence_row_html("box", row(state=""))
    assert '<span class="mst"></span>' in html
    assert "no state" not in html


def test_only_the_state_column_carries_a_tone():
    html = build.evidence_row_html("box", row())
    tags = re.findall(r'<span class="st ([^"]*)">', html)
    assert tags == ["nt", "nt", "nt", "fail"]


def test_a_rate_limited_port_keeps_its_flag_beside_the_state():
    html = build.evidence_row_html("box", row(state="intended", rate_limited=True))
    assert ('<span class="mst"><span class="st ok">intended</span>'
            '<span class="tag-rate" title="rate limited">rate limited</span></span>') in html
    assert "tag-rate" not in build.evidence_row_html("box", row())


def test_the_row_escapes_what_could_carry_document_text():
    html = build.evidence_row_html("box", row(service="<b>x</b>", agent="<i>y</i>", row="pr-<z>"))
    for raw in ("<b>x</b>", "<i>y</i>", "pr-<z>"):
        assert raw not in html
    assert "&lt;b&gt;x&lt;/b&gt;" in html


def test_the_table_is_one_panel_with_the_header_or_one_line():
    html = build.evidence_table_html("box", [row()])
    assert html.startswith('<div class="panel mxt"><div class="mxh"><span>Port</span>')
    assert ("<span>Port</span><span>Service</span><span>The agent, inside</span>"
            "<span>The prober, outside</span><span>The provider</span><span>State</span></div>") in html
    assert '<div class="mr mempty">No ports.</div>' in build.evidence_table_html("box", [])


def test_a_card_is_the_name_the_time_and_label_lines():
    html = build.view_card_html("The agent, inside", "reported 4m ago",
                                [("reads", f"{build.mono('netlink')}, no exec")])
    assert html == ('<div class="evcard"><div class="evt"><b>The agent, inside</b>'
                    '<span>reported 4m ago</span></div>'
                    '<div class="evl"><span class="evk">reads</span>'
                    '<span><b class="mono">netlink</b>, no exec</span></div></div>')
    assert build.view_card_html("The provider", "not connected", [], True) == (
        '<div class="evcard off"><div class="evt"><b>The provider</b>'
        '<span>not connected</span></div></div>')


def test_the_section_strip_is_the_same_tags_with_refused_in_amber():
    html = build.evidence_sections_html([("nftables", "", ""), ("ufw", "off", ""),
                                         ("rule file mtimes", "warn", "refused"),
                                         ("sockets", "fail", "not readable")])
    assert html.startswith('<div class="evsecs"><div class="k">what the agent read</div>')
    assert '<span class="st nt">nftables</span>' in html
    assert '<span class="st nt off">ufw</span>' in html
    assert theme.status("warn", "rule file mtimes · refused") in html
    assert theme.status("fail", "sockets · not readable") in html


def test_the_sample_tab_is_the_sample_servers_rows_and_every_row_opens_a_sample_port():
    """The rows the live page draws for the sample's one description
    (docs/RECORD.md 4.443): thirteen, one for each port and family the engine
    has a finding for. No provider is connected in that description, so the
    column says so on every row, where the hand-written rows said permitted
    beside an Overview that said not connected."""
    page = build.build_sample()
    section = page[page.index('id="host"'):]
    evidence = section.split('id="t-host-evidence"')[1].split('<div class="tab')[0]
    overview = section.split('id="t-host-overview"')[1].split('<div class="tab')[0]
    assert evidence.count('class="mr"') == 13
    for rid in re.findall(r'data-row="([^"]+)"', evidence):
        assert f'id="{rid}"' in overview, rid
    assert "The provider" in evidence and "permitted" not in evidence
    assert build.prober_from_html() in evidence
    assert build.prober_from_html() == '<span class="tag-planned">planned</span>'
    script = page[page.rindex("<script>"):]
    assert "'.hstrip [data-row],.stbl [data-row],.mxt [data-row]'" in script
    for old in ("mx-h", "ev3", 'class="tok', "how we know"):
        assert old not in page, old


# ------------------------------------------------------------- the live tab

def reporting(db, name, doc, minutes=2):
    add_host(db, name, [(NOW - timedelta(minutes=minutes), doc)],
             last_report_at=(NOW - timedelta(minutes=minutes)).isoformat())


def evidence_of(db, name="box"):
    return tab_body(host_section(rl.render(db, now=NOW), name), name, "evidence")


def rows_of(html):
    """[(port, family, service, [tags], state)] as drawn."""
    out = []
    for m in re.finditer(r'<div class="mr" data-row="[^"]+" data-tab="[^"]+">(.*?)</div>', html):
        r = m.group(1)
        port = re.search(r"<b>(\d+)</b>", r).group(1)
        fam = re.search(r'<i class="(v\d)">', r).group(1)
        svc = re.search(r'<span class="msv[^"]*">([^<]*)</span>', r).group(1)
        tags = re.findall(r'<span class="st nt[^"]*">([^<]+)</span>', r)
        state = re.search(r'<span class="mst">(?:<span class="st [^"]+">([^<]+)</span>)?', r).group(1)
        out.append((int(port), fam, svc, tags, state or ""))
    return out


def test_the_rows_are_the_overviews_order_with_v4_before_v6(db):
    web = dict(SSHD, process_name="caddy", pid=3, port=443)
    reporting(db, "box", document(listening=[SSHD, SSHD6, web, LOOP]))
    probe_result(db, "box", 443, "v4", "connect_succeeded")
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    declare_intent(db, "box", "tcp", 443, "v4", "closed")
    rows = rows_of(evidence_of(db))
    # a family with nothing on it, no socket, no probe, no rule, is no row
    assert [(p, f) for p, f, *_ in rows] == [(443, "v4"), (22, "v4"), (22, "v6"), (323, "v4")]
    assert rows[0][4] == "conflict" and rows[1][4] == "unreviewed"


def test_the_words_are_the_engines_with_the_specs_spelling_for_the_prober(db):
    reporting(db, "box", document(listening=[SSHD, dict(SSHD, port=443, pid=3), LOOP]))
    probe_result(db, "box", 22, "v4", "connect_refused")
    probe_result(db, "box", 443, "v4", "no_response")
    by = {(p, f): (svc, tags) for p, f, svc, tags, _s in rows_of(evidence_of(db))}
    assert by[(22, "v4")] == ("sshd", ["listening", "refused", "not connected"])
    assert by[(443, "v4")] == ("sshd", ["listening", "no answer", "not connected"])
    assert by[(323, "v4")] == ("chronyd", ["loopback", "not tested", "not connected"])


def test_nothing_bound_and_nothing_listening_are_told_apart(db):
    """A port with a socket on the other family is nothing bound here; a
    port nothing listens on at all, which only a rule or a declaration
    raises, is nothing listening."""
    doc = document(listening=[SSHD])
    # a rule permitting a port nothing listens on raises the port's row
    doc["nftables"] = {"status": "collected", "tables": [
        {"family": "ip", "name": "filter", "chains": [
            {"name": "ufw-user-input", "hook": "input", "priority": 0, "type": "filter",
             "rules": [{"text": "ip protocol tcp tcp dport 8096 counter accept",
                        "rendered": "full"}]}]}]}
    reporting(db, "box", doc)
    probe_result(db, "box", 22, "v6", "no_response")
    by = {(p, f): (tags, st) for p, f, _svc, tags, st in rows_of(evidence_of(db))}
    assert by[(22, "v6")][0] == ["nothing bound", "no answer", "not connected"]
    assert by[(8096, "v4")] == (["nothing listening", "not tested", "not connected"], "stale rule")


def test_the_service_is_the_declared_name_or_the_process_on_this_family(db):
    reporting(db, "box", document(listening=[SSHD, SSHD6]))
    declare_name(db, "box", "tcp", 22, "ssh for the admins")
    assert {svc for _p, _f, svc, *_ in rows_of(evidence_of(db))} == {"ssh for the admins"}


def test_the_provider_column_says_not_connected_in_every_cell_while_no_token_is_set(db):
    reporting(db, "box", document(listening=[SSHD]))
    evidence = evidence_of(db)
    matrix = evidence.split('<div class="evcs">')[0]
    assert "<span>The provider</span>" in matrix
    assert matrix.count('<span class="st nt off">not connected</span>') == 1  # one row
    # and the card says so once
    assert ('<div class="evcard off"><div class="evt"><b>The provider</b>'
            '<span>not connected</span></div></div>') in evidence


def test_every_row_opens_a_row_the_overview_has(db):
    reporting(db, "box", document(listening=[SSHD, LOOP], podman=[JELLYFIN]))
    section = host_section(rl.render(db, now=NOW), "box")
    evidence = tab_body(section, "box", "evidence")
    overview = tab_body(section, "box", "overview")
    rows = re.findall(r'data-row="([^"]+)"', evidence)
    assert rows and all(f'id="{r}"' in overview for r in rows)


def test_a_rate_limited_port_flags_its_v4_row_and_not_its_v6_row(db):
    reporting(db, "box", limited_doc([SSHD, SSHD6]))
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    evidence = evidence_of(db)
    v4 = evidence.split('<i class="v4">')[1].split("</div>")[0]
    v6 = evidence.split('<i class="v6">')[1].split("</div>")[0]
    assert "rate limited" in v4 and "rate limited" not in v6


# --------------------------------------------------------------- the cards

def cards_of(db, name="box"):
    """[(" off" or "", title, when, the card's html)] in order."""
    evidence = evidence_of(db, name)
    cards = evidence.split('<div class="evcs">')[1].split('<div class="evsecs">')[0]
    out = []
    for chunk in cards.split('<div class="evcard')[1:]:
        m = re.match(r'( off)?"><div class="evt"><b>([^<]+)</b><span>([^<]*)</span></div>', chunk)
        out.append((m.group(1) or "", m.group(2), m.group(3), chunk))
    return out


def lines_of(card_html):
    return dict(re.findall(r'<span class="evk">([^<]+)</span><span>(.*?)</span></div>', card_html))


def test_the_agent_card_is_what_the_document_says(db):
    doc = document(listening=[SSHD, SSHD6, LOOP])
    doc["agent_version"] = "0.1.8"
    # In the shape an agent sends it: ufw.conf holds ENABLED, and the policy
    # is the file's word under `defaults` (docs/RECORD.md 4.443).
    doc["ufw"] = {"status": "collected", "conf": {"ENABLED": "yes"},
                  "defaults": {"DEFAULT_INPUT_POLICY": "ACCEPT"}}
    doc["firewalld"] = {"status": "not_present"}
    reporting(db, "box", doc, minutes=4)
    off, title, when, body = cards_of(db)[0]
    assert (off, title, when) == ("", "The agent, inside", "reported 4m ago")
    lines = lines_of(body)
    assert lines["reads"] == f"{build.mono('netlink')} and {build.mono('/proc')}, no exec"
    assert lines["saw"] == f"{build.mono(2)} sockets on v4, {build.mono(1)} on v6"
    assert lines["filtering"] == f"ufw enabled, default incoming {build.mono('allow')}"
    assert lines["version"] == build.mono("0.1.8")


def test_an_agent_without_a_version_or_a_readable_sockets_section_says_so(db):
    doc = document(listening=[SSHD])
    doc["sockets"] = {"status": "permission_denied", "cause": "permission"}
    doc["firewalld"] = {"status": "not_present"}
    reporting(db, "box", doc)
    lines = lines_of(cards_of(db)[0][3])
    assert lines["saw"] == "not read"
    assert lines["version"] == "&mdash;"
    assert lines["filtering"] == "none found"


def test_the_prober_card_counts_what_it_measured_and_names_its_vantages(db):
    reporting(db, "box", document(listening=[SSHD, SSHD6, dict(SSHD, port=443, pid=3)]))
    probe_result(db, "box", 22, "v4", "connect_succeeded", vantage="probe1",
                 measured_at=NOW - timedelta(minutes=12))
    probe_result(db, "box", 443, "v4", "no_response", vantage="probe1",
                 measured_at=NOW - timedelta(minutes=12))
    probe_result(db, "box", 22, "v6", "connect_succeeded", vantage="probe1",
                 measured_at=NOW - timedelta(minutes=12))
    off, title, when, body = cards_of(db)[1]
    assert (off, title, when) == ("", "The prober, outside", "probed 12m ago")
    lines = lines_of(body)
    assert lines["reads"] == "TCP connect, no version detection"
    assert lines["tested"] == f"{build.mono(2)} ports on v4, {build.mono(1)} on v6"
    # no registry in this database, so the line names the vantage that measured
    # (test_disagree_mark.py covers the registry's own list)
    assert lines["vantages"] == build.mono("probe1")
    # the prober's own addresses are not recorded, so that line is planned
    assert lines["from"] == build.prober_from_html()


def test_a_prober_that_never_ran_says_so_and_counts_nothing(db):
    reporting(db, "box", document(listening=[SSHD]))
    off, _title, when, body = cards_of(db)[1]
    assert when == "never probed"
    lines = lines_of(body)
    assert lines["tested"] == f"{build.mono(0)} ports on v4, {build.mono(0)} on v6"
    assert lines["vantages"] == "&mdash;"


def test_the_prober_card_never_names_a_filtering_layer(db):
    """docs/PRODUCT.md 8a: the prober sees a port answer or not and never
    which layer decided."""
    reporting(db, "box", document(listening=[SSHD]))
    probe_result(db, "box", 22, "v4", "no_response")
    assert "filtering" not in cards_of(db)[1][3]


def test_the_cards_times_and_the_header_facts_are_the_same_source(db):
    reporting(db, "box", document(listening=[SSHD]), minutes=4)
    probe_result(db, "box", 22, "v4", "connect_succeeded", measured_at=NOW - timedelta(minutes=12))
    section = host_section(rl.render(db, now=NOW), "box")
    head = section.split('<div class="acts">')[0]
    assert '<div class="k">agent reported</div><div class="v"><span class="num">4m</span> ago</div>' in head
    assert probed_cell('<span class="num">12m</span> ago') in head
    cards = cards_of(db)
    assert cards[0][2] == "reported 4m ago" and cards[1][2] == "probed 12m ago"


# --------------------------------------------------------------- the strip

def chips_of(db, name="box"):
    strip = evidence_of(db, name).split('<div class="evchips">')[1]
    return re.findall(r'<span class="st ([^"]+)">([^<]+)</span>', strip)


def test_the_strip_is_every_section_the_agent_read_in_order_as_the_same_tags(db):
    """Only what was read (the owner, 2026-09-08: the ones that were not read
    go). A section the agent did not collect is left out, so
    a ufw chip on a host with no ufw never appears."""
    reporting(db, "box", document(listening=[SSHD]))
    chips = chips_of(db)
    order = [label for _key, label in rl.SECTION_LABELS]
    shown = [c[1] for c in chips]
    assert shown == [label for label in order if label in shown]
    assert ("nt", "listening sockets") in chips
    assert ("nt", "nftables") in chips
    assert not any(cls == "nt off" for cls, _label in chips), chips
    assert "ufw" not in shown


def test_a_refused_section_or_source_is_amber_and_says_so(db):
    doc = document(listening=[SSHD])
    doc["firewalld"] = refused()
    doc["sockets"]["sources"] = {"tcp": {"status": "collected"},
                                 "tcp6": {"status": "permission_denied"}}
    reporting(db, "box", doc)
    chips = dict((label, cls) for cls, label in chips_of(db))
    assert chips["firewalld · refused"] == "warn"
    assert chips["listening sockets · refused"] == "warn"


def test_an_address_host_has_the_matrix_and_the_cards_and_no_strip(db):
    import sqlite3
    from test_address_hosts_screen import add_address_host, prove, registry
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    registry().init(con)
    con.close()
    host_id = add_address_host(db, "outside-only")
    prove(db, host_id)
    probe_result(db, "outside-only", 443, "v4", "connect_succeeded")
    evidence = evidence_of(db, "outside-only")
    assert "evchips" not in evidence
    assert ('<div class="evcard off"><div class="evt"><b>The agent, inside</b>'
            '<span>no agent</span></div></div>') in evidence
    assert [tags for _p, _f, _s, tags, _st in rows_of(evidence)][0][0] == "no agent"


# ---------------------------------------------------------- in the browser

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>evidence drive</title>
<pre id="out"></pre>
<iframe id="f" width="1400" height="900"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var result={errs:[]};
    w.addEventListener('error',function(e){result.errs.push(String(e.message))});
    d.querySelector('#fleet .row[data-host="box"]').click(); await tick();
    d.getElementById('tb-box-evidence').click(); await tick();
    result.rowBefore=d.getElementById('pr-box-tcp-22').checked;
    d.querySelector('#host-box .mxt .mr[data-row="pr-box-tcp-22"]').click(); await tick();
    result.tabAfter=d.getElementById('tb-box-overview').checked;
    result.rowAfter=d.getElementById('pr-box-tcp-22').checked;
    out.textContent=JSON.stringify(result);
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
};
f.src='live.html';
</script>
"""


def test_a_row_opens_the_ports_row_on_the_overview(tmp_path, db):
    reporting(db, "box", document(listening=[SSHD, LOOP]))
    site = tmp_path / "www"
    site.mkdir()
    (site / "live.html").write_text(rl.render(db, now=NOW), encoding="utf-8")
    (site / "harness.html").write_text(HARNESS, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / 'chrome-profile'}",
             "--virtual-time-budget=8000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got, f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert result.get("errs") == [], result
    assert result["rowBefore"] is False
    assert (result["tabAfter"], result["rowAfter"]) == (True, True)
