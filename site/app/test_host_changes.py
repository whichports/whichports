"""The Changes tab: a log of the server, not of the dashboard, per
docs/screens/host-changes/SPEC.md (provisional). One table, newest first,
when, the layer that changed, the kind as a neutral tag, the port, and the
thing itself in the layer's own words. Only what the three views observed.

    Run from site/app: python3 -m pytest test_host_changes.py

Its own file, the way test_host_evidence.py is. The document diff and the
window are still covered in test_render_live.py; this file covers the
lines the screen makes of them, the range control, and the browser half.
"""
import functools
import html as html_mod
import http.server
import json
import pathlib
import re
import sys
import threading
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import build  # noqa: E402
import render_live as rl  # noqa: E402
from test_render_live import (  # noqa: E402
    JELLYFIN, LOOP, NOW, SSHD, SSHD6, add_host, db, document, host_section, tab_body, transition)
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

__all__ = ["db"]

WHEN = datetime(2026, 9, 4, 9, 14, tzinfo=timezone.utc)
LATER = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)


# ------------------------------------------------------------ the fragments

def change(**kw):
    base = dict(when=WHEN, layer="from outside", source="prober", kind="reachable",
                protocol="tcp", port=8410, families=("v4",),
                detail="connect succeeded from probe1")
    base.update(kw)
    return build.Change(**base)


def test_a_line_is_when_layer_kind_port_and_the_thing_itself():
    html = build.change_row_html(change(), LATER)
    assert html == (
        '<div class="cr" data-r="1"><span class="cwhen"><b>4 Sep</b> 09:14</span>'
        '<span class="clay">from outside<small>prober</small></span>'
        '<span class="ckind"><span class="st nt">reachable</span></span>'
        '<span class="cpn">8410<small>TCP/<i class="v4">v4</i></small></span>'
        '<span class="cdet">connect succeeded from probe1</span></div>')


def test_something_that_went_away_is_the_fainter_tag():
    html = build.change_row_html(change(kind="unreachable", off=True), LATER)
    assert '<span class="ckind off"><span class="st nt">unreachable</span></span>' in html
    assert ".ckind.off .st.nt{color:var(--faint);border-color:var(--line)}" in build.CSS


def test_both_families_read_v4_plus_v6_and_no_port_is_an_empty_cell():
    both = build.change_row_html(change(families=("v4", "v6")), LATER)
    assert '<small>TCP/<i class="v4">v4</i>+<i class="v6">v6</i></small>' in both
    none = build.change_row_html(change(protocol="", port="", families=()), LATER)
    assert '<span class="cpn"></span>' in none


def test_a_line_older_than_a_day_falls_in_the_week_range():
    assert 'data-r="7"' in build.change_row_html(change(), LATER + timedelta(days=2))
    assert 'data-r="1"' in build.change_row_html(change(), LATER)




def test_the_line_escapes_what_could_carry_document_text():
    html = build.change_row_html(change(layer="<b>x</b>", detail="<i>y</i>", protocol="<u>",
                                        port="<s>"), LATER)
    for raw in ("<b>x</b>", "<i>y</i>", "<u>", "<s>"):
        assert raw not in html


def test_the_count_line_picks_its_words_by_range_and_number():
    html = build.changes_count_html(1, 11)
    assert '<span class="c1"><b>1</b> change in the last 24 hours</span>' in html
    assert '<span class="c7"><b>11</b> changes in the last 7 days</span>' in html
    assert "<b>3</b> changes since 12 Aug 08:30</span>" in build.changes_count_html(0, 3, "12 Aug 08:30")


def test_the_range_control_is_two_radios_and_two_planned_pills():
    radios, pills = build.range_control_html("box")
    assert radios == ('<input type="radio" class="rgsel r1" name="rg-box" id="rg-box-24h">'
                      '<input type="radio" class="rgsel r7" name="rg-box" id="rg-box-7d" checked>')
    assert '<label class="rgl r1" for="rg-box-24h">24h</label>' in pills
    assert '<label class="rgl r7" for="rg-box-7d">7d</label>' in pills
    assert pills.count('class="rgl off"') == 2
    assert pills.count('<span class="tag-planned">planned</span>') == 2
    # the stylesheet does the switching, no script
    assert '.rgsel.r1:checked~.ctbl .cr[data-r="7"]{display:none}' in build.CSS
    assert ".rgsel.r1:checked~.ctop .c7,.rgsel.r7:checked~.ctop .c1{display:none}" in build.CSS


def test_the_table_is_the_radios_the_count_line_the_pills_and_the_rows():
    html = build.changes_table_html("box", [change(), change(when=WHEN - timedelta(days=3))], LATER)
    assert html.startswith('<input type="radio" class="rgsel r1"')
    assert '<div class="ctop"><span class="cnt">' in html
    assert "<b>1</b> change in the last 24 hours" in html
    assert "<b>2</b> changes in the last 7 days" in html
    assert html.count('class="cr"') == 2
    assert '<div class="panel ctbl"><div class="ch"><span>When · UTC</span>' in html
    assert ("<span>When · UTC</span><span>Layer</span><span>Change</span>"
            "<span>Port</span><span>Detail</span></div>") in html


def test_an_empty_log_is_one_line_and_a_cap_keeps_the_count():
    html = build.changes_table_html("box", [], LATER)
    assert f'<div class="cr cempty">{build.NO_CHANGES}</div>' in html
    capped = build.changes_table_html("box", [change(), change(), change()], LATER, shown=1)
    assert capped.count('class="cr"') == 1 and "<b>3</b> changes" in capped


def test_the_sample_page_carries_the_tab_and_the_old_list_is_gone():
    page = build.build_sample()
    for old in ("chg-d", "changes_html", "No transitions recorded"):
        assert old not in page, old
    assert not hasattr(build, "HISTORY") and not hasattr(rl, "transition_rows")


# ------------------------------------------------------------- the live tab

def reporting(db, name, docs):
    """`docs` is [(minutes ago, document)], newest first."""
    add_host(db, name, [(NOW - timedelta(minutes=m), d) for m, d in docs],
             last_report_at=(NOW - timedelta(minutes=docs[0][0])).isoformat())


def changes_of(db, name="box"):
    return tab_body(host_section(rl.render(db, now=NOW), name), name, "changes")


def lines_of(html):
    """[(when, layer, kind, port, detail)] as drawn, newest first."""
    out = []
    for m in re.finditer(r'<div class="cr" data-r="\d"><span class="cwhen"><b>([^<]+)</b> ([^<]+)</span>'
                         r'<span class="clay">([^<]+)<small>[^<]*</small></span>'
                         r'<span class="ckind[^"]*">(?:<span class="unsure"[^>]*>)?<span class="st nt">([^<]+)</span>'
                         r'(?:</span>)?</span><span class="cpn">(.*?)</span><span class="cdet">([^<]*)</span>', html):
        day, clock, layer, kind, port, detail = m.groups()
        out.append((f"{day} {clock}", layer, kind, re.sub(r"<[^>]+>", "", port), detail))
    return out


def test_a_measured_transition_is_a_line_and_an_answer_is_not(db):
    reporting(db, "box", [(2, document(listening=[SSHD]))])
    transition(db, "box", "tcp", 5432, "v4", "not reachable", "unreviewed", "raised",
               seen_at=NOW - timedelta(hours=2))
    # the same port moved by a declaration: the outside view stayed
    transition(db, "box", "tcp", 5432, "v4", "unreviewed", "intended", "noted",
               seen_at=NOW - timedelta(hours=1))
    lines = lines_of(changes_of(db))
    assert lines == [((NOW - timedelta(hours=2)).strftime("%-d %b %H:%M"), "from outside",
                      "reachable", "5432TCP/v4", "connect succeeded from probe1")]


def test_both_families_measured_in_one_sweep_are_one_line(db):
    reporting(db, "box", [(2, document(listening=[SSHD, SSHD6]))])
    when = NOW - timedelta(hours=2)
    transition(db, "box", "tcp", 22, "v4", "", "unreviewed", "raised", seen_at=when)
    transition(db, "box", "tcp", 22, "v6", "", "unreviewed", "raised", seen_at=when)
    lines = lines_of(changes_of(db))
    assert [(k, p) for _w, _l, k, p, _d in lines] == [("reachable", "22TCP/v4+v6")]


def test_the_agents_lines_come_from_the_document_diff_in_its_own_words(db):
    older = document(listening=[SSHD, LOOP], nft_rules=2)
    newer = document(listening=[SSHD], podman=[JELLYFIN], nft_rules=3,
                     rule_files=[{"path": "/etc/ufw/user.rules", "mtime_unix": 200}])
    older["rule_files"] = {"status": "collected",
                           "files": [{"path": "/etc/ufw/user.rules", "mtime_unix": 100}]}
    reporting(db, "box", [(2, newer), (17, older)])
    lines = lines_of(changes_of(db))
    by_kind = {(layer, kind): (port, detail) for _w, layer, kind, port, detail in lines}
    assert by_kind[("process", "stopped")] == ("323UDP/v4", "chronyd on 127.0.0.1:323")
    assert by_kind[("container", "published")] == ("8096TCP", "podman jellyfin, host port 8096 on 0.0.0.0")
    assert by_kind[("host firewall", "file changed")] == ("", "/etc/ufw/user.rules")
    assert by_kind[("host firewall", "rule added")] == ("", "nftables inet firewalld: 2 to 3 rules")
    # every line is stamped with the newer document's time
    assert all(w == (NOW - timedelta(minutes=2)).strftime("%-d %b %H:%M") for w, *_ in lines)


def test_the_log_is_newest_first_across_both_sources(db):
    reporting(db, "box", [(2, document(listening=[SSHD, LOOP])), (17, document(listening=[SSHD]))])
    transition(db, "box", "tcp", 22, "v4", "", "unreviewed", "raised",
               seen_at=NOW - timedelta(minutes=10))
    kinds = [k for _w, _l, k, _p, _d in lines_of(changes_of(db))]
    assert kinds == ["started", "reachable"]


def test_the_count_is_the_lines_in_the_range(db):
    reporting(db, "box", [(2, document(listening=[SSHD, LOOP])), (17, document(listening=[SSHD]))])
    transition(db, "box", "tcp", 22, "v4", "", "unreviewed", "raised",
               seen_at=NOW - timedelta(days=3))
    html = changes_of(db)
    assert "<b>1</b> change in the last 24 hours" in html
    assert "<b>2</b> changes in the last 7 days" in html
    assert 'data-r="1"' in html and 'data-r="7"' in html


def test_an_address_host_has_the_probers_lines_only(db):
    import sqlite3
    from test_address_hosts_screen import add_address_host, prove, registry
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    registry().init(con)
    con.close()
    host_id = add_address_host(db, "outside-only")
    prove(db, host_id)
    transition(db, "outside-only", "tcp", 443, "v4", "", "unreviewed", "raised",
               seen_at=NOW - timedelta(hours=1))
    lines = lines_of(changes_of(db, "outside-only"))
    assert [(l, k) for _w, l, k, _p, _d in lines] == [("from outside", "reachable")]


# ---------------------------------------------------------- in the browser

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>changes drive</title>
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
    d.getElementById('tb-box-changes').click(); await tick();
    var shown=function(){return Array.prototype.filter.call(
      d.querySelectorAll('#host-box .ctbl .cr'),function(r){return w.getComputedStyle(r).display!=='none'}).length};
    var count=function(){return Array.prototype.filter.call(
      d.querySelectorAll('#host-box .cnt > span'),function(s){return w.getComputedStyle(s).display!=='none'})
      .map(function(s){return s.textContent})};
    result.week={rows:shown(),count:count()};
    d.querySelector('#host-box label[for="rg-box-24h"]').click(); await tick();
    result.day={rows:shown(),count:count()};
    out.textContent=JSON.stringify(result);
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
};
f.src='live.html';
</script>
"""


def test_the_range_pills_switch_the_rows_and_the_count(tmp_path, db):
    reporting(db, "box", [(2, document(listening=[SSHD, LOOP])), (17, document(listening=[SSHD]))])
    transition(db, "box", "tcp", 22, "v4", "", "unreviewed", "raised",
               seen_at=NOW - timedelta(days=3))
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
    assert result["week"] == {"rows": 2, "count": ["2 changes in the last 7 days"]}
    assert result["day"] == {"rows": 1, "count": ["1 change in the last 24 hours"]}


def test_a_container_port_with_no_host_address_is_said_without_an_on(db):
    """Rootful Podman run with -p and no address holds the publication with
    an empty host address. The line read "podman wptest-c10, host port 8095
    on" and stopped there (second big test, 26 October, F7). With no address
    it names the port and nothing after it, as the card does since 25
    October."""
    no_address = {"id": "c10c10c10c10", "name": "wptest-c10", "image": "nginx:alpine",
                  "ports": [{"host_ip": "", "host_port": 8095, "container_port": 8095,
                             "protocol": "tcp"}]}
    reporting(db, "box", [(2, document(listening=[SSHD], podman=[no_address])),
                          (17, document(listening=[SSHD]))])
    by_kind = {(layer, kind): (port, detail)
               for _w, layer, kind, port, detail in lines_of(changes_of(db))}
    assert by_kind[("container", "published")] == ("8095TCP", "podman wptest-c10, host port 8095")
    reporting(db, "box2", [(2, document(listening=[SSHD])),
                           (17, document(listening=[SSHD], podman=[no_address]))])
    by_kind = {(layer, kind): (port, detail)
               for _w, layer, kind, port, detail in lines_of(changes_of(db, "box2"))}
    assert by_kind[("container", "unpublished")] == ("8095TCP", "podman wptest-c10, host port 8095")


def test_a_started_socket_is_named_by_its_unit_when_no_process_was_read(db):
    """The agent's own user reads no process name, and the kernel names the
    unit a socket belongs to (docs/RECORD.md 4.169). Every process line read
    "an unnamed process on 127.0.0.1:3306" where the Services tab named
    mariadb (second big test, 26 October, F7). A line names the socket by
    its process, else its unit as the kernel named it, the way the alerts do
    (controlplane/app/join.py, Socket.name)."""
    mariadb = {"protocol": "tcp", "family": "v4", "bind_address": "127.0.0.1", "port": 3306,
               "unit": "mariadb.service", "owner_uid": 104}
    nobody = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 9601}
    reporting(db, "box", [(2, document(listening=[SSHD, mariadb, nobody])),
                          (17, document(listening=[SSHD]))])
    started = sorted(detail for _w, layer, kind, _p, detail in lines_of(changes_of(db))
                     if (layer, kind) == ("process", "started"))
    assert started == ["an unnamed process on 0.0.0.0:9601",
                       "mariadb.service on 127.0.0.1:3306"]
