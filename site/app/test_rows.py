"""One row shape, one builder, on both feeds and in the page script.

The `.ch2` row is what every settings row, evidence row, rule-file row and
channel row is. Until 2026-09-03 it was written by hand in eleven places and
once more in JavaScript, for a port declared on the page. Now
`build.three_cell_row` is the one definition, and the script clones the
empty row the builder draws rather than writing one.
"""
import pathlib
import re
import sqlite3
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
from test_render_live import NOW, SCHEMA, add_host, declare_intent, document  # noqa: E402


def test_no_row_is_written_by_hand_in_either_renderer():
    for module, allowed in ((build, 1), (rl, 0)):
        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        assert source.count('class="ch2"') == allowed, module.__name__


def test_the_row_builder_writes_the_three_cells_as_they_were():
    assert build.three_cell_row("a", "b", "c") == \
        '<div class="ch2"><div>a</div><div class="d">b</div><div class="ar">c</div></div>'
    assert build.three_cell_row("a", "b", "", first_cls="d", middle_cls="", last_cls="") == \
        '<div class="ch2"><div class="d">a</div><div>b</div><div></div></div>'


def test_the_script_clones_the_port_row_and_writes_no_markup():
    js = build.script_body(build.PAGE_JS)
    fn = js[js.index("var portRow=function"):js.index("return row};", js.index("var portRow=function"))]
    assert "getElementById('port-row-tpl')" in fn
    assert "cloneNode(true)" in fn
    assert "createElement" not in fn
    assert "className=" not in fn


def test_the_template_is_the_same_row_the_server_draws():
    """The empty row in the template and a stored row come from one call."""
    assert build.port_row_template_html() == (
        '<template id="port-row-tpl">' + build.port_row("", "", "", "") + "</template>")
    stored = build.port_row("box", "tcp", 22, "declared open")
    assert '<b class="mono num">22/tcp</b><small class="dim">declared open</small>' in stored
    assert 'data-host="box" data-protocol="tcp" data-port="22"' in stored


def test_a_live_page_carries_the_template_outside_every_view_and_the_sample_does_not(tmp_path):
    db = str(tmp_path / "cp.db")
    con = sqlite3.connect(db)
    con.executescript(SCHEMA)
    con.commit()
    con.close()
    add_host(db, "box", [(NOW, document(listening=[]))], last_report_at=NOW.isoformat())
    declare_intent(db, "box", "tcp", 22, "v4", "open")
    declare_intent(db, "box", "tcp", 22, "v6", "open")
    html = rl.render(db, now=NOW)
    templates = re.findall(r'<template id="port-row-tpl">.*?</template>', html, re.S)
    assert len(templates) == 1
    # After the last view, beside the channel templates, inside no panel.
    assert html.index(templates[0]) > html.rindex('class="wrap view')
    assert 'class="crow-tpl"' in html[:html.index(templates[0])]
    # The stored declaration is drawn with the same builder as the template.
    assert build.port_row("box", "tcp", 22, "declared open") in html
    assert '<template id="port-row-tpl">' not in build.build_sample()


# ------------------------------------------------------------- the browser
#
# The clone is script, and nothing else here executes it. So a real browser
# drives a live page the way test_rename_button.py does: fetch is stubbed to
# say 204, a port is typed and Add is clicked, and the row that appears is
# read back and compared with the one the server would have drawn.

import functools  # noqa: E402
import html as html_mod  # noqa: E402
import http.server  # noqa: E402
import json  # noqa: E402
import threading  # noqa: E402
from test_rename_button import QuietHandler, find_chrome, run_chrome  # noqa: E402

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>port row drive</title>
<pre id="out"></pre>
<iframe id="f" width="1200" height="900"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var posts=[];
    w.fetch=function(url,opts){
      posts.push((opts&&opts.method||'GET')+' '+url);
      return Promise.resolve({status:204,ok:true,redirected:false,
        text:function(){return Promise.resolve('')},
        json:function(){return Promise.resolve({})}})};
    var tick=function(){return new Promise(function(r){setTimeout(r,50)})};
    var box=d.querySelector('.js-port-add').closest('.li');
    box.querySelector('.pd-port').value='8080';
    box.querySelector('.seg button[data-intent="open"]').click();
    d.querySelector('.js-port-add').click(); await tick(); await tick();
    var rows=Array.prototype.map.call(d.querySelectorAll('#t-box-settings .js-port-rm'),
      function(b){return b.closest('.li').outerHTML});
    out.textContent=JSON.stringify({posts:posts,rows:rows});
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
};
f.src='live.html';
</script>
"""


def test_a_port_added_on_the_page_is_the_row_the_server_would_draw(tmp_path):
    db = str(tmp_path / "cp.db")
    con = sqlite3.connect(db)
    con.executescript(SCHEMA)
    con.commit()
    con.close()
    add_host(db, "box", [(NOW, document(listening=[]))], last_report_at=NOW.isoformat())
    declare_intent(db, "box", "tcp", 22, "v4", "open")
    declare_intent(db, "box", "tcp", 22, "v6", "open")
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
             "--virtual-time-budget=15000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got, dom[:2000]
    result = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in result, result
    # Both families were declared, then the page was asked for.
    assert result["posts"][:2] == [
        "POST /api/admin/hosts/box/ports/tcp/8080/v4/declare",
        "POST /api/admin/hosts/box/ports/tcp/8080/v6/declare"]
    # The stored row, then the new one in port order, and the new one is
    # exactly what the server draws for it.
    # The browser serialises the row's icon its own way (<path></path> for
    # the builder's <path/>), so the icon is stripped from both sides.
    def no_icon(html):
        return re.sub(r"<svg.*?</svg>", "", html, flags=re.S)
    assert [no_icon(r) for r in result["rows"]] == [
        no_icon(build.port_row("box", "tcp", 22, "declared open")),
        no_icon(build.port_row("box", "tcp", 8080, "declared open"))]
