"""The first-look window opens on its own on a server's page loaded by its
address, in a real browser.

    Run from site/: python3 -m pytest app/test_first_look_by_address_browser.py

The second big test, 24 October 2026, case F6: a server opened by clicking
its Fleet row showed the window, and the same server loaded at
/host/<name> never did. Open server at the end of an install, the link in an
alert message, a reload and a bookmark all load the page at the server's
address. The page script set the window's opener only after the address had
been applied, so the view shown on load ran the empty opener (SPEC.md
section 8: it appears on its own once, the first time such a server is
opened, however it is opened).
"""
import functools
import html as html_mod
import http.server
import json
import pathlib
import re
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
from test_host_answers import NOW, SSHD, add_host, db, probe_result  # noqa: E402
from test_host_browser import mark_seen  # noqa: E402
from test_rename_button import find_chrome, run_chrome  # noqa: E402

__all__ = ["db"]

# Stands where the control plane stands, inside the page and ahead of its
# script, so a POST the page makes while it loads is kept to be read back.
STUB = """<script>
window.__posts=[];
window.fetch=function(url,opts){
  opts=opts||{};
  if((opts.method||'GET')==='POST')window.__posts.push(String(url));
  return Promise.resolve({ok:true,status:204,redirected:false,
    json:function(){return Promise.resolve({})},text:function(){return Promise.resolve('')}})};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>first look by address</title>
<pre id="out"></pre>
<iframe id="f" width="1400" height="900"></iframe>
<script>
var PLAN=%(plan)s, at=0, results=[];
var f=document.getElementById('f');
f.onload=function(){
  setTimeout(function(){
    var w=f.contentWindow, d=f.contentDocument;
    results.push({address:w.location.pathname,
                  view:(d.querySelector('.view.on')||{}).id||'',
                  modal:!!d.querySelector('.fv.on'),
                  posts:w.__posts||[]});
    at+=1;
    if(at<PLAN.length){f.src=PLAN[at]}
    else{document.getElementById('out').textContent=JSON.stringify(results)}
  },300);
};
f.src=PLAN[0];
</script>
"""


def load(tmp_path, page, paths):
    """Serve `page` at every address but the harness's, load each of
    `paths` in turn in one Chrome run, and read back what each showed."""
    plan = json.dumps(list(paths))
    harness = (HARNESS % {"plan": plan}).encode("utf-8")
    body = page.replace("<head>", "<head>" + STUB, 1).encode("utf-8")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            data = harness if self.path.startswith("/harness.html") else body
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
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
    return json.loads(html_mod.unescape(got.group(1)))


def waiting_page(db):
    """almabox with sshd reachable and nobody's answer yet."""
    add_host(db, "almabox", [SSHD])
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    return rl.render(db, now=NOW)


def test_a_server_loaded_by_its_address_opens_its_first_look_and_records_it(tmp_path, db):
    page = waiting_page(db)
    assert 'data-first="1"' in page
    (direct,) = load(tmp_path, page, ["/host/almabox"])
    assert direct["view"] == "host-almabox"
    assert direct["modal"] is True
    assert direct["posts"] == ["/api/admin/hosts/almabox/first-look"]


def test_a_tab_in_the_address_opens_it_too(tmp_path, db):
    (direct,) = load(tmp_path, waiting_page(db), ["/host/almabox/services"])
    assert (direct["view"], direct["modal"]) == ("host-almabox", True)


def test_a_server_whose_first_look_was_seen_opens_nothing_by_its_address(tmp_path, db):
    waiting_page(db)
    mark_seen(db, "almabox")
    page = rl.render(db, now=NOW)
    (direct,) = load(tmp_path, page, ["/host/almabox"])
    assert direct["view"] == "host-almabox"
    assert direct["modal"] is False and direct["posts"] == []


def test_the_fleet_loaded_by_its_address_opens_no_window(tmp_path, db):
    (fleet,) = load(tmp_path, waiting_page(db), ["/"])
    assert fleet["view"] == "fleet"
    assert fleet["modal"] is False and fleet["posts"] == []
