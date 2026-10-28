"""The dashboard's fonts load on a server's own URL, driven in a real browser.

The owner, 2026-09-20: the font sometimes fails to load after a refresh, and
had for a long time. Read from the box that day: the page names its
fonts by relative path, `fonts/WorkSans-400.woff2`. At `/` that is
`/fonts/...`, which answers 200. At `/host/student-net` it is
`/host/fonts/...`, which the application answers with a 303 and no font. So a
server opened from the Fleet kept the fonts already loaded, and a refresh on
that server's page lost them. The sign-in pages met the same fault at
`/login/2fa` and fixed it on 2026-09-09 with `<base href="/">`
(`controlplane/app/web_pages.py`). The dashboard never got it.

    Run from site/: python3 -m pytest app/test_fonts_at_depth_browser.py
"""
import functools
import html as html_mod
import json
import pathlib
import re
import shutil
import sqlite3
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
from test_rename_button import (FileServer, QuietHandler,  # noqa: E402
                                find_chrome, run_chrome)

NOW = trl.NOW
FONTS = pathlib.Path(__file__).resolve().parent.parent / "fonts"

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>fonts at depth</title>
<pre id="out"></pre>
<iframe id="f" width="1200" height="600"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var run=async function(){
    var d=f.contentDocument;
    await d.fonts.ready;
    var loaded=[], failed=[];
    d.fonts.forEach(function(face){
      (face.status==='loaded'?loaded:failed).push(face.family+' '+face.weight+' '+face.status)});
    out.textContent=JSON.stringify({
      body:d.fonts.check('400 16px "Work Sans"'),
      title:d.fonts.check('700 28px "Space Grotesk"'),
      loaded:loaded.length,errors:failed.filter(function(x){return x.indexOf('error')>=0})});
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
};
f.src='%(path)s';
</script>
"""


def drive(tmp_path, page, where):
    """Serve `page` at `where` under the site root, with the fonts at /fonts
    and nowhere else, the way the box serves them."""
    site = tmp_path / "www"
    (site / "fonts").mkdir(parents=True)
    for font in FONTS.glob("*.woff2"):
        shutil.copy(font, site / "fonts")
    target = site / where
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(page, encoding="utf-8")
    (site / "harness.html").write_text(HARNESS % {"path": where}, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = FileServer(("127.0.0.1", 0), handler)
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
    assert "error" not in result, result
    return result


def a_page(tmp_path):
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(path, "student-net", trl.document(listening=[trl.SSHD]))
    return rl.render(path, now=NOW)


def test_the_fonts_load_on_a_servers_own_url(tmp_path):
    # One level down, which is what decides how `fonts/X.woff2` resolves.
    # With the extension, because the test's file server names a type by it
    # and a page with none is offered as a download and never drawn.
    got = drive(tmp_path, a_page(tmp_path), "host/student-net.html")
    assert got["errors"] == []
    assert got["body"] and got["title"], got


def test_and_still_at_the_root(tmp_path):
    got = drive(tmp_path, a_page(tmp_path), "index.html")
    assert got["errors"] == []
    assert got["body"] and got["title"], got


def test_both_feeds_carry_the_base_before_anything_that_names_a_file(tmp_path):
    """The base has to come before the first relative reference, or the
    browser has already resolved it. The icons and the fonts are the two."""
    for page in (a_page(tmp_path), build.build_sample()):
        head = page[:page.index("</head>")]
        assert head.count('<base href="/">') == 1
        assert head.index('<base href="/">') < head.index('rel="icon"')
        assert head.index('<base href="/">') < head.index("@font-face")
