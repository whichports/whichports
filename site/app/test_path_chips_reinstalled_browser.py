"""The Packet path chips of a server installed again beside its old row, clicked
in a real browser.

    Run from site/: python3 -m pytest app/test_path_chips_reinstalled_browser.py

A server installed again keeps its old row and is named "<name>-2"
(controlplane/app/store.py). On 26 October, in the second big test, two of
such a server's chips did nothing when clicked: their ids were also the ids
of the old server's path boxes, earlier in the document, and a label reaches
the first. Only a browser says what a click on a label reaches, so this
clicks every chip of "box-2" with "box" on the same page and reads which path
is on screen after each click.
"""
import functools
import http.server
import json
import pathlib
import re
import sys
import threading
from html import unescape

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_path_browser import QuietHandler, find_chrome, run_chrome  # noqa: E402
from test_path_ids_per_server import PORTS, page  # noqa: E402

# Clicks each chip of box-2's picker, as a person clicks it, and reads back
# which walk is drawn, which chip radio is checked, and whether anything in
# box's own page changed.
PROBE = """
<script>
window.__err = [];
window.addEventListener('error', function (e) { window.__err.push(String(e.message)); });
window.addEventListener('load', function () { setTimeout(function () {
  var out = {errors: window.__err, clicks: []};
  var mine = document.getElementById('host-box-2');
  var old = document.getElementById('host-box');
  var checkedIn = function (view) {
    return [].filter.call(view.querySelectorAll('input[type="radio"]'),
                          function (r) { return r.checked; })
             .map(function (r) { return r.id; }).sort().join(' ');
  };
  var oldBefore = checkedIn(old);
  var labels = mine.querySelectorAll('.ppick label');
  out.chips = labels.length;
  [].forEach.call(labels, function (label, i) {
    label.click();
    var walks = mine.querySelectorAll('.walks>.walk');
    var shown = [];
    [].forEach.call(walks, function (w, k) {
      if (getComputedStyle(w).display !== 'none') shown.push(k + 1);
    });
    var chip = mine.querySelector('.pw>input.rr:checked');
    var radios = [].slice.call(mine.querySelectorAll('.pw>input.rr'));
    out.clicks.push({chip: i + 1, text: label.textContent, shown: shown,
                     checked: chip ? radios.indexOf(chip) + 1 : 0});
  });
  out.oldUnchanged = checkedIn(old) === oldBefore;
  var pre = document.createElement('pre');
  pre.id = 'out';
  pre.textContent = JSON.stringify(out);
  document.body.appendChild(pre);
}, 400); });
</script>
"""


def drive(tmp_path, html):
    html = html.replace(
        "</head>",
        "<style>#fleet{display:none!important}"
        "#host-box-2{display:block!important}</style></head>", 1)
    html = re.sub(r'(id="tb-box-2-\w+") checked>', r"\1>", html)
    html = html.replace('id="tb-box-2-path">', 'id="tb-box-2-path" checked>')
    html = html.replace("</body>", PROBE + "</body>", 1)
    site = tmp_path / "www"
    site.mkdir(exist_ok=True)
    (site / "live.html").write_text(html, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / 'chrome-profile'}",
             "--window-size=1440,900", "--virtual-time-budget=15000", "--dump-dom",
             f"http://127.0.0.1:{port}/live.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got, f"the probe wrote nothing, the dumped page was:\n{dom[:1500]}"
    data = json.loads(unescape(got.group(1)))
    assert data["errors"] == [], data["errors"]
    return data


def test_every_chip_of_a_server_named_name_2_shows_its_own_path(tmp_path):
    data = drive(tmp_path, page(tmp_path, ["box", "box-2"]))
    assert data["chips"] == len(PORTS), data
    for click in data["clicks"]:
        assert click["checked"] == click["chip"], data["clicks"]
        assert click["shown"] == [click["chip"]], data["clicks"]
    assert data["oldUnchanged"], data
