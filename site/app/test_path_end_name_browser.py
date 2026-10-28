"""The name at the Packet path's end, measured in a real browser with the
product's own fonts.

    Run from site/: python3 -m pytest app/test_path_end_name_browser.py

The right end of a path names what listens: a process, a container, the name
somebody gave the port, or the address it is bound on. Beside its tile the
name has 152 px. It was held to one line and cut there, and a process name of
twenty characters needs 160 px in the product's own face, so a real server's
page read "whichports-test-d" and an ellipsis (docs/RECORD.md 4.355).

Only a browser can say this, and only with the fonts the product serves: the
width of a name is the face's own, and a page drawn with the browser's
fallback face showed that same name whole. So this serves the page with
`site/fonts`, refuses to measure when they did not load, and reads the box
and the name in px at 1440 and at 1024.

What is held here:

  - a name that needs a second line takes it, and reads whole
  - a name longer than two lines is cut after the second, inside its column
    and clear of what stands above and below the path
  - a name with nowhere to break still stays inside its column
  - the small line under the name does the same: a container's "podman,
    80/tcp in the container" needs 205 px of the 152 and was cut on its one
    line
  - the ends stay where they are: the tile at the same place for every name,
    the wire still straight into it
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

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import joinbridge  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
from test_rename_button import (FileServer, QuietHandler,  # noqa: E402
                                find_chrome, run_chrome)

NOW = trl.NOW
FONTS = pathlib.Path(__file__).resolve().parent.parent / "fonts"
HOST = "app-01"
WIDTHS = (1440, 1024)

# The name the finding was measured with, twenty characters.
TWENTY = "whichports-test-dual"
# An address from the documentation range, written out in full: no hyphen
# and no space, so nothing offers the browser a place to break it.
LONG_ADDRESS = "2001:db8:85a3:8d3:1319:8a2e:370:7334"
# A container's name of a common shape, long enough for two lines.
CONTAINER = "app-01-web-frontend-1"
# The small line under a container's name, as the page writes it.
CONTAINER_LINE = "podman, 80/tcp in the container"
# As long as a name somebody gives a port may be, 64 characters.
LONGEST = "the metrics exporter read by the monitoring server in the office"


def socket(address, port, process=""):
    entry = {"protocol": "tcp", "family": "v6" if ":" in address else "v4",
             "bind_address": address, "port": port}
    if process:
        entry.update(process_name=process, pid=4000 + port)
    return entry


def the_page(tmp_path):
    """One server whose five ports end in names of five kinds."""
    # Held to the limit the product itself puts on such a name, so this
    # stays the longest one when that limit moves.
    assert len(LONGEST) == joinbridge.module("intent").MAX_NAME_LENGTH
    db = str(tmp_path / "cp.db")
    con = sqlite3.connect(db)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    doc = trl.document(listening=[
        socket("0.0.0.0", 22, "sshd"),
        socket("0.0.0.0", 3030, TWENTY),
        socket(LONG_ADDRESS, 8443),
        socket("0.0.0.0", 9100, "node_exporter")])
    doc["hostname"] = HOST
    doc["firewalld"] = {"status": "not_present"}
    doc["nftables"] = {"status": "collected", "tables": []}
    doc["containers"] = {"status": "collected", "podman": [
        {"id": "abc", "name": CONTAINER, "image": "nginx:1.27", "ports": [
            {"host_ip": "0.0.0.0", "host_port": 8080, "container_port": 80,
             "protocol": "tcp"}]}]}
    doc["ufw"] = {"status": "collected", "conf": {"ENABLED": "yes"},
                  "defaults": {"DEFAULT_INPUT_POLICY": "DROP"},
                  "rules": [f"allow tcp {port} 0.0.0.0/0 any 0.0.0.0/0 in"
                            for port in (22, 3030, 8080, 9100)],
                  "rules6": ["allow tcp 8443 ::/0 any ::/0 in"],
                  "sources": {"ufw.conf": {"status": "collected"},
                              "user.rules": {"status": "collected"},
                              "user6.rules": {"status": "collected"}}}
    trl.reporting(db, HOST, doc)
    trl.declare_name(db, HOST, "tcp", 9100, LONGEST)
    for port, family in ((22, "v4"), (3030, "v4"), (8080, "v4"), (8443, "v6"),
                         (9100, "v4")):
        trl.probe_result(db, HOST, port, family, "connect_succeeded")
    return rl.render(db, now=NOW)


# Every path of the server laid out at once, each read the same way: the
# name's box and what the name needs, where the words beside the tile start
# and end, where the tile and the last tool stand, and where the wire ends.
PROBE = """
<script>
window.__err = [];
window.addEventListener('error', function (e) { window.__err.push(String(e.message)); });
window.addEventListener('load', function () {
  var write = function (data) {
    var pre = document.createElement('pre');
    pre.id = 'out';
    pre.textContent = JSON.stringify(data);
    document.body.appendChild(pre);
  };
  var read = function () {
    var out = {errors: window.__err, window: window.innerWidth,
               faces: {name: document.fonts.check('600 15px "Work Sans"'),
                       mono: document.fonts.check('400 11px "IBM Plex Mono"')},
               paths: []};
    document.querySelectorAll('.walks>.walk').forEach(function (walk) {
      var flow = walk.querySelector('.pt-flow');
      var box = flow.getBoundingClientRect();
      var name = flow.querySelector('.pt-endR .pt-v');
      var small = flow.querySelector('.pt-endR .pt-s');
      var words = flow.querySelector('.pt-endR .pt-tx').getBoundingClientRect();
      var tile = flow.querySelector('.pt-endR .pt-tile').getBoundingClientRect();
      var tools = flow.querySelectorAll('.pt-mid .pt-nd');
      var last = tools[tools.length - 1].getBoundingClientRect();
      var above = walk.querySelector('.pt-meas').getBoundingClientRect();
      var below = [].filter.call(walk.querySelectorAll('.pt-under'), function (p) {
        return p.offsetParent !== null; })[0].getBoundingClientRect();
      var wire = (flow.querySelector('.pt-live').getAttribute('d') || '')
        .match(/-?\\d+(?:\\.\\d+)?/g) || [];
      out.paths.push({
        text: name.textContent,
        shown: name.clientWidth, needs: name.scrollWidth,
        high: name.clientHeight, needsHigh: name.scrollHeight,
        line: parseFloat(getComputedStyle(name).lineHeight),
        small: {text: small.textContent,
                shown: small.clientWidth, needs: small.scrollWidth,
                high: small.clientHeight, needsHigh: small.scrollHeight,
                line: parseFloat(getComputedStyle(small).lineHeight)},
        wordsTop: words.top, wordsBottom: words.bottom,
        aboveBottom: above.bottom, belowTop: below.top,
        tileLeft: tile.left - box.left, tileMiddle: tile.top + tile.height / 2 - box.top,
        lastToolMiddle: last.top + last.height / 2 - box.top,
        wireEndX: parseFloat(wire[wire.length - 2]),
        wireEndY: parseFloat(wire[wire.length - 1])});
    });
    write(out);
  };
  Promise.all([document.fonts.load('600 15px "Work Sans"'),
               document.fonts.load('400 11px "IBM Plex Mono"')])
    .then(function () { return document.fonts.ready; })
    .then(function () { setTimeout(read, 400); })
    .catch(function (e) { write({error: String(e)}); });
});
</script>
"""


def read_the_ends(folder, page, width):
    """Serve the page with the product's fonts, open the Packet path with
    every path laid out, and read each one's end."""
    page = page.replace(
        "</head>",
        f"<style>#fleet{{display:none!important}}#host-{HOST}{{display:block!important}}"
        ".walks>.walk{display:block!important}.ovl{display:none!important}"
        "</style></head>", 1)
    page = re.sub(rf'(id="tb-{HOST}-\w+") checked>', r"\1>", page)
    page = page.replace(f'id="tb-{HOST}-path">', f'id="tb-{HOST}-path" checked>')
    page = page.replace("</body>", PROBE + "</body>", 1)
    site = folder / "www"
    (site / "fonts").mkdir(parents=True)
    for font in FONTS.glob("*.woff2"):
        shutil.copy(font, site / "fonts")
    (site / "live.html").write_text(page, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = FileServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={folder / 'chrome-profile'}",
             f"--window-size={width},900", "--virtual-time-budget=15000",
             "--dump-dom", f"http://127.0.0.1:{port}/live.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got, f"the probe wrote nothing, the dumped page was:\n{dom[:1500]}"
    data = json.loads(html_mod.unescape(got.group(1)))
    assert not data.get("error"), data
    assert data["errors"] == [], data["errors"]
    # A name's width is the face's own. Measured in another face this whole
    # file would pass on a page that cuts the name.
    assert data["faces"] == {"name": True, "mono": True}, data["faces"]
    assert data["window"] == width, data["window"]
    return data["paths"]


@pytest.fixture(scope="module")
def ends(tmp_path_factory):
    """Each path's end at each width, read once: one browser start a width."""
    folder = tmp_path_factory.mktemp("ends")
    page = the_page(folder)
    read = {}
    for width in WIDTHS:
        at = folder / str(width)
        at.mkdir()
        read[width] = {path["text"]: path for path in read_the_ends(at, page, width)}
    return read


def cut_sideways(end):
    """The name needs more width than its box shows."""
    return end["needs"] > end["shown"]


def cut_below(end):
    """The name needs more lines than its box shows."""
    return end["needsHigh"] > end["high"] + 1


@pytest.mark.parametrize("width", WIDTHS)
def test_the_longest_name_a_port_can_be_given_stays_in_two_lines(ends, width):
    """A name of 64 characters is four lines of this column. It is cut after
    the second, never sideways, and its words stay clear of the line above
    the path and of the panel below it."""
    end = ends[width][LONGEST]
    assert not cut_sideways(end), end
    assert end["high"] <= 2 * end["line"] + 1, end
    assert end["wordsTop"] >= end["aboveBottom"], end
    assert end["wordsBottom"] <= end["belowTop"], end


@pytest.mark.parametrize("width", WIDTHS)
def test_a_name_with_nowhere_to_break_stays_inside_its_column(ends, width):
    """An address written out in full has no hyphen and no space. It is
    broken where the column ends rather than running out of it."""
    end = ends[width][f"[{LONG_ADDRESS}]:8443"]
    assert not cut_sideways(end), end
    assert end["high"] <= 2 * end["line"] + 1, end


@pytest.mark.parametrize("width", WIDTHS)
def test_a_name_of_twenty_characters_reads_whole_at_the_paths_end(ends, width):
    """The finding itself: the box shows 152 px and this name needs 160."""
    end = ends[width][TWENTY]
    assert not cut_sideways(end), end
    assert not cut_below(end), end


@pytest.mark.parametrize("width", WIDTHS)
def test_two_lines_of_name_over_two_of_small_line_stay_clear(ends, width):
    """The tallest an end gets: a name of two lines over a small line of
    two. Its words still stay off the line above the path and off the panel
    below it, and no small line is taller than two lines."""
    end = ends[width][CONTAINER]
    assert end["high"] > end["line"] + 1 and end["small"]["high"] > end["small"]["line"] + 1, end
    assert end["wordsTop"] >= end["aboveBottom"], end
    assert end["wordsBottom"] <= end["belowTop"], end
    for other in ends[width].values():
        small = other["small"]
        assert small["high"] <= 2 * small["line"] + 1, other
        assert not cut_sideways(small), other


@pytest.mark.parametrize("width", WIDTHS)
def test_the_small_line_under_a_containers_name_reads_whole(ends, width):
    """The box shows 152 px and this line needs 205."""
    small = ends[width][CONTAINER]["small"]
    assert small["text"] == CONTAINER_LINE, small
    assert not cut_sideways(small), small
    assert not cut_below(small), small


@pytest.mark.parametrize("width", WIDTHS)
def test_a_short_small_line_keeps_its_one_line(ends, width):
    small = ends[width]["sshd"]["small"]
    assert small["high"] <= small["line"] + 1, small
    assert not cut_sideways(small) and not cut_below(small), small


@pytest.mark.parametrize("width", WIDTHS)
def test_a_short_name_keeps_its_one_line(ends, width):
    end = ends[width]["sshd"]
    assert end["high"] <= end["line"] + 1, end
    assert not cut_sideways(end) and not cut_below(end), end


@pytest.mark.parametrize("width", WIDTHS)
def test_the_end_stays_pinned_whatever_the_name(ends, width):
    """The tile stands at the same place on every path, level with the last
    tool, and the wire runs straight into it. A second line of name moves
    none of that."""
    paths = list(ends[width].values())
    assert len(paths) == 5, [path["text"] for path in paths]
    assert len({round(path["tileLeft"]) for path in paths}) == 1, paths
    for path in paths:
        assert abs(path["tileMiddle"] - path["lastToolMiddle"]) <= 1, path
        assert abs(path["wireEndX"] - path["tileLeft"]) <= 2, path
        assert abs(path["wireEndY"] - path["tileMiddle"]) <= 1, path
