"""The Packet path in a real browser: the wire is laid and the packets fly.

    Run from site/app: python3 -m pytest test_path_browser.py

Everything else about this tab can be read off the markup. Two things cannot,
and both were wrong at some point on 2026-09-12 without anything failing:

  - **the wire.** Its path is measured from where the browser put the boxes,
    so no amount of reading the HTML says whether it runs from the probe,
    through each tool, to the service.
  - **the packets.** They move because CSS flies them along that path. A
    screenshot cannot show it and a frame loop cannot be trusted to run, so
    this drives the animation's own timeline and reads where they are. That is
    deterministic: no waiting, no flake, and it fails if the keyframes stop
    moving them.

The screenshots that were shown to the owner before this existed were taken from
`file://`, where the page script dies on its first `history.replaceState` with
a SecurityError. The page was dead in every one of them and nothing said so.
That is why this test serves the page over http, exactly as the box does.
"""
import functools
import http.server
import json
import os
import pathlib
import re
import shutil
import sys
import threading
from datetime import timedelta
from html import unescape

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402

CHROME_MAC = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
NOW = trl.NOW

SSHD = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 22,
        "process_name": "sshd", "pid": 812}
PG = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 5432,
      "process_name": "postgres", "pid": 2210}

# The packets' own speed, which the script sets and this reads back off the
# screen. Along a straight row one second of the animation is this many pixels.
SPEED = 105


def find_chrome():
    """The browser to drive with. Not finding one is a failure, never a skip:
    the gate allows no skips and this is the only executed proof the wire is
    laid and the packets move."""
    if os.path.exists(CHROME_MAC):
        return CHROME_MAC
    for name in ("google-chrome", "google-chrome-stable", "chromium-browser",
                 "chromium"):
        found = shutil.which(name)
        if found:
            return found
    pytest.fail("no Chrome or Chromium found, and the wire is laid by page "
                "script that only a browser can execute")


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


# One way of starting Chrome for every browser test, and it lives in
# test_rename_button.py, where it says why it starts Chrome a second time.
from test_rename_button import run_chrome  # noqa: E402,F401


# Reads the flow that is on screen: the wire it laid, and where each packet
# sits at four points of the animation's own timeline.
PROBE = """
<script>
window.__err = [];
window.addEventListener('error', function (e) { window.__err.push(String(e.message)); });
window.addEventListener('load', function () { setTimeout(function () {
  var out = {errors: window.__err};
  var walks = document.querySelectorAll('.walks>.walk');
  var flow = (walks[WALK - 1] || document).querySelector('.pt-flow');
  if (!flow) { out.error = 'no flow on the page'; write(out); return; }
  out.fate = flow.dataset.fate;
  var svg = flow.querySelector('svg.pt-wire');
  var box = flow.getBoundingClientRect();
  var at = function (sel) {
    var el = flow.querySelector(sel);
    if (!el) return null;
    var r = el.getBoundingClientRect();
    return {x: Math.round(r.left - box.left), y: Math.round(r.top - box.top),
            w: Math.round(r.width), h: Math.round(r.height)};
  };
  out.live = (svg.querySelector('.pt-live').getAttribute('d') || '');
  out.quiet = (svg.querySelector('.pt-quiet').getAttribute('d') || '');
  out.leftTile = at('.pt-endL .pt-tile');
  out.rightTile = at('.pt-endR .pt-tile');
  out.boxes = [].map.call(flow.querySelectorAll('.pt-mid .pt-nd'), function (n) {
    var r = n.getBoundingClientRect();
    return {x: Math.round(r.left - box.left), w: Math.round(r.width),
            stop: n.classList.contains('pt-stop'),
            ghost: n.classList.contains('pt-ghost')};
  });
  var packets = flow.querySelectorAll('.pt-pk');
  out.offsetPaths = [].map.call(packets, function (c) {
    return (c.style.offsetPath || '').slice(0, 6);
  });
  var flying = document.getAnimations().filter(function (a) {
    return a.effect && a.effect.target && a.effect.target.classList
        && a.effect.target.classList.contains('pt-pk')
        && flow.contains(a.effect.target);
  });
  out.animations = flying.length;
  out.duration = flying.length ? Math.round(flying[0].effect.getTiming().duration) : 0;
  out.frames = [];
  [0, 1000, 2000, 3000].forEach(function (t) {
    flying.forEach(function (a) { a.currentTime = t; });
    out.frames.push([].map.call(packets, function (c) {
      var r = c.getBoundingClientRect();
      return Math.round(r.left - box.left);
    }));
  });
  write(out);
  function write(data) {
    var pre = document.createElement('pre');
    pre.id = 'out';
    pre.textContent = JSON.stringify(data);
    document.body.appendChild(pre);
  }
}, 400); });
</script>
"""


def seeded(tmp_path, extra=None, states=()):
    """A host with a provider, ufw and a container runtime, rendered live."""
    import sqlite3
    db = str(tmp_path / "cp.db")
    con = sqlite3.connect(db)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    doc = trl.document(listening=[SSHD, PG])
    doc["firewalld"] = {"status": "not_present"}
    doc["ufw"] = {"status": "collected", "conf": {"ENABLED": "yes"},
                  "defaults": {"DEFAULT_INPUT_POLICY": "DROP"},
                  "rules": ["allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in",
                            "deny tcp 5432 0.0.0.0/0 any 0.0.0.0/0 in"],
                  "rules6": [],
                  "sources": {"ufw.conf": {"status": "collected"},
                              "user.rules": {"status": "collected"},
                              "user6.rules": {"status": "collected"}}}
    doc["nftables"] = {"status": "collected", "tables": [{
        "family": "inet", "name": "filter", "chains": [
            {"name": "input", "type": "filter", "hook": "input", "priority": 0,
             "policy": "drop", "rules": [
                 {"text": "counter jump ufw-user-input", "rendered": "full"}]},
            {"name": "ufw-user-input", "rules": [
                {"text": "tcp dport 22 counter accept", "rendered": "full"},
                {"text": "tcp dport 5432 counter drop", "rendered": "full"}]}]}]}
    if extra:
        doc.update(extra)
    trl.add_host(db, "box", [(NOW - timedelta(minutes=4), doc)],
                 last_report_at=(NOW - timedelta(minutes=4)).isoformat())
    for port, family, state in states:
        trl.probe_result(db, "box", port, family, state)
    return rl.render(db, now=NOW)


def read_flow(tmp_path, html, walk=1):
    """Serve the page, open the Packet path tab on one walk, and read it."""
    show = (".walks>.walk{display:none!important}"
            f".walks>.walk:nth-child({walk}){{display:block!important}}")
    html = html.replace(
        "</head>",
        f'<style>#fleet{{display:none!important}}#host-box{{display:block!important}}'
        f"{show}</style></head>", 1)
    html = re.sub(r'(id="tb-box-\w+") checked>', r"\1>", html)
    html = html.replace('id="tb-box-path">', 'id="tb-box-path" checked>')
    html = html.replace("</body>", PROBE.replace("WALK", str(walk)) + "</body>", 1)
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
    assert not data.get("error"), data
    assert data["errors"] == [], data["errors"]
    return data


def numbers(path):
    """The coordinates in a path string, in order."""
    return [float(n) for n in re.findall(r"-?\d+(?:\.\d+)?", path)]


def test_the_wire_runs_from_the_probe_through_every_box_to_the_service(tmp_path):
    """The one thing no reading of the markup can answer: the path is measured
    from where the browser put the boxes."""
    data = read_flow(tmp_path, seeded(tmp_path, states=[(22, "v4", "connect_succeeded")]))
    assert data["live"].startswith("M"), data["live"]
    xs = numbers(data["live"])[::2]
    # it starts at the right edge of the left tile and ends at the left edge of
    # the right tile
    assert abs(xs[0] - (data["leftTile"]["x"] + data["leftTile"]["w"])) <= 2, xs
    assert abs(xs[-1] - data["rightTile"]["x"]) <= 2, xs
    # and passes through the middle of every box on the way
    for box in data["boxes"]:
        middle = box["x"] + box["w"] / 2
        assert any(abs(x - middle) <= 2 for x in xs), (middle, xs)
    # one row of boxes, so the wire is straight and goes only forwards
    assert xs == sorted(xs), xs


def test_the_packets_fly_along_the_wire_at_the_speed_the_script_set(tmp_path):
    """Driven off the animation's own timeline, so this asks what the keyframes
    do rather than whether a frame happened to be produced."""
    data = read_flow(tmp_path, seeded(tmp_path, states=[(22, "v4", "connect_succeeded")]))
    assert data["animations"] == 5, data["animations"]
    assert data["duration"] > 1000, data["duration"]
    assert all(p == 'path("' for p in data["offsetPaths"]), data["offsetPaths"]
    first, second = data["frames"][0], data["frames"][1]
    moved = [b - a for a, b in zip(first, second)]
    # One second of the timeline is one second of travel, and on this wire that
    # is 105 pixels. A packet that reached the end in between wraps back to the
    # start, which is the large negative step.
    assert all(abs(step - SPEED) <= 20 or step < -100 for step in moved), moved
    assert any(abs(step - SPEED) <= 20 for step in moved), moved
    # they ride a fixed distance apart rather than a fixed count per wire
    apart = [b - a for a, b in zip(first, first[1:])]
    assert all(150 <= gap <= 190 for gap in apart), apart


def test_a_stopped_packet_goes_into_the_tool_and_the_wire_past_it_is_quiet(tmp_path):
    """The fate the tab exists for. The live wire ends at the tool that ends
    the journey and the rest of it is drawn separately and quietly."""
    html = seeded(tmp_path, states=[(22, "v4", "connect_succeeded"),
                                    (5432, "v4", "no_response")])
    data = read_flow(tmp_path, html, walk=2)
    assert data["fate"] == "stop", data["fate"]
    stopping = [i for i, b in enumerate(data["boxes"]) if b["stop"]]
    assert stopping, data["boxes"]
    box = data["boxes"][stopping[0]]
    xs = numbers(data["live"])[::2]
    assert abs(xs[-1] - (box["x"] + box["w"] / 2)) <= 2, (xs[-1], box)
    # the rest of the path exists and starts where the live one stopped
    assert data["quiet"].startswith("M"), data["quiet"]
    assert abs(numbers(data["quiet"])[0] - xs[-1]) <= 2, data["quiet"]
    # every tool after it is a ghost the packet never meets
    for later in data["boxes"][stopping[0] + 1:]:
        assert later["ghost"], data["boxes"]


def test_a_port_nobody_probed_draws_a_wire_and_no_packets(tmp_path):
    """`none` is the one fate with nothing moving: no packets, grey wire."""
    data = read_flow(tmp_path, seeded(tmp_path))
    assert data["fate"] == "none"
    assert data["live"].startswith("M")
    # the packets are still in the markup, and CSS keeps them off the wire
    assert data["animations"] in (0, 5)
