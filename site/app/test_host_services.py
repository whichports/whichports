"""The Services tab: a row is a thing that runs, never a port, in the four
groups of docs/screens/host-services/SPEC.md, with its ports as chips that
open the port's row on the Overview.

    Run from site/app: python3 -m pytest test_host_services.py

Its own file, the way test_host_answers.py is: the tab that replaced the
port-list-by-owner adds its tests here rather than growing
test_render_live.py, whose fixtures it borrows.
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

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import build  # noqa: E402
import render_live as rl  # noqa: E402
import theme  # noqa: E402
from test_render_live import (  # noqa: E402
    COCKPIT_SOCKET, COCKPIT_UNIT, JELLYFIN, LOOP, NOW, ROOT_SOCKET, SSHD, SSHD6,
    add_host, db, declare_intent, declare_name, document, host_section, probe_result,
    tab_body, unit_section)
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

__all__ = ["db"]


# ------------------------------------------------------------ the fragments

def row(**kw):
    base = dict(tone="warn", word="unreviewed", name="jellyfin", fact="jellyfin/jellyfin:10.9",
                ports=(("8096/tcp", "warn", "pr-box-tcp-8096"), ("8920/tcp", "", "pr-box-tcp-8920")),
                bound="0.0.0.0")
    base.update(kw)
    return build.ServiceRow(**base)


def test_a_row_is_the_state_the_name_over_its_fact_the_chips_and_the_addresses():
    html = build.service_row_html("box", row())
    assert html == (
        '<div class="srow"><span class="sst"><span class="st warn">unreviewed</span></span>'
        '<span class="snm"><b>jellyfin</b><small>jellyfin/jellyfin:10.9</small></span>'
        '<span class="schips">'
        '<button class="spc warn" data-row="pr-box-tcp-8096" data-tab="tb-box-overview">8096<small>tcp</small></button>'
        '<button class="spc off" data-row="pr-box-tcp-8920" data-tab="tb-box-overview">8920<small>tcp</small></button>'
        '</span><span class="sbd">0.0.0.0</span></div>')


def test_a_row_with_no_state_and_no_fact_leaves_those_cells_empty():
    html = build.service_row_html("box", row(tone="", word="", fact="", ports=(), bound=""))
    assert '<span class="sst"></span>' in html
    assert '<span class="snm"><b>jellyfin</b></span>' in html
    assert '<span class="schips"></span><span class="sbd"></span>' in html
    assert "<small>" not in html


def test_the_chips_wear_the_fleets_four_tones():
    for tone in ("fail", "warn", "ok", "off"):
        assert f".spc.{tone}{{" in build.CSS
    assert ".spc.fail{border-color:var(--fail);background:var(--fail-soft);color:var(--fail)}" in build.CSS
    assert ".spc.ok{border-color:var(--ok-mark)}" in build.CSS


def test_the_row_escapes_what_could_carry_document_text():
    html = build.service_row_html("box", row(name="<b>x</b>", fact="<i>y</i>", bound="<u>z</u>",
                                             ports=(("<s>1</s>/tcp", "warn", "pr-<x>"),)))
    for raw in ("<b>x</b>", "<i>y</i>", "<u>z</u>", "<s>1</s>", "pr-<x>"):
        assert raw not in html
    assert "&lt;b&gt;x&lt;/b&gt;" in html


def test_a_declared_name_sits_beside_the_measured_name():
    """In What runs, after the bold name and before the fact, and escaped like
    every other string a person typed (docs/RECORD.md 4.174)."""
    html = build.service_row_html("box", row(declared="media <b>"))
    assert ('<b>jellyfin</b><span class="sdn" title="named by you">media &lt;b&gt;</span>'
            '<small>jellyfin/jellyfin:10.9</small>') in html
    assert "unsure" not in html


def test_an_empty_group_is_not_drawn_and_a_full_one_is_a_band_and_its_rows():
    assert build.service_group_html("box", "Containers", "podman", []) == ""
    html = build.service_group_html("box", "Containers", "podman", [row()])
    assert html.startswith('<div class="sgh"><b>Containers</b><span>podman</span></div><div class="srow">')
    # no grey word, no span
    assert build.service_group_html("box", "Processes", "", [row()]).startswith(
        '<div class="sgh"><b>Processes</b></div>')


def test_a_group_heading_can_wear_the_marker():
    """No group carries one today, the Overlays question having been
    answered, and the mechanism stays for the next open question."""
    html = build.service_group_html("box", "Containers", "", [row()], "an open question")
    assert html.startswith('<div class="sgh unsure" title="an open question"><b>Containers</b></div>')


def test_the_table_is_one_panel_with_the_header_and_the_groups_in_order():
    groups = [("Containers", "podman", [row()], ""), ("Socket units", "systemd", [], ""),
              ("Processes", "", [row(name="sshd")], "")]
    html = build.services_table_html("box", groups)
    assert html.startswith('<div class="panel stbl"><div class="sh"><span>State</span>')
    assert '<span>State</span><span>What runs</span><span>Ports</span><span>Bound to</span></div>' in html
    assert html.index("<b>Containers</b>") < html.index("<b>Processes</b>")
    assert "Socket units" not in html


def test_an_empty_table_is_the_header_and_one_line():
    html = build.services_table_html("box", [("Processes", "", [], "")])
    assert html.endswith(f'<div class="srow sempty">{build.NOTHING_LISTENING}</div></div>')
    html = build.services_table_html("box", [], build.SOCKETS_UNREADABLE)
    assert build.SOCKETS_UNREADABLE in html


def test_the_page_carries_the_chip_click_and_the_old_list_is_gone():
    page = build.build_sample()
    script = page[page.rindex("<script>"):]
    assert "'.hstrip [data-row],.stbl [data-row],.mxt [data-row]'" in script
    assert "if(tab)tab.checked=true;" in script
    for old in ("svc-h", "svcg", "svc-n", "svc_groups_html"):
        assert old not in page, old
    assert not hasattr(build, "svc_groups_html")
    assert not hasattr(rl, "services_groups")


# ------------------------------------------------------------- the live tab

def services_of(db, name="box"):
    return tab_body(host_section(rl.render(db, now=NOW), name), name, "services")


def reporting(db, name, doc):
    add_host(db, name, [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())


def groups_of(html):
    """[(title, grey word, [row html])] as the tab draws them."""
    out = []
    for chunk in re.split(r'(?=<div class="sgh)', html)[1:]:
        m = re.match(r'<div class="sgh[^"]*"[^>]*><b>([^<]+)</b>(?:<span>([^<]*)</span>)?</div>', chunk)
        out.append((m.group(1), m.group(2) or "", re.findall(r'<div class="srow">.*?</div>(?=<div class="srow"|$)', chunk, re.S)))
    return out


def names_in(rows):
    return [re.search(r'<span class="snm"><b[^>]*>([^<]+)</b>', r).group(1) for r in rows]


def test_a_container_is_one_row_with_its_image_and_its_host_addresses(db):
    two = dict(JELLYFIN, ports=JELLYFIN["ports"] + [
        {"host_ip": "0.0.0.0", "host_port": 8920, "container_port": 8920, "protocol": "tcp"}])
    # the runtime's own host socket for the published port is the container's
    conmon = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 8096,
              "process_name": "conmon", "pid": 9}
    reporting(db, "box", document(listening=[SSHD, conmon], podman=[two]))
    groups = groups_of(services_of(db))
    assert [(t, w) for t, w, _ in groups] == [("Containers", "podman"), ("Processes", "")]
    (jelly,) = groups[0][2]
    assert "<b>jellyfin</b><small>jellyfin</small>" in jelly
    assert jelly.count('class="spc') == 2
    assert '<span class="sbd">0.0.0.0</span>' in jelly
    assert names_in(groups[1][2]) == ["sshd"]
    assert "conmon" not in services_of(db)


def test_a_container_that_publishes_nothing_is_on_no_row(db):
    reporting(db, "box", document(listening=[SSHD], podman=[dict(JELLYFIN, ports=[])]))
    assert "jellyfin" not in services_of(db)


def test_a_container_without_a_name_is_called_by_its_id(db):
    nameless = dict(JELLYFIN, name="", id="0123456789abcdef")
    reporting(db, "box", document(podman=[nameless]))
    assert "<b>0123456789ab</b>" in services_of(db)


def test_a_socket_unit_is_one_row_named_by_its_service_with_the_socket_file_under_it(db):
    reporting(db, "box", document(listening=[COCKPIT_SOCKET, ROOT_SOCKET],
                                  socket_units=unit_section([COCKPIT_UNIT])))
    groups = groups_of(services_of(db))
    assert [(t, w) for t, w, _ in groups] == [("Socket units", "systemd"), ("Processes", "")]
    (cockpit,) = groups[0][2]
    assert "<b>cockpit</b><small>cockpit.socket</small>" in cockpit
    assert '<span class="sbd">::</span>' in cockpit
    # the undeclared port keeps the measured fallback, under a limited agent
    # the owning user and no pid
    (root,) = groups[1][2]
    assert "<b>user root</b>" in root and "<small>pid" not in root


def test_a_process_on_both_families_is_one_row_with_both_addresses(db):
    reporting(db, "box", document(listening=[SSHD, SSHD6]))
    (rows,) = [g[2] for g in groups_of(services_of(db)) if g[0] == "Processes"]
    assert names_in(rows) == ["sshd"]
    assert "<b>sshd</b><small>pid 1</small>" in rows[0]
    assert rows[0].count('class="spc') == 1
    assert '<span class="sbd">0.0.0.0, ::</span>' in rows[0]


def test_two_processes_on_one_port_stay_two_rows(db):
    other = dict(SSHD, process_name="haproxy", pid=7, bind_address="10.0.0.1")
    reporting(db, "box", document(listening=[SSHD, other]))
    (rows,) = [g[2] for g in groups_of(services_of(db)) if g[0] == "Processes"]
    assert names_in(rows) == ["sshd", "haproxy"]


def test_one_process_with_two_ports_is_one_row_with_two_chips(db):
    web = dict(SSHD, process_name="caddy", pid=3, port=443)
    web80 = dict(web, port=80)
    reporting(db, "box", document(listening=[web, web80]))
    (rows,) = [g[2] for g in groups_of(services_of(db)) if g[0] == "Processes"]
    assert names_in(rows) == ["caddy"]
    assert re.findall(r'>(\d+)<small>tcp</small>', rows[0]) == ["80", "443"]


def test_the_chips_carry_the_overviews_state_and_the_worst_one_leads(db):
    web = dict(SSHD, process_name="caddy", pid=3, port=443)
    web80 = dict(web, port=80)
    reporting(db, "box", document(listening=[web, web80]))
    probe_result(db, "box", 443, "v4", "connect_succeeded")
    probe_result(db, "box", 80, "v4", "connect_succeeded")
    declare_intent(db, "box", "tcp", 443, "v4", "closed")
    declare_intent(db, "box", "tcp", 80, "v4", "open")
    (rows,) = [g[2] for g in groups_of(services_of(db)) if g[0] == "Processes"]
    assert re.findall(r'<button class="spc (\w+)" data-row="pr-box-tcp-(\d+)"', rows[0]) == [
        ("fail", "443"), ("ok", "80")]
    # the row's state is the worst of its ports, the fleet's rule
    assert theme.status("fail", "conflict") in rows[0]


def test_a_port_the_engine_has_no_state_for_is_a_grey_chip_and_no_state(db):
    reporting(db, "box", document(listening=[SSHD]))
    (rows,) = [g[2] for g in groups_of(services_of(db)) if g[0] == "Processes"]
    assert '<span class="sst"></span>' in rows[0]
    assert '<button class="spc off" data-row="pr-box-tcp-22"' in rows[0]


def test_a_thing_bound_to_loopback_alone_is_in_the_last_group(db):
    reporting(db, "box", document(listening=[SSHD, LOOP]))
    groups = groups_of(services_of(db))
    assert [t for t, _, _ in groups] == ["Processes", "Loopback only"]
    assert names_in(groups[1][2]) == ["chronyd"]
    assert "<b>chronyd</b><small>pid 2</small>" in groups[1][2][0]
    assert '<span class="sbd">127.0.0.1</span>' in groups[1][2][0]
    # a thing on loopback and on a public address is a process
    both = dict(SSHD, process_name="chronyd", pid=2, port=323, protocol="udp")
    reporting(db, "two", document(listening=[both, LOOP]))
    groups = groups_of(services_of(db, "two"))
    assert [t for t, _, _ in groups] == ["Processes"]


def test_every_chip_names_a_row_the_overview_has(db):
    reporting(db, "box", document(listening=[SSHD, SSHD6, LOOP], podman=[JELLYFIN]))
    section = host_section(rl.render(db, now=NOW), "box")
    services = tab_body(section, "box", "services")
    overview = tab_body(section, "box", "overview")
    rows = re.findall(r'data-row="([^"]+)"', services)
    assert rows and all(f'id="{r}"' in overview for r in rows)
    assert all(t == "tb-box-overview" for t in re.findall(r'data-tab="([^"]+)"', services))


def test_a_declared_name_shows_in_what_runs_and_the_measured_name_stays(db):
    reporting(db, "box", document(listening=[SSHD]))
    declare_name(db, "box", "tcp", 22, "ssh for the admins")
    services = services_of(db)
    assert ('<b>sshd</b><span class="sdn" title="named by you">ssh for the admins</span>'
            in services)
    assert "unsure" not in services


def test_overlays_are_not_a_group_on_this_tab(db):
    """They were a fifth group under a marker asking where they belong, since
    the spec has four. The owner, 2026-09-10: the overlays can go."""
    doc = document(listening=[SSHD])
    doc["overlays"] = {"status": "collected",
                       "interfaces": [{"name": "wg0", "type": "65534", "devtype": "wireguard"}],
                       "tailscale": {"socket": False}}
    reporting(db, "box", doc)
    services = services_of(db)
    assert "Overlays" not in services and "wg0" not in services


def test_an_unreadable_overlays_section_does_not_reach_this_tab_either(db):
    doc = document(listening=[SSHD])
    doc["overlays"] = {"status": "collected", "tailscale": "yes"}
    reporting(db, "box", doc)
    services = services_of(db)
    assert "Overlays" not in services and "overlay interfaces" not in services


def test_a_host_with_no_overlays_has_no_overlays_group(db):
    reporting(db, "box", document(listening=[SSHD]))
    assert "Overlays" not in services_of(db)


def test_nothing_listening_is_the_header_and_one_line(db):
    reporting(db, "box", document(listening=[]))
    services = services_of(db)
    assert build.NOTHING_LISTENING in services
    assert 'class="sgh' not in services


def test_unreadable_sockets_say_so(db):
    doc = document(listening=[])
    doc["sockets"] = {"status": "not_readable", "cause": "permission"}
    reporting(db, "box", doc)
    assert build.SOCKETS_UNREADABLE in services_of(db)


def test_the_tab_spends_no_green_on_a_measurement(db):
    """docs/DESIGN.md section 3: ok is `intended` alone."""
    reporting(db, "box", document(listening=[SSHD, LOOP], podman=[JELLYFIN]))
    services = services_of(db)
    assert 'class="st ok"' not in services and 'class="spc ok"' not in services


def test_the_tab_claims_nothing_about_reachability_without_a_measurement(db):
    reporting(db, "box", document(listening=[SSHD, LOOP], podman=[JELLYFIN]))
    services = services_of(db)
    for claim in ("reachable", "allowed", "blocked", "permitted", "open to the internet"):
        assert claim not in services, claim


# ---------------------------------------------------------- in the browser

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>services drive</title>
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
    d.getElementById('tb-box-services').click(); await tick();
    result.tabBefore=d.getElementById('tb-box-services').checked;
    result.rowBefore=d.getElementById('pr-box-tcp-22').checked;
    d.querySelector('#host-box .stbl [data-row="pr-box-tcp-22"]').click(); await tick();
    result.tabAfter=d.getElementById('tb-box-overview').checked;
    result.rowAfter=d.getElementById('pr-box-tcp-22').checked;
    out.textContent=JSON.stringify(result);
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
};
f.src='live.html';
</script>
"""


def test_a_chip_opens_the_ports_row_on_the_overview(tmp_path, db):
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
    assert (result["tabBefore"], result["rowBefore"]) == (True, False)
    assert (result["tabAfter"], result["rowAfter"]) == (True, True)


# ------------------------------------- the unit the kernel names, since 0.1.10
#
# Agent 0.1.10 holds no permission to read process names or pids and sends,
# on every listening socket, the systemd unit the kernel names for it and the
# cgroup path behind it (docs/PRODUCT.md, the sockets section; docs/RECORD.md
# 4.172). Until 2026-09-16 nothing read either field and every host on the
# fleet read "user caddy" and "user root". These are the first tests that
# render a document of that shape.

def kernel_socket(port, unit="", owner="root", uid=0, family="v4",
                  bind="0.0.0.0", protocol="tcp", cgroup=None, **extra):
    """One listening socket as 0.1.10 sends it: an owner and, where the
    kernel named one, a unit and its cgroup path. No process name, no pid."""
    s = {"protocol": protocol, "family": family, "bind_address": bind, "port": port,
         "owner_uid": uid, "owner_name": owner}
    if unit:
        s["unit"] = unit
        s["cgroup"] = cgroup or f"/system.slice/{unit}"
    elif cgroup:
        s["cgroup"] = cgroup
    s.update(extra)
    return s


def kernel_document(listening, **kw):
    """A 0.1.10 document: the sockets section carries the two new source
    verdicts beside the four tables and passwd."""
    doc = document(listening=listening, **kw)
    doc["sockets"]["sources"] = {
        name: {"status": "collected"}
        for name in ("tcp", "tcp6", "udp", "udp6", "passwd", "sock_diag", "cgroup2")}
    return doc


PROD_0110 = [
    kernel_socket(22, "ssh.socket"),
    kernel_socket(22, "ssh.socket", family="v6", bind="::"),
    kernel_socket(80, "caddy.service", owner="caddy", uid=999),
    kernel_socket(443, "caddy.service", owner="caddy", uid=999),
    kernel_socket(2019, "caddy.service", owner="caddy", uid=999, bind="127.0.0.1"),
    kernel_socket(8410, "whichports-ingest.service", owner="deploy", uid=1001, bind="127.0.0.1"),
    kernel_socket(53, "systemd-resolved.service", owner="systemd-resolve", uid=990,
                  bind="127.0.0.53"),
]


def test_a_unit_the_kernel_named_is_the_row_with_the_unit_under_it(db):
    reporting(db, "box", kernel_document(PROD_0110))
    html = services_of(db)
    groups = groups_of(html)
    assert [(t, w) for t, w, _ in groups] == [("Processes", ""), ("Loopback only", "")]
    # a row is a thing that runs: caddy's admin port on loopback rides on
    # caddy's row, and only a thing bound to loopback alone is in that group
    assert names_in(groups[0][2]) == ["ssh", "caddy"]
    assert names_in(groups[1][2]) == ["whichports-ingest", "systemd-resolved"]
    ssh, caddy = groups[0][2]
    assert "<b>ssh</b><small>ssh.socket</small>" in ssh
    assert '<span class="sbd">0.0.0.0, ::</span>' in ssh
    assert "<b>caddy</b><small>caddy.service</small>" in caddy
    assert caddy.count('class="spc') == 3          # 80, 443 and 2019, one row
    assert '<span class="sbd">0.0.0.0, 127.0.0.1</span>' in caddy
    # nothing says user or uid, nothing guesses a pid
    assert "user " not in html and "uid " not in html and "pid " not in html


def test_two_root_sockets_of_two_units_are_two_rows(db):
    reporting(db, "box", kernel_document([
        kernel_socket(22, "ssh.socket"), kernel_socket(323, "chrony.service", protocol="udp")]))
    (procs,) = groups_of(services_of(db))
    assert names_in(procs[2]) == ["ssh", "chrony"]


def test_docker_service_is_never_the_name_and_a_scope_never_the_service(db):
    """docker.service is what the kernel says for every published port, and
    the container names it; a .scope is a session. Both stay under the row as
    what the kernel said, and the row is named by its owner (docs/PRODUCT.md,
    the sockets section)."""
    reporting(db, "box", kernel_document([
        kernel_socket(2375, "docker.service"),
        kernel_socket(8096, "session-24.scope", cgroup="/user.slice/user-0.slice/session-24.scope"),
        kernel_socket(9000, "system.slice", cgroup="/system.slice"),
    ]))
    (procs,) = groups_of(services_of(db))
    rows = procs[2]
    assert names_in(rows) == ["user root", "user root", "user root"]
    assert "<b>user root</b><small>docker.service</small>" in rows[0]
    assert "<b>user root</b><small>session-24.scope</small>" in rows[1]
    assert "<b>user root</b><small>system.slice</small>" in rows[2]
    assert "<b>docker</b>" not in "".join(rows) and "<b>session-24</b>" not in "".join(rows)


def test_a_published_port_is_the_containers_row_and_not_dockers(db):
    """The socket docker.service holds for a published port is the container's
    row, as before; nothing named docker appears."""
    nginx = {"id": "0123456789abcdef", "name": "web", "image": "nginx:alpine",
             "ports": [{"host_ip": "0.0.0.0", "host_port": 18099, "container_port": 80,
                        "protocol": "tcp"}]}
    reporting(db, "box", kernel_document([
        kernel_socket(18099, "docker.service"), kernel_socket(22, "ssh.socket")], podman=[nginx]))
    html = services_of(db)
    groups = groups_of(html)
    assert [(t, w) for t, w, _ in groups] == [("Containers", "podman"), ("Processes", "")]
    assert names_in(groups[0][2]) == ["web"] and names_in(groups[1][2]) == ["ssh"]
    assert "docker" not in html


def test_where_the_kernel_named_nothing_the_row_says_the_user_and_guesses_nothing(db):
    """A kernel before 5.8, or no cgroup v2: no unit and no cgroup on the
    socket. The row is the owner, with nothing under it."""
    reporting(db, "box", kernel_document([kernel_socket(22), kernel_socket(80, owner="caddy", uid=999)]))
    (procs,) = groups_of(services_of(db))
    assert names_in(procs[2]) == ["user root", "user caddy"]
    # nothing under the name: no unit, no pid, no guess
    assert '<span class="snm"><b>user root</b></span>' in procs[2][0]
    assert '<span class="snm"><b>user caddy</b></span>' in procs[2][1]


def test_a_process_name_stays_the_name_and_the_unit_goes_under_it(db):
    """A document with both, a root agent or an older widened one: the
    measured process is the name, the unit the mono fact, which is the
    spec's line for a process that has one."""
    reporting(db, "box", kernel_document([
        kernel_socket(80, "caddy.service", owner="caddy", uid=999, process_name="caddy", pid=41)]))
    (procs,) = groups_of(services_of(db))
    assert "<b>caddy</b><small>caddy.service</small>" in procs[2][0]
    assert "pid 41" not in procs[2][0]


def test_a_socket_unit_file_still_wins_its_group_and_the_kernel_agrees(db):
    """The socket_units section names cockpit's port from its unit file, and
    the kernel names the same socket cockpit.socket. The row stays in Socket
    units, once, and the undeclared socket takes the kernel's unit."""
    cockpit = kernel_socket(9090, "cockpit.socket", family="v6", bind="::")
    reporting(db, "box", kernel_document([cockpit, kernel_socket(8080, "tailscaled.service")],
                                         socket_units=unit_section([COCKPIT_UNIT])))
    groups = groups_of(services_of(db))
    assert [(t, w) for t, w, _ in groups] == [("Socket units", "systemd"), ("Processes", "")]
    assert "<b>cockpit</b><small>cockpit.socket</small>" in groups[0][2][0]
    assert "<b>tailscaled</b><small>tailscaled.service</small>" in groups[1][2][0]


def test_the_overview_names_the_port_by_the_same_unit(db):
    """One namer for both tabs (test_render_live.py): the Overview's row for
    port 443 says caddy, never user caddy, on a 0.1.10 document."""
    reporting(db, "box", kernel_document(PROD_0110))
    overview = tab_body(host_section(rl.render(db, now=NOW), "box"), "box", "overview")
    assert "caddy" in overview and "user caddy" not in overview and "user root" not in overview


def test_a_unit_that_is_not_a_string_names_nothing():
    assert rl.socket_holder({"unit": 7, "owner_name": "root"}) == "user root"
    assert rl.socket_fact({"unit": 7}) == ""
    assert rl.socket_holder({"unit": "", "owner_uid": 3}) == "uid 3"
    assert rl.unit_names_the_service("caddy.service") is True
    assert rl.unit_names_the_service("ssh.socket") is True
    for unit in ("docker.service", "session-24.scope", "system.slice", "", None, "caddy"):
        assert rl.unit_names_the_service(unit) is False, unit


# ------------------------------------- the same name on Evidence and the opened row
#
# The owner, 2026-09-20, on the first outside server: the Services tab named
# the services that were running and Evidence named none. Evidence and
# the Overview's opened row read only `process_name`, which agent 0.1.10 never
# sends, while this tab read the unit. One document, one name, on all three.

def test_evidence_names_a_socket_the_way_this_tab_does(db):
    reporting(db, "box", kernel_document(PROD_0110))
    html = rl.render(db, now=NOW)
    evidence = html[html.index('id="t-box-evidence"'):]
    evidence = evidence[:evidence.index('id="t-box-changes"')]
    for name in ("ssh", "caddy", "whichports-ingest", "systemd-resolved"):
        assert f'<span class="msv">{name}</span>' in evidence, name


def test_the_opened_row_names_the_socket_and_never_says_unnamed(db):
    reporting(db, "box", kernel_document(PROD_0110))
    html = rl.render(db, now=NOW)
    overview = html[html.index('id="t-box-overview"'):html.index('id="t-box-services"')]
    assert "an unnamed process" not in overview
    assert '<b class="mono">ssh</b> listens on' in overview
    assert '<b class="mono">caddy</b> listens on' in overview


def test_a_socket_with_an_owner_and_no_unit_says_the_user_on_all_three(db):
    reporting(db, "box", kernel_document([kernel_socket(25, owner="postfix", uid=105)]))
    html = rl.render(db, now=NOW)
    overview = html[html.index('id="t-box-overview"'):html.index('id="t-box-services"')]
    assert '<b class="mono">user postfix</b> listens on' in overview
    evidence = html[html.index('id="t-box-evidence"'):]
    assert '<span class="msv">user postfix</span>' in evidence


def test_a_socket_nothing_names_is_called_the_same_on_its_row_and_its_card(db):
    """The row says `unknown process`, so the card under it does too. It said
    "an unnamed process" there while the row above it said something else."""
    reporting(db, "box", document(listening=[
        {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 25}]))
    html = rl.render(db, now=NOW)
    overview = html[html.index('id="t-box-overview"'):html.index('id="t-box-services"')]
    assert '<b class="mono">unknown process</b> listens on' in overview
    assert "an unnamed process" not in overview


# ------------------------------------ a socket unit file that holds no socket
#
# The first big server test (docs/RECORD.md 4.213, 4.220): on three
# distributions sshd ran as its own service, the package also shipped a socket
# unit file declaring port 22, and this tab filed port 22 under Socket units
# from that file, named after the file's service. The kernel says whose a
# listening socket is: one systemd holds for a socket unit is reported under
# that socket unit, and one a service opened itself under the service
# (measured, docs/RECORD.md 4.326). A file is asked only about a socket the
# kernel does not give to somebody else.
#
# The two sockets and the unit file below are as the agent on a Fedora 44 test
# server stored them on 2026-10-03, field for field.

SSHD_ON_22 = [
    {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 22,
     "owner_uid": 0, "owner_name": "root",
     "cgroup": "/system.slice/sshd.service", "unit": "sshd.service"},
    {"protocol": "tcp", "family": "v6", "bind_address": "::", "port": 22,
     "owner_uid": 0, "owner_name": "root",
     "cgroup": "/system.slice/sshd.service", "unit": "sshd.service"},
]

SSHD_SOCKET_FILE = {
    "name": "sshd.socket", "file": "/usr/lib/systemd/system/sshd.socket",
    "origin": "vendor", "source": "usr_lib_systemd_system", "parsed": True,
    "socket_section": True, "description": "OpenSSH Server Socket",
    "listen": [{"directive": "ListenStream", "value": "22", "kind": "port_only",
                "address_specified": False, "port": 22}],
    "service_unit": "sshd@.service", "service_source": "implied", "accept": "yes",
}


def overview_of(db, name="box"):
    return tab_body(host_section(rl.render(db, now=NOW), name), name, "overview")


@pytest.mark.parametrize("socket,unit_file,own", [
    # the kernel gives the socket to the socket unit: the file names it
    ({"unit": "cockpit.socket"}, "cockpit.socket", True),
    # the kernel gives it to a service, the file's own or another: it does not
    ({"unit": "sshd.service"}, "sshd.socket", False),
    ({"unit": "cockpit.service"}, "cockpit.socket", False),
    # another socket unit's, a session's, docker's
    ({"unit": "console.socket"}, "cockpit.socket", False),
    ({"unit": "session-24.scope"}, "cockpit.socket", False),
    ({"unit": "docker.service"}, "cockpit.socket", False),
    # the kernel named nothing, or the field holds what is not a name: the
    # file is all there is, as on a kernel before 5.8
    ({}, "cockpit.socket", True),
    ({"unit": ""}, "cockpit.socket", True),
    ({"unit": None}, "cockpit.socket", True),
    ({"unit": 7}, "cockpit.socket", True),
])
def test_a_file_names_a_socket_only_while_the_kernel_gives_it_to_nobody_else(
        socket, unit_file, own):
    assert rl.socket_is_units_own(socket, unit_file) is own


def test_a_socket_unit_file_that_holds_no_socket_does_not_claim_the_services_port(db):
    reporting(db, "box", kernel_document(SSHD_ON_22,
                                         socket_units=unit_section([SSHD_SOCKET_FILE])))
    html = services_of(db)
    groups = groups_of(html)
    assert [(t, w) for t, w, _ in groups] == [("Processes", "")]
    (sshd,) = groups[0][2]
    assert "<b>sshd</b><small>sshd.service</small>" in sshd
    assert '<span class="sbd">0.0.0.0, ::</span>' in sshd
    assert "Socket units" not in html
    assert "sshd@" not in html and "sshd.socket" not in html


def test_the_overview_names_that_port_by_the_service_the_kernel_named(db):
    """One namer for both tabs: the Overview said sshd@.service, declared by
    sshd.socket, for the same two sockets."""
    reporting(db, "box", kernel_document(SSHD_ON_22,
                                         socket_units=unit_section([SSHD_SOCKET_FILE])))
    overview = overview_of(db)
    assert "sshd@" not in overview and "declared by" not in overview
    assert '<b class="mono">sshd</b> listens on' in overview


def test_a_service_that_listens_beside_its_own_idle_socket_unit_is_a_process(db):
    """The second sighting, Debian 13: the kernel names ssh.service for both
    sockets on 22, and ssh.socket is on disk, inactive, declaring 22 for the
    same ssh.service. The shape of that document, written from the test's
    notes and not captured."""
    ssh = [kernel_socket(22, "ssh.service"),
           kernel_socket(22, "ssh.service", family="v6", bind="::")]
    ssh_socket = dict(SSHD_SOCKET_FILE, name="ssh.socket",
                      file="/usr/lib/systemd/system/ssh.socket",
                      service_unit="ssh.service", accept="no")
    reporting(db, "box", kernel_document(ssh, socket_units=unit_section([ssh_socket])))
    html = services_of(db)
    groups = groups_of(html)
    assert [(t, w) for t, w, _ in groups] == [("Processes", "")]
    assert "<b>ssh</b><small>ssh.service</small>" in groups[0][2][0]
    assert "ssh.socket" not in html
    assert "declared by" not in overview_of(db)


def test_one_port_a_socket_unit_holds_and_another_service_listens_on_is_two_rows(db):
    """Each socket is asked for itself. The one the kernel gives to the socket
    unit is the unit's row, and the one another service opened on the same
    port, on an address of its own, is that service's."""
    held = kernel_socket(9090, "cockpit.socket", family="v6", bind="::")
    other = kernel_socket(9090, "haproxy.service", owner="haproxy", uid=188, bind="10.0.0.1")
    reporting(db, "box", kernel_document([held, other],
                                         socket_units=unit_section([COCKPIT_UNIT])))
    groups = groups_of(services_of(db))
    assert [(t, w) for t, w, _ in groups] == [("Socket units", "systemd"), ("Processes", "")]
    assert "<b>cockpit</b><small>cockpit.socket</small>" in groups[0][2][0]
    assert '<span class="sbd">::</span>' in groups[0][2][0]
    assert "<b>haproxy</b><small>haproxy.service</small>" in groups[1][2][0]
    assert '<span class="sbd">10.0.0.1</span>' in groups[1][2][0]
    # The Overview has one row for the port. The file cannot name it for both
    # sockets, so each is named by the unit the kernel gave it.
    overview = overview_of(db)
    assert "declared by" not in overview
    assert "cockpit and haproxy" in overview


def test_a_socket_another_socket_unit_holds_is_not_this_files(db):
    """Two unit files, one port in one of them, and the kernel names the
    other unit for the socket: the file that declares the port holds
    nothing."""
    reporting(db, "box", kernel_document(
        [kernel_socket(9090, "console.socket", family="v6", bind="::")],
        socket_units=unit_section([COCKPIT_UNIT])))
    html = services_of(db)
    groups = groups_of(html)
    assert [(t, w) for t, w, _ in groups] == [("Processes", "")]
    assert "<b>console</b><small>console.socket</small>" in groups[0][2][0]
    assert "cockpit" not in html


# ------------------------------ sockets only their owner names, one row a port
#
# The first big server test, on a Rocky 8 server (docs/RECORD.md 4.220). Its
# kernel is 4.18, which names no unit for a socket, and the agent reads no
# process name and no pid. All that names such a socket is its owner, and the
# tab made one row of everything root owned: sshd, a test listener and a
# loopback service read as one "user root" bound to 0.0.0.0, ::, 127.0.0.1
# and ::1. An owner is not a thing that runs, so those sockets are one row a
# port, the Overview's own unit.
#
# The sockets below are that server's, port for port and address for address,
# written from the test's stored list of them and the rows the tab drew. The
# document itself was not kept.

ROCKY_8 = [
    kernel_socket(22), kernel_socket(22, family="v6", bind="::"),
    kernel_socket(6000), kernel_socket(6000, family="v6", bind="::"),
    kernel_socket(6001, owner="", uid=62638),
    kernel_socket(6001, owner="", uid=62638, family="v6", bind="::"),
    kernel_socket(323, protocol="udp", bind="127.0.0.1"),
    kernel_socket(323, protocol="udp", family="v6", bind="::1"),
]


def rows_of(db, title, name="box"):
    """The rows of one group as (name, chips, bound to), or [] without it."""
    found = [g[2] for g in groups_of(services_of(db, name)) if g[0] == title]
    return [(names_in([r])[0],
             re.findall(r'>(\d+)<small>(\w+)</small>', r),
             re.search(r'<span class="sbd">([^<]*)</span>', r).group(1))
            for r in (found[0] if found else [])]


def test_a_loopback_socket_is_not_pulled_into_a_row_with_a_public_one(db):
    """The worst of the blob: 323/udp listens on loopback alone and stood on a
    row bound to 0.0.0.0, outside its own group."""
    reporting(db, "box", kernel_document(ROCKY_8))
    assert rows_of(db, "Loopback only") == [
        ("user root", [("323", "udp")], "127.0.0.1, ::1")]
    for _name, _chips, bound in rows_of(db, "Processes"):
        assert "127.0.0.1" not in bound and "::1" not in bound, bound


def test_sockets_only_their_owner_names_are_one_row_a_port(db):
    reporting(db, "box", kernel_document(ROCKY_8))
    assert rows_of(db, "Processes") == [
        ("user root", [("22", "tcp")], "0.0.0.0, ::"),
        ("user root", [("6000", "tcp")], "0.0.0.0, ::"),
        ("uid 62638", [("6001", "tcp")], "0.0.0.0, ::"),
    ]
    # nothing is put under the name that nobody measured
    html = services_of(db)
    assert "<small>" not in "".join(re.findall(r'<span class="snm">.*?</span>', html))


def test_the_same_number_on_tcp_and_udp_is_two_rows_as_on_the_overview(db):
    """The Overview has a row for 53/tcp and one for 53/udp, and nothing in
    the document says one program holds both."""
    reporting(db, "box", kernel_document([
        kernel_socket(53, owner="named", uid=25),
        kernel_socket(53, owner="named", uid=25, protocol="udp")]))
    assert rows_of(db, "Processes") == [
        ("user named", [("53", "tcp")], "0.0.0.0"),
        ("user named", [("53", "udp")], "0.0.0.0")]


def test_sockets_nothing_names_at_all_are_one_row_a_port_too(db):
    bare = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 25}
    reporting(db, "box", document(listening=[bare, dict(bare, port=587)]))
    assert rows_of(db, "Processes") == [
        ("unknown process", [("25", "tcp")], "0.0.0.0"),
        ("unknown process", [("587", "tcp")], "0.0.0.0")]


def test_a_pid_or_a_unit_still_makes_two_ports_one_row(db):
    """Where something does say two sockets are one thing, they stay one row:
    a pid from an agent that reads one, a service unit from the kernel, and a
    session's scope, which is what the kernel said."""
    with_pid = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
                "owner_uid": 0, "owner_name": "root", "pid": 812}
    reporting(db, "box", kernel_document([
        dict(with_pid, port=8080), dict(with_pid, port=8443),
        kernel_socket(80, "caddy.service", owner="caddy", uid=999),
        kernel_socket(443, "caddy.service", owner="caddy", uid=999),
        kernel_socket(7000, "session-3.scope", cgroup="/user.slice/user-0.slice/session-3.scope"),
        kernel_socket(7001, "session-3.scope", cgroup="/user.slice/user-0.slice/session-3.scope"),
    ]))
    assert rows_of(db, "Processes") == [
        ("user root", [("8080", "tcp"), ("8443", "tcp")], "0.0.0.0"),
        ("caddy", [("80", "tcp"), ("443", "tcp")], "0.0.0.0"),
        ("user root", [("7000", "tcp"), ("7001", "tcp")], "0.0.0.0"),
    ]


def test_every_chip_of_those_rows_names_a_row_the_overview_has(db):
    reporting(db, "box", kernel_document(ROCKY_8))
    section = host_section(rl.render(db, now=NOW), "box")
    chips = re.findall(r'data-row="([^"]+)"', tab_body(section, "box", "services"))
    overview = tab_body(section, "box", "overview")
    assert sorted(chips) == ["pr-box-tcp-22", "pr-box-tcp-6000", "pr-box-tcp-6001",
                             "pr-box-udp-323"]
    assert all(f'id="{chip}"' in overview for chip in chips)


# ----------------------- a socket unit nothing enabled names no port of its own
#
# The second big test, 2026-10-25, case C8, on Rocky Linux 8.10 (kernel
# 4.18, which names no unit for a socket): sshd.service held 22, and
# sshd.socket was on disk, inactive and disabled, declaring ListenStream=22
# with Accept=yes. With no unit from the kernel the file was all there was,
# and both tabs named 22 "sshd@" under Socket units, a template nothing ran.
# Where the kernel names no unit, a socket unit file names a socket only when
# something enabled it: a link to it in a .wants or .requires directory, the
# agent's enable_links. A file nothing enabled claims nothing.

ENABLED_BY = ["/etc/systemd/system/sockets.target.wants/sshd.socket"]


def test_a_disabled_socket_unit_names_no_socket_the_kernel_gave_nobody(db):
    reporting(db, "box", kernel_document(ROCKY_8[:2],
                                         socket_units=unit_section([SSHD_SOCKET_FILE])))
    html = services_of(db)
    assert [(t, w) for t, w, _ in groups_of(html)] == [("Processes", "")]
    assert rows_of(db, "Processes") == [("user root", [("22", "tcp")], "0.0.0.0, ::")]
    assert "sshd@" not in html and "Socket units" not in html
    overview = overview_of(db)
    assert "sshd@" not in overview and "declared by" not in overview


def test_an_enabled_socket_unit_still_names_it_where_the_kernel_names_nothing(db):
    enabled = dict(SSHD_SOCKET_FILE, enable_links=ENABLED_BY)
    reporting(db, "box", kernel_document(ROCKY_8[:2], socket_units=unit_section([enabled])))
    groups = groups_of(services_of(db))
    assert [(t, w) for t, w, _ in groups] == [("Socket units", "systemd")]
    assert "<b>sshd@</b><small>sshd.socket</small>" in groups[0][2][0]


@pytest.mark.parametrize("socket,unit_file,enabled,own", [
    ({}, "sshd.socket", False, False),
    ({}, "sshd.socket", True, True),
    # what the kernel says is not changed by what is enabled
    ({"unit": "sshd.socket"}, "sshd.socket", False, True),
    ({"unit": "sshd.service"}, "sshd.socket", True, False),
])
def test_with_no_unit_from_the_kernel_only_an_enabled_file_names_a_socket(
        socket, unit_file, enabled, own):
    assert rl.socket_is_units_own(socket, unit_file, enabled) is own
