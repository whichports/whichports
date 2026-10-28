"""The CVE check on a port's row: the card's strip and the check's own mark.

    python -m pytest app/test_cve_card.py      (from site/)

`docs/SPEC-cve-check.md`, sections 3 and 8.1. The lines and the mark's words
come from the control plane (`controlplane/app/cvecard.py`). This file holds
how the page draws them: the strip under a port's two family cards, as it
was drawn for the owner's look on 2026-10-07 (docs/RECORD.md 4.437), and a
mark of the check's own that is not the warn triangle and does not count
under Needs a decision (4.446).
"""
import html as htmllib
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import joinbridge  # noqa: E402
import render_live as rl  # noqa: E402
import test_rarely_public_mark as trm  # noqa: E402
import test_render_live as trl  # noqa: E402
from test_render_live import db  # noqa: E402,F401  (the empty database fixture)

IDS = ("CVE-2025-00001", "CVE-2025-00002")
DRAWN = (("installed", "openssh-server 1:9.2p1-2+deb12u3", "", ()),
         ("update fixes", "2 CVEs", "", IDS),
         ("update to", "1:9.2p1-2+deb12u10", "in this server's package lists", ()),
         ("data of", "Debian security tracker, 2026-10-03 14:07 UTC", "", ()))
NOT_CHECKED = (("installed", "mariadb-server 1:11.4.13+maria~deb12", "not the distribution's package", ()),
               ("update fixes", "not checked", "", ()))
MARK = "an update fixes 2 CVEs"


def text(html):
    """What a reader sees: the tags out, the entities read."""
    return re.sub(r"\s+", " ", htmllib.unescape(re.sub(r"<[^>]+>", " ", html))).strip()


def row(**more):
    fields = dict(protocol="tcp", port=22, word="intended", tone="ok", service="sshd")
    fields.update(more)
    return build.PortRow(**fields)


# ------------------------------------------------------------- the strip

def test_a_port_with_no_card_draws_no_strip():
    assert build.cve_card_html(()) == ""
    assert "prpk" not in build.port_row_html("web-07", row())


def test_the_strip_holds_each_line_as_a_label_and_its_value():
    html = build.cve_card_html(DRAWN)
    assert html.startswith('<div class="prec prpk">') and html.endswith("</div>")
    assert re.findall(r'<span class="k">([^<]*)</span>', html) == ["installed", "update fixes", "update to", "data of"]
    assert text(html) == ("installed openssh-server 1:9.2p1-2+deb12u3 update fixes 2 CVEs CVE-2025-00001 "
                          "CVE-2025-00002 update to 1:9.2p1-2+deb12u10 · in this server's package lists "
                          "data of Debian security tracker, 2026-10-03 14:07 UTC")


def test_a_package_a_version_and_a_cve_id_are_in_mono_and_words_are_not():
    html = build.cve_card_html(DRAWN + NOT_CHECKED)
    mono = re.findall(r'<b class="mono">([^<]*)</b>', html)
    assert mono == ["openssh-server 1:9.2p1-2+deb12u3", *IDS, "1:9.2p1-2+deb12u10",
                    "mariadb-server 1:11.4.13+maria~deb12"]
    seen = htmllib.unescape(html)
    for words in ("2 CVEs", "in this server's package lists", "not checked", "not the distribution's package"):
        assert words in seen and f'<b class="mono">{words}' not in seen


def test_where_no_package_is_named_the_first_line_is_words():
    for words in ("package not determined", "unknown"):
        html = build.cve_card_html((("installed", words, "", ()), ("update fixes", "not checked", "", ())))
        assert "mono" not in html and text(html) == f"installed {words} update fixes not checked"


def test_what_a_server_sent_is_escaped():
    """A package's name and version are text out of a server's report."""
    html = build.cve_card_html((("installed", "<b>x</b> 1.0&2", '"note"', ("<i>id</i>",)),))
    assert "<b>x</b>" not in html and "<i>id</i>" not in html
    assert "&lt;b&gt;x&lt;/b&gt; 1.0&amp;2" in html and "&lt;i&gt;id&lt;/i&gt;" in html


def test_the_strip_stands_under_the_family_cards_and_over_the_dismiss_line():
    html = build.port_row_html("web-07", row(cve_lines=DRAWN, rare_mark="shown", rarely=True,
                                             cards=(("v4", "ok", "reachable", ()),)))
    opened = html[html.index('<div class="pre">'):]
    assert opened.index('class="preh"') < opened.index("prpk") < opened.index("prmk")


# -------------------------------------------------------------- the mark

def test_the_checks_mark_is_its_own_and_not_the_warn_triangle():
    assert build.fix_flag("") == ""
    mark = build.fix_flag(MARK)
    assert mark == f'<span class="tag-fix" title="{MARK}">{MARK}</span>'
    assert "tag-rare" not in mark


def test_a_port_with_the_mark_carries_it_beside_its_state():
    html = build.port_row_html("web-07", row(cve_lines=DRAWN, cve_mark=MARK))
    state = html[html.index('<span class="prst">'):html.index('<span class="prn">')]
    assert build.fix_flag(MARK) in state and "tag-rare" not in state


def test_the_checks_mark_alone_does_not_count_under_needs_a_decision():
    """The page's script counts a row under Needs a decision by this
    attribute. The triangle sets it, the check's own mark never does."""
    assert "data-rare-counts" not in build.port_row_html("web-07", row(cve_lines=DRAWN, cve_mark=MARK))
    both = build.port_row_html("web-07", row(cve_lines=DRAWN, cve_mark=MARK, rare_mark="shown", rarely=True))
    assert 'data-rare-counts="1"' in both and build.fix_flag(MARK) in both and "tag-rare" in both


def test_a_server_carries_the_mark_beside_its_state_and_its_other_marks():
    marks = build.state_marks_html("web-07", "watched", False, False, rarely=True, fix="a newer version fixes 29 CVEs")
    assert marks.index("tag-rare") < marks.index("tag-fix")
    assert build.state_marks_html("web-07", "watched", False, False) == build.state_marks_html(
        "web-07", "watched", False, False, fix="")


def test_the_mark_is_a_slim_mark_in_the_neutral_tone_with_an_icon_of_its_own():
    page = build.CSS

    def rule(selector):
        return re.search(re.escape(selector) + r"\{([^}]*)\}", page).group(1)

    # The same slim box and the same place for the icon as the four marks
    # before it, declaration for declaration.
    shared = ".tag-alert,.tag-mute,.tag-rate,.tag-rare"
    assert rule(".tag-fix{display:inline-block"[:8]) is not None
    boxes = re.findall(r"\.tag-fix\{(display:inline-block;[^}]*)\}", page)
    assert boxes == [rule(shared)]
    assert rule(".tag-fix::before") == rule(",".join(s + "::before" for s in shared.split(",")))
    assert ".tag-fix" in build.MARK_ICONS and build.MARK_ICONS[".tag-fix"] != build.MARK_ICONS[".tag-rare"]
    # Neutral: the faint ink and the plain line, never the warn or fail tone.
    own = "".join(re.findall(r"\.tag-fix\{[^}]*\}", page))
    assert "color:var(--faint)" in own and "var(--warn)" not in own and "var(--fail)" not in own


# ---------------------------------------------------------- the live page
#
# A server made up for the tests: OpenSSH behind on its updates, with the fix
# in the server's own lists, nginx whose fix the lists do not offer, MariaDB
# from MariaDB's own archive, and a port no unit stands behind.

def listening(port, program, unit):
    sock = trm.sock(port, program)
    sock.update(unit=unit, cgroup="/system.slice/" + unit)
    return sock


def owner(name, version, source=""):
    out = {"name": name, "architecture": "arm64", "installed": True, "version": version}
    if source:
        out["source"] = source
    return out


def unit(name, program, package):
    return {"unit": name, "finding": "complete", "program_kind": "elf",
            "unit_file": {"path": "/usr/lib/systemd/system/" + name, "owners": [package]},
            "program": {"path": program, "owners": [package]}}


def offer(version, archive="debian"):
    return {"version": version, "archive": archive, "not_automatic": False, "but_automatic_upgrades": False}


def offers(name, *offered, other=False, other_installed=False):
    return {"name": name, "offered": list(offered), "other_offers": other, "other_offers_installed": other_installed}


def packages():
    return {"status": "collected",
            "sources": {"dpkg_info": {"status": "collected"}, "apt_lists": {"status": "collected"}},
            "distribution": {"id": "debian", "version_id": "12", "version_codename": "bookworm"},
            "units": [unit("ssh.service", "/usr/sbin/sshd", owner("openssh-server", "1:9.2p1-2+deb12u3", "openssh")),
                      unit("nginx.service", "/usr/sbin/nginx", owner("nginx", "1.22.1-9")),
                      unit("mariadb.service", "/usr/sbin/mariadbd",
                           owner("mariadb-server", "1:11.4.13+maria~deb12", "mariadb"))],
            "offers": [offers("openssh-server", offer("1:9.2p1-2+deb12u10")),
                       offers("nginx", offer("1.22.1-9")),
                       offers("mariadb-server", offer("1:10.11.14-0+deb12u2"), other=True, other_installed=True)]}


def server(db, name="web-07", with_packages=True):
    doc = trl.document(listening=[listening(22, "sshd", "ssh.service"), listening(80, "nginx", "nginx.service"),
                                  listening(3307, "mariadbd", "mariadb.service"), trm.sock(9000, "tool")])
    doc["nftables"] = trm.allow(22, 80, 3307, 9000)
    if with_packages:
        doc["packages"] = packages()
    trl.reporting(db, name, doc)
    for port in (22, 80, 3307, 9000):
        trl.probe_result(db, name, port, "v4", "connect_succeeded")


def extract(db, rows=None, modified="2026-08-13T10:00:00Z", data=None):
    """The release's extract, kept where the control plane keeps it: in a
    folder `cve` beside the database."""
    cveextract = joinbridge.module("cveextract")
    rows = rows if rows is not None else [
        cveextract.Row("openssh", "CVE-2025-00001", "1:9.2p1-2+deb12u5", "low"),
        cveextract.Row("openssh", "CVE-2026-00002", "1:9.2p1-2+deb12u10", "low"),
        cveextract.Row("nginx", "CVE-2026-00003", "1.22.1-9+deb12u10", "low")]
    folder = pathlib.Path(db).parent / "cve"
    folder.mkdir(exist_ok=True)
    kept = data if data is not None else cveextract.dump(rows, "debian", "12", source_modified=modified)
    (folder / "debian-12.tsv.gz").write_bytes(kept)


def strip(html, name, port):
    """The text of one port's strip on one server's page."""
    section = trl.host_section(html, name)
    opened = section.split(f'id="pr-{name}-tcp-{port}"', 1)[1].split('<input type="checkbox" class="prsel"', 1)[0]
    found = re.search(r'<div class="prec prpk">.*?</div></div>', opened, re.S)
    return text(found.group(0)) if found else ""


def test_a_report_with_no_packages_section_draws_nothing_of_the_check(db):
    """Every report of the published agent. Not a strip that says unknown on
    every port of every server."""
    server(db, with_packages=False)
    extract(db)
    page = trm.drawn(rl.render(db, now=trl.NOW))
    assert "prpk" not in page and "tag-fix" not in page


def test_an_ubuntu_cards_data_line_links_its_source_and_its_licence(db):
    """Canonical's terms are CC BY-SA 4.0, which asks for the source and the
    licence with their links (controlplane/app/cvecard.py, ATTRIBUTION)."""
    doc = trl.document(listening=[listening(22, "sshd", "ssh.service")])
    doc["nftables"] = trm.allow(22)
    doc["packages"] = {
        "status": "collected",
        "sources": {"dpkg_info": {"status": "collected"}, "apt_lists": {"status": "collected"}},
        "distribution": {"id": "ubuntu", "version_id": "24.04", "version_codename": "noble"},
        "units": [unit("ssh.service", "/usr/sbin/sshd", owner("openssh-server", "1:9.6p1-3ubuntu13.5", "openssh"))],
        "offers": [offers("openssh-server", offer("1:9.6p1-3ubuntu13.19", "ubuntu"))]}
    trl.reporting(db, "mail-01", doc)
    trl.probe_result(db, "mail-01", 22, "v4", "connect_succeeded")
    cveextract = joinbridge.module("cveextract")
    folder = pathlib.Path(db).parent / "cve"
    folder.mkdir(exist_ok=True)
    (folder / "ubuntu-24.04.tsv.gz").write_bytes(cveextract.dump(
        [cveextract.Row("openssh", "CVE-2026-00005", "1:9.6p1-3ubuntu13.19", "medium")],
        "ubuntu", "24.04", source_modified="2026-08-13T10:00:00Z"))
    server(db)
    extract(db)
    html = rl.render(db, now=trl.NOW)
    ubuntu = opened(html, "mail-01", 22)
    assert ('<a class="src" href="https://security-metadata.canonical.com/osv/" rel="noopener noreferrer"'
            ' target="_blank">Ubuntu security data</a>') in ubuntu
    assert ('<a class="src" href="https://creativecommons.org/licenses/by-sa/4.0/" rel="noopener noreferrer"'
            ' target="_blank">CC BY-SA 4.0</a>') in ubuntu
    # The strip's text puts a blank where a tag ends, and a reader sees none.
    assert re.sub(r"\s+,", ",", strip(html, "mail-01", 22)).endswith(
        "data of Ubuntu security data, 2026-08-13 10:00 UTC · by Canonical, adapted, CC BY-SA 4.0")
    # Debian's card on the same page links nothing.
    assert "<a " not in opened(html, "web-07", 22).split('<div class="prec prpk">')[1].split("</div></div>")[0]


def test_a_link_is_drawn_only_for_the_texts_the_control_plane_gives():
    lines = (("data of", "Ubuntu security data, 2026-08-13 10:00 UTC", "by Canonical, adapted, CC BY-SA 4.0", ()),)
    assert "<a " not in build.cve_card_html(lines)
    linked = build.cve_card_html(lines, (("CC BY-SA 4.0", "https://creativecommons.org/licenses/by-sa/4.0/"),))
    assert linked.count("<a ") == 1
    # A text a server sent is escaped and never made a link.
    sent = (("installed", "<a href=x>pkg</a> 1.0", "", ()),)
    assert "<a href=x>" not in build.cve_card_html(sent, (("pkg", "https://example.com/"),))


def test_the_live_page_draws_each_ports_strip_from_the_report_and_the_data(db):
    server(db)
    extract(db)
    html = rl.render(db, now=trl.NOW)
    assert strip(html, "web-07", 22) == (
        "installed openssh-server 1:9.2p1-2+deb12u3 update fixes 2 CVEs in source package openssh"
        " CVE-2025-00001 CVE-2026-00002 "
        "update to 1:9.2p1-2+deb12u10 · in this server's package lists "
        "data of Debian security tracker, 2026-08-13 10:00 UTC")
    assert strip(html, "web-07", 80) == (
        "installed nginx 1.22.1-9 fixed in 1.22.1-9+deb12u10 · not offered by this server's package lists "
        "it fixes 1 CVE in source package nginx CVE-2026-00003"
        " data of Debian security tracker, 2026-08-13 10:00 UTC")
    assert strip(html, "web-07", 3307) == (
        "installed mariadb-server 1:11.4.13+maria~deb12 · not the distribution's package update fixes not checked")
    assert strip(html, "web-07", 9000) == "installed unknown update fixes not checked"


def test_the_mark_stands_beside_the_port_the_server_and_its_fleet_row(db):
    server(db)
    extract(db)
    html = trm.drawn(rl.render(db, now=trl.NOW))
    assert build.fix_flag("an update fixes 2 CVEs") in trm.state_cell(html, "web-07", 22)
    assert build.fix_flag("a newer version fixes 1 CVE") in trm.state_cell(html, "web-07", 80)
    for port in (3307, 9000):
        assert "tag-fix" not in trm.state_cell(html, "web-07", port)
    whole = build.fix_flag("a newer version fixes 3 CVEs")
    assert whole in trm.header(html, "web-07") and whole in trm.fleet_row(html, "web-07")
    assert "tag-rare" not in trm.header(html, "web-07")


def test_the_mark_raises_no_count_under_needs_a_decision(db):
    """The same server without the check's data and with it: the count on its
    page and its chips on the Fleet are the same, because a fix that waits is
    not a question."""
    def counted(html):
        section = trl.host_section(html, "web-07")
        count = re.search(r'<div class="l">Needs a decision</div><div class="n[^"]*">([^<]*)</div>', section).group(1)
        return count, re.findall(r'class="fpc[^"]*">([^<]*)<', trm.fleet_row(html, "web-07"))

    server(db)
    before = counted(rl.render(db, now=trl.NOW))
    extract(db)
    html = rl.render(db, now=trl.NOW)
    assert "tag-fix" in trm.drawn(html)
    assert counted(html) == before == ("0", [])
    assert "data-rare-counts" not in trm.port_row(html, "web-07", 22)


def test_with_no_extract_kept_every_named_package_says_so_and_no_mark_stands(db):
    server(db)
    html = rl.render(db, now=trl.NOW)
    assert strip(html, "web-07", 22) == ("installed openssh-server 1:9.2p1-2+deb12u3 · "
                                         "no security data for this release update fixes not checked")
    assert "tag-fix" not in trm.drawn(html)


def test_an_extract_that_is_not_whole_is_read_as_none_and_the_page_stands(db):
    server(db)
    extract(db, data=b"this is not an extract")
    html = rl.render(db, now=trl.NOW)
    assert "no security data for this release" in htmllib.unescape(strip(html, "web-07", 22))
    assert "tag-fix" not in trm.drawn(html)


def test_data_older_than_three_days_marks_nothing_on_the_live_page(db):
    server(db)
    extract(db, modified="2026-08-09T10:00:00Z")
    html = rl.render(db, now=trl.NOW)
    assert strip(html, "web-07", 22) == ("installed openssh-server 1:9.2p1-2+deb12u3 · "
                                         "security data 5 days old update fixes not checked")
    assert "tag-fix" not in trm.drawn(html)


def test_another_workspaces_extract_folder_is_not_read_when_one_is_named(db, monkeypatch, tmp_path):
    """An instance that names its own folder for the extracts reads that one
    and not the one beside the database."""
    server(db)
    extract(db)
    monkeypatch.setenv("WHICHPORTS_CVE_DIR", str(tmp_path / "empty"))
    assert "tag-fix" not in trm.drawn(rl.render(db, now=trl.NOW))


# ------------------------------------------------------ Dismiss and Restore
#
# The mark can be dismissed (docs/RECORD.md 4.338), with the control and the
# words the rarely-public mark has: Dismiss on the port's opened row, Restore
# once it is dismissed. A dismissal is for the CVEs the mark stood for, so a
# new one brings the mark back. The card keeps its lines either way.

def dismiss(db, name, port, *cves):
    """What `controlplane/app/cvedismiss.py` stores for a dismissed mark."""
    import sqlite3
    cvedismiss = joinbridge.module("cvedismiss")
    con = sqlite3.connect(db)
    con.executescript(cvedismiss.SCHEMA)
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()[0]
    con.executemany("INSERT INTO cve_dismissed (host_id, protocol, port, cve, dismissed_at) VALUES (?, 'tcp', ?, ?, ?)",
                    [(host_id, port, cve, trl.NOW.isoformat()) for cve in cves])
    con.commit()
    con.close()


def opened(html, name, port):
    """One port's opened row, from its cards to the next port."""
    section = trl.host_section(html, name)
    return section.split(f'id="pr-{name}-tcp-{port}"', 1)[1].split('<input type="checkbox" class="prsel"', 1)[0]


def test_the_line_is_the_marks_words_and_one_button():
    line = build.fix_mark_line_html("web-07", row(cve_lines=DRAWN, cve_mark=MARK))
    assert line.startswith('<div class="prmk fix">') and MARK in line and "tag-rare" not in line
    assert ('class="btn js-fix" data-host="web-07" data-protocol="tcp" data-port="22"'
            ' data-dismiss="1">Dismiss</button>') in line
    off = build.fix_mark_line_html("web-07", row(cve_lines=DRAWN, cve_mark=MARK, cve_dismissed=True))
    assert off.startswith('<div class="prmk fix off">') and MARK in off
    assert build.theme.status("off", build.RARE_DISMISSED_WORD) in off
    assert 'data-dismiss="0">Restore</button>' in off
    assert build.fix_mark_line_html("web-07", row(cve_lines=NOT_CHECKED)) == ""
    # The button names the port's own protocol, so a UDP port's is not TCP's.
    udp = build.fix_mark_line_html("web-07", row(protocol="udp", port=53, cve_lines=DRAWN, cve_mark=MARK))
    assert 'data-host="web-07" data-protocol="udp" data-port="53" data-dismiss="1">Dismiss</button>' in udp
    assert set(text(line).split()) == set(MARK.split()) | {"Dismiss"}
    assert set(text(off).split()) == set(MARK.split()) | {"dismissed", "Restore"}


def test_a_dismissed_row_carries_no_mark_and_keeps_its_strip_and_its_line():
    html = build.port_row_html("web-07", row(cve_lines=DRAWN, cve_mark=MARK, cve_dismissed=True))
    state = html[html.index('<span class="prst">'):html.index('<span class="prn">')]
    assert "tag-fix" not in state
    after = html[html.index('<div class="pre">'):]
    assert after.index("prpk") < after.index("prmk fix off")


def test_a_marked_port_offers_dismiss_on_its_opened_row(db):
    server(db)
    extract(db)
    html = rl.render(db, now=trl.NOW)
    assert ('<div class="prmk fix">' in opened(html, "web-07", 22)
            and 'data-port="22" data-dismiss="1">Dismiss</button>' in opened(html, "web-07", 22))
    assert 'data-port="80" data-dismiss="1">Dismiss</button>' in opened(html, "web-07", 80)
    for port in (3307, 9000):
        assert "prmk fix" not in opened(html, "web-07", port), port


def test_a_dismissed_port_loses_its_mark_keeps_its_card_and_offers_restore(db):
    server(db)
    extract(db)
    dismiss(db, "web-07", 22, "CVE-2025-00001", "CVE-2026-00002")
    html = trm.drawn(rl.render(db, now=trl.NOW))
    assert "tag-fix" not in trm.state_cell(html, "web-07", 22)
    assert "tag-fix" in trm.state_cell(html, "web-07", 80), "another port of the server keeps its mark"
    assert strip(html, "web-07", 22).startswith("installed openssh-server 1:9.2p1-2+deb12u3 update fixes 2 CVEs")
    line = opened(html, "web-07", 22)
    assert '<div class="prmk fix off">' in line and 'data-dismiss="0">Restore</button>' in line


def test_the_servers_mark_stands_for_the_ports_whose_mark_is_not_dismissed(db):
    server(db)
    extract(db)
    dismiss(db, "web-07", 22, "CVE-2025-00001", "CVE-2026-00002")
    html = trm.drawn(rl.render(db, now=trl.NOW))
    left = build.fix_flag("a newer version fixes 1 CVE")
    assert left in trm.header(html, "web-07") and left in trm.fleet_row(html, "web-07")
    dismiss(db, "web-07", 80, "CVE-2026-00003")
    html = trm.drawn(rl.render(db, now=trl.NOW))
    assert "tag-fix" not in trm.header(html, "web-07") and "tag-fix" not in trm.fleet_row(html, "web-07")


def test_the_servers_mark_leaves_out_a_silenced_port_which_keeps_its_own_mark_and_card(db):
    """A silence takes a port out of the server's count, as it takes an alert
    out of the count beside Alerts (docs/PRODUCT.md 4c), and a message counts
    what this mark stands for (controlplane/app/cvetell.py). The port keeps
    its own mark and its card. The second big test, finding G9. A silence of
    either family is enough, as it is for the message."""
    server(db)
    extract(db)
    trl.silence_port(db, "web-07", "tcp", 22, "v6")
    html = trm.drawn(rl.render(db, now=trl.NOW))
    left = build.fix_flag("a newer version fixes 1 CVE")
    assert left in trm.header(html, "web-07") and left in trm.fleet_row(html, "web-07")
    assert build.fix_flag("an update fixes 2 CVEs") in trm.state_cell(html, "web-07", 22)
    assert strip(html, "web-07", 22).startswith("installed openssh-server 1:9.2p1-2+deb12u3 update fixes 2 CVEs")
    trl.silence_port(db, "web-07", "tcp", 80, "v4")
    html = trm.drawn(rl.render(db, now=trl.NOW))
    assert "tag-fix" not in trm.header(html, "web-07") and "tag-fix" not in trm.fleet_row(html, "web-07")
    assert build.fix_flag("a newer version fixes 1 CVE") in trm.state_cell(html, "web-07", 80)


def test_a_dismissal_is_of_one_port_and_the_packages_other_port_keeps_its_mark(db):
    """nginx holds 80 and 443, so both marks stand for the same CVE. A
    person who dismissed it on 80 said nothing of 443."""
    doc = trl.document(listening=[listening(80, "nginx", "nginx.service"), listening(443, "nginx", "nginx.service")])
    doc["nftables"] = trm.allow(80, 443)
    doc["packages"] = packages()
    trl.reporting(db, "web-07", doc)
    for port in (80, 443):
        trl.probe_result(db, "web-07", port, "v4", "connect_succeeded")
    extract(db)
    dismiss(db, "web-07", 80, "CVE-2026-00003")
    html = trm.drawn(rl.render(db, now=trl.NOW))
    assert "tag-fix" not in trm.state_cell(html, "web-07", 80)
    assert build.fix_flag("a newer version fixes 1 CVE") in trm.state_cell(html, "web-07", 443)
    assert 'data-port="80" data-dismiss="0">Restore</button>' in opened(html, "web-07", 80)
    assert 'data-port="443" data-dismiss="1">Dismiss</button>' in opened(html, "web-07", 443)
    assert build.fix_flag("a newer version fixes 1 CVE") in trm.header(html, "web-07")


def test_a_cve_that_joins_later_brings_the_mark_back(db):
    """Dismissed for one CVE, and the release's data then names a second."""
    server(db)
    extract(db)
    dismiss(db, "web-07", 22, "CVE-2025-00001")
    html = trm.drawn(rl.render(db, now=trl.NOW))
    assert build.fix_flag("an update fixes 2 CVEs") in trm.state_cell(html, "web-07", 22)
    assert 'data-port="22" data-dismiss="1">Dismiss</button>' in opened(html, "web-07", 22)


def test_one_workspace_never_reads_anothers_dismissals(db):
    server(db)
    extract(db)
    dismiss(db, "web-07", 22, "CVE-2025-00001", "CVE-2026-00002")
    assert rl.load_cve_dismissed(db, workspace_id=1) == {
        "web-07": {("tcp", 22): frozenset({"CVE-2025-00001", "CVE-2026-00002"})}}
    assert rl.load_cve_dismissed(db, workspace_id=2) == {}


def test_a_database_from_before_dismissals_draws_every_mark(db):
    server(db)
    extract(db)
    assert rl.load_cve_dismissed(db, workspace_id=1) == {}
    assert "tag-fix" in trm.state_cell(trm.drawn(rl.render(db, now=trl.NOW)), "web-07", 22)
