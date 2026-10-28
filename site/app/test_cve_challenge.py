"""The challenge to the CVE check on the live page, 2026-10-11. Each test
fails on `cve-control-plane` at bfc81fd. Nothing here is fixed.

    python -m pytest app/test_cve_challenge.py      (from site/)
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import joinbridge  # noqa: E402
import render_live as rl  # noqa: E402
import test_cve_card as tc  # noqa: E402
import test_rarely_public_mark as trm  # noqa: E402
import test_render_live as trl  # noqa: E402
from test_render_live import db  # noqa: E402,F401  (the empty database fixture)

DEBIAN = {"id": "debian", "version_id": "12", "version_codename": "bookworm"}


def section(units, offered):
    return {"status": "collected", "distribution": DEBIAN,
            "sources": {"dpkg_info": {"status": "collected"}, "apt_lists": {"status": "collected"}},
            "units": units, "offers": offered}


def test_a_port_two_packages_hold_never_reads_none_for_the_one_asked_first(db):
    """Port 80 is nginx over IPv4, with every update installed, and Apache
    over IPv6, behind on an update its own lists offer. `cve_cards` asks
    over IPv4 first and takes the IPv6 answer only where the first names no
    package, so the port's one strip reads `installed nginx`, `update fixes
    none`, no mark stands on the port, the server or the Fleet, and nothing
    on the page says a second package holds the port."""
    over_v6 = trm.sock(80, "apache2", family="v6")
    over_v6.update(unit="apache2.service", cgroup="/system.slice/apache2.service")
    doc = trl.document(listening=[tc.listening(80, "nginx", "nginx.service"), over_v6])
    doc["nftables"] = trm.allow(80)
    doc["packages"] = section(
        [tc.unit("nginx.service", "/usr/sbin/nginx", tc.owner("nginx", "1.22.1-9+deb12u10")),
         tc.unit("apache2.service", "/usr/sbin/apache2", tc.owner("apache2-bin", "2.4.62-1~deb12u1", "apache2"))],
        [tc.offers("nginx", tc.offer("1.22.1-9+deb12u10")),
         tc.offers("apache2-bin", tc.offer("2.4.68-1~deb12u1"))])
    trl.reporting(db, "web-08", doc)
    trl.probe_result(db, "web-08", 80, "v4", "connect_succeeded")
    row = joinbridge.module("cveextract").Row
    tc.extract(db, rows=[row("apache2", "CVE-2026-00021", "2.4.68-1~deb12u1", "low"),
                         row("nginx", "CVE-2026-00003", "1.22.1-9+deb12u10", "low")])
    said = tc.strip(rl.render(db, now=trl.NOW), "web-08", 80)
    assert "update fixes none" not in said, said


def test_a_server_silent_for_a_month_does_not_read_none(db):
    """The last report is thirty days old. What is installed today was not
    read. The strip still holds that report against today's data and reads
    `update fixes none`, and a server behind on its updates that day would
    keep the check's mark on its Fleet row for as long as it stays silent."""
    doc = trl.document(listening=[tc.listening(22, "sshd", "ssh.service")])
    doc["nftables"] = trm.allow(22)
    doc["packages"] = section(
        [tc.unit("ssh.service", "/usr/sbin/sshd", tc.owner("openssh-server", "1:9.2p1-2+deb12u10", "openssh"))],
        [tc.offers("openssh-server", tc.offer("1:9.2p1-2+deb12u10"))])
    trl.reporting(db, "web-07", doc, minutes=60 * 24 * 30)
    trl.probe_result(db, "web-07", 22, "v4", "connect_succeeded")
    tc.extract(db)
    said = tc.strip(rl.render(db, now=trl.NOW), "web-07", 22)
    assert "update fixes none" not in said, said
