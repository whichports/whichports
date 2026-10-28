"""What the CVE check's message says, one for a workspace.

    python -m pytest tests/test_cvewords.py

`docs/SPEC-cve-check.md`, section 2, point 7, and section 8, point 6. The
shape is every alert's since 2026-10-06: a title, labelled values, the line
that nothing else will be sent, one button. The owner said no to the first
CVE mail for its text, its CVE ids, its versions and its dates
(`docs/RECORD.md` 4.338), and the message as drawn on 2026-10-07 holds none
of them (4.446). The servers and the CVE numbers are made up.
"""
import re

import pytest

from app import alertwords, cvewords, notify
from app.cvewords import Told, said

OPENSSH = frozenset(f"CVE-2026-0000{n}" for n in range(1, 4))
NGINX = frozenset({"CVE-2026-00011", "CVE-2026-00012"})
MAIL = Told("mail-01", ports=(("tcp", 22),), cves=OPENSSH, offered=True)
WEB = Told("web-07", ports=(("tcp", 80), ("tcp", 22)), cves=OPENSSH | NGINX, offered=False)
DB = Told("db-02", ports=(("tcp", 22),), cves=OPENSSH, offered=True, display="Database")


def test_one_server_whose_lists_offer_every_fix():
    got = said([MAIL])
    assert got == alertwords.Said(
        title="An update fixes CVEs on mail-01",
        fields=(("server", "mail-01"), ("port", "22"), ("CVEs", "3"), ("new", "3")),
        closing="Nothing else will be sent about these CVEs on the same port.",
        button="Open mail-01", link=got.link)
    assert got.link.endswith("/host/mail-01")


def test_one_server_with_a_fix_its_lists_do_not_offer_says_a_newer_version():
    """"An update" would say more than was read."""
    got = said([WEB])
    assert got.title == "A newer version fixes CVEs on web-07"
    assert got.fields == (("server", "web-07"), ("ports", "22, 80"), ("CVEs", "5"), ("new", "5"))
    assert got.closing == "Nothing else will be sent about these CVEs on the same ports."
    assert got.button == "Open web-07"


def test_several_servers_are_one_message_for_the_workspace():
    got = said([WEB, MAIL, DB])
    assert got.title == "A newer version fixes CVEs on 3 servers"
    # Each CVE is counted once, however many servers it is on.
    assert got.fields == (("servers", "Database, mail-01, web-07"), ("CVEs", "5"), ("new", "5"))
    assert got.closing == "Nothing else will be sent about these CVEs on the same ports."
    assert got.button == "Open Fleet" and got.link.endswith("/") and "/host/" not in got.link


def test_an_update_is_said_only_when_every_servers_lists_offer_every_fix():
    assert said([MAIL, DB]).title == "An update fixes CVEs on 2 servers"
    assert said([MAIL, WEB]).title == "A newer version fixes CVEs on 2 servers"


def test_the_count_is_what_the_servers_mark_stands_for_and_new_is_said_beside_it():
    """The mark on the page stands for five CVEs and one of them is new. The
    button opens that page, so `CVEs` is its five, and the title follows the
    mark: one of the five is fixed in a version the lists do not offer, so
    it is a newer version, though the new one's fix is offered."""
    one = Told("web-07", ports=(("tcp", 22),), cves=frozenset({"CVE-2026-00003"}), offered=True,
               marked=OPENSSH | NGINX, mark_offered=False)
    got = said([one])
    assert got.title == "A newer version fixes CVEs on web-07"
    assert got.fields == (("server", "web-07"), ("port", "22"), ("CVEs", "5"), ("new", "1"))
    # Over several servers each CVE is counted once, in both counts.
    other = Told("mail-01", ports=(("tcp", 22),), cves=frozenset({"CVE-2026-00003"}), offered=True,
                 marked=OPENSSH, mark_offered=True)
    assert said([one, other]).fields == (("servers", "mail-01, web-07"), ("CVEs", "5"), ("new", "1"))
    assert said([other]).title == "An update fixes CVEs on mail-01"


def test_the_last_line_promises_a_port_and_never_the_cve_everywhere():
    """What is kept is a CVE on a port of a server. A line that promised the
    CVE was broken by the same CVE on a second server (the second challenge,
    docs/SPEC-cve-check.md 7.12)."""
    for told in ([MAIL], [WEB], [WEB, MAIL, DB]):
        closing = said(told).closing
        assert closing in (cvewords.CLOSING_PORT, cvewords.CLOSING_PORTS)
        assert not closing.endswith("these CVEs.")
    assert said([MAIL]).closing.endswith("on the same port.")
    assert said([WEB]).closing.endswith("on the same ports.")


def test_a_server_with_a_display_name_is_said_with_the_name_it_is_found_by():
    """Two servers may carry one display name (docs/RECORD.md 4.255)."""
    got = said([DB])
    assert got.title == "An update fixes CVEs on Database"
    assert got.fields[0] == ("server", "Database (db-02)") and got.button == "Open Database"
    assert got.link.endswith("/host/db-02")


def test_a_long_list_names_five_and_counts_the_rest():
    many = [Told(f"box-{n:02d}", ports=(("tcp", 22),), cves=OPENSSH, offered=True) for n in range(8)]
    assert dict(said(many).fields)["servers"] == "box-00, box-01, box-02, box-03, box-04 and 3 more"
    ports = tuple(("tcp", port) for port in (8080, 22, 80, 443, 25, 5432, 3306))
    one = Told("web-07", ports=ports, cves=OPENSSH, offered=True)
    assert dict(said([one]).fields)["ports"] == "22, 25, 80, 443, 3306 and 2 more"


def test_a_port_that_is_not_tcp_says_its_protocol_and_a_port_is_said_once():
    got = said([Told("dns-01", ports=(("udp", 53), ("tcp", 53), ("tcp", 53)), cves=OPENSSH, offered=True)])
    assert dict(got.fields)["ports"] == "53, 53/udp"


def test_the_labels_are_one_closed_list():
    assert cvewords.LABELS == ("server", "port", "ports", "servers", "CVEs", "new")
    for told in ([MAIL], [WEB], [WEB, MAIL, DB]):
        for label, _value in said(told).fields:
            assert label in cvewords.LABELS


@pytest.mark.parametrize("told", [[MAIL], [WEB], [WEB, MAIL, DB]])
def test_no_cve_id_no_version_and_no_date_is_in_any_half_of_the_mail(told):
    """What he said no to on 2026-10-03. The count is there, the ids are on
    the server's page."""
    subject, text, html = notify.mail(said(told))
    for half in (subject, text, html):
        assert not re.search(r"CVE-\d", half), half[:200]
        assert not re.search(r"\d+:\d+\.\d+|deb12u|ubuntu\d", half)
        assert not re.search(r"20\d\d-\d\d-\d\d", half)
        for word in ("vulnerable", "secure", "safe", "at risk", "critical", "severity", "urgent"):
            assert word not in half.lower()
    assert subject == "[whichports] " + said(told).title
    assert said(told).closing in text


def test_a_message_about_nothing_is_refused():
    with pytest.raises(ValueError):
        said([])
    with pytest.raises(ValueError):
        said([Told("web-07", ports=(("tcp", 22),), cves=frozenset(), offered=True)])
    with pytest.raises(ValueError):
        said([Told("web-07", ports=(), cves=OPENSSH, offered=True)])
