"""Every link that leaves this control plane names this control plane.

Unset, the address is exactly https://app.whichports.com, which is what every
one of these lines said before the setting existed, so our own box and its
customers see nothing change. Set, a self-hosted instance enrols its servers
to itself and its mail sends people to its own dashboard (app/publicurl.py).
"""
import json
import urllib.parse

import pytest
from fastapi.testclient import TestClient

from app import (db, dispatch, ingest, mailhtml, notify, publicurl, senders,
                 store, users_cli, web_auth)
from operator_gate import gate

OURS = "https://whichports.example.com"


@pytest.fixture()
def unset(monkeypatch):
    monkeypatch.delenv(publicurl.ENV, raising=False)


@pytest.fixture()
def instance(monkeypatch):
    monkeypatch.setenv(publicurl.ENV, OURS)


# ------------------------------------------------------------- the rule

def test_unset_is_exactly_the_address_it_always_was(unset):
    assert publicurl.base() == "https://app.whichports.com"
    assert publicurl.host() == "app.whichports.com"
    assert publicurl.dashboard() == "https://app.whichports.com/"


def test_empty_is_unset(monkeypatch):
    monkeypatch.setenv(publicurl.ENV, "   ")
    assert publicurl.base() == "https://app.whichports.com"


def test_the_setting_is_the_one_sign_in_reads():
    """One fact, one setting. app/oidc.py builds the sign-in return address
    from the same variable."""
    from app import oidc
    assert publicurl.ENV == oidc.BASE_URL_ENV


@pytest.mark.parametrize("value,expected", [
    ("https://whichports.example.com", "https://whichports.example.com"),
    ("https://whichports.example.com/", "https://whichports.example.com"),
    ("  https://whichports.example.com  ", "https://whichports.example.com"),
    ("https://whichports.example.com:8443", "https://whichports.example.com:8443"),
    ("https://[2001:db8::1]", "https://[2001:db8::1]"),
    ("https://192.0.2.10", "https://192.0.2.10"),
])
def test_accepted(value, expected):
    assert publicurl.base({publicurl.ENV: value}) == expected


@pytest.mark.parametrize("value", [
    "http://whichports.example.com",
    "whichports.example.com",
    "https://",
    "https://whichports.example.com/app",
    "https://whichports.example.com/?x=1",
    "https://whichports.example.com/#top",
    "https://user:pw@whichports.example.com",
    "https://whichports.example.com;reboot",
    "https://whichports.example.com$(id)",
    "https://whichports.example.com`id`",
    "https://whichports example.com",
    "https://whichports.example.com&&id",
    "ftp://whichports.example.com",
])
def test_refused_never_repaired(value):
    with pytest.raises(publicurl.PublicUrlError):
        publicurl.base({publicurl.ENV: value})


def test_read_when_used_not_at_import(monkeypatch):
    """A command from a shell loads the env file after its imports
    (app/cli.py), so a value captured at import would be the stale one."""
    monkeypatch.delenv(publicurl.ENV, raising=False)
    before = notify.format_silence("box", "quiet", "now")[1]
    monkeypatch.setenv(publicurl.ENV, OURS)
    after = notify.format_silence("box", "quiet", "now")[1]
    assert "https://app.whichports.com/" in before
    assert f"{OURS}/" in after and "app.whichports.com" not in after


# --------------------------------------------------- the install command

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    for name in (dispatch.PROBER_API_ENV, dispatch.PROBER_API_KEY_ENV,
                 dispatch.PROBER_PROOF_KEY_ENV):
        monkeypatch.delenv(name, raising=False)
    return TestClient(ingest.app)


def add(client, name="newbox"):
    return client.post("/api/admin/hosts", content=json.dumps({"name": name}),
                       headers=gate())


def test_install_command_unset_is_byte_for_byte_what_it_was(client, unset):
    body = add(client).json()
    assert body["install_command"] == (
        "curl -fsSL https://get.whichports.com/install.sh | sudo sh -s --"
        " enroll --server=https://app.whichports.com"
        f" --credential={body['credential']}")


def test_install_command_enrols_to_the_instance(client, instance):
    body = add(client).json()
    command = body["install_command"]
    assert f" --server={OURS} " in command
    assert "app.whichports.com" not in command
    # The agent package still comes from us, the one place it is published.
    assert command.startswith(
        "curl -fsSL https://get.whichports.com/install.sh | sudo sh")


def test_install_command_carries_the_proof_key_with_the_instance(client, instance,
                                                                monkeypatch):
    """docs/PRODUCT.md 5g: the instance hands the proof key to every server
    it enrols, beside its own address."""
    monkeypatch.setenv(dispatch.PROBER_API_ENV, "https://app.whichports.com")
    monkeypatch.setenv(dispatch.PROBER_PROOF_KEY_ENV, "whpp_" + "a" * 64)
    command = add(client).json()["install_command"]
    assert f" --server={OURS} " in command
    assert command.endswith(" --prober-server=https://app.whichports.com"
                            f" --prober-proof-key=whpp_{'a' * 64}")


def test_a_malformed_address_refuses_and_makes_no_server(client, monkeypatch,
                                                        caplog):
    monkeypatch.setenv(publicurl.ENV, "http://whichports.example.com")
    with caplog.at_level("ERROR", logger="app.ingest"):
        resp = add(client)
    assert any(publicurl.ENV in r.getMessage() for r in caplog.records)
    assert resp.status_code == 500
    # Plain words on the screen, and the setting's name only in the log.
    assert resp.json()["detail"] == ingest.NO_INSTALL_COMMAND
    assert publicurl.ENV not in resp.json()["detail"]
    con = db.connect()
    db.init(con)
    count = con.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
    con.close()
    assert count == 0


def test_a_malformed_address_refuses_a_reissue_before_reissuing(client, monkeypatch):
    monkeypatch.delenv(publicurl.ENV, raising=False)
    first = add(client).json()
    con = db.connect()
    before = con.execute("SELECT token_hash FROM hosts WHERE name = ?",
                         (first["name"],)).fetchone()[0]
    con.close()
    monkeypatch.setenv(publicurl.ENV, "https://whichports.example.com/x")
    resp = client.post(f"/api/admin/hosts/{first['name']}/credential",
                       headers=gate())
    assert resp.status_code == 500
    con = db.connect()
    after = con.execute("SELECT token_hash FROM hosts WHERE name = ?",
                        (first["name"],)).fetchone()[0]
    con.close()
    assert after == before, "the old credential must still be the one stored"


# ------------------------------------------------------------- the mails

def alert_bodies():
    change = notify.Change(where="22/tcp v4", was="", now="unexplained",
                           description="reachable", vantage="probe1",
                           measured_at="now")
    return [
        notify.format_test()[1],
        notify.format_silence("box", "quiet", "now")[1],
        notify.format_outside_stale("box", "stale", "now")[1],
        notify.format_finding_changes("box", [change])[1],
        senders.text_for_alert("silence", "box", "quiet", "now"),
        senders.text_for_changes("box", [change]),
    ]


def test_alerts_link_the_instance(instance):
    for body in alert_bodies():
        assert f"{OURS}/" in body
        assert "app.whichports.com" not in body


def test_alerts_unset_link_ours(unset):
    for body in alert_bodies():
        assert "https://app.whichports.com/" in body


def test_the_html_mail_button_links_the_instance(instance):
    html = mailhtml.alert(notify.said_silence("box", "no report for 41 minutes"))
    assert f'href="{OURS}/host/box"' in html
    assert "app.whichports.com" not in html


def test_account_mails_name_the_instance(instance):
    subject, body, html = notify.format_account("a@example.com", f"{OURS}/x")
    assert "An account was made for you at whichports.example.com." in body
    assert "whichports.example.com" in html
    assert "app.whichports.com" not in body + html


def test_links_in_account_mails_point_at_the_instance(instance):
    assert web_auth._link_url(next(iter(web_auth._LINK_PATHS)), "tok") \
        .startswith(f"{OURS}/")
    assert users_cli.publicurl.base() == OURS


def test_store_is_untouched_by_the_setting(client, instance):
    """The credential and its hash do not depend on where the instance
    answers. Only the command around them does."""
    body = add(client).json()
    assert body["credential"].startswith(store.CREDENTIAL_PREFIX)


# ------------------------------------------- the address of a server's page
#
# An alert about a server links that server's own page
# (docs/screens/mails/SPEC-alert-messages.md).

def test_a_servers_address_is_one_path_segment(unset):
    assert publicurl.server("web-07") == "https://app.whichports.com/host/web-07"
    assert publicurl.integrations() == "https://app.whichports.com/integrations"
    # A name holding a slash, a question mark or a hash is still one segment,
    # so it can carry nothing past the server's page.
    for name in ("a/b", "a?b=c", "a#b", "../x", "a b", "a%2Fb"):
        tail = publicurl.server(name)[len("https://app.whichports.com/host/"):]
        for mark in "/?# ":
            assert mark not in tail, (name, tail)
        assert urllib.parse.unquote(tail) == name


def test_a_servers_address_follows_the_instance(instance):
    assert publicurl.server("web-07") == f"{OURS}/host/web-07"
    assert publicurl.integrations() == f"{OURS}/integrations"


def test_a_signed_out_reader_lands_on_the_server_after_signing_in(client, unset):
    """The link in a message is opened by somebody who may not be signed in.
    They are sent to sign in with the server's address kept, which is where
    the sign-in page sends them on to (tests/test_login.py holds that half)."""
    path = publicurl.server("web-07")[len(publicurl.base()):]
    resp = client.get(path, follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login?next=%2Fhost%2Fweb-07"
