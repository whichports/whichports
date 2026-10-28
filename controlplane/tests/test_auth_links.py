"""The screens around signing in, and the links that reach them.

    python -m pytest tests/test_auth_links.py

The four flows `docs/screens/sign-in/SPEC.md` names, driven through the
application rather than through `app/onetime.py`, which has its own file.

Because the owner reads every diff and has said he cannot be relied on to catch a
subtle security bug in review, these are the review. The
mutations they are built to catch, in the order they matter:

  1. **A reset form that answers questions.** Asking for a link about an
     address with no account must be indistinguishable, in words, in status
     and in timing-independent behaviour, from asking about one that has.
  2. **A link that works twice**, or after its clock ran out, or at the wrong
     route.
  3. **A form deciding whose account it is.** The link decides. A posted
     address must change nothing.
  4. **A link walking past the second factor.** Redeeming one on an account
     with two-factor on must land on the code step, not on the dashboard.
  5. **A password reaching a log line or a response.**
"""

import logging
import re
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import (accounts, db, ingest, notify, onetime, publicurl, ratelimit,
                 totp, web_auth)

EMAIL = "sysadmin@example.com"
PASSWORD = "correct-horse-battery-9"
NEW_PASSWORD = "a-brand-new-passphrase-9"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    monkeypatch.setenv("WHICHPORTS_SIGNUP", "open")
    ingest.app.state.limiters = ratelimit.Limiters()
    con = db.connect()
    db.init(con)
    accounts.init(con)
    onetime.init(con)
    accounts.create_user(con, EMAIL, PASSWORD)
    con.close()
    return TestClient(ingest.app)


@pytest.fixture()
def sent(monkeypatch):
    """Every mail the application tried to send, without a relay."""
    out = []

    def fake_send(subject, body, config=None, html=""):
        out.append({"subject": subject, "body": body, "html": html,
                    "to": getattr(config, "to", "")})
        return True, ""

    monkeypatch.setattr(notify, "send", fake_send)
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "mail.example.test")
    return out


def con_for():
    return db.connect()


def csrf_of(page_html):
    match = re.search(r'name="csrf" value="([^"]+)"', page_html)
    assert match, "the form did not carry a CSRF token"
    return match.group(1)


def ask_for_a_link(client, email=EMAIL):
    page = client.get("/forgot")
    assert page.status_code == 200
    return client.post("/forgot", data={"email": email, "csrf": csrf_of(page.text)})


def link_in(mail_body):
    """The one URL a mail carries."""
    found = re.findall(r"https://\S+", mail_body)
    assert len(found) == 1, found
    return found[0]


def path_of(url):
    return url.split(publicurl.host(), 1)[1]


def issue(purpose, email=EMAIL, **kw):
    con = con_for()
    try:
        user = accounts.get_user_by_email(con, email)
        return onetime.issue(con, purpose, email,
                             user_id=user["id"] if user else None, **kw)[0]
    finally:
        con.close()


# ================================================== forgot your password

def test_the_forgot_page_is_a_form_and_a_way_back(client):
    page = client.get("/forgot")
    assert page.status_code == 200
    assert "Reset your password" in page.text
    assert 'name="email"' in page.text
    assert 'href="/login"' in page.text
    assert page.headers["cache-control"] == "no-store"
    assert 'name="robots" content="noindex,nofollow"' in page.text


def test_an_address_with_an_account_gets_a_link_that_works(client, sent):
    answer = ask_for_a_link(client)
    assert answer.status_code == 200
    assert "A link went to" in answer.text
    assert len(sent) == 1 and sent[0]["to"] == EMAIL
    assert sent[0]["subject"] == "[whichports] Reset your password"
    con = con_for()
    try:
        token = path_of(link_in(sent[0]["body"])).rsplit("/", 1)[1]
        assert onetime.look_up(con, onetime.RESET, token) is not None
    finally:
        con.close()


def test_an_address_with_no_account_is_answered_exactly_the_same(client, sent):
    """The one that matters. A reset form is the easiest way to ask a product
    who its customers are, and this one does not answer."""
    known = ask_for_a_link(client, EMAIL)
    unknown = ask_for_a_link(client, "nobody@example.com")
    assert unknown.status_code == known.status_code == 200
    # The only difference between the two pages is the address echoed back,
    # which is the address that was typed.
    assert (unknown.text.replace("nobody@example.com", EMAIL)
            == known.text.replace("nobody@example.com", EMAIL))
    assert [mail["to"] for mail in sent] == [EMAIL]


def test_a_disabled_account_is_answered_the_same_and_gets_nothing(client, sent):
    con = con_for()
    accounts.set_disabled(con, EMAIL, True)
    con.close()
    answer = ask_for_a_link(client)
    assert answer.status_code == 200 and "A link went to" in answer.text
    assert sent == []


def test_a_second_ask_kills_the_first_link(client, sent):
    ask_for_a_link(client)
    ask_for_a_link(client)
    first, second = (path_of(link_in(mail["body"])).rsplit("/", 1)[1] for mail in sent)
    assert client.get(f"/reset/{first}", follow_redirects=False).status_code == 410
    assert client.get(f"/reset/{second}", follow_redirects=False).status_code == 200


def test_a_cross_site_ask_is_refused(client, sent):
    client.get("/forgot")
    answer = client.post("/forgot", data={"email": EMAIL, "csrf": "not-the-token"})
    assert answer.status_code == 400
    assert sent == []


def test_an_address_that_is_not_one_is_refused(client, sent):
    page = client.get("/forgot")
    answer = client.post("/forgot", data={"email": "not-an-address",
                                          "csrf": csrf_of(page.text)})
    assert answer.status_code == 400
    assert sent == []


def test_the_ask_is_rate_limited(client, sent):
    for _ in range(40):
        answer = ask_for_a_link(client)
        if answer.status_code == 429:
            break
    else:
        raise AssertionError("the reset form never rate limited")
    assert "Too many attempts" in answer.text


def test_a_relay_that_refuses_says_nothing_to_the_page(client, monkeypatch, capsys):
    """A failed send is ours to see in the journal. Handing it back would say
    whether that address has an account here, because nothing is sent when it
    does not."""
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "mail.example.test")
    monkeypatch.setattr(notify, "send", lambda *a, **k: (False, "relay refused"))
    answer = ask_for_a_link(client)
    assert answer.status_code == 200 and "A link went to" in answer.text
    assert "relay refused" in capsys.readouterr().err


def test_a_failed_send_tells_the_journal_the_class_and_never_the_address(
        client, monkeypatch, capsys):
    """The journal is a log of ours, and a mail address goes into none
    (app/journal.py, SI-8). The line says what failed, as the class
    `notify.send` hands back, and stops."""
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "mail.example.test")
    monkeypatch.setattr(notify, "send",
                        lambda *a, **k: (False, "SMTPRecipientsRefused"))
    ask_for_a_link(client)
    err = capsys.readouterr().err
    assert "SMTPRecipientsRefused" in err
    assert EMAIL not in err
    assert EMAIL.split("@")[0] not in err


def test_no_relay_tells_the_journal_without_the_address(client, monkeypatch,
                                                        capsys):
    monkeypatch.delenv("WHICHPORTS_SMTP_HOST", raising=False)
    answer = ask_for_a_link(client)
    assert answer.status_code == 200
    err = capsys.readouterr().err
    assert "no relay" in err
    assert EMAIL not in err
    assert EMAIL.split("@")[0] not in err


# ================================================== choosing a password

def test_the_reset_link_lands_on_the_form_with_the_address_shown(client):
    token = issue(onetime.RESET)
    page = client.get(f"/reset/{token}")
    assert page.status_code == 200
    assert "Choose a password" in page.text
    assert EMAIL in page.text
    # shown, not asked for: it is read only and it is not the posted field
    assert 'name="shown_email"' in page.text and "readonly" in page.text
    assert 'name="email"' not in page.text


def test_a_reset_sets_the_password_and_signs_in(client):
    token = issue(onetime.RESET)
    page = client.get(f"/reset/{token}")
    answer = client.post(f"/reset/{token}", follow_redirects=False, data={
        "password": NEW_PASSWORD, "confirm": NEW_PASSWORD, "csrf": csrf_of(page.text)})
    assert answer.status_code == 303 and answer.headers["location"] == "/"
    con = con_for()
    try:
        assert accounts.authenticate(con, EMAIL, NEW_PASSWORD) is not None
        assert accounts.authenticate(con, EMAIL, PASSWORD) is None
    finally:
        con.close()
    assert client.get("/api/auth/check").status_code == 204


def test_a_reset_ends_every_other_session(client):
    """Somebody resetting a password may have lost the old one to another
    person, so every session that password opened goes."""
    other = TestClient(ingest.app)
    page = other.get("/login")
    other.post("/login", follow_redirects=False, data={
        "email": EMAIL, "password": PASSWORD, "next": "/", "csrf": csrf_of(page.text)})
    assert other.get("/api/auth/check").status_code == 204
    token = issue(onetime.RESET)
    form = client.get(f"/reset/{token}")
    client.post(f"/reset/{token}", follow_redirects=False, data={
        "password": NEW_PASSWORD, "confirm": NEW_PASSWORD, "csrf": csrf_of(form.text)})
    assert other.get("/api/auth/check").status_code == 401


def test_a_link_works_once(client):
    token = issue(onetime.RESET)
    page = client.get(f"/reset/{token}")
    csrf = csrf_of(page.text)
    first = client.post(f"/reset/{token}", follow_redirects=False, data={
        "password": NEW_PASSWORD, "confirm": NEW_PASSWORD, "csrf": csrf})
    assert first.status_code == 303
    second = client.post(f"/reset/{token}", follow_redirects=False, data={
        "password": "another-passphrase-x9", "confirm": "another-passphrase-x9",
        "csrf": csrf})
    assert second.status_code == 410
    con = con_for()
    try:
        assert accounts.authenticate(con, EMAIL, "another-passphrase-x9") is None
    finally:
        con.close()


def test_a_link_that_expired_is_gone(client):
    con = con_for()
    try:
        user = accounts.get_user_by_email(con, EMAIL)
        token, _ = onetime.issue(
            con, onetime.RESET, EMAIL, user_id=user["id"],
            now=datetime.now(timezone.utc) - timedelta(hours=2))
    finally:
        con.close()
    assert client.get(f"/reset/{token}", follow_redirects=False).status_code == 410


def test_a_token_at_the_wrong_route_is_nothing(client):
    token = issue(onetime.RESET)
    assert client.get(f"/set-password/{token}", follow_redirects=False).status_code == 410
    assert client.get(f"/confirm/{token}", follow_redirects=False).status_code == 410
    assert client.get(f"/join/{token}", follow_redirects=False).status_code == 410


@pytest.mark.parametrize("token", ["nope", "0" * 64, "../../etc/passwd"])
def test_a_token_nobody_issued_is_nothing(client, token):
    assert client.get(f"/reset/{token}", follow_redirects=False).status_code in (404, 410)


def test_every_dead_link_says_one_thing(client):
    """Expired, spent, never issued and wrong purpose are one answer. Telling
    them apart would answer questions about somebody else's account."""
    spent = issue(onetime.RESET)
    page = client.get(f"/reset/{spent}")
    client.post(f"/reset/{spent}", follow_redirects=False, data={
        "password": NEW_PASSWORD, "confirm": NEW_PASSWORD, "csrf": csrf_of(page.text)})
    wrong_purpose = issue(onetime.CONFIRM)
    bodies = {client.get(f"/reset/{t}").text for t in (spent, wrong_purpose)}
    assert len(bodies) == 1, "two dead links said two different things"
    assert "has expired" in bodies.pop()


def test_the_two_passwords_have_to_match(client):
    token = issue(onetime.RESET)
    page = client.get(f"/reset/{token}")
    answer = client.post(f"/reset/{token}", follow_redirects=False, data={
        "password": NEW_PASSWORD, "confirm": "something-else-here",
        "csrf": csrf_of(page.text)})
    assert answer.status_code == 400
    assert "do not match" in answer.text
    # and the link still works, because nothing was set
    assert client.get(f"/reset/{token}").status_code == 200


def test_a_password_below_the_length_is_refused_with_the_reason(client):
    token = issue(onetime.RESET)
    page = client.get(f"/reset/{token}")
    answer = client.post(f"/reset/{token}", follow_redirects=False, data={
        "password": "short", "confirm": "short", "csrf": csrf_of(page.text)})
    assert answer.status_code == 400
    assert str(accounts.PASSWORD_MIN_CHARS) in answer.text
    assert client.get(f"/reset/{token}").status_code == 200


def test_a_posted_address_decides_nothing(client):
    """The link says whose account this is. A second opinion in the form must
    change nothing at all."""
    con = con_for()
    accounts.create_user(con, "someone@example.com", PASSWORD)
    con.close()
    token = issue(onetime.RESET)
    page = client.get(f"/reset/{token}")
    client.post(f"/reset/{token}", follow_redirects=False, data={
        "email": "someone@example.com", "shown_email": "someone@example.com",
        "password": NEW_PASSWORD, "confirm": NEW_PASSWORD, "csrf": csrf_of(page.text)})
    con = con_for()
    try:
        assert accounts.authenticate(con, EMAIL, NEW_PASSWORD) is not None
        assert accounts.authenticate(con, "someone@example.com", NEW_PASSWORD) is None
    finally:
        con.close()


def test_a_cross_site_post_sets_no_password(client):
    token = issue(onetime.RESET)
    client.get(f"/reset/{token}")
    answer = client.post(f"/reset/{token}", follow_redirects=False, data={
        "password": NEW_PASSWORD, "confirm": NEW_PASSWORD, "csrf": "not-the-token"})
    assert answer.status_code == 400
    con = con_for()
    try:
        assert accounts.authenticate(con, EMAIL, NEW_PASSWORD) is None
    finally:
        con.close()


def test_the_new_password_reaches_no_log_line(client, caplog):
    token = issue(onetime.RESET)
    page = client.get(f"/reset/{token}")
    with caplog.at_level(logging.DEBUG):
        answer = client.post(f"/reset/{token}", follow_redirects=False, data={
            "password": NEW_PASSWORD, "confirm": NEW_PASSWORD,
            "csrf": csrf_of(page.text)})
    assert NEW_PASSWORD not in caplog.text
    assert NEW_PASSWORD not in answer.text


# ======================================= a link is not a way past the code

def turn_two_factor_on():
    con = con_for()
    try:
        user = accounts.get_user_by_email(con, EMAIL)
        secret = accounts.begin_totp_enrollment(con, user["id"])
        accounts.confirm_totp_enrollment(con, user["id"],
                                         totp.code_at_time(secret, __import__("time").time()),
                                         at_time=__import__("time").time())
        return secret
    finally:
        con.close()


def test_a_reset_on_an_account_with_two_factor_lands_on_the_code_step(client):
    """A link proves somebody reads that mailbox. It does not prove they hold
    the operator's authenticator."""
    turn_two_factor_on()
    token = issue(onetime.RESET)
    page = client.get(f"/reset/{token}")
    answer = client.post(f"/reset/{token}", follow_redirects=False, data={
        "password": NEW_PASSWORD, "confirm": NEW_PASSWORD, "csrf": csrf_of(page.text)})
    assert answer.status_code == 303
    assert answer.headers["location"] == web_auth.TWO_FACTOR_PATH + "?next=%2F"
    # and the session it holds is not a signed-in one
    assert client.get("/api/auth/check").status_code == 401


# ============================================ a hand-made account's first password

def test_the_set_password_link_lands_on_the_same_form(client):
    token = issue(onetime.SET_PASSWORD)
    page = client.get(f"/set-password/{token}")
    assert page.status_code == 200
    assert "Choose a password" in page.text and EMAIL in page.text


def test_setting_a_first_password_signs_in(client):
    token = issue(onetime.SET_PASSWORD)
    page = client.get(f"/set-password/{token}")
    answer = client.post(f"/set-password/{token}", follow_redirects=False, data={
        "password": NEW_PASSWORD, "confirm": NEW_PASSWORD, "csrf": csrf_of(page.text)})
    assert answer.status_code == 303
    assert client.get("/api/auth/check").status_code == 204


# ================================================== confirming an address

def test_a_confirm_link_stamps_the_address_and_signs_in(client):
    token = issue(onetime.CONFIRM)
    answer = client.get(f"/confirm/{token}", follow_redirects=False)
    assert answer.status_code == 303
    con = con_for()
    try:
        assert accounts.email_confirmed_at(accounts.get_user_by_email(con, EMAIL))
    finally:
        con.close()
    assert client.get("/api/auth/check").status_code == 204


def test_a_confirm_link_works_once(client):
    token = issue(onetime.CONFIRM)
    assert client.get(f"/confirm/{token}", follow_redirects=False).status_code == 303
    assert client.get(f"/confirm/{token}", follow_redirects=False).status_code == 410


def test_confirming_twice_keeps_the_first_stamp(client):
    con = con_for()
    try:
        user = accounts.get_user_by_email(con, EMAIL)
        accounts.mark_email_confirmed(con, user["id"])
        first = accounts.email_confirmed_at(accounts.get_user_by_email(con, EMAIL))
    finally:
        con.close()
    token = issue(onetime.CONFIRM)
    client.get(f"/confirm/{token}", follow_redirects=False)
    con = con_for()
    try:
        assert accounts.email_confirmed_at(accounts.get_user_by_email(con, EMAIL)) == first
    finally:
        con.close()


# ================================================== joining a workspace

def a_workspace(name="ops"):
    con = con_for()
    try:
        cur = con.execute("INSERT INTO workspaces (name, created_at)"
                          " VALUES (?, '2026-01-01T00:00:00+00:00')", (name,))
        con.commit()
        return cur.lastrowid
    finally:
        con.close()


def an_invite(email="dad@example.com", workspace_id=None, invited_by=EMAIL):
    con = con_for()
    try:
        return onetime.issue(con, onetime.INVITE, email,
                             workspace_id=workspace_id or a_workspace(),
                             invited_by=invited_by)[0]
    finally:
        con.close()


def test_an_invitation_names_the_workspace_and_who_sent_it(client):
    token = an_invite()
    page = client.get(f"/join/{token}")
    assert page.status_code == 200
    assert "Join ops" in page.text
    assert f"Invited by {EMAIL}" in page.text
    assert 'name="name"' in page.text


def test_an_invitation_with_no_role_claims_none(client):
    """Roles are enforced nowhere in the code, so an invitation this product
    can issue today carries none and the page says none. "as Admin" over a
    permission level that does not exist is the claim the accuracy rule
    forbids."""
    page = client.get(f"/join/{an_invite()}")
    assert f"Invited by {EMAIL}</div>" in page.text
    assert ", as" not in page.text
    from app import web_pages
    with_role = web_pages.join_page("t", "/join/x", "ops", EMAIL, role="Admin")
    assert f"Invited by {EMAIL}, as Admin" in with_role


def test_joining_makes_the_account_in_that_workspace_and_signs_in(client):
    workspace_id = a_workspace("theirs")
    token = an_invite(workspace_id=workspace_id)
    page = client.get(f"/join/{token}")
    answer = client.post(f"/join/{token}", follow_redirects=False, data={
        "name": "Dad", "password": NEW_PASSWORD, "confirm": NEW_PASSWORD,
        "csrf": csrf_of(page.text)})
    assert answer.status_code == 303
    con = con_for()
    try:
        user = accounts.get_user_by_email(con, "dad@example.com")
        assert user is not None
        assert accounts.workspace_of(user) == workspace_id
        assert accounts.display_name_of(user) == "Dad"
    finally:
        con.close()
    assert client.get("/api/auth/check").status_code == 204


def test_a_posted_workspace_decides_nothing(client):
    """The link names the workspace. A field in the form must not move an
    account into somebody else's fleet."""
    mine = a_workspace("mine")
    theirs = a_workspace("theirs")
    token = an_invite(workspace_id=mine)
    page = client.get(f"/join/{token}")
    client.post(f"/join/{token}", follow_redirects=False, data={
        "name": "Dad", "password": NEW_PASSWORD, "confirm": NEW_PASSWORD,
        "workspace_id": str(theirs), "csrf": csrf_of(page.text)})
    con = con_for()
    try:
        assert accounts.workspace_of(accounts.get_user_by_email(con, "dad@example.com")) == mine
    finally:
        con.close()


def test_an_invitation_works_once(client):
    token = an_invite()
    page = client.get(f"/join/{token}")
    csrf = csrf_of(page.text)
    first = client.post(f"/join/{token}", follow_redirects=False, data={
        "name": "Dad", "password": NEW_PASSWORD, "confirm": NEW_PASSWORD, "csrf": csrf})
    assert first.status_code == 303
    assert client.get(f"/join/{token}", follow_redirects=False).status_code == 410


def test_an_invitation_to_an_address_that_already_has_an_account_is_refused(client):
    token = an_invite(email=EMAIL)
    page = client.get(f"/join/{token}")
    answer = client.post(f"/join/{token}", follow_redirects=False, data={
        "name": "x", "password": NEW_PASSWORD, "confirm": NEW_PASSWORD,
        "csrf": csrf_of(page.text)})
    assert answer.status_code == 400
    assert "already has an account" in answer.text


def test_an_invitation_into_a_workspace_that_went_away_is_dead(client):
    token = an_invite(workspace_id=999)
    assert client.get(f"/join/{token}", follow_redirects=False).status_code == 410


# ================================================== turning two-factor on
#
# The enrolment is a window on the account's Security settings since
# 2026-09-10, so what is tested here are the two routes it talks to. The
# window itself is driven in a browser by
# `site/app/test_account_settings.py`.


def sign_in(client):
    page = client.get("/login")
    return client.post("/login", follow_redirects=False, data={
        "email": EMAIL, "password": PASSWORD, "next": "/", "csrf": csrf_of(page.text)})


def test_starting_an_enrolment_needs_a_session(client):
    assert client.post("/api/admin/account/2fa/start").status_code == 403
    con = con_for()
    try:
        assert not accounts.get_user_by_email(con, EMAIL)["totp_secret"]
    finally:
        con.close()


def test_the_gate_header_alone_cannot_start_one(client):
    """A forged gate header carries no account, so there is nothing for it to
    enrol and the answer is a refusal rather than a guess at workspace 1."""
    answer = client.post("/api/admin/account/2fa/start",
                         headers={"X-Admin-Gate": "caddy"})
    assert answer.status_code == 403


def test_starting_hands_back_a_real_key_and_a_qr_as_data(client):
    sign_in(client)
    answer = client.post("/api/admin/account/2fa/start")
    assert answer.status_code == 200
    assert answer.headers["cache-control"] == "no-store"
    body = answer.json()
    con = con_for()
    try:
        secret = accounts.get_user_by_email(con, EMAIL)["totp_secret"]
    finally:
        con.close()
    assert secret, "the enrolment did not start"
    assert body["groups"] == totp.format_secret_groups(secret)
    # rows of "0" and "1", not a picture and not markup
    assert body["qr"] and all(set(row) <= {"0", "1"} for row in body["qr"])
    assert len({len(row) for row in body["qr"]}) == 1, "the matrix is square"
    assert "<" not in answer.text


def test_the_answer_carries_no_markup_and_no_image(client):
    """The page it feeds holds no image and fetches nothing, which is a rule
    about the whole page (`site/app/test_render_live.py`). An answer carrying
    an SVG or a data URI would put one there."""
    sign_in(client)
    body = client.post("/api/admin/account/2fa/start").text
    for smell in ("<svg", "data:", "<img", "http"):
        assert smell not in body, smell


def test_starting_twice_replaces_an_unconfirmed_secret(client):
    sign_in(client)
    first = client.post("/api/admin/account/2fa/start").json()["groups"]
    second = client.post("/api/admin/account/2fa/start").json()["groups"]
    assert first != second


def test_a_right_code_turns_it_on_and_hands_back_the_codes_once(client):
    import time
    sign_in(client)
    client.post("/api/admin/account/2fa/start")
    con = con_for()
    try:
        secret = accounts.get_user_by_email(con, EMAIL)["totp_secret"]
    finally:
        con.close()
    answer = client.post("/api/admin/account/2fa/confirm",
                         json={"code": totp.code_at_time(secret, time.time())})
    assert answer.status_code == 200
    codes = answer.json()["codes"]
    assert len(codes) == accounts.RECOVERY_CODE_COUNT
    con = con_for()
    try:
        user = accounts.get_user_by_email(con, EMAIL)
        assert accounts.totp_enabled(user)
        assert accounts.recovery_codes_remaining(con, user["id"]) == len(codes)
    finally:
        con.close()
    # and no route hands them out again: confirming a second time is refused
    assert client.post("/api/admin/account/2fa/confirm",
                       json={"code": "000000"}).status_code == 400


def test_a_wrong_code_turns_nothing_on(client):
    sign_in(client)
    client.post("/api/admin/account/2fa/start")
    answer = client.post("/api/admin/account/2fa/confirm", json={"code": "000000"})
    assert answer.status_code == 400
    assert "not right" in answer.json()["detail"]
    con = con_for()
    try:
        assert not accounts.totp_enabled(accounts.get_user_by_email(con, EMAIL))
    finally:
        con.close()


def test_a_code_that_is_not_text_is_refused(client):
    sign_in(client)
    client.post("/api/admin/account/2fa/start")
    assert client.post("/api/admin/account/2fa/confirm",
                       json={"code": 123456}).status_code == 400


def test_confirming_is_rate_limited_on_the_account(client):
    """The same two buckets the login's second step charges, so a window is
    not a fresh set of attempts."""
    sign_in(client)
    client.post("/api/admin/account/2fa/start")
    for _ in range(40):
        answer = client.post("/api/admin/account/2fa/confirm", json={"code": "000000"})
        if answer.status_code == 429:
            break
    else:
        raise AssertionError("the enrolment never rate limited")


def test_an_account_that_already_has_it_on_cannot_start_again(client):
    """Starting again would replace the secret the phone already holds."""
    turn_two_factor_on()
    con = con_for()
    try:
        user = accounts.get_user_by_email(con, EMAIL)
        token, _ = accounts.issue_session(con, user["id"])
    finally:
        con.close()
    other = TestClient(ingest.app, cookies={web_auth.SESSION_COOKIE: token})
    answer = other.post("/api/admin/account/2fa/start")
    assert answer.status_code == 400
    assert "already on" in answer.json()["detail"]


# ================================================== what the pages promise

def test_every_new_page_is_no_store_and_not_indexed(client):
    token = issue(onetime.RESET)
    for path in ("/forgot", f"/reset/{token}"):
        page = client.get(path)
        assert page.headers["cache-control"] == "no-store", path
        assert 'name="robots" content="noindex,nofollow"' in page.text, path


def test_every_new_page_takes_its_look_from_the_design_system(client):
    """The palette is not restated in the control plane, the rule the login
    page is held to."""
    from app import web_pages
    token = issue(onetime.RESET)
    theme = web_pages.theme()
    for path in ("/forgot", f"/reset/{token}"):
        page = client.get(path).text
        assert theme.TOKENS in page, path
        assert "<base href=\"/\">" in page, path


# ============================== pages that say only what happened (2026-10-25)
#
# The second big test, cases A15 and A15b. Every expired or unknown link drew
# the Check your mail page with its heading swapped and an empty address, "A
# link went to" and nothing after it. And with no relay set the reset page
# said "A link went to" an address when no mail left, while the journal said
# none was sent. A page states what happened and nothing else.

@pytest.mark.parametrize("route", ["reset", "set-password", "confirm", "join"])
def test_a_dead_link_says_it_has_expired_and_no_sentence_is_cut_short(client, route):
    page = client.get(f"/{route}/{'0' * 64}", follow_redirects=False)
    assert page.status_code == 410
    assert "That link has expired" in page.text
    assert "A link went to" not in page.text
    assert "<b></b>" not in page.text
    assert 'href="/login"' in page.text


def test_a_spent_link_posted_again_says_the_same(client):
    spent = issue(onetime.RESET)
    form = client.get(f"/reset/{spent}")
    data = {"password": NEW_PASSWORD, "confirm": NEW_PASSWORD, "csrf": csrf_of(form.text)}
    client.post(f"/reset/{spent}", follow_redirects=False, data=data)
    again = client.post(f"/reset/{spent}", follow_redirects=False, data=data)
    assert again.status_code == 410
    assert "That link has expired" in again.text and "A link went to" not in again.text


def test_with_no_relay_the_reset_page_says_no_link_was_sent(client, monkeypatch, capsys):
    monkeypatch.delenv("WHICHPORTS_SMTP_HOST", raising=False)
    known = ask_for_a_link(client, EMAIL)
    unknown = ask_for_a_link(client, "nobody@example.com")
    for answer in (known, unknown):
        assert answer.status_code == 200
        assert "No link was sent" in answer.text
        assert "A link went to" not in answer.text and "Check your mail" not in answer.text
        assert EMAIL not in answer.text and "nobody@example.com" not in answer.text
        assert 'href="/login"' in answer.text
    # one answer whatever the address, so it says nothing about who has an account
    assert known.text == unknown.text
    assert "no relay" in capsys.readouterr().err
    con = con_for()
    try:
        assert con.execute("SELECT COUNT(*) FROM one_time_links").fetchone()[0] == 0
    finally:
        con.close()


# ------------------------------------------- a form body is read to its cap
#
# /login, /join and every other form here read their body through
# `web_auth.form_fields`, on app.whichports.com, which strangers reach. A
# body that says it is larger than the cap is not read at all, and one that
# says nothing is read only to the cap, so a stranger cannot make the ingest
# hold a gigabyte in memory to be refused (decided 27 October 2026).

def _form_request(chunks, length=None):
    """A real Starlette request whose body arrives in `chunks`. Returns it
    and the list of chunks it has handed over so far."""
    from starlette.requests import Request
    handed = []
    queue = list(chunks)
    headers = [(b"content-type", b"application/x-www-form-urlencoded")]
    if length is not None:
        headers.append((b"content-length", str(length).encode()))
    scope = {"type": "http", "method": "POST", "path": "/login",
             "headers": headers, "query_string": b""}

    async def receive():
        body = queue.pop(0) if queue else b""
        handed.append(body)
        return {"type": "http.request", "body": body, "more_body": bool(queue)}

    return Request(scope, receive), handed


def _read(request, *names):
    import asyncio
    from app import web_auth
    return asyncio.run(web_auth.form_fields(request, *names))


def test_a_form_body_that_says_it_is_too_large_is_not_read():
    from app import web_auth
    request, handed = _form_request([b"x" * 1024] * 200,
                                    length=web_auth.FORM_BODY_MAX_BYTES + 1)
    assert _read(request, "email", "csrf") == {"email": "", "csrf": ""}
    assert handed == []


def test_a_form_body_with_no_length_is_read_only_to_the_cap():
    from app import web_auth
    request, handed = _form_request([b"x" * 1024] * 1000)
    assert _read(request, "email", "csrf") == {"email": "", "csrf": ""}
    assert sum(len(chunk) for chunk in handed) <= web_auth.FORM_BODY_MAX_BYTES + 1024


@pytest.mark.parametrize("with_length", [True, False])
def test_a_form_inside_the_cap_is_read_whole(with_length):
    body = b"email=ann%40example.org&csrf=" + b"d" * 40
    request, _handed = _form_request([body[:10], body[10:]],
                                     length=len(body) if with_length else None)
    assert _read(request, "email", "csrf") == {"email": "ann@example.org", "csrf": "d" * 40}


def test_login_and_join_read_their_form_through_the_capped_reader():
    from app import web_auth
    import inspect
    assert 'await form_fields(request, "email", "password", "next", "csrf")' in \
        inspect.getsource(web_auth.login_submit)
    assert 'await form_fields(request, "name", "password", "confirm", "csrf")' in \
        inspect.getsource(web_auth.join_submit)
