"""The operator every admin-route test acts as.

Until 2026-09-12 these tests sent the `X-Admin-Gate` header Caddy used to
stamp under basic auth, and the app took the header alone as proof. It takes
a live session now and nothing else (`app/ingest.py`, `require_operator`), so
a test that wants to act as the operator signs one in.

`gate()` returns a Cookie header carrying a fresh session for one operator
account in workspace 1, created on first use in whatever database the test's
`client` fixture pointed the process at. It is a header rather than a cookie
jar so `headers=gate()` slots in exactly where `headers=GATE` used to be.
`http.cookiejar` never overwrites a Cookie header a request already carries,
so a client built with its own session cookie and handed this header sends
this one.
"""
from app import accounts, db, web_auth

OPERATOR = "gate-operator@example.com"
PASSWORD = "correct-horse-battery-9"


def sign_in(client):
    """Put the operator's session into `client`'s own cookie jar and hand it
    back. For a test whose client already carries another cookie, because a
    Cookie header from `gate()` would replace the jar for that request."""
    client.cookies.set(web_auth.SESSION_COOKIE, _session())
    return client


def gate(**extra) -> dict:
    """Headers that prove an operator in workspace 1, plus any `extra`."""
    return {"Cookie": f"{web_auth.SESSION_COOKIE}={_session()}", **extra}


def _session() -> str:
    con = db.connect()
    try:
        db.init(con)
        accounts.init(con)
        user = accounts.get_user_by_email(con, OPERATOR)
        if user is None:
            accounts.create_user(con, OPERATOR, PASSWORD,
                                 workspace_id=db.DEFAULT_WORKSPACE_ID)
            # An account is given an email channel when it is made
            # (`tests/test_account_email_channel.py` holds that). This
            # operator exists only to carry a session, and the tests that use
            # it assert whole tables of rows they put there themselves, so its
            # channel is taken out again. Deleted outright, because those
            # tests list removed rows too.
            con.execute("DELETE FROM notification_channels"
                        " WHERE type = 'email' AND destination = ?",
                        (OPERATOR,))
            con.commit()
            user = accounts.get_user_by_email(con, OPERATOR)
        token, _ = accounts.issue_session(con, user["id"])
    finally:
        con.close()
    return token
