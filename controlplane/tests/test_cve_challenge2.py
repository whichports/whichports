"""The second challenge to the CVE check, on `cve-control-plane` at ff6035a8:
workspaces, the telling and the sending. Each test here fails on that commit.
Nothing here is fixed. The tests say what should hold.

    python -m pytest tests/test_cve_challenge2.py

The servers, the names and the CVE numbers are made up.
"""
import json
from datetime import timedelta

from app import cvecard, cvetell, db, displayname, finding_alerts, store
from test_cvesend import MAIL, NOW, Sent, batch, con, deliver, hook, mailbox  # noqa: F401
from test_cvetell import FIRST, LATER, extracts, report, reports


def said_of(post):
    """Everything one chat post says, as text."""
    _label, text, payload, message = post
    return " ".join([text, json.dumps(payload), message.title, repr(message.fields)])


# ------------------------------------------------------------ workspaces

def test_a_batch_never_says_another_workspaces_display_name(con):  # noqa: F811
    """A batch names its servers as text and outlives them. A display name
    is looked up by that text in every workspace at once
    (`cvesend.deliver`, `displayname.display_names_by_host(con)`).

    Workspace 1 is told about mail-01 and its one destination fails. Within
    the day workspace 1 removes and deletes mail-01, and another workspace
    gives that name to a server of its own with a display name. The batch
    is tried again and workspace 1's destination is handed the other
    workspace's display name."""
    other = db.create_workspace(con, "another")
    hook(con, "ours")
    batch(con, MAIL)
    sent = Sent(refuse={"ours"})
    assert deliver(con, sent) == 0
    assert store.revoke_host(con, "mail-01") and store.delete_host(con, "mail-01")
    store.add_host(con, "mail-01", workspace_id=other)
    assert displayname.set_display_name(con, "mail-01", "Their own name", workspace_id=other)
    sent.refuse.clear()
    assert deliver(con, sent, now=NOW + timedelta(minutes=5)) == 1
    assert "Their own name" not in said_of(sent.posts[0]), said_of(sent.posts[0])


# ------------------------------------------------- the telling and sending

def test_nothing_else_is_sent_about_a_cve_after_the_message_that_says_so(con):  # noqa: F811
    """Two servers of one workspace carry the same OpenSSH. One is muted the
    hour a fix is published. The first message tells the CVE for the other
    and ends "Nothing else will be sent about these CVEs." When the mute
    ends a second message tells the same CVE. What is kept is a CVE on a
    port of a server, and the line promises the CVE."""
    for name in ("web-07", "db-02"):
        host_id, _ = store.add_host(con, name)
        reports(con, host_id, report())
    mailbox(con)
    sent = Sent()
    cvetell.evaluate(con, now=NOW, extract_for=extracts(FIRST))
    finding_alerts.mute_host(con, "db-02", now=NOW)
    cvetell.evaluate(con, now=NOW, extract_for=extracts(LATER))
    deliver(con, sent)
    assert len(sent.mails) == 1 and "Nothing else will be sent about these CVEs on the same port." in sent.mails[0][2]
    finding_alerts.unmute_host(con, "db-02", now=NOW)
    cvetell.evaluate(con, now=NOW + timedelta(minutes=5), extract_for=extracts(LATER))
    deliver(con, sent, now=NOW + timedelta(minutes=5))
    told = [json.loads(row[0]) for row in con.execute("SELECT told FROM cve_batches ORDER BY id")]
    cves = [sorted({cve for server in one for cve in server["cves"]}) for one in told]
    assert len(sent.mails) == 1, f"a second message about the same CVE: {cves}"


def test_a_server_muted_after_its_batch_was_written_is_not_told_about_at_the_next_try(con):  # noqa: F811
    """The batch is written, its destination fails, and the server is muted
    before the next sweep. The batch is tried again and the message about
    the muted server goes out: the sending never asks about a mute."""
    hook(con, "ours")
    batch(con, MAIL)
    sent = Sent(refuse={"ours"})
    assert deliver(con, sent) == 0
    finding_alerts.mute_host(con, "mail-01", now=NOW)
    sent.refuse.clear()
    deliver(con, sent, now=NOW + timedelta(minutes=5))
    assert sent.posts == [], "told about a muted server: " + sent.posts[0][3].title


def test_the_count_in_the_mail_is_the_count_the_page_shows_for_that_server(con):  # noqa: F811
    """The mail's `CVEs` is what is new since the last look. The mark on the
    server's page, which the mail's one button opens, counts every CVE a
    newer version fixes. Nothing in the mail says its number is of new ones
    only."""
    host_id, _ = store.add_host(con, "web-07")
    reports(con, host_id, report())
    mailbox(con)
    sent = Sent()
    cvetell.evaluate(con, now=NOW, extract_for=extracts(FIRST))
    cvetell.evaluate(con, now=NOW, extract_for=extracts(LATER))
    deliver(con, sent)
    body = sent.mails[0][2]
    in_the_mail = int(body.split("  CVEs: ")[1].split("\n")[0])
    cards = cvecard.cards_of(report(), extracts(LATER), NOW)
    on_the_page = cvecard.server_mark(cards.values())
    assert on_the_page.endswith(f" {cvecard.count_of(in_the_mail)}"), (
        f"the mail says CVEs: {in_the_mail}, the page's mark says: {on_the_page}")



# ------------------------------------------------------------ what is kept

def test_a_batch_nobody_can_be_sent_any_more_is_not_kept_for_ever(con):  # noqa: F811
    """A batch is handed out for a day and to nobody after that. It holds the
    servers' names, their ports and the CVE ids, and it stays when its server
    is deleted. The sent log, which holds less, is pruned by the sweep after
    `alerts.SENT_LOG_DAYS`. Nothing ever deletes a batch: no statement in
    `cvetell.py` or `cvesend.py` does, and `store.HOST_TABLES` leaves the
    table out on purpose."""
    from app import alerts, cvesend
    mailbox(con)
    batch(con, MAIL)
    deliver(con, Sent())
    assert store.revoke_host(con, "mail-01") and store.delete_host(con, "mail-01")
    much_later = NOW + timedelta(days=alerts.SENT_LOG_DAYS + 1)
    # What a sweep runs for the check and for its log, on that day.
    cvetell.evaluate(con, now=much_later, extract_for=extracts(LATER))
    deliver(con, Sent(), now=much_later)
    alerts.prune_sent_log(con, much_later)
    assert con.execute("SELECT COUNT(*) FROM sent_log").fetchone()[0] == 0
    kept = [row[0] for row in con.execute("SELECT told FROM cve_batches")]
    assert kept == [], f"still kept, for a deleted server: {kept}"
    assert cvesend.SEND_WITHIN < timedelta(days=alerts.SENT_LOG_DAYS)
