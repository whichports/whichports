"""Run the sweeps once, then deliver anything they raised.

    python -m app.sweep_cli            # sweep, then send what is pending
    python -m app.sweep_cli --dry-run  # sweep, print, send nothing

Two sweeps run here. The dead-man switch (`app/alerts.py`) asks whether an
agent is reporting at all. The finding pass (`app/finding_alerts.py`) asks
what the reports and the probes add up to and whether that changed. They share
the alerts table, the delivery and the retry, and each has its own mail.

On the production box a five minute systemd timer runs this. Five rather than
fifteen so a host that goes quiet is noticed within a third of its own report
interval, and the sweep is cheap: one query over a handful of rows.

Exit codes are for the timer, not for a person. Zero unless the database
itself could not be opened, because "a host is silent" is the sweep working,
not the sweep failing, and a unit that goes red every time a server is down
teaches everyone to ignore it.
"""

import argparse
from dataclasses import replace
import sys
from datetime import datetime, timezone

from . import (alerts, authz, channels, cli, cvesend, cvetell, db, displayname,
               finding_alerts, hetzner, intent, notify, outbound, prober,
               reportingagain, senders, webhook)


def refresh_provider(con, now, client_factory=None) -> str:
    """Read the provider's firewalls with every held token, and say what
    happened in one line each.

    **It rides this timer rather than getting one of its own.** A new unit is a
    new thing to install by hand on the box, and this needs the same
    environment the sweep already has. Every sweep reads, since 2026-10-03
    (`docs/RECORD.md` 4.340): what a screen quotes as the reason a port
    answers has to be current, and an hour was not
    (`hetzner.SNAPSHOT_MAX_AGE_SECONDS` has the count of what it costs).

    **Off for a workspace with no token, and that is not an error.** It is
    what a fresh workspace looks like, and `app/join.py` already has a word
    for it: the provider view reads "not connected" on every row until one is
    held. Each workspace holding a token is read with its own token and its
    snapshot stored under its own id, since 2026-09-14 (record 4.178), so
    two customers' inventories never meet. A workspace may hold one token
    per project since 2026-09-27 (record 4.206), and each is read and aged
    on its own, so one project's refused token never stops another's read.

    **A failure here never fails the sweep.** The typed kind is printed and the
    stored snapshot stays as it was, because a provider that timed out is not a
    provider that changed its mind, and the alerting this timer exists for must
    not stop because an API did.
    """
    client_factory = client_factory or hetzner.client_for
    notes = []
    for workspace_id, token_id in hetzner.tokens_to_read(con):
        if not hetzner.needs_refresh(con, now, workspace_id=workspace_id,
                                     token_id=token_id):
            continue
        client = client_factory(hetzner.token_for(con, workspace_id, token_id))
        which = f"workspace {workspace_id} token {token_id}"
        try:
            snapshot = client.fetch_snapshot()
        except hetzner.ProviderError as exc:
            # The typed kind, never anything the provider wrote (SI-8's
            # posture). Recorded as well as printed, so the Integrations
            # screen can say the token was refused rather than showing the
            # last good snapshot as if nothing had happened.
            hetzner.record_fetch(con, now, exc, workspace_id=workspace_id,
                                 token_id=token_id)
            notes.append(f"{which}: provider not refreshed: {exc.kind}")
            continue
        hetzner.store_snapshot(con, snapshot, workspace_id=workspace_id, token_id=token_id)
        hetzner.record_fetch(con, now, workspace_id=workspace_id, token_id=token_id)
        left = client.rate_limit.remaining
        tail = f", {left} requests left this hour" if left is not None else ""
        notes.append(f"{which}: provider snapshot refreshed{tail}")
    return "\n".join(notes)


# The variable the environment-only arrangement on the production box reads,
# and the label the row standing in for it carries. Named once, because the
# fallback below and the notice it prints have to agree about both.
LEGACY_ENV = "WHICHPORTS_WEBHOOK_URL"


def mail_targets(con, env=None):
    """Who this run mails: `(rows, use_environment)`.

    `rows` is every email channel row that can deliver, from every workspace.
    Each is mailed about its own workspace's servers and no other's, which
    `mail_rows_deliver` holds.

    `use_environment` says whether `WHICHPORTS_ALERT_TO` is mailed as well. It
    is the operator's own address, so it stands in for the operator's
    workspace only, and only while that workspace holds no email row at all.
    A row that is switched off still counts as a row: a configured channel
    that cannot deliver is an answer, not a reason to reach for a recipient
    nobody named.

    **Decided per workspace since 2026-09-20.** It was decided once for the
    whole fleet, so workspace 1's rows switched the environment off for
    everybody and a workspace with no row of its own mailed nobody, which is
    what the first outside server did (`docs/RECORD.md` 4.186). And the
    environment's recipient never receives another workspace's alert, which
    is the owner's choice of the same day, from three put to him.
    """
    live_rows = channels.live(con, channels.TYPE_EMAIL)
    ready = [c for c in live_rows if c.enabled and c.resolve(env)]
    operator_has_rows = any(c.workspace_id == db.DEFAULT_WORKSPACE_ID
                            for c in live_rows)
    return ready, not operator_has_rows


# The mail for each kind, from the facts the sweep already has. One place, so
# the environment path and the row path cannot format the same alert two ways.
#
# `display` is the server's display name, or empty. Every message this run
# sends says it in its first line (docs/RECORD.md 4.238), and the names are
# read once per delivery pass, for the whole fleet, because a sweep has no
# session and watches every workspace.
def _format_for(kind, host_name, row=None, changes=None, display=""):
    if kind == finding_alerts.KIND_FINDING:
        return notify.format_finding_changes(host_name, changes, display)
    if kind == finding_alerts.KIND_OUTSIDE_STALE:
        return notify.format_outside_stale(host_name, row["detail"],
                                           row["raised_at"], display)
    return notify.format_silence(host_name, row["detail"], row["raised_at"],
                                 display)


def mail_environment_deliver(con, config, now):
    """Mail the environment's single recipient about the operator's own
    servers. Returns how many went out.

    Only the operator's workspace is read, see `mail_targets`. Stamped
    `notified_at` only on success, so a failed delivery is retried on the next
    sweep rather than lost. The alert itself is already recorded either way.
    """
    own = db.DEFAULT_WORKSPACE_ID
    names = displayname.display_names_by_host(con)
    sent = 0
    for row in alerts.pending_notifications(con, workspace_id=own):
        if row["kind"] == finding_alerts.KIND_FINDING:
            continue                          # coalesced below
        if row["kind"] not in (alerts.KIND_SILENT,
                               finding_alerts.KIND_OUTSIDE_STALE):
            continue                          # printed by main as unknown
        subject, body, html = _format_for(
            row["kind"], row["host_name"], row=row,
            display=names.get(row["host_name"], ""))
        ok, reason = notify.send(subject, body, config, html)
        if ok:
            alerts.mark_notified(con, row["id"], now)
            alerts.log_sent(con, row["id"], alerts.SENT_BY_ENVIRONMENT_MAIL, now)
            sent += 1
        else:
            print(f"not sent for {row['host_name']}: {reason}")

    for host_name, items in finding_alerts.pending_deliveries(
            con, workspace_id=own, now=now):
        # One mail per server, however many ports moved. Every alert in the
        # group is stamped together, because they left in one envelope.
        subject, body, html = _format_for(
            finding_alerts.KIND_FINDING, host_name,
            changes=[change for _, change in items],
            display=names.get(host_name, ""))
        ok, reason = notify.send(subject, body, config, html)
        if ok:
            for alert_id, _ in items:
                alerts.mark_notified(con, alert_id, now)
                alerts.log_sent(con, alert_id, alerts.SENT_BY_ENVIRONMENT_MAIL, now)
            sent += 1
        else:
            print(f"not sent for {host_name}: {reason}")
    return sent


def mail_rows_deliver(con, rows, config, now):
    """Mail every email channel row its own queue. Returns how many went out.

    **Driven by `alert_deliveries` and not by `notified_at`, and that is the
    whole point.** The first shape of this stamped `notified_at` on the first
    recipient's success and read the queue from `pending_notifications`, which
    filters on `notified_at IS NULL`. So the moment one address accepted, the
    alert left the mail queue and **a second address whose send had failed was
    never retried**. The tests did not catch it: the case they exercised was a
    second sweep with nothing outstanding, which passes either way. Found by
    deleting the guard and watching the test still pass.

    So this is shaped like the webhook loop below, for the same reason and with
    the same machinery: one queue per destination.

    `notified_at` is still stamped on success, because `docs/RECORD.md` 4.83
    decided it means a relay accepted the message and two screens read it. With
    several recipients it means at least one accepted, which is the honest
    reading of the same sentence.
    """
    names = displayname.display_names_by_host(con)
    sent = 0
    for channel in rows:
        key = alerts.key_for_channel(channel)
        to = channel.resolve()
        one = replace(config, to=to, sender=config.sender or to)

        for row in alerts.pending_for_channel(con, key,
                                              workspace_id=channel.workspace_id,
                                              added_at=channel.created_at or None):
            if row["kind"] == finding_alerts.KIND_FINDING:
                continue                      # coalesced below
            if not channel.takes(row["kind"]):
                alerts.mark_delivered(con, row["id"], key, now)
                continue
            subject, body, html = _format_for(
                row["kind"], row["host_name"], row=row,
                display=names.get(row["host_name"], ""))
            ok, reason = notify.send(subject, body, one, html)
            alerts.note_mail_answer(con, channel, ok, reason, now)
            if not ok:
                print(f"not sent for {row['host_name']}"
                      f" on {channel.label}: {reason}")
                continue
            alerts.mark_delivered(con, row["id"], key, now)
            alerts.mark_notified(con, row["id"], now)
            alerts.log_sent(con, row["id"], key, now)
            sent += 1

        for host_name, items in finding_alerts.pending_deliveries(
                con, channel=key, workspace_id=channel.workspace_id, now=now,
                added_at=channel.created_at or None):
            if not channel.takes(finding_alerts.KIND_FINDING):
                for alert_id, _ in items:
                    alerts.mark_delivered(con, alert_id, key, now)
                continue
            subject, body, html = _format_for(
                finding_alerts.KIND_FINDING, host_name,
                changes=[change for _, change in items],
                display=names.get(host_name, ""))
            ok, reason = notify.send(subject, body, one, html)
            alerts.note_mail_answer(con, channel, ok, reason, now)
            if not ok:
                print(f"not sent for {host_name} on {channel.label}: {reason}")
                continue
            for alert_id, _ in items:
                alerts.mark_delivered(con, alert_id, key, now)
                alerts.mark_notified(con, alert_id, now)
                alerts.log_sent(con, alert_id, key, now)
            sent += 1
    return sent


def note_for_the_operator(reason: str) -> None:
    """One more line under a refusal for a private address: which setting
    lets it through. It is said here, in the log an operator reads, and
    never on a screen (`app/outbound.py`)."""
    note = outbound.operator_note(reason)
    if note:
        print(f"  {note}")


def channel_targets(con, env=None):
    """Every non-mail channel this run should deliver to, as channel rows.

    **Rows first, and the environment only while there are none.** A channel
    row names the variable its destination lives in (`app/channels.py`), so the
    rows are what a screen can be told about. The fallback exists because the
    production box is configured by environment alone today, and a deploy that
    silently stopped delivering would be the monitoring tool failing quietly
    that `docs/PRODUCT.md` 4c exists to prevent.

    **The fallback says so on every run**, so it cannot become the permanent
    arrangement by nobody noticing. It ends the moment one row of any sending
    type exists.

    It returns a `channels.Channel` for the legacy case too, rather than a
    second shape the delivery loop would have to know about. That row is not in
    the database and never reaches it: it exists for the length of this call so
    one loop can carry both arrangements.
    """
    rows = []
    for channel_type in channels.SENDING_TYPES:
        rows.extend(channels.sending(con, channel_type, env))
    if rows:
        return rows

    if any(channels.live(con, t) for t in channels.SENDING_TYPES):
        # Rows exist and none can send. That is a configured channel with an
        # unset variable or one switched off, which is an answer rather than a
        # reason to fall back to a variable nobody pointed at.
        return []

    if webhook.config_from_env(env).configured:
        print(f"no channel rows, so {LEGACY_ENV} is being"
              " used directly. Add a row and this notice goes away:"
              " python -m app.channels_cli add --type webhook --label NAME"
              f" --env {LEGACY_ENV}")
        return [channels.Channel(id=0, type=channels.TYPE_WEBHOOK,
                                 label=LEGACY_ENV, destination_env=LEGACY_ENV,
                                 enabled=True, destination_extra="",
                                 # The operator's own arrangement, so it
                                 # watches the fleet rather than one workspace.
                                 workspace_id=None)]
    return []


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sweep", description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="sweep and report, deliver nothing")
    args = parser.parse_args(argv)

    con = cli.open_database(args)
    db.init(con)
    # The prober's and the declarations' tables are created here because the
    # finding pass reads both and this timer runs on a box where neither
    # command has ever been used.
    prober.init(con)
    intent.init(con)
    alerts.init(con)
    finding_alerts.init(con)
    authz.init(con)
    channels.init(con)
    hetzner.init(con)
    cvetell.init(con)
    cvesend.init(con)

    now = datetime.now(timezone.utc)

    # Before the sweeps, so a finding is joined against the provider's view
    # as this tick read it and not the one from the tick before.
    note = refresh_provider(con, now)
    if note:
        print(note)

    # Proofs of control, before anything that depends on them: a published
    # proof left in place is read again every day and stays alive, one whose
    # evidence went away ends, and what has lapsed is recorded so the
    # listing reads honestly. The gate decides by the clock either way
    # (app/authz.py), so none of this can make an address probeable that
    # would not be.
    renewals = authz.renew_published(con, now=now)
    for target in renewals["renewed"]:
        print(f"renewed: the proof for {target} was read again")
    for target, reason in renewals["failed"]:
        print(f"not renewed: {target}: {reason}")
    for target in renewals["ended"]:
        print(f"ended: the proof for {target} is gone from where it was"
              " published, so it is no longer probed")
    lapsed = authz.sweep(con, now=now)
    for target in lapsed["expired"]:
        print(f"lapsed: the proof for {target} has expired, so it is no longer probed")

    result = alerts.sweep(con, now=now)

    if result["self_outage"]:
        print("this control plane was down longer than the silence threshold, "
              "so new silence alerts are held for one window")
    for name in result["held"]:
        print(f"held: {name} is silent, not raised while recovering from our own outage")
    for name in result["raised"]:
        print(f"raised: {name} stopped reporting")
    for name in result["resolved"]:
        print(f"resolved: {name} is reporting again")
    for name in result["closed"]:
        print(f"closed: {name} is paused or revoked, so it is no longer watched")
    for name in result["retracted"]:
        print(f"retracted: {name} has never reported, so it never stopped reporting")
    for name in result["unreadable"]:
        print(f"not measured: {name} has a last report stamp this build cannot read")

    # After the dead-man sweep, because the recovery point it maintains is
    # what the finding pass measures its own window from.
    findings = finding_alerts.evaluate(con, now=now)
    for name in findings["gone"]:
        # Typed, the same every time. Not a failure of the run: the server
        # was deleted while the pass was under way, and the rest was written.
        print(f"left out: {name} was deleted during the pass")
    for label in findings["raised"]:
        print(f"changed: {label}")
    for label in findings["suppressed"]:
        print(f"changed, not mailed: {label} is muted or silenced")
    for label in findings["rate_limited"]:
        print(f"changed, not mailed: {label} sits behind a rate limit rule, and"
              " a rate limit makes the same port answer and not answer"
              " depending on how recently it was asked")
    for label in findings["told"]:
        print(f"became reachable: {label}, answered by a rule or a yes,"
              " one mail and nothing open")
    for label in findings["new_program"]:
        print(f"new program: {label}, a different program answers a port with"
              " an answer, one mail and nothing open")
    for label in findings["noted"]:
        print(f"settled: {label} no longer asks for attention")
    for label in findings["reverted"]:
        print(f"reverted: {label} went back inside the window and was not mailed")
    for label in findings["superseded"]:
        print(f"superseded: {label} changed again before the window elapsed")
    for label in findings["holding"]:
        print(f"holding: {label} changed and the window has not elapsed")
    for name in findings["closed"]:
        print(f"closed: {name} was revoked, so its findings are no longer watched")
    for label in findings["unreadable"]:
        print(f"not measured: {label} has a change stamp this build cannot read")

    # After the finding pass, because both read the same probe runs and this
    # one only asks how old they are.
    stale = finding_alerts.sweep_outside_views(con, now=now)
    for name in stale["stale"]:
        print(f"stale: {name} has had no probing pass finish in"
              f" {finding_alerts.OUTSIDE_STALE_AFTER_SECONDS // 3600} hours")
    for name in stale["resolved"]:
        print(f"fresh again: {name} is being probed")
    for name in stale["held"]:
        print(f"holding: {name} looks stale and this control plane was down,"
              " or its stamp cannot be read")

    pending = alerts.pending_notifications(con)
    silences = [row for row in pending if row["kind"] == alerts.KIND_SILENT]
    stale_rows = [row for row in pending
                  if row["kind"] == finding_alerts.KIND_OUTSIDE_STALE]
    groups = finding_alerts.pending_deliveries(con, now=now)
    # A kind with no formatter is printed rather than dropped. A future kind
    # that silently never delivers is the failure this line exists to make
    # loud.
    known = {alerts.KIND_SILENT, finding_alerts.KIND_FINDING,
             finding_alerts.KIND_OUTSIDE_STALE}
    for kind in sorted({row["kind"] for row in pending} - known):
        print(f"not sent: this build has no mail for alerts of kind {kind}")

    if args.dry_run:
        for row in silences:
            print(f"would send: {row['host_name']} stopped reporting")
        for host_name, items in groups:
            print(f"would send: {host_name}, {len(items)} findings changed")
        for row in stale_rows:
            print(f"would send: {row['host_name']}'s outside view is stale")
        targets = channel_targets(con)
        if targets:
            first = alerts.key_for_channel(targets[0])
            due = [row for row in alerts.pending_for_channel(
                       con, first, workspace_id=targets[0].workspace_id,
                       added_at=targets[0].created_at or None)
                   if row["kind"] != finding_alerts.KIND_FINDING]
            due += finding_alerts.pending_deliveries(
                con, channel=first, workspace_id=targets[0].workspace_id,
                now=now, added_at=targets[0].created_at or None)
            kinds = ", ".join(sorted({t.type for t in targets}))
            print(f"would post: {len(due)} to each of {len(targets)}"
                  f" channels ({kinds})")
        else:
            print("would post: nothing, no channel is configured")
        print(f"checked {result['checked']} hosts, "
              f"{len(result['pending'])} waiting for a first report, "
              f"{len(silences) + len(groups) + len(stale_rows)} pending,"
              " dry run")
        con.close()
        return 0

    config = notify.config_from_env()
    mail_rows, use_environment = mail_targets(con)
    sent = 0

    if use_environment:
        sent += mail_environment_deliver(con, config, now)
    sent += mail_rows_deliver(con, mail_rows, config, now)
    # A refusal the Fleet's banner shows stays only while its destination
    # is one this run mails (`alerts.note_mail_answer`).
    alerts.forget_mail_refusals_but(con, mail_rows)

    # ------------------------------------------------------- the channels
    #
    # Every channel that is not mail. Each has its own queue, read from
    # `alert_deliveries` rather than `notified_at`, so a mail that was accepted
    # beside a webhook that timed out leaves the webhook retryable without
    # sending the mail twice.
    #
    # It hangs off the same pending machinery the mail does, which is not
    # tidiness: `docs/PRODUCT.md` 4c's rules about when to alert live in that
    # machinery, so the debounce, the coalescing per server, the mute and the
    # permanent silence all apply here without being written a second time.
    #
    # **One channel's failure is never another's.** The key is per destination
    # (`alerts.channel_key`), so a Slack row that is refusing connections
    # leaves its own alerts pending and takes nothing away from the Telegram
    # row beside it.
    posted = 0
    names = displayname.display_names_by_host(con)
    chat_rows = channel_targets(con)
    for channel in chat_rows:
        key = alerts.key_for_channel(channel)
        for row in alerts.pending_for_channel(con, key,
                                              workspace_id=channel.workspace_id,
                                              added_at=channel.created_at or None):
            if row["kind"] == finding_alerts.KIND_FINDING:
                # Coalesced below, one post per server, so not here.
                continue
            if not channel.takes(row["kind"]):
                # Not subscribed. **Marked delivered rather than skipped**, or
                # this alert stays pending against this channel for ever and
                # every later sweep asks the same question again. The operator
                # said they do not want this kind, so it is dealt with.
                alerts.mark_delivered(con, row["id"], key, now)
                continue
            ok, reason = senders.deliver_alert(
                channel, row["kind"], row["host_name"], row["detail"],
                row["raised_at"], display=names.get(row["host_name"], ""))
            if ok:
                alerts.mark_delivered(con, row["id"], key, now)
                alerts.log_sent(con, row["id"], key, now)
                posted += 1
            else:
                print(f"not posted for {row['host_name']}"
                      f" on {channel.label}: {reason}")
                note_for_the_operator(reason)

        for host_name, items in finding_alerts.pending_deliveries(
                con, channel=key, workspace_id=channel.workspace_id, now=now,
                added_at=channel.created_at or None):
            if not channel.takes(finding_alerts.KIND_FINDING):
                for alert_id, _ in items:
                    alerts.mark_delivered(con, alert_id, key, now)
                continue
            ok, reason = senders.deliver_changes(
                channel, host_name, [change for _, change in items],
                display=names.get(host_name, ""))
            if ok:
                for alert_id, _ in items:
                    alerts.mark_delivered(con, alert_id, key, now)
                    alerts.log_sent(con, alert_id, key, now)
                posted += 1
            else:
                print(f"not posted for {host_name}"
                      f" on {channel.label}: {reason}")
                note_for_the_operator(reason)

    # ------------------------------------------------------ the CVE check
    #
    # What a newer version fixes that was not told before, one message a
    # workspace, to the destinations above (`app/cvetell.py`,
    # `app/cvesend.py`). A report with no packages section gives nothing to
    # look at, which is every report of the published agent.
    #
    # **Nothing in the check can stop the sweep.** The sweep's own work is
    # the alerts above, and it has done it by here. A fault in the look or
    # in the sending is said with its class, never its message, and the run
    # goes on to its end. A dry run never reaches this: the look writes down
    # what it saw.
    try:
        told = cvetell.evaluate(con, now=now)
    except Exception as exc:
        told = []
        print(f"the CVE look failed: {type(exc).__name__}")
    try:
        cves_sent = cvesend.deliver(con, now, config=config, use_environment=use_environment,
                                    mail_rows=mail_rows, chat_rows=chat_rows)
    except Exception as exc:
        cves_sent = 0
        print(f"the CVE sending failed: {type(exc).__name__}")
    if told or cves_sent:
        print(f"CVEs: {len(told)} {'workspace' if len(told) == 1 else 'workspaces'} told,"
              f" {cves_sent} sent")

    # The log of what went out keeps `alerts.SENT_LOG_DAYS` days. After the
    # sends, so nothing this run wrote can be what goes.
    alerts.prune_sent_log(con, now)

    # A silent agent that reports again: one short message to each channel
    # that was told it stopped (`app/reportingagain.py`). After every alert,
    # so it delays none, and a failure here never fails the sweep: the
    # class is printed and the next run tries again.
    try:
        again = reportingagain.deliver(con, now, config=config,
                                       use_environment=use_environment,
                                       mail_rows=mail_rows, chat_rows=chat_rows)
    except Exception as exc:
        again = 0
        print(f"the reporting again message failed: {type(exc).__name__}")
    if again:
        print(f"reporting again: {again} sent")

    print(f"checked {result['checked']} hosts, {len(result['raised'])} raised, "
          f"{len(result['resolved'])} resolved, {len(result['closed'])} closed, "
          f"{len(result['pending'])} waiting for a first report, "
          f"{len(findings['raised'])} findings changed, "
          f"{len(findings['told'])} became reachable with an answer, "
          f"{len(findings['new_program'])} answered by a different program, "
          f"{len(findings['suppressed'])} changed and muted, "
          f"{len(findings['rate_limited'])} changed behind a rate limit, "
          f"{sent} mailed, {posted} posted")
    con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
