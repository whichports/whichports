"""The Admin screen in B's shape, drawn from numbers somebody else counted.

Run from site/app: python3 -m pytest test_admin_view.py

Because the owner reads every diff but has said he cannot be relied on to catch a
subtle bug in review, these tests are the review. The screen is
`docs/screens/admin/SPEC.md`, his picks of `docs/record` 4.425. The ones
carrying the argument:

  - with no numbers there is no screen and no nav entry in the HTML at all, so
    an account without the flag has nothing to reveal by editing the address
  - the strip is on every tab, a box takes the fail tone only for a fault and
    never for zero of zero, and neither the probers' box nor the sweep's flaps
    between two runs of their timers
  - an instance's word is the freshness word for the same age, from its key's
    last use, and an instance with nothing to probe is not called silent
  - every table has the Fleet's head with the state first, every row is a
    link or opens in place, no row ends in a button, and every table's fixed
    tracks sum under the narrowest body at 1024
  - the lookup posts with the page's token, the address is kept nowhere, and
    what is not an address gets one word
  - the screen says only labels, values, names, numbers, statuses and one
    line when a section is empty, and never a hash or a key
  - every fixture address is at example.com and every name is made up
"""
import pathlib
import re
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

import build as tpl
import render_live as rl
import theme

NOW = datetime(2026, 10, 6, 17, 20, tzinfo=timezone.utc)

SCHEMA = """
CREATE TABLE workspaces (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, token_hash TEXT UNIQUE,
    kind TEXT NOT NULL DEFAULT 'agent',
    created_at TEXT NOT NULL, revoked_at TEXT, last_report_at TEXT,
    paused INTEGER NOT NULL DEFAULT 0, auto_named INTEGER NOT NULL DEFAULT 0,
    workspace_id INTEGER NOT NULL DEFAULT 1);
CREATE TABLE reports (
    id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id),
    received_at TEXT NOT NULL, collected_at_unix INTEGER NOT NULL,
    schema_version INTEGER NOT NULL, document TEXT NOT NULL);
INSERT INTO workspaces (id, name, created_at)
    VALUES (1, 'default', '2026-08-27T12:00:00+00:00');
"""


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "cp.db"
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    con.commit()
    con.close()
    return str(path)


def iso(**delta):
    return (NOW - timedelta(**delta)).isoformat()


def stats(**over):
    """The shape `controlplane/app/adminstats.collect` returns.

    Written out here rather than imported, deliberately. The control plane
    cannot be imported from this tree (site/app/joinbridge.py says why), and a
    fixture that mirrors a shape is how every other test in this directory
    handles that. `test_the_screen_carries_the_service_wide_numbers` in the
    control plane's own suite is what keeps the two honest. Every address is
    at example.com and every name is made up.
    """
    base = {
        "accounts": {"total": 3, "disabled": 0, "never_signed_in": 0,
                     "signed_in_week": 1, "new_week": 0, "new_month": 1,
                     "two_factor": 1, "providers": {"google": 1}},
        "workspaces": {"total": 3, "with_server": 3, "with_report": 2,
                       "with_probe": 2},
        # One world: the cards and the lists agree, as they do on the box,
        # where both come from one database. Silent 1 and not watched 1
        # are the quiet list's two rows; the workspaces' accounts add up to
        # the accounts list's three rows.
        "servers": {"total": 7, "revoked": 1, "agent": 6, "address": 1,
                    "paused": 0, "reporting": 5, "silent": 1,
                    "never_reported": 1},
        "activity": {"documents_day": 384, "documents_week": 2688,
                     "documents_total": 0, "probe_runs_day": 936,
                     "probe_runs_total": 0, "alerts_open": 0, "channels": 5},
        "newest": [{"email": "ops@example.net",
                    "created_at": "2026-10-01T12:00:00+00:00",
                    "last_login_at": "",
                    "workspace_id": 5, "servers": 0, "disabled": False},
                   {"email": "admin@example.org",
                    "created_at": "2026-09-30T12:40:00+00:00",
                    "last_login_at": "2026-10-04T09:12:00+00:00",
                    "workspace_id": 4, "servers": 4, "disabled": False},
                   {"email": "owner@example.com",
                    "created_at": "2026-08-13T18:30:00+00:00",
                    "last_login_at": "2026-10-06T16:50:00+00:00",
                    "workspace_id": 1, "servers": 3, "disabled": False}],
        "accounts_total": 3,
        "workspace_rows": [
            {"id": 1, "name": "default", "created_at": "2026-08-13T18:30:00+00:00",
             "accounts": 1, "servers": 3, "reporting": 3, "last_report_at": iso(minutes=1)},
            {"id": 4, "name": "sandbox", "created_at": "2026-09-30T12:40:00+00:00",
             "accounts": 1, "servers": 4, "reporting": 2, "last_report_at": iso(minutes=5)},
            {"id": 5, "name": "oakhill", "created_at": "2026-10-01T12:00:00+00:00",
             "accounts": 1, "servers": 0, "reporting": 0, "last_report_at": ""},
        ],
        "quiet_servers": [
            {"name": "new-b78f6d", "workspace_id": 4, "kind": "agent",
             "created_at": "2026-09-27T21:10:00+00:00", "last_report_at": "",
             "never": True, "paused": False},
            {"name": "web-02", "workspace_id": 1, "kind": "agent",
             "created_at": "2026-10-03T13:20:00+00:00", "last_report_at": iso(days=2),
             "never": False, "paused": False},
        ],
        "quiet_servers_total": 2,
        "watchdog": {"sweep": iso(seconds=40), "probe": iso(minutes=9),
                     "vantages": [{"name": "probe1", "enabled": True, "last_run": iso(minutes=9)},
                                  {"name": "probe2", "enabled": True, "last_run": iso(minutes=11)}]},
        "signups": "closed",
        "signups_allowed": 0,
        "instances": [
            {"id": 1, "name": "selfhost-test-1", "created_at": "2026-10-06T09:31:55+00:00",
             "revoked_at": "2026-10-06T09:44:28+00:00",
             "last_used_at": "2026-10-06T09:44:16+00:00",
             "last_batch_at": "2026-10-06T09:44:16+00:00",
             "proofs": 0, "targets_today": 2, "connects_hour": 0,
             "keys": [{"kind": "api", "created_at": "2026-10-06T09:31:55+00:00",
                       "revoked_at": "2026-10-06T09:44:28+00:00"},
                      {"kind": "proof", "created_at": "2026-10-06T09:31:55+00:00",
                       "revoked_at": "2026-10-06T09:44:28+00:00"}],
             "log": [{"vantage": "probe1", "targets": 2, "batches": 16, "connects": 96},
                     {"vantage": "probe2", "targets": 2, "batches": 16, "connects": 96}],
             "failure": None},
            {"id": 2, "name": "oakhill", "created_at": "2026-10-05T10:00:00+00:00",
             "revoked_at": None, "last_used_at": iso(minutes=3),
             "last_batch_at": "", "proofs": 0, "targets_today": 0, "connects_hour": 0,
             "keys": [{"kind": "api", "created_at": "2026-10-05T10:00:00+00:00", "revoked_at": None},
                      {"kind": "proof", "created_at": "2026-10-05T10:00:00+00:00", "revoked_at": None}],
             "log": [], "failure": None},
        ],
        "beta": {"rows": [], "total": 0},
        "thresholds": {"silent_after": 35 * 60, "sweep_stale": 11 * 60},
        # The Feedback tab's rows, open and done, as `feedback.listing`
        # gives them (docs/screens/feedback/BRIEF.md). None here: the open
        # count and the list are one world, test_feedback_window holds it.
        "feedback_open": 0,
        "feedback": {"open": [], "done": []},
        "lookup": None,
    }
    base.update(over)
    return base


def add_host(db, name):
    con = sqlite3.connect(db)
    con.execute("INSERT OR IGNORE INTO hosts (name, token_hash, created_at,"
                " last_report_at, workspace_id) VALUES (?, ?, ?, ?, 1)",
                (name, f"t-{name}", NOW.isoformat(),
                 (NOW - timedelta(minutes=3)).isoformat()))
    con.commit()
    con.close()


def page(db, **over):
    add_host(db, "web-01")
    return rl.render(db, now=NOW, workspace_id=1, admin=stats(**over), csrf="t" * 40)


def view_of(html):
    """The Admin view's markup, from its opening div to the next window."""
    view = html[html.index('<div class="wrap view" id="admin">'):]
    return view[:view.index('<div class="ovl"')]


def text_of(markup):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", markup)).strip()


def test_the_fixture_is_one_world():
    """The cards and the lists on a frame come from one database on the box
    and agree there; the fixture agrees the same way, or a frame contradicts
    itself (docs/record 4.440)."""
    numbers = stats()
    assert len(numbers["quiet_servers"]) == numbers["servers"]["silent"] + numbers["servers"]["never_reported"]
    assert numbers["quiet_servers_total"] == len(numbers["quiet_servers"])
    assert len(numbers["newest"]) == sum(r["accounts"] for r in numbers["workspace_rows"]) == numbers["accounts_total"]
    assert sum(r["servers"] for r in numbers["workspace_rows"]) == numbers["servers"]["total"]


# ======================================= no numbers, no screen, no nav entry

def test_a_page_without_numbers_has_no_admin_view(db):
    add_host(db, "web-01")
    html = rl.render(db, now=NOW, workspace_id=1)
    assert 'id="admin"' not in html
    assert ">Admin</a>" not in html and 'data-v="admin"' not in html


def test_a_page_with_numbers_has_both(db):
    html = page(db)
    assert 'id="admin"' in html
    assert 'data-v="admin"' in html


def test_the_nav_entry_and_the_view_always_arrive_together(db):
    add_host(db, "web-01")
    for numbers in (None, stats()):
        html = rl.render(db, now=NOW, workspace_id=1, admin=numbers)
        assert ('data-v="admin"' in html) == ('id="admin"' in html)


def test_the_ordinary_page_is_otherwise_unchanged(db):
    add_host(db, "web-01")
    plain = rl.render(db, now=NOW, workspace_id=1)
    withadmin = rl.render(db, now=NOW, workspace_id=1, admin=stats())
    assert 'id="fleet"' in plain and 'id="fleet"' in withadmin
    assert plain.count('class="row"') == withadmin.count('class="row"')


# ==================================================================== the strip

def strip_of(html):
    view = view_of(html)
    strip = view[view.index('class="fstrip adm"'):]
    return strip[:strip.index('<div class="subnav">')]


def test_the_strip_is_on_every_tab_and_each_box_opens_its_tab(db):
    view = view_of(page(db))
    assert view.count('class="fstrip adm"') == 1
    assert view.index('class="fstrip adm"') < view.index('class="subnav"')
    strip = strip_of(page(db))
    for key in ("instances", "betalist", "servers"):
        assert f'<label for="tb-admin-{key}"' in strip
    assert strip.count("<label ") == 4


def test_the_four_boxes_say_what_the_spec_says(db):
    text = text_of(strip_of(page(db)))
    assert "Instances reporting 1 of 1 live" in text
    assert "Waiting for an invite 0 on the beta list" in text
    assert "Probers 2 of 2 probe1 9m ago probe2 11m ago 936 runs in 24h" in text
    assert "Sweep 40s ago 384 documents in 24h" in text


def box_tone(html, label):
    strip = strip_of(html)
    box = strip[strip.index(label):]
    box = box[:box.index("</label>")]
    return "fail" if 'class="n fail"' in box else "plain"


def test_a_box_takes_the_fail_tone_only_for_a_fault_and_never_for_zero_of_zero(db):
    assert box_tone(page(db), "Instances reporting") == "plain"
    assert box_tone(page(db, instances=[]), "Instances reporting") == "plain", "0 of 0 live"
    silent = stats()["instances"]
    silent[1]["last_used_at"] = iso(hours=2)
    assert box_tone(page(db, instances=silent), "Instances reporting") == "fail"
    assert box_tone(page(db), "Waiting for an invite") == "plain"
    waiting = {"rows": [{"email": "a@example.com", "servers": "", "created_at": iso()}], "total": 1}
    assert box_tone(page(db, beta=waiting), "Waiting for an invite") == "plain"


def test_a_prober_box_does_not_flap_between_passes(db):
    """The fast lane runs every ten minutes with a minute of random delay, so
    stamps of 9 and 11 minutes read fine and 36 is a fault."""
    w = stats()["watchdog"]
    for minutes, tone in ((9, "plain"), (11, "plain"), (34, "plain"), (36, "fail")):
        w["vantages"][1]["last_run"] = iso(minutes=minutes)
        assert box_tone(page(db, watchdog=w), "Probers") == tone, minutes
    w["vantages"][1]["last_run"] = iso(minutes=36)
    assert "1 of 2" in text_of(strip_of(page(db, watchdog=w)))


def test_a_disabled_vantage_is_not_counted_and_not_a_fault(db):
    w = stats()["watchdog"]
    w["vantages"][1]["enabled"] = False
    w["vantages"][1]["last_run"] = iso(days=3)
    html = page(db, watchdog=w)
    assert box_tone(html, "Probers") == "plain"
    assert "1 of 1" in text_of(strip_of(html))


def test_the_sweep_box_does_not_flap_between_runs(db):
    """The sweep timer is every five minutes with thirty seconds of random
    delay, so 4 and 6 minutes read fine and 12 is a fault."""
    w = stats()["watchdog"]
    for minutes, tone in ((4, "plain"), (6, "plain"), (10, "plain"), (12, "fail")):
        w["sweep"] = iso(minutes=minutes)
        assert box_tone(page(db, watchdog=w), "Sweep") == tone, minutes
    w["sweep"] = ""
    html = page(db, watchdog=w)
    assert box_tone(html, "Sweep") == "fail"
    assert "Sweep never" in text_of(strip_of(html))


def test_the_thresholds_come_with_the_numbers_and_not_from_this_tree(db):
    w = stats()["watchdog"]
    w["sweep"] = iso(minutes=6)
    assert box_tone(page(db, watchdog=w), "Sweep") == "plain"
    shorter = {"silent_after": 35 * 60, "sweep_stale": 300}
    assert box_tone(page(db, watchdog=w, thresholds=shorter), "Sweep") == "fail"


# ===================================================================== the tabs

def subnav_of(html):
    view = view_of(html)
    nav = view[view.index('<div class="subnav">'):]
    return nav[:nav.index("</div>")]


def test_the_tabs_are_radios_and_switch_without_script(db):
    view = view_of(page(db))
    for key in ("instances", "betalist", "workspaces", "servers"):
        assert f'<input type="radio" class="tabsel k-{key}" name="tabs-admin" id="tb-admin-{key}"' in view
        assert f'<div class="tab k-{key}" id="t-admin-{key}">' in view
        assert f".tabsel.k-{key}:checked~.tab.k-{key}{{display:block}}" in tpl.ADMIN_CSS_RULES
    assert 'id="tb-admin-instances" checked>' in view, "Instances is open on arrival"
    assert "<script" not in view


def test_the_tab_order_and_the_planned_ones(db):
    nav = subnav_of(page(db))
    labels = re.findall(r"<label[^>]*>(.*?)</label>", nav)
    words = [re.sub(r"<[^>]+>", "", label).replace("planned", "").strip() for label in labels]
    assert words == ["Instances", "Beta list", "Feedback", "Workspaces", "Servers", "Billing"]
    for key in tpl.ADMIN_PLANNED:
        assert f'for="tb-admin-{key}"' not in nav
    assert nav.count("tag-planned") == len(tpl.ADMIN_PLANNED)


def test_a_planned_tab_says_the_tag_and_nothing_else(db):
    assert tpl.ADMIN_PLANNED_BODY == ""
    for key, _label, body in rl.admin_sections(stats(), NOW):
        if key in tpl.ADMIN_PLANNED:
            assert body == ""
    view = view_of(page(db))
    for key in tpl.ADMIN_PLANNED:
        assert f'id="t-admin-{key}"' not in view, "a planned tab has no panel"


def test_there_is_no_overview_and_no_activity_tab(db):
    nav = subnav_of(page(db))
    assert "Overview" not in nav and "Activity" not in nav
    assert "documents, all time" not in view_of(page(db))


def test_an_unknown_tab_is_refused():
    with pytest.raises(ValueError):
        tpl.admin_view([("nonsense", "Nonsense", "")], "")


# =================================================== every table, the Fleet's head

def tables_of(html):
    return re.findall(r'<div class="thead ([a-z0-9]+)">(.*?)</div>', view_of(html))


def test_every_table_head_is_the_fleets_and_the_state_is_first(db):
    waiting = {"rows": [{"email": "ops@example.net", "servers": "6-20",
                         "created_at": iso(days=1)}], "total": 1}
    heads = {cls: re.findall(r"<span[^>]*>(.*?)</span>", spans)
             for cls, spans in tables_of(page(db, beta=waiting))}
    assert heads["irow"] == ["State", "Instance", "Last seen", "Last batch", "Proved",
                             "Targets, today", "Connects, this hour"]
    assert heads["wrow2"][0] == "State" and heads["qrow2"][0] == "State"
    assert heads["acrow"] == ["Account", "Created", "Workspace", "Servers", "Last signed in"]
    assert heads["brow2"] == ["Address", "Fleet", "Joined"]


def fixed_px(rule):
    """The fixed tracks of a grid-template-columns value in px, the flexible
    one at its minimum, and how many gaps the row has."""
    tracks = rule.split()
    fixed = sum(int(t[:-2]) for t in tracks if t.endswith("px") and "(" not in t)
    minimum = sum(int(m) for m in re.findall(r"minmax\((\d+)px", rule))
    return fixed + minimum, len(tracks) - 1


def test_every_tables_fixed_tracks_sum_under_the_narrowest_body():
    """The body beside no rail is 972px at 1024 wide (1024 minus the wrap's
    two 26px gutters), the rows have 16px gaps and 40px of padding. Every
    table's tracks, the flexible one at its minimum, fit inside that: the
    fault of 4.412 held shut by the stylesheet itself."""
    rules = dict(re.findall(r"\.thead\.([a-z0-9]+),\.row\.[a-z0-9]+\{grid-template-columns:([^}]+)\}",
                            tpl.ADMIN_CSS))
    assert set(rules) >= {"irow", "wrow2", "qrow2", "acrow", "brow2", "lrow"}
    for cls, rule in rules.items():
        px, gaps = fixed_px(rule)
        assert px + 16 * gaps + 40 <= 972, (cls, px, gaps)


def test_every_row_is_a_link_or_opens_in_place_and_no_row_ends_in_a_button(db):
    """The one row that acts is a feedback message's, whose Done and Delete
    sit in the fixed end track the spec names (docs/screens/admin/SPEC.md 3,
    docs/record 4.436). Every other row is a link or opens in place."""
    a_message = {"id": 1, "instance_id": 2, "workspace_id": None, "kind": "bug",
                 "words": "w", "screen": "fleet", "instance_version": "unknown",
                 "received_at": "2026-10-06T17:21:00+00:00", "done_at": None}
    view = view_of(page(db, feedback={"open": [a_message], "done": []}, feedback_open=1))
    rows = re.findall(r'<(a|summary|div) class="row ([a-z0-9]+)"[^>]*>(.*?)</\1>', view, re.S)
    assert rows, "no rows found"
    assert any(cls == "frow" for _tag, cls, _inner in rows)
    frow = view[view.index('<div class="row frow"'):]
    frow = frow[:frow.index("</div></div>") + len("</div></div>")]
    assert frow.endswith('<div class="fact"><button class="btn js-fb-done">Done</button>'
                         '<button class="btn js-fb-del">Delete</button></div></div>')
    for tag, cls, inner in rows:
        if cls == "frow":
            continue
        assert "<button" not in inner and 'class="btn"' not in inner, (cls, inner[-120:])
    assert all(tag == "a" for tag, cls, _ in rows if cls in ("wrow2", "qrow2", "acrow"))
    assert all(tag == "summary" for tag, cls, _ in rows if cls == "irow")


def test_a_workspace_row_an_account_row_and_a_server_row_open_the_viewing_page(db):
    view = view_of(page(db))
    assert '<a class="row wrow2" href="/admin/workspace/4">' in view
    assert '<a class="row acrow" href="/admin/workspace/4">' in view
    assert '<a class="row qrow2" href="/admin/workspace/4">' in view


# ================================================================== instances

def test_the_instance_word_is_the_freshness_word_for_the_same_age():
    """One rule: the four words at the same stamps as a host's."""
    for stamp, expected in (("", ("off", "not watched")),
                            (iso(minutes=3), ("ok", "reporting")),
                            (iso(hours=2), ("warn", "silent 2h 0m"))):
        assert rl.instance_state({"revoked_at": None, "last_used_at": stamp}, NOW, 35 * 60) == expected
        assert rl.freshness({"revoked_at": None, "paused": 0, "last_report_at": stamp or None},
                            NOW) == expected
    assert rl.instance_state({"revoked_at": iso(days=1), "last_used_at": iso()}, NOW, 35 * 60) \
        == ("off", "revoked")


def instance_row_of(html, name):
    view = view_of(html)
    start = view.rfind('<details class="irow-d">', 0, view.index(f'class="nm">{name}<'))
    row = view[start:]
    return row[:row.index("</details>")]


def test_an_instance_with_nothing_to_probe_is_not_called_silent(db):
    """A key used three minutes ago and no batch ever: `reporting`, `never`
    under Last batch, `0 addresses` under Proved."""
    row = instance_row_of(page(db), "oakhill")
    summary = row[:row.index("</summary>")]
    assert "REPORTING" in text_of(summary).upper()
    assert "SILENT" not in text_of(summary).upper()
    assert ">never<" in summary
    assert "0 addresses" in summary


def test_an_instance_row_opens_in_place_with_keys_log_and_failure_and_nothing_that_acts(db):
    numbers = stats()
    numbers["instances"][1]["failure"] = {"error": "vantage_unreachable", "vantage": "probe2",
                                         "at": iso(minutes=2)}
    html = page(db, instances=numbers["instances"])
    first = instance_row_of(html, "selfhost-test-1")
    text = text_of(first)
    assert "api 06 Oct 2026 revoked 06 Oct 2026" in text
    assert "probe1 2 addresses 16 batches 96 connects" in text
    assert "<button" not in first and "<form" not in first and "<a " not in first
    assert "vantage_unreachable probe2 2m ago" in text_of(instance_row_of(html, "oakhill"))


def test_no_hash_and_no_key_is_ever_printed(db):
    view = view_of(page(db))
    assert "whpi_" not in view and "whpp_" not in view
    assert not re.search(r"[0-9a-f]{40,}", view)


def test_the_instances_hint_counts_live_and_revoked(db):
    assert "1 live, 1 revoked" in text_of(view_of(page(db)))


def test_no_instance_yet_is_one_line(db):
    assert "no instance yet" in text_of(view_of(page(db, instances=[])))


def test_instances_sort_the_worse_word_first_and_revoked_last(db):
    """As the Fleet sorts: silent, then not watched, then reporting, and
    a revoked instance last, since it is gone the way a removed server is."""
    numbers = stats()
    numbers["instances"] = [
        {**numbers["instances"][1], "id": 10, "name": "aaa-fine"},
        {**numbers["instances"][0], "id": 11, "name": "bbb-gone"},
        {**numbers["instances"][1], "id": 12, "name": "ccc-quiet", "last_used_at": iso(hours=2)},
        {**numbers["instances"][1], "id": 13, "name": "ddd-never", "last_used_at": ""},
    ]
    view = view_of(page(db, instances=numbers["instances"]))
    names = re.findall(r'<div class="nm">([a-z-]+)</div>', view[:view.index('id="t-admin-betalist"')])
    assert names == ["ccc-quiet", "ddd-never", "aaa-fine", "bbb-gone"]
    assert "NOT WATCHED" in text_of(view).upper() and "never reported" not in view


def test_the_quiet_list_and_the_accounts_list_name_the_workspace(db):
    """A workspace is a name on this screen, never a bare number: the number
    is under the name on the Workspaces tab and in the row's address."""
    view = view_of(page(db))
    quiet = view[view.index('class="thead qrow2"'):]
    quiet = quiet[:quiet.index("</div></div>")]
    assert "sandbox" in text_of(quiet) and ">4<" not in quiet
    accounts = view[view.index('class="thead acrow"'):]
    accounts = accounts[:accounts.index("</div></div>")]
    assert "sandbox" in text_of(accounts)
    assert 'href="/admin/workspace/4"' in quiet and 'href="/admin/workspace/4"' in accounts


def test_a_workspace_nobody_knows_the_name_of_is_its_number(db):
    numbers = stats()
    numbers["quiet_servers"][0]["workspace_id"] = 9
    view = view_of(page(db, quiet_servers=numbers["quiet_servers"]))
    quiet = view[view.index('class="thead qrow2"'):]
    assert "workspace 9" in text_of(quiet)


def test_cards_in_a_tab_stand_off_the_tab_line():
    """The Servers tab opens on cards, and cards against the tab line read
    as part of it. The same gap a section gets."""
    assert "#admin .tab>.stats{margin-top:22px}" in theme.css_without_comments(tpl.ADMIN_CSS)


def test_a_list_is_whole_and_no_hint_says_of_more(db):
    """Two lists showed their first rows with a hint of more and no way to
    the rest. The lists are whole now, so the hint can only ever say how
    many there are."""
    numbers = stats(quiet_servers_total=2)
    text = text_of(view_of(page(db, **{"quiet_servers_total": 2})))
    assert "2 of 15" not in text
    assert "Not reporting 2" in text or "Not reporting" in text


# =================================================================== the lookup

def lookup_of(html):
    view = view_of(html)
    form = view[view.index('<form class="lookup"'):]
    return form[:form.index("</form>")]


def test_the_lookup_posts_with_the_pages_token_and_never_gets(db):
    form = lookup_of(page(db))
    assert 'method="post"' in form and 'action="/admin/lookup"' in form
    assert 'name="csrf" value="' + "t" * 40 + '"' in form
    assert 'name="address"' in form
    assert 'method="get"' not in form.lower()


def test_the_lookup_lists_the_logs_rows_for_an_address(db):
    found = {"address": "2606:50c0:8000::153", "error": "",
             "rows": [{"instance": "oakhill", "vantage": "probe2", "day": "2026-10-06",
                       "first_at": iso(hours=3), "last_at": iso(hours=1), "batches": 8,
                       "connects": 48}]}
    html = page(db, lookup=found)
    assert 'value="2606:50c0:8000::153"' in lookup_of(html), "the address stays in its field"
    tables = dict(tables_of(html))
    assert re.findall(r"<span[^>]*>(.*?)</span>", tables["lrow"]) == [
        "Instance", "Vantage", "Day", "First", "Last", "Batches", "Connects"]
    text = text_of(view_of(html))
    assert "oakhill probe2 2026-10-06 3h 0m ago 1h 0m ago 8 48" in text
    assert "1 row" in text


def test_the_lookup_says_when_nothing_named_the_address(db):
    html = page(db, lookup={"address": "185.199.108.153", "error": "", "rows": []})
    assert "no batch has named it" in text_of(view_of(html))


def test_what_is_not_an_address_gets_one_word(db):
    html = page(db, lookup={"address": "not-this", "error": "not an address", "rows": []})
    assert "not an address" in text_of(view_of(html))
    assert 'value="not-this"' in lookup_of(html)


def test_the_address_is_escaped_everywhere_it_is_printed(db):
    evil = '"><script>alert(1)</script>'
    html = page(db, lookup={"address": evil, "error": "not an address", "rows": []})
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


# ============================================================= the other tabs

def test_the_beta_list_and_its_empty_line(db):
    assert "nobody on the list" in text_of(view_of(page(db)))
    waiting = {"rows": [{"email": "ops@example.net", "servers": "6-20",
                         "created_at": iso(days=1)}], "total": 1}
    text = text_of(view_of(page(db, beta=waiting)))
    assert "ops@example.net 6-20 05 Oct 2026" in text
    assert "1 waiting" in text


def test_a_workspace_carries_the_freshness_word_of_its_newest_document(db):
    view = view_of(page(db))
    rows = re.findall(r'<a class="row wrow2" href="/admin/workspace/(\d+)">(.*?)</a>', view, re.S)
    words = {int(i): text_of(inner).upper() for i, inner in rows}
    assert words[1].startswith("REPORTING")
    assert words[4].startswith("REPORTING")
    assert words[5].startswith("NO SERVER")
    numbers = stats()
    numbers["workspace_rows"][1]["reporting"] = 0
    numbers["workspace_rows"][1]["last_report_at"] = iso(days=2)
    view = view_of(page(db, workspace_rows=numbers["workspace_rows"]))
    assert "SILENT 2D" in text_of(view[view.index("sandbox"):]).upper()


def test_the_servers_tab_keeps_three_cards_and_the_not_reporting_list(db):
    body = next(b for k, _l, b in rl.admin_sections(stats(), NOW) if k == "servers")
    labels = re.findall(r'<div class="k">(.*?)</div>', body)
    assert labels == ["servers reporting", "silent", "not watched"]
    text = text_of(body)
    assert "Not reporting" in text and "of 15" not in text
    assert "not watched new-b78f6d sandbox 27 sep 2026 never" in text.lower()
    assert "web-02 default 03 Oct 2026 2d ago" in text


def test_every_server_is_reporting_is_one_line(db):
    sections = rl.admin_sections(stats(quiet_servers=[], quiet_servers_total=0), NOW)
    body = next(b for k, _l, b in sections if k == "servers")
    assert "every server is reporting" in body


def test_an_email_address_is_escaped():
    """The one screen in this product that prints somebody else's text."""
    evil = '<script>alert(1)</script>@example.com'
    html = tpl.admin_accounts_html([(evil, "x", 1, "default", 0, "never")])
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_a_card_prints_its_value_and_its_label():
    html = tpl.stats_html([("servers reporting", 8)])
    assert '<div class="v">8</div>' in html
    assert '<div class="k">servers reporting</div>' in html


# ================================================================ the nav badge

def nav_of(html):
    return html[html.index('<nav class="nav">'):html.index("</nav>")]


def test_the_admin_nav_entry_carries_a_count_when_a_box_faults_or_feedback_is_open(db):
    assert '<a data-v="admin">Admin</a>' in nav_of(page(db))
    w = stats()["watchdog"]
    w["sweep"] = iso(minutes=20)
    html = page(db, watchdog=w, feedback_open=2)
    assert '<a data-v="admin">Admin<span class="nb">3</span></a>' in nav_of(html)


# ================================ the rule for customer screens, nothing explains

FORBIDDEN = ("not built", "will be", "we ", "because", "coming soon",
             "environment variable", "control plane", "within the minute")


def test_the_screen_carries_no_explanation(db):
    """A screen may carry labels, values, names, numbers, statuses, findings,
    errors, refusals and an empty line. That is the whole list."""
    text = text_of(view_of(page(db))).lower()
    assert "instances" in text and "workspaces" in text
    for phrase in FORBIDDEN:
        assert phrase not in text, phrase


# The names a fixture or a frame may carry: the sample shell's servers, the
# test fleet's, and three made-up workspaces and instances. A name outside
# this set is a real one until shown otherwise (docs/record 4.412, 4.416).
MADE_UP_NAMES = {"web-01", "web-02", "media-01", "mail-relay", "new-b78f6d",
                 "selfhost-test-1", "oakhill", "sandbox", "default", "probe1", "probe2"}


def test_every_fixture_address_is_at_example_com_and_every_name_made_up():
    """Shots and fixtures carry no real person's address and no real server or
    workspace name: every address is at an example domain and every name is
    on the made-up list above, so a real one cannot get in unnoticed."""
    text = pathlib.Path(__file__).read_text()
    here = text[:text.index("def test_every_fixture_address_is_at_example_com")]
    for address in re.findall(r"[\w.+-]+@[\w.-]+\.\w+", here):
        assert address.endswith(("example.com", "example.net", "example.org")), address
    numbers = stats()
    named = ([r["name"] for r in numbers["quiet_servers"]]
             + [r["name"] for r in numbers["instances"]]
             + [r["name"] for r in numbers["workspace_rows"]]
             + [v["name"] for v in numbers["watchdog"]["vantages"]])
    for name in named:
        assert name in MADE_UP_NAMES, name


def test_the_admin_css_is_part_of_the_page():
    assert theme.css_without_comments(tpl.ADMIN_CSS) in tpl.CSS


def test_the_card_class_does_not_collide_with_the_global_number_class():
    assert ".num{" not in tpl.ADMIN_CSS
    assert ".stat{" in tpl.ADMIN_CSS
