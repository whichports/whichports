"""The Alerts screen, built from docs/screens/alerts/SPEC.md and its sketch.

    Run from site/app: python3 -m pytest test_alerts_screen.py

The markup half is checked without a browser: the two tables, their words,
the actions a line offers, the empty states, the count beside Alerts in the
top bar, the Add window's destination cards, and the empty Fleet. The second
half drives the row actions in a real browser over the live render with
fetch stubbed, so what a click posts can be read back.
"""
import functools
import html as html_mod
import http.server
import json
import pathlib
import re
import sqlite3
import sys
import threading
from datetime import datetime, timedelta

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import dataclasses  # noqa: E402
import build  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
from test_render_live import db  # noqa: E402,F401  (the empty database fixture)
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

NOW = datetime(2026, 9, 5, 12, 0)


def line(**kw):
    base = dict(when=datetime(2026, 9, 5, 9, 12), host="box", word="conflict", tone="fail",
                protocol="tcp", port=8410, families=("v4",), why="you said closed")
    base.update(kw)
    return build.AlertLine(**base)


# ------------------------------------------------------------- one line

def test_a_line_is_the_way_to_its_server():
    html = build.alert_line_html(line(), NOW)
    assert html.startswith('<div class="al" data-host="box"')
    assert '<b class="alh">box</b>' in html


def test_a_line_carries_the_six_columns_in_the_spec_order():
    html = build.alert_line_html(line(), NOW)
    order = [html.index(s) for s in ('class="cwhen"', 'class="alh"', 'class="altag"',
                                     'class="cpn"', 'class="alwhy"', 'class="alac"')]
    assert order == sorted(order)
    assert "<b>5 Sep</b> 09:12" in html


def test_the_tag_carries_the_word_and_its_tone_on_open_now():
    assert '<span class="st fail">conflict</span>' in build.alert_line_html(line(), NOW)
    warn = line(word="silent", tone="warn", protocol="", port="", families=())
    assert '<span class="st warn">silent</span>' in build.alert_line_html(warn, NOW)


def test_the_tag_is_neutral_on_sent_and_grey_for_a_state_that_went_away():
    sent = build.alert_line_html(line(channel="Email", destination="a@example.org"), NOW,
                                 sent=True)
    assert "st fail" not in sent
    assert build.evidence_tag("conflict") in sent
    gone = build.alert_line_html(line(word="reporting", off=True, channel="Email"), NOW,
                                 sent=True)
    assert build.evidence_tag("reporting", off=True) in gone


def test_the_why_is_a_few_words_and_never_the_sweeps_sentence():
    html = build.alert_line_html(line(), NOW)
    assert '<span class="alwhy">you said closed</span>' in html
    assert "was" not in html.split('class="alwhy"')[1][:40]


def test_a_sent_line_ends_with_the_channel_and_its_destination_small():
    html = build.alert_line_html(line(channel="Slack", destination="#ops"), NOW, sent=True)
    assert '<span class="alch">Slack<small>#ops</small></span>' in html
    bare = build.alert_line_html(line(channel="Email"), NOW, sent=True)
    assert '<span class="alch">Email</span>' in bare


def test_every_field_is_escaped():
    html = build.alert_line_html(
        line(host='"><script>', why="<img src=x>", channel="<u>", destination="<i>x"),
        NOW, sent=True)
    for raw in ('"><script>', "<img src=x>", "<u>", "<i>x"):
        assert raw not in html
    assert "&lt;script&gt;" in html


# --------------------------------------------------------- the actions

def test_a_port_line_offers_silence_with_every_field_the_route_needs():
    html = build.alert_line_html(line(action=("silence", "tcp", 8410, "v4", False)), NOW)
    assert ">Silence<" in html and "js-al-silence" in html
    for field in ('data-host="box"', 'data-protocol="tcp"', 'data-port="8410"',
                  'data-family="v4"'):
        assert field in html, field


def test_a_silenced_port_says_so_and_offers_nothing():
    html = build.alert_line_html(line(action=("silence", "tcp", 8410, "v4", True)), NOW)
    assert ">Silenced<" in html and "disabled" in html
    assert "js-al-silence" not in html


def test_a_silent_line_offers_pause_and_a_paused_one_says_so():
    quiet = line(word="silent", tone="warn", protocol="", port="", families=(),
                 why="nothing from the agent for 42 min")
    html = build.alert_line_html(line(**{**quiet.__dict__, "action": ("pause", False)}), NOW)
    assert ">Pause<" in html and 'class="btn js-al-pause" data-host="box"' in html
    paused = build.alert_line_html(line(**{**quiet.__dict__, "action": ("pause", True)}), NOW)
    assert ">Paused<" in paused and "js-al-pause" not in paused


def test_a_line_with_no_action_has_an_empty_last_cell():
    html = build.alert_line_html(line(word="unreachable", tone="off", why="was reachable"), NOW)
    assert '<span class="alac"></span>' in html


def test_no_line_offers_to_close_an_alert_by_hand():
    """A silence stops the mail and the alert stays open (docs/PRODUCT.md 4c).
    Nothing on this screen may drop a live finding on a click."""
    html = build.alerts_view(build.SAMPLE_OPEN, build.SAMPLE_SENT, NOW)
    # the lines are drawn, so the words below are looked for among them
    assert "js-al-silence" in html and build.NOTHING_YET not in html
    for word in ("Dismiss", "Resolve", "Acknowledge", "Ignore"):
        assert word not in html, word


# ------------------------------------------------------------ the tables

def test_the_two_tables_carry_the_spec_columns():
    html = build.alerts_view(build.SAMPLE_OPEN, build.SAMPLE_SENT, NOW)
    for column in ("Raised", "Server", "Alert", "Port", "Why", "When", "Channel"):
        assert f"<span>{column}</span>" in html, column
    # The table of where alerts go stands on Integrations since layout B
    # (docs/screens/alerts/SPEC-layout-b.md), and its columns went with it.
    sent_column = "<span>Sent<small>past 7 days</small></span>"
    assert sent_column not in html and "<span>Destination</span>" not in html
    integrations = build.integrations_view([], build.sample_channel_rows_html(), True)
    assert sent_column in integrations and "<span>Destination</span>" in integrations


def test_the_headings_carry_their_counts():
    html = build.alerts_view(build.SAMPLE_OPEN, build.SAMPLE_SENT, NOW)
    assert f'Open now<span class="cnt">{len(build.SAMPLE_OPEN)}</span>' in html
    # Sent carries one count for each range, and the page shows the chosen
    # one (test_alerts_sent_count_browser.py). Thirty days hold them all.
    assert f'<span class="cnt c30">{len(build.SAMPLE_SENT)}</span>' in html
    assert html.count('<h2 class="alh2">Sent<span class="cnt c') == 1


def test_sent_opens_on_seven_days_and_offers_all_three_ranges():
    html = build.alerts_view([], [], NOW)
    assert 'id="sg-alerts-7d" checked' in html
    assert html.count('class="sgsel') == 3
    for label in ("24h", "7d", "30d"):
        assert f">{label}</label>" in html
    assert "tag-planned" not in html.split('<h2 class="alh2">Sent')[1]


def test_a_sent_line_says_which_range_it_falls_in():
    lines = [line(when=NOW - timedelta(hours=2)), line(when=NOW - timedelta(days=3)),
             line(when=NOW - timedelta(days=20))]
    html = build.alerts_table_html(lines, build.SENT_COLUMNS, NOW, sent=True)
    assert re.findall(r'data-r="(\d+)"', html) == ["1", "7", "30"]


def test_sent_carries_one_empty_line_per_range_and_the_css_picks_it():
    html = build.alerts_table_html([], build.SENT_COLUMNS, NOW, sent=True)
    for _label, days, words in build.SENT_RANGES:
        assert f'<div class="al alempty e{days}">{words}</div>' in html
    css = build.CSS
    assert '.sgsel.r7:checked~.alsent:not(:has(.al[data-r="1"],.al[data-r="7"])) .alempty.e7{display:block}' in css
    assert '.sgsel.r1:checked~.alsent .al[data-r="7"]' in css


def test_the_channels_table_is_the_spec_shape():
    rows = build.sample_channel_rows_html()
    assert rows.startswith(build.alerts_thead_html(build.CHANNEL_COLUMNS))
    assert rows.count('<div class="crow">') == 3
    assert '<div class="crow-u z">0</div>' in rows
    assert '<div class="crow-u">4</div>' in rows


def test_the_row_menu_is_send_test_edit_turn_off_and_delete_apart():
    menu = build.row_menu_html("ops", enabled=True, channel_type="slack")
    order = [menu.index(s) for s in (">Send test<", ">Edit<", ">Turn off<",
                                     '<hr class="rm-hr">', ">Delete<")]
    assert order == sorted(order)
    assert 'class="rm-i rm-post rm-del"' in menu
    assert build.theme.ICONS["dots-three-vertical"] in menu
    assert ">Turn on<" in build.row_menu_html("ops", enabled=False)


# -------------------------------------------------------- the empty states

def test_nothing_yet_is_the_one_box_and_no_header_button():
    html = build.alerts_view([], [], NOW, nothing_yet=True)
    assert build.NOTHING_YET in html
    assert build.theme.ICONS["bell-slash"] in html
    # The box held the one Add channel button until layout B. What is
    # connected is added on Integrations, so nothing here opens a window
    # (docs/screens/alerts/SPEC-layout-b.md).
    assert "data-open" not in html and "<button" not in html
    assert '<div class="acts">' not in html
    assert "Channels" not in html and "Sent" not in html


def test_nothing_open_is_a_small_row_with_a_bell():
    html = build.alerts_view([], [], NOW)
    assert build.nothing_open_html() in html
    assert build.theme.ICONS["bell"] in build.nothing_open_html()
    assert build.NOTHING_OPEN in html
    # The header held Add channel until layout B. It holds no button now.
    assert "data-open" not in html and '<div class="acts">' not in html


def test_the_empty_fleet_is_the_slashed_drives_and_add_server():
    """docs/screens/fleet/SPEC.md, When there is no server: one box, Add
    server as the one button, no banner and no boxes with zeros. Handed what
    the live page hands it, the strip, a banner and the header's Add server,
    which an empty Fleet drew until the second big test (finding F3)."""
    strip = build.fleet_strip_html(build.fleet_totals([]))
    note = build.fleet_notes_html([("fail", "k", "Alert mail to <b>x</b> was refused by the relay.",
                                    "Open channel", "integrations")])
    acts = build.button("Add server", "pri js-add")
    html = build.fleet_view(note, strip, "", acts)
    assert build.NO_SERVERS in html
    assert html.count(">Add server</button>") == 1
    assert 'class="btn pri js-add">Add server</button>' in html.split('class="panel alnone"', 1)[1]
    assert 'class="fstrip"' not in html and "fnote" not in html and ">0<" not in html
    assert 'class="srch"' not in html and "thead" not in html
    full = build.fleet_view(note, strip, "<div>a row</div>", acts)
    assert build.NO_SERVERS not in full and 'class="thead"' in full
    assert 'class="fstrip"' in full and "fnote" in full and full.count(">Add server</button>") == 1


def test_the_live_empty_fleet_is_one_box_and_one_add_server(db):
    """What the page draws for a workspace with no server, through the same
    render the box serves (the second big test, finding F3: four boxes of
    zeros and Add server twice)."""
    html = rl.render(db, now=trl.NOW)
    fleet = html[html.index('id="fleet"'):]
    fleet = fleet[:fleet.index('<div class="wrap view"')]
    assert build.NO_SERVERS in fleet
    assert fleet.count(">Add server</button>") == 1
    assert 'class="fstrip"' not in fleet and 'class="fnote ' not in fleet
    assert "of 0 ports" not in fleet
    header = fleet[fleet.index('<div class="ph">'):fleet.index("</h1>") + 200]
    assert "Add server" not in header


# --------------------------------------------------------- the top bar

def test_the_count_beside_alerts_is_in_the_fail_tone_and_absent_at_zero():
    nav = build.nav_html(build.NAV, open_count=3)
    assert '>Alerts<span class="nb">3</span></a>' in nav
    assert '<span class="nb">' not in build.nav_html(build.NAV, open_count=0)
    assert '<span class="nb">' not in build.nav_html(build.NAV)
    assert ".nb{" in build.CSS and "var(--fail)" in build.CSS.split(".nb{")[1].split("}")[0]


def test_the_sample_shell_wears_its_open_count():
    """Three of the sample's four open alerts, because one of them is a port
    somebody silenced (docs/PRODUCT.md 4c)."""
    assert build.alerts_needing_you(build.SAMPLE_OPEN) == 3
    assert len(build.SAMPLE_OPEN) == 4
    assert '<span class="nb">3</span>' in build.build_sample()


def test_the_count_is_the_alerts_that_still_want_an_answer():
    """The owner asked for it twice, the second time on 2026-09-10: silencing an
    alert has to take it out of the count beside Alerts. A silenced port and
    a paused server have
    been answered. A line with no control at all has not."""
    line = build.SAMPLE_OPEN[0]
    quiet = [("silence", "tcp", 22, "v4", True), ("pause", True)]
    loud = [("silence", "tcp", 22, "v4", False), ("pause", False), ()]
    for action in quiet:
        assert build.alert_is_quiet(action) is True, action
        assert build.alerts_needing_you([dataclasses.replace(line, action=action)]) == 0
    for action in loud:
        assert build.alert_is_quiet(action) is False, action
        assert build.alerts_needing_you([dataclasses.replace(line, action=action)]) == 1


# ------------------------------------- the Add window, an alert destination

def test_the_window_offers_five_cards_and_opens_advanced():
    """The five channels are the destination cards of the one Add window
    since layout B, with Syslog after them as a planned sixth
    (docs/screens/alerts/SPEC-layout-b.md)."""
    html = build.add_modal(live=True)
    assert [n for n, _s in build.ADD_CHANNELS] == ["Email", "Slack", "Webhook",
                                                   "Telegram", "Discord"]
    cards = trl.kind_cards(html, "dest")
    assert '<div class="m-cards m5 w6">' in cards
    assert re.findall(r'<div class="m-card-t">([^<]+)', cards) == [
        "Email", "Slack", "Webhook", "Telegram", "Discord", "Syslog"]
    assert '<details class="m-adv" open>' in html
    # The timing is the one planned thing left in a channel's own steps. The
    # four channels the closed alpha held back from 2026-09-20 are real again
    # since 2026-10-01, on the owner's word (docs/RECORD.md 4.224). Syslog is the
    # one planned card among them.
    assert cards.count('class="tag-planned"') == 1
    assert '<div class="m-card-t">Syslog<span class="tag-planned">planned</span>' in cards
    after = html[html.index('<div class="m-stage" id="chan-'):]
    assert after.count('class="tag-planned"') == 1
    assert [n for n, stage in build.ADD_CHANNELS if stage] == ["Email", "Slack", "Webhook",
                                                              "Telegram", "Discord"]
    # the way out first, the action last, and the way out is Cancel
    foot = html.split('<div class="m-foot">')[1]
    assert foot.index(">Cancel<") < foot.index(">Save<")


# --------------------------------------------------- the live page's words

def open_lines(**kw):
    row = dict(host_name="box", kind="finding changed",
               detail="tcp/443 on v4 was open, now conflict", subject="tcp/443 v4",
               raised_at=NOW.isoformat())
    row.update(kw)
    return rl.open_alert_lines([row], NOW, **{})


@pytest.mark.parametrize("detail,declared,word,tone,why", [
    ("tcp/443 on v4 was open, now conflict", "closed", "conflict", "fail", "you said closed"),
    ("tcp/443 on v4 was closed, now conflict", "open", "conflict", "fail", "you said reachable"),
    ("tcp/443 on v4 was open, now conflict", "", "conflict", "fail", "not as declared"),
    ("tcp/443 on v4 had no state, now unreviewed", "", "reachable", "warn",
     "nobody has said whether it should be"),
    ("tcp/443 on v4 was intended, now unexplained", "", "reachable", "warn", "not explained"),
    ("tcp/443 on v4 was intended, now not reachable", "", "unreachable", "off", "was intended"),
    ("tcp/443 on v4 was unreviewed, now stale rule", "", "unreachable", "off", "rule stale"),
])
def test_a_finding_detail_becomes_a_word_a_tone_and_a_why(detail, declared, word, tone, why):
    row = dict(host_name="box", kind="finding changed", detail=detail,
               subject="tcp/443 v4", raised_at=NOW.isoformat())
    declarations = {"box": {("tcp", 443): {"v4": declared}}} if declared else {}
    got = rl.open_alert_lines([row], NOW, declarations=declarations)[0]
    assert (got.word, got.tone, got.why) == (word, tone, why)
    assert (got.protocol, got.port, got.families) == ("tcp", 443, ("v4",))


def test_a_silent_detail_becomes_the_first_clause_in_minutes():
    row = dict(host_name="box", kind="silent",
               detail="no report for 180 minutes, past the 35 minute threshold",
               subject=None, raised_at=NOW.isoformat())
    got = rl.open_alert_lines([row], NOW)[0]
    assert (got.word, got.tone, got.why) == (
        "silent", "warn", "nothing from the agent for 180 min")
    assert got.action == ("pause", False)
    assert rl.open_alert_lines([row], NOW, paused={"box"})[0].action == ("pause", True)


def test_a_port_that_went_away_offers_nothing():
    row = dict(host_name="box", kind="finding changed",
               detail="tcp/443 on v4 was intended, now not reachable",
               subject="tcp/443 v4", raised_at=NOW.isoformat())
    assert rl.open_alert_lines([row], NOW)[0].action == ()


def test_a_port_still_answering_offers_silence_unless_silenced():
    row = dict(host_name="box", kind="finding changed",
               detail="tcp/443 on v4 was open, now conflict",
               subject="tcp/443 v4", raised_at=NOW.isoformat())
    assert rl.open_alert_lines([row], NOW)[0].action == ("silence", "tcp", 443, "v4", False)
    quiet = rl.open_alert_lines([row], NOW, silences={"box": {("tcp", 443, "v4")}})[0]
    assert quiet.action == ("silence", "tcp", 443, "v4", True)


def test_a_detail_nobody_predicted_still_draws_a_line():
    row = dict(host_name="box", kind="finding changed", detail="something moved",
               subject="tcp/443 v4", raised_at=NOW.isoformat())
    got = rl.open_alert_lines([row], NOW)[0]
    assert got.word == "finding changed" and got.why == "something moved"
    # the subject still names the port, so the silence still applies
    assert got.action == ("silence", "tcp", 443, "v4", False)


def test_a_sent_row_names_the_channel_and_its_destination():
    rows = [dict(host_name="box", detail="tcp/443 on v4 was open, now conflict",
                 sent_at=NOW.isoformat(), channel="email"),
            dict(host_name="box", detail="no report for 40 minutes, past the 35 minute threshold",
                 sent_at=NOW.isoformat(), channel="slack:WHICHPORTS_SLACK_URL")]
    channel = type("C", (), {"destination_env": "WHICHPORTS_SLACK_URL", "destination_hint": ""})()
    got = rl.sent_alert_lines(rows, [(channel, None, 1, "slack:WHICHPORTS_SLACK_URL")])
    assert (got[0].channel, got[0].destination, got[0].word) == ("Email", "", "conflict")
    assert (got[1].channel, got[1].destination, got[1].word) == (
        "Slack", "WHICHPORTS_SLACK_URL", "silent")
    assert got[1].why == "nothing from the agent for 40 min"


def test_a_different_program_on_an_answered_port_reads_as_the_two_programs():
    """Told once and never open, so it lives on Sent only. The port is still
    reachable and still answered, so the tag says so, and the why is what
    moved: the program (docs/PRODUCT.md 4c, 2026-09-27)."""
    rows = [dict(host_name="fart",
                 detail="tcp/3000 on v4 program was porttest-a, now porttest-b",
                 sent_at=NOW.isoformat(), channel="email")]
    (got,) = rl.sent_alert_lines(rows)
    assert (got.word, got.protocol, got.port, got.families) == (
        "reachable", "tcp", 3000, ("v4",))
    assert got.why == "porttest-b, was porttest-a"


def test_a_port_that_became_reachable_under_an_answer_reads_as_reachable():
    rows = [dict(host_name="fart", detail="tcp/3000 on v4 had no state, now intended",
                 sent_at=NOW.isoformat(), channel="email")]
    (got,) = rl.sent_alert_lines(rows)
    assert (got.word, got.port) == ("reachable", 3000)


# ----------------------------- an alert whose port stopped asking, 4.207

def _finding(port, state, family="v4"):
    from types import SimpleNamespace
    return SimpleNamespace(protocol="tcp", port=port, family=family, state=state)


def _open_finding_alert(port, family="v4"):
    return dict(kind="finding changed", subject=f"tcp/{port} {family}",
                detail=f"tcp/{port} on {family} had no state, now unreviewed",
                raised_at=NOW.isoformat())


def test_an_alert_whose_port_measured_shut_is_not_drawn_while_it_settles():
    """fart, 2026-09-26: 3001 measured shut at 18:15 and its alert resolved at
    18:36. In between the port no longer asks, so no screen says it does."""
    alerts = {"fart": [_open_finding_alert(3001)]}
    kept = rl.alerts_still_asking(alerts, {"fart": (_finding(3001, "not reachable"),)})
    assert kept == {}


@pytest.mark.parametrize("state", ["unreviewed", "unexplained", "conflict"])
def test_an_alert_whose_port_still_asks_is_drawn(state):
    alerts = {"fart": [_open_finding_alert(3001)]}
    kept = rl.alerts_still_asking(alerts, {"fart": (_finding(3001, state),)})
    assert kept == alerts


def test_only_the_family_the_alert_is_about_is_read():
    alerts = {"fart": [_open_finding_alert(3001, "v4")]}
    findings = {"fart": (_finding(3001, "unreviewed", "v4"),
                         _finding(3001, "not reachable", "v6"))}
    assert rl.alerts_still_asking(alerts, findings) == alerts


def test_an_alert_for_a_port_the_engine_has_no_finding_for_is_kept():
    alerts = {"fart": [_open_finding_alert(3001)]}
    assert rl.alerts_still_asking(alerts, {"fart": ()}) == alerts


def test_a_silent_agent_is_never_filtered():
    silent = dict(kind="silent", subject=None, detail="no report for 41 minutes",
                  raised_at=NOW.isoformat())
    assert rl.alerts_still_asking({"box": [silent]}, {"box": ()}) == {"box": [silent]}


# ------------------------------------------------------ in a real browser
#
# The row actions: Silence and Pause paint their word at once and post, a
# refusal puts the word back with a toast, and a click on the line itself goes
# to the server.

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>alerts drive</title>
<pre id="out"></pre>
<iframe id="f" width="1400" height="900"></iframe>
<script>
var PLAN=%(plan)s;
var out=document.getElementById('out');
var f=document.getElementById('f');
var results=[], at=0;
f.onload=function(){
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument, step=PLAN[at].step;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var result={step:step,errs:[],posts:[]};
    w.addEventListener('error',function(e){result.errs.push(String(e.message))});
    var answer=PLAN[at].answer||{status:204};
    w.fetch=function(url,opts){
      opts=opts||{};
      if((opts.method||'GET')==='POST'){
        result.posts.push({url:String(url),body:opts.body||null});
        return Promise.resolve({ok:answer.status<300,redirected:false,status:answer.status,
          json:function(){return Promise.resolve(answer.json||{})},
          text:function(){return Promise.resolve('')}});
      }
      return Promise.resolve({ok:true,redirected:false,status:200,
        text:function(){return Promise.resolve('')}});
    };
    d.querySelector('.nav [data-v="alerts"]').click(); await tick();
    result.view=(d.querySelector('.view.on')||{}).id;
    var b=d.querySelector('#alerts '+PLAN[at].button);
    if(step==='act'||step==='refused'){
      result.before=b.textContent;
      b.click(); await tick();
      result.after=b.textContent;
      result.disabled=b.disabled;
      result.toast=d.getElementById('toast').textContent;
      result.viewAfter=(d.querySelector('.view.on')||{}).id;
    }
    if(step==='row'){
      d.querySelector('#alerts .al[data-host="box"] .alh').click(); await tick();
      result.viewAfter=(d.querySelector('.view.on')||{}).id;
    }
    results.push(result);
    at+=1;
    if(at<PLAN.length){f.src=PLAN[at].page}
    else{out.textContent=JSON.stringify(results)}
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
};
f.src=PLAN[0].page;
</script>
"""


def drive(tmp_path, steps):
    site = tmp_path / "www"
    site.mkdir(exist_ok=True)
    plan = []
    for i, (step, page, extra) in enumerate(steps):
        (site / f"page{i}.html").write_text(page, encoding="utf-8")
        plan.append(dict({"page": f"page{i}.html", "step": step}, **extra))
    (site / "harness.html").write_text(HARNESS % {"plan": json.dumps(plan)}, encoding="utf-8")
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
    results = json.loads(html_mod.unescape(got.group(1)))
    assert isinstance(results, list), results
    assert len(results) == len(steps), results
    for r in results:
        assert r["errs"] == [], r
    return results


def alerts_page(db):
    """A live page with a port alert and a silent alert on the same server."""
    trl.add_host(db, "box", [(trl.NOW - timedelta(hours=3), trl.document(listening=[trl.SSHD]))],
                 last_report_at=(trl.NOW - timedelta(hours=3)).isoformat())
    trl.add_alert(db, "box", "tcp/443 on v4 was open, now conflict",
                  trl.NOW - timedelta(hours=1), kind="finding changed", subject="tcp/443 v4")
    trl.add_alert(db, "box", "no report for 180 minutes, past the 35 minute threshold",
                  trl.NOW - timedelta(hours=2))
    return rl.render(db, now=trl.NOW)


@pytest.mark.skipif(find_chrome() is None, reason="no Chrome on this machine")
def test_silence_and_pause_paint_at_once_and_post_and_a_refusal_undoes(tmp_path):
    db = str(tmp_path / "cp.db")
    con = sqlite3.connect(db)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    page = alerts_page(db)
    got = drive(tmp_path, [
        ("act", page, {"button": ".js-al-silence"}),
        ("act", page, {"button": ".js-al-pause"}),
        ("refused", page, {"button": ".js-al-silence",
                           "answer": {"status": 400, "json": {"detail": "No such port."}}}),
        ("row", page, {"button": ".js-al-silence"}),
    ])
    silence, pause, refused, row = got
    assert silence["view"] == "alerts"
    assert (silence["before"], silence["after"], silence["disabled"]) == ("Silence", "Silenced", True)
    assert silence["posts"] == [{"url": "/api/admin/hosts/box/ports/tcp/443/v4/silence",
                                 "body": None}]
    # the click stopped at the button: the line under it did not open the server
    assert silence["viewAfter"] == "alerts"
    assert (pause["before"], pause["after"], pause["disabled"]) == ("Pause", "Paused", True)
    assert [p["url"] for p in pause["posts"]] == ["/api/admin/hosts/box/pause"]
    assert json.loads(pause["posts"][0]["body"]) == {"paused": True}
    assert (refused["after"], refused["disabled"]) == ("Silence", False)
    assert refused["toast"] == "No such port."
    assert row["viewAfter"] == "host-box"


def test_a_planned_card_takes_nothing_from_a_row_that_already_exists():
    """The four channels the closed alpha does not offer can still hold rows:
    The owner's own Mattermost webhook is one (docs/RECORD.md 4.189). Edit opens
    a row's step by its type (`page.js`, `bindEdit`), never through a card,
    so every stored type keeps its step in the window however its card reads."""
    html = build.add_modal(live=True)
    for kind in ("email", "slack", "webhook", "telegram", "discord"):
        assert f'<div class="m-stage" id="chan-{kind}" data-type="{kind}">' in html, kind
    script = (pathlib.Path(__file__).parent / "page.js").read_text(encoding="utf-8")
    # By its type among the destinations' own steps, which are the ones named
    # chan-, since the one Add window holds a provider's step too.
    assert "connOvl.querySelectorAll('.m-stage[data-type]').forEach(function(s){" in script
    assert "if(s.dataset.type===b.dataset.type&&s.id.indexOf('chan-')===0)stage=s;" in script
