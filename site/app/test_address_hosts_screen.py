"""A host with no agent, on the screens (RECORD 4.104, part 4): its fleet
row, its own page as the prober-only tier, the proofs in its settings, and the
two windows that walk a proof of control. Its own file, the way the other
screen-adding tests are, so parallel branches do not all grow one file."""
import json
import re
import sqlite3
import sys
import pathlib
from datetime import timedelta

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402

V4 = "185.199.108.153"
NOW = trl.NOW

# Proofs are seeded through the registry itself, reached the way the renderer
# reaches it (site/app/joinbridge.py), so this file never names a registry
# table: SI-6 keeps app/authz.py as the only file that does, and a test in
# the control plane fails if any other Python file, this one included, ever
# queries those tables directly.
def probed_cell(value):
    """The header's Probed fact as it is drawn: the turning mark, written
    always and shown only while probing (test_probing_mark.py), then the
    value."""
    import theme
    return ('<div class="k">probed</div><div class="v"><span class="pspin" title="probing">'
            + theme.icon("circle-notch", 13) + '</span>' + value + '</div>')


def registry():
    return rl.joinbridge.module("authz")


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "cp.db"
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    rw = sqlite3.connect(path)
    rw.row_factory = sqlite3.Row
    registry().init(rw)
    rw.close()
    return str(path)


def add_address_host(db, name, paused=False, revoked=False):
    con = sqlite3.connect(db)
    cur = con.execute(
        "INSERT INTO hosts (name, token_hash, kind, created_at, revoked_at, paused,"
        " workspace_id) VALUES (?, NULL, 'address', ?, ?, ?, 1)",
        (name, NOW.isoformat(), NOW.isoformat() if revoked else None, 1 if paused else 0))
    con.commit()
    host_id = cur.lastrowid
    con.close()
    return host_id


def prove(db, host_id, address=V4, family="v4", days_left=20, revoked=False,
          expired=False, failure=None):
    """One published proof in the state asked for, produced the way the
    registry produces it: verified at a moment chosen so that its thirty day
    life has `days_left` left at NOW, then revoked, swept into expiry, or
    left un-renewable, each through the registry's own call."""
    authz = registry()
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    ttl = timedelta(seconds=authz.PUBLISHED_TTL_SECONDS)
    verified_at = NOW - ttl + timedelta(days=days_left)
    challenge = authz.start_proof(con, address, authz.METHOD_HTTP_TOKEN,
                                  now=verified_at, host_id=host_id)
    result = authz.verify_proof(con, challenge.id, now=verified_at,
                                fetcher=lambda url, timeout=0: challenge.token)
    assert result.recorded, result.reason
    if revoked:
        authz.revoke(con, address, now=NOW)
    if expired:
        # days_left is negative here, and the bookkeeping sweep writes the
        # lapse down the way the timer does
        authz.sweep(con, now=NOW)
    if failure:
        def gone(url, timeout=0):
            raise authz.ProofError(failure)
        authz.renew_published(con, now=NOW, fetcher=gone)
    con.close()


def page(db):
    return rl.render(db, now=NOW)


def fleet_row(html, name):
    """One host's row in the fleet list, scoped to the fleet view the way
    test_render_live.fleet_order scopes its search."""
    fleet = html.split('id="fleet"', 1)[1].split('<div class="wrap view"', 1)[0]
    start = fleet.index(f'<a class="row" href="/host/{name}" data-host="{name}"')
    return fleet[start:fleet.index("</a>", start)]


def agent_word(html, name):
    """The word in the agent fact under a server's name, on its own page.
    The Fleet said it in an Agent column until 2026-10-02."""
    head = trl.host_section(html, name).split('<div class="acts">')[0]
    return re.search(r'<div class="k">agent</div><div class="v">(?:<svg.*?</svg>)?(\w+)</div>',
                     head, re.S).group(1)


def cells_empty(row):
    """Whether the Reachable and Needs a decision cells hold nothing."""
    return '<div class="frc"></div>' in row and '<div class="fchips"></div>' in row


def fleet_numbers(html):
    """The four boxes as {label: (number, of N ports)}."""
    strip = re.search(r'<div class="fstrip">(.*?)</div>\s*<input', html, re.S).group(1)
    out = {}
    for label, number, total in re.findall(
            r'<div class="l">([^<]+)</div><div class="n[^"]*">(\d+)</div>'
            r'<div class="d">of (\d+) ports?</div>', strip):
        out[label] = (int(number), int(total))
    assert len(out) == 4, out
    return out


# ---------------------------------------------------------------- the fleet

def test_an_address_host_with_no_proof_says_so_on_its_row(db):
    add_address_host(db, "outside-only")
    html = page(db)
    row = fleet_row(html, "outside-only")
    assert 'data-state="no proof"' in row
    # the agent's word for a host that never reported, `not watched` since
    # 2026-10-09, is not an address host's word for having no proof
    assert "never reported" not in row and "not watched" not in row
    # its page says there is no agent, and the two cells the spec empties for
    # this state hold nothing, not a sentence (docs/screens/fleet/SPEC.md
    # section 5)
    assert agent_word(html, "outside-only") == "none"
    assert cells_empty(row)


def test_a_proved_but_never_probed_host_waits_for_its_first_pass(db):
    host_id = add_address_host(db, "outside-only")
    prove(db, host_id)
    row = fleet_row(page(db), "outside-only")
    assert 'data-state="not watched"' in row
    assert cells_empty(row)


def test_a_probed_host_shows_what_the_probe_found_and_its_last_pass(db):
    """**This asserted `watched` until 2026-08-28** (`docs/RECORD.md` 4.115).
    The probe reached tcp/443 and nobody has declared it, which is a finding
    about this server. `watched` is a fact about our own monitoring and it is
    the ordinary one, so it is not what the State cell is for.

    The port answered, so this row now reads `unreviewed`, and `watched` is
    dropped rather than drawn as a second tag: a tag saying the monitoring is
    working would be on every healthy row on the page.
    """
    host_id = add_address_host(db, "outside-only")
    prove(db, host_id)
    trl.probe_result(db, "outside-only", 443, "v4", "connect_succeeded",
                     measured_at=NOW - timedelta(minutes=7))
    html = page(db)
    row = fleet_row(html, "outside-only")
    assert 'data-state="unreviewed"' in row
    assert "watched" not in row
    # the port is a chip in the Needs a decision cell, amber, and the
    # Reachable cell counts it as open: one of the one port observed
    assert '<span class="fpc warn">tcp/443</span>' in row
    assert '<div class="frc"><b>1</b> of 1 port</div>' in row
    # the last-seen age left this screen with the Last seen column
    assert "7m" not in row


def test_a_probed_host_with_nothing_measured_is_still_not_probed_yet(db):
    """The other side of the same rule, and the reason `watched` no longer
    reaches the State cell of an address host at all.

    A `not_tested` result is not a measurement, so `address_freshness` still
    answers `not watched` and the engine still has no state to show. Once
    anything IS measured, `_decide_without_an_agent` always produces a state,
    which then wins the cell. So `watched` stays a real word, used for the
    ports cell's empty-state line and as the ordinary liveness this row does
    not draw, and it stops being a thing the State cell says.
    """
    host_id = add_address_host(db, "quiet-one")
    prove(db, host_id)
    trl.probe_result(db, "quiet-one", 443, "v4", "not_tested",
                     measured_at=NOW - timedelta(minutes=7))
    row = fleet_row(page(db), "quiet-one")
    assert "not watched" in row


def test_a_measured_silence_reads_as_watched_with_nothing_open(db):
    """The most common row on a well run server. The engine's word for the
    port is `not reachable`, and the Fleet has one word for a fine server,
    `watched` (docs/screens/fleet/SPEC.md section 5), so the row reads that
    and the Reachable cell says what the probe found: nothing open of the one
    port it measured."""
    host_id = add_address_host(db, "shut-tight")
    prove(db, host_id)
    trl.probe_result(db, "shut-tight", 9100, "v4", "no_response",
                     measured_at=NOW - timedelta(minutes=7))
    row = fleet_row(page(db), "shut-tight")
    assert 'data-state="watched"' in row
    assert "not reachable" not in row
    assert '<div class="frc"><b>0</b> of 1 port</div>' in row
    assert '<div class="fchips"></div>' in row


def test_paused_and_revoked_keep_their_words(db):
    add_address_host(db, "resting", paused=True)
    add_address_host(db, "gone", revoked=True)
    html = page(db)
    assert "paused" in fleet_row(html, "resting")
    assert "gone" not in trl.fleet_order(html)


def test_the_sample_fleet_carries_a_watched_address_host(db):
    row = fleet_row(build.build_sample(), "office-06")
    assert 'data-state="watched"' in row
    assert '<div class="frc"><b>2</b> of 2 ports</div>' in row


# ------------------------------------------------------------- the host page

def test_the_page_has_the_four_tabs_and_not_the_agents_three(db):
    host_id = add_address_host(db, "outside-only")
    prove(db, host_id)
    section = trl.host_section(page(db), "outside-only")
    for key in ("overview", "evidence", "changes", "settings"):
        assert f'id="tb-outside-only-{key}"' in section, key
    for key in ("services", "path", "rules"):
        assert f'id="tb-outside-only-{key}"' not in section, key


def test_the_header_counts_proved_addresses_and_the_last_pass(db):
    host_id = add_address_host(db, "outside-only")
    prove(db, host_id)
    prove(db, host_id, address="2606:50c0:8000::153", family="v6")
    trl.probe_result(db, "outside-only", 443, "v4", "connect_succeeded",
                     measured_at=NOW - timedelta(minutes=3))
    section = trl.host_section(page(db), "outside-only")
    # the four facts under the name (docs/screens/host-overview/SPEC.md
    # section 2): agent none, addresses proved, probed, ports
    head = section.split('<div class="acts">')[0]
    assert ('<div class="k">addresses proved</div><div class="v"><span class="num">2</span></div>'
            in head)
    assert probed_cell('<span class="num">3m</span> ago') in head
    assert '<div class="k">ports</div><div class="v"><span class="num">1</span></div>' in head
    assert "sections read" not in section and "schema" not in section


def test_the_overview_lists_what_was_measured_and_nothing_else(db):
    host_id = add_address_host(db, "outside-only")
    prove(db, host_id)
    trl.probe_result(db, "outside-only", 443, "v4", "connect_succeeded")
    trl.probe_result(db, "outside-only", 22, "v4", "no_response")
    section = trl.host_section(page(db), "outside-only")
    overview = trl.tab_body(section, "outside-only", "overview")
    assert 'data-port="443/tcp"' in overview and 'data-port="22/tcp"' in overview
    # no agent, so the service cell is a dash and the line under the table
    # says why (the approved sketch's address-only case)
    assert '<span class="prs note">&mdash;</span>' in overview
    assert build.NO_AGENT_LINE in overview
    assert "unknown process" not in overview


def test_the_overview_of_an_unprobed_host_says_nothing_measured(db):
    host_id = add_address_host(db, "outside-only")
    prove(db, host_id)
    overview = trl.tab_body(trl.host_section(page(db), "outside-only"), "outside-only", "overview")
    # no rows and no sentence about it: the boxes read zero of no ports
    assert 'data-port="' not in overview
    assert "Nothing measured yet." not in overview
    assert overview.count("of 0 ports") == 2


def test_the_opened_row_card_says_the_firewall_is_not_seen_inside(db):
    """No agent reads this host's rules, and the firewall line says that and
    no more, in the one constant the Decided by cell uses for `unexplained`
    on a server with an agent (docs/record 4.451)."""
    host_id = add_address_host(db, "outside-only")
    prove(db, host_id)
    trl.probe_result(db, "outside-only", 443, "v4", "connect_succeeded")
    overview = trl.tab_body(trl.host_section(page(db), "outside-only"), "outside-only", "overview")
    line = f'<span class="k">firewall</span><span class="v">{rl.NOT_SEEN_INSIDE}</span>'
    # the measured family's card and the not-tested family's card
    assert overview.count(line) == 2
    assert "no view from inside" not in overview


def test_the_evidence_agent_column_says_no_agent(db):
    host_id = add_address_host(db, "outside-only")
    prove(db, host_id)
    trl.probe_result(db, "outside-only", 443, "v4", "connect_succeeded")
    evidence = trl.tab_body(trl.host_section(page(db), "outside-only"), "outside-only", "evidence")
    assert "no agent" in evidence
    assert "not read" not in evidence


# --------------------------------------------------------------- the settings

def test_the_settings_list_every_proof_with_its_status(db):
    """Since 2026-10-20 a published proof is read every day and a read that
    finds it gone ends it (docs/PRODUCT.md 5). So a live proof was read
    within the last day, and one whose read got no answer is still live only
    while its last good read is under two days old, which is what these two
    rows are."""
    host_id = add_address_host(db, "outside-only")
    prove(db, host_id, days_left=29.25)
    prove(db, host_id, address="185.199.109.153", days_left=28.5, failure="could not read http://x: HTTP 404")
    prove(db, host_id, address="185.199.110.153", revoked=True)
    prove(db, host_id, address="185.199.111.153", days_left=-2, expired=True)
    settings = trl.tab_body(trl.host_section(page(db), "outside-only"), "outside-only", "settings")
    assert "185.199.108.153" in settings and "proved until 12 Sep" in settings
    assert "not renewed: could not read http://x: HTTP 404" in settings
    assert "revoked 14 Aug" in settings
    assert "expired 14 Aug" in settings
    # only a live proof offers Revoke, and the window opener names the host
    assert settings.count('class="btn js-addr-revoke"') == 2
    assert '<button class="btn pri" data-open="addr-ovl" data-host="outside-only">Add address</button>' in settings
    # the planned sweep rows of an agent host are not pretended here
    assert "top-1000 sweep" not in settings


def test_the_settings_keep_pause_and_remove_and_show_the_id(db):
    """Only working controls. This list held "Labels" until 2026-08-29, when
    the dead planned rows left every live settings panel (the rule for customer screens: on a
    customer surface, leave the control out)."""
    host_id = add_address_host(db, "outside-only")
    prove(db, host_id)
    settings = trl.tab_body(trl.host_section(page(db), "outside-only"), "outside-only", "settings")
    for control in ("js-pause", "js-remove"):
        assert control in settings, control
    # The ID an operator typed when adding it is shown and not edited, as an
    # agent's server's is (docs/RECORD.md 4.298).
    assert '<span class="idv" id="id-outside-only">outside-only</span>' in settings
    assert "js-rename" not in settings


# --------------------------------------------------------------- the windows

def test_the_add_server_window_offers_addresses(db):
    """The live page carries the add-server window; the sample shell never
    did (its Add server is a toast), so this is the live feed's alone."""
    html = page(db)
    assert 'id="add-addr"' in html and "Addresses, no agent" in html
    assert "Range, no agent" not in html
    assert 'id="add-addr-stage"' in html
    assert 'id="add-addr-name"' in html and 'id="add-addr-address"' in html
    assert 'data-method="http-token"' in html and 'data-method="dns-txt"' in html


def test_the_address_window_is_on_both_feeds_and_says_nothing_but_labels(db):
    """The proof happens in a window since 2026-10-06 (docs/RECORD.md 4.379):
    the address, the way to prove it, Start, and the token with Verify once
    started. Until then it happened on a row under the addresses. The remove
    window is on both feeds too."""
    add_address_host(db, "gateway")
    for html in (build.build_sample(), page(db)):
        assert html.count('id="addr-ovl"') == 1 and "Add address" in html
        assert 'data-method="http-token"' in html and 'data-method="dns-txt"' in html
        assert "Publish this token" in html and 'id="ad-go"' in html
        assert 'id="rm-ovl"' in html and 'id="rm-go"' in html
        win = html.split('id="rm-ovl"')[1].split("</div>\n</div>")[0]
        for prose in ("planned", "not built", "control plane", "timer"):
            assert prose not in win, prose


def test_the_script_walks_the_proof_through_the_real_routes(db):
    script = build.build_sample().split("<script>")[-1]
    assert "/addresses'" in script and "/verify'" in script and "/addresses/revoke'" in script
    assert "kind:'address'" in script
    # Closing on a created host asks the server for the page rather than
    # reloading it (test_quiet_refresh.py owns the refresh itself).
    assert "if(addCreated||addCmds){addCreated=null;addCmds=null;refresh(true)}" in script.replace("{{", "{").replace("}}", "}")
    assert "location.reload" not in script
    assert "Click again to revoke" in script


# --------------------------------- every row can be found by some filter

def _one_of_each_kind(db):
    """A fleet holding both vocabularies: an agent host reporting, one that
    has gone quiet, one that never reported, and address hosts with no proof,
    with a proof and no pass, and being watched."""
    trl.add_host(db, "reports-fine",
                 [(NOW - timedelta(minutes=2), trl.document())],
                 last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    trl.add_host(db, "went-quiet",
                 [(NOW - timedelta(hours=9), trl.document())],
                 last_report_at=(NOW - timedelta(hours=9)).isoformat())
    trl.add_host(db, "never-said-anything", [])
    add_address_host(db, "no-address-proved")
    prove(db, add_address_host(db, "proved-not-probed"))
    watched = add_address_host(db, "being-watched")
    prove(db, watched)
    trl.probe_result(db, "being-watched", 443, "v4", "connect_succeeded",
                     measured_at=NOW - timedelta(minutes=7))


# Every word a row's State cell may carry, from the table in
# docs/screens/fleet/SPEC.md section 5. `silent` carries its age after it.
SPEC_STATE_WORDS = ("conflict", "not readable", "unreviewed", "unexplained",
                    "stale rule", "silent", "no proof", "paused", "not watched",
                    "watched")


def test_every_fleet_row_carries_a_state_word_the_spec_names(db):
    """The filter buttons left with the Fleet of 2026-09-03, and what keeps
    every row findable now is the spec's own table: a row's word is one of
    its eleven, so the sort and the reader meet no word nobody decided.
    `reporting`, `intended` and `not reachable` are not on this page."""
    _one_of_each_kind(db)
    html = page(db)
    fleet = html.split('id="fleet"', 1)[1].split('<div class="wrap view"', 1)[0]
    states = re.findall(r'data-state="([^"]+)"', fleet)
    assert len(states) == 6, "every seeded host is a row"
    for state in states:
        word = "silent" if state.startswith("silent") else state
        assert word in SPEC_STATE_WORDS, f"the row's word {state!r} is not in the spec"
    assert not any(w in states for w in ("reporting", "intended", "not reachable"))


def test_the_four_boxes_add_up_to_the_rows_under_them(db):
    """The boxes are sums of what the rows show (build.fleet_totals), so a
    reader can check them against the table. Seeded with one of each kind,
    so rows with empty cells are in the sum as zero."""
    _one_of_each_kind(db)
    html = page(db)
    numbers = fleet_numbers(html)
    rows = [fleet_row(html, n) for n in re.findall(
        r'<a class="row" href="[^"]*" data-host="([^"]+)"', html)]
    assert len(rows) == 6
    fail_chips = sum(r.count('class="fpc fail"') for r in rows)
    warn_chips = sum(r.count('class="fpc warn"') for r in rows)
    opened = sum(int(n) for r in rows for n in re.findall(r'<div class="frc"><b>(\d+)</b>', r))
    observed = sum(int(m) for r in rows for m in re.findall(r'</b> of (\d+) ports?</div>', r))
    assert numbers["Disagrees with what you declared"] == (fail_chips, observed)
    assert numbers["Needs a decision"] == (warn_chips, observed)
    assert numbers["Reachable from outside"] == (opened, observed)
    assert numbers["Changed in 24h"][1] == observed
    # being-watched answered on 443 and nothing else on this fleet is measured
    assert numbers["Reachable from outside"] == (1, 1)


def test_the_freshness_column_does_not_call_a_probe_a_report(db):
    """An address host never reports. The age in its freshness cell is when
    the prober last measured it, so the header must not say report."""
    host_id = add_address_host(db, "being-watched")
    prove(db, host_id)
    trl.probe_result(db, "being-watched", 443, "v4", "connect_succeeded",
                     measured_at=NOW - timedelta(minutes=7))
    html = page(db)
    labels = re.findall(r"<span>([^<]+)</span>",
                        re.search(r'<div class="thead[^"]*"[^>]*>(.*?)</div>', html, re.S).group(1))
    assert labels == list(build.FLEET_COLUMNS)
    assert not any("report" in label.lower() for label in labels)
    # The windows at the end of the page are not this host's: the remove
    # window carries a Last report row for an agent host, hidden here.
    screens = html[:html.index('<div class="ovl js-modal"')]
    assert "Last seen" not in screens and "Last report" not in screens


# ------------------------------------------------- how it says it is watched
#
# The third of the three ways, and the only one that is certain: `hosts.kind`
# says there is no agent, so nothing about this host is ever read from inside.

def test_the_mode_mark_carries_no_agent_on_the_page(db):
    host_id = add_address_host(db, "outside-only")
    prove(db, host_id)
    html = page(db)
    assert agent_word(html, "outside-only") == "none"
    # the host page says it in its agent fact, with the globe
    head = trl.host_section(html, "outside-only").split('<div class="acts">')[0]
    assert '<div class="k">agent</div><div class="v">' in head
    assert build.theme.icon("globe-hemisphere-west", 15) + "none</div>" in head


def test_no_agent_is_the_word_whatever_the_proof_and_the_probes_say(db):
    """The state word moves with the proof and the probes. How this host is
    watched does not: there is no agent on any of those days."""
    for name, kwargs in (("unproved", {}), ("resting", {"paused": True}),
                         ("gone", {"revoked": True})):
        add_address_host(db, name, **kwargs)
    proved = add_address_host(db, "proved")
    prove(db, proved)
    probed = add_address_host(db, "probed")
    prove(db, probed)
    trl.probe_result(db, "probed", 443, "v4", "connect_succeeded")
    html = page(db)
    for name in ("unproved", "resting", "proved", "probed"):
        assert agent_word(html, name) == "none", name


def test_a_host_with_no_agent_has_no_hostname_line_and_its_page_shows_the_globe(db):
    """An address host reports no document, so it has no hostname to put
    under its name, and the agent fact on its page is the globe and the word
    none."""
    add_address_host(db, "outside-only")
    html = page(db)
    row = fleet_row(html, "outside-only")
    assert '<div class="fsrv"><div class="hn">outside-only</div></div>' in row
    assert "fhost" not in row
    assert build.theme.icon("globe-hemisphere-west", 15) in trl.host_section(html, "outside-only")
    assert agent_word(html, "outside-only") == "none"


# ------------------------------------------- the empty screen shows the way

def test_an_unproved_hosts_overview_holds_no_sentence_and_no_control(db):
    """The empty overview used to say "No address proved." with an Add
    address button (the 2026-08-29 audit round). The approved sketch of
    2026-09-04 has neither: the state tag says no proof, the settings hold
    the control, and the overview is the boxes and an empty table. Said to
    the owner on 2026-09-05 as a thing the spec dropped."""
    add_address_host(db, "bare")
    overview = trl.tab_body(trl.host_section(page(db), "bare"), "bare",
                            "overview")
    assert "No address proved." not in overview
    assert "js-addr-add" not in overview
    assert build.NO_AGENT_LINE in overview


def test_a_proved_but_unmeasured_host_offers_no_act(db):
    """There is nothing for the reader to do: the address is proved and the
    timers do the rest. The line states the fact and stops."""
    host_id = add_address_host(db, "waiting")
    prove(db, host_id)
    overview = trl.tab_body(trl.host_section(page(db), "waiting"), "waiting",
                            "overview")
    assert "Nothing measured yet." not in overview
    assert "js-addr-add" not in overview
    assert 'data-port="' not in overview


def test_the_proof_row_keeps_its_status_on_one_line(db):
    """The address sits alone in the label column and the status in the
    detail column. Both used to share the 190px label cell, so a proof read
    "proved until" on one line and the date on the next."""
    host_id = add_address_host(db, "outside-only")
    prove(db, host_id)
    settings = trl.tab_body(trl.host_section(page(db), "outside-only"),
                            "outside-only", "settings")
    row = settings.split(V4)[1].split('<div class="li">')[0]
    assert '<small class="dim">' in row and "proved until" in row


def test_the_button_that_adds_an_address_is_in_the_headings_line(db):
    """Above the rows, at the right of the heading, where a list's own
    button sits on the Fleet and on Alerts."""
    host_id = add_address_host(db, "outside-only")
    prove(db, host_id)
    settings = trl.tab_body(trl.host_section(page(db), "outside-only"),
                            "outside-only", "settings")
    assert settings.index('data-open="addr-ovl"') < settings.index("js-addr-revoke")
    assert "js-addr-start" not in settings
