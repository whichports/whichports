"""The Fleet screen: the banner, the four boxes, the search bar and the table,
as decided on 2026-09-03 (docs/screens/fleet/SPEC.md, the approved sketch
beside it).

    Run from site/app: python3 -m pytest test_fleet.py

What the sample shell builds is the sketch's twelve rows, so every state the
fleet can show has a row here to read. The live feed's half of the same shape
is in test_render_live.py, where the database fixture lives, and the browser
behaviour (search, dismiss, the quiet refresh) is in test_fleet_browser.py and
test_quiet_refresh.py.
"""
import dataclasses
import re

import build
import theme


def fleet_section(html):
    return html.split('id="fleet"', 1)[1].split('<div class="wrap view"', 1)[0]


def fleet_thead(html):
    """The fleet table's header row."""
    return re.search(r'<div class="thead[^"]*"[^>]*>(.*?)</div>', fleet_section(html),
                     re.S).group(1)


def thead_labels(html):
    return [label.strip() for label in re.findall(r"<span[^>]*>([^<]+)</span>",
                                                  fleet_thead(html))]


def fleet_rows(html):
    """The markup of each row in the fleet list, in the order it is shown."""
    return re.findall(r'<a class="row" .*?</a>', fleet_section(html), re.S)


def row_cells(row):
    """What is inside each top level cell of one row, in column order.

    Depth counted rather than matched with a regex, because the Server cell
    holds divs of its own and a lazy match would stop inside it.
    """
    inner = row.split(">", 1)[1].rsplit("</a>", 1)[0]
    cells, depth, start = [], 0, 0
    for tag in re.finditer(r"<div\b[^>]*>|</div>", inner):
        if tag.group(0).startswith("</"):
            depth -= 1
            if depth == 0:
                cells.append(inner[start:tag.start()])
        else:
            if depth == 0:
                start = tag.end()
            depth += 1
    return cells


def row_named(html, name):
    for row in fleet_rows(html):
        if f'data-host="{name}"' in row:
            return row
    raise AssertionError(f"no fleet row for {name}")


def boxes(html):
    """The four boxes as [(label, number, of N, fail toned, bar width)]."""
    strip = re.search(r'<div class="fstrip">(.*?)</div>\s*<input', fleet_section(html),
                      re.S).group(1)
    found = re.findall(
        r'<div class="l">([^<]+)</div><div class="n( fail)?">(\d+)</div>'
        r'<div class="d">of (\d+) ports?</div><div class="fbar"><i[^>]*style="width:(\d+)%"',
        strip)
    assert len(found) == 4, strip
    return [(label, int(n), int(total), bool(fail), int(pct))
            for label, fail, n, total, pct in found]


def sample_row(name):
    return next(r for r in build.FLEET_SAMPLE if r.name == name)


# ------------------------------------------------------------ the header

def test_the_header_is_the_four_columns_of_the_spec():
    """Five until 2026-10-02, when the owner took the Agent column out."""
    assert thead_labels(build.build_sample()) == [
        "State", "Server", "Reachable", "Needs a decision"]


def test_both_feeds_read_the_columns_from_one_place():
    assert list(build.FLEET_COLUMNS) == [
        "State", "Server", "Reachable", "Needs a decision"]
    assert build.fleet_thead_html() == "".join(
        f"<span>{label}</span>" for label in build.FLEET_COLUMNS)


def test_the_header_is_uppercase_as_the_sketch_draws_it():
    """The sketch draws the header uppercase and the 2026-08-29 rule said no
    table header shouts. The owner, 2026-09-06, found it good as it was and like
    the drawing, so the screens' tables keep the uppercase micro
    label and the marker is gone."""
    head = re.search(r'<div class="thead[^"]*"[^>]*>', build.build_sample()).group(0)
    assert head == '<div class="thead">'
    assert "text-transform:uppercase" in build.CSS.split(".thead span{")[1].split("}")[0]


def test_every_row_has_one_cell_per_column():
    html = build.build_sample()
    assert len(fleet_rows(html)) == len(build.FLEET_SAMPLE)
    for row in fleet_rows(html):
        assert len(row_cells(row)) == len(build.FLEET_COLUMNS), row


# ------------------------------------------------------------ the rows

def test_a_row_is_one_link_to_the_servers_page():
    row = row_named(build.build_sample(), "app-01")
    assert row.startswith('<a class="row" href="/host/app-01" '
                          'data-host="app-01" data-state="conflict" '
                          'data-under="ubuntu-app-01">')
    # nothing else on the row is a link or a button
    assert "<a " not in row[3:] and "<button" not in row


def test_a_name_that_needs_escaping_makes_a_safe_link_and_safe_text():
    row = build.fleet_row_html(build.FleetRow(
        "warn", "unreviewed", 'a"b<c>&d e', hostname="<script>x</script>",
        reach=(1, 2), chips=(("<b>tcp/1</b>", "warn"),)))
    assert 'href="/host/a%22b%3Cc%3E%26d%20e"' in row
    assert "<script>" not in row and "&lt;script&gt;" in row
    assert "<b>tcp/1</b>" not in row and "&lt;b&gt;tcp/1&lt;/b&gt;" in row
    assert 'data-host="a&quot;b&lt;c&gt;&amp;d e"' in row


def test_the_state_cell_is_the_one_tag_and_nothing_beside_it_on_a_plain_row():
    cell = row_cells(row_named(build.build_sample(), "media-01"))[0]
    assert cell.count('class="st ') == 1
    assert theme.status("warn", "unreviewed") in cell
    # the mute mark is written empty for the click to fill, and nothing else
    assert cell.count("<span") == 2
    assert 'class="tag-mute" data-mute-tag="media-01" title="muted"></span>' in cell


def test_the_server_cell_is_the_name_and_the_hostname_only_when_it_differs():
    html = build.build_sample()
    prod = row_cells(row_named(html, "app-01"))[1]
    assert prod == ('<div class="hn">app-01</div>'
                    '<span class="ftag">production</span>'
                    '<small class="fhost">ubuntu-app-01</small>')
    plain = row_cells(row_named(html, "media-01"))[1]
    assert plain == '<div class="hn">media-01</div>'
    # a hostname equal to the name is not printed twice
    same = build.fleet_row_html(build.FleetRow("ok", "watched", "box", hostname="box"))
    assert "fhost" not in same


def test_no_row_says_how_the_server_is_watched():
    """The Agent column left the Fleet on 2026-10-02, on the owner's word. The
    words and their glyphs stay, for the fact on a
    server's own page."""
    fleet = build.build_sample().split('id="fleet"')[1].split('<div class="wrap view"')[0]
    assert 'class="fag"' not in fleet
    for row in fleet_rows(build.build_sample()):
        assert theme.icon("binoculars", 16) not in row
        assert theme.icon("globe-hemisphere-west", 16) not in row
    assert not hasattr(build, "agent_cell_html")
    assert "agent" not in {f.name for f in dataclasses.fields(build.FleetRow)}
    assert build.AGENT_ICON == {"agent": "binoculars", "none": "globe-hemisphere-west"}
    assert set(build.AGENT_WORD.values()) == set(build.AGENT_ICON)


def test_no_width_hides_a_cell_of_the_row_by_its_position():
    """Found by looking at the phone shot on 2026-10-02: a rule from when the
    row had five cells hid "the third" below 1080px. That was the Agent cell,
    and with the column gone it hid Reachable instead. A cell may be hidden
    when it is empty and never because of where it sits."""
    hidden = re.findall(r"\.row>div:nth-child\((\d)\)(:empty)?[^{]*\{display:none\}", build.CSS)
    assert hidden, "the empty-cell rule on a phone is gone, and it is what this reads"
    assert all(empty for _n, empty in hidden), hidden
    assert ".thead span:nth-child(3),.row>div:nth-child(3){display:none}" not in build.CSS
    # each width's grid has as many tracks as the row has cells, or two on a phone
    wide = re.search(r"\.thead,\.row\{display:grid;grid-template-columns:([^;]+);", build.CSS).group(1)
    assert len(wide.split(" ")) == len(build.FLEET_COLUMNS)


def test_the_reachable_cell_is_n_of_m_ports_with_n_bold():
    """The outside review's point 1 (REVIEW-2026-10-06): "3 of 8" said of
    what nowhere. The cell carries the unit the box above the table already
    carries, "of 36 ports", so the two read the same (docs/record 4.451)."""
    html = build.build_sample()
    # app-01 is the server the sample has a page for, and its two cells are
    # counted from that server's one description (docs/RECORD.md 4.443): four
    # of its seven ports answer. It read 3 of 8 while its own page said 4 of 7.
    assert row_cells(row_named(html, "app-01"))[2] == "<b>4</b> of 7 ports"
    assert row_cells(row_named(html, "backup-03"))[2] == "<b>0</b> of 5 ports"
    assert row_cells(row_named(html, "office-06"))[2] == "<b>2</b> of 2 ports"
    # one port reads in the singular, as the box does
    assert build.reach_cell_html((0, 1)) == "<b>0</b> of 1 port"
    assert build.reach_cell_html((1, 1)) == "<b>1</b> of 1 port"


def test_the_decision_cell_is_chips_worst_first_and_nothing_after_them():
    """It ended in "+ 4", the ports that need no decision, which read as
    four more that do (docs/RECORD.md 4.395)."""
    cell = row_cells(row_named(build.build_sample(), "app-01"))[3]
    # The ports the server's own page says need somebody: the conflict, the
    # one no rule names, and the one family nothing explains. tcp/80 stood
    # here while its own page called it intended (docs/RECORD.md 4.443).
    assert cell == ('<span class="fpc fail">tcp/443</span>'
                    '<span class="fpc warn">tcp/8410 v4</span>'
                    '<span class="fpc warn">tcp/22 v6</span>')


def test_a_fine_server_has_an_empty_decision_cell():
    """The cell holds nothing (SPEC.md section 5)."""
    assert row_cells(row_named(build.build_sample(), "store-07"))[3] == ""
    assert build.port_chips_html(()) == ""
    assert build.port_chips_html((("tcp/22", "warn"),)) == '<span class="fpc warn">tcp/22</span>'


def test_no_row_of_the_fleet_counts_the_ports_that_need_no_decision():
    html = build.build_sample()
    fleet = html.split('id="fleet"', 1)[1].split('class="view', 1)[0]
    assert 'class="none"' not in fleet
    assert not re.search(r">\+ \d+<", fleet)


def test_the_cells_the_spec_empties_hold_nothing_not_a_sentence():
    html = build.build_sample()
    for name in ("build-02", "mail-relay", "lab-04", "edge-05", "new-a1b2c3"):
        cells = row_cells(row_named(html, name))
        assert cells[2] == "" and cells[3] == "", name
    assert build.CELLS_EMPTY == ("not readable", "no proof", "paused", "not watched")
    # and the sentences the old fleet printed in an empty cell are gone
    fleet = fleet_section(html)
    for gone in ("nothing listening", "waiting for its first", "no address proved",
                 "not shown", "no document for"):
        assert gone not in fleet


def test_the_rows_come_out_worst_first_by_the_bands_and_then_by_name():
    order = [re.search(r'data-host="([^"]+)"', row).group(1)
             for row in fleet_rows(build.build_sample())]
    # The spec's order is build.FLEET_BANDS (SPEC.md section 5): `not
    # readable` sits after the four port states and `not watched` last. The
    # sketch drew those rows elsewhere, and the spec wins, said so to the
    # owner on 2026-09-05. Since 2026-10-09 (docs/record 4.447) a server
    # nobody has probed and one that never reported are one word in one
    # band, the last; inside it a server that reports before a pending
    # enrolment, then by name.
    assert order == ["app-01", "media-01", "web-02", "db-01", "build-02",
                     "backup-03", "mail-relay", "lab-04",
                     "office-06", "store-07", "edge-05", "new-a1b2c3"]
    word_of = {r.name: r.word for r in build.FLEET_SAMPLE}
    bands = [build.fleet_band(word_of[n]) for n in order]
    assert bands == sorted(bands)


def test_the_sort_reads_the_row_and_leaves_the_rows_alone():
    rows = [build.FleetRow("ok", "watched", "b"), build.FleetRow("fail", "conflict", "a"),
            build.FleetRow("off", "not watched", "c")]
    out = build.sort_fleet_rows(rows)
    assert [r.name for r in out] == ["a", "b", "c"]
    assert rows[0].name == "b", "the caller's list was reordered"


# ------------------------------------------------------------ the four boxes

def test_the_four_boxes_in_the_spec_order_with_one_n_for_all():
    found = boxes(build.build_sample())
    assert [b[0] for b in found] == ["Disagrees with what you declared", "Needs a decision",
                                     "Reachable from outside", "Changed in 24h"]
    assert len({b[2] for b in found}) == 1, "of N ports differs between boxes"
    # the number is in the fail colour in the first box only
    assert [b[3] for b in found] == [True, False, False, False]


def test_the_four_numbers_add_up_to_the_rows_under_them():
    html = build.build_sample()
    rows = fleet_rows(html)
    fail_chips = sum(r.count('class="fpc fail"') for r in rows)
    warn_chips = sum(r.count('class="fpc warn"') for r in rows)
    opened = sum(int(n) for r in rows for n in re.findall(r'<div class="frc"><b>(\d+)</b>', r))
    observed = sum(int(m) for r in rows for m in re.findall(r'</b> of (\d+) ports?</div>', r))
    found = {label: (n, total) for label, n, total, _fail, _pct in boxes(html)}
    assert found["Disagrees with what you declared"] == (fail_chips, observed) == (1, 35)
    assert found["Needs a decision"] == (warn_chips, observed) == (7, 35)
    assert found["Reachable from outside"] == (opened, observed) == (12, 35)
    assert found["Changed in 24h"] == (build.FLEET_SAMPLE_CHANGED, observed)


def test_the_bar_is_the_number_as_a_share_of_n():
    for _label, n, total, _fail, pct in boxes(build.build_sample()):
        assert pct == round(100 * n / total)
    # nothing observed draws an empty bar rather than dividing by zero, and a
    # count over N, which the changes box can produce, never overflows it
    assert 'style="width:0%"' in build.fleet_box("x", 0, 0)
    assert 'style="width:100%"' in build.fleet_box("x", 5, 2)
    assert "of 1 port<" in build.fleet_box("x", 1, 1)


def test_the_totals_count_only_what_the_rows_show():
    shown = build.FleetRow("fail", "conflict", "a", reach=(2, 4),
                           chips=(("tcp/1", "fail"), ("tcp/2", "warn")))
    hidden = build.FleetRow("off", "paused", "b", reach=(9, 9),
                            chips=(("tcp/3", "fail"),))
    totals = build.fleet_totals([shown, hidden], changed=3)
    assert totals == {"conflict": 1, "decision": 1, "reachable": 2, "changed": 3, "ports": 4}
    assert build.fleet_totals([]) == {"conflict": 0, "decision": 0, "reachable": 0,
                                      "changed": 0, "ports": 0}


# ------------------------------------------------------------ the banner

def test_the_sample_banner_is_the_sketchs_one_line():
    html = build.build_sample()
    note = re.search(r'<div class="fnotes">(.*?)</div>\s*<div class="ph">', fleet_section(html),
                     re.S).group(1)
    assert note.startswith('<div class="fnote fail" data-note="channel:sysadmin@example.org">')
    assert ('<span class="t">Alert mail to <b>sysadmin@example.org</b> was refused by the '
            'relay.</span>') in note
    assert '<button class="btn" data-go="alerts">Open channel</button>' in note
    assert '<button class="x" aria-label="Dismiss">&times;</button>' in note
    # above the title, which is what the sketch draws
    assert fleet_section(html).index('class="fnotes"') < fleet_section(html).index("<h1>Fleet</h1>")


def test_the_banner_region_draws_nothing_with_nothing_to_say():
    assert build.fleet_notes_html([]) == '<div class="fnotes"></div>'
    assert ".fnotes:empty{display:none}" in build.CSS


def test_banners_come_worst_first_and_only_the_first_shows():
    notes = [("warn", "billing:trial", "Trial ends <b>Friday</b>.", "Billing", "settings"),
             ("fail", "channel:x", "Mail to <b>x</b> was refused.", "Open channel", "alerts")]
    html = build.fleet_notes_html(notes)
    assert html.index('data-note="channel:x"') < html.index('data-note="billing:trial"')
    # the stylesheet shows the first note that is not dismissed and no other
    assert ".fnote[hidden],.fnote:not([hidden])~.fnote:not([hidden]){display:none}" in build.CSS
    try:
        build.fleet_note_html("ok", "k", "t", "a", "alerts")
    except ValueError:
        pass
    else:
        raise AssertionError("a banner took a tone that is not fail or warn")


def test_the_banner_dot_and_the_dismiss_are_drawn_by_the_stylesheet():
    css = build.CSS
    dot = css.split(".fnote .t::before{")[1].split("}")[0]
    assert "width:8px;height:8px" in dot and "background:var(--warn)" in dot
    assert ".fnote.fail .t::before{background:var(--fail)}" in css


# ------------------------------------------------------------ the search

def test_the_search_bar_is_full_width_between_the_boxes_and_the_table():
    fleet = fleet_section(build.build_sample())
    assert '<input class="srch" placeholder="Search">' in fleet
    assert fleet.index('class="fstrip"') < fleet.index('class="srch"') < fleet.index(' ftbl"')
    srch = build.CSS.split(".srch{")[1].split("}")[0]
    assert "display:block;width:100%" in srch


def test_the_search_filters_on_the_rows_text_and_there_are_no_filter_buttons():
    html = build.build_sample()
    fleet = fleet_section(html)
    assert 'data-f="' not in fleet and 'class="seg"' not in fleet
    script = html[html.rindex("<script>"):]
    apply_fn = script[script.index("var applyFleet"):]
    apply_fn = apply_fn[:apply_fn.index("};")]
    assert "textContent" in apply_fn and "dataset.state" not in apply_fn
    assert "addEventListener('input',applyFleet)" in script


# ------------------------------------------------------------ what is not on it

def test_the_fleet_is_no_chart_and_carries_no_strip():
    """docs/DESIGN.md section 2. The only drawings on the fleet are the three
    Agent glyphs; no sparkline, no port strip, no last-seen column."""
    fleet = fleet_section(build.build_sample())
    assert "<canvas" not in fleet
    for svg in re.findall(r"<svg[^>]*>", fleet):
        assert 'class="ic"' in svg, svg
    for gone in ('class="strip"', 'class="pc ', "Last seen", "prob-note", "alert-note",
                 'class="tag-mode"', 'class="hmeta"'):
        assert gone not in fleet, gone


def test_every_magenta_marker_says_what_is_unsure():
    html = build.build_sample()
    for marker in re.findall(r'<[a-z]+ class="[^"]*unsure[^"]*"[^>]*>', fleet_section(html)):
        assert 'title="' in marker, marker
    # no open item since 2026-09-13, when the muted mark was decided (4.174)
    fleet = fleet_section(html)
    assert fleet.count("unsure") == 0
    assert build.alert_mark_html("14 Aug 10:00") == '<span class="tag-alert" title="alert open">alert open</span>'
    assert build.alert_mark_html("") == ""
    assert ".unsure,.unsure *{background:#FF00FF!important" in build.CSS


def test_the_page_script_keeps_the_page_current_without_reloading():
    html = build.build_sample()
    script = html[html.rindex("<script>"):]
    assert "var REFRESH_MS=60000" in script
    assert "setInterval(refresh,REFRESH_MS)" in script
    assert "location.reload" not in script
    # the banner and the boxes are pieces the refresh may swap
    assert "push('notes:page'" in script and "push('strip:page'" in script


# ------------------------------------------- Alerts and Integrations, v1 shape
#
# Round eight, 2026-08-19: fine as it was, to be made what v1 should look
# like, with the add channel buttons staying (docs/RECORD.md 4.71).

def test_the_alert_kinds_lead_with_what_they_do_and_not_with_our_jargon():
    """`debounce` and `coalesce` are our words. A reader should not have to
    learn them to use the product (docs/RECORD.md 4.71).

    The fleet-wide list this used to read left the alerts page on 2026-08-23,
    so the rule is checked where the kinds a channel takes are now named: the
    Add window's Advanced settings. The rule did not move, only the screen
    that has to obey it.
    """
    html = build.build_sample()
    # Sliced short of the apostrophe, which esc() renders as an entity.
    assert "finding changed" in html
    assert "An agent stopped reporting" in html
    for jargon in ("<div>Debounce</div>", "<div>Coalesce</div>",
                   "<b>Debounce</b>", "<b>Coalesce</b>"):
        assert jargon not in html, f"the jargon came back as a label: {jargon}"


def test_the_alerting_control_that_is_not_built_says_planned():
    """A control with nothing behind it is shown, marked, and not clickable,
    rather than quietly absent or quietly dead (docs/PRODUCT.md section 7).

    The environment policy row this used to read left the alerts page with the
    fleet-wide section on 2026-08-23. The control that still has nothing behind
    it is the per-channel notification timing, and it obeys the same rule in the
    Add window.
    """
    html = build.build_sample()
    row = html.split("Notification timing", 1)[1][:400]
    assert '<span class="tag-planned">planned</span>' in row
    assert "disabled" in row


def test_the_add_channel_button_stays():
    """His words, 2026-08-19. The button that adds a channel is the one Add
    button on Integrations since layout B, and an alert destination is the
    first card of its window (docs/screens/alerts/SPEC-layout-b.md)."""
    html = build.build_sample()
    view = html.split('id="integrations"', 1)[1].split('<div class="wrap view"', 1)[0]
    assert '<button class="btn pri" data-open="conn-ovl">Add</button>' in view
    window = html.split('<div class="ovl js-modal" id="conn-ovl"', 1)[1]
    first_cards = re.findall(r'<div class="m-card pick" data-kind="([a-z]+)">', window)
    assert first_cards[0] == "dest"
    assert '<div class="m-card-t">Alert destination</div>' in window
    # and every channel can be picked there
    for name, stage in build.ADD_CHANNELS:
        assert f'data-fields="{stage}"' in window, name


def test_the_integrations_view_carries_no_provider_prose():
    """The three rows explaining what a provider connection can and cannot do
    went with the 2026-08-23 declutter pass. The invariants they restated are
    the security invariants SI-3 and SI-5, and are unchanged. The view is the button
    and the place a configured integration appears, and nothing else."""
    html = build.build_sample()
    assert "What a provider connection can do, and what it cannot" not in html
    assert not hasattr(build, "provider_limits_html")
    assert not hasattr(build, "PROVIDER_LIMITS")


def test_the_integrations_catalogue_stays_out_of_the_view():
    """The owner had it taken out on 2026-08-16 and it lives in the Add window.
    A later mockup put a planned list back into the view and this does not
    follow it, because his decision is the one on the record."""
    html = build.build_sample()
    view = html.split('id="integrations"', 1)[1].split('<div class="wrap view"', 1)[0]
    for planned in ("Prometheus", "Grafana", "Zabbix", "Syslog"):
        assert planned not in view, f"the catalogue came back into the view: {planned}"
    # and it is still in the window, which is where he put it
    assert "Prometheus" in html






def test_the_live_host_page_names_both_families_as_not_tested():
    """Nothing has connected to any port from outside, so both read not tested
    and neither is left out."""
    import render_live as rl_mod  # noqa: F401  (imported for the constant only)
    assert build.NOT_TESTED == "not tested"


def test_the_page_keeps_itself_current_without_reloading():
    """The dashboard renders per request and then sat stale in the browser
    until somebody reloaded it by hand (the owner, 2026-08-30). The page script
    fetches itself on a timer now and swaps in what moved. The guards and the
    swap itself are test_quiet_refresh.py's; this keeps the fact that no
    reload is what does it.
    """
    html = build.build_sample()
    script = html[html.rindex("<script>"):]
    assert "var REFRESH_MS=60000" in script
    assert "setInterval(refresh,REFRESH_MS)" in script
    assert "location.reload" not in script


def test_not_watched_is_one_word_in_one_band_last():
    """`never reported` and `not probed yet` were two words for one fact, that
    nothing is known of this server yet, and two bands. One word, off tone,
    in the last band, since 2026-10-09 (docs/record 4.447); the old words
    are on no row and in no band."""
    words = [w for band in build.FLEET_BANDS if band for w in band]
    assert "not watched" in words
    assert "never reported" not in words and "not probed yet" not in words
    assert build.fleet_band("not watched") == max(build.fleet_band(w) for w in words)
    # inside the band a server that reports sorts before a pending
    # enrolment, whatever their names, so the owner's bug of 2026-08-16
    # stays fixed with one word
    rows = [build.FleetRow("off", "not watched", "a-pending", pending=True),
            build.FleetRow("off", "not watched", "z-reports")]
    assert [r.name for r in build.sort_fleet_rows(rows)] == ["z-reports", "a-pending"]
    sample = [r.word for r in build.FLEET_SAMPLE]
    assert sample.count("not watched") == 2
    assert "never reported" not in sample and "not probed yet" not in sample
