"""The sample shell, the other feed of the same template.

    Run from site/app: python3 -m pytest test_build_sample.py

build.py is both the demo page and the template render_live.py fills from real
documents. It had no test of its own, which meant a change to the shared frame
could only be caught on the live side. The host detail is subcategorised in
both feeds, so both feeds are checked.
"""
import pathlib
import re

import pytest

import build
import sample_story
import theme


# Overview, Services, Evidence, Changes, Settings, then Rules and the Packet
# path, both of which came back on 2026-09-10 (docs/screens/host-overview/SPEC.md
# section 3, and the two specs of their own).
HOST_TABS = [("overview", "Overview"), ("services", "Services"), ("rules", "Rules"),
             ("evidence", "Evidence"), ("path", "Packet path"), ("changes", "Changes"),
             ("settings", "Settings")]

# What is built. All seven since 2026-09-10, when Rules and the Packet path
# came back, each drawn and approved.
HOST_TABS_BUILT = [(key, label) for key, label in HOST_TABS
                   if key not in build.HOST_TABS_PLANNED]

# The fixture below empties `build.HOST_TABS_PLANNED`, which is the one switch
# a tab would leave by. It is kept, and every test that reads a tab still asks
# for it, so the day a tab is planned again these keep proving the tab itself
# rather than skipping for a whole release. The gate allows no skips.


@pytest.fixture()
def v2_tabs(monkeypatch):
    """The sample with no tab planned, which is how it builds today."""
    monkeypatch.setattr(build, "HOST_TABS_PLANNED", ())


def page():
    return build.build_sample()


def host_view():
    """The sample host's slice of the page."""
    html = page()
    start = html.index('id="host"')
    rest = html[start:]
    end = rest.find('class="wrap view"')
    return rest[:end] if end > 0 else rest


def tab_body(section, key):
    """One tab panel of the sample host. The panel ends at the next panel or
    at the first-look window, which sits after the last panel on the page."""
    rest = section.split(f'id="t-host-{key}"')[1]
    return re.split(r'<div class="tab|<div class="ovl', rest)[0]


@pytest.mark.usefixtures("v2_tabs")
def test_the_sample_host_has_one_tab_per_subject_and_each_carries_content():
    section = host_view()
    for key, label in HOST_TABS:
        assert f'for="tb-host-{key}">{label}</label>' in section, f"no {label} tab"
        assert f'id="t-host-{key}"' in section, f"no {label} panel"
    # The panel headings that used to be these markers left on 2026-08-24,
    # the owner's second declutter round: each one restated the label of the tab
    # it sat under. So the markers are the tabs' own content now, which is the
    # stronger check anyway: a heading over an empty panel would have passed
    # the old one.
    for key, marker in (("overview", 'class="hstrip"'),
                        ("services", 'class="srow"'),
                        # one box per tool since 2026-09-10, one flow per
                        # port and family (docs/screens/host-packet-path)
                        ("path", 'class="pt-flow'),
                        ("evidence", 'class="mr"'),
                        # the day band, which is the changes list's own shape.
                        # Its rows are `.lst`, the shared list row.
                        ("changes", 'class="cr"'),
                        # one bordered list per firewall, the tab's own shape
                        # since 2026-09-10 (docs/screens/host-rules)
                        ("rules", 'class="fw"'),
                        ("settings", 'class="hset"')):
        assert marker in tab_body(section, key), f"the {key} tab does not carry {marker!r}"


def test_the_round_two_copy_stays_gone():
    """The owner, 2026-08-24, the second declutter round: the screens say less.
    Every string here left this feed in that round and must not come back.
    The live feed's half of this guard is in test_render_live.py."""
    html = page()
    for gone in ("Ports, and what answered from outside",
                 "12 ports answer from outside",
                 "Ports bound to a network address",
                 "What is running",
                 "Every port, and what each view says",
                 "What has changed on this server",
                 "None of these is built yet"):
        assert gone not in html, f"removed copy came back: {gone}"
    # an empty subtitle renders no div at all, not a blank strip
    assert '<div class="psub"></div>' not in html
    # the Add window carries no footer note: the planned tag on each card is
    # the whole of what may be said
    assert "m-note" not in build.add_modal()


@pytest.mark.usefixtures("v2_tabs")
def test_the_tabs_are_in_the_order_the_questions_are_asked():
    section = host_view()
    positions = [section.index(f'for="tb-host-{key}"') for key, _ in HOST_TABS]
    assert positions == sorted(positions)
    # The order is the builder's one list, and it is the order written out at
    # the top of this file (SPEC.md section 3, docs/RECORD.md 4.325).
    assert build.HOST_TAB_KEYS == [key for key, _ in HOST_TABS]


def test_every_tab_label_points_at_a_radio_that_exists():
    """A typo in one key would leave a label that switches nothing, which no
    Python error and no eye on a screenshot would necessarily catch."""
    html = page()
    for target in set(re.findall(r'<label class="k-[a-z]+" for="([^"]+)"', html)):
        assert f'id="{target}"' in html, f"label points at a missing radio: {target}"
    for target in set(re.findall(r'<label class="mini" for="([^"]+)"', html)):
        assert f'id="{target}"' in html, f"jump points at a missing radio: {target}"


@pytest.mark.usefixtures("v2_tabs")
def test_the_tabs_need_no_javascript():
    html = page()
    section = host_view()
    assert section.count('name="tabs-host"') == len(HOST_TABS)
    # one tab open, the first. Counted on the tab radios rather than on every
    # " checked>" in the slice, because the Settings tab is a rail of radios of
    # its own now and one of those is checked too.
    assert len(re.findall(r'class="tabsel k-\w+" name="tabs-host" id="[^"]+" checked>',
                          section)) == 1
    assert 'type="radio" class="tabsel k-overview"' in section
    for key, _label in HOST_TABS:
        assert f".tabsel.k-{key}:checked~.tab.k-{key}{{display:block}}" in html
    assert "function setT(" not in html
    assert "data-t=" not in html


def test_the_top_nav_is_the_four_built_views_plus_authorisation_planned():
    html = page()
    nav = html.split('<nav class="nav">')[1].split("</nav>")[0]
    # the count beside Alerts is its own element, covered in test_alerts_screen
    nav = __import__("re").sub(r'<span class="nb">\d+</span>', "", nav)
    for label in ("Fleet", "Alerts", "Integrations", "Settings"):
        assert f">{label}</a>" in nav
    # Changes folded into the host that changed, so it is neither a nav item
    # nor a view of its own any more
    assert "Changes" not in nav
    assert 'data-v="changes"' not in html
    assert 'id="changes"' not in html
    # Authorisation is shown, marked, and carries no data-v, which is what
    # makes it unclickable: the page script only binds elements that have one
    assert 'class="planned">Authorisation<span class="tag-planned">planned</span>' in nav
    assert 'data-v="auth"' not in html
    assert 'id="auth"' not in html


def test_the_avatar_chip_carries_no_letters_until_whoami_answers():
    """The chip read jb and turned into je when clicked (the owner, 2026-08-24):
    JB was hardcoded from the sample account and the menu's first open rewrote
    it with the first two letters of the signed-in email. The shell now starts
    the chip as a neutral glyph, fills it from whoami on load, and derives the
    letters, so no sample initials and no address slice can ever show."""
    html = page()
    chip = re.search(r'id="pm-btn"[^>]*>(.*?)</button>', html, re.S).group(1)
    assert "<svg" in chip
    assert "JB" not in chip
    assert "chipInitials" in html
    assert "u.slice(0,2)" not in html
    # filled when the page loads, once, not on the menu's first open
    assert "fillWho();" in html
    assert html.count("fetch('/api/admin/whoami'") == 1


def test_the_sample_services_tab_is_the_things_behind_the_sample_ports():
    """One row per thing that runs, its ports as chips that open the
    Overview's rows. Every chip names a row the sample Overview has.

    Two groups since 2026-10-11, where the hand-written tab drew four: the
    sample's server is one description now (docs/RECORD.md 4.443), and it
    runs no container and no socket unit. The old tab's container was a
    postgres that did not answer, which a port a container publishes would."""
    section = host_view()
    services = tab_body(section, "services")
    overview = tab_body(section, "overview")
    for title in ("Processes", "Loopback only"):
        assert f"<b>{title}</b>" in services, title
    for title in ("Containers", "Socket units"):
        assert f"<b>{title}</b>" not in services, title
    for row in re.findall(r'data-row="([^"]+)"', services):
        assert f'id="{row}"' in overview, row
    # five since 2026-09-10, when the Overlays group left the tab (wg0 was the
    # sixth row)
    assert services.count('class="srow"') == 5
    # The Overlays group was the one heading under a marker, and it left the
    # tab on 2026-09-10, on the owner's word.
    assert 'class="sgh unsure"' not in services
    # the stale rule's port has nothing behind it, so it is on no row here
    assert "8096" not in services


def test_the_sample_changes_tab_is_the_sketchs_log():
    """Eleven lines, newest first, every kind the spec lists, and the range
    control over them. The header names the zone, because the clocks are
    UTC and a bare clock was read as local time (the owner, 2026-08-24)."""
    changes = tab_body(host_view(), "changes")
    assert changes.count('class="cr"') == 11
    kinds = re.findall(r'<span class="st nt">([^<]+)</span>', changes)
    assert set(kinds) <= set(build.CHANGE_KINDS) and len(set(kinds)) >= 7
    assert "<span>When · UTC</span>" in changes
    assert "<b>11</b> changes in the last 7 days" in changes
    assert 'id="rg-host-7d" checked>' in changes


def test_per_server_settings_are_in_the_host_and_the_account_is_not():
    html = page()
    section = host_view()
    settings = tab_body(section, "settings")
    # The sample server has an agent, so its answers are headed as answers
    # (build.PROBING_LIST_AGENT, docs/RECORD.md 4.460).
    for wanted in ("Paused", "Timezone", "Remove this server", build.PROBING_LIST_AGENT,
                   "Add address", "Silenced ports"):
        assert wanted in settings, f"per server setting missing: {wanted}"
    # The ID is shown and not edited (docs/screens/host-settings/SPEC.md).
    # The Save that is there, hidden, is the display name's.
    assert '<span class="idv" id="id-host">app-01</span>' in settings
    assert 'aria-label="Server ID"' not in settings
    assert settings.count("hidden>Save</button>") == 1
    assert ">Rename</button>" not in settings
    # The pencil that renamed from the header is gone from the whole page,
    # not merely unhooked.
    for gone in ("pencil", "rnsel", "rnbox"):
        assert gone not in html, f"the header rename is still on the page: {gone}"
    # The mute row left on 2026-08-16: it repeated the button the header has.
    assert "Mute for 2 hours" not in settings
    # Account level settings stay on the top level Settings view.
    for account in ("Appearance", "Authenticator app", "Members", "Billing"):
        assert account not in section, f"account setting leaked into the host: {account}"
        assert account in html, f"account setting missing from the page: {account}"
    assert "Not in v1" not in html, "removed from settings but still on the page"
    # The provider connects on the Integrations screen since 2026-09-06
    # (docs/screens/integrations/SPEC.md), never on a server's settings.
    assert ">Connect</button>" not in section


def test_tags_are_bubbles_and_environment_is_shown_planned():
    """The owner asked for labels on 2026-08-24 (RECORD 4.102) and they are the
    Tags row since 2026-10-02. Environment is still not built: its row is
    shown with a disabled field and the planned tag, and the tag is the whole
    of what is said, so no sentence rides beside it."""
    settings = tab_body(host_view(), "settings")
    assert "<h3>Labels" not in settings
    assert '<span>production</span>' in settings
    assert 'data-msg="The tag would be removed here"' in settings
    assert "js-tag-del" not in settings and "js-tag-add" not in settings
    env = settings.split("<b>Environment</b>")[1].split('<div class="li"')[0]
    assert ('<input class="in" value="" placeholder="" disabled>'
            + build.PLANNED_TAG) in env
    assert 'class="dim"' not in env, "a sentence rides beside the planned tag"


def test_the_sample_pause_switch_stays_inert():
    """The sample host has no backend, so its pause switch must not carry the
    class the live handler binds to, and the handler in the shared script must
    ignore any switch that names no host rather than posting to nowhere."""
    settings = tab_body(host_view(), "settings")
    assert "Paused" in settings
    assert "js-pause" not in settings
    assert "data-host" not in settings
    html = page()
    assert "querySelectorAll('.js-pause')" in html   # the shared script rides along
    assert "if(!b.dataset.host)return" in html


def test_the_overview_is_the_three_boxes_then_the_port_table():
    """docs/screens/host-overview/SPEC.md: the fleet's numbers scoped to this
    server, Answer reachable ports, then one row per port with the three
    answers. No sentence above the table and nothing that points at a planned
    tab."""
    overview = tab_body(host_view(), "overview")
    assert overview.index('class="hstrip"') < overview.index("js-review-all") \
        < overview.index('class="panel ptbl"')
    assert ">Answer reachable ports</button>" in overview
    # the sample's server has answers on it, so its window is a later look
    html = build.build_sample()
    assert "<h2>Your answers for app-01</h2>" in html and "First look at" not in html
    assert "answers from the internet" not in overview
    for row in sample_story.parts().rows:
        assert f'data-port="{row.label}"' in overview, f"the table does not list {row.label}"
    assert 'for="tb-host-path"' not in overview


def test_every_overview_row_names_both_families_and_the_state_wears_its_word():
    """docs/PRODUCT.md 4b as a column, and docs/DESIGN.md section 3 on the
    tag: the word carries the state, the tone follows the word."""
    overview = tab_body(host_view(), "overview")
    rows = sample_story.parts().rows
    n = len(rows)
    assert overview.count('<span class="prf"><i class="') >= n
    for row in rows:
        if row.word:
            assert theme.status(row.tone, row.word) in overview, row.word
    # the two families are boxed on every row, in the answer's colour
    assert '<i class="fail">v4</i><i class="fail">v6</i>' in overview
    assert '<i class="">v4</i><i class="">v6</i>' in overview


def test_the_sample_fleet_is_the_approved_sketch_and_says_which_rows_are_real():
    """The sample fleet is the twelve rows of the sketch the owner approved on
    2026-09-03 (docs/screens/fleet), one row per state the fleet can show.
    Four are real servers and the builder says so beside the data; the rest
    are invented so that each state has a row."""
    names = [row.name for row in build.FLEET_SAMPLE]
    assert len(names) == 12 and len(set(names)) == 12
    assert {"app-01", "web-02", "media-01", "mail-relay"} <= set(names)
    words = [row.word for row in build.FLEET_SAMPLE]
    for word in ("conflict", "not readable", "unreviewed", "unexplained", "no proof",
                 "paused", "not watched", "watched"):
        assert word in words, f"no sample row for {word}"
    assert any(word.startswith("silent") for word in words)


def test_the_sample_says_not_seen_inside_where_it_said_no_view_from_inside():
    """app-01's tcp/22 answers on v6 with nothing bound there: its Decided by
    cell and its row in the first-look window carry the one constant
    (docs/record 4.451)."""
    html = build.build_sample()
    assert html.count(">not seen inside<") == 2
    assert "no view from inside" not in html


# ---------------------------------------------------- the path, as gates
#
# The sample is the one feed allowed to show a finding line over a walk,
# because its data is invented and it is the demo of the finished product. The
# live feed states no outcome at all, and test_render_live.py pins that. What
# these check is that the rail is the walk the data describes.

def sample_walks():
    """The Packet path tab, cut into one slice per port, in SAMPLE_WALKS
    order. Slice 0 is the picker chrome before the first walk."""
    return tab_body(host_view(), "path").split('<div class="walk">')


def test_no_tick_glyph_anywhere_on_the_sample_page():
    """docs/DESIGN.md section 3. healthchecks.io's diagram, which this borrows
    its shape from, is built out of checkmark circles."""
    html = page()
    for glyph in "✓✔✅☑☒✘✗❌✖":
        assert glyph not in html, f"a verdict glyph reached the page: {glyph!r}"


@pytest.mark.usefixtures("v2_tabs")
def test_the_diagram_carries_no_colour_of_its_own():
    """Every colour is a token in the stylesheet, so one diagram reads in both
    modes. A hex literal in the markup would read in one.

    `currentColor` is allowed and is the point: a glyph on the flow takes the
    colour the stylesheet gave the box around it. What is forbidden is an
    element choosing a colour for itself.
    """
    path = tab_body(host_view(), "path")
    allowed = ("currentColor", "none", "transparent")
    for svg in re.findall(r"<svg.*?</svg>", path, re.S):
        assert not re.search(r"#[0-9A-Fa-f]{3,8}\b", svg), "a hex colour in a diagram"
        for value in re.findall(r'\s(?:fill|stroke)="([^"]*)"', svg):
            assert value in allowed or value.startswith("var(--"), value


def test_a_port_no_rule_names_still_draws_its_whole_path():
    """The first Gates build drew nothing for a port no rule names, which took
    the walk off exactly the host it matters most for. Every tool is still a
    box and each says it has no rule, which is the honest answer."""
    path = tab_body(host_view(), "path")
    # the sample's 8410, reachable with no rule permitting it anywhere, found
    # by its chip: the flows are in the order the live page draws them
    chips = re.findall(r'<label for="pp-host-c-\d+">([^<]+)</label>', path)
    flows = path.split('data-flow="')[1:]
    assert len(flows) == len(chips)
    flow = flows[chips.index("8410/tcp v4")].split("</div></div>")[0]
    assert "no rule for 8410" in flow
    assert 'class="pt-nd' in flow


def test_the_page_says_nothing_we_are_not_allowed_to_say():
    """The writing rules, on the copy this file owns."""
    html = page()
    body = re.sub(r"<style>.*?</style>", "", html, flags=re.S)
    for word in ("secure", "protected", "compliant", "guaranteed", "certified"):
        assert word not in body.lower(), f"forbidden claim on the page: {word}"
    for dash in ("—", "–"):
        assert dash not in body, "em or en dash in the copy"


# ---------------------------------------------------------------- the type scale
# The owner, looking at the live dashboard on 2026-08-16: everything was too
# small and alike, so a reader could not tell what mattered. The cause was
# measurable. Sizes had accumulated one screen at a time until a port number, the
# sentence explaining it and a micro label all sat within two pixels of each
# other, so nothing told the eye where to land.
#
# The fix is the small named scale in theme.TYPE_SCALE, and this is the guard that
# stops a future screen inventing a sixth size: every font-size in the whole app
# stylesheet has to be one of those tokens.

# The two exceptions, and both are geometry rather than type.
#
#   .pg-name, .pg-did  SVG labels inside the packet path diagram. Their size is
#                      tied to LINE_H, NAME_WRAP and DID_WRAP in pathgraph.py,
#                      which lays the diagram out in pixels, so the number
#                      belongs beside that geometry rather than in a type scale.
#   .logo.lg .wm       the large lockup's wordmark, sized to the mark's own cells
#                      (docs/DESIGN.md section 1). The mark's proportions are a
#                      decided thing and not ours to restep.
GEOMETRY_NOT_TYPE = (".pg-name", ".pg-did", ".logo.lg .wm")


def stylesheet():
    """Every rule the app ships, in the order the page carries them."""
    return theme.TOKENS + theme.BASE + build.CSS


def css_rules(css):
    """(selector, declarations) for every rule, at-rule wrappers stripped.

    A nested @media leaves its prelude on the front of the first rule inside it,
    so the selector is taken as whatever follows the last brace. Boring, and it
    keeps this test out of the business of parsing CSS properly.
    """
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    for match in re.finditer(r"([^{}]+)\{([^{}]*)\}", css):
        yield match.group(1).split("{")[-1].strip(), match.group(2)


def test_every_font_size_in_the_app_is_one_step_of_the_scale():
    allowed = {f"var(--fs-{name})" for name in theme.TYPE_SCALE}
    stray = []
    for selector, body in css_rules(stylesheet()):
        for value in re.findall(r"font-size:\s*([^;}]+)", body):
            value = value.strip()
            if value in allowed or selector in GEOMETRY_NOT_TYPE:
                continue
            stray.append(f"{selector} -> {value}")
    distinct = sorted({s.split(" -> ")[1] for s in stray})
    assert not stray, (f"{len(stray)} font sizes outside the scale, "
                       f"{len(distinct)} distinct: {', '.join(distinct)}\n  "
                       + "\n  ".join(stray))


# ------------------------------------------- the tables share one geometry
#
# The owner, 2026-08-29, asked for one measured grid across the whole product.
# Before that round the
# product had three horizontal insets, six row heights and five header heights
# across tables that look like each other, so no two panels started their
# content at the same x and no two rows were the same height.
#
# These read the shipped stylesheet rather than a list written down twice, so
# a selector added tomorrow is covered the day it appears.

# Every table row in the app, by the class its rows carry.
# `.arow`, the old admin table, left on 2026-10-06: the admin console's rows
# are `.row` since B's shape (docs/screens/admin/SPEC.md).
TABLE_ROWS = (".row", ".mr", ".srow", ".pl", ".crow",
              ".ch2", ".lst", ".as-row", ".pr")

# Every band that heads one of those tables or a group inside it.
TABLE_HEADS = (".thead", ".mxh", ".sh", ".sgh", ".rgrp-h", ".prh")


def padding_of(selector, css=None):
    """The `padding` shorthand one selector sets, or None.

    Matches the selector as one of a comma separated list, so `.svc-h,.svc`
    answers for both of the names in it.
    """
    for sel, body in css_rules(css if css is not None else stylesheet()):
        if selector not in [part.strip() for part in sel.split(",")]:
            continue
        found = re.findall(r"(?:^|;)\s*padding:\s*([^;}]+)", body)
        if found:
            return found[-1].strip()
    return None


def test_every_table_starts_its_content_at_one_x():
    """One horizontal inset for every table in the product. The fleet was the
    only one at 22px and the account settings block the only one at 19px, so a
    reader scrolling from one screen to the next met three left edges."""
    insets = {}
    for selector in TABLE_ROWS + TABLE_HEADS:
        value = padding_of(selector)
        assert value, f"{selector} sets no padding"
        insets.setdefault(value.split()[1], []).append(selector)
    assert list(insets) == ["20px"], (
        "more than one horizontal inset: "
        + "; ".join(f"{k} -> {', '.join(v)}" for k, v in sorted(insets.items())))


def test_every_table_row_is_one_height_and_every_head_another():
    """A row is a row whatever table it is in. There were six row heights and
    five header heights, which is what made the screens feel unrelated."""
    rows = {}
    for selector in TABLE_ROWS:
        rows.setdefault(padding_of(selector).split()[0], []).append(selector)
    assert list(rows) == ["14px"], (
        "more than one row height: "
        + "; ".join(f"{k} -> {', '.join(v)}" for k, v in sorted(rows.items())))

    heads = {}
    for selector in TABLE_HEADS:
        heads.setdefault(padding_of(selector).split()[0], []).append(selector)
    assert list(heads) == ["9px"], (
        "more than one header height: "
        + "; ".join(f"{k} -> {', '.join(v)}" for k, v in sorted(heads.items())))


def test_no_table_header_shouts():
    """Sentence case everywhere. The Alerts channel table and the Admin tables
    were the only uppercase headers in the product, so the same kind of thing
    read two ways on two screens."""
    for selector, body in css_rules(stylesheet()):
        if selector in (".crow-h", ".arow-h"):
            assert "text-transform" not in body, selector


def test_the_fold_summary_reads_as_a_control():
    """The owner, 2026-08-25: the fold did not read as something you can open.

    So its summary carries the three affordances a row control gets here: a
    pointer cursor, a hover surface, and a chevron that turns when the fold is
    open. The chevron is a bordered box, never a glyph in a content property,
    which test_css_content_is_a_word_or_nothing rules out.
    """
    rules = dict(css_rules(stylesheet()))
    assert "cursor:pointer" in rules[".fs summary"]
    assert "background:var(--hover)" in rules[".fs summary:hover"]
    chevron = rules[".fs summary::after"]
    assert 'content:""' in chevron
    assert "border-right" in chevron and "border-bottom" in chevron
    assert "rotate(-45deg)" in chevron  # closed points right
    assert "transition:transform" in chevron  # the turn is animated
    assert "rotate(45deg)" in rules[".fs[open] summary::after"]  # open points down


# ---------------------------------- how the sample says each server is watched

def test_no_sample_row_carries_an_agent_cell():
    """The Agent column left the Fleet on 2026-10-02, on the owner's word, on
    both feeds. The sample shell is where the owner reads the
    shape of a screen, so a row still carrying the cell here is a shape the
    live page no longer has."""
    html = build.build_sample()
    rows = re.findall(r'<a class="row" [^>]*>.*?</a>', html, re.S)
    assert len(rows) == len(build.FLEET_SAMPLE)
    for row in rows:
        assert 'class="fag"' not in row, row


def test_the_agent_fact_uses_the_live_renderers_own_words():
    """Two feeds of one template, and a word invented here that the live page
    never produces would be a shape nobody can get to."""
    import render_live as rl
    # every word the live page measures maps to an agent word
    measured = {rl.MODE_NO_AGENT, rl.MODE_AGENT, rl.MODE_FULL_READ, rl.MODE_PARTIAL_READ}
    assert set(build.AGENT_WORD) == measured


# ------------------------------------------------- one button, one builder

def test_every_button_goes_through_the_helper():
    """Since 2026-09-03 no `<button class="btn` is written by hand in either
    renderer: `button()` is the one place. A literal anywhere else is a second
    definition of what a button is, which is what this refactor removed. The
    two admin links styled as buttons are `<a>` elements and stay as they are."""
    import pathlib
    import render_live
    for module in (build, render_live):
        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        assert not re.search(r'<button\b[^>]*class="btn', source), module.__name__


def test_the_helper_writes_a_button_the_way_they_were_written():
    assert build.button("Save") == '<button class="btn">Save</button>'
    assert build.button("Add", "pri", id="go", hidden=True) == \
        '<button class="btn pri" id="go" hidden>Add</button>'
    assert build.button("Rename", "js-rename", data_host="a&amp;b") == \
        '<button class="btn js-rename" data-host="a&amp;b">Rename</button>'
    # type goes before the class, the one order the page used with it
    assert build.button("Sign out", "js-signout", type="button") == \
        '<button type="button" class="btn js-signout">Sign out</button>'
    # False and None leave an attribute out, True writes it bare
    assert build.button("Add", disabled=False) == '<button class="btn">Add</button>'


# ------------------------------------------------- the Packet path, as drawn
#
# docs/screens/host-packet-path/SPEC.md. The parts that carry judgement are in
# site/app/test_host_path.py; these two are about the demo host's own tab.

def test_the_path_tab_is_a_picker_with_one_flow_per_port_and_family():
    """One chip per port and family, and one flow visible at a time."""
    path = tab_body(host_view(), "path")
    chips = re.findall(r'<label for="pp-host-c-\d+">([^<]+)</label>', path)
    # One for every port and family that has a listener and was measured, as
    # the live page draws them from the sample's one description.
    assert chips == ["22/tcp v4", "80/tcp v4", "80/tcp v6", "443/tcp v4", "443/tcp v6",
                     "5432/tcp v4", "5432/tcp v6", "8410/tcp v4"]
    assert path.count("data-fate=") == len(chips)
    # Two of the fates: six flows reach their program, and 5432's two stop at
    # the rule that denies them.
    assert set(re.findall(r'data-fate="(\w+)"', path)) == {"reach", "stop"}


def test_a_flow_leads_with_the_measurement_then_the_drawing():
    """The measurement is the one thing the tab states outright, because the
    prober measured it. Then the flow, then the panel for the selected box."""
    path = tab_body(host_view(), "path")
    assert path.index('class="pt-meas"') < path.index('class="pt-flow')
    assert path.index('class="pt-flow') < path.index('class="pt-under')
