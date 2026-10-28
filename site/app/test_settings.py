"""Account settings, and the selected-state rule the whole app has to keep.

    Run from site/app: python3 -m pytest test_settings.py

Two concerns live here. The first is the rule, because it is the one that keeps
coming back: `docs/DESIGN.md` section 3 says a selected state is a word plus
weight and colour, and that nothing is drawn beside the chosen item. The owner said
the same thing in plainer words about a left bar on a sub navigation rail. So
the first tests read the generated stylesheet and the generated markup and fail
if any chosen item has a bar, a bracket, a chevron or a tick drawn beside it.
Settings is now that rail, so the rule is tested twice over: once across the
whole sheet, and once again with only the rail's own rules in view, where the
bar is likeliest to come back.

The second is the Settings page itself: the account's, built from
docs/screens/account-settings/SPEC.md on 2026-09-07 in the server tab's
shape, with provider, install and the not-in-v1 list gone.
"""
import re

import pytest

import build
import theme

# What marks a rule as styling a chosen thing.
SELECTED_HINTS = (".on", ".sel", ".active", ":checked", "aria-selected")

# Declarations that draw something beside an element rather than changing the
# element itself. A pale surface, an ink colour and a weight are the vocabulary
# we are allowed; a bar down one edge or a pseudo element is not.
MARKER_DECLS = ("border-left", "border-right", "border-inline", "content:")

# Glyphs that read as a marker beside a label, in the markup or in a CSS
# content value. Ticks are in here too, because DESIGN.md section 3 bans them
# outright: a tick implies a verdict.
MARKER_GLYPHS = ("›", "‹", "»", "«", "▸", "▾",
                 "▶", "❯", "✓", "✔", "✗", "⟩",
                 "⟨", "•", "➜", "➤",
                 "&rsaquo;", "&lsaquo;", "&raquo;", "&laquo;", "&check;")


def css_rules(html):
    """(selector, body) for every rule in the page's stylesheet.

    Comments are stripped first, so a comment explaining why a marker is gone
    is never read as a marker coming back.
    """
    style = re.search(r"<style>(.*?)</style>", html, re.S).group(1)
    style = re.sub(r"/\*.*?\*/", "", style, flags=re.S)
    rules = []
    for chunk in style.split("}"):
        if "{" not in chunk:
            continue
        selector, body = chunk.rsplit("{", 1)
        rules.append((selector.strip(), body.strip()))
    return rules


def marker_offenders(rules):
    """Every rule that draws something beside a chosen item."""
    out = []
    for selector, body in rules:
        if not any(hint in selector for hint in SELECTED_HINTS):
            continue
        # The server settings rail is the one exception, on the owner's word:
        # the sketch he approved on 2026-09-05 after nine rounds has an
        # accent bar at the left of the open entry, GitHub's settings pages
        # being the reference (docs/screens/host-settings/SPEC.md).
        if ".hitem" in selector:
            continue
        if ":before" in selector or ":after" in selector:
            out.append(f"{selector} {{{body}}}")
            continue
        for decl in MARKER_DECLS:
            if decl in body:
                out.append(f"{selector} {{{body}}}")
                break
    return out


def test_nothing_is_drawn_beside_a_chosen_item():
    """The rule the owner asked for, as a test. A selected item is ink, weight and
    a surface. No left bar, no bracket, no chevron, no pseudo element."""
    offenders = marker_offenders(css_rules(build.build_sample()))
    assert not offenders, "a selected state draws a marker:\n" + "\n".join(offenders)


def test_css_content_is_a_word_or_nothing():
    """Pseudo element content in this app is either empty, where it draws a
    plain box, or a word. A glyph or a CSS escape means a marker."""
    for selector, body in css_rules(build.build_sample()):
        for value in re.findall(r'content:\s*"([^"]*)"', body):
            assert re.fullmatch(r"[A-Za-z ]*", value), (
                f'{selector} draws content:"{value}"')


def test_the_markup_carries_no_marker_glyph():
    html = build.build_sample()
    for glyph in MARKER_GLYPHS:
        assert glyph not in html, f"a marker glyph reached the markup: {glyph}"


def test_the_host_subnav_says_which_tab_is_open_with_weight_and_colour():
    """The one that regressed: the open tab used to carry an accent bar under
    it. It carries ink and 600 instead, and nothing is drawn."""
    css = "".join(f"{s}{{{b}}}" for s, b in css_rules(build.build_sample()))
    # The host sub-nav is CSS radios rather than buttons, because tabs that need
    # no JavaScript cannot be left all-hidden by a blocked script. So the open
    # tab is a checked input reaching its own label. What matters is unchanged
    # and is asserted below: weight, and nothing drawn.
    assert ".tabsel.k-overview:checked~.subnav label.k-overview{font-weight:600}" in css
    assert ".subnav button.on:after" not in css


def test_the_open_rail_item_is_a_surface_and_weight():
    """The account rail is the server tab's rail (docs/screens/account-settings
    takes its shape from docs/screens/host-settings): the open entry takes the
    raised surface and 600 weight, and the accent bar the owner approved for
    that rail on 2026-09-05 sits at its left."""
    css = "".join(f"{s}{{{b}}}" for s, b in css_rules(build.build_sample()))
    assert ".hsel.h-profile:checked~.hrail .hitem.h-profile{background:var(--panel2);font-weight:600}" in css
    assert ".hsel.h-profile:checked~.hrail .hitem.h-profile::before{" in css


def rail_rules(rules):
    """Every rule that styles the rail or an item in it."""
    return [(s, b) for s, b in rules if ".as-rail" in s or ".as-item" in s]


def test_the_rail_draws_nothing_beside_the_open_item():
    """The rule again, with only the rail in view.

    A box-shadow is banned here as well as the bars, because an inset shadow
    down one edge is a bar written another way. Elsewhere in the app a shadow
    rings a whole card, which is a border and not a marker, so this is scoped to
    the rail rather than added to MARKER_DECLS.
    """
    banned = MARKER_DECLS + ("box-shadow", "background-image")
    offenders = []
    for selector, body in rail_rules(css_rules(build.build_sample())):
        if not any(hint in selector for hint in SELECTED_HINTS):
            continue
        if ":before" in selector or ":after" in selector:
            offenders.append(f"{selector} {{{body}}}")
            continue
        for decl in banned:
            if decl in body:
                offenders.append(f"{selector} {{{body}}}")
                break
    assert not offenders, "the rail marks the open item:\n" + "\n".join(offenders)


def test_the_rail_is_rules_the_stylesheet_actually_has():
    """The rail would still look right with no rules at all, because an unstyled
    label is a readable label. So check the rules exist rather than trusting the
    markup, one per category."""
    css = "".join(f"{s}{{{b}}}" for s, b in css_rules(build.build_sample()))
    for key in build.ASET_KEYS:
        assert f".hsel.h-{key}:checked~.hbody .hstage.h-{key}{{display:block}}" in css, key
        assert f".hsel.h-{key}:checked~.hrail .hitem.h-{key}{{" in css, key


# ------------------------------------------------------------ what Settings is

def settings_html():
    return build.account_settings_view(live=False, **build.SAMPLE_ACCOUNT)


def rail_markup(html):
    return re.search(r'<nav class="hrail" aria-label="Settings">.*?</nav>', html, re.S).group(0)


def rail_items(html):
    """(key, markup) for each entry on the rail, in reading order."""
    return re.findall(r'<label class="hitem h-([a-z]+)[^"]*" for="hs-settings-[a-z]+">(.*?)</label>',
                      rail_markup(html), re.S)


def stage_bodies(html):
    out = {}
    for chunk in html.split('<div class="hstage h-')[1:]:
        out[chunk.split('"', 1)[0]] = chunk
    return out


def test_the_rail_is_the_six_categories_in_three_groups():
    html = settings_html()
    assert [key for key, _m in rail_items(html)] == list(build.ASET_KEYS)
    assert list(build.ASET_KEYS) == ["profile", "security", "workspace", "members", "billing", "api"]
    rail = rail_markup(html)
    assert rail.count("<hr>") == 2
    assert '<div class="g">Workspace</div>' in rail and '<div class="g">Developer</div>' in rail
    assert rail.index("Security") < rail.index('<div class="g">Workspace</div>') < rail.index('<div class="g">Developer</div>')
    assert sorted(stage_bodies(html)) == sorted(build.ASET_KEYS)


def test_a_planned_category_carries_the_tag_in_the_rail_and_on_every_row():
    html = settings_html()
    for key, markup in rail_items(html):
        planned = next(p for k, _t, _i, p in build.ASET_CATEGORIES if k == key)
        assert (build.PLANNED_TAG in markup) == planned, key
    for key in ("members", "billing", "api"):
        body = stage_bodies(html)[key]
        rows = re.findall(r'<div class="li(?: [^"]*)?">', body)
        assert rows and all("lipl" in r for r in rows), key
        assert body.count(build.PLANNED_TAG) >= len(rows)
        # and its controls are dashed and disabled
        for control in re.findall(r'<(?:button|input)[^>]*class="(?:btn|in)[^"]*"[^>]*>', body):
            assert "disabled" in control, control


def test_every_rail_entry_carries_a_glyph():
    for key, markup in rail_items(settings_html()):
        icon = next(i for k, _t, i, _p in build.ASET_CATEGORIES if k == key)
        assert theme.ICONS[icon] in markup, key


def test_switching_categories_needs_no_javascript():
    html = settings_html()
    radios = re.findall(r'<input type="radio" class="hsel h-(\w+)" name="hs-settings" id="hs-settings-\w+"( checked)?>', html)
    assert [key for key, _c in radios] == list(build.ASET_KEYS)
    assert [key for key, checked in radios if checked] == ["profile"]
    assert "<script" not in html


def test_profile_is_name_email_appearance_and_sign_out():
    body = stage_bodies(settings_html())["profile"]
    assert 'class="in js-who-name"' in body and 'value="Robin Sample"' in body
    assert '<span class="kv js-who-email">sysadmin@example.org</span>' in body
    assert "<input" not in body.split("Email")[1].split("Appearance")[0]
    for k in ("dark", "light", "system"):
        assert f"js-mode-{k}" in body, k
    assert '<span class="seg wide">' in body
    assert ">Sign out</button>" in body


def test_security_is_the_password_the_authenticator_and_two_planned_lists():
    body = stage_bodies(settings_html())["security"]
    assert "changed 13 Aug 2026" in body
    assert 'data-open="pw-ovl">Change</button>' in body
    # the switch shows the state and does not move: Turn on beside it opens
    # the screen that does it (docs/screens/sign-in, built 2026-09-09), and
    # turning it off stays on the box with `users_cli 2fa disable`
    assert 'class="sw js-who-totp" disabled' in body
    assert 'class="btn js-2fa-on"' in body
    assert "Passkeys" in body and "Sessions" in body
    # Passkeys and the three Sessions rows, and the Sessions heading. The
    # authenticator row lost its tag on 2026-09-09: it is real now.
    assert body.count(build.PLANNED_TAG) == 5
    assert build.PLANNED_TAG not in body.split("Authenticator app")[1].split("</div>")[0]


def test_the_authenticator_row_offers_turn_on_only_when_it_is_off():
    on = build.security_panel("changed 13 Aug 2026", True, live=True)
    off = build.security_panel("changed 13 Aug 2026", False, live=True)
    assert 'class="btn js-2fa-on" hidden' in on
    assert 'class="btn js-2fa-on" hidden' not in off
    assert 'class="btn js-2fa-on"' in off


def test_workspace_is_the_name_the_timezone_and_two_planned_lists():
    body = stage_bodies(settings_html())["workspace"]
    assert 'class="in js-wsname"' in body and 'value="whichports"' in body
    assert "Timezone" in body and build.PLANNED_TAG in body.split("Timezone")[1][:400]
    assert "Delete this workspace" in body
    assert '<div class="list danger">' in body


def test_every_field_and_choice_is_the_same_width():
    """docs/screens/account-settings/SPEC.md: 280px, so a field, a choice and
    a segmented control line up."""
    css = build.CSS
    assert ".li .c.fix{width:280px}" in css
    assert "width:280px" in css.split(".choice{")[1].split("}")[0]
    assert ".li .c .seg.wide{width:280px" in css


def test_the_email_is_read_only_and_no_sign_in_method_is_offered():
    """The owner, 2026-09-06: the email is read only, there is no plan to change
    it, and a sign-in method is the login page's business."""
    html = settings_html()
    assert "Sign in with" not in html and "Google" not in html and "Microsoft" not in html
    assert "New address" not in html


def test_the_password_window_takes_the_current_and_the_new():
    live = build.password_modal(live=True)
    assert 'id="pw-current" type="password"' in live and 'id="pw-new" type="password"' in live
    assert 'id="pw-go"' in live and ">Cancel<" in live and 'id="pw-err"' in live
    sample = build.password_modal()
    assert "pw-go" not in sample and "js-act" in sample


def test_settings_has_no_provider_block():
    html = settings_html()
    for gone in ("Provider", "Hetzner", "read only token", "Connect"):
        assert gone not in html, f"the provider block came back: {gone}"


def test_settings_has_no_install_command():
    html = settings_html()
    for gone in ("install.sh", "whichports-agent", "sudo", "Install the agent"):
        assert gone not in html, f"the install snippet came back: {gone}"


def test_settings_has_no_not_in_v1_list():
    html = settings_html()
    for gone in ("Not in v1", "Kubernetes", "NodePort", "Agents on appliances"):
        assert gone not in html, f"the not-in-v1 list came back: {gone}"


def test_the_removed_pieces_are_gone_from_the_template_too():
    for gone in ("PROVIDER_SAMPLE", "INSTALL", "INSTALL_NOTE", "NOT_V1", "SETTINGS_TABS",
                 "settings_view", "settings_sections_sample", "BILLING_TIERS", "TEAM"):
        assert not hasattr(build, gone), f"{gone} is still in the template"


def test_per_server_settings_are_not_in_the_top_level_settings():
    html = settings_html()
    for gone in ("This server", "Pause this server", "top-1000 sweep", "65535",
                 "Environment", "Rename", "Remove this server"):
        assert gone not in html, f"a per-server setting is in the account page: {gone}"


def test_no_figure_and_no_sentence_on_the_planned_categories():
    """A planned row is a name, a tag and a dashed control, never a sentence
    about what it will do or a price nobody decided."""
    html = settings_html()
    for gone in ("a month", "No price", "not built", "placeholder tier", "€"):
        assert gone not in html, gone


def test_settings_keeps_to_the_writing_rules():
    html = settings_html()
    for banned in ("—", "–", "secure", "protected", "compliant", "guaranteed",
                   "certified", "score", "grade"):
        assert banned not in html, f"the settings page says {banned}"


def test_settings_is_wired_into_the_sample_page():
    page = build.build_sample()
    assert '<div class="wrap view" id="settings">' in page
    assert not hasattr(build, "SETTINGS_PSUB")
    assert '<label class="hitem h-billing hpl" for="hs-settings-billing">' in page
    assert '<nav class="hrail" aria-label="Settings">' in page
    assert page.count('id="pw-ovl"') == 1


def test_account_text_in_a_settings_row_renders_as_text():
    """A name, an email and a workspace name are somebody's own text."""
    html = build.account_settings_view(live=False, name="<b>x</b>", email="<i>y</i>",
                                       changed="<u>z</u>", workspace="<s>w</s>")
    for raw in ("<b>x</b>", "<i>y</i>", "<u>z</u>", "<s>w</s>"):
        assert raw not in html
    assert "&lt;b&gt;x&lt;/b&gt;" in html
