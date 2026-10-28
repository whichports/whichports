"""The designed half of a mail.

What is worth testing here is not that a div exists. It is that the mail says
nothing the text half does not, that it loads nothing when opened, that its
colours and its mark are the product's own rather than a second opinion, and
that a host document cannot put markup through it.
"""
import html as html_module
import importlib.util
import pathlib
import re

import pytest

from app import mailhtml, notify, publicurl
from app.notify import Change


def a_change(**kw):
    fields = dict(where="tcp/1883 on v4", was="intended", now="conflict",
                  description="It answers from outside and you marked it closed.",
                  vantage="probe1", measured_at="2026-08-22 21:04 UTC",
                  port=1883, family="v4", answers=True,
                  allowed_by="host firewall", program="mosquitto",
                  program_said="mosquitto")
    fields.update(kw)
    return Change(**fields)


def alert_of(said):
    return mailhtml.alert(said)


LINK = "https://app.whichports.com/set-password/abc"
SILENCE = notify.said_silence("box", "no report for 41 minutes, past the 35 minute threshold")
STALE = notify.said_outside_stale(
    "box", "no probing pass has finished for box from probe1 in 7 hours, so"
           " what the screen says about reachability from there is that old")
CHANGES = notify.said_changes("box", [a_change()])
SEVERAL = notify.said_changes("box", [a_change(where=f"tcp/{port} on v4", port=port)
                                      for port in range(8000, 8008)])
TEST = notify.said_test()
ALERTS = [SILENCE, STALE, CHANGES, SEVERAL, TEST]
ALERT_IDS = ("silence", "stale", "one port", "several ports", "test")

EVERY_MAIL = [alert_of(said) for said in ALERTS] + [
    mailhtml.account("dad@example.net", LINK, "app.whichports.com", "24 hours"),
    mailhtml.reset("sysadmin@example.net", LINK, "30 minutes"),
    mailhtml.confirm("sysadmin@example.net", LINK, "24 hours"),
    mailhtml.invite("Robin", "sysadmin@example.net", "whichports", "Admin", LINK, "7 days"),
]
IDS = ALERT_IDS + ("account", "reset", "confirm", "invite")
# The one link each mail carries: the server for an alert about one, the
# Integrations screen for the test, the mail's own for an account mail.
EVERY_LINK = [publicurl.server("box")] * 4 + [publicurl.integrations()] + [LINK] * 4


def seen(html):
    """What a reader sees: the text of the body with the tags out."""
    body = html[html.index("<body"):]
    text = html_module.unescape(re.sub(r"<[^>]+>", " ", body)).replace("\xa0", " ")
    return re.sub(r"\s+", " ", text).strip()


# ------------------------------------------------------------ it loads nothing
#
# For a product whose pitch is that it collects little and reports plainly, a
# mail that phones home on open would be the wrong first impression. This is a
# property rather than a nicety, so it is a test rather than a comment.

@pytest.mark.parametrize("html", EVERY_MAIL, ids=IDS)
def test_a_mail_makes_no_network_request_when_it_is_opened(html):
    assert "<img" not in html.lower(), "an image is a request, and a tracking pixel"
    assert "background-image" not in html.lower()
    assert "url(" not in html.lower()
    assert "@import" not in html.lower()
    # One link, and a link is not a request until it is clicked.
    hrefs = re.findall(r'href="([^"]+)"', html)
    assert len(hrefs) == 1, hrefs


@pytest.mark.parametrize("html,link", list(zip(EVERY_MAIL, EVERY_LINK)), ids=IDS)
def test_the_one_link_is_the_server_for_an_alert_and_the_mails_own_otherwise(html, link):
    assert re.findall(r'href="([^"]+)"', html) == [link]


def test_the_button_says_what_the_link_does():
    for html, word in ((EVERY_MAIL[5], "Set your password"), (EVERY_MAIL[6], "Choose a new password"),
                       (EVERY_MAIL[7], "Confirm"), (EVERY_MAIL[8], "Join the workspace")):
        assert f'>{word}</a>' in html, word
        assert "Open the dashboard" not in html
    for html in EVERY_MAIL[:4]:
        assert ">Open box</a>" in html
    assert ">Open Integrations</a>" in EVERY_MAIL[4]


def test_the_link_and_the_button_are_escaped():
    html = mailhtml.shell("h", "l", "", "c", button="<b>go</b>", link='https://x/?a=1&b="2"')
    assert "<b>go</b>" not in html and "&lt;b&gt;go&lt;/b&gt;" in html
    assert 'href="https://x/?a=1&amp;b=&quot;2&quot;"' in html


def test_an_inviters_name_and_a_workspace_name_cannot_put_markup_into_a_mail():
    html = mailhtml.invite("<script>x</script>", "<i>m</i>", "<b>w</b>", "<u>r</u>", LINK, "7 days")
    for raw in ("<script>x</script>", "<i>m</i>", "<b>w</b>", "<u>r</u>"):
        assert raw not in html
    assert "&lt;script&gt;x&lt;/script&gt;" in html


# ------------------------------------------------------- it survives a client
#
# The rules that actually decide whether this arrives looking like anything.
# Outlook on Windows renders through Word: no flexbox, no grid, no var().

@pytest.mark.parametrize("html", EVERY_MAIL, ids=IDS)
def test_a_mail_uses_nothing_a_mail_client_will_not_render(html):
    for unsupported in ("display:flex", "display:grid", "var(--", "position:absolute"):
        assert unsupported not in html, f"{unsupported} does not render in Outlook"


@pytest.mark.parametrize("html", EVERY_MAIL, ids=IDS)
def test_a_mail_declares_both_schemes_so_a_client_does_not_invert_it_twice(html):
    assert 'name="color-scheme" content="light dark"' in html
    assert 'name="supported-color-schemes" content="light dark"' in html


# ------------------------------------------------------ the colours are ours
#
# A literal hex in a second file is exactly the fact that rots. The values are
# literal here because var() does not survive a mail client, so the agreement
# is asserted instead.

def site_theme():
    """site/theme.py, loaded by path. Nothing in app/ may depend on the site,
    which is why this is a test-only load and not an import."""
    here = pathlib.Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "site" / "theme.py"
        if candidate.exists():
            spec = importlib.util.spec_from_file_location("theme_site", candidate)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    return None


def light_tokens(theme):
    block = theme.TOKENS[theme.TOKENS.index('html[data-mode="light"]'):]
    return dict(re.findall(r"--([a-z0-9-]+):(#[0-9A-Fa-f]{6})", block))


def dark_tokens(theme):
    block = theme.TOKENS[theme.TOKENS.index(":root{"):
                         theme.TOKENS.index('html[data-mode="light"]')]
    return dict(re.findall(r"--([a-z0-9-]+):(#[0-9A-Fa-f]{6})", block))


def test_the_mail_palette_is_the_products_own_light_palette():
    theme = site_theme()
    if theme is None:
        pytest.skip("site/theme.py is not in this checkout")
    light = light_tokens(theme)
    for name, token in (("INK", "ink"), ("INK_STRONG", "ink-str"), ("MUTED", "muted"),
                        ("FAINT", "faint"), ("PAGE", "bg"), ("PANEL", "panel"),
                        ("PANEL2", "panel2"), ("LINE", "line"), ("LINE2", "line2"),
                        ("ACCENT_INK", "acc-ink")):
        assert getattr(mailhtml, name).upper() == light[token].upper(), (
            f"mail {name} is {getattr(mailhtml, name)} and --{token} is {light[token]}")


# ------------------------------------------------------------------ the mark
#
# docs/DESIGN.md section 1: six rounded cells, three by two, five dimmed,
# exactly one in periwinkle. Until 2026-10-04 the mail drew it with cells no
# dark rule could reach, so a dark mail showed five bright cells and the lit
# one dark. These hold the mail's mark to the one `site/theme.py` draws.

def mark_cells():
    return re.findall(r'<td class="(mk-[dl])" width="(\d+)" height="(\d+)" '
                      r'style="[^"]*background:(#[0-9A-Fa-f]{6});'
                      r'border-radius:(\d+)px', mailhtml.mark())


def test_the_mark_is_six_cells_with_the_fifth_lit():
    cells = mark_cells()
    assert len(cells) == 6
    assert [cls for cls, *_ in cells] == ["mk-d"] * 4 + ["mk-l", "mk-d"]
    # three across, two down
    assert mailhtml.mark().count("<tr>") == 3


def test_the_lit_cell_is_the_one_the_theme_lights():
    theme = site_theme()
    if theme is None:
        pytest.skip("site/theme.py is not in this checkout")
    lit = [at for at, cell in enumerate(re.findall(r"<i[^>]*>", theme.mark()))
           if "on" in cell]
    assert lit == [4]
    assert [at for at, (cls, *_) in enumerate(mark_cells()) if cls == "mk-l"] == lit


def test_the_marks_cells_are_the_small_lockups_size():
    """Beside a 15px word the theme draws 7px cells, 3px apart, 2px corners."""
    theme = site_theme()
    if theme is None:
        pytest.skip("site/theme.py is not in this checkout")
    assert ".mk i{display:block;width:7px;height:7px;border-radius:2px" in theme.BASE
    assert ".mk{display:grid;grid-template-columns:repeat(3,1fr);gap:3px" in theme.BASE
    for _cls, width, height, _colour, radius in mark_cells():
        assert (width, height, radius) == ("7", "7", "2")
    assert mailhtml.mark().count('width="3"') == 4
    assert 'height="3"' in mailhtml.mark()


def test_the_marks_tones_are_the_themes_on_a_light_and_on_a_dark_page():
    """The dim cells are --faint at 75 percent as that lands on each page,
    and the lit one is --acc."""
    theme = site_theme()
    if theme is None:
        pytest.skip("site/theme.py is not in this checkout")
    light, dark = light_tokens(theme), dark_tokens(theme)
    assert ".mk i{" in theme.BASE and "opacity:.75" in theme.BASE
    assert mailhtml.MARK_DIM == theme._blend(light["faint"], light["bg"], 0.75)
    assert mailhtml.MARK_DIM_DARK == theme._blend(dark["faint"], dark["bg"], 0.75)
    assert mailhtml.MARK_LIT.upper() == light["acc"].upper()
    assert mailhtml.MARK_LIT_DARK.upper() == dark["acc"].upper()
    for cls, _w, _h, colour, _r in mark_cells():
        assert colour == (mailhtml.MARK_LIT if cls == "mk-l" else mailhtml.MARK_DIM)


@pytest.mark.parametrize("html", EVERY_MAIL, ids=IDS)
def test_a_dark_client_can_reach_every_cell_of_the_mark(html):
    """A media query cannot beat an inline style without a class. Every cell
    has one, and the dark block gives each its dark tone."""
    dark = html[html.index("@media (prefers-color-scheme:dark)"):html.index("</style>")]
    assert f".mk-d{{background:{mailhtml.MARK_DIM_DARK} !important}}" in dark
    assert f".mk-l{{background:{mailhtml.MARK_LIT_DARK} !important}}" in dark
    assert html.count('class="mk-d"') == 5
    assert html.count('class="mk-l"') == 1


def test_on_a_dark_page_the_lit_cell_is_the_brightest_one():
    """What was wrong: the lit cell darker than the dim ones."""
    def brightness(colour):
        return sum(int(colour[at:at + 2], 16) for at in (1, 3, 5))
    assert brightness(mailhtml.MARK_LIT_DARK) > brightness(mailhtml.MARK_DIM_DARK)


# ------------------------------------------------------------- it says no more
#
# Every sentence comes from notify.py. A template that added a claim would
# undo the restraint those words are held to by their own tests.

@pytest.mark.parametrize("html", EVERY_MAIL, ids=IDS)
def test_no_mail_claims_anything_about_the_state_of_a_host(html):
    for forbidden in ("secure", "protected", "safe", "compliant", "guaranteed",
                      "certified", "is down", "is offline", "unreachable",
                      "at risk", "vulnerable"):
        assert forbidden not in html.lower(), f"the mail claims {forbidden}"


@pytest.mark.parametrize("said", ALERTS, ids=ALERT_IDS)
def test_an_alert_shows_what_its_text_half_says_and_nothing_else(said):
    """The whole of what a reader sees is the word beside the mark, the
    title, the test's one sentence, each label with its value, the button
    and the closing line, in that order."""
    parts = ["whichports", said.title, said.sentence]
    for label, value in said.fields:
        parts += [label, value]
    parts += [said.button, said.closing]
    assert seen(mailhtml.alert(said)) == " ".join(part for part in parts if part)
    subject, text, _html = notify.mail(said)
    assert subject == f"[whichports] {said.title}"
    for label, value in said.fields:
        assert f"  {label}: {value}\n" in text
    for line in (said.title, said.sentence, said.closing, said.link):
        assert line in text


@pytest.mark.parametrize("said", ALERTS, ids=ALERT_IDS)
def test_an_alert_draws_no_fixed_width_and_no_state_word(said):
    html = mailhtml.alert(said)
    assert mailhtml.MONO not in html
    for word in ("conflict", "unreviewed", "intended"):
        assert word not in seen(html)


def test_the_fields_are_two_to_a_row_and_an_odd_one_has_an_empty_cell_beside_it():
    assert len(CHANGES.fields) == 5
    html = mailhtml.alert(CHANGES)
    grid = html[html.index('<table role="presentation" width="100%" cellpadding="0"'
                           ' cellspacing="0" border="0" style="margin:'):]
    grid = grid[:grid.index("</table>")]
    assert grid.count("<tr>") == 3
    assert grid.count('<td width="50%"') == 6
    assert grid.count(">&nbsp;</td>") == 1
    # The test message has no values and so no grid at all.
    assert 'width="50%"' not in mailhtml.alert(TEST)


def test_a_message_with_no_closing_draws_no_empty_line_for_it():
    html = mailhtml.alert(TEST)
    assert TEST.closing == ""
    assert seen(html).endswith("Open Integrations")


# ------------------------------------------------------------------ escaping
#
# A program's name and a server's name come from a host document. Neither is
# trusted markup.

def test_a_host_document_cannot_put_markup_into_a_mail():
    # A name that is not plain never becomes `program_said`
    # (tests/test_alert_words.py). The mail escapes all the same, so this
    # hands it one as if that rule had failed.
    said = notify.said_changes(
        "<script>x</script>",
        [a_change(where="<b>tcp/22</b>", program_said="<img src=x onerror=y>",
                  was_program="before", was_program_said="<i>before</i>")])
    html = mailhtml.alert(said)
    assert "<script>" not in html
    assert "<b>tcp/22</b>" not in html
    assert "<img" not in html.lower()
    assert "<i>before</i>" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img src=x onerror=y&gt;" in html
    assert "&lt;i&gt;before&lt;/i&gt;" in html


def test_a_display_name_cannot_put_markup_into_a_mail():
    said = notify.said_silence("box", "no report for 41 minutes", '<b>"Shop"</b>')
    html = mailhtml.alert(said)
    assert "<b>" not in html[html.index("<body"):]
    assert "&lt;b&gt;&quot;Shop&quot;&lt;/b&gt;" in html
