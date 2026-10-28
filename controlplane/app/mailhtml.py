"""The HTML half of an alert mail. Stdlib only, and the text half stays the
authority on what is said.

Every sentence here comes from `notify.py` unchanged: an alert is drawn from
the `Said` that module builds, the same one its text half and every chat
channel are written from. This module decides how it looks and never what it
claims, so the restraint those words are held to by their own tests cannot be
undone by a template.

## Why this is not the app's stylesheet

A mail client is not a browser. The rules below are the ones that actually
decide whether this arrives looking like anything:

  - **Tables for layout.** Outlook on Windows renders through Word, which has
    no flexbox and no grid. A table is the only container that lands the same
    way everywhere.
  - **Inline styles.** A `<style>` block survives in most clients now and is
    still dropped by some, and Gmail clips a long message and can lose the
    head with it. Every rule that matters is on the element.
  - **No CSS variables.** `var()` is not resolved by Outlook or by several
    webmail clients, so the colours are literal, and a test asserts they are
    the same literals `site/theme.py` ships.
  - **No web fonts.** The product's own faces are embedded base64 in the app
    and cannot be in a mail. A system stack is used and the mono stack is kept
    for ports and rules, because `docs/DESIGN.md` section 1 makes mono the
    treatment for a port, a count or an address.
  - **600 pixels.** The width every client has handled for twenty years.

## No images, and that is a property rather than a shortcut

Nothing here loads. No logo file, no tracking pixel, no remote stylesheet, so
opening this mail makes no network request at all and tells us nothing about
when or whether it was read. For a product whose pitch is that it collects
little and reports plainly, a mail that phones home would be the wrong first
impression. The mark is drawn out of table cells instead.

## Light, with dark as an enhancement

`docs/DESIGN.md` section 1 makes dark the primary mode for the product, and
this is the one place that is not followed. A mail lands in a client whose
theme we do not control and several of them invert a dark design on their own,
which produces a result nobody designed. So the mail is built light, which
inverts predictably, and carries a `prefers-color-scheme` block for the
clients that honour it. `color-scheme` is declared so those clients leave the
rest alone rather than inverting it a second time.
"""
from html import escape

from . import publicurl

# The light palette, from site/theme.py. Literal because var() does not
# survive a mail client, and `tests/test_mailhtml.py` fails if these ever stop
# matching what the product ships. Status colour keeps one meaning wherever it
# is shown (docs/DESIGN.md section 3), and that is exactly the kind of fact
# that rots when it lives in two places.
INK = "#212230"
INK_STRONG = "#16161F"
MUTED = "#63657B"
FAINT = "#6D6F7F"
PAGE = "#FAFAFC"
PANEL = "#FFFFFF"
PANEL2 = "#F5F5FA"
LINE = "#E6E6EE"
LINE2 = "#D9D9E5"
ACCENT_INK = "#4E51A0"

# The mark's own tones, as `site/theme.py` draws it: the dim cells are
# `--faint` at 75 percent, written here as what that lands as on each page,
# and the lit one is `--acc`. `tests/test_mailhtml.py` works both out from
# the theme and holds these to it.
MARK_DIM = "#90929E"
MARK_LIT = "#6366B0"
MARK_DIM_DARK = "#6E7181"
MARK_LIT_DARK = "#9799CA"

SANS = ("-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,"
        "sans-serif")
MONO = "'SF Mono',SFMono-Regular,Menlo,Consolas,'Liberation Mono',monospace"


def mark():
    """The whichports mark, drawn out of table cells so the mail loads nothing.

    The same six slots `site/theme.py` draws: three across, two down, the
    fifth lit, which is the middle of the lower row (docs/DESIGN.md section
    1). Beside a 15px word the theme draws the small lockup, 7px cells 3px
    apart with 2px corners, and so does this.

    **Each cell carries a class**, `mk-d` or `mk-l`, because a dark client
    can retone only what a rule can reach. Until 2026-10-04 the cells had
    none and were drawn in the hairline's grey with the lit one in the
    button's ink: on a dark mail five cells stayed bright and the lit one
    dark, the mark inverted (docs/RECORD.md 4.346). Two earlier drawings were
    not ours at all, three rows of three and then six in one row (4.154).
    """
    lit = (1, 1)
    rows = []
    for y in range(2):
        cells = []
        for x in range(3):
            on = (x, y) == lit
            cells.append(
                f'<td class="{"mk-l" if on else "mk-d"}" width="7" height="7" '
                f'style="width:7px;height:7px;background:{MARK_LIT if on else MARK_DIM};'
                f'border-radius:2px;font-size:0;line-height:0;padding:0">&nbsp;</td>')
            if x < 2:
                cells.append('<td width="3" style="width:3px;font-size:0;padding:0">&nbsp;</td>')
        rows.append("<tr>" + "".join(cells) + "</tr>")
        if y < 1:
            rows.append('<tr><td colspan="5" height="3" '
                        'style="height:3px;font-size:0;line-height:0;padding:0">&nbsp;</td></tr>')
    return ('<table role="presentation" cellpadding="0" cellspacing="0" border="0">'
            + "".join(rows) + "</table>")


def _page(title, rows):
    """The document every mail is: the head, the page, the mark and the word
    beside it, and then `rows`, which are the rows of the 600 pixel column.

    Two notes on the <style> block, kept here because a comment inside it
    would be sent in every mail (site/theme.py, 2026-10-02). The media query
    for small screens is the one rule that cannot be inlined, and the only
    one worth the risk of a client dropping the head: a mail is unreadable on
    a phone at 600px fixed. Everything the layout depends on is inline as
    well, so losing this block costs the small screen and nothing else. The
    dark block is for the clients that say so. Light is the design and dark
    is the enhancement, because a client that inverts a dark mail on its own
    produces something nobody drew.
    """
    return f"""<!doctype html>
<html lang="en" style="margin:0;padding:0">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<title>{escape(title)}</title>
<style>
  @media only screen and (max-width:620px){{
    .wrap{{width:100% !important}}
    .pad{{padding-left:20px !important;padding-right:20px !important}}
  }}
  @media (prefers-color-scheme:dark){{
    .page{{background:#12141C !important}}
    .panel{{background:#1C1F2A !important}}
    .panel2{{background:#252935 !important}}
    .ink{{color:#E9EAF2 !important}}
    .muted{{color:#A2A5B6 !important}}
    .faint{{color:#8C90A3 !important}}
    .hair{{border-color:#3A4052 !important}}
    .mk-d{{background:{MARK_DIM_DARK} !important}}
    .mk-l{{background:{MARK_LIT_DARK} !important}}
  }}
</style>
</head>
<body class="page" style="margin:0;padding:0;background:{PAGE};
  -webkit-text-size-adjust:100%">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
  class="page" style="background:{PAGE}">
<tr><td align="center" style="padding:32px 12px">

<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0"
  class="wrap" style="width:600px;max-width:600px">

  <tr><td class="pad" style="padding:0 0 16px">
    <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
      <td style="padding-right:10px" valign="middle">{mark()}</td>
      <td class="ink" style="font-family:{SANS};font-size:15px;font-weight:600;
        color:{INK_STRONG};letter-spacing:-.01em" valign="middle">whichports</td>
    </tr></table>
  </td></tr>
{rows}
</table>
</td></tr>
</table>
</body>
</html>
"""


def _button(words, link):
    return (f'<a href="{escape(link, quote=True)}"\n'
            f'          style="display:inline-block;font-family:{SANS};font-size:13px;line-height:18px;\n'
            f'          font-weight:600;color:#FFFFFF;background:{ACCENT_INK};\n'
            f'          text-decoration:none;padding:8px 16px;border-radius:99px">{escape(words)}</a>')


def _closing(words):
    return (f'  <tr><td class="pad" style="padding:14px 0 0">\n'
            f'    <div class="faint" style="font-family:{SANS};font-size:12px;line-height:1.6;\n'
            f'      color:{FAINT}">{escape(words)}</div>\n'
            f'  </td></tr>\n')


def _field_cell(label, value):
    """One labelled value: the label small and faint over what it says."""
    return (f'<td width="50%" style="padding:0 12px 14px 0" valign="top">'
            f'<div class="faint" style="font-family:{SANS};font-size:11px;line-height:16px;'
            f'letter-spacing:.06em;text-transform:uppercase;color:{FAINT};margin:0 0 3px">'
            f'{escape(label)}</div>'
            f'<div class="ink" style="font-family:{SANS};font-size:14px;line-height:20px;'
            f'color:{INK};word-break:break-word">{escape(value)}</div></td>')


def _field_grid(fields, below_a_sentence):
    """The fields two to a row. An odd one out gets an empty cell beside
    it, so every row is two cells and a client lays them out alike."""
    if not fields:
        return ""
    cells = [_field_cell(label, value) for label, value in fields]
    if len(cells) % 2:
        cells.append('<td width="50%" style="padding:0">&nbsp;</td>')
    rows = "".join(f"<tr>{cells[at]}{cells[at + 1]}</tr>"
                   for at in range(0, len(cells), 2))
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0"'
            f' border="0" style="margin:{14 if below_a_sentence else 4}px 0 0">{rows}</table>')


def alert(said):
    """One alert, from the description its text half is written from
    (app/alertwords.py): the heading, the labelled values two to a row, the
    button, and under the card the line that nothing else will be sent
    (docs/screens/mails/SPEC-alert-messages.md). The test message has one
    sentence and no values. No state word in a frame and no time: what those
    held is on the page the button opens."""
    sentence = (f'<div class="ink" style="font-family:{SANS};font-size:14px;line-height:1.5;'
                f'color:{INK};margin:0">{escape(said.sentence)}</div>'
                if said.sentence else "")
    grid = _field_grid(said.fields, below_a_sentence=bool(said.sentence))
    card = f"""
  <tr><td class="panel hair pad" style="background:{PANEL};border:1px solid {LINE};
    border-radius:12px;padding:22px 24px">
    <div class="ink" style="font-family:{SANS};font-size:19px;line-height:1.3;
      font-weight:600;color:{INK_STRONG};margin:0 0 10px">{escape(said.title)}</div>
    {sentence}{grid}
    <div style="margin:{10 if grid else 18}px 0 0">{_button(said.button, said.link)}</div>
  </td></tr>
"""
    return _page(said.title, card + (_closing(said.closing) if said.closing else ""))


def shell(heading, lead, blocks, closing, button="Open the dashboard", link=None):
    """The frame the account mails share: one heading, one lead sentence,
    the blocks, then the button and the closing line.

    `heading`, `lead`, `button` and `link` are plain text and are escaped
    here. `blocks` is already-built markup from the builders below, never
    anything a host document controls. An account mail's button is the one
    link that works once and expires, and the words on it say what it does
    (docs/screens/mails). With no link given it is this control plane's
    dashboard (app/publicurl.py).
    """
    if link is None:
        link = publicurl.dashboard()
    card = f"""
  <tr><td class="panel hair" style="background:{PANEL};border:1px solid {LINE};
    border-radius:12px">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
      <tr><td class="pad" style="padding:22px 24px 20px">
        <div class="ink" style="font-family:{SANS};font-size:19px;line-height:1.3;
          font-weight:600;color:{INK_STRONG};margin:0 0 8px">{escape(heading)}</div>
        <div class="muted" style="font-family:{SANS};font-size:14px;line-height:1.5;
          color:{MUTED};margin:0">{escape(lead)}</div>
      </td></tr>
      {blocks}
      <tr><td class="pad hair" style="padding:18px 24px 20px;
        border-top:1px solid {LINE}">
        {_button(button, link)}
      </td></tr>
    </table>
  </td></tr>
"""
    return _page(heading, card + _closing(closing))


def _row(inner, background=None, top_border=True):
    """One band inside the card."""
    bg = f"background:{background};" if background else ""
    border = f"border-top:1px solid {LINE};" if top_border else ""
    return (f'<tr><td class="pad{" panel2" if background else ""} hair" '
            f'style="{bg}{border}padding:16px 24px">{inner}</td></tr>')


def field(label, value, mono=True, last=False):
    """A named fact, the label small and faint above what it says.

    `last` drops the trailing margin, so the band's own padding is the only
    space under the final field rather than padding plus a margin.
    """
    family = MONO if mono else SANS
    return (f'<div style="margin:0 0 {0 if last else 12}px">'
            f'<div class="faint" style="font-family:{SANS};font-size:11px;'
            f'line-height:16px;letter-spacing:.06em;text-transform:uppercase;'
            f'color:{FAINT};margin:0 0 3px">{escape(label)}</div>'
            f'<div class="ink" style="font-family:{family};font-size:13px;'
            f'line-height:20px;color:{INK};word-break:break-word">{escape(value)}</div>'
            f'</div>')


# ------------------------------------------------------------ account mails
#
# docs/screens/mails/SPEC.md, "The mails drafted for the beta", accepted by
# the owner on 2026-09-07 in the gallery beside that file. Each carries one
# link that works once and expires, and the button says what it does. The
# words are the text half's, in `notify.py`, and nothing is added here.


def fields(*pairs):
    """One band of named facts. `pairs` is (label, value, mono)."""
    return _row("".join(field(label, value, mono=mono, last=i == len(pairs) - 1)
                        for i, (label, value, mono) in enumerate(pairs)))


def account(email, link, sign_in_at, how_long):
    return shell(
        heading="Your whichports account",
        lead="An account was made for you.",
        blocks=fields(("email", email, True), ("sign in at", sign_in_at, True)),
        closing=f"The link works once and for {how_long}.",
        button="Set your password", link=link)


def reset(email, link, how_long):
    return shell(
        heading="Reset your password",
        lead="A reset was asked for this account.",
        blocks=fields(("email", email, True)),
        closing=f"If you did not ask for this, nothing changes. The link works once and for {how_long}.",
        button="Choose a new password", link=link)


def confirm(email, link, how_long):
    return shell(
        heading="Confirm your email",
        lead="One click finishes your account.",
        blocks=fields(("email", email, True)),
        closing=f"The link works once and for {how_long}.",
        button="Confirm", link=link)


def invite(inviter, inviter_email, workspace, role, link, how_long):
    """An empty role is left out rather than drawn empty, for the reason
    `notify.format_invite` gives: nothing enforces roles yet."""
    named = [("workspace", workspace, False)]
    if role:
        named.append(("role", role, False))
    named.append(("invited by", inviter_email, True))
    return shell(
        heading=f"{inviter} invited you to {workspace}",
        lead="The workspace has a place for you.",
        blocks=fields(*named),
        closing=f"The link works once and for {how_long}.",
        button="Join the workspace", link=link)
