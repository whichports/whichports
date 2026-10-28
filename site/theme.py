#!/usr/bin/env python3
"""The Periwinkle design system, shared by the landing page and the dashboard.

`docs/DESIGN.md` section 1 owns these values. This file is where they become
code, and it is imported rather than copied so the two sites cannot drift apart.

Decided 2026-08-12 from the frozen prototype in `explorations/`. Dark is
primary, light is a supported second mode, status colour never follows the
accent, and the background is a vignette rather than a pattern.

All three pages import it, `build_site.py` included since 2026-08-14. The note
that used to sit here, saying the long page kept its own older green look, was
left behind by that change and is gone.
"""
import base64
import pathlib
import re
import struct
import zlib

FONT_DIR = pathlib.Path(__file__).resolve().parent / "fonts"


# ---- no comment of ours leaves in a page ----
# A comment inside a stylesheet or a script is sent to every visitor and reads
# in view-source like any other line. Ours say why a rule is the way it is, who
# decided it and where that is written down, which is for whoever opens this
# repository and for nobody else. On 2026-10-02 the public pages were found
# carrying them, names and all (docs/RECORD.md 4.247).
#
# So the comments stay in the source, and every stylesheet and script is handed
# to a page through one of the two functions below. TOKENS and BASE in this
# file already are, so a builder only does it for what it writes itself.
# comments_in_page() is the check the tests run on every built page.

# A quoted string, or a comment. The string is matched so that a "/*" inside
# one is not taken for a comment, and it is put back as it was.
_CSS_STRING_OR_COMMENT = re.compile(
    r"""("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')|/\*.*?\*/""", re.S)
_QUOTED = re.compile(r""""(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'""")


def css_without_comments(css):
    """The stylesheet with every /* ... */ taken out and nothing else changed."""
    return _CSS_STRING_OR_COMMENT.sub(lambda found: found.group(1) or "", css)


def script_without_comments(script):
    """The script without the lines that are a // comment and nothing else.

    Line by line on purpose. Telling a comment that follows code from a "//"
    inside a string or a regular expression takes a JavaScript parser, and a
    strip that guessed wrong would cut working code in half without a sound.
    So a comment in a script we ship sits on a line of its own, this drops
    those lines, and comments_in_page() fails the build's tests on any other
    kind rather than this trying to remove it.
    """
    return "\n".join(line for line in script.split("\n")
                     if not line.lstrip().startswith("//"))


def comments_in_page(source):
    """Every comment a built page still carries, as a list of short lines for
    a test to print. Empty is the only right answer.

    It reads what a browser is sent: the HTML itself, each <style> block and
    each <script> block. Quoted strings are set aside first, so the "//" in
    an address is not a finding. It is strict where the strip is careful: a
    comment after code, a /* block */ in a script and a template literal are
    all findings, the last because the line-by-line strip above cannot tell
    what is inside one.
    """
    found = [f"an HTML comment: {' '.join(text.split())[:70]}"
             for text in re.findall(r"<!--.*?(?:-->|\Z)", source, re.S)]
    for css in re.findall(r"<style[^>]*>(.*?)</style>", source, re.S):
        bare = _QUOTED.sub('""', css)
        found += [f"a stylesheet comment: {' '.join(text.split())[:70]}"
                  for text in re.findall(r"/\*.*?(?:\*/|\Z)", bare, re.S)]
    for script in re.findall(r"<script[^>]*>(.*?)</script>", source, re.S):
        for line in script.split("\n"):
            bare = _QUOTED.sub('""', line)
            if "//" in bare or "/*" in bare:
                found.append(f"a script comment: {line.strip()[:70]}")
            if "`" in bare:
                found.append(f"a template literal, which the comment strip"
                             f" cannot read: {line.strip()[:50]}")
    return found

# Every weight the stylesheets ask of a family has to be a face listed here.
# A weight that is not here is drawn by the browser smearing the nearest one,
# which is what bold port numbers were until 2026-09-10: seven rules asked for
# IBM Plex Mono at 600 over a Regular that shipped alone, and the owner saw that
# it sometimes looked wrong. test_font_faces.py holds the rule.
#
# IBM Plex Mono is IBM's own release 2.5.0 (@ibm/plex-mono, complete/woff2,
# OFL 1.1). The Regular that shipped from the first day is byte for byte that
# release's file, checked by hash on 2026-09-10, so the SemiBold beside it is
# from the same one.
_FACES = [("Space Grotesk", "SpaceGrotesk-500", 500), ("Space Grotesk", "SpaceGrotesk-600", 600),
          ("Space Grotesk", "SpaceGrotesk-700", 700), ("Work Sans", "WorkSans-400", 400),
          ("Work Sans", "WorkSans-500", 500), ("Work Sans", "WorkSans-600", 600),
          ("IBM Plex Mono", "IBMPlexMono-Regular", 400),
          ("IBM Plex Mono", "IBMPlexMono-SemiBold", 600)]


def fonts(inline=False):
    """Self hosted, always. Never a CDN: GDPR, plus no third party at runtime."""
    if not inline:
        return "".join(
            f'@font-face{{font-family:"{f}";src:url(fonts/{fn}.woff2)format("woff2");'
            f'font-weight:{w};font-display:swap}}\n' for f, fn, w in _FACES)
    out = []
    for f, fn, w in _FACES:
        b64 = base64.b64encode((FONT_DIR / f"{fn}.woff2").read_bytes()).decode()
        out.append(f'@font-face{{font-family:"{f}";src:url(data:font/woff2;base64,{b64})'
                   f'format("woff2");font-weight:{w};font-display:swap}}')
    return "\n".join(out)


# ------------------------------------------------------------------ the sizes
# Five steps, and the dict is the only place a size is written. docs/DESIGN.md
# section 1 owns type; this is the size half of it as code.
#
# Why a scale at all, and why so few steps. Sizes had accumulated one screen at a
# time until the app carried ten of them between 9.5px and 15px, which meant a
# port number, the sentence explaining it and a micro label all landed within two
# pixels of each other. The owner, reading the live dashboard on his own servers
# on 2026-08-16, found everything too small and too alike to tell what matters
# (docs/RECORD.md 4.62). He is right, and the cause is that there was no
# hierarchy to read, only a spread.
#
# What each step is for. A screen picks the role, never a number:
#
#   micro   uppercase tracked labels, the status tag, nav and buttons. The floor.
#           Nothing on the page is smaller than this.
#   meta    supporting detail: the sentence under a fact, a timestamp, a hint,
#           quoted rule text.
#   body    the default. Table rows, sentences, fields, tab labels.
#   lead    the one fact a panel exists to convey, and a section heading. A port
#           number, a host name, a count. This is the step that does the work of
#           telling the eye where to land, so it is a real jump and not 1px.
#   title   the heading of a view, one per screen.
#
# The steps step by about a fifth each, except the title, which is a different
# kind of thing and sits on its own. Adding a sixth is a design decision and a
# test in site/app/test_build_sample.py makes a session take it deliberately.
TYPE_SCALE = {
    "micro": "11px",
    "meta": "13px",
    "body": "15px",
    "lead": "19px",
    "title": "28px",
}

TOKENS = """
:root{
  /* Lifted 2026-08-22 after the owner found the dark theme too dark and at
     times hard to read. Measured rather than nudged, and the
     measurement is in docs/DESIGN.md section 1: the text was never the
     problem, the structure was. A contrast ratio adds 0.05 to both
     luminances, which dominates near black, so the old surfaces scored the
     same ratios as light while emitting twelve times less difference. A panel
     did not separate from the page and a border did not separate from its
     panel, so a table had no grid and the eye had nothing to hold. */
  --bg:#12141C;--panel:#1C1F2A;--panel2:#252935;--hover:#2E3341;
  --line:#3A4052;--line2:#4E5568;
  --ink:#E9EAF2;--ink-str:#F4F5FA;--muted:#A2A5B6;--faint:#8C90A3;
  --acc:#9799CA;--acc-ink:#AEB0DC;--acc-fill:#4E51A0;--acc-bg:#171926;--acc-line:#2C3145;
  --ok:#4ADEA8;--ok-soft:#1D5442;--ok-mark:#4ADEA8;
  --warn:#F2C560;--warn-soft:#5A4718;
  --fail:#F98A8A;--fail-soft:#5E2727;
  --off:#949DAA;--off-soft:#3A4250;
  --neutral:#9A9CAC;--neutral-bg:rgba(255,255,255,.07);
  --on-fill:#FFFFFF;
  /* the vignette lifts the centre on dark, because near black has nowhere
     darker to go. docs/DESIGN.md section 1. */
  --vig:radial-gradient(125% 95% at 50% 40%,rgba(255,255,255,.055),transparent 68%);
  --r:12px;--quick:120ms;--move:180ms;--ease:cubic-bezier(.2,0,.2,1);
}
html[data-mode="light"]{
  --bg:#FAFAFC;--panel:#FFFFFF;--panel2:#F5F5FA;--hover:#F2F2F8;
  --line:#E6E6EE;--line2:#D9D9E5;
  /* --faint darkened 2026-08-22. It was 2.50:1 on a table header, the worst
     contrast in either mode, while carrying section headings and every micro
     label. Found by the test written for the dark complaint: light was worse
     on the same token and nobody had said so. docs/DESIGN.md section 1. */
  --ink:#212230;--ink-str:#16161F;--muted:#63657B;--faint:#6D6F7F;
  --acc:#6366B0;--acc-ink:#4E51A0;--acc-fill:#4E51A0;--acc-bg:#F3F3FA;--acc-line:#D8D9EC;
  --ok:#0E5C43;--ok-soft:#A7E8CE;--ok-mark:#0F9E6A;
  --warn:#8A6220;--warn-soft:#EEE0C4;
  --fail:#96271D;--fail-soft:#F0D8D5;
  --off:#6B7077;--off-soft:#DEDEDA;
  --neutral:#63657B;--neutral-bg:#EFEFED;
  --vig:radial-gradient(125% 95% at 50% 0%,transparent 40%,rgba(84,84,90,.13) 100%);
}
"""

# The scale as custom properties, generated from the dict above so the two can
# never say different things. Its own :root block, because the sizes do not move
# with the mode the way the colours do.
TOKENS += (":root{" + "".join(f"--fs-{name}:{size};" for name, size in TYPE_SCALE.items())
           + "}\n")
# What a page gets is the stylesheet without its comments, see the top of this
# file. The comments above are read here.
TOKENS = css_without_comments(TOKENS)

BASE = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Work Sans",sans-serif;background:var(--bg);color:var(--ink);
  font-size:var(--fs-body);line-height:1.55;-webkit-font-smoothing:antialiased;position:relative;
  min-height:100vh}
body:before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;background:var(--vig)}
body>*{position:relative;z-index:1}
h1,h2,h3{font-family:"Space Grotesk",sans-serif;font-weight:600;letter-spacing:-.02em;
  color:var(--ink-str);text-wrap:balance}
a{color:inherit;text-decoration:none}
.num{font-family:"IBM Plex Mono",monospace;font-variant-numeric:tabular-nums}
.faint{color:var(--faint)}
:focus-visible{outline:2px solid var(--acc);outline-offset:2px;border-radius:4px}
@media(prefers-reduced-motion:reduce){*{animation-duration:.01ms!important;
  transition-duration:.01ms!important}}

/* ---- the mark: a port grid with one of them lit, rebuilt in CSS so it is
   crisp at any size. Six slots, the fifth is the one that is open. ---- */
.logo{display:inline-flex;align-items:center;gap:11px}
.mk{display:grid;grid-template-columns:repeat(3,1fr);gap:3px;flex:0 0 auto}
.mk i{display:block;width:7px;height:7px;border-radius:2px;background:var(--faint);opacity:.75}
.mk i.on{background:var(--acc);opacity:1}
/* The wordmark rides the body step at its small size, and the large lockup keeps
   its own number because it is sized to the mark's 11px cells rather than to the
   text around it (docs/DESIGN.md section 1). */
.logo .wm{font-family:"Space Grotesk",sans-serif;font-weight:600;font-size:var(--fs-body);
  letter-spacing:-.01em;color:var(--ink-str)}
.logo.lg .mk i{width:11px;height:11px;border-radius:3px}
.logo.lg .mk{gap:4px}
.logo.lg .wm{font-size:22px}

/* ---- status, the Tag treatment (docs/DESIGN.md section 3) ---- */
/* ---- status: one box, one word ----
   Revised 2026-08-15. It used to be two elements, a mono abbreviation in a
   hairline box plus the full word beside it. Two problems, both the owner's:
   the abbreviation was keyed off the *tone* rather than the state, so
   "never reviewed" and "stale rule" both printed NEW and "unknown" and
   "paused" both printed --, which is why the set never looked uniform. And
   two elements read as two facts, which invited "what does NO mean".
   Now the word is the tag. It sits inside the frame, one element, and the
   tone is the border and the ink and never the only signal. */
.st{display:inline-flex;align-items:center;font-family:"IBM Plex Mono",monospace;
  font-size:var(--fs-micro);letter-spacing:.11em;text-transform:uppercase;white-space:nowrap;
  border:1px solid var(--line2);color:var(--muted);border-radius:3px;padding:3px 8px}
.st.warn{border-color:var(--warn);color:var(--warn)}
.st.fail{border-color:var(--fail);color:var(--fail);font-weight:600;
  box-shadow:0 0 0 3px var(--fail-soft)}
.st.off{border-color:var(--line);color:var(--faint)}
/* healthy stays quiet (DESIGN.md section 3). intended keeps the green ink
   the owner kept from an earlier project, inside a neutral frame, so twenty
   good rows
   never become a wall of green the broken row has to compete with. No fill
   and no added weight, ever. */
.st.ok{border-color:var(--line2);color:var(--ok)}
/* A row and a host header carry two of these when a server has a finding AND
   something to say about how it is watched (docs/DESIGN.md section 3: both
   axes use the same box, and docs/RECORD.md 4.115). They are two facts, so
   they are two tags, and the only thing needed is that they do not touch. The
   gap is the flags' own 8px, so a state with a status beside it and a state
   with a flag beside it are spaced the same way. */
.st+.st{margin-left:8px}

/* ---- planned: shown, never clickable. The owner: v1 is clickable, the rest is
   marked planned and the button does not work. ---- */
.planned{position:relative;opacity:.5;cursor:not-allowed}
/* .tag-rate is the rate-limit flag (docs/DESIGN.md section 3): a neutral flag
   beside a port's state, never a status. It shares .tag-planned's shape, the
   one treatment that sits beside a label without being one, so the shape stays
   a single fact. Neutral is the point, a status colour would read as blame and
   docs/PRODUCT.md 8c says a rate limit is blamed for nothing. */
/* .tag-rvw is the review mark and takes the same shape for the same reason: a
   second fact beside a port's state, never a state. An acknowledgement decides
   nothing and stops applying the moment the state changes, so it must not
   borrow a status colour and must not look like one of the five words. */
/* .tag-mute is the muted mark and .tag-rec the suggested choice in a picker,
   the same shape again each time: one small neutral word beside a label or a
   state, and the word is the whole statement. A mute is a fact
   about a server sitting beside its state, never a sixth state, because a
   muted host still reports, and both stay neutral since neither is a problem. */
/* .tag-mode is how a server is watched, the same shape once more and for the
   same reason: one small neutral word beside a label, never a state. Which way
   a server is watched is not a problem, so it takes no status colour. */
/* .tag-alert is the open-alert mark on a fleet row, the shape a sixth time.
   Neutral for the same reason as the rest: the State cell already carries
   this row's tone (docs/RECORD.md 4.115), so a status colour here would be a
   second one competing with it. */
/* .tag-disagree is the mark for two vantages whose newest measurements of
   one port differ (docs/PRODUCT.md 8e): a fact about the measurement beside
   the prober's word, never a state and never a tone, the rate flag's shape. */
.tag-planned,.tag-rate,.tag-rvw,.tag-mute,.tag-rec,.tag-mode,.tag-alert,.tag-disagree{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);letter-spacing:.1em;
  text-transform:uppercase;color:var(--faint);border:1px solid var(--line2);
  border-radius:3px;padding:2px 7px;margin-left:8px;white-space:nowrap}
/* The two facts that can sit beside a port's state step down below the status
   tag: same word size, which is already the scale's smallest, in a tighter box
   with tighter tracking. So a state with a fact beside it reads as exactly
   that and never as two states (docs/DESIGN.md section 3: smaller than the
   status tag). */
.tag-rate,.tag-rvw,.tag-mute,.tag-mode,.tag-disagree{letter-spacing:.08em;padding:1px 6px}
/* Written on every row and filled by the click, so an unreviewed row must not
   draw the empty box. */
.tag-rvw:empty{display:none}
/* The muted mark is written empty on every header and fleet row for the same
   reason: the mute click fills it in place, so the result shows at once. */
.tag-mute:empty{display:none}
/* An open alert is the fail tone on the Fleet row (the owner, 2026-09-08). */
.tag-alert{border-color:var(--fail);color:var(--fail)}

/* ---- controls ---- */
/* Sentence case, not tracked caps. Every artboard the owner chose in the 2026-08
   rounds used this, and the app shipped the tracked uppercase version, which is
   most of what he meant by the type being too big and not uniform. */
.btn{font-family:inherit;font-size:var(--fs-meta);font-weight:600;
  padding:8px 15px;border-radius:99px;border:1px solid var(--line2);background:var(--panel);
  color:var(--ink);cursor:pointer;transition:all var(--quick) var(--ease);white-space:nowrap}
.btn:hover:not(:disabled){background:var(--hover);border-color:var(--faint)}
.btn.pri{background:var(--acc-fill);border-color:var(--acc-fill);color:var(--on-fill)}
.btn.pri:hover:not(:disabled){background:var(--acc-fill);border-color:var(--acc-fill);
  color:var(--on-fill);filter:brightness(1.12)}
.btn:disabled{opacity:.45;cursor:not-allowed}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);
  overflow:hidden}
"""
BASE = css_without_comments(BASE)


def mark(lit=4, big=False):
    """Six slots, one lit. Default is the fifth slot, matching the logo file."""
    cells = "".join(f'<i class="on"></i>' if i == lit else "<i></i>" for i in range(6))
    return (f'<span class="logo{" lg" if big else ""}"><span class="mk">{cells}</span>'
            f'<span class="wm">whichports</span></span>')


# ---------------------------------------------------------------- the favicon
# The same mark as `mark()` above, drawn on its own ground so it reads on any
# browser tab. docs/DESIGN.md section 1 owns the mark and these colours.
#
# Why a ground rather than bare cells: a favicon is painted on the browser's
# tab strip, which is neither our light page nor our dark one, and a mark that
# adapts with `prefers-color-scheme` would still have to guess. Carrying its
# own background means one file answers both, and it is the same trade every
# app icon makes.
#
# Two files ship, from one geometry. SVG is the sharp one at any size. PNG is
# there because Safari renders an SVG icon only from version 26, released 2025
# (caniuse.com/link-icon-svg), and everything older ignores it.
ICON_SIZE = 32           # the SVG viewBox, and the PNG's pixel size
ICON_GROUND = "#0D0E14"  # --bg on dark, the primary mode
ICON_DIM = "#666A7C"     # --faint on dark, the five closed ports
ICON_LIT = "#9799CA"     # --acc on dark, the one that is open
ICON_DIM_ALPHA = 0.75    # what `.mk i` fades a dimmed cell to, see BASE above
_PLATE_R = 6             # the ground's corner radius
_CELL = 7                # a port, square
_CELL_R = 2
_GAP = 3


def _blend(fg, bg, alpha):
    """`fg` at `alpha` over an opaque `bg`, as a hex string.

    The dimmed cells are faded in CSS. Flattening that here rather than
    carrying an opacity into both files keeps the SVG and the PNG the same
    picture, and keeps the rasteriser below dealing in opaque colours only.
    """
    f, b = _rgb(fg), _rgb(bg)
    return "#%02X%02X%02X" % tuple(
        round(f[i] * alpha + b[i] * (1 - alpha)) for i in range(3))


def _icon_cells():
    """The six cells as (x, y, size, radius, colour), the lit one included.

    Three across, two down, centred on the square canvas. Same grid and same
    lit slot as the CSS mark, so the tab and the top bar agree.
    """
    dim = _blend(ICON_DIM, ICON_GROUND, ICON_DIM_ALPHA)
    grid_w = 3 * _CELL + 2 * _GAP
    grid_h = 2 * _CELL + _GAP
    x0 = (ICON_SIZE - grid_w) / 2
    y0 = (ICON_SIZE - grid_h) / 2
    out = []
    for i in range(6):
        x = x0 + (i % 3) * (_CELL + _GAP)
        y = y0 + (i // 3) * (_CELL + _GAP)
        out.append((x, y, _CELL, _CELL_R, ICON_LIT if i == 4 else dim))
    return out


def favicon_svg():
    """The mark as a standalone SVG document."""
    cells = "".join(
        f'<rect x="{x:g}" y="{y:g}" width="{s}" height="{s}" rx="{r}" fill="{c}"/>'
        for x, y, s, r, c in _icon_cells())
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{ICON_SIZE}" '
            f'height="{ICON_SIZE}" viewBox="0 0 {ICON_SIZE} {ICON_SIZE}">'
            f'<rect width="{ICON_SIZE}" height="{ICON_SIZE}" rx="{_PLATE_R}" '
            f'fill="{ICON_GROUND}"/>{cells}</svg>\n')


def _in_rounded_rect(px, py, x, y, w, h, r):
    """Is the point inside the rounded rectangle?

    A rounded rectangle is every point within `r` of the smaller rectangle
    inset by `r`, so clamp the point into that inner rectangle and measure.
    """
    cx = min(max(px, x + r), x + w - r)
    cy = min(max(py, y + r), y + h - r)
    return (px - cx) ** 2 + (py - cy) ** 2 <= r * r


def _icon_pixels(size, samples=4):
    """Rasterise the mark to straight-alpha RGBA rows.

    Every edge is antialiased by taking `samples` by `samples` points per
    pixel and averaging what they hit. The shapes are opaque, so a pixel's
    colour is the mean of the samples that landed on something and its alpha
    is the share of samples that did.
    """
    cells = _icon_cells()
    scale = ICON_SIZE / size
    rows = []
    for py in range(size):
        row = bytearray()
        for px in range(size):
            hits = []
            for sy in range(samples):
                for sx in range(samples):
                    ux = (px + (sx + 0.5) / samples) * scale
                    uy = (py + (sy + 0.5) / samples) * scale
                    hits.append(_sample_colour(ux, uy, cells))
            opaque = [h for h in hits if h is not None]
            if not opaque:
                row += b"\x00\x00\x00\x00"
                continue
            for channel in (0, 1, 2):
                row.append(round(sum(h[channel] for h in opaque) / len(opaque)))
            row.append(round(255 * len(opaque) / len(hits)))
        rows.append(bytes(row))
    return rows


def _sample_colour(ux, uy, cells):
    """The colour at one point in icon space, or None where nothing is drawn."""
    for x, y, s, r, colour in cells:
        if _in_rounded_rect(ux, uy, x, y, s, s, r):
            return _rgb(colour)
    if _in_rounded_rect(ux, uy, 0, 0, ICON_SIZE, ICON_SIZE, _PLATE_R):
        return _rgb(ICON_GROUND)
    return None


def _rgb(h):
    return (int(h[1:3], 16), int(h[3:5], 16), int(h[5:7], 16))


def _png_chunk(kind, payload):
    return (struct.pack(">I", len(payload)) + kind + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF))


def favicon_png(size=ICON_SIZE):
    """The same mark as a PNG, written with the standard library alone.

    Colour type 6 is 8 bit RGBA, filter 0 is "no filter" on every row, which
    is what the leading zero byte says. A 32 pixel icon does not need the
    filters to compress well and leaving them out keeps this readable.
    """
    rows = _icon_pixels(size)
    raw = b"".join(b"\x00" + row for row in rows)
    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n"
            + _png_chunk(b"IHDR", header)
            + _png_chunk(b"IDAT", zlib.compress(raw, 9))
            + _png_chunk(b"IEND", b""))


# The two lines every page that carries the mark puts in its head. Relative
# hrefs on purpose: the dashboard and the landing serve them from their own
# directory root, and nothing here should assume a hostname.
ICON_LINKS = ('<link rel="icon" href="favicon.svg" type="image/svg+xml">\n'
              '<link rel="icon" href="favicon-32.png" sizes="32x32">')


def write_icons(dist):
    """Drop both icon files into a built site directory."""
    (dist / "favicon.svg").write_text(favicon_svg())
    (dist / "favicon-32.png").write_bytes(favicon_png())


def status(tone, word):
    """The Tag treatment: one hairline box holding the word.

    The word is the signal and the tone is the second channel, so a state
    still reads printed in grey. There is deliberately no abbreviation: the
    old one was derived from the tone, so two different states with the same
    tone printed the same three letters, and a reader had to already know
    what NO meant to get anything from it.

    `word` is presented uppercase by CSS rather than here, so callers keep
    passing ordinary prose and the vocabulary stays readable in the source.
    """
    if tone not in ("ok", "warn", "fail", "off"):
        raise ValueError(f"unknown status tone {tone!r}")
    return f'<span class="st {tone}">{word}</span>'


# ---------------------------------------------------------------- icons
# Two sources, both inlined as path data so a glyph inherits currentColor and
# costs no request, the same reason an earlier project of the author's
# inlined them. The licences and
# the trademark position are in THIRD_PARTY_NOTICES.md, which is the one file
# that owns them.
#
# Phosphor Icons, regular weight, MIT, from @phosphor-icons/core 2.1.1
# (phosphoricons.com), drawn on a 256 grid. Every glyph that names a kind of
# thing rather than a product comes from here.
#
# Simple Icons 16.28.0 (simpleicons.org), CC0 1.0, drawn on a 24 grid. Vendor
# brand marks only, and only the three in BRAND_MARKS below.
#
# Never an icon that claims a verdict: no tick, seal, shield or padlock
# (DESIGN.md section 3, no tick glyphs anywhere).
ICONS = {
    "x": "M205.66,194.34a8,8,0,0,1-11.32,11.32L128,139.31,61.66,205.66a8,8,0,0,1-11.32-11.32L116.69,128,50.34,61.66A8,8,0,0,1,61.66,50.34L128,116.69l66.34-66.35a8,8,0,0,1,11.32,11.32L139.31,128Z",
    "sign-out": "M120,216a8,8,0,0,1-8,8H48a8,8,0,0,1-8-8V40a8,8,0,0,1,8-8h64a8,8,0,0,1,0,16H56V208h56A8,8,0,0,1,120,216Zm109.66-93.66-40-40a8,8,0,0,0-11.32,11.32L204.69,120H112a8,8,0,0,0,0,16h92.69l-26.35,26.34a8,8,0,0,0,11.32,11.32l40-40A8,8,0,0,0,229.66,122.34Z",
    "user-circle": "M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24ZM74.08,197.5a64,64,0,0,1,107.84,0,87.83,87.83,0,0,1-107.84,0ZM96,120a32,32,0,1,1,32,32A32,32,0,0,1,96,120Zm97.76,66.41a79.66,79.66,0,0,0-36.06-28.75,48,48,0,1,0-59.4,0,79.66,79.66,0,0,0-36.06,28.75,88,88,0,1,1,131.52,0Z",
    "users": "M117.25,157.92a60,60,0,1,0-66.5,0A95.83,95.83,0,0,0,3.53,195.63a8,8,0,1,0,13.4,8.74,80,80,0,0,1,134.14,0,8,8,0,0,0,13.4-8.74A95.83,95.83,0,0,0,117.25,157.92ZM40,108a44,44,0,1,1,44,44A44.05,44.05,0,0,1,40,108Zm210.14,98.7a8,8,0,0,1-11.07-2.33A79.83,79.83,0,0,0,172,168a8,8,0,0,1,0-16,44,44,0,1,0-16.34-84.87,8,8,0,1,1-5.94-14.85,60,60,0,0,1,55.53,105.64,95.83,95.83,0,0,1,47.22,37.71A8,8,0,0,1,250.14,206.7Z",
    "credit-card": "M224,48H32A16,16,0,0,0,16,64V192a16,16,0,0,0,16,16H224a16,16,0,0,0,16-16V64A16,16,0,0,0,224,48Zm0,16V88H32V64Zm0,128H32V104H224v88Zm-16-24a8,8,0,0,1-8,8H168a8,8,0,0,1,0-16h32A8,8,0,0,1,208,168Zm-64,0a8,8,0,0,1-8,8H120a8,8,0,0,1,0-16h16A8,8,0,0,1,144,168Z",
    "linux-logo": "M229,214.25A8,8,0,0,1,217.76,213C216.39,211.27,184,169.86,184,88A56,56,0,0,0,72,88c0,81.86-32.37,123.27-33.75,125a8,8,0,0,1-12.51-10c.15-.2,7.69-9.9,15.13-28.74C47.77,156.8,56,127.64,56,88a72,72,0,0,1,144,0c0,39.64,8.23,68.8,15.13,86.28,7.48,18.94,15.06,28.64,15.14,28.74A8,8,0,0,1,229,214.25ZM100,88a12,12,0,1,0,12,12A12,12,0,0,0,100,88Zm68,12a12,12,0,1,0-12,12A12,12,0,0,0,168,100ZM99.58,128.84a8,8,0,0,0-7.15,14.31l32,16a7.94,7.94,0,0,0,7.15,0l32-16a8,8,0,0,0-7.16-14.31L128,143.05ZM128,176a54.07,54.07,0,0,0-47,28.11,8,8,0,1,0,14,7.78,37.35,37.35,0,0,1,66,0,8,8,0,0,0,14-7.78A54.07,54.07,0,0,0,128,176Z",
    "windows-logo": "M208,136H128a8,8,0,0,0-8,8v57.45a8,8,0,0,0,6.57,7.88l80,14.54A7.61,7.61,0,0,0,208,224a8,8,0,0,0,8-8V144A8,8,0,0,0,208,136Zm-8,70.41-64-11.63V152h64ZM96,136H32a8,8,0,0,0-8,8v40a8,8,0,0,0,6.57,7.87l64,11.64a8.54,8.54,0,0,0,1.43.13,8,8,0,0,0,8-8V144A8,8,0,0,0,96,136Zm-8,50.05-48-8.73V152H88ZM213.13,33.86a8,8,0,0,0-6.56-1.73l-80,14.55A8,8,0,0,0,120,54.55V112a8,8,0,0,0,8,8h80a8,8,0,0,0,8-8V40A8,8,0,0,0,213.13,33.86ZM200,104H136V61.22l64-11.63ZM101.13,54.22a8,8,0,0,0-6.56-1.73l-64,11.64A8,8,0,0,0,24,72v40a8,8,0,0,0,8,8H96a8,8,0,0,0,8-8V60.36A8,8,0,0,0,101.13,54.22ZM88,104H40V78.68L88,70Z",
    "hard-drives": "M208,136H48a16,16,0,0,0-16,16v48a16,16,0,0,0,16,16H208a16,16,0,0,0,16-16V152A16,16,0,0,0,208,136Zm0,64H48V152H208v48Zm0-160H48A16,16,0,0,0,32,56v48a16,16,0,0,0,16,16H208a16,16,0,0,0,16-16V56A16,16,0,0,0,208,40Zm0,64H48V56H208v48ZM192,80a12,12,0,1,1-12-12A12,12,0,0,1,192,80Zm0,96a12,12,0,1,1-12-12A12,12,0,0,1,192,176Z",
    # The Rules tab's two firewalls that are not the host's own
    # (docs/screens/host-rules/SPEC.md): a cube for what a container runtime
    # publishes, and a wall for the empty answer. The wall is drawn slashed
    # there, the way the empty Fleet slashes these drives, and it is the
    # glyph the sketch drew a shield for. A shield is the one picture this
    # product may not use, whatever the slash says about it: it claims a
    # verdict, which is section 3 above and DESIGN.md section 3.
    # The service at the right end of the packet path, when it is a process
    # rather than a container (docs/screens/host-packet-path/SPEC.md).
    "app-window": "M216,40H40A16,16,0,0,0,24,56V200a16,16,0,0,0,16,16H216a16,16,0,0,0,16-16V56A16,16,0,0,0,216,40Zm0,160H40V56H216V200ZM80,84A12,12,0,1,1,68,72,12,12,0,0,1,80,84Zm40,0a12,12,0,1,1-12-12A12,12,0,0,1,120,84Z",
    "cube": "M223.68,66.15,135.68,18h0a15.88,15.88,0,0,0-15.36,0l-88,48.17a16,16,0,0,0-8.32,14v95.64a16,16,0,0,0,8.32,14l88,48.17a15.88,15.88,0,0,0,15.36,0l88-48.17a16,16,0,0,0,8.32-14V80.18A16,16,0,0,0,223.68,66.15ZM128,32h0l80.34,44L128,120,47.66,76ZM40,90l80,43.78v85.79L40,175.82Zm96,129.57V133.82L216,90v85.78Z",
    # The copy glyph on a name a window asks to be typed. Phosphor 2.1.1, like
    # everything above.
    "copy": "M216,32H88a8,8,0,0,0-8,8V80H40a8,8,0,0,0-8,8V216a8,8,0,0,0,8,8H168a8,8,0,0,0,8-8V176h40a8,8,0,0,0,8-8V40A8,8,0,0,0,216,32ZM160,208H48V96H160Zm48-48H176V88a8,8,0,0,0-8-8H96V48H208Z",
    "wall": "M224,48H32a8,8,0,0,0-8,8V200a8,8,0,0,0,8,8H224a8,8,0,0,0,8-8V56A8,8,0,0,0,224,48ZM88,144V112h80v32Zm-48,0V112H72v32Zm144-32h32v32H184Zm32-16H136V64h80ZM120,64V96H40V64ZM40,160h80v32H40Zm96,32V160h80v32Z",
    "download-simple": "M224,144v64a8,8,0,0,1-8,8H40a8,8,0,0,1-8-8V144a8,8,0,0,1,16,0v56H208V144a8,8,0,0,1,16,0Zm-101.66,5.66a8,8,0,0,0,11.32,0l40-40a8,8,0,0,0-11.32-11.32L136,124.69V32a8,8,0,0,0-16,0v92.69L93.66,98.34a8,8,0,0,0-11.32,11.32Z",
    "eye": "M247.31,124.76c-.35-.79-8.82-19.58-27.65-38.41C194.57,61.26,162.88,48,128,48S61.43,61.26,36.34,86.35C17.51,105.18,9,124,8.69,124.76a8,8,0,0,0,0,6.5c.35.79,8.82,19.57,27.65,38.4C61.43,194.74,93.12,208,128,208s66.57-13.26,91.66-38.34c18.83-18.83,27.3-37.61,27.65-38.4A8,8,0,0,0,247.31,124.76ZM128,192c-30.78,0-57.67-11.19-79.93-33.25A133.47,133.47,0,0,1,25,128,133.33,133.33,0,0,1,48.07,97.25C70.33,75.19,97.22,64,128,64s57.67,11.19,79.93,33.25A133.46,133.46,0,0,1,231.05,128C223.84,141.46,192.43,192,128,192Zm0-112a48,48,0,1,0,48,48A48.05,48.05,0,0,0,128,80Zm0,80a32,32,0,1,1,32-32A32,32,0,0,1,128,160Z",
    # The Fleet's Agent column, decided 2026-09-03 (docs/screens/fleet/SPEC.md
    # section 5): binoculars for a full read, a magnifying glass for a limited
    # one, and globe-hemisphere-west below for a server watched from outside.
    "binoculars": "M237.2,151.87v0a47.1,47.1,0,0,0-2.35-5.45L193.26,51.8a7.82,7.82,0,0,0-1.66-2.44,32,32,0,0,0-45.26,0A8,8,0,0,0,144,55V80H112V55a8,8,0,0,0-2.34-5.66,32,32,0,0,0-45.26,0,7.82,7.82,0,0,0-1.66,2.44L21.15,146.4a47.1,47.1,0,0,0-2.35,5.45v0A48,48,0,1,0,112,168V96h32v72a48,48,0,1,0,93.2-16.13ZM76.71,59.75a16,16,0,0,1,19.29-1v73.51a47.9,47.9,0,0,0-46.79-9.92ZM64,200a32,32,0,1,1,32-32A32,32,0,0,1,64,200ZM160,58.74a16,16,0,0,1,19.29,1l27.5,62.58A47.9,47.9,0,0,0,160,132.25ZM192,200a32,32,0,1,1,32-32A32,32,0,0,1,192,200Z",
    "magnifying-glass": "M229.66,218.34l-50.07-50.06a88.11,88.11,0,1,0-11.31,11.31l50.06,50.07a8,8,0,0,0,11.32-11.32ZM40,112a72,72,0,1,1,72,72A72.08,72.08,0,0,1,40,112Z",
    # The caret a Host Overview row opens on (docs/screens/host-overview).
    # The Add server window's one mark, a step being waited for
    # (docs/screens/add-server/BRIEF-arrival.md). Phosphor regular, read from
    # phosphor-icons/core on 2026-09-20. A step that is done has no mark:
    # docs/DESIGN.md section 3 allows no tick anywhere.
    "circle-notch": "M232,128a104,104,0,0,1-208,0c0-41,23.81-78.36,60.66-95.27a8,8,0,0,1,6.68,14.54C60.15,61.59,40,93.27,40,128a88,88,0,0,0,176,0c0-34.73-20.15-66.41-51.34-80.73a8,8,0,0,1,6.68-14.54C208.19,49.64,232,87,232,128Z",
    "caret-down": "M213.66,101.66l-80,80a8,8,0,0,1-11.32,0l-80-80A8,8,0,0,1,53.66,90.34L128,164.69l74.34-74.35a8,8,0,0,1,11.32,11.32Z",
    # The CVE check's own mark beside a port's state (docs/SPEC-cve-check.md,
    # section 8.1). Phosphor regular, read from phosphor-icons/core on
    # 2026-10-09. The glyph is the sketch's and is not decided.
    "arrow-circle-up": "M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm0,192a88,88,0,1,1,88-88A88.1,88.1,0,0,1,128,216Zm37.66-101.66a8,8,0,0,1-11.32,11.32L136,107.31V168a8,8,0,0,1-16,0V107.31l-18.34,18.35a8,8,0,0,1-11.32-11.32l32-32a8,8,0,0,1,11.32,0Z",
    # the Alerts screen (docs/screens/alerts)
    "bell": "M221.8,175.94C216.25,166.38,208,139.33,208,104a80,80,0,1,0-160,0c0,35.34-8.26,62.38-13.81,71.94A16,16,0,0,0,48,200H88.81a40,40,0,0,0,78.38,0H208a16,16,0,0,0,13.8-24.06ZM128,216a24,24,0,0,1-22.62-16h45.24A24,24,0,0,1,128,216ZM48,184c7.7-13.24,16-43.92,16-80a64,64,0,1,1,128,0c0,36.05,8.28,66.73,16,80Z",
    "bell-slash": "M53.92,34.62A8,8,0,1,0,42.08,45.38L58.82,63.8A79.59,79.59,0,0,0,48,104c0,35.34-8.26,62.38-13.81,71.94A16,16,0,0,0,48,200H88.8a40,40,0,0,0,78.4,0h15.44l19.44,21.38a8,8,0,1,0,11.84-10.76ZM128,216a24,24,0,0,1-22.62-16h45.24A24,24,0,0,1,128,216ZM48,184c7.7-13.24,16-43.92,16-80a63.65,63.65,0,0,1,6.26-27.62L168.09,184Zm166-4.73a8.13,8.13,0,0,1-2.93.55,8,8,0,0,1-7.44-5.08C196.35,156.19,192,129.75,192,104A64,64,0,0,0,96.43,48.31a8,8,0,0,1-7.9-13.91A80,80,0,0,1,208,104c0,35.35,8.05,58.59,10.52,64.88A8,8,0,0,1,214,179.25Z",
    "dots-three-vertical": "M140,128a12,12,0,1,1-12-12A12,12,0,0,1,140,128ZM128,72a12,12,0,1,0-12-12A12,12,0,0,0,128,72Zm0,112a12,12,0,1,0,12,12A12,12,0,0,0,128,184Z",
    # the Integrations screen (docs/screens/integrations): the slashed plugs
    # of its empty state, a neutral cloud for a provider the set has no mark
    # for, and the arrow on the Docs button
    "plugs": "M149.66,138.34a8,8,0,0,0-11.32,0L120,156.69,99.31,136l18.35-18.34a8,8,0,0,0-11.32-11.32L88,124.69,69.66,106.34a8,8,0,0,0-11.32,11.32L64.69,124,41.37,147.31a32,32,0,0,0,0,45.26l5.38,5.37-28.41,28.4a8,8,0,0,0,11.32,11.32l28.4-28.41,5.37,5.38a32,32,0,0,0,45.26,0L132,191.31l6.34,6.35a8,8,0,0,0,11.32-11.32L131.31,168l18.35-18.34A8,8,0,0,0,149.66,138.34Zm-52.29,65a16,16,0,0,1-22.62,0L52.69,181.25a16,16,0,0,1,0-22.62L76,135.31,120.69,180Zm140.29-185a8,8,0,0,0-11.32,0l-28.4,28.41-5.37-5.38a32.05,32.05,0,0,0-45.26,0L124,64.69l-6.34-6.35a8,8,0,0,0-11.32,11.32l80,80a8,8,0,0,0,11.32-11.32L191.31,132l23.32-23.31a32,32,0,0,0,0-45.26l-5.38-5.37,28.41-28.4A8,8,0,0,0,237.66,18.34Zm-34.35,79L180,120.69,135.31,76l23.32-23.31a16,16,0,0,1,22.62,0l22.06,22A16,16,0,0,1,203.31,97.37Z",
    "cloud": "M160,40A88.09,88.09,0,0,0,81.29,88.67,64,64,0,1,0,72,216h88a88,88,0,0,0,0-176Zm0,160H72a48,48,0,0,1,0-96c1.1,0,2.2,0,3.29.11A88,88,0,0,0,72,128a8,8,0,0,0,16,0,72,72,0,1,1,72,72Z",
    "arrow-square-out": "M224,104a8,8,0,0,1-16,0V59.32l-66.33,66.34a8,8,0,0,1-11.32-11.32L196.68,48H152a8,8,0,0,1,0-16h64a8,8,0,0,1,8,8Zm-40,24a8,8,0,0,0-8,8v72H48V80h72a8,8,0,0,0,0-16H48A16,16,0,0,0,32,80V208a16,16,0,0,0,16,16H176a16,16,0,0,0,16-16V136A8,8,0,0,0,184,128Z",
    # the account Settings (docs/screens/account-settings)
    "laptop": "M232,168h-8V72a24,24,0,0,0-24-24H56A24,24,0,0,0,32,72v96H24a8,8,0,0,0-8,8v16a24,24,0,0,0,24,24H216a24,24,0,0,0,24-24V176A8,8,0,0,0,232,168ZM48,72a8,8,0,0,1,8-8H200a8,8,0,0,1,8,8v96H48ZM224,192a8,8,0,0,1-8,8H40a8,8,0,0,1-8-8v-8H224ZM152,88a8,8,0,0,1-8,8H112a8,8,0,0,1,0-16h32A8,8,0,0,1,152,88Z",
    "receipt": "M72,104a8,8,0,0,1,8-8h96a8,8,0,0,1,0,16H80A8,8,0,0,1,72,104Zm8,40h96a8,8,0,0,0,0-16H80a8,8,0,0,0,0,16ZM232,56V208a8,8,0,0,1-11.58,7.15L192,200.94l-28.42,14.21a8,8,0,0,1-7.16,0L128,200.94,99.58,215.15a8,8,0,0,1-7.16,0L64,200.94,35.58,215.15A8,8,0,0,1,24,208V56A16,16,0,0,1,40,40H216A16,16,0,0,1,232,56Zm-16,0H40V195.06l20.42-10.22a8,8,0,0,1,7.16,0L96,199.06l28.42-14.22a8,8,0,0,1,7.16,0L160,199.06l28.42-14.22a8,8,0,0,1,7.16,0L216,195.06Z",
    "moon": "M240,96a8,8,0,0,1-8,8H216v16a8,8,0,0,1-16,0V104H184a8,8,0,0,1,0-16h16V72a8,8,0,0,1,16,0V88h16A8,8,0,0,1,240,96ZM144,56h8v8a8,8,0,0,0,16,0V56h8a8,8,0,0,0,0-16h-8V32a8,8,0,0,0-16,0v8h-8a8,8,0,0,0,0,16Zm72.77,97a8,8,0,0,1,1.43,8A96,96,0,1,1,95.07,37.8a8,8,0,0,1,10.6,9.06A88.07,88.07,0,0,0,209.14,150.33,8,8,0,0,1,216.77,153Zm-19.39,14.88c-1.79.09-3.59.14-5.38.14A104.11,104.11,0,0,1,88,64c0-1.79,0-3.59.14-5.38A80,80,0,1,0,197.38,167.86Z",
    # the server settings rail and rows (docs/screens/host-settings)
    "key": "M216.57,39.43A80,80,0,0,0,83.91,120.78L28.69,176A15.86,15.86,0,0,0,24,187.31V216a16,16,0,0,0,16,16H72a8,8,0,0,0,8-8V208H96a8,8,0,0,0,8-8V184h16a8,8,0,0,0,5.66-2.34l9.56-9.57A79.73,79.73,0,0,0,160,176h.1A80,80,0,0,0,216.57,39.43ZM224,98.1c-1.09,34.09-29.75,61.86-63.89,61.9H160a63.7,63.7,0,0,1-23.65-4.51,8,8,0,0,0-8.84,1.68L116.69,168H96a8,8,0,0,0-8,8v16H72a8,8,0,0,0-8,8v16H40V187.31l58.83-58.82a8,8,0,0,0,1.68-8.84A63.72,63.72,0,0,1,96,95.92c0-34.14,27.81-62.8,61.9-63.89A64,64,0,0,1,224,98.1ZM192,76a12,12,0,1,1-12-12A12,12,0,0,1,192,76Z",
    "time": "M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm0,192a88,88,0,1,1,88-88A88.1,88.1,0,0,1,128,216Zm64-88a8,8,0,0,1-8,8H128a8,8,0,0,1-8-8V72a8,8,0,0,1,16,0v48h48A8,8,0,0,1,192,128Z",
    "pause": "M200,32H160a16,16,0,0,0-16,16V208a16,16,0,0,0,16,16h40a16,16,0,0,0,16-16V48A16,16,0,0,0,200,32Zm0,176H160V48h40ZM96,32H56A16,16,0,0,0,40,48V208a16,16,0,0,0,16,16H96a16,16,0,0,0,16-16V48A16,16,0,0,0,96,32Zm0,176H56V48H96Z",
    "tag": "M243.31,136,144,36.69A15.86,15.86,0,0,0,132.69,32H40a8,8,0,0,0-8,8v92.69A15.86,15.86,0,0,0,36.69,144L136,243.31a16,16,0,0,0,22.63,0l84.68-84.68a16,16,0,0,0,0-22.63Zm-96,96L48,132.69V48h84.69L232,147.31ZM96,84A12,12,0,1,1,84,72,12,12,0,0,1,96,84Z",
    "plug": "M237.66,66.34a8,8,0,0,0-11.32,0L192,100.69,155.31,64l34.35-34.34a8,8,0,1,0-11.32-11.32L144,52.69,117.66,26.34a8,8,0,0,0-11.32,11.32L112.69,44l-53,53a40,40,0,0,0,0,56.57l15.71,15.71L26.34,218.34a8,8,0,0,0,11.32,11.32l49.09-49.09,15.71,15.71a40,40,0,0,0,56.57,0l53-53,6.34,6.35a8,8,0,0,0,11.32-11.32L203.31,112l34.35-34.34A8,8,0,0,0,237.66,66.34ZM147.72,185a24,24,0,0,1-33.95,0L71,142.23a24,24,0,0,1,0-33.95l53-53L200.69,132Z",
    "trash": "M216,48H176V40a24,24,0,0,0-24-24H104A24,24,0,0,0,80,40v8H40a8,8,0,0,0,0,16h8V208a16,16,0,0,0,16,16H192a16,16,0,0,0,16-16V64h8a8,8,0,0,0,0-16ZM96,40a8,8,0,0,1,8-8h48a8,8,0,0,1,8,8v8H96Zm96,168H64V64H192ZM112,104v64a8,8,0,0,1-16,0V104a8,8,0,0,1,16,0Zm48,0v64a8,8,0,0,1-16,0V104a8,8,0,0,1,16,0Z",
    "globe-hemisphere-west": "M128,24A104,104,0,1,0,232,128,104.11,104.11,0,0,0,128,24Zm88,104a87.62,87.62,0,0,1-6.4,32.94l-44.7-27.49a15.92,15.92,0,0,0-6.24-2.23l-22.82-3.08a16.11,16.11,0,0,0-16,7.86h-8.72l-3.8-7.86a15.91,15.91,0,0,0-11-8.67l-8-1.73L96.14,104h16.71a16.06,16.06,0,0,0,7.73-2l12.25-6.76a16.62,16.62,0,0,0,3-2.14l26.91-24.34A15.93,15.93,0,0,0,166,49.1l-.36-.65A88.11,88.11,0,0,1,216,128ZM143.31,41.34,152,56.9,125.09,81.24,112.85,88H96.14a16,16,0,0,0-13.88,8l-8.73,15.23L63.38,84.19,74.32,58.32a87.87,87.87,0,0,1,69-17ZM40,128a87.53,87.53,0,0,1,8.54-37.8l11.34,30.27a16,16,0,0,0,11.62,10l21.43,4.61L96.74,143a16.09,16.09,0,0,0,14.4,9h1.48l-7.23,16.23a16,16,0,0,0,2.86,17.37l.14.14L128,205.94l-1.94,10A88.11,88.11,0,0,1,40,128Zm102.58,86.78,1.13-5.81a16.09,16.09,0,0,0-4-13.9,1.85,1.85,0,0,1-.14-.14L120,174.74,133.7,144l22.82,3.08,45.72,28.12A88.18,88.18,0,0,1,142.58,214.78Z",
    # The alert channels and the integrations, added 2026-08-16. Same package,
    # same version, same regular weight as the eight above.
    #
    # Every one of these names a *kind of destination* rather than a product.
    # Three of the channels carry their vendor's own mark instead, see
    # BRAND_MARKS below, and the rest keep a neutral glyph either because there
    # is no brand to draw or because that brand's own guidelines rule the mark
    # out for us.
    "envelope-simple": "M224,48H32a8,8,0,0,0-8,8V192a16,16,0,0,0,16,16H216a16,16,0,0,0,16-16V56A8,8,0,0,0,224,48ZM203.43,64,128,133.15,52.57,64ZM216,192H40V74.19l82.59,75.71a8,8,0,0,0,10.82,0L216,74.19V192Z",
    "hash": "M224,88H175.4l8.47-46.57a8,8,0,0,0-15.74-2.86l-9,49.43H111.4l8.47-46.57a8,8,0,0,0-15.74-2.86L95.14,88H48a8,8,0,0,0,0,16H92.23L83.5,152H32a8,8,0,0,0,0,16H80.6l-8.47,46.57a8,8,0,0,0,6.44,9.3A7.79,7.79,0,0,0,80,224a8,8,0,0,0,7.86-6.57l9-49.43H144.6l-8.47,46.57a8,8,0,0,0,6.44,9.3A7.79,7.79,0,0,0,144,224a8,8,0,0,0,7.86-6.57l9-49.43H208a8,8,0,0,0,0-16H163.77l8.73-48H224a8,8,0,0,0,0-16Zm-76.5,64H99.77l8.73-48h47.73Z",
    "chat-circle-dots": "M140,128a12,12,0,1,1-12-12A12,12,0,0,1,140,128ZM84,116a12,12,0,1,0,12,12A12,12,0,0,0,84,116Zm88,0a12,12,0,1,0,12,12A12,12,0,0,0,172,116Zm60,12A104,104,0,0,1,79.12,219.82L45.07,231.17a16,16,0,0,1-20.24-20.24l11.35-34.05A104,104,0,1,1,232,128Zm-16,0A88,88,0,1,0,51.81,172.06a8,8,0,0,1,.66,6.54L40,216,77.4,203.53a7.85,7.85,0,0,1,2.53-.42,8,8,0,0,1,4,1.08A88,88,0,0,0,216,128Z",
    "chats-circle": "M232.07,186.76a80,80,0,0,0-62.5-114.17A80,80,0,1,0,23.93,138.76l-7.27,24.71a16,16,0,0,0,19.87,19.87l24.71-7.27a80.39,80.39,0,0,0,25.18,7.35,80,80,0,0,0,108.34,40.65l24.71,7.27a16,16,0,0,0,19.87-19.86ZM62,159.5a8.28,8.28,0,0,0-2.26.32L32,168l8.17-27.76a8,8,0,0,0-.63-6,64,64,0,1,1,26.26,26.26A8,8,0,0,0,62,159.5Zm153.79,28.73L224,216l-27.76-8.17a8,8,0,0,0-6,.63,64.05,64.05,0,0,1-85.87-24.88A79.93,79.93,0,0,0,174.7,89.71a64,64,0,0,1,41.75,92.48A8,8,0,0,0,215.82,188.23Z",
    "brackets-curly": "M43.18,128a29.78,29.78,0,0,1,8,10.26c4.8,9.9,4.8,22,4.8,33.74,0,24.31,1,36,24,36a8,8,0,0,1,0,16c-17.48,0-29.32-6.14-35.2-18.26-4.8-9.9-4.8-22-4.8-33.74,0-24.31-1-36-24-36a8,8,0,0,1,0-16c23,0,24-11.69,24-36,0-11.72,0-23.84,4.8-33.74C50.68,38.14,62.52,32,80,32a8,8,0,0,1,0,16C57,48,56,59.69,56,84c0,11.72,0,23.84-4.8,33.74A29.78,29.78,0,0,1,43.18,128ZM240,120c-23,0-24-11.69-24-36,0-11.72,0-23.84-4.8-33.74C205.32,38.14,193.48,32,176,32a8,8,0,0,0,0,16c23,0,24,11.69,24,36,0,11.72,0,23.84,4.8,33.74a29.78,29.78,0,0,0,8,10.26,29.78,29.78,0,0,0-8,10.26c-4.8,9.9-4.8,22-4.8,33.74,0,24.31-1,36-24,36a8,8,0,0,0,0,16c17.48,0,29.32-6.14,35.2-18.26,4.8-9.9,4.8-22,4.8-33.74,0-24.31,1-36,24-36a8,8,0,0,0,0-16Z",
    # The mark for a reachable port that should rarely face the internet
    # (docs/RECORD.md 4.248). Phosphor regular, read from the package's own
    # repository, assets/regular/warning.svg, on 2026-10-02.
    "warning": "M236.8,188.09,149.35,36.22h0a24.76,24.76,0,0,0-42.7,0L19.2,188.09a23.51,23.51,0,0,0,0,23.72A24.35,24.35,0,0,0,40.55,224h174.9a24.35,24.35,0,0,0,21.33-12.19A23.51,23.51,0,0,0,236.8,188.09ZM222.93,203.8a8.5,8.5,0,0,1-7.48,4.2H40.55a8.5,8.5,0,0,1-7.48-4.2,7.59,7.59,0,0,1,0-7.72L120.52,44.21a8.75,8.75,0,0,1,15,0l87.45,151.87A7.59,7.59,0,0,1,222.93,203.8ZM120,144V104a8,8,0,0,1,16,0v40a8,8,0,0,1-16,0Zm20,36a12,12,0,1,1-12-12A12,12,0,0,1,140,180Z",
    "bell-ringing": "M224,71.1a8,8,0,0,1-10.78-3.42,94.13,94.13,0,0,0-33.46-36.91,8,8,0,1,1,8.54-13.54,111.46,111.46,0,0,1,39.12,43.09A8,8,0,0,1,224,71.1ZM35.71,72a8,8,0,0,0,7.1-4.32A94.13,94.13,0,0,1,76.27,30.77a8,8,0,1,0-8.54-13.54A111.46,111.46,0,0,0,28.61,60.32,8,8,0,0,0,35.71,72Zm186.1,103.94A16,16,0,0,1,208,200H167.2a40,40,0,0,1-78.4,0H48a16,16,0,0,1-13.79-24.06C43.22,160.39,48,138.28,48,112a80,80,0,0,1,160,0C208,138.27,212.78,160.38,221.81,175.94ZM150.62,200H105.38a24,24,0,0,0,45.24,0ZM208,184c-10.64-18.27-16-42.49-16-72a64,64,0,0,0-128,0c0,29.52-5.38,53.74-16,72Z",
    "users-three": "M244.8,150.4a8,8,0,0,1-11.2-1.6A51.6,51.6,0,0,0,192,128a8,8,0,0,1-7.37-4.89,8,8,0,0,1,0-6.22A8,8,0,0,1,192,112a24,24,0,1,0-23.24-30,8,8,0,1,1-15.5-4A40,40,0,1,1,219,117.51a67.94,67.94,0,0,1,27.43,21.68A8,8,0,0,1,244.8,150.4ZM190.92,212a8,8,0,1,1-13.84,8,57,57,0,0,0-98.16,0,8,8,0,1,1-13.84-8,72.06,72.06,0,0,1,33.74-29.92,48,48,0,1,1,58.36,0A72.06,72.06,0,0,1,190.92,212ZM128,176a32,32,0,1,0-32-32A32,32,0,0,0,128,176ZM72,120a8,8,0,0,0-8-8A24,24,0,1,1,87.24,82a8,8,0,1,0,15.5-4A40,40,0,1,0,37,117.51,67.94,67.94,0,0,0,9.6,139.19a8,8,0,1,0,12.8,9.61A51.6,51.6,0,0,1,64,128,8,8,0,0,0,72,120Z",
    "chart-line": "M232,208a8,8,0,0,1-8,8H32a8,8,0,0,1-8-8V48a8,8,0,0,1,16,0v94.37L90.73,98a8,8,0,0,1,10.07-.38l58.81,44.11L218.73,90a8,8,0,1,1,10.54,12l-64,56a8,8,0,0,1-10.07.38L96.39,114.29,40,163.63V200H224A8,8,0,0,1,232,208Z",
    "gauge": "M207.06,72.67A111.24,111.24,0,0,0,128,40h-.4C66.07,40.21,16,91,16,153.13V176a16,16,0,0,0,16,16H224a16,16,0,0,0,16-16V152A111.25,111.25,0,0,0,207.06,72.67ZM224,176H119.71l54.76-75.3a8,8,0,0,0-12.94-9.42L99.92,176H32V153.13c0-3.08.15-6.12.43-9.13H56a8,8,0,0,0,0-16H35.27c10.32-38.86,44-68.24,84.73-71.66V80a8,8,0,0,0,16,0V56.33A96.14,96.14,0,0,1,221,128H200a8,8,0,0,0,0,16h23.67c.21,2.65.33,5.31.33,8Z",
    "pulse": "M240,128a8,8,0,0,1-8,8H204.94l-37.78,75.58A8,8,0,0,1,160,216h-.4a8,8,0,0,1-7.08-5.14L95.35,60.76,63.28,131.31A8,8,0,0,1,56,136H24a8,8,0,0,1,0-16H50.85L88.72,36.69a8,8,0,0,1,14.76.46l57.51,151,31.85-63.71A8,8,0,0,1,200,120h32A8,8,0,0,1,240,128Z",
    "broadcast": "M128,88a40,40,0,1,0,40,40A40,40,0,0,0,128,88Zm0,64a24,24,0,1,1,24-24A24,24,0,0,1,128,152Zm73.71,7.14a80,80,0,0,1-14.08,22.2,8,8,0,0,1-11.92-10.67,63.95,63.95,0,0,0,0-85.33,8,8,0,1,1,11.92-10.67,80.08,80.08,0,0,1,14.08,84.47ZM69,103.09a64,64,0,0,0,11.26,67.58,8,8,0,0,1-11.92,10.67,79.93,79.93,0,0,1,0-106.67A8,8,0,1,1,80.29,85.34,63.77,63.77,0,0,0,69,103.09ZM248,128a119.58,119.58,0,0,1-34.29,84,8,8,0,1,1-11.42-11.2,103.9,103.9,0,0,0,0-145.56A8,8,0,1,1,213.71,44,119.58,119.58,0,0,1,248,128ZM53.71,200.78A8,8,0,1,1,42.29,212a119.87,119.87,0,0,1,0-168,8,8,0,1,1,11.42,11.2,103.9,103.9,0,0,0,0,145.56Z",
    "plugs-connected": "M237.66,18.34a8,8,0,0,0-11.32,0l-52.4,52.41-5.37-5.38a32.05,32.05,0,0,0-45.26,0L100,88.69l-6.34-6.35A8,8,0,0,0,82.34,93.66L88.69,100,65.37,123.31a32,32,0,0,0,0,45.26l5.38,5.37-52.41,52.4a8,8,0,0,0,11.32,11.32l52.4-52.41,5.37,5.38a32,32,0,0,0,45.26,0L156,167.31l6.34,6.35a8,8,0,0,0,11.32-11.32L167.31,156l23.32-23.31a32,32,0,0,0,0-45.26l-5.38-5.37,52.41-52.4A8,8,0,0,0,237.66,18.34Zm-116.29,161a16,16,0,0,1-22.62,0L76.69,157.25a16,16,0,0,1,0-22.62L100,111.31,144.69,156Zm57.94-57.94L156,144.69,111.31,100l23.32-23.31a16,16,0,0,1,22.62,0l22.06,22A16,16,0,0,1,179.31,121.37ZM88.57,35A8,8,0,0,1,103.43,29l8,20A8,8,0,0,1,96.57,55ZM24.57,93A8,8,0,0,1,35,88.57l20,8A8,8,0,0,1,49,111.43l-20-8A8,8,0,0,1,24.57,93ZM231.43,163a8,8,0,0,1-10.4,4.46l-20-8A8,8,0,1,1,207,144.57l20,8A8,8,0,0,1,231.43,163Zm-64,58.06A8,8,0,0,1,152.57,227l-8-20A8,8,0,0,1,159.43,201Z",
    "file-code": "M181.66,146.34a8,8,0,0,1,0,11.32l-24,24a8,8,0,0,1-11.32-11.32L164.69,152l-18.35-18.34a8,8,0,0,1,11.32-11.32Zm-72-24a8,8,0,0,0-11.32,0l-24,24a8,8,0,0,0,0,11.32l24,24a8,8,0,0,0,11.32-11.32L91.31,152l18.35-18.34A8,8,0,0,0,109.66,122.34ZM216,88V216a16,16,0,0,1-16,16H56a16,16,0,0,1-16-16V40A16,16,0,0,1,56,24h96a8,8,0,0,1,5.66,2.34l56,56A8,8,0,0,1,216,88Zm-56-8h28.69L160,51.31Zm40,136V96H152a8,8,0,0,1-8-8V40H56V216H200Z",
    # Vendor logos, Phosphor regular, the same package and grid as every other
    # glyph here. The owner named these five on 2026-08-16 after the previous round
    # went looking for brand marks elsewhere: Phosphor draws them itself, so one
    # set, one licence, one 256 grid, and nothing to reconcile. The marks remain
    # the property of their owners and are used to name the destination.
    "slack-logo": "M221.13,128A32,32,0,0,0,184,76.31V56a32,32,0,0,0-56-21.13A32,32,0,0,0,76.31,72H56a32,32,0,0,0-21.13,56A32,32,0,0,0,72,179.69V200a32,32,0,0,0,56,21.13A32,32,0,0,0,179.69,184H200a32,32,0,0,0,21.13-56ZM72,152a16,16,0,1,1-16-16H72Zm48,48a16,16,0,0,1-32,0V152a16,16,0,0,1,16-16h16Zm0-80H56a16,16,0,0,1,0-32h48a16,16,0,0,1,16,16Zm0-48H104a16,16,0,1,1,16-16Zm16-16a16,16,0,0,1,32,0v48a16,16,0,0,1-16,16H136Zm16,160a16,16,0,0,1-16-16V184h16a16,16,0,0,1,0,32Zm48-48H152a16,16,0,0,1-16-16V136h64a16,16,0,0,1,0,32Zm0-48H184V104a16,16,0,1,1,16,16Z",
    "discord-logo": "M104,140a12,12,0,1,1-12-12A12,12,0,0,1,104,140Zm60-12a12,12,0,1,0,12,12A12,12,0,0,0,164,128Zm74.45,64.9-67,29.71a16.17,16.17,0,0,1-21.71-9.1l-8.11-22q-6.72.45-13.63.46t-13.63-.46l-8.11,22a16.18,16.18,0,0,1-21.71,9.1l-67-29.71a15.93,15.93,0,0,1-9.06-18.51L38,58A16.07,16.07,0,0,1,51,46.14l36.06-5.93a16.22,16.22,0,0,1,18.26,11.88l3.26,12.84Q118.11,64,128,64t19.4.93l3.26-12.84a16.21,16.21,0,0,1,18.26-11.88L205,46.14A16.07,16.07,0,0,1,218,58l29.53,116.38A15.93,15.93,0,0,1,238.45,192.9ZM232,178.28,202.47,62s0,0-.08,0L166.33,56a.17.17,0,0,0-.17,0l-2.83,11.14c5,.94,10,2.06,14.83,3.42A8,8,0,0,1,176,86.31a8.09,8.09,0,0,1-2.16-.3A172.25,172.25,0,0,0,128,80a172.25,172.25,0,0,0-45.84,6,8,8,0,1,1-4.32-15.4c4.82-1.36,9.78-2.48,14.82-3.42L89.83,56s0,0-.12,0h0L53.61,61.93a.17.17,0,0,0-.09,0L24,178.33,91,208a.23.23,0,0,0,.22,0L98,189.72a173.2,173.2,0,0,1-20.14-4.32A8,8,0,0,1,82.16,170,171.85,171.85,0,0,0,128,176a171.85,171.85,0,0,0,45.84-6,8,8,0,0,1,4.32,15.41A173.2,173.2,0,0,1,158,189.72L164.75,208a.22.22,0,0,0,.21,0Z",
    "telegram-logo": "M228.88,26.19a9,9,0,0,0-9.16-1.57L17.06,103.93a14.22,14.22,0,0,0,2.43,27.21L72,141.45V200a15.92,15.92,0,0,0,10,14.83,15.91,15.91,0,0,0,17.51-3.73l25.32-26.26L165,220a15.88,15.88,0,0,0,10.51,4,16.3,16.3,0,0,0,5-.79,15.85,15.85,0,0,0,10.67-11.63L231.77,35A9,9,0,0,0,228.88,26.19Zm-61.14,36L78.15,126.35l-49.6-9.73ZM88,200V152.52l24.79,21.74Zm87.53,8L92.85,135.5l119-85.29Z",
    "webhooks-logo": "M178.16,176H111.32A48,48,0,1,1,25.6,139.19a8,8,0,0,1,12.8,9.61A31.69,31.69,0,0,0,32,168a32,32,0,0,0,64,0,8,8,0,0,1,8-8h74.16a16,16,0,1,1,0,16ZM64,184a16,16,0,0,0,14.08-23.61l35.77-58.14a8,8,0,0,0-2.62-11,32,32,0,1,1,46.1-40.06A8,8,0,1,0,172,44.79a48,48,0,1,0-75.62,55.33L64.44,152c-.15,0-.29,0-.44,0a16,16,0,0,0,0,32Zm128-64a48.18,48.18,0,0,0-18,3.49L142.08,71.6A16,16,0,1,0,128,80l.44,0,35.78,58.15a8,8,0,0,0,11,2.61A32,32,0,1,1,192,200a8,8,0,0,0,0,16,48,48,0,0,0,0-96Z",
    "microsoft-teams-logo": "M112,104a8,8,0,0,1-8,8H96v40a8,8,0,0,1-16,0V112H72a8,8,0,0,1,0-16h32A8,8,0,0,1,112,104ZM232,92.74V152a40,40,0,0,1-36.63,39.85,64,64,0,0,1-118.7.15H40a16,16,0,0,1-16-16V80A16,16,0,0,1,40,64H96.81a40,40,0,0,1,73.31-28.85A32,32,0,0,1,211.69,80h7.57A12.76,12.76,0,0,1,232,92.74ZM112,56a23.82,23.82,0,0,0,1.38,8H136a16,16,0,0,1,15.07,10.68A24,24,0,1,0,112,56Zm24,120h0V80H40v96h96Zm48-80H152v80a16,16,0,0,1-16,16H94.44A48,48,0,0,0,184,168Zm16-32a16,16,0,0,0-24.4-13.6A39.89,39.89,0,0,1,168,80h16A16,16,0,0,0,200,64Zm16,32H200v72a62.76,62.76,0,0,1-.36,6.75A24,24,0,0,0,216,152Z",
}

# The brand marks, and the product each one identifies.
#
# The owner asked for real logos on 2026-08-16, which reversed the previous
# session's blanket "no vendor marks" and is his call to make. A mark is here
# only where that brand's own published guidelines allow us to reproduce it as
# one colour, because every glyph on our pages is drawn in currentColor.
#
# Four products in the two pickers deliberately keep a neutral Phosphor glyph
# instead. Slack, because Simple Icons will not ship the mark without written
# permission from Slack and we have none. Microsoft Teams, because Microsoft's
# own trademark guidelines say its logos can never be used without an express
# licence. Grafana and Prometheus, because both of their policies forbid
# changing the colour of the mark, and one colour is the only way it could sit
# in this set. THIRD_PARTY_NOTICES.md quotes each of those, with the date read.
#
# Nothing here is recoloured into a hue of ours, stretched, rotated or redrawn,
# and every mark remains the property of its owner.

PHOSPHOR_VIEWBOX = "0 0 256 256"

# Simple Icons 16.28.0 (simpleicons.org), CC0 1.0 for the set, drawn on a 24
# grid. The vendor marks the Integrations screen draws, as the sketch the owner
# approved on 2026-09-06 draws them. Each is its owner's trademark, and every
# owner whose terms could be read wants to be asked first: the owner chose to
# carry that on 2026-09-07 and to take a mark down the day its owner asks
# (record 4.152, site/THIRD_PARTY_NOTICES.md). Linode carries Akamai's mark
# since the set has no Linode mark.
# A mark is a path on the 24 grid, or (viewBox, path) for one drawn on its
# owner's own grid: Azure's is Simple Icons 8.15.0, the last version to carry
# Microsoft's marks, and Zabbix's is the monochrome wordmark from Zabbix's own
# 2025 logo pack (zabbix.com/trademark), on its own wide canvas.
BRAND_VIEWBOX = "0 0 24 24"
MARKS = {
    "microsoftazure": "M22.379 23.343a1.62 1.62 0 0 0 1.536-2.14v.002L17.35 1.76A1.62 1.62 0 0 0 15.816.657H8.184A1.62 1.62 0 0 0 6.65 1.76L.086 21.204a1.62 1.62 0 0 0 1.536 2.139h4.741a1.62 1.62 0 0 0 1.535-1.103l.977-2.892 4.947 3.675c.28.208.618.32.966.32m-3.084-12.531 3.624 10.739a.54.54 0 0 1-.51.713v-.001h-.03a.54.54 0 0 1-.322-.106l-9.287-6.9h4.853m6.313 7.006c.116-.326.13-.694.007-1.058L9.79 1.76a1.722 1.722 0 0 0-.007-.02h6.034a.54.54 0 0 1 .512.366l6.562 19.445a.54.54 0 0 1-.338.684",
    "zabbix": ("0 0 612 169.292", "M606,6v157.292H6V6h600M612,0H0v169.292h612V0h0Z M29.914,139.379v-13.605l59.737-81.004H29.914v-14.856h80.065v13.605l-59.736,81.004h59.736v14.856H29.914Z M120.459,139.379l41.597-109.465h17.201l41.597,109.465h-18.453l-9.695-25.646h-45.194l-9.695,25.646h-17.358ZM153.142,98.72h33.934l-16.889-47.226-17.045,47.226Z M235.698,139.379V29.914h41.91c12.614,0,21.84,2.711,27.679,8.132,5.942,5.317,8.913,12.354,8.913,21.111,0,5.63-1.512,10.477-4.535,14.543-3.023,3.962-6.985,6.828-11.885,8.601,6.464,1.46,11.572,4.431,15.325,8.914,3.858,4.379,5.786,10.112,5.786,17.202,0,6.047-1.303,11.416-3.909,16.107-2.606,4.587-6.776,8.236-12.51,10.946-5.63,2.607-12.98,3.91-22.05,3.91h-44.724ZM252.9,124.523h26.271c8.653,0,14.544-1.46,17.671-4.379,3.232-2.919,4.848-7.141,4.848-12.666s-1.616-9.8-4.848-12.823c-3.232-3.128-9.174-4.691-17.827-4.691h-26.115v34.56ZM252.9,76.202h23.3c7.923,0,13.344-1.46,16.263-4.379,3.024-2.919,4.535-6.776,4.535-11.572,0-4.9-1.511-8.705-4.535-11.416-2.919-2.71-8.34-4.066-16.263-4.066h-23.3v31.432Z M339.937,139.379V29.914h41.91c12.614,0,21.84,2.711,27.679,8.132,5.942,5.317,8.913,12.354,8.913,21.111,0,5.63-1.512,10.477-4.535,14.543-3.023,3.962-6.985,6.828-11.885,8.601,6.464,1.46,11.572,4.431,15.326,8.914,3.857,4.379,5.786,10.112,5.786,17.202,0,6.047-1.304,11.416-3.91,16.107-2.606,4.587-6.776,8.236-12.51,10.946-5.63,2.607-12.98,3.91-22.05,3.91h-44.724ZM357.139,124.523h26.271c8.653,0,14.544-1.46,17.671-4.379,3.232-2.919,4.848-7.141,4.848-12.666s-1.616-9.8-4.848-12.823c-3.232-3.128-9.174-4.691-17.827-4.691h-26.115v34.56ZM357.139,76.202h23.3c7.923,0,13.344-1.46,16.264-4.379,3.023-2.919,4.535-6.776,4.535-11.572,0-4.9-1.512-8.705-4.535-11.416-2.92-2.71-8.341-4.066-16.264-4.066h-23.3v31.432Z M447.701,139.379V29.914h17.202v109.465h-17.202Z M485.444,139.379l38-56.609-36.436-52.856h19.235l27.679,39.876,27.991-39.876h18.609l-36.279,52.543,37.843,56.922h-19.547l-28.93-44.255-29.243,44.255h-18.922Z"),
    # The two container runtimes, for the box a published port puts on the
    # packet path. The owner, 2026-09-08, on the marks generally: logos rather
    # than names, everywhere, as in the drawings. The trade he took with it is
    # in `docs/RECORD.md` 4.153.
    "docker": "M13.983 11.078h2.119a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.119a.185.185 0 00-.185.185v1.888c0 .102.083.185.185.185m-2.954-5.43h2.118a.186.186 0 00.186-.186V3.574a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m0 2.716h2.118a.187.187 0 00.186-.186V6.29a.186.186 0 00-.186-.185h-2.118a.185.185 0 00-.185.185v1.887c0 .102.082.185.185.186m-2.93 0h2.12a.186.186 0 00.184-.186V6.29a.185.185 0 00-.185-.185H8.1a.185.185 0 00-.185.185v1.887c0 .102.083.185.185.186m-2.964 0h2.119a.186.186 0 00.185-.186V6.29a.185.185 0 00-.185-.185H5.136a.186.186 0 00-.186.185v1.887c0 .102.084.185.186.186m5.893 2.715h2.118a.186.186 0 00.186-.185V9.006a.186.186 0 00-.186-.186h-2.118a.185.185 0 00-.185.185v1.888c0 .102.082.185.185.185m-2.93 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.083.185.185.185m-2.964 0h2.119a.185.185 0 00.185-.185V9.006a.185.185 0 00-.184-.186h-2.12a.186.186 0 00-.186.186v1.887c0 .102.084.185.186.185m-2.92 0h2.12a.185.185 0 00.184-.185V9.006a.185.185 0 00-.184-.186h-2.12a.185.185 0 00-.184.185v1.888c0 .102.082.185.185.185M23.763 9.89c-.065-.051-.672-.51-1.954-.51-.338.001-.676.03-1.01.087-.248-1.7-1.653-2.53-1.716-2.566l-.344-.199-.226.327c-.284.438-.49.922-.612 1.43-.23.97-.09 1.882.403 2.661-.595.332-1.55.413-1.744.42H.751a.751.751 0 00-.75.748 11.376 11.376 0 00.692 4.062c.545 1.428 1.355 2.48 2.41 3.124 1.18.723 3.1 1.137 5.275 1.137.983.003 1.963-.086 2.93-.266a12.248 12.248 0 003.823-1.389c.98-.567 1.86-1.288 2.61-2.136 1.252-1.418 1.998-2.997 2.553-4.4h.221c1.372 0 2.215-.549 2.68-1.009.309-.293.55-.65.707-1.046l.098-.288Z",
    "podman": "M17.2.275L6.75.308a.259.259 0 0 0-.203.098L.056 8.602a.259.259 0 0 0-.05.219l2.356 10.194a.26.26 0 0 0 .14.174l9.43 4.511a.258.258 0 0 0 .224-.002l9.401-4.566a.259.259 0 0 0 .141-.175L23.993 8.75a.258.258 0 0 0-.051-.22L17.403.374A.259.259 0 0 0 17.2.275zm-.123.517l6.385 7.966-2.242 9.964-9.177 4.457-9.205-4.402L.54 8.827 6.875.824zM11.46 2.857c-.933 0-1.84.1-2.426.332h-.002c-1.554.569-2.725 2.105-3.074 3.952v.004c-.309 1.463-.392 2.703-.556 3.824-.07.481-.159.94-.283 1.387-.628.497-1.079 1.263-1.244 2.138v.004c-.116.547-.181 1.04-.237 1.5h-.644v.518h8.891c-.061.464-.122.996-.181 1.42H7.596v.517h7.939c-.242-.078-.486-.218-.756-.502h-.697l-.85.488-.232-.396.162-.092h-1.069c.113-.776.17-1.601.373-2.564v-.004c.22-1.164.96-2.112 1.895-2.453l.004-.002h.002c.318-.127.928-.205 1.543-.205.613 0 1.244.075 1.622.207.935.341 1.676 1.29 1.895 2.453v.004c.204.963.26 1.788.373 2.564h-.742l.162.092-.233.396-.85-.488h-.75c-.219.25-.474.412-.747.502h4.392v-.518h-.842c-.103-.743-.181-1.67-.382-2.623v-.002a4.14 4.14 0 0 0-.264-.863h1.863v-.517h-2.13a3.488 3.488 0 0 0-.8-.906h1.8v-.518H17.95a8.862 8.862 0 0 1-.193-.775h1.484v-.518h-1.576c-.013-.081-.027-.161-.039-.244-.164-1.12-.246-2.36-.555-3.824v-.004c-.348-1.848-1.52-3.383-3.075-3.952l-.002-.002h-.002c-.65-.227-1.596-.33-2.531-.33zm0 .386c.904 0 1.833.11 2.404.309h.002c1.4.514 2.5 1.934 2.826 3.666v.003c.303 1.436.385 2.66.552 3.805.076.515.173 1.013.315 1.505-.449-.135-1.05-.197-1.648-.197-.12 0-.236.003-.352.008l-1.863-1.865a2.17 2.17 0 0 0 .11-.246l2.13 1.23.13-.224-2.185-1.262c.016-.069.027-.14.036-.21l2.302.616.068-.248-2.354-.63c-.02-1.153-1.008-2.078-2.208-2.078-1.205 0-2.196.931-2.206 2.091l-2.303.617.066.25 2.252-.605c.01.076.024.151.041.224L7.436 11.24l.129.222 2.087-1.207c.034.089.074.176.12.258l-1.266 1.266a6.959 6.959 0 0 0-1.045-.075c-.603 0-1.186.064-1.578.22a2.668 2.668 0 0 0-.285.124c.076-.335.137-.675.187-1.021.168-1.144.248-2.37.551-3.805l.002-.001v-.002c.326-1.733 1.426-3.153 2.828-3.666h.002l.004-.002c.488-.194 1.381-.307 2.287-.307zM8.473 5.194a1.295 1.295 0 0 0-.965.502l-.117.153.306.236.12-.152a.923.923 0 0 1 .673-.352.92.92 0 0 1 .67.262l.139.134.271-.275-.136-.137a1.293 1.293 0 0 0-.961-.37zm6.39 0a1.289 1.289 0 0 0-.96.371l-.138.137.274.275.136-.134a.923.923 0 0 1 .672-.262.923.923 0 0 1 .674.352l.119.152.307-.236-.12-.153c-.23-.3-.587-.486-.964-.502zM8.53 6.708c-.642 0-1.164.538-1.164 1.19 0 .65.522 1.187 1.164 1.187.643 0 1.164-.536 1.164-1.188 0-.651-.521-1.19-1.164-1.19zm6.273 0c-.643 0-1.162.538-1.162 1.19 0 .65.52 1.187 1.162 1.187.643 0 1.164-.536 1.164-1.188 0-.651-.521-1.19-1.164-1.19zm-6.273.387c.428 0 .776.355.776.802 0 .447-.348.8-.776.8a.785.785 0 0 1-.775-.8c0-.035.002-.07.006-.103.07.191.248.318.445.318a.487.487 0 0 0 .477-.496.49.49 0 0 0-.383-.486.759.759 0 0 1 .23-.035zm6.273 0c.428 0 .777.355.777.802 0 .447-.349.8-.777.8a.785.785 0 0 1-.77-.9c.072.19.248.315.444.315a.486.486 0 0 0 .479-.496.491.491 0 0 0-.383-.484.755.755 0 0 1 .23-.037zm-3.08.716c1.012 0 1.819.775 1.819 1.723 0 .947-.807 1.722-1.819 1.722s-1.82-.775-1.82-1.722c0-.948.808-1.723 1.82-1.723zm-.002.528c-.142 0-.258.043-.355.076a.804.804 0 0 1-.232.054c-.107 0-.2.047-.268.127a.568.568 0 0 0-.104.207c-.04.134-.062.268-.08.315a.276.276 0 0 0 .032.25c.033.056.071.1.117.146.09.092.206.183.322.268.12.088.237.166.326.224l-.008.09c-.043.036-.14.102-.324.178a.533.533 0 0 1-.299.025.43.43 0 0 1-.236-.172c.015-.138.044-.293.068-.449l-.376-.095c-.05.238-.067.43-.094.64l.037.059c.143.224.318.344.506.392a.908.908 0 0 0 .52-.033 1.57 1.57 0 0 0 .444-.242c.088.067.244.174.446.242a.908.908 0 0 0 .52.033.868.868 0 0 0 .507-.392l.037-.059a6.292 6.292 0 0 0-.096-.637l-.377.092c.032.148.051.32.07.451a.434.434 0 0 1-.237.17.533.533 0 0 1-.3-.025c-.178-.068-.272-.14-.325-.178l-.006-.084c.09-.058.209-.137.336-.23.115-.085.231-.176.322-.268a.72.72 0 0 0 .117-.146.273.273 0 0 0 .031-.25c-.018-.047-.039-.181-.08-.315a.564.564 0 0 0-.103-.207.343.343 0 0 0-.268-.127.815.815 0 0 1-.234-.054c-.097-.033-.212-.076-.354-.076zm.002.386c.057 0 .134.024.23.057.09.03.208.07.337.076.04.102.06.237.09.338a.361.361 0 0 1-.041.045 2.66 2.66 0 0 1-.276.228c-.165.122-.271.188-.342.233a5.287 5.287 0 0 1-.34-.233 2.557 2.557 0 0 1-.275-.228.34.34 0 0 1-.04-.047c.035-.119.046-.234.089-.34.08.012.246-.042.336-.072a.837.837 0 0 1 .232-.057zm-3.234.61a.635.635 0 0 0-.611.517l1.084-.289a.614.614 0 0 0-.473-.228zm6.336 0a.61.61 0 0 0-.436.187c.352.096.69.184 1.033.275a.632.632 0 0 0-.597-.462zm-.623.607c-.007.035-.002.07-.002.103l.921.532a.648.648 0 0 0 .276-.313l-1.195-.322zm-5.086.05l-1.18.315c.078.15.207.264.362.316l.797-.46c.018-.059.015-.12.021-.17zm4.441.714l1.656 1.658a4.19 4.19 0 0 0-.826.146l-.95-1.647a2.51 2.51 0 0 0 .12-.157zm-3.646.03c.04.055.083.118.129.169l-.658 1.134a2.656 2.656 0 0 0-.276-.119l-.002-.002a3.3 3.3 0 0 0-.292-.082zm3.338.317l.892 1.547c-.623.251-1.149.725-1.523 1.33h-1.652c-.262-.75-.741-1.38-1.358-1.764l.623-1.082c.394.347.919.559 1.492.559a2.25 2.25 0 0 0 1.526-.59zM7.46 12.09c.574 0 1.167.073 1.518.195.867.319 1.555 1.203 1.76 2.285l.001.002v.002c.109.513.173.98.227 1.424H9.86a.386.386 0 0 0-.494 0H9.11a1.351 1.351 0 0 0-.078-.418.799.799 0 0 0 .569.238c.45 0 .814-.375.814-.828a.824.824 0 0 0-.814-.828.822.822 0 0 0-.791 1.016 1.495 1.495 0 0 0-1.18-.559c-.798 0-1.46.611-1.48 1.38h-.342a.386.386 0 0 0-.494 0H4.028c.054-.445.116-.912.224-1.425l.002-.002v-.002c.205-1.084.894-1.97 1.764-2.287h.002l.004-.002c.295-.117.863-.191 1.437-.19zm-1.91 1.105a.898.898 0 0 0-.67.348l-.119.154.307.237.119-.155a.525.525 0 0 1 .379-.197.52.52 0 0 1 .377.147l.138.136.272-.275-.137-.137a.895.895 0 0 0-.666-.258zm4.094 0a.9.9 0 0 0-.668.258l-.137.137.273.275.137-.136a.522.522 0 0 1 .377-.147.525.525 0 0 1 .379.197l.119.155.307-.237-.12-.154a.894.894 0 0 0-.667-.348zm4.222.735a.947.947 0 0 0-.707.365l-.117.154.306.237.12-.155a.568.568 0 0 1 .413-.213.571.571 0 0 1 .414.159l.14.136.27-.275-.138-.137a.942.942 0 0 0-.701-.271zm4.374 0a.942.942 0 0 0-.7.271l-.14.137.272.275.139-.136a.571.571 0 0 1 .414-.159.568.568 0 0 1 .414.213l.119.155.306-.237-.117-.154a.947.947 0 0 0-.707-.365zm-12.65.232a.824.824 0 0 0-.815.828c0 .453.365.828.814.828.45 0 .815-.375.815-.828a.824.824 0 0 0-.815-.828zm5.518.285h1.242a4.137 4.137 0 0 0-.263.864v.002c-.05.237-.092.464-.127.685h-.602a16.77 16.77 0 0 0-.236-1.5l-.002-.002c-.003-.016-.009-.032-.012-.049zm-5.519.102a.43.43 0 0 1 .426.441.43.43 0 0 1-.426.442c-.22 0-.4-.171-.422-.397a.298.298 0 0 0 .215.092.31.31 0 0 0 .305-.316.317.317 0 0 0-.129-.258c.01-.001.02-.004.031-.004zm4.014 0c.235 0 .427.193.427.441a.433.433 0 0 1-.427.442.427.427 0 0 1-.422-.405.3.3 0 0 0 .256.145.31.31 0 0 0 .304-.317.314.314 0 0 0-.207-.298c.023-.004.045-.008.069-.008zm4.304.414a.865.865 0 0 0-.856.87c0 .478.382.874.856.874a.868.868 0 0 0 .857-.873.867.867 0 0 0-.857-.871zm4.292 0a.867.867 0 0 0-.814 1.14 1.597 1.597 0 0 0-1.295-.652c-.846 0-1.546.65-1.568 1.463l-1.525.408.066.248 1.477-.394c.004.028.009.06.015.087l-1.418.817.131.222 1.367-.789c.235.552.801.94 1.455.94.66 0 1.233-.397 1.463-.957l1.398.806.13-.222-1.45-.836c.005-.025.008-.053.012-.078l1.511.404.067-.248-1.563-.418a1.438 1.438 0 0 0-.107-.5c.157.186.39.303.648.303a.867.867 0 0 0 .856-.873.865.865 0 0 0-.856-.871zm-10.567.043c.598 0 1.071.444 1.092.992h-.41c.007-.01.016-.02.023-.033a.24.24 0 0 0 .025-.22c-.005-.016-.021-.102-.05-.196a.416.416 0 0 0-.078-.156.282.282 0 0 0-.225-.108.499.499 0 0 1-.129-.031c-.062-.021-.142-.05-.248-.05-.106 0-.188.029-.25.05a.49.49 0 0 1-.127.031.29.29 0 0 0-.225.108.424.424 0 0 0-.08.156c-.029.094-.043.18-.048.195a.242.242 0 0 0 .023.22c.008.014.017.023.025.034h-.41c.02-.548.494-.992 1.092-.992zm6.275.344c.259 0 .47.211.47.484a.477.477 0 0 1-.47.486.472.472 0 0 1-.467-.453.322.322 0 0 0 .246.115c.18 0 .326-.15.326-.338a.34.34 0 0 0-.156-.289c.017-.002.033-.005.05-.005zm4.292 0c.26 0 .469.211.469.484 0 .272-.21.486-.469.486a.477.477 0 0 1-.47-.486c0-.016.002-.031.004-.047a.33.33 0 0 0 .312.24c.18 0 .326-.15.326-.338a.338.338 0 0 0-.256-.332.475.475 0 0 1 .084-.007zm-10.567.24c.021 0 .063.01.125.031.086.03.117.039.186.049.012.041.022.088.033.129a1.475 1.475 0 0 1-.168.138c-.038.028-.064.045-.088.061h-.176c-.024-.016-.052-.033-.09-.06a1.602 1.602 0 0 1-.168-.14l.034-.128c.107-.014.146-.04.185-.049a.504.504 0 0 1 .127-.031zm8.458.25c.661 0 1.184.502 1.184 1.113 0 .156-.035.304-.096.44l-.002-.024-.022-.156a2.443 2.443 0 0 0-.04-.24l-.377.093.044.274a.24.24 0 0 1-.115.074.299.299 0 0 1-.168-.014c-.087-.03-.132-.063-.18-.094.057-.037.13-.084.198-.134.08-.06.16-.123.226-.19a.542.542 0 0 0 .092-.111.245.245 0 0 0 .026-.225c-.008-.019-.022-.112-.053-.21a.444.444 0 0 0-.084-.163.286.286 0 0 0-.23-.107.566.566 0 0 1-.14-.037c-.065-.022-.152-.055-.263-.055-.11 0-.195.032-.262.055a.575.575 0 0 1-.14.037.294.294 0 0 0-.23.107.436.436 0 0 0-.083.162c-.03.1-.045.192-.052.211a.246.246 0 0 0 .025.225.534.534 0 0 0 .09.111c.066.067.146.13.226.19.068.05.138.095.194.132a.57.57 0 0 1-.18.096.305.305 0 0 1-.17.014.237.237 0 0 1-.111-.076c.008-.09.026-.177.04-.272l-.376-.094c-.032.146-.045.286-.063.409a1.052 1.052 0 0 1-.09-.428c0-.611.521-1.113 1.182-1.113zm0 .623c.026 0 .074.01.14.033.066.025.169.052.206.055l.035.156c-.04.04-.112.1-.184.152-.095.07-.14.095-.197.131-.056-.036-.1-.061-.195-.13a1.236 1.236 0 0 1-.184-.157l.035-.152a1.04 1.04 0 0 0 .206-.055.523.523 0 0 1 .138-.033zm-2.22.353a.43.43 0 0 0-.385.272l.656-.176a.416.416 0 0 0-.271-.096zm4.333 0a.414.414 0 0 0-.22.07l.603.16a.426.426 0 0 0-.383-.23zm-4.054.567l-.607.162a.436.436 0 0 0 .125.113zm3.925.002l.407.234a.443.443 0 0 0 .087-.102zm-1.986.234c.067.047.165.108.285.148a.68.68 0 0 0 .389.024.57.57 0 0 0 .232-.121 1.201 1.201 0 0 1-.904.394c-.356 0-.67-.145-.885-.375a.58.58 0 0 0 .207.102c.144.036.28.014.391-.024.12-.04.218-.1.285-.148zm-9.524 1.61v.517h6.214v-.518zm3.619 1.292v.517H15.3v-.517z",
    "hetzner": "M0 0v24h24V0H0zm4.602 4.025h2.244c.509 0 .716.215.716.717v5.64h8.883v-5.64c0-.509.215-.717.717-.717h2.229c.5 0 .71.23.724.717v14.516c0 .509-.215.717-.717.717h-2.23c-.51 0-.717-.215-.717-.717v-5.735H7.562v5.735c0 .516-.215.717-.716.717H4.602c-.51 0-.717-.208-.717-.717V4.742c0-.509.207-.717.717-.717z",
    "digitalocean": "M12.04 0C5.408-.02.005 5.37.005 11.992h4.638c0-4.923 4.882-8.731 10.064-6.855a6.95 6.95 0 014.147 4.148c1.889 5.177-1.924 10.055-6.84 10.064v-4.61H7.391v4.623h4.61V24c7.86 0 13.967-7.588 11.397-15.83-1.115-3.59-3.985-6.446-7.575-7.575A12.8 12.8 0 0012.039 0zM7.39 19.362H3.828v3.564H7.39zm-3.563 0v-2.978H.85v2.978z",
    "vultr": "M8.36 2.172A1.194 1.194 0 007.348 1.6H1.2A1.2 1.2 0 000 2.8a1.211 1.211 0 00.182.64l11.6 18.4a1.206 1.206 0 002.035 0l3.075-4.874a1.229 1.229 0 00.182-.64 1.211 1.211 0 00-.182-.642zm10.349 8.68a1.206 1.206 0 002.035 0L21.8 9.178l2.017-3.2a1.211 1.211 0 00.183-.64 1.229 1.229 0 00-.183-.64l-1.6-2.526a1.206 1.206 0 00-1.016-.571h-6.148a1.2 1.2 0 00-1.201 1.2 1.143 1.143 0 00.188.64z",
    "grafana": "M23.02 10.59a8.578 8.578 0 0 0-.862-3.034 8.911 8.911 0 0 0-1.789-2.445c.337-1.342-.413-2.505-.413-2.505-1.292-.08-2.113.4-2.416.62-.052-.02-.102-.044-.154-.064-.22-.089-.446-.172-.677-.247-.231-.073-.47-.14-.711-.197a9.867 9.867 0 0 0-.875-.161C14.557.753 12.94 0 12.94 0c-1.804 1.145-2.147 2.744-2.147 2.744l-.018.093c-.098.029-.2.057-.298.088-.138.042-.275.094-.413.143-.138.055-.275.107-.41.166a8.869 8.869 0 0 0-1.557.87l-.063-.029c-2.497-.955-4.716.195-4.716.195-.203 2.658.996 4.33 1.235 4.636a11.608 11.608 0 0 0-.607 2.635C1.636 12.677.953 15.014.953 15.014c1.926 2.214 4.171 2.351 4.171 2.351.003-.002.006-.002.006-.005.285.509.615.994.986 1.446.156.19.32.371.488.548-.704 2.009.099 3.68.099 3.68 2.144.08 3.553-.937 3.849-1.173a9.784 9.784 0 0 0 3.164.501h.08l.055-.003.107-.002.103-.005.003.002c1.01 1.44 2.788 1.646 2.788 1.646 1.264-1.332 1.337-2.653 1.337-2.94v-.058c0-.02-.003-.039-.003-.06.265-.187.52-.387.758-.6a7.875 7.875 0 0 0 1.415-1.7c1.43.083 2.437-.885 2.437-.885-.236-1.49-1.085-2.216-1.264-2.354l-.018-.013-.016-.013a.217.217 0 0 1-.031-.02c.008-.092.016-.18.02-.27.011-.162.016-.323.016-.48v-.253l-.005-.098-.008-.135a1.891 1.891 0 0 0-.01-.13c-.003-.042-.008-.083-.013-.125l-.016-.124-.018-.122a6.215 6.215 0 0 0-2.032-3.73 6.015 6.015 0 0 0-3.222-1.46 6.292 6.292 0 0 0-.85-.048l-.107.002h-.063l-.044.003-.104.008a4.777 4.777 0 0 0-3.335 1.695c-.332.4-.592.84-.768 1.297a4.594 4.594 0 0 0-.312 1.817l.003.091c.005.055.007.11.013.164a3.615 3.615 0 0 0 .698 1.82 3.53 3.53 0 0 0 1.827 1.282c.33.098.66.14.971.137.039 0 .078 0 .114-.002l.063-.003c.02 0 .041-.003.062-.003.034-.002.065-.007.099-.01.007 0 .018-.003.028-.003l.031-.005.06-.008a1.18 1.18 0 0 0 .112-.02c.036-.008.072-.013.109-.024a2.634 2.634 0 0 0 .914-.415c.028-.02.056-.041.085-.065a.248.248 0 0 0 .039-.35.244.244 0 0 0-.309-.06l-.078.042c-.09.044-.184.083-.283.116a2.476 2.476 0 0 1-.475.096c-.028.003-.054.006-.083.006l-.083.002c-.026 0-.054 0-.08-.002l-.102-.006h-.012l-.024.006c-.016-.003-.031-.003-.044-.006-.031-.002-.06-.007-.091-.01a2.59 2.59 0 0 1-.724-.213 2.557 2.557 0 0 1-.667-.438 2.52 2.52 0 0 1-.805-1.475 2.306 2.306 0 0 1-.029-.444l.006-.122v-.023l.002-.031c.003-.021.003-.04.005-.06a3.163 3.163 0 0 1 1.352-2.29 3.12 3.12 0 0 1 .937-.43 2.946 2.946 0 0 1 .776-.101h.06l.07.002.045.003h.026l.07.005a4.041 4.041 0 0 1 1.635.49 3.94 3.94 0 0 1 1.602 1.662 3.77 3.77 0 0 1 .397 1.414l.005.076.003.075c.002.026.002.05.002.075 0 .024.003.052 0 .07v.065l-.002.073-.008.174a6.195 6.195 0 0 1-.08.639 5.1 5.1 0 0 1-.267.927 5.31 5.31 0 0 1-.624 1.13 5.052 5.052 0 0 1-3.237 2.014 4.82 4.82 0 0 1-.649.066l-.039.003h-.287a6.607 6.607 0 0 1-1.716-.265 6.776 6.776 0 0 1-3.4-2.274 6.75 6.75 0 0 1-.746-1.15 6.616 6.616 0 0 1-.714-2.596l-.005-.083-.002-.02v-.056l-.003-.073v-.096l-.003-.104v-.07l.003-.163c.008-.22.026-.45.054-.678a8.707 8.707 0 0 1 .28-1.355c.128-.444.286-.872.473-1.277a7.04 7.04 0 0 1 1.456-2.1 5.925 5.925 0 0 1 .953-.763c.169-.111.343-.213.524-.306.089-.05.182-.091.273-.135.047-.02.093-.042.138-.062a7.177 7.177 0 0 1 .714-.267l.145-.045c.049-.015.098-.026.148-.041.098-.029.197-.052.296-.076.049-.013.1-.02.15-.033l.15-.032.151-.028.076-.013.075-.01.153-.024c.057-.01.114-.013.171-.023l.169-.021c.036-.003.073-.008.106-.01l.073-.008.036-.003.042-.002c.057-.003.114-.008.171-.01l.086-.006h.023l.037-.003.145-.007a7.999 7.999 0 0 1 1.708.125 7.917 7.917 0 0 1 2.048.68 8.253 8.253 0 0 1 1.672 1.09l.09.077.089.078c.06.052.114.107.171.159.057.052.112.106.166.16.052.055.107.107.159.164a8.671 8.671 0 0 1 1.41 1.978c.012.026.028.052.04.078l.04.078.075.156c.023.051.05.1.07.153l.065.15a8.848 8.848 0 0 1 .45 1.34.19.19 0 0 0 .201.142.186.186 0 0 0 .172-.184c.01-.246.002-.532-.024-.856z",
    "prometheus": "M12 0C5.373 0 0 5.372 0 12c0 6.627 5.373 12 12 12s12-5.373 12-12c0-6.628-5.373-12-12-12zm0 22.46c-1.885 0-3.414-1.26-3.414-2.814h6.828c0 1.553-1.528 2.813-3.414 2.813zm5.64-3.745H6.36v-2.046h11.28v2.046zm-.04-3.098H6.391c-.037-.043-.075-.086-.111-.13-1.155-1.401-1.427-2.133-1.69-2.879-.005-.025 1.4.287 2.395.511 0 0 .513.119 1.262.255-.72-.843-1.147-1.915-1.147-3.01 0-2.406 1.845-4.508 1.18-6.207.648.053 1.34 1.367 1.387 3.422.689-.951.977-2.69.977-3.755 0-1.103.727-2.385 1.454-2.429-.648 1.069.168 1.984.894 4.256.272.854.237 2.29.447 3.201.07-1.892.395-4.652 1.595-5.605-.529 1.2.079 2.702.494 3.424.671 1.164 1.078 2.047 1.078 3.716a4.642 4.642 0 01-1.11 2.996c.792-.149 1.34-.283 1.34-.283l2.573-.502s-.374 1.538-1.81 3.019z",
    "amazonwebservices": "M6.763 10.036c0 .296.032.535.088.71.064.176.144.368.256.576.04.063.056.127.056.183 0 .08-.048.16-.152.24l-.503.335a.383.383 0 0 1-.208.072c-.08 0-.16-.04-.239-.112a2.47 2.47 0 0 1-.287-.375 6.18 6.18 0 0 1-.248-.471c-.622.734-1.405 1.101-2.347 1.101-.67 0-1.205-.191-1.596-.574-.391-.384-.59-.894-.59-1.533 0-.678.239-1.23.726-1.644.487-.415 1.133-.623 1.955-.623.272 0 .551.024.846.064.296.04.6.104.918.176v-.583c0-.607-.127-1.03-.375-1.277-.255-.248-.686-.367-1.3-.367-.28 0-.568.031-.863.103-.295.072-.583.16-.862.272a2.287 2.287 0 0 1-.28.104.488.488 0 0 1-.127.023c-.112 0-.168-.08-.168-.247v-.391c0-.128.016-.224.056-.28a.597.597 0 0 1 .224-.167c.279-.144.614-.264 1.005-.36a4.84 4.84 0 0 1 1.246-.151c.95 0 1.644.216 2.091.647.439.43.662 1.085.662 1.963v2.586zm-3.24 1.214c.263 0 .534-.048.822-.144.287-.096.543-.271.758-.51.128-.152.224-.32.272-.512.047-.191.08-.423.08-.694v-.335a6.66 6.66 0 0 0-.735-.136 6.02 6.02 0 0 0-.75-.048c-.535 0-.926.104-1.19.32-.263.215-.39.518-.39.917 0 .375.095.655.295.846.191.2.47.296.838.296zm6.41.862c-.144 0-.24-.024-.304-.08-.064-.048-.12-.16-.168-.311L7.586 5.55a1.398 1.398 0 0 1-.072-.32c0-.128.064-.2.191-.2h.783c.151 0 .255.025.31.08.065.048.113.16.16.312l1.342 5.284 1.245-5.284c.04-.16.088-.264.151-.312a.549.549 0 0 1 .32-.08h.638c.152 0 .256.025.32.08.063.048.12.16.151.312l1.261 5.348 1.381-5.348c.048-.16.104-.264.16-.312a.52.52 0 0 1 .311-.08h.743c.127 0 .2.065.2.2 0 .04-.009.08-.017.128a1.137 1.137 0 0 1-.056.2l-1.923 6.17c-.048.16-.104.263-.168.311a.51.51 0 0 1-.303.08h-.687c-.151 0-.255-.024-.32-.08-.063-.056-.119-.16-.15-.32l-1.238-5.148-1.23 5.14c-.04.16-.087.264-.15.32-.065.056-.177.08-.32.08zm10.256.215c-.415 0-.83-.048-1.229-.143-.399-.096-.71-.2-.918-.32-.128-.071-.215-.151-.247-.223a.563.563 0 0 1-.048-.224v-.407c0-.167.064-.247.183-.247.048 0 .096.008.144.024.048.016.12.048.2.08.271.12.566.215.878.279.319.064.63.096.95.096.502 0 .894-.088 1.165-.264a.86.86 0 0 0 .415-.758.777.777 0 0 0-.215-.559c-.144-.151-.416-.287-.807-.415l-1.157-.36c-.583-.183-1.014-.454-1.277-.813a1.902 1.902 0 0 1-.4-1.158c0-.335.073-.63.216-.886.144-.255.335-.479.575-.654.24-.184.51-.32.83-.415.32-.096.655-.136 1.006-.136.175 0 .359.008.535.032.183.024.35.056.518.088.16.04.312.08.455.127.144.048.256.096.336.144a.69.69 0 0 1 .24.2.43.43 0 0 1 .071.263v.375c0 .168-.064.256-.184.256a.83.83 0 0 1-.303-.096 3.652 3.652 0 0 0-1.532-.311c-.455 0-.815.071-1.062.223-.248.152-.375.383-.375.71 0 .224.08.416.24.567.159.152.454.304.877.44l1.134.358c.574.184.99.44 1.237.767.247.327.367.702.367 1.117 0 .343-.072.655-.207.926-.144.272-.336.511-.583.703-.248.2-.543.343-.886.447-.36.111-.734.167-1.142.167zM21.698 16.207c-2.626 1.94-6.442 2.969-9.722 2.969-4.598 0-8.74-1.7-11.87-4.526-.247-.223-.024-.527.272-.351 3.384 1.963 7.559 3.153 11.877 3.153 2.914 0 6.114-.607 9.06-1.852.439-.2.814.287.383.607zM22.792 14.961c-.336-.43-2.22-.207-3.074-.103-.255.032-.295-.192-.063-.36 1.5-1.053 3.967-.75 4.254-.399.287.36-.08 2.826-1.485 4.007-.215.184-.423.088-.327-.151.32-.79 1.03-2.57.695-2.994z",
    "akamai": "M13.0548 0C6.384 0 .961 5.3802.961 12.0078.961 18.6354 6.3698 24 13.0548 24c.6168 0 .6454-.3572.0859-.5293-4.9349-1.5063-8.5352-6.069-8.5352-11.4629 0-5.4656 3.6725-10.0706 8.6934-11.5195C13.8153.3448 13.6716 0 13.0548 0Zm2.3242 1.8223c-5.2648 0-9.5254 4.2606-9.5254 9.5254 0 1.2193.2285 2.3818.6445 3.4433.1722.459.4454.4584.4024.0137-.0287-.3156-.0567-.6447-.0567-.9746 0-5.2648 4.2606-9.5254 9.5254-9.5254 4.9779 0 6.4698 2.2235 6.6563 2.08.2008-.1577-1.808-4.5624-7.6465-4.5624zm.4687 4.0703c-1.8622.0592-3.651.7168-5.1035 1.8554-.2582.2009-.1567.3284.1445.1993 2.4675-1.076 5.5812-1.1046 8.6368-.043 2.0514.7173 3.2413 1.7364 3.3418 1.6934.1578-.0718-1.1915-2.2226-3.6446-3.1407-1.1135-.4196-2.2576-.6-3.375-.5644z",
    "ovh": "M19.881 10.095l2.563-4.45C23.434 7.389 24 9.404 24 11.555c0 2.88-1.017 5.523-2.71 7.594h-6.62l2.04-3.541h-2.696l3.176-5.513h2.691zm-2.32-5.243L9.333 19.14l.003.009H2.709C1.014 17.077 0 14.435 0 11.555c0-2.152.57-4.17 1.561-5.918L5.855 13.1 10.6 4.852h6.961z",
    "scaleway": "M16.605 11.11v5.72a1.77 1.77 0 01-1.54 1.69h-4a1.43 1.43 0 01-1.31-1.22 1.09 1.09 0 010-.18 1.37 1.37 0 011.37-1.36h1.74a1 1 0 001-1v-3.62a1.4 1.4 0 011.18-1.39h.17a1.37 1.37 0 011.39 1.36zm-6.46 1.74V9.26a1 1 0 011-1h1.85a1.37 1.37 0 001.37-1.37 1 1 0 000-.17 1.45 1.45 0 00-1.41-1.2h-3.96a1.81 1.81 0 00-1.58 1.66v5.7a1.37 1.37 0 001.37 1.37h.21a1.4 1.4 0 001.15-1.4zm12-4.29V20a4.53 4.53 0 01-4.15 4h-7.58a8.57 8.57 0 01-8.56-8.57V4.54A4.54 4.54 0 016.395 0h7.18a8.56 8.56 0 018.56 8.56zm-2.74 0a5.83 5.83 0 00-5.82-5.82h-7.19a1.79 1.79 0 00-1.8 1.8v10.89a5.83 5.83 0 005.82 5.8h7.44a1.79 1.79 0 001.54-1.48z",
}




def icon(name, size=20):
    """One inline glyph, on whichever grid its source draws on.

    A brand mark comes from Simple Icons and a neutral glyph from Phosphor, and
    the two use different viewBoxes. The name decides which, so a caller asks
    for a picture and never for a coordinate system.

    An unknown name is refused by name, for the same reason status() refuses an
    unknown tone: a bare KeyError deep in a dict lookup does not say which
    glyph is missing or where to get it.
    """
    if name in MARKS:
        mark = MARKS[name]
        box, path = mark if isinstance(mark, tuple) else (BRAND_VIEWBOX, mark)
        return (f'<svg class="ic" width="{size}" height="{size}" viewBox="{box}" '
                f'fill="currentColor" aria-hidden="true"><path d="{path}"/></svg>')
    if name not in ICONS:
        raise ValueError(f"no icon named {name!r}. Add its regular-weight path "
                         "from @phosphor-icons/core to ICONS above")
    return (f'<svg class="ic" width="{size}" height="{size}" viewBox="{PHOSPHOR_VIEWBOX}" '
            f'fill="currentColor" aria-hidden="true"><path d="{ICONS[name]}"/></svg>')
