#!/usr/bin/env python3
"""The prober identification set: who we are, in every place a stranger looks.

    Run from site/: python3 probers.py       writes prober-port80.html to look at
    The two published files are written by build_site.py into dist/.

One module owns all four artifacts, because they restate the same four facts
(the abuse address, the reverse DNS zone, the list URL, the list itself) and
four copies of a fact are four things that drift apart. The
scope decision they serve is `docs/PRODUCT.md` section 5.

WHAT THE PRIMARY SOURCES ACTUALLY SAY, read 2026-08-15
------------------------------------------------------
Durumeric, Wustrow and Halderman, "ZMap: Fast Internet-Wide Scanning and Its
Security Applications", USENIX Security 2013 (zmap.io/paper.pdf), section 5
"Scanning and Good Internet Citizenship":

  "First, we configured our source addresses to present a simple website on
  port 80 that describes the nature and purpose of the scans. The site
  explains that we are not targeting individual networks or attempting to
  obtain access to private systems, and it provides a contact email address to
  request exclusion from future scans. Second, we set reverse DNS records for
  our source addresses to researchscanx.eecs.umich.edu in order to signal that
  traffic from these hosts was part of an academic research study."

Its Table 5 "Recommended Practices" item 3 is "Signal the benign nature of the
scans in web pages and DNS entries of the source addresses" and item 5 is
"Provide a simple means of opting out, and honor requests promptly". Section
5.1 records that most exclusion requests arrived "at our institution's WHOIS
abuse address or at the e-mail address published on the scan source IP
addresses".

The published range list is NOT in that paper. It is in "Ten Years of ZMap"
(IMC 2024, arxiv.org/html/2406.15585v3) section 6 "Internet Citizenship", item
3 "Provide An Opt-Out Mechanism": "Provide a simple mechanism for operators to
request exclusion from future scans. Indicate the IP ranges you use for
scanning so that operators can drop research traffic themselves." The ZMap
project's own Scanning Best Practices page carries the same six items and
cites that section.

Item 2 of the same six, "Signal Intent", is "When possible, publish reverse DNS
entries, IP WHOIS records, and a website that describes the scans. Ensure that
operators can easily contact the research team." IP WHOIS records are a fifth
item this project had not counted, and they are the one we cannot do on a VPS,
because the address comes out of the provider's allocation and the object is
theirs. `docs/PRODUCT.md` section 5 holds that.

The abuse mailbox name is RFC 2142, "MAILBOX NAMES FOR COMMON SERVICES, ROLES
AND FUNCTIONS", D. Crocker, May 1997, section 4: ABUSE, "Inappropriate public
behaviour".

Deliberately not on any page here: any comparison with the internet search
engines. Their incentive is the opposite of ours and `docs/PRODUCT.md` section
5 forbids the comparison.
"""
import base64
import pathlib
import re
import sys
from typing import NamedTuple

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import theme  # noqa: E402

# ---------------------------------------------------------------- the facts

ABUSE = "abuse@whichports.com"

# The reverse DNS zone every prober address is named under. The name says the
# activity ("probe") and the operator ("whichports.com"), which is the whole
# job of a PTR in a stranger's log line, and it is the shape the 2013 paper
# used for researchscanx.eecs.umich.edu.
RDNS_ZONE = "probes.whichports.com"

_BASE = "https://whichports.com/notes"
LIST_URL = f"{_BASE}/probers.txt"
PAGE_URL = f"{_BASE}/probers.html"

# Hand edited when PROBERS changes, never stamped at build time. A build date
# on an unchanged list says nothing true, and a list that looks fresher than it
# is invites people to trust it further than they should.
UPDATED = "2026-09-09"


class Prober(NamedTuple):
    """One address we probe from. `address` may be a single address or a CIDR."""

    address: str
    rdns: str
    provider: str
    added: str


# Nothing goes in here until the host exists, is reachable, has its PTR set and
# serves the page below. A list naming an address we do not hold is worse than
# no list at all: it teaches somebody to allowlist an address a stranger might
# get next.
#
# The first entries went on on 2026-08-18, after all four were true. Both
# families are listed because the box holds both and probes from both, and a
# reader filtering our traffic needs the one their own log line shows them.
# Each was checked in both directions before being written down: the PTR
# resolves to the name and the name resolves forward to the same address.
PROBERS: list[Prober] = [
    Prober("78.141.210.130", "probe1.probes.whichports.com", "Vultr", "2026-08-18"),
    Prober("2a05:f480:1400:2015:5400:6ff:fe94:df5",
           "probe1.probes.whichports.com", "Vultr", "2026-08-18"),
    # probe2, Akamai (Linode) London, 2026-09-09. A second provider in a second
    # country, docs/PRODUCT.md 3a point 2. Same four checks as probe1 before it
    # went on: the box exists, the PTR resolves and resolves back on both
    # families, and the page answers on port 80 from outside.
    Prober("172.236.10.19", "probe2.probes.whichports.com", "Akamai", "2026-09-09"),
    Prober("2600:3c13::2000:75ff:fe75:b7b6",
           "probe2.probes.whichports.com", "Akamai", "2026-09-09"),
]


def rdns_name(n: int) -> str:
    """The reverse DNS name for prober `n`. probe1.probes.whichports.com."""
    return f"probe{n}.{RDNS_ZONE}"


# ---------------------------------------------------------------- the copy
# Kept as data rather than buried in the templates so the tests can read the
# prose on its own, and so the writing rules can be checked on it.

EMPTY_LINES = [
    "There are no addresses on this list yet.",
    "The list is published before there is anything on it, on purpose. An "
    "address goes on it before it sends its first packet, not after somebody "
    "asks what just connected to them. An empty list means nothing of ours "
    "has probed anything, and it does not mean the file failed to build.",
]

FORMAT_LINES = [
    "One address or block per line. Every other line starts with a #, and "
    "blank lines mean nothing, so two filters are enough to read it.",
    "The file carries an addresses count in a comment. Compare it against the "
    "number of lines you parsed, and a truncated download stops looking like "
    "an empty list.",
]

RDNS_LINES = [
    f"Every address has a reverse DNS name under {RDNS_ZONE}, and that name "
    "resolves forward to the same address.",
    "Check both directions. A reverse record on its own is set by whoever "
    "runs the reverse zone for that address, and the forward record is the "
    "half only we can set, so the two agreeing is what makes the name worth "
    "anything.",
]

ABUSE_LINES = [
    f"Mail {ABUSE} to have an address excluded, or to tell us that something "
    "of ours is doing something nobody asked for.",
    "You do not have to prove anything to make us stop.",
]

# The page served on port 80 of each prober address. Five things, in the order
# somebody reads them at the end of a working day: what happened, why it
# happened to them, how to check that without taking our word, how to make it
# stop, and what we kept.
PORT80_TITLE = "Something from this address connected to you"

PORT80_LEAD = (
    "This machine belongs to whichports.com. It checks whether ports are "
    "reachable, on servers whose owners asked us to check them. If you found "
    "this address in a log, what follows is the whole explanation."
)

PORT80_SECTIONS = [
    ("What it did", [
        "One TCP connection to one port, to see whether it opened, and then "
        "it closed again. On a TLS port it also finishes the handshake and "
        "reads the certificate.",
        "Nothing past that. No login attempt, no exploit, no version probe, "
        "and nothing read from inside your service.",
    ]),
    ("Why it connected to you", [
        "Because somebody who controls the address we connected to asked us "
        "to check it, and showed us they control it. We do not pick addresses "
        "ourselves and we do not walk ranges.",
        "Where we hold no proof of control for an address, we send it nothing.",
    ]),
    ("How to check that without asking us", [
        "Look up the address from your log. It has a reverse DNS name under "
        f"{RDNS_ZONE}. Look that name up forward and you get the same address "
        "back. Both halves have to agree, because a reverse record on its own "
        "is set by whoever runs the reverse zone for that address, and the "
        "forward record is the half only we can set.",
        f"Then compare it against the published list at {LIST_URL}. Every "
        "address we probe from is on it. If the address in your log is not on "
        "that list then it is not us, and we would like to hear about it.",
    ]),
    ("How to make it stop", [
        "The account that asked for the check can take the address off it, "
        "and the checks stop with it.",
        f"Or mail {ABUSE} and we stop probing the address, and when an agent "
        "proved it, every other address of that server or self-hosted "
        "instance stops with it. You do not have to prove anything to make "
        "us stop.",
        "Or drop our addresses at your own firewall. The published list is "
        "there for that, and we will not move to a different address to get "
        "around it.",
        f"If you own the address and nobody in your organisation asked for "
        f"this, mail {ABUSE}. We stop, and we tell you what proof of control "
        "we were holding and when it was recorded. An address changes hands, "
        "and an authorisation we should have dropped is our mistake to fix.",
    ]),
    ("What we keep", [
        "The port, whether the connection opened, and on a TLS port what the "
        "certificate said.",
        "No payload, no packet capture, and nothing from inside your service.",
    ]),
]


def prose() -> list[str]:
    """Every sentence any of these artifacts shows a reader, for the tests."""
    out = [PORT80_TITLE, PORT80_LEAD]
    out += EMPTY_LINES + FORMAT_LINES + RDNS_LINES + ABUSE_LINES
    for heading, paragraphs in PORT80_SECTIONS:
        out.append(heading)
        out += paragraphs
    return out


# ------------------------------------------------------- the machine readable

def range_list_text() -> str:
    """probers.txt. A comment block a person reads, and bare lines a script does."""
    head = [
        "# whichports prober addresses",
        "#",
        "# Every port check we make comes from an address in this list, and "
        "from no other",
        "# address. Allowlist them if you want the checks to reach you, or "
        "drop them if",
        "# you want them to stop.",
        "#",
        f"# addresses: {len(PROBERS)}",
        f"# updated: {UPDATED}",
        f"# this file: {LIST_URL}",
        f"# in words: {PAGE_URL}",
        f"# abuse and exclusion: {ABUSE}",
        "#",
    ]
    for line in FORMAT_LINES + RDNS_LINES:
        head += _wrap_comment(line)
        head.append("#")
    if not PROBERS:
        for line in EMPTY_LINES:
            head += _wrap_comment(line)
            head.append("#")
        return "\n".join(head) + "\n"
    body = []
    for p in PROBERS:
        body.append(f"# {p.rdns}, {p.provider}, on this list since {p.added}")
        body.append(p.address)
    return "\n".join(head + body) + "\n"


def _wrap_comment(text, width=72):
    """One sentence as `# ` comment lines, wrapped so a terminal shows it whole."""
    words = text.split()
    lines, current = [], "#"
    for word in words:
        if len(current) + 1 + len(word) > width and current != "#":
            lines.append(current)
            current = "#"
        current += " " + word
    lines.append(current)
    return lines


# ------------------------------------------------------------- the two pages

# Both pages are dark only, which is a decision rather than an omission. The
# landing and the notes page each carry the two small mode scripts of
# docs/DESIGN.md section 4, and a third copy of that script is one more
# thing to drift. Dark is the primary mode (DESIGN.md
# section 1), and the page on port 80 is better off with no JavaScript at all,
# because the machine serving it is a prober. Moving the mode scripts into
# theme.py so all four pages share one copy is its own PR.
_LIST_CSS = """
.wrap{max-width:820px;margin:0 auto;padding:0 28px}
.top{padding:26px 0;display:flex;align-items:center;justify-content:space-between;gap:20px}
.hd{padding:44px 0 34px;border-bottom:1px solid var(--line)}
h1{font-size:32px;line-height:1.18}
.lead{margin-top:18px;font-size:17px;line-height:1.6;color:var(--muted);max-width:62ch}
.s{padding:34px 0;border-bottom:1px solid var(--line)}
.k{font-size:10.5px;letter-spacing:.15em;text-transform:uppercase;color:var(--faint)}
h2{font-size:20px;margin-top:10px}
.p{margin-top:13px;font-size:14.5px;color:var(--muted);max-width:70ch;line-height:1.65}
.p a{color:var(--acc-ink);text-decoration:underline;text-underline-offset:2px}
.mono{font-family:"IBM Plex Mono",monospace}
.none{margin-top:20px;border:1px solid var(--line2);border-radius:var(--r);
  background:var(--panel);padding:18px 20px;font-family:"IBM Plex Mono",monospace;
  font-size:13.5px;color:var(--ink)}
table{width:100%;border-collapse:collapse;margin-top:20px;border:1px solid var(--line);
  border-radius:var(--r);overflow:hidden}
th{text-align:left;font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;
  color:var(--faint);font-weight:500;background:var(--panel2);padding:10px 14px}
td{padding:11px 14px;border-top:1px solid var(--line);font-size:13.5px;
  font-family:"IBM Plex Mono",monospace;color:var(--ink)}
.foot{padding:26px 0 60px;color:var(--faint);font-size:12.5px}
@media(max-width:700px){h1{font-size:26px}table,th,td{font-size:12.5px}}
"""


def _autolink(text):
    """Make the addresses in the copy clickable without putting HTML in the copy.

    The sentences above are held as plain text so the tests can read them and
    so the same words can go into a text file. A reader who found a log line
    still wants to click the list, so the links are added here at render time.
    The URL pattern stops before a trailing full stop or bracket on purpose.
    """
    text = re.sub(r"https://[^\s<]*[^\s<.,)]",
                  lambda m: f'<a class="mono" href="{m.group(0)}">{m.group(0)}</a>',
                  text)
    return re.sub(r"[\w.+-]+@[\w-]+\.[\w.-]+\w",
                  lambda m: f'<a class="mono" href="mailto:{m.group(0)}">'
                            f'{m.group(0)}</a>', text)


def _paras(lines, cls="p"):
    return "".join(f'<p class="{cls}">{_autolink(line)}</p>' for line in lines)


def _link(url):
    return f'<a class="mono" href="{url}">{url}</a>'


def range_list_page() -> str:
    """probers.html. The same list a person can read, in the house style."""
    if PROBERS:
        rows = "".join(
            f"<tr><td>{p.address}</td><td>{p.rdns}</td><td>{p.provider}</td>"
            f"<td>{p.added}</td></tr>" for p in PROBERS)
        listing = ('<table><tr><th>Address</th><th>Reverse DNS</th>'
                   '<th>Where it runs</th><th>On the list since</th></tr>'
                   f"{rows}</table>")
    else:
        listing = ('<div class="none">' + EMPTY_LINES[0] + "</div>"
                   + _paras(EMPTY_LINES[1:]))
    machine = FORMAT_LINES[0] + " " + FORMAT_LINES[1]
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>whichports prober addresses</title>
<meta name="description" content="Every address the whichports prober makes port
checks from, and how to have one excluded.">
{theme.ICON_LINKS}
<style>{theme.fonts()}{theme.TOKENS}{theme.BASE}{_LIST_CSS}</style></head>
<body>
<div class="wrap"><div class="top">{theme.mark()}
  <span class="k">updated {UPDATED}</span></div></div>

<div class="wrap hd">
  <h1>Prober addresses</h1>
  <p class="lead">Every port check we make comes from an address on this list, and
    from no other address. Allowlist them if you want the checks to reach you, or
    drop them if you want them to stop.</p>
</div>

<div class="wrap s">
  <div class="k">The list</div>
  <h2>{len(PROBERS)} addresses</h2>
  {listing}
</div>

<div class="wrap s">
  <div class="k">For a script</div>
  <h2>The same list as plain text</h2>
  <p class="p">{_link(LIST_URL)}</p>
  <p class="p">{machine}</p>
</div>

<div class="wrap s">
  <div class="k">Reverse DNS</div>
  <h2>Checking an address is really ours</h2>
  {_paras(RDNS_LINES)}
  <p class="p">Each address also serves a page on port 80 saying what it is and
    how to make it stop, so a log line answers itself without anyone reading
    this page first.</p>
</div>

<div class="wrap s">
  <div class="k">Abuse and exclusion</div>
  <h2>{ABUSE}</h2>
  {_paras(ABUSE_LINES)}
</div>

<div class="wrap foot">whichports, Ghent, Belgium</div>
</body></html>
"""


def port80_page() -> str:
    """The page every prober address serves on port 80.

    One file, on purpose. It carries its own fonts and its own icon as data,
    so the machine serving it makes no request anywhere and needs no second
    file. The cost is about 230 kB of base64 in the page, which is the right
    trade for a page a stranger loads once and needs to trust.
    """
    icon = base64.b64encode(theme.favicon_svg().encode()).decode()
    sections = "".join(
        f'<div class="wrap s"><h2>{heading}</h2>{_paras(paragraphs)}</div>'
        for heading, paragraphs in PORT80_SECTIONS)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>{PORT80_TITLE}</title>
<link rel="icon" href="data:image/svg+xml;base64,{icon}">
<style>{theme.fonts(inline=True)}{theme.TOKENS}{theme.BASE}{_LIST_CSS}</style></head>
<body>
<div class="wrap"><div class="top">{theme.mark()}</div></div>

<div class="wrap hd">
  <h1>{PORT80_TITLE}</h1>
  <p class="lead">{PORT80_LEAD}</p>
</div>

{sections}

<div class="wrap s">
  <div class="k">In one place</div>
  <h2>{ABUSE}</h2>
  {_paras(ABUSE_LINES)}
  <p class="p">The addresses we probe from: {_link(PAGE_URL)}, or
    {_link(LIST_URL)} for a script.</p>
</div>

<div class="wrap foot">whichports, Ghent, Belgium</div>
</body></html>
"""


if __name__ == "__main__":
    # Written beside this file so it can be opened and looked at. The two
    # published files belong to build_site.py, which writes them into dist/.
    out = pathlib.Path(__file__).resolve().parent / "prober-port80.html"
    page = port80_page()
    out.write_text(page)
    print("wrote", out, len(page), "bytes")
