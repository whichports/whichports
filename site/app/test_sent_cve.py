"""The Sent list's row for the CVE message.

    Run from site/: python3 -m pytest app/test_sent_cve.py

The sent log keeps the message's title as the line's words
(`controlplane/app/cvesend.py`, `_log`) and not its kind, so the Alerts
screen reads the kind from how the title opens. Until 2026-10-27 it did not
know this kind, and the tag was the whole title, where every other kind has
a short word of its own. The title is made here by the control plane's own
function, so this cannot drift from it.
"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import joinbridge  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402

NOW = trl.NOW


def title(offered, servers=("web",)):
    """The title of a CVE message as the control plane writes it."""
    cvewords = joinbridge.module("cvewords")
    return cvewords.said([cvewords.Told(host_name=name, ports=(("tcp", 443),),
                                        cves=frozenset({"CVE-2026-0001"}), offered=offered)
                          for name in servers]).title


def line(detail):
    rows = [dict(host_name="web", detail=detail, sent_at=NOW.isoformat(), channel="email")]
    (got,) = rl.sent_alert_lines(rows)
    return got


@pytest.mark.parametrize("offered", [True, False], ids=["an update", "a newer version"])
@pytest.mark.parametrize("servers", [("web",), ("web", "db")], ids=["one server", "two servers"])
def test_the_sent_line_is_tagged_cve(offered, servers):
    said = title(offered, servers)
    got = line(said)
    assert got.word == "cve"
    # The title is the line's words, said once, in Why and not as the tag.
    assert got.why == said
    assert (got.protocol, got.port, got.families) == ("", "", ())


def test_a_line_that_only_mentions_cves_is_not_this_kind():
    """Only the two openings the message has are this kind."""
    assert line("CVEs on web, something else").word != "cve"
