"""The sample's server tells one story on every tab (docs/RECORD.md 4.443).

An outside reader found the sample contradicting itself about port 8410:
the Overview said no rule names it and ufw's default is allow, the Rules tab
listed a rule for it and a default of deny, Evidence said the provider
permits it, the Overview said no provider is connected, and the Packet path
listed other rules again. Each tab was written by hand.

The server is one description now (sample_story.py) and every tab is drawn
from it by the live page's own function. This test reads three things off
each of the four tabs as a reader would, ufw's default for incoming, the rule
for 8410 and what is said of the provider, and fails when two tabs differ.
A tab that says nothing about one of them is left out of that comparison,
and the count of tabs that do speak is held, so nothing passes by silence.

    Run from site/: python3 -m pytest app/test_sample_one_story.py
"""
import html as html_mod
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import sample_story  # noqa: E402

PORT = 8410
TABS = ("overview", "rules", "evidence", "path")


def text_of(markup):
    bare = re.sub(r"<[^>]+>", " ", re.sub(r"<svg.*?</svg>", "", markup, flags=re.S))
    return " ".join(html_mod.unescape(bare).split()).replace(" ,", ",")


def tabs_of(page):
    """The four tabs of the sample's server page, as markup."""
    section = page[page.index('<div class="wrap view" id="host"'):]
    return {name: section.split(f'id="t-host-{name}"', 1)[1].split('id="t-host-', 1)[0]
            for name in TABS}


def after(words, marker):
    """The word that follows `marker`, or None when the words do not hold it."""
    found = re.search(re.escape(marker) + r" ([a-z]+)", words)
    return found.group(1) if found else None


def said(tabs):
    """What each tab says about the three things, in one vocabulary:
    {tab: {"default": word or None, "rule": "none" or the rule or None,
           "provider": words or None}}."""
    out = {}

    # The Overview: the v4 card of the port's own row.
    row = tabs["overview"].split(f'for="pr-host-tcp-{PORT}"', 1)[1].split('class="prsel"', 1)[0]
    card = row.split('<div class="prec">', 2)[1]
    lines = {k: text_of(v) for k, v in re.findall(
        r'<span class="k">([a-z]+)</span><span class="v">(.*?)</span></div>', card, re.S)}
    out["overview"] = {
        "default": after(lines["firewall"], "ufw default"),
        "rule": "none" if lines["firewall"].startswith(f"no rule names {PORT}") else lines["firewall"],
        "provider": lines["provider"]}

    # The Rules tab: ufw's own block and its numbered rules.
    rules = text_of(tabs["rules"])
    block = tabs["rules"].split('class="fwh"', 1)[1]
    naming = re.search(rf"\b(allow|deny|limit|reject) {PORT} tcp", rules)
    out["rules"] = {
        "default": after(text_of(block.split("</div>", 1)[0]), "incoming"),
        "rule": "none" if not naming else naming.group(0),
        "provider": "not connected" if "No provider connected" in rules else rules}

    # Evidence: the agent's card, the port's v4 row and the provider's card.
    evidence = tabs["evidence"]
    agent = text_of(evidence.split("<b>The agent, inside</b>", 1)[1].split('<div class="evcard', 1)[0])
    provider_card = text_of(evidence.split("<b>The provider</b>", 1)[1].split("</div>", 1)[0])
    out["evidence"] = {
        "default": after(agent, "default incoming"),
        "rule": None,
        "provider": "not connected" if provider_card.startswith("not connected") else provider_card}

    # The Packet path: the flow of the port over v4.
    path = tabs["path"]
    chips = re.findall(r'<label for="pp-host-c-\d+">([^<]+)</label>', path)
    flow = text_of(path.split('data-flow="')[1:][chips.index(f"{PORT}/tcp v4")])
    out["path"] = {
        "default": after(flow, "default incoming"),
        "rule": "none" if f"no rule for {PORT}" in flow else flow[:80],
        "provider": None}
    return out


def disagreements(told):
    """Every one of the three things on which two tabs say different words."""
    found = []
    for thing in ("default", "rule", "provider"):
        words = {tab: told[tab][thing] for tab in TABS if told[tab][thing] is not None}
        if len(set(words.values())) > 1:
            found.append(f"{thing}: {words}")
    return found


@pytest.fixture(scope="module")
def tabs():
    return tabs_of(build.build_sample())


def test_no_two_tabs_differ_on_the_default_the_rule_or_the_provider(tabs):
    assert disagreements(said(tabs)) == []


def test_enough_tabs_speak_that_silence_proves_nothing(tabs):
    told = said(tabs)
    speaking = {thing: [tab for tab in TABS if told[tab][thing] is not None]
                for thing in ("default", "rule", "provider")}
    assert speaking["default"] == ["overview", "rules", "evidence", "path"]
    assert speaking["rule"] == ["overview", "rules", "path"]
    assert speaking["provider"] == ["overview", "rules", "evidence"]


def test_the_story_is_the_overviews(tabs):
    """No ufw rule names 8410, the default for incoming is allow, no
    provider is connected: so it answers and nobody said it should."""
    told = said(tabs)
    assert told["overview"] == {"default": "allow", "rule": "none", "provider": "not connected"}
    row = next(r for r in sample_story.parts().rows if (r.protocol, r.port) == ("tcp", PORT))
    assert (row.word, row.decided) == ("unreviewed", "no rule")


def test_the_reading_notices_a_tab_that_says_otherwise(tabs):
    """The test above is only worth its green if this reading can fail. Each
    of the old sample's three contradictions, put back into one tab."""
    def told_with(tab, old, new):
        assert old in tabs[tab], (tab, old)
        return said({**tabs, tab: tabs[tab].replace(old, new)})

    deny = told_with("rules", "incoming <b>allow</b>", "incoming <b>deny</b>")
    assert [d.split(":")[0] for d in disagreements(deny)] == ["default"]
    permitted = told_with("evidence", "<b>The provider</b><span>not connected</span>",
                          "<b>The provider</b><span>connected</span>")
    assert [d.split(":")[0] for d in disagreements(permitted)] == ["provider"]
    named = told_with("path", f"no rule for {PORT}", f"allow {PORT}, from 10.0.0.0/8")
    assert [d.split(":")[0] for d in disagreements(named)] == ["rule"]
    listed = told_with("rules", ">8096<", f">{PORT}<")
    assert [d.split(":")[0] for d in disagreements(listed)] == ["rule"]


def test_the_rules_tab_lists_the_rules_the_story_has(tabs):
    """Four that allow, one that denies, none for 8410, and no provider's
    firewall, since none is connected."""
    rules = text_of(tabs["rules"])
    for port in sample_story.ALLOWED:
        assert f"allow {port} tcp" in rules, port
    for port in sample_story.DENIED:
        assert f"deny {port} tcp" in rules, port
    assert f"allow {PORT} tcp" not in rules and f"deny {PORT} tcp" not in rules
    assert "No provider connected" in rules


def test_the_overviews_boxes_are_the_engines_count(tabs):
    """Four of seven answer, two wait for an answer (a conflict is not counted
    there, it colours the box), and one port changed: the one this is about."""
    boxes = text_of(tabs["overview"].split('class="panel ptbl"', 1)[0])
    assert "Reachable from outside 4 of 7 ports" in boxes
    assert "Needs a decision 2 of 7 ports" in boxes
    assert "Changed in 24h 1 8410/tcp became reachable" in boxes


# The sample names one person's mail address, in the account, the channel,
# the alert lines and the Fleet's notice. The notice said example.com while
# every other place said example.org (docs/RECORD.md 4.453).
MAIL = re.compile(r"[A-Za-z0-9._+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")


def mail_addresses(page):
    """Every mail address the page names, each once."""
    return sorted(set(MAIL.findall(page)))


def test_the_reading_notices_a_second_address():
    page = "to a@example.org, from a@example.org, refused for a@example.com"
    assert mail_addresses(page) == ["a@example.com", "a@example.org"]


def test_the_sample_names_one_mail_address():
    page = build.build_sample()
    assert mail_addresses(page) == [build.SAMPLE_ACCOUNT["email"]]
    # the notice is one of the places read, and there are others beside it
    assert f'Alert mail to <b>{build.SAMPLE_ACCOUNT["email"]}</b>' in page
    assert len(MAIL.findall(page)) > 3
