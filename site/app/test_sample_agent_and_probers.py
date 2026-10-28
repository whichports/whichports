"""The sample page's agent version and its probers, held to what the public
pages say (docs/RECORD.md 4.443).

The sample page goes public with the repository, beside a landing page that
names the published agent and says two probers measure a port. The sample
read version 0.1.8 and named one prober. Its version is now the published
agent's, held to the landing page's builder by a test here since the two
builders do not import each other, and it names two probers on every line
that names one.

    Run from site/: python3 -m pytest app/test_sample_agent_and_probers.py
"""
import html as html_mod
import importlib.util
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402

LANDING_BUILDER = pathlib.Path(__file__).resolve().parent.parent / "landing" / "build.py"


def landing():
    """The landing page's builder, loaded under a name of its own: it is
    called build.py too."""
    spec = importlib.util.spec_from_file_location("landing_builder", LANDING_BUILDER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def text_of(markup):
    bare = re.sub(r"<[^>]+>", " ", re.sub(r"<svg.*?</svg>", "", markup, flags=re.S))
    return " ".join(html_mod.unescape(bare).split()).replace(" ,", ",")


def evidence_card(title):
    """One of the Evidence tab's three cards on the sample, label to words."""
    page = build.build_sample()
    tab = page.split('id="t-host-evidence"', 1)[1]
    card = tab.split(f"<b>{title}</b>", 1)[1].split('<div class="evcard', 1)[0]
    return {text_of(k): text_of(v) for k, v in re.findall(
        r'<span class="evk">(.*?)</span><span>(.*?)</span></div>', card, re.S)}


def prober_lines_of_the_overview():
    """Every card's prober line on the sample's Overview that names a prober."""
    page = build.build_sample()
    overview = page.split('id="t-host-overview"', 1)[1].split('id="t-host-services"', 1)[0]
    lines = re.findall(r'<span class="k">prober</span><span class="v">(.*?)</span></div>', overview, re.S)
    return [text_of(line) for line in lines if " from " in text_of(line)]


# ------------------------------------------------------------------ the version

def test_the_samples_agent_is_the_published_one():
    assert build.SAMPLE_AGENT_VERSION == landing().PUBLISHED_AGENT


def test_the_version_is_drawn_from_that_one_line_in_both_places():
    page = build.build_sample()
    assert evidence_card("The agent, inside")["version"] == build.SAMPLE_AGENT_VERSION
    agent = page.split('class="hstage h-agent"', 1)[1].split('class="hstage ', 1)[0]
    assert f"Version {build.SAMPLE_AGENT_VERSION}" in text_of(agent)


def test_no_older_version_is_left_on_the_sample():
    assert "0.1.8" not in build.build_sample()


# ------------------------------------------------------------------ the probers

def test_the_evidence_tab_names_two_probers():
    """The landing page says two probers measure a port."""
    assert "two probers" in LANDING_BUILDER.read_text(encoding="utf-8")
    assert evidence_card("The prober, outside")["vantages"] == "probe1, probe2"


def test_every_card_that_names_a_prober_names_the_ones_evidence_names():
    """A card naming one prober beside an Evidence tab naming two read as a
    prober that measured nothing, which the live page stopped doing in
    4.395."""
    named = evidence_card("The prober, outside")["vantages"]
    lines = prober_lines_of_the_overview()
    assert len(lines) >= 2, lines
    for line in lines:
        assert f"from {named}," in line, line
