"""One tag shape, one builder.

The small mark beside a label or a state, `<span class="tag-<kind>">`, was
drawn by six builders and eleven literals until 2026-09-03. `build.tag` is
the one definition now; the six builders say what a kind means and call it.
"""
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402


def test_no_tag_is_written_by_hand_in_either_renderer():
    """Comments and the stylesheet may name a tag class. Markup may not."""
    for module in (build, rl):
        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        assert not re.search(r'<span class="tag-(?!\{kind\})', source), module.__name__


def test_the_builder_draws_a_tag_the_way_they_were_drawn():
    assert build.tag("planned", "planned") == '<span class="tag-planned">planned</span>'
    assert build.PLANNED_TAG == '<span class="tag-planned">planned</span>'
    assert build.tag("rvw") == '<span class="tag-rvw"></span>'
    assert build.tag("mute", "muted", data_mute_tag="box") == \
        '<span class="tag-mute" data-mute-tag="box">muted</span>'
    assert build.tag("rate", "", data_silence_tag=True) == \
        '<span class="tag-rate" data-silence-tag></span>'


def test_the_six_builders_still_say_what_they_said():
    assert build.rate_flag(True) == '<span class="tag-rate" title="rate limited">rate limited</span>'
    assert build.rate_flag(False) == ""
    assert build.muted_flag("box", True) == \
        '<span class="tag-mute" data-mute-tag="box" title="muted">muted</span>'
    assert build.muted_flag("box", False) == '<span class="tag-mute" data-mute-tag="box" title="muted"></span>'
    assert build.mode_flag("full read") == '<span class="tag-mode">full read</span>'
    assert build.mode_flag("") == ""
    assert build.silenced_flag(True) == (
        '<span class="tag-rate" data-mark="silenced" title="silenced">'
        f'{build.SILENCED_WORD}</span>')
    assert build.silenced_flag(False) == ""
