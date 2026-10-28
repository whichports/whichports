"""Every weight a stylesheet asks of a family is a face that ships.

    Run from site/app: python3 -m pytest test_font_faces.py

A weight the page asks for and does not ship is not an error anywhere. The
browser draws it by smearing the nearest face it has, the page still renders,
and nothing fails but the look. Until 2026-09-10 seven rules asked for IBM
Plex Mono at 600 over a Regular that shipped alone, which is every bold port
number on the dashboard, and the only report of it was the owner's, that it
sometimes looked wrong.

**Why a weight below the nearest face is not flagged.** CSS matches 500 to 400
when 400 and 600 are the faces there are, without drawing anything. It only
smears when asked for something heavier than every face it has, and a face is
never synthesised lighter. So a rule asking for more than the heaviest face of
its family is the defect, and that is what this looks for.
"""
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import theme  # noqa: E402


def shipped_weights():
    """{family: the weights shipped for it}, from the one list of faces."""
    out = {}
    for family, _file, weight in theme._FACES:
        out.setdefault(family, set()).add(weight)
    return out


def rules_asking_for(css, family):
    """(selector, weight) for every rule that names the family and a weight."""
    out = []
    for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        if f'"{family}"' not in body:
            continue
        weight = re.search(r"font-weight:\s*(\d{3})", body)
        if weight:
            out.append((selector.strip()[-70:], int(weight.group(1))))
    return out


def stylesheets():
    """The two stylesheets every dashboard page carries."""
    return {"theme": theme.TOKENS + theme.BASE, "dashboard": build.CSS}


@pytest.mark.parametrize("family", sorted(shipped_weights()))
def test_no_rule_asks_a_family_for_more_than_its_heaviest_face(family):
    heaviest = max(shipped_weights()[family])
    too_heavy = [(name, selector, weight)
                 for name, css in stylesheets().items()
                 for selector, weight in rules_asking_for(css, family)
                 if weight > heaviest]
    assert not too_heavy, (
        f"{family} ships up to {heaviest}, and these ask for more, which the "
        f"browser fakes: {too_heavy}")


def test_every_face_listed_is_a_file_that_ships():
    """A face listed and not on disk is a request for a font that is never
    there, the same defect from the other side."""
    for _family, name, _weight in theme._FACES:
        assert (theme.FONT_DIR / f"{name}.woff2").is_file(), name


def test_bold_port_numbers_have_a_real_face_to_draw_with():
    """The case that was broken, named, so the reason for the SemiBold is on
    record in the suite and not only in a comment."""
    assert 600 in shipped_weights()["IBM Plex Mono"]
    assert any(selector.endswith(".prn") and weight == 600
               for selector, weight in rules_asking_for(build.CSS, "IBM Plex Mono"))
