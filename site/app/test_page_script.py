"""The page's script is page.js, read by build.py and filled in.

Until 2026-09-03 it was 1,783 lines inside the f-string that `page()` returns,
so every brace was doubled and no tool read it. Now it is a plain file. What
must hold: node parses it, every marker the file carries gets a value from
`page()`, a marker nobody fills is refused rather than shipped as its own
name, and the file's own header is not sent to a browser.
"""
import pathlib
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402

PAGE_JS = pathlib.Path(build.__file__).with_name("page.js")


def test_node_parses_the_script():
    """A syntax error in the script used to be a blank dashboard and nothing
    else. Not finding node is a failure, never a skip: the gate allows no
    skips and this is the one check that reads the file as JavaScript."""
    node = shutil.which("node")
    if not node:
        pytest.fail("no node on this machine, and page.js can only be parsed by one")
    subprocess.run([node, "--check", str(PAGE_JS)], check=True)


def test_every_marker_in_the_file_is_filled_by_the_page():
    """The markers the file carries and the values page() gives are one list,
    and a rendered page carries none of them."""
    markers = set(build.PAGE_JS_MARKER.findall(build.PAGE_JS))
    assert markers == {"__VIEWING_OPEN__", "__TRY_COMMAND__", "__SILENCED_WORD__",
                       "__TONE_JSON__", "__PASSWORD_MIN__", "__BOOT_JS__",
                       "__FEEDBACK_SCREENS__", "__FEEDBACK_MAX__"}
    html = build.build_sample()
    assert not build.PAGE_JS_MARKER.search(html)


def test_a_marker_without_a_value_is_refused():
    with pytest.raises(ValueError, match="__BOOT_JS__"):
        build.page_script(__VIEWING_OPEN__="[]", __TRY_COMMAND__="''",
                          __SILENCED_WORD__="", __TONE_JSON__="{}",
                          __PASSWORD_MIN__="12")


def test_the_files_own_header_does_not_ship():
    """The comment block at the top of page.js is for whoever opens the file.
    The page starts at the first line of code, exactly as it did when the
    script lived inside build.py."""
    assert build.PAGE_JS.startswith("//")
    body = build.script_body(build.PAGE_JS)
    assert body.startswith("var toastT;")
    html = build.build_sample()
    assert "<script>\nvar toastT;" in html
    assert "// The dashboard's script." not in html


def test_the_script_says_and_does_the_repeated_things_once():
    """Since 2026-09-03: one ask() reads an answer's body whatever its status,
    one copyText() reaches the clipboard, and the two sentences every action
    falls back on are written once. A second copy of any of these is the
    drift this removed."""
    body = build.script_body(build.PAGE_JS)
    assert body.count("return {ok:r.ok,status:r.status,body:j}") == 1
    assert body.count("execCommand('copy')") == 1
    assert body.count("No answer. Check your connection and try again.") == 1
    assert body.count("That did not work, HTTP ") == 1
    assert "var ask=function(url,opts)" in body
    assert "var copyText=function(text,box)" in body
