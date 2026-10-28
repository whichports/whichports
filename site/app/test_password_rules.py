"""The password rules, spelled twice and compared here.

    Run from site/app: python3 -m pytest test_password_rules.py

`controlplane/app/accounts.py` defines them and checks them. This side draws
them, and the browser re-checks them while somebody types, so the words exist
in three places: the control plane's list, `build.PASSWORD_RULES`, and the
three tests in `page.js`. Twice and never compared is how copies drift
apart, and this file is the comparison.
"""
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import joinbridge  # noqa: E402

accounts = joinbridge.module("accounts")


def test_the_rules_and_their_words_are_the_same_on_both_sides():
    theirs = [(key, words) for key, words, _test in accounts.PASSWORD_RULES]
    assert list(build.PASSWORD_RULES) == theirs


def test_the_minimum_is_the_same_number_on_both_sides():
    assert build.PASSWORD_MIN_CHARS == accounts.PASSWORD_MIN_CHARS


def test_the_browser_checks_exactly_the_rules_the_server_checks():
    """A page listing three rules while the browser tests two is a form that
    goes green on a password the server then refuses."""
    tested = set(re.findall(r"\n    (\w+):function\(v\)", build.PAGE_JS))
    assert tested == {key for key, _words in build.PASSWORD_RULES}


def test_the_browser_uses_the_minimum_the_page_was_given():
    """The number is filled in by `page()` rather than written into the
    script, so one change moves both."""
    assert "v.length>=__PASSWORD_MIN__" in build.PAGE_JS
    assert "v.length>=12" in build.build_sample()


def test_every_rule_the_browser_tests_agrees_with_the_server():
    """The same passwords through both. The browser's tests are read out of
    `page.js` and translated, because running them is a browser's job and
    agreeing with the server is this file's."""
    checks = {
        "length": lambda v: len(v) >= build.PASSWORD_MIN_CHARS,
        "digit": lambda v: re.search(r"[0-9]", v) is not None,
        "special": lambda v: re.search(r"[^A-Za-z0-9]", v) is not None,
    }
    for password in ("", "short", "abcdefghijkl", "abcdefghijkl9",
                     "abcdefghijkl!", "abcdefghijk9!", "abcdefghijk 9",
                     "12345678901!", "ééééééééééé9!"):
        server = accounts.password_rules_met(password)
        browser = {key: test(password) for key, test in checks.items()}
        assert server == browser, password


def test_both_painters_wait_for_a_field_before_they_say_anything_about_it():
    """A rule is grey until the field it is about has something in it.

    For the three tests that field is the password. For Both the same it is
    the confirm box, which is why the painter reads that box's own value: a
    red line under an untouched field is an error nobody has made yet.

    The dashboard and the sign-in pages carry their own copy of the painter,
    because one is in `page.js` and the other is served with the page. This is
    what keeps the two the same.
    """
    pages = (pathlib.Path(__file__).resolve().parent.parent.parent
             / "controlplane" / "app" / "web_pages.py").read_text()
    for name, script in (("page.js", build.PAGE_JS), ("web_pages.py", pages)):
        assert "var typed=test?value:second;" in script, name
        assert "ok=test?test(value):(!!second&&second===value)" in script, name
        assert "toggle('yes',!!typed&&ok)" in script, name
        assert "toggle('no',!!typed&&!ok)" in script, name


def test_the_rules_are_drawn_under_the_field_they_apply_to():
    html = build.password_rules_html("pw-new", "pw-again")
    assert 'data-for="pw-new"' in html and 'data-confirm="pw-again"' in html
    assert [m for m in re.findall(r'data-rule="(\w+)"', html)] == [
        key for key, _words in build.PASSWORD_RULES] + ["match"]
    # without a confirm field there is no fourth line to draw
    alone = build.password_rules_html("pw-new")
    assert "match" not in alone and "data-confirm" not in alone


def test_the_change_password_window_asks_twice_and_draws_the_rules():
    """The owner, 2026-09-10: the same flow for changing a password under
    Security, with the password typed twice."""
    html = build.password_modal(live=True)
    assert 'id="pw-current"' in html and 'id="pw-new"' in html and 'id="pw-again"' in html
    assert "Confirm password" in html and "Password again" not in html
    assert 'data-for="pw-new"' in html and 'data-confirm="pw-again"' in html


def test_no_screen_explains_why_the_rules_are_what_they_are():
    """The rules are the statement. The sentence that used to sit under the
    field, about length being the only rule, went with them."""
    html = build.build_sample()
    for gone in ("Password1", "Length is the only rule", "because the others"):
        assert gone not in html, gone
