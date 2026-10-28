"""No comment of ours leaves in a page this app serves itself, or in a mail.

The rule and its reason are in site/theme.py, and
site/test_no_comment_leaves_in_a_page.py holds it for the pages the site
builds. These are the control plane's own: the sign-in pages, which anybody
can open without an account, and the frame every mail is sent in.

On 2026-10-02 the live sign-in page carried 38 comments in its source
(docs/RECORD.md 4.247). A comment is not on the screen, so no test of what a
page says had ever read one.
"""
import pytest

from app import mailhtml, web_pages

CSRF = "x" * 40


def pages():
    return {
        "sign in": web_pages.login_page(csrf=CSRF, next_path="/"),
        "sign in with a code": web_pages.login_page(csrf=CSRF, next_path="/", code=True),
        "the second factor": web_pages.two_factor_page(csrf=CSRF, next_path="/"),
        "a plain message": web_pages.simple_page("Done", "<p>Done.</p>"),
        "register": web_pages.register_page(csrf=CSRF),
        "ask for a reset": web_pages.reset_ask_page(csrf=CSRF),
        "a link was sent": web_pages.link_sent_page("Check your mail", "a@example.org"),
        "choose a password": web_pages.choose_password_page(
            csrf=CSRF, action="/reset/abc", email="a@example.org"),
        "join a workspace": web_pages.join_page(
            csrf=CSRF, action="/join/abc", workspace="ops", invited_by="b@example.org"),
    }


NAMES = sorted(pages())


@pytest.mark.parametrize("name", NAMES)
def test_a_page_this_app_serves_carries_no_comment(name):
    found = web_pages.theme().comments_in_page(pages()[name])
    assert not found, f"{name} still carries:\n  " + "\n  ".join(found[:20])


def test_the_password_rules_script_still_runs_its_rules():
    """The strip takes whole comment lines out of that script. What is left
    has to be the script: its three tests and the paint that uses them."""
    page = web_pages.register_page(csrf=CSRF)
    for kept in ("length:function(v){return v.length>=MIN}",
                 "digit:function(v){return /[0-9]/.test(v)}",
                 "special:function(v){return /[^A-Za-z0-9]/.test(v)}",
                 "var typed=test?value:second;",
                 "input.addEventListener('input',paint);"):
        assert kept in page, kept


def test_the_comments_stay_in_the_source_for_whoever_reads_it():
    assert "/*" in web_pages._CSS
    assert "// " in web_pages._RULES_SCRIPT


def test_a_mail_carries_no_comment():
    """The frame every mail shares has a <style> block of its own, and a
    comment in it would be sent to every inbox."""
    mail = mailhtml.shell("A heading", "One lead sentence.", "", "A closing line.",
                          link="https://app.example.org/")
    assert web_pages.theme().comments_in_page(mail) == []
    # The two rules those comments were about are still there.
    assert "@media only screen and (max-width:620px)" in mail
    assert "@media (prefers-color-scheme:dark)" in mail
