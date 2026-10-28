"""Where alerts go is on Integrations, so nothing we say sends a person to
the Alerts screen for it.

    python -m pytest tests/test_no_sentence_names_the_alerts_screen.py

docs/screens/alerts/SPEC-layout-b.md. The table of destinations, the window
that adds one and Send test left the Alerts screen for Integrations. Four
sentences of the control plane still named the Alerts screen for them: the
test message, the same message as a webhook's typed document, the page a
Slack connect ends on, and a command's help. A message that says "Sent from
the Alerts screen" with a button to a screen that holds no Send test is a
wrong fact in somebody's inbox.

So every piece of text this code can say is read here, and none names the
Alerts screen. Comments and docstrings are not text it can say, and are
left to whoever reads them. A sentence that one day has to name the Alerts
screen for what is on it, an open alert, is named here when it is written.
"""
import ast
import pathlib

from app import alertwords, publicurl, senders, web_pages

APP = pathlib.Path(__file__).resolve().parent.parent / "app"
# The screen by its name in any case, and the two buttons that led to it as
# they were written. "Open alerts" in small letters is a count of alerts
# that are open, which a metric's help may say.
SCREEN = "alerts screen"
BUTTONS = ("Open Alerts", "Back to Alerts")


def names_it(text: str) -> bool:
    return SCREEN in text.lower() or any(words in text for words in BUTTONS)


def said_by(tree) -> list:
    """Every string the code can say: its constants, the parts of an
    f-string among them, less the docstrings."""
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            first = node.body[0] if node.body else None
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docstrings.add(id(first.value))
    return [node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
            and id(node) not in docstrings]


def test_no_text_the_control_plane_can_say_names_the_alerts_screen():
    read = 0
    for path in sorted(APP.glob("*.py")):
        for text in said_by(ast.parse(path.read_text(encoding="utf-8"))):
            read += 1
            assert not names_it(text), f"{path.name} says: {text!r}"
    assert read > 1000, "the reader found almost nothing to read"


def test_the_reader_does_find_such_a_sentence_when_there_is_one():
    """The check above passes on silence, so it is shown one."""
    tree = ast.parse('def f():\n    """the Alerts screen, in a docstring"""\n'
                     '    return f"Back to Alerts, {1}" + "x"\n')
    assert sorted(said_by(tree)) == ["Back to Alerts, ", "x"]
    assert names_it("Back to Alerts, ") and names_it("on the alerts screen")
    assert not names_it("Open alerts that have not been delivered to anyone.")


def test_the_test_message_sends_its_reader_to_integrations():
    said = alertwords.said_test()
    assert said.sentence == "Sent from the Integrations screen."
    assert said.button == "Open Integrations"
    assert said.link == publicurl.integrations()
    assert publicurl.integrations().endswith("/integrations")
    # the webhook's typed document for a test says the same
    assert senders.TEST_PAYLOAD_DETAIL == "a test message from the Integrations screen"


def test_the_page_a_slack_connect_ends_on_leads_back_to_integrations():
    page = web_pages.simple_page("Slack did not complete the connect", "Nothing was saved.")
    assert '<a class="btn" href="/integrations">Back to Integrations</a>' in page
    assert "/alerts" not in page
