"""The invite as one line (`app/invite.py`).

What these hold: a line that is cut short, of the old three-value shape, or
changed anywhere is refused, never half read. A whole line becomes exactly the
three settings the control plane has always read. The API key and the proof
key stay apart after the split: the line that enrols a server carries the
proof key and never the API key. And the names and shapes here are the ones
`app/dispatch.py` and `app/instances.py` use, so the two cannot drift.
"""
import io
import contextlib

import pytest

from app import db, dispatch, instances, instances_cli, invite, publicurl

API_KEY = "whpi_" + "0123456789abcdef" * 4
PROOF_KEY = "whpp_" + "fedcba9876543210" * 4
HOST = "app.whichports.com"
LINE = f"whpinvite1_{HOST}_{API_KEY}_{PROOF_KEY}"


# ---------------------------------------------------------- refused lines

@pytest.mark.parametrize("text", [
    "",
    "   ",
    LINE[:-1],                                   # cut short by one character
    LINE[:-20],
    LINE[:len("whpinvite1_") + len(HOST)],       # the host and nothing after
    f"whpinvite1_{HOST}_{API_KEY}",              # the proof key left off
    f"whpinvite1_{HOST}_{PROOF_KEY}_{API_KEY}",  # the keys the wrong way round
    LINE + "0",                                  # one character too many
    LINE + "_" + PROOF_KEY,
    "whpinvite2_" + LINE[len("whpinvite1_"):],   # a shape this does not know
    LINE.replace("whpinvite1_", "WHPINVITE1_"),
    LINE.upper(),
    LINE.replace("0123", "012G", 1),             # not hex
    " " + LINE[:-1] + " ",
    API_KEY,                                     # the old shape: one value
    PROOF_KEY,
    f"https://{HOST}",
    f"WHICHPORTS_PROBER_API_KEY={API_KEY}",
    f"{HOST} {API_KEY} {PROOF_KEY}",
])
def test_a_line_that_is_not_whole_is_refused(text):
    with pytest.raises(invite.InviteError):
        invite.split(text)


@pytest.mark.parametrize("host", [
    "localhost",                 # one label
    "203.0.113.9",               # an address, not a name
    "app_whichports.com",        # the underscore is the line's own separator
    "-app.whichports.com",
    "app-.whichports.com",
    "app..whichports.com",
    ".whichports.com",
    "whichports.com.",
    "App.Whichports.com",
    "app.whichports.com:8443",
    "a" * 64 + ".com",
    ("a" * 63 + ".") * 4 + "com",  # longer than 253
    "app.whichports.123",
    "",
])
def test_a_host_that_is_not_a_plain_name_is_refused(host):
    assert not invite.host_ok(host)
    with pytest.raises(invite.InviteError):
        invite.split(f"whpinvite1_{host}_{API_KEY}_{PROOF_KEY}")
    with pytest.raises(invite.InviteError):
        invite.line(host, API_KEY, PROOF_KEY)


def test_a_line_is_never_made_from_keys_of_the_wrong_kind():
    with pytest.raises(invite.InviteError):
        invite.line(HOST, PROOF_KEY, API_KEY)
    with pytest.raises(invite.InviteError):
        invite.line(HOST, API_KEY, API_KEY)
    with pytest.raises(invite.InviteError):
        invite.line(HOST, API_KEY[:-1], PROOF_KEY)


@pytest.mark.parametrize("host,api,proof", [
    (HOST + "\n", API_KEY, PROOF_KEY),
    (HOST, API_KEY + "\n", PROOF_KEY),
    (HOST, API_KEY, PROOF_KEY + "\n"),
])
def test_a_trailing_newline_is_no_part_of_a_host_or_a_key(host, api, proof):
    """A regular expression's $ matches before a final newline, so each
    part is held whole with fullmatch, and a line is never made with a
    newline inside it."""
    with pytest.raises(invite.InviteError):
        invite.line(host, api, proof)
    assert not invite.host_ok(HOST + "\n")


def test_the_refusal_names_the_setting_and_never_repeats_the_line():
    with pytest.raises(invite.InviteError) as caught:
        invite.split(LINE[:-1])
    said = str(caught.value)
    assert invite.INVITE_ENV in said
    assert API_KEY not in said and PROOF_KEY[:-1] not in said
    assert "\n" not in said


# ------------------------------------------------- the line and the settings

@pytest.mark.parametrize("host", [
    "app.whichports.com", "whichports.example.com", "a.b", "x-1.y-2.example",
    "ours.internal", "a" * 63 + ".com",
])
def test_a_whole_line_becomes_the_three_settings(host):
    line = invite.line(host, API_KEY, PROOF_KEY)
    assert line == f"whpinvite1_{host}_{API_KEY}_{PROOF_KEY}"
    assert invite.split(line) == {
        "WHICHPORTS_PROBER_API": f"https://{host}",
        "WHICHPORTS_PROBER_API_KEY": API_KEY,
        "WHICHPORTS_PROBER_PROOF_KEY": PROOF_KEY,
    }


def test_spaces_around_a_pasted_line_are_not_part_of_it():
    assert invite.split(f"  {LINE}\t") == invite.split(LINE)


def test_no_invite_set_means_no_settings_from_it():
    assert invite.settings({}) == {}
    assert invite.settings({invite.INVITE_ENV: ""}) == {}
    assert invite.settings({invite.INVITE_ENV: "  "}) == {}


@pytest.mark.parametrize("other", [
    "WHICHPORTS_PROBER_API", "WHICHPORTS_PROBER_API_KEY",
    "WHICHPORTS_PROBER_PROOF_KEY",
])
def test_the_invite_and_any_of_the_three_lines_together_are_refused(other):
    """Two places for one value is a value that can disagree with itself.
    Whichever was edited last would win without a word, so neither does."""
    with pytest.raises(invite.InviteError) as caught:
        invite.settings({invite.INVITE_ENV: LINE, other: "something"})
    assert invite.INVITE_ENV in str(caught.value)


def test_the_three_lines_left_empty_beside_the_invite_are_not_set():
    """`env.example` carries the three lines empty, and a copy of it with the
    invite filled in is the ordinary case."""
    environ = {invite.INVITE_ENV: LINE, "WHICHPORTS_PROBER_API": "",
               "WHICHPORTS_PROBER_API_KEY": " ", "WHICHPORTS_PROBER_PROOF_KEY": ""}
    assert invite.settings(environ)["WHICHPORTS_PROBER_API_KEY"] == API_KEY


# -------------------------------------------------- the two keys stay apart

def test_after_the_split_the_enrol_line_carries_the_proof_key_and_never_the_api_key():
    """SI-6. The invite brings both keys to the instance. The control plane
    keeps the API key, and only the proof key goes on to the servers it
    enrols, in the line Add server prints. Neither the API key nor the
    invite line itself may be in that line."""
    environ = invite.settings({invite.INVITE_ENV: LINE})
    flags = dispatch.prober_enroll_flags(environ)
    assert f"--prober-proof-key={PROOF_KEY}" in flags
    assert f"--prober-server=https://{HOST}" in flags
    assert API_KEY not in flags
    assert "whpinvite1_" not in flags


def test_after_the_split_the_transport_is_the_api_with_the_api_key():
    environ = invite.settings({invite.INVITE_ENV: LINE})
    transport = dispatch.default_transport_factory(environ)("probe1")
    assert isinstance(transport, dispatch.ApiTransport)


def test_every_host_the_line_takes_is_an_address_the_control_plane_takes():
    for host in ("app.whichports.com", "a.b", "x-1.y-2.example", "ours.internal"):
        environ = invite.split(invite.line(host, API_KEY, PROOF_KEY))
        assert dispatch._checked_base_url(environ["WHICHPORTS_PROBER_API"],
                                          allow_http=False) == f"https://{host}"
        assert publicurl.base({"WHICHPORTS_BASE_URL": f"https://{host}"}) == f"https://{host}"


# ------------------------------------------------- one name, one shape each

def test_the_three_names_are_the_ones_dispatch_reads():
    assert invite.PROBER_API_ENV == dispatch.PROBER_API_ENV
    assert invite.PROBER_API_KEY_ENV == dispatch.PROBER_API_KEY_ENV
    assert invite.PROBER_PROOF_KEY_ENV == dispatch.PROBER_PROOF_KEY_ENV


def test_the_keys_it_takes_are_the_keys_instances_issues():
    for _ in range(20):
        api = instances.new_key(instances.KIND_API)
        proof = instances.new_key(instances.KIND_PROOF)
        settings = invite.split(invite.line(HOST, api, proof))
        assert settings["WHICHPORTS_PROBER_API_KEY"] == api
        assert settings["WHICHPORTS_PROBER_PROOF_KEY"] == proof
    assert invite.PROOF_KEY_RE.pattern.strip("^$") == dispatch.PROOF_KEY_RE.pattern.strip("^$")


def test_the_module_loads_alone_with_nothing_else_of_the_control_plane():
    """selfhost/worker.py loads it by its path, never as part of the
    package, the way it loads publicurl.py."""
    import ast
    from pathlib import Path
    tree = ast.parse(Path(invite.__file__).read_text())
    imported = [node for node in ast.walk(tree)
                if isinstance(node, (ast.Import, ast.ImportFrom))]
    for node in imported:
        assert not isinstance(node, ast.ImportFrom) or node.level == 0, \
            "invite.py imports from the package, so it cannot load alone"


# ------------------------------------------------------- instances_cli add

@pytest.fixture()
def con():
    from app import authz
    connection = db.connect(":memory:")
    db.init(connection)
    authz.init(connection)
    instances.init(connection)
    yield connection
    connection.close()


def test_add_prints_the_invite_line_holding_the_two_keys_it_issued(con, monkeypatch):
    import argparse
    monkeypatch.setenv(publicurl.ENV, f"https://{HOST}")
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert instances_cli.run(con, argparse.Namespace(command="add", name="freedom")) == 0
    printed = out.getvalue()
    lines = [word for word in printed.split() if word.startswith("whpinvite1_")]
    assert len(lines) == 1, printed
    settings = invite.split(lines[0])
    assert settings["WHICHPORTS_PROBER_API"] == f"https://{HOST}"
    found = instances.instance_for_key(con, settings["WHICHPORTS_PROBER_API_KEY"], "api")
    assert found is not None and found.name == "freedom"
    assert instances.instance_for_key(
        con, settings["WHICHPORTS_PROBER_PROOF_KEY"], "proof").name == "freedom"


def test_add_names_our_own_host_when_no_base_url_is_set(con, monkeypatch):
    import argparse
    monkeypatch.delenv(publicurl.ENV, raising=False)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        instances_cli.run(con, argparse.Namespace(command="add", name="freedom"))
    line = next(w for w in out.getvalue().split() if w.startswith("whpinvite1_"))
    assert invite.split(line)["WHICHPORTS_PROBER_API"] == publicurl.DEFAULT


def test_add_with_a_malformed_base_url_issues_no_keys(con, monkeypatch):
    """The host is read before the keys are made, so a setting that cannot
    give one stops the command with nothing issued."""
    import argparse
    monkeypatch.setenv(publicurl.ENV, "http://not-https.example.com")
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        assert instances_cli.run(con, argparse.Namespace(command="add", name="freedom")) == 1
    assert publicurl.ENV in err.getvalue()
    assert instances.by_name(con, "freedom") is None
