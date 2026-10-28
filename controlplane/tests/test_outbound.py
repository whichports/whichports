"""Where an alert may be sent, and the one setting that widens it.

    python -m pytest tests/test_outbound.py

`app/outbound.py` holds two rules. The strict one is the rule the webhook
always had, globally routable and nothing else. The other adds five named
private networks, and is in force only on an instance whose operator set
`WHICHPORTS_ALERTS_TO_PRIVATE_ADDRESSES=yes` (docs/record 4.336).

What must not move is tested as hard as what moves: with the setting absent
every address is decided exactly as before, and some addresses stay refused
whatever the setting says.
"""
import ipaddress
import pathlib

import pytest

from app import authz, channels, outbound, senders, sweep_cli, webhook
from test_senders import ENV, FakeOpener, a_channel

ON = {outbound.SETTING: "yes"}
OFF = {}

# The five networks the setting lets through, written here and not read from
# the module, so the test says the ranges itself.
NETWORKS = [ipaddress.ip_network(text) for text in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "100.64.0.0/10")]
# The first and the last address of each. Worked out and not written down:
# an address somebody may hold is not named in a file that is published.
LET_THROUGH = [str(address) for network in NETWORKS
               for address in (network[0], network[-1])]
# Refused whatever the setting says, with the kind each is.
NEVER = [
    ("127.0.0.1", "loopback"), ("127.255.255.254", "loopback"), ("::1", "loopback"),
    ("169.254.169.254", "link-local, the cloud metadata address"),
    ("169.254.0.1", "link-local"), ("fe80::1", "link-local"),
    ("0.0.0.0", "unspecified"), ("::", "unspecified"),
    ("224.0.0.1", "multicast"), ("ff02::1", "multicast"),
    ("240.0.0.1", "reserved"), ("255.255.255.255", "reserved"),
    ("::ffff:10.0.0.5", "a private v4 address written as v6"),
    ("::ffff:8.8.8.8", "a public v4 address written as v6"),
    ("192.0.2.1", "documentation"), ("198.51.100.1", "documentation"),
    ("203.0.113.1", "documentation"), ("2001:db8::1", "documentation"),
    ("198.18.0.1", "benchmarking"), ("fec0::1", "site-local, deprecated"),
    ("0.1.2.3", "this network"),
]
PUBLIC = ["8.8.8.8", "2606:4700:4700::1111"]
# The first address past the end of each v4 network, and the one before the
# shared address space. Worked out, for the same reason.
PAST_THE_END = [str(network[-1] + 1) for network in NETWORKS if network.version == 4] \
    + [str(NETWORKS[-1][0] - 1)]
EVERY = LET_THROUGH + [address for address, _kind in NEVER] + PUBLIC + PAST_THE_END


def ip(text):
    return ipaddress.ip_address(text)


# ------------------------------------------------------------ the strict rule

@pytest.mark.parametrize("address", EVERY)
def test_the_strict_rule_is_todays_rule_for_every_address(address):
    assert outbound.strict(ip(address)) == authz._is_probeable(ip(address))


def test_the_strict_rule_calls_the_probing_rule_and_does_not_copy_it(monkeypatch):
    seen = []
    monkeypatch.setattr(authz, "_is_probeable", lambda one: seen.append(one) or True)
    assert outbound.strict(ip("10.0.0.5")) is True
    assert seen == [ip("10.0.0.5")]


@pytest.mark.parametrize("environ", [OFF, {outbound.SETTING: ""}, {outbound.SETTING: " "}])
def test_without_the_setting_the_rule_in_force_is_the_strict_one(environ):
    assert outbound.guard(environ) is outbound.strict
    assert outbound.setting_complaint(environ) == ""


# -------------------------------------------------------------- the setting

@pytest.mark.parametrize("value", ["yes", " yes ", "yes\n"])
def test_exactly_yes_turns_it_on(value):
    environ = {outbound.SETTING: value}
    assert outbound.guard(environ) is outbound.private_too
    assert outbound.setting_complaint(environ) == ""


@pytest.mark.parametrize("value", ["YES", "Yes", "true", "1", "on", "y", "no", "yes please"])
def test_any_other_value_is_off_and_is_a_complaint(value):
    """Never read as on, and never passed over in silence: a start asks
    `setting_complaint` and stops on a sentence."""
    environ = {outbound.SETTING: value}
    assert outbound.guard(environ) is outbound.strict
    complaint = outbound.setting_complaint(environ)
    assert outbound.SETTING in complaint and "yes" in complaint
    assert value not in complaint.replace("yes", "")


@pytest.mark.parametrize("address", LET_THROUGH)
def test_the_five_networks_are_let_through_only_with_the_setting(address):
    assert outbound.strict(ip(address)) is False
    assert outbound.private_too(ip(address)) is True
    assert outbound.guard(OFF)(ip(address)) is False
    assert outbound.guard(ON)(ip(address)) is True


@pytest.mark.parametrize("address, kind", NEVER)
def test_what_stays_refused_whatever_the_setting_says(address, kind):
    assert outbound.guard(OFF)(ip(address)) is False, kind
    assert outbound.guard(ON)(ip(address)) is False, kind


@pytest.mark.parametrize("address", PUBLIC)
def test_a_public_address_is_sent_to_either_way(address):
    assert outbound.guard(OFF)(ip(address)) is True
    assert outbound.guard(ON)(ip(address)) is True


@pytest.mark.parametrize("address", PAST_THE_END)
def test_the_address_past_the_end_of_a_network_is_decided_by_the_strict_rule(address):
    assert outbound.in_a_private_network(ip(address)) is False
    assert outbound.private_too(ip(address)) == outbound.strict(ip(address))


def test_the_networks_are_named_and_not_taken_from_a_property():
    """Python's `is_private` is true of loopback, link-local and the
    documentation ranges. A rule that asked it would let those through."""
    for address in ("127.0.0.1", "169.254.169.254", "192.0.2.1"):
        assert ip(address).is_private is True
        assert outbound.private_too(ip(address)) is False
    shared = NETWORKS[-1][1]
    assert shared.is_private is False and shared.is_global is False
    assert outbound.private_too(shared) is True
    assert [str(n) for n in outbound.LET_THROUGH_WITH_THE_SETTING] == [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
        "100.64.0.0/10"]


# ------------------------------------------------------------ what is said

def test_a_private_address_is_refused_in_words_a_screen_may_show():
    said = webhook.check_url("http://chat.lan:8065/hooks/x",
                             resolver=lambda host: ["192.168.1.50"],
                             guard=outbound.strict)
    assert said == ("the webhook host chat.lan resolves to 192.168.1.50, which"
                    " is inside a private network. Alerts are sent to public"
                    " addresses only.")


def test_an_address_refused_always_says_so_without_calling_it_private():
    for guard in (outbound.strict, outbound.private_too):
        said = webhook.check_url("http://here/x", resolver=lambda host: ["127.0.0.1"],
                                 guard=guard)
        assert said == ("the webhook host here resolves to 127.0.0.1, which is"
                        " not an address an alert can be sent to.")


def test_no_refusal_names_the_setting_or_our_own_server():
    """Both sentences show on a screen. A screen names none of our
    machinery, and the sentence it replaced spoke of 'this box', ours."""
    for sentence in (outbound.REFUSED_AS_PRIVATE, outbound.REFUSED_ALWAYS):
        assert outbound.SETTING not in sentence
        assert "WHICHPORTS" not in sentence and ".env" not in sentence
        assert "box" not in sentence and "ingest" not in sentence


def test_the_operator_is_told_the_setting_and_only_for_a_private_address():
    private = "the webhook host a resolves to 10.0.0.5, " + outbound.REFUSED_AS_PRIVATE
    never = "the webhook host a resolves to 127.0.0.1, " + outbound.REFUSED_ALWAYS
    assert outbound.SETTING + "=yes" in outbound.operator_note(private)
    assert outbound.operator_note(never) == ""
    assert outbound.operator_note("TimeoutError") == ""
    assert outbound.operator_note("") == ""


def test_the_sweeps_log_carries_the_note_under_the_refusal(capsys):
    sweep_cli.note_for_the_operator("x resolves to 10.0.0.5, " + outbound.REFUSED_AS_PRIVATE)
    assert outbound.SETTING in capsys.readouterr().out
    sweep_cli.note_for_the_operator("x resolves to ::1, " + outbound.REFUSED_ALWAYS)
    assert capsys.readouterr().out == ""


# ------------------------------------------------- every address of a name

def test_one_refused_address_refuses_the_name_in_either_mode():
    both = lambda host: ["8.8.8.8", "10.0.0.5"]            # noqa: E731
    assert "private network" in webhook.check_url("http://n/x", resolver=both,
                                                  guard=outbound.strict)
    assert webhook.check_url("http://n/x", resolver=both,
                             guard=outbound.private_too) == ""
    with_loopback = lambda host: ["10.0.0.5", "127.0.0.1"]  # noqa: E731
    for guard in (outbound.strict, outbound.private_too):
        assert webhook.check_url("http://n/x", resolver=with_loopback, guard=guard)


def test_the_check_asks_the_rule_in_force_when_none_is_handed_to_it(monkeypatch):
    private = lambda host: ["192.168.1.50"]                # noqa: E731
    monkeypatch.delenv(outbound.SETTING, raising=False)
    assert webhook.check_url("http://n/x", resolver=private)
    monkeypatch.setenv(outbound.SETTING, "yes")
    assert webhook.check_url("http://n/x", resolver=private) == ""
    monkeypatch.setenv(outbound.SETTING, "true")
    assert webhook.check_url("http://n/x", resolver=private)


@pytest.mark.parametrize("channel_type, name", [
    (channels.TYPE_WEBHOOK, "WHICHPORTS_SLACK_URL"),
    (channels.TYPE_SLACK, "WHICHPORTS_SLACK_URL"),
    (channels.TYPE_DISCORD, "WHICHPORTS_DISCORD_URL")])
def test_with_the_setting_an_alert_is_posted_to_a_private_address(
        monkeypatch, channel_type, name):
    """Through `senders.deliver`, the path an alert takes, and not only
    through the check."""
    private = lambda host: ["192.168.1.50"]                # noqa: E731
    channel = a_channel(channel_type, name)
    monkeypatch.delenv(outbound.SETTING, raising=False)
    opener = FakeOpener(status=204)
    sent, reason = senders.deliver(channel, "text", {}, ENV, resolver=private,
                                   opener=opener)
    assert sent is False and reason.endswith(outbound.REFUSED_AS_PRIVATE)
    assert opener.requests == [], "nothing left this process"
    monkeypatch.setenv(outbound.SETTING, "yes")
    opener = FakeOpener(status=204)
    sent, reason = senders.deliver(channel, "text", {}, ENV, resolver=private,
                                   opener=opener)
    assert sent is True, reason
    assert len(opener.requests) == 1


def test_with_the_setting_loopback_is_still_not_posted_to(monkeypatch):
    monkeypatch.setenv(outbound.SETTING, "yes")
    opener = FakeOpener(status=204)
    sent, reason = senders.deliver(
        a_channel(channels.TYPE_WEBHOOK, "WHICHPORTS_SLACK_URL"), "text", {}, ENV,
        resolver=lambda host: ["127.0.0.1"], opener=opener)
    assert sent is False and reason.endswith(outbound.REFUSED_ALWAYS)
    assert opener.requests == []


# ------------------------------------------------------------------ the door

@pytest.mark.parametrize("destination", [
    "http://10.0.0.5:8065/hooks/abc", "https://192.168.1.50/hook",
    "http://[fd00::5]/hook", f"http://{NETWORKS[-1][257]}/hook"])
def test_the_door_refuses_a_private_address_written_as_an_address(
        monkeypatch, destination):
    monkeypatch.delenv(outbound.SETTING, raising=False)
    said = channels.check_destination(channels.TYPE_WEBHOOK, destination)
    assert said == "this destination is an address " + outbound.REFUSED_AS_PRIVATE
    # Never repeated back, like every other answer of the door.
    assert "8065" not in said and "hook" not in said
    monkeypatch.setenv(outbound.SETTING, "yes")
    assert channels.check_destination(channels.TYPE_WEBHOOK, destination) == ""


@pytest.mark.parametrize("destination", [
    "http://127.0.0.1:8065/hooks/abc", "http://[::1]/hook",
    "http://169.254.169.254/latest/meta-data"])
def test_the_door_refuses_what_is_refused_always_with_the_setting_too(
        monkeypatch, destination):
    for value in (None, "yes"):
        if value is None:
            monkeypatch.delenv(outbound.SETTING, raising=False)
        else:
            monkeypatch.setenv(outbound.SETTING, value)
        assert channels.check_destination(channels.TYPE_WEBHOOK, destination) == \
            "this destination is an address " + outbound.REFUSED_ALWAYS


@pytest.mark.parametrize("destination", [
    "https://chat.internal/hooks/abc", "https://hooks.slack.com/services/T/B/x",
    "https://8.8.8.8/hook"])
def test_the_door_resolves_no_name_and_lets_a_public_address_in(monkeypatch,
                                                                destination):
    """A name's answer can change, so a name is checked at sending and the
    door does not look it up. Nothing here touches a resolver."""
    monkeypatch.delenv(outbound.SETTING, raising=False)
    monkeypatch.setattr(webhook.socket, "getaddrinfo",
                        lambda *a, **k: pytest.fail("the door resolved a name"))
    assert channels.check_destination(channels.TYPE_WEBHOOK, destination) == ""


# ------------------------------------------------- our own service never has it

def test_no_unit_file_of_ours_names_the_setting():
    """The hosted service's units are in controlplane/ops. None sets it, and
    the deploy stops when a file on the box does (ops/deploy-controlplane.sh
    in the private repository)."""
    units = sorted((pathlib.Path(__file__).resolve().parent.parent / "ops").glob("*"))
    assert units, "the unit files are where this test looks"
    for unit in units:
        if unit.is_file():
            assert outbound.SETTING not in unit.read_text(errors="replace"), unit.name
