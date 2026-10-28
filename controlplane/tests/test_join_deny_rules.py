"""The engine says which rules name a port and turn the packet away.

A port's card said "no rule names 5432" on a server whose ufw holds `deny
tcp 5432`: the engine kept the rules that permit a port and only counted the
others (docs/RECORD.md 4.454). A rule that names the port and ends on drop
or reject is a fact about the ruleset, quoted the way a permit is, for each
address family by itself. It decides no state: a measured silence still
names no layer (docs/PRODUCT.md 8b).

    Run from controlplane/: .venv/bin/python -m pytest tests/test_join_deny_rules.py
"""
import pytest

from app import join, prober
from tests.test_join import (_both_listeners, _handwritten, add_host, con,  # noqa: F401
                             document, finding_for, probe_run, report, ufw_v4, ufw_v6)

DROP_V4 = "ip protocol tcp tcp dport 5432 counter drop"
DROP_V6 = "ip6 nexthdr tcp tcp dport 5432 counter drop"
ACCEPT_22 = "ip protocol tcp tcp dport 22 counter accept"


def silent(con, host_id, port=5432):
    probe_run(con, host_id, [
        ("v4", port, prober.STATE_NO_RESPONSE, "timeout", "203.0.113.5"),
        ("v6", port, prober.STATE_NO_RESPONSE, "timeout", "2001:db8::5")])


def both(con, tables, port=5432):
    """The two families' findings of one port on a server with these tables,
    a listener on both families and silence from outside on both."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=_both_listeners(port), tables=tables))
    silent(con, host_id, port)
    result = join.host_findings(con, host_id)
    return finding_for(result, "tcp", port, "v4"), finding_for(result, "tcp", port, "v6")


def denies(finding):
    return [quote.text for quote in finding.inside.deny_rules]


# ---------------------------------------------- what is not a deny rule

def test_a_server_with_no_rule_for_the_port_has_no_deny_rule(con):
    v4, v6 = both(con, [ufw_v4([ACCEPT_22]), ufw_v6([])])
    assert denies(v4) == [] and denies(v6) == []


@pytest.mark.parametrize("text", [
    "ip protocol tcp tcp dport 5432 counter accept",          # a permit
    "ip protocol tcp tcp dport 5433 counter drop",            # another port
    "ip protocol udp udp dport 5432 counter drop",            # another protocol
    "ip protocol tcp tcp dport 5432 counter jump to-drop",    # a jump to a chain named like one
    "counter drop",                                           # names no port
])
def test_a_rule_that_does_not_name_the_port_and_turn_it_away_is_not_one(con, text):
    v4, _v6 = both(con, [ufw_v4([text]), ufw_v6([])])
    assert denies(v4) == []


def test_a_drop_the_page_could_not_fully_read_is_counted_and_not_quoted(con):
    """A port in a set, written by the agent as a bracket. Not a deny rule
    for this port, since nobody read which ports it names, and not nothing."""
    text = "ip protocol tcp [lookup @__set0] counter drop"
    v4, _v6 = both(con, [ufw_v4([text]), ufw_v6([])])
    assert denies(v4) == []
    assert v4.inside.unreadable_rule_count >= 1


# --------------------------------------------------------- what is one

def test_ufws_deny_is_quoted_on_each_family_from_that_familys_own_rule(con):
    v4, v6 = both(con, [ufw_v4([ACCEPT_22, DROP_V4]), ufw_v6([DROP_V6])])
    assert denies(v4) == [DROP_V4]
    assert denies(v6) == [DROP_V6]
    for finding in (v4, v6):
        assert finding.inside.deny_rules[0].layer == join.LAYER_HOST_FIREWALL
        assert finding.inside.permit_rules == ()


def test_a_deny_on_v4_alone_says_nothing_of_v6(con):
    """Nothing about v4 answers v6 (docs/PRODUCT.md 4b)."""
    v4, v6 = both(con, [ufw_v4([DROP_V4]), ufw_v6([])])
    assert denies(v4) == [DROP_V4]
    assert denies(v6) == []


def test_a_drop_pinned_to_one_family_in_a_table_for_both_is_that_familys(con):
    pinned = "meta nfproto ipv4 meta l4proto tcp tcp dport 5432 drop"
    v4, v6 = both(con, [_handwritten(pinned)])
    assert denies(v4) == [pinned]
    assert denies(v6) == []


def test_a_drop_in_a_table_for_both_families_is_quoted_on_both(con):
    text = "meta l4proto tcp tcp dport 5432 counter drop"
    v4, v6 = both(con, [_handwritten(text)])
    assert denies(v4) == [text] and denies(v6) == [text]


def test_a_drop_for_one_source_is_quoted_with_its_condition_as_written(con):
    text = "ip saddr 203.0.113.0/24 ip protocol tcp tcp dport 5432 counter drop"
    v4, _v6 = both(con, [ufw_v4([text]), ufw_v6([])])
    assert denies(v4) == [text]


def test_the_agents_own_reject_is_a_deny_rule_and_stays_quoted_as_written(con):
    """The agent writes a reject as the bare token `[reject]`, last in the
    rule, and grades the rule partial. The rest of such a rule was read in
    full, so it names the port."""
    text = "ip protocol tcp tcp dport 5432 counter [reject]"
    host_id = add_host(con)
    tables = [ufw_v4([]), ufw_v6([])]
    tables[0]["chains"][2]["rules"] = [{"text": text, "rendered": "partial", "comment": ""}]
    report(con, host_id, document(sockets=_both_listeners(5432), tables=tables))
    silent(con, host_id)
    v4 = finding_for(join.host_findings(con, host_id), "tcp", 5432, "v4")
    assert denies(v4) == [text]


def test_a_reject_beside_another_token_nobody_read_is_not_quoted(con):
    text = "ip protocol tcp [lookup @__set0] counter [reject]"
    host_id = add_host(con)
    tables = [ufw_v4([]), ufw_v6([])]
    tables[0]["chains"][2]["rules"] = [{"text": text, "rendered": "partial", "comment": ""}]
    report(con, host_id, document(sockets=_both_listeners(5432), tables=tables))
    silent(con, host_id)
    v4 = finding_for(join.host_findings(con, host_id), "tcp", 5432, "v4")
    assert denies(v4) == []


def test_a_deny_rule_decides_no_state_and_names_no_layer(con):
    """The state of a silent port with a deny rule is the state of one with
    none, and its cause quotes nothing new."""
    with_rule, _ = both(con, [ufw_v4([DROP_V4]), ufw_v6([DROP_V6])])
    assert with_rule.state == join.STATE_NOT_REACHABLE


def test_two_deny_rules_for_one_port_are_both_quoted_once_each(con):
    other = "ip saddr 203.0.113.0/24 ip protocol tcp tcp dport 5432 counter drop"
    v4, _v6 = both(con, [ufw_v4([other, DROP_V4, DROP_V4]), ufw_v6([])])
    assert denies(v4) == [other, DROP_V4]


# ------------------------------- a family the engine makes no finding for

def test_the_inside_view_of_a_family_with_nothing_bound_still_reads_its_rules(con):
    """Postgres listens on v4 alone and only v4 was probed, so the engine has
    no v6 finding. The v6 rules still name the port, and a reader holding the
    document can ask for that family's view."""
    doc = document(sockets=[_both_listeners(5432)[0]],
                   tables=[ufw_v4([DROP_V4]), ufw_v6([DROP_V6])])
    host_id = add_host(con)
    report(con, host_id, doc)
    probe_run(con, host_id, [("v4", 5432, prober.STATE_NO_RESPONSE, "timeout", "203.0.113.5")])
    result = join.host_findings(con, host_id)
    assert [f.family for f in result.findings if f.port == 5432] == ["v4"]

    view = join.inside_view(doc, "tcp", 5432, "v6")
    assert [quote.text for quote in view.deny_rules] == [DROP_V6]
    assert view.sockets == () and view.permit_rules == ()


def test_the_asked_for_view_is_the_one_a_finding_carries(con):
    doc = document(sockets=_both_listeners(5432),
                   tables=[ufw_v4([ACCEPT_22, DROP_V4]), ufw_v6([DROP_V6])])
    host_id = add_host(con)
    report(con, host_id, doc)
    silent(con, host_id)
    result = join.host_findings(con, host_id)
    for family in ("v4", "v6"):
        assert join.inside_view(doc, "tcp", 5432, family) == finding_for(
            result, "tcp", 5432, family).inside


def test_a_family_no_rule_names_has_an_empty_view_of_rules(con):
    doc = document(sockets=[_both_listeners(5432)[0]],
                   tables=[ufw_v4([DROP_V4]), ufw_v6([])])
    view = join.inside_view(doc, "tcp", 5432, "v6")
    assert view.deny_rules == () and view.permit_rules == () and view.narrowed_rules == ()
    assert view.unreadable_rule_count == 0
