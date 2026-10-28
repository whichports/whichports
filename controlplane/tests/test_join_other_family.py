"""The provider's view of a port's other family, carried on the finding that exists.

    Run from controlplane/: python -m pytest tests/test_join_other_family.py

A server's page draws both families of a port. Where the engine raised a
finding on one family only, the card for the other hard-coded "provider: not
connected", beside a provider that was connected (Sweep 2, C5, record 4.199).
The engine now answers that card's question with `_provider_view`, the one
that answers it for every finding, and hangs the answer on the finding it did
raise as `other_family_provider`. It raises nothing and moves no state.
"""
import dataclasses

import pytest

from app import join
from tests.test_join import (add_host, con, document, find, finding_for,  # noqa: F401
                             hetzner_snapshot, report, socket_row)

__all__ = ["con"]


def rule(port, sources, protocol="tcp"):
    return {"direction": "in", "protocol": protocol, "port": port,
            "description": None, "source_ips": list(sources), "destination_ips": []}


def v4_only(con, rules=None):
    """A socket on v4 alone, port 443, so the engine raises v4 and not v6."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443, process="caddy")]))
    if rules is not None:
        hetzner_snapshot(con, rules=rules)
    result = join.host_findings(con, host_id)
    assert find(result, "tcp", 443, "v6") is None
    return finding_for(result, "tcp", 443, "v4")


def test_with_no_provider_the_other_family_says_so(con):
    view = v4_only(con).other_family_provider
    assert view is not None
    assert (view.configured, view.matched, view.rules) == (False, False, ())


def test_a_connected_provider_with_no_v6_rule_is_read_as_one(con):
    """The C5 case: connected, the server found, nothing for 443 on v6."""
    view = v4_only(con, rules=[rule("22", ["0.0.0.0/0", "::/0"])]).other_family_provider
    assert (view.configured, view.matched, view.rules) == (True, True, ())


def test_a_v6_range_covering_the_port_is_quoted_for_v6(con):
    """A range raises no finding of its own (`_ports_from_provider`), so the
    v6 half has none, and the range still covers 443 on v6. Without this the
    card would say no rule names 443."""
    view = v4_only(con, rules=[rule("400-500", ["::/0"])]).other_family_provider
    assert view.matched is True
    assert view.rules and "400-500" in view.rules[0].text


def test_a_server_the_provider_does_not_list_is_not_found(con):
    hetzner_snapshot(con, server_name="someone-else", rules=[])
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443, process="caddy")]))
    view = finding_for(join.host_findings(con, host_id), "tcp", 443, "v4").other_family_provider
    assert (view.configured, view.matched) == (True, False)


def test_a_port_with_both_families_carries_nothing_extra(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443, process="caddy"),
                                           socket_row(443, family="v6", process="caddy",
                                                      bind_address="::")]))
    result = join.host_findings(con, host_id)
    assert finding_for(result, "tcp", 443, "v4").other_family_provider is None
    assert finding_for(result, "tcp", 443, "v6").other_family_provider is None


def test_the_view_moves_no_state_and_raises_no_finding(con, monkeypatch):
    """The same server with the step and without it gives the same findings
    in every other respect: the view is for a screen, `_decide` never sees
    it."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443, process="caddy"),
                                           socket_row(22)]))
    hetzner_snapshot(con, rules=[rule("400-500", ["::/0"]), rule("22", ["0.0.0.0/0"])])
    with_view = join.host_findings(con, host_id).findings
    monkeypatch.setattr(join, "_with_other_family_provider", lambda found, _r: tuple(found))
    without = join.host_findings(con, host_id).findings
    assert len(with_view) == len(without)
    for a, b in zip(with_view, without):
        assert a.other_family_provider is not None and b.other_family_provider is None
        assert dataclasses.replace(a, other_family_provider=None) == b


@pytest.mark.parametrize("family, other", [("v4", "v6"), ("v6", "v4")])
def test_either_family_can_be_the_missing_one(con, family, other):
    host_id = add_host(con)
    bind = "0.0.0.0" if family == "v4" else "::"
    report(con, host_id, document(sockets=[socket_row(8080, family=family, bind_address=bind)]))
    result = join.host_findings(con, host_id)
    assert find(result, "tcp", 8080, other) is None
    assert finding_for(result, "tcp", 8080, family).other_family_provider is not None
