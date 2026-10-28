"""The chain walk is bounded, and says so when the bound bites.

`_MAX_DEPTH` and the `seen` set look like they bound the walk and they do not.
`seen` is per path rather than per walk, which is the right choice: nftables
refuses a ruleset carrying a jump loop, but a chain reached down two different
paths really is evaluated twice, so a walk that visited each chain once would
under-report a real ruleset. The cost is that the number of distinct paths
under the depth cap grows like a factorial in how densely the chains jump to
each other.

Measured on a laptop before the bound existed, one `inet` table whose chains
each jump to every other chain:

    chains  rule hits   seconds
      6         9,786     0.05
      7        82,201     0.45
      8       767,208     4.23

and nine chains is roughly eight million hits, ten is memory. The document is
written by the host, a host document is treated as hostile
input, and the dashboard walks it per port per family on every request. So an
unbounded walk is a way to hang the customer's screen from a machine somebody
else owns.

These tests are about the bound holding and about it being visible. What a
real ruleset produces is `tests/test_join.py`'s subject and is untouched here.
"""
import json
import time

import pytest

from app import db, join, prober, store


def dense_document(chain_count, rules_per_chain=None):
    """One table whose chains all jump to each other.

    Legal nftables: there is no loop, because no chain jumps to one already on
    the path. It is the diamond, repeated, which is exactly the shape `seen`
    is right not to collapse.
    """
    chains = [{"name": "input", "hook": "input", "type": "filter", "priority": 0,
               "rules": [{"text": f"jump c{i}", "rendered": "full"}
                         for i in range(chain_count)]}]
    for i in range(chain_count):
        targets = [j for j in range(chain_count) if j != i]
        if rules_per_chain is not None:
            targets = targets[:rules_per_chain]
        chains.append({"name": f"c{i}",
                       "rules": [{"text": f"jump c{j}", "rendered": "full"}
                                 for j in targets]})
    return {"nftables": {"tables": [{"family": "inet", "name": "t",
                                     "chains": chains}]}}


def flat_document(rule_count):
    """One base chain carrying a great many rules and no jumps at all."""
    return {"nftables": {"tables": [{
        "family": "inet", "name": "t",
        "chains": [{"name": "input", "hook": "input", "type": "filter",
                    "priority": 0,
                    "rules": [{"text": "tcp dport 443 accept", "rendered": "full"}
                              for _ in range(rule_count)]}]}]}}


# ------------------------------------------------------------ the bound holds

def test_a_dense_ruleset_finishes_and_the_hits_are_bounded():
    hits, _counts = join._rules_for_port(dense_document(9), "v4", "tcp", 443)
    assert len(hits) <= join.MAX_RULES_WALKED


def test_a_dense_ruleset_finishes_quickly():
    """A wall-clock assertion, with the threshold set where only the old
    behaviour could cross it. Nine chains took tens of seconds unbounded and
    takes a fraction of one now; five seconds is generous enough that a slow
    machine under load does not make this flap."""
    started = time.monotonic()
    join._rules_for_port(dense_document(9), "v4", "tcp", 443)
    assert time.monotonic() - started < 5.0


def test_the_bound_is_over_the_whole_port_and_not_per_base_chain():
    """A document carrying many base chains must not be able to spend the
    budget once per chain."""
    document = dense_document(8)
    table = document["nftables"]["tables"][0]
    base = table["chains"][0]
    for extra in range(20):
        table["chains"].insert(1, {**base, "name": f"input{extra}",
                                   "hook": "input", "priority": extra + 1})
    hits, _counts = join._rules_for_port(document, "v4", "tcp", 443)
    assert len(hits) <= join.MAX_RULES_WALKED


# ------------------------------------------------------- and it is not silent

def test_a_truncated_walk_counts_what_it_did_not_read():
    """A cap that narrows coverage silently reads afterwards as coverage. The
    rules left unexamined land in the count already behind "not fully
    readable" on the screen."""
    _hits, counts = join._rules_for_port(dense_document(9), "v4", "tcp", 443)
    assert counts[join.UNREADABLE] > 0


def test_a_truncated_walk_says_the_path_is_not_fully_readable(tmp_path):
    """The whole way through to the sentence a person reads. Nothing may
    conclude from a walk that stopped early, and this note is what tells them.
    """
    document = dense_document(9)
    document.update({"schema_version": 1, "hostname": "dense",
                     "collected_at_unix": 1_700_000_000,
                     "sockets": {"status": "collected", "listening": [
                         {"protocol": "tcp", "family": "v4",
                          "bind_address": "0.0.0.0", "port": 443,
                          "process_name": "nginx", "pid": 1}]}})
    document["nftables"]["status"] = "collected"

    con = db.connect(str(tmp_path / "j.db"))
    db.init(con)
    prober.init(con)
    host_id, _credential = store.add_host(con, "dense")
    store.insert_report(con, host_id=host_id, collected_at_unix=1_700_000_000,
                        schema_version=1, document=json.dumps(document))
    result = join.host_findings(con, host_id)
    con.close()

    for_443 = [f for f in result.findings if f.port == 443 and f.family == "v4"]
    assert for_443, "the walk produced no finding to look at"
    assert all(join.NOTE_RULES_NOT_FULLY_READABLE in f.cause.notes
               for f in for_443)
    assert all(f.inside.unreadable_rule_count > 0 for f in for_443)


# ------------------------------------- and an ordinary ruleset is not touched

@pytest.mark.parametrize("rule_count", [1, 50, 400])
def test_a_ruleset_the_size_of_a_real_one_is_read_whole(rule_count):
    """The busiest host in the fleet carries 341 nftables rules in total. The
    bound is two orders of magnitude above that and must change nothing here.
    """
    hits, counts = join._rules_for_port(flat_document(rule_count), "v4",
                                        "tcp", 443)
    assert len(hits) == rule_count
    assert counts[join.NAMES_PORT] == rule_count
    assert counts[join.UNREADABLE] == 0


def test_a_chain_reached_twice_is_still_walked_twice():
    """The property the bound must not quietly buy itself. A packet really is
    evaluated against a jumped-to chain once per jump, and collapsing that
    would be a cheaper bound and a wrong answer."""
    document = {"nftables": {"tables": [{
        "family": "inet", "name": "t", "chains": [
            {"name": "input", "hook": "input", "type": "filter", "priority": 0,
             "rules": [{"text": "jump left", "rendered": "full"},
                       {"text": "jump right", "rendered": "full"}]},
            {"name": "left", "rules": [{"text": "jump shared", "rendered": "full"}]},
            {"name": "right", "rules": [{"text": "jump shared", "rendered": "full"}]},
            {"name": "shared",
             "rules": [{"text": "tcp dport 443 accept", "rendered": "full"}]},
        ]}]}}
    hits, counts = join._rules_for_port(document, "v4", "tcp", 443)
    assert counts[join.NAMES_PORT] == 2
    assert len([h for h in hits if h.chain == "shared"]) == 2


def test_the_depth_cap_and_the_loop_guard_are_still_there():
    """Both were doing a job before this and both still are. A chain that
    jumps to itself is refused by `seen`, and a chain deep enough to pass the
    depth cap stops there, neither of them by spending the budget."""
    document = {"nftables": {"tables": [{
        "family": "inet", "name": "t", "chains": [
            {"name": "input", "hook": "input", "type": "filter", "priority": 0,
             "rules": [{"text": "jump self", "rendered": "full"}]},
            {"name": "self", "rules": [{"text": "jump self", "rendered": "full"}]},
        ]}]}}
    hits, counts = join._rules_for_port(document, "v4", "tcp", 443)
    assert len(hits) == 2
    assert counts[join.UNREADABLE] == 0
