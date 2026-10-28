"""A ufw rule that lets one source in reads "permits some" on the Packet path.

    Run from site/: python3 -m pytest app/test_ufw_source_rule.py

`ufw allow from 198.51.100.7 to any port 443` lets that one address in. The
Packet path named it on the flow as the rule for the port, "allow 443,
198.51.100.7", under a packet that came from the prober's address and went
through to the service, as if that rule had let it in (the sweep of
2026-09-21, C4 in docs/RECORD.md 4.199). The box says "permits some" for such
a rule, the word the provider's firewall already has for a rule that lets
some sources in, and the rule itself stays in the list under it.
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from test_render_live import db  # noqa: E402
from test_ufw_port_list import ufw_box  # noqa: E402

__all__ = ["db"]

ONE = "allow tcp 443 0.0.0.0/0 any 198.51.100.7 in"
EVERYONE = "allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in"


def test_an_allow_for_one_source_reads_permits_some(db):
    text = ufw_box(db, [ONE])
    assert "ufw permits some" in text
    assert "ufw allow 443, 198.51.100.7" not in text
    # the rule itself is still in the list, with its source
    assert "allow 443 tcp/ v4 198.51.100.7" in text
    assert "as ufw writes it " + ONE in text


def test_an_allow_for_a_range_of_sources_reads_permits_some(db):
    text = ufw_box(db, ["allow tcp 443 0.0.0.0/0 any 198.51.100.0/24 in"])
    assert "ufw permits some" in text
    assert "allow 443 tcp/ v4 198.51.100.0/24" in text


def test_an_allow_from_anywhere_reads_as_it_did(db):
    text = ufw_box(db, [EVERYONE])
    assert "ufw allow 443, anywhere" in text
    assert "permits some" not in text


def test_an_allow_from_anywhere_is_the_rule_named_when_both_are_there(db):
    """The rule for one source comes first in ufw's file, and the port is open
    to everybody by the second. "Permits some" would say less than is true."""
    text = ufw_box(db, [ONE, EVERYONE])
    assert "ufw allow 443, anywhere" in text
    assert "ufw permits some" not in text
    assert "allow 443 tcp/ v4 198.51.100.7" in text   # both rules are listed


def test_the_order_of_the_two_rules_does_not_change_the_box(db):
    assert "ufw allow 443, anywhere" in ufw_box(db, [EVERYONE, ONE])


def test_a_deny_for_one_source_is_named_as_it_was(db):
    """Only an allow lets somebody in. A deny for one address is written out,
    as before."""
    text = ufw_box(db, ["deny tcp 443 0.0.0.0/0 any 198.51.100.7 in"])
    assert "ufw deny 443, 198.51.100.7" in text
    assert "permits some" not in text


def test_a_limit_for_one_source_is_named_as_it_was(db):
    text = ufw_box(db, ["limit tcp 443 0.0.0.0/0 any 198.51.100.7 in"])
    assert "ufw limit 443, 198.51.100.7" in text
    assert "permits some" not in text


def test_a_port_list_for_one_source_reads_permits_some_for_each_port(db):
    text = ufw_box(db, ["allow tcp 80,443 0.0.0.0/0 any 198.51.100.7 in"])
    assert "ufw permits some" in text


def test_a_rule_for_another_port_is_still_no_rule(db):
    text = ufw_box(db, ["allow tcp 8443 0.0.0.0/0 any 198.51.100.7 in"])
    assert "ufw no rule for 443" in text
    assert "permits some" not in text
