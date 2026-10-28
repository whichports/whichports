"""The list of ports that should rarely face the internet.

    python -m pytest tests/test_rarelypublic.py

The list is a claim the product makes, so what is tested is that an entry
cannot exist without its source, and that the set of ports is exactly the one
that was decided (`docs/RECORD.md` 4.248). Whether a sentence still stands on
its page is not something a test here can know: that is read by a person, on
the page, on the day in `read_on`.
"""
import dataclasses
import datetime

import pytest

from app import rarelypublic
from app.rarelypublic import Entry

GOOD = dict(protocol="tcp", port=6379, default_of="Redis",
            sentence="A sentence from the service's own documentation.",
            source="The page's title", source_url="https://example.com/security",
            port_stated="the default is 6379", port_url="https://example.com/config",
            read_on="2026-10-02")


def entry(**changed):
    return Entry(**{**GOOD, **changed})


# ----------------------------------------------------------- the decided set

def test_the_list_is_exactly_the_ports_that_were_decided():
    assert sorted((e.protocol, e.port) for e in rarelypublic.ENTRIES) == [
        ("tcp", 445), ("tcp", 2375), ("tcp", 3306), ("tcp", 6379), ("tcp", 9200),
        ("tcp", 11211), ("tcp", 27017), ("tcp", 27018), ("tcp", 27019)]


def test_seven_services_stand_behind_the_nine_ports():
    pages = {e.source_url for e in rarelypublic.ENTRIES}
    assert len(pages) == 7


@pytest.mark.parametrize("protocol, port", [
    ("tcp", 5432),    # PostgreSQL: its own documentation never says it
    ("tcp", 2376),    # the Docker daemon over TLS, the secured way to reach it
    ("tcp", 2379),    # etcd
    ("tcp", 10250),   # the kubelet
    ("tcp", 22), ("tcp", 80), ("tcp", 443),
])
def test_what_was_left_off_is_not_on_it(protocol, port):
    assert rarelypublic.lookup(protocol, port) is None


def test_nothing_on_the_list_is_udp():
    """Nothing is measured from outside over UDP, so a UDP entry could never
    show. memcached's port is on the list for TCP only."""
    assert {e.protocol for e in rarelypublic.ENTRIES} == {"tcp"}
    assert rarelypublic.lookup("udp", 11211) is None
    assert rarelypublic.lookup("tcp", 11211) is not None


def test_no_port_is_on_the_list_twice():
    keys = [(e.protocol, e.port) for e in rarelypublic.ENTRIES]
    assert len(keys) == len(set(keys))


# ------------------------------------------------ every entry has its source

@pytest.mark.parametrize("e", rarelypublic.ENTRIES, ids=lambda e: f"{e.protocol}/{e.port}")
def test_every_entry_carries_its_sentence_its_page_and_its_date(e):
    assert e.default_of.strip()
    # a sentence, not a word: it starts with a capital and ends with a full stop
    assert len(e.sentence) >= 40 and e.sentence[0].isupper() and e.sentence.endswith(".")
    assert e.source.strip()
    assert e.source_url.startswith("https://") and e.port_url.startswith("https://")
    assert e.port_stated.strip()
    assert datetime.date.fromisoformat(e.read_on) >= datetime.date(2026, 10, 2)


@pytest.mark.parametrize("e", rarelypublic.ENTRIES, ids=lambda e: f"{e.protocol}/{e.port}")
def test_the_words_that_give_the_port_name_the_port(e):
    """The port number is a claim too. Where its source says a number, it is
    this entry's number. MongoDB's page gives the numbers in a table beside
    these words, so its three entries are held by the decided set above."""
    if e.source_url.startswith("https://www.mongodb.com/"):
        return
    assert str(e.port) in e.port_stated


@pytest.mark.parametrize("field", ["default_of", "sentence", "source", "source_url",
                                   "port_stated", "port_url", "read_on"])
@pytest.mark.parametrize("empty", ["", "   ", None])
def test_an_entry_with_a_field_of_its_source_missing_cannot_be_made(field, empty):
    with pytest.raises(ValueError) as refused:
        entry(**{field: empty})
    assert field in str(refused.value)


def test_an_entry_with_everything_can_be_made():
    assert entry().port == 6379


@pytest.mark.parametrize("url_field", ["source_url", "port_url"])
@pytest.mark.parametrize("address", ["http://example.com/page", "example.com/page",
                                     "ftp://example.com/page", "see the manual"])
def test_a_source_that_is_not_an_https_address_is_refused(url_field, address):
    with pytest.raises(ValueError):
        entry(**{url_field: address})


@pytest.mark.parametrize("when", ["yesterday", "02-10-2026", "2026-13-01", "2026-10-32"])
def test_a_date_that_is_not_a_date_is_refused(when):
    with pytest.raises(ValueError):
        entry(read_on=when)


@pytest.mark.parametrize("protocol", ["udp", "sctp", "TCP", "", None])
def test_only_tcp_can_be_on_the_list(protocol):
    with pytest.raises(ValueError):
        entry(protocol=protocol)


@pytest.mark.parametrize("port", [0, -1, 65536, 6379.0, "6379", None, True])
def test_a_port_that_is_not_a_port_is_refused(port):
    with pytest.raises(ValueError):
        entry(port=port)


@pytest.mark.parametrize("port", [1, 65535])
def test_the_ends_of_the_port_range_are_ports(port):
    assert entry(port=port).port == port


def test_an_entry_cannot_be_changed_after_it_is_made():
    with pytest.raises(dataclasses.FrozenInstanceError):
        rarelypublic.ENTRIES[0].sentence = "something else"


# ------------------------------------------------------------------ the lookup

def test_lookup_finds_an_entry_by_protocol_and_port():
    found = rarelypublic.lookup("tcp", 6379)
    assert found.default_of == "Redis"
    assert "not a good idea to expose the Redis instance directly to the internet" in found.sentence


def test_lookup_reads_the_protocol_in_any_case():
    assert rarelypublic.lookup("TCP", 3306) is rarelypublic.lookup("tcp", 3306)


@pytest.mark.parametrize("protocol, port", [
    ("tcp", "6379"), ("tcp", 6379.0), ("tcp", None), ("tcp", True), (None, 6379),
    (6379, "tcp"), ("", 6379), ("tcp", 0), ("tcp", -6379), ("tcp", 70000),
])
def test_lookup_answers_none_for_anything_that_is_not_a_listed_port(protocol, port):
    assert rarelypublic.lookup(protocol, port) is None


def test_the_same_sentence_stands_behind_all_three_mongodb_ports():
    three = [rarelypublic.lookup("tcp", p) for p in (27017, 27018, 27019)]
    assert len({e.sentence for e in three}) == 1
    assert len({e.default_of for e in three}) == 3
