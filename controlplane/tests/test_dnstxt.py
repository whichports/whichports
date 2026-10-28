"""The DNS TXT reader.

    python -m pytest tests/test_dnstxt.py

This parses bytes that arrive from the network, so most of what is below is
about malformed answers. The rule the whole file exists to pin: every bad
answer comes out as `DnsError`, never as an IndexError, a struct.error or a
silently wrong list. A resolver that lies must produce a plain no.

Nothing here touches a real resolver. Every answer is built byte by byte.
"""

import struct

import pytest

from app import dnstxt

NAME = "153.108.199.185.in-addr.arpa"
QID = 0x4D2

FLAGS_ANSWER = 0x8180        # response, recursion available, rcode 0
FLAGS_NXDOMAIN = 0x8183
FLAGS_SERVFAIL = 0x8182
FLAGS_TRUNCATED = 0x8380
FLAGS_QUESTION = 0x0100      # QR clear, so not an answer at all


def txt_record(*strings: bytes, name: bytes = b"\xc0\x0c") -> bytes:
    """One TXT answer record. The default name is a compression pointer back
    to the question, which is what a real resolver sends."""
    rdata = b"".join(bytes([len(s)]) + s for s in strings)
    return name + struct.pack(">HHIH", dnstxt.TYPE_TXT, dnstxt.CLASS_IN, 300,
                              len(rdata)) + rdata


def other_record(rtype: int = 1, rdata: bytes = b"\x01\x02\x03\x04") -> bytes:
    return b"\xc0\x0c" + struct.pack(">HHIH", rtype, dnstxt.CLASS_IN, 300,
                                     len(rdata)) + rdata


def answer(records: bytes = b"", count: int | None = None, qid: int = QID,
           flags: int = FLAGS_ANSWER, name: str = NAME,
           qdcount: int = 1) -> bytes:
    if count is None:
        count = 1 if records else 0
    header = struct.pack(">HHHHHH", qid, flags, qdcount, count, 0, 0)
    question = dnstxt.encode_name(name) + struct.pack(">HH", dnstxt.TYPE_TXT,
                                                      dnstxt.CLASS_IN)
    return header + question + records


# ------------------------------------------------------------ reading a name

def test_a_txt_string_is_read():
    data = answer(txt_record(b"whpa_deadbeef"))
    assert dnstxt.parse_response(data, QID, NAME) == ["whpa_deadbeef"]


def test_the_strings_of_one_record_are_joined():
    """A TXT record over 255 characters arrives as several character-strings
    and a reader is meant to join them."""
    data = answer(txt_record(b"whpa_", b"deadbeef"))
    assert dnstxt.parse_response(data, QID, NAME) == ["whpa_deadbeef"]


def test_two_records_are_two_strings():
    data = answer(txt_record(b"one") + txt_record(b"two"), count=2)
    assert dnstxt.parse_response(data, QID, NAME) == ["one", "two"]


def test_a_record_of_another_type_is_skipped():
    """A name can hold an A record and a TXT record. Only the TXT is ours."""
    data = answer(other_record() + txt_record(b"mine"), count=2)
    assert dnstxt.parse_response(data, QID, NAME) == ["mine"]


def test_a_record_in_another_class_is_skipped():
    rdata = b"\x04here"
    record = b"\xc0\x0c" + struct.pack(">HHIH", dnstxt.TYPE_TXT, 3, 300,
                                       len(rdata)) + rdata
    data = answer(record + txt_record(b"mine"), count=2)
    assert dnstxt.parse_response(data, QID, NAME) == ["mine"]


def test_an_uncompressed_name_in_a_record_is_read():
    data = answer(txt_record(b"mine", name=dnstxt.encode_name(NAME)))
    assert dnstxt.parse_response(data, QID, NAME) == ["mine"]


def test_a_name_that_holds_nothing_is_an_empty_list():
    assert dnstxt.parse_response(answer(), QID, NAME) == []


def test_a_name_that_does_not_exist_is_an_empty_list():
    """NXDOMAIN is not an error. The name holds no token, which is a plain
    no, and treating it as a failure would have the caller retry forever."""
    data = answer(flags=FLAGS_NXDOMAIN)
    assert dnstxt.parse_response(data, QID, NAME) == []


# ------------------------------------------------------------- refusing

def test_a_server_failure_is_an_error_not_an_empty_answer():
    """SERVFAIL means the resolver could not answer. Reading that as "no
    token published" would refuse a proof that was in fact published."""
    with pytest.raises(dnstxt.DnsError):
        dnstxt.parse_response(answer(flags=FLAGS_SERVFAIL), QID, NAME)


def test_a_truncated_answer_is_refused():
    data = answer(txt_record(b"mine"), flags=FLAGS_TRUNCATED)
    with pytest.raises(dnstxt.DnsError):
        dnstxt.parse_response(data, QID, NAME)


def test_an_answer_to_another_question_is_refused():
    with pytest.raises(dnstxt.DnsError):
        dnstxt.parse_response(answer(txt_record(b"mine")), QID + 1, NAME)


def test_an_answer_echoing_another_name_is_refused():
    data = answer(txt_record(b"mine"), name="1.1.1.1.in-addr.arpa")
    with pytest.raises(dnstxt.DnsError):
        dnstxt.parse_response(data, QID, NAME)


def test_a_question_rather_than_an_answer_is_refused():
    data = answer(flags=FLAGS_QUESTION)
    with pytest.raises(dnstxt.DnsError):
        dnstxt.parse_response(data, QID, NAME)


def test_more_than_one_echoed_question_is_refused():
    data = answer(txt_record(b"mine"), qdcount=2)
    with pytest.raises(dnstxt.DnsError):
        dnstxt.parse_response(data, QID, NAME)


def test_a_record_count_larger_than_the_records_is_refused():
    data = answer(txt_record(b"mine"), count=4)
    with pytest.raises(dnstxt.DnsError):
        dnstxt.parse_response(data, QID, NAME)


def test_rdata_running_past_the_end_is_refused():
    record = b"\xc0\x0c" + struct.pack(">HHIH", dnstxt.TYPE_TXT, dnstxt.CLASS_IN,
                                       300, 400) + b"\x04mine"
    with pytest.raises(dnstxt.DnsError):
        dnstxt.parse_response(answer(record), QID, NAME)


def test_a_reserved_label_type_is_refused():
    record = b"\x80" + struct.pack(">HHIH", dnstxt.TYPE_TXT, dnstxt.CLASS_IN, 300, 0)
    with pytest.raises(dnstxt.DnsError):
        dnstxt.parse_response(answer(record), QID, NAME)


def test_a_character_string_running_past_its_record_is_skipped():
    """One malformed record must not take the whole lookup down, because a
    name can hold records nobody here put there."""
    rdata = b"\x40short"
    broken = b"\xc0\x0c" + struct.pack(">HHIH", dnstxt.TYPE_TXT, dnstxt.CLASS_IN,
                                       300, len(rdata)) + rdata
    data = answer(broken + txt_record(b"mine"), count=2)
    assert dnstxt.parse_response(data, QID, NAME) == ["mine"]


def test_a_non_ascii_record_is_skipped_not_mangled():
    data = answer(txt_record(b"\xff\xfe") + txt_record(b"mine"), count=2)
    assert dnstxt.parse_response(data, QID, NAME) == ["mine"]


def test_an_answer_shorter_than_a_header_is_refused():
    with pytest.raises(dnstxt.DnsError):
        dnstxt.parse_response(b"\x00\x01", QID, NAME)


def test_an_empty_answer_is_refused():
    with pytest.raises(dnstxt.DnsError):
        dnstxt.parse_response(b"", QID, NAME)


# --------------------------------------------------------- hostile answers

def test_every_truncation_of_a_good_answer_is_refused():
    """A short read, a cut connection or a resolver that stops mid-record.
    Each one has to be a plain no rather than an exception the caller was not
    expecting."""
    data = answer(txt_record(b"whpa_deadbeef") + txt_record(b"second"), count=2)
    for cut in range(len(data)):
        with pytest.raises(dnstxt.DnsError):
            dnstxt.parse_response(data[:cut], QID, NAME)


def test_any_single_byte_change_gives_a_list_or_a_refusal():
    """The property that matters for a parser fed by the network: whatever
    the bytes say, the answer is either strings or DnsError. Anything else
    escaping this function would land in a caller that cannot handle it."""
    data = answer(txt_record(b"whpa_deadbeef"))
    for index in range(len(data)):
        for value in (0x00, 0x01, 0x40, 0x80, 0xC0, 0xFF):
            mutated = data[:index] + bytes([value]) + data[index + 1:]
            try:
                result = dnstxt.parse_response(mutated, QID, NAME)
            except dnstxt.DnsError:
                continue
            assert isinstance(result, list)
            assert all(isinstance(item, str) for item in result)


# ------------------------------------------------------------ name encoding

def test_a_trailing_dot_is_accepted():
    assert dnstxt.encode_name("example.com.") == dnstxt.encode_name("example.com")


@pytest.mark.parametrize("name", ["", ".", "a..b", "a" * 64 + ".com", "exämple.com",
                                  ".".join(["abcdefghij"] * 30)])
def test_a_name_that_cannot_be_encoded_is_refused(name):
    with pytest.raises(dnstxt.DnsError):
        dnstxt.encode_name(name)


def test_a_query_carries_the_id_and_the_question():
    query = dnstxt.build_query(NAME, QID)
    assert struct.unpack(">H", query[:2])[0] == QID
    assert query.endswith(struct.pack(">HH", dnstxt.TYPE_TXT, dnstxt.CLASS_IN))
    assert dnstxt.encode_name(NAME) in query


# --------------------------------------------------------------- resolvers

def test_resolvers_are_read_from_the_file(tmp_path):
    path = tmp_path / "resolv.conf"
    path.write_text("# a comment\nsearch example.org\nnameserver 9.9.9.9\n"
                    "nameserver 2620:fe::fe\n")
    assert dnstxt.system_resolvers(str(path)) == ["9.9.9.9", "2620:fe::fe"]


def test_a_junk_nameserver_line_is_skipped(tmp_path):
    path = tmp_path / "resolv.conf"
    path.write_text("nameserver\nnameserver not-an-address\nnameserver 1.1.1.1\n")
    assert dnstxt.system_resolvers(str(path)) == ["1.1.1.1"]


def test_at_most_three_resolvers_are_used(tmp_path):
    path = tmp_path / "resolv.conf"
    path.write_text("".join(f"nameserver 10.0.0.{n}\n" for n in range(1, 9)))
    assert len(dnstxt.system_resolvers(str(path))) == dnstxt.MAX_RESOLVERS


def test_a_missing_resolv_conf_is_no_resolvers(tmp_path):
    assert dnstxt.system_resolvers(str(tmp_path / "nope")) == []


def test_a_lookup_without_a_resolver_is_refused():
    """No network is reached: the empty list is checked before any socket."""
    with pytest.raises(dnstxt.DnsError):
        dnstxt.query_txt(NAME, servers=[])
