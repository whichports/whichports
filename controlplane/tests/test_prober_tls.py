"""The TLS certificate read, which is the second half of SI-7.

    python -m pytest tests/test_prober_tls.py

SI-7 in full: *no version detection. TCP connect, plus a TLS handshake to read
the certificate. Nothing beyond the handshake. No banner grabbing, no CVE
matching.* This file is that sentence turned into assertions, and the ones that
matter most are the ones about what does **not** happen:

  - no application byte is ever sent, measured from the far end of a real
    loopback handshake rather than promised
  - no second handshake, no ALPN, no cipher list, no server name. One
    ClientHello with this machine's own defaults, and whatever comes back
  - nothing is verified against a trust store, and no field anywhere says
    valid, trusted or safe. We report what was presented
  - the gate is asked again immediately before the handshake, so a
    certificate is never read from an address nobody proved
  - a handshake that did not complete is a typed reason on a row that exists,
    never a row that quietly went missing

The certificate parser is fed hostile input on purpose: truncated, indefinite
length, lengths that point past the end, control characters and separator
characters inside a subject, and a fully synthetic certificate built byte by
byte so the malformed cases can be built at all.

No test here reaches a network. The handshake tests bind 127.0.0.1.
"""

import ast
import asyncio
import base64
import datetime as dt
import errno
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import warnings

import pytest

from app import authz, db, prober, store
from tests.test_prober import (FakeConnect, NOW, OTHER_V4, RefusingConnect, V4,
                               V6, authorise, document, os_error, run)


# ============================================================ real certificates
#
# Made once with `openssl req`/`openssl x509` and pasted here as DER, so the
# suite needs no key material and no shell to read a real certificate. The
# leaf is signed by a test CA, so its issuer differs from its subject, and the
# expired one is self-issued. Both are throwaway and neither has ever been
# used by anything.

LEAF_SIGNED_B64 = (
    "MIIDpjCCAo6gAwIBAgIUAphDowKGNFIxRg2ovTO3oRk7F8MwDQYJKoZIhvcNAQELBQAwSTEL"
    "MAkGA1UEBhMCQkUxGzAZBgNVBAoMEldoaWNocG9ydHMgVGVzdCBDQTEdMBsGA1UEAwwUV2hp"
    "Y2hwb3J0cyBUZXN0IFJvb3QwHhcNMjYwMTAxMDAwMDAwWhcNMjcwMTAxMDAwMDAwWjA6MQsw"
    "CQYDVQQGEwJCRTEUMBIGA1UECgwLRXhhbXBsZSBPcmcxFTATBgNVBAMMDGV4YW1wbGUudGVz"
    "dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKhl6BEpK03fi2qwKogXmC/t9YiK"
    "NKuUqmJ3zGiPiRsi+ENV4UsicKLlIUTJ+SAmHavPyQ+l112PGJIVqkl200IDYAcnQ1z+N6R+"
    "Z67WxSCQeKj3S64opfyf2tCxy0g/0kQX35cP2K0ZoK1gL61Dz40YAx7gbK0wEm+URMHji9be"
    "20tq0jvhCDuol5L3wU2NUgcf32o4HiPTfqYvi9t2PGAbxFsHKtnoPvmm4R316dx/cyLkBN/n"
    "pTpqHALR6xblfyQhT5KPEi6hVDW3rJgGijqM0H4Y6mNgGILQLaVIrpOS4tVJTc1LTPUIwwtm"
    "rhJoCZdeumnRs9RHFQr0TeSuNrUCAwEAAaOBlDCBkTAMBgNVHRMBAf8EAjAAMEEGA1UdEQQ6"
    "MDiCDGV4YW1wbGUudGVzdIIQd3d3LmV4YW1wbGUudGVzdIcEwAACCocQIAENuAAAAAAAAAAA"
    "AAAAATAdBgNVHQ4EFgQUY0rC1JLwMGgVZIXJoEUQev5fQfowHwYDVR0jBBgwFoAUBKAInZje"
    "9J04PkD5MCdm7enCTtIwDQYJKoZIhvcNAQELBQADggEBAIgqawCQeL9GTTLsmouCelmMRIBi"
    "hLinPYWOGgxLj8tDRukl4FPfsVc6+vm6PQ+wLQpr7TC77WvShtPWHc7qxJujstTnlVWKX5nt"
    "yhH++qjv/b6aA0ELzTPL/k1NTDiGmB9QN8JXP6wVKnWwi7Zq4gYn57WsOCMhR6itrIT7cY9C"
    "FyEh08HZgZhf0Z7zOWYQNB3bKCAyxNpkSWWZTHxaJCXywpIgRJjTYrY5RYm3mQQr8neOwNGn"
    "Mmb3XhnrFmew9qV8Gu8jAS1l+NqUSQqO96BNV6bD/bkii793fZ4VsZo3yEgi8oVR40ZA5Lag"
    "dPy61L0pwhLVw3QIVilM+pdQvcI="
)

EXPIRED_B64 = (
    "MIIDDDCCAfSgAwIBAgIUQYqCkY6lBNFkdHI1xveYegnkLuIwDQYJKoZIhvcNAQELBQAwFzEV"
    "MBMGA1UEAwwMZXhwaXJlZC50ZXN0MB4XDTIwMDEwMTAwMDAwMFoXDTIxMDEwMTAwMDAwMFow"
    "FzEVMBMGA1UEAwwMZXhwaXJlZC50ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC"
    "AQEA2qsK4oMcyd3cVuLBPzSkZu+KZGn4bQBgyw7bTOj1MjQmT2+r0N17LhTsNufWzv1R7ryK"
    "hUjbiehp8pSu3PjpFlKXWa4T14t5Bn23+mpC77a2dneKEo/IrsudW4pafnp0pJ2LCUwhc/cA"
    "O0acsfel3vIz1jfjbJLzg6w1sqFBalmwpFOykjzVEzetu/8nZlxia+6DAcAG4rKR909t9hPM"
    "aUGZqjTdaC3vxaRuDix8w5tFtre73CVfziufchR8nlSoGgIhd+YkEIEFsvh7y7yh4Re9vWco"
    "mHuAuY+Fz0Ovr9NmbX/qHxifo9vjOT+38K6UyDHEZXn4YJYjidOxngQq5wIDAQABo1AwTjAd"
    "BgNVHQ4EFgQUeNTfF90Inndi450EZjvE1sgXH6UwHwYDVR0jBBgwFoAUeNTfF90Inndi450E"
    "ZjvE1sgXH6UwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEApb2qd1PkZx0xsW/i"
    "81g5S3RMFmhfbew9anWoFBIanv1vTi6WNec0AwbuMijpqkeOQs9M74MqCK/OWG7BhUcvVHjE"
    "Fm9CXX02/kk6bKEoA4VjUQOqbnm9+0jAMhNQ7RsjXJC80jy5nfCURp4qKpCc5LrBDWk495AL"
    "OpNnNUg97/x6gYGqfSQ6SdReWoNbGmWm8x02SJMlJj27uXsAi7ZGPqxm205u/eKTLTZ8kqdD"
    "BRtWAD0zbqN5OMkoDhhu1Z9V0BrZDNP0PFYLE1VNVrnC1ZDUSi/IwVWodnqvMMudBWHQ6G75"
    "zV8XR/dW10XptY8Pf3eOXcjbzV4cwYxKEq/gkw=="
)

LEAF_SIGNED = base64.b64decode(LEAF_SIGNED_B64)
EXPIRED = base64.b64decode(EXPIRED_B64)


# ==================================================== building a certificate by hand
#
# The parser reads bytes a stranger chose, so the tests have to be able to
# choose those bytes. This is a DER writer small enough to read in one sitting,
# and it is deliberately willing to write malformed output.

def element(tag: int, content: bytes) -> bytes:
    """One DER element, with the long form of the length when it is needed."""
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    width = (len(content).bit_length() + 7) // 8
    return bytes([tag, 0x80 | width]) + len(content).to_bytes(width, "big") + content


def oid_bytes(dotted: str) -> bytes:
    parts = [int(part) for part in dotted.split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for arc in parts[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append((arc & 0x7F) | 0x80)
            arc >>= 7
        body += bytes(reversed(chunk))
    return element(0x06, body)


def attribute(oid: str, text: str, tag: int = 0x0C) -> bytes:
    """One AttributeTypeAndValue inside its own RelativeDistinguishedName."""
    encodings = {0x0C: "utf-8", 0x13: "ascii", 0x16: "ascii", 0x14: "latin-1",
                 0x1E: "utf-16-be", 0x1C: "utf-32-be"}
    value = element(tag, text.encode(encodings[tag]))
    return element(0x31, element(0x30, oid_bytes(oid) + value))


CN = "2.5.4.3"
ORG = "2.5.4.10"
COUNTRY = "2.5.4.6"


def name(*attributes: bytes) -> bytes:
    return element(0x30, b"".join(attributes))


def san_extension(*entries) -> bytes:
    """subjectAltName. `entries` are ("dns", text) or ("ip", text) or a raw
    (tag, bytes) pair for the shapes a stranger might send that we do not
    name."""
    general = b""
    for entry in entries:
        kind, value = entry
        if kind == "dns":
            general += element(0x82, value.encode("ascii"))
        elif kind == "ip":
            general += element(0x87, _packed_ip(value))
        else:
            general += element(kind, value)
    return element(0x30, oid_bytes("2.5.29.17")
                   + element(0x04, element(0x30, general)))


def _packed_ip(text: str) -> bytes:
    import ipaddress
    return ipaddress.ip_address(text).packed


def certificate(*, subject=None, issuer=None, not_before=b"260101000000Z",
                not_after=b"270101000000Z", time_tag=0x17, serial=b"\x2a",
                extensions=b"", version=True, tbs_extra=b"") -> bytes:
    """A certificate with the fields this parser reads and stubs for the rest.

    The signature is not real and nothing here signs anything: the parser never
    verifies a signature, which is the point of this whole module.
    """
    subject = subject if subject is not None else name(attribute(CN, "subject.test"))
    issuer = issuer if issuer is not None else name(attribute(CN, "issuer.test"))
    body = b""
    if version:
        body += element(0xA0, element(0x02, b"\x02"))
    body += element(0x02, serial)
    body += element(0x30, oid_bytes("1.2.840.113549.1.1.11") + element(0x05, b""))
    body += issuer
    body += element(0x30, element(time_tag, not_before) + element(time_tag, not_after))
    body += subject
    body += element(0x30, element(0x30, oid_bytes("1.2.840.113549.1.1.1"))
                    + element(0x03, b"\x00\x01"))
    if extensions:
        body += element(0xA3, element(0x30, extensions))
    body += tbs_extra
    tbs = element(0x30, body)
    return element(0x30, tbs
                   + element(0x30, oid_bytes("1.2.840.113549.1.1.11"))
                   + element(0x03, b"\x00\xff"))


# ================================================================== the parser

def test_a_real_certificate_reads_the_way_openssl_prints_it():
    """The leaf was made by `openssl x509` and these are the values `openssl
    x509 -noout -subject -issuer -dates -serial -ext subjectAltName` printed for
    it. If the parser and OpenSSL ever disagree, this is where it shows."""
    read = prober.parse_certificate(LEAF_SIGNED)
    assert read.subject == "C=BE,O=Example Org,CN=example.test"
    assert read.issuer == "C=BE,O=Whichports Test CA,CN=Whichports Test Root"
    assert read.not_before == "2026-01-01T00:00:00+00:00"
    assert read.not_after == "2027-01-01T00:00:00+00:00"
    assert read.serial == "029843a30286345231460da8bd33b7a1193b17c3"
    assert read.names == ("example.test", "www.example.test", "192.0.2.10",
                          "2001:db8::1")


def test_issuer_equals_subject_is_reported_as_a_fact_and_not_as_a_verdict():
    """`self_issued` is issuer equals subject and nothing more. We do not check
    that the signature was made by the key inside it, so this is never called
    self signed and never called untrusted."""
    self_issued = prober.parse_certificate(EXPIRED)
    assert self_issued.self_issued is True
    assert self_issued.subject == self_issued.issuer == "CN=expired.test"
    assert prober.parse_certificate(LEAF_SIGNED).self_issued is False


def test_an_expired_certificate_is_read_and_not_refused():
    """An expiry in the past is a fact to report. Nothing here compares it with
    the clock, because a state that says expired is a judgement and the dates
    are the measurement."""
    read = prober.parse_certificate(EXPIRED)
    assert read.not_before == "2020-01-01T00:00:00+00:00"
    assert read.not_after == "2021-01-01T00:00:00+00:00"
    assert read.subject == "CN=expired.test"


def test_the_certificate_carries_no_field_that_reads_as_a_verdict():
    """The writing rules. A certificate is exactly where somebody would write
    valid, and this is the test that stops it arriving later."""
    fields = {field.name for field in prober.dataclasses.fields(prober.Certificate)}
    for word in ("valid", "trusted", "safe", "secure", "verified", "ok",
                 "grade", "score", "expired"):
        assert not any(word in field for field in fields), (
            f"{word} appears in a certificate field name")


def test_the_fingerprint_is_the_sha256_of_exactly_what_was_presented():
    import hashlib
    read = prober.parse_certificate(LEAF_SIGNED)
    assert read.fingerprint_sha256 == hashlib.sha256(LEAF_SIGNED).hexdigest()


def test_a_certificate_with_no_subject_alternative_name_has_no_names():
    assert prober.parse_certificate(certificate()).names == ()


def test_only_dns_and_ip_names_are_taken_from_the_alternative_name():
    """An email address or a URI in there is not a thing a port answers on, so
    it is left rather than half read."""
    der = certificate(extensions=san_extension(
        ("dns", "a.test"), (0x81, b"someone@example.test"),
        ("ip", "198.51.100.7"), (0x86, b"https://example.test/")))
    assert prober.parse_certificate(der).names == ("a.test", "198.51.100.7")


def test_an_ip_in_the_alternative_name_that_is_not_four_or_sixteen_bytes_is_left():
    der = certificate(extensions=san_extension((0x87, b"\x01\x02\x03")))
    assert prober.parse_certificate(der).names == ()


def test_a_generalized_time_is_read_as_well_as_a_utc_time():
    der = certificate(not_before=b"20260101000000Z", not_after=b"20991231235959Z",
                      time_tag=0x18)
    read = prober.parse_certificate(der)
    assert read.not_before == "2026-01-01T00:00:00+00:00"
    assert read.not_after == "2099-12-31T23:59:59+00:00"


def test_a_two_digit_year_follows_the_rule_rfc_5280_gives():
    """RFC 5280 4.1.2.5.1: 00 to 49 is 20xx and 50 to 99 is 19xx. Without this
    a certificate from 1998 would be filed under 2098."""
    old = prober.parse_certificate(certificate(not_before=b"980101000000Z",
                                               not_after=b"490101000000Z"))
    assert old.not_before.startswith("1998-")
    assert old.not_after.startswith("2049-")


@pytest.mark.parametrize("bad", [b"", b"nonsense", b"2601010000Z",
                                 b"261301000000Z", b"260132000000Z",
                                 b"260101250000Z", b"260101000000+0100"])
def test_a_time_field_that_is_not_a_time_leaves_the_date_empty(bad):
    """The rest of the certificate is still worth reading, so an unreadable date
    is None rather than an exception that loses the subject as well."""
    read = prober.parse_certificate(certificate(not_after=bad))
    assert read.not_after is None
    assert read.not_before == "2026-01-01T00:00:00+00:00"
    assert read.subject == "CN=subject.test"


# ---------------------------------------------------------- text from a stranger

def test_a_subject_that_tries_to_look_like_two_attributes_cannot():
    """The separator characters are escaped, so a common name of
    `x,O=Somebody Else` cannot read on a screen as an organisation the
    certificate never carried."""
    der = certificate(subject=name(attribute(CN, "x,O=Somebody Else")))
    assert prober.parse_certificate(der).subject == "CN=x\\,O\\=Somebody Else"


def test_control_characters_in_a_subject_do_not_survive():
    """A newline in a subject would break a log line in two and a right to left
    override would reverse what a person reads."""
    der = certificate(subject=name(attribute(CN, "a\nb\r\x00c‮d")))
    read = prober.parse_certificate(der).subject
    for ch in "\n\r\x00‮":
        assert ch not in read
    assert read.startswith("CN=a")


def test_a_very_long_subject_is_cut_to_the_bound():
    der = certificate(subject=name(attribute(CN, "x" * 4000)))
    read = prober.parse_certificate(der)
    assert len(read.subject) <= prober.MAX_CERTIFICATE_TEXT


def test_a_long_alternative_name_list_is_bounded():
    der = certificate(extensions=san_extension(
        *[("dns", f"host{index}.test") for index in range(500)]))
    assert len(prober.parse_certificate(der).names) <= prober.MAX_CERTIFICATE_NAMES


def test_a_name_that_is_not_valid_utf8_is_read_rather_than_thrown_away():
    """A stranger can put any bytes in a UTF8String. The read must not fail, and
    what comes out must be text this codebase can store and print."""
    broken = element(0x31, element(0x30, oid_bytes(CN)
                                   + element(0x0C, b"caf\xff\xfe")))
    read = prober.parse_certificate(certificate(subject=element(0x30, broken)))
    assert read.subject.startswith("CN=caf")
    assert read.subject.isprintable()


def test_an_attribute_this_module_has_no_short_name_for_keeps_its_number():
    der = certificate(subject=name(attribute("1.3.6.1.4.1.99999.1", "x")))
    assert prober.parse_certificate(der).subject == "1.3.6.1.4.1.99999.1=x"


def test_an_attribute_whose_value_is_not_text_is_left_out():
    odd = element(0x31, element(0x30, oid_bytes(CN) + element(0x01, b"\xff")))
    der = certificate(subject=element(0x30, odd + attribute(ORG, "Kept")))
    assert prober.parse_certificate(der).subject == "O=Kept"


def test_the_short_names_are_the_ones_a_sysadmin_reads():
    der = certificate(subject=name(attribute(COUNTRY, "BE", tag=0x13),
                                   attribute(ORG, "Org"),
                                   attribute(CN, "host.test")))
    assert prober.parse_certificate(der).subject == "C=BE,O=Org,CN=host.test"


@pytest.mark.parametrize("tag", [0x13, 0x16, 0x14, 0x1E, 0x1C, 0x0C])
def test_every_string_type_a_name_may_use_is_read(tag):
    der = certificate(subject=name(attribute(CN, "host.test", tag=tag)))
    assert prober.parse_certificate(der).subject == "CN=host.test"


# ------------------------------------------------------------ malformed input

@pytest.mark.parametrize("der,why", [
    (b"", "nothing at all"),
    (b"\x30", "a tag and no length"),
    (b"\x30\x82", "a long length that is itself truncated"),
    (b"\x30\x0a\x30\x08", "a length that runs past the end"),
    (b"\x30\x80\x30\x00\x00\x00", "an indefinite length, which is BER not DER"),
    (b"\x30\x85\x01\x01\x01\x01\x01" + b"x" * 40, "a five byte length"),
    (b"\x02\x01\x01", "an integer where a certificate should be"),
    (b"\x30\x03\x02\x01\x01", "a sequence holding no certificate body"),
    (b"\xff" * 200, "bytes that are nothing"),
])
def test_something_that_is_not_a_certificate_is_refused_by_name(der, why):
    """Every one of these has to raise the module's own error, because a parse
    failure that arrives as any other exception would be classified as an
    unknown failure and read as a network problem."""
    with pytest.raises(prober.CertificateUnreadable):
        prober.parse_certificate(der)


def test_a_certificate_cut_short_at_every_length_is_refused_and_never_hangs():
    """Truncation is the shape a parser loops forever on. Every prefix of a real
    certificate is fed in, and each one either reads or raises our own error."""
    for cut in range(1, len(LEAF_SIGNED)):
        try:
            prober.parse_certificate(LEAF_SIGNED[:cut])
        except prober.CertificateUnreadable:
            continue


def test_a_certificate_larger_than_the_bound_is_refused_although_it_would_read():
    """The bound has to be tested with a certificate that is only too big.

    The first version of this test used bytes that were not a certificate at
    all, so deleting the bound left it green: it was asserting the exception
    and not the thing that caused it. That is `docs/RECORD.md` 4.46 in a new
    place, and it was found by deleting the bound on purpose.
    """
    over = certificate(subject=name(attribute(CN, "big.test")),
                       extensions=san_extension(("dns", "a.test")),
                       serial=b"\x01" * (prober.MAX_CERTIFICATE_BYTES + 1))
    assert len(over) > prober.MAX_CERTIFICATE_BYTES
    with pytest.raises(prober.CertificateUnreadable):
        prober.parse_certificate(over)
    # The same certificate under the bound reads, so what was refused above was
    # the size and nothing else.
    under = certificate(subject=name(attribute(CN, "big.test")),
                        extensions=san_extension(("dns", "a.test")))
    assert prober.parse_certificate(under).subject == "CN=big.test"


def test_deeply_nested_data_does_not_run_away():
    """A thousand nested sequences is a shape a recursive parser dies on. This
    one walks a fixed number of levels, so it either reads the fields or says
    the bytes are not a certificate."""
    payload = element(0x30, b"")
    for _ in range(400):
        payload = element(0x30, payload)
    with pytest.raises(prober.CertificateUnreadable):
        prober.parse_certificate(payload)


def test_a_certificate_with_no_version_field_still_reads():
    """Version is optional and a v1 certificate leaves it out entirely. Reading
    the serial as if it were the version would shift every field by one."""
    read = prober.parse_certificate(certificate(version=False, serial=b"\x07"))
    assert read.serial == "07"
    assert read.subject == "CN=subject.test"


def test_a_serial_a_stranger_made_enormous_is_bounded():
    read = prober.parse_certificate(certificate(serial=b"\x01" * 500))
    assert len(read.serial) <= prober.MAX_CERTIFICATE_TEXT


# ================================================== the context that never trusts

def test_the_reading_context_verifies_nothing_and_checks_no_hostname():
    """The one place in this codebase where verification is off. It is not a
    hole because nothing is sent and nothing is trusted: the handshake exists
    only so the certificate can be read, and an expired or self issued
    certificate is a fact we are here to report rather than an error."""
    context = prober._certificate_reading_context()
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False


def test_the_reading_context_offers_no_alpn_and_no_server_name():
    """Asking what protocols a server supports is version detection wearing a
    different hat. There is no way to read a context's ALPN list back, so the
    source is checked instead: the name never appears."""
    source = pathlib.Path(prober.__file__).read_text(encoding="utf-8")
    for forbidden in ("set_alpn_protocols", "set_npn_protocols",
                      "server_hostname", "set_ciphers", "minimum_version",
                      "maximum_version"):
        assert forbidden not in source, (
            f"{forbidden} is negotiation we do not do")


def test_the_reading_context_loads_no_certificate_authorities():
    """Nothing is compared against a trust store, so there is nothing in it."""
    context = prober._certificate_reading_context()
    assert context.get_ca_certs() == []


def test_two_reads_do_not_share_a_context():
    """A context caches sessions. Two reads that shared one could resume rather
    than handshake, and the second would report the first one's certificate."""
    assert prober._certificate_reading_context() is not \
        prober._certificate_reading_context()


# ==================================================== the engine, with the gate

@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    authz.init(connection)
    prober.init(connection)
    yield connection
    connection.close()


class FakeTlsRead:
    """Stands in for the handshake. `answers` maps a port to the DER it
    presents, or to an exception it raises."""

    def __init__(self, answers=None, default=LEAF_SIGNED):
        self.answers = answers or {}
        self.default = default
        self.calls = []

    async def __call__(self, target, family, port, timeout):
        self.calls.append((target, family, port))
        answer = self.answers.get(port, self.default)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    @property
    def ports(self):
        return [port for _target, _family, port in self.calls]


class RefusingTlsRead:
    """A handshake that must never happen."""

    def __init__(self):
        self.calls = []

    async def __call__(self, target, family, port, timeout):
        self.calls.append((target, family, port))
        raise AssertionError(
            f"a handshake was made with {target} port {port} ({family}) and the"
            " test exists because it must not be")


def probe_tls(con, addresses, ports, tls_ports, **kwargs):
    connect = kwargs.pop("connect", None) or FakeConnect()
    tls_read = kwargs.pop("tls_read", None) or FakeTlsRead()
    gate_clock = kwargs.pop("gate_clock", NOW)
    host_id = kwargs.pop("host_id", None)
    engine = prober.Prober(connect=connect, tls_read=tls_read, **kwargs)
    result = run(engine.run(con, addresses, ports, host_id=host_id,
                            gate_clock=gate_clock, tls_ports=tls_ports))
    return result, tls_read


def tls_rows(result, family=None):
    return [row for row in result.certificates
            if family is None or row.family == family]


def test_nothing_asks_for_a_certificate_unless_the_caller_named_the_port(con):
    """The default is no handshake at all. A TLS read is a second connection to
    the same port, so it happens where it was asked for and nowhere else."""
    authorise(con, V4)
    result, tls_read = probe_tls(con, [V4], [80, 443], tls_ports=(),
                                 tls_read=RefusingTlsRead())
    assert tls_read.calls == []
    assert result.certificates == ()


def test_a_named_port_that_connected_gets_exactly_one_certificate_row(con):
    authorise(con, V4)
    result, tls_read = probe_tls(con, [V4], [80, 443], tls_ports=[443])
    assert tls_read.calls == [(V4, "v4", 443)]
    rows = tls_rows(result, "v4")
    assert len(rows) == 1
    assert rows[0].port == 443
    assert rows[0].state == prober.TLS_STATE_READ
    assert rows[0].reason is None
    assert rows[0].certificate.subject == "C=BE,O=Example Org,CN=example.test"


def test_a_port_that_did_not_connect_is_never_handshaked_and_still_has_a_row(con):
    """The mutation this catches turns a failure into a silent absence. A port
    the caller asked about always has an answer, and here the answer says the
    connect is why there was no handshake."""
    authorise(con, V4)
    result, tls_read = probe_tls(
        con, [V4], [443], tls_ports=[443], tls_read=RefusingTlsRead(),
        connect=FakeConnect({443: ConnectionRefusedError(errno.ECONNREFUSED, "no")}))
    assert tls_read.calls == []
    rows = tls_rows(result, "v4")
    assert len(rows) == 1
    assert rows[0].state == prober.TLS_STATE_NOT_READ
    assert rows[0].reason == prober.REASON_TLS_NO_CONNECT
    assert rows[0].certificate is None


def test_a_family_with_no_address_still_answers_for_the_named_port(con):
    authorise(con, V4)
    result, _ = probe_tls(con, [V4], [443], tls_ports=[443])
    v6 = tls_rows(result, "v6")
    assert len(v6) == 1
    assert v6[0].state == prober.TLS_STATE_NOT_READ
    assert v6[0].reason == prober.REASON_TLS_NO_CONNECT
    assert v6[0].target is None


def test_an_unauthorised_target_is_never_handshaked(con):
    """SI-6 reaches the second connection too. Without this the TLS read would
    be a second path to a packet that the gate never saw."""
    result, tls_read = probe_tls(con, [V4], [443], tls_ports=[443],
                                 connect=RefusingConnect(),
                                 tls_read=RefusingTlsRead())
    assert tls_read.calls == []
    for row in tls_rows(result, "v4"):
        assert row.state == prober.TLS_STATE_NOT_READ


def test_the_gate_is_asked_again_immediately_before_the_handshake(con):
    """The connect succeeded, and then the authorisation went away between the
    connect and the handshake. No handshake may happen, and the row says the
    authorisation is why.

    Run against a version that trusts the connect's own gate answer, this fails
    with a handshake against a revoked address.
    """
    authorise(con, V4)

    async def revoke_after_connecting(target, family, port):
        authz.revoke(con, V4, now=NOW)
        return 0.001

    result, tls_read = probe_tls(con, [V4], [443], tls_ports=[443],
                                 connect=revoke_after_connecting,
                                 tls_read=RefusingTlsRead())
    assert tls_read.calls == []
    row = tls_rows(result, "v4")[0]
    assert row.state == prober.TLS_STATE_NOT_READ
    assert row.reason == prober.REASON_NO_AUTHORIZATION
    assert row.certificate is None


def test_a_handshake_that_failed_is_a_typed_reason_and_not_an_absence(con):
    """Everything a handshake can fail with lands on one closed reason. The far
    side's own words never come with it, which is SI-8."""
    authorise(con, V4)
    failure = ssl.SSLError(1, "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] the peer said no")
    result, _ = probe_tls(con, [V4], [443], tls_ports=[443],
                          tls_read=FakeTlsRead({443: failure}))
    row = tls_rows(result, "v4")[0]
    assert row.state == prober.TLS_STATE_NOT_READ
    assert row.reason == prober.REASON_TLS_HANDSHAKE_FAILED
    assert row.certificate is None


def test_no_reason_anywhere_carries_the_far_sides_own_text(con):
    """SI-8 asserted over every reason the TLS half can produce, because a free
    text field is the one that gets added without anybody noticing."""
    authorise(con, V4)
    shouty = ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER] wrong version number")
    for failure in (shouty, os_error("ECONNRESET"), TimeoutError(),
                    ValueError("a bug in the primitive")):
        result, _ = probe_tls(con, [V4], [443], tls_ports=[443],
                              tls_read=FakeTlsRead({443: failure}))
        row = tls_rows(result, "v4")[0]
        assert row.reason in prober.TLS_REASONS
        assert "SSL" not in (row.reason or "")


def test_a_peer_that_presents_no_certificate_says_so(con):
    """A handshake can complete with no certificate at all. That is a fact about
    the peer and it is not an error, and it is certainly not a certificate."""
    authorise(con, V4)
    result, _ = probe_tls(con, [V4], [443], tls_ports=[443],
                          tls_read=FakeTlsRead({443: b""}))
    row = tls_rows(result, "v4")[0]
    assert row.state == prober.TLS_STATE_NOT_READ
    assert row.reason == prober.REASON_TLS_NO_CERTIFICATE
    assert row.certificate is None


def test_bytes_that_are_not_a_certificate_are_reported_as_such(con):
    authorise(con, V4)
    result, _ = probe_tls(con, [V4], [443], tls_ports=[443],
                          tls_read=FakeTlsRead({443: b"\xff" * 64}))
    row = tls_rows(result, "v4")[0]
    assert row.state == prober.TLS_STATE_NOT_READ
    assert row.reason == prober.REASON_TLS_CERTIFICATE_UNREADABLE


def test_a_connect_level_failure_during_the_second_connection_is_classified(con):
    """The handshake needs its own TCP connection, and that connection can fail
    the same ways the first one can. Those keep the connect engine's own typed
    reasons rather than being folded into one TLS reason."""
    authorise(con, V4)
    result, _ = probe_tls(con, [V4], [443], tls_ports=[443],
                          tls_read=FakeTlsRead({443: os_error("EHOSTUNREACH")}))
    row = tls_rows(result, "v4")[0]
    assert row.state == prober.TLS_STATE_NOT_READ
    assert row.reason == prober.REASON_HOST_UNREACHABLE


def test_every_certificate_row_pairs_its_state_with_its_reason(con):
    """The one invariant that cannot be broken quietly: a row that read a
    certificate carries no reason, and a row that did not always carries one."""
    authorise(con, V4)
    result, _ = probe_tls(
        con, [V4, OTHER_V4], [443, 80, 0], tls_ports=[443, 80, 0],
        tls_read=FakeTlsRead({80: ssl.SSLError(1, "no"), 0: b""}))
    assert result.certificates
    for row in result.certificates:
        if row.state == prober.TLS_STATE_READ:
            assert row.reason is None
            assert row.certificate is not None
        else:
            assert row.state == prober.TLS_STATE_NOT_READ
            assert row.reason in prober.TLS_REASONS
            assert row.certificate is None


def test_a_named_port_that_is_not_a_port_is_never_handshaked(con):
    authorise(con, V4)
    result, tls_read = probe_tls(con, [V4], [70000, "x"], tls_ports=[70000, "x"],
                                 tls_read=RefusingTlsRead())
    assert tls_read.calls == []
    assert all(row.state == prober.TLS_STATE_NOT_READ
               for row in result.certificates)


def test_the_handshake_is_paced_by_the_same_bucket_as_the_connect(con):
    """A TLS read is a second connection to the host, so it takes a token from
    the host's own bucket. Without this a host with a TLS port would see twice
    the connections a second `docs/PRODUCT.md` section 5 allows."""
    from tests.test_prober import FakeTime
    authorise(con, V4)
    clock = FakeTime()
    ports = list(range(1, 41))
    engine = prober.Prober(connect=FakeConnect(), tls_read=FakeTlsRead(),
                           clock=clock.monotonic, sleep=clock.sleep,
                           rate_per_second=40.0)
    run(engine.run(con, [V4], ports, gate_clock=NOW, tls_ports=ports))
    # 40 connects plus 40 handshakes is 80 connections, and the bucket allows a
    # burst of 40 and then one every 25 ms.
    assert clock.now >= (80 - 40) / 40.0


def test_a_certificate_read_is_a_second_connection_and_the_docstring_says_so():
    """The packet arithmetic is a fact about this module, so it lives in the
    module rather than only in a pull request nobody reads again."""
    assert "second connection" in prober.__doc__


# ================================================================== storage

def test_a_certificate_is_stored_with_the_run_that_read_it(con):
    host_id = authorise(con, V4)
    result, _ = probe_tls(con, [V4], [443], tls_ports=[443], host_id=host_id)
    rows = prober.run_certificates(con, result.id)
    assert len(rows) == len(result.certificates)
    read = [row for row in rows if row["state"] == prober.TLS_STATE_READ]
    assert len(read) == 1
    assert read[0]["subject"] == "C=BE,O=Example Org,CN=example.test"
    assert read[0]["issuer"] == "C=BE,O=Whichports Test CA,CN=Whichports Test Root"
    assert read[0]["not_after"] == "2027-01-01T00:00:00+00:00"
    assert read[0]["self_issued"] == 0
    assert read[0]["names"] == "example.test www.example.test 192.0.2.10 2001:db8::1"
    assert read[0]["port"] == 443
    assert read[0]["read_at"]


def test_a_row_that_read_nothing_is_stored_with_its_reason_and_no_fields(con):
    authorise(con, V4)
    result, _ = probe_tls(con, [V4], [443], tls_ports=[443],
                          tls_read=FakeTlsRead({443: ssl.SSLError(1, "no")}))
    rows = prober.run_certificates(con, result.id)
    for row in rows:
        assert row["state"] == prober.TLS_STATE_NOT_READ
        assert row["reason"] in prober.TLS_REASONS
        assert row["subject"] is None
        assert row["not_after"] is None
        assert row["self_issued"] is None


def test_a_run_that_dies_during_a_handshake_stores_no_certificates(con):
    """The same rule the connect half has: a run that did not finish is visibly
    unfinished rather than a short list of findings."""
    authorise(con, V4)

    async def dies(target, family, port, timeout):
        raise KeyboardInterrupt("the operator pressed ctrl-c")

    with pytest.raises(KeyboardInterrupt):
        probe_tls(con, [V4], [443], tls_ports=[443], tls_read=dies)
    row = con.execute("SELECT * FROM probe_runs ORDER BY id DESC LIMIT 1").fetchone()
    assert row["finished_at"] is None
    assert prober.run_certificates(con, row["id"]) == []
    assert prober.run_results(con, row["id"]) == []


def test_the_stored_text_is_bounded_however_long_the_peers_text_was(con):
    authorise(con, V4)
    huge = certificate(subject=name(attribute(CN, "x" * 5000)),
                       extensions=san_extension(
                           *[("dns", f"h{index}.test") for index in range(400)]))
    result, _ = probe_tls(con, [V4], [443], tls_ports=[443],
                          tls_read=FakeTlsRead({443: huge}))
    row = [r for r in prober.run_certificates(con, result.id)
           if r["state"] == prober.TLS_STATE_READ][0]
    assert len(row["subject"]) <= prober.MAX_CERTIFICATE_TEXT
    assert len(row["names"].split()) <= prober.MAX_CERTIFICATE_NAMES


def test_certificate_init_is_idempotent(con):
    prober.init(con)
    prober.init(con)
    authorise(con, V4)
    result, _ = probe_tls(con, [V4], [443], tls_ports=[443])
    assert prober.run_certificates(con, result.id)


# ================================================== SI-7 as a structural fact

# `tests/test_prober.py` bans every name that would transfer a byte anywhere in
# the prober. Two functions are allowed to name TLS, and only TLS: the context
# builder and the one blocking read. This is the other half of that guard, and
# it is tighter rather than looser, because inside those two functions the byte
# transfer names are still banned and only three TLS names are allowed.

TLS_ALLOWED_NAMES = {"ssl", "SSLContext", "wrap_socket", "getpeercert"}


def test_the_tls_functions_transfer_no_bytes():
    from tests.test_prober import BANNED_NAMES
    source = pathlib.Path(prober.__file__)
    for function in prober_tls_function_names():
        names = _names_in_function(source, function)
        offending = names & (BANNED_NAMES - TLS_ALLOWED_NAMES)
        assert offending == set(), (
            f"{function} names {sorted(offending)}, which is beyond a handshake")


def prober_tls_function_names():
    from tests.test_prober import TLS_FUNCTIONS
    return sorted(TLS_FUNCTIONS)


def _names_in_function(path, function_name):
    """Every identifier inside one function, so a guard can be applied to one
    part of a file rather than to all of it."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == function_name:
            names = set()
            for inner in ast.walk(node):
                if isinstance(inner, ast.Attribute):
                    names.add(inner.attr)
                elif isinstance(inner, ast.Name):
                    names.add(inner.id)
            return names
    raise AssertionError(f"{function_name} is not in {path.name} any more")


def test_the_two_scans_between_them_cover_every_name_in_the_prober():
    """The seam between the two guards, which is where a name would hide.

    The file-wide scan skips the TLS functions whole, annotations and default
    arguments included, and this asserts the per-function scan picks up exactly
    what it dropped. A name in neither scan would be a name nothing checks.
    """
    from tests.test_prober import TLS_FUNCTIONS, _names_in
    source = pathlib.Path(prober.__file__)
    everything, _skipped = _names_in(source)
    scoped, skipped = _names_in(source, skip=TLS_FUNCTIONS)
    assert skipped == TLS_FUNCTIONS
    covered = set(scoped)
    for function in TLS_FUNCTIONS:
        covered |= _names_in_function(source, function)
    assert everything - covered == set(), (
        f"{sorted(everything - covered)} is in neither scan")


def test_the_function_scan_finds_something_to_scan():
    """The canary. A scan that has stopped seeing its function passes forever,
    which is `docs/RECORD.md` 4.46 exactly."""
    source = pathlib.Path(prober.__file__)
    names = _names_in_function(source, "_read_certificate_der")
    assert "wrap_socket" in names
    assert "getpeercert" in names


def test_the_function_scan_would_catch_a_violation(tmp_path):
    offender = tmp_path / "offender.py"
    offender.write_text("def _read_certificate_der(s):\n"
                        "    s.sendall(b'GET / HTTP/1.0\\r\\n')\n"
                        "    return s.recv(64)\n", encoding="utf-8")
    from tests.test_prober import BANNED_NAMES
    names = _names_in_function(offender, "_read_certificate_der")
    assert names & (BANNED_NAMES - TLS_ALLOWED_NAMES) == {"sendall", "recv"}


def test_the_prober_never_verifies_a_certificate_against_a_trust_store():
    """`load_default_certs`, `load_verify_locations` and `CERT_REQUIRED` are the
    three ways this would arrive, and none of them belongs here. We report what
    was presented and we say nothing about whether anybody should trust it."""
    source = pathlib.Path(prober.__file__).read_text(encoding="utf-8")
    for forbidden in ("load_default_certs", "load_verify_locations",
                      "CERT_REQUIRED", "CERT_OPTIONAL", "create_default_context",
                      "match_hostname"):
        assert forbidden not in source, f"{forbidden} would be verification"


def test_no_word_in_the_tls_vocabulary_is_a_verdict():
    """The writing rules, over the states and the four reasons this half adds.

    The connect engine's own reasons are covered by its own suite and are not
    re-checked here: `timeout_expired` is our clock giving up and reads as a
    verdict only to a substring match.
    """
    added = prober.TLS_REASONS - prober.REASONS
    assert len(added) == 4, "a reason was added or removed without this noticing"
    for word in prober.TLS_STATES + tuple(added):
        for banned in ("valid", "trusted", "secure", "safe", "compliant",
                       "expired", "good", "bad", "grade", "score"):
            assert banned not in word, f"{word} is a verdict"


# ======================================= a real handshake, on loopback only

def openssl_missing():
    return shutil.which("openssl") is None


def announce_no_openssl() -> str:
    """Loud, the way `tests/test_prober.py` is loud about a missing IPv6. A
    handshake half that quietly did not run is the whole point of this file."""
    message = ("THE REAL HANDSHAKE TESTS DID NOT RUN: openssl is not on this"
               " machine, so no key material could be made for a loopback TLS"
               " server. Nothing below measured an actual handshake.")
    warnings.warn(message, stacklevel=2)
    print(f"\n{'!' * 72}\n{message}\n{'!' * 72}", file=sys.stderr)
    return message


def test_the_missing_openssl_skip_is_loud(recwarn, capsys):
    message = announce_no_openssl()
    assert [str(w.message) for w in recwarn] == [message]
    assert "!" * 72 in capsys.readouterr().err


def server_key_and_certificate(tmp_path):
    """A throwaway key and a self issued certificate, made on the spot rather
    than committed. A private key does not belong in a repository even when it
    is only ever bound to 127.0.0.1."""
    if openssl_missing():
        pytest.skip(announce_no_openssl())
    key = tmp_path / "server.key"
    cert = tmp_path / "server.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec",
         "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", "/O=Loopback Test/CN=loopback.test",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True)
    return key, cert


class LoopbackTlsServer:
    """A TLS server on 127.0.0.1 that records what it was sent after the
    handshake. One connection, then it stops."""

    def __init__(self, key, cert, maximum_version=None):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if maximum_version is not None:
            context.minimum_version = maximum_version
            context.maximum_version = maximum_version
        context.load_cert_chain(str(cert), str(key))
        self.context = context
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.received = None
        self.server_name = "not asked"
        self.failed = None
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            self.sock.settimeout(10.0)
            raw, _peer = self.sock.accept()
            raw.settimeout(10.0)
            try:
                tls = self.context.wrap_socket(raw, server_side=True)
            except OSError as exc:
                self.failed = exc
                raw.close()
                return
            self.server_name = tls.server_hostname
            try:
                self.received = tls.recv(4096)
            except OSError as exc:
                self.failed = exc
            finally:
                tls.close()
        except OSError as exc:
            self.failed = exc

    def close(self):
        self.thread.join(timeout=10.0)
        self.sock.close()


def test_a_real_handshake_reads_the_certificate_the_server_presented(tmp_path):
    """The whole feature, end to end, against a socket. The certificate is self
    issued and would fail any verification, and reading it anyway is exactly
    what this is for."""
    key, cert = server_key_and_certificate(tmp_path)
    server = LoopbackTlsServer(key, cert)
    try:
        der = run(prober.tls_certificate("127.0.0.1", "v4", server.port, 10.0))
    finally:
        server.close()
    assert server.failed is None, f"the server side failed: {server.failed}"
    read = prober.parse_certificate(der)
    assert read.subject == "O=Loopback Test,CN=loopback.test"
    assert read.self_issued is True
    assert read.names == ("127.0.0.1",)


def test_a_real_handshake_sends_no_application_byte(tmp_path):
    """SI-7 measured from the other end of the wire. The server reads until EOF
    after the handshake and must see nothing at all."""
    key, cert = server_key_and_certificate(tmp_path)
    server = LoopbackTlsServer(key, cert)
    try:
        run(prober.tls_certificate("127.0.0.1", "v4", server.port, 10.0))
    finally:
        server.close()
    assert server.received == b"", (
        f"the prober sent {server.received!r} after the handshake")


@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1_2,
                                     ssl.TLSVersion.TLSv1_3])
def test_the_connection_ends_without_resetting_the_other_end(tmp_path, version):
    """We hang up, we do not slam the phone down.

    This pins a bug that was live and invisible. `_read_certificate_der` used
    to close abruptly, on the reasoning that a close alert costs bytes. In
    TLS 1.3 the server sends session tickets after the handshake, we never read
    them, and closing a socket with unread data in its receive queue sends a
    TCP reset instead of a FIN. On CPython 3.14, which is what the vantage host
    runs, that happened on every TLS 1.3 connection, so every host we touched
    would log an error rather than a client hanging up.

    The version is pinned explicitly rather than left to the default, because
    the whole failure lived in one version and a moving default would take this
    coverage away without anyone noticing.
    """
    key, cert = server_key_and_certificate(tmp_path)
    server = LoopbackTlsServer(key, cert, maximum_version=version)
    try:
        der = run(prober.tls_certificate("127.0.0.1", "v4", server.port, 10.0))
    finally:
        server.close()
    assert der, "the certificate should still be read"
    assert server.failed is None, (
        f"the other end saw {server.failed!r} rather than a clean close")
    # And the reason SI-7 is not weakened by saying goodbye: a close alert is
    # not application data, so the server still receives nothing at all.
    assert server.received == b""


def test_a_real_handshake_sends_no_server_name(tmp_path):
    """No SNI, because we probe an address and an address is not a name. It is
    a real limitation and it is stated rather than hidden: a server holding
    several certificates presents its default one to us."""
    key, cert = server_key_and_certificate(tmp_path)
    server = LoopbackTlsServer(key, cert)
    try:
        run(prober.tls_certificate("127.0.0.1", "v4", server.port, 10.0))
    finally:
        server.close()
    assert server.server_name is None


def test_a_real_handshake_against_a_port_that_speaks_no_tls_fails_cleanly():
    """A plain TCP listener that never answers the ClientHello. The read has to
    end by itself, and the failure has to be one this module classifies."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        with pytest.raises(Exception) as caught:
            run(prober.tls_certificate("127.0.0.1", "v4", port, 0.5))
    finally:
        listener.close()
    state, reason = prober.classify_tls(caught.value)
    assert state == prober.TLS_STATE_NOT_READ
    assert reason in prober.TLS_REASONS


def test_a_real_handshake_against_a_closed_port_is_classified_as_the_connect_was():
    from tests.test_prober import closed_loopback_port
    port = closed_loopback_port(socket.AF_INET)
    with pytest.raises(OSError) as caught:
        run(prober.tls_certificate("127.0.0.1", "v4", port, 1.0))
    assert caught.value.errno == errno.ECONNREFUSED
    state, reason = prober.classify_tls(caught.value)
    assert state == prober.TLS_STATE_NOT_READ


def test_the_real_primitive_refuses_a_target_that_is_not_a_literal_address():
    """The same guard the connect primitive has, because a name would be
    resolved and a packet could leave for an address the gate never saw."""
    for target, family in (("localhost", "v4"), ("example.com", "v4"),
                           ("127.0.0.1", "v6"), ("::1", "v4"), (None, "v4")):
        with pytest.raises(prober.TargetMismatch):
            run(prober.tls_certificate(target, family, 9, 1.0))


def test_a_real_read_reaches_no_resolver(monkeypatch, tmp_path):
    key, cert = server_key_and_certificate(tmp_path)
    server = LoopbackTlsServer(key, cert)

    def refuse(*args, **kwargs):
        raise AssertionError("the certificate read resolved something")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    try:
        der = run(prober.tls_certificate("127.0.0.1", "v4", server.port, 10.0))
    finally:
        server.close()
    assert der


def test_the_read_gives_up_rather_than_waiting_forever():
    """A port that accepts and then says nothing. Without a timeout the read
    would hold a slot until something else broke."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    held = []

    def accept_and_say_nothing():
        try:
            accepted, _peer = listener.accept()
            held.append(accepted)
        except OSError:
            pass

    thread = threading.Thread(target=accept_and_say_nothing, daemon=True)
    thread.start()
    started = dt.datetime.now()
    try:
        with pytest.raises(Exception):
            run(prober.tls_certificate("127.0.0.1", "v4", port, 0.5))
    finally:
        thread.join(timeout=5.0)
        for sock in held:
            sock.close()
        listener.close()
    assert (dt.datetime.now() - started).total_seconds() < 5.0


def test_the_engine_and_a_real_server_agree(con, tmp_path):
    """One run, with the real primitive, against a real TLS server on
    127.0.0.1. The gate refuses loopback and is right to, so the gate is
    handed a stand-in that allows it and everything else is production code."""
    key, cert = server_key_and_certificate(tmp_path)
    server = LoopbackTlsServer(key, cert)
    try:
        der = run(prober.tls_certificate("127.0.0.1", "v4", server.port, 10.0))
    finally:
        server.close()
    read = prober.parse_certificate(der)
    assert read.not_after is not None
    assert read.fingerprint_sha256 == prober.parse_certificate(der).fingerprint_sha256
