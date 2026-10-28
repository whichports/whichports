"""A DNS TXT lookup, small enough to read in one sitting.

Why this exists rather than a dependency: the control plane is the
internet-facing half of the product and this project puts the
standard library first. Python's standard library resolves names to addresses
and nothing else, so a TXT lookup has to be either written or installed. This
is the written version, and it answers exactly one question: what TXT strings
does this name hold.

`app/authz.py` is the only caller. It uses this to read a token the operator
published at the reverse-DNS name of an address they are proving they control.

What this deliberately does not do:

  - **No TCP fallback.** A truncated answer is a refusal. The record we ask
    for is one short token, so truncation means the name holds something other
    than what we asked for and guessing is worse than saying no.
  - **No caching and no retries beyond the configured resolvers.** One
    question, one datagram, one answer.
  - **No CNAME chasing.** A resolver already returns the final answer for a
    TXT query. Following a chain ourselves would be trusting a second name
    nobody checked.

Every read is bounded against the length of the datagram. The bytes come from
the network, so a malformed answer has to be a refusal rather than an
exception in a caller that was not expecting one. `DnsError` is the only thing
this module raises.
"""

import ipaddress
import secrets
import socket
import struct

RESOLV_CONF = "/etc/resolv.conf"

# One UDP datagram. Larger than any answer we care about and small enough that
# a hostile resolver cannot make us buffer anything interesting.
MAX_RESPONSE_BYTES = 4096

DEFAULT_TIMEOUT_SECONDS = 5.0

# At most three resolvers tried, which is what resolv.conf itself supports.
MAX_RESOLVERS = 3

TYPE_TXT = 16
CLASS_IN = 1

RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3


class DnsError(Exception):
    """A question that could not be answered. Never a "maybe"."""


def encode_name(name: str) -> bytes:
    """The wire form of a domain name: each label length-prefixed, then a
    zero byte. Limits are RFC 1035's, checked here so a bad name is a refusal
    before anything reaches a socket."""
    stripped = name.rstrip(".")
    if not stripped:
        raise DnsError("empty name")
    encoded = b""
    for label in stripped.split("."):
        try:
            raw = label.encode("ascii")
        except UnicodeEncodeError:
            raise DnsError("name is not ASCII") from None
        if not raw or len(raw) > 63:
            raise DnsError("label is empty or longer than 63 bytes")
        encoded += bytes([len(raw)]) + raw
    encoded += b"\x00"
    if len(encoded) > 255:
        raise DnsError("name is longer than 255 bytes")
    return encoded


def build_query(name: str, query_id: int) -> bytes:
    """One standard query, recursion desired. The id is the caller's, so the
    caller can check the answer belongs to the question it asked."""
    header = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    return header + encode_name(name) + struct.pack(">HH", TYPE_TXT, CLASS_IN)


def _skip_name(data: bytes, offset: int) -> int:
    """Walk past a name and return the offset after it.

    A compression pointer is always the end of a name, so this never follows
    one. We only ever need to know where a name stops, and not following
    pointers means this cannot be walked in a circle by a hostile answer.
    """
    while True:
        if offset >= len(data):
            raise DnsError("answer ended inside a name")
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 2 > len(data):
                raise DnsError("answer ended inside a compression pointer")
            return offset + 2
        if length & 0xC0:
            raise DnsError("reserved label type in a name")
        offset += 1 + length


def _read_character_strings(rdata: bytes) -> str | None:
    """TXT rdata is a sequence of length-prefixed strings, and a reader is
    meant to join them. Returns None for a record that does not parse or is
    not ASCII, so one odd record at a name is skipped rather than taking the
    whole lookup down."""
    parts = []
    index = 0
    while index < len(rdata):
        length = rdata[index]
        index += 1
        if index + length > len(rdata):
            return None
        parts.append(rdata[index:index + length])
        index += length
    try:
        return b"".join(parts).decode("ascii")
    except UnicodeDecodeError:
        return None


def parse_response(data: bytes, query_id: int, name: str) -> list[str]:
    """The TXT strings in an answer, or an empty list if the name holds none.

    Raises DnsError for anything that is not a usable answer to the question
    we asked. A name that does not exist is not an error: it holds no token,
    which is a plain no.
    """
    if len(data) < 12:
        raise DnsError("answer is shorter than a DNS header")
    answer_id, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    if answer_id != query_id:
        raise DnsError("answer id did not match the question")
    if not flags & 0x8000:
        raise DnsError("answer is not a response")
    if flags & 0x0200:
        raise DnsError("answer was truncated")
    rcode = flags & 0x000F
    if rcode == RCODE_NXDOMAIN:
        return []
    if rcode != RCODE_NOERROR:
        raise DnsError(f"resolver answered rcode {rcode}")
    if qdcount != 1:
        raise DnsError("answer did not echo exactly one question")

    offset = _skip_name(data, 12)
    # The echoed question must be the one we asked. Names are case insensitive
    # on the wire, so this compares lowered.
    if data[12:offset].lower() != encode_name(name).lower():
        raise DnsError("answer echoed a different question")
    offset += 4
    if offset > len(data):
        raise DnsError("answer ended inside the question")

    strings = []
    for _ in range(ancount):
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            raise DnsError("answer ended inside a record header")
        rtype, rclass, _ttl, rdlength = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            raise DnsError("record ran past the end of the answer")
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if rtype != TYPE_TXT or rclass != CLASS_IN:
            continue
        text = _read_character_strings(rdata)
        if text is not None:
            strings.append(text)
    return strings


def system_resolvers(path: str = RESOLV_CONF) -> list[str]:
    """The nameserver lines from resolv.conf. A missing or unreadable file is
    an empty list, which the caller turns into a refusal."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError:
        return []
    servers = []
    for line in lines:
        parts = line.split()
        if len(parts) < 2 or parts[0] != "nameserver":
            continue
        try:
            ipaddress.ip_address(parts[1])
        except ValueError:
            continue
        servers.append(parts[1])
        if len(servers) == MAX_RESOLVERS:
            break
    return servers


def query_txt(name: str,
              servers: list[str] | None = None,
              timeout: float = DEFAULT_TIMEOUT_SECONDS) -> list[str]:
    """Ask the system resolvers for the TXT strings at `name`.

    The socket is connected rather than used with sendto/recvfrom, so the
    kernel drops any datagram that did not come back from the resolver we
    asked. That plus a random query id is the cheap defence against an
    off-path forgery, and it is the same defence a stub resolver has.
    """
    servers = servers if servers is not None else system_resolvers()
    if not servers:
        raise DnsError("no resolver is configured")
    last_error = None
    for server in servers:
        query_id = secrets.randbelow(65536)
        query = build_query(name, query_id)
        family = socket.AF_INET6 if ":" in server else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.connect((server, 53))
                sock.send(query)
                data = sock.recv(MAX_RESPONSE_BYTES)
            return parse_response(data, query_id, name)
        except (OSError, DnsError) as exc:
            last_error = exc
    raise DnsError(f"no resolver answered: {type(last_error).__name__}")
