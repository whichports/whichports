"""Ports that should rarely face the internet, each in its own documentation's
words.

A reachable port on this list gets a mark beside its state, whatever rule
allows it (`docs/RECORD.md` 4.197 and 4.221). **The list is a claim this
product makes**, so nothing is on it without a sentence from the service's own
documentation saying so, quoted word for word, with the page it stands on and
the day it was read there (`docs/RECORD.md` 4.248).

**It is keyed on protocol and port, never on what runs there.** A reachable
tcp/3306 may be anything, and nothing here says what is listening. An entry
says whose default port the number is, and that is all it claims about the
port.

**TCP only.** The mark sits on a port measured reachable from outside, and
nothing is measured from outside over UDP, so a UDP entry could never show.

**Left off on purpose**, so nobody adds them without a new sentence to stand
on:

- tcp/5432, PostgreSQL. Its documentation gives the default listen address as
  localhost and never says the port should not face the internet.
- tcp/2376, the Docker daemon over TLS. Docker's page names it as the secured
  way to reach the daemon, so a mark there would say more than the source.
- etcd and the kubelet. Each page says what an unsecured one exposes and
  neither says not to expose it.

To add an entry: read the sentence on the service's own page, copy it exactly,
and give the page and the date. `tests/test_rarelypublic.py` holds the exact
set of ports, so a new one is a deliberate change there too.
"""

import dataclasses
import datetime

MIN_PORT = 1
MAX_PORT = 65535


@dataclasses.dataclass(frozen=True)
class Entry:
    """One port that should rarely face the internet.

    `default_of` is whose default port this number is. `sentence` is the
    service's own documentation, word for word. `source` is the page the
    sentence stands on and `source_url` its address. `port_stated` is the
    words that give the port number, and `port_url` the page they stand on,
    which is often another page than the sentence's. `read_on` is the day
    both were read, as YYYY-MM-DD.

    An entry with any of these empty cannot be made: a port with no sentence
    behind it is exactly what this list must never hold.
    """
    protocol: str
    port: int
    default_of: str
    sentence: str
    source: str
    source_url: str
    port_stated: str
    port_url: str
    read_on: str

    def __post_init__(self):
        if self.protocol != "tcp":
            raise ValueError(f"only tcp is measured from outside, not {self.protocol!r}")
        if isinstance(self.port, bool) or not isinstance(self.port, int):
            raise ValueError("a port is a whole number")
        if not MIN_PORT <= self.port <= MAX_PORT:
            raise ValueError(f"port {self.port} is outside {MIN_PORT} to {MAX_PORT}")
        for name in ("default_of", "sentence", "source", "source_url",
                     "port_stated", "port_url", "read_on"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"tcp/{self.port} has no {name}, and an entry"
                                 " without its source is not an entry")
        for name in ("source_url", "port_url"):
            if not getattr(self, name).startswith("https://"):
                raise ValueError(f"tcp/{self.port}: {name} must be an https address")
        # Raises on anything that is not a real date.
        datetime.date.fromisoformat(self.read_on)


_READ = "2026-10-02"

_REDIS = dict(
    default_of="Redis",
    sentence=("This means that usually it is not a good idea to expose the Redis"
              " instance directly to the internet or, in general, to an environment"
              " where untrusted clients can directly access the Redis TCP port or"
              " UNIX socket."),
    source="Redis security, Security model",
    source_url="https://redis.io/docs/latest/operate/oss_and_stack/management/security/",
    port_stated="Accept connections on the specified port, default is 6379",
    port_url="https://raw.githubusercontent.com/redis/redis/unstable/redis.conf",
)

# The page sets two words of this sentence in emphasis, "must not". The words
# are the page's own and the emphasis marks are left out.
_MEMCACHED = dict(
    default_of="memcached",
    sentence=("So you must not expose memcached directly to the internet, or"
              " otherwise any untrusted users."),
    source="memcached wiki, ConfiguringServer, Networking",
    source_url="https://github.com/memcached/memcached/wiki/ConfiguringServer",
    port_stated="Listen on TCP port <num>, the default is port 11211.",
    port_url="https://raw.githubusercontent.com/memcached/memcached/master/doc/memcached.1",
)

_MONGODB_SENTENCE = ("Allow only trusted clients to access the network interfaces and"
                     " ports on which MongoDB instances are available.")
_MONGODB_SOURCE = "MongoDB Manual, Security Checklist, Limit Network Exposure"
_MONGODB_URL = "https://www.mongodb.com/docs/manual/administration/security-checklist/"
_MONGODB_PORTS_URL = "https://www.mongodb.com/docs/manual/reference/default-mongodb-port/"


def _mongodb(port: int, default_of: str, port_stated: str) -> "Entry":
    return Entry("tcp", port, default_of, _MONGODB_SENTENCE, _MONGODB_SOURCE,
                 _MONGODB_URL, port_stated, _MONGODB_PORTS_URL, _READ)


ENTRIES = (
    Entry("tcp", 445, "SMB",
          sentence=("Block TCP port 445 inbound from the internet at your corporate"
                    " hardware firewalls."),
          source="Microsoft Learn, Secure SMB Traffic in Windows Server, Block inbound SMB access",
          source_url=("https://learn.microsoft.com/en-us/windows-server/storage/"
                      "file-server/smb-secure-traffic"),
          port_stated="Block TCP port 445 inbound from the internet",
          port_url=("https://learn.microsoft.com/en-us/windows-server/storage/"
                    "file-server/smb-secure-traffic"),
          read_on=_READ),
    # Without TLS. The same page names 2376 as the port with TLS, which is
    # left off this list, see the module docstring.
    Entry("tcp", 2375, "the Docker daemon's API without TLS",
          sentence=("Configuring Docker to accept connections from remote clients can"
                    " leave you vulnerable to unauthorized access to the host and other"
                    " attacks."),
          source="Docker Docs, Configure remote access for Docker daemon",
          source_url="https://docs.docker.com/engine/daemon/remote-access/",
          port_stated=("The default port is 2376 if you're using TLS encrypted"
                       " transport, or 2375 otherwise."),
          port_url="https://docs.docker.com/engine/daemon/remote-access/",
          read_on=_READ),
    Entry("tcp", 3306, "MySQL",
          sentence=("MySQL uses port 3306 by default. This port should not be"
                    " accessible from untrusted hosts."),
          source="MySQL 8.4 Reference Manual, 8.1.1 Security Guidelines",
          source_url="https://dev.mysql.com/doc/refman/8.4/en/security-guidelines.html",
          port_stated="MySQL uses port 3306 by default.",
          port_url="https://dev.mysql.com/doc/refman/8.4/en/security-guidelines.html",
          read_on=_READ),
    Entry("tcp", 6379, read_on=_READ, **_REDIS),
    # The sentence is about a node without security switched on. The port is
    # the first of the default range, which a node takes when it is free.
    Entry("tcp", 9200, "Elasticsearch's HTTP interface",
          sentence="Never expose an unprotected node to the public internet.",
          source="Elasticsearch Guide 8.19, Networking",
          source_url=("https://www.elastic.co/guide/en/elasticsearch/reference/8.19/"
                      "modules-network.html"),
          port_stated="Defaults to 9200-9300.",
          port_url=("https://www.elastic.co/guide/en/elasticsearch/reference/8.19/"
                    "modules-network.html"),
          read_on=_READ),
    Entry("tcp", 11211, read_on=_READ, **_MEMCACHED),
    _mongodb(27017, "MongoDB", "Default port for mongod and mongos."),
    _mongodb(27018, "a MongoDB shard server",
             "Default port for mongod when using the --shardsvr command-line option"),
    _mongodb(27019, "a MongoDB config server",
             "Default port for mongod when using the --configsvr command-line option"),
)

_BY_PORT = {(entry.protocol, entry.port): entry for entry in ENTRIES}
if len(_BY_PORT) != len(ENTRIES):
    raise ValueError("a port is on the rarely-public list twice")


def lookup(protocol, port) -> Entry | None:
    """The entry for this protocol and port, or None when it is not on the
    list. Anything that is not a protocol word and a whole number is not on
    the list either, rather than an error: this is asked about every port a
    report or a probe names."""
    if isinstance(port, bool) or not isinstance(port, int) or not isinstance(protocol, str):
        return None
    return _BY_PORT.get((protocol.lower(), port))
