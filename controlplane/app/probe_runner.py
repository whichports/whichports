"""Run one batch of probes on a vantage host, with no database anywhere.

    python -m app.probe_runner < batch.json > results.json

**This is the only thing that runs on the prober box.** It reads a batch on
stdin, measures, and writes the measurement on stdout. It opens no database,
holds no credential, and takes no arguments that could name a target: every
address it will touch is in the batch, and every address it is allowed to touch
is in the snapshot inside that batch.

## Why it can be trusted with so little

The batch carries an authorisation snapshot that the control plane built by
asking the registry. `authz.SnapshotAuthority` answers the same question the
database answers on the control plane, and `prober.Prober.measure` asks it
before every single connect rather than once per batch. So this process cannot
probe anything the control plane did not already authorise, and it stops being
able to probe at all once the snapshot expires.

The modules it needs are the ones `VANTAGE_MODULES` names below and nothing
else, which is deliberate. **Nothing that touches the database has to be
present on the least trusted box in the estate.**

## What it does when something is wrong

It refuses and says so on stderr with a non-zero exit, and it writes nothing to
stdout. A batch that cannot be read is not an empty measurement: reporting
silence for ports nobody probed is `docs/PRODUCT.md` 4b happening inside the
product, and `docs/RECORD.md` 4.46 is about exactly that shape.

## When the ssh that started it goes away

It stops at once, whatever it is doing, and writes nothing more. The lock
that keeps one runner of ours on a target (`docs/PRODUCT.md` 5d) is held on
the control plane, and the runner is here. When the process holding the lock
dies, the lock is let go at once and sshd here ends with the connection, but
until 2026-10-28 the runner did not notice. Measured on a stand-in prober,
it was still probing 56 s after its ssh was killed, with 66 connects open,
while the next batch could start on the same target. So `watch_for_hangup`
watches stdout, the only way its answer can leave, and ends the process the
moment nobody can read it any more.
"""
import asyncio
import ipaddress
import json
import os
import select
import socket
import stat
import sys
import threading

from . import authz, prober

BATCH_VERSION = 1

# Every file that goes to a vantage host, this one included, and the whole of
# what may be there. It is one list on purpose: the deploy script reads it
# from this file as text, and `tests/test_prober_module_set.py` checks that
# nothing on it imports a module that is not on it. `workspace.py` is two
# constants `authz` needs and no imports. Adding a name here widens what runs
# on the box most likely to be taken, so it is a decision and not a fix.
VANTAGE_MODULES = ("prober.py", "authz.py", "ratelimit.py", "dnstxt.py",
                   "probe_runner.py", "workspace.py")

EXIT_OK = 0
EXIT_UNREADABLE = 2
# Nobody could read the answer any more. Nobody reads this code either, since
# the ssh that would carry it is gone. It is not 0, so that no caller could
# ever take a runner that stopped half way for a finished batch.
EXIT_CALLER_GONE = 3


class BatchUnreadable(ValueError):
    """The batch is not a batch. Distinct from a refusal to probe."""


def parse_batch(payload) -> dict:
    """Everything the runner needs, or an exception. Nothing defaults."""
    if not isinstance(payload, dict):
        raise BatchUnreadable("the batch is not an object")
    if payload.get("version") != BATCH_VERSION:
        raise BatchUnreadable(
            f"the batch is version {payload.get('version')!r} and this build"
            f" reads version {BATCH_VERSION}")

    vantage = payload.get("vantage")
    if not isinstance(vantage, str) or not vantage.strip():
        raise BatchUnreadable("the batch names no vantage")

    addresses = payload.get("addresses")
    if not isinstance(addresses, list) or not addresses:
        raise BatchUnreadable("the batch names no addresses")

    ports = payload.get("ports")
    if not isinstance(ports, list):
        raise BatchUnreadable("the batch has no ports list")

    tls_ports = payload.get("tls_ports", [])
    if not isinstance(tls_ports, list):
        raise BatchUnreadable("the batch has a tls_ports that is not a list")

    # Raises SnapshotUnreadable, which is deliberately not caught here. A batch
    # whose snapshot will not parse is unusable, and the caller turns that into
    # a refusal rather than an empty run.
    snapshot = authz.snapshot_from_json(payload.get("snapshot"))

    # **A vantage may not measure itself**, and this is why it is refused here
    # rather than written in a runbook.
    #
    # Measured on 2026-08-18: this box probed its own address and reported
    # `connect_refused` on three ports that an outside machine sees time out,
    # because traffic from a host to its own public address does not traverse
    # the firewall the way traffic from the internet does. The run looked
    # entirely healthy. Nothing in it said the answer came from the wrong path.
    #
    # The refusal lives in the runner because the runner is the only thing that
    # knows its own addresses without being told, so it stays correct when the
    # instance is rebuilt.
    mine = own_addresses()
    for address in addresses:
        try:
            canonical = str(ipaddress.ip_address(str(address).strip()))
        except (ValueError, TypeError):
            continue
        if canonical in mine:
            raise BatchUnreadable(
                f"{canonical} is an address of this vantage host, and a vantage"
                " cannot measure itself. Traffic to a machine's own address"
                " does not traverse its firewall the way traffic from the"
                " internet does, so any answer would be about the local stack")

    return {"vantage": vantage.strip(), "addresses": addresses, "ports": ports,
            "tls_ports": tls_ports, "snapshot": snapshot}


def own_addresses(lister=None) -> set:
    """Every address this machine answers on, as canonical text.

    Read here rather than configured, so it stays right when the instance is
    rebuilt and nobody remembers to update a file. `lister` is injected by the
    tests and by nothing else.
    """
    lister = lister or _interface_addresses
    found = set()
    for text in lister():
        try:
            found.add(str(ipaddress.ip_address(text.split("%")[0].strip())))
        except ValueError:
            continue
    return found


def _interface_addresses():
    """The real read. `socket.getaddrinfo` on the empty host name returns the
    addresses this machine has, which is enough without a netlink parser: the
    guard only has to recognise its own public address, and that is the one a
    batch could name."""
    out = []
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None, family):
                out.append(info[4][0])
        except socket.gaierror:
            continue
    try:
        # The address that reaches the outside world, which is the one a
        # control plane is most likely to hand back as a target. No packet is
        # sent: a connected UDP socket only fixes a route.
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("192.0.2.1", 9))
        out.append(probe.getsockname()[0])
        probe.close()
    except OSError:
        pass
    return out


def measure_batch(batch: dict, **injected) -> dict:
    """Measure one parsed batch and return the wire form of the result.

    `injected` reaches `prober.Prober`, and the only thing that passes anything
    is a test. **`main` never injects**, so the process a vantage host actually
    runs always holds the real primitive. This exists because the alternative
    is a test suite that opens real sockets to real strangers to prove the
    happy path, which is not a thing this repository is willing to do.

    **The clock is deliberately not injectable.** The gate is asked against the
    real clock, so a snapshot has to be genuinely current for anything to be
    probed. A batch built an hour ago measures nothing, here and in production
    alike, and a test that wants the happy path has to build a fresh snapshot
    exactly as the control plane will.
    """
    engine = prober.Prober(vantage=batch["vantage"], **injected)
    measured = asyncio.run(engine.measure(
        batch["snapshot"], batch["addresses"], batch["ports"],
        tls_ports=batch["tls_ports"]))
    return prober.run_to_json(measured)


def hangup_is_visible(fd: int) -> bool:
    """Whether the kernel says so, and says nothing else, once nobody can
    read `fd` any more.

    Measured on 2026-10-27 with Python 3.12, on Linux and on macOS:

      - **A pipe.** Linux answers POLLERR once its reader is gone, macOS
        POLLHUP, and both say nothing while the reader is there. sshd hands
        the runner pipes, read on a stand-in prober running Debian's OpenSSH.
      - **A socket**, which some builds of sshd use instead of pipes. Linux
        answers POLLHUP only once the other end has closed both ways, and
        nothing when it only stopped sending, which is what a caller does
        once the batch is sent. macOS answers POLLHUP for that too, so on
        macOS a watched socket would stop a healthy batch. It is watched on
        Linux only, where the probers run.
      - **Anything else**, a file or /dev/null, has no reader to lose.
    """
    mode = os.fstat(fd).st_mode
    if stat.S_ISFIFO(mode):
        return True
    return stat.S_ISSOCK(mode) and sys.platform.startswith("linux")


def watch_for_hangup(stream) -> bool:
    """End this process the moment nobody can read `stream`. True when the
    watch started.

    A thread of its own, so it sees the hangup whatever the measuring is
    doing: waiting for the pace, waiting on a target that does not answer, or
    reading a certificate in a worker thread that nothing can interrupt. It
    sleeps in the kernel until the hangup comes, so it costs the batch
    nothing and never touches the pace.
    """
    try:
        fd = stream.fileno()
    except (AttributeError, OSError, ValueError):
        # An in-memory stream, which only the tests hand `main`. A process
        # sshd starts always has a real stdout.
        return False
    if not hangup_is_visible(fd):
        return False
    threading.Thread(target=_exit_on_hangup, args=(fd,), name="hangup watch",
                     daemon=True).start()
    return True


def _exit_on_hangup(fd: int) -> None:
    watch = select.poll()
    watch.register(fd, select.POLLERR | select.POLLHUP)
    while True:
        for _fd, events in watch.poll():
            if events & (select.POLLERR | select.POLLHUP):
                # os._exit and not sys.exit: it ends every thread at once, a
                # certificate read included, closes every socket, and flushes
                # nothing, so not one byte is written after the caller went.
                os._exit(EXIT_CALLER_GONE)
            if events & select.POLLNVAL:
                return  # stdout was closed under us, so nothing is left to watch


def main(argv=None, stdin=None, stdout=None, stderr=None) -> int:
    """The streams are arguments so the tests drive this exactly as a shell
    does, rather than testing something adjacent to what runs."""
    argv = sys.argv[1:] if argv is None else argv
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr

    if argv:
        # No flags at all, on purpose. Every input arrives in the batch, so
        # there is nothing a command line could usefully say and an argument
        # that named a target would be a second, ungated way in.
        print("usage: python -m app.probe_runner < batch.json > results.json",
              file=stderr)
        return EXIT_UNREADABLE

    try:
        payload = json.load(stdin)
    except (ValueError, UnicodeDecodeError) as exc:
        print(f"the batch is not JSON: {exc}", file=stderr)
        return EXIT_UNREADABLE

    try:
        batch = parse_batch(payload)
    except (BatchUnreadable, authz.SnapshotUnreadable) as exc:
        print(f"the batch cannot be used: {exc}", file=stderr)
        return EXIT_UNREADABLE

    watch_for_hangup(stdout)
    measured = measure_batch(batch)
    try:
        json.dump(measured, stdout)
        stdout.write("\n")
        stdout.flush()
    except BrokenPipeError:
        # The caller went while the answer was being written, the same hangup
        # the watch looks for, so the same exit and in silence: a traceback
        # would be a write after the caller went.
        os._exit(EXIT_CALLER_GONE)
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
