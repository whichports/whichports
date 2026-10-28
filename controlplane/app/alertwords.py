"""What an alert message says: one description, drawn by every channel.

The spec is docs/screens/mails/SPEC-alert-messages.md. Every alert is a title
a person would say aloud, labelled values under it, the line that nothing
else will be sent, and one button. The mail, Slack, Discord, Telegram and the
webhook's text all draw this one description (app/notify.py, app/senders.py),
so no channel can say a thing another does not.

**Nothing here is worked out from a finding.** Every value arrives frozen
with the change it is about (`notify.Change`, written by
`finding_alerts._open_change`). A rule edited after the change cannot rewrite
a message, and a change stored before a value existed leaves that field out.

**What it never says** (the spec's section 3): what stopped a packet, a cause
the engine did not name, a state word, a time, a score, and a program's name
that a channel could parse or link.
"""
from dataclasses import dataclass

from . import join, publicurl


@dataclass(frozen=True)
class Said:
    """One message. `fields` are (label, value) pairs in the order they are
    shown. `sentence` is the test message's one line and empty in every other
    kind, because no sentence stands between a title and its fields."""
    title: str
    fields: tuple = ()
    sentence: str = ""
    closing: str = ""
    button: str = ""
    link: str = ""


# Every label a message may carry. A field with nothing true to put in it is
# left out, never filled with a dash.
LABELS = ("server", "port", "you said", "allowed by", "server's firewall",
          "program", "before", "your yes", "reachable", "stopped answering",
          "different program", "no report for", "no check for")

# The fourteenth label, Discord's alone, over the link (docs/RECORD.md 4.409).
# Where the mail has its button, a Discord message has only a field to put a
# link in, and a field has a name: Discord's own page gives an embed a title,
# a description, a url, fields and a footer, and a field a name and a value
# (read on 2026-10-06). No other channel says this word, and it is not one of
# the labels a message's own fields may carry.
DISCORD_LINK_LABEL = "dashboard"

# What the port's other address family did when the change was seen. Frozen
# with the change by `finding_alerts.other_family`.
OTHER_ANSWERS = "answers"
OTHER_DOES_NOT_ANSWER = "does not answer"
OTHER_NOT_MEASURED = "not measured"
OTHER_FAMILY = (OTHER_ANSWERS, OTHER_DOES_NOT_ANSWER, OTHER_NOT_MEASURED)

# The engine's layer, in the words a message uses. A layer that is not here
# is not a rule that let the port answer, and gives no field.
ALLOWED_BY = {
    join.LAYER_PROVIDER: "a rule in your provider's firewall",
    join.LAYER_HOST_FIREWALL: "a rule in the server's firewall",
}
YOUR_YES = "your yes"

FAMILY_WORDS = {"v4": "IPv4", "v6": "IPv6"}

# How many ports one list names before it says how many more there are.
LIST_SHOWS = 5

PORT_CLOSING = "Nothing else will be sent about this port until it changes again."
PORTS_CLOSING = "Nothing else will be sent about these ports until they change again."
SERVER_CLOSING = "Nothing else will be sent about this server until it reports again."
STALE_CLOSING = "Nothing else will be sent about this until checking resumes."


# ------------------------------------------------------- a program's name
#
# A program's name is text a server wrote, and a chat channel parses what it
# is sent: a dot makes a domain a link, and markup makes a name bold. So a
# name is said only when it is plain, and otherwise the whole field is left
# out and stays on the server's page.
#
# Plain is ASCII letters and digits, plus the marks real names earned
# (the spec's rule 3.6 holds the reads): a hyphen and an @ for a unit or a
# process, a hyphen and an underscore for a container. A dot is plain for
# nothing, though Docker allows one in a container's name.
#
# And a plain name starts with a letter or a digit. Every real name read
# does, Docker requires it of a container, and a name that starts with a
# mark is how a server would write "@everyone" into a chat.
_LETTERS_AND_DIGITS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
PLAIN_FOR_A_UNIT_OR_A_PROCESS = _LETTERS_AND_DIGITS | frozenset("-@")
PLAIN_FOR_A_CONTAINER = _LETTERS_AND_DIGITS | frozenset("-_")


def program_words(names, container=False) -> str:
    """The program behind a port in the words a message may carry, or empty.

    `names` are the names still apart, which is why this is called where a
    change is frozen and never on a joined string: `container` and the comma
    are our words, and a process that calls itself "container web" holds a
    space, is not plain, and is not said.

    One name that is not plain empties the whole value. Saying the plain
    half of two programs would read as one program answering.
    """
    allowed = PLAIN_FOR_A_CONTAINER if container else PLAIN_FOR_A_UNIT_OR_A_PROCESS
    names = list(names)
    if not names:
        return ""
    for name in names:
        if not name or name[0] not in _LETTERS_AND_DIGITS:
            return ""
        if not all(character in allowed for character in name):
            return ""
    if container:
        return ", ".join(f"container {name}" for name in names)
    return ", ".join(names)


# ------------------------------------------------------------ the pieces

def _shown(host_name, display) -> str:
    """What a message calls a server: its display name when it has one, the
    name it is found by otherwise (app/displayname.py)."""
    return display or host_name


def _server(host_name, display) -> str:
    """The `server` field's value. Two servers may carry the same display
    name, so a message that says one also says the name the server is found
    by (docs/RECORD.md 4.255): `Webshop (web-07)`. A server without a
    display name is said by the one name it has."""
    if display and display != host_name:
        return f"{display} ({host_name})"
    return host_name


def _port(change) -> str:
    """The port as a message names it. The probers connect over TCP, so a
    bare number is a TCP port and any other protocol is said."""
    if change.protocol == "tcp":
        return str(change.port)
    return f"{change.port}/{change.protocol}"


def _is_program_change(change) -> bool:
    return bool(change.was_program)


def _stopped_answering(change) -> bool:
    """A port somebody said yes to that does not answer. `conflict` means
    both things (finding_alerts.NOT_REACHABLE_BEFORE says why), so the
    frozen outside answer is what tells them apart."""
    return (not _is_program_change(change) and not change.became_reachable
            and change.now == join.STATE_CONFLICT and not change.answers)


def _names_its_family(change) -> bool:
    """Whether "does not answer" must say which family (the spec's rule 3.1).

    It is said without a family only when the other family also does not
    answer or has no finding at all. When the other family answers, or was
    not measured, a bare "does not answer" would say more than was measured.
    """
    return change.other_family in (OTHER_ANSWERS, OTHER_NOT_MEASURED)


def _family(change) -> str:
    return FAMILY_WORDS.get(change.family, change.family)


def _allowed_by(change) -> str:
    """The rule that lets the port answer, in a message's words, or empty.

    Never for a port that does not answer: the engine does not say what
    dropped a packet. Never for `unexplained`, where naming a layer would be
    picking one. The value is the engine's, frozen with the change.
    """
    if not change.answers or change.now == join.STATE_UNEXPLAINED:
        return ""
    return ALLOWED_BY.get(change.allowed_by, "")


def _a_rule_answers(change) -> bool:
    """Whether a rule, and not a person's yes, is what answers for a port
    that already has an answer.

    A declaration wins over a rule in the engine, so a port somebody said
    yes to is answered by that yes even when a rule permits it too.
    `change.rule` is the rule the engine said decided, frozen with the
    change, and is empty whenever a yes did. When a rule answered and its
    layer was not frozen, which is a change stored before the layer was
    kept, the field is left out: saying "your yes" there would be false.
    """
    return bool(change.rule)


def _with(pairs) -> tuple:
    """The fields that have something to say, in order."""
    return tuple((label, value) for label, value in pairs if value)


# ------------------------------------------------------------- one port

def _one_port_fields(server, change) -> tuple:
    head = [("server", server), ("port", _port(change))]
    if _is_program_change(change):
        # The answer the port already had stays as it was.
        stays = (("allowed by", _allowed_by(change)) if _a_rule_answers(change)
                 else ("your yes", "stays"))
        return _with(head + [("program", change.program_said),
                             ("before", change.was_program_said), stays])
    if change.became_reachable:
        answer = _allowed_by(change) if _a_rule_answers(change) else YOUR_YES
        return _with(head + [("allowed by", answer),
                             ("program", change.program_said)])
    if change.outside_source:
        # A port that answered an address its own rule does not allow
        # (docs/RECORD.md 4.377). Three things that were read or measured and
        # nothing of a path. Somebody did say, with a rule, so there is no
        # "you said" field here, and the rule's addresses do not leave.
        return _with(head + [
            ("allowed by", ALLOWED_BY[join.LAYER_PROVIDER]),
            ("server's firewall", "allows some addresses only"),
            ("program", change.program_said)])
    if change.now == join.STATE_UNEXPLAINED:
        return _with(head + [("program", "none seen listening")])
    if change.now == join.STATE_UNREVIEWED:
        return _with(head + [("you said", "nothing yet"),
                             ("program", change.program_said)])
    if _stopped_answering(change):
        return _with(head + [("you said", "reachable"),
                             ("program", change.program_said)])
    return _with(head + [("you said", "closed"),
                         ("allowed by", _allowed_by(change)),
                         ("program", change.program_said)])


def _one_port_title(shown, changes) -> str:
    change = changes[0]
    port = _port(change)
    if _is_program_change(change):
        return f"A different program answers port {port} on {shown}"
    if change.became_reachable:
        return f"Port {port} on {shown} became reachable from the internet"
    if _stopped_answering(change):
        title = f"Port {port} on {shown} does not answer from the internet"
        # One family alone, with the other answering or not measured.
        if len(changes) == 1 and _names_its_family(change):
            title += f" over {_family(change)}"
        return title
    return f"Port {port} on {shown} is reachable from the internet"


# -------------------------------------------------------- several ports

LIST_REACHABLE = "reachable"
LIST_STOPPED = "stopped answering"
LIST_PROGRAM = "different program"


def _list_of(change) -> str:
    """Which of the three lists a change belongs in."""
    if _is_program_change(change):
        return LIST_PROGRAM
    if _stopped_answering(change):
        return LIST_STOPPED
    return LIST_REACHABLE


def _port_key(change) -> tuple:
    return (change.port, change.protocol)


def _listed(changes) -> str:
    """One list's value: its ports in order, five at most, then how many
    more. A port is named once however many of its families are in the
    list. A port that stopped in one family alone says which."""
    by_port = {}
    for change in changes:
        by_port.setdefault(_port_key(change), []).append(change)
    entries = []
    for key in sorted(by_port):
        of_this_port = by_port[key]
        entry = _port(of_this_port[0])
        only = of_this_port[0]
        if (len(of_this_port) == 1 and _stopped_answering(only)
                and _names_its_family(only)):
            entry += f" over {_family(only)}"
        entries.append(entry)
    shown = ", ".join(entries[:LIST_SHOWS])
    more = len(entries) - LIST_SHOWS
    return f"{shown} and {more} more" if more > 0 else shown


def _several_ports(shown, server, changes, ports) -> tuple:
    """The title and the fields for more than one port, or for one port
    whose two families did different things."""
    noun = "port" if len(ports) == 1 else "ports"
    title = f"{len(ports)} {noun} changed on {shown}"
    lists = []
    for label in (LIST_REACHABLE, LIST_STOPPED, LIST_PROGRAM):
        members = [change for change in changes if _list_of(change) == label]
        lists.append((label, _listed(members) if members else ""))
    return title, _with([("server", server)] + lists)


# ------------------------------------------------------------ the kinds

def said_changes(host_name, changes, display="") -> Said:
    """One message for every finding on one server that changed.

    One message a server is docs/PRODUCT.md 4c's coalescing rule. The title
    and "and N more" count ports, never findings: a port that changed in
    both families is one port.
    """
    changes = list(changes)
    if not changes:
        raise ValueError("a message about no change")
    shown = _shown(host_name, display)
    ports = {_port_key(change) for change in changes}
    lists = {_list_of(change) for change in changes}
    button, link = f"Open {shown}", publicurl.server(host_name)
    if len(ports) == 1 and len(lists) == 1:
        return Said(title=_one_port_title(shown, changes),
                    fields=_one_port_fields(_server(host_name, display), changes[0]),
                    closing=PORT_CLOSING, button=button, link=link)
    title, fields = _several_ports(shown, _server(host_name, display), changes, ports)
    return Said(title=title, fields=fields, closing=PORTS_CLOSING,
                button=button, link=link)


def _length(count, unit) -> str:
    return f"{count} {unit}" if count == 1 else f"{count} {unit}s"


def said_silence(host_name, minutes, display="") -> Said:
    """An agent that stopped reporting. It says the agent stopped reporting,
    which is what was measured, and never that the server is down.

    `minutes` is None when the stored alert does not say how long, and the
    field is then left out.
    """
    shown = _shown(host_name, display)
    length = "" if minutes is None else _length(minutes, "minute")
    return Said(title=f"{shown} stopped reporting",
                fields=_with([("server", _server(host_name, display)), ("no report for", length)]),
                closing=SERVER_CLOSING, button=f"Open {shown}",
                link=publicurl.server(host_name))


def lasted(minutes) -> str:
    """How long a silence lasted, in the largest unit it fills twice over,
    and never rounded up: 119 minutes, then 2 hours, and 2 days from 48
    hours on. A week of silence in minutes is a number nobody reads."""
    if minutes < 2 * 60:
        return _length(minutes, "minute")
    if minutes < 2 * 24 * 60:
        return _length(minutes // 60, "hour")
    return _length(minutes // (24 * 60), "day")


def said_reporting_again(host_name, minutes, display="") -> Said:
    """An agent that reports again, for a channel that was told it stopped.
    It says the agent reports, which is what was measured, and how long no
    report came: from the last one before the silence to the first after.

    `minutes` is None when one of those two reports is not held, and the
    field is then left out. No line says what will not be sent, because
    nothing is pending after this message.
    """
    shown = _shown(host_name, display)
    length = "" if minutes is None else lasted(minutes)
    return Said(title=f"{shown} is reporting again",
                fields=_with([("server", _server(host_name, display)), ("no report for", length)]),
                button=f"Open {shown}", link=publicurl.server(host_name))


def said_outside_stale(host_name, hours, display="") -> Said:
    """An outside view that stopped being refreshed. It says what stopped,
    and nothing about the ports, which nobody measured since."""
    shown = _shown(host_name, display)
    length = "" if hours is None else _length(hours, "hour")
    return Said(title=f"{shown} is no longer checked from outside",
                fields=_with([("server", _server(host_name, display)), ("no check for", length)]),
                closing=STALE_CLOSING, button=f"Open {shown}",
                link=publicurl.server(host_name))


def said_other(host_name, kind, display="") -> Said:
    """A kind nothing above has words for is said as it is, rather than
    dropped or dressed as one of the others. No kind reaches this today."""
    shown = _shown(host_name, display)
    return Said(title=f"{shown}, {kind}", fields=(("server", _server(host_name, display)),),
                button=f"Open {shown}", link=publicurl.server(host_name))


def said_test() -> Said:
    """Send test. It names no server and no port, so it has no fields, and
    its title says it is a test, because whoever receives it may not be
    whoever pressed the button."""
    return Said(title="Test message", sentence="Sent from the Integrations screen.",
                button="Open Integrations", link=publicurl.integrations())
