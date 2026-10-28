#!/usr/bin/env python3
"""app.whichports.com, the dashboard. python3 build.py -> dist/index.html

A detailed, clickable shell of the product. Nothing behind it is real: the data
is invented, shaped after the findings in `docs/RECORD.md` so the screens argue
the same case the product does.

**The rule the owner set for what is clickable.** Everything inside v1 works as a
control: you can move between views, open a host, switch its tabs, filter, and
press the buttons. They may do nothing, and that is fine. Everything outside v1
is shown, marked `planned`, and is not clickable, so the shape of the product is
visible without pretending the thing is finished.

v1 is `docs/PRODUCT.md` section 7 and nothing else:

  in     the agent (Docker and rootful Podman), one provider API (Hetzner), the
         prober on v4 and v6, the join engine and the cause sentence, the packet
         path in both directions, on demand check, history and drift alerts by
         email and webhook, host and service inventory, authorisation, acknowledge
  out    Kubernetes, the Windows agent, agents on appliances, vulnerability scanning, any
         write path, any compliance claim

One thing worth the owner's eye: §7 does not list the integrations, but
`RECORD.md` §4.1 calls a Prometheus endpoint a purchase condition, because his
father's yes depended on feeding a central view rather than being another
dashboard. They are marked planned here, following §7 as the scope owner, and
that tension is real rather than an oversight.

**This file is also the template.** The fragment builders and the page frame
below are shared with `render_live.py`, which fills the same screens from the
control plane's database instead of the sample lists. One template, two feeds,
so the demo and the product cannot drift apart. Run this file for the sample
shell, run render_live.py for the real one.
"""
import dataclasses
import datetime
import html
import json
import pathlib
import re
import shutil
import sys
import urllib.parse

# The same fork render_live.py makes, for the same reason: loaded as part of
# a package (the control plane's renderbridge does this under its own alias),
# the relative import keeps the name `app` untouched, which in that process is
# the control plane's own package. Bare, it is the script and the tests, and
# nothing changes.
if __package__:
    import theme  # noqa: E402
    from . import packetpath as pp  # noqa: E402  (what a rule's own text names)
else:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
    import theme  # noqa: E402
    import app.packetpath as pp  # noqa: E402  (what a rule's own text names)

HERE = pathlib.Path(__file__).resolve().parent
DIST = HERE / "dist"

# What the outside view says about one address family. Three values and there is
# no fourth: it answered, it did not, or nobody tested it. `not tested` is not a
# silence and is never drawn like one (docs/PRODUCT.md section 4b).
ANSWERED, SILENT, NOT_TESTED = "answered", "silent", "not tested"

# ---------------------------------------------------------------- the walks
# The packet path as data: one walk per port per address family, each a run of
# cells. The shape is the Gates drawing chosen on 2026-08-19 out of four rail
# variants ("i think 3 Gates is the best one for now"), drawn in
# site/explorations/fleet-2026-08/build_rail.py and carried here unchanged.
#
# **No cell states an outcome** (docs/PRODUCT.md 4g): a gate names a checkpoint
# and quotes what it holds, a quiet cell counts checkpoints that hold nothing
# naming this port, and the fork is the routing decision. The only sentence
# allowed to name a layer is the walk's own finding line, which is the join of
# this walk with a measurement, and only the sample has one, because only the
# sample's prober has run.


# What a chain is for, in plain words, keyed by the technical name we already
# show. The owner asked for this twice, on two different screens: once because
# the routes themselves were hard to follow (RECORD 4.67), and once for
# easier names than `inet filter input` (RECORD 4.71). He is the
# system and network administrator this is built for.
#
# Two rules, and the second is the one that keeps this honest.
#
# The technical name never goes away. It is what every other tool calls it and
# what the operator will grep their own ruleset for, so hiding it would trade
# one comprehension problem for another.
#
# **A chain nobody has written a plain name for keeps only its technical name.**
# No guessing from the chain's spelling. These words are ours, not quoted from
# the host, which means they can be wrong in a way a quoted rule cannot, so the
# list grows by someone deciding rather than by a pattern match. Until then the
# screen is half translated, which the design that won this round said out loud.
PLAIN_CHAIN_NAMES = {
    # The host's own inbound path.
    "filter INPUT": "the host firewall",
    "inet filter input": "the host firewall",
    "ip filter INPUT": "the host firewall",
    "ip6 filter INPUT": "the host firewall",
    # Forwarding, which is not traffic to this machine.
    "filter FORWARD": "traffic passing through, not to this machine",
    "inet filter forward": "traffic passing through, not to this machine",
    # Address rewriting.
    "nat PREROUTING": "address rewriting, on the way in",
    "nat POSTROUTING": "address rewriting, on the way out",
    # ufw's own chains.
    "filter ufw-user-input": "your ufw rules",
    "filter ufw-before-input": "ufw's own rules, before yours",
    "filter ufw-after-input": "ufw's own rules, after yours",
    # docker's chains. DOCKER-USER is the one an operator is meant to edit.
    "filter DOCKER-USER": "docker's hook for your rules",
    "filter DOCKER": "docker's published container ports",
    # The nat side of the same names, and they are different chains. `nat
    # DOCKER` is where publishing a port actually happens: the DNAT that
    # rewrites the destination, which `docs/PRODUCT.md` 4d is about and which
    # the packet path already shows running before the filter table.
    "nat DOCKER": "docker's address rewriting, which is what publishing a port does",
    "nat DOCKER-USER": "docker's hook for your rules, on the rewriting side",
    "filter DOCKER-ISOLATION-STAGE-1": "docker keeping its networks apart",
    "filter DOCKER-ISOLATION-STAGE-2": "docker keeping its networks apart",
}


def plain_chain_name(name):
    """The plain words for a chain, or "" when nobody has written any.

    Empty is a real answer and the caller shows the technical name alone. It is
    not a failure and it must not become a guess.
    """
    return PLAIN_CHAIN_NAMES.get(name, "")


def gate_cell(stage, name, gr, meta="", rules=(), note="", extra="", tone="", full=""):
    """One checkpoint that holds something: a block on the rail, and the panel
    it opens. `rules` is quoted verbatim in the panel. `extra` is already-built
    HTML from the caller's own fragments and is never document text."""
    return {"kind": "gate", "stage": stage, "name": name, "gr": gr, "meta": meta,
            "rules": list(rules), "note": note, "extra": extra, "tone": tone,
            "full": full or name, "plain": plain_chain_name(name)}


def quiet_cell(n):
    """A run of checkpoints holding nothing that names this port. Counted, not
    dropped: the count is the fact that they were evaluated."""
    return {"kind": "quiet", "n": n}


def fork_cell():
    """The routing decision. Not a checkpoint and not clickable: the kernel
    decides delivery here, and the agent reads rules rather than routes."""
    return {"kind": "fork"}


# The walks of the demo host, one per port per address family, against the same
# invented facts as the rest of this file: docker publishes 5432, ufw permits 22
# and the overlay range on 9100, nothing names 6379. A `None` family is one this
# host binds nothing for, and it draws no walk rather than borrowing the other
# family's (docs/PRODUCT.md 4b).
#
# The v6 chain name `ufw6-user-input` is read from the agent's own ufw fixture,
# agent/internal/collect/testdata/fsroots/ubuntu-ufw/etc/ufw/user6.rules, not
# remembered.
_DNAT4 = ("-A DOCKER -d 172.18.0.2/32 ! -i br-a1 -p tcp --dport 5432 "
          "-j DNAT --to-destination 172.18.0.2:5432")
_DNAT6 = ("-A DOCKER ! -i br-a1 -p tcp --dport 5432 "
          "-j DNAT --to-destination [fd00:dead:beef::2]:5432")


def _docker_walk(dnat, accept_dst, sock):
    """tcp/5432's walk, the flagship: DNAT in prerouting, then the forward
    hook, and ufw's default deny on input is never consulted. One function for
    both families so they cannot drift apart in shape."""
    return [
        quiet_cell(5),
        gate_cell("prerouting", "nat PREROUTING, chain DOCKER", "1 rule",
                  meta="nat · priority -100", rules=[dnat],
                  note="written by docker publish, and this runs before the filter "
                       "table where ufw's rules live", tone="new"),
        fork_cell(),
        gate_cell("forward", "chain DOCKER-USER", "1 rule", meta="filter · priority 0",
                  rules=["-A DOCKER-USER -j RETURN"],
                  note="the chain exists and nobody has filled it, and it is the hook "
                       "docker leaves you for exactly this"),
        gate_cell("forward", "chain DOCKER", "1 rule", meta="filter · priority 0",
                  rules=[f"-A DOCKER -d {accept_dst} ! -i br-a1 -o br-a1 -p tcp "
                         "--dport 5432 -j ACCEPT"],
                  note="written by docker publish"),
        quiet_cell(1),
        gate_cell("postrouting", "nat POSTROUTING", "1 rule", meta="nat · priority 100",
                  rules=["-A POSTROUTING -s 172.18.0.0/16 ! -o br-a1 -j MASQUERADE"],
                  note="on the way back out"),
        gate_cell("socket", "postgres, in the container", "1 listening",
                  rules=[sock], note="inside the container's own network namespace"),
    ]


def _local_walk(gate, sock):
    """A locally delivered port: the empty checkpoints, the fork, at most one
    input gate, and the socket. `gate` is None for a port nothing names."""
    cells = [quiet_cell(6), fork_cell()]
    cells.append(gate if gate else quiet_cell(1))
    cells.append(sock)
    return cells


def _sock(name, bind):
    return gate_cell("socket", name, "1 listening", rules=[f"{name} {bind}"],
                     note="what is actually listening, from /proc")


# The sentence the host page opens with: the finding, which is the join of the
# three views and the one sentence allowed to name a layer. It is also the say
# line of tcp/5432's walk, read from here rather than written twice.
ANSWER = ("<b>tcp/5432</b> answers from the internet on IPv4 and IPv6, and nobody has "
          "said it should. No cloud firewall is attached, and docker's publish rule "
          "sends the packet into the bridge before ufw's rules are reached. The layer "
          "that decided is <b>nat PREROUTING, chain DOCKER</b>.")

SAMPLE_WALKS = [
    {"port": "tcp/5432", "tone": "warn", "word": "unreviewed",
     "measured": "v4 answered · v6 answered · measured 14:02:47",
     "say": ANSWER,
     "families": [
         ("v4", _docker_walk(_DNAT4, "172.18.0.2/32", "postgres 0.0.0.0:5432")),
         ("v6", _docker_walk(_DNAT6, "fd00:dead:beef::2/128", "postgres [::]:5432")),
     ]},
    {"port": "tcp/22", "tone": "ok", "word": "intended",
     "measured": "v4 answered · v6 not tested · measured 14:02:47",
     "say": "You declared 22 open, and ufw permits it.",
     "families": [
         ("v4", _local_walk(
             gate_cell("input", "ufw, chain ufw-user-input", "1 rule",
                       meta="filter · priority 0",
                       rules=["-A ufw-user-input -p tcp --dport 22 -j ACCEPT"],
                       note="ufw writes into the filter table, and its default for "
                            "incoming is deny"),
             _sock("sshd", "0.0.0.0:22"))),
         ("v6", _local_walk(
             gate_cell("input", "ufw, chain ufw6-user-input", "1 rule",
                       meta="filter · priority 0",
                       rules=["-A ufw6-user-input -p tcp --dport 22 -j ACCEPT"],
                       note="ufw keeps a second set of chains for v6, in the same "
                            "filter table shape"),
             _sock("sshd", "[::]:22"))),
     ]},
    {"port": "tcp/9100", "tone": "off", "word": "not reachable",
     "measured": "v4 silent · v6 silent · measured 14:02:47",
     "say": ("9100 did not answer from outside. ufw permits the overlay range only, "
             "and the layer that decided on v4 is <b>ufw, chain ufw-user-input</b>."),
     "families": [
         ("v4", _local_walk(
             gate_cell("input", "ufw, chain ufw-user-input", "1 rule",
                       meta="filter · priority 0",
                       rules=["-A ufw-user-input -s 10.0.0.0/8 -p tcp --dport 9100 "
                              "-j ACCEPT"],
                       note="the rule was written for the overlay range, and the "
                            "prober is not in it"),
             _sock("node_exporter", "0.0.0.0:9100"))),
         ("v6", None),  # node_exporter is bound on v4 only
     ]},
    {"port": "tcp/6379", "tone": "off", "word": "not reachable",
     "measured": "v4 silent · v6 silent · measured 14:02:47",
     "say": ("6379 did not answer from outside. No rule on this host names it, and "
             "ufw's default for incoming is deny."),
     "families": [
         ("v4", _local_walk(None, _sock("redis-server", "0.0.0.0:6379"))),
         ("v6", None),  # redis is bound on v4 only
     ]},
]

# What a family with no walk says instead of drawing one. The reason a walk is
# absent is a fact about the socket, so the line names it.
NO_WALK = {"tcp/9100": "node_exporter is bound on v4 only",
           "tcp/6379": "redis is bound on v4 only"}

# The three views of tcp/5432, as a grid you read across. One column per source,
# one row per question, so the row is the comparison and a cell that says nothing
# was measured sits under the two that did.
#
# The third row is the whole product in three cells: ufw intends to deny, the
# probe got an answer anyway, and the provider says nothing is attached in front
# of it. All three are invented here, shaped after the finding in RECORD 4.7.
# Every port bound to a network address, one row each: the state, the port and
# what holds it, both families from outside, why it is the way it is, and where
# it is bound. Direction A of the server-page round ("i think A wins here",
# 2026-08-19): the fleet's port vocabulary carried down one level, so the two
# screens teach the same thing once. Both families are always named, and a
# family nobody tested says so rather than reading as a silence
# (docs/PRODUCT.md 4b).
#
# `fams` is which address families of this row carry a state, which is what the
# review control acts on. It is written out per row rather than worked out from
# the two family columns, because those columns say what the outside view
# measured and a state is a different question: a port nothing reached still
# has one when a rule permits it. Invented like the rest of this list, and
# `render_live.py` takes the real answer from the join engine.
#
# `declared` is what this sample port is declared to be, and `states` is what
# the State cell would say under each of the three answers, keyed `open`,
# `closed` and "" for no declaration. The live page takes both from the join
# engine, which is the only thing that may decide a state. Here they are drawn
# with it: a port that answers from outside is `intended` when it was declared
# open and `conflict` when it was declared closed, and `unreviewed` when nobody
# said (controlplane/app/join.py).
#
# The two silent rows carry no what-if, because `not reachable` is this
# drawing's own word and not one of the five the engine produces, so there is
# nothing honest to say about what a declaration would do to it. An empty
# what-if leaves the State cell exactly as it is.
#
# `quotes` is the rules this row's state was decided from, each as (the rule
# verbatim, where it was read), and it is what `port_row_quotes` in
# render_live.py produces on a live page (`docs/RECORD.md` 4.117). A rule is
# the host's own syntax and is never paraphrased, here or there.
#
# tcp/5432 quotes nothing on purpose: docker's publish rule put the packet
# into the bridge and the service answered it, so the layer that decided is
# the service and the evidence for that is the bind line the row already
# shows. A row with nothing to quote has to be in this sample, or the shell
# teaches that every row carries a rule.
#
# (port, service, runtime, state, v4, v6, bind, why, fams, declared, states,
#  quotes)
SAMPLE_PORTS = [
    ("tcp/22", "sshd.service", "systemd", "intended", ANSWERED, NOT_TESTED,
     "0.0.0.0:22 and [::]:22", "you declared 22 open", ("v4",), "open",
     {"open": "intended", "closed": "conflict", "": "unreviewed"},
     [("-A ufw-user-input -p tcp --dport 22 -j ACCEPT", "ufw, chain ufw-user-input")]),
    ("tcp/5432", "postgres:16", "docker", "unreviewed", ANSWERED, ANSWERED,
     "0.0.0.0:5432 and [::]:5432", "nobody has said whether 5432 should be open",
     ("v4", "v6"), "",
     {"open": "intended", "closed": "conflict", "": "unreviewed"},
     []),
    ("tcp/6379", "redis:7", "docker", "not reachable", SILENT, SILENT,
     "0.0.0.0:6379", "ufw drops it", ("v4", "v6"), "", {},
     [("-A ufw-user-input -j ufw-user-limit-accept", "ufw, chain ufw-user-input")]),
    ("tcp/9100", "node_exporter.service", "systemd", "not reachable", SILENT, SILENT,
     "0.0.0.0:9100", "ufw permits the overlay range only", ("v4", "v6"), "", {},
     [("-A ufw-user-input -s 10.0.0.0/8 -p tcp --dport 9100 -j ACCEPT",
       "ufw, chain ufw-user-input")]),
]

# The rulesets, as they were read: (title, hint, conf fields, table, groups),
# where a group is (name, what it is, [(rule text, the operator's comment,
# grade)]) and `table` is (label, summary) for a layer read out of the kernel,
# which is shown as a disclosure per table, or None for a layer read out of its
# own files, which is shown flat. Same split, and the same fragments, as the
# live page: intent is short and read straight, enforcement is long and folded.
#
# Short here because it is a sample, and the same two layers the packet path
# walks: what ufw intends, what is enforced.
#
# The comment on the ssh tuple is shown decoded, which is what a real page shows.
# ufw stores it in the tuple line hex-encoded and render_live.py decodes it for
# display, so the demo is the shape a real host produces rather than a nicer one.
# The Rules tab's demo data (docs/screens/host-rules/SPEC.md, the case the
# sketch calls app-01). The server name is made up, and so is every rule,
# time and count, in the shape each layer prints.
ANYWHERE = "anywhere"

# Every firewall reports its own defaults. ufw and Hetzner both deny inbound
# and permit outbound when nothing matches, ufw from its own status output and
# Hetzner from its firewall overview, both read on 2026-09-09.
FW_DEFAULTS = (("incoming", "deny"), ("outgoing", "allow"))


# One glyph per channel, named once here so the configured list and the Add
# channel window cannot end up drawing different pictures of the same thing.
# theme.ICONS owns the path data and refuses a name it does not carry.
#
# The owner, 2026-08-16, asked for real logos on alerts and integrations. So a
# channel with a real mark carries it, and theme.BRAND_MARKS says which three
# those are and why the other products keep a neutral glyph. Slack keeps the
# hash because a Slack destination is a #channel, and Teams keeps three people
# because a Teams destination is a channel full of them.
# The owner picked these by name on 2026-08-16. Phosphor draws the brand logos
# itself, so the five that have one use it and there is no second icon set to
# reconcile. ntfy has no Phosphor logo, so it keeps a neutral glyph.
CHANNEL_ICONS = {
    "Email": "envelope-simple",
    "Slack": "slack-logo",
    "Discord": "discord-logo",
    "Telegram": "telegram-logo",
    "Webhook": "webhooks-logo",
    "Ntfy": "bell-ringing",
    "Microsoft Teams": "microsoft-teams-logo",
}

# What is actually configured, one row each, and nothing else. Email is the one
# channel that delivers: the SMTP2GO sender domain is verified and the dead-man
# sweep mails (2026-08-16).
#
# The unbuilt channels used to have rows here, marked planned. The owner had them
# taken out on 2026-08-16, and he is right: a list headed "where it goes" is a
# list of what is set up, so a row for something that cannot deliver is a claim
# with nothing behind it. They are still in the Add window below, shown
# and marked planned, so nothing is hidden.
#
# The third element is the row's control, as markup, because the two feeds need
# different ones: the sample shell offers a switch you can flip, and the live
# page says where the recipient is set instead.
CHANNELS = [
    ("Email", "sysadmin@example.org", '<button class="sw" aria-label="Email"></button>'),
]

# The same list in the shape the configured rows draw since 2026-08-22:
# channel, glyph key, destination, label and when, status, times used, menu.
# The sample is the artboard the owner reads, so it shows the row a live page
# shows and not the older three column one.
#
# The destination is a variable name here too, because that is what a row
# holds. A sample that showed a URL would be drawing a screen we cannot build.
SAMPLE_CHANNEL_ROWS = [
    ("Email", "Email", "sysadmin@example.org", "ok", "4"),
    ("Slack", "Slack", "#ops", "ok", "2"),
    ("Webhook", "Webhook", "https://ops.example.net/hook/…", "off", "0"),
]

# The choices in the Add window: (name, stage id or None).
#
# A name with a stage id is a real choice and reveals that stage. A name with
# None is shown, marked planned, and disabled, so the browser itself refuses
# the click. Mail is the only channel with any machinery behind it, so it is
# the only one with a stage. Nothing is hidden, because the list of what is
# coming is worth reading even where none of it works yet.
#
# Each of these used to carry a sentence saying what it was, "A message to an
# address you own." and so on. The owner had them taken out on 2026-08-16: with a
# mark and a name on the card the sentence was restating the name, and seven of
# them turned a picker into a page of prose.
# Four of them stopped being planned on 2026-08-22, when the senders landed
# (docs/RECORD.md #259). ntfy and Microsoft Teams left the window with the
# Alerts screen's spec (docs/screens/alerts/SPEC.md): five cards, all of them
# real.
#
# **Four of the five are planned again for the closed alpha, since
# 2026-09-20.** `untilalpha.md`: "Alert mail per workspace to the tester's
# address. Email only. The other channels are planned." The window offered all
# five as live, and the first tester's first act was a generic webhook pointed
# at Mattermost that answered 400 (docs/RECORD.md 4.189). The senders, the
# routes and each channel's own step stay exactly as they are, so a row that
# already exists still delivers and still opens on Edit: the step is found by
# its id in `CHANNEL_FIELDS`, not through a card. Giving a card its stage id
# back is the whole of bringing a channel back.
#
# **All five are real again since 2026-10-01**. The owner, on sight of the window
# during the test fleet, had them opened first (docs/RECORD.md 4.224), so
# the channels can be tested end to end before the alpha.
ADD_CHANNELS = [
    ("Email", "chan-email"),
    ("Slack", "chan-slack"),
    ("Webhook", "chan-webhook"),
    ("Telegram", "chan-telegram"),
    ("Discord", "chan-discord"),
]

# What each built channel is called in the database, what its field holds,
# which input type the browser should give it, and the placeholder. The type
# is what `controlplane/app/channels.py` stores, so these strings are the
# contract between this window and that module.
#
# **An empty `holds` means the step asks for nothing**, which is Slack since
# 2026-08-24. Every other entry names one field.
#
# **The placeholder is per type since 2026-08-23**, when the owner saw an email
# recipient field that started with `https://`. The URL channels keep
# `https://` and nothing more, because an example URL in a placeholder gets
# copied and half a pasted example is worse than an empty field (#284). Mail
# and Telegram get an empty placeholder for the same rule: an example address
# or token would be copied too, and the label above the field already says
# what goes in it.
CHANNEL_FIELDS = {
    # Mail joined this on 2026-08-23, when the owner asked why email could not
    # be set up on the screen. A recipient is not a
    # credential, so it is an ordinary destination and mail is an ordinary
    # channel.
    "chan-email": ("email", "recipient address", "email", ""),
    # Slack asks for nothing: the owner had the webhook URL field removed on
    # 2026-08-24. The webhook comes back from the connect and is written by
    # `controlplane/app/ingest.py`, so there is no value left for anybody to
    # type here. The column still holds a pasted one, because rows on the box
    # have one and the CLI still writes one. Only this window stops offering it.
    "chan-slack": ("slack", "", "", ""),
    "chan-discord": ("discord", "Discord webhook URL", "url", "https://"),
    # The token is not a URL, so the field is plain text: type="url" would
    # make the browser refuse a real token at validation time.
    "chan-telegram": ("telegram", "Telegram bot token", "text", ""),
    "chan-webhook": ("webhook", "webhook URL", "url", "https://"),
}


# What the Add window holds each field of a destination to before it asks the
# server, and the line it says at that field when the field is refused, by
# its own check or by the server.
#
# A round of the test fleet found why (docs/RECORD.md 4.228): a bot token and
# a chat id typed into each other's field were refused by one line at the foot
# of the window, which named no field. A refusal stands at its field now, so
# each field has a check and words of its own.
#
# **The server decides.** What a field must look like is the rule in
# `controlplane/app/channels.py`, spelled here a second time because the page
# checks before it asks, and held to that module by test_add_refusal.py, the
# way EVENT_KINDS below is held to its kinds. No pattern here is a format of
# our own making.
#
# **A line says what the field must be and nothing else.** It names the field
# by the words on its label, gives no reason of ours, and never repeats what
# was typed, because the thing typed into the wrong field is the secret one.
# The reasons are that module's names for them (`channels.REASONS`).
@dataclasses.dataclass(frozen=True)
class FieldCheck:
    """One field of a destination's step.

    `wire` is the request's field a refusal from the server names for it,
    empty for a field the server never names by itself. `pattern` is what the
    trimmed value must look like, a regular expression Python and a browser
    read alike. `says` holds the line for each reason the field can be
    refused for. `longest` bounds the length, 0 for no bound. An `optional`
    field may be left empty."""
    wire: str
    pattern: str
    says: dict
    longest: int = 0
    optional: bool = False


# The server takes a URL that starts with one of these two
# (`channels.destination_refusal`).
URL_PATTERN = r"^https?://"
# An address written as numbers that no alert may be sent to is something
# only the server can know. Its two sentences for that were settled in
# docs/RECORD.md 4.336, and these are those, said of the field.
SAYS_PRIVATE = ("This address is inside a private network."
                " Alerts are sent to public addresses only.")
SAYS_UNSENDABLE = "An alert cannot be sent to this address."


def url_check(label):
    """The check of a field that holds a webhook's URL. `label` is the words
    on its label."""
    return FieldCheck(
        wire="destination", pattern=URL_PATTERN,
        says={"missing": f"Enter the {label}.",
              "shape": f"A {label} starts with https:// or http://.",
              "private": SAYS_PRIVATE, "unsendable": SAYS_UNSENDABLE})


# {step: {field: its check}}. A field's name is the end of its id:
# `chan-telegram-chat` is the field `chat` of the step `chan-telegram`.
CHANNEL_CHECKS = {
    "chan-email": {"dest": FieldCheck(
        wire="destination", pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
        says={"missing": "Enter the recipient address.",
              "shape": "A recipient address is one email address."})},
    "chan-slack": {},
    "chan-discord": {"dest": url_check("Discord webhook URL")},
    "chan-telegram": {
        "dest": FieldCheck(
            wire="destination", pattern=r"^[0-9]+:[A-Za-z0-9_-]+$", longest=256,
            says={"missing": "Enter the Telegram bot token.",
                  "shape": "A Telegram bot token is digits, a colon,"
                           " then the rest of the token."}),
        # The server takes these two as one value, chat:topic. The window
        # asks for each in its own field and the page joins them, so each
        # half has its own pattern and its own line.
        "chat": FieldCheck(
            wire="chat_id", pattern=r"^(-?[0-9]{1,16}|@[A-Za-z0-9_]{1,64})$",
            says={"missing": "Enter the chat id.",
                  "shape": "A chat id is a number or an @name."}),
        "thread": FieldCheck(
            wire="", pattern=r"^[0-9]{1,10}$", optional=True,
            says={"shape": "A topic is a number."}),
    },
    "chan-webhook": {"dest": url_check("webhook URL")},
}


# The Integrations screen's two lists (docs/screens/integrations/SPEC.md):
# (key, name, glyph, built). Alphabetical, in the window and in the table
# (the owner, 2026-09-06). What each one needs is INTEGRATION_FIELDS, read from
# each one's own API documentation on 2026-09-06, the sources are in the spec.
#
# The marks are the sketch's (theme.MARKS says where each comes from and on
# whose decision). Azure and Zabbix got theirs on 2026-09-07 at the owner's
# word, Syslog is a protocol and has none.
PROVIDERS = sorted([
    ("aws", "AWS", "amazonwebservices", False),
    ("azure", "Azure", "microsoftazure", False),
    ("digitalocean", "DigitalOcean", "digitalocean", False),
    ("hetzner", "Hetzner Cloud", "hetzner", True),
    ("linode", "Linode", "akamai", False),
    ("ovh", "OVHcloud", "ovh", False),
    ("scaleway", "Scaleway", "scaleway", False),
    ("vultr", "Vultr", "vultr", False),
], key=lambda p: p[1].lower())
# What was one list of feeds is two since layout B
# (docs/screens/alerts/SPEC-layout-b.md). Syslog carries alerts, so it is an
# alert destination and is offered where those are added, planned until its
# screen is built. The other three take series or read them, so they are
# their own kind in the Add window, each planned.
SYSLOG_CARD = ("syslog", "Syslog", "broadcast", False)
MONITORING = sorted([
    ("grafana", "Grafana", "grafana", False),
    ("prometheus", "Prometheus", "prometheus", False),
    ("zabbix", "Zabbix", "zabbix", False),
], key=lambda f: f[1].lower())
# The Add window's first cards, (key, name, glyph): one card for each kind of
# thing a workspace connects. Whether the planned monitoring cards get a first
# card of their own was the spec's one open point (section 8), and this tuple
# is the whole of the answer: without its third entry the window opens on two
# cards and shows no monitoring card at all.
ADD_KINDS = (("dest", "Alert destination", "bell"),
             ("prov", "Provider", "cloud"),
             ("mon", "Monitoring", "chart-line"))
# The window's overlay, and the word on its action for each kind that has
# fields to act on. A kind with no built card has no action.
ADD_WINDOW = "conn-ovl"
ADD_ACTIONS = {"dest": "Save", "prov": "Connect"}
# (label, placeholder, secret) per key. A secret field is a password input.
INTEGRATION_FIELDS = {
    # No placeholder: Hetzner's token page shows no example token, no prefix
    # and no length (docs.hetzner.com/cloud/api/getting-started/generating-api-token/,
    # read by the spec session on 2026-09-14), so any shape drawn here would
    # be invented.
    "hetzner": [("Read token", "", True)],
    "digitalocean": [("Token, read only", "dop_v1_…", True)],
    "linode": [("Personal access token, read only", "", True)],
    "ovh": [("Application key", "", True), ("Application secret", "", True),
            ("Consumer key", "", True)],
    "scaleway": [("Secret key", "", True)],
    "aws": [("Access key ID", "AKIA…", True), ("Secret access key", "", True),
            ("Region", "eu-central-1", False)],
    "azure": [("Tenant ID", "", True), ("Client ID", "", True),
              ("Client secret", "", True), ("Subscription ID", "", True)],
    "vultr": [("API key", "", True)],
    "syslog": [("Host", "syslog.example.net", True), ("Port", "6514", False)],
    "zabbix": [("Server", "zabbix.example.net", True), ("Port", "10051", False),
               ("Host name", "whichports", False)],
    "prometheus": [("Remote write URL", "https://…/api/v1/write", True),
                   ("User", "", False), ("Password", "", True)],
    "grafana": [],
}


# The slim marks beside a state, and the glyph each one is (the rules are in
# CSS below, `.tag-alert` and its neighbours). A selector to a name in theme.ICONS.
# Here and not in theme.py, because only the dashboard draws them: the theme is
# shared with the sign-in pages, which may carry no `http://` string at all, and
# an inline SVG has to name its namespace.
# `.tag-rate` is the rate limit's tag and the silence's, told apart by the
# attribute the silence's carries.
MARK_ICONS = {
    ".tag-alert": "bell-ringing",
    ".tag-rare": "warning",
    ".tag-fix": "arrow-circle-up",
    ".tag-mute": "bell-slash",
    # The paused mark is the muted mark's box with its own glyph, the way the
    # silenced mark below is the rate mark's box.
    ".tag-mute[data-mark=paused]": "pause",
    ".tag-rate": "gauge",
    ".tag-rate[data-silence-tag],.tag-rate[data-mark=silenced]": "bell-slash",
}


def _mark_icon_rules():
    """One mask rule per slim mark, the Phosphor path as an inline SVG."""
    rules = []
    for selector, name in MARK_ICONS.items():
        svg = ("%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 256 256'%3E"
               f"%3Cpath d='{theme.ICONS[name]}'/%3E%3C/svg%3E")
        before = ",".join(part + "::before" for part in selector.split(","))
        rules.append(f'{before}{{-webkit-mask:url("data:image/svg+xml,{svg}") center/contain no-repeat;'
                     f'mask:url("data:image/svg+xml,{svg}") center/contain no-repeat}}')
    return "\n".join(rules)


CSS = """
.top{position:sticky;top:0;z-index:30;background:color-mix(in srgb,var(--bg) 90%,transparent);
  backdrop-filter:blur(12px);border-bottom:1px solid var(--line)}
.top-in{max-width:1280px;margin:0 auto;padding:0 26px;height:56px;display:flex;
  align-items:center;gap:28px}
.nav{display:flex;gap:2px;flex:1;flex-wrap:wrap}
.nav a{font-size:var(--fs-meta);font-weight:600;color:var(--muted);
  padding:7px 12px;border-radius:99px;cursor:pointer;transition:all var(--quick) var(--ease)}
.nav a:hover{color:var(--ink);background:var(--panel2)}
.nav a.on{color:var(--ink);background:var(--panel2)}
.nav a.planned{cursor:not-allowed}
.nav a.planned:hover{background:none;color:var(--faint)}
.who{width:27px;height:27px;border-radius:50%;background:var(--panel2);border:1px solid var(--line2);
  display:grid;place-items:center;font-size:var(--fs-micro);color:var(--muted);flex:0 0 auto;
  cursor:pointer;font-family:inherit;transition:color var(--quick) var(--ease)}
.who:hover{color:var(--ink)}
.pm{position:relative;flex:0 0 auto}
.pm-menu{position:absolute;right:0;top:38px;min-width:236px;z-index:40;padding:6px;
  background:var(--panel);border:1px solid var(--line2);border-radius:10px;
  box-shadow:0 10px 30px rgba(0,0,0,.35)}
.pm-menu[hidden]{display:none}
.pm-who{padding:9px 11px 10px;border-bottom:1px solid var(--line);margin-bottom:5px;
  font-size:var(--fs-meta);color:var(--muted)}
.pm-who b{display:block;color:var(--ink);font-weight:600;margin-top:2px;
  font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta)}
.pm-row{display:flex;align-items:center;justify-content:space-between;gap:12px;width:100%;
  padding:9px 11px;border:0;border-radius:7px;background:none;font-family:inherit;
  font-size:var(--fs-body);color:var(--ink);cursor:pointer;text-align:left;
  transition:background var(--quick) var(--ease)}
.pm-row:hover{background:var(--hover)}
.pm-row .ic{color:var(--faint)}
.pm-seg{display:flex;gap:3px;background:var(--panel2);border-radius:99px;padding:2px}
.pm-seg button{font-family:inherit;font-size:var(--fs-micro);color:var(--muted);background:none;
  border:0;border-radius:99px;padding:4px 10px;cursor:pointer}
.pm-seg button.on{background:var(--panel);color:var(--ink)}
.wrap{max-width:1280px;margin:0 auto;padding:30px 26px 90px}
.ph{display:flex;align-items:flex-end;justify-content:space-between;gap:22px;flex-wrap:wrap}
h1{font-size:var(--fs-title)}
.psub{color:var(--muted);margin-top:8px}
.psub b{color:var(--ink);font-weight:600}
.acts{display:flex;gap:8px;flex-wrap:wrap}
.seg{display:flex;background:var(--panel);border:1px solid var(--line);border-radius:99px;padding:3px}
.seg button{font-family:inherit;font-size:var(--fs-meta);color:var(--muted);background:none;border:0;
  cursor:pointer;padding:6px 14px;border-radius:99px;transition:all var(--quick) var(--ease)}
.seg button:hover{color:var(--ink)}
.seg button.on{background:var(--panel2);color:var(--ink)}
/* Inside a settings row it hugs its two words instead of filling the cell. */
.ch2 .seg{display:inline-flex}
.seg button:disabled{opacity:.45;cursor:not-allowed}
.seg button:disabled:hover{color:var(--muted)}
/* ---- the Fleet, as the sketch in docs/screens/fleet draws it (SPEC.md).
   The weights the sketch sets on the title and the primary button are scoped
   to this view, so the other screens keep their own until their turn. */
#fleet h1{font-weight:700}
#fleet .btn.pri{font-weight:600}
/* The banner, one line above the title, only when something urgent needs
   saying. A dot in the tone colour, the sentence with its value in bold, one
   action and a dismiss. Several may be rendered, worst first, and only the
   first that is not dismissed shows: a dismissed one carries `hidden`, and a
   note that follows a visible note stays out of the way. */
.fnotes:empty{display:none}
.fnote{display:flex;align-items:center;gap:14px;margin-bottom:14px;padding:11px 16px;
  background:var(--panel);border:1px solid var(--line);border-radius:var(--r)}
.fnote[hidden],.fnote:not([hidden])~.fnote:not([hidden]){display:none}
.fnote .t{flex:1}
.fnote .t::before{content:"";display:inline-block;width:8px;height:8px;border-radius:50%;
  background:var(--warn);margin-right:12px;vertical-align:1px}
.fnote.fail .t::before{background:var(--fail)}
.fnote .t b{font-weight:600}
.fnote .btn{font-size:var(--fs-meta);padding:5px 12px}
.fnote .x{font-family:inherit;font-size:var(--fs-body);line-height:1;color:var(--faint);
  background:none;border:0;cursor:pointer;padding:0 2px}
.fnote .x:hover{color:var(--ink)}
/* The four boxes: one panel split in four, each a bold label, a large number,
   the same "of N ports" line and a bar showing the number as a share of N. The
   number takes the fail colour in the first box only. */
.fstrip{display:grid;grid-template-columns:repeat(4,1fr);gap:0;background:var(--panel);
  border:1px solid var(--line);border-radius:var(--r);margin-top:22px;overflow:hidden}
.fstrip>div{padding:16px 20px;border-left:1px solid var(--line)}
.fstrip>div:first-child{border-left:0}
.fstrip .l{font-size:var(--fs-meta);font-weight:600;color:var(--ink)}
.fstrip .n{font-family:"Space Grotesk",sans-serif;font-weight:600;font-size:var(--fs-title);
  line-height:1.1;margin-top:6px;font-variant-numeric:tabular-nums}
.fstrip .n.fail{color:var(--fail)}
.fstrip .d{font-size:var(--fs-meta);color:var(--faint);margin-top:4px}
.fbar{margin-top:10px;height:5px;border-radius:3px;background:var(--panel2);overflow:hidden}
.fbar i{display:block;height:100%;background:var(--acc-ink)}
.fbar i.fail{background:var(--fail)}
/* The search bar, full width between the boxes and the table. */
.srch{display:block;width:100%;margin-top:22px;padding:10px 14px;font-family:inherit;
  font-size:var(--fs-body);color:var(--ink);background:var(--panel);border:1px solid var(--line);
  border-radius:99px;outline:none}
.srch::placeholder{color:var(--faint)}
/* The table: State, Server, Reachable, Needs a decision. One row per server
   and a row is one link to the server's page. The Server column took the
   room the Agent column left on 2026-10-02, for the tags beside the name. */
.ftbl{margin-top:22px;overflow:hidden}
.thead,.row{display:grid;grid-template-columns:150px 320px 130px minmax(0,1fr);gap:16px;
  align-items:center}
.thead{padding:9px 20px;border-bottom:1px solid var(--line);background:var(--panel2)}
.thead span{font-size:var(--fs-micro);letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
.ar{text-align:right}
.row{padding:14px 20px;border-bottom:1px solid var(--line);cursor:pointer;text-decoration:none;
  color:inherit;transition:background var(--quick) var(--ease)}
/* The State cell holds the state and, while a mute covers the server, the
   mute mark. A wrapped mark must not hang off to the right of the tag above
   it, so the cell is a wrapping flex box with a gap and no inline margins. */
.row>div:first-child{display:flex;flex-wrap:wrap;align-items:center;gap:6px}
.row>div:first-child .tag-mute,.row>div:first-child .tag-alert,
.row>div:first-child .tag-rare,.row>div:first-child .tag-fix{margin-left:0}
.row:last-child{border-bottom:0}
.row:hover{background:var(--hover)}
/* A mark never wraps under its state (docs/DESIGN.md section 3). Measured on
   2026-10-11: at a fixed 150 px a third mark wrapped on every state word, a
   second one on the longer words, and at 1024 a second one on `watched`. So
   on the Fleet the rows share the table's own columns, and the State column
   is as wide as the widest state with its marks needs, never narrower than
   it was. One row with three marks widens the column for every row, so no
   name stands apart from the others. A browser that does not know subgrid
   keeps the fixed columns and the wrapping cell above.
   The first column's least width is the cell's 150 px and the row's own
   20 px of padding, which a row that shares its table's columns takes out
   of the first column. */
@supports (grid-template-columns:subgrid){
  #fleet .ftbl{display:grid;grid-template-columns:minmax(170px,max-content) 320px 130px minmax(0,1fr);
    column-gap:16px}
  #fleet .ftbl>.thead,#fleet .ftbl>.row{grid-column:1/-1;grid-template-columns:subgrid}
  #fleet .ftbl>.row>div:first-child{flex-wrap:nowrap}
}
.fsrv .hn{font-weight:600;color:var(--ink-str);overflow-wrap:anywhere}
.fhost,.funread{display:block;font-size:var(--fs-meta);color:var(--faint);font-weight:400}
/* A server's tags sit beside its bold name, on a line that wraps, and the
   hostname keeps its own line under them (the owner, 2026-09-30 and 2026-10-02).
   A tag is a word somebody typed, never a status, so it takes no tone: faint
   mono in a dashed box, smaller than the state tag. Dashed is his choice of
   2026-10-02. What tells a tag from something planned is the word: a planned
   field carries the PLANNED label and a tag carries only itself. A server
   with many tags grows its row and never its column. */
.fsrv{display:flex;flex-wrap:wrap;align-items:center;gap:4px 8px}
.fsrv .fhost{flex-basis:100%}
.fsrv .funread{flex-basis:100%}
.ftag{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);letter-spacing:.04em;
  line-height:16px;color:var(--faint);border:1px dashed var(--line2);border-radius:4px;padding:0 6px;
  white-space:nowrap}
.frc{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--muted)}
.frc b{font-weight:600;color:var(--ink)}
.fchips{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.fpc{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);border:1px solid var(--line2);
  border-radius:6px;padding:3px 8px;color:var(--ink)}
.fpc.fail{border-color:var(--fail);background:var(--fail-soft);color:var(--fail)}
.fpc.warn{border-color:var(--warn);color:var(--warn)}
/* Anything on the screen that is not decided yet: pure magenta, with a title
   saying what is unsure. Magenta never ships, and a marker leaves only by
   the owner's answer. */
.unsure,.unsure *{background:#FF00FF!important;color:#000!important;border-color:#000!important}
.row .unsure{display:inline-flex;align-items:center;gap:6px;padding:0 4px;
  font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);white-space:nowrap}
/* ---- the Host Evidence, as the sketch in docs/screens/host-evidence draws
   it: the matrix, three cards, the section strip. A fact is not a verdict:
   the neutral tag (.st.nt) is ink for a thing found and faint for an
   absence, and only the State cell carries a tone. */
.mxt{margin-top:22px;overflow:hidden}
.mxh,.mr{display:grid;grid-template-columns:150px 160px 1fr 1fr 1fr 150px;gap:16px;align-items:center;border-bottom:1px solid var(--line)}
.mr{padding:14px 20px;cursor:pointer}
.mr:hover{background:var(--hover)}
.mr:last-child{border-bottom:0}
.mxh{padding:9px 20px;background:var(--panel2)}
.mxh span{font-size:var(--fs-micro);letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
.mxh span:last-child,.mr .mst{text-align:right}
.mr .mst{display:flex;flex-direction:column;align-items:flex-end;gap:4px}
.mr .mst .tag-rate{margin-left:0}
/* The prober cell when two vantages disagree: the word with the neutral mark
   after it, and one mono line per vantage under it (SPEC.md, 2026-09-08). */
.mv{display:flex;flex-direction:column;align-items:flex-start;gap:4px}
/* The theme spaces one status tag from the next with .st+.st, which is what
   sets the prober and provider tags 8px in from their column on every row.
   The wrapped cell is not a .st, so it and the tag after it take the same
   8px, and a row with the mark stays in line with the rows without it
   (measured 2026-09-14: 700 against 708 before this). */
.mr .st+.mv,.mr .mv+.st{margin-left:8px}
.mvw{display:inline-flex;align-items:center}
.mvv{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);color:var(--muted);white-space:nowrap}
.frc .tag-disagree{margin-left:6px}
.mempty{display:block;cursor:default;font-size:var(--fs-meta);color:var(--muted)}
.mp{display:inline-flex;align-items:center;gap:8px;font-family:"IBM Plex Mono",monospace;color:var(--ink-str)}
.mp b{font-weight:600}
.mp small{font-size:var(--fs-micro);color:var(--faint);font-weight:400;text-transform:uppercase}
.mp small i{font-style:normal;text-transform:none}
.mp small i.v4{color:var(--faint)}
.mp small i.v6{color:var(--ink);font-weight:600}
.msv{font-size:var(--fs-meta);color:var(--ink);font-weight:600}
.msv.off{color:var(--faint);font-weight:400}
.mr .st.nt{justify-self:start}
.st.nt{color:var(--ink);border-color:var(--line2)}
.st.nt.off{color:var(--faint);border-color:var(--line)}
.evcs{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:22px}
.evcard{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:14px 16px}
.evt{display:flex;align-items:baseline;justify-content:space-between;gap:10px;padding-bottom:8px;border-bottom:1px solid var(--line);margin-bottom:6px}
.evt b{font-weight:600}
.evt span{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);color:var(--faint)}
.evl{display:grid;grid-template-columns:78px 1fr;gap:12px;padding:6px 0;font-size:var(--fs-meta);color:var(--muted)}
.evl .evk{color:var(--faint)}
.evl .mono{font-family:"IBM Plex Mono",monospace;color:var(--ink-str)}
.evcard.off .evl,.evcard.off .evt b{color:var(--faint)}
.evsecs{margin-top:22px}
.evsecs .k{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);letter-spacing:.06em;text-transform:uppercase;color:var(--faint);margin-bottom:8px}
.evchips{display:flex;flex-wrap:wrap;gap:8px}
/* ---- the Host Settings, as the sketch in docs/screens/host-settings draws
   it: the rail and the content side by side, every setting a row in a
   bordered list. The account's settings rail (.as) is another screen. */
.hset{display:grid;grid-template-columns:230px minmax(0,1fr);gap:48px;margin-top:26px;max-width:1080px}
.hset>input{position:absolute;width:1px;height:1px;opacity:0;pointer-events:none}
.hrail{padding:0 0 0 8px;align-self:start}
.hrail .g{font-size:var(--fs-micro);font-weight:600;color:var(--faint);padding:0 12px;margin:0 0 6px;height:22px;line-height:22px}
.hrail hr{border:0;border-top:1px solid var(--line);margin:12px 0 14px}
.hitem{position:relative;display:flex;align-items:center;gap:10px;height:34px;padding:0 12px;border-radius:8px;color:var(--ink);font-size:var(--fs-meta);font-weight:600;cursor:pointer;margin-bottom:2px}
.hitem svg{color:var(--muted);flex:none}
.hitem:hover{background:var(--hover)}
.hitem.hplanned{color:var(--muted);cursor:default}
.hitem.hplanned:hover{background:none}
.hitem .tag-planned{margin-left:auto}
.hbody{min-width:0}
.hstage{display:none}
.hstage h2{font-family:"Space Grotesk",sans-serif;font-size:var(--fs-lead);font-weight:600;margin:0 0 22px;height:34px;line-height:34px;padding-bottom:10px;border-bottom:1px solid var(--line);box-sizing:content-box}
.hstage h3{font-family:"Space Grotesk",sans-serif;font-size:var(--fs-body);font-weight:600;margin:30px 0 10px;display:flex;align-items:center;gap:8px;height:22px;line-height:22px}
.hstage h2+h3{margin-top:0}
.in{font:inherit;font-size:var(--fs-meta);color:var(--ink);background:var(--panel2);border:1px solid var(--line2);border-radius:8px;padding:0 12px;height:34px;box-sizing:border-box;width:280px}
.in.mono{font-family:"IBM Plex Mono",monospace}
.in.short{width:100px}
.in:focus{outline:none;border-color:var(--acc)}
.in:disabled{color:var(--faint);border-style:dashed}
/* Tags on a server's Settings: a bubble for each tag and a field that adds
   one more. The bubbles and the field wrap and stay at the right, where the
   other rows keep their fields. A bubble is a button: under the hand or the
   keyboard a line is drawn through its word from the left, the bubble takes
   the fail tone and grows a little, which is what a click on it does
   (docs/RECORD.md 4.298: a crossed word under the pointer, a click removes
   it, and a small pop). The growing is a transform, so nothing around the
   bubble moves and it cannot slide from under the pointer. Every step takes
   `quick` on the one curve, with no overshoot, and the reduced-motion rule
   in the theme makes them instant. A screen with no hover has no hand to
   rest on a bubble, so there each bubble shows a cross all the time. The
   theme's own focus ring is drawn around a bubble as around anything else,
   and its rule would square the corners, which `.tagb:focus-visible` keeps
   round. */
.li.tagrow .c{flex:0 1 auto;min-width:0}
.tagc{display:flex;flex-wrap:wrap;justify-content:flex-end;align-items:center;gap:8px}
.tagb{display:inline-flex;align-items:center;height:28px;padding:0 13px;margin:0;
  font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);letter-spacing:.04em;white-space:nowrap;
  color:var(--ink);background:var(--panel2);border:1px solid var(--line2);border-radius:99px;cursor:pointer;
  transition:color var(--quick) var(--ease),background var(--quick) var(--ease),border-color var(--quick) var(--ease),transform var(--quick) var(--ease)}
.tagb span{position:relative}
.tagb span::after{content:"";position:absolute;left:-3px;right:-3px;top:50%;height:1px;background:currentColor;
  transform:scaleX(0);transform-origin:left center;transition:transform var(--quick) var(--ease)}
.tagb svg{display:none}
.tagb:hover,.tagb:focus-visible{color:var(--fail);background:var(--fail-soft);border-color:var(--fail);transform:scale(1.06)}
.tagb:hover span::after,.tagb:focus-visible span::after{transform:scaleX(1)}
.tagb:focus-visible{border-radius:99px}
@media (hover:none){
  .tagb{padding-right:9px}
  .tagb svg{display:block;margin-left:6px}}
.in.tagin{width:132px}
.tagc.full .tagin{display:none}
/* A value that is shown and not edited, in the place a field would take:
   its text starts where a field's text starts. The ID is the one such row. */
.idv{flex:1;min-width:0;padding:0 13px;font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);
  color:var(--ink-str);overflow-wrap:anywhere;user-select:all}
.choice{display:inline-flex;align-items:center;justify-content:space-between;width:280px;height:34px;padding:0 12px;box-sizing:border-box;font-size:var(--fs-meta);color:var(--ink);background:var(--panel2);border:1px solid var(--line2);border-radius:8px}
.choice svg{color:var(--muted)}
.choice.off{color:var(--faint);border-style:dashed}
.list{background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
.list.danger{border-color:color-mix(in srgb,var(--fail) 55%,var(--line))}
.li{display:flex;align-items:center;gap:14px;padding:14px 20px;min-height:60px;box-sizing:border-box;border-bottom:1px solid var(--line)}
.li:last-child{border-bottom:0}
/* display:flex above beats the browser's own [hidden] rule, the trap
   .crow[hidden] and .pm-menu[hidden] name, so the proof block under the
   add-address row needs this line to stay hidden until Start. */
.li[hidden]{display:none}
.li>svg{color:var(--muted);flex:none}
.li .t{flex:1;min-width:0}
.li .t b{display:block;font-size:var(--fs-meta);font-weight:600;color:var(--ink);line-height:18px}
.li .t b.mono{font-family:"IBM Plex Mono",monospace;font-weight:500;color:var(--ink-str)}
.li .t small{display:block;font-size:var(--fs-micro);color:var(--muted);line-height:16px;margin-top:2px}
.li .t small.m-err{color:var(--fail)}
.li .t .code{margin-top:6px}
.li .c{display:flex;align-items:center;gap:8px;flex:none}
.li .c.fix{width:280px}
.li .c.fix .in{flex:1;width:auto;min-width:0}
.li .c .seg button{padding:5px 10px}
.li .c .tag-planned{margin-left:0}
.lempty{font-size:var(--fs-meta);color:var(--muted)}
.li .btn.danger{color:var(--fail);border-color:var(--fail)}
.rmw .s{font-size:var(--fs-meta);color:var(--muted);margin-top:6px}
.rmw .s .mono{font-family:"IBM Plex Mono",monospace;color:var(--ink-str)}
.rmw .in{display:block;width:100%;font-size:var(--fs-body);border-radius:10px;padding:0 14px;height:44px;margin-top:16px}
.rmw .btn.danger{color:var(--fail);border-color:var(--fail)}
.rmw .btn.danger:disabled{opacity:.45}
/* The two rows about the machine, between the field and the buttons: a label
   and a value, or a label and the command as a copy chip. display:flex would
   beat the browser's own [hidden] rule, so the hidden case is written out. */
.rmw .rmrow{display:flex;align-items:center;gap:14px;margin-top:14px;font-size:var(--fs-meta)}
.rmw .rmrow[hidden]{display:none}
.rmw .rmrow .l{color:var(--muted);flex:0 0 110px}
.rmw .rmrow .v{color:var(--ink)}
.rmw .rmrow.warn .v{color:var(--warn)}
.rmw .rmrow .code{margin:0;flex:1;min-height:0;padding:9px 12px;line-height:1.5}
.rmw .in:disabled{opacity:.55}
/* The servers Remove took out, under the fleet table, in the settings list
   shape: a name, the day, Delete. */
.fgone{margin-top:8px}
/* ---- the Host Changes, as the sketch in docs/screens/host-changes draws
   it: the count and the range pills, one table, no day rows, no colour
   beyond the neutral tags. */
.ctop{display:flex;align-items:center;justify-content:space-between;margin-top:22px}
.cnt{font-size:var(--fs-meta);color:var(--muted)}
.cnt b{font-weight:600;color:var(--ink)}
.rng{display:inline-flex;background:var(--panel);border:1px solid var(--line);border-radius:99px;padding:3px}
.rgl{display:inline-flex;align-items:center;gap:6px;font-family:inherit;font-size:var(--fs-meta);color:var(--muted);padding:5px 13px;border-radius:99px;cursor:pointer}
.rgl.off{color:var(--faint);cursor:default}
.ctbl{margin-top:14px;overflow:hidden}
.ch,.cr{display:grid;grid-template-columns:130px 150px 130px 130px minmax(0,1fr);gap:16px;align-items:center;border-bottom:1px solid var(--line)}
.cr{padding:14px 20px}
.ch{padding:9px 20px;background:var(--panel2)}
.ch span{font-size:var(--fs-micro);letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
.cr:last-child{border-bottom:0}
.cempty{display:block;font-size:var(--fs-meta);color:var(--muted)}
.cwhen{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--muted)}
.cwhen b{font-weight:500;color:var(--ink)}
.clay{font-size:var(--fs-meta);color:var(--ink);font-weight:600}
.clay small{font-weight:400;display:block;font-size:var(--fs-micro);color:var(--faint);font-family:"IBM Plex Mono",monospace;text-transform:uppercase;letter-spacing:.04em;margin-top:2px}
.cpn{font-family:"IBM Plex Mono",monospace;font-weight:600;color:var(--ink-str)}
.cpn small{font-size:var(--fs-micro);color:var(--faint);font-weight:400;margin-left:5px;text-transform:uppercase}
.cpn small i{font-style:normal;text-transform:none}
.cpn small i.v6{color:var(--ink);font-weight:600}
.ckind .st.nt{justify-self:start}
.ckind.off .st.nt{color:var(--faint);border-color:var(--line)}
.cdet{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
/* ---- the Host Services, as the sketch in docs/screens/host-services draws
   it: one table, a band per group, a row per thing that runs. Class names
   are the tab's own (s-prefixed) because .sh, .row and .nm are taken. */
.stbl{margin-top:22px;overflow:hidden}
.sgh{display:flex;align-items:baseline;gap:10px;padding:9px 20px;background:var(--panel2);border-bottom:1px solid var(--line)}
.sgh b{font-size:var(--fs-meta);font-weight:600;color:var(--ink)}
.sgh span{font-size:var(--fs-meta);color:var(--faint)}
.sh,.srow{display:grid;grid-template-columns:130px 300px minmax(0,1fr) 220px;gap:16px;align-items:center;border-bottom:1px solid var(--line)}
.srow{padding:14px 20px}
.sh{padding:9px 20px;background:var(--panel2)}
.sh span{font-size:var(--fs-micro);letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
.srow:last-child{border-bottom:0}
.sempty{display:block;font-size:var(--fs-meta);color:var(--muted)}
.snm b{font-weight:600}
.snm .sdn{margin-left:8px;color:var(--muted)}
.snm small{display:block;font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--muted);font-weight:400}
.schips{display:flex;gap:8px;flex-wrap:wrap}
/* The port chips in the fleet's colours (.fpc): red fill for conflict, amber
   for the three amber states, a hairline in the ok mark for intended, grey
   for the quiet state and for a port with no state. */
.spc{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);border:1px solid var(--line2);
  border-radius:6px;padding:3px 8px;color:var(--ink);background:none;cursor:pointer}
.spc small{font-size:var(--fs-micro);color:var(--faint);margin-left:4px;text-transform:uppercase}
.spc.fail{border-color:var(--fail);background:var(--fail-soft);color:var(--fail)}
.spc.warn{border-color:var(--warn);color:var(--warn)}
.spc.ok{border-color:var(--ok-mark)}
.spc.off{color:var(--muted);border-color:var(--line)}
.sbd{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--muted)}
/* ---- the Host Overview, as the sketch in docs/screens/host-overview draws
   it (SPEC.md). The title weight is scoped to a server's page the way the
   Fleet's is scoped to the Fleet. */
.view[id^="host"] h1{font-weight:700}
.hfacts{margin-top:12px;display:flex;align-items:stretch;flex-wrap:wrap}
.hfacts .f{padding:0 18px;border-left:1px solid var(--line)}
.hfacts .f:first-child{padding-left:0;border-left:0}
.hfacts .k{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);letter-spacing:.06em;
  text-transform:uppercase;color:var(--faint)}
.hfacts .v{font-size:var(--fs-meta);color:var(--ink);margin-top:2px;display:flex;align-items:center;gap:6px}
.hfacts .v svg{color:var(--faint)}
.hfacts .v .num{color:var(--ink)}
/* The three boxes, this server's numbers. A box that counts something names
   the first row it counts and opens it on a click. */
.hstrip{display:grid;grid-template-columns:repeat(3,1fr);background:var(--panel);
  border:1px solid var(--line);border-radius:var(--r);margin-top:22px;overflow:hidden}
.hstrip>div{padding:14px 20px;border-left:1px solid var(--line)}
.hstrip>div:first-child{border-left:0}
.hstrip>div[data-row]{cursor:pointer}
.hstrip>div[data-row]:hover{background:var(--hover)}
.hstrip .l{font-size:var(--fs-meta);color:var(--ink);font-weight:600}
.hstrip .n{font-family:"Space Grotesk",sans-serif;font-weight:600;font-size:var(--fs-title);
  line-height:1.1;margin-top:4px;font-variant-numeric:tabular-nums}
.hstrip .n.fail{color:var(--fail)}
.hstrip .n.warn{color:var(--warn)}
.hstrip .d{font-size:var(--fs-meta);color:var(--faint);margin-top:2px;min-height:1.4em}
.tools{display:flex;justify-content:flex-end;margin-top:18px}
.rv{display:inline-flex;align-items:center;gap:6px;color:var(--muted);padding:6px 14px}
/* The port table. A row opens on its checkbox, the row itself being the
   label, and the evidence under it is drawn with the page and hidden until
   then, so nothing here needs a script. */
.ptbl{margin-top:10px;overflow:hidden}
.prsel{position:absolute;width:1px;height:1px;opacity:0;margin:0;pointer-events:none}
/* The state column holds the widest state word and both slim marks a port can
   carry beside it, rate limited and silenced, on one line: a mark that wraps
   under its state is what the slim marks exist to end (the owner, 2026-09-20).
   The width comes out of the flexible Decided by column. */
.prh,.pr{display:grid;grid-template-columns:184px 100px 170px 110px minmax(0,1fr) 270px 22px;
  gap:16px;align-items:center}
/* Below 1220 those fixed columns left Decided by nothing. At 1024 it was 0
   wide, so its heading stood on two lines and "your rule" on two in every
   row (measured in a browser on 2026-10-06, docs/RECORD.md 4.373). There the
   other columns are held to what their widest content needs, measured the
   same day, and Decided by takes the rest. The state column keeps its width,
   for the reason above. */
@media(max-width:1220px){
  .prh,.pr{grid-template-columns:184px 80px 140px 94px minmax(0,1fr) 190px 16px;gap:12px;
    padding-left:16px;padding-right:16px}
}
.prh{padding:9px 20px;border-bottom:1px solid var(--line);background:var(--panel2)}
.prh span{font-size:var(--fs-micro);letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
.prh .pya{text-align:right}
.pr{padding:14px 20px;border-bottom:1px solid var(--line);cursor:pointer;color:inherit;
  transition:background var(--quick) var(--ease)}
.pr:hover{background:color-mix(in srgb,var(--panel2) 45%,transparent)}
.prsel:checked+.pr{background:color-mix(in srgb,var(--panel2) 60%,transparent);border-bottom:0}
.ptbl>.pre:last-child,.ptbl>.pr:last-child{border-bottom:0}
/* **The facts beside a state are slim marks, an icon in the tag's own border
   and no word**. The owner asked for it on 2026-09-20: a small symbol in the
   tag's own border, slim enough to sit beside the state and not under it,
   for an open alert, rate limited, silenced and the rest. One main
   state is the word. These are what else is true about it.
   The word stays in the element, pushed out of its box, so a screen reader
   reads it, the title shows it under the hand, and the script that fills the
   mute and the silence marks on a click writes what it always wrote. It
   keeps its size, because every font size here is a step of the scale and
   nothing is a step. The icon is the element's own colour through a mask, so
   a mark takes its tone from the rule above it and from nowhere else. Same
   height as the status tag. */
.tag-alert,.tag-mute,.tag-rate,.tag-rare{display:inline-block;position:relative;box-sizing:content-box;
  width:13px;height:13px;padding:3px 4px;overflow:hidden;text-indent:200%;white-space:nowrap;
  vertical-align:middle;cursor:default;line-height:13px}
.tag-alert::before,.tag-mute::before,.tag-rate::before,.tag-rare::before{content:"";position:absolute;
  left:4px;top:3px;width:13px;height:13px;background:currentColor}
/* .tag-rare is the mark on a reachable port that should rarely face the
   internet (docs/RECORD.md 4.197 and 4.248): the same slim box, in the warn
   tone, which was decided with the mark. A mark beside the state and never a
   state. Its box is written here and not in the theme, because only the
   dashboard draws it, as with the icons above. */
.tag-rare{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);letter-spacing:.08em;
  text-transform:uppercase;color:var(--warn);border:1px solid var(--warn);border-radius:3px;
  margin-left:8px}
/* .tag-fix is the CVE check's own mark, on a port for whose package a newer
   version fixes a CVE (docs/SPEC-cve-check.md, section 8.1): the same slim
   box in the neutral tone of the rate limit's mark. Not the warn tone and
   not counted under Needs a decision, because a fix that waits is common
   and the triangle is rare (docs/RECORD.md 4.446). Written here and not in
   the theme, as with .tag-rare. */
.tag-fix{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);letter-spacing:.08em;
  text-transform:uppercase;color:var(--faint);border:1px solid var(--line2);border-radius:3px;
  margin-left:8px}
/* The slim box and its icon's place, the same declarations as the four marks
   above. A rule of its own, so the rule above stays the four it was decided
   for. app/test_cve_card.py holds the two to one text. */
.tag-fix{display:inline-block;position:relative;box-sizing:content-box;
  width:13px;height:13px;padding:3px 4px;overflow:hidden;text-indent:200%;white-space:nowrap;
  vertical-align:middle;cursor:default;line-height:13px}
.tag-fix::before{content:"";position:absolute;
  left:4px;top:3px;width:13px;height:13px;background:currentColor}
__MARK_ICON_RULES__
/* The turning mark beside a server's Probed fact, drawn only while the cell
   says probing. The Add server window's keyframes turn it, and the blanket
   reduced-motion rule in the theme stops it. */
.pspin{display:none;width:13px;height:13px;margin-right:6px;vertical-align:-2px;color:var(--faint)}
.pspin .ic{display:block;width:13px;height:13px}
.f.probing .pspin{display:inline-block;animation:arr-turn .9s linear infinite}
.prst{display:flex;flex-wrap:nowrap;gap:4px;align-items:center}
.prst .tag-rate,.prst .tag-rare,.prst .tag-fix{margin-left:0}
.prn{font-family:"IBM Plex Mono",monospace;color:var(--ink-str);font-weight:600}
.prn small{font-size:var(--fs-micro);color:var(--faint);font-weight:400;margin-left:5px;text-transform:uppercase}
.prs{font-size:var(--fs-meta);color:var(--ink);font-weight:600}
.prs.note{color:var(--faint);font-weight:400}
/* A declared name says who declared it, in small grey after the name, and
   the measured process stays beside it (docs/PRODUCT.md 8b). */
.prs .by{display:block;font-size:var(--fs-micro);color:var(--faint)}
.prf{display:inline-flex;gap:5px}
.prf i{display:inline-block;padding:2px 7px;border-radius:4px;border:1px solid var(--line);color:var(--faint);
  font-style:normal;font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro)}
.prf i.ok{border-color:var(--ok-mark);color:var(--ok)}
.prf i.fail{border-color:var(--fail);color:var(--fail)}
.prf i.warn{border-color:var(--warn);color:var(--warn)}
.prw{font-size:var(--fs-meta);color:var(--faint)}
.pra{display:flex;justify-content:flex-end;align-items:center;gap:6px}
.pra .or{font-size:var(--fs-meta);color:var(--faint);margin-right:8px}
.ans{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);letter-spacing:.04em;
  text-transform:uppercase;color:var(--muted);background:none;border:1px solid var(--line);
  border-radius:4px;padding:3px 9px;cursor:pointer}
.ans:disabled{opacity:.45;cursor:not-allowed}
.ans.pick{background:var(--acc-fill);color:var(--on-fill);border-color:transparent}
/* A picked NO is neutral, the fill a picked LATER has. It was the fail tint
   until 2026-09-20, when the owner pointed out that answering no is not wrong,
   which is what red implies. No is an answer. Red belongs to
   the state tag beside it, which is where a conflict is said
   (docs/RECORD.md 4.189). */
.ans.no.pick,.ans.later.pick{background:var(--panel2);color:var(--ink);border-color:var(--line2)}
.pra.settled .ans:not(.pick){display:none}
.prsel:checked+.pr .pra.settled .ans{display:inline-block}
.pra.quiet .ans,.pra.quiet .or{visibility:hidden}
.prsel:checked+.pr .pra.quiet .ans,.prsel:checked+.pr .pra.quiet .or{visibility:visible}
.prc{justify-self:end;color:var(--faint);display:inline-flex;transition:transform var(--quick) var(--ease)}
.prsel:checked+.pr .prc{transform:rotate(180deg);color:var(--muted)}
/* The opened row: two cards, one per family. The 10px radius is the one
   place on the page with it (SPEC.md, how it looks). */
/* the day of an answer, under the two family cards of an opened row */
.prwhen{grid-column:1/-1;display:flex;gap:10px;align-items:baseline;font-size:var(--fs-meta)}
.prwhen .k{color:var(--faint)}
.prwhen .v{font-family:"IBM Plex Mono",monospace;color:var(--muted)}
.pre{display:none;grid-template-columns:1fr 1fr;gap:12px;border-bottom:1px solid var(--line);
  background:color-mix(in srgb,var(--panel2) 60%,transparent);padding:4px 20px 16px 20px}
.prsel:checked+.pr+.pre{display:grid}
.prec{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 16px}
.preh{display:flex;align-items:center;gap:10px;padding-bottom:8px;border-bottom:1px solid var(--line);
  margin-bottom:4px}
.preh .lead{font-size:var(--fs-body);color:var(--ink);font-weight:500}
.prec .l{display:grid;grid-template-columns:72px 1fr;gap:12px;padding:6px 0;font-size:var(--fs-meta);
  color:var(--muted)}
.prec .l .k{color:var(--faint)}
.prec .mono{font-family:"IBM Plex Mono",monospace;color:var(--ink-str);font-weight:400}
/* The opened row's line for the rarely-public mark (docs/RECORD.md 4.274),
   across both cards: the mark's words in its warn tone with Dismiss, or faint
   with the grey dismissed tag and Restore once a person dismissed it. */
/* The CVE check's strip under a port's two family cards: the whole width,
   a label column wide enough for "update fixes", the CVE ids in rows under
   their count, and whose data it is in the faint tone. */
.prpk{grid-column:1/-1}
.prpk .l{grid-template-columns:96px 1fr}
.prpk .cves{display:flex;flex-wrap:wrap;gap:2px 16px;margin-top:6px}
.prpk .of{color:var(--faint)}
.prpk a.src{color:inherit;text-decoration:underline;text-underline-offset:2px}
.prpk .sep{color:var(--faint);margin:0 8px}
.prmk{grid-column:1/-1;display:flex;align-items:center;flex-wrap:wrap;gap:8px 12px;
  padding:4px 2px 0;font-size:var(--fs-meta);color:var(--warn)}
.prmk .w{display:inline-flex;align-items:center;gap:6px}
.prmk .w .ic{width:14px;height:14px;flex:none}
.prmk.off{color:var(--faint)}
/* The CVE check's line under its strip: the mark's own neutral tone, never
   the warn tone of the line above. */
.prmk.fix{color:var(--muted)}
.prmk.fix.off{color:var(--faint)}
.prmk .btn{margin-left:auto}
/* On a phone the port table is wider than the screen and clipped at its
   edge, so the line wraps inside what the screen shows and its button stays
   in reach under the words. */
@media(max-width:640px){.prmk{max-width:calc(100vw - 92px)}}
/* ---- the Rules tab (docs/screens/host-rules/SPEC.md) ----
   One bordered list per firewall, in the order a packet from outside meets
   them. A rule opens on its checkbox, the same mechanism the port table above
   uses, so this tab needs no script either. */
.fw{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);
  overflow:hidden;margin-top:14px}
.fwh{display:flex;align-items:center;gap:12px;padding:0 20px;height:56px;
  background:var(--panel2);border-bottom:1px solid var(--line)}
.fwh .nm{display:flex;align-items:center;gap:10px;font-weight:600;color:var(--ink);
  font-size:var(--fs-meta)}
.fwh .nm svg{color:var(--ink)}
.fwh .nm small{font-weight:400;color:var(--faint);margin-left:4px;
  font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro)}
/* The firewall's own defaults, at the far right of its row. */
.fwh .df{font-size:var(--fs-micro);color:var(--muted);margin-left:auto}
.fwh .df b{color:var(--ink);font-weight:500;margin-right:12px}
.fwh .df b:last-child{margin-right:0}
.rsel{position:absolute;width:1px;height:1px;opacity:0;margin:0;pointer-events:none}
.rh,.fwr{display:grid;grid-template-columns:28px 110px 170px minmax(0,1fr) 22px;
  gap:16px;align-items:center}
.rh{padding:9px 20px;border-bottom:1px solid var(--line);
  background:color-mix(in srgb,var(--panel2) 45%,transparent)}
.rh span{font-size:var(--fs-micro);letter-spacing:.06em;text-transform:uppercase;
  color:var(--faint)}
.fwr{padding:0 20px;height:50px;border-bottom:1px solid var(--line);cursor:pointer;
  color:inherit;transition:background var(--quick) var(--ease)}
.fwr:hover{background:color-mix(in srgb,var(--panel2) 55%,transparent)}
.fw>.fwr:last-child{border-bottom:0}
.rsel:checked+.fwr{background:var(--panel2);border-bottom:0}
.fwr .ix{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);color:var(--faint)}
/* The action is a neutral tag: this tab reports what a rule says and never
   whether it is a good one. */
.fwr>.st{justify-self:start;color:var(--ink);border-color:var(--line2)}
.fwr>.st.deny{color:var(--muted)}
.rpn{font-family:"IBM Plex Mono",monospace;font-weight:600;color:var(--ink-str)}
.rpn small{font-size:var(--fs-micro);color:var(--faint);font-weight:400;margin-left:5px;
  text-transform:uppercase}
.rpn small i{font-style:normal;text-transform:none}
.rpn small i.v6{color:var(--ink);font-weight:600}
/* "any port" is ours, not a number a firewall printed, so it leaves the mono
   face and the weight behind. */
.rpn.any{font-weight:400;color:var(--muted);font-family:"Work Sans",system-ui,sans-serif}
/* The same size and weight as a service name on the Overview and the
   Evidence tab, so a rule reads as one line of the product rather than a
   heading (the owner, 2026-09-10). */
.rfr{font-size:var(--fs-meta);font-weight:600;color:var(--ink-str)}
.rfr.addr{font-family:"IBM Plex Mono",monospace}
.rfr small{color:var(--faint);margin-left:8px;font-size:var(--fs-micro);font-weight:400;
  font-family:"Work Sans",system-ui,sans-serif}
/* The tag rides inside the from cell, so it takes the cell's baseline
   rather than the row's. */
.rfr .st{margin-left:10px;padding:2px 6px;vertical-align:middle}
.fwr .cv{justify-self:end;color:var(--faint);display:inline-flex;
  transition:transform var(--quick) var(--ease)}
.rsel:checked+.fwr .cv{transform:rotate(180deg);color:var(--muted)}
/* The opened rule: one card, and only the firewall's own words. The kernel's
   copy of a ufw rule is the same fact in another dialect and belongs on the
   packet path (the owner asked on 2026-09-09 why the kernel was there as well). */
.rev{display:none;border-bottom:1px solid var(--line);
  background:color-mix(in srgb,var(--panel2) 60%,transparent);padding:4px 20px 16px}
.rsel:checked+.fwr+.rev{display:block}
.fw>.rev:last-child{border-bottom:0}
/* One grey line, for a layer with nothing in it to list. */
.fwline{font-size:var(--fs-meta);color:var(--muted);padding:16px 20px}
/* firewalld's zones that are not in effect: a row of the block that opens,
   never a box inside the block, so the rules under it stand in the block's
   own columns. */
.fw>.fs{border:0;border-radius:0;margin-top:0;background:none}
.fw>.fs summary,.fw>.fs[open] summary{padding:12px 20px;border-radius:0}
.fw>.fs .fold-b{padding:0}
.fw>.fs .fold-b>.rev:last-child{border-bottom:0}
/* The name a window asks to be typed, in a chip that copies it. Mono and
   bold because it is the machine's own name, and the copy glyph faint until
   the chip is pointed at. */
.cfchip{display:inline-flex;align-items:center;gap:7px;padding:3px 9px;margin:0 3px;
  border:1px solid var(--line2);border-radius:6px;background:var(--panel2);
  color:var(--ink-str);cursor:pointer;font:inherit;vertical-align:baseline}
.cfchip b.mono{font-family:"IBM Plex Mono",monospace;font-weight:600}
.cfchip svg{color:var(--faint);transition:color var(--quick) var(--ease)}
.cfchip:hover svg{color:var(--ink)}
/* ---- the Packet path tab (docs/screens/host-packet-path/SPEC.md) ----
   One box per tool, in the order a packet from outside meets them, the wire
   running through the middle of every box, and one panel under the flow for
   whichever box is selected.

   Every class here carries the `pt-` prefix. The sketch's own names are very
   short and three of them are already taken: `.ic` is the class theme.icon
   puts on every glyph, so `.end .ic{width:40px}` would have resized the
   glyphs themselves, and `.mk`, `.st` and `.t` are all in use. */
/* The selection radios. Kept in the layout but invisible, never
   display:none, so a keyboard can still reach them, exactly as the tab
   radios above are. */
.ptsel{position:absolute;width:1px;height:1px;opacity:0;margin:0;pointer-events:none}
/* The port picker and the measurement line belong together: the chips choose
   the port and the line says what was measured on it. So the pair is spaced
   away from the tab row above and kept tight to each other, rather than
   reading as a second row of tabs stuck under the first. */
.pw{margin-top:20px}
.pw .ppick{margin:0 0 2px}
.pt-meas{display:flex;align-items:center;gap:12px;margin-top:16px;
  font-size:var(--fs-meta);color:var(--ink);flex-wrap:wrap}
.pt-meas .rpn{font-size:var(--fs-body)}
.pt-sep{width:1px;height:16px;background:var(--line)}
/* the three columns: the outside, the tools, the service */
.pt-flow{position:relative;display:grid;
  grid-template-columns:184px 1px minmax(0,1fr) 1px 204px;column-gap:26px;
  margin-top:18px;padding:14px 0 10px}
.pt-flow>svg.pt-wire{position:absolute;left:0;top:0;pointer-events:none;
  overflow:visible;z-index:0}
.pt-dv{align-self:stretch;
  background:linear-gradient(transparent,var(--line) 16%,var(--line) 84%,transparent)}
.pt-end{position:relative;z-index:1;display:flex;align-items:center;gap:12px;
  height:58px;min-width:0}
/* The left column sits level with the first row of tools and the right with
   the last, so the wire enters top left and leaves bottom right. */
.pt-endL{align-self:start;flex-direction:row-reverse;justify-content:flex-start}
.pt-endL .pt-tx{text-align:right}
.pt-endR{align-self:end;cursor:pointer}
.pt-tile{position:relative;width:40px;height:40px;border-radius:11px;
  background:var(--panel);border:1px solid var(--line);display:flex;
  align-items:center;justify-content:center;color:var(--muted);flex:none;
  transition:border-color var(--quick) var(--ease),color var(--quick) var(--ease)}
.pt-tx{min-width:0}
.pt-l{display:block;font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);
  letter-spacing:.08em;text-transform:uppercase;color:var(--faint)}
/* The name beside the tile has 152px. One that needs more takes a second
   line and is cut after that one, where it used to be cut on its first, so a
   process name of twenty characters reads whole (docs/RECORD.md 4.355). The
   column keeps its width, because both ends of a path stay where they are
   whatever stands in them. `anywhere` is for an address written out in
   full, which has no hyphen and no space to break at. */
.pt-v{display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:2;
  font-size:var(--fs-body);font-weight:600;color:var(--ink-str);
  margin-top:2px;overflow:hidden;overflow-wrap:anywhere}
/* The small line under the name takes a second line the same way. A
   container's "podman, 80/tcp in the container" needs 205px of the 152 and
   was cut on its one line, measured 2026-10-11 beside the name of
   docs/RECORD.md 4.355. */
.pt-s{display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:2;
  font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);
  color:var(--faint);margin-top:1px;overflow:hidden;overflow-wrap:anywhere}
/* the tools, in a row that wraps like text */
.pt-mid{position:relative;z-index:1;display:flex;flex-wrap:wrap;gap:46px 34px;
  align-content:flex-start}
.pt-nd{position:relative;display:flex;align-items:center;gap:11px;width:204px;
  height:58px;padding:0 14px;box-sizing:border-box;background:var(--panel);
  border:1px solid var(--line);border-radius:10px;cursor:pointer;
  transition:border-color var(--quick) var(--ease)}
.pt-nd:hover{border-color:var(--line2)}
.pt-nd .pt-mk{display:flex;color:var(--ink);flex:none}
.pt-nt{min-width:0}
.pt-nn{display:block;font-size:var(--fs-meta);font-weight:600;color:var(--ink-str);
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pt-nc{display:block;font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);
  color:var(--muted);margin-top:3px;white-space:nowrap;overflow:hidden;
  text-overflow:ellipsis}
/* the tool the document says ends the journey */
.pt-nd.pt-stop{border-color:var(--warn);
  box-shadow:0 0 0 4px color-mix(in srgb,var(--warn) 12%,transparent)}
.pt-nd.pt-stop .pt-nc{color:var(--warn)}
.pt-nd.pt-stop.pt-pulse::after{content:'';position:absolute;inset:-4px;
  border-radius:13px;border:2px solid var(--warn);animation:pt-ring .75s ease-out forwards}
/* a tool the packet never meets: the packets are seen passing straight through */
.pt-nd.pt-ghost{background:transparent;border-style:dashed;opacity:.6}
.pt-nd.pt-ghost .pt-mk{color:var(--muted)}
/* ---- the wire, and the packets on it ----
   The packets are flown by CSS along the wire the script laid, rather than
   positioned by a script on every frame. Three reasons, and the first is the
   one that matters: a frame loop that runs for as long as the page is open
   costs a frame of work forever, on a page that is otherwise still. The
   second is that it keeps running when nothing is driving frames, which is
   how this was found: headless Chrome produced two frames in one and a half
   seconds and the packets stood still. The third is that a browser animates
   this off the main thread and a script cannot.

   The script's only job is geometry: it hands each packet the path and the
   duration, because only the browser knows where a wrapped row of boxes
   landed. */
.pt-dl{fill:none;stroke:var(--line2);stroke-width:1.6;stroke-dasharray:2 7;
  stroke-linecap:round;animation:pt-run 10s linear infinite}
@keyframes pt-run{to{stroke-dashoffset:-108}}
.pt-dl.pt-quiet{stroke:var(--line);opacity:.55;animation:none}
.pt-tmp{fill:none;stroke:none}
/* `--pt-dur` is the time one packet takes end to end, set per flow from the
   wire's own length so every path runs at the same speed whatever its
   shape. `--pt-beat` is that divided by the packets on it, which is how
   often one arrives. */
.pt-pk{fill:var(--acc);filter:drop-shadow(0 0 3px color-mix(in srgb,var(--acc) 70%,transparent));
  transform-box:view-box;offset-rotate:0deg;offset-distance:0%;opacity:0;
  animation:pt-fly var(--pt-dur,7s) linear infinite}
@keyframes pt-fly{
  0%{offset-distance:0%;opacity:0}
  5%{opacity:1}
  94%{opacity:1}
  100%{offset-distance:100%;opacity:0}}
/* Nothing came back and nothing accounts for it: the packets fade along the
   way and nothing is marked. */
.pt-lost .pt-pk{animation-name:pt-fade}
@keyframes pt-fade{
  0%{offset-distance:0%;opacity:0}
  6%{opacity:.95}
  70%{opacity:0}
  100%{offset-distance:100%;opacity:0}}
.pt-none .pt-pk{display:none}
.pt-none .pt-dl{stroke:var(--line);animation:none}
/* The one place the drawing shows a result: the service's tile rings as a
   packet lands, and the tool that ends the journey rings as one stops in it.
   Both beat on the packets' own cycle rather than on a script's callback. */
.pt-reach .pt-endR .pt-tile{border-color:color-mix(in srgb,var(--ok) 50%,var(--line));
  color:var(--ink)}
.pt-reach .pt-endR .pt-tile::after,.pt-stopf .pt-nd.pt-stop::after{
  content:'';position:absolute;inset:-3px;border-radius:13px;opacity:0;
  animation:pt-beat var(--pt-beat,1.4s) ease-out infinite}
.pt-reach .pt-endR .pt-tile::after{border:2px solid var(--ok)}
.pt-stopf .pt-nd.pt-stop::after{inset:-4px;border-radius:13px;
  border:2px solid var(--warn)}
@keyframes pt-beat{
  0%{opacity:.95;transform:scale(1)}
  20%{opacity:0;transform:scale(1.35)}
  100%{opacity:0;transform:scale(1.35)}}
.pt-stopf .pt-endR,.pt-lost .pt-endR,.pt-none .pt-endR,
.pt-refused .pt-endR{opacity:.55}
/* A reduced-motion setting stops the dots and the flowing wire and leaves the
   rest (SPEC.md). */
@media (prefers-reduced-motion:reduce){
  .pt-dl{animation:none}
  .pt-pk{display:none}
  .pt-reach .pt-endR .pt-tile::after,.pt-stopf .pt-nd.pt-stop::after{animation:none}}
/* the detail view, in the Rules tab's language */
.pt-under{display:none;background:var(--panel);border:1px solid var(--line);
  border-radius:10px;margin-top:14px;overflow:hidden}
.pt-uh{display:flex;align-items:center;gap:11px;padding:16px 20px 14px;flex-wrap:wrap}
.pt-uh .pt-mk{display:flex;color:var(--ink)}
.pt-uh h3{margin:0;font-family:"Space Grotesk",sans-serif;font-size:var(--fs-lead);
  font-weight:600}
.pt-role{font-size:var(--fs-meta);color:var(--faint)}
.pt-where{margin-left:auto;font-family:"IBM Plex Mono",monospace;
  font-size:var(--fs-micro);color:var(--faint)}
.pt-uf{display:flex;gap:40px;padding:4px 20px 18px;flex-wrap:wrap}
.pt-uf .pt-k{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);
  letter-spacing:.06em;text-transform:uppercase;color:var(--faint);margin-bottom:6px}
.pt-uf .pt-fv{display:flex;align-items:center;gap:10px;font-size:var(--fs-body);
  font-weight:600;color:var(--ink-str)}
.pt-uf .pt-fv.pt-no{color:var(--muted);font-weight:500}
.pt-uf .pt-fv .mono{font-family:"IBM Plex Mono",monospace}
.pt-urh,.pt-urr{display:grid;grid-template-columns:30px 100px 190px minmax(0,1fr);
  gap:16px}
.pt-urh{padding:9px 20px;border-top:1px solid var(--line);
  border-bottom:1px solid var(--line);
  background:color-mix(in srgb,var(--panel2) 45%,transparent)}
.pt-urh span{font-size:var(--fs-micro);letter-spacing:.06em;text-transform:uppercase;
  color:var(--faint)}
/* Every rule the tool holds, this port's in ink and the others faint. */
.pt-urr{align-items:center;padding:0 20px;min-height:46px;
  border-bottom:1px solid var(--line);opacity:.5}
.pt-urr:last-child{border-bottom:0}
.pt-urr.pt-hit{opacity:1;background:color-mix(in srgb,var(--acc) 5%,transparent)}
.pt-urr .pt-ix{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);
  color:var(--faint)}
.pt-urr>.st{justify-self:start}
.pt-urr .pt-fr{font-size:var(--fs-meta);font-weight:600;color:var(--ink-str)}
/* the tool's own line for the rule that matters, under it */
.pt-urr .pt-q{grid-column:2 / -1;font-family:"IBM Plex Mono",monospace;
  font-size:var(--fs-micro);color:var(--muted);padding:0 0 12px;margin-top:-6px}
.pt-urr .pt-q b{font-family:"Work Sans",system-ui,sans-serif;font-weight:400;
  color:var(--faint);margin-right:10px}
/* The first-look window. */
.fv .modal{width:min(720px,94vw)}
.fv-s{font-size:var(--fs-meta);color:var(--muted);margin:-8px 0 14px}
.fv-g{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);letter-spacing:.06em;
  text-transform:uppercase;color:var(--faint);padding:12px 0 6px}
.fv-r{display:grid;grid-template-columns:96px 1fr auto;gap:14px;align-items:center;padding:9px 0;
  border-top:1px solid var(--line)}
.fv-r .sv{font-size:var(--fs-meta);color:var(--ink)}
.fv-r .sv small{color:var(--faint);margin-left:8px}
.fv-note{font-size:var(--fs-meta);color:var(--faint)}
/* the gutter beside a quoted rule. Everything we know goes here and nothing we
   know is woven into the rule text, so the quote stays a quote (Rules round,
   design 1, chosen 2026-08-19). */
.rule{position:relative}
.rule-gutter{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}
.gt{font-size:var(--fs-micro);border-radius:3px;padding:2px 7px;white-space:nowrap;
  border:1px solid var(--line2);color:var(--faint)}
.gt.wrote{border-style:dashed}
.gt.hazy{border-color:var(--warn);color:var(--warn);white-space:normal}
/* the port a rule provably names. Mono, because it is a port, and accent
   because it is the one thing in the gutter the reader came looking for. */
.gt.port{border-color:var(--acc-line);color:var(--acc-ink);
  font-family:"IBM Plex Mono",monospace}
/* the packet path as gates: connected blocks in kernel order. A block names a
   checkpoint and says nothing about what happened to the packet (PRODUCT.md 4g). */
.gates{display:flex;align-items:stretch;flex-wrap:wrap;margin-top:4px}
.gates .gate{position:relative;border:1px solid var(--line2);border-right:0;
  background:var(--panel);padding:10px 16px 10px 22px;flex:1 1 140px;min-width:118px;
  font-family:inherit;text-align:left}
.gates .gate:first-child{border-radius:var(--r) 0 0 var(--r);padding-left:14px}
.gates .gate:last-child{border-right:1px solid var(--line2);
  border-radius:0 var(--r) var(--r) 0}
.gates .gate:after{content:"";position:absolute;right:-8px;top:50%;width:14px;height:14px;
  margin-top:-7px;background:inherit;border-top:1px solid var(--line2);
  border-right:1px solid var(--line2);transform:rotate(45deg);z-index:2}
.gates .gate:last-child:after{display:none}
.gates .gk{font-size:var(--fs-micro);letter-spacing:.1em;text-transform:uppercase;
  color:var(--faint)}
.gates .gn{font-size:var(--fs-meta);color:var(--ink-str);font-weight:600;margin-top:3px;
  line-height:1.3}
.gates .gr{font-size:var(--fs-micro);color:var(--faint);margin-top:3px;
  font-family:"IBM Plex Mono",monospace}
.gates label.gate{cursor:pointer;transition:all var(--quick) var(--ease)}
.gates label.gate:hover{background:var(--hover)}
.gates .gate.q{flex:0 1 104px;min-width:72px;background:var(--bg)}
.gates .gate.q:after{background:var(--bg)}
.gates .gate.q .gn{color:var(--faint);font-weight:400;font-size:var(--fs-meta)}
/* The technical chain name, under the plain words. Quieter and smaller, and
   deliberately still there: it is what every other tool calls this chain and
   what an operator greps their own ruleset for. */
.gates .gn-t{font-size:var(--fs-micro);color:var(--faint);font-weight:400;
  font-variant-numeric:tabular-nums;margin-top:1px}
.gates .gate.hot{background:var(--fail-soft);border-color:var(--fail);flex-grow:2}
.gates .gate.hot:after{background:var(--fail-soft);border-color:var(--fail)}
.gates .gate.hot .gn{color:var(--fail)}
.gates .gate.new{border-color:var(--warn);flex-grow:2}
.gates .gate.new .gn{color:var(--warn)}
.gates .gate.good .gn{color:var(--ok)}
/* the routing decision: on the rail because the packet meets it, not clickable
   because it is not a checkpoint and holds no rules */
.gates .gate.fork{flex:0 1 132px;background:var(--acc-bg);border-color:var(--acc-line)}
.gates .gate.fork:after{background:var(--acc-bg);border-color:var(--acc-line)}
.gates .gate.fork .gn{color:var(--acc-ink)}
.gates-ends{display:flex;justify-content:space-between;font-size:var(--fs-micro);
  color:var(--faint);margin-top:8px}
/* the panel a gate opens. Closed is the default and closed is the design: the
   default screen is the say line and the rail, nothing else (the Gates round's
   brief). The radio mechanics are in walk_css at the bottom of this block. */
.rr{position:absolute;width:1px;height:1px;opacity:0;margin:0;pointer-events:none}
.pans>.pan{display:none;margin-top:14px;background:var(--panel);
  border:1px solid var(--line2);border-radius:var(--r);padding:16px 18px}
.pan-h{display:flex;align-items:baseline;gap:11px;flex-wrap:wrap;margin-bottom:11px}
.pan-n{font-size:var(--fs-body);color:var(--ink-str);font-weight:600}
/* Same pairing in the open panel, where the reader actually lands. */
.pan-t{font-size:var(--fs-meta);color:var(--faint);font-weight:400}
.pan-w{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);color:var(--faint)}
.pan-x{font-size:var(--fs-meta);color:var(--muted);margin-top:10px;line-height:1.5;
  max-width:86ch}
.pan-c{margin-left:auto;font-size:var(--fs-meta);color:var(--acc-ink);cursor:pointer}
.pan-c:hover{text-decoration:underline}
.rulebox{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--muted);
  background:var(--panel2);border:1px solid var(--line);border-radius:6px;
  padding:8px 11px;overflow-x:auto;white-space:pre;margin-top:6px}
.rulebox:first-of-type{margin-top:0}
/* the port selector above the walks, and the head line of one walk */
.ppick{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:0 0 16px}
.ppick .lbl{font-size:var(--fs-meta);color:var(--faint);margin-right:2px}
.ppick label{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);
  color:var(--muted);border:1px solid var(--line2);border-radius:6px;padding:5px 11px;
  cursor:pointer;transition:all var(--quick) var(--ease)}
.ppick label:hover{color:var(--ink);border-color:var(--faint)}
/* the first walk is visible with no selector machinery at all, so a missing
   or capped rule fails to a readable page rather than an empty one. A checked
   input takes over from there: its hide-all rule outweighs this. */
.walks>.walk:first-child{display:block}
.walkhead{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:9px}
.measured{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--faint)}
/* the one sentence a walk opens with. On the sample it is the finding, which
   is the join and the only thing allowed to name a layer. A live page has no
   finding yet and its say is what the document supports. */
.say{font-size:var(--fs-body);line-height:1.5;color:var(--ink);max-width:86ch;
  margin-bottom:20px}
.say b{color:var(--ink-str);font-weight:600}
.say.dim{color:var(--muted)}
.gw{margin-bottom:6px}
.gw-fam{font-size:var(--fs-micro);color:var(--faint);margin:18px 0 7px}
.fold-b{padding:4px 14px 14px}
.rnote{font-size:var(--fs-meta);color:var(--muted);margin-top:6px;padding-left:11px;
  border-left:1.5px solid var(--line2)}
/* ---- the port chip on the host overview: the port number and the two bars
   under it, v4 then v6 (docs/DESIGN.md section 1, the mark at port size). ---- */
.fam{display:grid;grid-template-columns:1fr 1fr;gap:2px}
.fam i{display:block;height:3px;border-radius:1px;background:var(--line2)}
/* not tested is hollow, and it is the only hollow thing on the row, so an
   untested family can never be read as a measured silence (PRODUCT.md 4b) */
.fam i.n{background:none;box-shadow:inset 0 0 0 1px var(--faint);opacity:.7}
/* No line-through on the port number. It read as removed or dead and the owner
   had to ask twice what it meant (docs/RECORD.md 4.102). The dashed border and
   the faint ink are the whole mark. */
.u-hot{color:var(--warn);font-weight:600}
.back{font-size:var(--fs-meta);color:var(--muted);display:inline-block;margin-bottom:16px;cursor:pointer;background:none;border:0;
  font-family:inherit;padding:0}
.back:hover{color:var(--ink)}
.hh{display:flex;align-items:flex-start;justify-content:space-between;gap:22px;flex-wrap:wrap}
.hh h1{display:flex;align-items:center;gap:13px;flex-wrap:wrap}
/* The state and its slim marks are one group beside the name, as close to
   each other as they are on the Fleet row, and they wrap together or not at
   all. */
.hh h1 .stset{display:inline-flex;align-items:center;gap:6px}
.hh h1 .stset .tag-mute,.hh h1 .stset .tag-alert,.hh h1 .stset .tag-rare,.hh h1 .stset .tag-fix{margin-left:0}
.hsub{color:var(--muted);font-size:var(--fs-meta);margin-top:8px}
.hsub .num{color:var(--ink)}
.subnav{display:flex;gap:24px;border-bottom:1px solid var(--line);margin-top:24px;flex-wrap:wrap}
.subnav label{font-size:var(--fs-meta);font-weight:600;color:var(--muted);padding:0 0 12px;position:relative;cursor:pointer;
  user-select:none;transition:color var(--quick) var(--ease)}
.subnav label:hover{color:var(--ink)}
.subnav label.planned{cursor:not-allowed}
.subnav label.planned:hover{color:var(--faint)}
/* The tab radios. Kept in the layout but invisible, never display:none, so a
   keyboard can still reach them and the arrow keys still move between tabs. */
.tabsel{position:absolute;width:1px;height:1px;opacity:0;margin:0;pointer-events:none}
.tab{display:none}
.sec{margin-top:26px}
.sech{display:flex;align-items:baseline;justify-content:space-between;margin-bottom:11px;gap:14px;
  flex-wrap:wrap}
/* A section heading is a label, not a headline. Every artboard chosen in the
   2026-08 rounds set it micro and faint (HOST_CSS .sech), and the panel below
   it carries the weight. */
.sech h2{font-family:inherit;font-weight:400;letter-spacing:0;
  font-size:var(--fs-micro);color:var(--faint)}
.sech .hint{font-size:var(--fs-meta);color:var(--faint)}
.tr{display:grid;grid-template-columns:18px 1fr;gap:14px;padding:0 20px;position:relative}
.tr:before{content:"";position:absolute;left:28px;top:0;bottom:0;width:1px;background:var(--line2)}
.tr:first-child:before{top:18px}
.tr:last-child:before{bottom:calc(100% - 18px)}
.tr-d{width:9px;height:9px;border-radius:50%;margin-top:16px;margin-left:4px;z-index:1;
  background:var(--panel);border:1.6px solid var(--off)}
.tr-fail .tr-d{border-color:var(--fail)}
.tr-warn .tr-d{border-color:var(--warn)}
.tr-b{padding:13px 0 15px;border-bottom:1px solid var(--line)}
.tr:last-child .tr-b{border-bottom:0}
.tr-h{display:flex;gap:13px;align-items:baseline;flex-wrap:wrap}
.tr-n{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-body)}
.tr-v{font-size:var(--fs-body);font-weight:500;color:var(--muted)}
.tr-fail .tr-v{color:var(--fail)}
.tr-warn .tr-v{color:var(--warn)}
.tr-r{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--muted);background:var(--bg);
  border:1px solid var(--line);border-radius:8px;padding:9px 12px;margin-top:9px;
  overflow-x:auto;white-space:pre}
.tr-note{font-size:var(--fs-meta);color:var(--faint);margin-top:8px;max-width:84ch}
/* The three views, as a grid you read across: the question down the left, one
   column per source. Three lists side by side could not be compared, which is
   the one thing this panel exists to do (docs/PRODUCT.md section 8). A column
   nothing has measured yet keeps its width and goes faint, so the empty half of
   the product is visible rather than absent. */
.agree{padding:13px 20px;border-top:1px solid var(--line);font-size:var(--fs-meta);color:var(--muted);
  background:var(--panel2)}
/* A ruleset: the conf as fields, then one group per chain, one row per rule. */
/* A conf file as one line rather than a grid of boxes: the treatment the
   chosen Rules artboard used. It wraps by whole fields, so a long key and its
   value can never be split down the middle the way the grid split SKIP. */
.cf{padding:11px 20px;background:var(--panel2);border-bottom:1px solid var(--line);
  font-size:var(--fs-meta);line-height:1.7}
.cf-l{color:var(--faint);margin-right:10px}
.cf-f{font-family:"IBM Plex Mono",monospace;color:var(--ink);
  white-space:nowrap;display:inline-block}
.rgrps{background:var(--panel);border-radius:0 0 8px 8px;overflow:hidden}
.rgrp-h{display:flex;align-items:baseline;gap:11px;flex-wrap:wrap;
  padding:9px 20px;background:var(--panel2);border-top:1px solid var(--line)}
.rgrp:first-child .rgrp-h{border-top:0}
.rgrp-n{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--ink)}
/* the plain name leads and the real one stays beside it, smaller and faint,
   because the technical name is what every other tool calls it (RECORD 4.71) */
.rgrp-p{font-size:var(--fs-meta);color:var(--ink-str);font-weight:600}
.rgrp-n.tech{font-size:var(--fs-micro);color:var(--faint)}
.rgrp-m{font-size:var(--fs-micro);color:var(--faint);margin-left:auto;text-align:right}
/* ---- one rule, annotated ----
   Two columns: the rule exactly as the agent read it on the left, and
   everything we know about it in the gutter on the right. Nothing we know is
   ever woven into the text, so the quote stays a quote and our labels can be
   wrong without making the ruleset wrong. Design 1 of the Rules round. */
.rule{display:grid;grid-template-columns:minmax(0,1fr) 236px;gap:0;
  border-top:1px solid var(--line)}
.rule:hover{background:var(--hover)}
.rule-t{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--muted);
  white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.65;padding:8px 18px;
  border-right:1px solid var(--line)}
.rule-gutter{display:flex;gap:6px;flex-wrap:wrap;align-items:flex-start;padding:8px 16px}
/* The operator's own note. The one thing on the row a person wrote for a person,
   so it reads as accent text and never as a status. */
.rule-c{grid-column:1/-1;font-size:var(--fs-meta);color:var(--acc-ink);
  padding:0 18px 9px}
/* the tab's own heading */
.rsum{font-size:var(--fs-body);line-height:1.5;color:var(--ink);max-width:88ch;
  margin-bottom:20px}
.rsum b{color:var(--ink-str);font-weight:600}
/* 170px matches the channel table's first column above, so the two panels on
   the Alerts screen start their second column at one x. 160px is what the
   longest delivery line needs at the meta size, measured rather than guessed:
   at 130px the longest of them wrapped and the row grew taller than its
   neighbour. The comment names no delivery line verbatim, because this
   stylesheet ships inside the page and a test reads the page for those. */
.lst{display:grid;grid-template-columns:170px 1fr 160px;gap:16px;padding:14px 20px;
  border-top:1px solid var(--line);align-items:start;font-size:var(--fs-body)}
.lst:first-of-type{border-top:0}
.lst .t{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--faint)}
.lst .y{font-size:var(--fs-meta);color:var(--faint);margin-top:4px}
/* A server's name in a list row, the same treatment the fleet row's .hn
   gives the same name. It used to force Space Grotesk, so one server read in
   the heading face on the Alerts screen and the body face on the fleet.
   docs/DESIGN.md section 1 keeps the heading face for headings, and a name in
   a table row is a value. */
.lst .hh2{font-weight:600;color:var(--ink-str)}
/* An open alert is the way to the port it names, so its row behaves like a
   fleet row: the whole of it is the target and it says so on hover. The fourth
   column is the menu, and an alert with no port to silence leaves it empty
   rather than drawing a control that would not work. */
.lst.acts{position:relative;grid-template-columns:170px 1fr 160px 26px;
  transition:background var(--quick) var(--ease)}
.lst.acts:hover{background:var(--hover)}
.lst.acts:before{content:"";position:absolute;left:0;top:0;bottom:0;width:2px;
  background:transparent;transition:background var(--quick) var(--ease)}
.lst.acts:hover:before{background:var(--acc)}
/* The stretched link. The button carries the host name and nothing else, so
   that is its accessible name, and this pulls its own box over the whole row
   so a click anywhere on the row lands on it. Wrapping the row in a button
   instead would have put the menu's button inside it, which is markup no
   browser is required to make sense of. */
.rowgo{background:none;border:0;padding:0;font:inherit;color:inherit;
  cursor:pointer;text-align:left}
/* Scoped to the alert row rather than left on .rowgo alone. `inset:0` fills
   the nearest positioned ancestor, and the only element guaranteed to be one
   is `.lst.acts` above. A .rowgo used somewhere else later would otherwise
   stretch over whatever happened to be positioned near it, which is a fault
   nobody would think to look for. Unscoped it would still be the button. */
.lst.acts .rowgo:after{content:"";position:absolute;inset:0}
/* Lifted above the stretch, or the menu is unreachable underneath it. */
.lst.acts .rmenu{z-index:2}
.lst-m{display:flex;justify-content:flex-end;align-items:start}
/* The silenced mark is written empty on every alert row and filled by the
   click, so a row nobody has silenced must not draw the empty box. The same
   rule `.tag-rvw` and `.tag-mute` carry in theme.py, kept here rather than
   beside them because this is the only feed that writes this tag empty and
   putting it there rebuilt seven artboards to say it. */
.lst.acts .tag-rate:empty{display:none}
/* The right-hand cell of a list row. Meta, like the timestamp on the left and
   the detail line in the middle: without it the cell fell through to .lst's
   body size and a row carried two timestamps at two sizes. `.row` already
   carries the same rule for the same reason. */
.right{text-align:right;display:flex;flex-direction:column;align-items:flex-end;gap:6px;
  font-size:var(--fs-meta)}
.ch2{display:grid;grid-template-columns:190px 1fr 150px;gap:16px;padding:14px 20px;
  border-top:1px solid var(--line);align-items:center;font-size:var(--fs-body)}
.ch2:first-of-type{border-top:0}
.ch2 .d{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--muted)}
/* The rename control in a server's settings: the field and its button share a
   line and wrap together when the panel is narrow. */
.rnr{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
/* ---- a configured channel, five columns (docs/RECORD.md #259) ----
   Wider than .ch2 because this row answers more: which channel, where it goes,
   whether it is on, how often it has fired, and the menu. The used column is
   right aligned so a column of numbers reads as a column. The last column is
   fixed and narrow, because a menu trigger that moves as labels change is a
   menu trigger you have to look for. */
.crow{display:grid;grid-template-columns:170px minmax(200px,1fr) 130px 110px 44px;
  gap:16px;padding:14px 20px;border-top:1px solid var(--line);align-items:center;
  font-size:var(--fs-body)}
/* A deleted row is hidden by setting the attribute, and `display:grid` above
   beats the browser's own [hidden] rule, so without this line the attribute
   does nothing at all and the row sits there until the page is reloaded. The
   same trap as `.rm-i[hidden]` and `.pm-menu[hidden]` below, and the third
   time it has been paid for. `test_every_row_the_script_hides_can_actually_be
   _hidden` is what stops a fourth. */
.crow[hidden]{display:none}
/* Sentence case, like every other table header in the product. It was the
   only uppercase one, so the same kind of thing read two ways on two
   screens. */
.crow-h{border-top:0;font-family:"Work Sans",sans-serif;font-size:var(--fs-micro);
  color:var(--faint);padding-bottom:9px}
.crow-h + .crow{border-top:1px solid var(--line)}
.crow .d{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--muted);
  word-break:break-all}
/* The operator's own word for this channel, under the destination it belongs
   to. Faint, because the destination is the fact and this is the name given
   to it. */
.crow-l{font-size:var(--fs-meta);color:var(--faint);margin-top:3px}
.crow-u{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--muted);
  text-align:right}
.crow-m{display:flex;justify-content:flex-end}
/* ---- the per-row menu ----
   A plain button and an absolutely positioned panel, opened by adding .on.
   No <details>, because two open menus at once on a list of channels is a
   mess and one script closing the others is simpler than making disclosure
   elements exclusive. */
/* .panel crops its children so the rounded corners hold, which is right for
   every other panel and wrong for this one: a menu opening from the last row
   was cut off at the panel's edge, which a screenshot caught. The rows here
   carry no background of their own, only a top border, so nothing needs
   cropping and letting the menu out costs nothing. */
/* When this page was rendered. Bottom left, faint, mono, and never a status:
   it is a fact about our own machinery. A reader who wants to know whether
   they are looking at the newest page reads this instead of guessing from
   whether anything looks different. */
/* A build stamp, pinned bottom-left. It carries its own background so it never
   sits illegibly over a fleet row mid-scroll, which it did while it was a
   transparent watermark (2026-08-30). The page bg is near-flat at the edges,
   so a --bg chip in the corner blends rather than reading as a box. */
.pgstamp{position:fixed;left:0;bottom:0;z-index:5;
  font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);
  color:var(--faint);background:var(--bg);padding:6px 12px 8px;
  border-top-right-radius:8px;pointer-events:none}
/* An optional field says so beside its label, in the shape .tag-planned uses,
   because both are the same kind of thing: a small neutral word qualifying a
   label without being a status (docs/DESIGN.md section 3). */
.opt{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);
  letter-spacing:.1em;text-transform:uppercase;color:var(--faint);
  border:1px solid var(--line2);border-radius:3px;padding:2px 7px;margin-left:8px}
.panel.chanp{overflow:visible}
/* ---- which alerts a channel takes ----
   One switch per row, title only (the owner had the description removed on
   2026-08-24). The title takes the row and the switch sits flush right,
   centred on the title line, so the three switches land in one column. */
.evs{display:flex;flex-direction:column;gap:2px;margin-top:4px}
.evb{display:flex;gap:10px;align-items:center;padding:9px 10px;border-radius:8px;
  cursor:pointer}
.evb:hover{background:var(--hover)}
.evb b{font-family:"Space Grotesk",sans-serif;font-weight:600;color:var(--ink-str);
  font-size:var(--fs-body);flex:1;min-width:0}
.rmenu{position:relative}
.rm-t{background:none;border:0;padding:5px;margin:-5px;cursor:pointer;color:var(--faint);
  display:inline-flex;border-radius:6px;transition:color var(--quick) var(--ease)}
.rm-t:hover{color:var(--ink)}
.rm-p{position:absolute;right:0;top:calc(100% + 6px);z-index:30;min-width:186px;
  background:var(--panel2);border:1px solid var(--line2);border-radius:9px;
  padding:5px;display:none;box-shadow:0 10px 30px rgba(0,0,0,.28)}
.rmenu.on .rm-p{display:block}
.rm-i{display:block;width:100%;text-align:left;background:none;border:0;cursor:pointer;
  font-family:inherit;font-size:var(--fs-meta);color:var(--ink);padding:8px 10px;
  border-radius:6px}
.rm-i:hover{background:var(--hover)}
/* An item that does not apply right now, which is Unmute on a server that is
   not muted. `display:block` above beats the browser's own [hidden] rule, so
   without this line the attribute does nothing at all. */
.rm-i[hidden]{display:none}
/* Delete takes the fail ink and nothing else. No fill and no border: it is the
   one item that cannot be undone, and that is worth one signal, not three. */
.rm-i[data-act="remove"]{color:var(--fail)}
/* Asking before something irreversible. Narrower than a working window,
   because it holds a question and two answers and nothing else. The confirming
   button carries the fail tone for the same reason Delete does in the row menu:
   the colour is the second channel and the word is the signal. */
.ask{width:min(420px,94vw)}
.ask-b{color:var(--muted);font-size:var(--fs-body);margin:2px 0 4px}
/* Soft fill, strong ink, same pairing every other tone uses here, rather than
   a solid --fail which is an ink colour and made a pale button with dark text
   on it. Screenshot caught that, no test would have. */
.btn.pri.ask-go{background:var(--fail-soft);border-color:var(--fail);color:var(--fail)}
.btn.pri.ask-go:hover{background:var(--fail-soft);border-color:var(--fail);
  color:var(--fail);filter:brightness(1.12)}
/* ---- Advanced settings ----
   The same disclosure shape .rs uses for a ruleset, so the page has one way of
   saying "there is more inside this". Centred, because in the reference it sits
   between the field and the footer and reads as a step you may skip. */
/* The other way of configuring a channel, folded away. Pasting the value is
   the ordinary route (the owner, 2026-08-22: the way every other product does
   it), and naming a variable is how the box is configured today, so it
   is kept and put second rather than removed. Same disclosure shape as
   Advanced settings, so the window has one way of saying there is more here. */
/* The mark sits inside the button, so it reads as the same channel as the card
   above it. `gap` rather than a margin on the glyph, because the button is a
   flex row and the label is the thing that should be centred. */
.m-connect{display:inline-flex;align-items:center;gap:9px;text-decoration:none;
  margin-bottom:4px}
.m-connect .ic{color:currentColor;flex:0 0 auto}
.m-alt{margin-top:12px}
.m-alt summary{list-style:none;cursor:pointer;color:var(--acc-ink);
  font-size:var(--fs-meta)}
.m-alt summary:hover{text-decoration:underline}
.m-alt summary::-webkit-details-marker{display:none}
.m-adv{margin-top:16px;border-top:1px solid var(--line);padding-top:14px}
/* No drawn marker on the summary. `test_css_content_is_a_word_or_nothing`
   holds the rule and it is the right one: a CSS escape in a content property
   is a glyph nobody can read in the source, and this project has already had
   one marker mean two things. The accent ink is what says it can be opened,
   the same signal every other link on the page uses. */
.m-adv summary{list-style:none;cursor:pointer;text-align:center;color:var(--acc-ink);
  font-size:var(--fs-meta)}
.m-adv summary:hover{text-decoration:underline}
.m-adv summary::-webkit-details-marker{display:none}
.m-adv-b{margin-top:14px}
/* A label whose control is not built carries the planned tag, and the tag is
   the same shape it is everywhere else (docs/DESIGN.md section 3). The label
   itself dims with it, so the pair reads as one unavailable thing. */
.m-label.planned{opacity:.5}
select.m-input{appearance:none;cursor:not-allowed}
/* ---- the port table on a host's Overview (direction A, chosen 2026-08-19) ----
   The fleet's port vocabulary carried down one level: state, the port and what
   holds it, both families from outside, and why. The state column is fixed
   rather than sized to its content, because the tags are different widths and
   an auto column would step in and out down the list. A live page has no state
   or why to put in those cells yet and leaves them empty rather than filling
   them with a word the prober has not earned. */
.pt-h,.pt{display:grid;gap:16px;align-items:center;
  grid-template-columns:118px minmax(160px,1fr) 140px minmax(190px,1.3fr) 116px 100px}
.pt-h{padding:9px 20px;border-bottom:1px solid var(--line);background:var(--panel2)}
.pt-h span{font-size:var(--fs-micro);color:var(--faint)}
.psvc{font-size:var(--fs-meta);color:var(--faint);margin-top:2px}
.pcause{font-size:var(--fs-meta);color:var(--ink);line-height:1.4}
/* The rule that decided, quoted verbatim under the sentence that names its
   layer (docs/RECORD.md 4.117). Mono because it is the host's own syntax, and
   it wraps rather than truncating: a rule cut in half is a rule that can be
   read to mean the opposite of what it says. The source sits after it in the
   faint ink the bind line already uses, so the row reads sentence, evidence,
   where the evidence came from. */
.pqr{font-family:"IBM Plex Mono",monospace;color:var(--ink);word-break:break-word}
.pqs{color:var(--faint);margin-left:8px}
.pbind{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);color:var(--faint);
  margin-top:3px}
/* one address family per line: the fleet chip's mark, then the word. The chip
   box is neutralised here because the row is the box. */
/* the Declared cell: what this port is meant to be, and the two words that
   say it. The primary act on the row, so it is a real control and not a link
   (the owner, 2026-08-28, did not like review being one button to click
   first). It is the segmented control the Probing settings
   already declare a port with, one step smaller so a table of them does not
   shout: micro type, tighter padding, the same shape a reader has already met.
   A column rather than a line, because withdrawing a declaration and a
   declaration the two families do not agree on both sit under it. */
.pdc{display:flex;flex-direction:column;align-items:flex-start;gap:5px}
/* what was declared when the two address families do not carry the same word.
   Written empty on every row and filled by the click, so an agreeing row
   draws nothing. */
.pdw{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);color:var(--faint)}
.pdw:empty{display:none}
/* the action column: the why link, the review mark and the control that files
   it, in that order, right aligned. Reviewing is a per-row act because an
   acknowledgement is about one finding (the owner, 2026-08-24), so the control
   lives here and not in the page header. It reads as the link beside it
   rather than as a button, because a button in every row of a four row table
   is four buttons competing with the one real button on the screen. */
.pt-rv{font-family:inherit;font-size:var(--fs-micro);color:var(--acc-ink);
  background:none;border:0;padding:0;cursor:pointer}
.pt-rv:hover:not(:disabled){text-decoration:underline}
.pt-rv:disabled{opacity:.45;cursor:not-allowed}
.pt-rv[hidden]{display:none}
/* the State cell. The state word leads and the rate flag sits under it: one
   left edge, one small gap. A flex column rather than wrapped inline spans,
   because wrapping kept the shared shape's side margin, which indented every
   wrapped fact and read as misaligned chips (the owner's screenshot,
   2026-08-25). The margin is zeroed for the same reason: it was written for
   sitting beside the state on one line.

   **The review mark is not in this cell and may never come back into it.**
   The owner, 2026-08-28: after a click both `unreviewed` and `read` showed,
   they cancel out, so nothing should be shown. `unreviewed` is a fact about
   the port and `read` is a fact about the reader, and stacked in one cell
   under one heading they read as two answers to the same question. The mark
   is in the action column now, where the click that files it is, so the
   State cell answers State and nothing else. */
/* The mark is written empty on every row and filled by the click, and an
   empty one is not drawn. Said again for the port table because the shared
   rule sits earlier in the sheet and a later margin rule can tie it on
   specificity. */
/* One act, one place. The control is written on every row that has a finding
   and the mark takes its place the moment one is filed, so a row never offers
   `mark read` and wears `read` at the same time. It is CSS rather than a
   removal in the handler because a declaration can change the state, which
   lapses the acknowledgement, and then the control has to come back. */
/* a refused review, on the row it was refused for. Full width because the
   action column is 104 pixels and a sentence is not. Empty on every other row
   and on every row until something is refused, and an empty one is not drawn
   at all, so it costs no grid row. */
.prvw{grid-column:1/-1;font-size:var(--fs-meta);color:var(--fail);margin-top:2px}
.prvw:empty{display:none}
/* a configured channel or integration: its glyph beside its name, so a short
   list still reads as a set of destinations rather than a column of words. The
   glyph stays faint, because the name is the signal and the shape is the
   second channel (docs/DESIGN.md section 3). */
.nm{display:flex;align-items:center;gap:9px}
.nm .ic{color:var(--faint);flex:0 0 auto}
.nm b{font-family:"Space Grotesk",sans-serif;font-weight:600;color:var(--ink-str)}
.sw{width:34px;height:19px;border-radius:99px;background:var(--acc-fill);position:relative;
  border:0;cursor:pointer;flex:0 0 auto}
.sw:after{content:"";position:absolute;top:2px;left:17px;width:15px;height:15px;border-radius:50%;
  background:#fff;transition:left var(--quick) var(--ease)}
.sw.off{background:var(--line2)}
.sw.off:after{left:2px}
.sw:disabled{opacity:.45;cursor:not-allowed}
.pl{display:grid;grid-template-columns:230px 1fr;gap:16px;padding:14px 20px;
  border-top:1px solid var(--line);align-items:start}
.pl:first-of-type{border-top:0}
.pl b{font-family:"Space Grotesk",sans-serif;font-weight:600;color:var(--ink-str);
  display:flex;align-items:center;flex-wrap:wrap}
.pl span{font-size:var(--fs-meta);color:var(--faint);line-height:1.6}
.code{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);background:var(--bg);
  border:1px solid var(--line);border-radius:9px;padding:14px 16px;overflow-x:auto;
  white-space:pre;color:var(--muted);margin-top:12px}
.code b{color:var(--ink);font-weight:400}
.fn{margin-top:28px;font-size:var(--fs-meta);color:var(--faint);max-width:90ch;line-height:1.75}
.fn b{color:var(--muted)}
.view{display:none}.view.on{display:block}
/* A view that is switched to arrives: it fades in and rises 6px in `move`.
   On the class the script already sets, so the script knows nothing of it.
   No fill word: an element that kept its last frame would keep a transform,
   and the pinned top bar would then be placed against the view and not the
   browser window (docs/DESIGN.md section 5, docs/RECORD.md 4.416, 4.419). */
.view.on{animation:v-in var(--move) var(--ease)}
@keyframes v-in{from{opacity:0;transform:translateY(6px)}}
.toast{position:fixed;left:50%;bottom:28px;transform:translateX(-50%) translateY(80px);
  background:var(--panel2);border:1px solid var(--line2);color:var(--ink);font-size:var(--fs-body);
  padding:11px 18px;border-radius:99px;z-index:60;opacity:0;pointer-events:none;
  transition:all var(--move) var(--ease)}
.toast.on{opacity:1;transform:translateX(-50%) translateY(0)}
.ovl{position:fixed;inset:0;background:color-mix(in srgb,var(--bg) 62%,transparent);
  backdrop-filter:blur(3px);z-index:50;display:none;align-items:center;justify-content:center;
  padding:24px}
.ovl.on{display:flex}
/* A window that is opened: the page behind dims in `quick`, the window
   rises 8px from just under its size in `move`. No fill word here either,
   for the foot that stays at the window's bottom (4.416, 4.419). */
.ovl.on{animation:o-in var(--quick) var(--ease)}
.ovl.on .modal{animation:m-in var(--move) var(--ease)}
@keyframes o-in{from{opacity:0}}
@keyframes m-in{from{opacity:0;transform:translateY(8px) scale(.985)}}
.modal{width:min(600px,94vw);max-height:88vh;overflow-y:auto;padding:22px 24px 20px;
  border-color:var(--line2)}
.m-h{display:flex;align-items:baseline;justify-content:space-between;gap:14px;margin-bottom:16px}
.m-h h2{font-size:var(--fs-lead)}
.m-x{background:none;border:0;padding:4px;margin:-4px;cursor:pointer;color:var(--faint);
  display:inline-flex;border-radius:6px;transition:color var(--quick) var(--ease)}
.m-x:hover{color:var(--ink)}
.m-cards{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:18px}
.m-cards.m2{grid-template-columns:1fr 1fr}
.m-methods{margin-top:12px}
/* With a token out, one gap stands above each of the two labels. The empty
   line for a refusal keeps its room only while there is no token, where it
   stops the foot from moving: under a token it left a hole of 50px above
   "Publish this token" while "Read from" touched the token's box
   (docs/RECORD.md 4.379). */
.m-proof{margin-top:16px}
.m-proof .m-label~.m-label{margin-top:16px}
.m-methods:has(~.m-proof:not([hidden])){margin-bottom:0}
.m-err:empty:has(+.m-proof:not([hidden])){min-height:0;margin-top:0}
/* The Add server window draws a Name field over the form: the same gap
   above the form's own first label, which touched that field. */
#add-addr-stage .m-input+.m-label{margin-top:16px}
/* The token and where it is read from, each on one line in the mono an
   address is written in, in a box no taller than its line. A field and a way
   that cannot change any more read as fixed (docs/RECORD.md 4.379). */
.m-proof .code{font-size:var(--fs-micro);line-height:1.6;min-height:0;padding:10px 14px}
.m-input:disabled{opacity:.6}
.m-card[aria-disabled="true"]{opacity:.55;pointer-events:none}
.m-card.sel[aria-disabled="true"]{opacity:1}
.hstage h2.hhead{display:flex;align-items:center;justify-content:space-between}
.m-result{margin-top:10px;font-size:var(--fs-body);color:var(--muted)}
.m-result.ok{color:var(--ok)}
.m-result.fail{color:var(--fail)}
.m-cards.m3{grid-template-columns:1fr 1fr 1fr}
.m-card.pick{cursor:pointer;transition:border-color var(--quick) var(--ease)}
.m-card.pick:hover{border-color:var(--faint)}
.m-card .ic{color:var(--faint);margin-bottom:10px;display:block}
.m-card.sel .ic{color:var(--acc)}
/* A card that is only a mark and a name sits on one line. Stacking the glyph
   over two words left a tall card with a hole in it once the sentence went
   (the owner, 2026-08-16: the name and the logo, no other text). The glyph is
   the same faint as everywhere else, so a vendor mark takes no more weight
   than the line glyph beside it and nothing on the card is coloured. */
.m-card.nmo{display:flex;align-items:center;gap:10px;padding:13px 15px}
.m-card.nmo .ic{margin-bottom:0}
.m-stage{display:none}
.m-stage.on{display:block}
/* each step of Add server under a hairline (the owner, 2026-09-08) */
#add-ovl .m-stage.on{border-top:1px solid var(--line);margin-top:4px;padding-top:18px}
/* A plain pointer, never cursor:copy. macOS renders copy as the
   drag-and-drop green plus, which reads as "something is being added"
   rather than a click that copies (the owner, on an earlier project, 2026-07-22). */
.m-copy{cursor:pointer;position:relative;user-select:all;white-space:pre-wrap;
  word-break:break-all;line-height:1.8;min-height:86px;overflow:visible;padding:14px 16px}
.m-copy:hover{border-color:var(--acc)}
.m-copy.copied{border-color:var(--ok)}
.m-copy::after{content:"copied";position:absolute;bottom:8px;right:12px;
  background:var(--panel2);padding:1px 6px;border-radius:3px;
  font-family:"Work Sans",sans-serif;font-size:var(--fs-micro);letter-spacing:.1em;
  color:var(--faint);opacity:0;transform:translateY(3px);
  transition:opacity var(--quick) var(--ease),transform var(--quick) var(--ease)}
.m-copy.copied::after{opacity:1;transform:translateY(0)}
.m-card{border:1px solid var(--line2);border-radius:9px;padding:14px 15px;position:relative}
.m-card.sel{border-color:var(--acc);box-shadow:0 0 0 1px var(--acc)}
/* A card the window is not offering right now, which is every card but one
   while a row is being edited. Same dimming a planned card gets, because it is
   the same fact: not a choice here. The script refuses the click too, so this
   is presentation and not the check. */
.m-card.m-locked{opacity:.4;cursor:not-allowed}
.m-card.m-locked:hover{border-color:var(--line2)}
.m-card-t{font-family:"Space Grotesk",sans-serif;font-weight:600;font-size:var(--fs-body);
  color:var(--ink-str);display:flex;align-items:center;flex-wrap:wrap}
.m-card-d{font-size:var(--fs-meta);color:var(--faint);margin-top:6px;line-height:1.55}
/* A picker choice built by pick_card() is a real button, so a planned one
   carries the disabled attribute and the browser refuses the click, rather
   than a script deciding not to act on it. This undoes what a button brings
   with it and nothing more, so a card looks the same whichever element it
   is. */
button.m-card{display:block;width:100%;text-align:left;background:none;color:inherit;
  font-family:inherit}
.m-label{font-size:var(--fs-meta);color:var(--faint);
  display:block;margin-bottom:7px}
.m-input{width:100%;background:var(--bg);border:1px solid var(--line2);border-radius:9px;
  padding:10px 13px;font-family:"IBM Plex Mono",monospace;font-size:var(--fs-body);color:var(--ink)}
.m-input:focus{outline:none;border-color:var(--acc)}
/* A field that cannot be typed in has to look like one, or it reads as a
   setting you just failed to change. Same opacity as a disabled button. */
.m-input:disabled{opacity:.45;cursor:not-allowed}
.m-hint{font-size:var(--fs-meta);color:var(--faint);margin-top:7px}
.m-err{font-size:var(--fs-meta);color:var(--fail);margin-top:9px;min-height:18px}
/* The Feedback window: the words in the reading face, and under them the
   five lines that are the whole of what leaves, each a label and a value.
   The Feedback button sits in the top bar before the account circle. */
#fb-btn{flex:0 0 auto;margin-left:auto}
.top-in:has(#fb-btn) .pm{margin-left:-14px}
textarea.m-input{min-height:96px;resize:vertical;font-family:"Work Sans",sans-serif;
  line-height:1.5;display:block}
.fb-facts{display:grid;grid-template-columns:96px 1fr;gap:7px 14px;margin-top:16px;
  font-size:var(--fs-meta)}
#fb-result{min-height:22px;font-size:var(--fs-meta)}
.fb-facts .k{color:var(--faint)}
.fb-facts .v{font-family:"IBM Plex Mono",monospace;color:var(--ink);overflow-wrap:anywhere}
#fb-go.fb-wait::before{content:"";display:inline-block;width:11px;height:11px;margin-right:7px;
  vertical-align:-1px;border:1.5px solid currentColor;border-right-color:transparent;
  border-radius:50%;animation:arr-turn .9s linear infinite}
/* The server arriving under the install command: mark, label, value. The
   spinner is the one thing on this window that moves, it turns while a step
   is waited for and the blanket reduced-motion rule in the theme stops it. */
.arr{margin-top:14px;border:1px solid var(--line);border-radius:9px}
.arr-row{display:grid;grid-template-columns:16px 150px minmax(0,1fr);gap:11px;
  align-items:center;padding:10px 13px;font-size:var(--fs-meta);
  border-bottom:1px solid var(--line)}
.arr-row:last-child{border-bottom:0}
.arr-m{display:block;width:16px;height:16px}
.arr-m .ic{display:none}
.arr-l{color:var(--faint)}
.arr-v{font-family:"IBM Plex Mono",monospace;color:var(--ink);
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.arr-row[data-step="wait"] .arr-l,.arr-row[data-step="done"] .arr-l{color:var(--ink)}
.arr-row[data-step="wait"] .arr-m .ic{display:block;color:var(--faint);
  animation:arr-turn .9s linear infinite}
@keyframes arr-turn{to{transform:rotate(360deg)}}
/* The scan dialog's own two lines. The intro is body-weight explanation, the
   status is what the control plane answered. The status is neutral ink and
   never a tone: a refusal to scan too soon is a fact, not a fault, so it does
   not borrow warn (docs/DESIGN.md section 3). min-height holds the layout
   still while the answer arrives. */
.m-intro{font-size:var(--fs-meta);color:var(--muted);line-height:1.55;margin-bottom:14px}
.m-status{font-size:var(--fs-meta);color:var(--ink);line-height:1.5;min-height:20px;margin-bottom:14px}
.m-note{font-size:var(--fs-meta);color:var(--faint);max-width:32ch;line-height:1.5}
.m-foot{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-top:18px}
/* A window taller than the screen scrolls inside its own box, and its foot
   went under the fold with the one button that acts: measured 2026-10-06 in
   the Add server window at the token step, 900 high (docs/RECORD.md 4.379).
   The foot stays in view and the form scrolls under it. It reaches into the
   box's own padding, so a window that does not scroll is drawn as before. */
.modal>.m-foot{position:sticky;bottom:-20px;margin:18px -24px -20px;padding:0 24px 20px;
  background:var(--panel);z-index:1}
/* What scrolls under the foot fades out above it. Over the empty gap of a
   window that does not scroll the fade is the box's colour on itself. */
.modal>.m-foot::before{content:"";position:absolute;left:0;right:0;bottom:100%;height:18px;
  background:linear-gradient(transparent,var(--panel));pointer-events:none}
/* A footer with no note has one child, and space-between would park it on the
   left. The auto margin keeps the buttons on the right either way. */
.m-foot .acts{margin-left:auto}
@media(max-width:640px){.m-cards{grid-template-columns:1fr}}
.rs{border:1px solid var(--line);border-radius:9px;margin-top:10px;background:var(--panel2)}
.rs summary{display:flex;justify-content:space-between;gap:14px;padding:10px 14px;cursor:pointer;
  list-style:none;font-family:"IBM Plex Mono",monospace;font-size:var(--fs-body);align-items:baseline}
.rs summary::-webkit-details-marker{display:none}
.rs summary .grades{color:var(--faint);font-size:var(--fs-meta);text-align:right}
.rs[open] summary{border-bottom:1px solid var(--line)}
.rs .code{border:0;margin:0;border-radius:0 0 9px 9px;max-height:440px;overflow:auto}
/* fold_html's box. Same shell as .rs so the page keeps one disclosure shape,
   but its labels are prose, not table names, so the summary speaks the page
   font at the small faint heading size (.sech h2) rather than the ruleset
   mono that .rs keeps.

   The chevron and the hover are what say the row opens (the owner, 2026-08-25:
   it did not read as a button). The chevron is a bordered box turned with
   transform, the way the gates rail draws its arrow, because a glyph in a
   content property is ruled out by test_css_content_is_a_word_or_nothing.
   Pointing right means closed, pointing down means open. */
.fs{border:1px solid var(--line);border-radius:9px;margin-top:10px;background:var(--panel2)}
.fs summary{display:flex;justify-content:space-between;gap:14px;padding:10px 14px;cursor:pointer;
  list-style:none;font-family:inherit;font-size:var(--fs-micro);color:var(--faint);
  align-items:center;border-radius:8px;
  transition:background var(--quick) var(--ease),color var(--quick) var(--ease)}
.fs summary:hover{background:var(--hover);color:var(--ink)}
.fs summary::after{content:"";flex:0 0 auto;width:7px;height:7px;margin-right:2px;
  border-right:1.5px solid currentColor;border-bottom:1.5px solid currentColor;
  transform:rotate(-45deg);transition:transform var(--quick) var(--ease)}
.fs[open] summary::after{transform:rotate(45deg)}
.fs summary::-webkit-details-marker{display:none}
.fs[open] summary{border-bottom:1px solid var(--line);border-radius:8px 8px 0 0}
@media(max-width:1080px){
  /* The four columns, narrower. Until 2026-10-02 this hid the third cell,
     which was the Agent column and would now be Reachable. */
  .thead,.row{grid-template-columns:130px minmax(0,1fr) 100px minmax(0,1.4fr)}
  @supports (grid-template-columns:subgrid){
    #fleet .ftbl{grid-template-columns:minmax(150px,max-content) minmax(0,1fr) 100px minmax(0,1.4fr)}
  }
  .fstrip{grid-template-columns:1fr 1fr}
  .fstrip>div:nth-child(3){border-left:0}
  .fstrip>div:nth-child(n+3){border-top:1px solid var(--line)}
}
@media(max-width:640px){
  /* A phone. The state and the server share the first line, and what is
     reachable and what needs a decision share a second line under them, so
     the page never scrolls sideways (docs/DESIGN.md). */
  .thead,.row{grid-template-columns:auto minmax(0,1fr);gap:8px 12px}
  /* A phone stacks each row over two lines of its own, so the rows share no
     columns there and a mark may wrap, as before: the page never scrolls
     sideways. */
  @supports (grid-template-columns:subgrid){
    #fleet .ftbl{display:block}
    #fleet .ftbl>.thead,#fleet .ftbl>.row{grid-template-columns:auto minmax(0,1fr)}
    #fleet .ftbl>.row>div:first-child{flex-wrap:wrap}
  }
  .thead span:nth-child(n+3){display:none}
  .row>div:nth-child(3){grid-column:1}
  .row>div:nth-child(4){grid-column:2}
  .row>div:nth-child(3):empty,.row>div:nth-child(4):empty{display:none}
  .fnote{flex-wrap:wrap}
  .lst,.ch2,.pl{grid-template-columns:1fr}
  .pt-h,.sh{display:none}
  .srow{grid-template-columns:110px minmax(0,1fr)}
  .schips,.sbd{grid-column:2}
  .pt{grid-template-columns:100px 1fr}
  .pt>div:nth-child(n+3){grid-column:2}
  .mxh,.ch{display:none}
  .hset{grid-template-columns:1fr;gap:20px}
  .li{flex-wrap:wrap}
  .li .c.fix{width:100%}
  /* A field or a choice with the planned tag beside it is wider than a
     phone, so the field gives way and the tag stays on the screen. */
  .li .c{max-width:100%}
  .li .c .in,.li .c .choice{flex:0 1 280px;min-width:0}
  /* The Tags row's bubbles start at the left under their label, where
     every other row's field starts once the rows are stacked. */
  .li.tagrow .c{width:100%}
  .tagc{justify-content:flex-start}
  .cr{grid-template-columns:130px minmax(0,1fr)}
  .cr .cdet{grid-column:2;white-space:normal}
  .ctop{flex-wrap:wrap;gap:10px}
  .mr{grid-template-columns:120px minmax(0,1fr)}
  .mr .mst{grid-column:2;align-items:flex-start}
  .evcs{grid-template-columns:1fr}
}

/* ---------------------------------------------------------- the Admin rail
   A rail down the left, the section you picked on the right (the owner,
   2026-08-16), the shape the Admin screen keeps. Picking a section is a radio and revealing a setting is a
   <details>, so the whole page still works with JavaScript switched off.

   How the open section is shown, and this is the part that matters: the rail
   item takes the raised panel surface, ink and 600 weight, and its glyph takes
   the accent. The other two stay muted and flat on the page. Nothing is drawn
   beside any of them, no bar, no bracket, no chevron, no glyph in the margin.
   docs/DESIGN.md section 3, and the owner named that treatment himself. The
   per-key rules are generated further down, next to the section keys.

   The glyph is on every item, so it labels the section rather than marking the
   chosen one. Only its colour moves. */
.as{margin-top:26px;display:grid;grid-template-columns:212px minmax(0,1fr);gap:30px;
  align-items:start}
.as>input{position:absolute;width:1px;height:1px;opacity:0;pointer-events:none}
/* The rail stretches to the height of the section beside it, so its divider
   runs the whole way down instead of stopping under the last item and reading
   as a stray line. The items stay at the top of it. */
.as-rail{display:grid;gap:3px;align-content:start;align-self:stretch;
  border-right:1px solid var(--line);padding-right:14px}
.as-rh{font-size:var(--fs-meta);color:var(--faint);
  padding:2px 12px 10px}
.as-item{display:grid;grid-template-columns:18px 1fr;gap:11px;align-items:center;
  padding:9px 12px;border:1px solid transparent;border-radius:9px;cursor:pointer;
  transition:background var(--quick) var(--ease)}
.as-item:hover{background:var(--hover)}
.as-item .ic{display:block;color:var(--faint)}
.as-item .ct{font-family:"Space Grotesk",sans-serif;font-size:var(--fs-body);color:var(--muted);font-weight:600}
.as-stage{display:none}
.as-sh{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:15px}
.as-sh h2{font-family:inherit;font-weight:400;letter-spacing:0;
  font-size:var(--fs-micro);color:var(--faint)}
.as-sh .as-sm{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--faint)}
.as-block{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);
  overflow:hidden;margin-top:14px}
/* A settings row inside one of these blocks takes the same three columns as
   .as-rv>summary further down, which is the row the account page already uses
   inside this same block: what it is, the control, and the action pinned to
   the right edge. One label column, one control column and one right edge on
   every row, whatever the row holds.

   It was 190px 1fr 150px with the control in the third column on some rows and
   the second on others, so a screen carried three buttons at three different x
   positions and the fourth row's switch 368px right of the nearest one
   (the owner, 2026-08-29, saw that the settings were not in line).

   min-height is a 40px field plus its padding, so a row holding only a switch
   is as tall as a row holding a field.

   The narrow override is repeated here rather than left to the .ch2 rule in
   the 1080px query below, because this selector is both more specific and
   later, so without it the row would never collapse. */
.as-block .ch2{grid-template-columns:210px 1fr auto;padding:14px 20px;min-height:68px}
@media(max-width:1080px){.as-block .ch2{grid-template-columns:1fr;min-height:0}}
.as-sh+.as-block{margin-top:0}
.as-bh{padding:13px 20px;background:var(--panel2)}
.as-bh h3{font-size:var(--fs-body)}
.as-bh .bm{font-size:var(--fs-meta);color:var(--faint);margin-top:3px}
.as-row{display:grid;grid-template-columns:210px 1fr;gap:16px;padding:14px 20px;
  border-top:1px solid var(--line);align-items:baseline}
.as-row .rk{font-size:var(--fs-body);color:var(--ink)}
.as-row .rd{font-size:var(--fs-meta);color:var(--faint);margin-top:3px}
.as-row .rval{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-body);color:var(--muted)}
.as-rv{border-top:1px solid var(--line)}
.as-rv>summary{display:grid;grid-template-columns:210px 1fr auto;gap:16px;align-items:center;
  padding:13px 20px;cursor:pointer;list-style:none;
  transition:background var(--quick) var(--ease)}
.as-rv>summary::-webkit-details-marker{display:none}
.as-rv>summary:hover{background:var(--hover)}
.as-rv[open]>summary{background:var(--panel2)}
.as-rv .rk{font-size:var(--fs-body);color:var(--ink)}
.as-rv .rval{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-body);color:var(--muted)}
.as-rv .rx{font-size:var(--fs-meta);color:var(--muted);
  border:1px solid var(--line2);border-radius:99px;padding:5px 12px;white-space:nowrap}
.as-rv[open] .rx{color:var(--ink);border-color:var(--faint)}
/* the pill says what a click does now, because the state is a word here too */
.as-rv .rx .rc{display:none}
.as-rv[open] .rx .ro{display:none}
.as-rv[open] .rx .rc{display:inline}
.as-rb{padding:15px 20px 18px;display:grid;gap:12px;justify-items:start}
.as-rb .m-input{max-width:340px}
.as-opts{display:grid;grid-template-columns:repeat(auto-fit,minmax(152px,1fr));gap:10px;
  width:100%}
.as-opt{display:block;position:relative}
.as-opt input{position:absolute;width:1px;height:1px;opacity:0;pointer-events:none}
.as-opt label{display:block;height:100%;padding:12px 14px;border:1px solid var(--line);
  border-radius:10px;cursor:pointer;transition:background var(--quick) var(--ease)}
.as-opt label:hover{background:var(--hover)}
.as-opt .ot{display:block;font-family:"Space Grotesk",sans-serif;font-size:var(--fs-body);
  color:var(--muted)}
.as-opt .om{display:block;font-size:var(--fs-meta);color:var(--faint);margin-top:3px;line-height:1.5}
.as-opt input:checked+label{background:var(--panel2);border-color:var(--line2)}
.as-opt input:checked+label .ot{color:var(--ink-str);font-weight:600}
.as-opt input:checked+label .om{color:var(--muted)}
.as-opt input:focus-visible+label{outline:2px solid var(--acc);outline-offset:2px}
.as-mem{display:grid;grid-template-columns:34px 1fr auto;gap:14px;align-items:center;
  padding:12px 20px;border-top:1px solid var(--line)}
.as-mem .av{width:30px;height:30px;border-radius:50%;background:var(--panel2);
  border:1px solid var(--line2);display:grid;place-items:center;font-size:var(--fs-micro);
  color:var(--muted);font-family:"IBM Plex Mono",monospace}
.as-mem .mn{font-size:var(--fs-body);color:var(--ink)}
.as-mem .me{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--faint)}
.as-mem .mr{font-size:var(--fs-meta);color:var(--muted);
  border:1px solid var(--line2);border-radius:99px;padding:4px 11px;white-space:nowrap}
.as-illus{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--faint);
  line-height:1.65;max-width:70ch}
@media(max-width:820px){
  /* Too narrow for a rail beside the content, so it lies down above it and the
     divider moves with it. */
  .as{grid-template-columns:minmax(0,1fr);gap:20px}
  .as-rail{display:flex;flex-wrap:wrap;gap:4px;border-right:0;padding-right:0;
    border-bottom:1px solid var(--line);padding-bottom:11px}
  .as-rh{width:100%;padding:0 0 8px}
  .as-row,.as-rv>summary{grid-template-columns:1fr}
}
"""

# The slim marks' icon rules, written in once the table above and the
# stylesheet both exist.
CSS = CSS.replace("__MARK_ICON_RULES__", _mark_icon_rules())


# --------------------------------------------------------------- the Admin screen
#
# A grid of number cards and one table, which is the shape every product's own
# metrics screen has. Nothing bespoke was designed for it, deliberately: this
# is the least interesting screen in the product and the standard arrangement
# is the one that needs no learning.
#
# **The class is `stat` and not `num`, and that is not a preference.**
# `theme.py` already owns a global `.num`, which is the inline monospace number
# used in half the sentences on the host page. A second meaning for it here
# repainted every one of those, which a screenshot caught.
#
# Each card carries its own panel rather than sitting in one shared surface.
# With one shared surface the grid's last row is short whenever the number of
# cards does not divide by the column count, and the leftover cells drew as a
# wide empty block, which reads as something failing to load. Separate cards
# leave ordinary page background there instead. Four columns rather than
# auto-fit, so the count is known and the sections line up with each other.
ADMIN_CSS = """
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);
  padding:16px 18px}
.stat .v{font-family:"Space Grotesk",sans-serif;font-size:var(--fs-title);
  font-weight:600;letter-spacing:-.01em;color:var(--ink-str);line-height:1.15;
  font-variant-numeric:tabular-nums}
.stat .k{font-size:var(--fs-meta);color:var(--muted);margin-top:4px}
@media(max-width:1020px){.stats{grid-template-columns:repeat(2,1fr)}}
@media(max-width:560px){.stats{grid-template-columns:1fr}}
/* ---- the strip, on every tab ----
   The Fleet's strip without its bars. Each box is a label for the tab that
   holds the names behind its number, so a click opens that tab with no
   script, and the lines under the number are mono because they are values. */
.fstrip.adm{margin-top:22px}
.fstrip.adm>div{padding:0}
.fstrip.adm label{display:block;padding:16px 20px;cursor:pointer;height:100%;
  transition:background var(--quick) var(--ease)}
.fstrip.adm label:hover{background:var(--hover)}
.fstrip.adm .d{font-family:"IBM Plex Mono",monospace}
.fstrip.adm .d+.d{margin-top:2px}
#admin .tab>.sec:first-child{margin-top:22px}
#admin .tab>.stats{margin-top:22px}
#admin .sec .ftbl{margin-top:0}
#admin .lookup+.sec{margin-top:22px}
#admin .subnav{margin-top:22px}
/* ---- the tables ----
   Every one in the Fleet's shape: the head a band of panel2 with uppercase
   micro labels, the state first where a row has one, the row the link. The
   fixed tracks of every one, the flexible track at its minimum, with their
   16px gaps and 40px of padding, sum under 972px, the body at 1024 wide:
   test_every_tables_fixed_tracks_sum_under_the_narrowest_body reads these
   rules, so the clipped Open of docs/record 4.412 cannot come back. */
.thead.irow,.row.irow{grid-template-columns:140px minmax(120px,1fr) 95px 95px 100px 110px 150px}
.thead.wrow2,.row.wrow2{grid-template-columns:150px minmax(160px,1fr) 90px 90px 100px 130px}
.thead.acrow,.row.acrow{grid-template-columns:minmax(200px,1fr) 130px 100px 90px 130px}
.thead.qrow2,.row.qrow2{grid-template-columns:150px minmax(160px,1fr) 100px 120px 130px}
.thead.brow2,.row.brow2{grid-template-columns:minmax(200px,1fr) 100px 130px}
.thead.lrow,.row.lrow{grid-template-columns:minmax(140px,1fr) 100px 110px 90px 90px 90px 100px}
/* A feedback message: the words in the flexible column, whole and
   wrapping, and Done and Delete in a fixed end track that is never cut
   (docs/screens/feedback/BRIEF.md, docs/record 4.436). */
.thead.frow,.row.frow{grid-template-columns:140px minmax(120px,1fr) 60px 100px 80px minmax(160px,2fr) 140px}
.frow .fwords{white-space:pre-wrap;overflow-wrap:anywhere;color:var(--ink);font-size:var(--fs-body);
  line-height:1.5}
.frow .fact{display:flex;gap:6px;justify-content:flex-end}
.frow .fact .btn{padding:6px 11px}
.fb-done{margin-top:12px}
.fb-done summary .hint{margin-left:auto;margin-right:10px}
.fb-done .fold-b{padding:0}
.fb-done .ftbl{margin-top:0;border:0;border-radius:0 0 8px 8px}
.row .mono{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--muted);
  font-variant-numeric:tabular-nums}
.row .nm{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--ink);
  overflow-wrap:anywhere}
.row .ar{text-align:right}
.thead .ar{text-align:right}
div.row{cursor:default}
/* ---- an instance's row opens in place ----
   A details element: no script, the row is its summary, and what he would
   otherwise read from the box sits under it. Nothing in it acts. */
.irow-d>summary{list-style:none}
.irow-d>summary::-webkit-details-marker{display:none}
.irow-d[open]>summary{background:var(--panel2)}
.iopen{padding:14px 20px 18px;border-bottom:1px solid var(--line);background:var(--panel2);
  display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px}
.iopen .iok{font-size:var(--fs-micro);letter-spacing:.06em;text-transform:uppercase;
  color:var(--faint);margin-bottom:8px}
.iopen .iol{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--muted);
  line-height:1.7;font-variant-numeric:tabular-nums}
.iopen .iol b{font-weight:600;color:var(--ink)}
@media(max-width:820px){.iopen{grid-template-columns:1fr}}
/* ---- the lookup, above the Instances table ----
   A form that posts, never a query string: the address is somebody's who
   complained. */
.lookup{display:flex;gap:10px;margin-top:22px;align-items:center}
.lookup .srch{margin-top:0;flex:1}
.lookup-h{display:flex;align-items:baseline;gap:12px;margin-top:22px;margin-bottom:11px}
.lookup-h .addr{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-body);color:var(--ink)}
.lookup-h .hint{font-size:var(--fs-meta);color:var(--faint)}
.lookup-h .err{font-size:var(--fs-meta);color:var(--fail)}
/* ---- viewing somebody else's workspace ----
   Full bleed under the top bar, in the accent, because every screen below it
   is another workspace's servers and reading one as your own is the single
   thing this must not allow. */
.vbar{background:var(--acc-fill);color:#fff}
.vbar-in{max-width:1280px;margin:0 auto;padding:11px 26px;display:flex;
  align-items:center;gap:12px;flex-wrap:wrap}
.vbar .vb-t{font-family:"Work Sans",sans-serif;font-size:var(--fs-micro);
  letter-spacing:.11em;text-transform:uppercase;opacity:.85}
.vbar b{font-family:"Space Grotesk",sans-serif;font-weight:600}
.vbar .vb-w{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);
  opacity:.85}
.vbar .btn{margin-left:auto;background:rgba(255,255,255,.16);
  border-color:rgba(255,255,255,.32);color:#fff}
/* A control that cannot act here still has to look like the product, so it
   takes the ordinary disabled treatment rather than disappearing. */
body[data-viewing] .btn:disabled{opacity:.4}
"""

CSS += ADMIN_CSS


# ------------------------------------------------------- the host detail tabs
#
# One server's page is subcategorised rather than one long scroll (the owner,
# 2026-08-15). The order is his, of 2026-10-03 (docs/RECORD.md 4.325,
# docs/screens/host-overview/SPEC.md section 3): the verdict, what is
# running, the rules, the evidence, the packet's path, what moved, and
# Settings last because it is not data about the host at all. Until that day
# Rules and Packet path stood last, where they had been put while they were
# planned.
#
# **This list is the order.** Both feeds list their tabs in it, and a test
# holds each feed's row of tabs to it (site/app/test_tab_order.py).
HOST_TAB_KEYS = ["overview", "services", "rules", "evidence", "path", "changes", "settings"]

# Both tabs were after v1 (the owner, 2026-08-24, moved Rules and Packet path
# past v1 and had them shown as planned) and
# both came back on 2026-09-10, each drawn and approved: Rules in
# docs/screens/host-rules, the Packet path in docs/screens/host-packet-path
# after eight rounds. Nothing is planned here now, and the tuple stays because
# it is the one switch either tab would leave by.
#
# This tuple is the only place that fact is written. Both feeds build their tab
# list from it, and tab_css skips these keys because there is no radio for the
# selector to reach.
HOST_TABS_PLANNED = ()


def tab_css(keys):
    """The tab switching, in CSS, with no host names in it.

    The mechanism is one radio group per host: the inputs, the label row and
    the panels are all siblings of each other, so `~` reaches from a checked
    input to its own panel and no further. Two hosts on the same page therefore
    cannot switch each other's tabs, and nothing here needs JavaScript, which
    is what stops a blocked script leaving a host page with every tab hidden.
    """
    out = []
    for k in keys:
        out.append(f".tabsel.k-{k}:checked~.tab.k-{k}{{display:block}}")
        out.append(f".tabsel.k-{k}:checked~.subnav label.k-{k}{{color:var(--ink)}}")
        # The open tab is ink and 600 weight and nothing is drawn beside or
        # under it. An accent bar under the selection is the treatment
        # docs/DESIGN.md section 3 rules out, selected is weight and colour and
        # never a marker, and the owner named it directly on 2026-08-15.
        out.append(f".tabsel.k-{k}:checked~.subnav label.k-{k}{{font-weight:600}}")
        # The input carries the focus and cannot be seen, so the label wears it.
        out.append(f".tabsel.k-{k}:focus-visible~.subnav label.k-{k}"
                   "{outline:2px solid var(--acc);outline-offset:3px;border-radius:3px}")
    return "\n".join(out)


# Every key, the planned ones included. A planned tab has no radio and no
# panel, so its rules match nothing on the shipped page, and keeping them
# lets the tests render a page with HOST_TABS_PLANNED emptied and prove the
# hidden tabs still work, instead of skipping that proof for a whole
# release. The gate allows no skips, and this is what makes none needed.
CSS += tab_css(HOST_TAB_KEYS)

# --------------------------------------------- one server's own settings, railed
#
# The owner, 2026-08-16: these settings look the same as the general settings,
# with the column on the left. So this is the account rail, reused rather
# than copied: the markup carries the same `as-` classes and the stylesheet above
# is the only place they are described. The rules generated below are the ones
# that open a section, and they differ from the account's in one way that
# matters: they are keyed on a class, because a live page draws one of these per
# host and an id may appear once on a page.
#
# ------------------------------------------------------------ the Host Evidence
#
# docs/screens/host-evidence/SPEC.md: one row per port and family with one
# word per view as a neutral tag, three cards, and the document's sections
# as a strip of the same tags. It shows and never decides: only the State
# column carries a tone.

@dataclasses.dataclass
class EvidenceRow:
    """One port on one family. `agent`, `prober` and `provider` are the
    engine's words, `off` marks which of the three are an absence (drawn
    fainter), `state` is the joined state or "", `row` the Overview row the
    click opens."""
    protocol: str
    port: int
    family: str
    service: str
    agent: str
    prober: str
    provider: str
    state: str
    row: str
    rate_limited: bool = False
    off: tuple = ()
    # Two vantages' newest measurements of this port differ: the mark beside
    # the prober's word, and what each vantage said as (name, engine word),
    # measured vantages only (docs/PRODUCT.md 8e, SPEC.md 2026-09-08).
    disagree: bool = False
    views: tuple = ()


# The prober's words as the spec shows them (section 1). The engine's own
# stay in the data, this is the screen's spelling of each.
OUTSIDE_SHOWN = {"connect succeeded": "open", "connect refused": "refused",
                 "no response": "no answer", "not tested": "not tested"}
PROVIDER_SHOWN = {"permits": "permitted", "permits some": "permitted from some"}
# A word that is an absence, drawn fainter (the spec: ink for a thing found,
# the fainter grey for an absence).
ABSENT_WORDS = ("nothing bound", "nothing listening", "loopback", "not read", "no agent",
                "not tested", "no rule", "no match", "not connected")
EVIDENCE_COLUMNS = ("Port", "Service", "The agent, inside", "The prober, outside",
                    "The provider", "State")
NOT_CONNECTED = "not connected"


def prober_from_html():
    """The prober's own addresses, which nothing records yet: the planned tag
    under the marker, so the line the spec asks for is on the card and says
    it is not built."""
    return tag("planned", "planned")


def evidence_tag(word, off=None):
    """A fact, never a verdict: the neutral tag, fainter when it is an absence."""
    if off is None:
        off = word in ABSENT_WORDS
    return f'<span class="st nt{" off" if off else ""}">{esc(word)}</span>'


def evidence_port_html(protocol, port, family):
    return (f'<span class="mp"><b>{esc(port)}</b><small>{esc(str(protocol).upper())}/'
            f'<i class="{esc(family)}">{esc(family)}</i></small></span>')


def prober_cell_html(row):
    """The prober's word, and when two vantages disagree, the neutral mark
    after it and one mono line per vantage under it, name then its word in
    the spec's spelling. When they agree the cell is the word alone and no
    vantage is named (SPEC.md, decided 2026-09-08)."""
    word = evidence_tag(OUTSIDE_SHOWN.get(row.prober, row.prober))
    if not row.disagree:
        return word
    lines = "".join(
        f'<span class="mvv">{esc(name)} {esc(OUTSIDE_SHOWN.get(said, said))}</span>'
        for name, said in row.views)
    return f'<span class="mv"><span class="mvw">{word}{disagree_flag(True)}</span>{lines}</span>'


def evidence_row_html(slug, row, provider=True):
    tab = f"tb-{slug}-overview"
    service = (f'<span class="msv">{esc(row.service)}</span>' if row.service
               else '<span class="msv off">&mdash;</span>')
    cells = evidence_tag(row.agent) + prober_cell_html(row)
    if provider:
        cells += evidence_tag(PROVIDER_SHOWN.get(row.provider, row.provider))
    state = theme.status(PORT_TONE.get(row.state, "off"), esc(row.state)) if row.state else ""
    return (f'<div class="mr" data-row="{esc(row.row)}" data-tab="{esc(tab)}">'
            f'{evidence_port_html(row.protocol, row.port, row.family)}{service}{cells}'
            f'<span class="mst">{state}{rate_flag(row.rate_limited)}</span></div>')


def evidence_thead_html(provider=True):
    cols = [c for c in EVIDENCE_COLUMNS if provider or c != "The provider"]
    return (f'<div class="mxh">'
            + "".join(f"<span>{esc(c)}</span>" for c in cols) + "</div>")


def evidence_table_html(slug, rows, provider=True, empty="No ports."):
    """The matrix, the provider column always drawn (the owner, 2026-09-06),
    "not connected" in every cell while no token is set."""
    body = "".join(evidence_row_html(slug, r, provider) for r in rows)
    if not body:
        body = f'<div class="mr mempty">{esc(empty)}</div>'
    return f'<div class="panel mxt">{evidence_thead_html(provider)}{body}</div>'


def view_card_html(title, when, lines, off=False):
    """One view's card: the name, when it last answered, then label and value
    lines. The values arrive as markup built here (mono through `mono`),
    escaped where they came from a document."""
    body = "".join(f'<div class="evl"><span class="evk">{esc(k)}</span><span>{v}</span></div>'
                   for k, v in lines)
    return (f'<div class="evcard{" off" if off else ""}"><div class="evt"><b>{esc(title)}</b>'
            f'<span>{esc(when)}</span></div>{body}</div>')


def view_cards_html(cards):
    return '<div class="evcs">' + "".join(view_card_html(*c) for c in cards) + "</div>"


def evidence_sections_html(chips):
    """The document's sections as the same neutral tags: collected in ink,
    absent in grey, refused in amber with the word after the name. `chips`
    is [(label, tone, suffix)] with tone "", "off", "warn" or "fail"."""
    out = []
    for label, tone, suffix in chips:
        text = f"{label} · {suffix}" if suffix else label
        if tone in ("warn", "fail"):
            out.append(theme.status(tone, esc(text)))
        else:
            out.append(evidence_tag(text, off=(tone == "off")))
    return ('<div class="evsecs"><div class="k">what the agent read</div>'
            f'<div class="evchips">{"".join(out)}</div></div>')


def evidence_tab_html(slug, rows, cards, chips, provider=True):
    """`chips` None leaves the strip out, for a host with no document."""
    return (evidence_table_html(slug, rows, provider) + view_cards_html(cards)
            + (evidence_sections_html(chips) if chips is not None else ""))


# ------------------------------------------------------------ the Host Settings
#
# docs/screens/host-settings/SPEC.md: the rail and the content side by side,
# one entry per category with an icon, and every setting a row in a
# bordered list with its control at the right. Nothing here has a Save for
# the tab: a switch and a button act at once, a typed value has its own.

# (key, title, icon). Provider is the planned entry, drawn in the rail with
# the tag and opening nothing. The account's settings (team, who may see a
# server) are not here (the owner, 2026-09-05).
HSET_CATEGORIES = (("server", "Server", "hard-drives"), ("agent", "Agent", "binoculars"),
                   ("probing", "Probing", "broadcast"),
                   ("addresses", "Addresses", "globe-hemisphere-west"),
                   ("alerts", "Alerts", "bell-ringing"))
HSET_PLANNED = (("provider", "Provider", "plugs-connected"),)
HSET_GROUPS = (("", ("server", "agent", "probing", "addresses", "provider")),
               ("Notifications", ("alerts",)))
HSET_KEYS = tuple(key for key, _t, _i in HSET_CATEGORIES)
HSET_TITLE = {key: title for key, title, _i in HSET_CATEGORIES}
NO_SILENCES = "No silenced ports."
NO_ADDRESS_LINE = "No address proved yet."
SILENCE_NO_END = "no end"
PROOF_METHOD_WORD = {"http_token": "token file", "dns_txt": "DNS", "agent": "agent"}


def hset_row(icon, name, sub="", control="", mono=False, fixed=False, name_extra="", cls=""):
    """One setting: the icon, the bold name, one small line under it when
    there is one, and the control at the right. `fixed` keeps the controls
    at one width so a button that appears takes room from the field's right
    end. `name_extra` is markup after the name, inside the text cell. The
    name and the line arrive as markup, escaped where they came from
    somebody else."""
    b_cls = ' class="mono num"' if mono else ""
    small = f'<small class="dim">{sub}</small>' if sub else ""
    ctl = f'<span class="c{" fix" if fixed else ""}">{control}</span>' if control else ""
    return (f'<div class="li{" " + cls if cls else ""}">{theme.icon(icon, 18)}<span class="t"><b{b_cls}>{name}</b>'
            f'{small}{name_extra}</span>{ctl}</div>')


def hset_list(rows_html, danger=False):
    return f'<div class="list{" danger" if danger else ""}">{rows_html}</div>'


def hset_h3(title, planned=False):
    return f'<h3>{esc(title)}{PLANNED_TAG if planned else ""}</h3>'


def hset_input(value="", placeholder="", mono=False, disabled=False, short=False, cls="", **attrs):
    parts = "".join(f' {k.replace("_", "-")}="{v}"' for k, v in attrs.items())
    classes = "in" + (" mono" if mono else "") + (" short" if short else "") + (f" {cls}" if cls else "")
    return (f'<input class="{classes}" value="{esc(value)}" placeholder="{esc(placeholder)}"'
            f'{parts}{" disabled" if disabled else ""}>')


def hset_choice(text, disabled=False):
    """A choice with a caret. Static while nothing behind it takes a value."""
    return (f'<span class="choice{" off" if disabled else ""}">{esc(text)}'
            f'{theme.icon("caret-down", 14)}</span>')


def hset_switch(on, cls="", disabled=False, **attrs):
    parts = "".join(f' {k.replace("_", "-")}="{v}"' for k, v in attrs.items())
    return (f'<button type="button" class="sw{" " + cls if cls else ""}{"" if on else " off"}"'
            f'{parts}{" disabled" if disabled else ""}></button>')


def hset_rail(slug):
    out = []
    for i, (head, keys) in enumerate(HSET_GROUPS):
        if i:
            out.append("<hr>")
        if head:
            out.append(f'<div class="g">{esc(head)}</div>')
        for key in keys:
            planned = next((c for c in HSET_PLANNED if c[0] == key), None)
            if planned:
                _k, title, icon = planned
                out.append(f'<span class="hitem hplanned">{theme.icon(icon, 16)}{esc(title)}{PLANNED_TAG}</span>')
            else:
                _k, title, icon = next(c for c in HSET_CATEGORIES if c[0] == key)
                out.append(f'<label class="hitem h-{key}" for="hs-{esc(slug)}-{key}">'
                           f'{theme.icon(icon, 16)}{esc(title)}</label>')
    return f'<nav class="hrail" aria-label="Settings for this server">{"".join(out)}</nav>'


def hset_view(slug, panels, head=None):
    """The tab: the radios, the rail, the panels. `panels` is [(key, body)]
    in HSET_KEYS order, the first open. `head` is {key: markup} for a section
    whose heading carries a button at its right, in the heading's own line."""
    safe = esc(slug)
    head = head or {}
    radios = "".join(
        f'<input type="radio" class="hsel h-{key}" name="hs-{safe}" id="hs-{safe}-{key}"'
        + (" checked" if i == 0 else "") + ">" for i, (key, _body) in enumerate(panels))
    stages = "".join(
        f'<div class="hstage h-{key}"><h2{" class=\"hhead\"" if key in head else ""}>'
        f'{esc(HSET_TITLE[key])}{head.get(key, "")}</h2>{body}</div>'
        for key, body in panels)
    return f'<div class="hset">{radios}{hset_rail(slug)}<div class="hbody">{stages}</div></div>'


def hset_css(keys=None):
    """The rail's per-key rules. The account Settings screen (`aset_view`)
    shares the rail and the rules, so its keys go through here too."""
    out = []
    for k in keys or HSET_KEYS:
        out.append(f".hsel.h-{k}:checked~.hbody .hstage.h-{k}{{display:block}}")
        out.append(f".hsel.h-{k}:checked~.hrail .hitem.h-{k}{{background:var(--panel2);font-weight:600}}")
        out.append(f".hsel.h-{k}:checked~.hrail .hitem.h-{k}::before{{content:'';position:absolute;left:-8px;top:7px;bottom:7px;width:3px;border-radius:2px;background:var(--acc)}}")
        out.append(f".hsel.h-{k}:focus-visible~.hrail .hitem.h-{k}{{outline:2px solid var(--acc);outline-offset:2px}}")
    return "\n".join(out)


CSS += "\n" + hset_css() + "\n"


# The rows both feeds draw, so the sample cannot lay a control out
# differently from the product. Every value arrives escaped. `live` False
# is the sample shell, whose buttons say what would happen in a toast.

def name_row(slug, name, live=True):
    """The ID: the name the server is found by, in the address, in a command
    and in the remove window. Shown in mono and not edited, since 2026-10-03
    (`docs/RECORD.md` 4.298: the ID is what the agent first says, and a
    constant). The label a person gives a server is the row
    above it (`display_row`). `name` arrives escaped."""
    return hset_row("hard-drives", "ID", "", f'<span class="idv" id="id-{slug}">{name}</span>',
                    fixed=True)


def display_row(slug, display, live=True):
    """The server's display name, in the row labelled Name, edited in its
    field the way the ID is: Save beside it once the value differs, Enter
    saves, Escape puts the saved one back. It is the label a reader sees, so
    it is set in the page's own type and not in mono, which the row under it
    keeps for the name the server is found by. `display` arrives as plain
    text and is escaped here."""
    save = (button("Save", "pri js-display-save", data_host=slug, hidden=True) if live
            else button("Save", "pri js-act", data_msg="The name would be saved here",
                        hidden=True))
    field = hset_input(display, cls="js-display", aria_label="Server name",
                       autocomplete="off", spellcheck="false", maxlength="40")
    return hset_row("hard-drives", "Name", "", field + save, fixed=True)


# How many tags a server carries. The limit is the control plane's
# (`MAX_TAGS_PER_HOST` in controlplane/app/tags.py), which refuses one more
# whatever the page does. The two are different packages, so the number is
# written here a second time and site/app/test_tags_screen.py holds them equal.
MAX_TAGS = 3


def tag_bubble(slug, tag, live=True):
    """One tag on the Tags row, a bubble. It is a button, because a click
    takes the tag off the server at once. The cross is in the markup and the
    stylesheet shows it when the hand or the keyboard is on the bubble
    (`.tagb`). `title` and the label say what the click does, so the bubble
    never says it by its colour alone (docs/DESIGN.md 3). `tag` arrives as
    the plain word and is escaped here."""
    word = esc(tag)
    hook = (f'js-tag-del" data-host="{slug}" data-tag="{word}' if live
            else 'js-act" data-msg="The tag would be removed here')
    return (f'<button type="button" class="tagb {hook}" title="Remove" '
            f'aria-label="Remove tag {word}"><span>{word}</span>{theme.icon("x", 12)}</button>')


def tags_row(slug, tags, live=True):
    """Tags: one bubble for each, and a field that adds one more with Enter
    (the owner, 2026-10-03, `docs/RECORD.md` 4.285). Nothing here waits for a
    Save. The field is gone once the server carries `MAX_TAGS`, the class
    `full`, and a server tagged with more before the limit shows every one
    of them and gets its field back at fewer than that
    (docs/screens/host-settings/SPEC.md, Server).

    The `<template>` holds one empty bubble for the page script to copy, so
    the script and this function cannot draw two different bubbles. `tags`
    arrives as the plain words and is escaped in `tag_bubble`."""
    bubbles = "".join(tag_bubble(slug, tag, live) for tag in tags)
    full = " full" if len(tags) >= MAX_TAGS else ""
    if live:
        field = hset_input(placeholder="Add tag", mono=True, cls="tagin js-tag-add",
                           aria_label="Add a tag", autocomplete="off", spellcheck="false",
                           maxlength="32")
        box = (f'<span class="tagc{full}" data-host="{slug}" data-max="{MAX_TAGS}">'
               f'<template>{tag_bubble(slug, "", live)}</template>{bubbles}{field}</span>')
    else:
        field = hset_input(placeholder="Add tag", mono=True, cls="tagin", aria_label="Add a tag",
                           autocomplete="off", spellcheck="false", maxlength="32")
        box = f'<span class="tagc{full}">{bubbles}{field}</span>'
    return hset_row("tag", "Tags", "", box, cls="tagrow")


def server_panel(slug, name, paused, live=True, kind="agent", last="", reporting=False,
                 tags=(), display=""):
    """`kind` is agent or address, `last` how long ago the agent last
    reported or empty, `reporting` whether it still does. The Remove button
    carries the three, because the remove window says them: the last report
    in the warn tone while the agent still reports, and the one command for
    the machine, which an address-only server has no machine for
    (docs/PRODUCT.md 4f, docs/screens/host-settings/BRIEF-remove-command.md).
    `tags` is the server's tags as plain words, `display` its display name
    as plain text or empty.
    """
    pause = (hset_switch(paused, "js-pause", data_host=slug) if live
             else hset_switch(paused))
    about = {"data_kind": kind}
    if last:
        about["data_last"] = last
    if reporting:
        about["data_live"] = "1"
    remove = (button("Remove", "danger js-remove", data_host=slug, data_name=name, **about) if live
              else button("Remove", "danger js-act", data_msg="The remove window would open here"))
    # Environment stays planned, as one row the way Timezone is. The planned
    # Labels row is what Tags is now.
    return (hset_list(display_row(slug, display, live)
                      + name_row(slug, name, live)
                      + tags_row(slug, tags, live)
                      + hset_row("tag", "Environment", "",
                                 hset_input(disabled=True) + PLANNED_TAG)
                      + hset_row("time", "Timezone", "",
                                 hset_choice("UTC", disabled=True) + PLANNED_TAG)
                      + hset_row("pause", "Paused", "", pause))
            + hset_h3("Remove")
            + hset_list(hset_row("trash", "Remove this server", "", remove), danger=True))


def agent_panel(slug, mode, enrolled, version, live=True):
    """`mode` is the read mode (Full read, Limited read, Agent), `enrolled`
    the enrolment date, `version` the agent's own or empty. All escaped by
    the caller. No Credential row: the owner, 2026-09-06, asked whether the
    credential needs changing here at all, and a credential is reissued
    only for a server whose agent never spoke, which has its own page."""
    return hset_list(
        hset_row("binoculars", mode, f"enrolled {enrolled}" if enrolled else "")
        + hset_row("download-simple", f"Version {version}" if version else "Version &mdash;"))


def port_row(slug, protocol, port, sub, live=True):
    """One port to probe. The classes the page script reads when a port is
    added on the page: `.num` for the port, `.dim` for the line under it."""
    rm = (button("Remove", "js-port-rm", data_host=slug, data_protocol=protocol, data_port=port)
          if live else button("Remove", "js-act", data_msg="The port would be withdrawn here"))
    return hset_row("plug", f"{port}/{protocol}", "", rm, mono=True,
                    name_extra=f'<small class="dim">{sub}</small>')


def port_row_template_html():
    """The empty port row, in a `<template>` outside every view, for the page
    script to clone and fill when a port is declared on the page."""
    return f'<template id="port-row-tpl">{port_row("", "", "", "")}</template>'


def add_port_row(slug, live=True):
    intent = ('<span class="seg">'
              '<button type="button" data-intent="open">open</button>'
              '<button type="button" data-intent="closed">closed</button></span>')
    add = (button("Add", "js-port-add", data_host=slug) if live
           else button("Add", "js-act", data_msg="The port would be declared here"))
    return hset_row("plug", "Add a port", "",
                    hset_input(placeholder="443", mono=True, short=True, cls="pd-port",
                               inputmode="numeric", autocomplete="off", aria_label="Port")
                    + intent + add,
                    name_extra='<small class="pd-msg"></small>')


# What heads the list of answers under Probing. On a server with an agent the
# probers take every port it reports bound as well, so the list holds the
# answers and nothing else, and Remove takes one back while a bound port stays
# probed. On a server with no agent the answers are what tells the probers
# which ports to look at. Until 2026-10-14 both read "Ports to probe" (the
# outside review's point 9, docs/RECORD.md 4.460).
PROBING_LIST_AGENT = "Your answers"
PROBING_LIST_ADDRESS = "Ports to probe"


def probing_panel(slug, ports, live=True, agent=True):
    """`ports` is [(protocol, port, sub)], escaped. `agent` is whether the
    server has an agent."""
    return (hset_list(hset_row("time", "From outside"))
            + hset_h3(PROBING_LIST_AGENT if agent else PROBING_LIST_ADDRESS)
            + hset_list("".join(port_row(slug, p, n, sub, live) for p, n, sub in ports)
                        + add_port_row(slug, live)))


def address_row(slug, target, sub, revoke, live=True):
    control = ""
    if revoke:
        control = (button("Revoke", "js-addr-revoke", data_host=slug, data_address=target)
                   if live else button("Revoke", "js-act", data_msg="The proof would be revoked here"))
    return hset_row("globe-hemisphere-west", target, sub, control, mono=True)


def add_address_button(slug, live=True):
    """The one way to add an address: a button in the Addresses heading's
    line, which opens the address window for this server (`address_modal`).
    Until 2026-10-06 the section ended in a row holding a field, two ways to
    prove, Start, a token box and Verify, refused on sight (docs/RECORD.md
    4.365, 4.379)."""
    if not live:
        return button("Add address", "pri js-act", data_msg="The address window would open here")
    return button("Add address", "pri", data_open="addr-ovl", data_host=slug)


def addresses_panel(slug, addresses, live=True):
    """`addresses` is [(target, sub, revocable)], escaped. The proved
    addresses and nothing else: a row is only ever drawn from the registry's
    own row."""
    rows = "".join(address_row(slug, t, sub, rev, live) for t, sub, rev in addresses)
    if not rows:
        rows = f'<div class="li lempty">{esc(NO_ADDRESS_LINE)}</div>'
    return hset_list(rows)


def silence_row(slug, protocol, port, family, sub, live=True):
    un = (button("Unsilence", "js-unsilence", data_host=slug, data_protocol=protocol,
                 data_port=port, data_family=family) if live
          else button("Unsilence", "js-act", data_msg="The silence would end here"))
    # The family is in the row's name. A silence is for one family, and a port
    # silenced on both was two rows that read the same, each with a button
    # that ends one of them (measured 2026-10-06, docs/RECORD.md 4.393).
    return hset_row("plug", f"{port}/{protocol} {family}", sub, un, mono=True)


def alerts_panel(slug, quiet_minutes, silences, live=True, agent=True):
    """`silences` is [(protocol, port, family, sub)], escaped. `agent` is
    whether the server has an agent.

    The two mail rows are facts with nothing at their right. Both alerts are
    built and raised for every server. They carried a switch, on and
    disabled, and the planned tag, which read as alerts not built yet
    (the outside review of 2026-10-06, docs/RECORD.md 4.460). No switch per
    server exists: the header's Mute stops a server's change mails and
    Paused under Server stops its quiet alert (controlplane/app/alerts.py).
    A server with no agent never raises the quiet alert, because only a
    report ends one, so it has no quiet row."""
    mail = hset_row("envelope-simple", "On a change to this server")
    if agent:
        mail += hset_row("envelope-simple", "When the agent goes quiet",
                         f"after {int(quiet_minutes)} minutes" if quiet_minutes else "")
    rows = "".join(silence_row(slug, p, n, f, sub, live) for p, n, f, sub in silences)
    if not rows:
        rows = f'<div class="li lempty">{esc(NO_SILENCES)}</div>'
    return hset_h3("Mail") + hset_list(mail) + hset_h3("Silenced ports") + hset_list(rows)


def type_to_confirm_html(prefix, label):
    """The line and the field a window uses to have a name typed before it
    does something that cannot be undone.

    The name sits in a chip that copies it on a click, the pattern of a
    delete window that makes its reader type the name (the owner chose that
    flow on 2026-09-10). It is its own fragment because removing
    a server is the first of these and not the last. `prefix` names the ids,
    so one page can hold several, and the page script fills in the name when
    the window opens.
    """
    chip = (f'<button type="button" class="cfchip" id="{prefix}-chip" title="Copy">'
            f'<b class="mono" id="{prefix}-name2"></b>{theme.icon("copy", 14)}</button>')
    return (f'<div class="s">Type {chip} to confirm.</div>'
            f'<input class="in mono" id="{prefix}-input" autocomplete="off"'
            f' spellcheck="false" aria-label="{esc(label)}">')


# The one command that takes the agent off the machine, shipped inside the
# package so it needs no network (docs/PRODUCT.md 4f). It has no host-specific
# part, so the window carries it as it is.
UNINSTALL_COMMAND = "sudo whichports-uninstall"


def remove_modal():
    """The remove window, one for the page: the title with the name, the
    name to type with its copy chip, the field, two rows about the machine,
    then Cancel and a red Remove that is enabled only when the typed name
    matches. The way out comes first and the action last, as every other
    window here and the picture the owner sent both have it.

    The two rows start hidden and the page script shows what applies: when
    the agent last reported, and the command for the server as a copy chip
    (docs/screens/host-settings/BRIEF-remove-command.md). The window stays
    open after Remove, so the command can still be copied."""
    return f"""<div class="ovl js-modal" id="rm-ovl">
  <div class="modal panel rmw">
    <div class="m-h"><h2>Remove <span id="rm-name"></span></h2><button class="m-x" data-close="rm-ovl" aria-label="Close">{theme.icon('x', 18)}</button></div>
    {type_to_confirm_html("rm", "Server ID")}
    <div class="rmrow" id="rm-last" hidden><span class="l">Last report</span><span class="v" id="rm-last-v"></span></div>
    <div class="rmrow" id="rm-cmd" hidden><span class="l">On the server</span><div class="code m-copy" id="rm-cmd-v">{UNINSTALL_COMMAND}</div></div>
    <div class="m-foot"><span class="m-note"></span>
      <span class="acts">{button("Cancel", data_close="rm-ovl")}{button("Remove", "danger", id="rm-go", disabled=True)}</span></div>
  </div>
</div>"""


def delete_modal():
    """The delete window, one for the page, in the remove window's shape with
    its own ids: the title with the name, the name to type with its copy
    chip, the field, then Cancel and a red Delete enabled only when the typed
    name matches. It opens from a removed server's row alone, and what it
    takes is the row with everything stored about it (docs/PRODUCT.md 4f)."""
    return f"""<div class="ovl js-modal" id="del-ovl">
  <div class="modal panel rmw">
    <div class="m-h"><h2>Delete <span id="del-name"></span></h2><button class="m-x" data-close="del-ovl" aria-label="Close">{theme.icon('x', 18)}</button></div>
    {type_to_confirm_html("del", "Server ID")}
    <div class="m-foot"><span class="m-note"></span>
      <span class="acts">{button("Cancel", data_close="del-ovl")}{button("Delete", "danger", id="del-go", disabled=True)}</span></div>
  </div>
</div>"""


def removed_list_html(rows):
    """The servers Remove took out of the fleet, under the table: one row
    each with the day it was removed and Delete, which opens the delete
    window (docs/PRODUCT.md 4f). `rows` is ((name, removed), ...), both
    escaped by the caller.

    Always in the page, empty and hidden when there is none, so the quiet
    refresh has a piece to swap when the first server is removed: a piece
    that is not on the page cannot be swapped in."""
    if not rows:
        return '<div class="fgone" hidden></div>'
    lines = "".join(
        hset_row("hard-drives", name, removed,
                 button("Delete", "danger js-delete", data_host=name, data_name=name))
        for name, removed in rows)
    return f'<div class="fgone">{alerts_h2("Removed")}{hset_list(lines)}</div>'


# ------------------------------------------------------------- the Host Changes
#
# docs/screens/host-changes/SPEC.md, provisional: a log of the server, one
# table, newest first, five columns and no sentences. Only what the three
# views observed change. A person's own answers are not lines here.

@dataclasses.dataclass
class Change:
    """One line of the log. `when` is a datetime, `layer` the words under
    the spec's Layer column, `source` the small caps under it, `kind` the
    neutral tag, `families` the address families the change is about (one
    or both), `detail` the thing itself in the layer's own words, `off`
    whether something went away, `kind_unsure` a marker title for a kind
    the spec does not list."""
    when: object
    layer: str
    source: str
    kind: str
    protocol: str = ""
    port: object = ""
    families: tuple = ()
    detail: str = ""
    off: bool = False
    kind_unsure: str = ""


CHANGE_KINDS = ("reachable", "unreachable", "started", "stopped", "rule added",
                "rule removed", "published", "unpublished")
CHANGE_COLUMNS = ("When · UTC", "Layer", "Change", "Port", "Detail")
CHANGE_RANGES = (("24h", 1), ("7d", 7), ("30d", 30), ("90d", 90))
NO_CHANGES = "Nothing changed in this period."


def change_port_html(protocol, port, families):
    if not port:
        return '<span class="cpn"></span>'
    fams = "+".join(f'<i class="{esc(f)}">{esc(f)}</i>' for f in families)
    small = esc(str(protocol).upper()) + (f"/{fams}" if fams else "")
    return f'<span class="cpn">{esc(port)}<small>{small}</small></span>'


def change_row_html(change, now):
    """One line. `data-r` says which range it falls in, 1 for the last day
    and 7 otherwise, which is what the range control reads."""
    within_day = (now - change.when).total_seconds() <= 86400
    kind_cls = "ckind off" if change.off else "ckind"
    tag_html = evidence_tag(change.kind, off=False)
    return (f'<div class="cr" data-r="{1 if within_day else 7}">'
            f'<span class="cwhen"><b>{esc(change.when.strftime("%-d %b"))}</b> '
            f'{esc(change.when.strftime("%H:%M"))}</span>'
            f'<span class="clay">{esc(change.layer)}<small>{esc(change.source)}</small></span>'
            f'<span class="{kind_cls}">{tag_html}</span>'
            f'{change_port_html(change.protocol, change.port, change.families)}'
            f'<span class="cdet">{esc(change.detail)}</span></div>')


def changes_thead_html():
    return (f'<div class="ch">'
            + "".join(f"<span>{esc(c)}</span>" for c in CHANGE_COLUMNS) + "</div>")


def range_control_html(slug):
    """The radios and their pills. 24h and 7d switch the rows by CSS
    (changes_css); the two longer ranges are not read yet and say so."""
    radios = "".join(
        f'<input type="radio" class="rgsel r{days}" name="rg-{esc(slug)}" id="rg-{esc(slug)}-{label}"'
        + (" checked" if days == 7 else "") + ">"
        for label, days in CHANGE_RANGES if days <= 7)
    pills = ""
    for label, days in CHANGE_RANGES:
        if days <= 7:
            pills += f'<label class="rgl r{days}" for="rg-{esc(slug)}-{label}">{label}</label>'
        else:
            pills += f'<span class="rgl off">{label}{tag("planned", "planned")}</span>'
    return radios, f'<span class="rng">{pills}</span>'


def changes_count_html(day, week, since=""):
    """The line at the left: the count for the range the pills pick. `since`
    names the oldest document read when the read stopped short of the
    window, in place of the period."""
    period7 = f"since {esc(since)}" if since else "in the last 7 days"
    return ('<span class="cnt">'
            f'<span class="c1"><b>{int(day)}</b> {"change" if day == 1 else "changes"} in the last 24 hours</span>'
            f'<span class="c7"><b>{int(week)}</b> {"change" if week == 1 else "changes"} {period7}</span>'
            '</span>')


def changes_table_html(slug, changes, now, since="", shown=None):
    """The tab: the range radios, the count line with the pills, the table.
    `shown` caps the rows drawn; the count still says how many there were."""
    rows = changes if shown is None else changes[:shown]
    day = sum(1 for c in changes if (now - c.when).total_seconds() <= 86400)
    radios, pills = range_control_html(slug)
    body = "".join(change_row_html(c, now) for c in rows)
    if not body:
        body = f'<div class="cr cempty">{esc(NO_CHANGES)}</div>'
    return (f'{radios}<div class="ctop">{changes_count_html(day, len(changes), since)}{pills}</div>'
            f'<div class="panel ctbl">{changes_thead_html()}{body}</div>')


def changes_css():
    """The range control: the checked radio shows its count and hides the
    rows outside its range, and its pill reads as chosen."""
    return "\n".join([
        ".rgsel{position:absolute;opacity:0;pointer-events:none}",
        ".rgsel.r1:checked~.ctop .c7,.rgsel.r7:checked~.ctop .c1{display:none}",
        '.rgsel.r1:checked~.ctbl .cr[data-r="7"]{display:none}',
        ".rgsel.r1:checked~.ctop .rgl.r1,.rgsel.r7:checked~.ctop .rgl.r7{background:var(--panel2);color:var(--ink)}",
        ".rgsel:focus-visible~.ctop .rgl{outline:2px solid var(--acc);outline-offset:2px}",
    ])


CSS += "\n" + changes_css() + "\n"


# ------------------------------------------------------------ the Host Services
#
# docs/screens/host-services/SPEC.md: a row is a thing that runs, never a
# port. Four groups in a fixed order, an empty one not drawn, and a port chip
# opens that port's row on the Overview, where the answer lives.

@dataclasses.dataclass
class ServiceRow:
    """One thing that runs. `ports` is [(label, tone, row id)] with the label
    the port and its protocol ("8096/tcp"), the tone the port's state tone
    ("" for a port with no state) and the row id the Overview row the chip
    opens. `fact` is the one mono line under the name: the image, the unit
    file or the pid. `declared` is the name the operator gave a port on the
    row, empty when nobody gave one, drawn beside the measured name and never
    in its place (the owner's delegated call, 2026-09-13, docs/RECORD.md 4.174)."""
    tone: str
    word: str
    name: str
    fact: str = ""
    ports: tuple = ()
    bound: str = ""
    declared: str = ""


# (key, title, the grey word), in the spec's order. The runtime word of the
# containers group is the runtime itself, filled in per group.
SERVICE_GROUPS = (("containers", "Containers", ""), ("units", "Socket units", "systemd"),
                  ("processes", "Processes", ""), ("loopback", "Loopback only", ""))

# The provenance a declared name carries, in one spelling for every screen
# (render_live.NAMED_BY_YOU is this one). A declared name is something a
# person typed, never a measurement.
NAMED_BY_YOU = "named by you"
NOTHING_LISTENING = "Nothing listening."
SOCKETS_UNREADABLE = "Sockets not readable."


def service_chip_html(label, tone, row, tab):
    """One port chip. A button, because opening the port's row is a tab
    switch and a checkbox at once, which no label can do alone."""
    num, _, proto = label.partition("/")
    return (f'<button class="spc {tone or "off"}" data-row="{esc(row)}" data-tab="{esc(tab)}">'
            f'{esc(num)}<small>{esc(proto)}</small></button>')


def service_row_html(slug, row):
    tab = f"tb-{slug}-overview"
    chips = "".join(service_chip_html(label, tone, rid, tab) for label, tone, rid in row.ports)
    state = theme.status(row.tone, esc(row.word)) if row.word else ""
    fact = f"<small>{esc(row.fact)}</small>" if row.fact else ""
    given = (f'<span class="sdn" title="{NAMED_BY_YOU}">{esc(row.declared)}</span>'
             if row.declared else "")
    return (f'<div class="srow"><span class="sst">{state}</span>'
            f'<span class="snm"><b>{esc(row.name)}</b>{given}{fact}</span>'
            f'<span class="schips">{chips}</span>'
            f'<span class="sbd">{esc(row.bound)}</span></div>')


def service_group_html(slug, title, word, rows, unsure=""):
    """One group: its header band and its rows. An empty group is not drawn."""
    if not rows:
        return ""
    cls = ' class="sgh unsure"' if unsure else ' class="sgh"'
    title_attr = f' title="{esc(unsure)}"' if unsure else ""
    grey = f"<span>{esc(word)}</span>" if word else ""
    return (f"<div{cls}{title_attr}><b>{esc(title)}</b>{grey}</div>"
            + "".join(service_row_html(slug, r) for r in rows))


def services_thead_html():
    return (f'<div class="sh"><span>State</span>'
            '<span>What runs</span><span>Ports</span><span>Bound to</span></div>')


def services_table_html(slug, groups, empty_line=NOTHING_LISTENING):
    """The one table of the tab. `groups` is [(title, grey word, rows,
    unsure title)]. With nothing in any group the table is the header and
    one line, so the tab never opens on nothing at all."""
    body = "".join(service_group_html(slug, title, word, rows, unsure)
                   for title, word, rows, unsure in groups)
    if not body:
        body = f'<div class="srow sempty">{esc(empty_line)}</div>'
    return f'<div class="panel stbl">{services_thead_html()}{body}</div>'


def host_head(name_html, status_html, hsub_html, facts_html=""):
    """The top of a server's page: its name, its state, and the line of facts
    under it. Renaming is a row in the server's own settings, so the header
    only says the name. `facts_html` is the Host Overview's labelled cells
    (host_facts_html), drawn after the sub-line when there is one."""
    # An empty sub-line draws no element rather than an empty one, or the page
    # keeps the gap under the name for a line that says nothing.
    sub = f'<div class="hsub">{hsub_html}</div>' if hsub_html else ""
    return f'<div><h1>{name_html} {status_html}</h1>{sub}{facts_html}</div>'


# ---------------------------------------------------------------- fragments
# Each of these renders one repeated shape. build.py feeds them the sample
# lists below, render_live.py feeds them what the control plane measured.
# Same functions, so the two cannot drift apart.
#
# Field-level strings are HTML-escaped here, at the boundary where they enter
# markup. The agent already strips control characters because a process picks
# its own name (RECORD 4.14), but < > & are legal in a comm and in rule text,
# and a browser must render them as text, never parse them. Same rule as the
# terminal, different escape.

def esc(s):
    return html.escape(str(s), quote=True)


def scan_button(host, live=True):
    """Scan now on a host page: host page only and secondary weight
    (docs/PRODUCT.md 5f). No window: the click marks the Probed fact as
    probing at once and the page follows (docs/screens/host-overview/SPEC.md,
    "with no dialog"). A window was kept on 2026-09-06 to hold the one-shot
    command for the agent. On 2026-09-20 the owner found it odd to have to run
    a command on a server by hand for this, and the agent
    reports by itself every fifteen minutes, so the window and the command
    left the screen (docs/RECORD.md 4.196).

    `live=False` is the sample shell, where nothing is wired to a control
    plane: the button says what it would do, as every other control there
    does. It was the live button until 2026-10-07, and on a page with nothing
    behind it the click answered with a refusal (docs/RECORD.md 4.443)."""
    if not live:
        return button("Scan now", "js-act", data_msg="The server would be scanned here")
    return button("Scan now", "js-scan", data_host=host)


def button(label, cls="", **attrs):
    """One button. `cls` is what follows `btn` in the class, `attrs` are the
    attributes in the order given, an underscore in a name standing for a
    hyphen (`data_host` is `data-host`), and True for a bare attribute such
    as `disabled`. Neither the label nor a value is escaped here: callers
    pass what they mean to put on the page, escaped where it came from
    somebody else, exactly as they did when every button was written out.

    Every `btn` on both feeds goes through this since 2026-09-03, so a button
    has one shape and one place to change it."""
    parts = []
    # type goes first, the one attribute the sites that used it wrote before
    # the class, so their bytes are unchanged.
    if "type" in attrs:
        parts.append(f' type="{attrs.pop("type")}"')
    parts.append(f' class="btn{" " + cls if cls else ""}"')
    for name, value in attrs.items():
        name = name.replace("_", "-")
        if value is True:
            parts.append(f" {name}")
        elif value is not False and value is not None:
            parts.append(f' {name}="{value}"')
    return f"<button{''.join(parts)}>{label}</button>"


def tag(kind, word="", **attrs):
    """One tag: the small mark beside a label or a state, `<span
    class="tag-<kind>">word</span>`. `planned`, `rate`, `mute`, `mode`, `rvw`,
    `alert`, `rec`, `disagree` and `rare` are the kinds the stylesheet knows. The word may be empty
    where a mark is written for the script to fill later, and the attributes
    follow the same rules as button(): given order, underscore for hyphen,
    True for a bare attribute. Nothing is escaped here.

    Every tag on both feeds goes through this since 2026-09-03; the six
    builders below it are what a kind means, this is only how one is drawn."""
    parts = []
    for name, value in attrs.items():
        name = name.replace("_", "-")
        if value is True:
            parts.append(f" {name}")
        elif value is not False and value is not None:
            parts.append(f' {name}="{value}"')
    return f'<span class="tag-{kind}"{"".join(parts)}>{word}</span>'


PLANNED_TAG = tag("planned", "planned")


# ------------------------------------------------------- the order of the list
# The fleet list is sorted by how much a row needs a person, then by host name.
# The owner asked for it on 2026-08-15: what matters rises to the top, and the
# rest is alphabetical.
#
# The bands, worst first, and one line each on why the band is where it is:
#
#   0  conflict            reachable and you marked it closed. The to-do list
#   1  unreviewed          reachable, nobody has said whether that is intended
#   2  (was stale rule until 2026-09-21. It is with the quiet majority now: a
#      rule with nothing behind it is worth seeing and is owed by nobody,
#      docs/RECORD.md 4.198. The numbers below keep their old values so the
#      notes that cite them still read.)
#   3  unexplained         the probe sees it, no agent can attribute it
#   4  not watched         enrolled and its agent never spoke, or nobody has
#                          probed it yet. `never reported` until 2026-10-09.
#   5  silent              it reported before and has stopped
#   6  paused, revoked     deliberately not watched, so not a finding
#   7  anything else       a word this table does not know, see below
#   8  intended, reporting, stale rule   the quiet majority, last
#
# Port states come before agent problems: a reachable port nobody has reviewed
# is a fact about the server, a quiet agent is a fact about our own measurement.
# Bands 0 to 3 need the prober, so a live page today only ever produces bands 4
# upwards. They are in the table because the sample shell shows them and
# because the order is decided once, not twice.
#
# Two rules make the order stable and not merely correct. Inside a band, rows
# sort by host name and case is ignored, so two renders of the same fleet
# cannot come out in different orders. And a word this table does not know
# keeps its row: it lands in band 7, above the quiet majority so somebody sees
# it, below every state we do recognise so it can never push a conflict off the
# top. Dropping the row instead is the worst bug this list could have, so
# a test proves it cannot happen.
#
# The words themselves are `docs/DESIGN.md` section 3, which owns them. This
# only says what order they come in.
FLEET_BANDS = (
    ("conflict",),
    ("unreviewed",),
    ("unexplained",),
    # A host whose newest stored document could not be read at all. Ranked
    # with the problems on purpose: nothing about this host can be read, which
    # is worse than a host whose last good document merely went stale.
    ("not readable",),
    # A server whose ports are fine and that still has an alert open: under
    # every port problem, above the quiet servers (the owner, 2026-09-20).
    ("alert open",),
    # A host that WAS reporting and went quiet is a real problem, so it stays
    # near the top. A host that never reported is not the same thing and is
    # ranked below, see the note under this table.
    ("silent",),
    # An address host nobody has proved an address for cannot be looked at,
    # which is a problem of the same weight as an agent gone quiet.
    ("no proof",),
    ("paused",),
    # Nobody has measured this server from outside yet. Not a problem, and not
    # an answer either, so it sits above the servers that have one. It used to
    # fall into the unknown band below by accident, which put it in the same
    # place by luck; since 2026-08-28 an agent host with no probe lands here
    # too (`docs/RECORD.md` 4.115), so it is ranked on purpose. Since
    # 2026-10-09 its word is `not watched`, one word and one band with a
    # host that never reported, the last (docs/record 4.447).
    None,                      # every word the table does not know
    # The quiet majority. `not reachable` joined them on 2026-08-28 with the
    # state itself (`docs/RECORD.md` 4.112): a port that is shut and that
    # nobody has declared is not a finding to act on, and ranking it above
    # `intended` would put every firewalled port on the fleet ahead of the
    # ports somebody actually decided about.
    # `stale rule` joined them on 2026-09-21 (docs/RECORD.md 4.198). No server
    # reads it any more, and as a port state it ranks with the quiet ones.
    ("stale rule", "intended", "reporting", "watched", "not reachable"),
    # Last, deliberately. Revised 2026-08-16 after the owner opened the live page
    # and found nine of twelve rows were `new-xxxxxx` placeholders sitting above
    # his three real servers, and said the Fleet's text was rendered wrong
    # throughout. He was right, and this table was part of why.
    #
    # A row that never reported is a pending enrolment, not a finding. It is the
    # same distinction the dead-man sweep needed: a host that never started has
    # not stopped. Ranking it with the problems buried the working fleet under
    # rows that had never been a server. `never reported` and `not probed
    # yet` are this one word since 2026-10-09.
    ("not watched",),
)

# The words the tag used before they were renamed, each pointing at the word
# that replaced it. They are read because the rename and this sort are separate
# branches that can land in either order, and because a sort is not the place
# to notice that a word moved. Delete a line here once no builder writes that
# word any more.
RETIRED_STATE_WORDS = {
    "you said no": "conflict",
    "never reviewed": "unreviewed",
    "unknown": "unexplained",
}

BAND_OF_STATE = {word: band for band, words in enumerate(FLEET_BANDS) if words
                 for word in words}
UNRANKED_BAND = FLEET_BANDS.index(None)


def fleet_band(word):
    """Which band a state word sorts into. An unknown word gets its own."""
    w = " ".join(str(word).split()).lower()
    w = RETIRED_STATE_WORDS.get(w, w)
    # `freshness()` in render_live.py appends the age to this one word, as in
    # "silent 12m", so it is matched on its start. Every other word is matched
    # whole, because a loose match would quietly swallow a word nobody has
    # thought about yet and it would sort as something it is not.
    if w.startswith("silent"):
        w = "silent"
    return BAND_OF_STATE.get(w, UNRANKED_BAND)


def fleet_sort_key(row):
    """(band, folded shown name, name) for a FleetRow.

    The folded name is the order a reader sees, so it is the name the row
    shows in bold: the display name when the server has one. The name the
    server is found by settles two rows that show the same thing, which two
    display names may, so the result does not depend on the order the rows
    happened to arrive in.
    """
    word, name = row.word, row.name
    shown = getattr(row, "display", "") or name
    # An open alert first, whatever the state word, as the owner asked on
    # 2026-09-08 (docs/RECORD.md 4.155), then the bands.
    return (0 if getattr(row, "alert", "") else 1, fleet_band(word),
            1 if getattr(row, "pending", False) else 0,
            str(shown).casefold(), str(name))


def sort_fleet_rows(rows):
    """The fleet rows, worst first and then by name. A new list, so a caller
    that needs its own order keeps it."""
    return sorted(rows, key=fleet_sort_key)


# ------------------------------------------------------- what a fleet row says
# The Fleet screen as decided on 2026-09-03: the spec is
# docs/screens/fleet/SPEC.md and the approved sketch is fleet.html beside it.
# Everything here draws what that spec says and nothing it does not.

# The four columns, in reading order. Both feeds build the header from this, so
# the sample shell and a live page cannot come out with different columns.
# There were five until 2026-10-02: the owner took the Agent column out
# (docs/screens/fleet/SPEC.md section 5).
FLEET_COLUMNS = ("State", "Server", "Reachable", "Needs a decision")

# The port states that put a chip in the Needs a decision cell, worst first
# (SPEC.md section 5). `intended` and `not reachable` are the quiet majority and
# get no chip.
NEEDS_DECISION = ("conflict", "unreviewed", "unexplained")

# The state words a row shows for a server nothing is wrong with. The engine's
# own words for its ports are `intended` and `not reachable`, and the spec has
# one word for a fine server, `watched`, on an agent host and an address host
# alike (SPEC.md section 5).
# `stale rule` joined them on 2026-09-21. It is a rule that permits a port
# nothing listens on: worth seeing on its row, in grey, and not a decision
# anybody owes. Counted as one, it turned a server amber, and a fleet on
# firewalld's default permits would have opened amber on its first day
# (the owner's hard rule that nothing should feel like homework, and his yes to
# this, docs/RECORD.md 4.198).
QUIET_PORT_WORDS = ("intended", "not reachable", "stale rule")
WATCHED = ("ok", "watched")
# What a server reads in place of `watched` while an alert on it is still
# open. The owner, 2026-09-20: a green `watched` does not belong on a server
# with an alert still open, only once everything is resolved. The word is
# the open-alert mark's own, as a state.
ALERT_OPEN = ("fail", "alert open")

# How a server is watched, among the facts under its name on its own page:
# the word, and the Phosphor glyph beside it. The keys are the words
# `monitoring_mode` in render_live.py produces, so the mapping from a
# measurement to a word is written once.
# Two kinds since 2026-09-12, agent and none (docs/screens/fleet/SPEC.md
# section 5, docs/RECORD.md 4.169): the read modes the renderer still
# distinguishes all draw the one word, because there is one agent and the
# word said what kind it was. "full" and "limited" left on 2026-09-18.
AGENT_WORD = {"full read": "agent", "partial read": "agent", "no agent": "none",
              "agent": "agent"}
AGENT_ICON = {"agent": "binoculars", "none": "globe-hemisphere-west"}

# The state words whose row leaves Reachable and Needs a decision empty, from
# the table in SPEC.md section 5. Every other row shows what it has, and a cell
# with nothing to show holds nothing: no sentence in it, ever.
CELLS_EMPTY = ("not readable", "no proof", "paused", "not watched")


@dataclasses.dataclass(frozen=True)
class FleetRow:
    """One server on the Fleet table. `reach` is (ports open from outside,
    ports observed on this server) or None when nothing was observed. `chips`
    is ((label, tone), ...) worst first. `alert` is when the server's open alert
    was raised, or empty; it is drawn as a magenta marker while item 12 of the
    Fleet build is undecided. `tags` is the words a person put on the server,
    in the order they were saved. `display` is the display name a person gave
    it, or empty: a label for the reader, and `name` stays what the server is
    found by."""
    tone: str
    word: str
    name: str
    hostname: str = ""
    reach: tuple | None = None
    chips: tuple = ()
    muted: bool = False
    alert: str = ""
    disagree: bool = False
    tags: tuple = ()
    display: str = ""
    # The server has a port that answers from outside and is on the list of
    # ports that should rarely face the internet: the mark beside its state.
    rarely: bool = False
    # A pending enrolment: a server that has never sent a document. It shares
    # the word `not watched` with a server nobody has probed since
    # 2026-10-09, and inside that band it sorts after one that reports, so
    # the owner's bug of 2026-08-16 stays fixed (docs/record 4.447).
    pending: bool = False
    # The server is paused. Its state says so when nothing worse is to be
    # said, and under a worse word this draws the mark beside it.
    paused: bool = False
    # The words of the CVE check's own mark for this server, or empty.
    fix: str = ""
    # The newest report arrived and could not be read, which is what the
    # state `not readable` stands for on this row. The line under the name
    # says so (FLEET_UNREADABLE_LINE).
    unread: bool = False

    @property
    def cells_shown(self):
        return self.word not in CELLS_EMPTY


def fleet_totals(rows, changed=0):
    """The four numbers over the table, from the rows under them.

    Each is a sum of what the rows show, so the boxes and the table cannot
    disagree: a row whose cells are empty by the spec's table contributes
    nothing. `ports` is the joined port set the sub-line reads, every port
    with a listener or a probe result on a row that shows its ports.
    `changed` comes from the recorded transitions and is handed in.
    """
    conflict = decision = reachable = ports = 0
    for row in rows:
        if not row.cells_shown:
            continue
        conflict += sum(1 for _label, tone in row.chips if tone == "fail")
        decision += sum(1 for _label, tone in row.chips if tone != "fail")
        if row.reach:
            reachable += row.reach[0]
            ports += row.reach[1]
    return {"conflict": conflict, "decision": decision, "reachable": reachable,
            "changed": changed, "ports": ports}


def fleet_box(label, number, total, tone=""):
    """`tone` colours the number and the bar only when there is a number to
    colour: a zero in red said something was wrong (the owner, 2026-09-06)."""
    if not number:
        tone = ""
    pct = round(100 * number / total) if total else 0
    pct = min(pct, 100)
    n_cls = f' class="n {tone}"' if tone else ' class="n"'
    i_cls = f' class="{tone}"' if tone else ""
    return (f'<div><div class="l">{esc(label)}</div><div{n_cls}>{number}</div>'
            f'<div class="d">of {plural(total, "port")}</div>'
            f'<div class="fbar"><i{i_cls} style="width:{pct}%"></i></div></div>')


def fleet_strip_html(totals):
    """The four boxes (SPEC.md section 3), in this order and no other."""
    t = totals
    return ('<div class="fstrip">'
            + fleet_box("Disagrees with what you declared", t["conflict"], t["ports"], "fail")
            + fleet_box("Needs a decision", t["decision"], t["ports"])
            + fleet_box("Reachable from outside", t["reachable"], t["ports"])
            + fleet_box("Changed in 24h", t["changed"], t["ports"])
            + '</div>')


# The two tones a banner can take, worst first.
NOTE_TONES = ("fail", "warn")


def fleet_note_html(tone, key, text_html, action_label, action_view):
    """One banner (SPEC.md section 1): a dot in the tone colour, the sentence
    with its value in bold, one action, a dismiss.

    `key` names the fact, source and value together, so the dismiss can hide
    this fact on this browser and a new fact shows again. `text_html` is
    already escaped by the caller, with the value inside <b>.
    """
    if tone not in NOTE_TONES:
        raise ValueError(f"a banner is fail or warn, not {tone!r}")
    return (f'<div class="fnote {tone}" data-note="{esc(key)}">'
            f'<span class="t">{text_html}</span>'
            f'{button(esc(action_label), data_go=esc(action_view))}'
            f'<button class="x" aria-label="Dismiss">&times;</button></div>')


def fleet_notes_html(notes):
    """The banner region. `notes` is [(tone, key, text_html, action_label,
    action_view)]. They are drawn worst first and the stylesheet shows only
    the first that is not dismissed, so at most one banner shows at a time.
    Nothing to say draws an empty region, which the stylesheet keeps off the
    screen."""
    order = {tone: i for i, tone in enumerate(NOTE_TONES)}
    body = "".join(fleet_note_html(*note)
                   for note in sorted(notes, key=lambda n: order.get(n[0], len(NOTE_TONES))))
    return f'<div class="fnotes">{body}</div>'


def fleet_thead_html():
    """The header row, built from FLEET_COLUMNS. Uppercase, as the approved
    sketch draws it, and marked unsure because the 2026-08-29 rule says a
    table header is sentence case."""
    return "".join(f"<span>{label}</span>" for label in FLEET_COLUMNS)


def port_chips_html(chips):
    """The Needs a decision cell: one chip per port that needs somebody, and
    nothing else. Nothing needing a decision is an empty cell. It ended in
    "+ N", the count of the ports that need none, until that read as N more
    that do (docs/RECORD.md 4.395)."""
    return "".join(f'<span class="fpc {tone}">{esc(label)}</span>' for label, tone in chips)


def reach_cell_html(reach, disagree=False):
    """"n of m ports", and the neutral disagree mark after it when any port
    on the server carries the engine's mark (docs/screens/fleet/SPEC.md, the
    Reachable column with two vantages). The unit is on the cell since
    2026-10-11, as it is on the box above the table (docs/record 4.451)."""
    if reach is None:
        return ""
    n, m = reach
    return f'<b>{int(n)}</b> of {plural(int(m), "port")}{disagree_flag(disagree)}'


def alert_mark_html(raised):
    """The open-alert badge beside the state. The owner, 2026-09-06: a badge
    without the date for now, so the row says an alert is open and the
    Alerts screen says when."""
    if not raised:
        return ""
    return tag("alert", ALERT_OPEN_WORD, title=ALERT_OPEN_WORD)


def state_marks_html(name, word, muted, raised, rarely=False, paused=False, fix=""):
    """The slim marks beside a server's one main state: paused, muted, an
    open alert, a reachable port that should rarely face the internet, and
    the CVE check's own mark with its words in `fix`. One function, so the
    Fleet row and the server's own header draw the same marks for the same
    server. The header drew no alert at all before 2026-09-21.

    An open alert is not marked beside the state `alert open`, which is the
    same fact said once already. Paused is not marked beside the state
    `paused` for the same reason.
    """
    alert = "" if word == ALERT_OPEN[1] else alert_mark_html(raised)
    pause = "" if word == PAUSED_WORD else paused_flag(paused)
    return pause + muted_mark_html(name, muted) + alert + rarely_flag(rarely) + fix_flag(fix)


def state_set_html(name, tone_word, muted, raised, rarely=False, paused=False, fix=""):
    """A server's one main state with its slim marks, as the one group the
    header draws beside the name."""
    tone, word = tone_word
    return (f'<span class="stset">{theme.status(tone, esc(word))}'
            f'{state_marks_html(name, word, muted, raised, rarely, paused, fix)}</span>')


def muted_mark_html(name, muted):
    """The mute mark beside the state, written empty on every row so the mute
    click can fill it (see muted_flag). The sketch has no mute mark. It stays,
    in the neutral tag shape, so a muted server does not read as a quiet one:
    The owner's delegated call on 2026-09-13, `docs/RECORD.md` 4.174."""
    return muted_flag(name, muted)


def fleet_tags_html(tags):
    """A server's tags, one small box per word."""
    return "".join(f'<span class="ftag">{esc(t)}</span>' for t in tags)


def fleet_shown_name(row):
    """What a row says in bold: the display name a person gave the server
    when it has one, the name it is found by otherwise."""
    return row.display or row.name


def fleet_under(row):
    """What sits under the bold name: the hostname the server reports, or the
    name it is found by when it reports none. It is drawn only when it says
    something the bold name does not."""
    return row.hostname or row.name


def fleet_host_html(shown, under):
    """The line under a server's bold name, only when it differs from what
    the bold name says."""
    if not under or under == shown:
        return ""
    return f'<small class="fhost">{esc(under)}</small>'


# The line under a server's name when its newest report could not be read.
# The row read `not readable` and nothing said what (the outside review's
# point 2, docs/RECORD.md 4.460). It is its own element and not `.fhost`,
# which the page script redraws when a display name is saved.
FLEET_UNREADABLE_LINE = "newest report could not be read"


def fleet_unread_html(row):
    if not row.unread:
        return ""
    return f'<small class="funread">{esc(FLEET_UNREADABLE_LINE)}</small>'


def fleet_row_html(row):
    """One server, one link to its page. In bold its display name, or its
    name when it has none, with its tags beside it. Under them the hostname,
    when it differs from what is in bold. Reachable and Needs a decision are
    empty for the states the spec's table empties them for.

    **The link, `data-host` and everything that acts on the server carry its
    name, never its display name.** `data-under` is what goes under the bold
    name, written on every row so the page script can redraw that line the
    moment a display name is saved or cleared."""
    shown = row.cells_shown
    reach = reach_cell_html(row.reach, row.disagree) if shown else ""
    chips = port_chips_html(row.chips) if shown else ""
    bold = fleet_shown_name(row)
    under = fleet_under(row)
    tags = fleet_tags_html(row.tags)
    host = fleet_host_html(bold, under)
    href = "/host/" + urllib.parse.quote(row.name, safe="")
    return (f'<a class="row" href="{esc(href)}" data-host="{esc(row.name)}"'
            f' data-state="{esc(row.word)}" data-under="{esc(under)}">'
            f'<div>{theme.status(row.tone, esc(row.word))}'
            f'{state_marks_html(row.name, row.word, row.muted, row.alert, row.rarely, row.paused, row.fix)}</div>'
            f'<div class="fsrv"><div class="hn">{esc(bold)}</div>{tags}{host}{fleet_unread_html(row)}</div>'
            f'<div class="frc">{reach}</div>'
            f'<div class="fchips">{chips}</div></a>')


def fleet_rows_html(rows):
    """Every row, in the order given. Sort first with sort_fleet_rows."""
    return "".join(fleet_row_html(row) for row in rows)


# The word an open alert's mark carries, kept for the magenta marker above.
ALERT_OPEN_WORD = "alert open"


# ------------------------------------------------ the port chip vocabulary
# The host overview's port rows carry a chip per port with two bars under it,
# v4 and v6. **A family is filled only where it was measured.** Hollow means
# not tested and never a measured silence, which is `docs/PRODUCT.md` section
# 4b drawn instead of written.
# What a port's own state does to its chip. `listening` is the live page's only
# value today, because nothing joins a measurement onto a port yet, and it is
# deliberately toneless: a chip with a tone would be claiming a finding.
CHIP_CLASS = {"conflict": "hot", "unreviewed": "new", "intended": "ok",
              "stale rule": "stale", "not reachable": "quiet",
              # The warn treatment, like the other two amber findings. It wore
              # the quiet chip until 2026-08-29, the one state whose colour
              # disagreed with its own rank (docs/DESIGN.md section 3).
              "unexplained": "new", "listening": "quiet"}

# Which tone a port state's tag takes, written once. The tone is a property of
# the state and nothing else (docs/DESIGN.md section 3: the word carries the
# state, the tone follows the word).
PORT_TONE = {"conflict": "fail", "unreviewed": "warn", "stale rule": "off",
             # warn since 2026-08-29. It took `off`, which the evidence key
             # says means a view that cannot know, while FLEET_BANDS sorts it
             # with the problems. A finding reads amber like the other two.
             "intended": "ok", "not reachable": "off", "unexplained": "warn"}

# The five states the join engine decides (controlplane/app/join.py), worst
# first. The two maps above also carry `listening`, which is the live page's
# word for a row with no finding, and `not reachable`, which is the sample
# shell's own word. **A declaration can produce neither**, so the page script
# is handed these five and nothing else: a live page that shipped the word
# `not reachable` in its script would be carrying a reachability claim it never
# measured, which is docs/PRODUCT.md 4b.
#
# `render_live.STATE_SEVERITY` is this same list doing the same job of picking
# one word for a port with two families, and a test holds the two together.
DECIDED_STATES = ("conflict", "unexplained", "stale rule", "unreviewed",
                  "intended")


# ------------------------------------------------------------ the Host Overview
# docs/screens/host-overview/SPEC.md, decided 2026-09-04 after twelve rounds,
# built 2026-09-05. The tab a server's page opens on: the fleet's numbers
# scoped to this server, then one row per port in the joined set with the
# three answers, and the evidence for a port under its row when it is opened.

# The six columns, in reading order. The seventh cell is the caret.
HOST_COLUMNS = ("State", "Port", "Service", "From outside", "Decided by", "Your answer")

# The three answers, in the order a row offers them (SPEC.md decision 2).
# Yes declares the port open, no declares it closed, later hides the question
# until the port's state changes, which is what an acknowledgement does
# (controlplane/app/intent.py). The words are also the button classes.
ANSWERS = ("yes", "no", "later")

# What the answer column says beside a stale rule's one answer.
REMOVE_THE_RULE = "or remove the rule"

# The line under the port table of a server watched from outside only.
NO_AGENT_LINE = "No agent, so nothing from inside."


@dataclasses.dataclass(frozen=True)
class PortRow:
    """One port on the Host Overview. `word` is the port's joined state, the
    worse of its families, and "" for a port whose evidence supports none.
    `marks` are the two From outside tones, v4 then v6, "" for not tested.
    `decided` is the Decided by words. `answers` are the answers the row offers, `lit` the
    one that is the answer, `settled` hides the others until the row opens
    and `quiet` hides them all. `cards` is one (family, tone, lead, lines)
    per family for the opened row, `lines` being ((label, html), ...)."""
    protocol: str
    port: int
    word: str = ""
    tone: str = ""
    service: str = ""
    service_note: bool = False
    provenance: str = ""
    marks: tuple = ("", "")
    decided: str = ""
    answers: tuple = ()
    lit: str = ""
    settled: bool = False
    quiet: bool = False
    aside: str = ""
    families: tuple = ("v4", "v6")
    if_declared: tuple = ("", "", "")
    rate_limited: bool = False
    silenced: bool = False
    reach_open: bool = False
    # Answers from outside and is on the list of ports that should rarely
    # face the internet: the slim warn mark beside the state.
    rarely: bool = False
    # What the opened row offers for that mark: "shown" while it is drawn,
    # "dismissed" once a person dismissed it, "" on every other port.
    rare_mark: str = ""
    # What the CVE check says of the package behind the port, as the control
    # plane worked it out (controlplane/app/cvecard.py): the card's lines as
    # ((label, value, note, ids), ...), the words of the check's own mark, and
    # the CVE ids the mark stands for. All empty for a report that carries no
    # packages section, which is every report of the published agent.
    cve_lines: tuple = ()
    cve_mark: str = ""
    cve_ids: tuple = ()
    # A person dismissed the check's mark for everything it stands for
    # (controlplane/app/cvedismiss.py). The card keeps its lines, the mark is
    # not drawn, and the opened row offers Restore.
    cve_dismissed: bool = False
    # Texts on the card drawn as links, as (text, address): the source and
    # the licence of data shared under one (controlplane/app/cvecard.py).
    cve_links: tuple = ()
    state_families: tuple = ()
    # The day a person answered for this port, shown in the opened row as a
    # label and a value since 2026-10-09; "" when nobody has.
    answered_on: str = ""
    cards: tuple = ()
    open: bool = False

    @property
    def label(self):
        return f"{self.port}/{self.protocol}"


def row_id(slug, protocol, port):
    """The checkbox id a port row opens on. `slug` is the host's own slug and
    the rest is ours, never document text, so it is safe in an id."""
    return f"pr-{slug}-{protocol}-{port}"


# What a control of the sample shell says where a live page would ask the
# server. Nothing is wired to a control plane there, and the page goes public
# with nothing behind it, so a control that asked would get a refusal from a
# server that is not there (docs/RECORD.md 4.443).
SAMPLE_ANSWER = "The answer would be saved here"
SAMPLE_ANSWERS = "The answers would be saved here"
SAMPLE_SILENCE = "The port would be silenced here"
SAMPLE_PAUSE = "The server would be paused here"


def answers_html(row, live=True):
    """The answer buttons of one row, the lit one picked. `live=False` is
    the sample shell: each button says what it would do."""
    if not row.answers:
        return ""
    out = ""
    if row.aside:
        out += f'<span class="or">{esc(row.aside)}</span>'
    stub = "" if live else f' js-act" data-msg="{esc(SAMPLE_ANSWER)}'
    for word in row.answers:
        pick = " pick" if word == row.lit else ""
        out += f'<button class="ans {word}{pick}{stub}" data-answer="{word}">{word}</button>'
    return out


def family_marks_html(marks):
    """Both families, boxed, in the answer's colour: green when what the
    prober found agrees with what you say, red when it disagrees, amber when
    it answers and you have not said, grey when not tested (SPEC.md section 6)."""
    v4, v6 = marks
    return f'<span class="prf"><i class="{v4}">v4</i><i class="{v6}">v6</i></span>'


def evidence_card_html(family, tone, lead, lines):
    """One family's card under an opened row: the family mark in its colour,
    the answer in one line, then four lines in the page's text size. What a
    machine said is mono and brighter, which the caller marks with <b>."""
    body = "".join(f'<div class="l"><span class="k">{esc(k)}</span><span class="v">{v}</span></div>'
                   for k, v in lines)
    return (f'<div class="prec"><div class="preh"><span class="prf"><i class="{tone}">{family}</i></span>'
            f'<span class="lead">{esc(lead)}</span></div>{body}</div>')


def mono(text):
    """What a machine said, on a card: mono and brighter."""
    return f'<b class="mono">{esc(text)}</b>'


def port_row_html(slug, row, live=True):
    """One port: the checkbox that opens it, the row as its label, and the
    evidence under it. A row opening is a checkbox and CSS, no script, the
    same way the tabs work (SPEC.md, what it does).

    `live=False` is the sample shell. Its answers name no server, which is
    how the page script knows to leave them to say what they would do."""
    rid = row_id(slug, row.protocol, row.port)
    state = theme.status(row.tone, esc(row.word)) if row.word else ""
    state += (rate_flag(row.rate_limited) + silenced_flag(row.silenced)
              + rarely_flag(row.rarely)
              + fix_flag("" if row.cve_dismissed else row.cve_mark))
    svc_cls = "prs note" if row.service_note or not row.service else "prs"
    kind = "settled" if row.settled else ("quiet" if row.quiet else "")
    open_, closed, none = row.if_declared
    host_attr = f' data-host="{esc(slug)}"' if live else ""
    answers = (f'<span class="pra {kind}"{host_attr} data-protocol="{esc(row.protocol)}"'
               f' data-port="{row.port}" data-fams="{esc(",".join(row.families))}"'
               f' data-stfams="{esc(",".join(row.state_families))}"'
               f' data-st-open="{esc(open_)}" data-st-closed="{esc(closed)}"'
               f' data-st-none="{esc(none)}">{answers_html(row, live)}</span>')
    cards = "".join(evidence_card_html(*card) for card in row.cards)
    cards += answered_line_html(row)
    cards += cve_card_html(row.cve_lines, row.cve_links)
    cards += fix_mark_line_html(slug, row)
    cards += rare_mark_line_html(slug, row)
    # A port counted in Needs a decision only because of the mark, so the page
    # script can take it off the count the moment the mark is dismissed and
    # put it back on Restore (render_live._needs_decision).
    counts = ' data-rare-counts="1"' if row.rare_mark and row.word not in NEEDS_DECISION else ""
    return (f'<input type="checkbox" class="prsel" id="{rid}"{" checked" if row.open else ""}>'
            f'<label class="pr" for="{rid}" data-port="{esc(row.label)}"{counts}>'
            f'<span class="prst">{state}</span>'
            f'<span class="prn">{row.port}<small>{esc(row.protocol)}</small></span>'
            f'<span class="{svc_cls}">{esc(row.service) if row.service else "&mdash;"}'
            f'{f"<small class=\"by\">{esc(row.provenance)}</small>" if row.provenance else ""}</span>'
            f'{family_marks_html(row.marks)}'
            f'<span class="prw">{esc(row.decided)}</span>'
            f'{answers}'
            f'<span class="prc">{theme.icon("caret-down", 14)}</span></label>'
            f'<div class="pre">{cards}</div>')


def host_thead_html():
    """The header row. Uppercase as the approved sketch draws it, and marked
    unsure for the same reason the Fleet's header is."""
    cells = "".join(f"<span>{label}</span>" for label in HOST_COLUMNS[:-1])
    return (f'<div class="prh">{cells}'
            f'<span class="pya">{HOST_COLUMNS[-1]}</span><span></span></div>')


def host_rows_html(slug, rows, foot="", live=True):
    """The port table: the header, one row per port, and a line under it
    when the caller has one (the address host's)."""
    body = "".join(port_row_html(slug, row, live) for row in rows)
    foot_html = f'<div class="agree">{esc(foot)}</div>' if foot else ""
    return f'<div class="panel ptbl">{host_thead_html()}{body}{foot_html}</div>'


def review_all_html(slug):
    """The one small round button above the table, over the answer column,
    that opens the window where a person answers for every port that
    answers from outside. It says what a person does there, since
    2026-10-11, and carries no redo arrow: nothing runs again, a window
    opens (the outside review's point 6, docs/record 4.451)."""
    return (f'<div class="tools">{button("Answer reachable ports", "rv js-review-all", data_host=esc(slug))}'
            '</div>')


def host_strip_html(reach, decision, changed):
    """The three boxes (SPEC.md section 4). `reach` is (open, of N ports),
    `decision` is (count, tone), `changed` is (count, the line under it) with
    count 0 drawn as the word none. Each box names the row it opens first,
    so a click scrolls to it; an empty box names none."""
    def box(label, number, sub, tone="", target=""):
        n_cls = f' class="n {tone}"' if tone else ' class="n"'
        tgt = f' data-row="{esc(target)}"' if target else ""
        return (f'<div{tgt}><div class="l">{esc(label)}</div><div{n_cls}>{number}</div>'
                f'<div class="d">{esc(sub)}</div></div>')
    n, total, first_reach = reach
    count, tone, first_decision = decision
    moved, line, first_changed = changed
    return ('<div class="hstrip">'
            + box("Reachable from outside", n, f"of {plural(total, 'port')}", "", first_reach)
            + box("Needs a decision", count, f"of {plural(total, 'port')}", tone, first_decision)
            + box("Changed in 24h", moved if moved else "none", line, "", first_changed)
            + '</div>')


PROBING_WORD = "probing"


def host_facts_html(agent, facts, host="", probing=False):
    """The small labelled cells under a server's name: the agent mark and
    word first, then (label, value html) pairs, hairlines between them.

    The `probed` cell carries a small turning mark, written always and drawn
    only while the cell has the `probing` class: while a probing pass runs or
    a scan somebody asked for is waiting for one (the owner, 2026-09-10 and
    2026-09-20, docs/RECORD.md 4.196). The Scan now click adds the class
    itself, so the mark shows at once. No tick when it is done, which
    docs/DESIGN.md section 3 allows nowhere: done is the mark gone and the
    age beside it.
    """
    cells = (f'<div class="f"><div class="k">agent</div>'
             f'<div class="v">{theme.icon(AGENT_ICON[agent], 15)}{esc(agent)}</div></div>')
    for k, v in facts:
        if k == "probed":
            spin = (f'<span class="pspin" title="{PROBING_WORD}">'
                    f'{theme.icon("circle-notch", 13)}</span>')
            cells += (f'<div class="f{" probing" if probing else ""}" data-probed="{esc(host)}">'
                      f'<div class="k">{esc(k)}</div><div class="v">{spin}{v}</div></div>')
        else:
            cells += f'<div class="f"><div class="k">{esc(k)}</div><div class="v">{v}</div></div>'
    return f'<div class="hfacts">{cells}</div>'


# ----------------------------------------- the Packet path tab, fragments
#
# docs/screens/host-packet-path/SPEC.md, approved 2026-09-10 after eight
# rounds (docs/RECORD.md 4.168). One box per tool in the
# order a packet from outside meets them, the provider first, then a
# container runtime that published the port, then the host firewall, then
# anything else in the kernel that belongs to a tool, and the service at the
# right. A tool the packet never meets is a ghost it passes through.
#
# Both feeds build from these, so the demo cannot be laid out differently
# from the product.

# What a tool's role is called in its own panel, by kind.
PATH_ROLES = {"provider": "provider firewall", "runtime": "container runtime",
              "host": "host firewall", "other": "also in the kernel",
              "hand": "written by hand"}

# The fates, and the only outcomes the drawing may show (SPEC.md). Each is
# measured or is what the document itself marks, never inferred.
#
# **`refused` is not in the spec and was added on 2026-09-10 while building
# it.** The spec names four, and a port that answered with a refusal is none
# of them: the prober measures `connect_refused`, and drawing it as `lost`
# would fade the packets away over a port that did answer. So the packets run
# the whole way and nothing rings, because the packet arrived and something
# said no. The demo host's own 5432 is this case, which is how it was found.
PATH_FATES = ("reach", "stop", "lost", "refused", "none")

# The word the prober's own answer wears, and its tone. The words are the
# prober's, never ours.
PATH_MEASURED_TONES = {"answered": "ok", "no answer": "off",
                       "refused": "off", "not probed yet": "off"}

# How many boxes on one path can be selected. The selection is radios and CSS
# so the tab still works with JavaScript off, and the rules for it are
# generated once here rather than per host, the way the gates picker's are.
#
# **A box past the cap is not a label at all.** It is drawn, because leaving a
# tool off the path would be the worse lie, and it simply does not open a
# panel, rather than carrying a `for` that reaches nothing. The spec's own
# list of what can stand on a path is about eight things long, so this is
# roughly twice the room anything real needs.
PATH_CAP = 16


def path_css(cap=PATH_CAP):
    """The selection: the picked box takes the accent and its panel shows."""
    out = []
    for i in range(cap + 1):
        sel = f".ptsel.p{i}:checked"
        out.append(f"{sel}~.pt-flow .pt-nd.n{i}{{border-color:var(--acc)}}")
        out.append(f"{sel}~.pt-flow .pt-endR .pt-tile.n{i}{{border-color:var(--acc)}}")
        out.append(f"{sel}~.pt-under.u{i}{{display:block}}")
        out.append(f".ptsel.p{i}:focus-visible~.pt-flow .n{i}"
                   "{outline:2px solid var(--acc);outline-offset:3px}")
    return "\n".join(out)


def path_measured_html(port_html, word, detail):
    """The one thing the tab states outright, because the prober measured it:
    the port, the prober's own word, and its detail in plain text."""
    tone = PATH_MEASURED_TONES.get(word, "off")
    rest = (f'<span class="pt-sep"></span><span>{esc(detail)}</span>'
            if detail else "")
    return (f'<div class="pt-meas">{port_html}<span class="pt-sep"></span>'
            f'{theme.status(tone, esc(word))}{rest}</div>')


def path_end_left_html(vantage, address):
    """Where the packet comes from: the vantage that measured this port."""
    return (f'<div class="pt-end pt-endL"><span class="pt-tile">'
            f'{theme.icon("globe-hemisphere-west", 19)}</span>'
            f'<span class="pt-tx"><span class="pt-l">from outside</span>'
            f'<span class="pt-v">{esc(vantage)}</span>'
            f'<span class="pt-s">{esc(address)}</span></span></div>')


def path_end_right_html(sid, index, kind, name, sub, word):
    """The service at the right. `word` is "reaches" only when the prober
    connected, because reaching is a measurement and listening is a fact from
    the document (SPEC.md)."""
    glyph = "cube" if kind == "container" else "app-window"
    opens = f' for="{sid}"' if sid else ""
    tag = "label" if sid else "div"
    return (f'<{tag} class="pt-end pt-endR"{opens}>'
            f'<span class="pt-tile n{index}">{theme.icon(glyph, 19)}</span>'
            f'<span class="pt-tx"><span class="pt-l">{esc(word)}</span>'
            f'<span class="pt-v">{esc(name)}</span>'
            f'<span class="pt-s">{esc(sub)}</span></span></{tag}>')


def path_node_html(sid, index, mark_name, name, finding, state=""):
    """One tool on the path: its own mark, its name, and one short line in
    its own word for this port. No count and no generic glyph: the mark says
    which tool and the line says what it has."""
    cls = f' pt-{state}' if state else ""
    opens = f' for="{sid}"' if sid else ""
    tag = "label" if sid else "div"
    return (f'<{tag} class="pt-nd n{index}{cls}"{opens}>'
            f'<span class="pt-mk">{theme.icon(mark_name, 18)}</span>'
            f'<span class="pt-nt"><span class="pt-nn">{esc(name)}</span>'
            f'<span class="pt-nc">{esc(finding)}</span></span></{tag}>')


def path_rule_rows_html(rules, tool_name):
    """A tool's rules as the Rules tab draws them, this port's row in ink and
    the others faint, and under the row that matters the tool's own line."""
    rows = []
    for i, rule in enumerate(rules, 1):
        quote = ""
        if rule.get("hit") and rule.get("quote"):
            quote = (f'<span class="pt-q"><b>as {esc(tool_name)} writes it</b>'
                     f'{esc(rule["quote"])}</span>')
        rows.append(
            f'<div class="pt-urr{" pt-hit" if rule.get("hit") else ""}">'
            f'<span class="pt-ix">{i}</span>'
            f'{theme.status("off", esc(rule["action"]))}'
            f'{rule_port_html(rule.get("port"), rule.get("protocol", ""), rule.get("families", ()))}'
            f'<span class="pt-fr">{esc(rule["from"])}</span>{quote}</div>')
    return "".join(rows)


PATH_RULE_COLUMNS = ("#", "action", "port", "from")

PATH_RULE_HEAD = ('<div class="pt-urh">'
                  + "".join(f"<span>{c}</span>" for c in PATH_RULE_COLUMNS)
                  + "</div>")

# The two states a tool's panel can carry, in the words the spec gives them.
PATH_STATE_TAGS = {"stop": ("warn", "ends its journey here"),
                   "ghost": ("off", "not reached")}


def path_panel_html(index, mark_name, name, kind, where, facts, rules=(),
                    state=""):
    """One tool's panel: what it has for this port first and largest, its
    default in its own words, then its rules.

    `facts` is (label, value html, quiet) so the caller keeps the wording.
    No kernel chain names here: the kernel's copy of a ufw rule is the same
    fact in another dialect (the owner, 2026-09-09).
    """
    tag = ""
    if state in PATH_STATE_TAGS:
        tone, word = PATH_STATE_TAGS[state]
        tag = theme.status(tone, word)
    head = (f'<div class="pt-uh"><span class="pt-mk">{theme.icon(mark_name, 22)}</span>'
            f'<h3>{esc(name)}</h3>'
            f'<span class="pt-role">{esc(PATH_ROLES.get(kind, kind))}</span>{tag}'
            + (f'<span class="pt-where">{esc(where)}</span>' if where else "")
            + '</div>')
    cells = "".join(
        f'<div><div class="pt-k">{esc(label)}</div>'
        f'<div class="pt-fv{" pt-no" if quiet else ""}">{value}</div></div>'
        for label, value, quiet in facts)
    table = (PATH_RULE_HEAD + path_rule_rows_html(rules, name)) if rules else ""
    return (f'<div class="pt-under u{index}">{head}'
            f'<div class="pt-uf">{cells}</div>{table}</div>')


def path_dest_panel_html(index, kind, name, facts):
    """The service's panel: what it is bound on, and the process or the
    container behind it."""
    glyph = "cube" if kind == "container" else "app-window"
    role = "the container" if kind == "container" else "the service"
    head = (f'<div class="pt-uh"><span class="pt-mk">{theme.icon(glyph, 22)}</span>'
            f'<h3>{esc(name)}</h3><span class="pt-role">{role}</span></div>')
    cells = "".join(
        f'<div><div class="pt-k">{esc(label)}</div>'
        f'<div class="pt-fv"><span class="mono">{esc(value)}</span></div></div>'
        for label, value in facts)
    return f'<div class="pt-under u{index}">{head}<div class="pt-uf">{cells}</div></div>'


# How many packets ride one wire. Five is the sketch's own number.
PATH_PACKETS = 5


def path_flow_html(uid, nodes_html, end_left, end_right, fate, stop):
    """The flow: the wire's svg, the outside, the tools, the service.

    `fate` is one of PATH_FATES and `stop` the index of the tool that ends
    the journey, or -1. The script reads both off this element, because only
    the browser knows where a wrapped row of tools landed.
    """
    if fate not in PATH_FATES:
        raise ValueError(f"unknown fate {fate!r}")
    packets = "".join('<circle class="pt-pk" r="3.6" cx="0" cy="0"/>'
                      for _ in range(PATH_PACKETS))
    svg = ('<svg class="pt-wire" aria-hidden="true">'
           '<path class="pt-dl pt-live"/><path class="pt-dl pt-quiet"/>'
           f'<path class="pt-tmp"/>{packets}</svg>')
    return (f'<div class="pt-flow pt-{"stopf" if fate == "stop" else fate}"'
            f' data-fate="{fate}" data-stop="{int(stop)}" data-flow="{esc(uid)}">'
            f'{svg}{end_left}<span class="pt-dv"></span>'
            f'<div class="pt-mid">{nodes_html}</div>'
            f'<span class="pt-dv"></span>{end_right}</div>')


def path_selection_radios(uid, count, first):
    """One radio per selectable box, the one the tab opens on checked.

    It opens on the tool that ends the journey, else on a ghost, else on the
    last tool (SPEC.md). `count` includes the service at the right.
    """
    return "".join(
        f'<input class="ptsel p{i}" type="radio" name="{esc(uid)}"'
        f' id="{esc(uid)}-{i}"{" checked" if i == first else ""}>'
        for i in range(min(count, PATH_CAP + 1)))


def path_example_html(uid, flow):
    """One port's whole path: the measurement line, the flow, and the panel
    under it for whichever box is selected.

    `flow` is the shape both feeds fill: the port, the prober's word and
    detail, the fate, the tools, and what is at the right end. Keeping it one
    function is what stops the demo being laid out differently from the live
    page.
    """
    tools = flow["tools"]
    stop = next((i for i, t in enumerate(tools) if t.get("state") == "stop"), -1)
    ghost = next((i for i, t in enumerate(tools) if t.get("state") == "ghost"), -1)
    # It opens on the tool that ends the journey, else on a ghost, else on the
    # last tool (SPEC.md).
    first = stop if stop >= 0 else ghost if ghost >= 0 else max(len(tools) - 1, 0)
    dest = flow["dest"]

    def sid(i):
        return f"{uid}-{i}" if i <= PATH_CAP else ""

    nodes = "".join(
        path_node_html(sid(i), i, t["mark"], t["name"], t["finding"],
                       t.get("state", ""))
        for i, t in enumerate(tools))
    end = path_end_right_html(sid(len(tools)), len(tools), dest["kind"],
                              dest["name"], dest["on"], dest["word"])
    panels = "".join(
        path_panel_html(i, t["mark"], t["name"], t["kind"], t.get("where", ""),
                        t["facts"], t.get("rules", ()), t.get("state", ""))
        for i, t in enumerate(tools))
    panels += path_dest_panel_html(len(tools), dest["kind"], dest["name"],
                                   dest["facts"])
    return (path_measured_html(rule_port_html(flow["port"], flow["protocol"],
                                              flow["families"]),
                               flow["word"], flow["detail"])
            + path_selection_radios(uid, len(tools) + 1, first)
            + path_flow_html(uid, nodes,
                             path_end_left_html(flow["vantage"], flow["address"]),
                             end, flow["fate"], stop)
            + panels)


# --------------------------------------------------- the Rules tab, fragments
#
# docs/screens/host-rules/SPEC.md. The one question the tab answers: which
# firewalls does this server have, and what are their rules. One bordered list
# per firewall, in the order a packet from outside meets them, the provider's
# first and whatever else the kernel holds last.
#
# Both feeds build from these, so the demo cannot be laid out differently from
# the product. Nothing here says why a packet is dropped or where: that is the
# Overview's answer and the packet path's.

# The word a rule's action prints, and whether it reads as a refusal. The tag
# is neutral either way: this tab reports what a rule says and never whether
# it is a good rule.
DENY_WORDS = ("deny", "drop", "reject")


def three_facts_html(boxes):
    """The Overview's strip, filled with three (label, value, under) facts.

    The same markup as `host_strip_html`, which is why the two strips line up
    on the two tabs. Every value is drawn the same way, the date included
    (the owner, 2026-09-09: the date looked different from the numbers).
    """
    cells = "".join(
        f'<div><div class="l">{esc(label)}</div><div class="n">{esc(str(value))}</div>'
        f'<div class="d">{esc(under)}</div></div>' for label, value, under in boxes)
    return f'<div class="hstrip">{cells}</div>'


def rules_row_id(slug, key, index):
    """The checkbox id one rule opens on.

    `key` names the firewall and is ours, never document text, so the id is
    safe. `slug` is the host's own slug, so two hosts on one page cannot open
    each other's rules.
    """
    return f"rr-{slug}-{key}-{index}"


def rule_port_html(port, protocol, families, unreadable=False):
    """The port column: the number in mono, the protocol and families small.

    v6 is in ink so a rule that reaches v6 reads as one at a glance. A rule
    with no port of its own says "any port" in the page face, because those
    are our words and not a number a firewall printed.

    `unreadable` is a rule this page could not read the parts of. Its cell is
    empty, because "any port" would be a claim about a rule nobody could read
    and a claim is exactly what is missing. The row still carries the rule's
    own text and the tag that says so.
    """
    if unreadable:
        return '<span class="rpn"></span>'
    if not port:
        return '<span class="rpn any">any port</span>'
    fams = "+".join(f'<i class="{esc(f)}">{esc(f)}</i>' for f in families)
    # Nothing to say about the protocol or the family, no line to say it on.
    tail = "/".join(w for w in (esc(protocol) if protocol else "", fams) if w)
    small = f"<small>{tail}</small>" if tail else ""
    return f'<span class="rpn">{esc(str(port))}{small}</span>'


def rule_from_html(text, machine=False, note="", unread=False):
    """The from column: where the rule applies from.

    `machine` is the caller saying this is an address, which takes the mono
    face because it is a machine's word (docs/DESIGN.md section 1). Our own
    words, "anywhere" and "a set of addresses", stay in the page face.

    A rule the agent could not fully read keeps its action and carries the
    tag. It is never dropped, because a rule nobody can see is the thing this
    tab exists to surface.
    """
    small = f"<small>{esc(note)}</small>" if note else ""
    if unread:
        small += theme.status("warn", "not fully readable")
    return f'<span class="rfr{" addr" if machine else ""}">{esc(text)}{small}</span>'


def rule_card_html(word, lead, lines):
    """The card an opened rule shows: one source, and only its own words.

    The source as a neutral tag, the lead in ink, then short lines where only
    what a machine said is mono. Drawn with the classes an opened port row on
    the Overview uses, so the two read as the same thing.
    """
    body = "".join(f'<div class="l"><span class="k">{esc(k)}</span><span class="v">{v}</span></div>'
                   for k, v in lines)
    return (f'<div class="prec"><div class="preh">{theme.status("off", esc(word))}'
            f'<span class="lead">{esc(lead)}</span></div>{body}</div>')


def rule_row_html(slug, key, index, action, port_html, from_html, card_html=""):
    """One rule: its number, its action, its port, where from, and the caret.

    Numbered in the order the firewall lists them, because that order is what
    the firewall applies and the number is what you type to delete one.

    The row opens on a checkbox and CSS, no script, the same way a port row on
    the Overview opens and the same way the tabs switch.
    """
    rid = rules_row_id(slug, key, index)
    tone_cls = " deny" if action in DENY_WORDS else ""
    # No word, no tag. An empty box where an action should be reads as a rule
    # whose action is blank, and a rule this page could not read the verdict
    # of has nothing to put there.
    tag = f'<span class="st off{tone_cls}">{esc(action)}</span>' if action else "<span></span>"
    return (f'<input type="checkbox" class="rsel" id="{rid}">'
            f'<label class="fwr" for="{rid}"><span class="ix">{index}</span>'
            f'{tag}{port_html}{from_html}'
            f'<span class="cv">{theme.icon("caret-down", 14)}</span></label>'
            f'<div class="rev">{card_html}</div>')


RULE_COLUMNS = ("#", "action", "port", "from")

RULE_HEAD_HTML = ('<div class="rh">'
                  + "".join(f"<span>{c}</span>" for c in RULE_COLUMNS)
                  + "<span></span></div>")


def firewall_block_html(icon_name, name, sub, state, defaults, rows_html, after_html=""):
    """One firewall: its own row, the column titles, then its rules.

    The state sits with the name and there is no rule count, because the strip
    counts them (the owner, 2026-09-09). `defaults` is the firewall's own, in two
    words at the right, and a firewall that reports none draws none.

    `after_html` is the caller's own markup under the rules, inside the block:
    firewalld's fold of the zones that are not in effect.
    """
    tone, word = state
    mark = f'<small>{esc(sub)}</small>' if sub else ""
    df = "".join(f'{esc(k)} <b>{esc(v)}</b>' for k, v in defaults)
    head = (f'<div class="fwh"><span class="nm">{theme.icon(icon_name, 18)}{esc(name)}{mark}</span>'
            f'{theme.status(tone, esc(word))}<span class="df">{df}</span></div>')
    return (f'<div class="fw">{head}{RULE_HEAD_HTML if rows_html else ""}{rows_html}'
            f'{after_html}</div>')


def firewall_line_html(text):
    """A layer with nothing to list: one grey line in a box of its own."""
    return f'<div class="fw"><div class="fwline">{esc(text)}</div></div>'


def no_firewall_html():
    """No firewall active: the slashed wall, and the three words.

    Slashed the way the empty Fleet slashes its drives, so the empty answers
    across the product read as one family. The sketch drew a shield here and
    this is a wall, because a shield claims a verdict and is the one picture
    this product may not draw (docs/DESIGN.md section 3).
    """
    wall = theme.ICONS["wall"]
    art = ('<svg width="44" height="44" viewBox="0 0 256 256" aria-hidden="true">'
           f'<path fill="currentColor" d="{wall}"/>'
           '<line x1="44" y1="36" x2="212" y2="220" stroke="var(--panel)" stroke-width="30"/>'
           '<line x1="48" y1="40" x2="208" y2="216" stroke="currentColor" stroke-width="16"'
           ' stroke-linecap="round"/></svg>')
    return f'<div class="fw"><div class="alnone">{art}<div class="w">{NO_FIREWALL}</div></div></div>'


# The two groups of the first-look window, in order, with their headings.
# The ports waiting for an answer come first since 2026-10-02: the window is
# sorted so the ports most like a forgotten one lead (docs/RECORD.md 4.221),
# and a port no rule answers is the first of those.
#
# The second group holds every port that has an answer, a rule's or a
# person's, and its heading says so. It read "answered by a rule you wrote"
# until 2026-10-11, which on a server with no firewall filed a person's own
# Yes and No under a rule (docs/RECORD.md 4.220, 4.453). Whose answer it is
# stands under each row's service, `you` or `your rule`. The group's key is
# older than that and is nobody's to read.
FIRST_LOOK_ANSWERED = "answered already"
FIRST_LOOK_GROUPS = (("waiting", "waiting for you"), ("rule", FIRST_LOOK_ANSWERED))

def first_look_rows_html(rows):
    """The rows of the first-look window: (group, port label, service,
    source, lit) each, drawn under their group's heading."""
    out = ""
    for key, heading in FIRST_LOOK_GROUPS:
        mine = [r for r in rows if r[0] == key]
        if not mine:
            continue
        out += f'<div class="fv-g">{esc(heading)}</div>'
        for _group, label, service, source, lit, protocol, port, stfams in mine:
            number, _, proto = label.partition("/")
            buttons = "".join(
                f'<button class="ans {w}{" pick" if w == lit else ""}" data-answer="{w}">{w}</button>'
                for w in ANSWERS)
            out += (f'<div class="fv-r" data-protocol="{esc(protocol)}" data-port="{port}"'
                    f' data-stfams="{esc(stfams)}">'
                    f'<span class="prn">{esc(number)}<small>{esc(proto)}</small></span>'
                    f'<span class="sv">{esc(service) if service else "&mdash;"}<small>{esc(source)}</small></span>'
                    f'<span class="pra">{buttons}</span></div>')
    return out


def first_look_modal(slug, name, rows, reachable, live=True, first=True):
    """The first-look window for one server (SPEC.md section 8): the app's own
    modal shape, the two groups, Later and Confirm. It is on the page for
    every server and opens on its own once, or from Answer reachable ports.
    `live=False` is the sample shell, where Confirm says what it would do.

    `first` is whether this page is the look the page opens on its own, which
    the caller already knows (`render_live.is_first_look`). The title is
    "First look at <name>" only then, and "Your answers for <name>" on every
    later look, the column's own words (docs/record 4.451)."""
    mid = f"fv-{slug}"
    title = f"First look at {esc(name)}" if first else f"Your answers for {esc(name)}"
    confirm = (button("Confirm", "pri js-fv-confirm") if live
               else button("Confirm", "pri js-act", data_msg=SAMPLE_ANSWERS))
    line = f"{plural(reachable, 'port')} answer{'s' if reachable == 1 else ''} from outside. Say for each whether it should."
    return f"""<div class="ovl js-modal fv" id="{mid}" data-host="{esc(slug)}">
  <div class="modal panel">
    <div class="m-h"><h2>{title}</h2>
      <button class="m-x" data-close="{mid}" aria-label="Close">{theme.icon('x', 18)}</button></div>
    <div class="fv-s">{esc(line)}</div>
    {first_look_rows_html(rows)}
    <div class="m-foot"><span class="m-note"></span>
      <span class="acts">{button("Later", "js-fv-later", data_close=mid)}{confirm}</span></div>
  </div>
</div>"""


def beside_status(beside):
    """The second status tag on a row or a host header, or nothing.

    `beside` is a (tone, word) pair or None. One place, used by the fleet row
    and by the host page header, so the two cannot end up drawing the same
    fact two ways.
    """
    if not beside:
        return ""
    tone, word = beside
    return theme.status(tone, esc(word))


def trace_html(steps):
    """steps: (name, value, tone, rule_text, note) with an optional sixth
    element of already-built HTML, appended inside the step.

    The sixth element is the one place in this module that inserts markup it
    did not escape itself, so it takes only HTML built by these fragments,
    never a value out of a host document. render_live.py uses it to hang the
    full rule walk of a checkpoint behind a disclosure. The sample below never
    passes it, which is why the tuples stay five long there."""
    out = []
    for step in steps:
        n, v, tone, r, note = step[:5]
        extra = step[5] if len(step) > 5 else ""
        out.append(
            f'<div class="tr tr-{tone}"><div class="tr-d"></div><div class="tr-b">'
            f'<div class="tr-h"><span class="tr-n">{esc(n)}</span><span class="tr-v">{esc(v)}</span></div>'
            + (f'<div class="tr-r">{esc(r)}</div>' if r else "")
            + (f'<div class="tr-note">{esc(note)}</div>' if note else "")
            + extra + '</div></div>')
    return "".join(out)


# ------------------------------------------------- Evidence, the port matrix
# Design 4 of the Evidence round, the port matrix, chosen 2026-08-19
# (docs/RECORD.md 4.69). The whole host at once, one row per port and address
# family, one
# short token per view.
#
# The finding underneath it, which holds whichever way this is drawn: three
# columns imply three opinions on every row and that is false. Only the agent
# can say what is listening, only the provider what the cloud firewall permits,
# only the prober whether it answered. So a token is never blank and never a
# negative when a view simply cannot know: it is dashed, and dashed means this
# view has no way to answer, which is a different fact from no.
#
# `no state` is not a sixth state word. docs/PRODUCT.md 8a: a port whose
# evidence supports none of the five has no state, and today that is most of a
# real fleet, because two of the three views are not running.
# The outside view's four words are the join engine's own (`_OUTSIDE_WORDS` in
# controlplane/app/join.py), so the screen and the engine say the same thing
# about the same measurement. They took the tones the sample vocabulary already
# used for the same meanings: something answers from outside is `warn`, it does
# not is `ok`, nobody looked is `off` and therefore dashed.
#
# **`connect refused` and `no response` are kept apart and this is deliberate.**
# A refusal means nothing was listening. A timeout means something dropped the
# packet silently. `ops/RUNBOOK.md` says telling those two apart is the product,
# so collapsing them into one word here would throw away the distinction on the
# one screen built to show it. docs/DESIGN.md section 3 carries the decision.
#
# A word missing from this map falls to `off`, which the key below tells the
# reader means a view that cannot know. That is the right default and the wrong
# answer for any word that is a measurement, so every word a measurement can
# produce is listed here rather than left to it.
# **`listening` and `loopback` are facts and take no tone.** `docs/DESIGN.md`
# section 3 spends the ok tone on `intended` and on a control that is switched
# on, and on nothing else. The Services tab was corrected for exactly this on
# 2026-08-28 (`docs/RECORD.md` 4.122) and this table was missed, so twelve of
# eighteen rows of a real host's matrix drew green and green came to mean "we
# read this" rather than "this is correct".
#
# The four outside-view words keep theirs, which the same section sanctions by
# name: something answers from outside is warn, it does not is ok, nobody
# looked is off.
# Sentence case, like every other table header in the product. This one used
# to mix both cases inside itself: `Port` and `Together` capitalised and the
# three views not.
RATE_LIMITED_WORD = "rate limited"


def rate_flag(rate_limited):
    """The neutral flag that sits beside a port's state when a rule on its path
    decides on how recently and how often a connection was made
    (join.py Finding.rate_limited, docs/RECORD.md 4.81).

    It is the `.tag-planned` shape retoned to neutral, per docs/DESIGN.md
    section 3: a second fact about the port, sitting next to the state and never
    replacing it or recolouring it. Never a status tone, because borrowing one
    would smuggle blame in through a border colour. A port with no such rule
    gets no flag at all, so the empty string is the common answer.

    The word itself is the signal, so it reads printed in grey (DESIGN section
    3, never colour alone).
    """
    return tag("rate", RATE_LIMITED_WORD, title=RATE_LIMITED_WORD) if rate_limited else ""


# The words of the mark on a reachable port that is on the list of ports that
# should rarely face the internet (controlplane/app/rarelypublic.py). They are
# the mark's title and what a screen reader reads, and they are the whole of
# what the screen says about it: which service's documentation says so is in
# the list and the record, not on the row.
RARELY_WORD = "should rarely face the internet"


# The opened row's word for a mark a person dismissed (docs/RECORD.md 4.274).
RARE_DISMISSED_WORD = "dismissed"


def answered_line_html(row):
    """The opened row's line for the day a person answered: a label and a
    value, nothing on a port nobody answered. Decided by says who and this
    says when (docs/record 4.447)."""
    if not row.answered_on:
        return ""
    return (f'<div class="prwhen"><span class="k">answered</span>'
            f'<span class="v">{esc(row.answered_on)}</span></div>')


def rare_mark_line_html(slug, row):
    """The opened row's line for the rarely-public mark: its words and Dismiss
    while it is drawn, its words, dismissed, and Restore once a person
    dismissed it. Nothing on any other port. The button carries the server's
    name and the port, never its display name, like every control that acts
    on a server."""
    if not row.rare_mark:
        return ""
    dismissed = row.rare_mark == "dismissed"
    # A status, so the Tag treatment in its grey tone (docs/DESIGN.md section 3).
    state = theme.status("off", RARE_DISMISSED_WORD) if dismissed else ""
    act = button("Restore" if dismissed else "Dismiss", "js-rare", type="button",
                 data_host=esc(slug), data_protocol=esc(row.protocol), data_port=row.port,
                 data_dismiss="0" if dismissed else "1")
    cls = "prmk off" if dismissed else "prmk"
    return (f'<div class="{cls}"><span class="w">{theme.icon("warning", 14)}'
            f'{esc(RARELY_WORD)}</span>{state}{act}</div>')


# The values of the CVE check's strip that are words and not what a server
# sent. Everything else on the lines below is a package, a version or a CVE
# id, and is set in mono.
CVE_WORDS = ("package not determined", "unknown")
CVE_MONO_LABELS = ("installed", "update to", "fixed in")


def cve_card_html(lines, links=()):
    """The CVE check's strip in a port's opened row, or nothing when the
    report gave no card. `lines` are ((label, value, note, ids), ...) as
    `controlplane/app/cvecard.py` worked them out. A package's name and its
    version are text a server sent, so everything is escaped here.

    `links` are (text, address) pairs the control plane gives, the source
    and the licence of data shared under one. Each is drawn as a link where
    its text stands on the data line, and nowhere else, so no text a server
    sent is ever made a link."""
    if not lines:
        return ""
    out = []
    for label, value, note, ids in lines:
        mono = label in CVE_MONO_LABELS and value not in CVE_WORDS
        shown = f'<b class="mono">{esc(value)}</b>' if mono else esc(value)
        if label == "data of":
            shown = f'<span class="of">{_linked(esc(value), links)}</span>'
        if note:
            shown += f'<span class="sep">&middot;</span>' + (_linked(esc(note), links) if label == "data of" else esc(note))
        if ids:
            shown += ('<span class="cves">'
                      + "".join(f'<b class="mono">{esc(one)}</b>' for one in ids) + '</span>')
        out.append(f'<div class="l"><span class="k">{esc(label)}</span><span class="v">{shown}</span></div>')
    return f'<div class="prec prpk">{"".join(out)}</div>'


def _linked(escaped, links):
    """`escaped` with the first place each of `links` stands drawn as a link
    out, opening apart and telling the other site nothing of this page."""
    for text, address in links:
        found = esc(text)
        if found in escaped:
            escaped = escaped.replace(
                found, f'<a class="src" href="{esc(address)}" rel="noopener noreferrer" target="_blank">{found}</a>', 1)
    return escaped


def fix_mark_line_html(slug, row):
    """The opened row's line for the CVE check's mark, as the rarely-public
    mark has one: its words and Dismiss while it is drawn, its words,
    dismissed, and Restore once a person dismissed it. Nothing on a port
    that carries no mark. The button carries the server's name and the port,
    never a CVE: which CVEs a dismissal is for is the server's to work out."""
    if not row.cve_mark:
        return ""
    dismissed = row.cve_dismissed
    state = theme.status("off", RARE_DISMISSED_WORD) if dismissed else ""
    act = button("Restore" if dismissed else "Dismiss", "js-fix", type="button",
                 data_host=esc(slug), data_protocol=esc(row.protocol), data_port=row.port,
                 data_dismiss="0" if dismissed else "1")
    cls = "prmk fix off" if dismissed else "prmk fix"
    return (f'<div class="{cls}"><span class="w">{theme.icon("arrow-circle-up", 14)}'
            f'{esc(row.cve_mark)}</span>{state}{act}</div>')


def fix_flag(words):
    """The CVE check's own mark beside a state, with its words as its title,
    or nothing. Never the warn triangle, and never a reason to count a port
    under Needs a decision (docs/RECORD.md 4.446)."""
    return tag("fix", esc(words), title=esc(words)) if words else ""


def rarely_flag(rarely):
    """The slim warn mark beside a state, for a port that answers from outside
    and is on the list, or for a server that has such a port. Never a state
    and never a replacement for one (docs/RECORD.md 4.197, 4.221). Nothing at
    all otherwise, which is the common answer."""
    return tag("rare", RARELY_WORD, title=RARELY_WORD) if rarely else ""


# The word a paused server's state reads, and the word inside the mark.
PAUSED_WORD = "paused"


def paused_flag(paused):
    """The neutral mark beside a server's state while the server is paused
    and its state says something worse.

    The State cell shows one word, the worse of the two a server has, and
    drops the other (docs/DESIGN.md section 3). When the dropped word was
    `paused`, a paused server with a port nobody had answered for read
    `unreviewed` and nothing said paused (docs/RECORD.md 4.453). The dropped
    word is this mark: the muted mark's box and tone, since a pause is the
    operator's own choice as a mute is, with the pause glyph. It carries no
    server name, so the mute click, which fills the mark that does, leaves
    it alone.
    """
    return tag("mute", PAUSED_WORD, data_mark="paused", title=PAUSED_WORD) if paused else ""


DISAGREE_WORD = "disagree"


def disagree_flag(disagree):
    """The neutral mark for two vantages whose newest measurements of a port
    differ (join.py OutsideView.disagree, docs/PRODUCT.md 8e). The rate
    flag's shape and rule: a fact about the measurement beside the word,
    never a state and never a tone, and nothing at all when they agree."""
    return tag("disagree", DISAGREE_WORD) if disagree else ""


# The muted mark takes the rate flag's language: a second fact beside a state,
# never a sixth state, because a muted host still reports. One word, because
# the tag is the whole of what may be said.
MUTED_WORD = "muted"


def muted_flag(host, muted):
    """The neutral mark beside a server's state while a live mute covers it.

    The `.tag-rate` precedent exactly (docs/DESIGN.md section 3): the
    `.tag-planned` shape retoned to neutral, sitting beside the state word and
    never replacing or recolouring it. Never a status tone, because a mute is
    the operator's own choice and a tone would paint it as a problem.

    The span is written on every header and fleet row and filled only when the
    mute holds, the same trick as `.tag-rvw`: the mute click paints its result
    at once, and painting needs an element that is already
    there. `.tag-mute:empty` keeps the empty box off the screen. `data-mute-tag`
    carries the host name so the click can find every copy of this host's mark.
    """
    word = MUTED_WORD if muted else ""
    # The title is there whether or not the mark is filled: an empty mark is
    # not drawn at all, and the click that fills it writes only its word.
    return tag("mute", word, data_mute_tag=esc(host), title=MUTED_WORD)


def mode_flag(word):
    """The neutral mark saying how a server is watched, beside its name or its
    state. The words, and what each one is measured from, are
    `monitoring_mode` in render_live.py. This is only how one is drawn.

    The `.tag-rate` language a fourth time (docs/DESIGN.md section 3): a second
    fact about the server sitting next to a label, never a state and never a
    status tone. Which way a server is watched is not a problem, so it must not
    borrow a colour that says one, and the word is the whole statement.
    """
    return tag("mode", esc(word)) if word else ""


# ------------------------------------------------ the packet path, as gates
# Chosen 2026-08-19 out of four rail variants, the third, Gates, as the best
# for now (docs/RECORD.md 4.67). The walk as a run of connected blocks rather
# than a line with things
# on it, so the packet moves through the picture instead of past it.
#
# The default screen is the say line and the rail, nothing else. Every rule is
# one click away and at most one gate is open at a time, which was the whole of
# the round's brief: "i wouldn't overflow him with information, just make it
# clear and if needed more info its clickable".
#
# A run of checkpoints that hold no rule naming this port becomes one narrow dim
# block carrying its count. They are not dropped: the count is the fact that
# they were evaluated (RECORD.md 4.49, 4.51). The socket is a gate like the
# checkpoints before it, which is also what keeps the rail from ever being
# empty: a traced port always ends at something that holds it.
#
# **No gate states an outcome.** docs/PRODUCT.md 4g: the inside path says which
# chains a packet is evaluated against, in kernel order, and quotes them. Not
# allowed, not blocked, not reachable.
#
# The vocabulary is still the kernel's, which the owner has called too technical
# twice (RECORD.md 4.67 and 4.71). That decision is open and is deliberately not
# pre-empted here: this builds the shape he chose, and a plain-name pass is one
# lookup away when the wording is settled.

# What the stage caption over a gate says. One dict, shared by the sample data
# and the live walker, so the two feeds cannot caption the same hook two ways.
STAGE_LABEL = {"provider": "before the host", "ingress": "the device",
               "prerouting": "prerouting", "input": "input", "forward": "forward",
               "postrouting": "postrouting", "socket": "the socket"}

# How many gates and how many ports the static interaction CSS covers. The
# selectors in walk_css are positional and written out once, so a walk past the
# cap falls back to a non-clickable rail rather than to gates that silently do
# nothing. Everything a panel would hold is still on the page, in the
# checkpoint-by-checkpoint fold under the rail.
GATE_CAP = 24


def walk_css(cap=GATE_CAP):
    """The gate and port switching, in CSS, with no host names in it.

    The mechanism is the tab mechanism: a radio group per walk, the inputs
    siblings of the rail and the panels, so `:checked~` reaches its own walk
    and no further. The selectors are positional (the k-th gate input opens the
    k-th panel and lights the k-th label), which is what lets this be one
    static block instead of generated per page.
    """
    out = []
    for k in range(1, cap + 1):
        gi = f".gw>input.rr:nth-of-type({k + 1})"
        out.append(f"{gi}:checked~.pans>.pan:nth-child({k}){{display:block}}")
        out.append(f"{gi}:checked~.gates label.gate:nth-of-type({k})"
                   "{border-color:var(--acc);background:var(--acc-bg)}")
        out.append(f"{gi}:focus-visible~.gates label.gate:nth-of-type({k})"
                   "{outline:2px solid var(--acc);outline-offset:2px}")
        pi = f".pw>input.rr:nth-of-type({k})"
        out.append(f"{pi}:checked~.walks>.walk{{display:none}}")
        out.append(f"{pi}:checked~.walks>.walk:nth-child({k}){{display:block}}")
        out.append(f"{pi}:checked~.ppick label:nth-of-type({k})"
                   "{color:var(--ink);border-color:var(--acc);background:var(--acc-bg)}")
        out.append(f"{pi}:focus-visible~.ppick label:nth-of-type({k})"
                   "{outline:2px solid var(--acc);outline-offset:2px}")
    return "\n".join(out)


def gates_walk_html(uid, cells, host_label):
    """One walk as the chosen Gates drawing: the radios, the rail, the ends
    line, and one closed panel per gate.

    `cells` come from gate_cell, quiet_cell and fork_cell. Rule text and notes
    are escaped here; a cell's `extra` is already-built HTML from the caller's
    own fragments and is never document text.
    """
    gates = [c for c in cells if c["kind"] == "gate"]
    clickable = 0 < len(gates) <= GATE_CAP
    rail, panels = [], []
    k = 0
    for c in cells:
        if c["kind"] == "quiet":
            rail.append(f'<div class="gate q"><div class="gk">&nbsp;</div>'
                        f'<div class="gn">{c["n"]} quiet</div>'
                        f'<div class="gr">&nbsp;</div></div>')
            continue
        if c["kind"] == "fork":
            rail.append('<div class="gate fork"><div class="gk">routing</div>'
                        '<div class="gn">the decision</div>'
                        '<div class="gr">&nbsp;</div></div>')
            continue
        k += 1
        tone = f' {c["tone"]}' if c["tone"] else ""
        # Plain words lead and the technical name sits under them, smaller.
        # With no plain words the technical name leads alone, which is the
        # honest half-translated state rather than an invented label.
        if c.get("plain"):
            named = (f'<div class="gn">{esc(c["plain"])}</div>'
                     f'<div class="gn-t">{esc(c["name"])}</div>')
        else:
            named = f'<div class="gn">{esc(c["name"])}</div>'
        inner = (f'<div class="gk">{esc(STAGE_LABEL.get(c["stage"], c["stage"]))}</div>'
                 + named
                 + f'<div class="gr">{esc(c["gr"])}</div>')
        if not clickable:
            rail.append(f'<div class="gate{tone}">{inner}</div>')
            continue
        rail.append(f'<label class="gate{tone}" for="{uid}-{k}">{inner}</label>')
        meta = f'<span class="pan-w">{esc(c["meta"])}</span>' if c["meta"] else ""
        note = f'<div class="pan-x">{esc(c["note"])}</div>' if c["note"] else ""
        pan_name = esc(c["full"])
        if c.get("plain"):
            pan_name = (f'{esc(c["plain"])} '
                        f'<span class="pan-t">{esc(c["full"])}</span>')
        panels.append(f'<div class="pan"><div class="pan-h">'
                      f'<span class="pan-n">{pan_name}</span>{meta}'
                      f'<label class="pan-c" for="{uid}-none">close</label></div>'
                      + "".join(f'<div class="rulebox">{esc(r)}</div>' for r in c["rules"])
                      + note + c["extra"] + '</div>')
    radios = tail = ""
    if clickable:
        radios = (f'<input class="rr" type="radio" name="{uid}" id="{uid}-none" checked>'
                  + "".join(f'<input class="rr" type="radio" name="{uid}" id="{uid}-{i}">'
                            for i in range(1, len(gates) + 1)))
        tail = f'<div class="pans">{"".join(panels)}</div>'
    return (f'<div class="gw">{radios}<div class="gates">{"".join(rail)}</div>'
            f'<div class="gates-ends"><span>a packet from outside</span>'
            f'<span>{esc(host_label)}</span></div>{tail}</div>')


def walk_picker_html(uid, chips, walks):
    """The port selector over the walks: one radio-backed chip per port, the
    first checked, one walk visible at a time.

    A page with more ports than the static CSS covers stacks every walk under
    its own heading instead, so a port can never be unreachable because a
    selector ran out of selectors.
    """
    if not chips:
        return ""
    if len(chips) > GATE_CAP:
        return "".join(
            f'<div class="sec"><div class="sech"><h2>{esc(c)}</h2></div>{w}</div>'
            for c, w in zip(chips, walks))
    radios = "".join(f'<input class="rr" type="radio" name="{uid}" id="{uid}-{i}"'
                     f'{" checked" if i == 1 else ""}>'
                     for i in range(1, len(chips) + 1))
    labels = "".join(f'<label for="{uid}-{i}">{esc(c)}</label>'
                     for i, c in enumerate(chips, 1))
    shown = "".join(f'<div class="walk">{w}</div>' for w in walks)
    return (f'<div class="pw">{radios}'
            f'<div class="ppick"><span class="lbl">Path for</span>{labels}</div>'
            f'<div class="walks">{shown}</div></div>')


def fold_html(label, body_html):
    """A fold holding already-built markup: the label, the body one click down.

    `body_html` is the caller's own fragments and is never document text, the
    same contract trace_html uses for its sixth element.
    """
    return (f'<details class="fs"><summary><span>{esc(label)}</span></summary>'
            f'<div class="fold-b">{body_html}</div></details>')


# Appended here, not at the bottom of the file: an append below the __main__
# block runs after the page is already written, and the first build of this
# rail shipped exactly that way, with a picker over four invisible walks.
CSS += walk_css()
CSS += "\n" + path_css() + "\n"


def quotes_html(quotes, more=0):
    """The rules a port's state was decided from, verbatim, each with where it
    was read.

    Mono for the rule because it is the host's own syntax and a proportional
    face makes an nftables line unreadable. The source is the engine's own
    phrase for where it came from, so a reader can go and find it.
    """
    if not quotes:
        return ""
    lines = "".join(
        f'<div class="pq"><span class="pqr">{esc(text)}</span>'
        f'<span class="pqs">{esc(source)}</span></div>'
        for text, source in quotes)
    if more:
        lines += (f'<div class="pq"><span class="pqs">and '
                  f'{more} more rule{"s" if more != 1 else ""} on this port'
                  f'</span></div>')
    return lines


# What an acknowledged row wears, and what the control that files it says.
#
# Not `reviewed`, and that is the whole point of these two lines. The owner
# saw on 2026-08-27 that reviewing a rule marked it reviewed and unreviewed at
# once (docs/RECORD.md 4.105). The mark sits beside the state, and
# `unreviewed` is one of the
# five state words (docs/DESIGN.md section 3), so a row that had been
# acknowledged read `UNREVIEWED  REVIEWED`. Two elements, two facts, and they
# contradict each other on the face of it.
#
# It is the same failure DESIGN section 3 already records once: the earlier
# two-element status read as two facts and is what made him ask what `you said
# no` was supposed to mean. A word that needs the manual is the wrong word.
#
# The state word is not the one to move. `unreviewed` names the absence of a
# declaration, it is decided (docs/RECORD.md 4.50) and it is in the table
# DESIGN section 3 owns. So the acknowledgement takes the word the product
# already uses for it in its own sentence: `app/join.py`'s `describe` says
# "You have read this and said you are not acting on it." A row now reads
# `UNREVIEWED  READ`, which is a state and a fact about the reader, and
# neither denies the other.
REVIEW_WORD = "mark read"


DECLARE_WORDS = ("open", "closed")

# Withdrawing a declaration. One word, and the row's own dialog is that the
# button says what it does: nothing is destroyed on the host and the store
# keeps what was there as history (controlplane/app/intent.py).
CLEAR_WORD = "clear"


SILENCED_WORD = "silenced"


def silenced_flag(silenced):
    """The mark on a port whose alerts are switched off.

    **A silenced port never alerts and looked exactly like one that would**
    (`docs/RECORD.md` 4.119). For a tool whose job is to say when something
    changed, a switch that turns that off with no trace on the screen is the
    worst failure it has, and this product already has a rule against it: an
    error is never downgraded to make output cleaner.

    The rate flag's shape and the rate flag's rule (docs/DESIGN.md section 3):
    a second fact beside the state, neutral, never a status tone. Somebody
    asking not to be told is not a verdict about the port.
    """
    # `data-mark` is what gives it the silence's glyph and not the rate
    # limit's, whose tag it shares (`theme.MARK_ICONS`).
    return (tag("rate", SILENCED_WORD, data_mark="silenced", title=SILENCED_WORD)
            if silenced else "")


# ------------------------------------------------------------------- rulesets
# One block per layer, the chains inside it, one row per rule. It used to be one
# block of mono text per table, which is the shape the ruleset arrives in and not
# the shape it is read in: the chain header is what you scan for, and the
# operator's own comment was nowhere on the screen at all (the owner, 2026-08-16).
#
# The rule text is never summarised, shortened or filtered. Quoting the rule
# verbatim is the product, so a grouping that could drop one is the worst bug
# this tab could have and a test counts the rules in and out.

def conf_line_html(pairs, lead="what you configured"):
    """A conf file as one quiet line of `key=value`, in the file's own form.

    This was a four-column grid until 2026-08-22, which is not what the chosen
    Rules artboard drew: `rl-1b` put the conf fields inline in the group header
    as `what you configured - Status=active Default incoming=deny`, and the
    grid was the app's own older shape the round left in place. On a real host
    it also broke: `DEFAULT_APPLICATION_POLICY` and its value share a 250 pixel
    column, so `SKIP` wrapped mid-word as `SKI` over `P`.

    The value is left exactly as the file has it, an empty one included, so
    `IPT_MODULES=` reads the way it reads in `/etc/ufw/ufw.conf`. A conf line
    is a quote the same way a rule is a quote.
    """
    if not pairs:
        return ""
    fields = " &middot; ".join(
        f'<span class="cf-f">{esc(k)}={esc(v)}</span>' for k, v in pairs)
    return f'<div class="cf"><span class="cf-l">{esc(lead)}</span>{fields}</div>'


# ------------------------------------------------ Rules, the annotated raw
# Design 1 of the Rules round, the annotated raw, chosen 2026-08-19, redrawn
# as 1b after he found it still too technical and asked for the chains to be
# named more plainly (docs/RECORD.md 4.71).
#
# The bet, and it is a deliberate one. `RECORD.md` 4.67 and 4.71 are the target
# user saying twice that he does not follow the model these screens arrange, and
# the raw ruleset is the one form he already reads every day. So **the rule text
# is left exactly as it arrives, in a monospace column, and everything we know
# goes in the gutter beside it rather than woven into it.** Our labels can then
# be wrong without making the ruleset wrong, and a reader who trusts none of
# them still has the file.
#
# Nothing is reordered, nothing is folded away and nothing is dropped. From
# `docs/PRODUCT.md`: the rule text is never summarised, shortened or filtered,
# because quoting the rule verbatim is the product.

# Who wrote a rule, worked out from the chain it sits in and from nothing else.
# It is the one attribution the document already supports without new
# collection, and it earns its place because docker's chains, ufw's chains and
# the two rules a person actually typed all look identical today, while only one
# of the three is something the reader can act on.
#
# A chain nobody recognises gets no chip. An attribution we cannot make is one
# we do not make.
def rule_author(chain):
    chain = str(chain or "")
    if chain.startswith(("DOCKER", "docker")) or "DOCKER" in chain:
        return "docker"
    if chain.startswith("ufw") or "ufw-" in chain:
        return "ufw"
    return ""


# ufw writes one of these lines per rule the admin added, and the agent quotes
# it verbatim. The format is the agent's own observation, recorded in
# `agent/internal/collect/ufw.go`: "allow tcp 80 0.0.0.0/0 any
# 0.0.0.0/0 in", seen on Ubuntu 26.04 on 2026-08-12. Field 3 of the tuple is
# the destination port in ufw's normal form.
#
# **The marker is not in the stored line.** `readUfwTuples` cuts the
# `### tuple ###` prefix off before the document is written, so a real host
# document carries `allow tcp 22 0.0.0.0/0 any 203.0.113.37 in` and nothing
# else. The first version of this read the marker to decide it was looking at a
# ufw line, so it never fired on a real host and every ufw rule on the page
# went unlabelled. The caller knows which grammar it is holding, so it says so
# rather than this guessing from the text (the owner, 2026-08-21, reading his own
# prod host).
#
# Read conservatively on purpose. Only a bare decimal port with a named
# transport protocol earns a label: ufw also writes ranges (80:90), lists
# (80,443) and the word `any`, and none of those names one port.
UFW_TUPLE_MARKER = "### tuple ###"
UFW_PROTOCOLS = ("tcp", "udp")
UFW = "ufw"
KERNEL = "kernel"


def ufw_tuple_port(text):
    """The port a ufw tuple line names, or "" for any line this cannot read
    without guessing.

    Takes the line as the agent stores it, marker already removed, and
    tolerates the marker for a document old enough to still carry one.
    """
    text = str(text or "").strip()
    if text.startswith(UFW_TUPLE_MARKER):
        text = text[len(UFW_TUPLE_MARKER):]
    fields = text.split()
    # action, protocol, destination port, and at least a destination after it.
    if len(fields) < 4:
        return ""
    protocol, port = fields[1], fields[2]
    if protocol not in UFW_PROTOCOLS or not port.isdigit():
        return ""
    return f"{protocol}/{port}"


def rule_port_label(text, grade, grammar=KERNEL):
    """Which port a rule's own text names, and whether it was fully readable.

    `grade` is this module's own spelling: empty for a rule the agent rendered
    in full, and the word otherwise. `grammar` is which syntax the line is in,
    and the caller always knows: ufw's own files are not the kernel's
    vocabulary and cannot be read by the same reader.
    """
    if grammar == UFW:
        return ufw_tuple_port(text), True
    return pp.rule_port_claim(text, grade or "full")


def rule_rows_html(rules, author="", grammar=KERNEL):
    """rules: [(text, comment, grade)], one row each.

    The row is two columns. On the left the rule exactly as the agent read it,
    in mono, wrapping rather than truncating. On the right the gutter: which
    port this rule provably names, whether anything in it could select a port
    without saying so, and who wrote the chain it sits in.

    `comment` is the rule author's own note and spans both columns, because it
    is the one thing on the row a person wrote for a person.

    Nothing in the gutter is ever woven into the text. That is the whole design
    (Rules round, direction 1, chosen 2026-08-19).
    """
    out = []
    for text, comment, grade in rules:
        port, readable = rule_port_label(text, grade, grammar)
        tags = []
        if port:
            tags.append(f'<span class="gt port">{esc(port)}</span>')
        # The grade keeps its own word. It names WHICH grade, partial or none,
        # and a chip saying only "not fully readable" would flatten the two.
        # RECORD 4.18 is behind that field and it is not this round's to reword.
        # Two different facts and they keep two different words. `rendered:
        # partial` is the agent saying it could not fully render this rule
        # (RECORD 4.18, and that exact phrasing predates this round). `not
        # fully readable` is a rule the agent did render whose text still
        # carries a token that could select a port, a set or a raw offset.
        if grade:
            tags.append(f'<span class="gt hazy">rendered: {esc(grade)}</span>')
        elif not readable:
            tags.append('<span class="gt hazy">not fully readable</span>')
        if author:
            tags.append(f'<span class="gt wrote">{esc(author)}</span>')
        out.append('<div class="rule">'
                   f'<div class="rule-t">{esc(text)}</div>'
                   f'<div class="rule-gutter">{"".join(tags)}</div>'
                   + (f'<div class="rule-c">your comment: {esc(comment)}</div>'
                      if comment else "")
                   + '</div>')
    return "".join(out)


def rule_group_html(name, meta, rules, empty="no rules in this chain", key="",
                    grammar=KERNEL):
    """One chain, or one rules file: what it is for in plain words, its real
    name beside that, then its rules.

    `key` is the name to look the plain words up under, when the displayed name
    is not it. A chain's plain name is keyed by its table as well as itself,
    `inet filter input`, because `INPUT` alone means a different thing in every
    table, and the header here shows the chain in the context of its own table
    disclosure.

    A group with no rules keeps its header and says so. An empty chain is a real
    answer and dropping it would lose the fact that the chain exists.
    """
    # The plain name comes from PLAIN_CHAIN_NAMES, which the packet path
    # already reads. One vocabulary for the product, so the same chain cannot
    # be called two things on two tabs.
    plain = plain_chain_name(key or name)
    if plain:
        head = (f'<span class="rgrp-p">{esc(plain)}</span>'
                f'<span class="rgrp-n tech">{esc(name)}</span>'
                f'<span class="rgrp-m">{esc(meta)}</span>')
    else:
        head = (f'<span class="rgrp-n">{esc(name)}</span>'
                f'<span class="rgrp-m">{esc(meta)}</span>')
    body = (rule_rows_html(rules, rule_author(name), grammar) if rules
            else f'<div class="rule"><div class="rule-t">{esc(empty)}</div>'
                 '<div class="rule-gutter"></div></div>')
    return f'<div class="rgrp"><div class="rgrp-h">{head}</div>{body}</div>'


def rules_counts(groups):
    """(rules, chains, files, named, hazy) over every group on the tab.

    A group is `(name, meta, rules)` for a kernel chain and
    `(name, meta, rules, "file")` for one of ufw's rules files. The two are
    counted apart because they are different things: a chain is in the kernel
    and a file is what somebody wrote, and calling a file a chain in the
    heading would be this page misdescribing the host by one word.

    Counted in one place, because the heading and the tab printing different
    totals would be a real bug.
    """
    rules = chains = files = named = hazy = 0
    for group in groups:
        rows = group[2]
        is_file = len(group) > 3 and group[3] == "file"
        if is_file:
            files += 1
        else:
            chains += 1
        # A rules file is ufw's own file, and its lines are ufw's grammar. The
        # heading counting them with the kernel reader is what let the count
        # and the gutter disagree.
        grammar = UFW if is_file else KERNEL
        for text, _comment, grade in rows:
            rules += 1
            port, readable = rule_port_label(text, grade, grammar)
            if port:
                named += 1
            if grade or not readable:
                hazy += 1
    return rules, chains, files, named, hazy


def rules_header_html(rules, chains, files, named, hazy):
    """What is on this tab before any of it is read.

    A count, not a verdict. It says how much there is, how much of it we could
    read, and how much we could not, which is the honest summary of a screen
    whose whole job is to quote.
    """
    if not rules:
        return ('<div class="rsum">This host reported no firewall rules at all, in any '
                'layer the agent reads.</div>')
    where = [plural(chains, "chain")] if chains else []
    if files:
        where.append(plural(files, "rules file"))
    said = f'<b>{plural(rules, "rule")}</b> across {" and ".join(where)}.'
    if named:
        said += f' {plural(named, "names", "name")} a port outright.'
    if hazy:
        said += f' {plural(hazy, "could", "could")} select one without saying so.'
    return f'<div class="rsum">{said}</div>'


def plural(count, singular, plural_form=None):
    """`3 rules`, `1 rule`. The word after a count, with the count in it."""
    word = singular if count == 1 else (plural_form or singular + "s")
    return f"{count} {word}"


def rules_disclosure(label, meta, groups_html, is_open=False):
    """One table's chains behind a click, the counts in the summary so a closed
    one still says what is inside it. A long ruleset is scanned at this level
    and read at the next."""
    return (f'<details class="rs"{" open" if is_open else ""}><summary>'
            f'<span>{esc(label)}</span><span class="grades">{esc(meta)}</span></summary>'
            f'<div class="rgrps">{groups_html}</div></details>')


# When a row's name is not one of the known ones. A channel a person named
# themselves has no glyph of its own, and the alternative was a KeyError.
DEFAULT_ROW_ICON = "bell-ringing"


def named_rows_html(rows, icons, empty):
    """A list of configured things: the glyph, the name, a detail, a control.

    `rows` is [(name, detail, control_html)] with an optional fourth element,
    the key to look the glyph up under. Without it the name is the key, which
    is what the sample lists do.

    **The fourth element exists because a name stopped being a fixed word.**
    A channel row on the live page is called whatever the operator called it,
    and `icons[name]` on a label nobody predicted is a `KeyError` that takes
    the whole render down. So the lookup falls back to `DEFAULT_ROW_ICON` and
    a caller that knows the type passes it.

    `empty` is the sentence shown when nothing is configured. An empty list is
    a real state and says so, rather than rendering a panel with nothing in it
    that reads as a page that failed.

    The name and the detail are plain text and are escaped. The control is
    markup the caller built, because the sample shell and the live page need
    different ones.
    """
    if not rows:
        return f'<div class="agree">{empty}</div>'
    out = []
    for row in rows:
        name, detail, control = row[0], row[1], row[2]
        key = row[3] if len(row) > 3 else name
        glyph = icons.get(key, DEFAULT_ROW_ICON)
        out.append(
            three_cell_row(f'{theme.icon(glyph, 17)}<b>{esc(name)}</b>',
                           esc(detail), control, first_cls="nm"))
    return "".join(out)


def channels_html(rows):
    """Where alerts go. Only what is set up, because the heading says so."""
    return named_rows_html(
        rows, CHANNEL_ICONS,
        "No channel is set up, so changes are recorded and nothing is mailed. "
        "Add one and it appears here.")


# The three dots that open a row's menu, drawn here as three circles rather
# than added to theme.ICONS. That map holds path data taken from an icon set
# and this is not that: it is three circles on the same 256 grid, so it sits
# beside a Phosphor glyph without looking borrowed from somewhere else.
DOTS_GLYPH = theme.icon("dots-three-vertical", 18)

# What a row's menu offers, decided by the owner on 2026-08-23: edit, send a
# test notification, enable or disable, and delete. Those four
# and nothing else. Another product's menu was the reference for which actions
# belong on a row and never for how they look, and its fifth item, showing
# what was sent,
# is not in his list and is not here.
#
# `kind` decides what the click does:
#
#   edit   reopens the Add window on this row, to replace where it goes
#   test   asks the control plane to send one message now
#   post   an admin endpoint that writes the row
#
# **Send test is a real send since 2026-08-23, and only for a row that holds
# its own destination.** A row naming an environment variable, and every mail
# row, still cannot be tested from here: only the sweep unit reads
# /etc/whichports/alerts.env, so this process has neither those variables nor
# the relay password. Handing them to it to power a button would widen the set
# of processes holding secrets, which is the split docs/RECORD.md 4.87 exists
# to keep. The control plane answers with the line to run on the box instead,
# and the toast repeats that answer rather than claiming a send.
ROW_MENU_EDIT = ("Edit", "edit", "edit")
ROW_MENU_TEST = ("Send test", "test", "test")
ROW_MENU_DELETE = ("Delete", "post", "remove")
ROW_MENU_OFF = "Turn off"
ROW_MENU_ON = "Turn on"


def row_menu_html(label, enabled=True, channel_type="", events=""):
    """One row's menu. `label` is the channel's own name and identifies it to
    the admin endpoints, so it is escaped here and again in the attribute.

    **The switch item names the action, not the state.** An enabled channel
    offers Turn off, because a menu item is a thing you are about to do. Reading
    the row's own state off its menu is the two-elements-read-as-two-facts shape
    docs/DESIGN.md section 3 retired, and the Status cell already answers it.

    `channel_type` is what the row stores, and Edit needs it to reopen the Add
    channel window on the right step. Empty on the sample shell, where no card
    is wired to anything, so Edit there says it cannot and does nothing.

    `events` is the row's stored subscriptions, comma separated, so Edit can set
    the switches to what this row takes. Empty is every kind, which is what the
    row means (`controlplane/app/channels.py`). It is a kind name and never a
    destination, so it is a fact this page may hold.
    """
    safe = esc(label)
    toggle = ((ROW_MENU_OFF, "post", "disable") if enabled
              else (ROW_MENU_ON, "post", "enable"))
    items = "".join(
        f'<button type="button" class="rm-i rm-{kind}" data-act="{act}"'
        f' data-label="{safe}" data-type="{esc(channel_type)}"'
        f' data-events="{esc(events)}">{esc(text)}</button>'
        for text, kind, act in (ROW_MENU_TEST, ROW_MENU_EDIT, toggle))
    # Delete sits under a line and in the fail tone, apart from the three
    # items that keep the row (docs/screens/alerts/SPEC.md).
    text, kind, act = ROW_MENU_DELETE
    items += (f'<hr class="rm-hr"><button type="button" class="rm-i rm-{kind} rm-del"'
              f' data-act="{act}" data-label="{safe}" data-type="{esc(channel_type)}"'
              f' data-events="{esc(events)}">{esc(text)}</button>')
    return (f'<div class="rmenu"><button type="button" class="rm-t"'
            f' data-menu="{safe}" aria-label="Manage {safe}">{DOTS_GLYPH}</button>'
            f'<div class="rm-p">{items}</div></div>')


# How long a mute lasts, offered by the Mute button. The owner, 2026-08-24: one
# hour, eight, twenty-four, or until it is turned back on. Seconds,
# because seconds is what the mute endpoint takes, and an empty one is the mute
# that carries no expiry (controlplane/app/ingest.py).
MUTE_CHOICES = (("1 hour", 3600), ("8 hours", 8 * 3600),
                ("24 hours", 24 * 60 * 60),
                ("Until I turn it back on", None))


def mute_menu_html(host, muted=False, live=True):
    """The Mute control: a button that opens this page's own menu of lengths.

    The same menu language as a channel row's: a `.rmenu` box, a trigger
    carrying `data-menu`, and a `.rm-p` panel of `.rm-i` items. Only the
    trigger differs, because this one is a labelled button rather than three
    dots, and one menu shape on a page is worth more than a second one that
    fits its corner better.

    **Unmute is always in the markup and hidden while it does not apply.** The
    click paints its own result, and painting it means showing an item that is
    already bound rather than building markup in the browser with nothing
    listening to it, which is the trap the channel row's handler names.

    `live=False` is the sample shell, where nothing is wired to a control
    plane, so the items raise a toast the way every other sample control does.
    """
    safe = esc(host)
    # js-mute posts, js-act toasts. The markup is otherwise identical, so the
    # two feeds cannot drift apart on the shape of this menu.
    item_class = "rm-i js-mute" if live else "rm-i js-act"
    items = [f'<button type="button" class="{item_class}" data-act="unmute"'
             f' data-host="{safe}" data-msg="Unmuted."'
             f'{"" if muted else " hidden"}>Unmute</button>']
    for text, seconds in MUTE_CHOICES:
        # data-msg is the sample shell's toast and says only what happened.
        said = f"Muted for {text.lower()}." if seconds else "Muted."
        items.append(
            f'<button type="button" class="{item_class}" data-act="mute"'
            f' data-host="{safe}" data-seconds="{seconds if seconds else ""}"'
            f' data-msg="{esc(said)}">{esc(text)}</button>')
    # data-host is what lets the click find this host's muted marks: the box
    # is where the paint starts and the marks sit outside it, in the header
    # and on the fleet row.
    return (f'<div class="rmenu" data-muted="{"1" if muted else ""}"'
            f' data-host="{safe}">'
            f'{button("Muted" if muted else "Mute", "js-mute-t", type="button", data_menu=f"mute-{safe}")}'
            f'<div class="rm-p">{"".join(items)}</div></div>')


def sample_channel_rows_html():
    """The artboard's version of the configured list. Mail carries no menu,
    because it has no row behind it to act on, exactly as on a live page."""
    rows = []
    for word, key, destination, tone, used in SAMPLE_CHANNEL_ROWS:
        # The switched-off row draws Turn on and the others draw Turn off, so
        # the artboard shows both halves of the one item that changes.
        menu = "" if word == "Email" else row_menu_html(word, enabled=tone == "ok")
        rows.append((word, key, destination, "",
                     theme.status(tone, "on" if tone == "ok" else "off"),
                     used, menu))
    return channel_rows_html(rows, NO_DESTINATION_ADDED)


def channel_rows_html(rows, empty):
    """The configured channels, one row each: the channel, where it goes, its
    state, how often it has fired, and a menu.

    `rows` is [(channel_word, icon_key, destination, label, state_html, used,
    menu_html)]. The caller builds the state and the menu, because the sample
    shell and the live page differ on both: the sample is a drawing and the
    live page is wired to endpoints.

    **Destination and label sit in one cell, destination first.** They answer
    one question between them, which is where this goes, and the label is the
    operator's own word for it. Two columns would read as two facts, which is
    the shape docs/DESIGN.md section 3 retired for status.
    """
    if not rows:
        # The one line an empty section shows, drawn as the line under
        # Providers is, since the two stand on one screen.
        return f'<div class="al alempty">{empty}</div>'
    return alerts_thead_html(CHANNEL_COLUMNS) + "".join(channel_row_html(row) for row in rows)


def channel_row_html(row):
    """One configured channel, as one row.

    `row` is the seven-field tuple `channel_rows_html` documents.

    **This is its own function because the browser builds a row too.** A
    channel added on the alerts screen has to appear at once, and the row it
    appears as must be the row a reload draws. So the page carries a hidden
    copy of this markup per channel type, made here, and the browser clones one
    and fills in the values instead of writing its own markup. One function
    draws every row on the screen, whoever asked for it.
    """
    word, icon_key, destination, label, state_html, used, menu = row
    glyph = CHANNEL_ICONS.get(icon_key, DEFAULT_ROW_ICON)
    label_line = (f'<div class="crow-l">{esc(label)}</div>' if label else "")
    return (f'<div class="crow"><div class="nm">{theme.icon(glyph, 17)}'
            f'<b>{esc(word)}</b></div>'
            f'<div><div class="d">{esc(destination)}</div>{label_line}</div>'
            f'<div>{state_html}</div>'
            f'<div class="crow-u{" z" if str(used) == "0" else ""}">{esc(used)}</div>'
            f'<div class="crow-m">{menu}</div></div>')


def planned_html(rows):
    return "".join(
        f'<div class="pl"><b>{n}{PLANNED_TAG}</b>'
        f'<span>{d}</span></div>' for n, d in rows)


def host_tabs_html(slug, tabs):
    """One host's sub navigation and its panels. tabs: [(key, label, body)].

    The radios come first because the CSS in tab_css() reads forward from a
    checked input to its own panel. The first tab is checked, so a host page
    opens on it, and a reader who switches tab, walks back to the fleet and
    returns finds the tab they left.

    `body` is markup the fragments above already escaped. `slug` and the keys
    are ours, never a value out of a host document, so they are safe in an id.

    A key in HOST_TABS_PLANNED gets its label and the tag and nothing else. It
    has no radio and its label has no `for`, which is what makes it unclickable,
    the same way a planned nav item carries no data-v. Its body is not rendered,
    so both feeds pass an empty one.
    """
    built = [(key, label, body) for key, label, body in tabs
             if key not in HOST_TABS_PLANNED]
    inputs = "".join(
        f'<input type="radio" class="tabsel k-{key}" name="tabs-{slug}" '
        f'id="tb-{slug}-{key}"{" checked" if i == 0 else ""}>'
        for i, (key, _label, _body) in enumerate(built))
    labels = "".join(
        f'<label class="planned">{label}{PLANNED_TAG}</label>'
        if key in HOST_TABS_PLANNED
        else f'<label class="k-{key}" for="tb-{slug}-{key}">{label}</label>'
        for key, label, _body in tabs)
    panels = "".join(f'<div class="tab k-{key}" id="t-{slug}-{key}">{body}</div>'
                     for key, _label, body in built)
    return f'{inputs}<div class="subnav">{labels}</div>{panels}'


def sec_panel(title, body_html, panel_style="", hint=""):
    """A titled section holding one panel. The shape every tab is built from.

    `hint` is a short count or two, printed at the end of the heading line. A
    field, never a sentence: it is there so a section says how much is inside it
    before you read any of it.

    With no title and no hint the heading row is left out entirely, rather
    than drawing an empty strip above the panel (the owner's 2026-08-24 round:
    several tabs are one panel, and a heading that restates the tab label
    said nothing).
    """
    style = f' style="{panel_style}"' if panel_style else ""
    right = f'<span class="hint">{esc(hint)}</span>' if hint else ""
    head = (f'<div class="sech"><h2>{title}</h2>{right}</div>'
            if title or hint else "")
    return (f'<div class="sec">{head}'
            f'<div class="panel"{style}>{body_html}</div></div>')


def sec_block(title, body_html, hint=""):
    """A titled section whose body brings its own surfaces: a list of
    disclosures, or a table that is its own panel, rather than one panel.
    With no title and no hint the heading row is left out, as sec_panel
    leaves it out."""
    right = f'<span class="hint">{esc(hint)}</span>' if hint else ""
    head = (f'<div class="sech"><h2>{esc(title)}</h2>{right}</div>'
            if title or hint else "")
    return f'<div class="sec">{head}{body_html}</div>'


def three_cell_row(first, middle, last, first_cls="", middle_cls="d", last_cls="ar"):
    """The one row shape both feeds draw, `.ch2`: three cells, the middle one
    dimmed and the last one right-aligned unless a caller says otherwise. Every
    settings row, evidence row, rule-file row and channel row is this since
    2026-09-03, so a row has one definition and one place to change it.

    The cells arrive as markup, escaped where they hold somebody else's text,
    and nothing is escaped here. A cell class of "" writes a bare `<div>`,
    exactly as the rows this replaced did."""
    def cell(cls, html):
        return f'<div class="{cls}">{html}</div>' if cls else f'<div>{html}</div>'
    return (f'<div class="ch2">{cell(first_cls, first)}'
            f'{cell(middle_cls, middle)}{cell(last_cls, last)}</div>')


def setting_row(label, detail, control):
    """One row of a settings panel: what it is, what it does, the control.

    All three are builder-written markup rather than host data, which is why
    they are not escaped here. A host's own name goes through esc() at the call
    site."""
    return three_cell_row(label, detail, control)


# ---------------------------------------------------------------- the frame

def nav_html(nav_items, open_count=0, admin_count=0):
    """The top bar's items. nav_items is [(view_id, label)] with an optional
    third element marking one planned. `open_count` is how many alerts are
    open, worn by the Alerts item in the fail tone and absent at zero
    (docs/screens/alerts/SPEC.md).

    A planned item carries no data-v, which is what makes it unclickable: the
    page script only ever binds a click to an element that has one."""
    out = []
    for i, item in enumerate(nav_items):
        vid, label = item[0], item[1]
        if len(item) > 2 and item[2]:
            out.append(f'<a class="planned">{label}'
                       f'{PLANNED_TAG}</a>')
        else:
            on = ' class="on"' if i == 0 else ""
            # Alerts carries how many need you; Admin carries the strip's
            # fault boxes plus open feedback (docs/screens/admin/SPEC.md 4).
            badge = ""
            if vid == "alerts" and open_count:
                badge = f'<span class="nb">{int(open_count)}</span>'
            elif vid == "admin" and admin_count:
                badge = f'<span class="nb">{int(admin_count)}</span>'

            out.append(f'<a data-v="{vid}"{on}>{label}{badge}</a>')
    return "".join(out)


# The only `/api/admin/` routes a page may still call while it is showing
# somebody else's workspace. Neither touches anything a workspace owns: one
# asks who is signed in, the other ends your own session. **A write route
# added here is the bug**, which is why it is one list in one place with a test
# on it rather than a string inside the script.
VIEWING_OPEN = ("/api/admin/whoami", "/api/admin/signout")


def viewing_open_js():
    """`VIEWING_OPEN` as a JavaScript array literal, so the script and the
    constant above cannot drift."""
    return "[" + ",".join(f"'{route}'" for route in VIEWING_OPEN) + "]"


# The page's script lives in page.js beside this file, read once here. It is
# not an f-string, so a brace in it is a brace and `node --check` reads it.
# The values it needs from Python are marked __LIKE_THIS__ and filled in by
# page_script(), which refuses a marker it was not given a value for, so a
# new marker in the script cannot ship as its own name.
PAGE_JS = (HERE / "page.js").read_text(encoding="utf-8")
# A marker holds at least one letter. The pattern used to be `__[A-Z_]+__`,
# which also matched the six underscores the code field draws as its
# placeholder, so a page carrying that field read as a page with an unfilled
# marker in it (2026-09-10).
PAGE_JS_MARKER = re.compile(r"__[A-Z][A-Z_]*__")


def script_body(text):
    """The file without its comments. They are for whoever opens the file and
    are not sent to a browser. Until 2026-10-02 this dropped the leading block
    only, and the other comment lines went out with every page.
    site/theme.py says why none do, and what a comment in page.js must look
    like for that to hold: a line of its own."""
    return theme.script_without_comments(text)


def page_script(**values):
    script = script_body(PAGE_JS)
    for marker, value in values.items():
        script = script.replace(marker, value)
    left = PAGE_JS_MARKER.findall(script)
    if left:
        raise ValueError(f"page.js markers with no value: {sorted(set(left))}")
    return script


def page(nav_items, views_html, boot_js="", modal_html="", stamp="",
         templates_html="", viewing_html="", open_count=0, admin_count=0, sample=False,
         feedback_html=""):
    """The whole page: top bar, the views, the shared script. nav_items is
    [(view_id, label)], views_html is the concatenated .view divs.

    `feedback_html` is the Feedback button, drawn in the top bar beside the
    account circle, and empty on a page that shows somebody else's
    workspace (docs/screens/feedback/BRIEF.md).

    `templates_html` is `<template>` elements the script clones, parked after
    the views and inside no view. A template renders nothing and its content is
    not part of the document, so this is markup the page holds and never shows.
    It sits outside the views deliberately: a hidden copy of a row inside the
    panel that lists rows reads, to anything looking at the markup, like a row.

    `stamp` is when this page was rendered, and it is the answer to whether this is my
    change or an old page (the owner, 2026-08-23). **The dashboard is rendered on
    the box per request rather than deployed**, so a control plane change is on
    the next refresh, and the stamp is the request's own time beside the
    deployed commit.

    Empty on the sample shell, which is a drawing and has no render behind it.
    """
    nav = nav_html(nav_items, open_count, admin_count)
    # The port table's two lookups, handed to the script as data rather than
    # written a second time in JavaScript. One source, so a tone cannot mean
    # one thing on the server and another in the browser.
    tone_json = json.dumps({word: PORT_TONE[word] for word in DECIDED_STATES},
                           sort_keys=True)
    stamp_html = (f'<div class="pgstamp">{esc(stamp)}</div>' if stamp else "")
    # The marker the guard below reads. Present only when this render is
    # somebody else's workspace, so an ordinary page has nothing to switch off.
    viewing_attr = ' data-viewing="1"' if viewing_html else ""
    # The account button asks the server who is signed in, once. On the
    # sample shell nobody is and no server is there, so the button is marked
    # as having asked and the menu says what it said when the answer never
    # came (docs/RECORD.md 4.443).
    who_asked = ' data-asked="1"' if sample else ""
    who_line = "Signed in" if sample else 'Signed in as<b id="pm-user">...</b>'
    script = page_script(
        __VIEWING_OPEN__=viewing_open_js(), __TRY_COMMAND__=repr(TRY_COMMAND),
        __SILENCED_WORD__=SILENCED_WORD, __TONE_JSON__=tone_json,
        __PASSWORD_MIN__=str(PASSWORD_MIN_CHARS), __BOOT_JS__=boot_js,
        __FEEDBACK_SCREENS__=feedback_screens_js(),
        __FEEDBACK_MAX__=str(FEEDBACK_MAX_WORDS))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>whichports</title>
<base href="/">
<script>try{{var m=localStorage.getItem('wp-mode');if(m==='light'||(m==='system'&&window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches))document.documentElement.dataset.mode='light'}}catch(e){{}}</script>
{theme.ICON_LINKS}
<style>{theme.fonts()}{theme.TOKENS}{theme.BASE}{CSS}</style></head>
<body{viewing_attr}>
{viewing_html}
<div class="top"><div class="top-in">
  {theme.mark()}
  <nav class="nav">
    {nav}
  </nav>
  {feedback_html}
  <span class="pm">
    <button class="who" id="pm-btn" aria-label="Account" aria-haspopup="true"{who_asked}>{theme.icon('user-circle', 18)}</button>
    <div class="pm-menu" id="pm-menu" hidden>
      <div class="pm-who">{who_line}</div>
      <div class="pm-row"><span>Appearance</span>
        <span class="pm-seg"><button id="mode-dark">dark</button>
        <button id="mode-light">light</button></span></div>
      <button class="pm-row" id="pm-signout"><span>Sign out</span>
        {theme.icon('sign-out', 16)}</button>
    </div>
  </span>
</div></div>

{views_html}

{modal_html}
{templates_html}

<div class="ovl" id="ask">
  <div class="modal panel ask">
    <div class="m-h"><h2 id="ask-t"></h2></div>
    <div class="ask-b" id="ask-b"></div>
    <div class="m-foot"><span class="m-note"></span>
      <span class="acts">{button("", "pri ask-go", id="ask-yes")}
        {button("Cancel", id="ask-no")}</span></div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
{script}</script>
{stamp_html}
</body></html>
"""


# Changes is not here any more: a transition belongs to the server it happened
# on, so it is a tab inside that server (the owner, 2026-08-15). Authorisation is
# shown and marked planned because it is in v1 scope and is not built.
NAV = [("fleet", "Fleet"), ("alerts", "Alerts"), ("integrations", "Integrations"),
       ("settings", "Settings"), ("auth", "Authorisation", True)]


def psub_html(psub):
    """The line under a page title, or nothing at all. An empty grey div still
    spends its margin, so a page with no subtitle must not render one."""
    return f'<div class="psub">{psub}</div>' if psub else ""


def fleet_view(notes_html, strip_html, rows_html, acts_html, removed_html=""):
    """The Fleet, top to bottom as SPEC.md lists it: the banner, the title row,
    the four boxes, the search bar, the table, and under it the servers Remove
    took out, from removed_list_html."""
    # No server yet: the box with the slashed drives stands where the strip,
    # the search and the table would, with Add server as the one button, and
    # there is no banner and no Add server in the header (docs/screens/fleet/
    # SPEC.md, When there is no server). Decided here and not by the caller:
    # the live page handed this its strip and its header button whatever the
    # rows, and an empty Fleet drew four boxes of zeros and Add server twice
    # (the second big test, finding F3).
    if rows_html:
        table = f"""<input class="srch" placeholder="Search">
  <div class="panel ftbl">
    <div class="thead">{fleet_thead_html()}</div>
    {rows_html}
  </div>"""
    else:
        notes_html, strip_html, acts_html = "", "", ""
        table = fleet_empty_html()
    return f"""<div class="wrap view on" id="fleet">
  {notes_html}
  <div class="ph">
    <div><h1>Fleet</h1></div>
    <div class="acts">{acts_html}</div>
  </div>
  {strip_html}
  {table}
  {removed_html}
</div>"""


def simple_view(vid, title, psub, body_html, acts_html=""):
    acts = f'<div class="acts">{acts_html}</div>' if acts_html else ""
    return f"""<div class="wrap view" id="{vid}">
  <div class="ph">
    <div><h1>{title}</h1>{psub_html(psub)}</div>
    {acts}
  </div>
  {body_html}
</div>"""


# The word for the one action an open alert offers, and the word for taking it
# back. `Unsilence` rather than a sentence, because the pair beside it in the
# mute menu is `Mute` and `Unmute` and one menu language on a page is worth more
# than a second one that reads better on its own row.
SILENCE_WORD = "Silence"
UNSILENCE_WORD = "Unsilence"


# ------------------------------------------------------------ the Alerts screen
#
# docs/screens/alerts/SPEC.md: what is open right now, and where alerts go.
# Open now and Sent are one table shape, a few grey words of why and never a
# sentence, Channels in the shape of an ordinary notifications page, and the
# empty states carried by Phosphor's bells.

@dataclasses.dataclass
class AlertLine:
    """One line of Open now or Sent. `word` is the state word the tag
    carries, `tone` its tone on Open now (a Sent line wears the neutral
    tag). `action` is ("silence", protocol, port, family, silenced) or
    ("pause", paused) or () for Open now; `channel` and `destination` are
    the Sent line's last column."""
    when: object
    host: str
    word: str
    tone: str = ""
    protocol: str = ""
    port: object = ""
    families: tuple = ()
    why: str = ""
    action: tuple = ()
    channel: str = ""
    destination: str = ""
    off: bool = False


ALERT_COLUMNS = ("Raised", "Server", "Alert", "Port", "Why", "")
SENT_COLUMNS = ("When", "Server", "Alert", "Port", "Why", "Channel")
CHANNEL_COLUMNS = ("Channel", "Destination", "Status", "Sent", "")
NOTHING_YET = "Nothing here yet"
NOTHING_OPEN = "No open alerts"
# The period the destinations table's Sent column counts, and the pill Sent opens
# on (docs/screens/alerts/SPEC.md).
SENT_DAYS = 7
NO_SERVERS = "No servers yet"
# The Rules tab with nothing to list (docs/screens/host-rules/SPEC.md).
NO_FIREWALL = "No firewall active"
# The Rules tab's third fact when no rule change is known to the page: no
# rule file with a date and no change between two reports. It read "never",
# which is a thing nobody watched for (docs/RECORD.md 4.395).
NO_RULE_CHANGE_SEEN = "none seen"
# The destinations panel with no row in it. **"added" and not "set up"**: a
# workspace may still be mailed with no row, which is the operator's own
# workspace while the box's environment names a recipient
# (`controlplane/app/sweep_cli.py`, `mail_targets`). The page cannot see that
# environment, so it says the one thing it knows, that no channel was added
# here, and not that alerts go nowhere. It read "No channel is set up." above
# ten mailed alerts on 2026-09-21 (docs/RECORD.md 4.199).
# Under the heading Alert destinations when a workspace has none. It was
# "No channel added" under the Alerts screen's Channels, and takes the
# heading's own noun.
NO_DESTINATION_ADDED = "No alert destination added"
NO_PROVIDER_FIREWALL = "No provider connected"
# Two more answers the same grey line gives, because "no provider connected"
# was being said about a provider that was connected (the owner, 2026-09-20).
# The words are the ones the Overview's opened row already uses for the
# first, `server not found`.
PROVIDER_SERVER_NOT_FOUND = "Server not found at the provider"
NO_FIREWALL_AT_PROVIDER = "No firewall at the provider"
NOTHING_ELSE_IN_KERNEL = "Nothing else in the kernel"
# The three ranges the pills offer, and the empty line each shows when
# nothing falls in it. Sent reads the longest of them and the pills cut the
# list down by CSS, so `render_live.load_sent` is bounded by SENT_READ_DAYS.
SENT_RANGES = (("24h", 1, "Nothing sent in the last 24 hours"),
               ("7d", 7, "Nothing sent in the last 7 days"),
               ("30d", 30, "Nothing sent in the last 30 days"))
SENT_READ_DAYS = SENT_RANGES[-1][1]
NOTHING_SENT = SENT_RANGES[1][2]


def alert_when_html(when):
    return f'<span class="cwhen"><b>{esc(when.strftime("%-d %b"))}</b> {esc(when.strftime("%H:%M"))}</span>'


def alert_action_html(action, host, live=True):
    """The one action an open alert offers: Silence for a port, Pause for a
    silent agent, nothing otherwise. A silence stops the mail and the alert
    stays open (docs/PRODUCT.md 4c); nothing here closes an alert.
    `live=False` is the sample shell, where each says what it would do."""
    if not action:
        return ""
    if action[0] == "silence":
        _k, protocol, port, family, silenced = action
        if silenced:
            return button("Silenced", disabled=True)
        if not live:
            return button("Silence", "js-act", data_msg=SAMPLE_SILENCE)
        return button("Silence", "js-al-silence", data_host=host, data_protocol=protocol,
                      data_port=port, data_family=family)
    if action[0] == "pause":
        if action[1]:
            return button("Paused", disabled=True)
        if not live:
            return button("Pause", "js-act", data_msg=SAMPLE_PAUSE)
        return button("Pause", "js-al-pause", data_host=host)
    return ""


def sent_range_of(line, now):
    """The smallest of the Sent ranges a line falls in, as its days."""
    age = (now - line.when).total_seconds()
    return next((days for _l, days, _e in SENT_RANGES if age <= days * 86400),
                SENT_READ_DAYS)


def sent_counts_html(lines, now):
    """The count beside Sent, once for each range, and the CSS shows the one
    whose range is chosen (`sent_range_css`). It was one count of every line
    read, thirty days of them, whatever range was chosen: "Sent 3" stood
    above "Nothing sent in the last 7 days" (measured 2026-10-06,
    docs/RECORD.md 4.393). A range with nothing in it has no count, as a
    section with nothing in it has none."""
    out = []
    for _label, days, _empty in SENT_RANGES:
        count = sum(1 for line in lines if sent_range_of(line, now) <= days)
        if count:
            out.append(f'<span class="cnt c{days}">{count}</span>')
    return "".join(out)


def alert_line_html(line, now, sent=False, live=True):
    """One line. On Open now the tag carries the tone and the last cell the
    action; on Sent the tag is neutral and the last cell the channel. The
    line is the way to the server it names (`data-host`), and `data-r` says
    which range it falls in for the Sent pills. Every field arrives escaped
    by the caller except the words this module chooses."""
    reach = sent_range_of(line, now)
    if sent:
        tag_html = evidence_tag(line.word, off=line.off)
        last = (f'<span class="alch">{esc(line.channel)}'
                + (f'<small>{esc(line.destination)}</small>' if line.destination else "")
                + '</span>')
    else:
        tag_html = theme.status(line.tone or "off", esc(line.word))
        last = f'<span class="alac">{alert_action_html(line.action, line.host, live)}</span>'
    return (f'<div class="al" data-host="{esc(line.host)}" data-r="{reach}">'
            f'{alert_when_html(line.when)}<b class="alh">{esc(line.host)}</b>'
            f'<span class="altag">{tag_html}</span>'
            f'{change_port_html(line.protocol, line.port, line.families)}'
            f'<span class="alwhy">{esc(line.why)}</span>{last}</div>')


def alerts_thead_html(columns):
    return '<div class="alhd">' + "".join(
        (f'<span>Sent<small>past 7 days</small></span>' if c == "Sent" else f"<span>{esc(c)}</span>")
        for c in columns) + "</div>"


def alerts_table_html(lines, columns, now, sent=False, empty="", live=True):
    """Open now has one empty line. Sent carries one per range, and the CSS
    shows the one whose range holds no line (`sent_range_css`)."""
    body = "".join(alert_line_html(line, now, sent, live) for line in lines)
    if sent:
        body += "".join(f'<div class="al alempty e{days}">{esc(words)}</div>'
                        for _label, days, words in SENT_RANGES)
    elif not body:
        body = f'<div class="al alempty">{esc(empty)}</div>'
    return f'<div class="panel altbl{" alsent" if sent else ""}">{alerts_thead_html(columns)}{body}</div>'


def alerts_h2(title, count=None, extra="", counts_html=""):
    """`counts_html` is for a section whose count follows a range, drawn by
    `sent_counts_html`. Otherwise `count` is the one number, and none at
    zero."""
    cnt = counts_html or (f'<span class="cnt">{int(count)}</span>' if count else "")
    return f'<h2 class="alh2">{esc(title)}{cnt}{extra}</h2>'


def nothing_yet_html():
    """No alert ever: the slashed bell and the three words. No button, since
    an alert is recorded and shown here whether or not anything is connected,
    and what is connected is added on Integrations."""
    return (f'<div class="panel alnone">{theme.icon("bell-slash", 44)}'
            f'<div class="w">{NOTHING_YET}</div></div>')


def nothing_open_html():
    return (f'<div class="panel alquiet">{theme.icon("bell", 26)}'
            f'<div class="w">{NOTHING_OPEN}</div></div>')


def fleet_empty_html():
    """No server yet: Phosphor's drives with the slash its slashed icons
    carry, the three words, and Add server."""
    drives = theme.ICONS["hard-drives"]
    art = (f'<svg width="44" height="44" viewBox="0 0 256 256" aria-hidden="true">'
           f'<path fill="currentColor" d="{drives}"/>'
           '<line x1="44" y1="36" x2="212" y2="220" stroke="var(--panel)" stroke-width="30"/>'
           '<line x1="48" y1="40" x2="208" y2="216" stroke="currentColor" stroke-width="16" stroke-linecap="round"/></svg>')
    # The header's own button, js-add, which starts the Add server window
    # clean, since it is the one Add server on an empty Fleet.
    return (f'<div class="panel alnone">{art}<div class="w">{NO_SERVERS}</div>'
            f'{button("Add server", "pri js-add")}</div>')


def sent_range_html(pills_id):
    """The three pills, radios first so the CSS can read forward from them.
    7d is the one the page opens on (docs/screens/alerts/SPEC.md)."""
    radios = "".join(
        f'<input type="radio" class="sgsel r{days}" name="sg-{pills_id}" id="sg-{pills_id}-{label}"'
        + (" checked" if days == SENT_DAYS else "") + ">"
        for label, days, _e in SENT_RANGES)
    pills = "".join(f'<label class="rgl r{days}" for="sg-{pills_id}-{label}">{label}</label>'
                    for label, days, _e in SENT_RANGES)
    return radios, f'<span class="rng alrng">{pills}</span>'


def sent_section_html(lines, now):
    radios, pills = sent_range_html("alerts")
    return (radios + alerts_h2("Sent", extra=pills, counts_html=sent_counts_html(lines, now))
            + alerts_table_html(lines, SENT_COLUMNS, now, sent=True))


def alerts_view(open_lines, sent_lines, now, nothing_yet=False, live=True):
    """The alerts page: what happened. `open_lines` and `sent_lines` are
    AlertLine lists, newest first. With nothing ever raised the page is the
    one box (SPEC.md, the empty states).

    Where alerts go is not on this page since layout B
    (SPEC-layout-b.md): the table that stood here as Channels is on
    Integrations as Alert destinations, and this header has no button."""
    if nothing_yet:
        body = alerts_h2("Open now") + nothing_yet_html()
    else:
        open_html = (alerts_table_html(open_lines, ALERT_COLUMNS, now, live=live) if open_lines
                     else nothing_open_html())
        body = (alerts_h2("Open now", len(open_lines)) + open_html
                + sent_section_html(sent_lines, now))
    return f"""<div class="wrap view" id="alerts">
  <div class="ph">
    <div><h1>Alerts</h1></div>
  </div>
  {body}
</div>"""


ALERTS_CSS = """/* ---- the Alerts screen, as the sketch in docs/screens/alerts draws it:
   one table shape for Open now and Sent, Channels as an ordinary
   notifications page has them, and the empty states carried by Phosphor's
   bells. */
.nb{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);line-height:1;padding:3px 6px;border-radius:5px;border:1px solid var(--fail);color:var(--fail);margin-left:7px}
.alh2{font-family:"Space Grotesk",sans-serif;font-size:var(--fs-body);font-weight:600;margin:30px 0 14px;display:flex;align-items:center;gap:8px;height:22px;line-height:22px}
.alh2 .cnt{font-weight:500;color:var(--faint)}
.alh2 .alrng{margin-left:auto}
.alrng .rgl{padding:3px 11px}
.ph+.alh2{margin-top:22px}
.altbl{overflow:hidden}
.altbl.chan{overflow:visible}
.chan .alhd{border-radius:var(--r) var(--r) 0 0}
.alhd,.al{display:grid;grid-template-columns:130px 170px 130px 140px minmax(0,1fr) 170px;gap:16px;align-items:center;border-bottom:1px solid var(--line)}
.chan .alhd,.chan .crow{grid-template-columns:150px minmax(0,1fr) 110px 120px 48px}
.alhd{padding:9px 20px;background:var(--panel2)}
.alhd span{font-size:var(--fs-micro);letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
.alhd span small{text-transform:none;letter-spacing:0;margin-left:5px}
.alhd span:last-child{text-align:right}
.al{padding:14px 20px;cursor:pointer;font-size:var(--fs-meta)}
.al:hover{background:var(--hover)}
.al:last-child,.chan .crow:last-child{border-bottom:0}
.al .altag .st{justify-self:start}
.alh{font-weight:600;color:var(--ink)}
.alwhy{color:var(--muted)}
.alac{text-align:right}
.alch{text-align:right;color:var(--ink)}
.alch small{display:block;font-size:var(--fs-micro);color:var(--faint);font-family:"IBM Plex Mono",monospace;margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.alempty{display:block;cursor:default;color:var(--muted)}
.alnone{display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:56px 20px 60px;color:var(--muted)}
.alnone svg{margin-bottom:16px}
.alnone .w{font-size:var(--fs-body);font-weight:600;color:var(--ink)}
.alnone .btn{margin-top:18px}
.alquiet{display:flex;align-items:center;gap:14px;padding:20px;color:var(--muted)}
.alquiet .w{font-size:var(--fs-meta);font-weight:500}
/* the channel rows, in the table above: the kind with its glyph, the
   address in bold mono, the status tag, the count and the menu */
.chan .crow{padding:14px 20px;border-top:0;border-bottom:1px solid var(--line);font-size:var(--fs-meta)}
.chan .crow .nm{display:flex;align-items:center;gap:10px;color:var(--ink)}
.chan .crow .nm svg{color:var(--muted)}
.chan .crow .d{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);font-weight:600;color:var(--ink-str);word-break:break-all}
.chan .crow .st{justify-self:start}
.chan .crow-u{text-align:left;color:var(--ink)}
.chan .crow-u.z{color:var(--faint)}
.rm-hr{border:0;border-top:1px solid var(--line);margin:5px 4px}
.m-cards.m5{grid-template-columns:repeat(5,1fr)}
.m-cards.m5 .m-card.nmo{flex-direction:column;justify-content:center;text-align:center;gap:8px;padding:14px 6px 12px}
"""


def sent_range_css():
    return "\n".join([
        ".sgsel{position:absolute;opacity:0;pointer-events:none}",
        # a line outside the chosen range is hidden
        '.sgsel.r1:checked~.alsent .al[data-r="7"],.sgsel.r1:checked~.alsent .al[data-r="30"],'
        '.sgsel.r7:checked~.alsent .al[data-r="30"]{display:none}',
        # the empty line for a range shows only when no line falls in it, and
        # the column head goes with the last line
        ".alsent .alempty{display:none}",
        ".alsent:not(:has(.al[data-r])) .alhd{display:none}",
        '.sgsel.r1:checked~.alsent:not(:has(.al[data-r="1"])) .alempty.e1{display:block}',
        '.sgsel.r7:checked~.alsent:not(:has(.al[data-r="1"],.al[data-r="7"])) .alempty.e7{display:block}',
        '.sgsel.r30:checked~.alsent:not(:has(.al[data-r])) .alempty.e30{display:block}',
        # the count beside the heading is the chosen range's
        ".alh2 .cnt.c1,.alh2 .cnt.c7,.alh2 .cnt.c30{display:none}",
        ".sgsel.r1:checked~.alh2 .cnt.c1,.sgsel.r7:checked~.alh2 .cnt.c7,"
        ".sgsel.r30:checked~.alh2 .cnt.c30{display:inline}",
        ".sgsel.r1:checked~.alh2 .rgl.r1,.sgsel.r7:checked~.alh2 .rgl.r7,"
        ".sgsel.r30:checked~.alh2 .rgl.r30{background:var(--panel2);color:var(--ink)}",
        ".sgsel:focus-visible~.alh2 .rgl{outline:2px solid var(--acc);outline-offset:2px}",
    ])


CSS += "\n" + ALERTS_CSS + sent_range_css() + "\n"


# The sample shell's Alerts screen, as the sketch draws it. Invented names,
# like every other name in this shell.
SAMPLE_ALERTS_NOW = datetime.datetime(2026, 9, 5, 12, 0)
def alert_is_quiet(action):
    """Whether this line's own control says somebody already dealt with it.

    The last element of both actions is that flag: a silenced port and a
    paused server. A line with no action at all is not quiet, it is a line
    with nothing to click.
    """
    if not action:
        return False
    return action[0] in ("silence", "pause") and bool(action[-1])


def alerts_needing_you(lines):
    """How many open alerts still want an answer, which is what the count
    beside Alerts says.

    A silence stops the mail and the alert stays open (`docs/PRODUCT.md` 4c),
    and its line stays on the screen marked Silenced, so nothing live is
    hidden. It leaves this count, because the count is a number of things to
    do and a silenced port is one somebody has answered. A paused server is
    the same. The owner asked for it twice, the second time on 2026-09-10:
    silencing an alert has to take it out of the count beside Alerts.
    """
    return sum(1 for line in lines if not alert_is_quiet(line.action))


SAMPLE_OPEN = [
    # app-01's conflict is 443 on both families, as its own page says
    # (sample_story.py). It read 8410 here while the page called 8410
    # unreviewed (docs/RECORD.md 4.443).
    AlertLine(datetime.datetime(2026, 9, 5, 9, 12), "app-01", "conflict", "fail",
              "tcp", 443, ("v4", "v6"), "you said closed",
              ("silence", "tcp", 443, "v4", False)),
    # The three lines under it name servers of the sample's Fleet, each in
    # the state its row shows (docs/RECORD.md 4.453). backup-03 is the row
    # that reads silent 3h 12m: its last report was at 08:48 by this screen's
    # clock, and the line was raised 36 minutes after it.
    AlertLine(datetime.datetime(2026, 9, 5, 9, 24), "backup-03", "silent", "warn",
              why="nothing from the agent for 36 min", action=("pause", False)),
    # media-01's row asks about tcp/8096.
    AlertLine(datetime.datetime(2026, 9, 4, 23, 50), "media-01", "reachable", "warn",
              "tcp", 8096, ("v4", "v6"), "nobody has said whether it should be",
              ("silence", "tcp", 8096, "v4", True)),
    # web-02's row says three of its five ports answer and asks about those
    # three. This is one of the other two. Not a server that reads watched:
    # with an alert still open a live row never does (docs/RECORD.md 4.195).
    AlertLine(datetime.datetime(2026, 9, 4, 17, 5), "web-02", "unreachable", "off",
              "tcp", 8080, ("v4",), "was reachable"),
]
SAMPLE_SENT = [
    AlertLine(datetime.datetime(2026, 9, 5, 9, 12), "app-01", "conflict", "",
              "tcp", 443, ("v4", "v6"), "you said closed", channel="Email",
              destination="sysadmin@example.org"),
    AlertLine(datetime.datetime(2026, 9, 5, 9, 12), "app-01", "conflict", "",
              "tcp", 443, ("v4", "v6"), "you said closed", channel="Slack", destination="#ops"),
    AlertLine(datetime.datetime(2026, 9, 5, 9, 24), "backup-03", "silent", "",
              why="nothing from the agent for 36 min", channel="Email", destination="sysadmin@example.org"),
    AlertLine(datetime.datetime(2026, 9, 4, 23, 50), "media-01", "reachable", "",
              "tcp", 8096, ("v4", "v6"), "nobody has said whether it should be", channel="Email",
              destination="sysadmin@example.org"),
    AlertLine(datetime.datetime(2026, 9, 4, 23, 50), "media-01", "reachable", "",
              "tcp", 8096, ("v4", "v6"), "nobody has said whether it should be", channel="Slack", destination="#ops"),
    AlertLine(datetime.datetime(2026, 9, 3, 14, 2), "backup-03", "reporting", "",
              why="reporting again", channel="Email", destination="sysadmin@example.org",
              off=True),
]


# ------------------------------------------------------ the Integrations screen
#
# docs/screens/integrations/SPEC.md: what is connected, and how to connect
# something. The Alerts screen's table shape, a Providers table and the Alert
# destinations table, and the one Add window
# (docs/screens/alerts/SPEC-layout-b.md).

@dataclasses.dataclass
class ProviderLine:
    """One connected provider. `word` and `tone` are the status tag,
    `read` the Read column's text and `read_warn` whether it is amber, the
    four counts are the snapshot's own and empty when there is none."""
    key: str
    name: str
    token: str
    word: str
    tone: str
    servers: object = ""
    in_fleet: object = ""
    firewalls: object = ""
    without: object = ""
    read: str = ""
    read_warn: bool = False
    # The token this row is, by its id, since a workspace may hold one token
    # per project (docs/RECORD.md 4.206). The menu's three acts name it, so
    # Read now on one Hetzner row never reads another's project. Empty on a
    # row with no token behind it, which acts on the only one.
    ref: object = ""


PROVIDER_COLUMNS = ("Provider", "Token", "Status", "Servers", "Firewalls", "Read", "")
NOTHING_CONNECTED = "Nothing connected yet"
PROVIDER_GLYPHS = {key: glyph for key, _name, glyph, _built in PROVIDERS}
PROVIDER_NAMES = {key: name for key, name, _glyph, _built in PROVIDERS}
# The row's three acts, each with the class the page script binds to it and
# the message the sample shell raises instead, since the shell has no server.
PROVIDER_MENU = (("Read now", "js-prov-read", "The provider would be read now"),
                 ("Replace token", "js-prov-token", "The token window would open here"),
                 ("Disconnect", "js-prov-off rm-del", "The provider would be disconnected"))


def provider_menu_html(key, live=True, ref=""):
    """The row's menu: Read now, Replace token, and Disconnect apart under a
    line in the fail tone as Delete is on a channel row. Live since the
    credential store exists (record 4.178); the sample shell keeps the same
    items raising a toast, as every other menu on it does.

    Each item names the row's token by `ref`, and the menu's own id carries
    it too, so two Hetzner rows are two menus that open and act apart."""
    safe, token = esc(key), esc(str(ref))
    items = ""
    for text, cls, msg in PROVIDER_MENU:
        if "rm-del" in cls:
            items += '<hr class="rm-hr">'
        if live:
            items += (f'<button type="button" class="rm-i {cls}"'
                      f' data-provider="{safe}" data-token="{token}">{esc(text)}</button>')
        else:
            tail = " rm-del" if "rm-del" in cls else ""
            items += (f'<button type="button" class="rm-i js-act{tail}"'
                      f' data-msg="{esc(msg)}">{esc(text)}</button>')
    menu = f"intg-{safe}-{token}" if token else f"intg-{safe}"
    return (f'<div class="rmenu"><button type="button" class="rm-t"'
            f' data-menu="{menu}" aria-label="Manage {esc(PROVIDER_NAMES.get(key, key))}">'
            f'{DOTS_GLYPH}</button><div class="rm-p">{items}</div></div>')


def count_cell_html(number, under):
    if number == "":
        return '<span class="pvn2"></span>'
    return f'<span class="pvn2">{esc(number)}<small>{esc(under)}</small></span>'


def provider_line_html(line, live=True):
    without = line.without
    under = "" if without == "" else f'{without} server{"" if without == 1 else "s"} without'
    glyph = PROVIDER_GLYPHS.get(line.key, "cloud")
    # a mark on the 24 grid draws smaller than a Phosphor glyph at one size
    return (f'<div class="al pv" data-provider="{esc(line.key)}" data-token="{esc(str(line.ref))}">'
            f'<span class="pvn">{theme.icon(glyph, 18)}{esc(line.name)}</span>'
            f'<b class="pvtok">{esc(line.token)}</b>'
            f'<span class="altag">{theme.status(line.tone, esc(line.word))}</span>'
            f'{count_cell_html(line.servers, f"{line.in_fleet} in your fleet")}'
            f'{count_cell_html(line.firewalls, under)}'
            f'<span class="pvread{" warn" if line.read_warn else ""}">{esc(line.read)}</span>'
            f'<span class="alac">{provider_menu_html(line.key, live, line.ref)}</span></div>')


def providers_table_html(lines, live=True):
    return (f'<div class="panel altbl pvt">{alerts_thead_html(PROVIDER_COLUMNS)}'
            + "".join(provider_line_html(line, live) for line in lines) + "</div>")


def add_button_html():
    """The one button that adds anything on Integrations."""
    return button("Add", "pri", data_open=ADD_WINDOW)


def nothing_connected_html():
    return (f'<div class="panel alnone">{theme.icon("plugs", 44)}'
            f'<div class="w">{NOTHING_CONNECTED}</div>'
            f'{add_button_html()}</div>')


def integrations_view(lines, destinations_html, has_destinations, live=True):
    """The page: everything a workspace connects. Providers, then Alert
    destinations, which is the table the Alerts screen held as Channels,
    drawn by the same function from the same rows
    (docs/screens/alerts/SPEC-layout-b.md).

    `destinations_html` is `channel_rows_html`'s answer and `has_destinations`
    whether it holds a row. With no provider and no destination the page is
    the one box, and its button is the only one. With one kind connected and
    not the other, the empty one shows its one line under its heading."""
    if not lines and not has_destinations:
        return f"""<div class="wrap view" id="integrations">
  <div class="ph">
    <div><h1>Integrations</h1></div>
  </div>
  {nothing_connected_html()}
</div>"""
    if lines:
        providers = providers_table_html(lines, live)
    else:
        # The words a server's firewall panel says for the same fact.
        providers = (f'<div class="panel altbl"><div class="al alempty">'
                     f'{NO_PROVIDER_FIREWALL}</div></div>')
    return f"""<div class="wrap view" id="integrations">
  <div class="ph">
    <div><h1>Integrations</h1></div>
    <div class="acts">{add_button_html()}</div>
  </div>
  {alerts_h2("Providers")}{providers}
  {alerts_h2("Alert destinations")}<div class="panel altbl chan chanp">{destinations_html}</div>
</div>"""


def add_kind_card_html(key, name, glyph):
    """One first card of the Add window, drawn as the Add server window
    draws its own: a block with the icon above the word."""
    return (f'<div class="m-card pick" data-kind="{esc(key)}">'
            f'{theme.icon(glyph, 22)}<div class="m-card-t">{esc(name)}</div></div>')


def add_card_html(name, glyph, fields=""):
    """One card of the Add window's second step: the mark, then the name.

    A built one names the step that holds its own fields. A planned one is
    tagged and disabled, and the tag is all it says. It names its step in
    `data-fields` and not in `data-stage`, because the page's shared picker
    shows one step at a time and this window keeps the cards of the kind in
    view above the fields."""
    ic = theme.icon(glyph, 20)
    if fields:
        return (f'<button type="button" class="m-card pick nmo" data-fields="{esc(fields)}">{ic}'
                f'<div class="m-card-t">{esc(name)}</div></button>')
    return ('<button type="button" class="m-card planned nmo" disabled aria-disabled="true">'
            f'{ic}<div class="m-card-t">{esc(name)}{PLANNED_TAG}</div></button>')


def add_cards_by_kind():
    """{kind: (the grid's classes, its cards)} for the second step."""
    destinations = "".join(add_card_html(name, CHANNEL_ICONS[name], stage)
                           for name, stage in ADD_CHANNELS)
    destinations += add_card_html(SYSLOG_CARD[1], SYSLOG_CARD[2])
    providers = "".join(add_card_html(name, glyph, f"intg-{key}" if built else "")
                        for key, name, glyph, built in PROVIDERS)
    monitoring = "".join(add_card_html(name, glyph)
                         for _key, name, glyph, _built in MONITORING)
    return {"dest": ("m5 w6", destinations), "prov": ("m4", providers),
            "mon": ("m4 w3", monitoring)}


def integration_stage_html(key):
    """The picked card's own fields, two to a row, a lone or odd last one
    spanning the width (CSS).

    Each field is followed by its own line, where a refusal of that field
    stands, as a destination's field is (docs/RECORD.md 4.228). The fields
    are numbered from one in the order they are drawn."""
    fields = "".join(
        f'<div><div class="m-label">{esc(label)}</div>'
        f'<input class="m-input" id="intg-{esc(key)}-{number}" placeholder="{esc(placeholder)}"'
        f'{" type=\"password\"" if secret else ""}'
        f' aria-describedby="intg-{esc(key)}-{number}-err">'
        f'{field_line_html(f"intg-{key}-{number}")}</div>'
        for number, (label, placeholder, secret) in enumerate(INTEGRATION_FIELDS[key], 1))
    return f'<div class="m-stage" id="intg-{esc(key)}" data-type="{esc(key)}"><div class="m-two">{fields}</div></div>'


def add_modal(live=False):
    """The one Add window, in the flow the Add server window has
    (docs/screens/alerts/SPEC-layout-b.md). Three steps, each under the one
    before it:

      1  the kinds, one first card each (`ADD_KINDS`)
      2  the cards of the kind picked
      3  the picked card's own fields, as its window had them

    The foot holds Cancel alone, as the primary button, until a built card's
    fields show. Then Cancel is plain and the action stands beside it: Save
    for a destination, Connect for a provider. So there is one primary button
    at every step and no action before there is something to act on. The
    page script owns both buttons.

    On the live page the action writes: a destination's row, or a provider's
    token, which is read at once (record 4.178). On the sample shell it says
    what it would do, because the shell has no server behind it."""
    by_kind = add_cards_by_kind()
    first = "".join(add_kind_card_html(*kind) for kind in ADD_KINDS)
    second = "".join(
        f'<div class="m-stage m-kind" id="conn-{key}">'
        f'<div class="m-cards {by_kind[key][0]}">{by_kind[key][1]}</div></div>'
        for key, _name, _glyph in ADD_KINDS)
    fields = ("".join(channel_stage(stage) for stage in CHANNEL_FIELDS)
              + "".join(integration_stage_html(key)
                        for key, _n, _g, built in PROVIDERS if built))
    body = f"""<div class="m-cards m{len(ADD_KINDS)} m-first">{first}</div>
    {second}
    {fields}
    <div class="m-stage" id="chan-adv">{ADVANCED_HTML}</div>
    <div class="m-err m-quiet" id="conn-err"></div>"""
    # The tag follows its word, as everywhere: before Docs it read as if the
    # window itself were planned.
    docs = (f'<span class="m-docs">'
            f'{button("Docs" + theme.icon("arrow-square-out", 14), "out", disabled=True)}'
            f'{PLANNED_TAG}</span>')
    words = {f"data_{kind}": word for kind, word in ADD_ACTIONS.items()}
    if not live:
        words["data_sample"] = "1"
    buttons = (button("Cancel", "pri", id="conn-cancel", data_close=ADD_WINDOW)
               + button(ADD_ACTIONS["dest"], "pri", id="conn-go", hidden=True, **words))
    return modal_shell(ADD_WINDOW, "Add", body, head_extra=docs, buttons=buttons)


def provider_token_modal():
    """Replace token, opened from a provider row's menu: one field for the
    new token and Save. The old token of that row is gone the moment the new
    one is stored, and the provider is read with the new one at once. The
    workspace's other tokens are untouched."""
    body = ('<div class="m-two"><div><div class="m-label">Read token</div>'
            '<input class="m-input" id="ptok-input" type="password" autocomplete="off"'
            ' spellcheck="false" aria-label="Read token"></div></div>'
            '<div class="m-err" id="ptok-err"></div>')
    return modal_shell("ptok-ovl", "Replace token", body, action="Save",
                       action_id="ptok-go", close_word="Cancel")


INTEGRATIONS_CSS = """
/* ---- the Integrations screen (docs/screens/integrations) */
.pvt .alhd,.pvt .al{grid-template-columns:200px minmax(0,1fr) 130px 120px 120px 120px 48px}
.pvt{overflow:visible}
.pvt .alhd{border-radius:var(--r) var(--r) 0 0}
.al.pv{cursor:default}
.al.pv:hover{background:none}
.pvn{display:flex;align-items:center;gap:10px;color:var(--ink)}
.pvn .ic{color:var(--ink)}
.pvtok{font-family:"IBM Plex Mono",monospace;font-weight:600;color:var(--ink-str);word-break:break-all}
.pvn2{font-family:"IBM Plex Mono",monospace;color:var(--ink)}
.pvn2 small{display:block;font-family:inherit;font-size:var(--fs-micro);color:var(--muted);margin-top:2px;font-family:"Work Sans",system-ui,sans-serif}
.pvread{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-micro);color:var(--muted)}
.pvread.warn{color:var(--warn)}
.pvt .rm-p{min-width:200px}
.rm-i.rm-pl{color:var(--faint);cursor:default;display:flex;align-items:center;gap:10px;white-space:nowrap}
.rm-i.rm-pl:hover{background:none}
.rm-i.rm-pl.rm-del{color:var(--fail);opacity:.6}
.m-grp{font-size:var(--fs-micro);letter-spacing:.06em;text-transform:uppercase;color:var(--faint);font-family:"IBM Plex Mono",monospace;margin:0 0 8px}
.m-cards+.m-grp{margin-top:4px}
.m-cards.m4{grid-template-columns:repeat(4,1fr)}
.m-cards.m4 .m-card.nmo{flex-direction:column;justify-content:center;text-align:center;gap:8px;padding:14px 6px 12px}
.m-cards.m4 .m-card.planned .m-card-t,
.m-cards.m5 .m-card.planned .m-card-t{display:flex;flex-direction:column;align-items:center;gap:6px}
/* the Add window's second step: six destinations across, three monitoring */
.m-cards.m5.w6{grid-template-columns:repeat(6,1fr)}
.m-cards.m4.w3{grid-template-columns:repeat(3,1fr)}
/* its error line takes no room until it says something, so the first step
   is the cards and the foot */
.m-err.m-quiet:empty{display:none}
/* A field the window refused: its border in the fail colour, with its line
   under it, until the field is edited (docs/DESIGN.md section 3). The
   focused form is named too, so a refused field that holds the cursor still
   shows it. */
.m-input[aria-invalid="true"],.m-input[aria-invalid="true"]:focus{border-color:var(--fail)}
/* The window grows downward from a top that stays put. Centred, it moved up
   at every step and took the card just clicked out from under the pointer,
   60 px and then 195 at 900 high. */
#conn-ovl{align-items:flex-start}
#conn-ovl .modal{margin-top:6vh}
/* In a row of its cards the icons stand at one height and the words at one,
   with a planned tag or without: the tag goes under. */
#conn-ovl .m-kind .m-card.nmo{justify-content:flex-start}
/* An edit is about one row. Its kind is not a choice and its type cannot
   change, so neither row of cards is drawn: the fields stand under the
   title, which says which row it is. The script names the row in
   data-editing while it edits. */
#conn-ovl[data-editing]:not([data-editing=""]) .m-first,
#conn-ovl[data-editing]:not([data-editing=""]) .m-kind{display:none}
/* With nothing connected there is no heading over the one box. It starts
   where a screen's first table starts: under a heading's room. */
#integrations .ph+.alnone{margin-top:58px}
.m-two{display:grid;grid-template-columns:1fr 1fr;gap:0 14px;margin-top:6px}
.m-two>div:nth-child(odd):last-child{grid-column:1/-1}
.m-two .m-label{margin-top:8px}
.m-docs{display:inline-flex;align-items:center;gap:8px;margin-left:auto;margin-right:12px}
.btn.out .ic{margin-left:6px;vertical-align:-2px}
.m-foot .acts .tag-planned{align-self:center}
"""
CSS += INTEGRATIONS_CSS

# The sample shell's one connected provider, as the sketch draws it.
# Invented numbers, like every other number in this shell.
SAMPLE_PROVIDERS = [
    ProviderLine("hetzner", "Hetzner Cloud", "hz_…c3f1", "connected", "ok",
                 4, 3, 2, 1, "12 min ago"),
]


# ---------------------------------------------------------------- Admin
#
# The nav entry is appended by the renderer rather than written into NAV,
# because it is there only for an account that carries the admin flag. NAV is
# what every other view is drawn from and the sample shell builds from it too,
# so a fourth entry in it would put an Admin tab on a drawing that has no
# numbers behind it.
ADMIN_NAV = ("admin", "Admin")

# The screen in B's shape (docs/screens/admin/SPEC.md, his pick of B and his
# three picks of docs/record 4.425): a strip of four on every tab, then
# the host page's tabs. Instances first, since the strip is the overview and
# the beta is self-hosted instances asking our probers. Billing is planned:
# the tag is the whole of what is said about it. Feedback is built with the
# window's wire (docs/screens/feedback/BRIEF.md).
ADMIN_TABS = ("instances", "betalist", "feedback", "workspaces", "servers", "billing")
ADMIN_TAB_LABELS = {"instances": "Instances", "betalist": "Beta list",
                    "feedback": "Feedback", "workspaces": "Workspaces",
                    "servers": "Servers", "billing": "Billing"}
ADMIN_PLANNED = ("billing",)
ADMIN_PLANNED_BODY = ""

# The tab switching, the host page's own mechanism on its own radio group,
# `tabs-admin`. Kept as its own name as well as folded into CSS, so a test
# can read the rules for one tab without matching against the whole sheet.
ADMIN_CSS_RULES = tab_css(ADMIN_TABS)
CSS += ADMIN_CSS_RULES


def stats_html(cards):
    """A grid of number cards. `cards` is [(label, value)], both plain text.

    The value is printed as it is handed over, so a caller that wants
    thousands separated does that itself. Nothing here decides what a number
    means.
    """
    return ('<div class="stats">'
            + "".join(f'<div class="stat"><div class="v">{esc(str(value))}</div>'
                      f'<div class="k">{esc(label)}</div></div>'
                      for label, value in cards)
            + "</div>")


def admin_strip_html(boxes):
    """The strip: `boxes` is [(label, number, lines, tone, tab_key)], the
    lines a list of values under the number. Each box is a label for the tab
    behind its number. `tone` is "fail" or "", decided by the renderer from
    the thresholds that came with the numbers: this only draws it."""
    out = []
    for label, number, lines, tone, key in boxes:
        n_cls = ' class="n fail"' if tone == "fail" else ' class="n"'
        under = "".join(f'<div class="d">{esc(line)}</div>' for line in lines)
        out.append(f'<div><label for="tb-admin-{esc(key)}"><div class="l">{esc(label)}</div>'
                   f'<div{n_cls}>{esc(str(number))}</div>{under}</label></div>')
    return '<div class="fstrip adm">' + "".join(out) + "</div>"


def admin_thead_html(labels):
    """The Fleet's head: one span per column, right aligned where the column
    is a number. `labels` is [(label, right)]."""
    return "".join(f'<span class="ar">{esc(label)}</span>' if right
                   else f"<span>{esc(label)}</span>" for label, right in labels)


def admin_table_html(cls, labels, rows_html, empty):
    """One table in the Fleet's shape: the panel, the head, the rows, or one
    line when there is nothing. `cls` names the grid, whose tracks are in
    ADMIN_CSS."""
    body = rows_html if rows_html else f'<div class="row {cls}"><div class="empty">{esc(empty)}</div></div>'
    return (f'<div class="panel ftbl"><div class="thead {cls}">{admin_thead_html(labels)}</div>'
            f"{body}</div>")


INSTANCE_COLUMNS = (("State", False), ("Instance", False), ("Last seen", True),
                    ("Last batch", True), ("Proved", True), ("Targets, today", True),
                    ("Connects, this hour", True))


def instance_row_html(tone, word, name, seen, batch, proved, targets, connects, opened_html):
    """One instance, a details element: the row is the summary and what he
    would otherwise read from the box opens under it. Every value arrives as
    text and is escaped here."""
    return (f'<details class="irow-d"><summary class="row irow">'
            f"<div>{theme.status(tone, esc(word))}</div>"
            f'<div class="nm">{esc(name)}</div>'
            f'<div class="mono ar">{esc(seen)}</div>'
            f'<div class="mono ar">{esc(batch)}</div>'
            f'<div class="mono ar">{esc(proved)}</div>'
            f'<div class="mono ar">{esc(str(targets))}</div>'
            f'<div class="mono ar">{esc(connects)}</div></summary>'
            f'<div class="iopen">{opened_html}</div></details>')


def instance_open_html(keys, log, failure):
    """What an open instance row holds: its keys' days, the abuse log's last
    week per vantage, and a failure still on the box. Three lists of values,
    nothing that acts. `keys` is [(kind, issued, revoked)], `log`
    [(vantage, targets, batches, connects)], `failure` (error, vantage, when)
    or None."""
    key_lines = "".join(
        f"<div><b>{esc(kind)}</b> {esc(issued)}"
        + (f" revoked {esc(revoked)}" if revoked else "") + "</div>"
        for kind, issued, revoked in keys) or "<div>none</div>"
    log_lines = "".join(
        f"<div><b>{esc(vantage)}</b> {plural(targets, 'address', 'addresses')}"
        f" {plural(batches, 'batch', 'batches')} {plural(connects, 'connect')}</div>"
        for vantage, targets, batches, connects in log) or "<div>none this week</div>"
    if failure:
        error, vantage, when = failure
        fail_line = f"<div><b>{esc(error)}</b> {esc(vantage)} {esc(when)}</div>"
    else:
        fail_line = "<div>none</div>"
    return (f'<div><div class="iok">Keys</div><div class="iol">{key_lines}</div></div>'
            f'<div><div class="iok">Log, 7 days</div><div class="iol">{log_lines}</div></div>'
            f'<div><div class="iok">Failed batch</div><div class="iol">{fail_line}</div></div>')


WORKSPACE_COLUMNS = (("State", False), ("Workspace", False), ("Accounts", True),
                     ("Servers", True), ("Reporting", True), ("Newest document", True))


def workspace_row_html(tone, word, workspace_id, name, accounts, servers, reporting, newest):
    """One workspace, the row the way in: its own dashboard under the
    viewing banner."""
    return (f'<a class="row wrow2" href="/admin/workspace/{int(workspace_id)}">'
            f"<div>{theme.status(tone, esc(word))}</div>"
            f'<div class="fsrv"><div class="hn">{esc(name)}</div>'
            f'<div class="fhost crow-l">workspace {int(workspace_id)}</div></div>'
            f'<div class="mono ar">{esc(str(accounts))}</div>'
            f'<div class="mono ar">{esc(str(servers))}</div>'
            f'<div class="mono ar">{esc(str(reporting))}</div>'
            f'<div class="mono ar">{esc(newest)}</div></a>')


ADMIN_ACCOUNT_COLUMNS = (("Account", False), ("Created", False),
                         ("Workspace", True), ("Servers", True),
                         ("Last signed in", True))


def admin_accounts_html(rows, empty="no accounts yet"):
    """The newest accounts, one row each, the row the way into that account's
    workspace.

    `rows` is [(email, created, workspace_id, workspace_name, servers,
    last_seen)], all of it printed as text and all of it escaped here: an
    email address is somebody else's input and this is the one place on any
    screen that prints one. The workspace is its name; its number is in the
    row's address.
    """
    body = "".join(
        f'<a class="row acrow" href="/admin/workspace/{int(workspace)}">'
        f'<div class="nm">{esc(email)}</div>'
        f'<div class="mono">{esc(created)}</div>'
        f'<div class="mono ar">{esc(name)}</div>'
        f'<div class="mono ar">{esc(str(servers))}</div>'
        f'<div class="mono ar">{esc(last_seen)}</div></a>'
        for email, created, workspace, name, servers, last_seen in rows)
    return admin_table_html("acrow", ADMIN_ACCOUNT_COLUMNS, body, empty)


ADMIN_QUIET_COLUMNS = (("State", False), ("Server", False), ("Workspace", True),
                       ("Added", True), ("Last document", True))


def admin_quiet_html(rows, empty="every server is reporting"):
    """The servers that are not reporting, one row each, the row the way into
    the server's workspace, where it sits on the Fleet.

    `rows` is [(name, workspace_id, workspace_name, added, last, tone,
    state)]. The tone comes from the caller because it has to be the fleet's
    tone for the same state, not one chosen here. The workspace is its name;
    its number is in the row's address. The empty line says every server is
    reporting rather than saying nothing: an empty list here is the good
    answer and has to read as one.
    """
    body = "".join(
        f'<a class="row qrow2" href="/admin/workspace/{int(workspace)}">'
        f"<div>{theme.status(tone, esc(state))}</div>"
        f'<div class="nm">{esc(name)}</div>'
        f'<div class="mono ar">{esc(wname)}</div>'
        f'<div class="mono ar">{esc(added)}</div>'
        f'<div class="mono ar">{esc(last)}</div></a>'
        for name, workspace, wname, added, last, tone, state in rows)
    return admin_table_html("qrow2", ADMIN_QUIET_COLUMNS, body, empty)


BETA_COLUMNS = (("Address", False), ("Fleet", True), ("Joined", True))


def admin_beta_html(rows, empty="nobody on the list"):
    """Who asked for an invitation: the address, the fleet size they said,
    the day. No row opens and no row acts. `rows` is [(email, fleet, joined)]."""
    body = "".join(
        f'<div class="row brow2"><div class="nm">{esc(email)}</div>'
        f'<div class="mono ar">{esc(fleet)}</div>'
        f'<div class="mono ar">{esc(joined)}</div></div>'
        for email, fleet, joined in rows)
    return admin_table_html("brow2", BETA_COLUMNS, body, empty)


LOOKUP_COLUMNS = (("Instance", False), ("Vantage", False), ("Day", False),
                  ("First", True), ("Last", True), ("Batches", True), ("Connects", True))


def lookup_form_html(csrf, address=""):
    """The address lookup: a form that posts, with the page's own token, so
    the address of somebody who complained is never in a query string. It
    reads with no script."""
    return (f'<form class="lookup" method="post" action="/admin/lookup">'
            f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
            f'<input class="srch" name="address" placeholder="Address" autocomplete="off"'
            f' maxlength="64" value="{esc(address)}" aria-label="Address">'
            f'{button("Look up", type="submit")}</form>')


def lookup_result_html(address, error, rows):
    """What a lookup answered: the address, how many rows or the one word,
    then the rows. `rows` is [(instance, vantage, day, first, last, batches,
    connects)]. Nothing of the address is kept anywhere but here."""
    if error:
        head = (f'<div class="lookup-h"><span class="addr">{esc(address)}</span>'
                f'<span class="err">{esc(error)}</span></div>')
        return head
    head = (f'<div class="lookup-h"><span class="addr">{esc(address)}</span>'
            f'<span class="hint">{plural(len(rows), "row")}</span></div>')
    body = "".join(
        f'<div class="row lrow"><div class="nm">{esc(instance)}</div>'
        f'<div class="mono">{esc(vantage)}</div><div class="mono">{esc(day)}</div>'
        f'<div class="mono ar">{esc(first)}</div><div class="mono ar">{esc(last)}</div>'
        f'<div class="mono ar">{esc(str(batches))}</div>'
        f'<div class="mono ar">{esc(str(connects))}</div></div>'
        for instance, vantage, day, first, last, batches, connects in rows)
    return head + admin_table_html("lrow", LOOKUP_COLUMNS, body, "no batch has named it")


FEEDBACK_COLUMNS = (("When", False), ("From", False), ("Kind", False),
                    ("Screen", False), ("Version", False), ("Words", False),
                    ("", False))


def feedback_row_html(row_id, when, sender, kind, screen, version, words, done):
    """One message in the console. Every value arrives as text and is
    escaped here. The words are escaped and nothing else: never a link,
    never cut, newlines kept by the cell's own style. The actions sit in
    the fixed end track: Done and Delete on an open one, Delete alone on a
    done one (docs/record 4.425, 4.436). The sender and the time ride on
    the row for the delete dialog to name."""
    acts = ("" if done else button("Done", "js-fb-done")) + button("Delete", "js-fb-del")
    return (f'<div class="row frow" data-id="{int(row_id)}" data-from="{esc(sender)}"'
            f' data-when="{esc(when)}">'
            f'<div class="mono">{esc(when)}</div>'
            f'<div class="nm">{esc(sender)}</div>'
            f'<div class="mono">{esc(kind)}</div>'
            f'<div class="mono">{esc(screen)}</div>'
            f'<div class="mono">{esc(version)}</div>'
            f'<div class="fwords">{esc(words)}</div>'
            f'<div class="fact">{acts}</div></div>')


def admin_feedback_html(open_rows, done_rows):
    """The Feedback tab: the open messages in one table, the done ones
    under a fold. Both lists are whole. `open_rows` and `done_rows` are
    [(id, when, sender, kind, screen, version, words)], newest first."""
    open_html = "".join(feedback_row_html(*row, done=False) for row in open_rows)
    done_html = "".join(feedback_row_html(*row, done=True) for row in done_rows)
    hint = f"{len(open_rows)} open, {len(done_rows)} done"
    fold = (f'<details class="fs fb-done" id="fb-done"><summary><span>Done</span>'
            f'<span class="hint" id="fb-done-n">{len(done_rows)}</span></summary>'
            f'<div class="fold-b">'
            f'{admin_table_html("frow", FEEDBACK_COLUMNS, done_html, "nothing done yet")}'
            f'</div></details>')
    return (f'<div class="sec"><div class="sech"><h2></h2>'
            f'<span class="hint" id="fb-hint">{hint}</span></div>'
            f'{admin_table_html("frow", FEEDBACK_COLUMNS, open_html, "no message yet")}'
            f'{fold}</div>')


def admin_view(sections, strip_html, feedback_open=0):
    """The Admin screen: the title, the strip on every tab, then the host
    page's tabs.

    `sections` is [(key, label, body_html)] and every key has to be one of
    ADMIN_TABS, for the same reason `settings_view` insists: the stylesheet
    carries a rule per key, so a key it does not know renders a tab that
    opens nothing. A planned key gets its label and the tag, no radio and no
    panel, the way a planned host tab does.

    `feedback_open` is worn by the Feedback tab's label in the badge the
    Alerts entry wears, and absent at zero.
    """
    unknown = [key for key, _label, _body in sections if key not in ADMIN_TABS]
    if unknown:
        raise ValueError(f"no stylesheet rule for admin tab: {unknown}")
    built = [(key, label, body) for key, label, body in sections if key not in ADMIN_PLANNED]
    inputs = "".join(
        f'<input type="radio" class="tabsel k-{key}" name="tabs-admin" id="tb-admin-{key}"'
        f'{" checked" if i == 0 else ""}>'
        for i, (key, _label, _body) in enumerate(built))
    badges = {"feedback": (f'<span class="nb" id="fb-open-nb">{int(feedback_open)}</span>'
                           if feedback_open else "")}
    labels = "".join(
        f'<label class="planned">{esc(label)}{PLANNED_TAG}</label>' if key in ADMIN_PLANNED
        else f'<label class="k-{key}" for="tb-admin-{key}">{esc(label)}{badges.get(key, "")}</label>'
        for key, label, _body in sections)
    panels = "".join(f'<div class="tab k-{key}" id="t-admin-{key}">{body}</div>'
                     for key, _label, body in built)
    return f"""<div class="wrap view" id="admin">
  <div class="ph">
    <div><h1>Admin</h1></div>
  </div>
  {strip_html}
  {inputs}<div class="subnav">{labels}</div>{panels}
</div>"""


def viewing_banner(name, workspace_id):
    """The strip that says whose fleet this is.

    It is not decoration. Every screen below it is somebody else's servers, and
    the one thing that must never happen is reading a page as your own. It
    names the workspace and offers the way back, and nothing else.
    """
    return (f'<div class="vbar"><div class="vbar-in">'
            f'<span class="vb-t">Viewing</span>'
            f'<b>{esc(name)}</b>'
            f'<span class="vb-w">workspace {esc(str(workspace_id))}</span>'
            f'<a class="btn" href="/admin">Back to Admin</a>'
            f'</div></div>')


# What "Try it, send nothing" puts in the command box.
#
# Two lines and no enrolment. The package installs, and until a host is
# enrolled AND its timer is enabled nothing leaves the machine: the packaged
# unit says so in its own header, and `agent/cmd/agent/main.go` says
# `--mode=stdout` does "send nothing off the machine". So this
# prints the document on the operator's own terminal and there is nothing to
# revoke afterwards.
#
# It is the same installer the other two cards use, without the `enroll` and
# without `systemctl enable`. Naming a second download path would be a second
# thing to keep signed and a second thing to trust.
TRY_COMMAND = ("curl -fsSL https://get.whichports.com/install.sh | sudo sh"
               " && sudo whichports-agent --mode=stdout")


ARRIVAL_STEPS = (("arr-report", "First report"),
                 ("arr-probe", "First measurement"))


def arrival_rows_html():
    """The server arriving, under the install command: two rows, each a mark,
    a label and a value (docs/screens/add-server/BRIEF-arrival.md).

    A row's `data-step` is `idle` before its turn, `wait` while it is waited
    for and `done` once it happened. Only `wait` has a mark, the spinner. A
    done step is its value in ink and nothing else, because docs/DESIGN.md
    section 3 allows no tick anywhere: done is a word and a weight. The page script moves it and writes the
    value. Hidden until a command is on the window. No sentence, ever: a step
    that has not happened keeps its spinner.
    """
    rows = "".join(
        f'<div class="arr-row" id="{step_id}" data-step="idle">'
        f'<span class="arr-m">{theme.icon("circle-notch", 16)}</span>'
        f'<span class="arr-l">{esc(label)}</span><span class="arr-v"></span></div>'
        for step_id, label in ARRIVAL_STEPS)
    return f'<div class="arr" id="add-arr" hidden>{rows}</div>'


def add_server_modal():
    """The add-server dialog, in three stages: pick a platform, pick a
    method, get the command. Nothing is preselected, so the first click is
    always a real choice.

    **Try it, send nothing, added 2026-08-28** (`docs/RECORD.md` 4.124). The
    agent has had this mode since it was written and the product never offered
    it: `--mode=stdout` is its default, its own header calls it "the way to
    evaluate the agent without trusting anything", and it does not read the
    enrolment file and sends nothing off the machine. A person deciding whether
    to put this on a production
    server wants that first, and the flow's least committing option was
    installing an agent and enrolling it in one paste.

    This card mints no credential, which is why it is wired separately from
    the two agent cards. Nothing about the fleet changes when it is clicked
    and no host is created.

    **Windows became a real pick on 2026-08-27** and it lands on the same
    stage Other devices lands on, which offers addresses and no agent. The
    Windows agent is still v2 (`docs/PRODUCT.md` section 7) and nothing here
    claims otherwise: what a Windows box gets is the outside view, which is
    the same answer that section already gives for appliances, "probe only
    there". Before this it was greyed and tagged planned, which told somebody
    with a Windows estate that the product had nothing for them when it had
    the whole agentless tier for them."""
    return f"""<div class="ovl" id="add-ovl">
  <div class="modal panel">
    <div class="m-h"><h2>Add server</h2><button class="m-x" id="add-close" aria-label="Close">{theme.icon('x', 18)}</button></div>
    <div class="m-cards m3">
      <div class="m-card pick" id="add-linux">
        {theme.icon('linux-logo', 22)}<div class="m-card-t">Linux</div>
      </div>
      <div class="m-card pick" id="add-windows">
        {theme.icon('windows-logo', 22)}<div class="m-card-t">Windows</div>
      </div>
      <div class="m-card pick" id="add-other">
        {theme.icon('hard-drives', 22)}<div class="m-card-t">Other devices</div>
      </div>
    </div>

    <div class="m-stage" id="add-method-linux">
      <div class="m-cards m3">
        <div class="m-card pick" id="add-try">
          {theme.icon('file-code', 20)}
          <div class="m-card-t">Try it locally</div>
        </div>
        <div class="m-card pick" id="add-agent">
          {theme.icon('download-simple', 20)}
          <div class="m-card-t">Agent</div>
        </div>
        <div class="m-card pick" id="add-addr">
          {theme.icon('globe-hemisphere-west', 20)}
          <div class="m-card-t">Addresses, no agent</div>
        </div>
      </div>
    </div>

    <div class="m-stage" id="add-method-other">
      <div class="m-cards" style="grid-template-columns:1fr">
        <div class="m-card pick" id="add-addr-other">
          {theme.icon('globe-hemisphere-west', 20)}
          <div class="m-card-t">Addresses, no agent</div>
        </div>
      </div>
    </div>

    <div class="m-stage" id="add-method-windows">
      <div class="m-cards m2">
        <div class="m-card pick" id="add-addr-windows">
          {theme.icon('globe-hemisphere-west', 20)}
          <div class="m-card-t">Addresses, no agent</div>
        </div>
        <div class="m-card" aria-disabled="true">
          {theme.icon('download-simple', 20)}
          <div class="m-card-t">Windows agent{PLANNED_TAG}</div>
        </div>
      </div>
    </div>

    <div class="m-stage" id="add-addr-stage">
      <div class="m-label">Name</div>
      <input class="m-input" id="add-addr-name" aria-label="Server name" autocomplete="off">
      {proof_form_html("add-addr")}
    </div>

    <div class="m-stage" id="add-cmd-stage">
      <div class="m-label">Run on the server. Click to copy</div>
      <div class="code m-copy" id="add-cmd"></div>
      {arrival_rows_html()}
      <div class="m-err" id="add-err"></div>
    </div>

    <div class="m-foot"><span class="m-note"></span>
      <span class="acts">{button("Cancel", id="add-done")}
      {button("Create", "pri", id="add-addr-go", hidden=True)}</span></div>
  </div>
</div>"""


def proof_form_html(prefix):
    """The proof of control form: one address, one of two ways to prove it,
    and what comes back. Used twice, in the add-server window under a name
    field and in the address window a server's settings open, so the two can
    never drift apart. `prefix` keeps the ids apart.

    The token is shown when the proof is started and is copyable, with where
    to publish it beside it. A second address of the same server is shown the
    server's token again, since one machine serves one file (docs/RECORD.md
    4.329). Verify reads the evidence and the result is one line, the
    registry's own words (controlplane/app/authz.py), whether it is yes or no.
    """
    return f"""
      <div class="m-label">Address</div>
      <input class="m-input" id="{prefix}-address" aria-label="IP address" autocomplete="off" spellcheck="false">
      <div class="m-cards m2 m-methods">
        <button type="button" class="m-card pick" id="{prefix}-http" data-method="http-token">
          {theme.icon('file-code', 20)}<div class="m-card-t">Token file on port 80</div>
        </button>
        <button type="button" class="m-card pick" id="{prefix}-dns" data-method="dns-txt">
          {theme.icon('hash', 20)}<div class="m-card-t">DNS TXT record</div>
        </button>
      </div>
      <div class="m-err" id="{prefix}-err"></div>
      <div class="m-proof" id="{prefix}-proof" hidden>
        <div class="m-label">Publish this token. Click to copy</div>
        <div class="code m-copy" id="{prefix}-token"></div>
        <div class="m-label">Read from</div>
        <div class="code m-copy" id="{prefix}-where"></div>
        <div class="m-result" id="{prefix}-result"></div>
      </div>"""


# ------------------------------------------------------- the shared modal
# add_server_modal() above establishes the window: an overlay, a panel, a
# heading with a close glyph, choices as cards, and the card you pick revealing
# the next step in place. The owner asked for the same window on Alerts and on
# Integrations, so the frame and the picker are functions here rather than a
# second copy of that markup.
#
# add_server_modal() keeps its own script because it mints a credential over
# the network. These two need none of that, so the frame's open, close and
# reveal are handled by the small generic block in page(): a trigger names its
# overlay in data-open, anything with data-close closes that overlay, and a
# pick card names the stage it reveals in data-stage. Nothing else changes in
# page(), and add_server_modal() is untouched.

def modal_shell(mid, title, body, note="", action="Done", action_msg="",
                action_ready=True, action_id="", close_word="Close",
                head_extra="", action_planned=False, action_hidden=False,
                buttons=""):
    """One modal window. `mid` is the overlay id a trigger names in data-open.

    `action` is the primary button's label and `action_msg` the toast it raises.
    `action_ready=False` renders that button disabled and adds a plain Close
    beside it, because a disabled button is no longer a way out. That is how a
    live page shows a control whose machinery is not built, instead of offering
    one that cannot act.

    `action_id` is for a button that really does something over the network.
    It takes that id and, deliberately, **no `data-close`**: a window that
    closed itself on click would close before the answer came back, so the
    script that made the request is what closes it. A plain Close is added
    beside it, because the primary button is no longer a way out either.

    `buttons` is the foot's buttons whole, for a window whose foot changes
    from step to step and so belongs to its own script (`add_modal`).
    """
    if buttons:
        pass
    elif action_id:
        # The way out first and the action last, the order the sketch of the
        # Add channel window draws (docs/screens/alerts).
        # `action_hidden` is a window with no primary button until there is
        # something for it to do: the script shows it.
        hidden = {"hidden": True} if action_hidden else {}
        buttons = (f'{button(close_word, data_close=mid)}'
                   f'{button(esc(action), "pri", id=esc(action_id), **hidden)}')
    elif action_ready:
        cls = "btn pri js-act" if action_msg else "btn pri"
        msg = f' data-msg="{esc(action_msg)}"' if action_msg else ""
        buttons = f'<button class="{cls}" data-close="{mid}"{msg}>{esc(action)}</button>'
    elif action_planned:
        # The way out, then the action it cannot take yet, marked (docs/PRODUCT.md
        # section 7): the tag is the whole of what is said about it.
        buttons = (f'{button(close_word, data_close=mid)}{PLANNED_TAG}'
                   f'{button(esc(action), "pri", disabled=True)}')
    else:
        buttons = (f'{button(esc(action), "pri", disabled=True)}'
                   f'{button("Close", data_close=mid)}')
    # No note, no note element: .m-foot .acts keeps the buttons on the right
    # by itself, so an empty span would only be a place for text to creep back.
    note_html = f'<span class="m-note">{esc(note)}</span>' if note else ""
    # data-title is the heading this window opened with. The Add window
    # renames its own heading when it is reopened to edit a row, so the word to
    # put back has to be written down somewhere that survives that.
    return f"""<div class="ovl js-modal" id="{mid}" data-title="{esc(title)}">
  <div class="modal panel">
    <div class="m-h"><h2>{esc(title)}</h2>{head_extra}
      <button class="m-x" data-close="{mid}" aria-label="Close">{theme.icon('x', 18)}</button></div>
    {body}
    <div class="m-foot">{note_html}
      <span class="acts">{buttons}</span></div>
  </div>
</div>"""


def pick_card(name, glyph, stage=None):
    """One choice in a modal picker: the mark, then the name, and nothing else.

    With a stage id it is a button that reveals that stage. Without one it is
    shown, marked planned, and disabled, so it cannot be clicked at all
    (docs/PRODUCT.md section 7, and the note at the top of this file).

    `glyph` is a name in theme.ICONS and is not optional, because a picker where
    some cards have a shape and some do not looks broken.
    """
    ic = theme.icon(glyph, 20)
    if stage:
        return (f'<button type="button" class="m-card pick nmo" data-stage="{esc(stage)}">{ic}'
                f'<div class="m-card-t">{esc(name)}</div></button>')
    return ('<button type="button" class="m-card planned nmo" disabled aria-disabled="true">'
            f'{ic}<div class="m-card-t">{esc(name)}'
            f'{PLANNED_TAG}</div></button>')


def field_check_attrs(field_id, check):
    """The attributes that carry one field's check to the page script: the
    request's field it is, what it must look like, the line for each reason
    it can be refused for, and the id of the line under it."""
    parts = [f' data-wire="{esc(check.wire)}"',
             f' data-pattern="{esc(check.pattern)}"']
    if check.longest:
        parts.append(f' data-longest="{check.longest}"')
    if check.optional:
        parts.append(" data-optional")
    for reason, words in check.says.items():
        parts.append(f' data-says-{esc(reason)}="{esc(words)}"')
    parts.append(f' aria-describedby="{esc(field_id)}-err"')
    return "".join(parts)


def field_line_html(field_id):
    """The line under one field, where a refusal of that field stands. Empty,
    it takes no room."""
    return f'<div class="m-err m-quiet" id="{esc(field_id)}-err"></div>'


def channel_stage(stage_id):
    """One built channel's own step: the field it needs, and nothing else.

    **The environment variable option left this window on 2026-08-23**
    (the owner had it deleted). `destination_env` stays in the schema and
    the CLI, and the rows on the box keep working. Only the screen stops
    offering it.

    **The explainer prose left the same day**, because the owner wanted no text
    explaining everything. Field labels are what is
    left, and there is no hint anywhere in here.

    **Slack's step holds nothing at all since 2026-08-24**, when the owner had
    the webhook URL field removed. Its destination arrives from Slack, so the
    step has no field, no divider and no line of prose, and the footer button
    is the whole of it. The page script owns that button.
    """
    channel_type, holds, input_type, placeholder = CHANNEL_FIELDS[stage_id]
    checks = CHANNEL_CHECKS[stage_id]
    # An empty `holds` is a step that asks for nothing, so it draws no field.
    # Everything downstream reads the field's absence rather than the type:
    # the save path, the edit path and the footer button all key off whether
    # `.js-dest` is there.
    #
    # Every field carries its own check and is followed by its own line,
    # where a refusal of that field stands (docs/RECORD.md 4.228).
    field = ""
    if holds:
        field = (
            f'<div class="m-label">{esc(holds[0].upper() + holds[1:])}</div>'
            f'<input class="m-input js-dest" id="{stage_id}-dest" type="{input_type}"'
            f' placeholder="{placeholder}" autocomplete="off" spellcheck="false"'
            f'{field_check_attrs(f"{stage_id}-dest", checks["dest"])}>'
            f'{field_line_html(f"{stage_id}-dest")}')
    extra = ""
    if channel_type == "telegram":
        # The chat id is the non-secret half of a Telegram destination and the
        # reason this stage has more than one field at all.
        extra = (
            '<div class="m-label" style="margin-top:14px">Chat id</div>'
            f'<input class="m-input js-chat" id="{stage_id}-chat" placeholder="-1001234567890"'
            f'{field_check_attrs(f"{stage_id}-chat", checks["chat"])}>'
            f'{field_line_html(f"{stage_id}-chat")}'
            '<div class="m-label" style="margin-top:14px">Topic'
            '<span class="opt">optional</span></div>'
            f'<input class="m-input js-thread" id="{stage_id}-thread" placeholder="42"'
            f'{field_check_attrs(f"{stage_id}-thread", checks["thread"])}>'
            f'{field_line_html(f"{stage_id}-thread")}')
    return f"""<div class="m-stage" id="{stage_id}" data-type="{channel_type}">
      {field}
      {extra}
    </div>"""


# The kinds of alert a channel can subscribe to, and the words a person reads.
#
# **These strings are `controlplane/app/channels.py`'s `KINDS` and a test
# asserts they still match.** The site cannot import the control plane except
# through joinbridge, so the vocabulary is spelled twice and compared, which is
# the shape `docs/RECORD.md` 4.88 settled on for exactly this problem.
EVENT_KINDS = [
    ("finding changed", "A port's finding changed"),
    ("silent", "An agent stopped reporting"),
    ("outside view stale", "The outside view went stale"),
    # The CVE check's message, one for a workspace
    # (controlplane/app/cvetell.py). Sent for nothing until an agent that
    # reads packages reports, which no published agent does.
    ("cve", "A newer version fixes a CVE"),
]


def event_switches_html():
    """One switch per kind, every one starting on.

    A switch and not a checkbox (the owner, 2026-08-23, asked for the on or off
    switch), and it is the honest control anyway: a channel
    that has never been asked takes every kind (`controlplane/app/channels.py`,
    empty subscriptions take everything), so a row of switches that start on
    shows that truth where a row of empty boxes read as nothing chosen. The
    page script refuses a save with every switch off, because no row can mean
    "hears nothing".

    Title only on each row (the owner had the description removed, 2026-08-24).
    """
    out = []
    for kind, title in EVENT_KINDS:
        out.append(
            f'<div class="evb"><b>{esc(title)}</b>'
            f'<button type="button" class="sw js-event" data-kind="{esc(kind)}"'
            f' aria-label="{esc(title)}"></button></div>')
    return f'<div class="evs">{"".join(out)}</div>'


# The Advanced settings step, shared by every channel because its fields are
# the same wherever you came from. The timing control is shown and marked
# planned, this project's rule for a control with nothing behind it
# (docs/PRODUCT.md section 7): a timing control that silently did nothing
# would be worse than one that says it is not built.
#
# The Label field left on 2026-08-23, on the owner's word. Rows are still keyed
# by label, so the control plane generates one
# from the type when the request carries none.
ADVANCED_HTML_TEMPLATE = """<details class="m-adv" open>
      <summary><span>Advanced settings</span></summary>
      <div class="m-adv-b">
        <div class="m-label planned">Notification timing
          {PLANNED_TAG}</div>
        <select class="m-input" disabled><option>All hours</option></select>

        <div class="m-label" style="margin-top:16px">Which alerts this destination takes</div>
        {EVENT_BOXES}
      </div>
    </details>"""

ADVANCED_HTML = (ADVANCED_HTML_TEMPLATE.replace("{EVENT_BOXES}", event_switches_html())
                 .replace("{PLANNED_TAG}", PLANNED_TAG))


# ------------------------------------------------------ the account Settings
#
# docs/screens/account-settings/SPEC.md: the server tab's shape, Profile,
# Security and Workspace real in part, Members, Billing and API planned as a
# whole. A planned category carries the tag in the rail, every row in it
# carries the tag after its name, and its controls are dashed and disabled.

ASET_CATEGORIES = (("profile", "Profile", "user-circle", False),
                   ("security", "Security", "key", False),
                   ("workspace", "Workspace", "hard-drives", False),
                   ("members", "Members", "users", True),
                   ("billing", "Billing", "credit-card", True),
                   ("api", "API", "brackets-curly", True))
ASET_GROUPS = (("", ("profile", "security")),
               ("Workspace", ("workspace", "members", "billing")),
               ("Developer", ("api",)))
ASET_KEYS = tuple(key for key, _t, _i, _p in ASET_CATEGORIES)
ASET_TITLE = {key: title for key, title, _i, _p in ASET_CATEGORIES}
ASET_SLUG = "settings"
APPEARANCES = (("dark", "Dark"), ("light", "Light"), ("system", "System"))


def aset_rail():
    out = []
    for i, (head, keys) in enumerate(ASET_GROUPS):
        if i:
            out.append("<hr>")
        if head:
            out.append(f'<div class="g">{esc(head)}</div>')
        for key in keys:
            _k, title, icon, planned = next(c for c in ASET_CATEGORIES if c[0] == key)
            tag_html = PLANNED_TAG if planned else ""
            out.append(f'<label class="hitem h-{key}{" hpl" if planned else ""}" for="hs-{ASET_SLUG}-{key}">'
                       f'{theme.icon(icon, 16)}{esc(title)}{tag_html}</label>')
    return f'<nav class="hrail" aria-label="Settings">{"".join(out)}</nav>'


def aset_view(panels):
    """The page body: the radios, the rail, the panels. `panels` is
    [(key, body)] in ASET_KEYS order, the first open. A planned category is
    still a page you can open, so its rows are read (the tag says what they
    are)."""
    radios = "".join(
        f'<input type="radio" class="hsel h-{key}" name="hs-{ASET_SLUG}" id="hs-{ASET_SLUG}-{key}"'
        + (" checked" if i == 0 else "") + ">" for i, (key, _body) in enumerate(panels))
    stages = "".join(
        f'<div class="hstage h-{key}"><h2>{esc(ASET_TITLE[key])}</h2>{body}</div>'
        for key, body in panels)
    return f'<div class="hset aset">{radios}{aset_rail()}<div class="hbody">{stages}</div></div>'


def pl_row(icon, name, sub="", control=""):
    """A planned row: greyed, the tag after the name, its controls dashed."""
    return hset_row(icon, esc(name) + PLANNED_TAG, sub, control, cls="lipl")


def pl_button(text):
    return button(esc(text), "ghost", disabled=True)


def pl_input(value="", short=False):
    return hset_input(value, disabled=True, short=short, cls="ghost")


def seg_html(on, options, cls="", wide=True, disabled=False):
    """A segmented control: (key, word) options, the picked one `on`. With
    a class each button carries `{cls}-{key}` so a script can bind it."""
    buttons = ""
    for key, word in options:
        classes = " ".join(c for c in ((f"{cls}-{key}" if cls else ""), ("on" if key == on else "")) if c)
        buttons += (f'<button type="button"{f" class={chr(34)}{classes}{chr(34)}" if classes else ""}'
                    f'{" disabled" if disabled else ""}>{esc(word)}</button>')
    return f'<span class="seg{" wide" if wide else " short"}{" ghost" if disabled else ""}">{buttons}</span>'


def appearance_html():
    return seg_html("dark", APPEARANCES, cls="js-mode")


# The rules a password has to meet, in the order the screens list them.
#
# **Spelled here and in `controlplane/app/accounts.py`, and compared by a
# test.** The site cannot import the control plane except through joinbridge,
# which the sample shell does not have, so the words are written twice, the
# same shape `EVENT_KINDS` is in. Twice and never compared is how two copies
# drift apart, so `test_password_rules.py` compares them.
PASSWORD_MIN_CHARS = 12
PASSWORD_RULES = (("length", f"At least {PASSWORD_MIN_CHARS} characters"),
                  ("digit", "A number"),
                  ("special", "A special character"))
BOTH_THE_SAME = "Both the same"


def password_rules_html(field_id, confirm_id=""):
    """The rules under a password field, one per line, coloured while
    somebody types (the owner, 2026-09-10). Grey before anything is typed,
    because red at somebody who has not started is telling them off for
    nothing."""
    rows = "".join(f'<li data-rule="{esc(key)}">{esc(words)}</li>'
                   for key, words in PASSWORD_RULES)
    extra = ""
    if confirm_id:
        rows += f'<li data-rule="match">{BOTH_THE_SAME}</li>'
        extra = f' data-confirm="{esc(confirm_id)}"'
    return f'<ul class="rules" data-for="{esc(field_id)}"{extra}>{rows}</ul>'


def address_modal():
    """The window a server's Add address button opens: the proof of control
    form the Add server window carries, in the frame every window has, so
    the two cannot drift apart. One on the page, and the button hands it its
    server. No primary button until a way to prove is picked, then Start,
    then Verify, then Done alone (docs/RECORD.md 4.375, 4.379)."""
    return modal_shell("addr-ovl", "Add an address", proof_form_html("ad"),
                       action="Start", action_id="ad-go", close_word="Cancel",
                       action_hidden=True)


# ------------------------------------------------------------ feedback
#
# The Feedback window (docs/screens/feedback/BRIEF.md): the words a person
# types, sent with a click and at no other time. It is the one exception to
# SI-8's "no free text" (docs/record 4.425), and the window is the whole of
# what leaves: two cards, the field, and five lines that are the body's five
# fields. The first request of any kind is the click on Send.

# Every screen the button can be pressed on, in the wire's order
# (controlplane/app/feedback.py, SCREENS). The instance's route refuses a
# word outside this list, and a test holds the two lists together. The word
# comes from the view and its tab, never from the address bar, which holds
# a server's name.
FEEDBACK_SCREENS = ("fleet", "host", "host/services", "host/evidence", "host/rules",
                    "host/path", "host/changes", "host/settings", "alerts",
                    "integrations", "settings", "admin")
# Counted in code points, as the wire counts (feedback.MAX_WORDS).
FEEDBACK_MAX_WORDS = 2000
FEEDBACK_HEX = re.compile(r"[0-9a-f]{7,40}")


def feedback_screens_js():
    """`FEEDBACK_SCREENS` as a JavaScript array literal, so the script and
    the tuple cannot drift."""
    return json.dumps(list(FEEDBACK_SCREENS))


def feedback_version(commit):
    """The version line: the commit the footer shows, hex only, or
    `unknown`. The footer may say `+local changes` after the hash, and the
    wire takes 7 to 40 hex or that one word."""
    found = FEEDBACK_HEX.match(commit or "")
    return found.group(0) if found else "unknown"


def feedback_button_html():
    """The one button, in the top bar beside the account circle. The page's
    own data-open wiring opens the window."""
    return button("Feedback", id="fb-btn", data_open="fb-ovl")


def feedback_modal(to, version, live=True):
    """The window, in the Add server window's shape: the two cards, the
    field, then the five lines. `to` is the host a message goes to, and
    empty when it is the instance's own, which the page fills in from its
    own address. `version` is the commit the footer shows, or `unknown`.

    One line for every answer, `#fb-result` under the five lines and above
    the buttons: Sent in the ok tone, a refusal's line, the no-answer line
    and the cap's line in the fail tone. Nothing else on the window moves.

    On the sample shell Send is a stub that says what it would do and asks
    no server. On a live page it is the button the script posts from."""
    to_html = (f'<span class="v" id="fb-to">{esc(to)}</span>' if to
               else '<span class="v" id="fb-to" data-own="1"></span>')
    facts = (f'<span class="k">To</span>{to_html}'
             '<span class="k">From</span><span class="v" id="fb-from">this instance</span>'
             '<span class="k">Screen</span><span class="v" id="fb-screen"></span>'
             f'<span class="k">Version</span><span class="v" id="fb-version">{esc(version)}</span>'
             '<span class="k">Kind</span><span class="v" id="fb-kind"></span>')
    body = (f'<div class="m-cards m2">'
            f'<button type="button" class="m-card pick" id="fb-feature">'
            f'{theme.icon("chat-circle-dots", 20)}<div class="m-card-t">Feature</div></button>'
            f'<button type="button" class="m-card pick" id="fb-bug">'
            f'{theme.icon("warning", 20)}<div class="m-card-t">Bug</div></button></div>'
            '<label class="m-label" for="fb-words">Message</label>'
            '<textarea class="m-input" id="fb-words" rows="4"></textarea>'
            f'<div class="fb-facts">{facts}</div>'
            '<div class="m-result" id="fb-result"></div>')
    return modal_shell("fb-ovl", "Feedback", body, action="Send", close_word="Cancel",
                       action_id="fb-go" if live else "",
                       action_msg="" if live else "The message would be sent here")


def password_modal(live=False):
    """Change password: the current one, then the new one twice, with the
    same rules the sign-in pages draw (the owner, 2026-09-10: the same flow for
    changing a password under Security, with the password typed twice)."""
    body = ('<div class="m-label">Current password</div>'
            '<input class="m-input" id="pw-current" type="password" autocomplete="current-password">'
            '<div class="m-label pw-gap">New password</div>'
            '<input class="m-input" id="pw-new" type="password" autocomplete="new-password">'
            '<div class="m-label pw-gap">Confirm password</div>'
            '<input class="m-input" id="pw-again" type="password" autocomplete="new-password">'
            + password_rules_html("pw-new", "pw-again")
            + '<div class="m-err" id="pw-err"></div>')
    return modal_shell("pw-ovl", "Change password", body, action="Save",
                       action_msg="" if live else "The password would change here",
                       action_id="pw-go" if live else "", close_word="Cancel")


def two_factor_modal(live=False):
    """Turning the authenticator app on, in a window on the Security
    settings (the owner, 2026-09-10). Two stages in one window: scan or type the
    key and answer with a code, then the recovery codes, which exist in
    readable form in this one render and nowhere else.

    The QR and the key arrive from the control plane when the window opens,
    because the secret is minted then. Nothing is drawn here.
    """
    setup = ('<div class="tfa-stage on" id="tfa-setup">'
             '<div class="m-qr" id="tfa-qr"></div>'
             '<div class="m-key" id="tfa-key" data-copy="" title="Click to copy"></div>'
             '<div class="m-label pw-gap">Code</div>'
             '<input class="m-input code" id="tfa-code" inputmode="numeric" maxlength="6"'
             ' placeholder="______" autocomplete="one-time-code" autocapitalize="off"'
             ' spellcheck="false">'
             '<div class="m-err" id="tfa-err"></div></div>')
    codes = ('<div class="tfa-stage" id="tfa-codes">'
             '<div class="m-label">Recovery codes, each works once</div>'
             '<div class="codes" id="tfa-codelist" data-copy="" title="Click to copy"></div>'
             f'{button("Download", "js-2fa-download", type="button")}</div>')
    return modal_shell("tfa-ovl", "Authenticator app", setup + codes,
                       action="Turn on",
                       action_msg="" if live else "Two-factor would go on here",
                       action_id="tfa-go" if live else "", close_word="Cancel")


def profile_panel(name, email, live):
    """Name in its field, Save appears once it changed. Email read only, in
    mono. Appearance, and Sign out."""
    save = (button("Save", "pri js-name-save", hidden=True) if live
            else button("Save", "pri js-act", data_msg="Your name would be saved here", hidden=True))
    field = hset_input(name, cls="js-who-name", aria_label="Your name", autocomplete="off",
                       spellcheck="false")
    signout = (button("Sign out", "js-signout", type="button") if live
               else button("Sign out", "js-act", data_msg="You would be signed out here"))
    return (hset_list(hset_row("user-circle", "Name", "", field + save, fixed=True)
                      + hset_row("envelope-simple", "Email", "",
                                 f'<span class="kv js-who-email">{esc(email)}</span>')
                      + hset_row("moon", "Appearance", "", appearance_html()))
            + hset_h3("Session")
            + hset_list(hset_row("sign-out", "Sign out", "", signout)))


def security_panel(changed, totp, live):
    """Password with when it was last set and Change, the authenticator app's
    state and the way to turn it on, Passkeys and Sessions planned.

    **The switch shows the state and does not move.** Turning the app on is a
    code exchange, so it is Turn on, which opens the window that does it
    (`two_factor_modal`, the owner 2026-09-10). Turning it off stays on the box,
    with `users_cli 2fa disable`: it is the lockout path, and the person who
    can undo a lost phone should be the person with a shell there.
    """
    sub = f'<span class="js-who-pwd">{esc(changed)}</span>'
    turn_on = button("Turn on", "js-2fa-on", hidden=totp, data_open="tfa-ovl")
    return (hset_list(hset_row("key", "Password", sub, button("Change", data_open="pw-ovl"))
                      + hset_row("key", "Authenticator app", "",
                                 hset_switch(totp, "js-who-totp", disabled=True) + turn_on)
                      + pl_row("key", "Passkeys", "", pl_button("Add a passkey")))
            + hset_h3("Sessions", planned=True)
            + hset_list(pl_row("laptop", "This browser", "this session")
                        + pl_row("laptop", "Other browsers", "", pl_button("Sign out"))
                        + pl_row("laptop", "Everywhere else", "", pl_button("Sign out"))))


def workspace_panel(workspace, live):
    save = (button("Save", "pri js-ws-save", hidden=True) if live
            else button("Save", "pri js-act", data_msg="The workspace name would be saved here", hidden=True))
    field = hset_input(workspace, cls="js-wsname", aria_label="Workspace name", autocomplete="off",
                       spellcheck="false")
    return (hset_list(hset_row("hard-drives", "Name", "", field + save, fixed=True)
                      + hset_row("time", "Timezone", "", hset_choice("UTC", disabled=True) + PLANNED_TAG))
            + hset_h3("Data", planned=True)
            + hset_list(pl_row("receipt", "Export", "", pl_button("Download"))
                        + pl_row("time", "Keep changes for", "", pl_input("90 days", short=True)))
            + hset_h3("Remove", planned=True)
            + hset_list(pl_row("trash", "Delete this workspace", "", pl_button("Delete")), danger=True))


ROLES = (("owner", "Owner"), ("admin", "Admin"), ("viewer", "Viewer"))


def members_panel(name, email):
    """Planned as a whole: the one member the account is, an Invite row, and
    Access. Every control dashed and disabled. The member's name and mail
    are the account's own, filled by the script on the live page."""
    role = seg_html("owner", ROLES, wide=False, disabled=True)
    invite_role = seg_html("viewer", ROLES[1:], wide=False, disabled=True)
    who = f'<span class="js-who-name-text">{esc(name or email)}</span>'
    mail = f'<span class="js-who-email">{esc(email if name else "")}</span>'
    return (hset_list(hset_row("user-circle", who + PLANNED_TAG, mail, role + pl_button("Remove"), cls="lipl")
                      + pl_row("envelope-simple", "Invite", "", pl_input("") + invite_role + pl_button("Send")))
            + hset_h3("Access", planned=True)
            + hset_list(hset_row("user-circle", who + PLANNED_TAG, "sees",
                                 seg_html("all", (("all", "All servers"), ("some", "Some")), wide=False, disabled=True),
                                 cls="lipl")))


def billing_panel():
    return (hset_list(pl_row("credit-card", "Plan", "", pl_input("Alpha, free") + pl_button("Change"))
                      + pl_row("credit-card", "Payment method", "", pl_button("Add")))
            + hset_h3("Invoices", planned=True)
            + hset_list(pl_row("receipt", "No invoice yet", "")))


def api_panel():
    return hset_list(pl_row("brackets-curly", "No token yet", "")
                     + pl_row("brackets-curly", "Create a token", "", pl_input("") + pl_button("Create")))


def account_settings_view(live=True, name="", email="", changed="", totp=False, workspace=""):
    """The page. On the live page the account's facts arrive from the
    control plane after the page loads (the script asks whoami and fills the
    marked fields), so the values here are what the sample shell draws."""
    panels = [("profile", profile_panel(name, email, live)),
              ("security", security_panel(changed, totp, live)),
              ("workspace", workspace_panel(workspace, live)),
              ("members", members_panel(name, email)),
              ("billing", billing_panel()),
              ("api", api_panel())]
    return f"""<div class="wrap view" id="settings">
  <div class="ph">
    <div><h1>Settings</h1></div>
  </div>
  {aset_view(panels)}
</div>"""


ASET_CSS = """
/* ---- the account Settings (docs/screens/account-settings): the server
   tab's rail and rows, planned rows greyed with dashed controls */
.hitem.hpl{color:var(--muted)}
.hitem.hpl svg{color:var(--faint)}
.li.lipl .t b,.li.lipl .t small{color:var(--muted)}
.li.lipl>svg{color:var(--faint)}
.li .t b .tag-planned{margin-left:8px;vertical-align:middle}
.btn.ghost{color:var(--faint);border-style:dashed;cursor:default}
.in.ghost{border-style:dashed;color:var(--faint)}
.seg.ghost{border-style:dashed}
.seg.ghost button{color:var(--faint)}
.seg.ghost button.on{color:var(--muted)}
.li .c .seg.wide{width:280px;box-sizing:border-box;border-radius:8px}
.li .c .seg.wide button{flex:1;text-align:center;border-radius:6px}
.li .c .seg.short{border-radius:8px}
.li .c .seg.short button{border-radius:6px}
.li .kv{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--ink-str)}
.li .c .sw{flex:none}
.pw-gap{margin-top:14px}
/* The password rules, one per line under the fields they apply to
   (docs/screens/sign-in, 2026-09-10). Grey until something is typed, red
   while a rule is unmet, green when it is met. The mark is a dot rather than
   a tick: docs/DESIGN.md section 3 keeps ticks off every surface. */
.rules{list-style:none;margin:10px 0 6px;padding:0;display:grid;gap:5px}
.rules li{display:flex;align-items:center;gap:8px;font-size:var(--fs-meta);
  color:var(--faint);transition:color var(--quick) var(--ease)}
.rules li::before{content:"";width:7px;height:7px;border-radius:99px;flex:0 0 auto;
  border:1px solid currentColor;transition:all var(--quick) var(--ease)}
.rules li.no{color:var(--fail)}
.rules li.yes{color:var(--ok)}
.rules li.yes::before{background:currentColor}
/* The QR has to be dark on light to scan, whatever theme the page is in. */
/* This window's two halves. Its own class rather than `.m-stage`, which
   every window's open handler clears on the way in: these are not a picker's
   steps, they are before and after. */
.tfa-stage{display:none}
.tfa-stage.on{display:block}
.m-qr{display:flex;justify-content:center;margin:2px 0 12px}
.m-qr svg{width:168px;height:168px;background:#FFFFFF;border-radius:8px;
  padding:8px;box-sizing:border-box}
.m-qr:empty{display:none}
.m-key{font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--ink-str);
  text-align:center;line-height:1.9;padding:12px 14px;background:var(--panel2);
  border:1px solid var(--line);border-radius:8px;cursor:pointer}
/* Both boxes are filled when the window opens, so neither draws an empty
   frame while the control plane is answering. */
.m-key:empty{display:none}
.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px 16px;
  font-family:"IBM Plex Mono",monospace;font-size:var(--fs-meta);color:var(--ink-str);
  margin:8px 0 14px;padding:14px 16px;background:var(--panel2);
  border:1px solid var(--line);border-radius:8px;cursor:pointer}
.copied{border-color:var(--acc)}
"""
CSS += ASET_CSS + "\n" + hset_css(ASET_KEYS) + "\n"
# **This is the last thing added to CSS, and it has to stay the last.** A page
# gets the stylesheet without its comments, because a comment in a stylesheet
# is sent to everybody who opens the page (site/theme.py says more). Every
# piece above is added to CSS with its comments in, for whoever reads this
# file, and they are taken out here once. A piece added below this line would
# ship its comments, and test_no_comment_leaves_in_a_page.py fails on that.
CSS = theme.css_without_comments(CSS)

# The sample account, invented like every name in this shell.
SAMPLE_ACCOUNT = dict(name="Robin Sample", email="sysadmin@example.org",
                      changed="changed 13 Aug 2026", totp=True, workspace="whichports")


# The demo host's own packet paths, one per port and family that has a story
# the other tabs already tell (docs/screens/host-packet-path/SPEC.md). Four of
# the five fates are here. `none`, a port nobody probed, is covered in the live
# suite instead, because every port this host has was probed.
#
# A rule for a panel: the action, the port, and where from, with `hit` marking
# the one this packet's port lands on and `quote` the tool's own line for it.
def _prule(action, port, protocol, families, frm, hit=False, quote=""):
    return {"action": action, "port": port, "protocol": protocol,
            "families": families, "from": frm, "hit": hit, "quote": quote}


_HZ_PROD = [
    _prule("allow", 22, "tcp", ("v4", "v6"), "anywhere"),
    _prule("allow", 80, "tcp", ("v4", "v6"), "anywhere"),
    _prule("allow", 443, "tcp", ("v4", "v6"), "anywhere"),
    _prule("allow", None, "", ("v4", "v6"), "anywhere, ICMP"),
]
_UFW_PROD = [
    _prule("allow", 22, "tcp", ("v4", "v6"), "anywhere",
           quote="22/tcp ALLOW IN Anywhere"),
    _prule("allow", 80, "tcp", ("v4", "v6"), "anywhere",
           quote="80/tcp ALLOW IN Anywhere"),
    _prule("allow", 443, "tcp", ("v4", "v6"), "anywhere",
           quote="443/tcp ALLOW IN Anywhere"),
    _prule("allow", 8096, "tcp", ("v4",), "anywhere",
           quote="8096/tcp ALLOW IN Anywhere"),
]


def _lit(rules, port):
    """The same rules with this port's row marked, which is what puts it in
    ink and leaves the others faint."""
    return [dict(r, hit=(r["port"] == port)) for r in rules]


# The agent the sample server runs: the published one. The landing page's
# builder owns that number (PUBLISHED_AGENT in site/landing/build.py). The two
# builders do not import each other, so it is written here a second time and
# test_sample_agent_and_probers.py fails the day the two differ. It read 0.1.8
# until 2026-10-07 (docs/RECORD.md 4.443), 0.1.12 until 2026-10-14, the
# day after 0.1.13 was published (4.456), and 0.1.13 until 2026-10-25, when
# the landing caught up with 0.1.14 of 16 October (4.465).
SAMPLE_AGENT_VERSION = "0.1.14"


def sample_settings_tab():
    """Per-server settings for the demo host, every category filled with the
    invented values the sketch shows. Muting has no row here: the header
    already carries the button. The answers under Probing are the sample
    server's own, drawn from its one description the way the live page draws
    a server's (sample_story.py). They were four ports written here while
    the Overview had an answer on one (docs/RECORD.md 4.460)."""
    # Asked for here and not at the top, for the reason sample_host_view gives.
    import sample_story
    story = sample_story.parts()
    return hset_view("host", [
        ("server", server_panel("host", "app-01", False, live=False,
                                tags=("production",))),
        ("agent", agent_panel("host", "Full read", "13 Aug 2026", SAMPLE_AGENT_VERSION, live=False)),
        ("probing", probing_panel("host", story.probing, live=False)),
        ("addresses", addresses_panel("host", [
            ("203.0.113.198", "token file, proved until 2 Dec 2026", True),
            ("2001:db8:c17:2b::1", "DNS, proved until 2 Dec 2026", True)], live=False)),
        ("alerts", alerts_panel("host", 35, [("tcp", 9100, "v4", SILENCE_NO_END)], live=False)),
    ], head={"addresses": add_address_button("host", live=False)})


SAMPLE_NOW = datetime.datetime(2026, 9, 4, 12, 0, tzinfo=datetime.timezone.utc)


def _sample_change(month, day, clock, layer, source, kind, protocol, port, fams, detail,
                   off=False, unsure=""):
    hour, minute = clock.split(":")
    when = datetime.datetime(2026, month, day, int(hour), int(minute), tzinfo=datetime.timezone.utc)
    return Change(when, layer, source, kind, protocol, port, fams, detail, off, unsure)


SAMPLE_CHANGES = [
    _sample_change(9, 4, "09:14", "from outside", "prober", "reachable", "tcp", 8410, ("v4",),
                   "connected in 14 ms from 78.141.210.130"),
    _sample_change(9, 4, "09:00", "process", "agent", "started", "tcp", 8410, ("v4",),
                   "uvicorn on 0.0.0.0:8410, pid 1183"),
    _sample_change(9, 3, "16:05", "from outside", "prober", "reachable", "tcp", 22, ("v6",),
                   "connected in 18 ms, nothing bound on v6"),
    _sample_change(9, 2, "11:29", "host firewall", "agent", "rule added", "tcp", 8096, ("v4",),
                   "ufw: 8096/tcp ALLOW IN Anywhere"),
    _sample_change(9, 2, "11:29", "host firewall", "agent", "rule added", "tcp", 80, ("v4",),
                   "ufw: 80/tcp ALLOW IN Anywhere"),
    _sample_change(9, 2, "08:14", "from outside", "prober", "unreachable", "tcp", 5432, ("v4",),
                   "no answer from 78.141.210.130", off=True),
    _sample_change(9, 2, "08:02", "provider firewall", "provider", "rule removed", "tcp", 5432, ("v4",),
                   "hetzner-fw-1: inbound 5432/tcp from 0.0.0.0/0", off=True),
    _sample_change(8, 31, "14:40", "container", "agent", "unpublished", "tcp", 8096, ("v4",),
                   "podman jellyfin, host port 8096", off=True),
    _sample_change(8, 31, "14:02", "container", "agent", "published", "tcp", 8096, ("v4",),
                   "podman jellyfin, host port 8096"),
    _sample_change(8, 29, "03:23", "from outside", "prober", "reachable", "tcp", 443, ("v4", "v6"),
                   "connected in 14 ms and 16 ms"),
    _sample_change(8, 29, "03:17", "provider firewall", "provider", "rule added", "tcp", 443, ("v4",),
                   "hetzner-fw-1: inbound 443/tcp from 0.0.0.0/0"),
]


def sample_host_view():
    """The demo host page. Its state, its header's facts and five of its tabs
    are drawn from one description of the server by the functions the live
    page draws them with (sample_story.py, docs/RECORD.md 4.443). They were
    rows written by hand, tab by tab, and the tabs told two stories. Changes
    and Settings are still the invented rows above."""
    # Asked for here and not at the top: sample_story draws with render_live,
    # which is built on this module.
    import sample_story
    story = sample_story.parts()
    # Three headings left on 2026-08-24, the owner's second declutter round: each
    # one restated the label of the tab it sat under.
    tabs = [
        ("overview", "Overview", story.overview),
        ("services", "Services", story.services),
        # A planned tab's body is not built - the tuple is the one switch,
        # which is also what lets the tests build the full sample with it
        # emptied and keep proving the two renderers work.
        ("rules", "Rules",
         "" if "rules" in HOST_TABS_PLANNED else story.rules),
        ("evidence", "Evidence", story.evidence),
        ("path", "Packet path",
         "" if "path" in HOST_TABS_PLANNED else story.path),
        ("changes", "Changes", changes_table_html("host", SAMPLE_CHANGES, SAMPLE_NOW)),
        ("settings", "Settings", sample_settings_tab()),
    ]
    facts = host_facts_html("agent", story.facts)
    first_look_rows, answering = story.first_look
    return f"""<div class="wrap view" id="host">
  <button class="back" data-v="fleet">&larr; Fleet</button>
  <div class="hh">
    {host_head('<span class="hname" id="host-name">app-01</span>',
               theme.status(*story.word) + muted_flag("host", False),
               "", facts)}
    <div class="acts">
      {mute_menu_html("host", live=False)}
      {scan_button("host", live=False)}
    </div>
  </div>
{host_tabs_html("host", tabs)}
{first_look_modal("host", "app-01", first_look_rows, answering, live=False, first=False)}
</div>"""


# The sample fleet is the approved sketch's twelve rows (docs/screens/fleet,
# decided 2026-09-03), one server for every state the fleet can show, so each
# case can be looked at. Every server, port and number here is made up so
# that the state has a row, and so is every tag and the one display name.
FLEET_SAMPLE = [
    # The one server the sample has a page for. Its Reachable and Needs a
    # decision cells are not written here: sample_fleet_rows takes them from
    # the one description of that server, so the Fleet and the server's own
    # page count the same ports (docs/RECORD.md 4.443).
    FleetRow("fail", "conflict", "app-01", hostname="ubuntu-app-01",
             tags=("production",)),
    FleetRow("fail", "not readable", "build-02", tags=("staging",), unread=True),
    # Three ports answer and nobody has answered for any of them. The row
    # read 1 of 5 beside its three chips (docs/RECORD.md 4.453).
    FleetRow("warn", "unreviewed", "web-02", reach=(3, 5),
             chips=(("tcp/22", "warn"), ("tcp/80", "warn"), ("tcp/443", "warn"))),
    FleetRow("warn", "unreviewed", "media-01", reach=(1, 7),
             chips=(("tcp/8096", "warn"),)),
    FleetRow("warn", "unexplained", "db-01", reach=(1, 4),
             chips=(("tcp/5432 v6", "warn"),), tags=("production", "database"),
             display="Postgres"),
    FleetRow("warn", "silent 3h 12m", "backup-03", reach=(0, 5)),
    FleetRow("warn", "no proof", "mail-relay"),
    FleetRow("off", "paused", "lab-04", reach=(1, 3), muted=True),
    FleetRow("off", "not watched", "edge-05", reach=(0, 2)),
    FleetRow("off", "not watched", "new-a1b2c3", pending=True),
    FleetRow("ok", "watched", "office-06", reach=(2, 2),
             tags=("office",)),
    FleetRow("ok", "watched", "store-07", reach=(1, 5)),
]
# The sample has no recorded transitions behind it, so the fourth box's number
# is invented like the rows, and said so here.
FLEET_SAMPLE_CHANGED = 2


def sample_fleet_rows():
    """The sample fleet's rows, with the two cells of the server that has a
    page taken from that server's one description (sample_story.py)."""
    # Asked for here and not at the top, as in sample_host_view.
    import sample_story
    reach, chips = sample_story.parts().fleet
    return [dataclasses.replace(row, reach=reach, chips=chips) if row.name == "app-01" else row
            for row in FLEET_SAMPLE]
# The banner the sketch shows. A live page has no source for one yet and draws
# none, so this is the only place the shape can be looked at.
FLEET_SAMPLE_NOTES = [
    ("fail", "channel:sysadmin@example.org",
     "Alert mail to <b>sysadmin@example.org</b> was refused by the relay.",
     "Open channel", "alerts"),
]


def build_sample():
    """The clickable shell, invented data, unchanged behaviour."""
    # Sorted here rather than in FLEET_SAMPLE, so the sample shell and a live
    # page cannot disagree about what order a fleet comes in.
    rows = sort_fleet_rows(sample_fleet_rows())
    acts = f'{button("Add server", "pri js-act", data_msg="The add-server flow would open here")}'
    views = fleet_view(fleet_notes_html(FLEET_SAMPLE_NOTES),
                       fleet_strip_html(fleet_totals(rows, FLEET_SAMPLE_CHANGED)),
                       fleet_rows_html(rows), acts, removed_list_html(()))
    views += sample_host_view()
    # One button in the header since 2026-08-23. The page-level Send test went
    # with the per-channel one arriving in every row's menu (the owner wanted the
    # test per channel and the big button gone), and it
    # was the weaker control anyway: it could not say which channel it had
    # tested.
    views += alerts_view(SAMPLE_OPEN, SAMPLE_SENT, SAMPLE_ALERTS_NOW, live=False)
    open_count = alerts_needing_you(SAMPLE_OPEN)
    # The button and the place a configured integration appears, and nothing
    # else (the owner, 2026-08-16). The catalogue that used to fill this view is in
    # the Add window. The subtitle went with it: it promised that we
    # feed the monitoring you already have, in the present tense, and none of it
    # is built.
    views += integrations_view(SAMPLE_PROVIDERS, sample_channel_rows_html(),
                               bool(SAMPLE_CHANNEL_ROWS), live=False)
    views += account_settings_view(live=False, **SAMPLE_ACCOUNT)
    # The Feedback window as a stub, like the shell's other controls: it
    # says what it would do and asks no server.
    return page(NAV, views, open_count=open_count, sample=True,
                feedback_html=feedback_button_html(),
                modal_html=add_modal()
                + provider_token_modal()
                + password_modal() + two_factor_modal()
                + remove_modal() + delete_modal() + address_modal()
                + feedback_modal("app.whichports.com", "unknown", live=False))


def write_dist(html, dist=DIST):
    dist.mkdir(exist_ok=True)
    (dist / "index.html").write_text(html)
    fonts_out = dist / "fonts"
    fonts_out.mkdir(exist_ok=True)
    for f in theme.FONT_DIR.glob("*.woff2"):
        shutil.copy2(f, fonts_out / f.name)
    shutil.copy2(theme.FONT_DIR / "OFL.txt", fonts_out / "OFL.txt")
    theme.write_icons(dist)
    (dist / "robots.txt").write_text("User-agent: *\nDisallow: /\n")
    print("wrote", dist / "index.html", len(html), "bytes")


if __name__ == "__main__":
    write_dist(build_sample())
