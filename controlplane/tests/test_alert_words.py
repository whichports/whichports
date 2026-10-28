"""What an alert message says, held to its spec
(docs/screens/mails/SPEC-alert-messages.md).

Every alert is one description: a title, labelled values, a closing line
and one button. These tests hold that description. How each channel draws
it is in test_alert_shapes.py.

Nothing here opens a database or a socket: a change is given as the values
that were frozen with it.
"""
import re

import pytest

from app import alertwords, join, notify

SERVER = "web-07"


def change(port=8410, family="v4", now=join.STATE_CONFLICT, answers=True,
           protocol="tcp", **more):
    """One changed finding, as the values frozen with it."""
    return notify.Change(
        where=f"{protocol}/{port} on {family}", was="", now=now, description="",
        port=port, protocol=protocol, family=family, answers=answers, **more)


def said(*changes, display=""):
    return alertwords.said_changes(SERVER, list(changes), display)


def fields(message):
    return dict(message.fields)


def labels(message):
    return [label for label, _ in message.fields]


def every_kind():
    """One message of every kind the product sends, by a name for the test
    output."""
    return {
        "marked closed": said(change(allowed_by=join.LAYER_HOST_FIREWALL,
                                     program_said="nginx")),
        "nobody answered": said(change(now=join.STATE_UNREVIEWED, program_said="nginx")),
        "outside its rule's source": said(change(
            now=join.STATE_UNREVIEWED, outside_source=True,
            program_said="container web")),
        "nothing owns it": said(change(now=join.STATE_UNEXPLAINED)),
        "a yes does not answer": said(change(port=25, answers=False, program_said="postfix")),
        "became reachable, a rule": said(change(
            port=3000, now=join.STATE_INTENDED, became_reachable=True,
            rule="in tcp 3000 at the provider",
            allowed_by=join.LAYER_PROVIDER, program_said="porttest-a")),
        "became reachable, a yes": said(change(
            port=3000, now=join.STATE_INTENDED, became_reachable=True,
            program_said="porttest-a")),
        "different program": said(change(
            port=3000, now=join.STATE_INTENDED, was_program="porttest-a",
            program_said="porttest-b", was_program_said="porttest-a")),
        "several ports": said(change(port=8410), change(port=8025),
                              change(port=25, answers=False)),
        "stopped reporting": alertwords.said_silence(SERVER, 41),
        "outside view stale": alertwords.said_outside_stale(SERVER, 7),
        "test": alertwords.said_test(),
    }


# ------------------------------------------------------------- the shape

def test_every_kind_is_a_title_its_fields_a_closing_line_and_one_button():
    for name, message in every_kind().items():
        assert message.title, name
        assert message.button and message.link.startswith("https://"), name
        if name == "test":
            continue
        assert message.fields, name
        assert message.fields[0] == ("server", SERVER), name
        assert message.sentence == "", name
        assert message.closing.startswith("Nothing else will be sent about"), name


def test_every_label_is_from_the_fixed_list():
    assert len(alertwords.LABELS) == 13
    for name, message in every_kind().items():
        for label in labels(message):
            assert label in alertwords.LABELS, (name, label)


def test_no_message_carries_a_time_or_a_state_word():
    states = (join.STATE_CONFLICT, join.STATE_UNREVIEWED, join.STATE_UNEXPLAINED,
              join.STATE_INTENDED, join.STATE_STALE_RULE, join.STATE_NOT_REACHABLE)
    for name, message in every_kind().items():
        text = " ".join([message.title, message.sentence, message.closing]
                        + [f"{label} {value}" for label, value in message.fields])
        for state in states:
            assert state not in text, (name, state)
        assert not re.search(r"\d{4}-\d{2}-\d{2}|\d{2}:\d{2}|UTC|measured", text), name


def test_a_field_with_nothing_to_say_is_left_out():
    message = said(change())
    assert labels(message) == ["server", "port", "you said"]
    for _, value in message.fields:
        assert value and value not in ("-", "unknown", "none", "not named")


def test_the_test_message_has_no_fields():
    message = alertwords.said_test()
    assert message.title == "Test message"
    assert message.fields == ()
    # Send test is pressed on Integrations, where the destinations are
    # (docs/screens/alerts/SPEC-layout-b.md).
    assert message.sentence == "Sent from the Integrations screen."
    assert message.closing == ""
    assert message.button == "Open Integrations"
    assert message.link.endswith("/integrations")


def test_every_kind_but_the_test_keeps_its_closing_line():
    kinds = every_kind()
    port = "Nothing else will be sent about this port until it changes again."
    for name in ("marked closed", "nobody answered", "outside its rule's source",
                 "nothing owns it", "a yes does not answer", "became reachable, a rule",
                 "became reachable, a yes", "different program"):
        assert kinds[name].closing == port, name
    assert kinds["several ports"].closing == (
        "Nothing else will be sent about these ports until they change again.")
    assert kinds["stopped reporting"].closing == (
        "Nothing else will be sent about this server until it reports again.")
    assert kinds["outside view stale"].closing == (
        "Nothing else will be sent about this until checking resumes.")
    assert kinds["test"].closing == ""


def test_the_button_opens_the_server_by_the_name_it_is_found_by():
    message = said(change(), display="Web seven")
    assert message.button == "Open Web seven"
    assert message.link.endswith("/host/web-07")
    assert message.title == "Port 8410 on Web seven is reachable from the internet"


def test_a_server_with_a_display_name_is_said_by_both_names_in_its_field():
    # Two servers may carry one display name, so the field says which server.
    for message in (said(change(), display="Web seven"),
                    said(change(port=1), change(port=2), display="Web seven"),
                    alertwords.said_silence(SERVER, 41, "Web seven"),
                    alertwords.said_outside_stale(SERVER, 7, "Web seven")):
        assert message.fields[0] == ("server", "Web seven (web-07)")
        assert "Web seven" in message.title and SERVER not in message.title
    # Without one, and with one that is the same word, the one name is said once.
    for display in ("", SERVER):
        assert said(change(), display=display).fields[0] == ("server", SERVER)


# ------------------------------------------------------------ one port

def test_a_port_marked_closed_says_you_said_closed():
    message = said(change(allowed_by=join.LAYER_HOST_FIREWALL, program_said="nginx"))
    assert message.title == "Port 8410 on web-07 is reachable from the internet"
    assert message.fields == (
        ("server", "web-07"), ("port", "8410"), ("you said", "closed"),
        ("allowed by", "a rule in the server's firewall"), ("program", "nginx"))


def test_a_port_nobody_answered_for_says_nothing_yet():
    message = said(change(now=join.STATE_UNREVIEWED, program_said="nginx"))
    assert message.title == "Port 8410 on web-07 is reachable from the internet"
    assert message.fields == (
        ("server", "web-07"), ("port", "8410"), ("you said", "nothing yet"),
        ("program", "nginx"))


def test_a_port_you_said_yes_to_that_does_not_answer_says_you_said_reachable():
    message = said(change(port=25, answers=False, program_said="postfix"))
    assert message.title == "Port 25 on web-07 does not answer from the internet"
    assert message.fields == (
        ("server", "web-07"), ("port", "25"), ("you said", "reachable"),
        ("program", "postfix"))


def test_a_port_nothing_owns_says_none_seen_listening():
    message = said(change(now=join.STATE_UNEXPLAINED))
    assert message.fields == (
        ("server", "web-07"), ("port", "8410"), ("program", "none seen listening"))


def test_a_port_that_became_reachable_says_what_allowed_it():
    under_a_rule = said(change(port=3000, now=join.STATE_INTENDED, became_reachable=True,
                               rule="in tcp 3000 at the provider",
                               allowed_by=join.LAYER_PROVIDER, program_said="porttest-a"))
    assert under_a_rule.title == "Port 3000 on web-07 became reachable from the internet"
    assert under_a_rule.fields == (
        ("server", "web-07"), ("port", "3000"),
        ("allowed by", "a rule in your provider's firewall"), ("program", "porttest-a"))
    under_a_yes = said(change(port=3000, now=join.STATE_INTENDED, became_reachable=True,
                              program_said="porttest-a"))
    assert fields(under_a_yes)["allowed by"] == "your yes"


def test_a_yes_beside_a_rule_is_still_your_yes():
    # A declaration wins over a rule in the engine. The port was said yes
    # to, a rule permits it as well, and the yes is what answers for it.
    message = said(change(port=3000, now=join.STATE_INTENDED, became_reachable=True,
                          rule="", allowed_by=join.LAYER_HOST_FIREWALL))
    assert fields(message)["allowed by"] == "your yes"
    program = said(change(port=3000, now=join.STATE_INTENDED, was_program="a",
                          rule="", allowed_by=join.LAYER_HOST_FIREWALL))
    assert program.fields[-1] == ("your yes", "stays")


def test_a_rule_that_answered_before_its_layer_was_kept_names_no_layer():
    # A change stored before the layer was frozen: a rule answered, so
    # "your yes" would be false, and which firewall is not known.
    for more in ({"became_reachable": True}, {"was_program": "a"}):
        message = said(change(port=3000, now=join.STATE_INTENDED,
                              rule="tcp dport 3000 accept in ufw", **more))
        assert "allowed by" not in labels(message)
        assert "your yes" not in labels(message)
        assert "your yes" not in dict(message.fields).values()


def test_a_different_program_says_the_one_before_and_what_stays():
    under_a_yes = said(change(port=3000, now=join.STATE_INTENDED, was_program="porttest-a",
                              program_said="porttest-b", was_program_said="porttest-a"))
    assert under_a_yes.title == "A different program answers port 3000 on web-07"
    assert under_a_yes.fields == (
        ("server", "web-07"), ("port", "3000"), ("program", "porttest-b"),
        ("before", "porttest-a"), ("your yes", "stays"))
    under_a_rule = said(change(port=3000, now=join.STATE_INTENDED, was_program="porttest-a",
                               program_said="porttest-b", was_program_said="porttest-a",
                               rule="tcp dport 3000 accept in ufw",
                               allowed_by=join.LAYER_HOST_FIREWALL))
    assert labels(under_a_rule) == ["server", "port", "program", "before", "allowed by"]
    assert fields(under_a_rule)["allowed by"] == "a rule in the server's firewall"


def test_a_port_outside_its_rules_source_says_both_firewalls_and_no_address():
    message = said(change(now=join.STATE_UNREVIEWED, outside_source=True,
                          program_said="container web",
                          rule="ip saddr 203.0.113.0/24 tcp dport 8410 accept in ufw"))
    assert message.title == "Port 8410 on web-07 is reachable from the internet"
    assert message.fields == (
        ("server", "web-07"), ("port", "8410"),
        ("allowed by", "a rule in your provider's firewall"),
        ("server's firewall", "allows some addresses only"),
        ("program", "container web"))
    assert "203.0.113" not in str(message)


def test_a_change_that_carries_the_field_never_says_nobody_has_said():
    alone = said(change(now=join.STATE_UNREVIEWED, outside_source=True))
    among = said(change(now=join.STATE_UNREVIEWED, outside_source=True),
                 change(port=25, answers=False))
    for message in (alone, among):
        text = str(message).lower()
        assert "you said" not in labels(message)
        assert "nobody has said" not in text
        assert "nothing yet" not in text


# ------------------------------------------------------------- families

def test_one_family_that_stopped_while_the_other_answers_names_its_family():
    message = said(change(port=25, answers=False, other_family=alertwords.OTHER_ANSWERS))
    assert message.title == "Port 25 on web-07 does not answer from the internet over IPv4"
    six = said(change(port=25, family="v6", answers=False,
                      other_family=alertwords.OTHER_ANSWERS))
    assert six.title.endswith("over IPv6")


def test_one_family_that_stopped_with_the_other_not_measured_names_its_family():
    message = said(change(port=25, answers=False,
                          other_family=alertwords.OTHER_NOT_MEASURED))
    assert message.title == "Port 25 on web-07 does not answer from the internet over IPv4"


def test_a_port_with_one_family_says_no_family():
    for other in ("", alertwords.OTHER_DOES_NOT_ANSWER):
        message = said(change(port=25, answers=False, other_family=other))
        assert message.title == "Port 25 on web-07 does not answer from the internet"
    assert "IPv" not in said(change()).title


def test_both_families_saying_the_same_are_one_port():
    message = said(change(port=25, family="v4", answers=False,
                          other_family=alertwords.OTHER_DOES_NOT_ANSWER),
                   change(port=25, family="v6", answers=False,
                          other_family=alertwords.OTHER_DOES_NOT_ANSWER))
    assert message.title == "Port 25 on web-07 does not answer from the internet"
    assert fields(message)["port"] == "25"


def test_a_port_whose_families_differ_is_one_port_in_two_lists():
    message = said(change(port=25, family="v4", answers=False,
                          other_family=alertwords.OTHER_ANSWERS),
                   change(port=25, family="v6", now=join.STATE_UNREVIEWED))
    assert message.title == "1 port changed on web-07"
    assert message.fields == (
        ("server", "web-07"), ("reachable", "25"),
        ("stopped answering", "25 over IPv4"))


# -------------------------------------------------------- several ports

def test_several_ports_are_listed_under_what_happened_to_them():
    message = said(
        change(port=8410), change(port=8025, now=join.STATE_UNREVIEWED),
        change(port=9000, now=join.STATE_UNEXPLAINED),
        change(port=3000, now=join.STATE_INTENDED, became_reachable=True),
        change(port=25, answers=False), change(port=587, answers=False),
        change(port=5432, now=join.STATE_INTENDED, was_program="postgres",
               program_said="container db", was_program_said="postgres"))
    assert message.title == "7 ports changed on web-07"
    assert message.fields == (
        ("server", "web-07"),
        ("reachable", "3000, 8025, 8410, 9000"),
        ("stopped answering", "25, 587"),
        ("different program", "5432"))
    assert message.closing == (
        "Nothing else will be sent about these ports until they change again.")


def test_a_list_holds_five_ports_and_says_how_many_more():
    message = said(*[change(port=port) for port in (8001, 8002, 8003, 8004, 8005,
                                                    8006, 8007, 8008)])
    assert message.title == "8 ports changed on web-07"
    assert fields(message)["reachable"] == "8001, 8002, 8003, 8004, 8005 and 3 more"
    six = said(*[change(port=port) for port in (1, 2, 3, 4, 5, 6)])
    assert fields(six)["reachable"] == "1, 2, 3, 4, 5 and 1 more"
    five = said(*[change(port=port) for port in (1, 2, 3, 4, 5)])
    assert fields(five)["reachable"] == "1, 2, 3, 4, 5"


def test_an_empty_list_is_left_out_with_its_label():
    message = said(change(port=8410), change(port=8025))
    assert labels(message) == ["server", "reachable"]
    stopped = said(change(port=25, answers=False), change(port=587, answers=False))
    assert labels(stopped) == ["server", "stopped answering"]


def test_the_title_and_the_rest_count_ports():
    # Eight ports, each changed in both families: sixteen changes, eight ports.
    changes = []
    for port in range(8001, 8009):
        changes += [change(port=port, family="v4"), change(port=port, family="v6")]
    message = said(*changes)
    assert message.title == "8 ports changed on web-07"
    assert fields(message)["reachable"] == "8001, 8002, 8003, 8004, 8005 and 3 more"


def test_a_port_that_is_not_tcp_says_its_protocol():
    message = said(change(port=53, now=join.STATE_UNEXPLAINED, protocol="udp"))
    assert fields(message)["port"] == "53/udp"


# ------------------------------------------------------------ the cause

def test_no_message_names_what_stopped_a_packet():
    # Whatever was frozen beside a port that does not answer, no layer is said.
    for layer in (join.LAYER_PROVIDER, join.LAYER_HOST_FIREWALL, join.LAYER_SERVICE,
                  join.LAYER_NOT_DETERMINED):
        message = said(change(port=25, answers=False, allowed_by=layer))
        assert "allowed by" not in labels(message)
        assert "firewall" not in str(message)


def test_an_unexplained_port_has_no_allowed_by():
    message = said(change(now=join.STATE_UNEXPLAINED, allowed_by=join.LAYER_PROVIDER))
    assert "allowed by" not in labels(message)


def test_a_conflict_with_no_permitting_rule_has_no_allowed_by():
    for layer in ("", join.LAYER_SERVICE, join.LAYER_NOT_DETERMINED, "something new"):
        message = said(change(allowed_by=layer))
        assert "allowed by" not in labels(message), layer


# ------------------------------------------------------- a program's name

def test_a_program_name_that_is_not_plain_is_left_out():
    for name in ("python3.12", "my app", "a/b", "x:y", "nginx<script>", "a+b", "café",
                 "", "a`b", "a*b", "[x](http://a.b)"):
        assert alertwords.program_words([name]) == "", name
    for name in ("nginx", "porttest-a", "postgresql@15-main", "Xorg", "a1"):
        assert alertwords.program_words([name]) == name


def test_a_name_that_starts_with_a_mark_is_never_plain():
    # "@" is earned by units such as postgresql@15-main, where it sits
    # inside the name. At the front it is how a chat reads a mention.
    for name in ("@everyone", "@here", "@admin", "-rf", "--help"):
        assert alertwords.program_words([name]) == "", name
    for name in ("_private", "-web", "@web"):
        assert alertwords.program_words([name], container=True) == "", name
    assert alertwords.program_words(["getty@tty1"]) == "getty@tty1"
    assert alertwords.program_words(["9front"]) == "9front"


def test_a_name_with_a_scheme_a_bare_domain_or_a_dot_is_never_plain():
    for name in ("http://b.c", "https://evil.example", "evil.io", "www.evil.io", "a.b"):
        assert alertwords.program_words([name]) == "", name
        assert alertwords.program_words([name], container=True) == "", name


def test_a_containers_name_with_a_hyphen_is_said_after_our_word():
    assert alertwords.program_words(["whichports-caddy-1"], container=True) == (
        "container whichports-caddy-1")


def test_a_containers_name_with_an_underscore_is_said():
    assert alertwords.program_words(["quirky_hopper"], container=True) == (
        "container quirky_hopper")
    assert alertwords.program_words(["my_project_web_1"], container=True) == (
        "container my_project_web_1")


def test_a_containers_name_with_a_dot_is_left_out_and_the_field_with_it():
    assert alertwords.program_words(["app.v2"], container=True) == ""
    message = said(change(now=join.STATE_UNREVIEWED,
                          program_said=alertwords.program_words(["app.v2"], container=True)))
    assert "program" not in labels(message)


def test_a_units_name_with_an_underscore_is_left_out():
    assert alertwords.program_words(["my_unit"]) == ""
    # And @, which a unit earns, is not a container's.
    assert alertwords.program_words(["web@1"], container=True) == ""


def test_a_process_that_calls_itself_container_is_not_said():
    assert alertwords.program_words(["container web"]) == ""
    assert alertwords.program_words(["container web"], container=True) == ""


def test_two_programs_are_said_only_when_every_name_is_plain():
    assert alertwords.program_words(["nginx", "sshd"]) == "nginx, sshd"
    assert alertwords.program_words(["web", "db_1"], container=True) == (
        "container web, container db_1")
    assert alertwords.program_words(["nginx", "python3.12"]) == ""
    assert alertwords.program_words(["web", "app.v2"], container=True) == ""
    assert alertwords.program_words([]) == ""


def test_a_program_said_that_is_empty_leaves_the_field_out():
    message = said(change(now=join.STATE_UNREVIEWED, program="python3.12", program_said=""))
    assert "program" not in labels(message)
    assert "python3.12" not in str(message)


# --------------------------------------------- an agent, the outside view

def test_an_agent_that_stopped_reporting_says_for_how_long():
    message = alertwords.said_silence(SERVER, 41)
    assert message.title == "web-07 stopped reporting"
    assert message.fields == (("server", "web-07"), ("no report for", "41 minutes"))
    assert alertwords.said_silence(SERVER, 1).fields[1] == ("no report for", "1 minute")
    # A length that could not be read back leaves the field out.
    assert alertwords.said_silence(SERVER, None).fields == (("server", "web-07"),)


def test_an_outside_view_gone_stale_says_for_how_long():
    message = alertwords.said_outside_stale(SERVER, 7)
    assert message.title == "web-07 is no longer checked from outside"
    assert message.fields == (("server", "web-07"), ("no check for", "7 hours"))
    assert alertwords.said_outside_stale(SERVER, 1).fields[1] == ("no check for", "1 hour")
    assert alertwords.said_outside_stale(SERVER, None).fields == (("server", "web-07"),)


def test_a_message_about_no_change_is_refused():
    with pytest.raises(ValueError):
        alertwords.said_changes(SERVER, [], "")
