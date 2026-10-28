"""The screens chosen across the 2026-08 UI rounds, as built.

    Run from site/app: python3 -m pytest test_screens.py

Its own file on purpose. Three branches in a row appended to `test_fleet.py`
and the third one hit a merge conflict in it, so a round that adds a screen adds
its tests here instead of at the end of a file everything else is also growing.

What each screen was chosen from is in `docs/RECORD.md` 4.64 to 4.71, and the
drawings are in `site/explorations/fleet-2026-08`.
"""
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import build
import theme
import app.packetpath as pp  # noqa: E402











# ---------------------------- the rate-limit flag beside the state
# docs/DESIGN.md section 3: a rate limit is a flag beside the state, never a
# second state. The treatment is the `.tag-planned` shape retoned to neutral.



def test_the_rate_flag_is_neutral_and_never_takes_a_status_tone():
    """docs/DESIGN.md section 3: neutral, never `warn`. Borrowing a status tone
    would smuggle blame in through a border colour, and PRODUCT.md 8c says a
    rate limit is blamed for nothing."""
    flag = build.rate_flag(True)
    assert flag == '<span class="tag-rate" title="rate limited">rate limited</span>'
    for tone in ("warn", "fail", "ok", "off"):
        assert f"st {tone}" not in flag
        assert f"tok {tone}" not in flag






def test_the_flag_is_smaller_than_the_status_tag():
    """docs/DESIGN.md section 3: the flag is smaller than the status tag. At
    the status tag's own box the pair read as two states stacked, which is the
    second-state reading RECORD 4.81 rules out. The word itself stays at the
    scale's smallest step, so the step-down is the box and the tracking."""
    assert (".tag-rate,.tag-rvw,.tag-mute,.tag-mode,.tag-disagree"
            "{letter-spacing:.08em;padding:1px 6px}") in theme.BASE
    # the shared shape stays: the step-down adds to it, never replaces it
    assert ".tag-planned,.tag-rate,.tag-rvw,.tag-mute" in theme.BASE




def test_the_matrix_together_cell_stacks_the_same_way():
    """Same fix on the Evidence matrix, on the column's right edge because the
    Together column is right aligned."""
    assert (".mr .mst{display:flex;flex-direction:column;"
            "align-items:flex-end;gap:4px}") in build.CSS
    assert ".mr .mst .tag-rate{margin-left:0}" in build.CSS


# ------------------------------------------- Rules, annotated raw, the gutter
# Chosen 2026-08-19, design 1, the annotated raw (docs/RECORD.md 4.71).

def test_who_wrote_a_rule_is_worked_out_from_the_chain_and_nothing_else():
    """It is the one attribution the document already supports without new
    collection. A chain nobody recognises gets no chip, because an attribution
    we cannot make is one we do not make."""
    assert build.rule_author("DOCKER") == "docker"
    assert build.rule_author("DOCKER-USER") == "docker"
    assert build.rule_author("ufw-user-input") == "ufw"
    assert build.rule_author("INPUT") == ""
    assert build.rule_author("") == ""
    assert build.rule_author(None) == ""


def test_what_we_know_goes_beside_the_quote_and_never_into_it():
    """Design 1's whole argument: our labels can be wrong without making the
    ruleset wrong, and a reader who trusts none of them still has the file."""
    row = build.rule_rows_html([("-A DOCKER -j RETURN", "", "")], author="docker")
    text = row.split('<div class="rule-t">')[1].split("</div>")[0]
    assert text == "-A DOCKER -j RETURN", "a label was woven into the rule text"
    assert 'class="gt wrote">docker' in row


def test_the_grade_keeps_its_own_word():
    """It names which grade, partial or none. A chip saying only `not fully
    readable` would flatten the two, and RECORD 4.18 is behind that field."""
    row = build.rule_rows_html([("x", "", "partial")], author="docker")
    assert "rendered: partial" in row
    row_none = build.rule_rows_html([("x", "", "none")])
    assert "rendered: none" in row_none


def test_a_rule_with_nothing_to_say_gets_an_empty_gutter():
    """The gutter is a column of the row now, so it is always there and the
    question is whether anything is in it. A rule with no author, no readable
    port and no grade earns no chip, because an attribution we cannot make is
    one we do not make."""
    row = build.rule_rows_html([("-A INPUT -j ACCEPT", "", "")])
    assert '<div class="rule-gutter"></div>' in row
    assert "gt " not in row


# ------------------------------------------------ Rules, the annotated raw
# Design 1 of the Rules round, the annotated raw, chosen 2026-08-19
# (docs/RECORD.md 4.71). The rule text is left exactly as it arrives and everything we
# know goes in the gutter beside it, never woven into it.

def test_a_conf_file_is_one_line_of_fields_in_the_files_own_form():
    """The treatment the chosen artboard used. It was a four-column grid, which
    the round left in place and which broke on a real host."""
    line = build.conf_line_html([("ENABLED", "yes"), ("LOGLEVEL", "low")])
    assert 'class="cf-l">what you configured</span>' in line
    assert '<span class="cf-f">ENABLED=yes</span>' in line
    assert '<span class="cf-f">LOGLEVEL=low</span>' in line


def test_an_empty_conf_value_is_shown_as_the_file_has_it():
    """`IPT_MODULES=` is empty in /etc/ufw/ufw.conf and reads that way here. A
    conf line is a quote the same way a rule is a quote, so nothing is
    substituted for the absence."""
    line = build.conf_line_html([("IPT_MODULES", "")])
    assert '<span class="cf-f">IPT_MODULES=</span>' in line


def test_a_long_field_is_never_split_down_the_middle():
    """The grid gave a key and its value 250 pixels between them, so
    DEFAULT_APPLICATION_POLICY pushed SKIP into wrapping as SKI over P on
    the owner's own host. A field is one unbreakable token now and the line wraps
    between fields."""
    line = build.conf_line_html([("DEFAULT_APPLICATION_POLICY", "SKIP")])
    assert '<span class="cf-f">DEFAULT_APPLICATION_POLICY=SKIP</span>' in line
    assert "white-space:nowrap" in build.CSS.split(".cf-f{")[1].split("}")[0]


def test_a_layer_with_no_conf_fields_draws_no_line():
    assert build.conf_line_html([]) == ""


def test_the_rule_text_and_what_we_know_are_two_columns():
    """The whole design. Our labels can be wrong without making the ruleset
    wrong, and a reader who trusts none of them still has the file."""
    row = build.rule_rows_html([("tcp dport 22 accept", "", "")], author="ufw")
    assert '<div class="rule-t">tcp dport 22 accept</div>' in row
    # nothing we know reached the quoted text
    text = row.split('class="rule-t">')[1].split("</div>")[0]
    assert "ufw" not in text and "tcp/22" not in text


def test_a_rule_that_names_a_port_says_which_in_the_gutter():
    row = build.rule_rows_html([("ip protocol tcp tcp dport 5432 accept", "", "")])
    assert '<span class="gt port">tcp/5432</span>' in row


def test_a_rule_that_names_no_port_gets_no_port_chip():
    row = build.rule_rows_html([("ct state established,related accept", "", "")])
    assert "gt port" not in row


def test_a_range_or_a_negation_never_reads_as_naming_one_port():
    """A rule matching `dport >= 1024` carries a port match and does not name a
    port. A chip saying it did would be a claim about one port that the rule
    does not make."""
    for text in ("ip protocol tcp tcp dport >= 1024 accept",
                 "ip protocol tcp tcp dport != 22 accept"):
        assert "gt port" not in build.rule_rows_html([(text, "", "")]), text


def test_a_rule_carrying_something_undecoded_is_labelled_not_dropped():
    """docs/PRODUCT.md: shown and labelled rather than read as naming nothing.
    A set lookup can select a port without the text ever saying which."""
    row = build.rule_rows_html([("tcp dport [lookup @sshguard] drop", "", "")])
    assert "not fully readable" in row
    assert "lookup @sshguard" in row, "the rule itself was dropped"
    assert "gt port" not in row


def test_the_rules_tab_and_the_packet_path_agree_about_one_rule():
    """Both read the same tokens through packetpath, so a rule cannot name a
    port on one tab and name nothing on the other."""
    text = "ip protocol tcp tcp dport 5432 accept"
    label, readable = build.rule_port_label(text, "")
    assert (label, readable) == ("tcp/5432", True)
    assert pp.classify_rule(text, "full", "tcp", 5432) == pp.NAMES_PORT
    assert pp.classify_rule(text, "full", "tcp", 22) == pp.OTHER_PORT


def test_a_ufw_tuple_is_read_as_the_agent_stores_it():
    """The line the way it reaches this page, which is the way the document
    holds it: `readUfwTuples` cuts the `### tuple ###` prefix before writing,
    so a real rule arrives as `allow tcp 443 ...` and nothing else.

    The first version of this read the marker to decide it was looking at a
    ufw line, and the test fed it a marker the product never produces, so it
    passed while every ufw rule on a real host went unlabelled. The owner found it
    on his own prod host.
    """
    row = build.rule_rows_html(
        [("allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in", "", "")], grammar=build.UFW)
    assert '<span class="gt port">tcp/443</span>' in row


def test_every_ufw_form_a_real_host_writes_is_read():
    """limit and allow, v4 and v6, and a source address that is not the
    wildcard. All four are on the owner's own prod host."""
    for line, want in (
            ("allow tcp 22 0.0.0.0/0 any 203.0.113.37 in", "tcp/22"),
            ("limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in", "tcp/22"),
            ("allow tcp 80 ::/0 any ::/0 in", "tcp/80"),
            ("allow udp 443 ::/0 any ::/0 in", "udp/443")):
        row = build.rule_rows_html([(line, "", "")], grammar=build.UFW)
        assert f'<span class="gt port">{want}</span>' in row, line


def test_a_ufw_tuple_this_cannot_read_without_guessing_gets_no_chip():
    """ufw also writes ranges, lists and the word `any`, and none of those
    names one port."""
    for line in ("allow tcp 80:90 0.0.0.0/0 any 0.0.0.0/0 in",
                 "allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 in",
                 "allow any 22 0.0.0.0/0 any 0.0.0.0/0 in",
                 "allow tcp"):
        row = build.rule_rows_html([(line, "", "")], grammar=build.UFW)
        assert "gt port" not in row, line


def test_a_ufw_line_is_never_read_by_the_kernel_reader():
    """The two grammars are not compatible and nothing sniffs. A ufw line
    handed to the kernel reader names no port, which is why the caller has to
    say which grammar it is holding."""
    line = "allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"
    assert build.rule_port_label(line, "", build.KERNEL)[0] == ""
    assert build.rule_port_label(line, "", build.UFW)[0] == "tcp/22"


def test_the_operators_own_comment_spans_the_row_and_is_named_as_theirs():
    row = build.rule_rows_html([("tcp dport 22 accept", "opened for the migration", "")])
    assert "your comment: opened for the migration" in row


def test_a_chain_header_leads_with_plain_words_and_keeps_its_real_name():
    group = build.rule_group_html("chain PREROUTING", "1 rule", [("x", "", "")],
                                  key="nat PREROUTING")
    assert '<span class="rgrp-p">address rewriting, on the way in</span>' in group
    assert '<span class="rgrp-n tech">chain PREROUTING</span>' in group


def test_a_chain_nobody_has_named_keeps_its_technical_name_alone():
    group = build.rule_group_html("chain WPTEST", "1 rule", [("x", "", "")],
                                  key="filter WPTEST")
    assert "rgrp-p" not in group
    assert '<span class="rgrp-n">chain WPTEST</span>' in group


def test_the_heading_counts_what_the_tab_actually_shows():
    groups = [("chain A", "", [("ip protocol tcp tcp dport 22 accept", "", ""),
                               ("ct state established accept", "", "")]),
              ("chain B", "", [("x", "", "partial")])]
    rules, chains, files, named, hazy = build.rules_counts(groups)
    assert (rules, chains, files, named, hazy) == (3, 2, 0, 1, 1)
    head = build.rules_header_html(rules, chains, files, named, hazy)
    assert "3 rules" in head and "2 chains" in head
    assert "1 names a port outright" in head


def test_a_rules_file_is_not_counted_as_a_chain():
    """A chain is in the kernel and a file is what somebody wrote. Calling one
    the other in the heading is this page misdescribing the host by a word."""
    groups = [("chain A", "", [("x", "", "")]),
              ("user.rules", "", [("y", "", "")], "file")]
    rules, chains, files, _named, _hazy = build.rules_counts(groups)
    assert (rules, chains, files) == (2, 1, 1)
    assert "1 chain and 1 rules file" in build.rules_header_html(rules, chains, files, 0, 0)


def test_a_host_with_no_rules_at_all_says_so_rather_than_showing_nothing():
    """An empty screen reads as one that failed to load. No firewall rules on a
    host is a finding."""
    head = build.rules_header_html(*build.rules_counts([]))
    assert "no firewall rules at all" in head


def test_the_chip_key_is_gone_from_the_template():
    """The legend under the Rules tab went with the 2026-08-23 declutter pass.
    The chips keep their words on every row, `rendered: partial` and `not fully
    readable` included, which the tests above pin. Only the paragraph that
    explained the chips is gone, constant and stylesheet rules with it."""
    assert not hasattr(build, "rules_key_html")
    assert ".rkey" not in build.CSS


# --------------------------------------------- the packet path, as gates
# Chosen 2026-08-19 out of four rail variants, the third, Gates, as the best
# for now (docs/RECORD.md 4.67).

def test_a_run_of_checkpoints_holding_nothing_becomes_one_block_with_its_count():
    """They are not dropped. The count is the fact that they were evaluated,
    which is what folding them away used to take (RECORD.md 4.49, 4.51)."""
    cells = [build.quiet_cell(3),
             build.gate_cell("input", "inet filter input", "1 rule",
                             rules=["tcp dport 22 accept"])]
    html = build.gates_walk_html("t", cells, "host-1")
    assert "3 quiet" in html
    assert html.count('class="gate q"') == 1
    assert "inet filter input" in html


def test_no_gate_states_an_outcome():
    """docs/PRODUCT.md 4g: the inside path says which chains a packet is
    evaluated against and quotes them. It never says what happened to it."""
    cells = [build.gate_cell("input", "inet filter input", "1 rule",
                             rules=["tcp dport 22 accept"]),
             build.fork_cell(),
             build.gate_cell("socket", "sshd", "1 holder", rules=["sshd 0.0.0.0:22"])]
    html = build.gates_walk_html("t", cells, "host-1")
    for verdict in ("allowed", "blocked", "reachable", "accepted", "permitted",
                    "arrives"):
        assert verdict not in html, f"a gate drew a conclusion: {verdict}"


def test_the_rail_is_never_empty_and_a_quiet_walk_still_draws():
    """The first Gates build returned nothing for a host whose checkpoints all
    held nothing, which took the walk off exactly the screen it was promised
    on. The rail always ends at the socket, so there is always something to
    draw."""
    cells = [build.quiet_cell(4), build.fork_cell(), build.quiet_cell(1),
             build.gate_cell("socket", "pveproxy", "1 holder",
                             rules=["pveproxy 0.0.0.0:8006"])]
    html = build.gates_walk_html("t", cells, "vpn-gateway")
    assert html != ""
    assert "4 quiet" in html and "the decision" in html
    assert "pveproxy" in html
    assert "a packet from outside" in html


def test_a_gate_opens_its_own_panel_and_only_one_at_a_time():
    """The radio mechanics: a none input checked by default, one input per
    gate, the close label pointing back at none. The positional CSS in
    walk_css does the showing."""
    cells = [build.gate_cell("input", "a", "1 rule", rules=["r1"]),
             build.gate_cell("socket", "b", "1 holder", rules=["r2"])]
    html = build.gates_walk_html("t", cells, "h")
    assert 'id="t-none" checked' in html
    assert 'for="t-1"' in html and 'for="t-2"' in html
    assert html.count('for="t-none"') == 2, "each panel closes back to none"
    assert html.count('class="pan"') == 2


def test_a_walk_past_the_gate_cap_stays_readable_without_panels():
    """The interaction CSS is positional and bounded, so a walk with more
    gates than it covers falls back to a plain rail rather than to gates that
    silently do nothing."""
    cells = [build.gate_cell("input", f"chain c{i}", "1 rule", rules=["r"])
             for i in range(build.GATE_CAP + 1)]
    html = build.gates_walk_html("t", cells, "h")
    assert "<label" not in html, "a gate past the cap rendered as clickable"
    assert 'class="pan"' not in html
    assert html.count('class="gate"') == build.GATE_CAP + 1


def test_a_checkpoint_name_out_of_a_document_renders_as_text():
    html = build.gates_walk_html(
        "t", [build.gate_cell("input", "<script>x</script>", "1 rule",
                              rules=["<script>y</script>"])], "<script>z</script>")
    assert "<script>" not in html
    assert html.count("&lt;script&gt;") >= 3


def test_the_kernel_vocabulary_is_still_the_kernel_vocabulary():
    """Deliberate, and open. The owner has called it too technical twice, in
    RECORD.md 4.67 and 4.71, and that decision is not pre-empted here: this
    builds the shape he chose. A plain-name pass is one lookup away."""
    html = build.gates_walk_html(
        "t", [build.gate_cell("prerouting", "nat PREROUTING", "1 rule",
                              rules=["-A DOCKER -j RETURN"])], "h")
    assert "nat PREROUTING" in html


def test_the_interaction_css_is_on_the_page_and_the_default_is_readable():
    """The first build of this rail appended walk_css below the __main__ block,
    so the shipped page had a picker over four invisible walks. The page must
    carry the machinery, and the first walk must be visible with none of it,
    so a missing rule fails to a readable page rather than an empty one."""
    assert ".pw>input.rr:nth-of-type(1):checked~.walks>.walk{display:none}" in build.CSS
    assert ".gw>input.rr:nth-of-type(2):checked~.pans>.pan:nth-child(1){display:block}" in build.CSS
    assert ".walks>.walk:first-child{display:block}" in build.CSS


def test_the_port_picker_shows_one_walk_and_falls_back_past_the_cap():
    """One chip per port, the first checked. Past the cap every walk stacks
    under its own heading, so a port can never be unreachable because a
    selector ran out of selectors."""
    html = build.walk_picker_html("p", ["tcp/22", "tcp/443"], ["w22", "w443"])
    assert 'id="p-1" checked' in html and 'id="p-2"' in html
    assert html.count('class="walk"') == 2
    many = build.walk_picker_html(
        "p", [f"tcp/{i}" for i in range(build.GATE_CAP + 1)],
        [f"w{i}" for i in range(build.GATE_CAP + 1)])
    assert "ppick" not in many
    assert many.count("<h2>") == build.GATE_CAP + 1


# The Alerts screen's own markup is covered in test_alerts_screen.py.


# The owner asked twice, on two different screens, for the chain names to be
# readable: once because he did not fully follow the routes himself (RECORD
# 4.67), and once because the names were still too technical and should be
# plainer (RECORD 4.71). Decided 2026-08-21: adopt the drawn fix, rl-1b.
def test_a_chain_leads_with_plain_words_and_keeps_its_technical_name():
    html = build.gates_walk_html(
        "t", [build.gate_cell("input", "inet filter input", "1 rule",
                              rules=["-A INPUT -j ACCEPT"])], "host")
    assert '<div class="gn">the host firewall</div>' in html
    # The technical name never goes away. It is what every other tool calls it
    # and what an operator greps their own ruleset for.
    assert '<div class="gn-t">inet filter input</div>' in html


# The honest half of the design: a chain nobody has written words for keeps its
# technical name alone. No guessing from how the chain is spelled, because
# these words are ours and can be wrong in a way a quoted rule cannot.
def test_an_unnamed_chain_is_not_given_invented_words():
    name = "filter SOMETHING-NOBODY-HAS-NAMED"
    html = build.gates_walk_html(
        "t", [build.gate_cell("input", name, "1 rule", rules=["-A X -j Y"])], "host")
    assert f'<div class="gn">{name}</div>' in html
    assert "gn-t" not in html
    assert build.plain_chain_name(name) == ""


# Every plain name must be for a chain, not a rule file or a socket, and none
# may be empty, because an empty one would silently render as unnamed.
def test_every_plain_name_is_a_non_empty_string():
    for technical, plain in build.PLAIN_CHAIN_NAMES.items():
        assert plain.strip(), f"{technical} maps to nothing"
        assert plain != technical, f"{technical} maps to itself"


# ------------------------------------------------------------- a view has an address
#
# The owner and his father, 2026-08-22: every screen lives at app.whichports.com
# and nothing else, they find it annoying and it should change. The concrete
# cost is that an alert mail can say "open the dashboard" and never "open
# tcp/1883 on mqtt-01", which is the one link somebody wants at two in the
# morning.

def test_the_page_carries_the_routing_it_needs():
    html = build.build_sample()
    for fn in ("function viewToPath(", "function pathToView(",
               "function applyPath(", "function goto("):
        assert fn in html, fn
    # back and forward move between views rather than doing nothing
    assert "addEventListener('popstate'" in html


def test_navigation_pushes_an_address_rather_than_only_switching():
    """Every nav item and every fleet row goes through goto, which is what
    puts the address in the bar. A caller left on setV would switch the view
    and leave the URL lying about where the reader is."""
    html = build.build_sample()
    assert "a.onclick=function(){goto(a.dataset.v)}" in html
    assert "goto('host-'+r.dataset.host)" in html


def test_a_host_tab_replaces_the_address_rather_than_pushing_it():
    """Seven tabs on one host would otherwise put seven entries in the
    history, and back would walk them instead of leaving the host."""
    html = build.build_sample()
    tab_handler = html.split("document.querySelectorAll('.tabsel')")[1][:400]
    assert "history.replaceState" in tab_handler
    assert "history.pushState" not in tab_handler


def test_a_deep_link_is_answered_by_something(tmp_path):
    """The bug this was written for. The Caddyfile fell back to
    /__spa-fallback.html and nothing has ever written a file of that name, so
    every deep link 404'd after the auth prompt. A fallback pointing at nothing
    fails only on the paths nobody clicks while testing.

    **The mechanism changed on 2026-08-23 and this test changed with it.** The
    dashboard block on the box stopped being a `file_server` with `try_files`
    and became a `reverse_proxy` to the control plane, because which page a
    browser may see comes from its session and Caddy holds no session. So a
    deep link is answered by a route in the app rather than by a fallback file,
    and asserting on `try_files` was asserting on an arrangement that had
    stopped existing.

    The question is the same one either way: **can a deep link be answered at
    all.** So this checks whichever mechanism the reference actually describes,
    and fails if it describes neither.
    """
    import re
    build.write_dist(build.build_sample(), dist=tmp_path)
    written = {path.name for path in tmp_path.iterdir()}

    # The Caddy configuration this tree has: the one for our own server where
    # it is present, the self-hosted one otherwise. Both proxy to the app.
    root = pathlib.Path(__file__).resolve().parents[2]
    present = [path for path in (root / "ops" / "caddyfile.reference",
                                 root / "selfhost" / "Caddyfile")
               if path.is_file()]
    assert present, "this tree has no Caddy configuration to read"
    reference = present[0].read_text()

    targets = re.findall(r"try_files [^\n]*?(/[\w.-]+)\s*$", reference, re.M)
    if targets:
        # Served from disk: every fallback has to name a file the builder
        # really writes.
        for target in targets:
            assert target.lstrip("/") in written, (
                f"the Caddyfile falls back to {target} and nothing writes a file of "
                f"that name, so every deep link 404s. Written: {sorted(written)}")
        return

    # Proxied instead: the app has to carry a route for the deep-link paths,
    # or they 404 behind the auth prompt exactly as they did before.
    # The self-hosted file names the port through a setting whose default is
    # the same number.
    assert re.search(r"reverse_proxy 127\.0\.0\.1:"
                     r"(8410|\{\$WHICHPORTS_INGEST_PORT:8410\})", reference), (
        "the dashboard is neither served from disk nor proxied, so nothing "
        "answers a deep link")
    web_auth = (pathlib.Path(__file__).resolve().parents[2]
                / "controlplane" / "app" / "web_auth.py").read_text()
    assert "DASHBOARD_PATHS" in web_auth, (
        "the dashboard is proxied to the app and the app names no dashboard "
        "paths, so a deep link has nothing to answer it")
    for path in ("/alerts", "/host/"):
        assert path in web_auth, f"no route for {path}, which a refresh lands on"


# -------------------------------------------- the mark for how a server is watched

def test_the_mode_mark_carries_the_word_and_nothing_else():
    assert build.mode_flag("partial read") == '<span class="tag-mode">partial read</span>'


def test_no_word_draws_no_mark():
    """A caller with nothing to say draws nothing. An empty box on a row would
    read as a fact that failed to render."""
    assert build.mode_flag("") == ""


def test_the_mode_mark_escapes_what_it_is_given():
    assert "&lt;b&gt;" in build.mode_flag("<b>")
    assert "<b>" not in build.mode_flag("<b>")


def test_the_mode_mark_takes_no_status_tone():
    """docs/DESIGN.md section 3. Which way a server is watched is not a
    problem, and a status colour on it would say one."""
    css = theme.BASE
    assert (".tag-planned,.tag-rate,.tag-rvw,.tag-mute,.tag-rec,.tag-mode,"
            ".tag-alert,.tag-disagree{") in css
    # Every mark that shares this shape shares its rule: neutral, never a
    # status tone. Read from the selector so a seventh added tomorrow is
    # covered the day it appears.
    for mark in ("mode", "rate", "rvw", "mute", "rec", "planned", "alert", "disagree"):
        for tone in ("ok", "warn", "fail", "off"):
            assert f".tag-{mark}.{tone}" not in css


def test_the_mode_mark_is_off_the_fleet_row():
    """Since the Fleet of 2026-09-03 the row says how a server is watched in
    its Agent column (build.AGENT_WORD), and the mark stays on the host page
    header only. A row carrying both would say one fact twice."""
    fleet = build.build_sample().split('id="fleet"', 1)[1].split('<div class="wrap view"', 1)[0]
    assert "tag-mode" not in fleet
    assert set(build.AGENT_WORD.values()) == set(build.AGENT_ICON)
