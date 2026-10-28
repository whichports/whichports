"""A refusal in the Add window, clicked and typed through in a real browser.

    Run from site/: python3 -m pytest app/test_add_refusal_browser.py

Found in a round of the test fleet (docs/RECORD.md 4.228): a bot token and a
chat id typed into each other's field were refused by one line at the foot of
the window, which named no field. test_add_refusal.py holds what the page is
sent with. This file holds what a person sees:

  - a refusal stands under the field it is about, each field of the step is
    checked and not only the first, and nothing typed is repeated in a line,
  - it is gone when its field is edited, when another channel or another kind
    is picked, and when the window is closed,
  - a refusal from the server, after the page's own check let the save
    through, stands at the field the server names, in the page's words,
  - no sentence the server wrote and no sentence of the browser's is ever
    printed in the window.

The server is a stand-in put in the page's own head, ahead of its script, so
the page's fetch wrapper wraps it as it wraps the real fetch (docs/RECORD.md
4.199). What the real server answers for the same requests is held by the
control plane's own tests, and each answer of the stand-in below is one of
those.
"""
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
from test_layout_b_browser import walk  # noqa: E402

# Made-up values in the shape each field takes. The token is the example in
# Telegram's own documentation and was never issued.
TOKEN = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
CHAT = "-1009876543210"
HOOK = "https://hooks.example.com/services/T0/B0/abc"
TYPED = (TOKEN, CHAT, HOOK, "hooks.example.com", "ABC-DEF1234")

TELEGRAM = build.CHANNEL_CHECKS["chan-telegram"]
TOKEN_SHAPE = TELEGRAM["dest"].says["shape"]
CHAT_SHAPE = TELEGRAM["chat"].says["shape"]
TOPIC_SHAPE = TELEGRAM["thread"].says["shape"]
WEBHOOK = build.CHANNEL_CHECKS["chan-webhook"]["dest"].says
NO_ANSWER = "No answer. Check your connection and try again."
# What to do, and no reason of ours after it. It read "Leave at least one
# kind switched on, or this destination can never send anything."
NO_KIND = "Switch on at least one kind."

# What the walks read off the page, put in front of their steps.
LOOKS = """
    var field=function(id){return d.getElementById(id)};
    // Typing: the value, then the event a keystroke fires, which is the one
    // the page listens to.
    var type=async function(id,value){var el=field(id);el.focus();el.value=value;
      el.dispatchEvent(new w.Event('input',{bubbles:true}));await tick()};
    // At each field that is drawn: the line under it, and whether the field
    // is marked as refused.
    var lines=function(){var out={};
      all('#conn-ovl input.m-input').filter(shown).forEach(function(el){
        var line=d.getElementById(el.getAttribute('aria-describedby')||'');
        out[el.id]={says:line&&shown(line)?text(line):'',
          marked:el.getAttribute('aria-invalid')==='true',
          // the line fits its box, and stands under its own field
          cut:!!line&&line.scrollWidth>line.clientWidth+1,
          under:!line||!shown(line)||line.getBoundingClientRect().top>=el.getBoundingClientRect().bottom}});
      return out};
    // Whether the line at the foot can be read where the window stands: it
    // is drawn, below the window's top and above the foot's buttons, which
    // stay put over whatever scrolls under them.
    var footSeen=function(){
      var line=d.getElementById('conn-err'), box=q('#conn-ovl .modal'), foot=q('#conn-ovl .m-foot');
      if(!shown(line)||!text(line))return false;
      var r=line.getBoundingClientRect();
      return r.top>=box.getBoundingClientRect().top&&r.bottom<=foot.getBoundingClientRect().top+1};
    var look=function(){return {open:win().classList.contains('on'),
      lines:lines(),
      foot:text(d.getElementById('conn-err')),
      footSeen:footSeen(),
      needs:q('#conn-ovl .modal').scrollHeight,has:q('#conn-ovl .modal').clientHeight,
      // every line of the window that says something, drawn or not, so a
      // refusal left behind in a step nobody is looking at is found too
      said:all('#conn-ovl .m-err').map(text).filter(function(t){return t}),
      marked:all('#conn-ovl [aria-invalid]').map(function(e){return e.id}),
      focus:d.activeElement?d.activeElement.id:'',
      // everything the window shows as words, and the toast
      words:win().innerText+' '+text(d.getElementById('toast')),
      toast:text(d.getElementById('toast')),
      go:d.getElementById('conn-go').disabled}};
"""


def says(look):
    """{field: its line} for the fields that show one."""
    return {name: line["says"] for name, line in look["lines"].items() if line["says"]}


def nothing_said(look):
    assert look["said"] == [] and look["marked"] == [] and look["foot"] == "", look


def repeats_nothing_typed(look):
    for value in TYPED:
        assert value not in look["words"], f"the window repeats {value!r}"


# ------------------------------------------------------- the page's own check

CHECKED = LOOKS + """
    await view('integrations');
    await open();await kind('dest');await card('chan-telegram');
    R.untouched=look();
    // The bot token and the chat id in each other's field.
    await type('chan-telegram-dest',%(chat)s);await type('chan-telegram-chat',%(token)s);
    await act();                                    R.swapped=look();R.swappedBox=spill();
    // The token's field edited: its line goes and the chat id's stays.
    await type('chan-telegram-dest','1');           R.edited=look();
    // Each field empty.
    await type('chan-telegram-dest','');await type('chan-telegram-chat','');
    await act();                                    R.empty=look();
    await type('chan-telegram-dest','   ');await type('chan-telegram-chat','  ');
    await act();                                    R.blank=look();
    // A URL where the token belongs, and the chat id right.
    await type('chan-telegram-dest',%(hook)s);await type('chan-telegram-chat',%(chat)s);
    await act();                                    R.url=look();
    // The token right, and only the topic wrong.
    await type('chan-telegram-dest',%(token)s);await type('chan-telegram-thread','general');
    await act();                                    R.topic=look();
    // Every kind switched off as well: the field and the kinds are both said.
    all('#conn-ovl .js-event').forEach(function(b){b.click()});
    await act();                                    R.kindsOff=look();
    // The topic put right and the kinds still off: the one refusal left is
    // about no field, on the step that is taller than the window.
    q('#conn-ovl .modal').scrollTop=0;
    await type('chan-telegram-thread','42');
    await act();                                    R.kindsOffAlone=look();
    all('#conn-ovl .js-event').forEach(function(b){b.click()});
    q('#conn-ovl .modal').scrollTop=0;
    await type('chan-telegram-thread','general');
    // Another channel chosen.
    await card('chan-email');                       R.otherCard=look();
    await act();                                    R.mailEmpty=look();
    await type('chan-email-dest','ops@');await act(); R.mailShape=look();
    await card('chan-webhook');await act();         R.hookEmpty=look();
    await type('chan-webhook-dest','hooks.example.com/x');await act(); R.hookShape=look();
    await card('chan-discord');await act();         R.discordEmpty=look();
    await type('chan-discord-dest',%(token)s);await act(); R.discordShape=look();
    // Another kind chosen.
    await kind('prov');                             R.otherKind=look();
    // The window closed with a refusal showing, by each way out, and opened again.
    await kind('dest');await card('chan-telegram');await act(); R.again=look();
    q('#conn-cancel').click();await tick();         R.cancelled=look();
    await open();                                   R.reopened=look();
    await kind('dest');await card('chan-telegram'); R.reopenedStep=look();
    await act();
    q('#conn-ovl .m-x').click();await tick();       R.crossed=look();
    await open();await kind('dest');await card('chan-telegram');await act();
    d.dispatchEvent(new w.KeyboardEvent('keydown',{key:'Escape',bubbles:true}));await tick();
    R.escaped=look();
    await open();await kind('dest');await card('chan-telegram');await act();
    win().dispatchEvent(new w.MouseEvent('click',{bubbles:true}));await tick();
    R.clickedAway=look();
    // An edit: its field is empty, and Save on it is refused at the field.
    await menu('ops','rm-edit');                    R.edit=look();
    await act();                                    R.editEmpty=look();
"""


@pytest.fixture(scope="module")
def checked(tmp_path_factory):
    return walk(tmp_path_factory.mktemp("checked"), CHECKED % {
        "token": json.dumps(TOKEN), "chat": json.dumps(CHAT), "hook": json.dumps(HOOK)})


def test_swapped_token_and_chat_id_are_each_refused_at_their_own_field(checked):
    """The mistake the finding is about."""
    nothing_said(checked["untouched"])
    swapped = checked["swapped"]
    assert swapped["open"]
    assert says(swapped) == {"chan-telegram-dest": TOKEN_SHAPE,
                             "chan-telegram-chat": CHAT_SHAPE}
    assert swapped["marked"] == ["chan-telegram-dest", "chan-telegram-chat"]
    # Nothing at the foot: each line is at its field and said once.
    assert swapped["foot"] == "" and len(swapped["said"]) == 2
    # The first field refused is where the cursor is put.
    assert swapped["focus"] == "chan-telegram-dest"
    repeats_nothing_typed(swapped)
    assert checked["posts"] == [], "a save the page refused was sent all the same"


def test_a_line_stands_under_its_field_and_fits(checked):
    for name in ("swapped", "empty", "topic", "hookShape"):
        for field, line in checked[name]["lines"].items():
            assert line["under"], f"{name}: the line of {field} is not under it"
            assert not line["cut"], f"{name}: the line of {field} is cut"
    box = checked["swappedBox"]
    assert box["page"] <= 0 and box["modalLeft"] >= 0 and box["modalRight"] >= 0


def test_a_refusal_goes_when_its_field_is_edited_and_only_that_one(checked):
    edited = checked["edited"]
    assert says(edited) == {"chan-telegram-chat": CHAT_SHAPE}
    assert edited["marked"] == ["chan-telegram-chat"]


def test_each_empty_field_is_refused_and_the_optional_one_is_not(checked):
    for name in ("empty", "blank"):
        assert says(checked[name]) == {
            "chan-telegram-dest": "Enter the Telegram bot token.",
            "chan-telegram-chat": "Enter the chat id."}, name
        assert checked[name]["foot"] == ""


def test_a_url_where_the_token_belongs_is_refused_at_the_token(checked):
    assert says(checked["url"]) == {"chan-telegram-dest": TOKEN_SHAPE}
    repeats_nothing_typed(checked["url"])


def test_a_topic_that_is_no_number_is_refused_at_the_topic(checked):
    assert says(checked["topic"]) == {"chan-telegram-thread": TOPIC_SHAPE}
    assert checked["topic"]["focus"] == "chan-telegram-thread"


def test_a_wrong_field_and_no_kind_are_both_said(checked):
    both = checked["kindsOff"]
    assert says(both) == {"chan-telegram-thread": TOPIC_SHAPE}
    assert both["foot"] == NO_KIND


def test_a_refusal_about_no_field_is_brought_into_view_on_a_tall_step(checked, served):
    """The Telegram step is taller than the window at 900 px high, and the
    line at the foot stands under the fold there. Measured on main: a
    refusal was said in that line and nobody could see it without
    scrolling. A refusal about a field is at its field, in view."""
    alone = checked["kindsOffAlone"]
    assert alone["needs"] > alone["has"], "the step fits now, so this holds nothing"
    assert alone["foot"] == NO_KIND
    assert says(alone) == {} and alone["footSeen"]
    assert served["noField"]["foot"] == "That did not work, HTTP 400"
    assert served["noField"]["footSeen"]
    # With a field refused as well the cursor is at the field, and the window
    # stays there.
    assert checked["kindsOff"]["focus"] == "chan-telegram-thread"


def test_every_channel_refuses_its_own_field_in_its_own_words(checked):
    assert says(checked["mailEmpty"]) == {"chan-email-dest": "Enter the recipient address."}
    assert says(checked["mailShape"]) == {
        "chan-email-dest": build.CHANNEL_CHECKS["chan-email"]["dest"].says["shape"]}
    assert says(checked["hookEmpty"]) == {"chan-webhook-dest": "Enter the webhook URL."}
    assert says(checked["hookShape"]) == {"chan-webhook-dest": WEBHOOK["shape"]}
    assert says(checked["discordEmpty"]) == {"chan-discord-dest": "Enter the Discord webhook URL."}
    assert says(checked["discordShape"]) == {
        "chan-discord-dest": build.CHANNEL_CHECKS["chan-discord"]["dest"].says["shape"]}
    for name in ("mailShape", "hookShape", "discordShape"):
        repeats_nothing_typed(checked[name])
        # One line, at the one field that shows: none of another channel's.
        assert len(checked[name]["said"]) == 1, name


def test_a_refusal_is_gone_when_another_channel_or_kind_is_picked(checked):
    assert says(checked["topic"]), "the walk had a refusal to lose"
    nothing_said(checked["otherCard"])
    assert says(checked["discordShape"])
    nothing_said(checked["otherKind"])


def test_a_refusal_is_gone_when_the_window_is_closed_and_opened_again(checked):
    """By Cancel, by the cross, by Escape and by a click beside the window.
    The line is gone with the window and not only by the time it is back."""
    assert says(checked["again"]) == {"chan-telegram-thread": TOPIC_SHAPE}
    for name in ("cancelled", "crossed", "escaped", "clickedAway"):
        assert not checked[name]["open"], name
        assert checked[name]["said"] == [] and checked[name]["marked"] == [], name
    nothing_said(checked["reopened"])
    nothing_said(checked["reopenedStep"])


def test_an_edit_opens_with_no_refusal_and_refuses_its_empty_field(checked):
    nothing_said(checked["edit"])
    assert says(checked["editEmpty"]) == {"chan-webhook-dest": "Enter the webhook URL."}
    assert checked["editEmpty"]["open"]


def test_nothing_the_page_refused_was_ever_sent(checked):
    assert checked["posts"] == []


# ---------------------------------------- the server refuses what the page let through

# Each answer is one the control plane gives (its tests hold them in
# test_channels_endpoint.py): the sentence under `detail`, and the field and
# the reason as two fixed words. The sentence here is a marker, so a line
# that printed it would be found.
SENTENCE = "a sentence of the server, with https://hooks.example.com/SECRET in it"

REFUSING = """<script>
window.__posts=[];
window.fetch=function(url,opts){
  url=String(url);
  if(!(opts&&opts.method==='POST'))return new Promise(function(){});
  var body=opts.body?JSON.parse(opts.body):{};
  window.__posts.push({url:url,body:body});
  var to=body.destination||'';
  var refuse=function(status,answer){return Promise.resolve({ok:false,status:status,
    json:function(){return answer===null?Promise.reject(new Error('not JSON')):Promise.resolve(answer)}})};
  var sentence=%(sentence)s;
  if(to.indexOf('//10.0.0.5/')>=0)return refuse(400,{detail:sentence,field:'destination',reason:'private'});
  if(to.indexOf('//127.0.0.1')>=0)return refuse(400,{detail:sentence,field:'destination',reason:'unsendable'});
  if(to.indexOf('/drift')>=0)return refuse(400,{detail:sentence,field:'destination',reason:'shape'});
  if(body.chat_id==='-100200:7')return refuse(400,{detail:sentence,field:'chat_id',reason:'shape'});
  if(body.chat_id==='-100300')return refuse(400,{detail:sentence,field:'',reason:'shape'});
  if(to.indexOf('/no-label-left')>=0)return refuse(400,{detail:sentence,field:'label',reason:'taken'});
  if(to.indexOf('/new-reason')>=0)return refuse(400,{detail:sentence,field:'destination',reason:'invented'});
  if(to.indexOf('/no-class')>=0)return refuse(400,{detail:sentence});
  if(to.indexOf('/odd-class')>=0)return refuse(400,{detail:sentence,field:['destination'],reason:{}});
  if(to.indexOf('/not-json')>=0)return refuse(502,null);
  if(to.indexOf('/no-answer')>=0)return Promise.reject(new TypeError('Failed to fetch'));
  return Promise.resolve({ok:true,status:201,json:function(){return Promise.resolve(
    {type:'webhook',label:'new one',destination:'hooks.example.com',events:[]})}});
};
</script>""" % {"sentence": json.dumps(SENTENCE)}

SERVED = LOOKS + """
    await view('integrations');
    await open();await kind('dest');await card('chan-webhook');
    var send=async function(value){await type('chan-webhook-dest',value);await act();return look()};
    R.private=await send('https://10.0.0.5/hook');
    // Edited after the server refused it: the line goes, as the page's own does.
    await type('chan-webhook-dest','https://10.0.0.5/hoo');  R.editedAfter=look();
    R.unsendable=await send('http://127.0.0.1:8065/hook');
    R.drift=await send(%(hook)s+'/drift');
    R.noLabelLeft=await send(%(hook)s+'/no-label-left');
    R.newReason=await send(%(hook)s+'/new-reason');
    R.noClass=await send(%(hook)s+'/no-class');
    R.oddClass=await send(%(hook)s+'/odd-class');
    R.notJson=await send(%(hook)s+'/not-json');
    R.noAnswer=await send(%(hook)s+'/no-answer');
    // The chat id, refused by the server after the page let it through.
    await card('chan-telegram');
    await type('chan-telegram-dest',%(token)s);await type('chan-telegram-chat','-100200');
    await type('chan-telegram-thread','7');
    await act();                                    R.chat=look();
    // A refusal that names no field, on the step whose topic has no name of
    // its own to answer to.
    await type('chan-telegram-chat','-100300');await type('chan-telegram-thread','');
    await act();                                    R.noField=look();
    // And a save the server takes.
    await card('chan-webhook');                     R.back=look();
    R.saved=await send(%(hook)s);
    R.fieldAfterSave=field('chan-webhook-dest').value;
"""


@pytest.fixture(scope="module")
def served(tmp_path_factory):
    return walk(tmp_path_factory.mktemp("served"), SERVED % {
        "token": json.dumps(TOKEN), "hook": json.dumps(HOOK)}, stub=REFUSING)


def test_a_refusal_from_the_server_stands_at_the_field_it_names(served):
    """After the page's own check let the save through. The words are the
    page's, for the reason the server gave."""
    for name, reason in (("private", "private"), ("unsendable", "unsendable"),
                         ("drift", "shape")):
        seen = served[name]
        assert seen["open"], name
        assert says(seen) == {"chan-webhook-dest": WEBHOOK[reason]}, name
        assert seen["marked"] == ["chan-webhook-dest"] and seen["foot"] == "", name
        assert seen["focus"] == "chan-webhook-dest", name
    assert says(served["chat"]) == {"chan-telegram-chat": CHAT_SHAPE}
    assert served["chat"]["open"] and served["chat"]["foot"] == ""


def test_a_servers_refusal_goes_when_its_field_is_edited(served):
    nothing_said(served["editedAfter"])


def test_an_answer_the_page_has_no_line_for_says_only_that_it_did_not_work(served):
    """A field the window does not ask for, a reason it has never heard of,
    an answer with no class at all or with something that is no word in
    their place, and an answer that is not JSON."""
    for name in ("noLabelLeft", "newReason", "noClass", "oddClass", "noField"):
        seen = served[name]
        assert seen["open"], name
        assert seen["foot"] == "That did not work, HTTP 400", name
        assert says(seen) == {} and seen["marked"] == [], name
    assert served["notJson"]["foot"] == "That did not work, HTTP 502"
    assert served["notJson"]["open"] and says(served["notJson"]) == {}


def test_no_answer_at_all_is_said_in_the_pages_words(served):
    seen = served["noAnswer"]
    assert seen["open"] and seen["foot"] == NO_ANSWER
    assert "Failed to fetch" not in seen["words"]


def test_no_sentence_of_the_server_and_nothing_typed_is_ever_printed(served):
    for name, seen in served.items():
        if not isinstance(seen, dict) or "words" not in seen:
            continue
        assert "sentence of the server" not in seen["words"], name
        assert "SECRET" not in seen["words"], name
        for value in ("10.0.0.5", "127.0.0.1", HOOK, TOKEN, "-100200", "-100300"):
            assert value not in seen["words"], f"{name} repeats {value!r}"


def test_the_action_is_never_left_switched_off_by_a_refusal(served):
    for name in ("private", "noLabelLeft", "notJson", "noAnswer", "chat"):
        assert served[name]["go"] is False, name


def test_each_save_the_page_let_through_was_asked_once(served):
    sent = [post["body"]["destination"] for post in served["posts"]]
    assert len(sent) == 12 and len(set(sent)) == 11
    assert served["posts"][-3]["body"] == {
        "type": "telegram", "destination": TOKEN, "chat_id": "-100200:7",
        "events": [kind for kind, _words in build.EVENT_KINDS]}


def test_a_save_the_server_takes_closes_the_window_and_empties_its_field(served):
    """What was typed is a webhook's address or a bot's token, so it is not
    left in the field for the next time the window opens."""
    nothing_said(served["back"])
    assert not served["saved"]["open"]
    assert served["saved"]["toast"] == "Destination added."
    assert served["fieldAfterSave"] == ""


# ------------------------------------------ what was typed, when the window closes

# Cancel and Escape are the two ways a person says no, so what was typed goes
# with them. The cross goes with Escape, which presses it. A click beside the
# window closes it too, and that one is a slip of the hand as often as not,
# so it keeps what was typed and a pasted address is not lost to it.
CLOSING = LOOKS + """
    await view('integrations');
    // Every field of every step that holds something, by its step and place.
    var holds=function(){var out={};all('#conn-ovl .m-stage[data-type]').forEach(function(stage){
      Array.prototype.forEach.call(stage.querySelectorAll('input'),function(el,i){
        if(el.value)out[stage.id+':'+i]=el.value})});return out};
    var typeInto=async function(el,value){el.focus();el.value=value;
      el.dispatchEvent(new w.Event('input',{bubbles:true}));await tick()};
    // A destination with three fields, another with one, and a provider's token.
    var fill=async function(){
      await open();await kind('dest');await card('chan-telegram');
      await type('chan-telegram-dest',%(token)s);await type('chan-telegram-chat',%(chat)s);
      await type('chan-telegram-thread','42');
      await card('chan-webhook');await type('chan-webhook-dest',%(hook)s);
      await kind('prov');await card('intg-hetzner');
      await typeInto(q('#intg-hetzner input'),'hzread-sample');
    };
    var shut=function(){return !win().classList.contains('on')};
    await fill();                                   R.filled=holds();
    q('#conn-cancel').click();await tick();         R.cancel={shut:shut(),holds:holds()};
    await fill();
    d.dispatchEvent(new w.KeyboardEvent('keydown',{key:'Escape',bubbles:true}));await tick();
    R.escape={shut:shut(),holds:holds()};
    await fill();
    q('#conn-ovl .m-x').click();await tick();       R.cross={shut:shut(),holds:holds()};
    await fill();
    win().dispatchEvent(new w.MouseEvent('click',{bubbles:true}));await tick();
    R.beside={shut:shut(),holds:holds()};
    // Opened again after the slip: what was typed is there, and no refusal is.
    await open();await kind('dest');await card('chan-webhook');
    R.back=look();R.backHolds=holds();
"""


@pytest.fixture(scope="module")
def closing(tmp_path_factory):
    return walk(tmp_path_factory.mktemp("closing"), CLOSING % {
        "token": json.dumps(TOKEN), "chat": json.dumps(CHAT), "hook": json.dumps(HOOK)})


FILLED = {"chan-telegram:0": TOKEN, "chan-telegram:1": CHAT, "chan-telegram:2": "42",
          "chan-webhook:0": HOOK, "intg-hetzner:0": "hzread-sample"}


def test_what_was_typed_is_emptied_on_cancel(closing):
    assert closing["filled"] == FILLED, "the walk typed into every step"
    assert closing["cancel"] == {"shut": True, "holds": {}}


def test_what_was_typed_is_emptied_on_escape(closing):
    assert closing["escape"] == {"shut": True, "holds": {}}


def test_the_cross_empties_what_was_typed_as_escape_does(closing):
    """Escape presses the cross, so the two cannot differ."""
    assert closing["cross"] == {"shut": True, "holds": {}}


def test_what_was_typed_is_kept_on_a_click_beside_the_window(closing):
    assert closing["beside"] == {"shut": True, "holds": FILLED}
    # And it stands in its field when the window is opened again, with no
    # refusal beside it.
    assert closing["backHolds"] == FILLED
    nothing_said(closing["back"])
    assert closing["posts"] == []


# ------------------------------------------------- a provider's token field

# The one refusal the page makes of a provider by itself, an empty token,
# stood at the foot of the window. It is under the token's field now, by the
# same rules as a destination's.
TOKEN_FIELD = "intg-hetzner-1"

PROVIDER = LOOKS + """
    await view('integrations');
    var typeInto=async function(el,value){el.focus();el.value=value;
      el.dispatchEvent(new w.Event('input',{bubbles:true}));await tick()};
    var token=function(){return q('#intg-hetzner input')};
    await open();await kind('prov');await card('intg-hetzner');
    R.untouched=look();
    await act();                                    R.empty=look();
    // One key in the field: the line goes.
    await typeInto(token(),'h');                    R.edited=look();
    // Nothing but spaces is nothing.
    await typeInto(token(),'   ');await act();      R.blank=look();
    // Another kind picked, and back.
    await kind('dest');                             R.otherKind=look();
    await kind('prov');await card('intg-hetzner');  R.back=look();
    await typeInto(token(),'');await act();         R.again=look();
    // Closed with the line showing, and opened again.
    win().dispatchEvent(new w.MouseEvent('click',{bubbles:true}));await tick();
    R.shut=look();
    await open();await kind('prov');await card('intg-hetzner');
    R.reopened=look();
    // And a token typed: the request the window always made.
    await typeInto(token(),'hzread-sample');await act();
    R.connected=look();
"""


@pytest.fixture(scope="module")
def provider(tmp_path_factory):
    return walk(tmp_path_factory.mktemp("provider"), PROVIDER)


def test_an_empty_token_is_refused_under_the_tokens_field(provider):
    nothing_said(provider["untouched"])
    for name in ("empty", "blank", "again"):
        seen = provider[name]
        assert seen["open"], name
        assert says(seen) == {TOKEN_FIELD: "Paste the read token."}, name
        assert seen["foot"] == "" and seen["said"] == ["Paste the read token."], name
        assert seen["marked"] == [TOKEN_FIELD] and seen["focus"] == TOKEN_FIELD, name
        line = seen["lines"][TOKEN_FIELD]
        assert line["under"] and not line["cut"], name


def test_the_tokens_refusal_goes_when_the_field_is_edited(provider):
    nothing_said(provider["edited"])


def test_the_tokens_refusal_goes_with_another_kind_and_with_the_window(provider):
    nothing_said(provider["otherKind"])
    nothing_said(provider["back"])
    assert not provider["shut"]["open"]
    assert provider["shut"]["said"] == [] and provider["shut"]["marked"] == []
    nothing_said(provider["reopened"])


def test_a_refused_token_asks_nothing_and_a_typed_one_connects(provider):
    assert provider["posts"] == [{"url": "/api/admin/integrations/hetzner",
                                  "body": {"token": "hzread-sample"}}]
    assert not provider["connected"]["open"]
    assert provider["connected"]["toast"] == "Connected"
