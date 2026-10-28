"""The HTML the control plane serves itself: the login page, and the second
step that asks for a code.

The dashboard is not here. It is rendered by `site/app/render_live.py` from
the database on every request, and `app/dashboard.py` owns that call. A login
form could never have been static anyway, because each render has to carry a
fresh CSRF token, so it was always built here.

**The palette, the type and the mark are not restated here.** `site/theme.py`
owns them (docs/DESIGN.md section 1 owns the values, theme.py is where they
become code) and this module loads that exact file. Copying the tokens into a
second place is how one fact drifts into two, and a login
page that is a shade off the dashboard is how it would show up.

Loading it is by file path rather than by import, for two reasons that are both
about names:

  - `site` is a standard library module. `import site.theme` would be a
    permanent trap for whoever reads it next.
  - `site/app/build.py` is a package called `app`, and so is this one. The two
    cannot both be importable in one interpreter, which is why
    `controlplane/app/alerts.py` repeats a constant instead of importing it.

Loading is also lazy, and that is deliberate. This module is imported by the
ingest, which is the process agents post to. A missing or unreadable theme.py
must break the login page and nothing else, never the ingest at import time.
"""

import html
import importlib.util
import pathlib
from urllib.parse import quote

from . import accounts

# Where site/theme.py sits, in the two layouts that exist. First hit wins.
_THEME_CANDIDATES = (
    # The production box: ops/deploy-controlplane.sh puts the package at
    # /srv/controlplane/app and theme.py at /srv/controlplane/site/theme.py.
    pathlib.Path(__file__).resolve().parent.parent / "site" / "theme.py",
    # This repository: controlplane/app/ and site/ are siblings under the root.
    pathlib.Path(__file__).resolve().parent.parent.parent / "site" / "theme.py",
)

_theme_module = None


def theme():
    """The design system, loaded once from site/theme.py.

    Raises FileNotFoundError when it is not on the box, which is the honest
    answer: the deploy copies it and a login page without it would be a
    different product's login page.
    """
    global _theme_module
    if _theme_module is not None:
        return _theme_module
    for path in _THEME_CANDIDATES:
        if not path.is_file():
            continue
        # A name of our own, so nothing collides with the standard library's
        # `site` or with either `app` package.
        spec = importlib.util.spec_from_file_location("whichports_theme", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _theme_module = module
        return module
    raise FileNotFoundError(
        "site/theme.py was not found in any of: "
        + ", ".join(str(p) for p in _THEME_CANDIDATES))


# **Every page here carries `<base href="/">` and it is load bearing.**
# `theme.fonts()` and `theme.ICON_LINKS` reference their files by relative path,
# which is right for the public site: the landing sits at `/` and the prober
# list at `/notes/`, and each ships its own copy beside it. The control plane serves
# pages at several depths from one place, so on `/login/2fa` a relative
# `fonts/X.woff2` asks for `/login/fonts/X.woff2`, which nothing serves, and the
# page silently falls back to a system font.
#
# The base element fixes every relative reference on the page at once rather
# than making theme.py absolute, which would break the notes page that depends
# on resolving per directory. Every form on these pages already posts to an
# absolute action, so nothing else moves.

# **No `required` attribute on any field here, deliberately.** The browser's
# own "Please fill in this field" bubble cannot be styled, matches nothing else
# on the page, and appears in a different place on every engine. The owner, seeing
# it, ruled the browser's own hint out for good. The server
# validates every one of these fields regardless and answers in the same
# message treatment as every other refusal, so removing the attribute costs a
# round trip and buys a page that looks like one product.

# The login page's own layout. Everything it uses below this line is a token
# from theme.TOKENS or a class from theme.BASE, so nothing here is a colour.
_CSS = """
body{display:flex;align-items:center;justify-content:center;padding:24px}
main{width:100%;max-width:380px}
.brand{display:flex;justify-content:center;margin-bottom:26px}
.card{padding:28px 26px 26px}
h1{font-size:19px;margin-bottom:18px;text-align:center}
.sub{color:var(--muted);font-size:13px;margin-bottom:22px}
label{display:block;font-size:11.5px;letter-spacing:.09em;text-transform:uppercase;
  color:var(--faint);margin-bottom:6px}
input{width:100%;font-family:inherit;font-size:14px;color:var(--ink);
  background:var(--panel2);border:1px solid var(--line2);border-radius:8px;
  padding:10px 12px;transition:border-color var(--quick) var(--ease)}
input:hover{border-color:var(--faint)}
.field{margin-bottom:16px}
button{width:100%;margin-top:6px}
.msg{display:flex;gap:9px;align-items:flex-start;font-size:13px;border-radius:8px;
  padding:9px 11px;margin-bottom:18px;border:1px solid var(--line2);
  background:var(--panel2);color:var(--muted)}
.msg em{font-style:normal;font-family:"IBM Plex Mono",monospace;font-size:9px;
  letter-spacing:.1em;border:1px solid var(--tone);color:var(--tone);border-radius:3px;
  padding:1px 5px;flex:0 0 auto;margin-top:2px}
.msg{--tone:var(--muted)}
.msg.fail{--tone:var(--fail);color:var(--fail);font-weight:600;
  border-color:var(--fail-soft)}
/* The closed-signups banner. Warn ink on the warn soft fill, the pairing
   docs/DESIGN.md section 1 defines and the site already uses for warn
   surfaces. Normal weight, because warn takes its colour and nothing else. */
.msg.closed{color:var(--warn);background:var(--warn-soft);
  border-color:var(--warn-soft)}
.foot{text-align:center;color:var(--faint);font-size:12px;margin-top:18px}
/* The code is six digits read off a phone, so it gets room and tracking
   rather than the ordinary field treatment. A recovery code goes in the same
   box, which is why the font is not fixed to tabular figures. */
input.code{font-family:"IBM Plex Mono",monospace;font-size:19px;letter-spacing:.22em;
  text-align:center;padding:12px}
/* theme.py styles .btn for a <button>. The one place a link wears it is the
   continue action after a recovery code, so it gets the block layout the
   button rule above gives its own element. */
a.btn{display:block;text-align:center;text-decoration:none;margin-top:6px}
/* The provider buttons sit BELOW the form and side by side, which is where a
   person who has used any other product expects them. They keep the plain
   button treatment rather than the primary one, so the page still has exactly
   one filled button and it is the action the form is about. */
.provs{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.provs.one{grid-template-columns:1fr}
a.btn.prov{margin-top:0;display:flex;align-items:center;justify-content:center;
  gap:8px;padding:9px 10px;font-size:13px}
a.btn.prov svg{width:16px;height:16px;flex:0 0 auto}
.or{display:flex;align-items:center;gap:10px;margin:20px 0 14px;
  color:var(--faint);font-size:11.5px;letter-spacing:.09em;text-transform:uppercase}
.or::before,.or::after{content:"";flex:1;height:1px;background:var(--line2)}
code{font-family:"IBM Plex Mono",monospace;font-size:12px;color:var(--ink)}
/* The password rule, under the field it applies to. */
.hint{color:var(--faint);font-size:11.5px;margin-top:6px;line-height:1.45}
/* The way to the other page. A full width outlined action rather than a small
   grey link, because signing up and signing in are the two things somebody
   arrives wanting and one of them should not be a footnote. */
.swap{margin-top:20px;padding-top:18px;border-top:1px solid var(--line)}
.swap .lead{color:var(--muted);font-size:12.5px;text-align:center;
  margin-bottom:10px}
.swap .sub-note{color:var(--faint);font-size:12px;margin-bottom:0;margin-top:10px}
/* theme.py already dims a disabled button. This only stops it taking
   the top margin the form's own submit button gets. */
.swap button.wide{width:100%;margin-top:0}
a.btn.wide{margin-top:0}
.foot{color:var(--faint)}
.foot a{color:var(--muted)}
/* Every button bold, the dashboard's own weight since 2026-09-08
   (site/theme.py) and the owner's first note on these screens. */
.btn{font-weight:600}
/* The one link under a card, and the "Forgot your password?" beside it. */
.foot a{text-decoration:none;border-bottom:1px solid var(--line2)}
.foot .sep{padding:0 6px}
/* A link went to an address. The sentence is quiet and the address is the
   fact, so it takes the mono treatment docs/DESIGN.md section 1 gives an
   address and the sentence stays muted. No badge above it: the owner, 2026-09-09. */
.sent{font-size:13px;color:var(--muted);margin:-4px 0 20px;text-align:center}
.sent b{font-family:"IBM Plex Mono",monospace;font-weight:500;color:var(--ink-str)}
/* A field that is shown and not asked for: the address a link decided. Dashed,
   the same treatment a planned control wears on the settings screens, because
   both mean "this is here to read, not to fill in". */
input.ro{color:var(--muted);background:var(--panel);border-style:dashed;cursor:default}
input.code::placeholder{color:var(--faint);letter-spacing:.35em}
/* The authenticator key, and the recovery codes. Both are copied by clicking
   the box, the way the install command on Add server is. */
/* The key wraps between its groups and never inside one: a group split
   across two lines is a key nobody can read back to a phone. */
.secret{font-family:"IBM Plex Mono",monospace;font-size:13px;color:var(--ink-str);
  text-align:center;line-height:1.9;margin:0 0 8px;word-break:normal;
  padding:12px 14px;background:var(--panel2);border:1px solid var(--line);
  border-radius:8px;cursor:pointer}
/* The QR has to be dark on light to scan, whatever theme the page is in, so
   it sits on its own white square rather than on the panel. */
.qr{display:flex;justify-content:center;margin:2px 0 14px}
.qr svg{width:168px;height:168px;background:#FFFFFF;border-radius:8px;
  padding:8px;box-sizing:border-box}
.codes{display:grid;grid-template-columns:1fr 1fr;gap:8px 16px;
  font-family:"IBM Plex Mono",monospace;font-size:13px;color:var(--ink-str);
  margin:0 0 20px;padding:14px 16px;background:var(--panel2);
  border:1px solid var(--line);border-radius:8px;cursor:pointer}
.copied{border-color:var(--acc)}
/* The password rules, one per line under the field they apply to
   (the owner, 2026-09-10). Grey before anything is typed, because red at
   somebody who has not started is telling them off for nothing. Red once
   there is text and the rule is unmet, green when it is met. The mark is a
   word-sized glyph rather than a tick: docs/DESIGN.md section 3 keeps ticks
   off every surface, so a met rule is a filled dot and an unmet one is
   hollow, and the colour is the second half of the answer rather than the
   whole of it. */
.rules{list-style:none;margin:8px 0 6px;padding:0;display:grid;gap:5px}
.rules li{display:flex;align-items:center;gap:8px;font-size:12px;
  color:var(--faint);transition:color var(--quick) var(--ease)}
.rules li::before{content:"";width:7px;height:7px;border-radius:99px;flex:0 0 auto;
  border:1px solid currentColor;transition:all var(--quick) var(--ease)}
.rules li.no{color:var(--fail)}
.rules li.yes{color:var(--ok)}
.rules li.yes::before{background:currentColor}
/* Two actions of equal weight, so they take equal room. `a.btn` is a block
   and `button` is full width, so both are told to share instead. */
.two{display:flex;gap:8px}
.two>.btn{flex:1;width:auto;margin-top:6px}
"""


def _page_css() -> str:
    """_CSS as a page gets it: without its comments. A comment in a stylesheet
    is sent to everybody who opens the page, and the sign-in page is open to
    everybody (site/theme.py holds the rule and the function)."""
    return theme().css_without_comments(_CSS)


# A click on a box copies what it holds, the way the install command on Add
# server does, and Download writes the codes from the page rather than from a
# second route that would have to hold them in readable form. The only script
# on any of these pages, and everything on them works without it: the key and
# the codes are text on screen either way.
_COPY_SCRIPT = """<script>
(function(){
  var flash=function(el){el.classList.add('copied');
    setTimeout(function(){el.classList.remove('copied')},900)};
  document.querySelectorAll('[data-copy]').forEach(function(el){
    el.onclick=function(){
      var text=el.dataset.copy;
      if(navigator.clipboard&&navigator.clipboard.writeText){
        navigator.clipboard.writeText(text).then(function(){flash(el)},function(){});
      }
    }});
  var down=document.getElementById('download'), box=document.getElementById('codes');
  if(down&&box){
    down.onclick=function(){
      var blob=new Blob([box.dataset.copy+'\\n'],{type:'text/plain'});
      var a=document.createElement('a');
      a.href=URL.createObjectURL(blob);
      a.download='whichports-recovery-codes.txt';
      a.click();
      URL.revokeObjectURL(a.href);
    }}
})();
</script>"""


# The three rules, drawn from the one list that defines them
# (`accounts.PASSWORD_RULES`), and re-checked in the browser while somebody
# types. The browser's copy is keyed on the same three words, and
# `tests/test_password_rules.py` fails if the two lists ever stop matching.
_RULES_SCRIPT = """<script>
(function(){
  var MIN=%(min)d;
  var TESTS={
    length:function(v){return v.length>=MIN},
    digit:function(v){return /[0-9]/.test(v)},
    special:function(v){return /[^A-Za-z0-9]/.test(v)}
  };
  document.querySelectorAll('.rules[data-for]').forEach(function(list){
    var input=document.getElementById(list.dataset.for);
    if(!input)return;
    var confirm=list.dataset.confirm?document.getElementById(list.dataset.confirm):null;
    var paint=function(){
      var value=input.value||'';
      var second=confirm?(confirm.value||''):'';
      list.querySelectorAll('li[data-rule]').forEach(function(li){
        var test=TESTS[li.dataset.rule];
        // Grey until the field the rule is about has been typed in. The three
        // tests read the password field, the match reads the confirm field,
        // so an untouched confirm box is not a red line about a mistake
        // nobody has made yet.
        var typed=test?value:second;
        var ok=test?test(value):(!!second&&second===value);
        li.classList.toggle('yes',!!typed&&ok);
        li.classList.toggle('no',!!typed&&!ok);
      });
    };
    input.addEventListener('input',paint);
    if(confirm)confirm.addEventListener('input',paint);
    paint();
  });
})();
</script>""" % {"min": accounts.PASSWORD_MIN_CHARS}


def _rules_script() -> str:
    """_RULES_SCRIPT as a page gets it: without its comment lines, for the
    same reason as _page_css()."""
    return theme().script_without_comments(_RULES_SCRIPT)


def _password_rules(field_id: str, confirm_id: str = "") -> str:
    """The rules under a password field, one per line.

    `confirm_id` adds the fourth line, that the two match, and is what the
    confirm field's own list is built from: one list under one field rather
    than two lists saying overlapping things.
    """
    rows = "".join(
        f'<li data-rule="{html.escape(key)}">{html.escape(words)}</li>'
        for key, words, _test in accounts.PASSWORD_RULES)
    if confirm_id:
        rows += '<li data-rule="match">Both the same</li>'
        confirm_attr = f' data-confirm="{html.escape(confirm_id)}"'
    else:
        confirm_attr = ""
    return (f'<ul class="rules" data-for="{html.escape(field_id)}"{confirm_attr}>'
            f'{rows}</ul>')


def _message(tone: str, tag: str, text: str) -> str:
    """One notice row, in the tag treatment docs/DESIGN.md section 3 sets: a
    short mono abbreviation carrying the tone, the words following it."""
    return (f'<div class="msg {tone}"><em>{html.escape(tag)}</em>'
            f'<span>{html.escape(text)}</span></div>')


def _closed_banner(text: str) -> str:
    """The closed-signups notice, one short sentence in the warn tone.

    Deliberately not `_message`: that treatment carries a tag chip, and the
    chip is what the owner ruled out on 2026-08-23 after seeing SHUT and NO
    stacked above the form. He asked for one plain yellow banner that says
    registration is not open for now (docs/RECORD.md 4.100). The sentence is
    the whole fact, so nothing sits beside it.
    """
    return f'<div class="msg closed"><span>{html.escape(text)}</span></div>'


# The provider marks, drawn here rather than fetched.
#
# **No third-party request, which docs/DESIGN.md section 4 requires of every
# page we serve.** Loading these from Google's or Microsoft's CDN would tell
# them who is looking at our login page before anybody has chosen to sign in
# with them, which is exactly the thing self-hosting the fonts already avoids.
#
# They are each company's own mark, used to label the button that signs a
# person in with that company, which is what a mark is for. Nothing else on the
# page borrows their colour: `docs/DESIGN.md` owns our palette and these two
# swatches never leak into it.
_MARK_GOOGLE = (
    '<svg viewBox="0 0 48 48" aria-hidden="true">'
    '<path fill="#4285F4" d="M45.12 24.5c0-1.56-.14-3.06-.4-4.5H24v8.51h11.84'
    'c-.51 2.75-2.06 5.08-4.39 6.64v5.52h7.11c4.16-3.83 6.56-9.47 6.56-16.17z"/>'
    '<path fill="#34A853" d="M24 46c5.94 0 10.92-1.97 14.56-5.33l-7.11-5.52'
    'c-1.97 1.32-4.49 2.1-7.45 2.1-5.73 0-10.58-3.87-12.31-9.07H4.34v5.7'
    'C7.96 41.07 15.4 46 24 46z"/>'
    '<path fill="#FBBC05" d="M11.69 28.18C11.25 26.86 11 25.45 11 24s.25-2.86'
    '.69-4.18v-5.7H4.34C2.85 17.09 2 20.45 2 24s.85 6.91 2.34 9.88l7.35-5.7z"/>'
    '<path fill="#EA4335" d="M24 10.75c3.23 0 6.13 1.11 8.41 3.29l6.31-6.31'
    'C34.91 4.18 29.93 2 24 2 15.4 2 7.96 6.93 4.34 14.12l7.35 5.7'
    'c1.73-5.2 6.58-9.07 12.31-9.07z"/></svg>')

_MARK_MICROSOFT = (
    '<svg viewBox="0 0 23 23" aria-hidden="true">'
    '<path fill="#F25022" d="M1 1h10v10H1z"/>'
    '<path fill="#7FBA00" d="M12 1h10v10H12z"/>'
    '<path fill="#00A4EF" d="M1 12h10v10H1z"/>'
    '<path fill="#FFB900" d="M12 12h10v10H12z"/></svg>')

_MARKS = {"google": _MARK_GOOGLE, "microsoft": _MARK_MICROSOFT}


def _provider_buttons(providers, next_path: str, verb: str = "Sign in") -> str:
    """The provider buttons, side by side under the form.

    They are links and not buttons in a form, because starting a provider
    sign-in is a navigation to somebody else's consent screen and nothing here
    changes until the browser comes back.

    An empty list renders nothing at all, not a divider with a gap under it, so
    a build with no provider configured is a plain email and password page
    rather than a page with a hole in it. One provider gets the full width
    rather than half of it and an empty column beside it.
    """
    if not providers:
        return ""
    links = "".join(
        f'<a class="btn prov" href="/login/{html.escape(name)}'
        f'?next={quote(next_path, safe="")}">{_MARKS.get(name, "")}'
        f'<span>{html.escape(label)}</span></a>'
        for name, label in providers)
    width = "" if len(providers) > 1 else " one"
    return (f'<div class="or"><span>{html.escape(verb)} with</span></div>'
            f'<div class="provs{width}">{links}</div>')


def login_page(csrf: str, next_path: str, email: str = "",
               error: str | None = None, notice: tuple[str, str] | None = None,
               providers=(), closed: str | None = None, code: bool = False) -> str:
    """The sign-in page. Every value that reaches the HTML is escaped, because
    two of them (the email and ?next=) come from the request.

    `notice` is a (tag, text) pair so a redirect can carry a one-shot line here
    without a flash-cookie mechanism. `error` always wins over it.

    `providers` is the (name, label) pairs that are configured on this server.

    **`code=True` is the second factor, and it is this card rather than a page
    of its own** (docs/screens/sign-in/SPEC.md, the owner 2026-09-09: there is no
    separate two-factor page any more). The password has already been proved by
    the time it is drawn, so what it drops is what would be untrue to keep: the
    email and password fields, and the two ways of starting a sign-in from
    scratch, which are not offered halfway through one.

    **The address is not on it either**, which the sketch draws and this does
    not. That is an older decision with a test on it
    (`tests/test_two_factor.py`): nothing on this step names an account, so it
    can never become a way to ask a question about somebody else's. What is
    left is this card, one field, and the line saying which field it is.
    """
    th = theme()
    if closed and error == closed:
        # A sign-in refused because signups are closed repeats the banner's own
        # words: signup.CLOSED_NOTICE is one string on purpose. The owner hit the
        # two stacked after a Google callback was refused, so the banner says
        # it once and no error is drawn on top. Any other refusal keeps the
        # error treatment below.
        error = None
    banner = ""
    if error:
        banner = _message("fail", "NO", error)
    elif notice:
        banner = _message("", notice[0], notice[1])
    # Closed signups replace the way to the register page rather than sitting
    # beside it. Offering a button that leads to a refusal is the dead end this
    # page already had once, in a different shape.
    if closed:
        # A permanent banner at the top, not a line at the bottom and not
        # an error after the fact. That is what the owner asked for, in so many
        # words. Somebody should know before
        # they spend a consent screen finding out.
        banner = _closed_banner(closed) + banner
        closed_notice = ""
    else:
        closed_notice = ('<div class="lead">New here?</div>'
                         '<a class="btn wide" href="/register">Create an account</a>')
    swap = f'<div class="swap">{closed_notice}</div>' if closed_notice else ""
    forgot = '<a href="/forgot">Forgot your password?</a>'
    if code:
        # The password is proved and the account owes six digits. The form
        # goes to the second step, which is where the pending session is.
        action, swap, providers = "/login/2fa", "", ()
        fields = (
            '<div class="sub">Enter the code from your authenticator app.</div>'
            + _field("Code", "code", "text", cls="code",
                     autocomplete="one-time-code",
                     extra='inputmode="numeric" maxlength="6" placeholder="______"'
                           ' autocapitalize="off" spellcheck="false" autofocus'))
        foot = (f'{forgot}<span class="sep">·</span>'
                'A recovery code works here too.')
    else:
        action = "/login"
        fields = (
            _field("Email", "email", "email", email, "username",
                   extra='autocapitalize="off" spellcheck="false"')
            + _field("Password", "password", "password",
                     autocomplete="current-password"))
        foot = forgot
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<base href="/">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Sign in - whichports</title>
<script>try{{var m=localStorage.getItem('wp-mode');if(m)document.documentElement.dataset.mode=m}}catch(e){{}}</script>
{th.ICON_LINKS}
<style>{th.fonts()}{th.TOKENS}{th.BASE}{_page_css()}</style></head>
<body>
<main>
  <div class="brand">{th.mark(big=True)}</div>
  <div class="panel card">
    <form method="post" action="{action}">
      <h1>Sign in</h1>
      {banner}
      <input type="hidden" name="csrf" value="{html.escape(csrf)}">
      <input type="hidden" name="next" value="{html.escape(next_path)}">
      {fields}
      <button class="btn pri" type="submit">Sign in</button>
    </form>
    {_provider_buttons(providers, next_path, verb="Sign in")}
    {swap}
  </div>
  <div class="foot">{foot}</div>
</main>
</body></html>
"""


def two_factor_page(csrf: str, next_path: str, error: str | None = None,
                    recovery_left: int | None = None) -> str:
    """The login's second step.

    It says nothing about the account. There is no email on it, because getting
    here already cost a correct password and the page must not become a way to
    ask a question about somebody else's account.

    `recovery_left` is the one case that is not a form to fill in: a recovery
    code has just been spent and the operator is signed in. The count is shown
    once, here, because it is the only place they will ever see it.
    """
    th = theme()
    if recovery_left is not None:
        return _recovery_spent_page(th, next_path, recovery_left)
    banner = _message("fail", "NO", error) if error else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<base href="/">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Two-factor - whichports</title>
<script>try{{var m=localStorage.getItem('wp-mode');if(m)document.documentElement.dataset.mode=m}}catch(e){{}}</script>
{th.ICON_LINKS}
<style>{th.fonts()}{th.TOKENS}{th.BASE}{_page_css()}</style></head>
<body>
<main>
  <div class="brand">{th.mark(big=True)}</div>
  <form class="panel card" method="post" action="/login/2fa">
    <h1>Two-factor</h1>
    <div class="sub">Enter the code from your authenticator app.</div>
    {banner}
    <input type="hidden" name="csrf" value="{html.escape(csrf)}">
    <input type="hidden" name="next" value="{html.escape(next_path)}">
    <div class="field">
      <label for="code">Code</label>
      <input id="code" class="code" name="code" type="text"
             autocomplete="one-time-code" inputmode="text" autocapitalize="off"
             spellcheck="false" autofocus>
    </div>
    <button class="btn pri" type="submit">Continue</button>
  </form>
  <div class="foot">A recovery code works here too.</div>
</main>
</body></html>
"""


def _recovery_spent_page(th, next_path: str, recovery_left: int) -> str:
    """Shown once, after a recovery code has been used to sign in. The count is
    the point: recovery codes run out, and nobody finds that out at a good
    moment unless they are told here."""
    plural = "" if recovery_left == 1 else "s"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<base href="/">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Signed in - whichports</title>
<script>try{{var m=localStorage.getItem('wp-mode');if(m)document.documentElement.dataset.mode=m}}catch(e){{}}</script>
{th.ICON_LINKS}
<style>{th.fonts()}{th.TOKENS}{th.BASE}{_page_css()}</style></head>
<body>
<main>
  <div class="brand">{th.mark(big=True)}</div>
  <div class="panel card">
    <h1>Signed in</h1>
    <div class="sub">You used a recovery code.</div>
    {_message("", "LEFT", f"{recovery_left} recovery code{plural} remaining.")}
    <p class="sub">Each one works once. Run
      <code>users_cli 2fa reset-codes</code> on the server for a fresh set.</p>
    <a class="btn pri" href="{html.escape(next_path)}">Continue</a>
  </div>
</main>
</body></html>
"""


def simple_page(heading: str, body: str, back: str = "/integrations") -> str:
    """One heading, one paragraph, one way back.

    For the ends of a flow that leaves the app and comes back, which today is
    only the Slack connect. It is a real page rather than a status code because
    a person is looking at it, having just been sent to another company's site
    and returned.

    Both strings are escaped. `body` carries Slack's own short error codes and
    our own sentences, and neither is markup.
    """
    th = theme()
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<base href="/">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>whichports</title>
<script>try{{var m=localStorage.getItem('wp-mode');if(m)document.documentElement.dataset.mode=m}}catch(e){{}}</script>
{th.ICON_LINKS}
<style>{th.fonts()}{th.TOKENS}{th.BASE}{_page_css()}</style></head>
<body>
<main>
  <div class="brand">{th.mark(big=True)}</div>
  <div class="panel card">
    <h1>{html.escape(heading)}</h1>
    <p class="sub">{html.escape(body)}</p>
    <a class="btn" href="{html.escape(back, quote=True)}">Back to Integrations</a>
  </div>
</main>
</body></html>
"""


def register_page(csrf: str, email: str = "", error: str | None = None,
                  closed: str | None = None, providers=()) -> str:
    """Create an account and the workspace that comes with it.

    The only page here anybody can reach without already having something. It
    is a plain form: an address, a password, and the same password again.
    """
    th = theme()
    if closed and error == closed:
        # The refusal repeats the banner's own words, so the banner says it
        # once, the same collapse the login page does.
        error = None
    banner = _message("fail", "NO", error) if error else ""
    closed_attr = ""
    if closed:
        banner = _closed_banner(closed) + banner
        # app/signup.py refuses this either way, so the attribute is not the
        # check. It is the page telling the truth before somebody types a
        # password into a form that was never going to work.
        closed_attr = ' disabled aria-disabled="true"'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<base href="/">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Create your account - whichports</title>
<script>try{{var m=localStorage.getItem('wp-mode');if(m)document.documentElement.dataset.mode=m}}catch(e){{}}</script>
{th.ICON_LINKS}
<style>{th.fonts()}{th.TOKENS}{th.BASE}{_page_css()}</style></head>
<body>
<main>
  <div class="brand">{th.mark(big=True)}</div>
  <div class="panel card">
    <form method="post" action="/register">
      <h1>Create your account</h1>
      {banner}
      <input type="hidden" name="csrf" value="{html.escape(csrf)}">
      <div class="field">
        <label for="email">Email</label>
        <input id="email" name="email" type="email" autocomplete="username"
               autocapitalize="off" spellcheck="false"
               value="{html.escape(email)}">
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input id="password" name="password" type="password"
               autocomplete="new-password">
      </div>
      <div class="field">
        <label for="confirm">Confirm password</label>
        <input id="confirm" name="confirm" type="password"
               autocomplete="new-password">
      </div>
      {_password_rules("password", "confirm")}
      <button class="btn pri" type="submit"{closed_attr}>Create account</button>
    </form>
    {_provider_buttons(providers, "/", verb="Sign in")}
    <div class="swap">
      <div class="lead">Already have an account?</div>
      <a class="btn wide" href="/login">Sign in</a>
    </div>
  </div>
  {_rules_script()}
</main>
</body></html>
"""


# ---------------------------------------------------- the screens around it
#
# docs/screens/sign-in/SPEC.md, the sketch the owner approved on 2026-09-09.
# Everything below shares the card, the type and the one primary button with
# the three pages above it, because a new screen that looks like a different
# product is the thing that sketch exists to prevent.


def _shell(title: str, body: str) -> str:
    """The head every page here carries, and the card under the mark.

    The three pages above this line each spell their own head out. This is
    the same head, named once, for the screens added on 2026-09-09: seven
    more copies of it would be seven places to forget the base element.
    """
    th = theme()
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<base href="/">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>{html.escape(title)} - whichports</title>
<script>try{{var m=localStorage.getItem('wp-mode');if(m)document.documentElement.dataset.mode=m}}catch(e){{}}</script>
{th.ICON_LINKS}
<style>{th.fonts()}{th.TOKENS}{th.BASE}{_page_css()}</style></head>
<body>
<main>
  <div class="brand">{th.mark(big=True)}</div>
  {body}
</main>
</body></html>
"""


def _field(label: str, name: str, kind: str = "text", value: str = "",
           autocomplete: str = "", cls: str = "", extra: str = "") -> str:
    """One labelled input. Every value that reaches it is escaped here, because
    two of them arrive from a request and one from a database."""
    auto = f' autocomplete="{html.escape(autocomplete)}"' if autocomplete else ""
    classes = f' class="{cls}"' if cls else ""
    return (f'<div class="field"><label for="{html.escape(name)}">{html.escape(label)}</label>'
            f'<input id="{html.escape(name)}" name="{html.escape(name)}"'
            f' type="{html.escape(kind)}"{classes}{auto}'
            f' value="{html.escape(value)}" {extra}></div>')


def _back_to_sign_in() -> str:
    return '<div class="foot"><a href="/login">Back to sign in</a></div>'


def reset_ask_page(csrf: str, email: str = "", error: str | None = None,
                   notice: str | None = None) -> str:
    """Forgot your password: the address, and one button.

    It asks for the address and says nothing about whether that address has an
    account. The answer to a submitted form is the same page-after either way
    (`link_sent_page`), which is what stops this becoming a way to find out who
    has an account here.
    """
    banner = ""
    if error:
        banner = _message("fail", "NO", error)
    elif notice:
        banner = _message("", "MAIL", notice)
    body = f"""<div class="panel card">
    <form method="post" action="/forgot">
      <h1>Reset your password</h1>
      {banner}
      <input type="hidden" name="csrf" value="{html.escape(csrf)}">
      {_field("Email", "email", "email", email, "username",
              extra='autocapitalize="off" spellcheck="false" autofocus')}
      <button class="btn pri" type="submit">Send the link</button>
    </form>
  </div>
  {_back_to_sign_in()}"""
    return _shell("Reset your password", body)


def link_sent_page(heading: str, email: str, csrf: str = "",
                   again_action: str = "") -> str:
    """A link went out. One line, and the address it went to in mono.

    `again_action` adds Send it again as a real form, which is the confirm
    flow's, because somebody who has not received it has nowhere else to go.
    The reset flow has no such button on purpose: the way to ask again is to
    ask again, and a button here would let anybody holding the page mail
    somebody repeatedly.
    """
    again = ""
    if again_action:
        again = f"""<form method="post" action="{html.escape(again_action, quote=True)}">
      <input type="hidden" name="csrf" value="{html.escape(csrf)}">
      <input type="hidden" name="email" value="{html.escape(email)}">
      <button class="btn" type="submit">Send it again</button>
    </form>"""
    body = f"""<div class="panel card">
    <h1>{html.escape(heading)}</h1>
    <div class="sent">A link went to <b>{html.escape(email)}</b></div>
    {again}
  </div>
  {_back_to_sign_in()}"""
    return _shell(heading, body)


def link_expired_page() -> str:
    """An expired, spent or unknown link: the heading and the way back.

    It drew the Check your mail page with the heading swapped and no
    address, "A link went to" and nothing after it (the second big test,
    2026-10-25, case A15b). One page for every dead link, whatever made it
    dead, so it answers nothing about somebody else's account."""
    body = f"""<div class="panel card">
    <h1>That link has expired</h1>
  </div>
  {_back_to_sign_in()}"""
    return _shell("That link has expired", body)


def no_link_sent_page() -> str:
    """A reset asked for where no mail relay is set, so no mail can leave.

    The page said "A link went to" the address while the journal said no
    mail was sent (the second big test, 2026-10-25, case A15). It is the
    same page for every address, so it says nothing about who has an
    account here."""
    body = f"""<div class="panel card">
    <h1>No link was sent</h1>
    <div class="sent">No mail relay is set up.</div>
  </div>
  {_back_to_sign_in()}"""
    return _shell("No link was sent", body)


def choose_password_page(csrf: str, action: str, email: str,
                         error: str | None = None) -> str:
    """Where both the reset mail and a hand-made account's mail land.

    The address is a field rather than a sentence, read only, so the form
    reads as one thing and nobody has to wonder which account they are about
    to set a password on. It is not submitted: the link decides whose account
    this is, and a posted address would be a second opinion about that.
    """
    banner = _message("fail", "NO", error) if error else ""
    body = f"""<div class="panel card">
    <form method="post" action="{html.escape(action, quote=True)}">
      <h1>Choose a password</h1>
      {banner}
      <input type="hidden" name="csrf" value="{html.escape(csrf)}">
      {_field("Email", "shown_email", "email", email, cls="ro",
              extra='readonly tabindex="-1"')}
      {_field("New password", "password", "password", autocomplete="new-password",
              extra="autofocus")}
      {_field("Confirm password", "confirm", "password", autocomplete="new-password")}
      {_password_rules("password", "confirm")}
      <button class="btn pri" type="submit">Save and sign in</button>
    </form>
  </div>
  {_rules_script()}"""
    return _shell("Choose a password", body)


def join_page(csrf: str, action: str, workspace: str, invited_by: str,
              role: str = "", name: str = "", error: str | None = None) -> str:
    """An invitation, redeemed. The workspace is the title, because that is
    the thing being joined and the person reading has probably never heard of
    us.

    **An empty role says nothing rather than trailing an "as".** Roles are not
    enforced anywhere in the code yet, so the invitations this product can
    issue today carry none, and a line reading "as Admin" would be claiming a
    permission level that does not exist (the accuracy rule). The argument
    stays for when Members lands.
    """
    banner = _message("fail", "NO", error) if error else ""
    who = f"Invited by {html.escape(invited_by)}"
    if role:
        who += f", as {html.escape(role)}"
    body = f"""<div class="panel card">
    <form method="post" action="{html.escape(action, quote=True)}">
      <h1>Join {html.escape(workspace)}</h1>
      <div class="sub">{who}</div>
      {banner}
      <input type="hidden" name="csrf" value="{html.escape(csrf)}">
      {_field("Name", "name", "text", name, "name", extra="autofocus")}
      {_field("Password", "password", "password", autocomplete="new-password")}
      {_field("Confirm password", "confirm", "password", autocomplete="new-password")}
      {_password_rules("password", "confirm")}
      <button class="btn pri" type="submit">Join</button>
    </form>
  </div>
  {_rules_script()}"""
    return _shell(f"Join {workspace}", body)


