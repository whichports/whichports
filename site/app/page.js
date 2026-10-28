// The dashboard's script. One file, read by build.py at import and put in
// the page with a handful of values filled in (page_script there names them):
// the words and maps the page and the builder must agree on. Plain
// JavaScript with no build step, so `node --check page.js` reads it and a
// brace here is a brace.
//
// It runs on the sample shell and on every live page alike. Nothing in it
// decides anything: every change of state is asked of the control plane and
// painted from its answer (docs/DESIGN.md section 4).
var toastT;
function toast(m){var t=document.getElementById('toast');t.textContent=m;t.classList.add('on');
  clearTimeout(toastT);toastT=setTimeout(function(){t.classList.remove('on')},2600);}
// Asking before something irreversible, in this product's own dialog.
//
// **Never window.confirm.** It cannot be styled, it looks like nothing else
// here, it names the site in a way we do not control, and it sits in a
// different place on every engine.
//
// One overlay in the page, reused, so there is nothing to build per call and
// nothing to clean up. Escape and the backdrop both cancel, because a dialog
// asking about a delete must be as easy to refuse as to accept.
function askConfirm(title,body,word,onYes){
  var ovl=document.getElementById('ask');
  document.getElementById('ask-t').textContent=title;
  document.getElementById('ask-b').textContent=body;
  var yes=document.getElementById('ask-yes');
  yes.textContent=word;
  var close=function(){
    ovl.classList.remove('on');
    document.removeEventListener('keydown',onKey);
  };
  var onKey=function(e){if(e.key==='Escape')close()};
  // Assigned rather than added, so asking twice never leaves the first
  // answer's handler behind to fire on the second.
  yes.onclick=function(){close();onYes()};
  document.getElementById('ask-no').onclick=close;
  ovl.onclick=function(e){if(e.target===ovl)close()};
  document.addEventListener('keydown',onKey);
  ovl.classList.add('on');
  // The safe one takes focus, so Enter cancels rather than deletes.
  document.getElementById('ask-no').focus();
}
// What runs after a view is shown. The page script below sets it, so the
// first-look window can open on its own the first time a server is opened.
var afterView=function(){};
function setV(v){
  document.querySelectorAll('.view').forEach(function(e){e.classList.toggle('on',e.id===v)});
  document.querySelectorAll('.nav a[data-v]').forEach(function(a){
    a.classList.toggle('on',a.dataset.v===v)});
  window.scrollTo(0,0);
  afterView(v);
}
// ---------------------------------------------------------------- the URL
//
// A view has an address. The owner and his father, 2026-08-22, on every screen
// living at app.whichports.com and nothing else: they find it annoying and it
// should change. The concrete cost is that an alert mail can say "open the
// dashboard" and never "open this port on this server", which is the one link
// in the product somebody actually wants at two in the morning.
//
// The mapping is derived from the view id rather than stored beside it,
// because both feeds already name their views the same way: `fleet`, a plain
// word for each nav entry, and `host-<name>` for a server. The sample shell
// has one demo host under the bare id `host` and it answers to /host/demo.
//
// A host tab replaces rather than pushes. Seven tabs on one host would
// otherwise put seven entries in the history and the back button would walk
// them instead of leaving the host, which is not what back means here.
function viewToPath(v,tab){
  var p;
  if(v==='fleet') p='/';
  else if(v==='host') p='/host/demo';
  else if(v.indexOf('host-')===0) p='/host/'+encodeURIComponent(v.slice(5));
  else p='/'+v;
  if(tab&&tab!=='overview'&&p!=='/') p=p+'/'+tab;
  return p;
}
function pathToView(path){
  var parts=path.replace(/^\/+|\/+$/g,'').split('/');
  if(!parts[0]) return {v:'fleet',tab:''};
  if(parts[0]==='host'&&parts[1]){
    var name=decodeURIComponent(parts[1]);
    var v=(name==='demo'&&document.getElementById('host'))?'host':'host-'+name;
    return {v:v,tab:parts[2]||''};
  }
  return {v:parts[0],tab:''};
}
function slugFor(v){ return v==='host'?'host':(v.indexOf('host-')===0?v.slice(5):''); }
function currentTab(v){
  var slug=slugFor(v);
  if(!slug) return '';
  var on=document.querySelector('.tabsel[name="tabs-'+slug+'"]:checked');
  return on?(on.id.slice(('tb-'+slug+'-').length)):'';
}
// Apply a path. An address nobody has a view for falls back to the fleet and
// corrects the bar, rather than showing a blank page: a stale bookmark to a
// host that has since been removed is a normal thing to have.
function applyPath(path,push){
  var r=pathToView(path);
  var el=document.getElementById(r.v);
  if(!el){ r={v:'fleet',tab:''}; push='replace'; }
  setV(r.v);
  if(r.tab){
    var t=document.getElementById('tb-'+slugFor(r.v)+'-'+r.tab);
    if(t) t.checked=true;
  }
  var want=viewToPath(r.v,r.tab||currentTab(r.v));
  if(push==='replace') history.replaceState({},'',want);
  else if(push) history.pushState({},'',want);
}
function goto(v){
  setV(v);
  history.pushState({},'',viewToPath(v,currentTab(v)));
}
// A host's own tabs are radios and CSS (tab_css), so nothing here switches
// them. What this does is keep the address honest about which one is open.
// ------------------------------------------------- viewing another workspace
//
// An admin is looking at somebody else's fleet. Every control on this page
// posts to `/api/admin/...`, and those routes act on the workspace of the
// signed-in account, never on the one being looked at
// (controlplane/app/ingest.py, operator_workspace). So a click here would act
// on a server OF YOUR OWN with the same name, which is the one way this screen
// could destroy something.
//
// **The stop is on fetch and not on a list of buttons, and that is the whole
// design decision.** The first attempt turned off everything matching
// `[class*="js-"],[data-open]`, and a test that read this file found the
// counterexample immediately: the channel row menu posts from `.rm-post`
// items bound through a helper. A selector list is a list somebody has to
// remember to add to, which is the same failure shape as the hand-written
// command list in app/cli.py. Wrapping fetch needs nothing remembered: a
// control added next year is covered the day it is written.
//
// **The server side is not relying on this.** No request from this page can
// reach another workspace whatever the browser does, and that invariant is
// untouched. This stops a mis-click acting on the wrong server of your own,
// which is a real accident rather than a boundary.
//
// The two routes that stay open are the account menu's. Neither touches anything a
// workspace owns: one asks who is signed in, the other ends your own session,
// and being unable to sign out of a page you are looking at would be absurd.
var VIEWING_OPEN = __VIEWING_OPEN__;
// Cosmetic only. The buttons are already inert by the wrapper above; this is
// so they LOOK inert rather than looking clickable and doing nothing.
var VIEWING_DIM = '[class*="js-"],[data-open],.rm-post';
function lockViewing(){
  if(!document.body.dataset.viewing) return;
  var real = window.fetch;
  window.fetch = function(url){
    var u = String(url);
    if(u.indexOf('/api/admin/') === 0 && VIEWING_OPEN.indexOf(u) < 0){
      toast('Viewing another workspace');
      return Promise.reject(new Error('viewing another workspace'));
    }
    return real.apply(this, arguments);
  };
}
// Its own pass, because a piece the quiet refresh swaps in arrives looking
// clickable and has to be dimmed like the rest.
function dimViewing(){
  if(!document.body.dataset.viewing) return;
  document.querySelectorAll(VIEWING_DIM).forEach(function(el){
    if('disabled' in el) el.disabled = true;
    el.setAttribute('aria-disabled', 'true');
  });
}
// ------------------------------------------------ what the refresh may swap
//
// The page asks the server for itself again in the background (the refresh
// further down) and swaps in only the pieces whose markup changed. This is
// the list of pieces. Every piece has a key that says where it lives, so the
// same function reads the server's answer and the screen:
//
//   row:<server>     a fleet row
//   notes:page       the fleet's banner region
//   strip:page       the fleet's four boxes
//   head:<view id>   a server page's header, with its state and its buttons
//   tab:<panel id>   one tab panel of a server's page
//   look:<window id> a server's first-look window, which sits in its page
//                    beside the tabs
//   view:<view id>   a whole screen: a server's page before its first
//                    document (it has no tabs yet), the alerts, the admin
//   stamp:page       the footer
//
// What is not here is not refreshed: the other windows and the account
// page. The top bar is not a piece either, because which of its entries is
// lit is the page's own doing. Its count beside Alerts is brought over by
// itself (alertsCount, below).
function hostPieces(v){
  var tabs=v.querySelectorAll('.tab[id]');
  if(!tabs.length) return [['view:'+v.id,v]];
  var out=[['head:'+v.id,v.querySelector('.hh')]];
  tabs.forEach(function(t){out.push(['tab:'+t.id,t])});
  return out;
}
function regionsOf(root){
  var out=[];
  var push=function(key,el){if(el)out.push([key,el])};
  root.querySelectorAll('#fleet .panel .row[data-host]').forEach(function(r){
    push('row:'+r.dataset.host,r)});
  push('notes:page',root.querySelector('#fleet .fnotes'));
  push('strip:page',root.querySelector('#fleet .fstrip'));
  root.querySelectorAll('.view[id^="host-"]').forEach(function(v){
    hostPieces(v).forEach(function(p){push(p[0],p[1])})});
  root.querySelectorAll('.view[id^="host-"] .fv[id]').forEach(function(o){
    push('look:'+o.id,o)});
  push('gone:page',root.querySelector('#fleet .fgone'));
  push('view:alerts',root.querySelector('#alerts'));
  push('view:integrations',root.querySelector('#integrations'));
  push('view:admin',root.querySelector('#admin'));
  push('stamp:page',root.querySelector('.pgstamp'));
  return out;
}
// The piece on the screen a key names, for the keys that are not a list.
function liveFor(key){
  var kind=key.slice(0,key.indexOf(':')), id=key.slice(kind.length+1);
  if(kind==='stamp') return document.querySelector('.pgstamp');
  if(kind==='notes') return document.querySelector('#fleet .fnotes');
  if(kind==='strip') return document.querySelector('#fleet .fstrip');
  if(kind==='gone') return document.querySelector('#fleet .fgone');
  var el=document.getElementById(id);
  if(kind==='head') return el&&el.querySelector('.hh');
  return el;
}
// The count beside Alerts in the top bar, as its text, or nothing when no
// alert is open.
function alertsCount(root){
  var badge=root.querySelector('.nav a[data-v="alerts"] .nb');
  return badge?badge.textContent:'';
}
// A piece somebody is in the middle of: a field that no longer says what the
// page loaded with, or the open/closed choice made for a port not yet added.
// It is left alone and caught up with next time.
function holdsEdits(el){
  var dirty=false;
  el.querySelectorAll('input,textarea').forEach(function(i){
    if(i.type==='radio'||i.type==='checkbox') return;
    if(i.value!==i.defaultValue) dirty=true;
  });
  if(el.querySelector('.seg button.on')) dirty=true;
  return dirty;
}
// What somebody opened or chose inside a piece is theirs to keep when the
// piece is swapped: a port's open row, an open rule, the path that is drawn,
// the section of the Settings rail. Each is a hidden checkbox or radio, and
// the piece the server sends knows nothing of it, so an open row closed on
// every refresh that changed its tab (measured 2026-10-04, docs/RECORD.md
// 4.362).
//
// What an input is known by. Most ids are built from what the input is, a
// port or a section, and the id is enough. Two are built from where it is:
// the second path, the third rule. The second path of the new piece may be
// another port's, so those two are known by the words of their label as
// well, and a label that reads differently is a different thing.
function choiceKey(input,words){
  if(input.classList.contains('rr')) return input.name+'|'+words[input.id];
  if(input.classList.contains('rsel')) return input.id+'|'+words[input.id];
  return input.id;
}
function labelWords(root){
  var words={};
  root.querySelectorAll('label[for]').forEach(function(l){
    words[l.htmlFor]=l.textContent});
  return words;
}
var CHOICES='input[type="checkbox"][id],input[type="radio"][id]';
// A fold has no id. It is known by the words of its summary, and by which of
// the folds with those words it is, since two firewalls can each have one.
function foldKeys(piece){
  var count={}, out=[];
  piece.querySelectorAll('details').forEach(function(f){
    var s=f.querySelector('summary'), words=s?s.textContent:'';
    count[words]=(count[words]||0)+1;
    out.push(['fold|'+words+'|'+count[words],f]);
  });
  return out;
}
// Everything checked or opened inside a piece, read before the piece is
// taken out.
function choicesOf(piece){
  var words=labelWords(piece), chosen={};
  piece.querySelectorAll(CHOICES).forEach(function(i){
    if(i.checked) chosen[choiceKey(i,words)]=true});
  foldKeys(piece).forEach(function(k){if(k[1].open) chosen[k[0]]=true});
  return chosen;
}
// And put back on the piece that took its place, once that piece is on the
// page, where checking one radio unchecks the rest of its group. Only ever
// checks and opens: what nobody chose keeps what the server sent, so a group
// whose chosen one is gone keeps the server's own first choice and is never
// left with none.
function keepChoices(chosen,piece){
  var words=labelWords(piece);
  piece.querySelectorAll(CHOICES).forEach(function(i){
    if(chosen[choiceKey(i,words)]===true) i.checked=true});
  foldKeys(piece).forEach(function(k){if(chosen[k[0]]===true) k[1].open=true});
}
document.addEventListener('DOMContentLoaded',function(){
  // Every piece the refresh may swap, as the server sent it. Taken before
  // anything below touches the page, because a piece is compared with what
  // the server said last time and never with what the script painted since:
  // a row the filter hid, a word written on a click.
  var baseline={};
  regionsOf(document).forEach(function(r){baseline[r[0]]=r[1].outerHTML});
  baseline['count:alerts']=alertsCount(document);
  // ---- what is bound to the screen, and bound again after a swap ----
  // A piece the refresh swaps in carries no handlers, because the passes
  // below ran before it existed. So every pass over the screen's own controls
  // goes through onWire, which runs it now and again after every swap.
  // Assigning onclick rather than adding a listener is what makes running a
  // pass twice safe: the second run replaces the first instead of doubling it.
  var passes=[];
  var onWire=function(pass){passes.push(pass);pass()};
  var wire=function(){passes.forEach(function(pass){pass()})};
  // Every request the page makes passes through here, so the refresh can
  // tell when a click is being handled: `inflight` while an answer is owed,
  // `touched` when one was last asked for or arrived.
  var inflight=0, touched=0;
  (function(){
    var real=window.fetch;
    window.fetch=function(url,opts){
      if(!opts||opts.method!=='POST') return real.apply(this,arguments);
      inflight++;touched=Date.now();
      var done=function(){inflight--;touched=Date.now()};
      var p=real.apply(this,arguments);
      p.then(done,done);
      return p;
    };
  })();
  lockViewing();
  onWire(dimViewing);
  // ---- three things every action says or does the same way ----
  // The answer is read whatever the status, because the control plane's
  // refusals carry a `detail` written for the operator, and a body that
  // will not parse is an empty object rather than a second failure.
  var ask=function(url,opts){
    return fetch(url,opts).then(function(r){
      return r.json().catch(function(){return {}}).then(function(j){
        return {ok:r.ok,status:r.status,body:j}})})};
  var NO_ANSWER='No answer. Check your connection and try again.';
  var KINDS_NOT_SAVED='The kinds did not save. Try again.';
  var didNotWork=function(status){return 'That did not work, HTTP '+status};
  // Copy text to the clipboard and flash the box it came from. The textarea
  // path is for a browser without the clipboard API or without permission.
  var copyText=function(text,box){
    if(!text)return;
    var flash=function(){box.classList.add('copied');
      setTimeout(function(){box.classList.remove('copied')},1400)};
    if(navigator.clipboard&&navigator.clipboard.writeText){
      navigator.clipboard.writeText(text).then(flash)}
    else{var ta=document.createElement('textarea');ta.value=text;
      document.body.appendChild(ta);ta.select();document.execCommand('copy');
      document.body.removeChild(ta);flash()}};
  // The nav in the top bar and the Back button on every server page.
  onWire(function(){
  document.querySelectorAll('[data-v]').forEach(function(a){
    a.onclick=function(){goto(a.dataset.v)}});
  });
  onWire(function(){
  document.querySelectorAll('.tabsel').forEach(function(t){
    t.onchange=function(){
      var view=t.closest('.view');
      if(view&&view.classList.contains('on'))
        history.replaceState({},'',viewToPath(view.id,currentTab(view.id)));
    };
  });
  });
  window.addEventListener('popstate',function(){applyPath(location.pathname,false)});
  // **And the address the page loaded on**, which is the line this was missing.
  // applyPath was written, was correct, and was wired only to the back button,
  // so every reload and every pasted link landed on the fleet whatever the
  // address said (the owner, 2026-08-23: a reload of /alerts and a pasted link
  // to /integrations both ended on the fleet). 'replace' rather than a push,
  // because arriving somewhere is not a
  // navigation and must not put an extra entry in the history.
  applyPath(location.pathname,'replace');
  // ---- the page keeps itself current, quietly ----
  //
  // The dashboard renders from the database on every request and then sat in
  // the browser going stale until somebody reloaded it by hand, which the owner
  // named on 2026-08-30 (docs/RECORD.md 4.138). Until 2026-09-02 the page
  // reloaded itself once a minute,
  // which threw away whatever he was looking at (docs/RECORD.md 4.141).
  //
  // Now it asks the server for the page again in the background and swaps in
  // only the pieces whose markup changed (regionsOf, above). Nothing else is
  // touched, so scroll, the open screen, the open tab, the filter and the
  // search all survive, and a piece that did not change keeps its handlers.
  //
  // **Never under somebody's hands.** It waits until the tab is visible,
  // nothing is open, nothing is focused, nothing is selected, no click is
  // waiting on its answer, and the last pointer or key activity is a few
  // seconds old. A tab left in the background refreshes the moment it is
  // looked at again instead of on its timer. A window that created something
  // asks for it at once when it closes (`refresh(true)`), which skips the
  // idle wait and nothing else.
  var REFRESH_MS=60000, IDLE_MS=5000;
  var lastActivity=Date.now(), freshAt=Date.now();
  ['pointerdown','keydown','wheel','touchstart'].forEach(function(kind){
    document.addEventListener(kind,function(){lastActivity=Date.now()},
                              {passive:true})});
  var busy=function(){
    if(document.querySelector('.rmenu.on'))return true;
    var a=document.activeElement;
    // A field somebody may be typing in. Not a radio or a checkbox: every
    // tab, every row that opens and every range pill is a label over a hidden
    // one, and in Chrome a click on the label leaves that input focused, so
    // one click on a tab stopped the quiet refresh until the next click on
    // plain page (measured 2026-09-21, docs/RECORD.md 4.199). `holdsEdits`
    // leaves them out for the same reason.
    var typing=a&&(a.tagName==='TEXTAREA'||a.tagName==='SELECT'||
      (a.tagName==='INPUT'&&a.type!=='radio'&&a.type!=='checkbox'));
    if(typing)return true;
    var sel=window.getSelection&&window.getSelection();
    if(sel&&String(sel).length)return true;
    if(inflight)return true;
    return Date.now()-lastActivity<IDLE_MS;
  };
  // The rows of one list, in the server's order. A row that changed is
  // swapped, a new one is put in, a gone one is taken out, and the rest are
  // left exactly as they are. `carry` copies what the script owns on a row
  // (the filter button that is on) onto its replacement.
  var mergeList=function(prefix,liveList,freshList,sel,keyOf,carry){
    if(!liveList||!freshList)return false;
    var changed=false, have={}, order=[];
    liveList.querySelectorAll(sel).forEach(function(el){have[keyOf(el)]=el});
    freshList.querySelectorAll(sel).forEach(function(el){
      var k=keyOf(el), old=have[k];
      delete have[k];
      if(old&&baseline[prefix+k]===el.outerHTML){order.push(old);return}
      baseline[prefix+k]=el.outerHTML;
      if(old){if(carry)carry(old,el);liveList.replaceChild(el,old)}
      else liveList.appendChild(el);
      order.push(el);changed=true;
    });
    Object.keys(have).forEach(function(k){
      liveList.removeChild(have[k]);delete baseline[prefix+k];changed=true});
    // Moved only when the order moved, so an untouched list is not touched.
    var now=Array.prototype.slice.call(liveList.querySelectorAll(sel));
    if(now.some(function(el,i){return el!==order[i]})){
      order.forEach(function(el){liveList.appendChild(el)});changed=true}
    return changed;
  };
  var apply=function(doc){
    var changed=false;
    var pieces=regionsOf(doc);
    // The Fleet with no server is a box where the table would be, and the
    // Fleet with one is a search field and a table. The rows are merged into
    // the table on the screen (mergeList, below), so a workspace's first
    // server had no table to go into and showed only after a reload, and the
    // last one's going left an empty table (docs/RECORD.md 4.297). When the
    // server's Fleet has a table and the screen's has none, or the other way
    // round, the Fleet is swapped whole, the way a server's page is when its
    // shape changes. Before everything else here, because a new server's
    // page is put in after the Fleet that is on the screen.
    var fleetNow=document.getElementById('fleet'), fleetNext=doc.getElementById('fleet');
    if(fleetNow&&fleetNext&&
       !!fleetNow.querySelector('.ftbl')!==!!fleetNext.querySelector('.ftbl')){
      // Every piece of the new Fleet is as the server sent it, so the loops
      // below find nothing left to do in it. A row that is gone is forgotten.
      Object.keys(baseline).forEach(function(k){
        if(k.indexOf('row:')===0)delete baseline[k]});
      pieces.forEach(function(r){
        if(fleetNext.contains(r[1]))baseline[r[0]]=r[1].outerHTML});
      // Whichever screen is showing stays the one that shows.
      fleetNext.classList.toggle('on',fleetNow.classList.contains('on'));
      fleetNow.parentNode.replaceChild(fleetNext,fleetNow);
      changed=true;
    }
    // A server's page comes and goes with the server. A new one goes in after
    // the last, which is where the render puts it, and the page of a server
    // that is gone goes with it: if it was the one on the screen, the fleet is
    // what is left, the same as a stale link lands on.
    var keep={};
    doc.querySelectorAll('.view[id^="host-"]').forEach(function(v){keep[v.id]=true});
    document.querySelectorAll('.view[id^="host-"]').forEach(function(v){
      if(keep[v.id])return;
      var on=v.classList.contains('on');
      v.parentNode.removeChild(v);
      if(on)applyPath('/','replace');
      changed=true;
    });
    var after=document.getElementById('fleet');
    doc.querySelectorAll('.view[id^="host-"]').forEach(function(v){
      var old=document.getElementById(v.id);
      if(!old){
        hostPieces(v).forEach(function(p){baseline[p[0]]=p[1].outerHTML});
        after.parentNode.insertBefore(v,after.nextSibling);
        after=v;changed=true;return;
      }
      after=old;
      // A page whose shape changed, which is a first document turning one
      // panel into tabs. Swapped whole, and the tabs start on the first.
      var was=hostPieces(old), now=hostPieces(v);
      var key=function(p){return p[0]};
      if(was.map(key).join('|')===now.map(key).join('|'))return;
      if(holdsEdits(old))return;
      now.forEach(function(p){baseline[p[0]]=p[1].outerHTML});
      if(old.classList.contains('on'))v.classList.add('on');
      old.parentNode.replaceChild(v,old);
      changed=true;
    });
    // The count beside Alerts, compared with what the server said last time
    // and never with the screen: Silence and Pause take the count down on
    // the click, and an answer older than that click still carries the old
    // count, which must not put it back up. The server's own mark is moved
    // in, so the count is drawn by the builder and by nothing here.
    var count=alertsCount(doc);
    if(count!==baseline['count:alerts']){
      baseline['count:alerts']=count;
      var entry=document.querySelector('.nav a[data-v="alerts"]');
      var mark=entry&&entry.querySelector('.nb');
      var fresh=doc.querySelector('.nav a[data-v="alerts"] .nb');
      if(mark)mark.remove();
      if(entry&&fresh)entry.appendChild(fresh);
    }
    pieces.forEach(function(r){
      var key=r[0], el=r[1];
      if(key.indexOf('row:')===0)return;
      if(baseline[key]===el.outerHTML)return;
      var old=liveFor(key);
      // It came in with its whole screen, further up: a new server's page
      // brings its first-look window along. Noted as what the server said.
      if(old===el){baseline[key]=el.outerHTML;return}
      if(!old||holdsEdits(old))return;
      baseline[key]=el.outerHTML;
      if(old.classList.contains('on'))el.classList.add('on');
      var chosen=choicesOf(old);
      old.parentNode.replaceChild(el,old);
      keepChoices(chosen,el);
      changed=true;
    });
    var fleet=document.getElementById('fleet'), freshFleet=doc.getElementById('fleet');
    if(fleet&&freshFleet){
      changed=mergeList('row:',fleet.querySelector('.ftbl'),freshFleet.querySelector('.ftbl'),
        '.row[data-host]',function(r){return r.dataset.host},null)||changed;
    }
    if(changed){wire();applyFleet()}
  };
  var refreshing=false, again=false;
  var refresh=function(force){
    if(refreshing){again=again||!!force;return}
    if(document.hidden)return;
    if(document.querySelector('.ovl.on'))return;
    if(!force&&busy())return;
    refreshing=true;
    var started=Date.now();
    fetch(location.pathname,{cache:'no-store'})
    .then(function(r){
      // Signed out meanwhile: the answer is the login page, and that is
      // where this browser belongs.
      if(r.redirected){location.href=r.url;return ''}
      return r.ok?r.text():'';
    })
    .then(function(text){
      refreshing=false;
      // A click was handled while this answer was on its way, and the answer
      // may not know about it yet. Thrown away rather than painted over what
      // the click already showed; the next one carries it.
      // **`<=` and not `<`, since 2026-09-21.** Every action that calls
      // refresh(true) does so from its POST's own then, and the fetch wrapper
      // above stamps `touched` when that POST settles, in the same
      // millisecond this refresh reads `started`. With `<` that answer was
      // thrown away nearly every time, measured 60 of 60, so a click painted
      // its own control and the rest of the page waited for the minute tick:
      // the fleet row after Pause, a provider's status after Connect, the
      // Channels panel after a workspace's first channel (docs/RECORD.md
      // 4.199). A POST that settled before this refresh began is one its
      // answer already knows about. One that settles after it still has a
      // later stamp, and is still thrown away.
      if(text&&touched<=started&&(force||!busy())){
        apply(new DOMParser().parseFromString(text,'text/html'));
        freshAt=Date.now();
      }
      if(again){again=false;refresh(true)}
    })
    .catch(function(){refreshing=false});
  };
  setInterval(refresh,REFRESH_MS);
  document.addEventListener('visibilitychange',function(){
    if(!document.hidden&&Date.now()-freshAt>REFRESH_MS)refresh();
  });
  // A fleet row and an open alert's row both go to the server they name. One
  // handler for both: an alert row's stretched button carries the same
  // data-host, so the way to a server is written once.
  onWire(function(){
  document.querySelectorAll('.row[data-host],.rowgo[data-host],.al[data-host]').forEach(function(r){
    r.onclick=function(e){
      // A fleet row is a real link to /host/<name>, so a page whose script
      // did not run still leads somewhere. With the script it opens in place.
      if(e&&e.preventDefault)e.preventDefault();
      if(document.getElementById('host-'+r.dataset.host)){
        goto('host-'+r.dataset.host);
      }else{
        var hn=document.getElementById('host-name');
        if(hn)hn.textContent=r.dataset.host;
        goto('host');
      }
    }});
  document.querySelectorAll('.js-act').forEach(function(b){
  // closeMenus is assigned further down and this runs on a click, so it is
  // there by then. A stub inside a menu has to close the menu it was picked
  // from, or the sample shell leaves one hanging open behind its toast.
  // The press is for this control alone. One that stands in a row which is
  // itself a way to another screen, as Silence does on an open alert, must
  // not take the reader there as well.
  b.onclick=function(e){e.stopPropagation();closeMenus();toast(b.dataset.msg)}});
  });
  // .js-pause is excluded because it has its own handler further down that
  // also tells the server. If this generic visual toggle fired for it too, one
  // click would flip the switch twice and it would land where it started.
  onWire(function(){
  document.querySelectorAll('.sw:not(:disabled):not(.js-pause)').forEach(function(s){
    s.onclick=function(){s.classList.toggle('off')}});
  });
  var srch=document.querySelector('#fleet .srch');
  var applyFleet=function(){
    var q=(srch&&srch.value?srch.value:'').toLowerCase();
    document.querySelectorAll('#fleet .row').forEach(function(r){
      // The row's text, and the name the server is found by: a row with a
      // display name prints the display name and the hostname, and typing
      // the name from the address bar must still find it.
      var okText=!q||r.textContent.toLowerCase().indexOf(q)>-1
        ||(r.dataset.host||'').toLowerCase().indexOf(q)>-1;
      r.style.display=okText?'':'none'})};
  onWire(function(){
  document.querySelectorAll('.seg button').forEach(function(b){
    b.onclick=function(){b.parentNode.querySelectorAll('button').forEach(function(o){
      o.classList.remove('on')});b.classList.add('on')}});
  });
  if(srch){srch.addEventListener('input',applyFleet)}
  // ---- the banner: dismissed per browser, until the fact changes ----
  //
  // A note carries data-note, the fact's own id (its source and its value),
  // and dismissing it stores that id in this browser. The same fact stays
  // hidden here, a new fact shows again, and an id whose note is gone from
  // the page is forgotten so the list cannot grow (the owner, 2026-09-05,
  // answer 2). No write to the server, no table.
  var NOTES_KEY='wp-notes-dismissed';
  var dismissed=function(){
    try{return JSON.parse(localStorage.getItem(NOTES_KEY)||'[]')}catch(e){return []}};
  var applyNotes=function(){
    var gone=dismissed(), present=[];
    document.querySelectorAll('#fleet .fnote').forEach(function(n){
      present.push(n.dataset.note);
      n.hidden=gone.indexOf(n.dataset.note)>-1});
    var keep=gone.filter(function(k){return present.indexOf(k)>-1});
    try{localStorage.setItem(NOTES_KEY,JSON.stringify(keep))}catch(e){}
    // An action on a note goes where it says.
    document.querySelectorAll('#fleet .fnote [data-go]').forEach(function(b){
      b.onclick=function(){goto(b.dataset.go)}});
    document.querySelectorAll('#fleet .fnote .x').forEach(function(x){
      x.onclick=function(){
        var n=x.closest('.fnote'), keys=dismissed();
        if(keys.indexOf(n.dataset.note)<0)keys.push(n.dataset.note);
        try{localStorage.setItem(NOTES_KEY,JSON.stringify(keys))}catch(e){}
        n.hidden=true}});
  };
  onWire(applyNotes);
  var pmBtn=document.getElementById('pm-btn');
  if(pmBtn){
    var pmMenu=document.getElementById('pm-menu');
    // What was chosen: dark, light, or system, which follows the browser.
    // Nothing chosen is dark, the page's own look. The head script applied
    // the choice before the first paint; this is the same reading.
    var chosenMode=function(){
      var m='';try{m=localStorage.getItem('wp-mode')||''}catch(e){}
      return m==='light'||m==='system'?m:'dark';
    };
    var applyMode=function(){
      var h=document.documentElement, m=chosenMode();
      var light=m==='light'||(m==='system'&&window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches);
      if(light)h.dataset.mode='light';else h.removeAttribute('data-mode');
    };
    var markMode=function(){
      var light=document.documentElement.dataset.mode==='light';
      document.getElementById('mode-light').classList.toggle('on',light);
      document.getElementById('mode-dark').classList.toggle('on',!light);
    };
    var setMode=function(m){
      try{if(m==='dark')localStorage.removeItem('wp-mode');else localStorage.setItem('wp-mode',m)}catch(e){}
      applyMode();
      markMode();
    };
    // The Settings page carries the same choice as a three-way control, so
    // the page and the menu are one behaviour rather than two that can drift.
    var markModeAll=function(){
      var m=chosenMode();
      ['dark','light','system'].forEach(function(k){
        document.querySelectorAll('.js-mode-'+k).forEach(function(b){b.classList.toggle('on',m===k)})});
    };
    var _markMode=markMode; markMode=function(){_markMode();markModeAll()};
    markMode();
    if(window.matchMedia){
      window.matchMedia('(prefers-color-scheme: light)').addEventListener('change',function(){
        if(chosenMode()==='system'){applyMode();markMode()}});
    }
    document.getElementById('mode-light').onclick=function(e){e.stopPropagation();setMode('light')};
    document.getElementById('mode-dark').onclick=function(e){e.stopPropagation();setMode('dark')};
    // Inside a wire pass, and registered after the `.seg button` pass above,
    // which assigns onclick on every segmented button on every refresh. Set
    // once, outside, this was replaced by that pass at the first quiet
    // refresh, and Dark, Light and System moved their highlight and changed
    // nothing (measured 2026-09-21, docs/RECORD.md 4.199).
    onWire(function(){
    ['dark','light','system'].forEach(function(k){
      document.querySelectorAll('.js-mode-'+k).forEach(function(b){
        b.onclick=function(){setMode(k)}})});
    });
    // The chip's letters, from what the account actually holds. A stored
    // name gives the first letter of its first two words. Without one the
    // email's local part does, split on the separators addresses use, so
    // robin.sample gives two letters and a bare robin gives one. Only a
    // letter or a digit counts, so the chip never shows punctuation, and an
    // answer with nothing usable leaves the neutral glyph in place.
    var chipInitials=function(name,email){
      var from=function(parts){
        var out='';
        for(var i=0;i<parts.length&&out.length<2;i++){
          var m=parts[i].match(/[A-Za-z0-9]/);
          if(m)out+=m[0];
        }
        return out;
      };
      var got=from((name||'').trim().split(/\s+/).filter(Boolean));
      if(!got)got=from(((email||'').split('@')[0]||'').split(/[._-]+/).filter(Boolean));
      return got.toUpperCase();
    };
    // Who is signed in, asked of the control plane: the app session when
    // there is one, else the name the edge authenticated, else empty.
    // Empty means nobody the app can name, and the menu then says only
    // "Signed in" rather than showing a guess or a template. Asked once,
    // when the page loads, so the chip is already right before the menu is
    // ever opened. dataset.asked keeps the click path from asking again.
    // The account Settings screen's facts, from the same answer
    // (docs/screens/account-settings): the name and the workspace's name in
    // their fields, the email in mono, when the password was last set, and
    // whether the authenticator app is on. textContent and value, never
    // markup: every one of these is somebody's own text.
    var whenText=function(iso){
      if(!iso)return '';
      var d=new Date(iso);
      if(isNaN(d.getTime()))return '';
      return 'changed '+d.getDate()+' '+['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][d.getMonth()]+' '+d.getFullYear();
    };
    var fillSettings=function(j){
      var name=(j&&j.name)||'', u=(j&&j.user)||'', ws=(j&&j.workspace)||'';
      document.querySelectorAll('.js-who-name').forEach(function(i){i.value=name;i.defaultValue=name});
      document.querySelectorAll('.js-who-email').forEach(function(e){e.textContent=name?u:(e.classList.contains('kv')?u:'')});
      document.querySelectorAll('.js-who-name-text').forEach(function(e){e.textContent=name||u});
      document.querySelectorAll('.js-who-pwd').forEach(function(e){e.textContent=whenText(j&&j.password_changed_at)});
      var totpOn=!!(j&&j.totp);
      document.querySelectorAll('.js-who-totp').forEach(function(b){b.classList.toggle('off',!totpOn)});
      // Turn on opens the screen that does it, and is not offered to an
      // account that already has it on.
      document.querySelectorAll('.js-2fa-on').forEach(function(b){b.hidden=totpOn});
      document.querySelectorAll('.js-wsname').forEach(function(i){i.value=ws;i.defaultValue=ws});
    };
    var fillWho=function(){
      if(pmBtn.dataset.asked)return;
      pmBtn.dataset.asked='1';
      var quiet=function(){document.querySelector('.pm-who').textContent='Signed in'};
      fetch('/api/admin/whoami',{cache:'no-store'}).then(function(r){return r.json()})
      .then(function(j){
        var u=(j&&j.user)||'';
        if(!u){quiet();return}
        document.getElementById('pm-user').textContent=u;
        fillSettings(j);
        var init=chipInitials((j&&j.name)||'',u);
        if(init)pmBtn.textContent=init;
      }).catch(quiet);
    };
    fillWho();
    pmBtn.onclick=function(e){
      e.stopPropagation();
      pmMenu.hidden=!pmMenu.hidden;
      fillWho();
    };
    document.addEventListener('click',function(e){
      if(!pmMenu.hidden&&!e.target.closest('.pm'))pmMenu.hidden=true});
    document.getElementById('pm-signout').onclick=function(){
      // The app revokes the session server side and clears its cookie, then
      // the login page is where a signed-out browser belongs. POST, for the
      // same reason /logout is POST only: a bare link must not sign somebody
      // out. If the sign-out did not happen, /login bounces a still-live
      // session straight back to the dashboard, so what renders next is
      // honest either way. Caddy's outer basic auth is a separate layer: the
      // browser keeps that credential until the forward_auth migration in
      // ops/RUNBOOK.md retires it.
      fetch('/api/admin/signout',{method:'POST',cache:'no-store'})
      .catch(function(){})
      .then(function(){location.href='/login'});
    };
    document.querySelectorAll('.js-signout').forEach(function(b){
      b.onclick=function(){
        fetch('/api/admin/signout',{method:'POST',cache:'no-store'})
        .catch(function(){}).then(function(){location.href='/login'});
      }});
  }
  // Every modal built by modal_shell(): a trigger names its overlay in
  // data-open, anything with data-close closes that overlay, and a pick card
  // names the stage it reveals in data-stage. A planned card carries neither
  // the pick class nor a data-stage and is disabled, so no selector here
  // matches it and the browser refuses the click as well.
  onWire(function(){
  document.querySelectorAll('[data-open]').forEach(function(t){
    t.onclick=function(){
      var o=document.getElementById(t.dataset.open);
      if(!o)return;
      // Every open starts clean, so the first card you pick is a real choice.
      o.querySelectorAll('.m-card').forEach(function(c){
        c.classList.remove('sel');
        // **And every open leaves edit mode.** A window opened on Edit locks
        // every card but its own and renames its own heading, and both survive
        // a close, so an Add opened afterwards would still be editing the row
        // the operator looked at ten minutes ago.
        c.classList.remove('m-locked');
      });
      o.querySelectorAll('.m-stage').forEach(function(s){s.classList.remove('on')});
      // **And every kind is on again**, as the server draws the window. Edit
      // sets these switches to what one channel takes, and they stayed that
      // way after a close, so the window opened to add with another channel's
      // choice (measured 2026-10-04, docs/RECORD.md 4.362). Edit sets its
      // own after this, from what is stored.
      o.querySelectorAll('.sw.js-event').forEach(function(sw){sw.classList.remove('off')});
      if(o.dataset.editing){
        o.dataset.editing='';
        var h=o.querySelector('.m-h h2');
        if(h&&o.dataset.title)h.textContent=o.dataset.title;
      }
      o.classList.add('on');
    }});
  document.querySelectorAll('[data-close]').forEach(function(t){
    t.onclick=function(){
      var o=document.getElementById(t.dataset.close);
      if(o)o.classList.remove('on');
    }});
  });
  document.querySelectorAll('.ovl.js-modal').forEach(function(o){
    o.addEventListener('click',function(e){if(e.target===o)o.classList.remove('on')})});
  // Escape closes the window that is open. Nine windows did not answer the
  // key (measured 2026-10-04, docs/RECORD.md 4.362). The key presses the
  // window's own cross, so a window does on the key exactly what it does on
  // a click: the Add server window asks for the page when it made a server.
  // The confirm dialog is left to itself, since it answers the key already.
  document.addEventListener('keydown',function(e){
    if(e.key!=='Escape')return;
    var open=document.querySelectorAll('.ovl.on');
    if(!open.length)return;
    var top=open[open.length-1];
    if(top.id==='ask')return;
    var cross=top.querySelector('.m-x');
    if(cross)cross.click();
  });
  document.querySelectorAll('.m-card.pick[data-stage]').forEach(function(c){
    c.onclick=function(){
      // A locked card is one the window is not offering right now, which is
      // every card but one while a row is being edited. The class is not the
      // check on its own, so the handler refuses as well: changing a channel's
      // type would change what its destination has to look like and what its
      // delivery key is built from.
      if(c.classList.contains('m-locked'))return;
      var o=c.closest('.ovl');
      o.querySelectorAll('.m-card').forEach(function(x){x.classList.remove('sel')});
      o.querySelectorAll('.m-stage').forEach(function(s){
        s.classList.toggle('on',s.id===c.dataset.stage)});
      c.classList.add('sel');
    }});
  // ---- a configured channel's row menu ----
  // One open at a time, and a click anywhere else closes it. Both are the
  // same rule: a menu left open behind another one is a menu whose next click
  // acts on a row you stopped looking at.
  var closeMenus=function(){
    document.querySelectorAll('.rmenu.on').forEach(function(m){m.classList.remove('on')});
  };
  // Every menu trigger on the page, matched on data-menu rather than on the
  // dots class, because the Mute control opens the same menu from a labelled
  // button. One rule for one shape.
  // Each of the handlers a channel row carries is a named function taking one
  // element, because a row added on this page has to be given the same ones. A
  // page-wide pass runs here and `wireChannelRow` below runs them again inside
  // one new row.
  var bindMenu=function(t){
    t.onclick=function(e){
      e.stopPropagation();
      var mine=t.closest('.rmenu'), was=mine.classList.contains('on');
      closeMenus();
      if(!was)mine.classList.add('on');
    }};
  onWire(function(){document.querySelectorAll('[data-menu]').forEach(bindMenu)});
  document.addEventListener('click',closeMenus);
  var bindPanel=function(pnl){
    pnl.onclick=function(e){e.stopPropagation()}};
  onWire(function(){document.querySelectorAll('.rm-p').forEach(bindPanel)});
  // ---- the Add window on Integrations ----
  // One window for everything a workspace connects
  // (docs/screens/alerts/SPEC-layout-b.md), in three steps that stay in view,
  // each under the one before: a kind, that kind's cards, the picked card's
  // own fields. Its cards name their step in data-kind and data-fields and
  // not in data-stage, so the shared picker above, which shows one step at a
  // time, leaves them alone.
  var chatValue=function(chat,thread){
    if(!chat)return '';
    var c=chat.value.trim(), t=thread?thread.value.trim():'';
    return t?c+':'+t:c;
  };
  // Every switch on the page, including the ones in Advanced settings. A
  // switch is a button that carries its state as a class, so this is the one
  // place that flips it.
  document.querySelectorAll('.sw.js-event').forEach(function(sw){
    sw.onclick=function(){sw.classList.toggle('off')}});
  var connOvl=document.getElementById('conn-ovl');
  var connGo=document.getElementById('conn-go');
  var connCancel=document.getElementById('conn-cancel');
  var connErr=document.getElementById('conn-err');
  // The fields that are showing, or null before a built card is picked.
  var connFields=function(){
    return connOvl?connOvl.querySelector('.m-stage.on[data-type]'):null;
  };
  // ---- a refusal at its field ----
  // A refusal stands under the field it is about, says what that field must
  // be, and is gone when the field is edited (docs/RECORD.md 4.228: a bot
  // token and a chat id typed into each other's field were refused by one
  // line at the foot of the window, which named no field).
  //
  // Each field of a destination names its own line in aria-describedby and
  // carries its check: what it must look like in data-pattern, and the words
  // for each reason it can be refused for in data-says-<reason>
  // (site/app/build.py, CHANNEL_CHECKS). The words are this page's own.
  // Nothing the server wrote is printed here and nothing typed is repeated.
  var CHECKED='input[data-pattern]';
  // Every field of the window that has a line of its own under it: each
  // destination's, and a provider's, whose one refusal the page makes itself
  // is an empty token.
  var LINED='input[aria-describedby]';
  var fieldLine=function(input){
    return document.getElementById(input.getAttribute('aria-describedby')||'');
  };
  var refuseField=function(input,words){
    var line=fieldLine(input);
    if(line)line.textContent=words;
    input.setAttribute('aria-invalid','true');
  };
  var clearField=function(input){
    var line=fieldLine(input);
    if(line)line.textContent='';
    input.removeAttribute('aria-invalid');
  };
  // What was typed into the window, in every step: each field of each
  // destination and of each provider.
  var connEmpty=function(){
    connOvl.querySelectorAll('.m-stage[data-type] input').forEach(function(input){input.value=''});
  };
  // Every refusal in the window: each field's own, and the line at the foot.
  var connClear=function(){
    connOvl.querySelectorAll(LINED).forEach(clearField);
    connErr.textContent='';
  };
  // What is about no field is said in the one line above the foot. On a
  // step taller than the window that line stands under the fold, so the
  // window's content is brought to its end, which is where the line is
  // (measured at 900 px high on the Telegram step: a refusal was said there
  // and could not be seen without scrolling).
  var sayAtFoot=function(words){
    connErr.textContent=words;
    var box=connOvl.querySelector('.modal');
    if(box)box.scrollTop=box.scrollHeight;
  };
  // Why this field is refused, by the reason's name, or '' when it fits.
  // Trimmed first, because the server trims what it is sent.
  var fieldReason=function(input){
    var value=input.value.trim();
    if(!value)return input.hasAttribute('data-optional')?'':'missing';
    var longest=Number(input.dataset.longest||0);
    if(longest&&value.length>longest)return 'shape';
    return new RegExp(input.dataset.pattern).test(value)?'':'shape';
  };
  // Every field of the step is checked and not only the first, so two values
  // typed into each other's field are both shown at once. Answers with the
  // fields it refused, in the order they stand.
  var checkFields=function(stage){
    var refused=[];
    stage.querySelectorAll(CHECKED).forEach(function(input){
      var reason=fieldReason(input);
      if(!reason){clearField(input);return}
      refuseField(input,input.getAttribute('data-says-'+reason));
      refused.push(input);
    });
    return refused;
  };
  // **The server decides, and this page's check is a convenience**, so a
  // save the check let through can still be refused. The answer names the
  // field and the reason as two fixed words (controlplane/app/channels.py,
  // FIELDS and REASONS), and the line shown is this page's own for that
  // pair. An answer this page has no line for, whatever it holds, says only
  // that it did not work: the server's own sentence is written for a
  // terminal and is not shown.
  var refusedByServer=function(stage,status,answer){
    var found=null, words='';
    // A field with no name is no field: the topic has none of its own, since
    // it travels inside the chat id, and must not answer to an empty one.
    if(answer.field&&typeof answer.field==='string'&&typeof answer.reason==='string')
      stage.querySelectorAll(CHECKED).forEach(function(input){
        if(found||input.dataset.wire!==answer.field)return;
        var said=input.getAttribute('data-says-'+answer.reason);
        if(said){found=input;words=said}
      });
    if(!found){sayAtFoot(didNotWork(status));return}
    refuseField(found,words);
    found.focus();
  };
  // Which kind those fields belong to: the kind whose cards hold the card
  // that names them. Matched on the attribute, never through a selector
  // built from it.
  var connKind=function(){
    var stage=connFields(), kind='';
    if(!stage)return '';
    connOvl.querySelectorAll('.m-card[data-fields]').forEach(function(c){
      if(c.dataset.fields===stage.id)kind=c.closest('.m-kind').id.slice(5);
    });
    return kind;
  };
  // Slack hands its own webhook over, so while its step is picked the action
  // reads Connect to Slack and leaves for Slack (the owner, 2026-08-23 and
  // 2026-08-24: the button replaces the save, and those are its words).
  //
  // **An edit is never a connect.** The connect flow writes a row of its own,
  // and an edit is open on one that already exists, so a connect there would
  // leave the operator with two rows and no way to tell which one Slack posts
  // through.
  var slackConnect=function(){
    var stage=connFields();
    return !!stage&&stage.dataset.type==='slack'&&!connOvl.dataset.editing;
  };
  // The foot, from what is showing. Cancel alone is the primary button until
  // there are fields to act on. Then the action is, with Cancel plain beside
  // it. So there is one primary button at every step, and no action before
  // there is something to act on.
  var connFoot=function(){
    if(!connOvl)return;
    var kind=connKind();
    connGo.hidden=!kind;
    connCancel.className=kind?'btn':'btn pri';
    if(kind)connGo.textContent=slackConnect()?'Connect to Slack':connGo.dataset[kind];
  };
  // Saving a destination: the request the Add channel window made, to the
  // same route, with the same body.
  var saveDestination=function(stage){
    // A step with no field of its own has no destination to send, and Slack
    // is that step. Read the field's absence rather than the type, so a step
    // that loses its field later takes this path too.
    var destField=stage.querySelector('.js-dest');
    var dest=destField?destField.value.trim():'';
    var chat=stage.querySelector('.js-chat');
    var thread=stage.querySelector('.js-thread');
    // Each field of the step against its own check, each refusal at its own
    // field. A step with no field has nothing to refuse.
    var refused=checkFields(stage);
    // Every switch on means every kind, which is what the control plane
    // stores for "all of them" (controlplane/app/channels.py). Every switch
    // off is the one answer that cannot be stored, because a channel that
    // hears nothing is a row that exists and can never deliver, so it is
    // refused here rather than saved as its opposite. It is about no field,
    // so it stands at the foot, and beside a refused field both are said.
    var events=Array.prototype.filter.call(
      connOvl.querySelectorAll('.js-event'),
      function(b){return !b.classList.contains('off')})
      .map(function(b){return b.dataset.kind});
    var noKind=events.length?'':'Switch on at least one kind.';
    connErr.textContent=noKind;
    // The cursor goes to the first field refused, where the typing resumes.
    if(refused.length){refused[0].focus();return}
    if(noKind){sayAtFoot(noKind);return}
    connGo.disabled=true;
    // An edit reuses this window, so the same Save writes to the row it was
    // opened on instead of creating one.
    var editing=connOvl.dataset.editing||'';
    // **Editing a step with no field changes which kinds it takes, and
    // nothing else.** A Slack row's destination came back from Slack and is
    // not on this page, so posting it to /destination would send an empty
    // string and the control plane would refuse it. /events is the route
    // that writes only the switches (controlplane/app/ingest.py), so the
    // stored webhook is left exactly as it is and the row cannot be broken
    // from here.
    var kindsOnly=!!editing&&!destField;
    var url='/api/admin/channels';
    if(editing)
      url+='/'+encodeURIComponent(editing)+(kindsOnly?'/events':'/destination');
    var body=kindsOnly
      ?{events:events}
      :{type:stage.dataset.type,
         // chat and topic are one field on the row, written chat:thread,
         // because one topic is one destination and the delivery key is
         // built from this value (controlplane/app/alerts.py).
         destination:dest,
         chat_id:chatValue(chat,thread),
         events:events};
    // **An edit that carries a destination is said saved only when the
    // answer holds the kinds that were sent.** The route answers the kinds
    // the row takes as stored, each named. It once wrote the address alone
    // and answered 200, and this window said saved over a row that still
    // took every kind (the second big test, finding E20). The kinds-only
    // path answers 204, which is its own word that it wrote them.
    var keptKinds=function(j){
      if(!j||!Array.isArray(j.events))return false;
      var stored=j.events.slice().sort().join(','), sent=events.slice().sort().join(',');
      return stored===sent;
    };
    var saved=function(j){
      if(editing&&!kindsOnly&&!keptKinds(j)){sayAtFoot(KINDS_NOT_SAVED);return}
      connOvl.classList.remove('on');
      // What was typed is a webhook's address or a bot's token. It is
      // stored now, so it is not left in the field for the next time the
      // window opens on this step.
      stage.querySelectorAll(CHECKED).forEach(function(input){input.value=''});
      // The list says what happened, which is the whole point of the
      // click. `addChannelRow` and `editChannelRow` are further down, with
      // the row handlers they hand a new row.
      //
      // A workspace's first destination has no table to go into: the
      // section shows its one empty line, or the page its one box. So the
      // page asks for itself and the table arrives with the row in it.
      // Without this the first one showed only after a reload (the owner,
      // 2026-09-20).
      var first=!document.querySelector('.chanp .crow');
      if(editing)editChannelRow(editing,j,kindsOnly?events:j.events);
      else if(first)refresh(true);
      else if(j)addChannelRow(j);
      // The window closing is the confirmation. Both of these used to name
      // our own machinery, the render on one branch and the sweep on the
      // other, which is the thing a customer can neither use nor act on
      // (the rule for customer screens).
      toast(editing?'Saved.':'Destination added.');
    };
    fetch(url,{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(body)})
      .then(function(r){
        // A refusal. Its body may be no JSON at all, the page of a proxy in
        // front of the server is not, and then there is no field to read.
        if(!r.ok)
          return r.json().catch(function(){return {}}).then(function(j){
            refusedByServer(stage,r.status,j||{});
          });
        // A save with nothing to say answers 204, which is the kinds-only
        // path. Everything else that saved answers with the row as it now
        // stands, and a body that cannot be read is not turned into a
        // failure, because the save did happen.
        var row=r.status===204?null:r.json().catch(function(){return null});
        return Promise.resolve(row).then(saved);
      },function(){
        // No answer at all. Said in this page's words, as everywhere else on
        // it, and never in the browser's.
        sayAtFoot(NO_ANSWER);
      })
      .then(function(){connGo.disabled=false},function(){connGo.disabled=false});
  };
  if(connOvl){
    connOvl.querySelectorAll('.m-card[data-kind]').forEach(function(c){
      c.onclick=function(){
        // An edit is about one row, so its kind is not a choice: the other
        // kinds are locked and a click on its own changes nothing.
        if(c.classList.contains('m-locked')||connOvl.dataset.editing)return;
        connOvl.querySelectorAll('.m-card').forEach(function(x){x.classList.remove('sel')});
        // The other kind's cards go, and so do any fields that were showing.
        connOvl.querySelectorAll('.m-stage').forEach(function(s){
          s.classList.toggle('on',s.id==='conn-'+c.dataset.kind)});
        c.classList.add('sel');
        connClear();
        connFoot();
      }});
    connOvl.querySelectorAll('.m-card.pick[data-fields]').forEach(function(c){
      c.onclick=function(){
        // A locked card is one the window is not offering right now, which is
        // every card but one while a row is being edited: changing a
        // channel's type would change what its destination has to look like
        // and what its delivery key is built from.
        if(c.classList.contains('m-locked'))return;
        var cards=c.closest('.m-kind');
        cards.querySelectorAll('.m-card').forEach(function(x){x.classList.remove('sel')});
        connOvl.querySelectorAll('.m-stage').forEach(function(s){
          if(s===cards)return;
          // Advanced settings belong to every destination and to nothing else.
          s.classList.toggle('on',s.id===c.dataset.fields||
            (s.id==='chan-adv'&&cards.id==='conn-dest'))});
        c.classList.add('sel');
        connClear();
        connFoot();
      }});
    // Opening the window starts it clean (the shared opener above), so the
    // foot is painted again after it. Heard on the document, because a button
    // that opens the window is drawn again whenever the page asks for itself,
    // and the opener's own handler has run by the time a click gets here.
    //
    // **Closing it takes every refusal with it**, by Cancel, by the cross,
    // by Escape, which presses the cross, and by a click beside the window.
    // A refusal is about what was typed while the window was open, and is
    // not kept for the next time.
    //
    // **Cancel and Escape also empty what was typed**, and so does the
    // cross that Escape presses: each is a person saying no. A click beside
    // the window closes it and keeps what was typed, because that one is a
    // slip of the hand as often as not, and a pasted address is not lost to
    // it (docs/RECORD.md 4.228).
    document.addEventListener('click',function(e){
      var t=e.target&&e.target.closest?e.target.closest('[data-open="conn-ovl"]'):null;
      if(t){connClear();connFoot();return}
      var out=e.target&&e.target.closest?e.target.closest('[data-close="conn-ovl"]'):null;
      if(out)connEmpty();
      if(out||e.target===connOvl)connClear();
    });
    // A refusal is gone when its field is edited, and only that field's.
    connOvl.addEventListener('input',function(e){
      if(e.target&&e.target.matches&&e.target.matches(LINED))clearField(e.target);
    });
    connGo.onclick=function(){
      var stage=connFields(), kind=connKind();
      if(!stage)return;
      // The sample shell has no server behind it, so the action says what it
      // would do, as every other control there does.
      if(connGo.dataset.sample){
        connOvl.classList.remove('on');
        toast(kind==='prov'?'The provider would be connected here':'The destination would be saved here');
        return;
      }
      if(slackConnect()){
        location.href='/api/admin/channels/slack/connect';
        return;
      }
      if(kind==='prov')connectProvider(stage);
      else saveDestination(stage);
    };
  }
  // ---- what a row's menu does ----
  // Enable, disable and delete write the row, and each paints its own result
  // at once. The page behind it is rendered from the database on every
  // request, so the next reload agrees with what was painted.
  // The three acts this handler has a route for, listed rather than trusted
  // from the attribute. Edit carries data-act="edit" and opens the window
  // instead of posting, so it is not in this class today, and a change that put
  // it here would otherwise post to a path the control plane does not serve.
  // That mismatch already happened once between this screen and #296.
  var POSTABLE={remove:'deleted',disable:'disabled',enable:'enabled'};
  // **The row changes on the click, not on the answer.** The old handler
  // said our machinery out loud on every action: "the page catches up within
  // the minute". A customer neither needs that nor can act on it. The owner on
  // 2026-08-23: it is drawn disabled at once, with no wait and no reload,
  // and whatever the server takes is never shown.
  //
  // So each act paints its own result and the request goes out behind it. If
  // the server refuses, the paint is undone and the row says what happened,
  // which is the only case where anything is said at all.
  // Switching a row on or off, and taking it away. `undo` is the same function
  // with the opposite effect, so a refusal is one call and never a second copy
  // of the markup: **a deleted row is hidden and not removed**, which keeps its
  // menu handlers alive for the case where the delete did not save. Rebuilding
  // a row from its own outerHTML would hand back markup with nothing bound to
  // it, which is a row whose buttons quietly do nothing.
  var setRow=function(row,on){
    var st=row.querySelector('.st');
    if(st){st.textContent=on?'on':'off';st.className='st '+(on?'ok':'off')}
    var item=row.querySelector('.rm-post[data-act="enable"],.rm-post[data-act="disable"]');
    if(item){
      item.textContent=on?'Turn off':'Turn on';
      item.dataset.act=on?'disable':'enable';
    }
  };
  var ACTS={
    disable:{do:function(r){setRow(r,false)}, undo:function(r){setRow(r,true)}},
    enable: {do:function(r){setRow(r,true)},  undo:function(r){setRow(r,false)}},
    remove: {do:function(r){r.hidden=true},   undo:function(r){r.hidden=false}}
  };
  var bindPost=function(b){
    b.onclick=function(){
      var act=b.dataset.act, label=b.dataset.label, row=b.closest('.crow');
      if(!POSTABLE[act]){toast('That action has no route.');closeMenus();return}
      closeMenus();
      var go=function(){
        var effect=ACTS[act];
        if(effect&&row)effect.do(row);
        fetch('/api/admin/channels/'+encodeURIComponent(label)+'/'+act,{method:'POST'})
          .then(function(r){
            if(!r.ok)throw new Error('That did not save, so nothing changed.');
          })
          // One place undoes it, so a refused request and a dead connection
          // take the same path and the row cannot be un-painted twice.
          .catch(function(e){
            if(effect&&row)effect.undo(row);
            toast(e.message);
          });
      };
      if(act==='remove')
        askConfirm('Delete '+label+'?','Alerts stop going there.','Delete',go);
      else go();
    }};
  onWire(function(){document.querySelectorAll('.rm-post').forEach(bindPost)});
  // Send test. **The control plane decides whether it can send**, because only
  // it knows whether the row holds its own destination or names a variable this
  // process never reads (docs/RECORD.md 4.87). A row it cannot test answers
  // with the line to run on the box, and that answer is shown as it came rather
  // than being turned into a claim that something was sent.
  var bindTest=function(b){
    b.onclick=function(){
      var label=b.dataset.label;
      closeMenus();
      toast('Sending a test to '+label+'...');
      fetch('/api/admin/channels/'+encodeURIComponent(label)+'/test',{method:'POST'})
        .then(function(r){
          return r.json().catch(function(){return {}}).then(function(j){
            if(!r.ok)throw new Error(j.detail||('the server answered '+r.status));
            return j;
          });
        })
        // Three answers, and the third is the one that matters: a row whose
        // secret this process does not hold comes back with a `command` to run
        // on the box (controlplane/app/ingest.py). Showing only `detail` would
        // tell the operator it could not be done here and not what to do
        // instead. `detail` is empty on success, so the fallback words are ours.
        .then(function(j){
          var said=j.detail||(j.sent?'Test sent to '+label+'.':'The test did not send.');
          toast(j.command?said+' Run: '+j.command:said);
        })
        .catch(function(e){toast(e.message)});
    }};
  onWire(function(){document.querySelectorAll('.rm-test').forEach(bindTest)});
  // Edit opens the Add window on this row: its kind and its type picked and
  // every other card locked, its switches set to what the row takes, and the
  // destination field empty because this page is never given the stored one
  // to put back in it. Closing without saving changes nothing. While it
  // edits, the page's own style draws none of the cards, so the lock is what
  // holds if that style ever does not.
  //
  // **A Slack row has no destination field to fill in**, so editing one is the
  // switches and nothing else, and Save posts them to /events. The stored
  // webhook is never touched from here, which is what keeps a connected row
  // from being edited into one that cannot deliver.
  var bindEdit=function(b){
    b.onclick=function(){
      var label=b.dataset.label;
      closeMenus();
      if(!connOvl)return;
      // The row's own step, found by its type among the destinations' steps.
      var stage=null;
      connOvl.querySelectorAll('.m-stage[data-type]').forEach(function(s){
        if(s.dataset.type===b.dataset.type&&s.id.indexOf('chan-')===0)stage=s;
      });
      if(!stage){toast('That channel type cannot be edited on this screen yet.');return}
      connOvl.dataset.editing=label;
      connOvl.querySelectorAll('.m-card').forEach(function(c){
        // Only this row's own kind and type are reachable while editing.
        // Changing a channel's type would change what its destination has to
        // look like and what its delivery key is built from, which is a new
        // channel wearing an old row's name.
        var mine=c.dataset.kind==='dest'||c.dataset.fields===stage.id;
        c.classList.toggle('sel',mine);
        c.classList.toggle('m-locked',!mine);
      });
      connOvl.querySelectorAll('.m-stage').forEach(function(s){
        s.classList.toggle('on',s.id==='conn-dest'||s.id===stage.id||s.id==='chan-adv')});
      var dest=stage.querySelector('.js-dest');
      if(dest)dest.value='';
      // The kinds this row takes, so the switches say what is stored rather
      // than always saying every kind. An empty list is every kind, which is
      // what the row means (controlplane/app/channels.py), so every switch
      // stays on.
      var takes=(b.dataset.events||'').split(',').filter(function(k){return k});
      connOvl.querySelectorAll('.js-event').forEach(function(sw){
        sw.classList.toggle('off',
          takes.length>0&&takes.indexOf(sw.dataset.kind)<0);
      });
      connClear();
      var head=connOvl.querySelector('.m-h h2');
      if(head)head.textContent='Edit '+label;
      connOvl.classList.add('on');
      // Never Connect to Slack on an edit, which `slackConnect` holds to.
      connFoot();
    }};
  onWire(function(){document.querySelectorAll('.rm-edit').forEach(bindEdit)});
  // A row the browser puts up carries no handlers, because the passes above
  // ran before it existed. So every one of them is run again inside it, and
  // nothing is bound twice.
  var wireChannelRow=function(row){
    row.querySelectorAll('[data-menu]').forEach(bindMenu);
    row.querySelectorAll('.rm-p').forEach(bindPanel);
    row.querySelectorAll('.rm-post').forEach(bindPost);
    row.querySelectorAll('.rm-test').forEach(bindTest);
    row.querySelectorAll('.rm-edit').forEach(bindEdit);
  };
  // ---- the configured list, after a channel is added or changed ----
  // **Adding a channel used to change nothing until the page was reloaded.**
  // A click shows its result at once (the rule for customer screens, and
  // the owner on 2026-08-23 about a row's own controls: at once, with no reload).
  //
  // This paints on the answer where the row menu above paints on the click,
  // and the difference is deliberate. A delete knows its own result before it
  // asks. An add does not: the label is the control plane's to give when the
  // window sends none, and how much of a destination may be shown is
  // `Channel.hint`'s decision, which elides a webhook's secret last segment.
  // Painting either of those from what was typed would put a row on the screen
  // that a reload disagrees with.
  var channelRow=function(label){
    var found=null;
    document.querySelectorAll('.chanp .crow .rm-i').forEach(function(b){
      if(b.dataset.label===label)found=b.closest('.crow');
    });
    return found;
  };
  // Every menu item on a row carries the label and the kinds, so both are
  // written to all of them rather than to whichever one is read first.
  var setRowLabel=function(row,label){
    row.querySelectorAll('.rm-i').forEach(function(b){b.dataset.label=label});
    var trigger=row.querySelector('.rm-t');
    if(trigger){
      trigger.dataset.menu=label;
      trigger.setAttribute('aria-label','Manage '+label);
    }
  };
  var setRowEvents=function(row,events){
    var value=(events||[]).join(',');
    row.querySelectorAll('.rm-i').forEach(function(b){b.dataset.events=value});
  };
  // textContent and never innerHTML: a destination is somebody else's text.
  var setRowDest=function(row,text){
    var cell=row.querySelector('.d');
    if(cell)cell.textContent=text;
  };
  // The new row is cloned from the hidden one this page carries per channel
  // type, which the renderer drew with the same call it drew every visible row
  // with (site/app/render_live.py, site/app/build.py channel_row_html). So
  // nothing here writes markup and the two cannot drift.
  var addChannelRow=function(j){
    var list=document.querySelector('.chanp');
    if(!list)return;
    var shape=null;
    // Matched on the attribute rather than through a selector built from the
    // answer, so nothing the control plane says can be read as a selector.
    document.querySelectorAll('.crow-tpl').forEach(function(t){
      if(t.dataset.type===j.type)shape=t;
    });
    // A type this page carries no row for. Nothing is put in its place,
    // because a row written here would be markup nobody drew.
    if(!shape)return;
    var row=shape.content.firstElementChild.cloneNode(true);
    setRowLabel(row,j.label);
    setRowEvents(row,j.events);
    // The variable name when the row names one and the destination summary
    // otherwise, which is the same choice the rendered row makes.
    setRowDest(row,j.env||j.destination||'');
    // Last, because the stored rows come back oldest first
    // (controlplane/app/channels.py live()).
    list.appendChild(row);
    wireChannelRow(row);
  };
  var editChannelRow=function(label,j,events){
    var row=channelRow(label);
    if(!row)return;
    setRowEvents(row,events);
    // Only a save that carried a destination gets one back. The Slack path
    // writes the kinds and nothing else, so that row's destination is left
    // exactly as it stands.
    if(j&&typeof j.destination==='string')setRowDest(row,j.destination);
  };
  // ---- proof of control, one flow for both windows ----
  //
  // The address window a server's Settings open, and the Add server window's
  // Addresses card, draw one form (build.proof_form_html) and walk it here:
  // an address, a way to prove it, Start, the token to publish, Verify, and
  // the registry's answer. Nothing here probes anything and nothing here can
  // record a proof: only the control plane's registry does, when it has read
  // the evidence itself (SI-6, controlplane/app/authz.py). No row is drawn
  // here either. A proved address is a row when the page is next asked for.
  //
  // One primary button at a time, and it says what a press will do: nothing
  // until a way is picked, then Start, then Verify, then Done alone
  // (docs/RECORD.md 4.375, 4.379).
  //
  // What the window does with an answer is decided by the registry's typed
  // code, never by the wording of a sentence, and a code it does not know is
  // never a yes. The three lists are held to authz.PROOF_CODES by a test.
  var PROOF_PROVED='proved';
  var PROOF_START_AGAIN=['challenge_expired','challenge_cancelled','no_such_challenge'];
  var PROOF_VERIFY_AGAIN=['token_not_found','evidence_unreadable','challenge_mismatch',
    'not_a_published_method','target_refused','not_held','address_held'];
  // A request of this form is given this long. One that fails or runs out
  // puts its button back and says so, or the window would be dead.
  var PROOF_WAIT_MS=30000;
  // Per form: where it is in the walk, the challenge that is out, and a
  // count that lets a late answer be told from the one being waited for.
  var proofs={};
  var proofOf=function(prefix){
    if(!proofs[prefix])proofs[prefix]={step:'fill',challenge:null,run:0,busy:false,onStep:null};
    return proofs[prefix]};
  var proofEl=function(prefix,part){return document.getElementById(prefix+'-'+part)};
  var proofMethod=function(prefix){
    var sel=document.querySelector('#'+prefix+'-http.sel,#'+prefix+'-dns.sel');
    return sel?sel.dataset.method:null};
  // What is still missing before a proof can start, in the words the form
  // says it in, or nothing.
  var proofMissing=function(prefix){
    if(!proofEl(prefix,'address').value.trim())return 'An address is needed';
    if(!proofMethod(prefix))return 'Choose how to prove it';
    return ''};
  // Once a token is out it belongs to one address and one way, so the field
  // and the cards are fixed. Another address is Cancel and a new start.
  var proofFix=function(prefix,fixed){
    proofEl(prefix,'address').disabled=fixed;
    ['http','dns'].forEach(function(way){
      var card=proofEl(prefix,way);
      if(fixed)card.setAttribute('aria-disabled','true');
      else card.removeAttribute('aria-disabled')})};
  var proofSay=function(prefix,words,tone){
    var res=proofEl(prefix,'result');
    res.textContent=words||'';res.className='m-result'+(tone?' '+tone:'')};
  var proofStep=function(prefix,step){
    var state=proofOf(prefix);
    state.step=step;
    if(state.onStep)state.onStep(step)};
  var proofReset=function(prefix){
    var state=proofOf(prefix);
    state.run++;state.busy=false;state.challenge=null;
    proofEl(prefix,'address').value='';
    proofEl(prefix,'err').textContent='';
    var proof=proofEl(prefix,'proof');proof.hidden=true;
    proofEl(prefix,'token').textContent='';
    proofEl(prefix,'where').textContent='';
    proofSay(prefix,'','');
    ['http','dns'].forEach(function(way){proofEl(prefix,way).classList.remove('sel')});
    proofFix(prefix,false);
    proofStep(prefix,'fill')};
  // One request, answered at most once: with the answer, or with nothing
  // when it failed or ran out of time. A late answer is dropped.
  var proofAsk=function(prefix,url,opts,answered,unanswered){
    var state=proofOf(prefix), mine=++state.run;
    state.busy=true;
    var over=function(act){return function(value){
      if(mine!==state.run)return;
      state.run++;state.busy=false;clearTimeout(timer);act(value)}};
    var timer=setTimeout(over(unanswered),PROOF_WAIT_MS);
    ask(url,opts).then(over(answered),over(unanswered))};
  var proofStart=function(prefix,host,button){
    var state=proofOf(prefix), err=proofEl(prefix,'err');
    if(state.busy)return;
    var missing=proofMissing(prefix);
    if(missing){err.textContent=missing;return}
    err.textContent='';proofSay(prefix,'','');button.disabled=true;
    proofAsk(prefix,'/api/admin/hosts/'+encodeURIComponent(host)+'/addresses',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({address:proofEl(prefix,'address').value.trim(),
                           method:proofMethod(prefix)})},
    function(r){
      button.disabled=false;
      if(!r.ok){err.textContent=r.body.detail||didNotWork(r.status);return}
      state.challenge=r.body.id;
      proofEl(prefix,'token').textContent=r.body.token;
      proofEl(prefix,'where').textContent=r.body.publish_at;
      var proof=proofEl(prefix,'proof');proof.hidden=false;
      proofFix(prefix,true);
      proofStep(prefix,'token')},
    function(){button.disabled=false;err.textContent=NO_ANSWER})};
  var proofVerify=function(prefix,host,button){
    var state=proofOf(prefix);
    if(state.busy||!state.challenge)return;
    proofSay(prefix,'','');button.disabled=true;
    proofAsk(prefix,'/api/admin/hosts/'+encodeURIComponent(host)+'/addresses/'
             +state.challenge+'/verify',{method:'POST'},
    function(r){
      button.disabled=false;
      var code=r.body&&r.body.code;
      if(r.ok&&r.body.ok===true&&code===PROOF_PROVED){
        proofSay(prefix,r.body.detail,'ok');
        state.challenge=null;
        proofStep(prefix,'done');return}
      proofSay(prefix,(r.body&&r.body.detail)||didNotWork(r.status),'fail');
      // Its day is over or it is gone: the same address and way, started
      // again. Anything else, a code this does not know among them, leaves
      // Verify where it is.
      if(PROOF_START_AGAIN.indexOf(code)>=0){
        state.challenge=null;proofStep(prefix,'again')}},
    function(){button.disabled=false;proofSay(prefix,NO_ANSWER,'fail')})};
  // What the form's one button does at each step. `start` is the window's
  // own way to begin, since the Add server window makes its server first.
  var proofPress=function(prefix,host,button,start,close){
    var step=proofOf(prefix).step;
    if(step==='done'){close();return}
    if(step==='token'){proofVerify(prefix,host,button);return}
    start()};
  var proofCopy=function(box){copyText(box.textContent,box)};
  // A way is picked by its card, while the form is still being filled.
  document.querySelectorAll('.m-methods .m-card').forEach(function(c){
    c.onclick=function(){
      if(c.getAttribute('aria-disabled')==='true')return;
      c.parentNode.querySelectorAll('.m-card').forEach(function(o){o.classList.remove('sel')});
      c.classList.add('sel');
      var prefix=c.id.replace(/-(http|dns)$/,'');
      proofEl(prefix,'err').textContent='';
      proofStep(prefix,proofOf(prefix).step)}});
  // A never-reported server hands out a fresh install command. The answer
  // lands in the row itself and copies on a click, the same behaviour every
  // other command box on the page has. A refusal is the server's own
  // sentence, in the toast like every other refused row action.
  onWire(function(){
  document.querySelectorAll('.js-recred').forEach(function(b){
    b.onclick=function(){
      b.disabled=true;
      ask('/api/admin/hosts/'+encodeURIComponent(b.dataset.host)+'/credential',
            {method:'POST'})
      .then(function(r){
        b.disabled=false;
        if(!r.ok){toast(r.body.detail||didNotWork(r.status));return}
        var out=document.getElementById('rc-'+b.dataset.host);
        if(out){out.textContent=r.body.install_command;out.hidden=false;
          out.onclick=function(){proofCopy(out)}}
      })
      .catch(function(){b.disabled=false;
        toast(NO_ANSWER)});
    }});
  });
  document.querySelectorAll('.m-proof .m-copy').forEach(function(box){
    box.onclick=function(){proofCopy(box)}});
  // ---- Add an address, in its window (docs/RECORD.md 4.379) ----
  // One window on the page. The button under a server's Addresses hands it
  // that server. It sits with the other windows, outside every piece the
  // quiet refresh swaps, and the refresh stands still while any window is
  // open, so a token on the screen is never taken away from under a hand.
  var adOvl=document.getElementById('addr-ovl');
  if(adOvl){
    var adGo=document.getElementById('ad-go'), adHost=null, adProved=false;
    var adCancel=adOvl.querySelector('.m-foot [data-close="addr-ovl"]');
    var adClose=function(){adOvl.classList.remove('on')};
    proofOf('ad').onStep=function(step){
      // No primary button until a way is picked, and Done alone at the end.
      adGo.hidden=(step==='fill'&&!proofMethod('ad'));
      adGo.textContent=step==='token'?'Verify':step==='done'?'Done':'Start';
      adCancel.hidden=(step==='done');
      if(step==='done')adProved=true};
    adGo.onclick=function(){
      proofPress('ad',adHost,adGo,function(){proofStart('ad',adHost,adGo)},adClose)};
    // Enter in the address field does what the button would, and nothing
    // while there is none.
    document.getElementById('ad-address').onkeydown=function(e){
      if(e.key!=='Enter')return;
      e.preventDefault();
      if(!adGo.hidden&&!adGo.disabled)adGo.click()};
    onWire(function(){
      document.querySelectorAll('[data-open="addr-ovl"]').forEach(function(b){
        b.onclick=function(){
          adHost=b.dataset.host;adProved=false;
          proofReset('ad');
          adOvl.classList.add('on');
          document.getElementById('ad-address').focus()}});
    });
    // Closed by Done, Cancel, the cross, the backdrop or Escape, which
    // presses the cross of whatever window is open: all of them take the
    // class off, so the class is what is watched. After a proof the
    // page is asked for, and the new row is the one the server draws.
    new MutationObserver(function(){
      if(adOvl.classList.contains('on'))return;
      proofOf('ad').run++;
      if(adProved){adProved=false;refresh(true)}
    }).observe(adOvl,{attributes:true,attributeFilter:['class']});
  }
  onWire(function(){
  document.querySelectorAll('.js-addr-revoke').forEach(function(b){
    b.onclick=function(){
      if(!b.dataset.armed){b.dataset.armed='1';b.textContent='Click again to revoke';return}
      b.disabled=true;
      fetch('/api/admin/hosts/'+encodeURIComponent(b.dataset.host)+'/addresses/revoke',{method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({address:b.dataset.address})})
      .then(function(r){
        if(r.status===204){
          // The row says revoked at once; the server already agrees.
          var row=b.closest('.li')||b.parentNode;
          var dim=row.querySelector('.dim');if(dim)dim.textContent='revoked';
          b.remove();
          // The host's state, its header and its fleet row follow the proof.
          refresh(true);return}
        b.disabled=false;b.dataset.armed='';b.textContent='Revoke';
        return r.json().catch(function(){return {}}).then(function(j){
          toast(j.detail||didNotWork(r.status))})})
      .catch(function(){b.disabled=false;b.dataset.armed='';b.textContent='Revoke';
        toast(NO_ANSWER)})}});
  });
  // ---- the ports a server is watched on, in its settings ----
  //
  // One click covers both address families, because the row is about a port
  // and the store is keyed per family. That is the shape .js-review already
  // takes further down, and the same rule holds here: partly done is not
  // done, so the row only changes once every family answered.
  //
  // Everything the row prints is set with textContent rather than built into
  // a string of markup, so a server name and a port cannot become anything
  // but text.
  var portFams=['v4','v6'];
  var portPath=function(host,protocol,port,family,action){
    return '/api/admin/hosts/'+encodeURIComponent(host)+'/ports/'
      +encodeURIComponent(protocol)+'/'+encodeURIComponent(port)+'/'
      +encodeURIComponent(family)+'/'+action};
  var portRefusal=function(r){
    if(r.status===204)return '';
    return r.json().catch(function(){return {}}).then(function(j){
      return j.detail||didNotWork(r.status)})};
  var wirePortRemove=function(b){
    b.onclick=function(){
      var row=b.closest('.li');
      b.disabled=true;
      Promise.all(portFams.map(function(f){
        return fetch(portPath(b.dataset.host,b.dataset.protocol,b.dataset.port,f,'clear'),
          {method:'POST'}).then(portRefusal)}))
      .then(function(answers){
        var refused=answers.filter(function(a){return a});
        if(refused.length){b.disabled=false;toast(refused[0]);return}
        // The row goes at once; the server already agrees. The Overview
        // lists the declared ports too, so the page is asked for.
        row.remove();refresh(true)})
      .catch(function(){b.disabled=false;
        toast(NO_ANSWER)})}};
  onWire(function(){document.querySelectorAll('.js-port-rm').forEach(wirePortRemove)});
  // Cloned from the empty row the builder draws (build.port_row_template_html),
  // the same call every stored row is drawn with, so no row markup is written
  // here and the two cannot drift. Everything printed is set with textContent.
  var portRow=function(host,protocol,port,value){
    var shape=document.getElementById('port-row-tpl');
    if(!shape)return null;
    var row=shape.content.firstElementChild.cloneNode(true);
    row.querySelector('.num').textContent=port+'/'+protocol;
    row.querySelector('.dim').textContent=value;
    var rm=row.querySelector('.js-port-rm');
    rm.dataset.host=host;rm.dataset.protocol=protocol;rm.dataset.port=port;
    wirePortRemove(rm);
    return row};
  onWire(function(){
  document.querySelectorAll('.js-port-add').forEach(function(b){
    b.onclick=function(){
      var box=b.closest('.li');
      var msg=box.querySelector('.pd-msg');
      var field=box.querySelector('.pd-port');
      var chosen=box.querySelector('.seg button.on');
      var port=(field.value||'').trim();
      msg.textContent='';
      // Checked here as well as at the endpoint, so a typo answers on the row
      // instead of travelling. The endpoint is still the one that decides.
      if(!/^[0-9]{1,5}$/.test(port)||+port<1||+port>65535){
        msg.textContent='Port must be a whole number between 1 and 65535.';return}
      if(!chosen){msg.textContent='Choose open or closed.';return}
      var value=chosen.dataset.intent;
      b.disabled=true;
      Promise.all(portFams.map(function(f){
        return fetch(portPath(b.dataset.host,'tcp',port,f,'declare'),{method:'POST',
          headers:{'Content-Type':'application/json'},
          body:JSON.stringify({intent:value})}).then(portRefusal)}))
      .then(function(answers){
        var refused=answers.filter(function(a){return a});
        b.disabled=false;
        if(refused.length){msg.textContent=refused[0];return}
        // A port already listed is replaced rather than listed twice, which is
        // what the store did with it.
        var listed=null;
        box.parentNode.querySelectorAll('.js-port-rm').forEach(function(o){
          if(o.dataset.protocol==='tcp'&&o.dataset.port===String(+port)
            &&o.dataset.host===b.dataset.host)listed=o});
        if(listed){listed.closest('.li').querySelector('.dim').textContent='declared '+value}
        else{
          // In its place in the list, which is by port, so the row does not
          // move when the page is next drawn.
          var after=null;
          box.parentNode.querySelectorAll('.js-port-rm').forEach(function(o){
            if(after===null&&+o.dataset.port>+port)after=o.closest('.li')});
          var made=portRow(b.dataset.host,'tcp',+port,'declared '+value);
          // the add row stays last in the list it adds to
          if(made)box.parentNode.insertBefore(made,after||box);
        }
        field.value='';
        box.querySelectorAll('.seg button').forEach(function(o){
          o.classList.remove('on')});
        refresh(true);
      })
      .catch(function(){b.disabled=false;
        msg.textContent=NO_ANSWER})}});
  });
  var ovl=document.getElementById('add-ovl');
  if(ovl){
    // The agent card clicked mints the credential, once per page. One install
    // command since 2026-09-13 (docs/RECORD.md 4.172), so the response carries
    // the one string and re-picking never mints a second credential.
    var addCmds=null;
    var addPick='install_command';
    var cmdBox=document.getElementById('add-cmd');
    var shownCmd=function(){return addCmds?addCmds[addPick]:null};
    var stage=function(id,on){document.getElementById(id).classList.toggle('on',on)};
    // The server arriving, under the command: First report, then First
    // measurement (docs/screens/add-server/BRIEF-arrival.md). The window asks
    // the control plane every three seconds while it is open on a command,
    // and stops when both steps are done or the window closes. The page's own
    // quiet refresh stands still while a window is open, so nothing else
    // would move here.
    var ARRIVAL_MS=3000;
    var arrBox=document.getElementById('add-arr');
    var arrTimer=null, arrHost=null, arrName=null, arrBusy=false;
    var arrRow=function(id,step,value){
      var row=document.getElementById(id);
      row.dataset.step=step;
      row.querySelector('.arr-v').textContent=value||'';
    };
    var arrAge=function(iso){
      var s=Math.max(0,Math.round((Date.now()-new Date(iso).getTime())/1000));
      if(s<60)return s+'s ago';
      if(s<3600)return Math.floor(s/60)+'m ago';
      return Math.floor(s/3600)+'h ago';
    };
    var arrivalStop=function(){
      if(arrTimer){clearInterval(arrTimer);arrTimer=null}
      arrHost=null;arrName=null;
      if(arrBox){arrBox.hidden=true;
        arrRow('arr-report','idle');arrRow('arr-probe','idle')}
    };
    // "n of m", read off this server's Fleet row in the page as the server
    // draws it now, so this window and the Fleet cannot show two numbers.
    var arrivalReach=function(name){
      return fetch(location.pathname,{cache:'no-store'})
      .then(function(r){return r.ok&&!r.redirected?r.text():''})
      .then(function(text){
        if(!text)return '';
        var found='';
        new DOMParser().parseFromString(text,'text/html')
          .querySelectorAll('#fleet .row').forEach(function(row){
            if(row.dataset.host!==name)return;
            // The bold count and the " of m" text after it, and not the
            // disagree mark that may follow them in the same cell.
            var n=row.querySelector('.frc b');
            if(n)found=(n.textContent+(n.nextSibling?n.nextSibling.textContent:'')).trim()});
        return found;
      }).catch(function(){return ''});
    };
    var arrivalDone=function(name){
      if(arrTimer){clearInterval(arrTimer);arrTimer=null}
      arrName=name;
      var done=document.getElementById('add-done');
      done.textContent='Open server';done.className='btn pri';
    };
    var arrivalAsk=function(){
      if(arrBusy||arrHost===null)return;
      var asked=arrHost;
      arrBusy=true;
      ask('/api/admin/hosts/arrival/'+encodeURIComponent(asked))
      .then(function(r){
        arrBusy=false;
        // The window was closed or reopened for another server meanwhile.
        if(asked!==arrHost||!r.ok)return;
        if(!r.body.reported_at)return;
        arrRow('arr-report','done',r.body.name+', '+arrAge(r.body.reported_at));
        if(!r.body.probed_at){arrRow('arr-probe','wait');return}
        var name=r.body.name;
        arrivalDone(name);
        arrivalReach(name).then(function(reach){
          if(asked!==arrHost)return;
          arrRow('arr-probe','done',reach?reach+' reachable':'')});
      })
      .catch(function(){arrBusy=false});
    };
    var arrivalStart=function(id){
      if(!arrBox||id===undefined||id===null)return;
      arrivalStop();
      arrHost=id;arrBox.hidden=false;
      arrRow('arr-report','wait');arrRow('arr-probe','idle');
      arrTimer=setInterval(arrivalAsk,ARRIVAL_MS);
    };
    var reset=function(){
      document.getElementById('add-linux').classList.remove('sel');
      document.getElementById('add-windows').classList.remove('sel');
      document.getElementById('add-other').classList.remove('sel');
      document.getElementById('add-agent').classList.remove('sel');
      document.getElementById('add-addr').classList.remove('sel');
      document.getElementById('add-addr-other').classList.remove('sel');
      document.getElementById('add-addr-windows').classList.remove('sel');
      stage('add-method-linux',false);stage('add-method-other',false);
      stage('add-method-windows',false);
      stage('add-cmd-stage',false);stage('add-addr-stage',false);
      var go=document.getElementById('add-addr-go');if(go)go.hidden=true;
      var done=document.getElementById('add-done');
      // Cancel until something has happened. A picker nobody has picked from
      // has nothing to be done with, and a footer saying Done there reads as
      // a step the reader missed (the 2026-08-29 audit round).
      done.className='btn pri';done.textContent='Cancel';
      document.getElementById('add-err').textContent='';
      arrivalStop();
    };
    var mint=function(){
      if(addCmds){cmdBox.textContent=shownCmd();return}
      cmdBox.textContent='creating the credential...';
      ask('/api/admin/hosts',{method:'POST',
        headers:{'Content-Type':'application/json'},body:'{}'})
      .then(function(r){
        if(!r.ok){document.getElementById('add-err').textContent=
          r.body.detail||didNotWork(r.status);cmdBox.textContent='';return}
        addCmds=r.body;cmdBox.textContent=shownCmd();
        arrivalStart(r.body.id);
      })
      .catch(function(){document.getElementById('add-err').textContent=NO_ANSWER;cmdBox.textContent=''});
    };
    onWire(function(){
    document.querySelectorAll('.js-add').forEach(function(b){
      b.onclick=function(){reset();ovl.classList.add('on')}});
    });
    document.getElementById('add-linux').onclick=function(){
      reset();this.classList.add('sel');stage('add-method-linux',true)};
    document.getElementById('add-other').onclick=function(){
      reset();this.classList.add('sel');stage('add-method-other',true)};
    // Windows has its own stage since 2026-08-30: the same outside-only card
    // an appliance gets, plus the planned Windows agent card, which is v2
    // (docs/PRODUCT.md section 7) and which the owner asked to see.
    document.getElementById('add-windows').onclick=function(){
      reset();this.classList.add('sel');stage('add-method-windows',true)};
    var linuxCards=['add-try','add-agent','add-addr'];
    var clearLinux=function(){linuxCards.forEach(function(id){
      var el=document.getElementById(id);if(el)el.classList.remove('sel')})};
    var pickAgent=function(card,key){
      clearLinux();
      card.classList.add('sel');addPick=key;
      stage('add-addr-stage',false);addGo.hidden=true;
      stage('add-cmd-stage',true);
      document.getElementById('add-done').textContent='Done';mint()};
    // ---- try it, send nothing ----
    //
    // The one card that mints nothing and creates no host. `--mode=stdout` is
    // the agent's default, it does not read the enrolment file and sends
    // nothing off the machine, and
    // agent/cmd/agent/main.go calls it "the way to evaluate the agent without
    // trusting anything" (docs/RECORD.md 4.124). So there is no credential to
    // ask the server for and the command is the same on every page.
    document.getElementById('add-try').onclick=function(){
      clearLinux();this.classList.add('sel');addPick=null;
      stage('add-addr-stage',false);addGo.hidden=true;
      stage('add-cmd-stage',true);
      document.getElementById('add-done').textContent='Done';
      document.getElementById('add-cmd').textContent=__TRY_COMMAND__;
      document.getElementById('add-err').textContent=''};
    // ---- addresses, no agent ----
    // The window creates the host, then walks the same proof of control the
    // settings window walks (proofFlow below). Closing the window once a
    // host was created asks the server for the page again, so the fleet
    // shows the row the server has.
    var addGo=document.getElementById('add-addr-go');
    // The server this window made, and the name that was typed for it, so
    // one server is never asked for twice.
    var addCreated=null, addCreatedAs=null;
    var addDone=document.getElementById('add-done');
    proofOf('add-addr').onStep=function(step){
      // One primary button: Create once a way is picked, then Verify, then
      // Done alone.
      addGo.hidden=(step==='done')||(step==='fill'&&!proofMethod('add-addr'));
      addGo.textContent=step==='token'?'Verify':step==='again'?'Start':'Create';
      if(step==='done'){addDone.className='btn pri';addDone.textContent='Done'}};
    var pickAddr=function(card){
      clearLinux();
      document.getElementById('add-addr-other').classList.remove('sel');
      card.classList.add('sel');
      stage('add-cmd-stage',false);
      // Create is the action on this stage, so Done steps back to plain.
      addDone.className='btn';
      proofReset('add-addr');
      stage('add-addr-stage',true)};
    document.getElementById('add-addr').onclick=function(){pickAddr(this)};
    document.getElementById('add-addr-other').onclick=function(){pickAddr(this)};
    document.getElementById('add-addr-windows').onclick=function(){pickAddr(this)};
    // The window makes its server, then proves the address on it.
    var addStart=function(){
      var name=document.getElementById('add-addr-name').value.trim();
      var err=document.getElementById('add-addr-err');
      if(!name){err.textContent='A name is needed';return}
      // The address and the way to prove it are looked at before anything
      // is made. The server used to be made first, so Create with no address
      // left a server behind, and the next click asked for the same server
      // again (measured 2026-10-04, docs/RECORD.md 4.362).
      var missing=proofMissing('add-addr');
      if(missing){err.textContent=missing;return}
      // This window made the server already, under this name, and the
      // control plane refused its address. The address was put right, so
      // only the address is asked for again. Another name typed meanwhile
      // is another server.
      if(addCreated&&addCreatedAs===name){proofStart('add-addr',addCreated,addGo);return}
      err.textContent='';addGo.disabled=true;
      ask('/api/admin/hosts',{method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({name:name,kind:'address'})})
      .then(function(r){
        addGo.disabled=false;
        if(!r.ok){err.textContent=r.body.detail||didNotWork(r.status);return}
        addCreated=r.body.name;addCreatedAs=name;
        addDone.textContent='Done';
        proofStart('add-addr',addCreated,addGo)})
      .catch(function(){addGo.disabled=false;
        err.textContent=NO_ANSWER});
    };
    addGo.onclick=function(){
      proofPress('add-addr',addCreated,addGo,addStart,function(){})};
    document.getElementById('add-agent').onclick=function(){
      pickAgent(this,'install_command')};
    var closeAdd=function(){
      // Both steps done: the footer button reads Open server and goes there.
      // The cross still only closes.
      if(this&&this.id==='add-done'&&arrName){
        location.href='/host/'+encodeURIComponent(arrName);return}
      arrivalStop();
      ovl.classList.remove('on');
      // Either card that created a host: the row is on the server now, and
      // the next open mints a credential of its own rather than handing the
      // same one out for a second server.
      addCreatedAs=null;
      if(addCreated||addCmds){addCreated=null;addCmds=null;refresh(true)}};
    document.getElementById('add-close').onclick=closeAdd;
    document.getElementById('add-done').onclick=closeAdd;
    ovl.addEventListener('click',function(e){if(e.target===ovl)closeAdd()});
    // The command that is shown is the one copied. The try-it card asks the
    // control plane for nothing and writes its command into the box itself
    // (addPick is null then), so there the box's own text is the command. On
    // the agent's card it is the one the control plane handed out, and
    // nothing while that is still being made.
    cmdBox.onclick=function(){
      copyText(addPick===null?cmdBox.textContent:shownCmd(),cmdBox)};
  }
  // A server's ID is shown and not edited (docs/RECORD.md 4.298), so nothing
  // here renames one. Until 2026-10-03 its row was a field with a Save.
  // A server's display name, edited in its field the way its name is. It is
  // a label: the server is still found by its name, so nothing here touches
  // data-host, an id or the address bar. On a save the header and the fleet
  // row say the stored spelling at once, and an empty one puts the name back.
  var paintRowName=function(host,display){
    var row=document.querySelector('#fleet .row[data-host="'+host+'"]');
    var cell=row&&row.querySelector('.fsrv');
    if(!cell)return;
    var bold=display||host;
    var hn=cell.querySelector('.hn');if(hn)hn.textContent=bold;
    // The line under the name says what the bold name does not
    // (build.fleet_host_html): data-under, when it differs from the bold
    // name. It is the cell's last piece, after the tags.
    var under=row.dataset.under||'';
    var fhost=cell.querySelector('.fhost');
    if(under&&under!==bold){
      if(!fhost){fhost=document.createElement('small');fhost.className='fhost';
        cell.appendChild(fhost)}
      fhost.textContent=under;
    }else if(fhost){fhost.remove()}
  };
  onWire(function(){
  document.querySelectorAll('.js-display').forEach(function(inp){
    var save=inp.parentNode.querySelector('.js-display-save');
    if(!save)return;
    var show=function(){save.hidden=inp.value.trim()===inp.defaultValue};
    // Assigned, never added: this runs on every wire pass, and a listener
    // added each time would stack, so Enter would click Save once per
    // refresh the page had lived through (docs/RECORD.md 4.180).
    inp.oninput=show;
    inp.onkeydown=function(e){
      if(e.key==='Enter'){e.preventDefault();if(!save.hidden)save.click()}
      if(e.key==='Escape'){inp.value=inp.defaultValue;show()}};
    save.onclick=function(){
      var host=save.dataset.host;
      ask('/api/admin/hosts/'+host+'/display-name',{method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({display_name:inp.value})})
      .then(function(a){
        if(!a.ok||typeof a.body.display_name!=='string'){
          toast(a.body.detail||didNotWork(a.status));return}
        var stored=a.body.display_name;
        inp.value=stored;inp.defaultValue=stored;save.hidden=true;
        var view=inp.closest('.view');
        var shown=view&&view.querySelector('.hh h1 .hname');
        if(shown)shown.textContent=stored||host;
        paintRowName(host,stored);
        toast('Saved');
        refresh(true)})
      .catch(function(){toast(NO_ANSWER)})};
  });
  });
  // A server's tags on its Settings are one bubble each, and a field that
  // adds one more (the owner, 2026-10-03, docs/RECORD.md 4.285). Nothing waits
  // for a Save: Enter in the field adds the tag and a click on a bubble
  // takes it off. Each is one request that carries the whole list, which is
  // what the route takes, and the server answers with the tags as it stored
  // them. What a tag may be, and how many a server carries, is the server's
  // to decide (controlplane/app/tags.py), so a refusal is its own words in a
  // toast.
  var paintRowTags=function(host,tags){
    var cell=document.querySelector('#fleet .row[data-host="'+host+'"] .fsrv');
    if(!cell)return;
    cell.querySelectorAll('.ftag').forEach(function(t){t.remove()});
    // Beside the name and before the hostname, where the builder puts them
    // (build.fleet_row_html). With no hostname line they go last.
    var host=cell.querySelector('.fhost');
    tags.forEach(function(t){var s=document.createElement('span');
      s.className='ftag';s.textContent=t;cell.insertBefore(s,host)});
  };
  var tagsOf=function(box){
    return Array.prototype.map.call(box.querySelectorAll('.js-tag-del'),
      function(b){return b.dataset.tag})};
  // The bubbles of one server, drawn from a list. A bubble is a copy of the
  // one the builder left in the box's <template>, so the script and the
  // builder cannot draw two different bubbles. The field goes when the
  // server carries all the tags it may (`full`, build.tags_row).
  var paintTags=function(box,tags){
    box.querySelectorAll('.js-tag-del').forEach(function(b){b.remove()});
    var model=box.querySelector('template').content.querySelector('.tagb');
    var field=box.querySelector('.js-tag-add');
    tags.forEach(function(t){
      var b=model.cloneNode(true);
      b.dataset.tag=t;b.setAttribute('aria-label','Remove tag '+t);
      b.querySelector('span').textContent=t;
      box.insertBefore(b,field)});
    box.classList.toggle('full',tags.length>=parseInt(box.dataset.max,10));
  };
  var paintBoth=function(box,tags){
    paintTags(box,tags);paintRowTags(box.dataset.host,tags)};
  var postTags=function(box,tags){
    return ask('/api/admin/hosts/'+box.dataset.host+'/tags',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({tags:tags})})};
  // Where the keyboard is after a tag was added or taken off by keyboard:
  // on a bubble, or in the field when `tag` is empty. The refresh that
  // follows swaps the settings in again, which drops the focus, so the pass
  // below puts it back, for a few seconds and only when nothing else has it.
  // After the last tag a server may carry, the field is gone and nothing
  // takes the focus: a bubble under the keyboard is one Enter away from being
  // taken off, and the Enter that added it may be pressed twice.
  var tagFocus=null;
  var focusTag=function(box,tag){
    var el=null;
    if(tag){el=Array.prototype.filter.call(box.querySelectorAll('.js-tag-del'),
      function(b){return b.dataset.tag===tag})[0]}
    else if(!box.classList.contains('full')){el=box.querySelector('.js-tag-add')}
    if(el)el.focus();
  };
  onWire(function(){
    if(!tagFocus||Date.now()-tagFocus.at>3000)return;
    if(document.activeElement&&document.activeElement!==document.body)return;
    var box=document.querySelector('.tagc[data-host="'+tagFocus.host+'"]');
    if(box)focusTag(box,tagFocus.tag);
  });
  // Bound to the document, so a bubble drawn here or swapped in by the
  // refresh needs no second pass.
  document.addEventListener('click',function(e){
    var b=e.target.closest&&e.target.closest('.js-tag-del');
    if(!b)return;
    e.preventDefault();
    var box=b.closest('.tagc'), before=tagsOf(box);
    var at=before.indexOf(b.dataset.tag);
    var after=before.filter(function(t){return t!==b.dataset.tag});
    // Enter or Space on a bubble is a click with no pointer behind it. The
    // keyboard then goes to the bubble that took this one's place.
    var byKeyboard=e.detail===0;
    var next=after.length?after[Math.min(at,after.length-1)]:'';
    // The bubble goes at once and comes back if the server says no.
    paintBoth(box,after);
    if(byKeyboard){focusTag(box,next);
      tagFocus={host:box.dataset.host,tag:next,at:Date.now()}}
    postTags(box,after)
    .then(function(a){
      if(!a.ok||!Array.isArray(a.body.tags)){
        paintBoth(box,before);
        toast(a.body.detail||didNotWork(a.status));return}
      if(a.body.tags.join(',')!==tagsOf(box).join(','))paintBoth(box,a.body.tags);
      toast('Removed');
      refresh(true)})
    .catch(function(){paintBoth(box,before);toast(NO_ANSWER)});
  });
  document.addEventListener('keydown',function(e){
    var inp=e.target.closest&&e.target.closest('.js-tag-add');
    if(!inp||e.isComposing)return;
    if(e.key==='Escape'){inp.value='';return}
    // A comma ends a tag as Enter does: it is never part of one.
    if(e.key!=='Enter'&&e.key!==',')return;
    e.preventDefault();
    var word=inp.value.trim();
    if(!word||inp.dataset.busy==='1')return;
    var box=inp.closest('.tagc'), before=tagsOf(box);
    inp.dataset.busy='1';
    postTags(box,before.concat([word]))
    .then(function(a){
      inp.dataset.busy='';
      if(!a.ok||!Array.isArray(a.body.tags)){
        toast(a.body.detail||didNotWork(a.status));return}
      inp.value='';
      paintBoth(box,a.body.tags);
      // A tag the server already had comes back as the same list.
      if(a.body.tags.length>before.length)toast('Added');
      // The field keeps the keyboard for the next tag. When it is gone,
      // nothing takes the focus, for the reason focusTag gives.
      if(box.classList.contains('full')){inp.blur()}
      else{inp.focus();tagFocus={host:box.dataset.host,tag:'',at:Date.now()}}
      refresh(true)})
    .catch(function(){inp.dataset.busy='';toast(NO_ANSWER)});
  });
  // Dismiss and Restore on the rarely-public mark of one port, on its opened
  // row (docs/RECORD.md 4.274). The row's mark, the line, the server's own
  // Needs a decision count and the mark beside its name change the moment
  // the server answers, and the quiet refresh brings the Fleet along. What
  // can be dismissed is the server's to decide
  // (controlplane/app/rarelydismiss.py), so a refusal is its words in a toast.
  var RARE_WORD='should rarely face the internet';
  var paintRare=function(btn,dismissed){
    var line=btn.closest('.prmk'), label=line.parentNode.previousElementSibling;
    var view=btn.closest('.view'), st=label.querySelector('.prst');
    var mark=st.querySelector('.tag-rare');
    if(dismissed&&mark)mark.remove();
    if(!dismissed&&!mark){var m=document.createElement('span');
      m.className='tag-rare';m.title=RARE_WORD;m.textContent=RARE_WORD;st.appendChild(m)}
    line.classList.toggle('off',dismissed);
    var word=line.querySelector('.st');
    if(dismissed&&!word){word=document.createElement('span');word.className='st off';
      word.textContent='dismissed';line.insertBefore(word,btn)}
    if(!dismissed&&word)word.remove();
    btn.textContent=dismissed?'Restore':'Dismiss';
    btn.dataset.dismiss=dismissed?'0':'1';
    if(label.dataset.rareCounts==='1'){
      var n=view.querySelector('.hstrip>div:nth-child(2) .n');
      var count=n?parseInt(n.textContent,10):NaN;
      if(!isNaN(count)){count=Math.max(0,count+(dismissed?-1:1));n.textContent=String(count);
        // The box's own tone rule (render_live.host_overview_body): red stays
        // while a conflict does, amber while anything is counted.
        if(!n.classList.contains('fail'))n.classList.toggle('warn',count>0)}}
    // The mark beside the server's name stays while any port of it is marked.
    var head=view.querySelector('.hh .stset');
    var any=view.querySelector('.pr .prst .tag-rare');
    var headMark=head&&head.querySelector('.tag-rare');
    if(head&&!any&&headMark)headMark.remove();
    if(head&&any&&!headMark)head.appendChild(any.cloneNode(true));
  };
  // Dismiss and Restore on the CVE check's mark of one port, on its opened
  // row (docs/RECORD.md 4.338), as the rarely-public mark above has them. The
  // request names the port and a yes or a no and never a CVE: which CVEs the
  // mark stands for is the server's to work out
  // (controlplane/app/cvedismiss.py), so a refusal is its words in a toast.
  // The mark was never counted under Needs a decision, so no count moves.
  var paintFix=function(btn,dismissed){
    var line=btn.closest('.prmk'), label=line.parentNode.previousElementSibling;
    var view=btn.closest('.view'), st=label.querySelector('.prst');
    var words=line.querySelector('.w').textContent;
    var mark=st.querySelector('.tag-fix');
    if(dismissed&&mark)mark.remove();
    if(!dismissed&&!mark){var m=document.createElement('span');
      m.className='tag-fix';m.title=words;m.textContent=words;st.appendChild(m)}
    line.classList.toggle('off',dismissed);
    var word=line.querySelector('.st');
    if(dismissed&&!word){word=document.createElement('span');word.className='st off';
      word.textContent='dismissed';line.insertBefore(word,btn)}
    if(!dismissed&&word)word.remove();
    btn.textContent=dismissed?'Restore':'Dismiss';
    btn.dataset.dismiss=dismissed?'0':'1';
    // The mark beside the server's name stays while any port of it is
    // marked. Its words count every marked port, which is the server's to
    // say, so the quiet refresh brings them.
    var head=view.querySelector('.hh .stset');
    var any=view.querySelector('.pr .prst .tag-fix');
    var headMark=head&&head.querySelector('.tag-fix');
    if(head&&!any&&headMark)headMark.remove();
    if(head&&any&&!headMark)head.appendChild(any.cloneNode(true));
  };
  document.addEventListener('click',function(e){
    var btn=e.target.closest&&e.target.closest('.js-fix');
    if(!btn)return;
    e.preventDefault();
    var dismiss=btn.dataset.dismiss==='1';
    ask('/api/admin/hosts/'+btn.dataset.host+'/cve-mark/'+btn.dataset.protocol+'/'+btn.dataset.port,
      {method:'POST',headers:{'Content-Type':'application/json'},
       body:JSON.stringify({dismissed:dismiss})})
    .then(function(a){
      if(!a.ok||typeof a.body.dismissed!=='boolean'){
        toast(a.body.detail||didNotWork(a.status));return}
      paintFix(btn,a.body.dismissed);
      toast(a.body.dismissed?'Dismissed':'Restored');
      refresh(true)})
    .catch(function(){toast(NO_ANSWER)});
  });
  document.addEventListener('click',function(e){
    var btn=e.target.closest&&e.target.closest('.js-rare');
    if(!btn)return;
    e.preventDefault();
    var dismiss=btn.dataset.dismiss==='1';
    ask('/api/admin/hosts/'+btn.dataset.host+'/rarely/'+btn.dataset.protocol+'/'+btn.dataset.port,
      {method:'POST',headers:{'Content-Type':'application/json'},
       body:JSON.stringify({dismissed:dismiss})})
    .then(function(a){
      if(!a.ok||typeof a.body.dismissed!=='boolean'){
        toast(a.body.detail||didNotWork(a.status));return}
      paintRare(btn,a.body.dismissed);
      toast(a.body.dismissed?'Dismissed':'Restored');
      refresh(true)})
    .catch(function(){toast(NO_ANSWER)});
  });
  // Remove opens the window, which asks for the name to be typed and
  // enables Remove only when it matches (docs/screens/host-settings/SPEC.md).
  //
  // **Set up once, outside every wire() pass.** Until 2026-09-14 this sat
  // inside the rename pass above, so every refresh that swapped a piece ran
  // it again: a fresh rmHost, one more input listener on the field, and one
  // more pass wiring the buttons. The buttons ended up on an older run's
  // handler and the newest listener, firing last against its own null,
  // disabled Remove against a name that matched. The owner saw exactly that on
  // 2026-09-13, and a hard reload cleared it (docs/RECORD.md 4.175).
  var rmOvl=document.getElementById('rm-ovl');
  if(rmOvl){
    var rmHost=null, rmDone=false;
    var rmInput=document.getElementById('rm-input'), rmGo=document.getElementById('rm-go');
    var rmLast=document.getElementById('rm-last'), rmCmd=document.getElementById('rm-cmd');
    var rmCancel=rmOvl.querySelector('.acts [data-close]');
    rmInput.addEventListener('input',function(){rmGo.disabled=rmDone||rmInput.value.trim()!==rmHost});
    rmInput.addEventListener('keydown',function(e){if(e.key==='Enter'&&!rmGo.disabled)rmGo.click()});
    // The chip copies the name, so it can be pasted rather than retyped, and
    // the command box copies the command.
    var rmChip=document.getElementById('rm-chip');
    if(rmChip)rmChip.onclick=function(){copyText(rmHost,rmChip)};
    var rmCmdBox=document.getElementById('rm-cmd-v');
    if(rmCmdBox)rmCmdBox.onclick=function(){copyText(rmCmdBox.textContent,rmCmdBox)};
    onWire(function(){
    document.querySelectorAll('.js-remove').forEach(function(b){
      b.onclick=function(){
        rmHost=b.dataset.host;rmDone=false;
        document.getElementById('rm-name').textContent=b.dataset.name||rmHost;
        document.getElementById('rm-name2').textContent=rmHost;
        // What the window says about the machine: when the agent last
        // reported, a warning while it still does, and the one command for
        // the server. An address-only server has no agent and gets neither.
        if(rmLast){rmLast.hidden=!b.dataset.last;
          document.getElementById('rm-last-v').textContent=b.dataset.last||'';
          rmLast.classList.toggle('warn',b.dataset.live==='1')}
        if(rmCmd)rmCmd.hidden=b.dataset.kind!=='agent';
        if(rmCancel)rmCancel.textContent='Cancel';
        rmInput.value='';rmInput.disabled=false;rmGo.disabled=true;
        rmOvl.classList.add('on');rmInput.focus()}});
    });
    rmGo.onclick=function(){
      if(rmDone||!rmHost||rmInput.value.trim()!==rmHost)return;
      rmGo.disabled=true;
      fetch('/api/admin/hosts/'+encodeURIComponent(rmHost)+'/revoke',{method:'POST'})
      .then(function(r){if(r.ok){
        // The server is gone, so its row goes now and the fleet is what is
        // left, the same place a stale link lands on. The window stays open
        // with the command still there to copy
        // (docs/screens/host-settings/BRIEF-remove-command.md), so the page
        // catches up with the server the moment the window closes, below.
        rmDone=true;rmInput.disabled=true;
        var row=document.querySelector('#fleet .row[data-host="'+rmHost+'"]');
        if(row)row.style.display='none';
        if(rmCancel)rmCancel.textContent='Close';
        toast('Removed');goto('fleet')}
        else{rmGo.disabled=false;toast(didNotWork(r.status))}})
      .catch(function(){rmGo.disabled=false;toast(NO_ANSWER)})};
    // Closed by Close, the cross, the backdrop or Escape: all four take the
    // class off, so the class is what is watched.
    new MutationObserver(function(){
      if(rmDone&&!rmOvl.classList.contains('on')){rmDone=false;refresh(true)}
    }).observe(rmOvl,{attributes:true,attributeFilter:['class']});
  }
  // Delete, on a removed server's row under the fleet table: the same typed
  // name, and then the row goes with everything stored about it
  // (docs/PRODUCT.md 4f). Set up once, like Remove.
  var delOvl=document.getElementById('del-ovl');
  if(delOvl){
    var delHost=null;
    var delInput=document.getElementById('del-input'), delGo=document.getElementById('del-go');
    delInput.addEventListener('input',function(){delGo.disabled=delInput.value.trim()!==delHost});
    delInput.addEventListener('keydown',function(e){if(e.key==='Enter'&&!delGo.disabled)delGo.click()});
    var delChip=document.getElementById('del-chip');
    if(delChip)delChip.onclick=function(){copyText(delHost,delChip)};
    onWire(function(){
    document.querySelectorAll('.js-delete').forEach(function(b){
      b.onclick=function(){
        delHost=b.dataset.host;
        document.getElementById('del-name').textContent=b.dataset.name||delHost;
        document.getElementById('del-name2').textContent=delHost;
        delInput.value='';delGo.disabled=true;
        delOvl.classList.add('on');delInput.focus()}});
    });
    delGo.onclick=function(){
      if(!delHost||delInput.value.trim()!==delHost)return;
      delGo.disabled=true;
      fetch('/api/admin/hosts/'+encodeURIComponent(delHost)+'/delete',{method:'POST'})
      .then(function(r){if(r.ok){
        // The row goes at once, and the list with it when that was the last.
        var b=document.querySelector('.js-delete[data-host="'+delHost+'"]');
        var li=b&&b.closest('.li');
        if(li)li.parentNode.removeChild(li);
        var gone=document.querySelector('#fleet .fgone');
        if(gone&&!gone.querySelector('.li'))gone.hidden=true;
        delOvl.classList.remove('on');toast('Deleted');refresh(true)}
        else{delGo.disabled=false;toast(didNotWork(r.status))}})
      .catch(function(){delGo.disabled=false;toast(NO_ANSWER)})};
  }
  // ---- a provider, on a live page ----
  // Connect in the Add window, and the three acts on a provider row's menu.
  // Every one posts to the session's own workspace and paints the answer the
  // server gave: a token the provider refused is refused on the spot with the
  // status it answered, never stored as connected
  // (controlplane/app/ingest.py, the integrations routes).
  var providerWord=function(j){
    if(j.status==='connected')return 'Connected';
    if(j.status==='refused')return 'Token refused'+(j.http_status?', HTTP '+j.http_status:'');
    return 'Could not read the provider'+(j.kind?': '+j.kind:'');
  };
  // Connecting a provider: the request the Add integration window made, to
  // the same route, with the same body. `stage` is the picked provider's own
  // fields in the Add window, whose action calls this.
  var connectProvider=function(stage){
    var field=stage.querySelector('input[type="password"]');
    var token=field?field.value.trim():'';
    // An empty token is refused under the token's field, as a destination's
    // field is, and the line is gone when the field is edited
    // (docs/RECORD.md 4.228). It stood at the foot of the window.
    if(!token){
      connErr.textContent='';
      if(field){refuseField(field,'Paste the read token.');field.focus()}
      return;
    }
    connClear();connGo.disabled=true;
    ask('/api/admin/integrations/'+encodeURIComponent(stage.dataset.type),{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({token:token})})
    .then(function(r){
      connGo.disabled=false;
      if(!r.ok){connErr.textContent=r.body.detail||didNotWork(r.status);return}
      if(field)field.value='';
      connOvl.classList.remove('on');
      toast(providerWord(r.body));
      refresh(true)})
    .catch(function(){connGo.disabled=false;connErr.textContent=NO_ANSWER});
  };
  // A workspace holds one token per project (docs/RECORD.md 4.206), so every
  // act below names the row's token by the id the row carries, and a row with
  // none acts on the workspace's only token, as the server reads it.
  var tokenBody=function(token,extra){
    var body=extra||{};
    if(token)body.token_id=Number(token);
    return body;
  };
  var ptokOvl=document.getElementById('ptok-ovl'), ptokProvider='', ptokToken='';
  if(ptokOvl){
    var ptokGo=document.getElementById('ptok-go'), ptokIn=document.getElementById('ptok-input'),
        ptokErr=document.getElementById('ptok-err');
    ptokGo.onclick=function(){
      var token=ptokIn.value.trim();
      if(!token){ptokErr.textContent='Paste the read token.';return}
      ptokErr.textContent='';ptokGo.disabled=true;
      ask('/api/admin/integrations/'+encodeURIComponent(ptokProvider)+'/token',{method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify(tokenBody(ptokToken,{token:token}))})
      .then(function(r){
        ptokGo.disabled=false;
        if(!r.ok){ptokErr.textContent=r.body.detail||didNotWork(r.status);return}
        ptokIn.value='';ptokOvl.classList.remove('on');
        toast(providerWord(r.body));
        refresh(true)})
      .catch(function(){ptokGo.disabled=false;ptokErr.textContent=NO_ANSWER});
    };
  }
  var providerAct=function(provider,token,act,word){
    closeMenus();
    toast(word+'...');
    ask('/api/admin/integrations/'+encodeURIComponent(provider)+'/'+act,{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify(tokenBody(token))})
    .then(function(r){
      if(!r.ok){toast(r.body.detail||didNotWork(r.status));return}
      toast(act==='read'?providerWord(r.body):'Disconnected');
      refresh(true)})
    .catch(function(){toast(NO_ANSWER)});
  };
  onWire(function(){
    document.querySelectorAll('.js-prov-read').forEach(function(b){
      b.onclick=function(){providerAct(b.dataset.provider,b.dataset.token,'read','Reading')}});
    document.querySelectorAll('.js-prov-token').forEach(function(b){
      b.onclick=function(){
        closeMenus();ptokProvider=b.dataset.provider;ptokToken=b.dataset.token||'';
        if(ptokOvl){ptokErr.textContent='';ptokIn.value='';ptokOvl.classList.add('on');ptokIn.focus()}}});
    document.querySelectorAll('.js-prov-off').forEach(function(b){
      b.onclick=function(){
        closeMenus();
        // The title and the red button say it; no sentence under them
        // (the rule for customer screens), the same as the Remove window.
        // With two rows of one provider the name alone does not say which,
        // so the title carries the token's hint as its row shows it.
        var row=b.closest('.al'), name=b.dataset.provider, hint='';
        if(row){name=row.querySelector('.pvn').textContent.trim();
          var tok=row.querySelector('.pvtok');hint=tok?tok.textContent.trim():''}
        askConfirm('Disconnect '+name+(hint?' '+hint:'')+'?',
          '','Disconnect',
          function(){providerAct(b.dataset.provider,b.dataset.token,'disconnect','Disconnecting')})}});
  });
  // ---- Mute, and how long for ----
  // The button paints the answer on the click and the request goes out behind
  // it, the same order every other action on this page takes. If the server
  // refuses, the paint is undone and the button says what happened, which is
  // the only case where anything is said at all.
  var setMuted=function(box,on){
    box.dataset.muted=on?'1':'';
    var trigger=box.querySelector('[data-menu]');
    if(trigger)trigger.textContent=on?'Muted':'Mute';
    var un=box.querySelector('[data-act="unmute"]');
    if(un)un.hidden=!on;
    // The muted marks beside this host's state, in its header and on its
    // fleet row. Filled and emptied here so the whole page tells one story
    // the moment the click lands.
    var host=box.dataset.host||'';
    document.querySelectorAll('[data-mute-tag="'+host+'"]').forEach(function(t){
      t.textContent=on?'muted':''});
  };
  onWire(function(){
  document.querySelectorAll('.js-mute').forEach(function(b){
    b.onclick=function(){
      var box=b.closest('.rmenu'), host=b.dataset.host;
      var wanted=b.dataset.act!=='unmute', was=box.dataset.muted==='1';
      closeMenus();
      setMuted(box,wanted);
      // An empty data-seconds is the length that has no end, and the control
      // plane takes that as its own field rather than as a zero.
      var opts={method:'POST'};
      if(wanted){
        opts.headers={'Content-Type':'application/json'};
        opts.body=JSON.stringify(b.dataset.seconds
          ?{seconds:parseInt(b.dataset.seconds,10)}:{indefinite:true});
      }
      fetch('/api/admin/hosts/'+encodeURIComponent(host)+'/'+(wanted?'mute':'unmute'),opts)
        .then(function(r){
          if(!r.ok)throw new Error('That did not save, so nothing changed.');
        })
        // One place undoes it, so a refused request and a dead connection take
        // the same path and the button cannot be un-painted twice.
        .catch(function(e){setMuted(box,was);toast(e.message)});
    }});
  });

  // Pause. On means paused. The switch flips before the server answers, because
  // a click shows its result at once, and a non-204 answer flips it back so the
  // screen never claims a state the server refused. A switch without data-host
  // (the sample page's copy) is left alone rather than posting to nowhere.
  onWire(function(){
  document.querySelectorAll('.js-pause').forEach(function(b){
    b.onclick=function(){
      if(!b.dataset.host)return;
      // One click at a time. A second one while the first was on its way
      // posted the opposite, so a double click paused and unpaused and the
      // server ended as it began (measured 2026-10-04, docs/RECORD.md
      // 4.362). Held by a mark and not by `disabled`, which would draw the
      // switch grey, the way a planned one is drawn.
      if(b.dataset.busy)return;
      b.dataset.busy='1';
      var free=function(){b.dataset.busy=''};
      b.classList.toggle('off');
      var paused=!b.classList.contains('off');
      fetch('/api/admin/hosts/'+b.dataset.host+'/pause',{method:'POST',
        headers:{'Content-Type':'application/json'},body:JSON.stringify({paused:paused})})
      .then(function(r){
        free();
        if(r.status!==204){b.classList.toggle('off');
          return r.json().catch(function(){return {}}).then(function(j){
            toast(j.detail||didNotWork(r.status))})}
        // The word on the fleet row and in the header moves with this.
        refresh(true)})
      .catch(function(){free();b.classList.toggle('off');
        toast(NO_ANSWER)})}});
  });
  // ---- Silence one port, from the alert that keeps naming it ----
  // The same order every other action on this page takes: the menu paints the
  // answer on the click and the request goes out behind it, and a refusal
  // undoes the paint and says what happened. It stops the mail and nothing
  // else, so the alert stays open and the count above it does not move.
  var setSilenced=function(box,on){
    box.dataset.silenced=on?'1':'';
    var off=box.querySelector('[data-act="silence"]');
    var back=box.querySelector('[data-act="unsilence"]');
    if(off)off.hidden=on;
    if(back)back.hidden=!on;
    // The mark on the row this menu belongs to. Written empty by the builder
    // and filled here, so the row says what was just done to it.
    var row=box.closest('.lst');
    var tag=row&&row.querySelector('[data-silence-tag]');
    if(tag)tag.textContent=on?'__SILENCED_WORD__':'';
  };
  onWire(function(){
  document.querySelectorAll('.js-silence').forEach(function(b){
    b.onclick=function(){
      var box=b.closest('.rmenu');
      var wanted=b.dataset.act==='silence', was=box.dataset.silenced==='1';
      closeMenus();
      setSilenced(box,wanted);
      fetch(portPath(b.dataset.host,b.dataset.protocol,b.dataset.port,
                     b.dataset.family,wanted?'silence':'unsilence'),
            {method:'POST'})
      .then(portRefusal)
      .then(function(refused){
        if(refused){setSilenced(box,was);toast(refused)}})
      .catch(function(){setSilenced(box,was);
        toast(NO_ANSWER)})}});
  });
  // The Alerts screen's row actions (docs/screens/alerts/SPEC.md). Silence
  // stops the mail for that port and the alert stays open, Pause stops a
  // silent server's alerts. Each paints its word at once and the request goes
  // out behind it, and a refusal puts the button back and says why. The click
  // stops there, because the row around it goes to the server.
  // The count beside Alerts is how many alerts still want an answer, so one
  // that was just silenced or paused leaves it on the click rather than on the
  // next render (docs/PRODUCT.md 4c). Only the buttons on this screen move it,
  // because only here is the alert the button belongs to on the page.
  var alertCountDown=function(){
    var badge=document.querySelector('.nav .nb');
    if(!badge)return;
    var left=(parseInt(badge.textContent,10)||0)-1;
    if(left>0)badge.textContent=left;else badge.remove();
  };
  var alertAction=function(b,doneWord,request,done){
    var word=b.textContent;
    b.textContent=doneWord;b.disabled=true;
    var back=function(said){b.textContent=word;b.disabled=false;toast(said)};
    request().then(function(refused){if(refused)back(refused);else if(done)done()})
      .catch(function(){back(NO_ANSWER)});
  };
  onWire(function(){
  document.querySelectorAll('.js-al-silence').forEach(function(b){
    b.onclick=function(e){
      e.stopPropagation();
      alertAction(b,'Silenced',function(){
        return fetch(portPath(b.dataset.host,b.dataset.protocol,b.dataset.port,
                              b.dataset.family,'silence'),{method:'POST'})
          .then(portRefusal)},alertCountDown);
    }});
  document.querySelectorAll('.js-al-pause').forEach(function(b){
    b.onclick=function(e){
      e.stopPropagation();
      alertAction(b,'Paused',function(){
        return fetch('/api/admin/hosts/'+encodeURIComponent(b.dataset.host)+'/pause',
          {method:'POST',headers:{'Content-Type':'application/json'},
           body:JSON.stringify({paused:true})})
          .then(function(r){
            if(r.status===204)return '';
            return r.json().catch(function(){return {}})
              .then(function(j){return j.detail||didNotWork(r.status)})})},
        alertCountDown);
    }});
  });
  // ---- the Packet path's wire ----
  //
  // docs/screens/host-packet-path/SPEC.md. The wire runs through the middle of
  // every tool's box, so a packet slips behind a tool and comes out the far
  // side. Only the browser knows where a wrapped row of boxes landed, so the
  // path is measured from the placed elements.
  //
  // **This lays the wire and nothing else.** The packets are flown along it by
  // CSS, which is why there is no frame loop here: one that ran for as long as
  // the page is open would cost a frame of work forever on a still page, and
  // it stops dead wherever nothing drives frames.
  // How fast a packet travels, and how far apart they ride. Both are in the
  // wire's own pixels, so a wrapped path and a straight one look the same.
  var PT_SPEED = 105, PT_APART = 170, PT_R = 14, ptFlows = [], ptSizes = null;
  var ptRel=function(el,box){var r=el.getBoundingClientRect();
    return {x:r.left-box.left,y:r.top-box.top,w:r.width,h:r.height}};
  // One leg of the wire. Along a row it is straight. Where a row wraps it
  // drops into the gap, runs back across and drops into the next row.
  var ptStep=function(a,b){
    if(Math.abs(a.y-b.y)<4)return ' L'+b.x+' '+b.y;
    if(a.mid&&b.mid){
      var ym=(a.y+b.y)/2, dir=b.x<a.x?-1:1;
      return ' L'+a.x+' '+(ym-PT_R)+' Q'+a.x+' '+ym+' '+(a.x+dir*PT_R)+' '+ym+
             ' L'+(b.x-dir*PT_R)+' '+ym+' Q'+b.x+' '+ym+' '+b.x+' '+(ym+PT_R)+
             ' L'+b.x+' '+b.y;
    }
    var mx=(a.x+b.x)/2;
    return ' C'+mx+' '+a.y+' '+mx+' '+b.y+' '+b.x+' '+b.y};
  var ptLayout=function(f){
    var box=f.fl.getBoundingClientRect();
    if(!box.width)return;
    f.w=f.fl.clientWidth;
    f.svg.setAttribute('width',box.width);f.svg.setAttribute('height',box.height);
    f.svg.setAttribute('viewBox','0 0 '+box.width+' '+box.height);
    var left=f.fl.querySelector('.pt-endL .pt-tile');
    var right=f.fl.querySelector('.pt-endR .pt-tile');
    if(!left||!right)return;
    var L=ptRel(left,box), E=ptRel(right,box);
    var pts=[{x:L.x+L.w,y:L.y+L.h/2,mid:false}];
    f.fl.querySelectorAll('.pt-mid .pt-nd').forEach(function(n){
      var q=ptRel(n,box);pts.push({x:q.x+q.w/2,y:q.y+q.h/2,mid:true})});
    pts.push({x:E.x,y:E.y+E.h/2,mid:false});
    var whole='M'+pts[0].x+' '+pts[0].y, upto=[whole];
    for(var i=1;i<pts.length;i++){whole+=ptStep(pts[i-1],pts[i]);upto.push(whole)}
    // The packets go into the tool that ends the journey and do not come out,
    // and the wire past it goes quiet.
    var stops=f.fate==='stop'&&f.stop>=0&&f.stop+1<pts.length;
    var flown=stops?upto[f.stop+1]:whole;
    f.live.setAttribute('d',flown);
    if(stops){
      var rest='M'+pts[f.stop+1].x+' '+pts[f.stop+1].y;
      for(var j=f.stop+2;j<pts.length;j++)rest+=ptStep(pts[j-1],pts[j]);
      f.quiet.setAttribute('d',rest);
    }else{f.quiet.setAttribute('d','')}
    // Hand the packets the path and the pace. Every wire runs at the same
    // speed whatever its shape, so a longer path simply takes longer, and the
    // packets sit a fixed distance apart rather than a fixed count per wire:
    // five of them crammed into the short hop to a tool that stops the
    // journey read as a queue rather than as traffic.
    var length=f.live.getTotalLength();
    var seconds=Math.max(1.2,length/PT_SPEED);
    var riding=Math.max(1,Math.min(f.pk.length,Math.round(length/PT_APART)));
    f.fl.style.setProperty('--pt-dur',seconds.toFixed(2)+'s');
    f.fl.style.setProperty('--pt-beat',(seconds/riding).toFixed(2)+'s');
    f.pk.forEach(function(c,i){
      if(i>=riding){c.style.display='none';return}
      c.style.display='';
      c.style.offsetPath='path("'+flown+'")';
      c.style.animationDelay=(-(i*seconds/riding)).toFixed(2)+'s'});
  };
  // Collected on every binding pass, because a quiet refresh replaces the
  // elements these hold on to. A flow lays itself out when it is first shown
  // and whenever its width changes, which is the same event: a hidden walk
  // has no width until the chip above it is picked.
  onWire(function(){
    if(ptSizes)ptSizes.disconnect();
    ptSizes=window.ResizeObserver?new ResizeObserver(function(seen){
      seen.forEach(function(entry){
        ptFlows.forEach(function(f){if(f.fl===entry.target)ptLayout(f)})})}):null;
    ptFlows=[];
    document.querySelectorAll('.pt-flow').forEach(function(fl){
      var svg=fl.querySelector('svg.pt-wire');
      if(!svg)return;
      var f={fl:fl,svg:svg,live:svg.querySelector('.pt-live'),
             quiet:svg.querySelector('.pt-quiet'),
             pk:Array.prototype.slice.call(svg.querySelectorAll('.pt-pk')),
             fate:fl.dataset.fate,stop:parseInt(fl.dataset.stop||'-1',10),w:-1};
      ptFlows.push(f);
      ptLayout(f);
      if(ptSizes)ptSizes.observe(fl)});
  });
  // Without a ResizeObserver the window's own resize is the fallback.
  window.addEventListener('resize',function(){
    if(!ptSizes)ptFlows.forEach(ptLayout)});
  // The password rules, coloured while somebody types (docs/screens/sign-in,
  // 2026-09-10). Grey before anything is typed, red while a rule is unmet,
  // green when it is met. The three tests are keyed on the same words
  // build.PASSWORD_RULES uses, and test_password_rules.py fails if the two
  // lists ever stop matching.
  var RULE_TESTS={
    length:function(v){return v.length>=__PASSWORD_MIN__},
    digit:function(v){return /[0-9]/.test(v)},
    special:function(v){return /[^A-Za-z0-9]/.test(v)}
  };
  onWire(function(){
  document.querySelectorAll('.rules[data-for]').forEach(function(list){
    var input=document.getElementById(list.dataset.for);
    if(!input)return;
    var confirm=list.dataset.confirm?document.getElementById(list.dataset.confirm):null;
    var paint=function(){
      var value=input.value||'';
      var second=confirm?(confirm.value||''):'';
      list.querySelectorAll('li[data-rule]').forEach(function(li){
        var test=RULE_TESTS[li.dataset.rule];
        // Every rule stays grey until the field it is about has something in
        // it. For the three tests that is the password field, for the match
        // it is the confirm field, which is why it reads its own value: a red
        // line on a box nobody has reached yet is an error nobody made.
        var typed=test?value:second;
        var ok=test?test(value):(!!second&&second===value);
        li.classList.toggle('yes',!!typed&&ok);
        li.classList.toggle('no',!!typed&&!ok);
      });
    };
    input.oninput=paint;
    if(confirm)confirm.oninput=paint;
    paint();
  });
  });
  // Turning the authenticator app on, in the window on the Security settings.
  // The secret is minted when the window opens, so nothing is drawn until the
  // control plane answers, and the recovery codes it hands back at the end are
  // the only readable copy there will ever be.
  var twoFactor=document.getElementById('tfa-ovl');
  if(twoFactor){
    var qrBox=document.getElementById('tfa-qr'), keyBox=document.getElementById('tfa-key');
    var setup=document.getElementById('tfa-setup'), codesStage=document.getElementById('tfa-codes');
    var codeList=document.getElementById('tfa-codelist');
    var twoErr=document.getElementById('tfa-err'), twoGo=document.getElementById('tfa-go');
    var codeField=document.getElementById('tfa-code');
    // The QR arrives as rows of "0" and "1" and is drawn here, with elements
    // and attributes rather than markup: nothing parses an answer, and the
    // page still holds no image and fetches nothing. One path of squares,
    // because a rect per module is thousands of elements for the same picture.
    var SVG='http://www.w3.org/2000/svg';
    var drawQr=function(rows){
      qrBox.textContent='';
      if(!rows.length)return;
      var d='';
      for(var y=0;y<rows.length;y++){
        for(var x=0;x<rows[y].length;x++){
          if(rows[y][x]==='1')d+='M'+x+' '+y+'h1v1h-1z';
        }
      }
      var svg=document.createElementNS(SVG,'svg');
      svg.setAttribute('viewBox','0 0 '+rows[0].length+' '+rows.length);
      svg.setAttribute('shape-rendering','crispEdges');
      var path=document.createElementNS(SVG,'path');
      // Near-black on the white ground the box paints, because a QR has to be
      // dark on light to scan whatever theme the page is in.
      path.setAttribute('fill','#16161F');
      path.setAttribute('d',d);
      svg.appendChild(path);
      qrBox.appendChild(svg);
    };
    var showCodes=function(codes){
      // Elements and textContent, never markup from an answer.
      codeList.textContent='';
      codes.forEach(function(code){
        var cell=document.createElement('span');
        cell.textContent=code;
        codeList.appendChild(cell);
      });
      codeList.dataset.copy=codes.join('\n');
      setup.classList.remove('on');
      codesStage.classList.add('on');
      twoGo.hidden=true;
      // The way out says the window is finished rather than abandoned.
      var close=twoFactor.querySelector('.m-foot [data-close="tfa-ovl"]');
      if(close)close.textContent='Done';
      // The state on the row behind the window moves at once.
      document.querySelectorAll('.js-who-totp').forEach(function(b){b.classList.remove('off')});
      document.querySelectorAll('.js-2fa-on').forEach(function(b){b.hidden=true});
    };
    document.querySelectorAll('[data-open="tfa-ovl"]').forEach(function(b){
      b.addEventListener('click',function(){
        twoErr.textContent='';qrBox.textContent='';keyBox.textContent='';
        // A window reopened after it finished starts at the beginning again.
        setup.classList.add('on');codesStage.classList.remove('on');
        if(twoGo)twoGo.hidden=false;
        var back=twoFactor.querySelector('.m-foot [data-close="tfa-ovl"]');
        if(back)back.textContent='Cancel';
        if(codeField)codeField.value='';
        fetch('/api/admin/account/2fa/start',{method:'POST',cache:'no-store'})
        .then(function(r){
          if(r.status!==200)return r.json().catch(function(){return {}})
            .then(function(j){twoErr.textContent=j.detail||didNotWork(r.status)});
          return r.json().then(function(j){
            drawQr(j.qr||[]);
            keyBox.textContent=j.groups||'';
            keyBox.dataset.copy=j.groups||'';
          })})
        .catch(function(){twoErr.textContent=NO_ANSWER});
      })});
    if(twoGo){
      twoGo.onclick=function(){
        twoErr.textContent='';twoGo.disabled=true;
        fetch('/api/admin/account/2fa/confirm',{method:'POST',
          headers:{'Content-Type':'application/json'},
          body:JSON.stringify({code:codeField?codeField.value:''})})
        .then(function(r){
          twoGo.disabled=false;
          if(r.status!==200)return r.json().catch(function(){return {}})
            .then(function(j){twoErr.textContent=j.detail||didNotWork(r.status)});
          return r.json().then(function(j){showCodes(j.codes||[])})})
        .catch(function(){twoGo.disabled=false;twoErr.textContent=NO_ANSWER});
      };
    }
    // A click on a box copies what it holds, the way the install command
    // does, and Download writes the codes from the page rather than from a
    // second route that would have to hold them.
    document.querySelectorAll('#tfa-key,#tfa-codelist').forEach(function(box){
      box.onclick=function(){
        if(!box.dataset.copy)return;
        if(navigator.clipboard&&navigator.clipboard.writeText){
          navigator.clipboard.writeText(box.dataset.copy).then(function(){
            box.classList.add('copied');
            setTimeout(function(){box.classList.remove('copied')},900)},function(){});
        }}});
    document.querySelectorAll('.js-2fa-download').forEach(function(b){
      b.onclick=function(){
        var blob=new Blob([(codeList.dataset.copy||'')+'\n'],{type:'text/plain'});
        var a=document.createElement('a');
        a.href=URL.createObjectURL(blob);
        a.download='whichports-recovery-codes.txt';
        a.click();
        URL.revokeObjectURL(a.href);
      }});
  }
  // The account Settings screen's two names (docs/screens/account-settings):
  // Save appears once the field differs from what is stored, Enter saves,
  // Escape puts it back, a refusal is a toast with the field left as typed.
  var wireNameField=function(input,saveSel,path){
    var save=input.parentNode.querySelector(saveSel);
    if(!save)return;
    var mark=function(){save.hidden=input.value.trim()===input.defaultValue.trim()};
    input.oninput=mark;
    input.onkeydown=function(e){
      if(e.key==='Enter'){e.preventDefault();if(!save.hidden)save.click()}
      if(e.key==='Escape'){input.value=input.defaultValue;mark()}
    };
    save.onclick=function(){
      var name=input.value.trim();
      save.disabled=true;
      fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({name:name})})
      .then(function(r){
        save.disabled=false;
        if(r.status===204){input.value=name;input.defaultValue=name;mark();
          document.querySelectorAll('.js-who-name-text').forEach(function(e){if(path.indexOf('account')>0)e.textContent=name||e.textContent});
          return}
        return r.json().catch(function(){return {}}).then(function(j){toast(j.detail||didNotWork(r.status))})})
      .catch(function(){save.disabled=false;toast(NO_ANSWER)});
    };
    mark();
  };
  onWire(function(){
  document.querySelectorAll('.js-who-name').forEach(function(i){
    wireNameField(i,'.js-name-save','/api/admin/account/name')});
  document.querySelectorAll('.js-wsname').forEach(function(i){
    wireNameField(i,'.js-ws-save','/api/admin/workspace/name')});
  });
  // Change password: the current one is checked by the control plane, and
  // a refusal is written under the fields rather than raised as a toast,
  // because the window stays open for another try.
  // ---- Feedback: the words a person types, sent with a click and at no
  // other time (docs/screens/feedback/BRIEF.md, the one exception to SI-8,
  // docs/record 4.425). The window is the whole of what leaves: five
  // fields, and the first request of any kind is the click on Send.
  //
  // The screen word comes from the view and its tab, never from the address
  // bar, which holds a server's name. The twelve words are the builder's
  // list, the same one the instance's route refuses anything outside of.
  var FEEDBACK_SCREENS=__FEEDBACK_SCREENS__;
  var FEEDBACK_MAX=__FEEDBACK_MAX__;
  // One line a person reads per class the instance or our box can answer
  // with. The no-answer line is the page's own, NO_ANSWER above.
  var FEEDBACK_LINES={
    unknown_key:function(to){return to+" did not accept this instance's key."},
    too_large:function(){return 'Too long. 2,000 characters at most.'},
    over_instance_pace:function(){return 'Twenty messages a day is the most. Try again tomorrow.'},
    malformed_request:function(to){return to+' could not read this message, HTTP 400.'},
    unsupported_version:function(to){return to+' could not read this message, HTTP 400.'}
  };
  var feedbackScreen=function(){
    var view=document.querySelector('.view.on');
    var id=view?view.id:'fleet';
    var word=id;
    if(id==='host'||id.indexOf('host-')===0){
      var tab=currentTab(id);
      word=(tab&&tab!=='overview')?'host/'+tab:'host';
    }
    return FEEDBACK_SCREENS.indexOf(word)>=0?word:'fleet';
  };
  // The wire's one list of characters that go (controlplane/app/feedback.py,
  // clean): a Windows newline becomes a newline, every control but the
  // newline goes, and the marks that turn a line's direction go. Done as
  // the person types, so what is shown is what is sent.
  var feedbackClean=function(text){
    return String(text).replace(/\r\n/g,'\n')
      .replace(/[\u0000-\u0009\u000B-\u001F\u007F-\u009F]/g,'')
      .replace(/[\u202A-\u202E\u2066-\u2069]/g,'');
  };
  // Code points, as our box counts, never UTF-16 units: an emoji is one.
  var feedbackCount=function(text){return Array.from(String(text)).length;};
  var fbOvl=document.getElementById('fb-ovl'), fbGo=document.getElementById('fb-go');
  if(fbOvl&&fbGo){
    var fbWords=document.getElementById('fb-words'), fbTo=document.getElementById('fb-to');
    var fbResult=document.getElementById('fb-result');
    var fbKindV=document.getElementById('fb-kind'), fbScreenV=document.getElementById('fb-screen');
    var fbVersionV=document.getElementById('fb-version');
    var fbCancel=fbOvl.querySelector('.m-foot [data-close="fb-ovl"]');
    var fbCards={feature:document.getElementById('fb-feature'),bug:document.getElementById('fb-bug')};
    var fbKind='';
    // On an instance without our key the message stays on this one, and
    // the To line names the page's own host.
    if(fbTo&&fbTo.dataset.own)fbTo.textContent=location.host;
    // One line for every answer, under the five facts: fail for a refusal,
    // the cap and no answer, ok for Sent, empty between.
    var fbLine=function(text,tone){fbResult.textContent=text;fbResult.className='m-result'+(text?' '+(tone||'fail'):'')};
    // Send waits for a kind and for words, and nothing over the cap is
    // ever sent: the cap's own line shows at once instead.
    var fbReady=function(){
      var n=feedbackCount(fbWords.value), over=n>FEEDBACK_MAX;
      if(over)fbLine(FEEDBACK_LINES.too_large());
      else if(fbResult.textContent===FEEDBACK_LINES.too_large())fbLine('');
      fbGo.disabled=!(fbKind&&n>0&&!over);
    };
    var fbPick=function(k){
      fbKind=k;
      Object.keys(fbCards).forEach(function(key){fbCards[key].classList.toggle('sel',key===k)});
      fbKindV.textContent=k;
      fbReady();
    };
    Object.keys(fbCards).forEach(function(k){fbCards[k].onclick=function(){fbPick(k)}});
    fbWords.oninput=function(){
      var cleaned=feedbackClean(fbWords.value);
      if(cleaned!==fbWords.value){
        var at=fbWords.selectionStart;
        fbWords.value=cleaned;
        try{fbWords.selectionStart=fbWords.selectionEnd=Math.min(at,cleaned.length)}catch(e){}
      }
      fbReady();
    };
    // Every open starts empty: the screen the button was pressed on, no
    // kind, no words, no answer. A message closed is gone, by the brief.
    var fbOpen=function(){
      fbKind='';
      Object.keys(fbCards).forEach(function(k){fbCards[k].classList.remove('sel')});
      fbKindV.textContent='';
      fbScreenV.textContent=feedbackScreen();
      fbWords.value='';
      fbLine('');
      fbGo.hidden=false;fbGo.textContent='Send';fbGo.classList.remove('fb-wait');
      if(fbCancel)fbCancel.textContent='Cancel';
      fbReady();
      fbOvl.classList.add('on');
      fbWords.focus();
    };
    document.querySelectorAll('[data-open="fb-ovl"]').forEach(function(b){
      b.addEventListener('click',fbOpen)});
    // From the click to the answer: Send is disabled with the spinner for
    // ten seconds at most, then one line. The words stay unless it was
    // sent. An answer after the wait is over is not taken.
    fbGo.onclick=function(){
      if(fbGo.disabled)return;
      var body={version:1,kind:fbKind,words:feedbackClean(fbWords.value),
        screen:fbScreenV.textContent,instance_version:fbVersionV.textContent};
      var to=fbTo?fbTo.textContent:'';
      fbLine('');
      fbGo.textContent='Send';fbGo.disabled=true;fbGo.classList.add('fb-wait');
      var over=false;
      var ctl=('AbortController' in window)?new AbortController():null;
      var done=function(){clearTimeout(timer);fbGo.disabled=false;fbGo.classList.remove('fb-wait')};
      var noAnswer=function(){done();fbLine(NO_ANSWER);fbGo.textContent='Try again'};
      var timer=setTimeout(function(){over=true;if(ctl)ctl.abort();noAnswer()},10000);
      fetch('/api/admin/feedback',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify(body),signal:ctl?ctl.signal:undefined})
      .then(function(r){
        return r.json().catch(function(){return {}}).then(function(j){
          if(over)return;
          if(r.status===200&&j&&j.stored===true){
            done();fbWords.value='';fbReady();
            fbLine('Sent','ok');
            fbGo.hidden=true;
            if(fbCancel)fbCancel.textContent='Done';
            return}
          var line=j&&FEEDBACK_LINES[j.error];
          if(line){done();fbLine(line(to));return}
          noAnswer();
        })})
      .catch(function(){if(!over)noAnswer()});
    };
    fbReady();
  }
  // ---- the console's Feedback tab: Done moves a row under the fold,
  // Delete asks with the page's own dialog and takes the row out. The
  // counts follow: the hint, the tab's badge and the Admin entry's badge,
  // whose number is the strip's faults plus the open messages. Bound again
  // after every swap, like every control on the screen.
  onWire(function(){
  var fbTab=document.getElementById('t-admin-feedback');
  var fbFold=document.getElementById('fb-done');
  if(!fbTab||!fbFold)return;
  var openTable=fbTab.querySelector('.panel.ftbl'), doneTable=fbFold.querySelector('.panel.ftbl');
  var countRows=function(table){return table.querySelectorAll('.row.frow[data-id]').length};
  var navEntry=null;
  document.querySelectorAll('.nav a').forEach(function(a){if(a.dataset.v==='admin')navEntry=a});
  var navMark=navEntry&&navEntry.querySelector('.nb');
  var faults=(navMark?parseInt(navMark.textContent,10)||0:0)-countRows(openTable);
  var setBadge=function(parent,id,n){
    if(!parent)return;
    var mark=parent.querySelector('.nb');
    if(n<1){if(mark)mark.remove();return}
    if(!mark){mark=document.createElement('span');mark.className='nb';if(id)mark.id=id;parent.appendChild(mark)}
    mark.textContent=String(n);
  };
  var emptyLine=function(table,text){
    var rows=countRows(table), empty=table.querySelector('.row .empty');
    if(rows&&empty)empty.parentNode.remove();
    if(!rows&&!empty){
      var d=document.createElement('div');d.className='row frow';
      var e=document.createElement('div');e.className='empty';e.textContent=text;
      d.appendChild(e);table.appendChild(d);
    }
  };
  var recount=function(){
    var open=countRows(openTable), done=countRows(doneTable);
    emptyLine(openTable,'no message yet');emptyLine(doneTable,'nothing done yet');
    document.getElementById('fb-hint').textContent=open+' open, '+done+' done';
    document.getElementById('fb-done-n').textContent=String(done);
    setBadge(document.querySelector('.subnav label.k-feedback'),'fb-open-nb',open);
    setBadge(navEntry,'',faults+open);
  };
  fbTab.querySelectorAll('.js-fb-done').forEach(function(b){b.onclick=function(){
    var row=b.closest('.row.frow');
    b.disabled=true;
    fetch('/api/admin/feedback/'+row.dataset.id+'/done',{method:'POST'})
    .then(function(r){
      if(!r.ok){b.disabled=false;toast(didNotWork(r.status));return}
      b.remove();
      var head=doneTable.querySelector('.thead');
      head.parentNode.insertBefore(row,head.nextSibling);
      recount();
    })
    .catch(function(){b.disabled=false;toast(NO_ANSWER)});
  }});
  fbTab.querySelectorAll('.js-fb-del').forEach(function(b){b.onclick=function(){
    var row=b.closest('.row.frow');
    askConfirm('Delete this message?',row.dataset.from+', '+row.dataset.when,'Delete',function(){
      b.disabled=true;
      fetch('/api/admin/feedback/'+row.dataset.id+'/delete',{method:'POST'})
      .then(function(r){
        if(!r.ok){b.disabled=false;toast(didNotWork(r.status));return}
        row.remove();
        recount();
      })
      .catch(function(){b.disabled=false;toast(NO_ANSWER)});
    });
  }});
  });
  var pwGo=document.getElementById('pw-go');
  if(pwGo){
    var pwOvl=document.getElementById('pw-ovl'), pwErr=document.getElementById('pw-err');
    pwGo.onclick=function(){
      var cur=document.getElementById('pw-current'), nw=document.getElementById('pw-new');
      var again=document.getElementById('pw-again');
      pwErr.textContent='';
      if(again&&nw.value!==again.value){pwErr.textContent='Those two do not match.';return}
      pwGo.disabled=true;
      fetch('/api/admin/account/password',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify({current:cur.value,new:nw.value})})
      .then(function(r){
        pwGo.disabled=false;
        if(r.status===204){cur.value='';nw.value='';if(again)again.value='';
          document.querySelectorAll('#pw-ovl .rules li').forEach(function(li){
            li.classList.remove('yes','no')});
          pwOvl.classList.remove('on');
          document.querySelectorAll('.js-who-pwd').forEach(function(e){e.textContent=whenText(new Date().toISOString())});
          return}
        return r.json().catch(function(){return {}}).then(function(j){pwErr.textContent=j.detail||didNotWork(r.status)})})
      .catch(function(){pwGo.disabled=false;pwErr.textContent=NO_ANSWER});
    };
  }
  // Unsilence, on the Settings tab's row. The row goes at once and a
  // refusal is a toast with the row back.
  onWire(function(){
  document.querySelectorAll('.js-unsilence').forEach(function(b){
    b.onclick=function(){
      var row=b.closest('.li');
      b.disabled=true;
      fetch(portPath(b.dataset.host,b.dataset.protocol,b.dataset.port,b.dataset.family,'unsilence'),
            {method:'POST'})
      .then(portRefusal)
      .then(function(refused){
        if(refused){b.disabled=false;toast(refused);return}
        row.remove();refresh(true)})
      .catch(function(){b.disabled=false;toast(NO_ANSWER)})}});
  });
  // Scan now. No window (docs/screens/host-overview/SPEC.md: "with no
  // dialog"). The click marks this server's Probed fact as probing at once,
  // and the page then asks for itself a few times, so the mark, the age and
  // the family marks follow what the server says: the mark stays while a pass
  // runs and goes when it is done. A refusal is the control plane's own
  // sentence, as a toast. The window this replaced held a command for the
  // agent, which SI-2 means nothing here can run, and which nobody needs to:
  // the agent reports by itself (docs/RECORD.md 4.196).
  var SCAN_FOLLOW_MS=[4000,9000,16000,28000,45000];
  onWire(function(){
  document.querySelectorAll('.js-scan').forEach(function(b){
    b.onclick=function(){
      var host=b.dataset.host;
      b.disabled=true;
      ask('/api/admin/hosts/'+encodeURIComponent(host)+'/scan',{method:'POST'})
      .then(function(r){
        b.disabled=false;
        if(!r.ok){toast(r.body.detail||didNotWork(r.status));return}
        if(!r.body.accepted){toast(r.body.sentence||didNotWork(r.status));return}
        document.querySelectorAll('[data-probed]').forEach(function(f){
          if(f.dataset.probed===host)f.classList.add('probing')});
        SCAN_FOLLOW_MS.forEach(function(ms){
          setTimeout(function(){refresh(true)},ms)});
      })
      .catch(function(){b.disabled=false;toast(NO_ANSWER)});
    }});
  });
  // The state a word wears, handed over by page() as data rather than
  // written a second time here, so a tone means one thing on both sides.
  var PORT_TONE=__TONE_JSON__;
  // ---- the Host Overview: one answer per port, three words ----
  //
  // Yes declares the port open and no declares it closed, both families in
  // one click, the same rule the declare control above posts under. Later
  // acknowledges the families that carry a state, which is what hides the
  // question until the state changes (controlplane/app/join.py). Every
  // answer posts at once and the row repaints at once; the quiet refresh
  // brings the rest of the page along.
  var answerIntent={yes:'open',no:'closed'};
  var postAnswer=function(host,protocol,port,fams,word){
    if(word==='later'){
      return Promise.all(fams.map(function(f){
        return fetch(portPath(host,protocol,port,f,'acknowledge'),{method:'POST'})
          .then(portRefusal)}));
    }
    var body=JSON.stringify({intent:answerIntent[word]});
    return Promise.all(fams.map(function(f){
      return fetch(portPath(host,protocol,port,f,'declare'),
        {method:'POST',headers:{'Content-Type':'application/json'},body:body})
        .then(portRefusal)}));
  };
  var famsFor=function(box,word){
    return String(word==='later'?box.dataset.stfams:box.dataset.fams).split(',')
      .filter(function(f){return f})};
  var wireAnswers=function(box){
    // A row of the sample shell names no server. Its answers say what they
    // would do, bound with the page's other stand-ins, and are left alone.
    if(!box.dataset.host)return;
    box.querySelectorAll('.ans').forEach(function(b){
      b.onclick=function(e){
        // The row is a label that opens the row. An answer is not that.
        e.preventDefault();e.stopPropagation();
        if(b.classList.contains('pick'))return;
        var word=b.dataset.answer, fams=famsFor(box,word);
        if(!fams.length)return;
        var all=box.querySelectorAll('.ans');
        all.forEach(function(o){o.disabled=true});
        postAnswer(box.dataset.host,box.dataset.protocol,box.dataset.port,fams,word)
        .then(function(answers){
          all.forEach(function(o){o.disabled=false});
          var refused=answers.filter(function(a){return a});
          if(refused.length){toast(refused[0]);return}
          all.forEach(function(o){o.classList.toggle('pick',o===b)});
          box.classList.remove('quiet');box.classList.add('settled');
          // The State cell repaints with the word the server said this
          // answer makes it. Later moves no state.
          if(word!=='later'){
            var st=box.dataset[word==='yes'?'stOpen':'stClosed'];
            var cell=box.closest('.pr').querySelector('.prst'), chip=cell.querySelector('.st');
            if(st){
              if(!chip){chip=document.createElement('span');cell.insertBefore(chip,cell.firstChild)}
              chip.className='st '+(PORT_TONE[st]||'off');chip.textContent=st;
            }
          }
          refresh(true);
        })
        .catch(function(){all.forEach(function(o){o.disabled=false});toast(NO_ANSWER)});
      }});
  };
  onWire(function(){document.querySelectorAll('.pr .pra').forEach(wireAnswers)});
  // A box over the table scrolls to and opens the first row it counts. A
  // port chip on the Services tab and a row of the Evidence matrix do the
  // same for their port, switching to the Overview first (data-tab names
  // that tab's radio).
  onWire(function(){
    document.querySelectorAll('.hstrip [data-row],.stbl [data-row],.mxt [data-row]').forEach(function(box){
      box.onclick=function(){
        var sel=document.getElementById(box.dataset.row);
        if(!sel)return;
        var tab=box.dataset.tab&&document.getElementById(box.dataset.tab);
        if(tab)tab.checked=true;
        sel.checked=true;
        sel.nextElementSibling.scrollIntoView({block:'center'});
      }});
  });
  // The first-look window: on its own once per account, the first time a
  // server with reachable ports and no answers is opened (the view carries
  // data-first), and from review all ports at any time. Opening it on its
  // own is recorded on the server, so nobody in the account sees it twice
  // (the owner, 2026-09-06).
  var openFirstLook=function(host){
    var o=document.getElementById('fv-'+host);
    if(o)o.classList.add('on')};
  afterView=function(v){
    var view=document.getElementById(v);
    if(!view||v.indexOf('host-')!==0||view.dataset.first!=='1')return;
    var host=v.slice(5);
    view.dataset.first='';
    openFirstLook(host);
    fetch('/api/admin/hosts/'+encodeURIComponent(host)+'/first-look',{method:'POST'})
      .catch(function(){});
  };
  // The view the page loaded on was shown before the opener above existed,
  // so a server loaded by its address, Open server after an install, an
  // alert's link, a reload, never opened it (the second big test, 24
  // October, case F6). It is asked once now for that view.
  var shownOnLoad=document.querySelector('.view.on');
  if(shownOnLoad)afterView(shownOnLoad.id);
  onWire(function(){
    document.querySelectorAll('.js-review-all').forEach(function(b){
      b.onclick=function(){openFirstLook(b.dataset.host)}});
    document.querySelectorAll('.fv').forEach(function(o){
      var host=o.dataset.host;
      o.querySelectorAll('.fv-r .ans').forEach(function(b){
        b.onclick=function(){
          b.closest('.fv-r').querySelectorAll('.ans').forEach(function(x){
            x.classList.toggle('pick',x===b)})}});
      var confirm=o.querySelector('.js-fv-confirm');
      if(!confirm)return;
      confirm.onclick=function(){
        confirm.disabled=true;
        var posts=[];
        o.querySelectorAll('.fv-r').forEach(function(row){
          var pick=row.querySelector('.ans.pick');
          if(!pick)return;
          var word=pick.dataset.answer;
          var fams=word==='later'?String(row.dataset.stfams).split(',').filter(function(f){return f}):portFams;
          if(fams.length)posts.push(postAnswer(host,row.dataset.protocol,row.dataset.port,fams,word));
        });
        Promise.all(posts).then(function(all){
          confirm.disabled=false;
          var refused=[].concat.apply([],all).filter(function(a){return a});
          if(refused.length){toast(refused[0]);return}
          o.classList.remove('on');
          refresh(true);
        }).catch(function(){confirm.disabled=false;toast(NO_ANSWER)});
      };
    });
  });
__BOOT_JS__});
