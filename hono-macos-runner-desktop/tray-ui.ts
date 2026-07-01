const TRAY_PANEL_WIDTH_HOME = 320;
const TRAY_PANEL_WIDTH_SETTINGS = 560;

const TRAY_STYLE = `
:root{
  --bg:rgba(246,246,248,.96);--border:rgba(0,0,0,.06);--shadow:0 10px 26px rgba(0,0,0,.12);
  --text:#1d1d1f;--sub:#6e6e73;--accent:#007aff;--accent-bg:rgba(0,122,255,.06);
  --green:#34c759;--divider:rgba(0,0,0,.08);--gear-bg:rgba(0,0,0,.06);
  --danger-text:#c41e3a;--danger-border:#c41e3a;--banner-bg:#fdeceb;--banner-border:#f8c9c5;--banner-text:#a13b32;--banner-dismiss:#c79490;
  --avatar-bg:#d8dde3;--avatar-text:#48484a;--scope-border:rgba(0,0,0,.08);--scope-radio:#8e8e93;
  --card-bg:#f5f5f7;--card-border:rgba(0,0,0,.07);--nav-bg:#ececec;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:rgba(40,40,42,.9);--border:rgba(255,255,255,.1);--shadow:0 10px 30px rgba(0,0,0,.5);
    --text:#f2f2f3;--sub:#9a9a9e;--accent:#0a84ff;--accent-bg:rgba(10,132,255,.12);
    --green:#32d74b;--divider:rgba(255,255,255,.08);--gear-bg:rgba(255,255,255,.08);
    --danger-text:#ff3b3b;--danger-border:#ff3b3b;--banner-bg:rgba(248,113,113,.14);--banner-border:rgba(248,113,113,.3);--banner-text:#fca5a5;--banner-dismiss:#fca5a5;
    --avatar-bg:#4a4a4d;--avatar-text:#e3e3e5;--scope-border:rgba(255,255,255,.1);--scope-radio:#8e8e93;
    --card-bg:#2f2f32;--card-border:rgba(255,255,255,.14);--nav-bg:#2c2c2e;
  }
}
*{box-sizing:border-box}
html,body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'SF Pro Text',sans-serif;background:var(--bg)}
.panel{width:320px;position:relative;transition:width .32s cubic-bezier(.4,0,.2,1);overflow:hidden}
.panel-blur{position:absolute;inset:0;background:var(--bg);z-index:0}
.panel>*:not(.panel-blur):not(.modal-backdrop){position:relative;z-index:1}
.appshell{display:flex}
.contentarea{flex:1;min-width:0}
.navrail{flex:none;width:0;overflow:hidden;display:flex;flex-direction:column;gap:2px;padding:14px 0;background:var(--nav-bg);border-right:0 solid var(--divider);opacity:0;transition:width .32s cubic-bezier(.4,0,.2,1),opacity .22s ease-out,padding .32s cubic-bezier(.4,0,.2,1)}
.navrail.show{width:120px;padding:14px 8px;opacity:1;border-right-width:1px}
.navitem{padding:8px 10px;border-radius:7px;font-size:12px;font-weight:600;color:var(--sub);cursor:pointer;white-space:nowrap}
.navitem.active{background:var(--accent-bg);color:var(--accent)}
.settings-content{padding:18px 20px;animation:paneIn .1s ease-out}
@keyframes paneIn{from{opacity:0}to{opacity:1}}
.section-title{font-size:10.5px;font-weight:700;color:var(--sub);text-transform:uppercase;letter-spacing:.04em;margin-bottom:8px}
.section-title.danger{color:var(--danger-text)}
.card{background:var(--card-bg);border:1px solid var(--card-border);border-radius:8px;padding:11px 13px;margin-bottom:14px}
.card-label{font-size:10px;color:#8e8e93;margin-bottom:3px}
.card-mono{font-family:ui-monospace,'SF Mono',monospace;font-size:12px;color:var(--text)}
.assoc-row{display:flex;align-items:center;gap:9px}
.assoc-avatar{width:24px;height:24px;border-radius:50%;background:#4a4a4d;display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:#e3e3e5}
.assoc-info{flex:1}
.assoc-handle{font-size:12px;color:var(--text)}
.assoc-date{font-size:10px;color:#8e8e93}
.btn-proof{font-size:11px;color:var(--accent);font-weight:600;cursor:pointer;margin-top:4px}
.btn-proof:hover{opacity:.8}
.assoc-action{font-size:11px;color:var(--accent);font-weight:600;cursor:pointer}
.hr{border-top:1px solid var(--divider);margin:0 0 14px}
.danger-row{display:flex;align-items:center;justify-content:space-between;gap:14px}
.danger-copy{font-size:11px;color:var(--sub);line-height:1.5}
.btn-outline-danger{flex:none;background:transparent;border:1.5px solid var(--danger-border);color:var(--danger-text);font-size:11.5px;font-weight:600;padding:7px 13px;border-radius:7px;white-space:nowrap;cursor:pointer}
.placeholder{padding:24px;color:var(--sub);font-size:12px;text-align:center}
.policy-pill{font-size:11px;font-weight:700;color:#8e8e93;letter-spacing:.04em;text-transform:uppercase;background:var(--card-bg);display:inline-block;padding:4px 10px;border-radius:6px;margin-bottom:12px}
.policy-heading{font-size:13px;font-weight:600;color:var(--text);margin-bottom:6px;text-align:center}
.policy-body{font-size:11.5px;color:var(--sub);line-height:1.55;max-width:280px;margin:0 auto 16px;text-align:center}
.policy-addrule{border:1px dashed var(--card-border);border-radius:8px;padding:10px;opacity:.5}
.policy-addrule-text{font-size:11px;color:#8e8e93;text-align:left}
.modal-backdrop{display:none;position:absolute;inset:0;background:rgba(0,0,0,.4);align-items:flex-start;justify-content:center;z-index:2;padding:80px 16px 0}
.modal-backdrop.show{display:flex}
.modal{flex:1;background:var(--card-bg);border-radius:12px;box-shadow:0 20px 50px rgba(0,0,0,.4);padding:22px 22px 16px;text-align:center}
.modal-icon{width:38px;height:38px;border-radius:50%;background:rgba(196,30,58,.15);display:flex;align-items:center;justify-content:center;margin:0 auto 10px}
.modal-icon-inner{width:22px;height:22px;border-radius:50%;background:var(--danger-border);color:#fff;font-size:14px;font-weight:800;display:flex;align-items:center;justify-content:center}
.modal-title{font-size:13.5px;font-weight:700;color:var(--text);margin-bottom:6px}
.modal-body{font-size:11.5px;color:var(--sub);line-height:1.5;margin-bottom:16px}
.modal-actions{display:flex;gap:8px;justify-content:flex-end}
.btn{padding:6px 14px;border-radius:6px;font-size:12px;cursor:pointer;border:1px solid var(--card-border);color:var(--text);background:transparent}
.btn-danger{background:var(--danger-border);color:#fff;font-weight:600;border:none}
.banner{display:none;background:var(--banner-bg);border-bottom:1px solid var(--banner-border);padding:10px 16px;align-items:center;gap:8px}
.banner.show{display:flex}
.banner-icon{width:16px;height:16px;border-radius:50%;background:var(--danger-border);color:#fff;font-size:11px;font-weight:800;display:flex;align-items:center;justify-content:center;flex:none}
.banner-text{font-size:11px;color:var(--banner-text);line-height:1.4;flex:1}
.banner-retry{font-weight:700;text-decoration:underline;cursor:pointer}
.banner-dismiss{font-size:14px;color:var(--banner-dismiss);cursor:pointer}
.header{display:flex;align-items:center;gap:9px;padding:14px 16px 10px}
.glyph{width:22px;height:22px;border-radius:6px;background:linear-gradient(140deg,#1d1d1f,#48484a)}
@media (prefers-color-scheme: dark){.glyph{background:linear-gradient(140deg,#e8e8ea,#aeb0b6)}}
.title{font-size:13.5px;font-weight:600;color:var(--text);flex:1}
.active{display:flex;align-items:center;gap:5px;margin-right:6px}
.active .dot{width:6px;height:6px;border-radius:50%;background:var(--green)}
.active .label{font-size:10.5px;color:var(--green);font-weight:600}
.gear{width:20px;height:20px;border-radius:5px;background:var(--gear-bg);display:flex;align-items:center;justify-content:center;font-size:11px;color:var(--sub);cursor:pointer}
.avatar-row{padding:0 16px 12px;display:flex;align-items:center;gap:9px}
.avatar{width:24px;height:24px;border-radius:50%;background:var(--avatar-bg);display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:700;color:var(--avatar-text)}
.handle{font-size:12px;color:var(--text);flex:1}
.checkmark{width:14px;height:14px;border-radius:50%;background:var(--green);display:flex;align-items:center;justify-content:center;color:#fff;font-size:9px}
.divider{height:1px;background:var(--divider);margin:0 16px}
.row{padding:14px 16px;display:flex;align-items:center;justify-content:space-between}
.row.compact{padding:8px 16px}
.row-label{font-size:12.5px;font-weight:600;color:var(--text)}
.row.compact .row-label{font-weight:400;font-size:12.5px}
.row-sub{font-size:10.5px;color:var(--sub)}
.toggle{width:36px;height:21px;border-radius:11px;position:relative;cursor:pointer;flex:none;background:#d1d1d6}
@media (prefers-color-scheme: dark){.toggle{background:rgba(255,255,255,.16)}}
.toggle.on{background:var(--green)}
.toggle .knob{position:absolute;top:2px;left:2px;width:17px;height:17px;border-radius:50%;background:#fff;box-shadow:0 1px 2px rgba(0,0,0,.25);transition:left .15s}
.toggle.on .knob{left:17px}
.section-header{padding:12px 16px 4px;font-size:10.5px;font-weight:600;color:var(--sub);text-transform:uppercase;letter-spacing:.03em}
.scope-list{padding:8px 16px 4px}
.scope-row{display:flex;align-items:center;gap:9px;border:1px solid var(--scope-border);border-radius:8px;padding:8px 10px;margin-bottom:7px}
.scope-row.selectable{cursor:pointer}
.scope-row.selected{border:1.5px solid var(--accent);background:var(--accent-bg)}
.scope-row.locked{opacity:.45}
.scope-row.locked-todo{opacity:.35}
.scope-radio{width:14px;height:14px;border-radius:50%;border:1.5px solid var(--scope-radio);flex:none}
.scope-row.selected .scope-radio{border:4px solid var(--accent)}
.scope-label{font-size:12px;color:var(--text);flex:1}
.scope-row.selected .scope-label{font-weight:600}
.scope-lock{font-size:13px}
.scope-pill{font-size:9px;border:1px solid var(--scope-radio);border-radius:3px;padding:1px 5px;color:var(--sub)}
.scope-caption{font-size:10.5px;color:var(--sub);opacity:.85;line-height:1.4;padding:2px 2px 12px}
.footer{padding:12px 16px}
.footer-link{font-size:11.5px;color:var(--accent);font-weight:600;margin-bottom:3px;cursor:pointer}
.footer-sub{font-size:10.5px;color:var(--sub);line-height:1.4}
.linking{padding:16px;display:flex;flex-direction:column;box-sizing:border-box}
.linking .header{padding:0 0 14px}
.linking-box{background:rgba(127,127,127,.08);border:1px solid var(--border);border-radius:10px;padding:12px;display:flex;align-items:center;gap:10px;margin:auto 0}
.spinner{width:16px;height:16px;border-radius:50%;border:2.5px solid rgba(0,122,255,.25);border-top-color:var(--accent);animation:spin .9s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.linking-text{font-size:12.5px;color:var(--text)}
.linking-help{font-size:11px;color:var(--sub);margin:10px 2px 0}
.cancel-link{font-size:12px;color:var(--accent);font-weight:600;text-align:center;margin-top:12px;cursor:pointer}
`;

const TRAY_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Compute Provider</title>
<style>${TRAY_STYLE}</style>
</head>
<body>
<div class="panel">
  <div class="panel-blur"></div>
  <div class="banner" id="banner">
    <div class="banner-icon">!</div>
    <div class="banner-text" id="bannerText">Couldn't connect identity. <span class="banner-retry" id="bannerRetry">Retry</span></div>
    <div class="banner-dismiss" id="bannerDismiss">&times;</div>
  </div>

  <div id="linkingView" class="linking" style="display:none">
    <div class="header"><div class="glyph"></div><div class="title">Compute Provider</div></div>
    <div class="linking-box"><div class="spinner"></div><div class="linking-text">Waiting for approval in your browser…</div></div>
    <div class="linking-help">Local jobs keep running while you finish.</div>
    <div class="cancel-link" id="cancelLink">Cancel</div>
  </div>

  <div id="mainView">
  <div class="appshell">
  <div class="navrail" id="navrail">
    <div class="navitem active" id="navHome" data-view="home">Home</div>
    <div class="navitem" id="navGeneral" data-view="general">General</div>
    <div class="navitem" id="navIdentity" data-view="identity">Identity</div>
    <div class="navitem" id="navPolicy" data-view="policy">Policy</div>
  </div>
  <div class="contentarea">
  <div id="paneHome">
    <div class="header">
      <div class="glyph"></div>
      <div class="title">Compute Provider</div>
      <div class="active"><span class="dot"></span><span class="label">Active</span></div>
      <div class="gear" id="gearBtn">&#9881;</div>
    </div>

    <div class="avatar-row" id="avatarRow" style="display:none">
      <div class="avatar" id="avatarInitial">?</div>
      <div class="handle" id="handleText"></div>
      <div class="checkmark">&#10003;</div>
    </div>
    <div class="divider" id="avatarDivider" style="display:none"></div>

    <div class="row">
      <div><div class="row-label">Dispatching</div><div class="row-sub">Accepting jobs from authorized sources</div></div>
      <div class="toggle" id="toggleDispatch"><div class="knob"></div></div>
    </div>
    <div class="divider"></div>
    <div class="section-header">Job Types</div>
    <div class="row compact">
      <div><div class="row-label">Deno Workers</div><div class="row-sub">Lightweight isolated functions</div></div>
      <div class="toggle" id="toggleWorkers"><div class="knob"></div></div>
    </div>
    <div class="row compact" style="padding-bottom:12px">
      <div><div class="row-label">Containers</div><div class="row-sub">Full OCI containers via runtime</div></div>
      <div class="toggle" id="toggleContainers"><div class="knob"></div></div>
    </div>
    <div class="divider"></div>
    <div class="section-header">Accept Jobs From</div>
    <div class="scope-list">
      <div class="scope-row" id="scopeOnlyMe" data-scope="only_me">
        <div class="scope-radio"></div><div class="scope-label">Only me</div>
      </div>
      <div class="scope-row" id="scopeDirectNetwork" data-scope="direct_network">
        <div class="scope-radio"></div><div class="scope-label">Direct network</div>
      </div>
      <div class="scope-row locked-todo">
        <div class="scope-radio"></div><div class="scope-label">Policy-based</div><div class="scope-pill">TODO</div>
      </div>
      <div class="scope-caption" id="scopeCaption">No remote scopes are available yet — nothing dispatches jobs here until you link an identity.</div>
    </div>
    <div class="divider"></div>
    <div class="footer" id="footerUnlinked">
      <div class="footer-link" id="connectLink">Connect ATProto identity</div>
      <div class="footer-sub">Unlocks "Only me" and "Direct network" scoping.</div>
    </div>
    <div class="footer" id="footerLinked" style="display:none">
      <div class="footer-link" id="openSettingsLink">Open Settings…</div>
    </div>
  </div>

  <div id="paneGeneral" class="settings-content" style="display:none">
    <div class="placeholder">General settings are coming soon.</div>
  </div>
  <div id="paneIdentity" class="settings-content" style="display:none">
    <div class="section-title">Hardware-bound Key</div>
    <div class="card">
      <div class="card-label">Secure Enclave Key ID</div>
      <div class="card-mono" id="keyIdText">—</div>
    </div>
    <div class="section-title">ATProto Association</div>
    <div class="card" id="assocCard">
      <div class="assoc-row" id="assocLinked" style="display:none">
        <div class="assoc-avatar" id="assocAvatar">?</div>
        <div class="assoc-info"><div class="assoc-handle" id="assocHandle"></div><div class="assoc-date" id="assocDate"></div><div class="btn-proof" id="assocProof" style="display:none">View Association Proof</div></div>
        <div class="assoc-action" id="unlinkBtn">Unlink</div>
      </div>
      <div class="assoc-row" id="assocUnlinked">
        <div class="assoc-info"><div class="assoc-handle">Not linked</div></div>
        <div class="assoc-action" id="connectBtn">Connect identity</div>
      </div>
    </div>
    <div class="hr"></div>
    <div class="section-title danger">Danger Zone</div>
    <div class="danger-row">
      <div class="danger-copy">Creates a brand-new Secure Enclave key pair. Your current ATProto association becomes invalid.</div>
      <div class="btn-outline-danger" id="regenBtn">Regenerate Key…</div>
    </div>
  </div>
  <div id="panePolicy" class="settings-content" style="display:none">
    <div style="text-align:center">
      <div class="policy-pill">Coming soon</div>
      <div class="policy-heading">Policy-based dispatch</div>
      <div class="policy-body">Define rules for exactly which DIDs, domains, or networks may dispatch jobs to this device.</div>
      <div class="policy-addrule"><div class="policy-addrule-text">+ Add rule</div></div>
    </div>
  </div>
  </div>
  </div>
  </div>

  <div class="modal-backdrop" id="regenModal">
    <div class="modal">
      <div class="modal-icon"><div class="modal-icon-inner">!</div></div>
      <div class="modal-title">Regenerate device key?</div>
      <div class="modal-body" id="regenBody">This creates a new key and invalidates your ATProto association. You'll need to sign in again to re-link.</div>
      <div class="modal-actions">
        <div class="btn" id="regenCancel">Cancel</div>
        <div class="btn btn-danger" id="regenConfirm">Regenerate</div>
      </div>
    </div>
  </div>
</div>
<script>
(function(){
var $=function(id){return document.getElementById(id);};
var APP_TOKEN='__APP_TOKEN__';
var _fetch=window.fetch;
window.fetch=function(input,init){init=init||{};init.headers=Object.assign({},init.headers,{'X-App-Token':APP_TOKEN});return _fetch(input,init);};
var state=null;
var views={home:$('paneHome'),general:$('paneGeneral'),identity:$('paneIdentity'),policy:$('panePolicy')};
var navItems={home:$('navHome'),general:$('navGeneral'),identity:$('navIdentity'),policy:$('navPolicy')};
var panelEl=document.querySelector('.panel');
var navrailEl=$('navrail');
var currentPanelWidth=320;
function showView(name){
  Object.keys(views).forEach(function(k){
    views[k].style.display=k===name?'':'none';
    navItems[k].className='navitem'+(k===name?' active':'');
  });
  var expanded=name!=='home';
  var targetWidth=expanded?560:320;
  if(targetWidth===currentPanelWidth){ currentPanelWidth=targetWidth;reportHeight();return; }
  currentPanelWidth=targetWidth;
  navrailEl.className='navrail'+(expanded?' show':'');

  // Pre-measure scrollHeight at final layout state. Disable transitions on
  // both panel and navrail so the measurement reflects the fully-expanded
  // navrail (120px wide, content area only 440px) rather than the start-of-
  // transition state where navrail is still 0px wide (content area at full
  // 560px). Without this, measured height is too short and grey area appears.
  var navWas=navrailEl.style.transition;
  navrailEl.style.transition='none';
  panelEl.style.transition='none';
  panelEl.style.width=targetWidth+'px';
  void panelEl.offsetHeight;
  var h=document.body.scrollHeight;
  panelEl.style.width=(targetWidth===560?320:560)+'px';
  void panelEl.offsetHeight;
  navrailEl.style.transition=navWas;
  panelEl.style.transition='';

  sendResize(targetWidth,h);
  // Lock height to the pre-measured value during the CSS width animation so
  // intermediate layout states cannot change scrollHeight and trigger a wrong
  // native-window resize via reportHeight(). Clear the lock when the
  // transition finishes and measure the exact final height.
  panelEl.style.height=h+'px';
  panelEl.addEventListener('transitionend',function onEnd(ev){
    if(ev.propertyName!=='width')return;
    panelEl.removeEventListener('transitionend',onEnd);
    panelEl.style.height='';
    reportHeight();
  });
  panelEl.style.width=targetWidth+'px';
}
function sendResize(w,h){
  lastReportedWidth=w;lastReportedHeight=h;
  fetch('/api/tray-resize',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({width:w,height:h})});
}
Object.keys(navItems).forEach(function(k){navItems[k].addEventListener('click',function(){showView(k);});});

function setToggle(el,on){el.className='toggle'+(on?' on':'');}

function patchState(patch){
  fetch('/api/state',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(patch)}).then(render);
}

function render(){
  fetch('/api/state').then(function(r){return r.json();}).then(function(d){
    state=d;
    var linked=!!(d.session&&d.session.handle);

    if(d.oauthInFlight){
      $('linkingView').style.minHeight=(lastMainHeight||280)+'px';
      $('linkingView').style.display='';
      $('mainView').style.display='none';
      $('banner').className='banner';
      reportHeight();
      return;
    }
    $('linkingView').style.display='none';
    $('mainView').style.display='';

    if(d.oauthError){
      $('banner').className='banner show';
      $('bannerText').firstChild.textContent="Couldn't connect identity: "+d.oauthError+". ";
    }else{
      $('banner').className='banner';
    }

    if(linked){
      $('avatarRow').style.display='flex';
      $('avatarDivider').style.display='';
      $('avatarInitial').textContent=d.session.handle.charAt(0).toUpperCase();
      $('handleText').textContent='@'+d.session.handle;
      $('footerUnlinked').style.display='none';
      $('footerLinked').style.display='';
    }else{
      $('avatarRow').style.display='none';
      $('avatarDivider').style.display='none';
      $('footerUnlinked').style.display='';
      $('footerLinked').style.display='none';
    }

    setToggle($('toggleDispatch'),d.dispatchingEnabled);
    setToggle($('toggleWorkers'),d.workersEnabled);
    setToggle($('toggleContainers'),d.containersEnabled);

    var only=$('scopeOnlyMe'),direct=$('scopeDirectNetwork');
    only.className='scope-row'+(linked?' selectable':' locked');
    direct.className='scope-row'+(linked?' selectable':' locked');
    only.querySelector('.scope-lock')&&only.removeChild(only.querySelector('.scope-lock'));
    if(!linked){
      if(!only.querySelector('.scope-lock')){var l1=document.createElement('div');l1.className='scope-lock';l1.textContent='\\uD83D\\uDD12';only.appendChild(l1);}
      if(!direct.querySelector('.scope-lock')){var l2=document.createElement('div');l2.className='scope-lock';l2.textContent='\\uD83D\\uDD12';direct.appendChild(l2);}
    }else{
      var lo=only.querySelector('.scope-lock');if(lo)only.removeChild(lo);
      var ld=direct.querySelector('.scope-lock');if(ld)direct.removeChild(ld);
      if(d.acceptScope==='only_me')only.classList.add('selected');else only.classList.remove('selected');
      if(d.acceptScope==='direct_network')direct.classList.add('selected');else direct.classList.remove('selected');
    }
    $('scopeCaption').style.display=linked?'none':'';

    $('keyIdText').textContent=d.persistentKeyId||'—';
    $('assocLinked').style.display=linked?'flex':'none';
    $('assocUnlinked').style.display=linked?'none':'flex';
    if(linked){
      $('assocAvatar').textContent=d.session.handle.charAt(0).toUpperCase();
      $('assocHandle').textContent='@'+d.session.handle;
      $('assocDate').textContent=d.linkedAt?('Linked '+new Date(d.linkedAt).toLocaleDateString('en-US',{month:'short',day:'numeric',year:'numeric'})):'';
      var proofEl=$('assocProof');
      if(d.associationRecordUri){
        proofEl.style.display=''; proofEl.onclick=function(){
          fetch('/api/open-external',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({url:'https://pdsls.dev/'+d.associationRecordUri})});
        };
      } else { proofEl.style.display='none'; }
      $('regenBody').textContent="This creates a new key and invalidates your ATProto association. You'll need to sign in again to re-link @"+d.session.handle+".";
    }

    if(d.requestedView&&views[d.requestedView])showView(d.requestedView);
    lastMainHeight=$('mainView').scrollHeight;
    reportHeight();
  });
}

var lastMainHeight=0;
var lastReportedHeight=0;
var lastReportedWidth=0;
function reportHeight(){
  requestAnimationFrame(function(){
    var w=currentPanelWidth;
    var h=document.body.scrollHeight;
    if(h===lastReportedHeight&&w===lastReportedWidth)return;
    lastReportedHeight=h;
    lastReportedWidth=w;
    fetch('/api/tray-resize',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({width:w,height:h})});
  });
}

$('gearBtn').addEventListener('click',function(){showView('identity');});
$('openSettingsLink').addEventListener('click',function(){showView('identity');});
$('unlinkBtn').addEventListener('click',function(){fetch('/api/atproto/unlink',{method:'POST'}).then(render);});
$('connectBtn').addEventListener('click',startConnect);
$('regenBtn').addEventListener('click',function(){$('regenModal').className='modal-backdrop show';});
$('regenCancel').addEventListener('click',function(){$('regenModal').className='modal-backdrop';});
$('regenConfirm').addEventListener('click',function(){
  fetch('/api/atproto/regenerate-key',{method:'POST'}).then(function(){
    $('regenModal').className='modal-backdrop';
    render();
  });
});
$('toggleDispatch').addEventListener('click',function(){patchState({dispatchingEnabled:!(state&&state.dispatchingEnabled)});});
$('toggleWorkers').addEventListener('click',function(){patchState({workersEnabled:!(state&&state.workersEnabled)});});
$('toggleContainers').addEventListener('click',function(){patchState({containersEnabled:!(state&&state.containersEnabled)});});
$('scopeOnlyMe').addEventListener('click',function(){if(state&&state.session)patchState({acceptScope:'only_me'});});
$('scopeDirectNetwork').addEventListener('click',function(){if(state&&state.session)patchState({acceptScope:'direct_network'});});
$('bannerDismiss').addEventListener('click',function(){$('banner').className='banner';});
$('bannerRetry').addEventListener('click',function(){startConnect();});
$('cancelLink').addEventListener('click',function(){fetch('/api/atproto/cancel-oauth',{method:'POST'}).then(render);});

function startConnect(){
  var handle=window.prompt('ATProto handle','alice.bsky.social');
  if(!handle)return;
  fetch('/api/atproto/start-oauth',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({handle:handle})}).then(render);
}
$('connectLink').addEventListener('click',startConnect);

render();
setInterval(render,2000);
})();
</script>
</body>
</html>`;

export { TRAY_STYLE, TRAY_HTML, TRAY_PANEL_WIDTH_HOME, TRAY_PANEL_WIDTH_SETTINGS };
