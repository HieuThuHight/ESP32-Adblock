#pragma once
// Dashboard HTML for the ESP AdBlocker web UI, kept in its own header so the
// Arduino IDE preprocessor doesn't choke on the inlined markup (issue #6).

const char PAGE[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>ESP AdBlock</title><style>
body{font:14px system-ui,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}
header{background:#161b22;padding:14px 18px;border-bottom:1px solid #30363d;display:flex;justify-content:space-between;align-items:center}
h1{margin:0;font-size:18px}h1 span{color:#3fb950}.wrap{padding:16px;max-width:1000px;margin:auto}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 16px;flex:1;min-width:120px}
.card .v{font-size:22px;font-weight:600}.card .l{color:#8b949e;font-size:12px}
table{width:100%;border-collapse:collapse;background:#161b22;border-radius:8px;overflow:hidden;margin-bottom:18px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #21262d;font-size:13px}
th{background:#21262d;color:#8b949e}tr:hover td{background:#1c2128}
.b{color:#f85149}.a{color:#3fb950}.tag{background:#30363d;border-radius:4px;padding:1px 6px;font-size:11px}
button{background:#21262d;color:#c9d1d9;border:1px solid #30363d;border-radius:5px;padding:4px 9px;cursor:pointer}
button:hover{background:#30363d}.ban{color:#f85149}input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:5px;padding:6px}
h2{font-size:14px;color:#8b949e;margin:18px 0 8px}
</style></head><body>
<header><div><h1>🛡️ ESP AdBlock <span id=host></span></h1></div><button id=langBtn onclick=tl()></button></header><div class=wrap>
<div class=cards id=sys></div>
<h2 i1=clients></h2><table id=ct><thead><tr><th i1=client></th><th>MAC</th><th i1=blocked></th><th i1=allowed></th><th></th></tr></thead><tbody></tbody></table>
<h2 i1=custom></h2>
<div style=margin-bottom:8px><input id=dom placeholder="ads.example.com" size=30><button onclick=addDom() i1=bldom></button></div>
<table id=cl><tbody></tbody></table>
<h2 i1=blup></h2>
<form id=upf style=margin-bottom:6px><input type=file id=blf accept=.bin><button i1=upbl></button> <span id=upmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px" i1=bldesc></div>
<h2 i1=blrem></h2>
<div style=margin-bottom:6px><input id=uurl placeholder="https://host/blocklist.bin" size=40> <span i1=every></span> <input id=uiv size=2 value=72><span i1=h></span>
<button onclick=saveUpd() i1=save></button> <button onclick=fetchNow() i1=fetchnow></button></div>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px"><span i1=blremdesc></span> <span id=ustat>&mdash;</span></div>
<h2 i1=fwup></h2>
<form id=fwf style=margin-bottom:6px><input type=file id=fwb accept=.bin><button i1=flashfw></button> <span id=fwmsg style=color:#8b949e></span></form>
<div style="color:#8b949e;font-size:12px;margin-bottom:18px" i1=fwdesc></div>
</div><script>
let l=localStorage.getItem('lng')||'zh';
const D={
en:{clients:"CLIENTS",client:"Client",blocked:"Blocked",allowed:"Allowed",custom:"CUSTOM BLOCKED DOMAINS",bldom:"Block domain",
blup:"BLOCKLIST &mdash; UPLOAD",bldesc:"build <code>blocklist.bin</code> with <code>tools/build_blocklist.py</code>, then upload here &mdash; no USB",
blrem:"BLOCKLIST &mdash; REMOTE AUTO-UPDATE",every:"every",h:"h",save:"Save",fetchnow:"Fetch now",
blremdesc:"device pulls a prebuilt <code>blocklist.bin</code> on a schedule. last:",fwup:"FIRMWARE &mdash; OTA UPDATE",flashfw:"Flash firmware",
fwdesc:"upload <code>.pio/build/c3/firmware.bin</code> &mdash; device verifies it and reboots",t_tb:"Total blocked",t_ta:"Total allowed",t_bl:"Blocklist",
t_cl:"Clients",t_fr:"Free RAM",t_up:"Uptime",ban:"Ban",unban:"Unban",rm:"remove",none:"none yet"},
zh:{clients:"連線設備",client:"設備 IP",blocked:"已阻擋",allowed:"已放行",custom:"自訂黑名單 (不需重新編譯)",bldom:"加入黑名單",
blup:"防禦庫 &mdash; 手動上傳更新",bldesc:"用 <code>tools/build_blocklist.py</code> 產生的 <code>blocklist.bin</code> 可以在這裡直接上傳，不需插線",
blrem:"防禦庫 &mdash; 雲端自動更新",every:"每",h:"小時更新",save:"儲存",fetchnow:"立即抓取",
blremdesc:"設備會定時去指定的雲端網址自動抓取最新名單。上次狀態:",fwup:"系統韌體 &mdash; OTA 無線升級",flashfw:"上傳韌體",
fwdesc:"直接上傳編譯好的 <code>firmware.bin</code>，設備會自動驗證並重新啟動",t_tb:"總阻擋次數",t_ta:"總放行次數",t_bl:"防禦庫容量",
t_cl:"連線設備數",t_fr:"剩餘記憶體",t_up:"開機時間",ban:"封鎖",unban:"解封",rm:"移除",none:"目前沒有自訂網域"}
};
function al(){
document.querySelectorAll('[i1]').forEach(e=>e.innerHTML=D[l][e.getAttribute('i1')]||'');
langBtn.innerText=l==='en'?'繁體中文':'English';
}
function tl(){l=l==='en'?'zh':'en';localStorage.setItem('lng',l);al();load();}
function fmt(n){return n.toLocaleString()}
async function load(){let s=await(await fetch('/stats.json')).json();
host.textContent='@ '+s.ip;
sys.innerHTML=[[D[l].t_tb,fmt(s.blocked),'b'],[D[l].t_ta,fmt(s.allowed),'a'],[D[l].t_bl,fmt(s.domains),''],
[D[l].t_cl,s.clients.length,''],['WiFi',s.rssi+' dBm',''],['Temp',s.temp+' °C',''],[D[l].t_fr,Math.round(s.heap/1024)+' KB',''],[D[l].t_up,s.uptime,'']]
.map(c=>`<div class=card><div class="v ${c[2]}">${c[1]}</div><div class=l>${c[0]}</div></div>`).join('');
ct.tBodies[0].innerHTML=s.clients.sort((a,b)=>(b.blocked+b.allowed)-(a.blocked+a.allowed)).map(c=>
`<tr><td>${c.ip}${c.banned?' <span class=tag style=color:#f85149>BANNED</span>':''}</td><td>${c.mac}</td>
<td class=b>${fmt(c.blocked)}</td><td class=a>${fmt(c.allowed)}</td>
<td><button class=ban onclick="fetch('/ban?ip=${c.ip}').then(load)">${c.banned?D[l].unban:D[l].ban}</button></td></tr>`).join('');
cl.tBodies[0].innerHTML=s.custom.map(d=>`<tr><td>${d}</td><td style=text-align:right><button onclick="fetch('/unblock?d='+encodeURIComponent('${d}')).then(load)">${D[l].rm}</button></td></tr>`).join('')||`<tr><td style=color:#8b949e>${D[l].none}</td></tr>`;
if(document.activeElement!=uurl)uurl.value=s.upurl||'';
if(document.activeElement!=uiv)uiv.value=s.upiv||72;
ustat.textContent=s.upstat||'—';}
function addDom(){let d=dom.value.trim();if(d){fetch('/addblock?d='+encodeURIComponent(d)).then(()=>{dom.value='';load()})}}
function saveUpd(){fetch('/setupdate?u='+encodeURIComponent(uurl.value.trim())+'&h='+(parseInt(uiv.value)||72)).then(load)}
function fetchNow(){ustat.textContent='fetching...';fetch('/fetchnow').then(r=>r.text()).then(t=>{ustat.textContent=t;load()})}
fwf.onsubmit=async e=>{e.preventDefault();let f=fwb.files[0];if(!f)return;fwmsg.textContent='flashing '+(f.size/1048576).toFixed(2)+' MB...';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/update',{method:'POST',body:fd});fwmsg.textContent=r.ok?'✓ rebooting, reconnect in ~15s':'✗ '+await r.text();}
catch(_){fwmsg.textContent='✓ rebooting, reconnect in ~15s';}};
upf.onsubmit=async e=>{e.preventDefault();let f=blf.files[0];if(!f)return;
upmsg.textContent='uploading '+(f.size/1048576).toFixed(2)+' MB...';
let fd=new FormData();fd.append('f',f);
try{let r=await fetch('/upload',{method:'POST',body:fd});upmsg.textContent=r.ok?'✓ updated':'✗ '+await r.text();}
catch(_){upmsg.textContent='✗ upload failed';}
blf.value='';setTimeout(load,600);};
al();load();setInterval(load,3000);
</script></body></html>)HTML";
