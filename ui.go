package main

const uiHTML = `<!doctype html>
<html lang="ro"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>StreamHub</title>
<style>
:root{--bg:#0b0e13;--panel:#12161d;--panel2:#171c25;--line:#232a35;--text:#e4e8ee;--mut:#7f8a9a;--ok:#2ec27e;--bad:#ed5e5e;--warn:#e5a50a;--acc:#5b9bff;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:16px;flex-wrap:wrap;padding:12px 20px;background:rgba(11,14,19,.92);backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
.brand{font-weight:700;font-size:17px;letter-spacing:.2px}.brand span{color:var(--acc)}
#sum{display:flex;gap:18px;flex:1;flex-wrap:wrap;color:var(--mut);font-size:13px}
#sum span{white-space:nowrap}
#sum b{color:var(--text);font-family:var(--mono);font-weight:600}
button{font:inherit;color:var(--text);background:var(--panel2);border:1px solid var(--line);border-radius:7px;padding:6px 12px;cursor:pointer}
button:hover{border-color:#3a4555}
button.pri{background:var(--acc);border-color:var(--acc);color:#fff;font-weight:600}
button.dng:hover{border-color:var(--bad);color:var(--bad)}
button.sm{padding:3px 9px;font-size:12px}
main{padding:16px 20px 40px;max-width:1400px;margin:0 auto}
.ch{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-bottom:8px;overflow:hidden}
.ch.dis{opacity:.55}
.row{display:grid;grid-template-columns:14px minmax(160px,1.3fr) minmax(160px,2fr) 110px 110px 70px 70px auto;gap:14px;align-items:center;padding:11px 14px;cursor:pointer}
.row:hover{background:var(--panel2)}
.dot{width:10px;height:10px;border-radius:50%;background:var(--mut)}
.dot.ok{background:var(--ok);box-shadow:0 0 0 3px rgba(46,194,126,.15)}
.dot.bad{background:var(--bad);box-shadow:0 0 0 3px rgba(237,94,94,.15)}
.nm b{display:block;font-size:14px}.nm small,.in small{color:var(--mut);font-size:12px}
.in{min-width:0}.in div{font-family:var(--mono);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.num{font-family:var(--mono);font-size:13px;text-align:right}
.num small{display:block;color:var(--mut);font-family:system-ui;font-size:11px}
.bad-t{color:var(--bad)}.warn-t{color:var(--warn)}
.tag{display:inline-block;font-size:10.5px;padding:1px 6px;border-radius:4px;border:1px solid var(--line);color:var(--mut);margin-left:6px;vertical-align:1px}
.tag.w{color:var(--warn);border-color:rgba(229,165,10,.4)}.tag.r{color:var(--bad);border-color:rgba(237,94,94,.4)}
.ops{display:flex;gap:6px;justify-content:flex-end}
.det{display:none;border-top:1px solid var(--line);padding:14px;background:var(--panel2)}
.ch.open .det{display:block}
.urls{display:flex;flex-direction:column;gap:6px;margin-bottom:12px}
.url{display:flex;gap:8px;align-items:center}
.url code{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--mono);font-size:12px;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:5px 8px}
.url .k{width:44px;color:var(--mut);font-size:12px}
.err{color:var(--bad);font-size:13px;margin-bottom:10px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:left;color:var(--mut);font-weight:500;padding:5px 8px;border-bottom:1px solid var(--line)}
td{padding:5px 8px;border-bottom:1px solid rgba(35,42,53,.6);font-family:var(--mono)}
td.t{font-family:inherit}
.k-video{color:#7cc4ff}.k-audio{color:#b69cff}.k-psi{color:var(--mut)}.k-teletext,.k-subtitle{color:#7fd6b6}
.cols{display:grid;grid-template-columns:2fr 1fr;gap:16px}
h4{margin:0 0 8px;font-size:12px;color:var(--mut);font-weight:600;text-transform:uppercase;letter-spacing:.6px}
.tabs{display:flex;gap:4px;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:3px}.tabs button{border:0;background:none;padding:5px 12px;color:var(--mut)}.tabs button.on{background:var(--panel);color:var(--text);box-shadow:0 0 0 1px var(--line)}
.ctab{background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:auto}.ctab table{min-width:760px}.ctab td,.ctab th{padding:8px 12px}.ctab tr:hover td{background:var(--panel2)}.ua{color:var(--mut);font-family:inherit;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fil{display:flex;gap:10px;align-items:center;margin-bottom:10px}.fil input{max-width:280px}
.empty{text-align:center;color:var(--mut);padding:60px 20px}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.6);display:flex;align-items:flex-start;justify-content:center;padding:40px 16px;z-index:20;overflow:auto}
.modal.hidden{display:none}
.box{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px;width:100%;max-width:560px}
.box h3{margin:0 0 14px}
label{display:block;font-size:12px;color:var(--mut);margin:12px 0 4px}
input[type=text],input[type=number],input[type=password],textarea{width:100%;font:13px var(--mono);color:var(--text);background:var(--bg);border:1px solid var(--line);border-radius:7px;padding:8px 10px}
textarea{min-height:84px;resize:vertical}
input:focus,textarea:focus{outline:none;border-color:var(--acc)}
.chk{display:flex;gap:18px;flex-wrap:wrap;margin-top:14px}
.chk label{display:flex;gap:6px;align-items:center;margin:0;color:var(--text);font-size:13px}
.hint{font-size:11.5px;color:var(--mut);margin-top:4px;line-height:1.5}
.hint code{font-family:var(--mono);color:#aab4c3}
.foot{display:flex;justify-content:flex-end;gap:8px;margin-top:18px}
.msg{color:var(--bad);font-size:13px;margin-top:10px}
@media(max-width:900px){header{padding:10px 14px;gap:10px}.brand{flex:1}.tabs{order:4}#sum{order:3;flex-basis:100%;gap:6px 14px;font-size:12px}main{padding:12px 12px 32px}.row{grid-template-columns:12px 1fr 90px;row-gap:6px}.in,.row .num:nth-child(5),.row .num:nth-child(6),.row .num:nth-child(7){display:none}.ops{grid-column:1/-1}.cols{grid-template-columns:1fr}}
</style></head><body>
<header>
  <div class="brand">Stream<span>Hub</span></div>
  <div id="sum"></div>
  <div class="tabs"><button id="t_ch" class="on" onclick="setView('ch')">Canale</button><button id="t_cl" onclick="setView('cl')">Clienți</button></div>
  <button onclick="openSettings()">Setări</button>
  <button class="pri" onclick="editCh(null)">+ Canal</button>
</header>
<main id="list"><div class="empty">Se încarcă…</div></main>
<div id="modal" class="modal hidden" onclick="if(event.target===this)closeM()"><div class="box" id="mbox"></div></div>
<script>
var cfg={tokens:[],channels:[]},st=null,opened={};
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function api(m,u,b){return fetch(u,{method:m,headers:{'Content-Type':'application/json'},body:b?JSON.stringify(b):undefined}).then(function(r){if(!r.ok)return r.text().then(function(t){throw new Error(t||('HTTP '+r.status));});return r.json();});}
function loadCfg(){return api('GET','/api/config').then(function(c){cfg=c;});}
function tick(){api('GET','/api/status').then(function(s){st=s;render();}).catch(function(){});}
function rate(k){return k>=1000?(k/1000).toFixed(2)+' Mb/s':k+' kb/s';}
function dur(s){if(!s)return '—';var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return d?d+'z '+h+'h':h?h+'h '+m+'m':m+'m '+(s%60)+'s';}
function hex(p){var h=p.toString(16).toUpperCase();while(h.length<4)h='0'+h;return '0x'+h;}
function tok(){return cfg.tokens&&cfg.tokens.length?cfg.tokens[0]:'';}
function outs(c){var b=location.origin,q=(!c.public&&tok())?'?token='+encodeURIComponent(tok()):'',r=[];
  if(c.http)r.push(['HTTP',b+'/'+c.id+q]);if(c.hls)r.push(['HLS',b+'/'+c.id+'.m3u8'+q]);if(c.udp)r.push(['UDP',c.udp]);return r;}
var view='ch',filt='';
function setView(v){view=v;document.getElementById('t_ch').className=v==='ch'?'on':'';document.getElementById('t_cl').className=v==='cl'?'on':'';render();}
function size(b){b=b||0;return b>=1e9?(b/1e9).toFixed(2)+' GB':b>=1e6?(b/1e6).toFixed(1)+' MB':(b/1e3).toFixed(0)+' KB';}
function player(ua){ua=ua||'';var m=[[/VLC|LibVLC/i,'VLC'],[/TiviMate/i,'TiviMate'],[/Kodi/i,'Kodi'],[/Smarters/i,'IPTV Smarters'],[/OTT ?Navigator/i,'OTT Navigator'],[/Perfect ?Player/i,'Perfect Player'],[/ExoPlayer|ExoPlayerLib/i,'ExoPlayer (Android)'],[/Lavf|ffmpeg|ffprobe/i,'FFmpeg'],[/Astra/i,'Astra'],[/StreamHub/i,'StreamHub'],[/mpv/i,'mpv'],[/Tizen|SMART-TV|SmartTV/i,'Samsung TV'],[/Web0S|webOS|NetCast/i,'LG TV'],[/AppleCoreMedia|iPhone|iPad/i,'iOS'],[/Edg\//i,'Edge'],[/Chrome/i,'Chrome'],[/Firefox/i,'Firefox'],[/Safari/i,'Safari'],[/curl/i,'curl'],[/wget/i,'wget']];
  for(var i=0;i<m.length;i++)if(m[i][0].test(ua))return m[i][1];return ua?ua.split(/[\/ ]/)[0]:'—';}
function renderClients(){
  var rows=[];st.channels.forEach(function(c){c.clients.forEach(function(x){rows.push({c:c,x:x});});});
  var f=filt.toLowerCase();if(f)rows=rows.filter(function(r){return (r.x.addr+' '+(r.c.name||'')+' '+r.c.id+' '+player(r.x.ua)+' '+r.x.type).toLowerCase().indexOf(f)>=0;});
  rows.sort(function(a,b){return b.x.kbps-a.x.kbps;});
  var ips={};rows.forEach(function(r){ips[r.x.addr]=1;});
  var h='<div class="fil"><input type="text" id="cf" placeholder="Caută IP, canal, player…" value="'+esc(filt)+'" oninput="filt=this.value;render();var e=document.getElementById(\'cf\');e.focus();e.setSelectionRange(e.value.length,e.value.length);"><span class="hint">'+rows.length+' conexiuni · '+Object.keys(ips).length+' IP-uri unice</span></div>';
  if(!rows.length)return h+'<div class="empty">Niciun client conectat.</div>';
  h+='<div class="ctab"><table><tr><th>IP client</th><th>Canal</th><th>Format</th><th>Player</th><th style="text-align:right">Viteză</th><th style="text-align:right">Transferat</th><th style="text-align:right">Conectat de</th></tr>';
  rows.forEach(function(r){var x=r.x,c=r.c;
    h+='<tr><td>'+esc(x.addr)+'</td><td class="t"><b>'+esc(c.name||c.id)+'</b> <span style="color:var(--mut)">'+esc(c.id)+'</span></td><td class="t">'+x.type+'</td><td class="ua" title="'+esc(x.ua)+'">'+esc(player(x.ua))+'</td><td style="text-align:right">'+rate(x.kbps||0)+'</td><td style="text-align:right">'+size(x.bytes)+'</td><td style="text-align:right">'+dur(x.secs)+'</td></tr>';});
  return h+'</table></div>';
}
function tog(id){opened[id]=!opened[id];render();}
function render(){
  if(!st)return;var L=document.getElementById('list'),h='',on=0,en=0,bw=0,ob=0,cl=0,cc=0;
  st.channels.forEach(function(c){
    if(c.enabled)en++;if(c.online)on++;bw+=c.kbps||0;ob+=c.out_kbps||0;cl+=c.clients.length;cc+=c.cc||0;
    var cls=c.enabled?(c.online?'ok':'bad'):'',tags='';
    if(c.input_idx>0&&c.online)tags+='<span class="tag w">backup #'+(c.input_idx+1)+'</span>';
    if(c.scrambled)tags+='<span class="tag r">criptat</span>';
    if(!c.enabled)tags+='<span class="tag">oprit</span>';
    h+='<div class="ch'+(c.enabled?'':' dis')+(opened[c.id]?' open':'')+'"><div class="row" onclick="tog(\''+esc(c.id)+'\')">';
    h+='<span class="dot '+cls+'"></span>';
    h+='<div class="nm"><b>'+esc(c.name||c.id)+tags+'</b><small>'+esc(c.id)+(c.service?' · '+esc(c.service):'')+'</small></div>';
    h+='<div class="in"><small>Intrare'+(c.inputs&&c.inputs.length>1?' ('+(c.input_idx+1)+'/'+c.inputs.length+')':'')+'</small><div>'+esc(c.input||(c.inputs&&c.inputs[0])||'—')+'</div></div>';
    h+='<div class="num">'+(c.online?rate(c.kbps):'<span class="bad-t">'+(c.enabled?'offline':'—')+'</span>')+'<small>'+(c.online?'activ '+dur(c.uptime):'')+'</small></div>';
    h+='<div class="num">'+(c.online||c.out_kbps?rate(c.out_kbps||0):'—')+'<small>ieșire</small></div>';
    h+='<div class="num'+(c.cc?' warn-t':'')+'">'+(c.cc||0)+'<small>erori CC</small></div>';
    h+='<div class="num">'+c.clients.length+'<small>clienți</small></div>';
    h+='<div class="ops" onclick="event.stopPropagation()"><button class="sm" onclick="editCh(\''+esc(c.id)+'\')">Editează</button><button class="sm" onclick="restartCh(\''+esc(c.id)+'\')">Repornește</button><button class="sm dng" onclick="delCh(\''+esc(c.id)+'\')">Șterge</button></div></div>';
    h+='<div class="det">';
    if(c.error&&!c.online)h+='<div class="err">'+esc(c.error)+'</div>';
    var o=outs(c);if(o.length){h+='<h4>Ieșiri</h4><div class="urls">';o.forEach(function(x){h+='<div class="url"><span class="k">'+x[0]+'</span><code>'+esc(x[1])+'</code><button class="sm" onclick="cp(this,\''+esc(x[1])+'\')">Copiază</button></div>';});h+='</div>';}
    h+='<div class="cols"><div><h4>PID-uri'+(c.provider?' · '+esc(c.provider):'')+'</h4>';
    if(c.pids&&c.pids.length){h+='<table><tr><th>PID</th><th>Tip</th><th>Limbă</th><th style="text-align:right">Bitrate</th><th style="text-align:right">CC</th></tr>';
      c.pids.forEach(function(p){h+='<tr><td>'+hex(p.pid)+' <span style="color:var(--mut)">'+p.pid+'</span></td><td class="t k-'+p.kind+'">'+esc(p.type)+(p.scrambled?' <span class="tag r">criptat</span>':'')+'</td><td>'+esc(p.lang||'')+'</td><td style="text-align:right">'+rate(p.kbps)+'</td><td style="text-align:right"'+(p.cc?' class="warn-t"':'')+'>'+p.cc+'</td></tr>';});
      h+='</table>';}else h+='<div class="hint">Fără date.</div>';
    h+='</div><div><h4>Clienți</h4>';
    if(c.clients.length){h+='<table>';c.clients.forEach(function(x){h+='<tr><td>'+esc(x.addr)+'</td><td class="t">'+x.type+'</td><td class="ua" title="'+esc(x.ua)+'">'+esc(player(x.ua))+'</td><td style="text-align:right">'+rate(x.kbps||0)+'</td><td style="text-align:right">'+dur(x.secs)+'</td></tr>';});h+='</table>';}else h+='<div class="hint">Niciun client conectat.</div>';
    if(c.hls)h+='<div class="hint" style="margin-top:10px">Segmente HLS în memorie: '+c.hls_segs+'</div>';
    if(c.switches)h+='<div class="hint">Comutări sursă: '+c.switches+'</div>';
    h+='</div></div></div></div>';
  });
  if(view==='cl')h=renderClients();
  L.innerHTML=h||'<div class="empty">Niciun canal. Apasă <b>+ Canal</b> ca să adaugi primul.</div>';
  document.getElementById('t_cl').textContent='Clienți ('+cl+')';
  document.getElementById('sum').innerHTML='<span>Online <b>'+on+'/'+en+'</b></span><span>Intrare <b>'+rate(bw)+'</b></span><span>Ieșire <b>'+rate(ob)+'</b></span><span>Clienți <b>'+cl+'</b></span><span>Erori CC <b>'+cc+'</b></span><span>Uptime <b>'+dur(st.uptime)+'</b></span>';
}
function cp(b,t){var done=function(){b.textContent='Copiat';setTimeout(function(){b.textContent='Copiază';},1200);};
  if(navigator.clipboard&&window.isSecureContext)navigator.clipboard.writeText(t).then(done);else{var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove();done();}}
function closeM(){document.getElementById('modal').classList.add('hidden');}
function showM(h){document.getElementById('mbox').innerHTML=h;document.getElementById('modal').classList.remove('hidden');}
function editCh(id){
  var c=null;(cfg.channels||[]).forEach(function(x){if(x.id===id)c=x;});
  var n=!c;c=c||{id:'',name:'',enabled:true,inputs:[],http:true,hls:true,udp:'',public:false};
  showM('<h3>'+(n?'Canal nou':'Editează '+esc(c.name||c.id))+'</h3>'+
  '<label>ID (apare în URL)</label><input type="text" id="f_id" value="'+esc(c.id)+'" placeholder="hd365">'+
  '<label>Nume</label><input type="text" id="f_name" value="'+esc(c.name)+'" placeholder="HD365">'+
  '<label>Intrări (una pe linie, în ordinea priorității — următoarele sunt backup)</label><textarea id="f_in" placeholder="udp://eth0@239.1.1.1:1234">'+esc((c.inputs||[]).join('\n'))+'</textarea>'+
  '<div class="hint"><code>udp://[iface@]239.1.1.1:1234</code> · <code>rtp://@239.1.1.1:5000</code> · <code>udp://0.0.0.0:5000</code><br><code>http://server/stream.ts</code> · <code>http://server/live.m3u8</code><br><code>srt://host:9000?mode=caller</code> · <code>srt://:9000?mode=listener</code><br><code>rtmp://host/app/key</code> · <code>rtmp-listen://0.0.0.0:1935/live/key</code><br>UDP/RTP/HTTP/HLS(.ts)/SRT păstrează PID-urile originale. RTMP și HLS fMP4 nu au PID-uri: primesc video 0x100, audio 0x101, PMT 0x1000 (prin ffmpeg).</div>'+
  '<label>Ieșire UDP (opțional)</label><input type="text" id="f_udp" value="'+esc(c.udp)+'" placeholder="udp://eth1@239.10.0.1:1234?ttl=8">'+
  '<div class="chk"><label><input type="checkbox" id="f_en"'+(c.enabled?' checked':'')+'> Activ</label><label><input type="checkbox" id="f_http"'+(c.http?' checked':'')+'> HTTP-TS</label><label><input type="checkbox" id="f_hls"'+(c.hls?' checked':'')+'> HLS</label><label><input type="checkbox" id="f_pub"'+(c.public?' checked':'')+'> Public (fără token)</label></div>'+
  '<div class="msg" id="f_msg"></div><div class="foot"><button onclick="closeM()">Anulează</button><button class="pri" onclick="saveCh(\''+esc(n?'':c.id)+'\')">Salvează</button></div>');
}
function v(id){return document.getElementById(id);}
function saveCh(old){
  var b={id:v('f_id').value.trim(),name:v('f_name').value.trim(),inputs:v('f_in').value.split('\n'),udp:v('f_udp').value.trim(),enabled:v('f_en').checked,http:v('f_http').checked,hls:v('f_hls').checked,public:v('f_pub').checked};
  api('POST','/api/channel'+(old?'?old='+encodeURIComponent(old):''),b).then(function(){closeM();return loadCfg();}).then(tick).catch(function(e){v('f_msg').textContent=e.message;});
}
function delCh(id){if(!confirm('Ștergi canalul '+id+'?'))return;api('DELETE','/api/channel?id='+encodeURIComponent(id)).then(loadCfg).then(tick);}
function restartCh(id){api('POST','/api/restart?id='+encodeURIComponent(id)).then(tick);}
function genTok(){var a=new Uint8Array(12);crypto.getRandomValues(a);var s='';a.forEach(function(x){s+=('0'+x.toString(16)).slice(-2);});var t=v('s_tok');t.value=(t.value.trim()?t.value.trim()+'\n':'')+s;}
function openSettings(){
  showM('<h3>Setări</h3><label>Tokeni de acces (unul pe linie). Gol = toate canalele deschise.</label><textarea id="s_tok">'+esc((cfg.tokens||[]).join('\n'))+'</textarea>'+
  '<div class="hint">Se adaugă la URL: <code>?token=…</code>. Canalele marcate „Public” nu cer token.</div><button class="sm" style="margin-top:6px" onclick="genTok()">Generează token</button>'+
  '<label>Durată segment HLS (secunde)</label><input type="number" id="s_seg" min="1" max="20" value="'+cfg.hls_segment+'">'+
  '<label>Segmente în playlist HLS</label><input type="number" id="s_win" min="2" max="30" value="'+cfg.hls_window+'">'+
  '<label>Parolă nouă admin (lasă gol ca să rămână)</label><input type="password" id="s_pass" autocomplete="new-password">'+
  '<div class="msg" id="s_msg"></div><div class="foot"><button onclick="closeM()">Anulează</button><button class="pri" onclick="saveSet()">Salvează</button></div>');
}
function saveSet(){
  var p=v('s_pass').value;
  api('POST','/api/settings',{tokens:v('s_tok').value.split('\n'),hls_segment:+v('s_seg').value,hls_window:+v('s_win').value,admin_pass:p}).then(function(){closeM();if(p)location.reload();return loadCfg();}).then(tick).catch(function(e){v('s_msg').textContent=e.message;});
}
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeM();});
loadCfg().then(tick);setInterval(tick,2000);
</script>
</body></html>`
