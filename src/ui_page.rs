// 单页实验台界面。所有密钥信息仅以 key id / 公钥呈现。

pub const INDEX_HTML: &str = r##"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>签名信任路径实验台</title>
<style>
  :root { --bg:#0f1420; --panel:#171e2e; --ink:#e8edf6; --dim:#93a0b8; --ok:#3fb96f; --bad:#e35d6a; --warn:#e0a93e; --info:#5aa1e8; }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--ink); font:14px/1.55 -apple-system,"PingFang SC","Microsoft YaHei",monospace; }
  header { padding:22px 28px; border-bottom:1px solid #24304a; background:linear-gradient(120deg,#152038,#101727); }
  h1 { margin:0; font-size:22px; letter-spacing:1px; }
  .sub { color:var(--dim); margin-top:6px; }
  main { display:grid; grid-template-columns: 420px 1fr; gap:18px; padding:18px 28px; }
  .card { background:var(--panel); border:1px solid #24304a; border-radius:10px; padding:16px; margin-bottom:16px; }
  .card h2 { font-size:14px; margin:0 0 12px; color:#b9c6df; letter-spacing:.5px; }
  label { display:block; color:var(--dim); margin:10px 0 4px; font-size:12px; }
  input,select,textarea { width:100%; background:#0e1422; border:1px solid #2a3852; color:var(--ink); border-radius:6px; padding:8px; font:inherit; }
  textarea { min-height:54px; word-break:break-all; }
  button { background:#2b5fb3; color:#fff; border:0; border-radius:6px; padding:8px 14px; cursor:pointer; font:inherit; margin:8px 8px 0 0; }
  button:hover { background:#3570cc; }
  button.ghost { background:#28324a; }
  .row { display:flex; gap:8px; }
  .row > * { flex:1; }
  .pill { display:inline-block; padding:1px 8px; border-radius:99px; font-size:12px; }
  .trusted { background:rgba(63,185,111,.18); color:var(--ok); border:1px solid var(--ok); }
  .historical { background:rgba(224,169,62,.18); color:var(--warn); border:1px solid var(--warn); }
  .invalid { background:rgba(227,93,106,.18); color:var(--bad); border:1px solid var(--bad); }
  .incomplete { background:rgba(90,161,232,.18); color:var(--info); border:1px solid var(--info); }
  .kv { color:var(--dim); font-size:12px; word-break:break-all; }
  .step { border-left:3px solid #2a3852; padding:6px 10px; margin:6px 0; background:#101726; border-radius:0 6px 6px 0; }
  .step.ok { border-left-color:var(--ok); }
  .step.no { border-left-color:var(--bad); }
  .step .c { color:#c9d5ea; font-weight:600; }
  .step .d { color:var(--dim); }
  .path { border:1px solid #24304a; border-radius:8px; padding:10px 12px; margin:10px 0; }
  .chain { display:flex; flex-wrap:wrap; gap:6px; align-items:center; margin:8px 0; }
  .node { background:#0e1422; border:1px solid #2a3852; border-radius:6px; padding:3px 8px; font-size:12px; }
  .arrow { color:var(--dim); }
  details summary { cursor:pointer; color:#9fb4d8; margin:6px 0; }
  table { width:100%; border-collapse:collapse; font-size:12px; }
  td,th { border-bottom:1px solid #22304c; padding:6px 8px; text-align:left; vertical-align:top; }
  th { color:var(--dim); font-weight:500; }
  .mono { font-family:ui-monospace,Menlo,monospace; font-size:12px; word-break:break-all; }
  #toast { position:fixed; right:20px; bottom:20px; max-width:420px; }
  .toast { background:#202a40; border:1px solid #34456a; border-radius:8px; padding:10px 14px; margin-top:8px; }
  .toast.err { border-color:var(--bad); }
  @media (max-width:1000px){ main { grid-template-columns:1fr; } }
</style>
</head>
<body>
<header>
  <h1>签名信任路径实验台</h1>
  <div class="sub">本地测试密钥 · Ed25519 · 私钥 AES-GCM 加密存放 · API/日志/导出只出现公钥与 key id · 时钟可注入</div>
  <div class="sub">图版本：<span id="gver" class="mono">…</span> ｜ 图摘要：<span id="gdig" class="mono">…</span></div>
</header>
<main>
  <div>
    <div class="card">
      <h2>① 验证（摘要 + 签名 + 声明签署时刻 + 验证时刻）</h2>
      <label>制品摘要（sha256 hex）</label>
      <textarea id="digest"></textarea>
      <label>签名者 key id</label>
      <input id="kid">
      <label>签名（hex，可从“制品签名”列表带入）</label>
      <textarea id="sig"></textarea>
      <div class="row">
        <div><label>声明签署时刻 claimed_at（Unix 秒）</label><input id="claimed" type="number"></div>
        <div><label>验证时刻 verify_at（Unix 秒）</label><input id="vat" type="number"></div>
      </div>
      <button onclick="doVerify()">寻找所有信任路径并验证</button>
      <button class="ghost" onclick="presetA(false)">预置制品A·T9（compromise前）</button>
      <button class="ghost" onclick="presetA(true)">预置制品A·T8（compromise后）</button>
    </div>

    <div class="card">
      <h2>② 批量验证（冻结信任图摘要）</h2>
      <div class="kv" id="freezeInfo">批次创建时冻结；运行中新增撤销留到下一批。</div>
      <button onclick="createDemoBatch()">创建并运行预置批次</button>
      <input id="batchId" placeholder="批次 id（恢复时填入）">
      <button class="ghost" onclick="resumeBatch()">恢复/查询批次</button>
      <div id="batchOut"></div>
    </div>

    <div class="card">
      <h2>③ 发布信任事件（乐观版本控制）</h2>
      <div class="kv">两操作者并发时，expected_version 不匹配的一方收到 409 版本冲突。</div>
      <label>动作</label>
      <select id="act">
        <option value="key">创建本地密钥</option>
        <option value="anchor">根锚点</option>
        <option value="rotation">轮换/中间证明</option>
        <option value="revocation_comp">撤销（compromise）</option>
        <option value="revocation_sup">撤销（superseded）</option>
        <option value="supersede">纠错（追加 superseding 事件）</option>
        <option value="sign">制品签名</option>
        <option value="fill_orphan">补齐孤儿证明（incomplete→trusted）</option>
      </select>
      <div id="dyn"></div>
      <label>幂等键 idem_key（可空）</label><input id="idem">
      <label>expected_version（-1 = 任意当前版本，仅演示用）</label><input id="ever" value="-1" type="number">
      <button onclick="publish()">提交</button>
    </div>
  </div>

  <div>
    <div class="card">
      <h2>验证结论 —— 可从结论沿路径回到每个证明与时间判断</h2>
      <div id="result">尚未验证。</div>
    </div>
    <div class="card">
      <h2>当前信任图（只追加；纠错事件不删除原记录）</h2>
      <div id="graph"></div>
    </div>
    <div class="card">
      <h2>日志（仅 key id 等公开标识）与导出</h2>
      <button class="ghost" onclick="loadLogs()">查看日志</button>
      <a href="/api/export" target="_blank"><button class="ghost" type="button">导出全部公开数据 JSON</button></a>
      <pre id="logs" class="mono" style="white-space:pre-wrap;max-height:240px;overflow:auto"></pre>
    </div>
  </div>
</main>
<div id="toast"></div>
<script>
const $ = (id) => document.getElementById(id);
async function api(path, opts={}) {
  const res = await fetch(path, {headers:{'Content-Type':'application/json'}, ...opts});
  const data = await res.json().catch(()=>({}));
  if (!res.ok) { toast((data.error||res.statusText), true); throw new Error(data.error||'err'); }
  return data;
}
function toast(msg, err=false) {
  const d = document.createElement('div'); d.className='toast'+(err?' err':''); d.textContent=msg;
  $('toast').appendChild(d); setTimeout(()=>d.remove(), 6000);
}
const esc = (s)=> String(s??'').replace(/[&<>]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function pill(v) { return '<span class="pill '+v+'">'+v+'</span>'; }
let STATE = {keys:[], events:[], sigs:[], seed:null};

function stepHtml(s) {
  return '<div class="step '+(s.ok?'ok':'no')+'"><div class="c">'+esc(s.check)+
    ' ['+(s.ok?'通过':'失败')+']</div><div class="d">'+esc(s.detail)+'</div></div>';
}
function linkHtml(l) {
  return '<span class="node">'+esc(l.role)+': '+esc(l.kid.slice(0,12))+
    (l.not_before!=null?'<br><span class="kv">['+l.not_before+','+l.not_after+']</span>':'')+
    '</span>';
}
function pathHtml(p, name) {
  const chain = p.chain.map(linkHtml).join('<span class="arrow"> ←验签 </span>');
  return '<div class="path"><b>'+name+'</b> '+pill(p.status)+
    (p.root_kid?' <span class="kv">根: '+esc(p.root_kid)+'</span>':'')+
    (p.gap_kid?' <span class="kv">缺口: '+esc(p.gap_kid)+'</span>':'')+
    '<div class="chain">'+chain+'</div>'+
    '<details open><summary>'+p.steps.length+' 项逐步原因（签名 / key usage / 生效区间 / 轮换连续性 / 撤销）</summary>'+
    p.steps.map(stepHtml).join('')+'</details></div>';
}
function renderReport(r) {
  let h = '<div>'+pill(r.verdict)+' <b>'+esc(r.summary)+'</b></div>';
  h += '<div class="kv">图摘要 '+esc(r.graph_digest.slice(0,20))+' ｜ 签署 '+r.claimed_at+' ｜ 验证 '+r.verify_at+'</div>';
  h += '<details open><summary>全局检查</summary>'+r.global_steps.map(stepHtml).join('')+'</details>';
  if (r.adopted) h += pathHtml(r.adopted, '采用路径');
  if (r.rejected && r.rejected.length) h += '<details><summary>拒绝/备选路径（'+r.rejected.length+'）</summary>'+
    r.rejected.map((p)=>pathHtml(p,'拒绝路径')).join('')+'</details>';
  $('result').innerHTML = h;
}
async function doVerify() {
  const body = {digest:$('digest').value.trim(), kid:$('kid').value.trim(),
    signature:$('sig').value.trim(), claimed_at:Number($('claimed').value), verify_at:Number($('vat').value)};
  renderReport(await api('/api/verify', {method:'POST', body:JSON.stringify(body)}));
}
async function presetA(after) {
  const s = STATE.seed; if (!s) { toast('尚无预置数据', true); return; }
  $('digest').value = s.digest_a; $('kid').value = s.leaf;
  $('sig').value = s.sig_a; $('claimed').value = s.t4;
  $('vat').value = after ? s.verify_after : s.verify_before;
  await doVerify();
}
async function createDemoBatch() {
  const r = await api('/api/batches', {method:'POST', body:JSON.stringify({use_demo:true})});
  $('batchId').value = r.batch_id;
  const run = await api('/api/batches/'+r.batch_id+'/run', {method:'POST'});
  renderBatch(run);
  await refresh();
}
async function resumeBatch() {
  const id = $('batchId').value.trim(); if (!id) return;
  renderBatch(await api('/api/batches/'+id+'/run', {method:'POST'}));
}
function renderBatch(r) {
  let h = '<div class="kv">批次 '+esc(r.batch_id)+' ｜ 冻结图版本 v'+r.graph_version+
    ' ｜ 摘要 '+esc(r.graph_digest.slice(0,16))+'<br>总数 '+r.total+'，本次新处理 '+r.processed_now+
    '，此前已完成(恢复跳过) '+r.already_done+'</div>';
  r.results.forEach((x,i)=>{ h += '<div class="path">#'+i+' '+pill(x.verdict)+' '+esc(x.summary)+'</div>'; });
  $('batchOut').innerHTML = h;
}
const DYN = {
  key: '用途<select id="d_usage"><option value="root">root</option><option value="intermediate">intermediate</option><option value="signing">signing</option></select>',
  anchor: 'root kid<input id="d_kid"><div class="row"><div>not_before<input id="d_nb" type="number"></div><div>not_after<input id="d_na" type="number"></div></div>',
  rotation: 'issuer<input id="d_issuer"> child<input id="d_child"><div class="row"><div>not_before<input id="d_nb" type="number"></div><div>not_after<input id="d_na" type="number"></div></div>',
  revocation_comp: 'issuer<input id="d_issuer"> subject<input id="d_subject"> recorded_at<input id="d_at" type="number">',
  revocation_sup: 'issuer<input id="d_issuer"> subject<input id="d_subject"> recorded_at<input id="d_at" type="number">',
  supersede: 'issuer(=原事件签发者)<input id="d_issuer"> 目标事件id<input id="d_target"> recorded_at<input id="d_at" type="number">',
  sign: 'kid<input id="d_kid"> digest(hex)<textarea id="d_digest"></textarea> claimed_at<input id="d_at" type="number">',
  fill_orphan: '记录时间(默认T3)<input id="d_at" type="number" value="0">'
};
$('act').onchange = ()=> $('dyn').innerHTML = DYN[$('act').value];
$('dyn').innerHTML = DYN.key;
async function publish() {
  const act = $('act').value, idem = $('idem').value.trim()||null;
  const ev = Number($('ever').value);
  let body = {idem_key:idem, expected_version:ev}, path='/api/events', method='POST';
  const v = (id)=>$(id)?.value.trim();
  if (act==='key') { path='/api/keys'; body={usage:v('d_usage'), idem_key:idem}; }
  else if (act==='anchor') Object.assign(body,{kind:'root_anchor',root_kid:v('d_kid'),not_before:Number(v('d_nb')),not_after:Number(v('d_na'))});
  else if (act==='rotation') Object.assign(body,{kind:'rotation',issuer_kid:v('d_issuer'),child_kid:v('d_child'),not_before:Number(v('d_nb')),not_after:Number(v('d_na'))});
  else if (act.startsWith('revocation')) Object.assign(body,{kind:'revocation',issuer_kid:v('d_issuer'),subject_kid:v('d_subject'),recorded_at:Number(v('d_at')),reason:act==='revocation_comp'?'compromise':'superseded'});
  else if (act==='supersede') Object.assign(body,{kind:'supersede',issuer_kid:v('d_issuer'),target_event_id:v('d_target'),recorded_at:Number(v('d_at'))});
  else if (act==='sign') { path='/api/signatures'; body={kid:v('d_kid'),digest:v('d_digest'),claimed_at:Number(v('d_at')),idem_key:idem}; }
  else if (act==='fill_orphan') {
    await api('/api/events',{method:'POST',body:JSON.stringify({kind:'rotation',issuer_kid:STATE.seed.intermediate,
      child_kid:STATE.seed.orphan,not_before:STATE.seed.t3,not_after:STATE.seed.t1+10000,
      idem_key:'seed:rotation:i1-orphan',expected_version:ev})});
    await refresh(); toast('孤儿证明已补齐，再验证该摘要应为 trusted（或按撤销语义 historical）'); return;
  }
  const r = await api(path,{method,body:JSON.stringify(body)});
  toast('已写入：'+(r.id||r.kid||'ok'));
  await refresh();
}
async function loadLogs() { $('logs').textContent = (await api('/api/logs')).join('\n'); }
async function refresh() {
  const st = await api('/api/state');
  STATE = st;
  $('gver').textContent = 'v'+st.graph_version; $('gdig').textContent = st.graph_digest.slice(0,24)+'…';
  $('graph').innerHTML =
    '<table><tr><th>key id</th><th>用途</th><th>公钥(hex)</th></tr>'+
    st.keys.map(k=>'<tr><td class="mono">'+esc(k.kid)+'</td><td>'+esc(k.usage)+'</td><td class="mono">'+esc(k.public_key.slice(0,20))+'…</td></tr>').join('')+'</table>'+
    '<table style="margin-top:10px"><tr><th>seq</th><th>类型</th><th>内容（仅 kid/区间/原因）</th><th>纠错</th></tr>'+
    st.events.map(e=>'<tr><td>'+e.seq+'</td><td>'+esc(e.kind)+'</td><td class="mono">'+
      esc(e.issuer_kid)+(e.child_kid?' → '+esc(e.child_kid):'')+(e.subject_kid?' ✕ '+esc(e.subject_kid):'')+
      (e.reason?' ('+esc(e.reason)+'@'+e.recorded_at+')':'')+
      (e.not_before!=null?' ['+e.not_before+','+e.not_after+']':'')+
      (e.superseded_event?' ⤳ '+esc(e.superseded_event):'')+'</td><td>'+(e.superseded_by?'被 '+esc(e.superseded_by):'')+'</td></tr>').join('')+
    '</table><table style="margin-top:10px"><tr><th>制品签名</th><th>kid</th><th>claimed_at</th></tr>'+
    st.signatures.map(s=>'<tr style="cursor:pointer" onclick="$(\'digest\').value=\''+esc(s.digest)+'\';$(\'kid\').value=\''+esc(s.kid)+'\';$(\'sig\').value=\''+esc(s.signature)+'\';$(\'claimed\').value='+s.claimed_at+';$(\'vat\').value='+ (STATE.seed?STATE.seed.verify_after:0)+';toast(\'已带入，点验证\')"><td class="mono">'+esc(s.digest.slice(0,16))+'…</td><td class="mono">'+esc(s.kid.slice(0,12))+'</td><td>'+s.claimed_at+'</td></tr>').join('')+'</table>';
}
refresh();
</script>
</body></html>
"##;
