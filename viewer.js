// View-only viewer for exam files (restricted files) for Admin and Teacher accounts.
// No download, print or save links; right-click, copy, Ctrl+S/P are blocked; every page carries a watermark with the
// viewer's email and the time so any screenshot can be traced. (No website can fully stop screenshots or phone photos.)
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const preview = require('./preview');
const { esc } = preview;

const PDF = 'application/pdf';
const IMG = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif']);
const PDFJS_DIR = path.join(path.dirname(require.resolve('pdfjs-dist/package.json')), 'build');

function shell({ name, body, nonce, mark, script = '' }) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(name)}</title>
<style>
html,body{margin:0}body{font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#e5e7eb;color:#1f2937;-webkit-user-select:none;user-select:none;-webkit-touch-callout:none}
.top{position:sticky;top:0;z-index:5;display:flex;gap:12px;align-items:center;justify-content:space-between;padding:10px 18px;background:#0f2a44;color:#fff}
.top b{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.top span{font-size:12px;opacity:.85;white-space:nowrap}
.wrap{position:relative;max-width:1000px;margin:18px auto;padding:0 12px}
.sheet,.slide{background:#fff;border-radius:8px;box-shadow:0 1px 3px #0002;padding:28px 34px;margin-bottom:18px;overflow:auto}
.slide .n{color:#6b7280;font-size:12px}.slide p{margin:4px 0}.slide .imgs{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}.slide .imgs img{max-height:320px}
.note{color:#6b7280;font-size:13px;margin:0 0 12px}h2.tab{font-size:16px;margin:0 0 10px}
table{border-collapse:collapse;font-size:13px}td,th{border:1px solid #d1d5db;padding:4px 8px;vertical-align:top}img{max-width:100%;height:auto;-webkit-user-drag:none;pointer-events:none}
canvas{display:block;width:100%;height:auto;margin:0 auto 14px;background:#fff;box-shadow:0 1px 3px #0003}
.wm{position:fixed;inset:0;z-index:4;pointer-events:none;overflow:hidden}
.wm div{position:absolute;white-space:nowrap;transform:rotate(-30deg);font:600 15px system-ui,sans-serif;color:rgba(15,42,68,.13)}
#msg{padding:30px;text-align:center;color:#6b7280}
@media print{body *{display:none!important}body:after{content:"Printing is not allowed.";display:block;padding:40px;font:20px sans-serif}}
</style></head><body oncontextmenu="return false">
<div class="top"><b>${esc(name)}</b><span>View only · ${esc(mark)}</span></div>
<div class="wm" aria-hidden="true">${Array.from({ length: 35 }, (_, i) => `<div style="left:${(i % 5) * 24 - 10 + (Math.floor(i / 5) % 2) * 12}%;top:${Math.floor(i / 5) * 16 + 4}%">${esc(mark)}</div>`).join('')}</div>
<div class="wrap">${body}</div>
<script nonce="${nonce}">
document.addEventListener('contextmenu',e=>e.preventDefault());
['copy','cut','dragstart','selectstart'].forEach(t=>document.addEventListener(t,e=>e.preventDefault()));
document.addEventListener('keydown',e=>{const k=(e.key||'').toLowerCase();if((e.ctrlKey||e.metaKey)&&['s','p','c','a','u'].includes(k)||k==='printscreen'){e.preventDefault();if(k==='printscreen'){try{navigator.clipboard.writeText('')}catch(_){}}}});
</script>${script}</body></html>`;
}

function csp(nonce) {
  return `default-src 'none'; script-src 'self' 'nonce-${nonce}'; worker-src 'self' blob:; connect-src 'self'; img-src data: blob:; style-src 'unsafe-inline'; font-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'`;
}

async function page(f, id, user) {
  const nonce = crypto.randomBytes(16).toString('base64');
  const when = new Date().toLocaleString('en-GB', { timeZone: 'Europe/London', day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  const mark = `${user.email} · ${when} · FC Training Academy`;
  const dataUrl = `/_blob/${encodeURIComponent(id)}?viewdata=1`;
  let body, script = '';
  if (f.type === PDF || IMG.has(f.type)) {
    body = `<div id="pages"></div><div id="msg">Loading…</div>`;
    script = f.type === PDF ? `<script type="module" nonce="${nonce}">
import * as pdfjs from '/_pdfjs/pdf.min.mjs';
pdfjs.GlobalWorkerOptions.workerSrc='/_pdfjs/pdf.worker.min.mjs';
const msg=document.getElementById('msg'),box=document.getElementById('pages');
try{const r=await fetch(${JSON.stringify(dataUrl)},{headers:{'X-FC-View':'1'},credentials:'same-origin'});if(!r.ok)throw 0;
const doc=await pdfjs.getDocument({data:new Uint8Array(await r.arrayBuffer()),isEvalSupported:false}).promise;msg.remove();
const w=Math.min(box.clientWidth||900,1000);
for(let i=1;i<=doc.numPages;i++){const p=await doc.getPage(i);const v=p.getViewport({scale:1});const s=(w/v.width)*(window.devicePixelRatio||1);const vp=p.getViewport({scale:s});
const c=document.createElement('canvas');c.width=vp.width;c.height=vp.height;box.appendChild(c);await p.render({canvasContext:c.getContext('2d'),viewport:vp}).promise}}
catch(e){msg.textContent="Couldn't open this file."}
</script>` : `<script nonce="${nonce}">
(async()=>{const msg=document.getElementById('msg');try{const r=await fetch(${JSON.stringify(dataUrl)},{headers:{'X-FC-View':'1'},credentials:'same-origin'});if(!r.ok)throw 0;
const u=URL.createObjectURL(await r.blob());const im=new Image();im.alt='';im.src=u;msg.replaceWith(im);document.getElementById('pages').remove()}catch(e){msg.textContent="Couldn't open this file."}})();
</script>`;
  } else {
    const b = preview.CAN_PREVIEW.has(f.type) ? await preview.bodyOf(f) : null;
    if (b) body = (b.note ? `<p class="note">${esc(b.note)}</p>` : '') + b.body;
    else if (/^text\//.test(f.type) || f.type === 'application/json') body = `<div class="sheet"><pre style="white-space:pre-wrap;margin:0">${esc(f.data.toString('utf8').slice(0, 2e6))}</pre></div>`;
    else body = `<div class="sheet">This type of file (${esc((f.name || '').split('.').pop())}) can't be shown online. Ask the Manager if you need it.</div>`;
  }
  return { html: shell({ name: f.name || 'File', body, nonce, mark, script }), csp: csp(nonce) };
}

function mountPdfjs(app, auth) {
  app.get('/_pdfjs/:f', auth, (req, res) => {
    if (!/^pdf(\.worker)?\.min\.mjs$/.test(req.params.f)) return res.status(404).send('Not found');
    res.set({ 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'private, max-age=86400' });
    res.send(fs.readFileSync(path.join(PDFJS_DIR, req.params.f)));
  });
}

module.exports = { page, mountPdfjs };
