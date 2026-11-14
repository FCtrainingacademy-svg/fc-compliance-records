// Turns Word, Excel and PowerPoint files into a read-only HTML page so they open in the browser instead of downloading.
// The page has no scripts (strict CSP); images are embedded as data: URLs. A "Download original" link is always shown.
const mammoth = require('mammoth');
const XLSX = require('xlsx');
const JSZip = require('jszip');
const WordExtractor = require('word-extractor');

const DOCX = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
const XLSX_T = ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/vnd.ms-excel'];
const PPTX = 'application/vnd.openxmlformats-officedocument.presentationml.presentation';
const DOC = 'application/msword';
const CAN_PREVIEW = new Set([DOCX, DOC, PPTX, ...XLSX_T]);
const CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'";

const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function page(name, body, dl, note) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(name)}</title>
<style>
body{margin:0;font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:#f3f4f6;color:#1f2937}
.top{position:sticky;top:0;z-index:2;display:flex;gap:12px;align-items:center;justify-content:space-between;padding:10px 18px;background:#0f2a44;color:#fff}
.top b{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.top a{color:#fff;background:#ffffff22;border:1px solid #ffffff55;border-radius:6px;padding:5px 12px;text-decoration:none;white-space:nowrap;font-size:14px}
.wrap{max-width:1000px;margin:18px auto;padding:0 12px}.sheet{background:#fff;border-radius:8px;box-shadow:0 1px 3px #0002;padding:28px 34px;margin-bottom:18px;overflow:auto}
.note{color:#6b7280;font-size:13px;margin:0 0 12px}h2.tab{font-size:16px;margin:0 0 10px}
table{border-collapse:collapse;font-size:13px}td,th{border:1px solid #d1d5db;padding:4px 8px;vertical-align:top}img{max-width:100%;height:auto}
.slide{background:#fff;border-radius:8px;box-shadow:0 1px 3px #0002;padding:22px 28px;margin-bottom:16px}.slide .n{color:#6b7280;font-size:12px;margin-bottom:6px}.slide p{margin:4px 0}.slide .imgs{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}.slide .imgs img{max-height:320px}
</style></head><body><div class="top"><b>${esc(name)}</b><a href="${esc(dl)}">Download original</a></div><div class="wrap">${note ? `<p class="note">${esc(note)}</p>` : ''}${body}</div></body></html>`;
}

// Older Word (.doc) files: text and paragraphs (some are really .docx inside, which get the full layout).
async function doc(buf) {
  if (buf[0] === 0x50 && buf[1] === 0x4b) return docx(buf);
  const d = await new WordExtractor().extract(buf);
  const paras = String(d.getBody() || '').split(/\r?\n/).map(t => t.replace(/\s+$/, ''));
  const html = paras.map(t => t.trim() ? `<p>${esc(t)}</p>` : '').join('');
  return `<div class="sheet">${html || '<p>(This document has no text.)</p>'}</div>`;
}
async function docx(buf) {
  const r = await mammoth.convertToHtml({ buffer: buf });
  return `<div class="sheet">${r.value || '<p>(This document has no text.)</p>'}</div>`;
}

function sheets(buf) {
  const wb = XLSX.read(buf, { type: 'buffer', cellStyles: false });
  return wb.SheetNames.map(n => {
    const html = XLSX.utils.sheet_to_html(wb.Sheets[n], { header: '', footer: '' }).replace(/<script[\s\S]*?<\/script>/gi, '');
    return `<div class="sheet"><h2 class="tab">${esc(n)}</h2>${html}</div>`;
  }).join('') || '<div class="sheet">(Empty workbook)</div>';
}

const MIME = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', bmp: 'image/bmp' };
async function pptx(buf) {
  const zip = await JSZip.loadAsync(buf);
  const slides = Object.keys(zip.files).filter(p => /^ppt\/slides\/slide\d+\.xml$/.test(p)).sort((a, b) => +a.match(/\d+/)[0] - +b.match(/\d+/)[0]);
  let total = 0; const out = [];
  for (const [i, p] of slides.entries()) {
    const xml = await zip.file(p).async('string');
    const paras = (xml.match(/<a:p>[\s\S]*?<\/a:p>/g) || []).map(pp => (pp.match(/<a:t>([\s\S]*?)<\/a:t>/g) || []).map(t => t.replace(/<\/?a:t>/g, '')).join('')).filter(t => t.trim());
    const relP = p.replace('slides/', 'slides/_rels/') + '.rels'; const imgs = [];
    if (zip.file(relP)) {
      const rels = await zip.file(relP).async('string');
      for (const m of rels.matchAll(/Target="\.\.\/media\/([^"]+)"/g)) {
        const ext = m[1].split('.').pop().toLowerCase(); const f = zip.file('ppt/media/' + m[1]);
        if (!MIME[ext] || !f) continue; const b = await f.async('nodebuffer');
        if (b.length > 3e6 || total + b.length > 25e6) continue; total += b.length;
        imgs.push(`<img alt="" src="data:${MIME[ext]};base64,${b.toString('base64')}">`);
      }
    }
    out.push(`<div class="slide"><div class="n">Slide ${i + 1}</div>${paras.map(t => `<p>${t}</p>`).join('')}${imgs.length ? `<div class="imgs">${imgs.join('')}</div>` : ''}</div>`);
  }
  return out.join('') || '<div class="slide">(No slides)</div>';
}

async function render(f, dl) {
  let body, note = '';
  if (f.type === DOCX) body = await docx(f.data);
  else if (f.type === DOC) body = await doc(f.data);
  else if (XLSX_T.includes(f.type)) body = sheets(f.data);
  else if (f.type === PPTX) { body = await pptx(f.data); note = 'Preview shows each slide\'s text and pictures. Download the original to see the full slide layout.'; }
  return page(f.name || 'File', body, dl, note);
}

// body only (used by the view-only viewer)
async function bodyOf(f) {
  if (f.type === DOCX) return { body: await docx(f.data) };
  if (f.type === DOC) return { body: await doc(f.data) };
  if (XLSX_T.includes(f.type)) return { body: sheets(f.data) };
  if (f.type === PPTX) return { body: await pptx(f.data), note: 'Preview shows each slide\'s text and pictures.' };
  return null;
}

module.exports = { CAN_PREVIEW, CSP, render, bodyOf, esc };
