'use strict';
// Industry news: one list kept in the LMS (config/news). Stories are drafts until the Manager publishes them in the LMS.
// Draft stories prepared outside the LMS go in news/drafts.json; on start-up any new ones are added to the LMS as drafts
// (a story's id is remembered, so a draft the Manager deletes doesn't come back).
// Published stories show on the public News page (/news/), in the learner portal, and at /api/news (for the website).
const fs = require('fs');
const path = require('path');

module.exports = function news(app, { pool, bumpRev }) {
  const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const getDoc = async () => { const r = await pool.query(`SELECT data FROM docs WHERE col='config' AND id='news'`); return r.rows[0] ? r.rows[0].data : null; };
  const isDate = v => /^\d{4}-\d{2}-\d{2}$/.test(String(v || ''));
  const safeUrl = v => /^https:\/\/\S+$/i.test(String(v || '')) ? String(v) : '';
  const clean = x => ({ id: String(x.id), date: isDate(x.date) ? x.date : '', title: String(x.title || ''), summary: String(x.summary || ''),
    body: String(x.body || ''), source: String(x.source || ''), url: safeUrl(x.url), tag: String(x.tag || '') });
  const published = d => ((d && d.items) || []).filter(x => x && x.status === 'published' && x.title && x.id)
    .map(clean).sort((a, b) => (b.date || '').localeCompare(a.date || ''));

  async function seed() {
    let drafts = [];
    try { drafts = JSON.parse(fs.readFileSync(path.join(__dirname, 'news', 'drafts.json'), 'utf8')); } catch (e) { return; }
    if (!Array.isArray(drafts) || !drafts.length) return;
    const d = (await getDoc()) || { items: [], seen: [] }; d.items = d.items || []; d.seen = d.seen || [];
    const known = new Set([...d.seen, ...d.items.map(x => x.id)]); let added = 0;
    for (const x of drafts) {
      if (!x || !x.id || !x.title || known.has(String(x.id))) continue;
      d.items.push({ ...clean(x), status: 'draft', addedAt: new Date().toISOString() }); d.seen.push(String(x.id)); known.add(String(x.id)); added++;
    }
    if (!added) return;
    await pool.query(`INSERT INTO docs (col, id, data, updated_at, updated_by) VALUES ('config','news',$1,now(),'news drafts')
      ON CONFLICT (col, id) DO UPDATE SET data=EXCLUDED.data, updated_at=now(), updated_by=EXCLUDED.updated_by`, [d]);
    await bumpRev(); console.log(`News: ${added} new draft(s) waiting for the Manager to publish`);
  }

  // Published stories as JSON. Open to any site so fctrainingacademy.com can show them too.
  app.get('/api/news', async (req, res) => {
    res.set({ 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=300' });
    try { res.json({ items: published(await getDoc()) }); } catch (e) { res.status(500).json({ items: [] }); }
  });

  const fmt = d => d ? new Date(d + 'T12:00:00Z').toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'Europe/London' }) : '';
  // Plain text to HTML: blank line = new paragraph, lines starting "- " = bullet list.
  const paras = t => String(t || '').split(/\n\s*\n/).map(p => p.trim()).filter(Boolean).map(p => {
    let out = '', txt = [], ul = [];
    const flushT = () => { if (txt.length) out += `<p>${txt.map(esc).join('<br>')}</p>`; txt = []; };
    const flushU = () => { if (ul.length) out += `<ul>${ul.map(l => `<li>${esc(l)}</li>`).join('')}</ul>`; ul = []; };
    p.split('\n').forEach(l => { const m = l.match(/^\s*[-•]\s+(.*)$/); if (m) { flushT(); ul.push(m[1]); } else { flushU(); txt.push(l.trim()); } });
    flushT(); flushU(); return out; }).join('');

  app.get(['/news', '/news/'], async (req, res) => {
    let items = []; try { items = published(await getDoc()); } catch (e) {}
    const list = items.map(x => `<article id="${esc(x.id)}"><div class="meta">${x.tag ? `<span class="tag">${esc(x.tag)}</span>` : ''}<time datetime="${esc(x.date)}">${esc(fmt(x.date))}</time></div>
      <h2><a href="#${esc(x.id)}">${esc(x.title)}</a></h2>${x.summary ? `<p class="sum">${esc(x.summary)}</p>` : ''}${paras(x.body)}
      ${x.url ? `<p class="src">Source: <a href="${esc(x.url)}" target="_blank" rel="noopener">${esc(x.source || x.url.replace(/^https:\/\//, '').split('/')[0])} ↗</a></p>` : ''}</article>`).join('')
      || `<p class="empty">No news yet. Check back soon.</p>`;
    res.set({ 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'public, max-age=300' });
    res.send(`<!doctype html><html lang="en-GB"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Gas industry news | FC Training Academy</title><meta name="description" content="Gas industry updates for engineers and learners from FC Training Academy, Ilford: new standards, Gas Safe Register technical bulletins and changes to ACS assessments.">
<link rel="icon" href="/fc-logo.png"><style>
:root{--bg:#EEF1F4;--paper:#fff;--ink:#14212B;--muted:#5B6B78;--line:#D3DBE2;--flue:#0E5A86;--flame:#D98A12;--flame-soft:#FBEFD9}
@media (prefers-color-scheme:dark){:root{--bg:#0D151C;--paper:#15212B;--ink:#E4EBF0;--muted:#94A4B1;--line:#253441;--flue:#5BA8DA;--flame:#F2B04A;--flame-soft:#3A2B12;color-scheme:dark}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:17px/1.6 "Source Sans 3",system-ui,-apple-system,"Segoe UI",sans-serif}
header{background:var(--paper);border-bottom:1px solid var(--line)}.bar{max-width:760px;margin:0 auto;padding:10px 16px;display:flex;gap:12px;align-items:center}
.bar img{width:40px;height:40px;border-radius:50%}.bar .t{flex:1}.bar small{display:block;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.bar b{font-size:18px}.bar a.btn{border:1px solid var(--line);border-radius:8px;padding:8px 12px;color:var(--ink);text-decoration:none;font-weight:600;font-size:15px}
main{max-width:760px;margin:0 auto;padding:24px 16px 48px}h1{font-size:clamp(28px,5vw,38px);margin:8px 0 4px;line-height:1.2}.lead{color:var(--muted);margin:0 0 18px}
article{background:var(--paper);border:1px solid var(--line);border-radius:10px;padding:20px;margin-top:14px;scroll-margin-top:16px}
article:target{border-color:var(--flue);box-shadow:0 0 0 2px var(--flue)}article h2{font-size:22px;line-height:1.3;margin:6px 0 8px}article h2 a{color:inherit;text-decoration:none}
.meta{display:flex;gap:10px;align-items:center;font-size:14px;color:var(--muted)}.tag{font-size:12px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;border-radius:999px;padding:2px 9px;background:var(--flame-soft);color:var(--flame)}
.sum{font-weight:600}article p{margin:0 0 10px}article ul{margin:0 0 10px;padding-left:22px}.src{font-size:15px;color:var(--muted)}.src a{color:var(--flue);font-weight:600}
.empty{color:var(--muted)}footer{margin-top:28px;font-size:13px;color:var(--muted)}
</style></head><body><header><div class="bar"><img src="/fc-logo.png" alt="FC Training Academy"><div class="t"><small>FC Training Academy</small><b>News</b></div>
<a class="btn" href="https://fctrainingacademy.com">Website</a><a class="btn" href="/learn/">Learners</a></div></header>
<main><h1>Gas industry news</h1><p class="lead">Changes to standards, Gas Safe Register updates and what they mean for your work and your assessments.</p>${list}
<footer>© FC Training Academy, Ilford. Summaries are for guidance. Always work to the current edition of the standard, Gas Safe Register guidance and the manufacturer's instructions.</footer></main></body></html>`);
  });

  return { seed };
};
