'use strict';
// Learner portal: separate learner logins (own cookie, own table), invite links set by the Manager,
// server-marked mock exams, and attempt history visible to staff on the learner's record.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const LCOOKIE = 'fcl_session';
// The question bank is stored encrypted (the code repository is public). EXAM_KEY (64 hex chars) is set on the server.
function loadBank() {
  const plain = path.join(__dirname, 'private', 'mock-exams.json');
  if (!process.env.EXAM_KEY && fs.existsSync(plain)) return JSON.parse(fs.readFileSync(plain, 'utf8'));
  const raw = Buffer.from(fs.readFileSync(path.join(__dirname, 'private', 'mock-exams.enc'), 'utf8'), 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', Buffer.from(String(process.env.EXAM_KEY || ''), 'hex'), raw.subarray(0, 12));
  d.setAuthTag(raw.subarray(12, 28));
  return JSON.parse(Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8'));
}
let BANK;
try { BANK = loadBank(); } catch (e) { console.error('Mock exam bank could not be loaded (check EXAM_KEY):', e.message); BANK = { sections: {}, mocks: {} }; }
const MINUTES = 45;

module.exports = function learnerPortal(app, d) {
  const { HTML_CSP, pool, express, bcrypt, jwt, auth, notPending, needRole, pwOk, throttled, attempts, log, getSecret } = d;
  const cookieOpts = () => ({ httpOnly: true, sameSite: 'lax', secure: process.env.COOKIE_INSECURE !== '1', maxAge: 12 * 3600 * 1000, path: '/' });
  const sha = s => crypto.createHash('sha256').update(String(s)).digest('hex');
  const shuffle = a => { a = a.slice(); for (let i = a.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; };

  async function migrate() {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS learner_logins (learner_id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, pass_hash TEXT,
        active BOOLEAN NOT NULL DEFAULT TRUE, invite_hash TEXT, invite_expires TIMESTAMPTZ, token_version INT NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_login TIMESTAMPTZ);
      CREATE TABLE IF NOT EXISTS exam_attempts (id BIGSERIAL PRIMARY KEY, learner_id TEXT NOT NULL, mock TEXT NOT NULL,
        paper JSONB NOT NULL, answers JSONB, score INT, total INT, pct INT, by_section JSONB,
        started_at TIMESTAMPTZ NOT NULL DEFAULT now(), due_at TIMESTAMPTZ NOT NULL, finished_at TIMESTAMPTZ);
      CREATE INDEX IF NOT EXISTS exam_attempts_learner ON exam_attempts (learner_id);
    `);
  }

  async function learnerDoc(id) {
    const r = await pool.query(`SELECT data FROM docs WHERE col='learners' AND id=$1`, [id]); return r.rows[0] ? r.rows[0].data : null;
  }
  // Staff can preview the portal with their own staff sign-in (X-Preview header). Preview attempts are kept apart from real learners.
  async function staffPreview(req, force) {
    if ((!force && req.get('x-preview') !== '1') || !req.cookies.clr_session) return null;
    try {
      const p = jwt.verify(req.cookies.clr_session, getSecret()); if (!p.uid) return null;
      const r = await pool.query(`SELECT id, name, email, role, active, token_version, must_change FROM users WHERE id=$1`, [p.uid]); const u = r.rows[0];
      if (!u || !u.active || u.must_change || u.token_version !== p.tv || !['manager', 'admin'].includes(u.role)) return null;
      return { id: 'preview-' + u.id, email: u.email, name: u.name, cohort: 'Preview mode', programme: '', preview: true };
    } catch (e) { return null; }
  }
  async function lauth(req, res, next) {
    const pv = await staffPreview(req); if (pv) { req.learner = pv; return next(); }
    try {
      const t = req.cookies[LCOOKIE]; if (!t) return res.status(401).json({ error: 'signin' });
      const p = jwt.verify(t, getSecret()); if (p.typ !== 'learner') throw 0;
      const r = await pool.query(`SELECT learner_id, email, active, token_version FROM learner_logins WHERE learner_id=$1`, [p.lid]);
      const u = r.rows[0]; if (!u || !u.active || u.token_version !== p.tv) return res.status(401).json({ error: 'signin' });
      const l = await learnerDoc(u.learner_id); if (!l || (l.status && l.status !== 'Active')) return res.status(401).json({ error: 'signin' });
      req.learner = { id: u.learner_id, email: u.email, name: l.name, cohort: l.cohort || '', programme: l.programme || '' }; next();
    } catch (e) { return res.status(401).json({ error: 'signin' }); }
  }
  const issue = (res, u) => res.cookie(LCOOKIE, jwt.sign({ typ: 'learner', lid: u.learner_id, tv: u.token_version }, getSecret(), { expiresIn: '12h' }), cookieOpts());

  // ---------- staff side ----------
  app.get('/api/portal/:lid', auth, notPending, needRole('manager', 'admin'), async (req, res) => {
    const r = await pool.query(`SELECT email, active, pass_hash IS NOT NULL AS has_password, invite_expires, last_login FROM learner_logins WHERE learner_id=$1`, [req.params.lid]);
    const a = await pool.query(`SELECT id, mock, score, total, pct, by_section, started_at, finished_at FROM exam_attempts WHERE learner_id=$1 AND finished_at IS NOT NULL ORDER BY finished_at DESC LIMIT 50`, [req.params.lid]);
    res.json({ access: r.rows[0] || null, attempts: a.rows, sections: BANK.sections });
  });
  app.post('/api/portal/:lid/invite', auth, notPending, needRole('manager'), async (req, res) => {
    const l = await learnerDoc(req.params.lid); if (!l) return res.status(404).json({ error: 'Learner not found.' });
    const email = String(l.email || '').trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(email)) return res.status(400).json({ error: "Add a valid email address to this learner's details first. It becomes their username." });
    if ((l.status || 'Active') !== 'Active') return res.status(400).json({ error: 'Only active learners can have portal access.' });
    const clash = await pool.query(`SELECT learner_id FROM learner_logins WHERE email=$1 AND learner_id<>$2`, [email, req.params.lid]);
    if (clash.rows.length) return res.status(400).json({ error: 'Another learner already uses this email for the portal. Give each learner their own email.' });
    const token = crypto.randomBytes(24).toString('hex');
    await pool.query(`INSERT INTO learner_logins (learner_id, email, invite_hash, invite_expires) VALUES ($1,$2,$3, now() + interval '14 days')
      ON CONFLICT (learner_id) DO UPDATE SET email=$2, invite_hash=$3, invite_expires=now() + interval '14 days', active=true`, [req.params.lid, email, sha(token)]);
    await log(req.user, 'created learner portal invite', 'learners', req.params.lid, l.name);
    res.json({ url: `https://${req.get('host')}/learn/?invite=${token}`, email });
  });
  app.post('/api/portal/:lid/disable', auth, notPending, needRole('manager'), async (req, res) => {
    await pool.query(`UPDATE learner_logins SET active=false, invite_hash=NULL, token_version=token_version+1 WHERE learner_id=$1`, [req.params.lid]);
    await log(req.user, 'turned off learner portal access', 'learners', req.params.lid); res.json({ ok: true });
  });
  app.get('/api/portal-attempt/:id', auth, notPending, needRole('manager', 'admin'), async (req, res) => {
    const r = await pool.query(`SELECT * FROM exam_attempts WHERE id=$1 AND finished_at IS NOT NULL`, [req.params.id]); const a = r.rows[0];
    if (!a) return res.status(404).json({ error: 'not found' }); res.json({ review: review(a) });
  });

  // ---------- learner side ----------
  app.get('/api/learn/invite/:token', async (req, res) => {
    const r = await pool.query(`SELECT learner_id, email FROM learner_logins WHERE invite_hash=$1 AND invite_expires > now() AND active`, [sha(req.params.token)]);
    if (!r.rows[0]) return res.status(404).json({ error: 'This invite link has expired or was already used. Ask FC Training Academy for a new one.' });
    const l = await learnerDoc(r.rows[0].learner_id); res.json({ email: r.rows[0].email, name: l ? l.name : '' });
  });
  app.post('/api/learn/invite/:token', express.json(), async (req, res) => {
    const pw = req.body.password;
    if (!pwOk(pw)) return res.status(400).json({ error: 'Use at least 10 characters with letters and numbers.' });
    const r = await pool.query(`UPDATE learner_logins SET pass_hash=$1, invite_hash=NULL, invite_expires=NULL, token_version=token_version+1, last_login=now()
      WHERE invite_hash=$2 AND invite_expires > now() AND active RETURNING *`, [await bcrypt.hash(pw, 12), sha(req.params.token)]);
    if (!r.rows[0]) return res.status(404).json({ error: 'This invite link has expired or was already used.' });
    issue(res, r.rows[0]); res.json({ ok: true });
  });
  app.post('/api/learn/login', express.json(), async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase(); const key = 'L|' + req.ip + '|' + email;
    if (throttled(key)) return res.status(429).json({ error: 'Too many attempts. Wait 15 minutes and try again.' });
    const r = await pool.query(`SELECT * FROM learner_logins WHERE email=$1`, [email]); const u = r.rows[0];
    const ok = u && u.active && u.pass_hash && await bcrypt.compare(String(req.body.password || ''), u.pass_hash);
    const l = ok ? await learnerDoc(u.learner_id) : null;
    if (!ok || !l || (l.status && l.status !== 'Active')) { attempts.get(key).push(Date.now()); return res.status(401).json({ error: 'Email or password is not right.' }); }
    attempts.delete(key); await pool.query(`UPDATE learner_logins SET last_login=now() WHERE learner_id=$1`, [u.learner_id]);
    issue(res, u); res.json({ ok: true });
  });
  app.post('/api/learn/logout', (req, res) => { res.clearCookie(LCOOKIE, { path: '/' }); res.json({ ok: true }); });
  app.post('/api/learn/password', lauth, express.json(), async (req, res) => {
    const r = await pool.query(`SELECT pass_hash FROM learner_logins WHERE learner_id=$1`, [req.learner.id]);
    if (!await bcrypt.compare(String(req.body.current || ''), r.rows[0].pass_hash)) return res.status(400).json({ error: 'Your current password is not right.' });
    if (!pwOk(req.body.password)) return res.status(400).json({ error: 'Use at least 10 characters with letters and numbers.' });
    const u = await pool.query(`UPDATE learner_logins SET pass_hash=$1, token_version=token_version+1 WHERE learner_id=$2 RETURNING *`, [await bcrypt.hash(req.body.password, 12), req.learner.id]);
    issue(res, u.rows[0]); res.json({ ok: true });
  });
  app.get('/api/learn/me', lauth, async (req, res) => {
    const a = await pool.query(`SELECT id, mock, score, total, pct, finished_at FROM exam_attempts WHERE learner_id=$1 AND finished_at IS NOT NULL ORDER BY finished_at DESC LIMIT 30`, [req.learner.id]);
    const open = await pool.query(`SELECT id, mock, due_at FROM exam_attempts WHERE learner_id=$1 AND finished_at IS NULL AND due_at > now() ORDER BY started_at DESC LIMIT 1`, [req.learner.id]);
    res.json({ learner: { name: req.learner.name, cohort: req.learner.cohort, email: req.learner.email, preview: !!req.learner.preview },
      mocks: Object.keys(BANK.mocks).map(k => ({ id: k, count: BANK.mocks[k].length, minutes: MINUTES })), attempts: a.rows, open: open.rows[0] || null });
  });
  app.get('/api/learn/resources', lauth, async (req, res) => {
    const r = await pool.query(`SELECT data FROM docs WHERE col='config' AND id='learner-resources'`);
    const items = ((r.rows[0] && r.rows[0].data.items) || []).filter(x => x && x.title && (resFile(x) || /^https:\/\//i.test(String(x.url || ''))));
    res.json({ items: items.map(x => { const f = resFile(x);
      return { title: String(x.title), url: f ? '/api/learn/file/' + f.id : String(x.url), file: f ? { name: String(f.name || ''), type: String(f.type || '') } : null, note: String(x.note || ''), group: String(x.group || '') }; }) });
  });
  // Files attached to learner resources. Only files listed in the resources config can be opened.
  function resFile(x) { const f = x && x.file; return f && /^[0-9a-f]{32}$/.test(String(f.id || '')) ? f : null; }
  // Resource files open in a new tab, which can't send the X-Preview header, so staff signed in to the LMS can open them directly.
  const fileAuth = async (req, res, next) => { const pv = await staffPreview(req, true); if (pv) { req.learner = pv; return next(); }
    // Opened as a page (not by script) and not signed in: send them to the portal sign-in instead of showing an error.
    if (req.accepts(['html', 'json']) === 'html') { const j = res.json.bind(res); res.json = b => (res.statusCode === 401 ? (res.status(302), res.redirect('/learn/')) : j(b)); }
    return lauth(req, res, next); };
  app.get('/api/learn/file/:id', fileAuth, async (req, res) => {
    const id = String(req.params.id || ''); if (!/^[0-9a-f]{32}$/.test(id)) return res.status(404).send('Not found');
    const c = await pool.query(`SELECT data FROM docs WHERE col='config' AND id='learner-resources'`);
    const listed = ((c.rows[0] && c.rows[0].data.items) || []).some(x => { const f = resFile(x); return f && f.id === id; });
    if (!listed) return res.status(404).send('Not found');
    const r = await pool.query(`SELECT name, type, data, restricted FROM files WHERE id=$1`, [id]);
    const f = r.rows[0]; if (!f || f.restricted) return res.status(404).send('Not found');
    const inline = ['application/pdf', 'image/png', 'image/jpeg', 'image/webp', 'image/gif', 'text/plain', 'text/html'].includes(f.type);
    if (f.type === 'text/html') res.set({ 'Content-Security-Policy': HTML_CSP, 'Content-Type': 'text/html; charset=utf-8' });
    res.set({ 'Content-Type': f.type, 'Content-Disposition': `${inline ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(f.name || id)}`,
      'Cache-Control': 'private, max-age=600', 'X-Content-Type-Options': 'nosniff' });
    res.send(f.data);
  });
  const paperFor = a => a.paper.map(p => { const q = BANK.mocks[a.mock][p.q]; return { s: q.s, sec: BANK.sections[q.s], q: q.q, opts: p.o.map(i => q.o[i]) }; });
  app.post('/api/learn/start/:mock', lauth, async (req, res) => {
    const qs = BANK.mocks[req.params.mock]; if (!qs) return res.status(404).json({ error: 'No such mock.' });
    await pool.query(`UPDATE exam_attempts SET finished_at=now() WHERE learner_id=$1 AND finished_at IS NULL AND due_at <= now()`, [req.learner.id]);
    const paper = shuffle(qs.map((_, i) => i)).map(q => ({ q, o: shuffle([0, 1, 2, 3]) }));
    const r = await pool.query(`INSERT INTO exam_attempts (learner_id, mock, paper, answers, due_at) VALUES ($1,$2,$3,$4, now() + ($5 || ' minutes')::interval) RETURNING *`,
      [req.learner.id, req.params.mock, JSON.stringify(paper), JSON.stringify(Array(paper.length).fill(null)), String(MINUTES + 1)]);
    const a = r.rows[0]; res.json({ id: a.id, mock: a.mock, due: a.due_at, questions: paperFor(a), answers: a.answers });
  });
  app.get('/api/learn/attempt/:id', lauth, async (req, res) => {
    const r = await pool.query(`SELECT * FROM exam_attempts WHERE id=$1 AND learner_id=$2`, [req.params.id, req.learner.id]); const a = r.rows[0];
    if (!a) return res.status(404).json({ error: 'not found' });
    if (a.finished_at) return res.json({ id: a.id, mock: a.mock, finished: true, review: review(a) });
    res.json({ id: a.id, mock: a.mock, due: a.due_at, questions: paperFor(a), answers: a.answers });
  });
  app.put('/api/learn/attempt/:id/answers', lauth, express.json(), async (req, res) => {
    const ans = Array.isArray(req.body.answers) ? req.body.answers.map(x => (x === 0 || x === 1 || x === 2 || x === 3) ? x : null) : null;
    if (!ans) return res.status(400).json({ error: 'bad answers' });
    await pool.query(`UPDATE exam_attempts SET answers=$1 WHERE id=$2 AND learner_id=$3 AND finished_at IS NULL AND due_at > now() AND jsonb_array_length(paper)=$4`,
      [JSON.stringify(ans), req.params.id, req.learner.id, ans.length]);
    res.json({ ok: true });
  });
  app.post('/api/learn/attempt/:id/finish', lauth, express.json(), async (req, res) => {
    const r = await pool.query(`SELECT * FROM exam_attempts WHERE id=$1 AND learner_id=$2`, [req.params.id, req.learner.id]); let a = r.rows[0];
    if (!a) return res.status(404).json({ error: 'not found' });
    if (!a.finished_at) {
      let ans = a.answers;
      if (Array.isArray(req.body.answers) && req.body.answers.length === a.paper.length && new Date(a.due_at) > new Date())
        ans = req.body.answers.map(x => (x === 0 || x === 1 || x === 2 || x === 3) ? x : null);
      const by = {}; let score = 0;
      a.paper.forEach((p, i) => { const s = BANK.mocks[a.mock][p.q].s; const b = by[s] = by[s] || { r: 0, t: 0 }; b.t++; if (ans[i] != null && p.o[ans[i]] === 0) { b.r++; score++; } });
      const u = await pool.query(`UPDATE exam_attempts SET answers=$1, score=$2, total=$3, pct=$4, by_section=$5, finished_at=now() WHERE id=$6 RETURNING *`,
        [JSON.stringify(ans), score, a.paper.length, Math.round(score / a.paper.length * 100), JSON.stringify(by), a.id]);
      a = u.rows[0];
    }
    res.json({ id: a.id, mock: a.mock, finished: true, review: review(a) });
  });
  function review(a) {
    return { mock: a.mock, score: a.score, total: a.total, pct: a.pct, by_section: a.by_section, sections: BANK.sections, finished_at: a.finished_at,
      items: a.paper.map((p, i) => { const q = BANK.mocks[a.mock][p.q]; const opts = p.o.map(j => q.o[j]); const correct = p.o.indexOf(0);
        return { s: q.s, q: q.q, opts, correct, given: a.answers ? a.answers[i] : null, e: q.e, r: q.r }; }) };
  }

  return { migrate };
};
