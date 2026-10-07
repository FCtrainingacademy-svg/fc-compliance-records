// FC Training Academy – Compliance & Learner Records (online, multi-user)
'use strict';
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const archiver = require('archiver');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const PORT = process.env.PORT || 10000;
let SECRET = process.env.SESSION_SECRET || '';
let SETUP_CODE = process.env.SETUP_CODE || '';
if (!process.env.DATABASE_URL) { console.error('DATABASE_URL is not set. In Render: Environment > add DATABASE_URL = the Internal Database URL of fc-compliance-db.'); process.exit(1); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSL === 'off' ? false : { rejectUnauthorized: false } });

// Manager: changes everything directly, manages users, approves Admin requests.
// Admin: views everything; every change is sent to the Manager for approval.
const ROLES = ['manager', 'admin'];
const COLLECTIONS = new Set(['staff', 'items', 'documents', 'learners', 'otj', 'attendance', 'audit', 'config', 'exams', 'ecordia']);
// Collections only the Manager can see or change (exam papers, model answers).
const MANAGER_ONLY = new Set(['exams']);
const isMgr = u => u && u.role === 'manager';
const MAX_FILE = 20 * 1024 * 1024;
const OFFICE_TYPES = ['application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation'];
const FILE_TYPES = new Set(['application/pdf', 'image/png', 'image/jpeg', 'image/webp', 'image/gif', 'text/plain', 'text/csv', 'text/markdown', 'application/json', ...OFFICE_TYPES]);

async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL,
      pass_hash TEXT NOT NULL, active BOOLEAN NOT NULL DEFAULT TRUE, must_change BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_login TIMESTAMPTZ, token_version INT NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS docs (col TEXT NOT NULL, id TEXT NOT NULL, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_by TEXT, PRIMARY KEY (col, id));
    CREATE TABLE IF NOT EXISTS files (id TEXT PRIMARY KEY, name TEXT, type TEXT NOT NULL, size INT NOT NULL, data BYTEA NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(), created_by TEXT);
    CREATE TABLE IF NOT EXISTS activity (id BIGSERIAL PRIMARY KEY, at TIMESTAMPTZ NOT NULL DEFAULT now(), user_email TEXT, user_name TEXT,
      action TEXT NOT NULL, col TEXT, doc_id TEXT, detail TEXT);
    CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS changes (id BIGSERIAL PRIMARY KEY, at TIMESTAMPTZ NOT NULL DEFAULT now(), by_email TEXT, by_name TEXT,
      method TEXT NOT NULL, col TEXT NOT NULL, doc_id TEXT NOT NULL, body JSONB, before JSONB, status TEXT NOT NULL DEFAULT 'pending',
      decided_by TEXT, decided_at TIMESTAMPTZ, note TEXT);
    ALTER TABLE files ADD COLUMN IF NOT EXISTS restricted BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS cal_token TEXT;
    UPDATE users SET role='manager' WHERE role NOT IN ('manager','admin');
    INSERT INTO meta (k, v) VALUES ('rev', '1') ON CONFLICT (k) DO NOTHING;
  `);
  // Secrets: use env vars if given, otherwise generate once and keep them in the database.
  if (!SECRET || SECRET.length < 32) {
    await pool.query(`INSERT INTO meta (k, v) VALUES ('session_secret', $1) ON CONFLICT (k) DO NOTHING`, [crypto.randomBytes(48).toString('hex')]);
    SECRET = (await pool.query(`SELECT v FROM meta WHERE k='session_secret'`)).rows[0].v;
  }
  const users = (await pool.query(`SELECT count(*)::int n FROM users`)).rows[0].n;
  if (!SETUP_CODE && users === 0) {
    await pool.query(`INSERT INTO meta (k, v) VALUES ('setup_code', $1) ON CONFLICT (k) DO NOTHING`, [crypto.randomBytes(5).toString('hex').toUpperCase()]);
    SETUP_CODE = (await pool.query(`SELECT v FROM meta WHERE k='setup_code'`)).rows[0].v;
    console.log('=== FIRST-TIME SETUP CODE: ' + SETUP_CODE + ' (enter it on the website to create the Manager account) ===');
  }
}
async function bumpRev(c) { const r = await (c || pool).query(`UPDATE meta SET v = (v::bigint + 1)::text WHERE k='rev' RETURNING v`); return Number(r.rows[0].v); }
async function getRev() { const r = await pool.query(`SELECT v FROM meta WHERE k='rev'`); return Number(r.rows[0].v); }
async function log(u, action, col, docId, detail) {
  try { await pool.query(`INSERT INTO activity (user_email, user_name, action, col, doc_id, detail) VALUES ($1,$2,$3,$4,$5,$6)`,
    [u && u.email, u && u.name, action, col || null, docId || null, detail ? String(detail).slice(0, 300) : null]); } catch (e) { console.warn('log', e.message); }
}
function titleOf(d) { return d && (d.title || d.name || d.item) ? String(d.title || d.name || d.item) : null; }

function merge(t, p) {
  for (const k of Object.keys(p)) {
    const v = p[k];
    if (v && typeof v === 'object' && !Array.isArray(v) && v.__delete__) { delete t[k]; continue; }
    if (v && typeof v === 'object' && !Array.isArray(v) && t[k] && typeof t[k] === 'object' && !Array.isArray(t[k])) merge(t[k], v);
    else t[k] = v;
  }
  return t;
}

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(compression());
app.use(cookieParser());
app.use((req, res, next) => {
  res.set({ 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin',
    'Strict-Transport-Security': 'max-age=31536000' });
  next();
});

// ---------- auth ----------
const COOKIE = 'clr_session';
const cookieOpts = () => ({ httpOnly: true, sameSite: 'lax', secure: process.env.COOKIE_INSECURE !== '1', maxAge: 12 * 3600 * 1000, path: '/' });
function issue(res, u) { res.cookie(COOKIE, jwt.sign({ uid: u.id, tv: u.token_version }, SECRET, { expiresIn: '12h' }), cookieOpts()); }
async function auth(req, res, next) {
  try {
    const t = req.cookies[COOKIE]; if (!t) return res.status(401).json({ error: 'signin' });
    const p = jwt.verify(t, SECRET);
    const r = await pool.query(`SELECT id, email, name, role, active, must_change, token_version FROM users WHERE id=$1`, [p.uid]);
    const u = r.rows[0];
    if (!u || !u.active || u.token_version !== p.tv) return res.status(401).json({ error: 'signin' });
    req.user = u; next();
  } catch (e) { return res.status(401).json({ error: 'signin' }); }
}
function needRole(...roles) { return (req, res, next) => roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'forbidden' }); }
function notPending(req, res, next) { if (req.user.must_change) return res.status(403).json({ error: 'change_password' }); next(); }
function pwOk(p) { return typeof p === 'string' && p.length >= 10 && /[A-Za-z]/.test(p) && /[0-9]/.test(p); }

const attempts = new Map(); // simple login throttle per IP+email
function throttled(key) {
  const now = Date.now(); const a = (attempts.get(key) || []).filter(t => now - t < 15 * 60 * 1000);
  attempts.set(key, a); return a.length >= 8;
}

app.post('/api/login', express.json(), async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(); const key = req.ip + '|' + email;
  if (throttled(key)) return res.status(429).json({ error: 'Too many attempts. Wait 15 minutes and try again.' });
  const r = await pool.query(`SELECT * FROM users WHERE lower(email)=$1`, [email]); const u = r.rows[0];
  const ok = u && u.active && await bcrypt.compare(String(req.body.password || ''), u.pass_hash);
  if (!ok) { attempts.get(key).push(Date.now()); return res.status(401).json({ error: 'Email or password is not right.' }); }
  attempts.delete(key);
  await pool.query(`UPDATE users SET last_login=now() WHERE id=$1`, [u.id]);
  issue(res, u); await log(u, 'signed in');
  res.json({ user: { email: u.email, name: u.name, role: u.role, must_change: u.must_change } });
});
app.post('/api/logout', (req, res) => { res.clearCookie(COOKIE, { path: '/' }); res.json({ ok: true }); });

app.get('/api/setup', async (req, res) => { const r = await pool.query(`SELECT count(*)::int n FROM users`); res.json({ needed: r.rows[0].n === 0 }); });
app.post('/api/setup', express.json(), async (req, res) => {
  const r = await pool.query(`SELECT count(*)::int n FROM users`); if (r.rows[0].n > 0) return res.status(400).json({ error: 'Already set up.' });
  if (!SETUP_CODE || !crypto.timingSafeEqual(Buffer.from(String(req.body.code || '').padEnd(64)), Buffer.from(SETUP_CODE.padEnd(64))))
    return res.status(403).json({ error: 'Setup code is not right.' });
  const { email, name, password } = req.body;
  if (!email || !name || !pwOk(password)) return res.status(400).json({ error: 'Enter a name, email and a password of at least 10 characters with letters and numbers.' });
  const ins = await pool.query(`INSERT INTO users (email, name, role, pass_hash, must_change) VALUES ($1,$2,'manager',$3,false) RETURNING *`,
    [String(email).trim().toLowerCase(), String(name).trim(), await bcrypt.hash(password, 12)]);
  issue(res, ins.rows[0]); await log(ins.rows[0], 'created the first Manager account');
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => res.json({ user: { email: req.user.email, name: req.user.name, role: req.user.role, must_change: req.user.must_change } }));
app.post('/api/password', auth, express.json(), async (req, res) => {
  const r = await pool.query(`SELECT pass_hash FROM users WHERE id=$1`, [req.user.id]);
  if (!await bcrypt.compare(String(req.body.current || ''), r.rows[0].pass_hash)) return res.status(400).json({ error: 'Current password is not right.' });
  if (!pwOk(req.body.password)) return res.status(400).json({ error: 'Use at least 10 characters, with letters and numbers.' });
  const u = (await pool.query(`UPDATE users SET pass_hash=$1, must_change=false, token_version=token_version+1 WHERE id=$2 RETURNING *`,
    [await bcrypt.hash(req.body.password, 12), req.user.id])).rows[0];
  issue(res, u); await log(req.user, 'changed own password'); res.json({ ok: true });
});

// ---------- users (admin) ----------
app.get('/api/users', auth, notPending, needRole('manager'), async (req, res) => {
  const r = await pool.query(`SELECT id, email, name, role, active, must_change, created_at, last_login FROM users ORDER BY role, name`); res.json({ users: r.rows });
});
app.post('/api/users', auth, notPending, needRole('manager'), express.json(), async (req, res) => {
  const { email, name, role, password } = req.body;
  if (!email || !name || !ROLES.includes(role)) return res.status(400).json({ error: 'Enter a name, email and role.' });
  if (!pwOk(password)) return res.status(400).json({ error: 'Temporary password: at least 10 characters, with letters and numbers.' });
  try {
    const r = await pool.query(`INSERT INTO users (email, name, role, pass_hash, must_change) VALUES ($1,$2,$3,$4,true) RETURNING id`,
      [String(email).trim().toLowerCase(), String(name).trim(), role, await bcrypt.hash(password, 12)]);
    await log(req.user, 'added user', 'users', String(r.rows[0].id), `${name} (${role})`); res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.code === '23505' ? 'That email already has an account.' : 'Could not add the user.' }); }
});
app.patch('/api/users/:id', auth, notPending, needRole('manager'), express.json(), async (req, res) => {
  const id = Number(req.params.id); const b = req.body; const sets = []; const vals = []; let n = 1;
  if (b.role !== undefined) { if (!ROLES.includes(b.role)) return res.status(400).json({ error: 'Bad role' }); sets.push(`role=$${n++}`); vals.push(b.role); }
  if (b.name !== undefined) { sets.push(`name=$${n++}`); vals.push(String(b.name).trim()); }
  if (b.active !== undefined) { sets.push(`active=$${n++}`); vals.push(!!b.active); sets.push(`token_version=token_version+1`); }
  if (b.password !== undefined) { if (!pwOk(b.password)) return res.status(400).json({ error: 'Temporary password: at least 10 characters, with letters and numbers.' });
    sets.push(`pass_hash=$${n++}`); vals.push(await bcrypt.hash(b.password, 12)); sets.push(`must_change=true`, `token_version=token_version+1`); }
  if (id === req.user.id && (b.active === false || (b.role && b.role !== 'manager'))) return res.status(400).json({ error: "You can't remove your own Manager access." });
  if (!sets.length) return res.json({ ok: true });
  vals.push(id); const r = await pool.query(`UPDATE users SET ${sets.join(', ')} WHERE id=$${n} RETURNING name`, vals);
  if (!r.rows[0]) return res.status(404).json({ error: 'Not found' });
  await log(req.user, b.password ? 'reset password for' : 'updated user', 'users', String(id), r.rows[0].name); res.json({ ok: true });
});

// ---------- records ----------
app.get('/api/rev', auth, async (req, res) => {
  const p = await pool.query(`SELECT count(*)::int n FROM changes WHERE status='pending'`);
  res.json({ rev: await getRev(), pendingApprovals: p.rows[0].n });
});
app.get('/api/data', auth, notPending, async (req, res) => {
  const rev = await getRev(); const r = await pool.query(`SELECT col, id, data FROM docs`);
  const collections = {}; for (const row of r.rows) { if (MANAGER_ONLY.has(row.col) && !isMgr(req.user)) continue; (collections[row.col] = collections[row.col] || {})[row.id] = row.data; }
  res.json({ rev, collections });
});
function checkPath(req, res) {
  const col = req.params.col; if (!COLLECTIONS.has(col) || !/^[A-Za-z0-9_.:@+~-]{1,200}$/.test(req.params.id)) { res.status(400).json({ error: 'bad path' }); return null; }
  return col;
}
// Apply a change to the records (used for Manager edits and for approved Admin requests).
async function applyChange(method, col, id, body, byEmail) {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    if (method === 'DELETE') {
      await c.query(`DELETE FROM docs WHERE col=$1 AND id=$2`, [col, id]);
    } else {
      let data = body;
      if (method === 'PATCH') {
        const r = await c.query(`SELECT data FROM docs WHERE col=$1 AND id=$2 FOR UPDATE`, [col, id]);
        data = merge(r.rows[0] ? r.rows[0].data : {}, body);
      }
      await c.query(`INSERT INTO docs (col, id, data, updated_at, updated_by) VALUES ($1,$2,$3,now(),$4)
        ON CONFLICT (col, id) DO UPDATE SET data=EXCLUDED.data, updated_at=now(), updated_by=EXCLUDED.updated_by`, [col, id, data, byEmail]);
    }
    const rev = await bumpRev(c); await c.query('COMMIT'); return rev;
  } catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; } finally { c.release(); }
}
async function handleWrite(req, res, method) {
  const col = checkPath(req, res); if (!col) return;
  if (MANAGER_ONLY.has(col) && !isMgr(req.user)) return res.status(403).json({ error: 'Only the Manager can change this.' });
  const id = req.params.id; const body = method === 'DELETE' ? null : req.body;
  const prev = await pool.query(`SELECT data FROM docs WHERE col=$1 AND id=$2`, [col, id]);
  const before = prev.rows[0] ? prev.rows[0].data : null;
  const title = titleOf(body) || titleOf(before);
  if (req.user.role === 'admin') {
    const r = await pool.query(`INSERT INTO changes (by_email, by_name, method, col, doc_id, body, before) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
      [req.user.email, req.user.name, method, col, id, body, before]);
    const rev = await bumpRev(); await log(req.user, 'sent for approval: ' + (method === 'DELETE' ? 'delete' : before ? 'update' : 'add'), col, id, title);
    return res.json({ pending: true, change: r.rows[0].id, rev });
  }
  try {
    const rev = await applyChange(method, col, id, body, req.user.email);
    await log(req.user, method === 'DELETE' ? 'deleted' : before ? 'updated' : 'added', col, id, title); res.json({ rev });
  } catch (e) { res.status(500).json({ error: 'save failed' }); }
}
app.put('/api/doc/:col/:id', auth, notPending, express.json({ limit: '2mb' }), (req, res) => handleWrite(req, res, 'PUT'));
app.patch('/api/doc/:col/:id', auth, notPending, express.json({ limit: '2mb' }), (req, res) => handleWrite(req, res, 'PATCH'));
app.delete('/api/doc/:col/:id', auth, notPending, (req, res) => handleWrite(req, res, 'DELETE'));

// ---------- approvals ----------
app.get('/api/changes', auth, notPending, async (req, res) => {
  const status = ['pending', 'approved', 'rejected'].includes(req.query.status) ? req.query.status : null;
  const r = await pool.query(`SELECT c.*, (SELECT data FROM docs d WHERE d.col=c.col AND d.id=c.doc_id) AS current FROM changes c
    ${status ? 'WHERE status=$1' : ''} ORDER BY (status='pending') DESC, id DESC LIMIT 200`, status ? [status] : []);
  res.json({ changes: r.rows });
});
app.post('/api/changes/:id/approve', auth, notPending, needRole('manager'), express.json(), async (req, res) => {
  const r = await pool.query(`UPDATE changes SET status='approved', decided_by=$1, decided_at=now(), note=$2 WHERE id=$3 AND status='pending' RETURNING *`,
    [req.user.name, req.body && req.body.note ? String(req.body.note).slice(0, 500) : null, req.params.id]);
  const ch = r.rows[0]; if (!ch) return res.status(409).json({ error: 'This request has already been dealt with.' });
  try { await applyChange(ch.method, ch.col, ch.doc_id, ch.body, ch.by_email); }
  catch (e) { await pool.query(`UPDATE changes SET status='pending', decided_by=NULL, decided_at=NULL WHERE id=$1`, [ch.id]); return res.status(500).json({ error: 'Could not apply the change.' }); }
  await log(req.user, `approved ${ch.by_name}'s change`, ch.col, ch.doc_id, titleOf(ch.body) || titleOf(ch.before)); res.json({ ok: true, rev: await getRev() });
});
app.post('/api/changes/:id/reject', auth, notPending, needRole('manager'), express.json(), async (req, res) => {
  const r = await pool.query(`UPDATE changes SET status='rejected', decided_by=$1, decided_at=now(), note=$2 WHERE id=$3 AND status='pending' RETURNING *`,
    [req.user.name, req.body && req.body.note ? String(req.body.note).slice(0, 500) : null, req.params.id]);
  const ch = r.rows[0]; if (!ch) return res.status(409).json({ error: 'This request has already been dealt with.' });
  const rev = await bumpRev(); await log(req.user, `rejected ${ch.by_name}'s change`, ch.col, ch.doc_id, titleOf(ch.body) || titleOf(ch.before)); res.json({ ok: true, rev });
});
app.post('/api/changes/:id/withdraw', auth, notPending, async (req, res) => {
  const r = await pool.query(`UPDATE changes SET status='rejected', decided_by=$1, decided_at=now(), note='Withdrawn by requester' WHERE id=$2 AND status='pending' AND by_email=$3 RETURNING id`,
    [req.user.name, req.params.id, req.user.email]);
  if (!r.rowCount) return res.status(409).json({ error: 'Not found' }); await bumpRev(); res.json({ ok: true });
});

// ---------- files ----------
app.post('/api/files', auth, notPending, express.raw({ type: () => true, limit: MAX_FILE }), async (req, res) => {
  const type = String(req.get('x-file-type') || '').split(';')[0].trim();
  if (!FILE_TYPES.has(type)) return res.status(400).json({ error: 'unsupported_type' });
  if (!req.body || !req.body.length) return res.status(400).json({ error: 'empty' });
  const id = String(req.get('x-file-id') || '');
  const fid = /^[0-9a-f]{32}$/.test(id) && (req.user.role === 'manager') ? id : crypto.randomBytes(16).toString('hex');
  const name = decodeURIComponent(String(req.get('x-file-name') || '')).slice(0, 200);
  const restricted = isMgr(req.user) && req.get('x-restricted') === '1';
  await pool.query(`INSERT INTO files (id, name, type, size, data, created_by, restricted) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (id) DO NOTHING`,
    [fid, name, type, req.body.length, req.body, req.user.email, restricted]);
  await log(req.user, 'uploaded file', restricted ? 'exams' : 'files', fid, name);
  res.json({ id: fid, url: '/_blob/' + fid, sizeBytes: req.body.length, contentType: type });
});
app.delete('/api/files/:id', auth, notPending, needRole('manager'), async (req, res) => {
  const r = await pool.query(`DELETE FROM files WHERE id=$1 RETURNING name`, [req.params.id]);
  if (r.rowCount) await log(req.user, 'deleted file', 'files', req.params.id, r.rows[0].name);
  res.json({ deleted: !!r.rowCount });
});
app.get('/_blob/:id', auth, async (req, res) => {
  const r = await pool.query(`SELECT name, type, data, restricted FROM files WHERE id=$1`, [req.params.id]);
  if (!r.rows[0] || (r.rows[0].restricted && !isMgr(req.user))) return res.status(404).send('Not found');
  const f = r.rows[0]; const inline = !OFFICE_TYPES.includes(f.type);
  res.set({ 'Content-Type': f.type, 'Content-Disposition': `${inline ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(f.name || req.params.id)}`, 'Cache-Control': 'private, max-age=3600' });
  res.send(f.data);
});

// ---------- activity ----------
app.get('/api/activity', auth, notPending, needRole('manager', 'admin'), async (req, res) => {
  const r = await pool.query(`SELECT at, user_name, user_email, action, col, doc_id, detail FROM activity ${isMgr(req.user) ? '' : "WHERE col IS DISTINCT FROM 'exams'"} ORDER BY id DESC LIMIT 300`); res.json({ activity: r.rows });
});

// ---------- export (offline copy) and import ----------
app.get('/api/export.zip', auth, notPending, needRole('manager', 'admin'), async (req, res) => {
  // Exam papers stay online only (the offline app has no Exams tab).
  const docs = await pool.query(`SELECT col, id, data FROM docs WHERE col <> ALL($1)`, [[...MANAGER_ONLY]]);
  const files = await pool.query(`SELECT id, type FROM files WHERE NOT restricted`);
  const ext = { 'application/msword': 'doc', 'application/vnd.ms-excel': 'xls', 'application/vnd.ms-powerpoint': 'ppt', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx', 'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'pptx', 'application/pdf': 'pdf', 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp', 'image/gif': 'gif', 'text/plain': 'txt', 'text/csv': 'csv', 'text/markdown': 'md', 'application/json': 'json' };
  const collections = {}; for (const row of docs.rows) (collections[row.col] = collections[row.col] || {})[row.id] = row.data;
  const fmap = {}; for (const f of files.rows) fmap[f.id] = { path: `files/${f.id}.${ext[f.type] || 'bin'}`, type: f.type };
  const day = new Date().toISOString().slice(0, 10);
  const data = { app: 'FC Compliance Offline', exportedFrom: 'online', exportedAt: new Date().toISOString(), collections, files: fmap };
  res.set({ 'Content-Type': 'application/zip', 'Content-Disposition': `attachment; filename="FC Compliance Offline ${day}.zip"` });
  const z = archiver('zip', { zlib: { level: 6 } }); z.pipe(res);
  const R = 'FC Compliance Offline/';
  z.append(JSON.stringify(data, null, 1), { name: R + 'data/data.json' });
  z.append(fs.readFileSync(path.join(__dirname, 'offline', 'FC Compliance.html')), { name: R + 'FC Compliance.html' });
  z.append(fs.readFileSync(path.join(__dirname, 'offline', 'READ ME FIRST.txt')), { name: R + 'READ ME FIRST.txt' });
  z.append(fs.readFileSync(path.join(__dirname, 'public', 'lcl-approved-centre.png')), { name: R + 'lcl-approved-centre.png' });
  for (const f of files.rows) {
    const b = await pool.query(`SELECT data FROM files WHERE id=$1`, [f.id]);
    z.append(b.rows[0].data, { name: R + fmap[f.id].path });
  }
  await log(req.user, 'downloaded an offline copy');
  z.finalize();
});
app.post('/api/import', auth, notPending, needRole('manager'), express.json({ limit: '20mb' }), async (req, res) => {
  const cols = req.body && req.body.collections; if (!cols || typeof cols !== 'object') return res.status(400).json({ error: 'No records in that file.' });
  const c = await pool.connect(); let n = 0;
  try {
    await c.query('BEGIN');
    for (const [col, docs] of Object.entries(cols)) {
      if (!COLLECTIONS.has(col)) continue;
      for (const [id, data] of Object.entries(docs || {})) {
        await c.query(`INSERT INTO docs (col, id, data, updated_at, updated_by) VALUES ($1,$2,$3,now(),$4)
          ON CONFLICT (col, id) DO UPDATE SET data=EXCLUDED.data, updated_at=now(), updated_by=EXCLUDED.updated_by`, [col, id, data, req.user.email]); n++;
      }
    }
    await bumpRev(c); await c.query('COMMIT');
  } catch (e) { await c.query('ROLLBACK').catch(() => {}); return res.status(500).json({ error: 'Import failed.' }); } finally { c.release(); }
  await log(req.user, 'imported records', null, null, `${n} records`); res.json({ ok: true, records: n });
});
app.get('/api/files/missing', auth, notPending, needRole('manager'), async (req, res) => {
  const ids = String(req.query.ids || '').split(',').filter(x => /^[0-9a-f]{32}$/.test(x));
  if (!ids.length) return res.json({ missing: [] });
  const r = await pool.query(`SELECT id FROM files WHERE id = ANY($1)`, [ids]); const have = new Set(r.rows.map(x => x.id));
  res.json({ missing: ids.filter(x => !have.has(x)) });
});

// ---------- floor plan (signed-in users only) ----------
const FLOOR = { 'floor-plan.pdf': 'application/pdf', 'fp-1.png': 'image/png', 'fp-2.png': 'image/png' };
app.get('/private/:f', auth, (req, res) => {
  const t = FLOOR[req.params.f]; if (!t) return res.status(404).send('Not found');
  res.set({ 'Content-Type': t, 'Cache-Control': 'private, max-age=3600' });
  if (req.params.f.endsWith('.pdf')) res.set('Content-Disposition', 'inline; filename="FC Training Academy - Floor Plan v1.pdf"');
  res.sendFile(path.join(__dirname, 'private', req.params.f));
});

// ---------- calendar feed (Manager subscribes once in Outlook / Google; it refreshes itself) ----------
function addMonthsISO(iso, n) {
  if (!iso || !n) return ''; const [y, m, d] = iso.split('-').map(Number); const dt = new Date(Date.UTC(y, m - 1 + Number(n), 1));
  const last = new Date(Date.UTC(dt.getUTCFullYear(), dt.getUTCMonth() + 1, 0)).getUTCDate(); dt.setUTCDate(Math.min(d, last)); return dt.toISOString().slice(0, 10);
}
function addDaysISO(iso, n) { const [y, m, d] = iso.split('-').map(Number); return new Date(Date.UTC(y, m - 1, d) + n * 864e5).toISOString().slice(0, 10); }
const isISO = v => typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v);
function icsEsc(v) { return String(v || '').replace(/\\/g, '\\\\').replace(/[,;]/g, m => '\\' + m).replace(/\r?\n/g, '\\n'); }
function icsFold(line) { const out = []; while (line.length > 74) { out.push(line.slice(0, 74)); line = ' ' + line.slice(74); } out.push(line); return out.join('\r\n'); }
async function buildFeed() {
  const r = await pool.query(`SELECT col, id, data FROM docs WHERE col IN ('staff','items','learners')`);
  const staff = {}, items = [], learners = [];
  for (const row of r.rows) { if (row.col === 'staff') staff[row.id] = row.data; else if (row.col === 'items') items.push({ id: row.id, ...row.data }); else learners.push({ id: row.id, ...row.data }); }
  const today = new Date().toISOString().slice(0, 10);
  const stamp = new Date().toISOString().replace(/[-:]/g, '').slice(0, 15) + 'Z';
  const L = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//FC Training Academy//Compliance//EN', 'CALSCALE:GREGORIAN', 'METHOD:PUBLISH',
    'X-WR-CALNAME:FC Training compliance', 'X-WR-TIMEZONE:Europe/London', 'REFRESH-INTERVAL;VALUE=DURATION:PT1H', 'X-PUBLISHED-TTL:PT1H'];
  const ev = (uid, date, summary, desc) => {
    if (!isISO(date)) return;
    L.push('BEGIN:VEVENT', 'UID:' + uid + '@fc-compliance', 'DTSTAMP:' + stamp, 'DTSTART;VALUE=DATE:' + date.replace(/-/g, ''),
      'DTEND;VALUE=DATE:' + addDaysISO(date, 1).replace(/-/g, ''), 'SUMMARY:' + icsEsc(summary), 'DESCRIPTION:' + icsEsc(desc), 'TRANSP:TRANSPARENT', 'END:VEVENT');
  };
  for (const it of items) {
    if (!it.staffId || it.oneOff) continue; // centre checks are no longer tracked in the app
    const s = staff[it.staffId]; if (!s || s.active === false) continue;
    const due = it.due || addMonthsISO(it.issued, it.cycleMonths); if (!isISO(due)) continue;
    const rd = Number(it.remindDays) || 60;
    ev(it.id + '-due', due, `DUE: ${it.title} (${s.name})`, `${it.category || ''} expires/due ${due}. Mark it renewed in FC Compliance & Learner Records.`);
    const rem = addDaysISO(due, -rd); if (rem >= today) ev(it.id + '-rem', rem, `Renew soon: ${it.title} (${s.name})`, `Due ${due} (${rd} days' notice).`);
  }
  for (const l of learners) {
    if ((l.status || 'Active') !== 'Active') continue;
    ev(l.id + '-rev', l.nextReview, `Progress review: ${l.name}`, l.programme || '');
    ev(l.id + '-gw', l.gateway, `EPA gateway: ${l.name}`, l.programme || '');
    ev(l.id + '-end', l.plannedEnd, `Planned end: ${l.name}`, l.programme || '');
  }
  L.push('END:VCALENDAR');
  return L.map(icsFold).join('\r\n') + '\r\n';
}
const calUrl = (req, t) => `https://${req.get('host')}/cal/${t}.ics`;
app.get('/api/calendar-link', auth, notPending, needRole('manager'), async (req, res) => {
  let t = (await pool.query(`SELECT cal_token FROM users WHERE id=$1`, [req.user.id])).rows[0].cal_token;
  if (!t) { t = crypto.randomBytes(24).toString('hex'); await pool.query(`UPDATE users SET cal_token=$1 WHERE id=$2`, [t, req.user.id]); await log(req.user, 'created calendar link'); }
  res.json({ url: calUrl(req, t) });
});
app.post('/api/calendar-link/reset', auth, notPending, needRole('manager'), async (req, res) => {
  const t = crypto.randomBytes(24).toString('hex'); await pool.query(`UPDATE users SET cal_token=$1 WHERE id=$2`, [t, req.user.id]);
  await log(req.user, 'reset calendar link'); res.json({ url: calUrl(req, t) });
});
app.get('/cal/:token.ics', async (req, res) => {
  try {
    if (!/^[0-9a-f]{48}$/.test(req.params.token)) return res.status(404).send('Not found');
    const u = (await pool.query(`SELECT id FROM users WHERE cal_token=$1 AND active AND role='manager'`, [req.params.token])).rows[0];
    if (!u) return res.status(404).send('Not found');
    res.set({ 'Content-Type': 'text/calendar; charset=utf-8', 'Cache-Control': 'no-cache', 'Content-Disposition': 'inline; filename="fc-compliance.ics"' });
    res.send(await buildFeed());
  } catch (e) { console.warn('cal', e.message); res.status(500).send('Error'); }
});

// ---------- learner portal ----------
const portal = require('./learner-portal')(app, { pool, express, bcrypt, jwt, auth, notPending, needRole, pwOk, throttled, attempts, log, getSecret: () => SECRET });
// learners.<domain> is the learners' address: its home page goes straight to the learner portal.
app.get('/', (req, res, next) => /^learners\./i.test(req.hostname || '') ? res.redirect(302, '/learn/') : next());
app.get('/learn', (req, res, next) => { const u = req.originalUrl; if (u.split('?')[0] !== '/learn') return next(); res.redirect(301, '/learn/' + (u.includes('?') ? u.slice(u.indexOf('?')) : '')); });

// ---------- static ----------
app.get('/healthz', (req, res) => res.send('ok'));
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', maxAge: '5m' }));
app.use((req, res) => res.status(404).send('Not found'));

migrate().then(() => portal.migrate()).then(() => app.listen(PORT, () => console.log('CLR listening on', PORT))).catch(e => { console.error(e); process.exit(1); });
