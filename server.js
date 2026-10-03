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

const ROLES = ['admin', 'manager', 'assessor'];
// Collections each role may change. Admin and manager may change everything.
const ASSESSOR_WRITE = new Set(['learners', 'otj', 'attendance']);
const COLLECTIONS = new Set(['staff', 'items', 'documents', 'learners', 'otj', 'attendance', 'audit', 'config']);
const MAX_FILE = 20 * 1024 * 1024;
const FILE_TYPES = new Set(['application/pdf', 'image/png', 'image/jpeg', 'image/webp', 'image/gif', 'text/plain', 'text/csv', 'text/markdown', 'application/json']);

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
    console.log('=== FIRST-TIME SETUP CODE: ' + SETUP_CODE + ' (enter it on the website to create the Admin account) ===');
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
function canWrite(u, col) { return u.role === 'admin' || u.role === 'manager' || (u.role === 'assessor' && ASSESSOR_WRITE.has(col)); }
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
  const ins = await pool.query(`INSERT INTO users (email, name, role, pass_hash, must_change) VALUES ($1,$2,'admin',$3,false) RETURNING *`,
    [String(email).trim().toLowerCase(), String(name).trim(), await bcrypt.hash(password, 12)]);
  issue(res, ins.rows[0]); await log(ins.rows[0], 'created the first admin account');
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
app.get('/api/users', auth, notPending, needRole('admin'), async (req, res) => {
  const r = await pool.query(`SELECT id, email, name, role, active, must_change, created_at, last_login FROM users ORDER BY role, name`); res.json({ users: r.rows });
});
app.post('/api/users', auth, notPending, needRole('admin'), express.json(), async (req, res) => {
  const { email, name, role, password } = req.body;
  if (!email || !name || !ROLES.includes(role)) return res.status(400).json({ error: 'Enter a name, email and role.' });
  if (!pwOk(password)) return res.status(400).json({ error: 'Temporary password: at least 10 characters, with letters and numbers.' });
  try {
    const r = await pool.query(`INSERT INTO users (email, name, role, pass_hash, must_change) VALUES ($1,$2,$3,$4,true) RETURNING id`,
      [String(email).trim().toLowerCase(), String(name).trim(), role, await bcrypt.hash(password, 12)]);
    await log(req.user, 'added user', 'users', String(r.rows[0].id), `${name} (${role})`); res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: e.code === '23505' ? 'That email already has an account.' : 'Could not add the user.' }); }
});
app.patch('/api/users/:id', auth, notPending, needRole('admin'), express.json(), async (req, res) => {
  const id = Number(req.params.id); const b = req.body; const sets = []; const vals = []; let n = 1;
  if (b.role !== undefined) { if (!ROLES.includes(b.role)) return res.status(400).json({ error: 'Bad role' }); sets.push(`role=$${n++}`); vals.push(b.role); }
  if (b.name !== undefined) { sets.push(`name=$${n++}`); vals.push(String(b.name).trim()); }
  if (b.active !== undefined) { sets.push(`active=$${n++}`); vals.push(!!b.active); sets.push(`token_version=token_version+1`); }
  if (b.password !== undefined) { if (!pwOk(b.password)) return res.status(400).json({ error: 'Temporary password: at least 10 characters, with letters and numbers.' });
    sets.push(`pass_hash=$${n++}`); vals.push(await bcrypt.hash(b.password, 12)); sets.push(`must_change=true`, `token_version=token_version+1`); }
  if (id === req.user.id && (b.active === false || (b.role && b.role !== 'admin'))) return res.status(400).json({ error: "You can't remove your own admin access." });
  if (!sets.length) return res.json({ ok: true });
  vals.push(id); const r = await pool.query(`UPDATE users SET ${sets.join(', ')} WHERE id=$${n} RETURNING name`, vals);
  if (!r.rows[0]) return res.status(404).json({ error: 'Not found' });
  await log(req.user, b.password ? 'reset password for' : 'updated user', 'users', String(id), r.rows[0].name); res.json({ ok: true });
});

// ---------- records ----------
app.get('/api/rev', auth, async (req, res) => res.json({ rev: await getRev() }));
app.get('/api/data', auth, notPending, async (req, res) => {
  const rev = await getRev(); const r = await pool.query(`SELECT col, id, data FROM docs`);
  const collections = {}; for (const row of r.rows) (collections[row.col] = collections[row.col] || {})[row.id] = row.data;
  res.json({ rev, collections });
});
function checkCol(req, res) {
  const col = req.params.col; if (!COLLECTIONS.has(col) || !/^[A-Za-z0-9_.:@+~-]{1,200}$/.test(req.params.id)) { res.status(400).json({ error: 'bad path' }); return null; }
  if (!canWrite(req.user, col)) { res.status(403).json({ error: 'Your role can only view this.' }); return null; }
  return col;
}
app.put('/api/doc/:col/:id', auth, notPending, express.json({ limit: '2mb' }), async (req, res) => {
  const col = checkCol(req, res); if (!col) return;
  const prev = await pool.query(`SELECT 1 FROM docs WHERE col=$1 AND id=$2`, [col, req.params.id]);
  await pool.query(`INSERT INTO docs (col, id, data, updated_at, updated_by) VALUES ($1,$2,$3,now(),$4)
    ON CONFLICT (col, id) DO UPDATE SET data=EXCLUDED.data, updated_at=now(), updated_by=EXCLUDED.updated_by`, [col, req.params.id, req.body, req.user.email]);
  const rev = await bumpRev(); await log(req.user, prev.rowCount ? 'updated' : 'added', col, req.params.id, titleOf(req.body)); res.json({ rev });
});
app.patch('/api/doc/:col/:id', auth, notPending, express.json({ limit: '2mb' }), async (req, res) => {
  const col = checkCol(req, res); if (!col) return;
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const r = await c.query(`SELECT data FROM docs WHERE col=$1 AND id=$2 FOR UPDATE`, [col, req.params.id]);
    const data = merge(r.rows[0] ? r.rows[0].data : {}, req.body);
    await c.query(`INSERT INTO docs (col, id, data, updated_at, updated_by) VALUES ($1,$2,$3,now(),$4)
      ON CONFLICT (col, id) DO UPDATE SET data=EXCLUDED.data, updated_at=now(), updated_by=EXCLUDED.updated_by`, [col, req.params.id, data, req.user.email]);
    const rev = await bumpRev(c); await c.query('COMMIT');
    await log(req.user, 'updated', col, req.params.id, titleOf(data)); res.json({ rev });
  } catch (e) { await c.query('ROLLBACK').catch(() => {}); res.status(500).json({ error: 'save failed' }); } finally { c.release(); }
});
app.delete('/api/doc/:col/:id', auth, notPending, async (req, res) => {
  const col = checkCol(req, res); if (!col) return;
  if (req.user.role === 'assessor' && col === 'learners') return res.status(403).json({ error: 'Only an admin or manager can delete a learner.' });
  const r = await pool.query(`DELETE FROM docs WHERE col=$1 AND id=$2 RETURNING data`, [col, req.params.id]);
  const rev = await bumpRev(); await log(req.user, 'deleted', col, req.params.id, r.rows[0] && titleOf(r.rows[0].data)); res.json({ rev });
});

// ---------- files ----------
app.post('/api/files', auth, notPending, express.raw({ type: () => true, limit: MAX_FILE }), async (req, res) => {
  const type = String(req.get('x-file-type') || '').split(';')[0].trim();
  if (!FILE_TYPES.has(type)) return res.status(400).json({ error: 'unsupported_type' });
  if (!req.body || !req.body.length) return res.status(400).json({ error: 'empty' });
  const id = String(req.get('x-file-id') || '');
  const fid = /^[0-9a-f]{32}$/.test(id) && (req.user.role === 'admin') ? id : crypto.randomBytes(16).toString('hex');
  const name = decodeURIComponent(String(req.get('x-file-name') || '')).slice(0, 200);
  await pool.query(`INSERT INTO files (id, name, type, size, data, created_by) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (id) DO NOTHING`,
    [fid, name, type, req.body.length, req.body, req.user.email]);
  await log(req.user, 'uploaded file', 'files', fid, name);
  res.json({ id: fid, url: '/_blob/' + fid, sizeBytes: req.body.length, contentType: type });
});
app.delete('/api/files/:id', auth, notPending, needRole('admin', 'manager'), async (req, res) => {
  const r = await pool.query(`DELETE FROM files WHERE id=$1 RETURNING name`, [req.params.id]);
  if (r.rowCount) await log(req.user, 'deleted file', 'files', req.params.id, r.rows[0].name);
  res.json({ deleted: !!r.rowCount });
});
app.get('/_blob/:id', auth, async (req, res) => {
  const r = await pool.query(`SELECT name, type, data FROM files WHERE id=$1`, [req.params.id]);
  if (!r.rows[0]) return res.status(404).send('Not found');
  const f = r.rows[0];
  res.set({ 'Content-Type': f.type, 'Content-Disposition': `inline; filename*=UTF-8''${encodeURIComponent(f.name || req.params.id)}`, 'Cache-Control': 'private, max-age=3600' });
  res.send(f.data);
});

// ---------- activity ----------
app.get('/api/activity', auth, notPending, needRole('admin', 'manager'), async (req, res) => {
  const r = await pool.query(`SELECT at, user_name, user_email, action, col, doc_id, detail FROM activity ORDER BY id DESC LIMIT 300`); res.json({ activity: r.rows });
});

// ---------- export (offline copy) and import ----------
app.get('/api/export.zip', auth, notPending, needRole('admin', 'manager'), async (req, res) => {
  const docs = await pool.query(`SELECT col, id, data FROM docs`);
  const files = await pool.query(`SELECT id, type FROM files`);
  const ext = { 'application/pdf': 'pdf', 'image/png': 'png', 'image/jpeg': 'jpg', 'image/webp': 'webp', 'image/gif': 'gif', 'text/plain': 'txt', 'text/csv': 'csv', 'text/markdown': 'md', 'application/json': 'json' };
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
app.post('/api/import', auth, notPending, needRole('admin'), express.json({ limit: '20mb' }), async (req, res) => {
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
app.get('/api/files/missing', auth, notPending, needRole('admin'), async (req, res) => {
  const ids = String(req.query.ids || '').split(',').filter(x => /^[0-9a-f]{32}$/.test(x));
  if (!ids.length) return res.json({ missing: [] });
  const r = await pool.query(`SELECT id FROM files WHERE id = ANY($1)`, [ids]); const have = new Set(r.rows.map(x => x.id));
  res.json({ missing: ids.filter(x => !have.has(x)) });
});

// ---------- static ----------
app.get('/healthz', (req, res) => res.send('ok'));
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', maxAge: '5m' }));
app.use((req, res) => res.status(404).send('Not found'));

migrate().then(() => app.listen(PORT, () => console.log('CLR listening on', PORT))).catch(e => { console.error(e); process.exit(1); });
