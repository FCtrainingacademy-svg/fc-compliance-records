// One-off Exams tab tidy-up (14 Nov 2026), runs once per database:
//  - takes out the Lesson plans, Classwork and NICEIC Gas Training groups
//  - adds "Scheme of works final.xlsx" under Lesson plans
// Removed entries are kept in meta 'exams_cleanup_v1_removed' (and their files stay in the files table) so they can be restored.
// The spreadsheet is stored encrypted (the repo is public); SOW_KEY on the server decrypts it.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DONE_KEY = 'exams_cleanup_v1';
const REMOVE = [/lesson\s*plan/i, /class\s*work/i, /niceic\s*gas\s*training/i];
const NEW_NAME = 'Scheme of works final.xlsx';
const XLSX = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';

function loadSow() {
  const raw = Buffer.from(fs.readFileSync(path.join(__dirname, 'private', 'sow-final.enc'), 'utf8'), 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', Buffer.from(String(process.env.SOW_KEY || ''), 'hex'), raw.subarray(0, 12));
  d.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([d.update(raw.subarray(28)), d.final()]);
}

module.exports = async function examsCleanup(pool, bumpRev, log) {
  const done = await pool.query(`SELECT 1 FROM meta WHERE k=$1`, [DONE_KEY]);
  if (done.rowCount) return;
  if (!process.env.SOW_KEY) { console.warn('exams cleanup: SOW_KEY not set, skipping'); return; }
  const sow = loadSow();

  const rows = (await pool.query(`SELECT id, data FROM docs WHERE col='exams'`)).rows;
  const folders = d => String((d && (d.path || d.title)) || '').split('/').slice(0, -1);
  const removed = rows.filter(r => folders(r.data).some(seg => REMOVE.some(re => re.test(seg))));

  // put the new file in the same Lesson plans folder the old ones were in (or a new "Lesson plans" group)
  let prefix = 'Lesson plans';
  for (const r of removed) {
    const f = folders(r.data); const i = f.findIndex(seg => REMOVE[0].test(seg));
    if (i >= 0) { prefix = f.slice(0, i + 1).join('/'); break; }
  }
  const fileId = crypto.randomBytes(16).toString('hex');
  const docId = 'ex-sow-final';
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    await c.query(`INSERT INTO meta (k, v) VALUES ($1, $2) ON CONFLICT (k) DO UPDATE SET v=EXCLUDED.v`, [DONE_KEY + '_removed', JSON.stringify(removed)]);
    if (removed.length) await c.query(`DELETE FROM docs WHERE col='exams' AND id = ANY($1)`, [removed.map(r => r.id)]);
    await c.query(`INSERT INTO files (id, name, type, size, data, created_by, restricted) VALUES ($1,$2,$3,$4,$5,$6,true)`,
      [fileId, NEW_NAME, XLSX, sow.length, sow, 'system']);
    const doc = { title: NEW_NAME, path: prefix + '/' + NEW_NAME, fileId, type: XLSX, size: sow.length, addedAt: new Date().toISOString(), addedBy: 'Claude (for Anis)' };
    await c.query(`INSERT INTO docs (col, id, data, updated_by) VALUES ('exams', $1, $2, 'system') ON CONFLICT (col, id) DO UPDATE SET data=EXCLUDED.data, updated_at=now()`, [docId, doc]);
    await c.query(`INSERT INTO meta (k, v) VALUES ($1, $2)`, [DONE_KEY, new Date().toISOString()]);
    await bumpRev(c);
    await c.query('COMMIT');
  } catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
  await log({ email: 'system', name: 'System' }, `Exams tidy-up: removed ${removed.length} Lesson plans / Classwork / NICEIC Gas Training files; added ${NEW_NAME}`, 'exams', docId, prefix);
  console.log(`exams cleanup: removed ${removed.length}, added ${NEW_NAME} under "${prefix}"`);
};
