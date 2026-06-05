// import-legacy.js — import the recovered legacy portal data into a fresh v2 DB.
// Usage: LEGACY_DB=<legacy.db> DATA_DIR=<target dir> node --experimental-sqlite src/import-legacy.js
// Importing db.js first creates the v2 schema at DATA_DIR/data.db; we then copy
// rows table-by-table using only columns present in BOTH schemas (so any legacy
// drift is handled), preserving IDs. Sessions are intentionally not copied.
import { DatabaseSync } from 'node:sqlite';
import { db } from './db.js';

const legacyPath = process.env.LEGACY_DB;
if (!legacyPath) { console.error('Set LEGACY_DB=<path to legacy data.db>'); process.exit(1); }
const src = new DatabaseSync(legacyPath, { readOnly: true });

const cols = (database, table) => {
  try { return database.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name); }
  catch { return []; }
};

function copyTable(table) {
  const srcCols = cols(src, table);
  if (!srcCols.length) { console.log(`  ${table}: not present in legacy — skipped`); return 0; }
  const dst = new Set(cols(db, table));
  const shared = srcCols.filter((c) => dst.has(c));
  if (!shared.length) { console.log(`  ${table}: no shared columns — skipped`); return 0; }
  const list = shared.map((c) => `"${c}"`).join(',');
  const rows = src.prepare(`SELECT ${list} FROM ${table}`).all();
  const ins = db.prepare(`INSERT OR REPLACE INTO ${table} (${list}) VALUES (${shared.map(() => '?').join(',')})`);
  db.exec('BEGIN');
  for (const r of rows) ins.run(...shared.map((c) => r[c]));
  db.exec('COMMIT');
  console.log(`  ${table}: imported ${rows.length} rows (${shared.length}/${srcCols.length} cols matched)`);
  return rows.length;
}

console.log('Importing from', legacyPath, '\n');
for (const t of ['users', 'profiles', 'documents', 'invite_codes', 'audit_log', 'employment_history', 'reference_checks']) {
  copyTable(t);
}
// Reset AUTOINCREMENT counters so new inserts never collide with imported IDs.
for (const t of ['users', 'profiles', 'documents', 'invite_codes', 'audit_log']) {
  const m = db.prepare(`SELECT COALESCE(MAX(id),0) m FROM ${t}`).get().m;
  db.prepare('DELETE FROM sqlite_sequence WHERE name=?').run(t);
  if (m > 0) db.prepare('INSERT INTO sqlite_sequence (name,seq) VALUES (?,?)').run(t, m);
}
console.log('\nResult:');
for (const t of ['users', 'profiles', 'documents', 'invite_codes', 'audit_log']) {
  console.log(`  ${t}: ${db.prepare(`SELECT COUNT(*) n FROM ${t}`).get().n}`);
}
const admin = db.prepare("SELECT email,role FROM users WHERE role='admin'").all();
console.log('  admins:', JSON.stringify(admin));
src.close();
console.log('\nImport complete.');
