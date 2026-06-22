// backup.js — point-in-time backup of the staff portal's data volume.
//
// Writes data/backups/backup-YYYYMMDD-HHMMSS.zip containing:
//   - data.db     a transaction-consistent SQLite snapshot (via VACUUM INTO;
//                 a raw copy of a live WAL database can miss committed data)
//   - uploads/    every uploaded compliance document
//   - branding/   custom logo etc., if present
//
// Only reads live data, so it is safe to run while the server is online.
// Usage: node --experimental-sqlite src/backup.js
//        DATA_DIR=/path node --experimental-sqlite src/backup.js   (custom volume)

import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import archiver from 'archiver';

const DATA_DIR = process.env.DATA_DIR || path.resolve('data');
const DB_PATH = path.join(DATA_DIR, 'data.db');
const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
const BRAND_DIR = path.join(DATA_DIR, 'branding');
const BACKUP_DIR = path.join(DATA_DIR, 'backups');

const pad = (n) => String(n).padStart(2, '0');
const stamp = (d) => `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}`
  + `-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
// SQLite accepts forward slashes on Windows; double up any single quotes.
const sqlPath = (p) => p.replace(/\\/g, '/').replace(/'/g, "''");

async function main() {
  if (!fs.existsSync(DB_PATH)) {
    console.error(`No database at ${DB_PATH} — nothing to back up.`);
    process.exit(1);
  }
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
  const ts = stamp(new Date());

  // 1) Consistent snapshot of the database (handles WAL correctly).
  const snap = path.join(BACKUP_DIR, `.snapshot-${ts}.db`);
  const db = new DatabaseSync(DB_PATH);
  try {
    db.exec(`VACUUM INTO '${sqlPath(snap)}'`);
  } finally {
    db.close();
  }

  // 2) Bundle snapshot + documents + branding into one timestamped zip.
  const outPath = path.join(BACKUP_DIR, `backup-${ts}.zip`);
  const out = fs.createWriteStream(outPath);
  const zip = archiver('zip', { zlib: { level: 9 } });
  const done = new Promise((resolve, reject) => {
    out.on('close', resolve);
    zip.on('warning', (e) => (e.code === 'ENOENT' ? null : reject(e)));
    zip.on('error', reject);
  });
  zip.pipe(out);
  zip.file(snap, { name: 'data.db' });
  if (fs.existsSync(UPLOADS_DIR)) zip.directory(UPLOADS_DIR, 'uploads');
  if (fs.existsSync(BRAND_DIR)) zip.directory(BRAND_DIR, 'branding');
  await zip.finalize();
  await done;

  fs.unlinkSync(snap); // the snapshot now lives inside the zip

  const mb = (fs.statSync(outPath).size / 1024 / 1024).toFixed(2);
  console.log(`Backup written: ${outPath} (${mb} MB)`);
}

main().catch((e) => { console.error('Backup failed:', e); process.exit(1); });
