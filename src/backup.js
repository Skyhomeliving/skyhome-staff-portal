// backup.js — point-in-time backup of the staff portal's data volume.
//
// Writes data/backups/backup-YYYYMMDD-HHMMSS.zip containing:
//   - data.db     a transaction-consistent SQLite snapshot (via VACUUM INTO;
//                 a raw copy of a live WAL database can miss committed data)
//   - uploads/    every uploaded compliance document
//   - branding/   custom logo etc., if present
//
// Only reads live data, so it is safe to run while the server is online.
//
// CLI:    node --experimental-sqlite src/backup.js
// In-app: startBackupScheduler() runs it nightly (wired up in server.js).
//
// Env (local):
//   DATA_DIR      data volume (default ./data)
//   BACKUP_KEEP   how many local backups to retain (default 14; 0 = keep all)
//   BACKUP_HOUR   hour-of-day (0-23) for the nightly job (default 2)
// Env (off-site, S3-compatible — all three required to enable; absent => skipped):
//   BACKUP_S3_BUCKET, BACKUP_S3_ACCESS_KEY_ID, BACKUP_S3_SECRET_ACCESS_KEY
//   BACKUP_S3_ENDPOINT   set for Cloudflare R2 / Backblaze B2 / MinIO; omit for AWS S3
//   BACKUP_S3_REGION     'auto' for R2 (default); the bucket's real region for AWS S3
//   BACKUP_S3_PREFIX     optional key prefix, e.g. "skyhome/"
//   BACKUP_S3_KEEP       remote retention (default = BACKUP_KEEP)
//   BACKUP_S3_FORCE_PATH_STYLE=1   for MinIO / some B2 setups

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
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
// Backups, oldest-first (the timestamp name sorts chronologically).
const listBackups = () => (fs.existsSync(BACKUP_DIR) ? fs.readdirSync(BACKUP_DIR) : [])
  .filter((f) => /^backup-\d{8}-\d{6}\.zip$/.test(f)).sort();

// Keep the newest `keep` backups, delete older ones. keep < 1 keeps all.
export function pruneBackups(keep = Number(process.env.BACKUP_KEEP ?? 14)) {
  if (!keep || keep < 1) return [];
  const all = listBackups();
  const stale = all.slice(0, Math.max(0, all.length - keep));
  for (const f of stale) { try { fs.unlinkSync(path.join(BACKUP_DIR, f)); } catch {} }
  return stale;
}

// Has a backup already been written today? (the filesystem is the source of truth)
export function backedUpToday(d = new Date()) {
  const prefix = `backup-${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-`;
  return listBackups().some((f) => f.startsWith(prefix));
}

// --- off-site upload (S3-compatible: AWS S3, Cloudflare R2, Backblaze B2, MinIO) ---
// Configured entirely via env vars; absent config => upload is skipped silently.
function s3Config() {
  const bucket = process.env.BACKUP_S3_BUCKET;
  const accessKeyId = process.env.BACKUP_S3_ACCESS_KEY_ID;
  const secretAccessKey = process.env.BACKUP_S3_SECRET_ACCESS_KEY;
  if (!bucket || !accessKeyId || !secretAccessKey) return null;
  return {
    bucket,
    prefix: process.env.BACKUP_S3_PREFIX || '',
    region: process.env.BACKUP_S3_REGION || 'auto',           // 'auto' for R2; real region for AWS S3
    endpoint: process.env.BACKUP_S3_ENDPOINT || undefined,    // set for R2/B2/MinIO; omit for AWS S3
    forcePathStyle: process.env.BACKUP_S3_FORCE_PATH_STYLE === '1' || undefined,
    maxAttempts: Number(process.env.BACKUP_S3_MAX_ATTEMPTS || 3),
    credentials: { accessKeyId, secretAccessKey },
  };
}

export const s3Configured = () => s3Config() !== null;

// Upload one backup zip off-site, then trim remote copies to BACKUP_S3_KEEP
// (defaults to BACKUP_KEEP). The AWS SDK is imported lazily, so it costs
// nothing at startup when off-site backups aren't configured.
export async function uploadBackup(filePath) {
  const cfg = s3Config();
  if (!cfg) return { uploaded: false, reason: 'not configured' };
  const { S3Client, PutObjectCommand, ListObjectsV2Command, DeleteObjectsCommand } =
    await import('@aws-sdk/client-s3');
  const client = new S3Client({
    region: cfg.region, endpoint: cfg.endpoint, forcePathStyle: cfg.forcePathStyle,
    maxAttempts: cfg.maxAttempts, credentials: cfg.credentials,
  });
  const key = `${cfg.prefix}${path.basename(filePath)}`;
  await client.send(new PutObjectCommand({
    Bucket: cfg.bucket, Key: key, ContentType: 'application/zip',
    Body: fs.createReadStream(filePath), ContentLength: fs.statSync(filePath).size,
  }));

  // Remote retention: keep the newest `keep` objects under the prefix.
  const keep = Number(process.env.BACKUP_S3_KEEP ?? process.env.BACKUP_KEEP ?? 14);
  let pruned = [];
  if (keep >= 1) {
    const res = await client.send(new ListObjectsV2Command({ Bucket: cfg.bucket, Prefix: `${cfg.prefix}backup-` }));
    const keys = (res.Contents || []).map((o) => o.Key)
      .filter((k) => /backup-\d{8}-\d{6}\.zip$/.test(k)).sort();
    const stale = keys.slice(0, Math.max(0, keys.length - keep));
    if (stale.length) {
      await client.send(new DeleteObjectsCommand({ Bucket: cfg.bucket, Delete: { Objects: stale.map((k) => ({ Key: k })) } }));
      pruned = stale;
    }
  }
  return { uploaded: true, bucket: cfg.bucket, key, pruned };
}

export async function runBackup({ prune = false, upload = true } = {}) {
  if (!fs.existsSync(DB_PATH)) throw new Error(`No database at ${DB_PATH}`);
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
  const ts = stamp(new Date());

  // 1) Consistent snapshot of the database (handles WAL correctly).
  const snap = path.join(BACKUP_DIR, `.snapshot-${ts}.db`);
  const db = new DatabaseSync(DB_PATH);
  try { db.exec(`VACUUM INTO '${sqlPath(snap)}'`); } finally { db.close(); }

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
  if (prune) pruneBackups();

  let remote = { uploaded: false, reason: 'not configured' };
  if (upload && s3Configured()) {
    try { remote = await uploadBackup(outPath); }
    catch (e) { remote = { uploaded: false, reason: e.message }; }
  }
  return { path: outPath, remote };
}

// Daily scheduler: hourly tick, runs once per day after BACKUP_HOUR (default 02:00).
export function startBackupScheduler() {
  const HOUR = Number(process.env.BACKUP_HOUR || 2);
  const tick = async () => {
    try {
      if (new Date().getHours() < HOUR) return;
      if (backedUpToday()) return;
      const { path: out, remote } = await runBackup({ prune: true });
      const off = remote.uploaded ? ` (off-site: ${remote.key})`
        : remote.reason === 'not configured' ? '' : ` (off-site FAILED: ${remote.reason})`;
      console.log(`[backup] nightly backup written: ${path.basename(out)}${off}`);
    } catch (e) { console.error('[backup] error:', e.message); }
  };
  setInterval(tick, 60 * 60 * 1000);
  setTimeout(tick, 30000);
}

// CLI entry point (only when run directly, not when imported by the server).
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runBackup({ prune: true })
    .then(({ path: p, remote }) => {
      console.log(`Backup written: ${p} (${(fs.statSync(p).size / 1024 / 1024).toFixed(2)} MB)`);
      if (remote.uploaded) console.log(`Off-site: uploaded to s3://${remote.bucket}/${remote.key}`
        + (remote.pruned?.length ? ` (pruned ${remote.pruned.length} old remote copies)` : ''));
      else console.log(`Off-site: skipped (${remote.reason})`);
    })
    .catch((e) => { console.error('Backup failed:', e.message); process.exit(1); });
}
