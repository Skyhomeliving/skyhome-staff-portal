// evidence.js — attaches the evidence context that compliance.js needs but the
// profiles table does not hold: how many references have been received, and which
// document categories have a file actually present on disk.
//
// Document presence is checked against the filesystem, not documents.status. A
// row marked 'approved' whose file has been deleted is not evidence, and treating
// it as such is the same defect class as scoring an empty record "Compliant".
//
// Batched: two queries for any number of staff, so the dashboard and staff list
// do not run per-row lookups.
import fs from 'node:fs';
import path from 'node:path';
import { db as defaultDb, DATA_DIR } from './db.js';

const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');

// A stored file counts only if it is still on disk. path.basename keeps this
// confined to the uploads directory even if file_path were ever tampered with.
export const fileOnDisk = (filePath) =>
  !!filePath && fs.existsSync(path.join(UPLOADS_DIR, path.basename(filePath)));

// Categories for one already-loaded document list (used where docs are in hand).
export const presentCategories = (docs = []) =>
  new Set(docs.filter((d) => fileOnDisk(d.file_path)).map((d) => d.category));

// Enriches staff rows in place-ish (returns new objects) with references_count
// and document_categories. Safe with an empty list.
export function attachEvidence(rows, db = defaultDb) {
  if (!Array.isArray(rows) || rows.length === 0) return rows || [];
  const ids = rows.map((r) => r.id);
  const holes = ids.map(() => '?').join(',');

  const refs = new Map(
    db.prepare(`SELECT user_id, COUNT(*) n FROM reference_checks
                 WHERE status = 'received' AND user_id IN (${holes}) GROUP BY user_id`)
      .all(...ids).map((r) => [r.user_id, r.n])
  );

  const cats = new Map();
  for (const d of db.prepare(`SELECT user_id, category, file_path FROM documents WHERE user_id IN (${holes})`).all(...ids)) {
    if (!fileOnDisk(d.file_path)) continue;
    if (!cats.has(d.user_id)) cats.set(d.user_id, new Set());
    cats.get(d.user_id).add(d.category);
  }

  return rows.map((r) => ({
    ...r,
    references_count: refs.get(r.id) || 0,
    document_categories: cats.get(r.id) || new Set(),
  }));
}

// Single-record convenience for the staff record page and PDF export.
export function attachEvidenceOne(profile, userId, db = defaultDb) {
  const [row] = attachEvidence([{ ...profile, id: userId }], db);
  return row;
}
