// completeness.js — "file completeness" score for a staff member: how much of the
// core recruitment/compliance record (CQC Schedule 3) is actually filled in.
// This is distinct from compliance.js, which scores whether dated items are still
// IN DATE (RAG by expiry). Here we score whether the record is COMPLETE.
//
// Field names match the real schema (profiles table); references are counted from
// the reference_checks table rather than a (non-existent) profiles column.
import { db as defaultDb } from './db.js';

const filled = (v) => v !== null && v !== undefined && String(v).trim() !== '';

const REQUIRED = [
  { field: 'full_name',               label: 'Full name' },
  { field: 'dbs_certificate_number',  label: 'DBS certificate number' },
  { field: 'dbs_issue_date',          label: 'DBS issue date' },
  { field: 'right_to_work_type',      label: 'Right to Work basis' },
  { field: 'right_to_work_status',    label: 'Right to Work confirmed', check: (v) => String(v || '').toLowerCase() === 'confirmed' },
  { field: 'care_certificate_date',   label: 'Care Certificate date' },
  { field: 'references_count',        label: 'References (min 2 received)', check: (v) => Number(v) >= 2 },
  { field: 'health_declaration_date', label: 'Health declaration' },
];

export function scoreStaff(staff) {
  const missing = [];
  let passed = 0;
  for (const { field, label, check } of REQUIRED) {
    const val = staff[field];
    const ok = check ? check(val) : filled(val);
    if (ok) passed++; else missing.push(label);
  }
  const pct = Math.round((passed / REQUIRED.length) * 100);
  const rag = pct === 100 ? 'green' : pct >= 75 ? 'amber' : 'red';
  return { id: staff.id, name: staff.full_name || staff.email || 'Unknown', pct, rag, missing };
}

// Scores every non-admin staff member. Selects only the needed columns (avoids the
// users.id / profiles.id name collision) plus a count of received references.
export function scoreAllStaff(db = defaultDb) {
  const rows = db.prepare(`
    SELECT u.id AS id, u.email AS email,
      p.full_name, p.dbs_certificate_number, p.dbs_issue_date,
      p.right_to_work_type, p.right_to_work_status, p.care_certificate_date,
      p.health_declaration_date,
      (SELECT COUNT(*) FROM reference_checks r
         WHERE r.user_id = u.id AND r.status = 'received') AS references_count
    FROM users u
    LEFT JOIN profiles p ON p.user_id = u.id
    WHERE u.role != 'admin'
    ORDER BY p.full_name, u.email
  `).all();
  return rows.map(scoreStaff);
}
