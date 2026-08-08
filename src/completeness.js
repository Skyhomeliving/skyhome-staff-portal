// completeness.js — "file completeness" score for a staff member: how much of the
// core recruitment/compliance record (CQC Schedule 3) is actually filled in.
//
// This no longer keeps its own copy of the requirements. The score is derived
// from computeCompliance() in compliance.js, so the dashboard's "Fully compliant"
// headline and this panel's "Incomplete files" list are two views of one
// calculation. They previously ran as independent engines and contradicted each
// other on the same screen.
import { db as defaultDb } from './db.js';
import { computeCompliance, REQUIRED_TOTAL } from './compliance.js';
import { attachEvidence } from './evidence.js';

// `staff` must already carry evidence context (references_count,
// document_categories) — see evidence.js.
export function scoreStaff(staff) {
  const c = computeCompliance(staff);
  const passed = REQUIRED_TOTAL - c.missing.length;
  const pct = Math.round((passed / REQUIRED_TOTAL) * 100);
  return {
    id: staff.id,
    name: staff.full_name || staff.email || 'Unknown',
    pct,
    // Colour tracks the compliance status so the % chip and the status badge
    // always agree: anything missing is 'incomplete', never amber-as-nearly-fine.
    rag: c.status === 'compliant' ? 'green' : c.status === 'expired' ? 'red' : 'incomplete',
    missing: c.missing,
    status: c.status,
    complete: c.complete,
  };
}

// Scores every active non-admin staff member. Selects the columns the requirement
// list needs (avoiding the users.id / profiles.id collision), then attaches
// reference counts and on-disk document categories in two batched queries.
export function scoreAllStaff(db = defaultDb) {
  const rows = db.prepare(`
    SELECT u.id AS id, u.email AS email,
      p.full_name, p.dbs_certificate_number, p.dbs_issue_date,
      p.right_to_work_type, p.right_to_work_status, p.right_to_work_expiry,
      p.care_certificate_date, p.health_declaration_date,
      p.last_supervision_date, p.last_appraisal_date
    FROM users u
    LEFT JOIN profiles p ON p.user_id = u.id
    WHERE u.role != 'admin' AND u.is_active = 1
    ORDER BY p.full_name, u.email
  `).all();
  return attachEvidence(rows, db).map(scoreStaff);
}
