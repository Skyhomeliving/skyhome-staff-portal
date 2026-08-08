// compliance.js — domain model: how compliance fields are grouped for the UI,
// the document categories that can be uploaded, and the expiry/alert engine that
// powers the dashboard and per-staff RAG (red/amber/green) status.

// Roles, lowest → highest privilege. Three tiers drive access decisions:
//   frontline   — carers/support workers: their own record only
//   oversight   — coordinators: read-only view of staff & compliance
//   management  — managers/admins: full edit; admin also owns settings
// 'staff' is a legacy alias that behaves as frontline (migrated to 'carer' on boot).
export const ROLES = [
  { value: 'carer', label: 'Carer', tier: 'frontline' },
  { value: 'support_worker', label: 'Support Worker', tier: 'frontline' },
  { value: 'coordinator', label: 'Coordinator', tier: 'oversight' },
  { value: 'manager', label: 'Manager', tier: 'management' },
  { value: 'admin', label: 'Compliance / Admin', tier: 'management' },
];
const ROLE_TIER = Object.fromEntries(ROLES.map((r) => [r.value, r.tier]));
export const roleTier = (role) => ROLE_TIER[role] || 'frontline';
export const isFrontline = (role) => roleTier(role) === 'frontline';
export const isOversight = (role) => roleTier(role) === 'oversight' || roleTier(role) === 'management';
export const isManagerLevel = (role) => roleTier(role) === 'management';
export const isAdmin = (role) => role === 'admin';
export const roleLabel = (role) => ROLES.find((r) => r.value === role)?.label || (role === 'staff' ? 'Staff' : role);

// Document upload categories (driving licence, sponsorship evidence, etc.)
export const DOCUMENT_CATEGORIES = [
  { value: 'photo_id', label: 'Photo ID' },
  { value: 'passport', label: 'Passport' },
  { value: 'driving_licence', label: 'Driving licence' },
  { value: 'brp', label: 'BRP / visa card' },
  { value: 'visa_share_code', label: 'Right to Work share code / visa' },
  { value: 'right_to_work', label: 'Right to Work evidence' },
  { value: 'dbs_certificate', label: 'DBS certificate' },
  { value: 'care_certificate', label: 'Care Certificate' },
  { value: 'training_certificate', label: 'Training certificate' },
  { value: 'qualification', label: 'Qualification' },
  { value: 'professional_registration', label: 'Professional registration (NMC/HCPC)' },
  { value: 'employment_reference', label: 'Employment reference' },
  { value: 'proof_of_address', label: 'Proof of address' },
  { value: 'contract', label: 'Contract of employment' },
  { value: 'health_declaration', label: 'Health / fitness declaration' },
  { value: 'cv', label: 'CV' },
  { value: 'other', label: 'Other' },
];
export const categoryLabel = (v) => DOCUMENT_CATEGORIES.find((c) => c.value === v)?.label || v;

const sel = (...opts) => ({ type: 'select', options: ['', ...opts] });

// Profile form layout — grouped into clear, navigable sections.
export const PROFILE_SECTIONS = [
  { id: 'personal', title: 'Personal details', icon: 'user', fields: [
    { key: 'full_name', label: 'Full name', type: 'text' },
    { key: 'preferred_name', label: 'Preferred name', type: 'text' },
    { key: 'date_of_birth', label: 'Date of birth', type: 'date' },
    { key: 'ni_number', label: 'National Insurance no.', type: 'text' },
    { key: 'phone', label: 'Phone', type: 'tel' },
    { key: 'home_address', label: 'Home address', type: 'textarea' },
    { key: 'emergency_contact_name', label: 'Emergency contact', type: 'text' },
    { key: 'emergency_contact_phone', label: 'Emergency contact phone', type: 'tel' },
  ]},
  { id: 'employment', title: 'Employment', icon: 'briefcase', fields: [
    { key: 'job_title', label: 'Job title', type: 'text' },
    { key: 'department', label: 'Department', type: 'text' },
    { key: 'location', label: 'Location / branch', type: 'text' },
    { key: 'start_date', label: 'Start date', type: 'date' },
    { key: 'employment_type', label: 'Employment type', ...sel('Full-time', 'Part-time', 'Bank', 'Agency') },
    { key: 'line_manager', label: 'Line manager', type: 'text' },
    { key: 'status', label: 'Status', ...sel('active', 'on_leave', 'left') },
  ]},
  { id: 'rtw', title: 'Right to Work & immigration', icon: 'globe', fields: [
    { key: 'right_to_work_status', label: 'Right to Work status', ...sel('Confirmed', 'Pending', 'Not confirmed') },
    { key: 'right_to_work_type', label: 'RTW basis', ...sel('British/Irish citizen', 'Settled/Pre-settled', 'Visa', 'Sponsored worker', 'Other') },
    { key: 'right_to_work_expiry', label: 'RTW review date', type: 'date', expiry: true },
    { key: 'is_sponsored', label: 'Sponsored worker (Home Office)', type: 'checkbox' },
    { key: 'share_code', label: 'RTW share code', type: 'text' },
    { key: 'share_code_checked_date', label: 'Share code checked', type: 'date' },
    { key: 'passport_number', label: 'Passport number', type: 'text' },
    { key: 'passport_expiry', label: 'Passport expiry', type: 'date', expiry: true },
    { key: 'visa_type', label: 'Visa / leave type', type: 'text' },
    { key: 'visa_expiry', label: 'Visa / leave expiry', type: 'date', expiry: true },
    { key: 'brp_number', label: 'BRP number', type: 'text' },
    { key: 'brp_expiry', label: 'BRP expiry', type: 'date', expiry: true },
    { key: 'cos_reference', label: 'Certificate of Sponsorship ref', type: 'text' },
  ]},
  { id: 'dbs', title: 'DBS', icon: 'shield', fields: [
    { key: 'dbs_status', label: 'DBS status', ...sel('Clear', 'Pending', 'Expired', 'Not started') },
    { key: 'dbs_type', label: 'DBS type', ...sel('Enhanced + barred', 'Enhanced', 'Standard', 'Basic') },
    { key: 'dbs_certificate_number', label: 'Certificate number', type: 'text' },
    { key: 'dbs_issue_date', label: 'Issue date', type: 'date' },
    { key: 'dbs_expiry', label: 'Review / renewal date', type: 'date', expiry: true },
    { key: 'dbs_update_service', label: 'On DBS Update Service', ...sel('Yes', 'No') },
  ]},
  { id: 'driving', title: 'Driving licence', icon: 'car', fields: [
    { key: 'drives_for_work', label: 'Drives for work', type: 'checkbox' },
    { key: 'driving_licence_number', label: 'Licence number', type: 'text' },
    { key: 'driving_licence_categories', label: 'Categories', type: 'text' },
    { key: 'driving_licence_expiry', label: 'Licence expiry', type: 'date', expiry: true },
    { key: 'driving_check_code', label: 'DVLA check code', type: 'text' },
    { key: 'business_insurance_expiry', label: 'Business insurance expiry', type: 'date', expiry: true },
  ]},
  { id: 'training', title: 'Training & qualifications', icon: 'award', fields: [
    { key: 'care_certificate_status', label: 'Care Certificate', ...sel('Completed', 'In progress', 'Not started', 'Exempt') },
    { key: 'care_certificate_date', label: 'Care Certificate date', type: 'date' },
    { key: 'mandatory_training_date', label: 'Mandatory training done', type: 'date' },
    { key: 'mandatory_training_expiry', label: 'Mandatory training expiry', type: 'date', expiry: true },
    { key: 'safeguarding_training_date', label: 'Safeguarding done', type: 'date' },
    { key: 'safeguarding_training_expiry', label: 'Safeguarding expiry', type: 'date', expiry: true },
    { key: 'moving_handling_date', label: 'Moving & handling done', type: 'date' },
    { key: 'moving_handling_expiry', label: 'Moving & handling expiry', type: 'date', expiry: true },
    { key: 'medication_training_date', label: 'Medication training done', type: 'date' },
    { key: 'medication_training_expiry', label: 'Medication training expiry', type: 'date', expiry: true },
    { key: 'first_aid_date', label: 'First aid done', type: 'date' },
    { key: 'first_aid_expiry', label: 'First aid expiry', type: 'date', expiry: true },
    { key: 'qualifications', label: 'Qualifications', type: 'textarea' },
  ]},
  { id: 'professional', title: 'Professional registration', icon: 'badge', fields: [
    { key: 'professional_reg_body', label: 'Body', ...sel('None', 'NMC', 'HCPC', 'Social Work England', 'Other') },
    { key: 'professional_reg_number', label: 'Registration number', type: 'text' },
    { key: 'professional_reg_expiry', label: 'Registration expiry', type: 'date', expiry: true },
  ]},
  { id: 'health', title: 'Health & fitness', icon: 'heart', fields: [
    { key: 'health_declaration_status', label: 'Health declaration', ...sel('Received', 'Outstanding') },
    { key: 'health_declaration_date', label: 'Declaration date', type: 'date' },
    { key: 'occupational_health_status', label: 'Occupational health', ...sel('Cleared', 'Referred', 'Not required') },
    { key: 'occupational_health_date', label: 'Occ. health date', type: 'date' },
  ]},
  { id: 'supervision', title: 'References & supervision', icon: 'check', fields: [
    { key: 'references_received', label: 'References received', ...sel('Yes', 'Partial', 'No') },
    { key: 'last_supervision_date', label: 'Last supervision', type: 'date' },
    { key: 'last_appraisal_date', label: 'Last appraisal', type: 'date' },
  ]},
  { id: 'notes', title: 'Notes', icon: 'note', fields: [
    { key: 'notes', label: 'Notes', type: 'textarea' },
  ]},
];

// All editable profile keys (used for safe updates).
export const PROFILE_KEYS = PROFILE_SECTIONS.flatMap((s) => s.fields.map((f) => f.key));

// Fields ONLY a manager/admin may set — the verification & HR decisions that a
// staff member must not be able to self-certify (e.g. marking their own DBS
// "Clear" or Right to Work "Confirmed"). Everything NOT in this set is editable
// by the staff member on their own record, so they can complete their own
// onboarding details (personal info, document numbers, qualifications, etc.).
export const MANAGER_ONLY_KEYS = new Set([
  // Employment / HR decisions
  'job_title', 'department', 'location', 'start_date', 'employment_type', 'line_manager', 'status',
  // Right to Work — employer verifies
  'right_to_work_status', 'right_to_work_expiry', 'is_sponsored', 'share_code_checked_date', 'cos_reference',
  // DBS — employer-processed clearance
  'dbs_status', 'dbs_expiry', 'dbs_update_service',
  // Care Certificate (verified completion)
  'care_certificate_status', 'care_certificate_date',
  // Training validity (drives compliance status)
  'mandatory_training_date', 'mandatory_training_expiry',
  'safeguarding_training_date', 'safeguarding_training_expiry',
  'moving_handling_date', 'moving_handling_expiry',
  'medication_training_date', 'medication_training_expiry',
  'first_aid_date', 'first_aid_expiry',
  // Professional registration (verified)
  'professional_reg_body', 'professional_reg_number', 'professional_reg_expiry',
  // Health / fitness (verified)
  'health_declaration_status', 'health_declaration_date', 'occupational_health_status', 'occupational_health_date',
  // References & supervision (recorded by the manager)
  'references_received', 'last_supervision_date', 'last_appraisal_date',
  // Internal notes
  'notes',
]);

// A staff member may edit any profile field that isn't manager-only.
export const isSelfEditableKey = (key) => !MANAGER_ONLY_KEYS.has(key);

// Every date field marked expiry:true becomes a tracked renewal.
export const EXPIRY_TRACKERS = PROFILE_SECTIONS.flatMap((s) =>
  s.fields.filter((f) => f.expiry).map((f) => ({ key: f.key, label: f.label, area: s.title }))
);

// --- Expiry / alert engine --------------------------------------------------
// Whole calendar days from today until dateStr; negative once the date has passed,
// 0 on the day itself. Returns null for blank/unparseable input.
//
// Compares LOCAL midnight to LOCAL midnight, deliberately. A date-only string
// ("2026-08-08") is parsed by JS as midnight *UTC*, so comparing it against the
// current instant used to mix a date with a time: at 12:00 BST an item expiring
// today read as 11 hours in the past, floored to "expired 1 day ago". Every
// renewal therefore reported a day early and every overdue count was inflated
// by one. Normalising both sides to local midnight removes the time-of-day
// component entirely, so the answer no longer depends on when it is asked.
//
// Math.round (not floor) absorbs DST: local midnights are 23 or 25 hours apart
// across a clock change, and flooring 29.96 would silently lose a day each spring.
export function daysUntil(dateStr) {
  if (!dateStr) return null;
  const s = String(dateStr).trim();
  let target = null;
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  if (m) {
    const [y, mo, da] = [Number(m[1]), Number(m[2]), Number(m[3])];
    const d = new Date(y, mo - 1, da);
    // Reject impossible dates that JS would silently roll over (2026-02-30 → 2 Mar).
    if (d.getFullYear() === y && d.getMonth() === mo - 1 && d.getDate() === da) target = d;
  } else {
    const d = new Date(s);
    if (!Number.isNaN(d.getTime())) target = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  }
  if (!target) return null;
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  return Math.round((target.getTime() - today.getTime()) / 86400000);
}

export function levelFor(days) {
  if (days === null) return null;
  if (days < 0) return 'expired';
  if (days <= 30) return 'critical';
  if (days <= 60) return 'warning';
  return 'ok';
}

export const isFilled = (v) => v !== null && v !== undefined && String(v).trim() !== '';

// --- What a complete staff file must contain --------------------------------
// The single source of truth for "is this record complete?". completeness.js
// derives its percentage from the same list, so the dashboard headline count and
// the "Incomplete files" panel are computed from one definition and cannot drift
// apart (they previously disagreed on the same screen).
//
// `references_count` is supplied by the caller (counted from reference_checks),
// not stored on profiles.
export const REQUIRED_FIELDS = [
  { field: 'full_name', label: 'Full name', area: 'Personal details' },
  { field: 'dbs_certificate_number', label: 'DBS certificate number', area: 'DBS' },
  { field: 'dbs_issue_date', label: 'DBS issue date', area: 'DBS' },
  { field: 'right_to_work_type', label: 'Right to Work basis', area: 'Right to Work & immigration' },
  { field: 'right_to_work_status', label: 'Right to Work confirmed', area: 'Right to Work & immigration',
    check: (v) => String(v || '').toLowerCase() === 'confirmed' },
  { field: 'care_certificate_date', label: 'Care Certificate date', area: 'Training & qualifications' },
  { field: 'references_count', label: 'References (min 2 received)', area: 'References & supervision',
    check: (v) => Number(v) >= 2 },
  { field: 'health_declaration_date', label: 'Health declaration', area: 'Health & fitness' },
  { field: 'last_supervision_date', label: 'Last supervision recorded', area: 'References & supervision' },
  { field: 'last_appraisal_date', label: 'Last appraisal recorded', area: 'References & supervision' },
];

// Documents whose FILE must actually exist for the record to count as complete.
// Deliberately not driven by documents.status: a row marked 'approved' whose file
// has since been deleted is not evidence. Callers pass `document_categories`
// already filtered to files verified present on disk (see evidence.js).
export const REQUIRED_DOCUMENTS = [
  { category: 'dbs_certificate', label: 'DBS certificate (uploaded)' },
  { category: 'right_to_work', label: 'Right to Work evidence (uploaded)' },
];

export const REQUIRED_TOTAL = REQUIRED_FIELDS.length + REQUIRED_DOCUMENTS.length;

// Ordering for the "needs attention" lists: already-unlawful first, then never
// -provided, then imminent renewals. Missing items carry days:null, so they must
// never reach a numeric comparison (NaN would scramble the whole sort).
const LEVEL_RANK = { expired: 0, missing: 1, critical: 2, warning: 3 };
const compareAlerts = (a, b) => {
  const r = (LEVEL_RANK[a.level] ?? 9) - (LEVEL_RANK[b.level] ?? 9);
  if (r !== 0) return r;
  if (a.days === null || b.days === null) return String(a.label).localeCompare(String(b.label));
  return a.days - b.days;
};

// Compliance status for one staff record.
//
// `staff` is a profile row plus two pieces of evidence context the profile table
// does not hold: `references_count` (number) and `document_categories` (Set of
// categories whose file is present on disk). Both default to "none", so a caller
// that forgets them sees an under-stated record rather than a falsely clean one.
//
// Three states, because "never provided" and "lapsed" mean different things
// operationally:
//   incomplete — a required field or document is missing (takes precedence:
//                you cannot judge currency of evidence you do not hold)
//   expired    — everything required is present, but a dated item has passed
//   compliant  — everything present, nothing expired
//
// Returns { alerts, counts, missing, status, complete, rag }.
export function computeCompliance(staff) {
  const alerts = [];

  // 1. Dated items that have expired or are approaching expiry.
  for (const t of EXPIRY_TRACKERS) {
    const val = staff[t.key];
    const days = daysUntil(val);
    if (days === null) continue;
    const level = levelFor(days);
    if (level === 'ok') continue;
    alerts.push({ kind: 'expiry', key: t.key, label: t.label, area: t.area, date: val, days, level });
  }

  // 2. Required fields that were never filled in. Previously invisible: a blank
  //    field yields no date, so it produced no alert and left the record green.
  const missing = [];
  for (const r of REQUIRED_FIELDS) {
    const ok = r.check ? r.check(staff[r.field]) : isFilled(staff[r.field]);
    if (ok) continue;
    missing.push(r.label);
    alerts.push({ kind: 'missing', key: r.field, label: r.label, area: r.area, date: '', days: null, level: 'missing' });
  }

  // 3. Required documents with no file present.
  const present = staff.document_categories instanceof Set
    ? staff.document_categories
    : new Set(staff.document_categories || []);
  for (const d of REQUIRED_DOCUMENTS) {
    if (present.has(d.category)) continue;
    missing.push(d.label);
    alerts.push({ kind: 'missing', key: `doc:${d.category}`, label: d.label, area: 'Documents', date: '', days: null, level: 'missing' });
  }

  alerts.sort(compareAlerts);
  const counts = {
    expired: alerts.filter((a) => a.level === 'expired').length,
    critical: alerts.filter((a) => a.level === 'critical').length,
    warning: alerts.filter((a) => a.level === 'warning').length,
    missing: missing.length,
  };
  const status = counts.missing ? 'incomplete' : counts.expired ? 'expired' : 'compliant';
  // Colour token for the UI. 'incomplete' is its own colour, not amber: a file
  // with no DBS on it must not read as "nearly fine".
  const rag = status === 'incomplete' ? 'incomplete'
    : status === 'expired' ? 'red'
    : counts.critical ? 'amber' : 'green';
  return { alerts, counts, missing, status, complete: counts.missing === 0, rag };
}

// True when this record's Right to Work position needs immediate attention —
// either the review date has passed or the check was never completed. Surfaced
// prominently on the record itself, not only in the alerts list: continuing to
// employ someone without a valid check is an illegal-working risk.
export function rightToWorkRisk(staff) {
  const days = daysUntil(staff.right_to_work_expiry);
  if (days !== null && days < 0) return { level: 'overdue', days: -days };
  if (!isFilled(staff.right_to_work_type)) return { level: 'no_basis', days: null };
  if (String(staff.right_to_work_status || '').toLowerCase() !== 'confirmed') return { level: 'unconfirmed', days: null };
  return null;
}
