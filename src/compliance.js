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
export function daysUntil(dateStr) {
  if (!dateStr) return null;
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return null;
  return Math.floor((d.getTime() - Date.now()) / 86400000);
}

export function levelFor(days) {
  if (days === null) return null;
  if (days < 0) return 'expired';
  if (days <= 30) return 'critical';
  if (days <= 60) return 'warning';
  return 'ok';
}

// Returns { alerts:[{label,area,date,days,level}], counts, rag }
export function computeCompliance(profile) {
  const alerts = [];
  for (const t of EXPIRY_TRACKERS) {
    const val = profile[t.key];
    const days = daysUntil(val);
    if (days === null) continue;
    const level = levelFor(days);
    if (level === 'ok') continue;
    alerts.push({ label: t.label, area: t.area, date: val, days, level });
  }
  alerts.sort((a, b) => a.days - b.days);
  const counts = {
    expired: alerts.filter((a) => a.level === 'expired').length,
    critical: alerts.filter((a) => a.level === 'critical').length,
    warning: alerts.filter((a) => a.level === 'warning').length,
  };
  const rag = counts.expired ? 'red' : counts.critical ? 'amber' : 'green';
  return { alerts, counts, rag };
}
