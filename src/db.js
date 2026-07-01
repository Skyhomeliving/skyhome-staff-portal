// db.js — SQLite data layer for the Sky Home Living staff compliance portal.
// Uses Node's built-in sqlite (no native build). Schema is a superset of the
// legacy portal's tables so the recovered data imports cleanly, then is
// extended with the full NHS/CQC/Home Office compliance field set.

import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';

export const DATA_DIR = process.env.DATA_DIR || path.resolve('data');
fs.mkdirSync(DATA_DIR, { recursive: true });
export const DB_PATH = path.join(DATA_DIR, 'data.db');
export const UPLOADS_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(UPLOADS_DIR, { recursive: true });
export const PHOTOS_DIR = path.join(DATA_DIR, 'photos');
fs.mkdirSync(PHOTOS_DIR, { recursive: true });

export const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');

// --- Base tables (legacy-compatible: identical names/columns to the recovered DB) ---
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'staff',          -- admin | manager | staff
    created_at INTEGER NOT NULL,
    name TEXT                                     -- legacy column, kept for compatibility
  );

  CREATE TABLE IF NOT EXISTS profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL DEFAULT '',
    preferred_name TEXT NOT NULL DEFAULT '',
    date_of_birth TEXT NOT NULL DEFAULT '',
    ni_number TEXT NOT NULL DEFAULT '',
    job_title TEXT NOT NULL DEFAULT '',
    department TEXT NOT NULL DEFAULT '',
    location TEXT NOT NULL DEFAULT '',
    start_date TEXT NOT NULL DEFAULT '',
    employment_type TEXT NOT NULL DEFAULT '',
    line_manager TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL DEFAULT '',
    emergency_contact_name TEXT NOT NULL DEFAULT '',
    emergency_contact_phone TEXT NOT NULL DEFAULT '',
    home_address TEXT NOT NULL DEFAULT '',
    right_to_work_status TEXT NOT NULL DEFAULT '',
    right_to_work_expiry TEXT NOT NULL DEFAULT '',
    right_to_work_type TEXT NOT NULL DEFAULT '',
    dbs_status TEXT NOT NULL DEFAULT '',
    dbs_certificate_number TEXT NOT NULL DEFAULT '',
    dbs_issue_date TEXT NOT NULL DEFAULT '',
    dbs_update_service TEXT NOT NULL DEFAULT '',
    care_certificate_status TEXT NOT NULL DEFAULT '',
    care_certificate_date TEXT NOT NULL DEFAULT '',
    mandatory_training_date TEXT NOT NULL DEFAULT '',
    mandatory_training_expiry TEXT NOT NULL DEFAULT '',
    safeguarding_training_date TEXT NOT NULL DEFAULT '',
    safeguarding_training_expiry TEXT NOT NULL DEFAULT '',
    moving_handling_date TEXT NOT NULL DEFAULT '',
    moving_handling_expiry TEXT NOT NULL DEFAULT '',
    medication_training_date TEXT NOT NULL DEFAULT '',
    medication_training_expiry TEXT NOT NULL DEFAULT '',
    first_aid_date TEXT NOT NULL DEFAULT '',
    first_aid_expiry TEXT NOT NULL DEFAULT '',
    last_supervision_date TEXT NOT NULL DEFAULT '',
    last_appraisal_date TEXT NOT NULL DEFAULT '',
    references_received TEXT NOT NULL DEFAULT '',
    qualifications TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    photo_path TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    updated_at INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    file_path TEXT NOT NULL,
    mime_type TEXT NOT NULL DEFAULT '',
    expiry_date TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',       -- pending | approved | rejected
    uploaded_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS invite_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL,
    full_name TEXT NOT NULL DEFAULT '',
    job_title TEXT NOT NULL DEFAULT '',
    created_by_email TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER,
    used_at INTEGER,
    used_by_user_id INTEGER
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id INTEGER,
    actor_email TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    target_user_id INTEGER,
    details TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
  );

  -- New: structured employment history (CQC Schedule 3 — full history + gaps)
  CREATE TABLE IF NOT EXISTS employment_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    employer TEXT NOT NULL DEFAULT '',
    job_title TEXT NOT NULL DEFAULT '',
    from_date TEXT NOT NULL DEFAULT '',
    to_date TEXT NOT NULL DEFAULT '',
    is_care_role INTEGER NOT NULL DEFAULT 0,
    reason_for_leaving TEXT NOT NULL DEFAULT '',
    gap_explanation TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
  );

  -- New: references (CQC Schedule 3 — at least two, inc. most recent employer)
  CREATE TABLE IF NOT EXISTS reference_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    referee_name TEXT NOT NULL DEFAULT '',
    referee_org TEXT NOT NULL DEFAULT '',
    relationship TEXT NOT NULL DEFAULT '',
    referee_email TEXT NOT NULL DEFAULT '',
    is_most_recent_employer INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'requested',     -- requested | received | rejected
    requested_at TEXT NOT NULL DEFAULT '',
    received_at TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS app_meta (
    key TEXT PRIMARY KEY,
    value TEXT
  );

  -- Single-use password-reset tokens (self-service "forgot password")
  CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
  );
`);

// --- Additive compliance columns on profiles (driving licence, Home Office
//     sponsorship, professional registration, health). Added idempotently so the
//     legacy recovered DB upgrades in place on first boot. ---
const NEW_PROFILE_COLUMNS = {
  // Driving licence (community care staff who drive)
  driving_licence_number: "TEXT NOT NULL DEFAULT ''",
  driving_licence_categories: "TEXT NOT NULL DEFAULT ''",
  driving_licence_expiry: "TEXT NOT NULL DEFAULT ''",
  driving_check_code: "TEXT NOT NULL DEFAULT ''",          // DVLA share code
  drives_for_work: "INTEGER NOT NULL DEFAULT 0",
  business_insurance_expiry: "TEXT NOT NULL DEFAULT ''",
  // Home Office / sponsored worker
  is_sponsored: "INTEGER NOT NULL DEFAULT 0",
  share_code: "TEXT NOT NULL DEFAULT ''",                  // RTW online share code
  share_code_checked_date: "TEXT NOT NULL DEFAULT ''",
  passport_number: "TEXT NOT NULL DEFAULT ''",
  passport_expiry: "TEXT NOT NULL DEFAULT ''",
  visa_type: "TEXT NOT NULL DEFAULT ''",
  visa_expiry: "TEXT NOT NULL DEFAULT ''",
  brp_number: "TEXT NOT NULL DEFAULT ''",
  brp_expiry: "TEXT NOT NULL DEFAULT ''",
  cos_reference: "TEXT NOT NULL DEFAULT ''",               // Certificate of Sponsorship
  // DBS extras
  dbs_type: "TEXT NOT NULL DEFAULT ''",                    // enhanced + barred list(s)
  dbs_expiry: "TEXT NOT NULL DEFAULT ''",
  // Professional registration (e.g. NMC/HCPC)
  professional_reg_body: "TEXT NOT NULL DEFAULT ''",
  professional_reg_number: "TEXT NOT NULL DEFAULT ''",
  professional_reg_expiry: "TEXT NOT NULL DEFAULT ''",
  // Health / fitness to work
  health_declaration_status: "TEXT NOT NULL DEFAULT ''",
  health_declaration_date: "TEXT NOT NULL DEFAULT ''",
  occupational_health_status: "TEXT NOT NULL DEFAULT ''",
  occupational_health_date: "TEXT NOT NULL DEFAULT ''",
};

function ensureColumns(table, columns) {
  const existing = new Set(db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name));
  for (const [name, def] of Object.entries(columns)) {
    if (!existing.has(name)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${def}`);
  }
}

// Legacy DBs may also be missing some base columns (e.g. users.name); reconcile both.
function reconcileSchema() {
  ensureColumns('users', {
    name: 'TEXT',
    failed_logins: 'INTEGER NOT NULL DEFAULT 0',
    locked_until: 'INTEGER NOT NULL DEFAULT 0',
    last_login_at: 'INTEGER NOT NULL DEFAULT 0',
    must_change_password: 'INTEGER NOT NULL DEFAULT 0',
  });
  ensureColumns('profiles', NEW_PROFILE_COLUMNS);
  ensureColumns('invite_codes', { role: "TEXT NOT NULL DEFAULT 'carer'" });
  ensureColumns('documents', {
    reviewed_by_email: "TEXT NOT NULL DEFAULT ''",
    reviewed_at: 'INTEGER NOT NULL DEFAULT 0',
    review_note: "TEXT NOT NULL DEFAULT ''",
  });
  db.exec('CREATE INDEX IF NOT EXISTS idx_documents_user ON documents(user_id)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_emphist_user ON employment_history(user_id)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_resets_token ON password_resets(token)');
  // Migrate the legacy 'staff' role to the new 'carer' frontline role.
  db.exec("UPDATE users SET role='carer' WHERE role='staff'");
}
reconcileSchema();

export function tableNames() {
  return db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").all().map((r) => r.name);
}
export function profileColumns() {
  return db.prepare('PRAGMA table_info(profiles)').all().map((c) => c.name);
}
