// seed.js — seed the admin account, and (in dev) some synthetic staff so the
// dashboard/alerts have data. No real PII is used here.
import fs from 'node:fs';
import path from 'node:path';
import { db, UPLOADS_DIR } from './db.js';
import { hashPassword } from './auth.js';
import { ORG } from './org.js';

export function createUser({ email, password, role = 'staff', name = '' }) {
  const now = Date.now();
  const info = db.prepare('INSERT INTO users (email,password,role,created_at,name) VALUES (?,?,?,?,?)')
    .run(email.toLowerCase(), hashPassword(password), role, now, name);
  const id = Number(info.lastInsertRowid);
  db.prepare('INSERT INTO profiles (user_id, full_name, status, updated_at) VALUES (?,?,?,?)')
    .run(id, name, 'active', now);
  return id;
}

export function seedAdmin() {
  const email = ORG.adminEmail;
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) return;
  const pw = process.env.ADMIN_SEED_PASSWORD;
  if (!pw) { console.warn('[seed] ADMIN_SEED_PASSWORD not set — skipping admin seed'); return; }
  createUser({ email, password: pw, role: 'admin', name: `${ORG.name} Admin` });
  console.log('[seed] admin created:', email);
}

export function seedDemo() {
  if (db.prepare('SELECT COUNT(*) n FROM users').get().n > 1) return;
  const iso = (off) => { const d = new Date(); d.setDate(d.getDate() + off); return d.toISOString().slice(0, 10); };
  // Demo logins come from the environment; defaults keep the original local-dev values.
  const managerEmail = process.env.DEMO_MANAGER_EMAIL || 'manager@demo.local';
  const password = process.env.DEMO_PASSWORD || 'demo';
  const staffDomain = process.env.DEMO_STAFF_DOMAIN || 'demo.local';
  createUser({ email: managerEmail, password, role: 'manager', name: 'Sam Taylor' });
  // Fictional staff with a realistic spread of issues: expired DBS, visa due, training overdue/due.
  const samples = [
    { name: 'Aisha Khan', job: 'Care Worker', role: 'carer', rtw: iso(400), dbs: iso(-20), visa: '', fa: iso(18), mand: iso(220), sg: iso(300), mh: iso(150), med: iso(200), drives: 1, dl: iso(900) },
    { name: 'Tomasz Nowak', job: 'Senior Carer', role: 'carer', rtw: iso(110), dbs: iso(300), visa: iso(40), fa: iso(-6), mand: iso(25), sg: iso(90), mh: iso(20), med: iso(120), drives: 0, dl: '' },
    { name: 'Grace Adeyemi', job: 'Support Worker', role: 'support_worker', rtw: iso(900), dbs: iso(540), visa: '', fa: iso(360), mand: iso(360), sg: iso(330), mh: iso(280), med: iso(300), drives: 1, dl: iso(50) },
    { name: 'Priya Sharma', job: 'Care Worker', role: 'carer', rtw: iso(700), dbs: iso(420), visa: iso(700), fa: iso(240), mand: iso(-12), sg: iso(200), mh: iso(-3), med: iso(160), drives: 1, dl: iso(1200) },
    { name: 'Daniel Brooks', job: 'Care Coordinator', role: 'carer', rtw: iso(1500), dbs: iso(600), visa: '', fa: iso(500), mand: iso(400), sg: iso(380), mh: iso(410), med: iso(350), drives: 1, dl: iso(2000) },
    { name: 'Kwame Mensah', job: 'Senior Carer', role: 'carer', rtw: iso(75), dbs: iso(260), visa: iso(75), fa: iso(120), mand: iso(140), sg: iso(10), mh: iso(190), med: iso(85), drives: 1, dl: iso(25) },
    { name: 'Ewa Kowalska', job: 'Care Worker', role: 'carer', rtw: iso(1000), dbs: iso(30), visa: '', fa: iso(210), mand: iso(260), sg: iso(240), mh: iso(230), med: iso(-30), drives: 0, dl: '' },
    { name: 'Liam Carter', job: 'Care Worker', role: 'carer', rtw: iso(1800), dbs: iso(700), visa: '', fa: iso(330), mand: iso(300), sg: iso(320), mh: iso(310), med: iso(290), drives: 1, dl: iso(1500) },
  ];
  for (const s of samples) {
    const [first, last] = s.name.toLowerCase().split(' ');
    const id = createUser({ email: `${first}.${last}@${staffDomain}`, password, role: s.role || 'carer', name: s.name });
    db.prepare(`UPDATE profiles SET full_name=?, job_title=?, dbs_status='Clear', right_to_work_status='Confirmed',
      right_to_work_expiry=?, dbs_expiry=?, visa_expiry=?, is_sponsored=?, first_aid_expiry=?, mandatory_training_expiry=?,
      safeguarding_training_expiry=?, moving_handling_expiry=?, medication_training_expiry=?,
      drives_for_work=?, driving_licence_expiry=? WHERE user_id=?`)
      .run(s.name, s.job, s.rtw, s.dbs, s.visa, s.visa ? 1 : 0, s.fa, s.mand, s.sg, s.mh, s.med, s.drives, s.dl, id);
    completeDemoRecord(id, iso, { references: s.name === 'Ewa Kowalska' ? 1 : 2 });
  }
  const manager = db.prepare('SELECT id FROM users WHERE email=?').get(managerEmail.toLowerCase());
  if (manager) {
    db.prepare(`UPDATE profiles SET job_title='Registered Manager', dbs_status='Clear', right_to_work_status='Confirmed',
      right_to_work_expiry=?, dbs_expiry=?, first_aid_expiry=?, mandatory_training_expiry=? WHERE user_id=?`)
      .run(iso(2000), iso(500), iso(400), iso(300), manager.id);
    completeDemoRecord(manager.id, iso, { references: 2 });
  }
  console.log('[seed] demo staff created');
}


// Fills in the evidence a complete record needs (see REQUIRED_FIELDS / REQUIRED_DOCUMENTS
// in compliance.js) with fictional values, and stores small placeholder PDFs marked as
// sample documents. Demo installations only.
const SAMPLE_PDF = Buffer.from([
  '%PDF-1.4',
  '1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj',
  '2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj',
  '3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj',
  '4 0 obj<</Length 60>>stream',
  'BT /F1 18 Tf 60 760 Td (SAMPLE - fictional demo document) Tj ET',
  'endstream endobj',
  '5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj',
  'trailer<</Root 1 0 R>>',
  '%%EOF',
  '',
].join('\n'));

function completeDemoRecord(userId, iso, { references = 2 } = {}) {
  db.prepare(`UPDATE profiles SET dbs_certificate_number=?, dbs_issue_date=?, dbs_type='Enhanced + barred',
    right_to_work_type=CASE WHEN is_sponsored=1 THEN 'Sponsored worker' ELSE 'British/Irish citizen' END,
    care_certificate_status='Completed', care_certificate_date=?, health_declaration_status='Received',
    health_declaration_date=?, last_supervision_date=?, last_appraisal_date=?, start_date=? WHERE user_id=?`)
    .run(`00${String(1000000000 + userId * 7919).slice(-10)}`, iso(-400), iso(-380), iso(-390), iso(-35), iso(-160), iso(-420), userId);
  const now = Date.now();
  for (let i = 0; i < references; i++) {
    db.prepare(`INSERT INTO reference_checks (user_id, referee_name, referee_org, relationship, status, received_at, created_at)
      VALUES (?,?,?,?,'received',?,?)`).run(userId, i ? 'Sample Referee B' : 'Sample Referee A', 'Previous employer (sample)', 'Line manager', iso(-410), now);
  }
  for (const [category, title] of [['dbs_certificate', 'DBS certificate (sample)'], ['right_to_work', 'Right to Work evidence (sample)']]) {
    const file = `demo-${userId}-${category}.pdf`;
    fs.writeFileSync(path.join(UPLOADS_DIR, file), SAMPLE_PDF);
    db.prepare(`INSERT INTO documents (user_id, category, title, file_path, mime_type, status, uploaded_at)
      VALUES (?,?,?,?,'application/pdf','approved',?)`).run(userId, category, title, file, now);
  }
}
