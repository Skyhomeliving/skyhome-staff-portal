// seed.js — seed the admin account, and (in dev) some synthetic staff so the
// dashboard/alerts have data. No real PII is used here.
import { db } from './db.js';
import { hashPassword } from './auth.js';

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
  const email = 'admin@skyhomeliving.co.uk';
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) return;
  const pw = process.env.ADMIN_SEED_PASSWORD;
  if (!pw) { console.warn('[seed] ADMIN_SEED_PASSWORD not set — skipping admin seed'); return; }
  createUser({ email, password: pw, role: 'admin', name: 'Sky Home Living Admin' });
  console.log('[seed] admin created:', email);
}

export function seedDemo() {
  if (db.prepare('SELECT COUNT(*) n FROM users').get().n > 1) return;
  const iso = (off) => { const d = new Date(); d.setDate(d.getDate() + off); return d.toISOString().slice(0, 10); };
  createUser({ email: 'manager@demo.local', password: 'demo', role: 'manager', name: 'Pat Morgan' });
  const samples = [
    { name: 'Aisha Khan', job: 'Care Worker', role: 'carer', rtw: iso(400), dbs: iso(-20), visa: '', fa: iso(18), mand: iso(220), drives: 1, dl: iso(900) },
    { name: 'Bilal Shafiq', job: 'Senior Carer', role: 'carer', rtw: iso(110), dbs: iso(300), visa: iso(40), fa: iso(-6), mand: iso(25), drives: 0, dl: '' },
    { name: 'Grace Okafor', job: 'Support Worker', role: 'support_worker', rtw: iso(900), dbs: iso(540), visa: '', fa: iso(360), mand: iso(360), drives: 1, dl: iso(50) },
  ];
  for (const s of samples) {
    const id = createUser({ email: `${s.name.split(' ')[0].toLowerCase()}@demo.local`, password: 'demo', role: s.role || 'carer', name: s.name });
    db.prepare(`UPDATE profiles SET full_name=?, job_title=?, dbs_status='Clear', right_to_work_status='Confirmed',
      right_to_work_expiry=?, dbs_expiry=?, visa_expiry=?, is_sponsored=?, first_aid_expiry=?, mandatory_training_expiry=?,
      drives_for_work=?, driving_licence_expiry=? WHERE user_id=?`)
      .run(s.name, s.job, s.rtw, s.dbs, s.visa, s.visa ? 1 : 0, s.fa, s.mand, s.drives, s.dl, id);
  }
  console.log('[seed] demo staff created');
}
