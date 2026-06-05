// server.js — Express app for the Sky Home Living staff compliance portal.
import express from 'express';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import path from 'node:path';
import fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { db, UPLOADS_DIR } from './db.js';
import {
  hashPassword, verifyPassword, createSession, destroySession, setSessionCookie,
  attachUser, requireAuth, requireRole, canAccessStaff, audit, SESSION_COOKIE,
} from './auth.js';
import {
  PROFILE_SECTIONS, PROFILE_KEYS, DOCUMENT_CATEGORIES, categoryLabel, computeCompliance,
} from './compliance.js';
import { seedAdmin, seedDemo } from './seed.js';
import { layout, loginPage, esc, fmtDate, ragBadge, levelBadge, initials, roleLabel, icon } from './views.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const app = express();
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(ROOT, 'public')));

// ---- data helpers ----------------------------------------------------------
const getUser = (id) => db.prepare('SELECT * FROM users WHERE id=?').get(id);
const getUserByEmail = (e) => db.prepare('SELECT * FROM users WHERE email=?').get(String(e).toLowerCase());
const getProfile = (uid) => db.prepare('SELECT * FROM profiles WHERE user_id=?').get(uid) || {};
const listStaff = () => db.prepare(`SELECT u.id,u.email,u.role,p.* FROM users u
  LEFT JOIN profiles p ON p.user_id=u.id WHERE u.role IN ('staff','manager') ORDER BY p.full_name, u.email`).all();
const listDocs = (uid) => db.prepare('SELECT * FROM documents WHERE user_id=? ORDER BY uploaded_at DESC').all(uid);
const listEmployment = (uid) => db.prepare('SELECT * FROM employment_history WHERE user_id=? ORDER BY from_date DESC, id DESC').all(uid);
const listReferences = (uid) => db.prepare('SELECT * FROM reference_checks WHERE user_id=? ORDER BY created_at DESC').all(uid);

seedAdmin();
if (process.env.SEED_DEMO === '1') seedDemo();

app.use(attachUser);
app.get('/healthz', (_req, res) => res.type('text').send('ok'));

// ---- auth ------------------------------------------------------------------
app.get('/login', (req, res) => res.send(loginPage({ message: req.query.registered ? 'Account created — please sign in.' : '' })));
app.post('/login', (req, res) => {
  const u = getUserByEmail(req.body.email);
  if (!u || !verifyPassword(req.body.password || '', u.password))
    return res.status(401).send(loginPage({ error: 'Incorrect email or password.' }));
  const token = createSession(u.id); setSessionCookie(res, token); audit(u, 'login');
  res.redirect('/');
});
app.get('/logout', (req, res) => { destroySession(req.cookies?.[SESSION_COOKIE]); res.clearCookie(SESSION_COOKIE, { path: '/' }); res.redirect('/login'); });

// ---- registration via invite ----------------------------------------------
app.get('/register', (req, res) => res.send(registerPage({})));
app.post('/register', (req, res) => {
  const code = String(req.body.code || '').trim().toUpperCase();
  const email = String(req.body.email || '').trim().toLowerCase();
  const inv = db.prepare('SELECT * FROM invite_codes WHERE code=?').get(code);
  if (!inv || inv.email.toLowerCase() !== email) return res.status(400).send(registerPage({ error: 'Invite code and email do not match.' }));
  if (inv.used_at) return res.status(400).send(registerPage({ error: 'This invite code has already been used.' }));
  if (inv.expires_at && inv.expires_at < Date.now()) return res.status(400).send(registerPage({ error: 'This invite code has expired.' }));
  if (getUserByEmail(email)) return res.status(400).send(registerPage({ error: 'An account with this email already exists.' }));
  if ((req.body.password || '').length < 8) return res.status(400).send(registerPage({ error: 'Choose a password of at least 8 characters.', code, email }));
  const now = Date.now();
  const info = db.prepare('INSERT INTO users (email,password,role,created_at,name) VALUES (?,?,?,?,?)')
    .run(email, hashPassword(req.body.password), 'staff', now, inv.full_name || '');
  const uid = Number(info.lastInsertRowid);
  db.prepare('INSERT INTO profiles (user_id, full_name, job_title, status, updated_at) VALUES (?,?,?,?,?)')
    .run(uid, inv.full_name || '', inv.job_title || '', 'active', now);
  db.prepare('UPDATE invite_codes SET used_at=?, used_by_user_id=? WHERE id=?').run(now, uid, inv.id);
  audit({ id: uid, email }, 'register');
  res.redirect('/login?registered=1');
});

// ---- dashboard -------------------------------------------------------------
app.get('/', requireAuth, (req, res) => {
  if (req.user.role === 'staff') return res.redirect(`/staff/${req.user.id}`);
  const staff = listStaff();
  const rows = staff.map((s) => ({ ...s, c: computeCompliance(s) }));
  const tot = { red: 0, amber: 0, green: 0, expired: 0, critical: 0 };
  for (const r of rows) { tot[r.c.rag]++; tot.expired += r.c.counts.expired; tot.critical += r.c.counts.critical; }
  const attention = rows.filter((r) => r.c.rag !== 'green')
    .sort((a, b) => (b.c.counts.expired - a.c.counts.expired) || (b.c.counts.critical - a.c.counts.critical));

  const body = `
  <div class="page-head"><div><h1>Compliance dashboard</h1>
    <p class="muted">${staff.length} staff · live view of DBS, Right to Work, training and renewals</p></div></div>
  <div class="grid cols-4" style="margin-bottom:1.2rem">
    <div class="stat"><div class="n">${staff.length}</div><div class="l">Staff on file</div></div>
    <div class="stat red"><div class="n">${tot.red}</div><div class="l">Action needed</div></div>
    <div class="stat amber"><div class="n">${tot.amber}</div><div class="l">Renewing soon</div></div>
    <div class="stat green"><div class="n">${tot.green}</div><div class="l">Fully compliant</div></div>
  </div>
  <div class="card"><div class="card-h">Needs attention
    <a class="btn ghost sm" href="/alerts">View all alerts</a></div>
    <div class="card-b" style="padding:0">
    ${attention.length ? `<table class="tbl"><thead><tr><th>Staff</th><th>Role</th><th>Status</th><th>Soonest issue</th></tr></thead><tbody>
      ${attention.slice(0, 12).map((r) => {
        const a = r.c.alerts[0];
        return `<tr onclick="location='/staff/${r.id}'" style="cursor:pointer">
          <td><b>${esc(r.full_name || r.email)}</b></td>
          <td>${esc(r.job_title || roleLabel(r.role))}</td>
          <td>${ragBadge(r.c.rag)}</td>
          <td>${a ? `${esc(a.label)} — ${a.days < 0 ? `expired ${-a.days}d ago` : `in ${a.days}d`}` : '—'}</td></tr>`;
      }).join('')}
    </tbody></table>` : `<div class="card-b muted">Everyone is compliant. 🎉</div>`}
    </div></div>`;
  res.send(layout({ user: req.user, title: 'Dashboard', active: '/', body, scripts: '' }));
});

// ---- staff list ------------------------------------------------------------
app.get('/staff', requireRole('admin', 'manager'), (req, res) => {
  const q = String(req.query.q || '').toLowerCase();
  let rows = listStaff().map((s) => ({ ...s, c: computeCompliance(s) }));
  if (q) rows = rows.filter((r) => `${r.full_name} ${r.email} ${r.job_title}`.toLowerCase().includes(q));
  const body = `
  <div class="page-head"><div><h1>Staff records</h1><p class="muted">${rows.length} shown</p></div>
    <a class="btn" href="/admin/invites">${icon('invite')} Invite staff</a></div>
  <form class="card" style="margin-bottom:1rem"><div class="card-b" style="display:flex;gap:.6rem">
    <input name="q" value="${esc(req.query.q || '')}" placeholder="Search name, email or job title" style="flex:1;padding:.5rem .6rem;border:1px solid var(--line);border-radius:8px">
    <button class="btn ghost">Search</button></div></form>
  <div class="card"><div class="card-b" style="padding:0">
  <table class="tbl"><thead><tr><th>Name</th><th>Job title</th><th>DBS</th><th>Right to Work</th><th>Status</th></tr></thead><tbody>
  ${rows.map((r) => `<tr onclick="location='/staff/${r.id}'" style="cursor:pointer">
    <td><div style="display:flex;align-items:center;gap:.55rem"><div class="avatar">${initials(r.full_name || r.email)}</div>
      <div><b>${esc(r.full_name || '—')}</b><div class="muted small">${esc(r.email)}</div></div></div></td>
    <td>${esc(r.job_title || '—')}</td>
    <td>${esc(r.dbs_status || '—')}</td>
    <td>${esc(r.right_to_work_status || '—')}${r.is_sponsored ? ' <span class="badge blue">Sponsored</span>' : ''}</td>
    <td>${ragBadge(r.c.rag)}</td></tr>`).join('') || '<tr><td colspan="5" class="muted" style="padding:1rem">No staff yet.</td></tr>'}
  </tbody></table></div></div>`;
  res.send(layout({ user: req.user, title: 'Staff', active: '/staff', body }));
});

// ---- profile view ----------------------------------------------------------
function renderViewField(f, val) {
  let disp;
  if (f.type === 'checkbox') disp = val ? 'Yes' : 'No';
  else if (f.type === 'date') disp = fmtDate(val);
  else disp = val ? esc(val) : '<span class="muted">—</span>';
  return `<div class="field"><label>${esc(f.label)}</label><div>${disp}</div></div>`;
}
function renderEditField(f, val) {
  const id = `f_${f.key}`;
  if (f.type === 'checkbox')
    return `<div class="checkrow"><input type="checkbox" id="${id}" name="${f.key}" value="1" ${val ? 'checked' : ''}><label for="${id}">${esc(f.label)}</label></div>`;
  let input;
  if (f.type === 'select')
    input = `<select name="${f.key}">${f.options.map((o) => `<option ${String(val) === o ? 'selected' : ''} value="${esc(o)}">${o ? esc(o) : '—'}</option>`).join('')}</select>`;
  else if (f.type === 'textarea')
    input = `<textarea name="${f.key}">${esc(val || '')}</textarea>`;
  else
    input = `<input name="${f.key}" type="${f.type === 'tel' ? 'tel' : f.type === 'date' ? 'date' : 'text'}" value="${esc(val || '')}">`;
  return `<div class="field"><label>${esc(f.label)}</label>${input}</div>`;
}

app.get('/staff/:id', requireAuth, (req, res) => {
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send('Forbidden');
  const u = getUser(req.params.id); if (!u) return res.status(404).send('Not found');
  const p = getProfile(u.id); const c = computeCompliance(p); const docs = listDocs(u.id);
  const emp = listEmployment(u.id); const refs = listReferences(u.id);
  const canEdit = req.user.role === 'admin' || req.user.role === 'manager' || req.user.id === u.id;
  const sectNav = PROFILE_SECTIONS.map((s) => `<a href="#${s.id}">${esc(s.title)}</a>`).join('');
  const sections = PROFILE_SECTIONS.map((s) => `
    <div class="card" id="${s.id}" style="margin-bottom:1rem"><div class="card-h">${esc(s.title)}</div>
      <div class="card-b"><div class="form-grid">
      ${s.fields.map((f) => renderViewField(f, p[f.key])).join('')}
      </div></div></div>`).join('');

  const docRows = docs.map((d) => `<tr>
    <td>${esc(categoryLabel(d.category))}</td><td>${esc(d.title || '—')}</td>
    <td>${d.expiry_date ? fmtDate(d.expiry_date) : '—'}</td>
    <td><a href="/documents/${d.id}">View</a>${canEdit ? ` · <a href="/documents/${d.id}/delete" onclick="return confirm('Delete this document?')">Delete</a>` : ''}</td></tr>`).join('');

  const body = `
  <div class="page-head">
    <div style="display:flex;align-items:center;gap:.8rem"><div class="avatar" style="width:46px;height:46px;font-size:1rem">${initials(p.full_name || u.email)}</div>
      <div><h1 style="margin:0">${esc(p.full_name || u.email)}</h1>
      <p class="muted" style="margin:0">${esc(p.job_title || roleLabel(u.role))} · ${esc(u.email)}</p></div></div>
    <div style="display:flex;gap:.5rem;align-items:center">${ragBadge(c.rag)}
      ${canEdit ? `<a class="btn" href="/staff/${u.id}/edit">Edit record</a>` : ''}</div>
  </div>
  ${c.alerts.length ? `<div class="card" style="margin-bottom:1rem"><div class="card-h">Renewals & alerts</div><div class="card-b" style="padding:0">
    <table class="tbl"><tbody>${c.alerts.map((a) => `<tr><td>${esc(a.label)}</td><td class="muted">${esc(a.area)}</td>
      <td>${fmtDate(a.date)}</td><td>${levelBadge(a.level, a.days < 0 ? `Expired ${-a.days}d ago` : `${a.days}d left`)}</td></tr>`).join('')}</tbody></table></div></div>` : ''}
  <div class="card" style="margin-bottom:1rem"><div class="card-h">Documents
    ${canEdit ? `<a class="btn ghost sm" href="/staff/${u.id}/edit#documents">Upload</a>` : ''}</div>
    <div class="card-b" style="padding:0">${docs.length ? `<table class="tbl"><thead><tr><th>Type</th><th>Title</th><th>Expiry</th><th></th></tr></thead><tbody>${docRows}</tbody></table>` : '<div class="card-b muted">No documents uploaded yet.</div>'}</div></div>
  <div class="card" style="margin-bottom:1rem"><div class="card-h">Employment history <span class="muted small">CQC Schedule 3</span></div>
    <div class="card-b" style="padding:0">
    <table class="tbl"><thead><tr><th>Employer</th><th>Role</th><th>From</th><th>To</th><th>Care role</th><th>Reason for leaving</th>${canEdit ? '<th></th>' : ''}</tr></thead><tbody>
    ${emp.map((e) => `<tr><td><b>${esc(e.employer)}</b>${e.gap_explanation ? `<div class="muted small">Gap: ${esc(e.gap_explanation)}</div>` : ''}</td><td>${esc(e.job_title)}</td><td>${fmtDate(e.from_date)}</td><td>${e.to_date ? fmtDate(e.to_date) : 'Present'}</td><td>${e.is_care_role ? '<span class="badge blue">Care</span>' : '—'}</td><td class="muted">${esc(e.reason_for_leaving)}</td>${canEdit ? `<td><a href="/staff/${u.id}/employment/${e.id}/delete" onclick="return confirm('Delete this entry?')">Delete</a></td>` : ''}</tr>`).join('') || `<tr><td colspan="${canEdit ? 7 : 6}" class="muted" style="padding:1rem">No employment history recorded.</td></tr>`}
    </tbody></table>
    ${canEdit ? `<form method="post" action="/staff/${u.id}/employment" class="card-b" style="border-top:1px solid var(--line-2)"><div class="form-grid">
      <div class="field"><label>Employer</label><input name="employer" required></div>
      <div class="field"><label>Role</label><input name="job_title"></div>
      <div class="field"><label>From</label><input type="date" name="from_date"></div>
      <div class="field"><label>To (blank = current)</label><input type="date" name="to_date"></div>
      <div class="field"><label>Reason for leaving</label><input name="reason_for_leaving"></div>
      <div class="field"><label>Explanation of any gap</label><input name="gap_explanation"></div>
    </div><div class="checkrow"><input type="checkbox" id="care_role" name="is_care_role" value="1"><label for="care_role">Care / health &amp; social care role</label></div>
    <button class="btn sm">Add employment</button></form>` : ''}
    </div></div>
  <div class="card" style="margin-bottom:1rem"><div class="card-h">References <span class="muted small">at least two, inc. most recent employer</span></div>
    <div class="card-b" style="padding:0">
    <table class="tbl"><thead><tr><th>Referee</th><th>Organisation</th><th>Relationship</th><th>Recent employer</th><th>Status</th>${canEdit ? '<th></th>' : ''}</tr></thead><tbody>
    ${refs.map((r) => `<tr><td><b>${esc(r.referee_name)}</b></td><td>${esc(r.referee_org)}</td><td>${esc(r.relationship)}</td><td>${r.is_most_recent_employer ? 'Yes' : '—'}</td><td>${levelBadge(r.status === 'received' ? 'ok' : r.status === 'rejected' ? 'expired' : 'warning', r.status)}</td>${canEdit ? `<td><a href="/staff/${u.id}/references/${r.id}/delete" onclick="return confirm('Delete this reference?')">Delete</a></td>` : ''}</tr>`).join('') || `<tr><td colspan="${canEdit ? 6 : 5}" class="muted" style="padding:1rem">No references recorded.</td></tr>`}
    </tbody></table>
    ${canEdit ? `<form method="post" action="/staff/${u.id}/references" class="card-b" style="border-top:1px solid var(--line-2)"><div class="form-grid">
      <div class="field"><label>Referee name</label><input name="referee_name" required></div>
      <div class="field"><label>Organisation</label><input name="referee_org"></div>
      <div class="field"><label>Relationship</label><input name="relationship" placeholder="e.g. Former line manager"></div>
      <div class="field"><label>Status</label><select name="status"><option value="requested">Requested</option><option value="received">Received</option><option value="rejected">Rejected</option></select></div>
    </div><div class="checkrow"><input type="checkbox" id="recent_emp" name="is_most_recent_employer" value="1"><label for="recent_emp">Most recent employer</label></div>
    <button class="btn sm">Add reference</button></form>` : ''}
    </div></div>
  <div class="sectnav">${sectNav}</div>
  ${sections}`;
  res.send(layout({ user: req.user, title: p.full_name || 'Record', active: '/staff', body }));
});

// ---- profile edit ----------------------------------------------------------
app.get('/staff/:id/edit', requireAuth, (req, res) => {
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send('Forbidden');
  const u = getUser(req.params.id); if (!u) return res.status(404).send('Not found');
  const p = getProfile(u.id);
  const sections = PROFILE_SECTIONS.map((s) => `
    <div class="card" id="${s.id}" style="margin-bottom:1rem"><div class="card-h">${esc(s.title)}</div>
      <div class="card-b"><div class="form-grid">${s.fields.map((f) => renderEditField(f, p[f.key])).join('')}</div></div></div>`).join('');
  const cats = DOCUMENT_CATEGORIES.map((c) => `<option value="${c.value}">${esc(c.label)}</option>`).join('');
  const body = `
  <div class="page-head"><div><h1>Edit record</h1><p class="muted">${esc(p.full_name || u.email)}</p></div>
    <a class="btn ghost" href="/staff/${u.id}">Cancel</a></div>
  <form method="post" action="/staff/${u.id}">
    ${sections}
    <div style="position:sticky;bottom:0;background:linear-gradient(#fff0,#fff 40%);padding:1rem 0">
      <button class="btn" type="submit">Save changes</button>
      <a class="btn ghost" href="/staff/${u.id}">Cancel</a></div>
  </form>
  <div class="card" id="documents" style="margin:1.4rem 0"><div class="card-h">Upload a document</div><div class="card-b">
    <form method="post" action="/staff/${u.id}/documents" enctype="multipart/form-data">
      <div class="form-grid">
        <div class="field"><label>Document type</label><select name="category" required><option value="">Select…</option>${cats}</select></div>
        <div class="field"><label>Title / description</label><input name="title" placeholder="e.g. DBS certificate 2026"></div>
        <div class="field"><label>Expiry date (if any)</label><input type="date" name="expiry_date"></div>
      </div>
      <label class="dropzone" id="dz">Drag & drop a file here, or click to choose<br><span class="small">PDF, image or Word · up to 25&nbsp;MB</span>
        <input id="file" name="file" type="file" required style="display:none"
          accept=".pdf,.jpg,.jpeg,.png,.webp,.heic,.heif,.doc,.docx"></label>
      <div id="fname" class="small muted" style="margin:.5rem 0"></div>
      <button class="btn" type="submit">Upload document</button>
    </form></div></div>
  <script>
    const dz=document.getElementById('dz'),fi=document.getElementById('file'),fn=document.getElementById('fname');
    dz.addEventListener('click',()=>fi.click());
    fi.addEventListener('change',()=>fn.textContent=fi.files[0]?('Selected: '+fi.files[0].name):'');
    ['dragover','dragenter'].forEach(e=>dz.addEventListener(e,ev=>{ev.preventDefault();dz.classList.add('drag')}));
    ['dragleave','drop'].forEach(e=>dz.addEventListener(e,ev=>{ev.preventDefault();dz.classList.remove('drag')}));
    dz.addEventListener('drop',ev=>{if(ev.dataTransfer.files[0]){fi.files=ev.dataTransfer.files;fn.textContent='Selected: '+ev.dataTransfer.files[0].name;}});
  </script>`;
  res.send(layout({ user: req.user, title: 'Edit record', active: '/staff', body }));
});

app.post('/staff/:id', requireAuth, (req, res) => {
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send('Forbidden');
  const u = getUser(req.params.id); if (!u) return res.status(404).send('Not found');
  const checkboxKeys = new Set(PROFILE_SECTIONS.flatMap((s) => s.fields.filter((f) => f.type === 'checkbox').map((f) => f.key)));
  const sets = [], vals = [];
  for (const k of PROFILE_KEYS) {
    let v;
    if (checkboxKeys.has(k)) v = req.body[k] ? 1 : 0;
    else v = (req.body[k] ?? '').toString();
    sets.push(`${k}=?`); vals.push(v);
  }
  vals.push(Date.now(), u.id);
  db.prepare(`UPDATE profiles SET ${sets.join(',')}, updated_at=? WHERE user_id=?`).run(...vals);
  audit(req.user, 'update_profile', u.id);
  res.redirect(`/staff/${u.id}`);
});

// ---- documents -------------------------------------------------------------
const ALLOWED_EXT = new Set(['.pdf', '.jpg', '.jpeg', '.png', '.webp', '.heic', '.heif', '.doc', '.docx']);
const upload = multer({
  storage: multer.diskStorage({
    destination: (_q, _f, cb) => cb(null, UPLOADS_DIR),
    filename: (_q, file, cb) => {
      const safe = file.originalname.replace(/[^a-z0-9.\-_]/gi, '_');
      cb(null, `${Date.now()}-${randomBytes(4).toString('hex')}-${safe}`);
    },
  }),
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (_q, file, cb) => cb(null, ALLOWED_EXT.has(path.extname(file.originalname).toLowerCase())),
});

app.post('/staff/:id/documents', requireAuth, (req, res) => {
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send('Forbidden');
  upload.single('file')(req, res, (err) => {
    if (err) return res.status(400).send('Upload failed: ' + err.message);
    if (!req.file) return res.status(400).send('No file (allowed: PDF, image, Word).');
    db.prepare('INSERT INTO documents (user_id,category,title,file_path,mime_type,expiry_date,status,uploaded_at) VALUES (?,?,?,?,?,?,?,?)')
      .run(req.params.id, req.body.category || 'other', req.body.title || '', req.file.filename, req.file.mimetype, req.body.expiry_date || '', 'pending', Date.now());
    audit(req.user, 'upload_document', Number(req.params.id), req.body.category || '');
    res.redirect(`/staff/${req.params.id}`);
  });
});

app.get('/documents/:id', requireAuth, (req, res) => {
  const d = db.prepare('SELECT * FROM documents WHERE id=?').get(req.params.id);
  if (!d || !canAccessStaff(req.user, d.user_id)) return res.status(403).send('Forbidden');
  const fp = path.join(UPLOADS_DIR, path.basename(d.file_path));
  if (!fs.existsSync(fp)) return res.status(404).send('File missing');
  res.sendFile(fp);
});
app.get('/documents/:id/delete', requireAuth, (req, res) => {
  const d = db.prepare('SELECT * FROM documents WHERE id=?').get(req.params.id);
  if (!d || !canAccessStaff(req.user, d.user_id)) return res.status(403).send('Forbidden');
  try { fs.unlinkSync(path.join(UPLOADS_DIR, path.basename(d.file_path))); } catch {}
  db.prepare('DELETE FROM documents WHERE id=?').run(d.id);
  audit(req.user, 'delete_document', d.user_id);
  res.redirect(`/staff/${d.user_id}`);
});

// ---- employment history & references ---------------------------------------
app.post('/staff/:id/employment', requireAuth, (req, res) => {
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send('Forbidden');
  db.prepare('INSERT INTO employment_history (user_id,employer,job_title,from_date,to_date,is_care_role,reason_for_leaving,gap_explanation,created_at) VALUES (?,?,?,?,?,?,?,?,?)')
    .run(req.params.id, req.body.employer || '', req.body.job_title || '', req.body.from_date || '', req.body.to_date || '', req.body.is_care_role ? 1 : 0, req.body.reason_for_leaving || '', req.body.gap_explanation || '', Date.now());
  audit(req.user, 'add_employment', Number(req.params.id));
  res.redirect(`/staff/${req.params.id}`);
});
app.get('/staff/:id/employment/:eid/delete', requireAuth, (req, res) => {
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send('Forbidden');
  db.prepare('DELETE FROM employment_history WHERE id=? AND user_id=?').run(req.params.eid, req.params.id);
  audit(req.user, 'delete_employment', Number(req.params.id));
  res.redirect(`/staff/${req.params.id}`);
});
app.post('/staff/:id/references', requireAuth, (req, res) => {
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send('Forbidden');
  db.prepare('INSERT INTO reference_checks (user_id,referee_name,referee_org,relationship,is_most_recent_employer,status,created_at) VALUES (?,?,?,?,?,?,?)')
    .run(req.params.id, req.body.referee_name || '', req.body.referee_org || '', req.body.relationship || '', req.body.is_most_recent_employer ? 1 : 0, req.body.status || 'requested', Date.now());
  audit(req.user, 'add_reference', Number(req.params.id));
  res.redirect(`/staff/${req.params.id}`);
});
app.get('/staff/:id/references/:rid/delete', requireAuth, (req, res) => {
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send('Forbidden');
  db.prepare('DELETE FROM reference_checks WHERE id=? AND user_id=?').run(req.params.rid, req.params.id);
  audit(req.user, 'delete_reference', Number(req.params.id));
  res.redirect(`/staff/${req.params.id}`);
});

// ---- alerts ----------------------------------------------------------------
app.get('/alerts', requireRole('admin', 'manager'), (req, res) => {
  const rows = [];
  for (const s of listStaff()) for (const a of computeCompliance(s).alerts) rows.push({ s, a });
  rows.sort((x, y) => x.a.days - y.a.days);
  const body = `
  <div class="page-head"><div><h1>Compliance alerts</h1><p class="muted">${rows.length} renewals expired or due soon</p></div></div>
  <div class="card"><div class="card-b" style="padding:0">
  <table class="tbl"><thead><tr><th>Staff</th><th>Requirement</th><th>Date</th><th>Status</th></tr></thead><tbody>
  ${rows.map(({ s, a }) => `<tr onclick="location='/staff/${s.id}'" style="cursor:pointer">
    <td><b>${esc(s.full_name || s.email)}</b></td><td>${esc(a.label)} <span class="muted small">· ${esc(a.area)}</span></td>
    <td>${fmtDate(a.date)}</td><td>${levelBadge(a.level, a.days < 0 ? `Expired ${-a.days}d ago` : `${a.days}d left`)}</td></tr>`).join('')
    || '<tr><td colspan="4" class="muted" style="padding:1rem">No alerts — everyone is up to date.</td></tr>'}
  </tbody></table></div></div>`;
  res.send(layout({ user: req.user, title: 'Alerts', active: '/alerts', body }));
});

// ---- invites ---------------------------------------------------------------
app.get('/admin/invites', requireRole('admin', 'manager'), (req, res) => {
  const invites = db.prepare('SELECT * FROM invite_codes ORDER BY created_at DESC').all();
  const origin = `${req.protocol}://${req.get('host')}`;
  const body = `
  <div class="page-head"><div><h1>Invitations</h1><p class="muted">Invite a staff member to create their account</p></div></div>
  <div class="card" style="margin-bottom:1.2rem"><div class="card-b">
    <form method="post" action="/admin/invites"><div class="form-grid">
      <div class="field"><label>Email</label><input name="email" type="email" required></div>
      <div class="field"><label>Full name</label><input name="full_name"></div>
      <div class="field"><label>Job title</label><input name="job_title"></div>
    </div><button class="btn">Create invite</button></div></form></div>
  <div class="card"><div class="card-b" style="padding:0">
  <table class="tbl"><thead><tr><th>Code</th><th>Email</th><th>Expires</th><th>Status</th><th>Link</th></tr></thead><tbody>
  ${invites.map((i) => `<tr><td><code>${esc(i.code)}</code></td><td>${esc(i.email)}</td>
    <td>${i.expires_at ? fmtDate(new Date(i.expires_at).toISOString()) : '—'}</td>
    <td>${i.used_at ? '<span class="badge grey">Used</span>' : (i.expires_at && i.expires_at < Date.now() ? '<span class="badge red">Expired</span>' : '<span class="badge green">Active</span>')}</td>
    <td class="small">${esc(origin)}/register</td></tr>`).join('') || '<tr><td colspan="5" class="muted" style="padding:1rem">No invites yet.</td></tr>'}
  </tbody></table></div></div>`;
  res.send(layout({ user: req.user, title: 'Invitations', active: '/admin/invites', body }));
});
app.post('/admin/invites', requireRole('admin', 'manager'), (req, res) => {
  const code = `${rand4()}-${rand4()}-${rand4()}`;
  const now = Date.now();
  db.prepare('INSERT INTO invite_codes (code,email,full_name,job_title,created_by_email,created_at,expires_at) VALUES (?,?,?,?,?,?,?)')
    .run(code, String(req.body.email || '').toLowerCase(), req.body.full_name || '', req.body.job_title || '', req.user.email, now, now + 14 * 86400000);
  audit(req.user, 'create_invite', null, req.body.email || '');
  res.redirect('/admin/invites');
});
const rand4 = () => randomBytes(3).toString('hex').toUpperCase().slice(0, 4);

// ---- audit -----------------------------------------------------------------
app.get('/admin/audit', requireRole('admin', 'manager'), (req, res) => {
  const rows = db.prepare('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200').all();
  const body = `
  <div class="page-head"><div><h1>Audit log</h1><p class="muted">Most recent 200 actions</p></div></div>
  <div class="card"><div class="card-b" style="padding:0">
  <table class="tbl"><thead><tr><th>When</th><th>Who</th><th>Action</th><th>Details</th></tr></thead><tbody>
  ${rows.map((r) => `<tr><td class="small">${new Date(r.created_at).toLocaleString('en-GB')}</td>
    <td>${esc(r.actor_email)}</td><td>${esc(r.action)}</td><td class="muted">${esc(r.details || '')}</td></tr>`).join('')
    || '<tr><td colspan="4" class="muted" style="padding:1rem">No activity yet.</td></tr>'}
  </tbody></table></div></div>`;
  res.send(layout({ user: req.user, title: 'Audit', active: '/admin/audit', body }));
});

function registerPage({ error = '', code = '', email = '' }) {
  return loginPageShell(`
    <h1 style="margin-bottom:.2rem">Create your account</h1>
    <p class="muted" style="margin-top:0">Use the invite code from your manager</p>
    ${error ? `<div class="flash err">${esc(error)}</div>` : ''}
    <form method="post" action="/register">
      <div class="field"><label>Invite code</label><input name="code" value="${esc(code)}" required></div>
      <div class="field"><label>Email</label><input name="email" type="email" value="${esc(email)}" required></div>
      <div class="field"><label>Choose a password</label><input name="password" type="password" minlength="8" required></div>
      <button class="btn" style="width:100%;justify-content:center">Create account</button>
    </form>
    <p class="small muted" style="text-align:center;margin-top:1rem"><a href="/login">Back to sign in</a></p>`);
}
function loginPageShell(inner) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow"><title>Sky Home Living</title><link rel="stylesheet" href="/styles.css"></head>
  <body><div class="auth-wrap"><div class="auth-card"><div class="logo">SH</div>${inner}</div></div></body></html>`;
}

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Sky Home Living staff portal on :${PORT}`));
