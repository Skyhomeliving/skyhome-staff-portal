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
  loginLockRemaining, registerLoginFailure, registerLoginSuccess,
  createPasswordReset, getValidReset, consumePasswordReset,
} from './auth.js';
import {
  PROFILE_SECTIONS, PROFILE_KEYS, SELF_EDITABLE_KEYS, DOCUMENT_CATEGORIES, categoryLabel, computeCompliance, daysUntil,
} from './compliance.js';
import { seedAdmin, seedDemo } from './seed.js';
import { streamZip, pdfBuffer, writeSummary } from './export.js';
import { startScheduler, sendDigest, sendMail, mailConfigured, recipients, lastSentAt } from './reminders.js';
import { getBranding, BRAND_DIR, brandMeta, customLogoPath } from './branding.js';
import { layout, loginPage, forgotPage, resetPage, errorPage, esc, fmtDate, ragBadge, levelBadge, initials, roleLabel, icon, miniIcon, avatarClass, fileKind, fileExt } from './views.js';
import { securityMiddleware } from './security.js';
import { startBackupScheduler } from './backup.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, '..');
const app = express();
securityMiddleware(app);
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
startScheduler();
startBackupScheduler();

app.use(attachUser);
app.get('/healthz', (_req, res) => res.type('text').send('ok'));
app.get('/branding/logo', (_req, res) => { const p = customLogoPath(); if (!p) return res.status(404).end(); res.sendFile(p); });

// ---- auth ------------------------------------------------------------------
app.get('/login', (req, res) => res.send(loginPage({ message: req.query.registered ? 'Account created — please sign in.' : req.query.reset ? 'Your password has been reset — please sign in.' : '' })));
app.post('/login', (req, res) => {
  const u = getUserByEmail(req.body.email);
  const lockMs = loginLockRemaining(u);
  if (lockMs > 0) {
    audit(u, 'login_blocked_locked');
    return res.status(429).send(loginPage({ error: `Too many failed attempts. Try again in ${Math.ceil(lockMs / 60000)} minute(s), or contact your manager.` }));
  }
  if (!u || !verifyPassword(req.body.password || '', u.password)) {
    if (u && registerLoginFailure(u)) audit(u, 'account_locked', null, 'too many failed logins');
    return res.status(401).send(loginPage({ error: 'Incorrect email or password.' }));
  }
  registerLoginSuccess(u);
  const token = createSession(u.id); setSessionCookie(res, token); audit(u, 'login');
  res.redirect('/');
});
app.get('/logout', (req, res) => { destroySession(req.cookies?.[SESSION_COOKIE]); res.clearCookie(SESSION_COOKIE, { path: '/' }); res.redirect('/login'); });

// ---- password reset (self-service) -----------------------------------------
app.get('/forgot', (_req, res) => res.send(forgotPage()));
app.post('/forgot', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const u = email ? getUserByEmail(email) : null;
  if (u) {
    try {
      const token = createPasswordReset(u.id);
      const link = `${req.protocol}://${req.get('host')}/reset?token=${token}`;
      await sendMail({
        to: u.email,
        subject: 'Reset your Sky Home Living password',
        text: `We received a request to reset your password.\n\nReset it here (expires in 1 hour, single use):\n${link}\n\nIf you didn't request this, ignore this email — your password won't change.`,
        html: `<div style="font-family:Segoe UI,Arial,sans-serif;color:#1f2937;max-width:520px">
          <h2 style="color:#0c2a4d">Reset your password</h2>
          <p>We received a request to reset the password for your Sky Home Living staff portal account.</p>
          <p><a href="${link}" style="background:#0c2a4d;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none">Choose a new password</a></p>
          <p style="color:#555;font-size:13px">This link expires in 1 hour and can be used once. If you didn't request it, ignore this email — your password won't change.</p></div>`,
      });
      audit(u, 'password_reset_requested');
    } catch (e) { console.error('[reset] email failed:', e.message); }
  }
  // Always neutral — never reveal whether an account exists.
  res.send(forgotPage({ message: 'If that email matches an account, we have sent a reset link. Please check your inbox.' }));
});
app.get('/reset', (req, res) => {
  const valid = !!getValidReset(req.query.token);
  res.send(resetPage({ token: String(req.query.token || ''), valid }));
});
app.post('/reset', (req, res) => {
  const token = String(req.body.token || '');
  if (!getValidReset(token)) return res.status(400).send(resetPage({ valid: false }));
  const pw = String(req.body.password || '');
  if (pw.length < 8) return res.send(resetPage({ token, error: 'Choose a password of at least 8 characters.' }));
  if (pw !== String(req.body.confirm || '')) return res.send(resetPage({ token, error: 'Passwords do not match.' }));
  const uid = consumePasswordReset(token, pw);
  if (!uid) return res.status(400).send(resetPage({ valid: false }));
  audit(getUser(uid), 'password_reset_completed');
  res.redirect('/login?reset=1');
});

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
  const filter = String(req.query.filter || 'all');
  let all = listStaff().map((s) => ({ ...s, c: computeCompliance(s), ndocs: db.prepare('SELECT COUNT(*) n FROM documents WHERE user_id=?').get(s.id).n }));
  if (q) all = all.filter((r) => `${r.full_name} ${r.email} ${r.job_title}`.toLowerCase().includes(q));
  const counts = { all: all.length, red: all.filter((r) => r.c.rag === 'red').length, amber: all.filter((r) => r.c.rag === 'amber').length, green: all.filter((r) => r.c.rag === 'green').length };
  const rows = filter === 'all' ? all : all.filter((r) => r.c.rag === filter);
  const qs = (f) => `?filter=${f}${q ? `&q=${encodeURIComponent(req.query.q)}` : ''}`;
  const pill = (f, label, n) => `<a class="${filter === f ? 'on' : ''}" href="/staff${qs(f)}">${label}<span class="c">${n}</span></a>`;
  const chip = (label, lvl) => `<span class="chip ${lvl}">${esc(label)}</span>`;
  const dbsChip = (r) => { const s = (r.dbs_status || '').toLowerCase(); return r.dbs_status ? chip('DBS', s.includes('clear') ? 'green' : s.includes('pend') ? 'amber' : 'red') : ''; };
  const rtwChip = (r) => { const s = (r.right_to_work_status || '').toLowerCase(); return r.right_to_work_status ? chip('RTW', s.includes('confirm') ? 'green' : s.includes('pend') ? 'amber' : 'red') : ''; };
  const body = `
  <div class="page-head"><div><h1>Staff records</h1><p class="muted">${counts.all} staff on file</p></div>
    <a class="btn" href="/admin/invites">${icon('invite')} Invite staff</a></div>
  <form method="get" style="margin-bottom:.8rem"><input type="hidden" name="filter" value="${esc(filter)}">
    <input name="q" value="${esc(req.query.q || '')}" placeholder="Search name, email or job title…" style="width:100%;max-width:440px;padding:.6rem .8rem;border:1px solid var(--line);border-radius:9px;background:#fff"></form>
  <div class="filters">${pill('all', 'All', counts.all)}${pill('red', 'Action needed', counts.red)}${pill('amber', 'Renewing soon', counts.amber)}${pill('green', 'Compliant', counts.green)}</div>
  <div class="card"><div class="card-b" style="padding:0">
  <table class="tbl"><thead><tr><th>Name</th><th>Job title</th><th>Compliance</th><th>Docs</th><th>Status</th></tr></thead><tbody>
  ${rows.map((r) => `<tr onclick="location='/staff/${r.id}'" style="cursor:pointer">
    <td><div style="display:flex;align-items:center;gap:.65rem"><div class="avatar ${avatarClass(r.full_name || r.email)}">${initials(r.full_name || r.email)}</div>
      <div><b>${esc(r.full_name || '—')}</b><div class="muted small">${esc(r.email)}</div></div></div></td>
    <td>${esc(r.job_title || '—')}${r.is_sponsored ? '<div style="margin-top:.2rem"><span class="chip">Sponsored</span></div>' : ''}</td>
    <td><div class="chips">${dbsChip(r)}${rtwChip(r)}${r.c.counts.expired ? chip(`${r.c.counts.expired} expired`, 'red') : ''}${r.c.counts.critical ? chip(`${r.c.counts.critical} due soon`, 'amber') : ''}${!r.c.counts.expired && !r.c.counts.critical && r.c.rag === 'green' ? chip('Up to date', 'green') : ''}</div></td>
    <td>${r.ndocs}</td>
    <td>${ragBadge(r.c.rag)}</td></tr>`).join('') || '<tr><td colspan="5" class="muted" style="padding:1rem">No staff match.</td></tr>'}
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
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to view this record.' }));
  const u = getUser(req.params.id); if (!u) return res.status(404).send(errorPage({ user: req.user, code: 404, title: 'Record not found', message: 'That record no longer exists.' }));
  const p = getProfile(u.id); const c = computeCompliance(p); const docs = listDocs(u.id);
  const emp = listEmployment(u.id); const refs = listReferences(u.id);
  const canEdit = req.user.role === 'admin' || req.user.role === 'manager' || req.user.id === u.id;
  const sectNav = PROFILE_SECTIONS.map((s) => `<a href="#${s.id}">${esc(s.title)}</a>`).join('');
  const sections = PROFILE_SECTIONS.map((s) => `
    <div class="card" id="${s.id}" style="margin-bottom:1rem"><div class="card-h">${esc(s.title)}</div>
      <div class="card-b"><div class="form-grid">
      ${s.fields.map((f) => renderViewField(f, p[f.key])).join('')}
      </div></div></div>`).join('');

  const docRowsHtml = docs.map((d) => {
    const kind = fileKind(d.file_path || d.mime_type);
    const dd = d.expiry_date ? daysUntil(d.expiry_date) : null;
    const expCls = dd == null ? '' : dd < 0 ? 'exp-over' : dd <= 60 ? 'exp-soon' : '';
    return `<div class="doc-row">
      <div class="fileicon ${kind}">${fileExt(d.file_path)}</div>
      <div class="doc-meta"><div class="doc-title">${esc(d.title || categoryLabel(d.category))}</div>
        <div class="doc-sub">${esc(categoryLabel(d.category))} · uploaded ${fmtDate(new Date(d.uploaded_at).toISOString())}${d.expiry_date ? ` · <span class="${expCls}">expires ${fmtDate(d.expiry_date)}</span>` : ''}</div></div>
      <div class="doc-actions">
        <a class="iconbtn" href="/documents/${d.id}" target="_blank" rel="noopener">${miniIcon('eye')} View</a>
        <a class="iconbtn" href="/documents/${d.id}?dl=1">${miniIcon('download')} Download</a>
        ${canEdit ? `<form method="post" action="/documents/${d.id}/delete" style="display:inline" onsubmit="return confirm('Delete this document?')"><button class="iconbtn danger" type="submit" title="Delete">${miniIcon('trash')}</button></form>` : ''}
      </div></div>`;
  }).join('');
  const lvlDate = (s) => { const dd = daysUntil(s); return dd == null ? 'grey' : dd < 0 ? 'red' : dd <= 30 ? 'amber' : 'green'; };
  const tile = (lbl, val, sub, lvl) => `<div class="ctile ${lvl}"><div class="lbl">${esc(lbl)}</div><div class="val">${esc(val || 'Not recorded')}</div>${sub ? `<div class="sub">${esc(sub)}</div>` : ''}</div>`;
  const low = (s) => (s || '').toLowerCase();
  const dbsLvl = p.dbs_expiry ? lvlDate(p.dbs_expiry) : (low(p.dbs_status).includes('clear') ? 'green' : low(p.dbs_status).includes('pend') ? 'amber' : 'grey');
  const rtwLvl = p.right_to_work_expiry ? lvlDate(p.right_to_work_expiry) : (low(p.right_to_work_status).includes('confirm') ? 'green' : low(p.right_to_work_status).includes('pend') ? 'amber' : 'grey');
  const ccLvl = low(p.care_certificate_status).includes('complet') ? 'green' : low(p.care_certificate_status).includes('progress') ? 'amber' : 'grey';
  const refLvl = low(p.references_received) === 'yes' ? 'green' : low(p.references_received) === 'partial' ? 'amber' : 'grey';
  const tilesHtml = `<div class="cgrid">
    ${tile('DBS', p.dbs_status, p.dbs_expiry ? `Renews ${fmtDate(p.dbs_expiry)}` : '', dbsLvl)}
    ${tile('Right to Work', p.right_to_work_status, p.right_to_work_expiry ? `Review ${fmtDate(p.right_to_work_expiry)}` : (p.is_sponsored ? 'Sponsored worker' : ''), rtwLvl)}
    ${tile('Care Certificate', p.care_certificate_status, p.care_certificate_date ? fmtDate(p.care_certificate_date) : '', ccLvl)}
    ${tile('Mandatory training', p.mandatory_training_expiry ? 'Valid' : (p.mandatory_training_date ? 'Recorded' : ''), p.mandatory_training_expiry ? `Expires ${fmtDate(p.mandatory_training_expiry)}` : '', p.mandatory_training_expiry ? lvlDate(p.mandatory_training_expiry) : 'grey')}
    ${tile('References', p.references_received, '', refLvl)}</div>`;

  const body = `
  <div class="hero">
    <div class="av ${avatarClass(p.full_name || u.email)}">${initials(p.full_name || u.email)}</div>
    <div class="hero-meta">
      <h1>${esc(p.full_name || u.email)}</h1>
      <div class="sub">${esc(p.job_title || roleLabel(u.role))} · ${esc(u.email)}</div>
      <div style="margin-top:.55rem;display:flex;gap:.4rem;flex-wrap:wrap">${ragBadge(c.rag)}${p.is_sponsored ? '<span class="badge">Sponsored worker</span>' : ''}${p.status && p.status !== 'active' ? `<span class="badge">${esc(p.status)}</span>` : ''}</div>
    </div>
    <div class="hero-actions">
      ${(req.user.role === 'admin' || req.user.role === 'manager') ? `<a class="btn ghost" href="/staff/${u.id}/export.zip" title="ZIP of all documents + PDF summary for CQC/HMRC">${icon('pack')} Document pack</a><a class="btn ghost" href="/staff/${u.id}/summary.pdf">Summary PDF</a>` : ''}
      ${canEdit ? `<a class="btn ghost" href="/staff/${u.id}/edit">Edit record</a>` : ''}
    </div>
  </div>
  ${tilesHtml}
  ${c.alerts.length ? `<div class="card" style="margin-bottom:1rem"><div class="card-h">Renewals & alerts</div><div class="card-b" style="padding:0">
    <table class="tbl"><tbody>${c.alerts.map((a) => `<tr><td>${esc(a.label)}</td><td class="muted">${esc(a.area)}</td>
      <td>${fmtDate(a.date)}</td><td>${levelBadge(a.level, a.days < 0 ? `Expired ${-a.days}d ago` : `${a.days}d left`)}</td></tr>`).join('')}</tbody></table></div></div>` : ''}
  <div class="card" style="margin-bottom:1rem"><div class="card-h"><span>Documents <span class="muted small" style="font-weight:400">· ${docs.length} on file</span></span>
    ${canEdit ? `<a class="btn ghost sm" href="/staff/${u.id}/edit#documents">Upload</a>` : ''}</div>
    <div class="card-b" style="padding:0">${docs.length ? `<div class="doc-list">${docRowsHtml}</div>` : '<div class="card-b muted">No documents uploaded yet.</div>'}</div></div>
  <div class="card" style="margin-bottom:1rem"><div class="card-h">Employment history <span class="muted small">CQC Schedule 3</span></div>
    <div class="card-b" style="padding:0">
    <table class="tbl"><thead><tr><th>Employer</th><th>Role</th><th>From</th><th>To</th><th>Care role</th><th>Reason for leaving</th>${canEdit ? '<th></th>' : ''}</tr></thead><tbody>
    ${emp.map((e) => `<tr><td><b>${esc(e.employer)}</b>${e.gap_explanation ? `<div class="muted small">Gap: ${esc(e.gap_explanation)}</div>` : ''}</td><td>${esc(e.job_title)}</td><td>${fmtDate(e.from_date)}</td><td>${e.to_date ? fmtDate(e.to_date) : 'Present'}</td><td>${e.is_care_role ? '<span class="badge blue">Care</span>' : '—'}</td><td class="muted">${esc(e.reason_for_leaving)}</td>${canEdit ? `<td><form method="post" action="/staff/${u.id}/employment/${e.id}/delete" onsubmit="return confirm('Delete this entry?')"><button class="linkbtn danger" type="submit">Delete</button></form></td>` : ''}</tr>`).join('') || `<tr><td colspan="${canEdit ? 7 : 6}" class="muted" style="padding:1rem">No employment history recorded.</td></tr>`}
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
    ${refs.map((r) => `<tr><td><b>${esc(r.referee_name)}</b></td><td>${esc(r.referee_org)}</td><td>${esc(r.relationship)}</td><td>${r.is_most_recent_employer ? 'Yes' : '—'}</td><td>${levelBadge(r.status === 'received' ? 'ok' : r.status === 'rejected' ? 'expired' : 'warning', r.status)}</td>${canEdit ? `<td><form method="post" action="/staff/${u.id}/references/${r.id}/delete" onsubmit="return confirm('Delete this reference?')"><button class="linkbtn danger" type="submit">Delete</button></form></td>` : ''}</tr>`).join('') || `<tr><td colspan="${canEdit ? 6 : 5}" class="muted" style="padding:1rem">No references recorded.</td></tr>`}
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
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to view this record.' }));
  const u = getUser(req.params.id); if (!u) return res.status(404).send(errorPage({ user: req.user, code: 404, title: 'Record not found', message: 'That record no longer exists.' }));
  const p = getProfile(u.id);
  const isManager = req.user.role === 'admin' || req.user.role === 'manager';
  const sections = PROFILE_SECTIONS.map((s) => `
    <div class="card" id="${s.id}" style="margin-bottom:1rem"><div class="card-h">${esc(s.title)}</div>
      <div class="card-b"><div class="form-grid">${s.fields.map((f) =>
        (isManager || SELF_EDITABLE_KEYS.has(f.key)) ? renderEditField(f, p[f.key]) : renderViewField(f, p[f.key])
      ).join('')}</div></div></div>`).join('');
  const cats = DOCUMENT_CATEGORIES.map((c) => `<option value="${c.value}">${esc(c.label)}</option>`).join('');
  const body = `
  <div class="page-head"><div><h1>Edit record</h1><p class="muted">${esc(p.full_name || u.email)}</p></div>
    <a class="btn ghost" href="/staff/${u.id}">Cancel</a></div>
  ${!isManager ? `<div class="flash info">Your compliance details (DBS, Right to Work, training, references) are kept up to date by your manager and shown here read-only. You can update your contact &amp; emergency details, and upload documents below for your manager to approve.</div>` : ''}
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
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to view this record.' }));
  const u = getUser(req.params.id); if (!u) return res.status(404).send(errorPage({ user: req.user, code: 404, title: 'Record not found', message: 'That record no longer exists.' }));
  // Managers/admins may edit the whole record; a staff member editing their own
  // record may only change contact details — never their own compliance status.
  const isManager = req.user.role === 'admin' || req.user.role === 'manager';
  const editableKeys = isManager ? PROFILE_KEYS : PROFILE_KEYS.filter((k) => SELF_EDITABLE_KEYS.has(k));
  const checkboxKeys = new Set(PROFILE_SECTIONS.flatMap((s) => s.fields.filter((f) => f.type === 'checkbox').map((f) => f.key)));
  const sets = [], vals = [];
  for (const k of editableKeys) {
    let v;
    if (checkboxKeys.has(k)) v = req.body[k] ? 1 : 0;
    else v = (req.body[k] ?? '').toString();
    sets.push(`${k}=?`); vals.push(v);
  }
  if (sets.length) {
    vals.push(Date.now(), u.id);
    db.prepare(`UPDATE profiles SET ${sets.join(',')}, updated_at=? WHERE user_id=?`).run(...vals);
  }
  audit(req.user, isManager ? 'update_profile' : 'update_own_contact', u.id);
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
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to view this record.' }));
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
  if (!d || !canAccessStaff(req.user, d.user_id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to view this record.' }));
  const fp = path.join(UPLOADS_DIR, path.basename(d.file_path));
  if (!fs.existsSync(fp)) return res.status(404).send(errorPage({ user: req.user, code: 404, title: 'File missing', message: 'The stored file could not be found. It may have been removed.' }));
  if (req.query.dl) {
    const ext = path.extname(d.file_path) || '';
    const name = `${categoryLabel(d.category)}_${d.title || 'document'}`.replace(/[^a-z0-9]+/gi, '_').replace(/_+/g, '_') + ext;
    return res.download(fp, name);
  }
  res.sendFile(fp);
});
app.post('/documents/:id/delete', requireAuth, (req, res) => {
  const d = db.prepare('SELECT * FROM documents WHERE id=?').get(req.params.id);
  if (!d || !canAccessStaff(req.user, d.user_id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to view this record.' }));
  try { fs.unlinkSync(path.join(UPLOADS_DIR, path.basename(d.file_path))); } catch {}
  db.prepare('DELETE FROM documents WHERE id=?').run(d.id);
  audit(req.user, 'delete_document', d.user_id);
  res.redirect(`/staff/${d.user_id}`);
});

// ---- exports: compliance pack (PDF summary + ZIP of documents) -------------
app.get('/staff/:id/summary.pdf', requireAuth, async (req, res) => {
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to view this record.' }));
  const u = getUser(req.params.id); if (!u) return res.status(404).send(errorPage({ user: req.user, code: 404, title: 'Record not found', message: 'That record no longer exists.' }));
  const p = getProfile(u.id); const docs = listDocs(u.id);
  audit(req.user, 'export_summary_pdf', u.id);
  const buf = await pdfBuffer((doc) => writeSummary(doc, { profile: p, user: u, docs, actor: req.user }));
  const safe = (p.full_name || u.email).replace(/[^a-z0-9]+/gi, '_');
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${safe}_compliance_summary.pdf"`);
  res.end(buf);
});
app.get('/staff/:id/export.zip', requireAuth, async (req, res) => {
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to view this record.' }));
  const u = getUser(req.params.id); if (!u) return res.status(404).send(errorPage({ user: req.user, code: 404, title: 'Record not found', message: 'That record no longer exists.' }));
  const p = getProfile(u.id); const docs = listDocs(u.id);
  audit(req.user, 'export_zip_pack', u.id);
  await streamZip(res, { profile: p, user: u, docs, actor: req.user, uploadsDir: UPLOADS_DIR });
});

// ---- employment history & references ---------------------------------------
app.post('/staff/:id/employment', requireAuth, (req, res) => {
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to view this record.' }));
  db.prepare('INSERT INTO employment_history (user_id,employer,job_title,from_date,to_date,is_care_role,reason_for_leaving,gap_explanation,created_at) VALUES (?,?,?,?,?,?,?,?,?)')
    .run(req.params.id, req.body.employer || '', req.body.job_title || '', req.body.from_date || '', req.body.to_date || '', req.body.is_care_role ? 1 : 0, req.body.reason_for_leaving || '', req.body.gap_explanation || '', Date.now());
  audit(req.user, 'add_employment', Number(req.params.id));
  res.redirect(`/staff/${req.params.id}`);
});
app.post('/staff/:id/employment/:eid/delete', requireAuth, (req, res) => {
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to view this record.' }));
  db.prepare('DELETE FROM employment_history WHERE id=? AND user_id=?').run(req.params.eid, req.params.id);
  audit(req.user, 'delete_employment', Number(req.params.id));
  res.redirect(`/staff/${req.params.id}`);
});
app.post('/staff/:id/references', requireAuth, (req, res) => {
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to view this record.' }));
  db.prepare('INSERT INTO reference_checks (user_id,referee_name,referee_org,relationship,is_most_recent_employer,status,created_at) VALUES (?,?,?,?,?,?,?)')
    .run(req.params.id, req.body.referee_name || '', req.body.referee_org || '', req.body.relationship || '', req.body.is_most_recent_employer ? 1 : 0, req.body.status || 'requested', Date.now());
  audit(req.user, 'add_reference', Number(req.params.id));
  res.redirect(`/staff/${req.params.id}`);
});
app.post('/staff/:id/references/:rid/delete', requireAuth, (req, res) => {
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to view this record.' }));
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
  ${req.query.reminder === 'sent' ? `<div class="card" style="margin-bottom:1rem"><div class="card-b" style="color:#1a7f4b">✓ Reminder digest emailed to ${esc(req.query.n || '')} recipient(s).</div></div>` : ''}
  ${req.query.reminder === 'error' ? `<div class="card" style="margin-bottom:1rem"><div class="card-b" style="color:#b42318">Could not send: ${esc(req.query.msg || '')}</div></div>` : ''}
  <div class="card" style="margin-bottom:1rem"><div class="card-h">Email reminders ${mailConfigured() ? '<span class="badge green">Active</span>' : '<span class="badge amber">Not configured</span>'}</div>
    <div class="card-b" style="display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap">
      <div class="small muted">${mailConfigured() ? `Daily digest to: ${esc(recipients().join(', '))}.${lastSentAt() ? ` Last sent ${new Date(lastSentAt()).toLocaleString('en-GB')}.` : ' Not sent yet.'}` : 'Add the info@skyhomeliving.co.uk SMTP settings to enable automatic daily reminders.'}</div>
      <form method="post" action="/admin/send-reminders"><button class="btn sm" ${mailConfigured() ? '' : 'disabled'}>Send reminders now</button></form>
    </div></div>
  <div class="card"><div class="card-b" style="padding:0">
  <table class="tbl"><thead><tr><th>Staff</th><th>Requirement</th><th>Date</th><th>Status</th></tr></thead><tbody>
  ${rows.map(({ s, a }) => `<tr onclick="location='/staff/${s.id}'" style="cursor:pointer">
    <td><b>${esc(s.full_name || s.email)}</b></td><td>${esc(a.label)} <span class="muted small">· ${esc(a.area)}</span></td>
    <td>${fmtDate(a.date)}</td><td>${levelBadge(a.level, a.days < 0 ? `Expired ${-a.days}d ago` : `${a.days}d left`)}</td></tr>`).join('')
    || '<tr><td colspan="4" class="muted" style="padding:1rem">No alerts — everyone is up to date.</td></tr>'}
  </tbody></table></div></div>`;
  res.send(layout({ user: req.user, title: 'Alerts', active: '/alerts', body }));
});

app.post('/admin/send-reminders', requireRole('admin', 'manager'), async (req, res) => {
  let r;
  try { r = await sendDigest(); } catch (e) { r = { sent: false, reason: e.message }; }
  audit(req.user, 'send_reminders', null, r.sent ? `to ${r.to.length}` : r.reason);
  res.redirect(r.sent ? `/alerts?reminder=sent&n=${r.to.length}` : `/alerts?reminder=error&msg=${encodeURIComponent(r.reason)}`);
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

// ---- settings / branding ---------------------------------------------------
const logoUpload = multer({
  storage: multer.diskStorage({
    destination: (_q, _f, cb) => cb(null, BRAND_DIR),
    filename: (_q, file, cb) => cb(null, 'logo' + path.extname(file.originalname).toLowerCase()),
  }),
  limits: { fileSize: 4 * 1024 * 1024 },
  fileFilter: (_q, file, cb) => cb(null, /\.(png|jpe?g|svg|webp|gif)$/i.test(file.originalname)),
});

app.get('/admin/settings', requireRole('admin'), (req, res) => {
  const b = getBranding();
  const body = `
  <div class="page-head"><div><h1>Settings</h1><p class="muted">Branding & organisation</p></div></div>
  ${req.query.saved ? '<div class="card" style="margin-bottom:1rem"><div class="card-b" style="color:#1a7f4b">✓ Saved.</div></div>' : ''}
  ${req.query.err ? `<div class="card" style="margin-bottom:1rem"><div class="card-b" style="color:#b42318">${esc(req.query.err)}</div></div>` : ''}
  <div class="grid cols-2">
    <div class="card"><div class="card-h">Logo</div><div class="card-b">
      <p class="muted small" style="margin-top:0">Shown on the sign-in screen and the sidebar. ${b.hasCustom ? 'Currently using your uploaded logo.' : 'Currently using the official Sky Home Living logo.'}</p>
      <img class="logo-preview" src="${b.loginLogo}" alt="Current logo">
      <form method="post" action="/admin/branding/logo" enctype="multipart/form-data" style="margin-top:1rem">
        <div class="field"><label>Upload a new logo (PNG, JPG, SVG or WebP · max 4&nbsp;MB)</label>
          <input type="file" name="logo" accept=".png,.jpg,.jpeg,.svg,.webp" required></div>
        <button class="btn">Upload logo</button>
      </form>
      ${b.hasCustom ? `<form method="post" action="/admin/branding/logo/delete" style="margin-top:.7rem"><button class="btn ghost sm">Reset to default logo</button></form>` : ''}
    </div></div>
    <div class="card"><div class="card-h">Organisation name</div><div class="card-b">
      <form method="post" action="/admin/settings">
        <div class="field"><label>Name (shown in the header and email reminders)</label><input name="org_name" value="${esc(b.orgName)}"></div>
        <button class="btn">Save</button>
      </form>
    </div></div>
  </div>`;
  res.send(layout({ user: req.user, title: 'Settings', active: '/admin/settings', body }));
});
app.post('/admin/settings', requireRole('admin'), (req, res) => {
  brandMeta.set('org_name', (req.body.org_name || 'Sky Home Living').trim() || 'Sky Home Living');
  audit(req.user, 'update_settings');
  res.redirect('/admin/settings?saved=1');
});
app.post('/admin/branding/logo', requireRole('admin'), (req, res) => {
  logoUpload.single('logo')(req, res, (err) => {
    if (err) return res.redirect('/admin/settings?err=' + encodeURIComponent('Upload failed: ' + err.message));
    if (!req.file) return res.redirect('/admin/settings?err=' + encodeURIComponent('Choose a PNG, JPG, SVG or WebP image.'));
    for (const f of fs.readdirSync(BRAND_DIR)) if (f.startsWith('logo') && f !== req.file.filename) { try { fs.unlinkSync(path.join(BRAND_DIR, f)); } catch {} }
    brandMeta.set('logo_file', req.file.filename);
    brandMeta.set('logo_ver', String(Date.now()));
    audit(req.user, 'update_logo');
    res.redirect('/admin/settings?saved=1');
  });
});
app.post('/admin/branding/logo/delete', requireRole('admin'), (req, res) => {
  const f = brandMeta.get('logo_file');
  if (f) { try { fs.unlinkSync(path.join(BRAND_DIR, f)); } catch {} }
  brandMeta.del('logo_file');
  audit(req.user, 'reset_logo');
  res.redirect('/admin/settings?saved=1');
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
  const b = getBranding();
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow"><link rel="icon" href="/favicon.png"><title>${esc(b.orgName)}</title><link rel="stylesheet" href="/styles.css"></head>
  <body><div class="auth-wrap"><div class="auth-card"><img class="login-logo" src="${b.loginLogo}" alt="${esc(b.orgName)}">${inner}</div></div></body></html>`;
}

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Sky Home Living staff portal on :${PORT}`));
