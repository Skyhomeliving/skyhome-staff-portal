// server.js — Express app for the Sky Home Living staff compliance portal.
import express from 'express';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import path from 'node:path';
import fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { db, UPLOADS_DIR, PHOTOS_DIR } from './db.js';
import {
  hashPassword, verifyPassword, createSession, destroySession, setSessionCookie,
  attachUser, requireAuth, requireRole, requireOversight, requireManager, requireAdmin,
  canAccessStaff, canEditStaff, canDeleteEvidence, canVerifyEvidence, audit, SESSION_COOKIE,
  loginLockRemaining, registerLoginFailure, registerLoginSuccess,
  createPasswordReset, getValidReset, consumePasswordReset,
} from './auth.js';
import {
  PROFILE_SECTIONS, PROFILE_KEYS, isSelfEditableKey, DOCUMENT_CATEGORIES, categoryLabel, computeCompliance, daysUntil,
  ROLES, isFrontline, isOversight, isManagerLevel, REQUIRED_TOTAL, rightToWorkRisk, isFilled,
} from './compliance.js';
import { attachEvidence, attachEvidenceOne, presentCategories, fileOnDisk } from './evidence.js';
import { seedAdmin, seedDemo } from './seed.js';
import { streamZip, streamCategoryZip, pdfBuffer, writeSummary } from './export.js';
import { writeOfferLetter, writeEmploymentContract, writeHandbookAck, DEFAULT_MANAGER } from './onboarding.js';
import { startScheduler, sendDigest, sendMail, mailConfigured, recipients, lastSentAt } from './reminders.js';
import { getBranding, BRAND_DIR, brandMeta, customLogoPath } from './branding.js';
import { layout, loginPage, forgotPage, resetPage, errorPage, esc, fmtDate, ragBadge, levelBadge, alertStatusText, initials, roleLabel, icon, miniIcon, avatarClass, avatarTag, fileKind, fileExt } from './views.js';
import { securityMiddleware } from './security.js';
import { startBackupScheduler } from './backup.js';
import { scoreAllStaff } from './completeness.js';

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
// Active (non-admin) staff — the default working set for counts, dashboards and
// alerts. Deactivated (offboarded) staff are excluded here and surfaced
// separately via listInactiveStaff so they never inflate active counts.
const listStaff = () => db.prepare(`SELECT u.id,u.email,u.role,u.is_active,p.* FROM users u
  LEFT JOIN profiles p ON p.user_id=u.id WHERE u.role != 'admin' AND u.is_active = 1 ORDER BY p.full_name, u.email`).all();
const listInactiveStaff = () => db.prepare(`SELECT u.id,u.email,u.role,u.is_active,p.* FROM users u
  LEFT JOIN profiles p ON p.user_id=u.id WHERE u.role != 'admin' AND u.is_active = 0 ORDER BY p.full_name, u.email`).all();
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

// A deactivated account is denied everywhere. attachUser has already revoked the
// session and cleared the cookie; here we show a clear message rather than a
// silent redirect. Fires at most once (the session is gone next request).
app.use((req, res, next) => {
  if (!req.deactivated) return next();
  return res.status(403).send(errorPage({
    code: 403, title: 'Account deactivated',
    message: 'Your account has been deactivated and you have been signed out of all devices. If you think this is a mistake, contact your manager.',
  }));
});

// A staff member whose manager issued a temporary password must set their own
// before reaching anything else. (/healthz and /branding/logo are handled above.)
app.use((req, res, next) => {
  if (req.user?.must_change_password && req.path !== '/account/password' && req.path !== '/logout') {
    return res.redirect('/account/password');
  }
  next();
});

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
  // Deny deactivated accounts even with the correct password (checked after the
  // password so we never reveal account state to someone who can't authenticate).
  if (u.is_active === 0) {
    audit(u, 'login_blocked_deactivated');
    return res.status(403).send(loginPage({ error: 'This account has been deactivated. Please contact your manager.' }));
  }
  registerLoginSuccess(u);
  const token = createSession(u.id); setSessionCookie(res, token); audit(u, 'login');
  res.redirect('/');
});
app.get('/logout', (req, res) => { destroySession(req.cookies?.[SESSION_COOKIE]); res.clearCookie(SESSION_COOKIE, { path: '/' }); res.redirect('/login'); });

// ---- change own password (also the forced flow after a temp password) ------
app.get('/account/password', requireAuth, (req, res) => {
  res.send(changePasswordPage({ forced: !!req.user.must_change_password }));
});
app.post('/account/password', requireAuth, (req, res) => {
  const forced = !!req.user.must_change_password;
  // Require proof of the current password before setting a new one — otherwise
  // a hijacked session (stolen device, leaked cookie, XSS) is enough on its own
  // to lock the real owner out permanently, and sessions here last 180 days.
  const u = getUser(req.user.id);
  if (!verifyPassword(String(req.body.current_password || ''), u.password)) {
    return res.send(changePasswordPage({ forced, error: 'Current password is incorrect.' }));
  }
  const pw = String(req.body.password || '');
  if (pw.length < 8) return res.send(changePasswordPage({ forced, error: 'Choose a password of at least 8 characters.' }));
  if (pw !== String(req.body.confirm || '')) return res.send(changePasswordPage({ forced, error: 'Passwords do not match.' }));
  db.prepare('UPDATE users SET password=?, must_change_password=0 WHERE id=?').run(hashPassword(pw), req.user.id);
  audit(req.user, 'change_own_password');
  res.redirect('/');
});

// ---- password reset (self-service) -----------------------------------------
app.get('/forgot', (_req, res) => res.send(forgotPage()));
app.post('/forgot', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const u = email ? getUserByEmail(email) : null;
  if (u) {
    const token = createPasswordReset(u.id);
    const link = `${req.protocol}://${req.get('host')}/reset?token=${token}`;
    // Fire-and-forget: the response below must return in the same time whether
    // or not the account exists. Awaiting the email send here would make the
    // "account exists" case measurably slower than the "doesn't exist" case,
    // leaking exactly what the neutral wording below is meant to hide.
    sendMail({
      to: u.email,
      subject: 'Reset your Sky Home Living password',
      text: `We received a request to reset your password.\n\nReset it here (expires in 1 hour, single use):\n${link}\n\nIf you didn't request this, ignore this email — your password won't change.`,
      html: `<div style="font-family:Segoe UI,Arial,sans-serif;color:#1f2937;max-width:520px">
        <h2 style="color:#0c2a4d">Reset your password</h2>
        <p>We received a request to reset the password for your Sky Home Living staff portal account.</p>
        <p><a href="${link}" style="background:#0c2a4d;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none">Choose a new password</a></p>
        <p style="color:#555;font-size:13px">This link expires in 1 hour and can be used once. If you didn't request it, ignore this email — your password won't change.</p></div>`,
    }).then(() => audit(u, 'password_reset_requested'))
      .catch((e) => console.error('[reset] email failed:', e.message));
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
    .run(email, hashPassword(req.body.password), inv.role || 'carer', now, inv.full_name || '');
  const uid = Number(info.lastInsertRowid);
  db.prepare('INSERT INTO profiles (user_id, full_name, job_title, status, updated_at) VALUES (?,?,?,?,?)')
    .run(uid, inv.full_name || '', inv.job_title || '', 'active', now);
  db.prepare('UPDATE invite_codes SET used_at=?, used_by_user_id=? WHERE id=?').run(now, uid, inv.id);
  audit({ id: uid, email }, 'register');
  res.redirect('/login?registered=1');
});

// ---- dashboard -------------------------------------------------------------
app.get('/', requireAuth, (req, res) => {
  if (isFrontline(req.user.role)) return res.redirect(`/staff/${req.user.id}`);
  // One pass drives every figure on this page. The headline count and the
  // "Incomplete files" panel below it are derived from the same rows, so they
  // cannot disagree the way two independent engines previously did.
  const staff = attachEvidence(listStaff());
  const rows = staff.map((s) => ({ ...s, c: computeCompliance(s) }));
  const tot = { compliant: 0, incomplete: 0, expired: 0, renewing: 0, criticalItems: 0 };
  for (const r of rows) {
    tot[r.c.status]++;
    if (r.c.status === 'compliant' && r.c.counts.critical) tot.renewing++;
    tot.criticalItems += r.c.counts.critical;
  }
  const attention = rows.filter((r) => r.c.status !== 'compliant')
    .sort((a, b) => (b.c.counts.expired - a.c.counts.expired) || (b.c.counts.missing - a.c.counts.missing));
  const incomplete = rows.filter((r) => !r.c.complete)
    .map((r) => ({ id: r.id, name: r.full_name || r.email, missing: r.c.missing,
                   pct: Math.round(((REQUIRED_TOTAL - r.c.missing.length) / REQUIRED_TOTAL) * 100) }))
    .sort((a, b) => a.pct - b.pct);

  const body = `
  <div class="page-head"><div><h1>Compliance dashboard</h1>
    <p class="muted">${staff.length} staff · live view of DBS, Right to Work, training and renewals</p></div></div>
  <div class="grid cols-4" style="margin-bottom:1.2rem">
    <div class="stat"><div class="n">${staff.length}</div><div class="l">Staff on file</div></div>
    <div class="stat red"><div class="n">${tot.expired}</div><div class="l">Expired evidence</div></div>
    <div class="stat incomplete"><div class="n">${tot.incomplete}</div><div class="l">Evidence missing</div></div>
    <div class="stat green"><div class="n">${tot.compliant}</div><div class="l">Fully compliant${tot.renewing ? ` <span class="muted">· ${tot.renewing} renewing soon</span>` : ''}</div></div>
  </div>
  <div class="card"><div class="card-h">Needs attention
    <a class="btn ghost sm" href="/alerts">View all alerts</a></div>
    <div class="card-b" style="padding:0">
    ${attention.length ? `<table class="tbl"><thead><tr><th>Staff</th><th>Role</th><th>Status</th><th>Most urgent issue</th></tr></thead><tbody>
      ${attention.slice(0, 12).map((r) => {
        const a = r.c.alerts[0];
        return `<tr onclick="location='/staff/${r.id}'" style="cursor:pointer">
          <td><b>${esc(r.full_name || r.email)}</b></td>
          <td>${esc(r.job_title || roleLabel(r.role))}</td>
          <td>${ragBadge(r.c.rag)}</td>
          <td>${a ? `${esc(a.label)} — ${esc(alertStatusText(a).toLowerCase())}` : '—'}</td></tr>`;
      }).join('')}
    </tbody></table>` : `<div class="card-b muted">Everyone is compliant. 🎉</div>`}
    </div></div>
  <div class="card" style="margin-top:1.2rem"><div class="card-h">Incomplete files
    <span class="muted small" style="font-weight:400">· ${incomplete.length} below 100%</span></div>
    <div class="card-b" style="padding:0">
    ${incomplete.length ? `<table class="tbl"><thead><tr><th>Staff</th><th>Complete</th><th>Still needed</th></tr></thead><tbody>
      ${incomplete.slice(0, 12).map((s) => `<tr onclick="location='/staff/${s.id}'" style="cursor:pointer">
        <td><b>${esc(s.name)}</b></td><td><span class="chip incomplete">${s.pct}%</span></td>
        <td class="muted small">${esc(s.missing.join(', '))}</td></tr>`).join('')}
    </tbody></table>` : `<div class="card-b muted">Every staff file is complete. 🎉</div>`}
    </div></div>`;
  res.send(layout({ user: req.user, title: 'Dashboard', active: '/', body, scripts: '' }));
});

// ---- staff list ------------------------------------------------------------
app.get('/staff', requireOversight, (req, res) => {
  const q = String(req.query.q || '').toLowerCase();
  const filter = String(req.query.filter || 'all');
  // Document counts come from one grouped query rather than a lookup per row.
  const docTotals = new Map(db.prepare('SELECT user_id, COUNT(*) n FROM documents GROUP BY user_id').all().map((r) => [r.user_id, r.n]));
  let all = attachEvidence(listStaff()).map((s) => ({ ...s, c: computeCompliance(s), ndocs: docTotals.get(s.id) || 0 }));
  if (q) all = all.filter((r) => `${r.full_name} ${r.email} ${r.job_title}`.toLowerCase().includes(q));
  const counts = {
    all: all.length,
    expired: all.filter((r) => r.c.status === 'expired').length,
    incomplete: all.filter((r) => r.c.status === 'incomplete').length,
    compliant: all.filter((r) => r.c.status === 'compliant').length,
  };
  const rows = filter === 'all' ? all : all.filter((r) => r.c.status === filter);
  const qs = (f) => `?filter=${f}${q ? `&q=${encodeURIComponent(req.query.q)}` : ''}`;
  const pill = (f, label, n) => `<a class="${filter === f ? 'on' : ''}" href="/staff${qs(f)}">${label}<span class="c">${n}</span></a>`;
  const chip = (label, lvl) => `<span class="chip ${lvl}">${esc(label)}</span>`;
  const dbsChip = (r) => { const s = (r.dbs_status || '').toLowerCase(); return r.dbs_status ? chip('DBS', s.includes('clear') ? 'green' : s.includes('pend') ? 'amber' : 'red') : ''; };
  const rtwChip = (r) => { const s = (r.right_to_work_status || '').toLowerCase(); return r.right_to_work_status ? chip('RTW', s.includes('confirm') ? 'green' : s.includes('pend') ? 'amber' : 'red') : ''; };
  // File-completeness chip, derived from the same computeCompliance() result as
  // the status badge in the last column — they can never report different things.
  const fileChip = (r) => {
    const pct = Math.round(((REQUIRED_TOTAL - r.c.missing.length) / REQUIRED_TOTAL) * 100);
    const t = r.c.missing.length ? `Missing: ${r.c.missing.join(', ')}` : 'Complete';
    return `<span class="chip ${r.c.complete ? 'green' : 'incomplete'}" title="${esc(t)}">${pct}%</span>`;
  };

  // Bulk export by document type (manager-only): one ZIP of a single category
  // across all staff. Shows how many documents exist per type.
  const isMgr = isManagerLevel(req.user.role);
  const docCounts = new Map(db.prepare('SELECT category, COUNT(*) n FROM documents GROUP BY category').all().map((r) => [r.category, r.n]));
  const exportItem = (c) => {
    const n = docCounts.get(c.value) || 0;
    return n
      ? `<a class="btn ghost sm" href="/exports/documents/${c.value}.zip" style="justify-content:flex-start" title="Download all ${esc(c.label)} documents as a ZIP">${miniIcon('download')} ${esc(c.label)} <span class="chip" style="margin-left:auto">${n}</span></a>`
      : `<span class="btn ghost sm" style="justify-content:flex-start;opacity:.5;pointer-events:none">${esc(c.label)} <span class="chip grey" style="margin-left:auto">0</span></span>`;
  };
  const exportsPanel = isMgr ? `
  <div class="card" style="margin-top:1.2rem"><div class="card-h">Export documents by type <span class="muted small" style="font-weight:400">· one ZIP per document type, across all staff</span></div>
    <div class="card-b"><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:.5rem">
      ${DOCUMENT_CATEGORIES.map(exportItem).join('')}
    </div></div></div>` : '';

  // Deactivated (offboarded) staff — kept visible for reactivation but excluded
  // from the active list and its counts above.
  const inactive = listInactiveStaff();
  const inactiveCard = inactive.length ? `
  <div class="card" style="margin-top:1.2rem"><div class="card-h">Deactivated staff <span class="muted small" style="font-weight:400">· ${inactive.length} · excluded from active counts${isMgr ? ' · open a record to reactivate' : ''}</span></div>
    <div class="card-b" style="padding:0">
    <table class="tbl"><tbody>
    ${inactive.map((r) => `<tr onclick="location='/staff/${r.id}'" style="cursor:pointer;opacity:.72">
      <td><div style="display:flex;align-items:center;gap:.65rem">${avatarTag(r.id, r.photo_path, r.full_name || r.email, 'sm')}
        <div><b>${esc(r.full_name || '—')}</b> <span class="badge red">Inactive</span><div class="muted small">${esc(r.email)}</div></div></div></td>
      <td>${esc(r.job_title || '—')}</td></tr>`).join('')}
    </tbody></table></div></div>` : '';

  const body = `
  <div class="page-head"><div><h1>Staff records</h1><p class="muted">${counts.all} active staff on file${inactive.length ? ` · ${inactive.length} deactivated` : ''}</p></div>
    <a class="btn" href="/admin/invites">${icon('invite')} Invite staff</a></div>
  <form method="get" style="margin-bottom:.8rem"><input type="hidden" name="filter" value="${esc(filter)}">
    <input name="q" value="${esc(req.query.q || '')}" placeholder="Search name, email or job title…" style="width:100%;max-width:440px;padding:.6rem .8rem;border:1px solid var(--line);border-radius:9px;background:#fff"></form>
  <div class="filters">${pill('all', 'All', counts.all)}${pill('expired', 'Expired', counts.expired)}${pill('incomplete', 'Evidence missing', counts.incomplete)}${pill('compliant', 'Compliant', counts.compliant)}</div>
  <div class="card"><div class="card-b" style="padding:0">
  <table class="tbl"><thead><tr><th>Name</th><th>Job title</th><th>Compliance</th><th>File</th><th>Docs</th><th>Status</th></tr></thead><tbody>
  ${rows.map((r) => `<tr onclick="location='/staff/${r.id}'" style="cursor:pointer">
    <td><div style="display:flex;align-items:center;gap:.65rem">${avatarTag(r.id, r.photo_path, r.full_name || r.email, 'sm')}
      <div><b>${esc(r.full_name || '—')}</b><div class="muted small">${esc(r.email)}</div></div></div></td>
    <td>${esc(r.job_title || '—')}${r.is_sponsored ? '<div style="margin-top:.2rem"><span class="chip">Sponsored</span></div>' : ''}</td>
    <td><div class="chips">${dbsChip(r)}${rtwChip(r)}${r.c.counts.missing ? chip(`${r.c.counts.missing} missing`, 'incomplete') : ''}${r.c.counts.expired ? chip(`${r.c.counts.expired} expired`, 'red') : ''}${r.c.counts.critical ? chip(`${r.c.counts.critical} due soon`, 'amber') : ''}${r.c.status === 'compliant' && !r.c.counts.critical ? chip('Up to date', 'green') : ''}</div></td>
    <td>${fileChip(r)}</td>
    <td>${r.ndocs}</td>
    <td>${ragBadge(r.c.rag)}</td></tr>`).join('') || '<tr><td colspan="6" class="muted" style="padding:1rem">No staff match.</td></tr>'}
  </tbody></table></div></div>
  ${exportsPanel}
  ${inactiveCard}`;
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
  const p = getProfile(u.id); const docs = listDocs(u.id);
  // Evidence context is loaded once and shared: the status calculation below and
  // the compliance tiles further down must be reading the same reference count
  // and the same set of on-disk documents, not two independently-fetched copies.
  const evidence = attachEvidenceOne(p, u.id);
  const c = computeCompliance(evidence);
  const emp = listEmployment(u.id); const refs = listReferences(u.id);
  const canEdit = canEditStaff(req.user, u.id);
  const sectNav = PROFILE_SECTIONS.map((s) => `<a href="#${s.id}">${esc(s.title)}</a>`).join('');
  const sections = PROFILE_SECTIONS.map((s) => `
    <div class="card" id="${s.id}" style="margin-bottom:1rem"><div class="card-h">${esc(s.title)}</div>
      <div class="card-b"><div class="form-grid">
      ${s.fields.map((f) => renderViewField(f, p[f.key])).join('')}
      </div></div></div>`).join('');

  const canReview = isManagerLevel(req.user.role);
  const canRemove = canDeleteEvidence(req.user);
  const docStatusChip = (s) => s === 'approved' ? '<span class="chip green">Approved</span>'
    : s === 'rejected' ? '<span class="chip red">Rejected</span>' : '<span class="chip amber">Pending review</span>';
  // Documents are listed newest-first, so any earlier upload in the same category
  // has been superseded by a later one. Computed at render time — the older file
  // is kept on record rather than deleted, which is what an audit trail needs.
  const newestPerCategory = new Map();
  for (const d of docs) if (!newestPerCategory.has(d.category)) newestPerCategory.set(d.category, d.id);
  const docRowsHtml = docs.map((d) => {
    const kind = fileKind(d.file_path || d.mime_type);
    const dd = d.expiry_date ? daysUntil(d.expiry_date) : null;
    const expCls = dd == null ? '' : dd < 0 ? 'exp-over' : dd <= 60 ? 'exp-soon' : '';
    const reviewedAt = d.reviewed_at ? fmtDate(new Date(d.reviewed_at).toISOString()) : '';
    let reviewLine = '';
    if (d.status === 'approved' && d.reviewed_by_email)
      reviewLine = `<div class="doc-sub" style="color:var(--green)">Approved by ${esc(d.reviewed_by_email)}${reviewedAt ? ` · ${reviewedAt}` : ''}</div>`;
    else if (d.status === 'rejected')
      reviewLine = `<div class="doc-sub" style="color:var(--red)">Rejected${d.reviewed_by_email ? ` by ${esc(d.reviewed_by_email)}` : ''}${reviewedAt ? ` · ${reviewedAt}` : ''}${d.review_note ? ` — ${esc(d.review_note)}` : ''}</div>`;
    const superseded = newestPerCategory.get(d.category) !== d.id;
    const supersededLine = superseded
      ? '<div class="doc-sub muted">Superseded by a newer upload in this category · kept for the audit trail</div>' : '';
    return `<div class="doc-row"${superseded ? ' style="opacity:.62"' : ''}>
      <div class="fileicon ${kind}">${fileExt(d.file_path)}</div>
      <div class="doc-meta"><div class="doc-title">${esc(d.title || categoryLabel(d.category))} ${docStatusChip(d.status)}${superseded ? ' <span class="chip grey">Superseded</span>' : ''}</div>
        <div class="doc-sub">${esc(categoryLabel(d.category))} · uploaded ${fmtDate(new Date(d.uploaded_at).toISOString())}${d.expiry_date ? ` · <span class="${expCls}">expires ${fmtDate(d.expiry_date)}</span>` : ''}</div>${reviewLine}${supersededLine}</div>
      <div class="doc-actions">
        <a class="iconbtn" href="/documents/${d.id}" target="_blank" rel="noopener">${miniIcon('eye')} View</a>
        <a class="iconbtn" href="/documents/${d.id}?dl=1">${miniIcon('download')} Download</a>
        ${canEdit && !superseded ? `<a class="iconbtn" href="/staff/${u.id}/edit?replace=${encodeURIComponent(d.category)}#documents" title="Upload a newer version of this document">${miniIcon('download')} Replace</a>` : ''}
        ${canReview && d.status !== 'approved' ? `<form method="post" action="/documents/${d.id}/approve" style="display:inline"><button class="iconbtn" type="submit" title="Approve this document">✓ Approve</button></form>` : ''}
        ${canReview && d.status !== 'rejected' ? `<form method="post" action="/documents/${d.id}/reject" style="display:inline" onsubmit="var r=prompt('Reason for rejecting (optional):','');if(r===null)return false;this.note.value=r;return true;"><input type="hidden" name="note"><button class="iconbtn danger" type="submit" title="Reject this document">Reject</button></form>` : ''}
        ${canRemove ? `<form method="post" action="/documents/${d.id}/delete" style="display:inline" onsubmit="return confirm('Permanently delete this document? This removes the file and may change the staff member\\'s compliance status.')"><button class="iconbtn danger" type="submit" title="Delete">${miniIcon('trash')}</button></form>` : ''}
      </div></div>`;
  }).join('');
  const lvlDate = (s) => { const dd = daysUntil(s); return dd == null ? 'grey' : dd < 0 ? 'red' : dd <= 30 ? 'amber' : 'green'; };
  const tile = (lbl, val, sub, lvl) => `<div class="ctile ${lvl}"><div class="lbl">${esc(lbl)}</div><div class="val">${esc(val || 'Not recorded')}</div>${sub ? `<div class="sub">${esc(sub)}</div>` : ''}</div>`;
  const low = (s) => (s || '').toLowerCase();
  // Tiles reflect held evidence, not just a status word: a "Clear" DBS with no
  // certificate number and no uploaded certificate is not a green tile.
  // (`evidence` is loaded once at the top of the handler.)
  const hasDbsEvidence = isFilled(p.dbs_certificate_number) && evidence.document_categories.has('dbs_certificate');
  const hasRtwEvidence = isFilled(p.right_to_work_type) && evidence.document_categories.has('right_to_work');
  const dbsLvl = !hasDbsEvidence ? 'incomplete'
    : p.dbs_expiry ? lvlDate(p.dbs_expiry)
    : (low(p.dbs_status).includes('clear') ? 'green' : low(p.dbs_status).includes('pend') ? 'amber' : 'grey');
  const rtwLvl = !hasRtwEvidence ? 'incomplete'
    : p.right_to_work_expiry ? lvlDate(p.right_to_work_expiry)
    : (low(p.right_to_work_status).includes('confirm') ? 'green' : low(p.right_to_work_status).includes('pend') ? 'amber' : 'grey');
  const ccLvl = isFilled(p.care_certificate_date) && low(p.care_certificate_status).includes('complet') ? 'green'
    : low(p.care_certificate_status).includes('progress') ? 'amber' : 'incomplete';
  const refLvl = evidence.references_count >= 2 ? 'green' : evidence.references_count === 1 ? 'amber' : 'incomplete';
  // The overdue magnitude belongs on the tile itself — "664 days overdue" is the
  // fact a manager needs, and it should not require scrolling to the alerts table.
  const rtwDays = daysUntil(p.right_to_work_expiry);
  const rtwSub = rtwDays !== null && rtwDays < 0 ? `Review ${-rtwDays} days OVERDUE`
    : p.right_to_work_expiry ? `Review ${fmtDate(p.right_to_work_expiry)}`
    : (p.is_sponsored ? 'Sponsored worker' : 'No review date recorded');
  const tilesHtml = `<div class="cgrid">
    ${tile('DBS', p.dbs_status, hasDbsEvidence ? (p.dbs_expiry ? `Renews ${fmtDate(p.dbs_expiry)}` : '') : 'Certificate not on file', dbsLvl)}
    ${tile('Right to Work', p.right_to_work_status, rtwSub, rtwLvl)}
    ${tile('Care Certificate', p.care_certificate_status, p.care_certificate_date ? fmtDate(p.care_certificate_date) : '', ccLvl)}
    ${tile('Mandatory training', p.mandatory_training_expiry ? 'Valid' : (p.mandatory_training_date ? 'Recorded' : ''), p.mandatory_training_expiry ? `Expires ${fmtDate(p.mandatory_training_expiry)}` : '', p.mandatory_training_expiry ? lvlDate(p.mandatory_training_expiry) : 'grey')}
    ${tile('References', p.references_received, `${evidence.references_count} received`, refLvl)}</div>`;

  // ---- Right to Work risk banner (F-05) -------------------------------------
  // An overdue or never-completed RTW check is an illegal-working risk, so it is
  // stated in full on the record rather than living only in the alerts list.
  // Managers see the regulatory framing; the staff member sees a plain prompt to
  // contact their manager — same trigger, wording matched to who is reading.
  const rtwRisk = rightToWorkRisk(p);
  let rtwBanner = '';
  if (rtwRisk) {
    const forManager = isOversight(req.user.role);
    const warnIcon = '<svg class="rb-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 1 21h22L12 2Zm1 14h-2v2h2v-2Zm0-6h-2v4h2v-4Z"/></svg>';
    const headline = rtwRisk.level === 'overdue'
      ? `Right to Work review is ${rtwRisk.days} day${rtwRisk.days === 1 ? '' : 's'} overdue`
      : rtwRisk.level === 'no_basis' ? 'No Right to Work basis recorded'
      : 'Right to Work has not been confirmed';
    const detail = forManager
      ? `Continuing to employ this person without a valid Right to Work check is an illegal-working risk and may expose Sky Home Living Ltd to a Home Office civil penalty. Re-verify before their next shift and record the outcome. <a href="/staff/${u.id}/edit#rtw">Update Right to Work</a>`
      : 'Please contact your manager so your Right to Work check can be brought up to date.';
    rtwBanner = `<div class="riskbanner${forManager ? '' : ' soft'}" role="alert">${warnIcon}
      <div><div class="rb-title">${esc(headline)}</div><div class="rb-body">${detail}</div></div></div>`;
  }

  // ---- Onboarding approval pipeline (manager-only): offer letter → contract ----
  let onboardingHtml = '';
  if (canReview) {
    // A document gates the onboarding pipeline only if its file is actually on
    // disk. An 'approved' row whose file has since been deleted is not evidence —
    // same defect class as scoring a record with no evidence "Compliant".
    const approvedCats = new Set(docs.filter((d) => d.status === 'approved' && fileOnDisk(d.file_path)).map((d) => d.category));
    const reqDBS = approvedCats.has('dbs_certificate');
    const reqRTW = approvedCats.has('right_to_work') || approvedCats.has('visa_share_code');
    const reqRef = approvedCats.has('employment_reference');
    const docsApproved = reqDBS && reqRTW && reqRef;
    const offerIssued = u.offer_letter_status === 'issued' || u.offer_letter_status === 'accepted';
    const contractIssued = u.employment_contract_status === 'issued' || u.employment_contract_status === 'signed';
    const chip = (ok) => ok ? '<span class="chip green">Issued</span>' : '<span class="chip amber">Not yet</span>';
    const flash = req.query.onboard === 'needdocs' ? '<div class="flash err">Approve the DBS, Right to Work and reference documents before issuing an offer letter.</div>'
      : req.query.onboard === 'needoffer' ? '<div class="flash err">Issue the offer letter before approving for employment.</div>'
      : req.query.onboard === 'offer' ? '<div class="flash ok">Offer letter generated and issued.</div>'
      : req.query.onboard === 'contract' ? '<div class="flash ok">Approved for employment — contract and handbook acknowledgement generated.</div>' : '';

    let step1;
    if (offerIssued) {
      step1 = `<div class="doc-sub" style="color:var(--green)">Issued ${u.offer_letter_issued_at ? fmtDate(u.offer_letter_issued_at) : ''}</div>
        <a class="btn ghost sm" href="/manager/staff/${u.id}/offer-letter/pdf">${miniIcon('download')} Offer letter PDF</a>`;
    } else if (docsApproved) {
      step1 = `<p class="muted small" style="margin:.2rem 0 .5rem">All required documents are approved. Confirm the offer terms and generate the formal offer letter.</p>
        <form method="post" action="/manager/staff/${u.id}/offer-letter"><div class="form-grid">
          <div class="field"><label>Role title</label><input name="role_title" value="${esc(p.offer_role_title || p.job_title || '')}" required></div>
          <div class="field"><label>Start date</label><input type="date" name="start_date" value="${esc(p.offer_start_date || p.start_date || '')}"></div>
          <div class="field"><label>Hourly rate (£)</label><input name="hourly_rate" value="${esc(p.offer_hourly_rate || '')}" placeholder="e.g. 11.44" required></div>
          <div class="field"><label>Hours per week</label><input name="hours_per_week" value="${esc(p.offer_hours_per_week || '')}" placeholder="e.g. 37.5" required></div>
          <div class="field"><label>Probationary period</label><input name="probation_period" value="${esc(p.offer_probation || '6 months')}"></div>
        </div><button class="btn" type="submit">Generate Offer Letter</button></form>`;
    } else {
      const missing = [!reqDBS ? 'DBS certificate' : null, !reqRTW ? 'Right to Work' : null, !reqRef ? 'employment reference' : null].filter(Boolean).join(', ');
      step1 = `<p class="muted small" style="margin:.2rem 0 .5rem">Approve all required documents first — still needed: <b>${esc(missing)}</b>.</p>
        <button class="btn" disabled title="Approve required documents first">Generate Offer Letter</button>`;
    }

    let step2;
    if (contractIssued) {
      step2 = `<div class="doc-sub" style="color:var(--green)">Issued ${u.employment_contract_issued_at ? fmtDate(u.employment_contract_issued_at) : ''}</div>
        <a class="btn ghost sm" href="/manager/staff/${u.id}/employment-contract/pdf">${miniIcon('download')} Employment contract</a>
        <a class="btn ghost sm" href="/manager/staff/${u.id}/staff-handbook/pdf">${miniIcon('download')} Staff handbook acknowledgement</a>`;
    } else if (offerIssued) {
      step2 = `<p class="muted small" style="margin:.2rem 0 .5rem">A separate, later approval. It generates the employment contract and the staff handbook acknowledgement together.</p>
        <form method="post" action="/manager/staff/${u.id}/employment-contract" onsubmit="return confirm('Approve this staff member for employment? This generates and issues their employment contract and staff handbook acknowledgement.')"><button class="btn" type="submit">Approve for Employment</button></form>`;
    } else {
      step2 = `<p class="muted small" style="margin:.2rem 0 .5rem">Available once the offer letter has been issued.</p>
        <button class="btn" disabled title="Issue the offer letter first">Approve for Employment</button>`;
    }

    onboardingHtml = `<div class="card" style="margin-bottom:1rem"><div class="card-h">Onboarding — offer &amp; contract <span class="muted small" style="font-weight:400">· manager only</span></div>
      <div class="card-b">${flash}
        <div style="display:flex;gap:.9rem;align-items:flex-start">
          <div style="flex:0 0 1.6rem;font-weight:700">1</div>
          <div style="flex:1"><div style="margin-bottom:.3rem"><b>Step 1 · Offer letter</b> ${chip(offerIssued)}</div>${step1}</div></div>
        <div style="display:flex;gap:.9rem;align-items:flex-start;margin-top:1rem;border-top:1px solid var(--line-2);padding-top:1rem">
          <div style="flex:0 0 1.6rem;font-weight:700">2</div>
          <div style="flex:1"><div style="margin-bottom:.3rem"><b>Step 2 · Employment contract &amp; handbook</b> ${chip(contractIssued)}</div>${step2}</div></div>
      </div></div>`;
  }

  const body = `
  <div class="hero">
    ${avatarTag(u.id, p.photo_path, p.full_name || u.email, 'lg')}
    <div class="hero-meta">
      <h1>${esc(p.full_name || u.email)}</h1>
      <div class="sub">${esc(p.job_title || roleLabel(u.role))} · ${esc(u.email)}</div>
      <div style="margin-top:.55rem;display:flex;gap:.4rem;flex-wrap:wrap">${u.is_active === 0 ? '<span class="badge red">Inactive</span>' : ''}${ragBadge(c.rag)}${p.is_sponsored ? '<span class="badge">Sponsored worker</span>' : ''}${p.status && p.status !== 'active' ? `<span class="badge">${esc(p.status)}</span>` : ''}</div>
    </div>
    <div class="hero-actions">
      ${isOversight(req.user.role) ? `<a class="btn ghost" href="/staff/${u.id}/export.zip" title="ZIP of all documents + PDF summary for CQC/HMRC">${icon('pack')} Document pack</a><a class="btn ghost" href="/staff/${u.id}/summary.pdf">Summary PDF</a>` : ''}
      ${canEdit ? `<a class="btn ghost" href="/staff/${u.id}/edit">Edit record</a>` : ''}
      ${isManagerLevel(req.user.role) && u.role !== 'admin' && u.id !== req.user.id ? (u.is_active === 0
        ? `<form method="post" action="/manager/staff/${u.id}/reactivate" style="display:inline"><button class="btn ghost" type="submit" title="Restore access for this staff member">Reactivate</button></form>`
        : `<form method="post" action="/manager/staff/${u.id}/deactivate" style="display:inline" onsubmit="return confirm('Deactivate this staff member? This immediately signs them out of all devices and blocks sign-in until you reactivate them.')"><button class="btn ghost danger" type="submit" title="Revoke access and sign out of all devices">Deactivate</button></form>`) : ''}
    </div>
  </div>
  ${rtwBanner}
  ${tilesHtml}
  ${c.alerts.length ? `<div class="card" style="margin-bottom:1rem"><div class="card-h">Renewals &amp; missing evidence
    <span class="muted small" style="font-weight:400">· ${c.counts.missing} missing · ${c.counts.expired} expired</span></div><div class="card-b" style="padding:0">
    <table class="tbl"><tbody>${c.alerts.map((a) => `<tr><td>${esc(a.label)}</td><td class="muted">${esc(a.area)}</td>
      <td>${a.level === 'missing' ? '<span class="muted">—</span>' : fmtDate(a.date)}</td><td>${levelBadge(a.level, alertStatusText(a))}</td></tr>`).join('')}</tbody></table></div></div>` : ''}
  <div class="card" style="margin-bottom:1rem"><div class="card-h"><span>Documents <span class="muted small" style="font-weight:400">· ${docs.length} on file${docs.filter((d) => d.status === 'pending').length ? ` · ${docs.filter((d) => d.status === 'pending').length} pending review` : ''}</span></span>
    ${canEdit ? `<a class="btn ghost sm" href="/staff/${u.id}/edit#documents">Upload</a>` : ''}</div>
    <div class="card-b" style="padding:0">${docs.length ? `<div class="doc-list">${docRowsHtml}</div>` : '<div class="card-b muted">No documents uploaded yet.</div>'}</div></div>
  ${onboardingHtml}
  <div class="card" style="margin-bottom:1rem"><div class="card-h">Employment history <span class="muted small">CQC Schedule 3</span></div>
    <div class="card-b" style="padding:0">
    <table class="tbl"><thead><tr><th>Employer</th><th>Role</th><th>From</th><th>To</th><th>Care role</th><th>Reason for leaving</th>${canRemove ? '<th></th>' : ''}</tr></thead><tbody>
    ${emp.map((e) => `<tr><td><b>${esc(e.employer)}</b>${e.gap_explanation ? `<div class="muted small">Gap: ${esc(e.gap_explanation)}</div>` : ''}</td><td>${esc(e.job_title)}</td><td>${fmtDate(e.from_date)}</td><td>${e.to_date ? fmtDate(e.to_date) : 'Present'}</td><td>${e.is_care_role ? '<span class="badge blue">Care</span>' : '—'}</td><td class="muted">${esc(e.reason_for_leaving)}</td>${canRemove ? `<td><form method="post" action="/staff/${u.id}/employment/${e.id}/delete" onsubmit="return confirm('Delete this employment history entry? It is CQC Schedule 3 evidence.')"><button class="linkbtn danger" type="submit">Delete</button></form></td>` : ''}</tr>`).join('') || `<tr><td colspan="${canRemove ? 7 : 6}" class="muted" style="padding:1rem">No employment history recorded.</td></tr>`}
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
    <table class="tbl"><thead><tr><th>Referee</th><th>Organisation</th><th>Relationship</th><th>Recent employer</th><th>Status</th>${canRemove ? '<th></th>' : ''}</tr></thead><tbody>
    ${refs.map((r) => `<tr><td><b>${esc(r.referee_name)}</b></td><td>${esc(r.referee_org)}</td><td>${esc(r.relationship)}</td><td>${r.is_most_recent_employer ? 'Yes' : '—'}</td><td>${levelBadge(r.status === 'received' ? 'ok' : r.status === 'rejected' ? 'expired' : 'warning', r.status)}</td>${canRemove ? `<td><form method="post" action="/staff/${u.id}/references/${r.id}/delete" onsubmit="return confirm('Delete this reference? This may change the compliance status of the record.')"><button class="linkbtn danger" type="submit">Delete</button></form></td>` : ''}</tr>`).join('') || `<tr><td colspan="${canRemove ? 6 : 5}" class="muted" style="padding:1rem">No references recorded.</td></tr>`}
    </tbody></table>
    ${canEdit ? `<form method="post" action="/staff/${u.id}/references" class="card-b" style="border-top:1px solid var(--line-2)"><div class="form-grid">
      <div class="field"><label>Referee name</label><input name="referee_name" required></div>
      <div class="field"><label>Organisation</label><input name="referee_org"></div>
      <div class="field"><label>Relationship</label><input name="relationship" placeholder="e.g. Former line manager"></div>
      ${canVerifyEvidence(req.user)
        ? '<div class="field"><label>Status</label><select name="status"><option value="requested">Requested</option><option value="received">Received</option><option value="rejected">Rejected</option></select></div>'
        : '<div class="field"><label>Status</label><input value="Requested" disabled><div class="muted small">Your manager records a reference as received once they have it.</div></div>'}
    </div><div class="checkrow"><input type="checkbox" id="recent_emp" name="is_most_recent_employer" value="1"><label for="recent_emp">Most recent employer</label></div>
    <button class="btn sm">Add reference</button></form>` : ''}
    </div></div>
  <div class="sectnav">${sectNav}</div>
  ${sections}`;
  res.send(layout({ user: req.user, title: p.full_name || 'Record', active: '/staff', body }));
});

// ---- profile edit ----------------------------------------------------------
app.get('/staff/:id/edit', requireAuth, (req, res) => {
  if (!canEditStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to edit this record.' }));
  const u = getUser(req.params.id); if (!u) return res.status(404).send(errorPage({ user: req.user, code: 404, title: 'Record not found', message: 'That record no longer exists.' }));
  const p = getProfile(u.id);
  const isManager = isManagerLevel(req.user.role);
  const sections = PROFILE_SECTIONS.map((s) => `
    <div class="card" id="${s.id}" style="margin-bottom:1rem"><div class="card-h">${esc(s.title)}</div>
      <div class="card-b"><div class="form-grid">${s.fields.map((f) =>
        (isManager || isSelfEditableKey(f.key)) ? renderEditField(f, p[f.key]) : renderViewField(f, p[f.key])
      ).join('')}</div></div></div>`).join('');
  const cats = DOCUMENT_CATEGORIES.map((c) => `<option value="${c.value}">${esc(c.label)}</option>`).join('');
  const body = `
  <div class="page-head"><div><h1>Edit record</h1><p class="muted">${esc(p.full_name || u.email)}</p></div>
    <a class="btn ghost" href="/staff/${u.id}">Cancel</a></div>
  ${!isManager ? `<div class="flash info">Please fill in your own details below and upload your documents. The <b>verification fields</b> (DBS, Right to Work and training <i>status</i>) are confirmed by your manager and shown read-only — that's why they can't be edited here.</div>` : ''}
  <div class="card" style="margin-bottom:1rem"><div class="card-h">Profile photo</div><div class="card-b">
    <div class="photo-edit">
      ${avatarTag(u.id, p.photo_path, p.full_name || u.email, 'lg')}
      <form method="post" action="/staff/${u.id}/photo" enctype="multipart/form-data" class="photo-form">
        <input type="file" name="photo" accept=".png,.jpg,.jpeg,.webp,.heic,.heif" required>
        <button class="btn sm" type="submit">Upload photo</button>
      </form>
      ${p.photo_path ? `<form method="post" action="/staff/${u.id}/photo/delete" onsubmit="return confirm('Remove profile photo?')"><button class="btn ghost sm" type="submit">Remove</button></form>` : ''}
    </div>
    <p class="small muted" style="margin:.6rem 0 0">A clear head-and-shoulders photo helps colleagues recognise you. PNG, JPG or WebP, up to 5&nbsp;MB.</p>
  </div></div>
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
  if (!canEditStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to edit this record.' }));
  const u = getUser(req.params.id); if (!u) return res.status(404).send(errorPage({ user: req.user, code: 404, title: 'Record not found', message: 'That record no longer exists.' }));
  // Managers/admins may edit the whole record; a staff member editing their own
  // record may only change contact details — never their own compliance status.
  const isManager = isManagerLevel(req.user.role);
  const editableKeys = isManager ? PROFILE_KEYS : PROFILE_KEYS.filter(isSelfEditableKey);
  const checkboxKeys = new Set(PROFILE_SECTIONS.flatMap((s) => s.fields.filter((f) => f.type === 'checkbox').map((f) => f.key)));
  if (editableKeys.length) {
    const vals = editableKeys.map((k) => (checkboxKeys.has(k) ? (req.body[k] ? 1 : 0) : (req.body[k] ?? '').toString()));
    // Upsert, not a bare UPDATE: accounts created outside the invite/registration
    // flow can have no profiles row yet, and a plain UPDATE silently affects zero
    // rows for them — the form appears to save but nothing is ever persisted.
    const cols = ['user_id', ...editableKeys, 'updated_at'];
    const setClause = [...editableKeys.map((k) => `${k}=excluded.${k}`), 'updated_at=excluded.updated_at'].join(',');
    db.prepare(`INSERT INTO profiles (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})
      ON CONFLICT(user_id) DO UPDATE SET ${setClause}`).run(u.id, ...vals, Date.now());
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

// Profile photo upload (images only)
const PHOTO_EXT = new Set(['.png', '.jpg', '.jpeg', '.webp', '.heic', '.heif']);
const photoUpload = multer({
  storage: multer.diskStorage({
    destination: (_q, _f, cb) => cb(null, PHOTOS_DIR),
    filename: (req, file, cb) => cb(null, `photo-${req.params.id}-${randomBytes(4).toString('hex')}${path.extname(file.originalname).toLowerCase()}`),
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_q, file, cb) => cb(null, PHOTO_EXT.has(path.extname(file.originalname).toLowerCase())),
});

app.post('/staff/:id/documents', requireAuth, (req, res) => {
  if (!canEditStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to edit this record.' }));
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
// Deleting evidence is management-only, including on your own record. Staff who
// need a document corrected upload a replacement instead (the newer upload
// supersedes the older one); the original stays on file for the audit trail
// until a manager removes it.
app.post('/documents/:id/delete', requireAuth, (req, res) => {
  const d = db.prepare('SELECT * FROM documents WHERE id=?').get(req.params.id);
  if (!d || !canAccessStaff(req.user, d.user_id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to view this record.' }));
  if (!canDeleteEvidence(req.user)) {
    audit(req.user, 'delete_document_denied', d.user_id, categoryLabel(d.category));
    return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed',
      message: 'Only a manager can remove a compliance document. If this document is wrong or out of date, upload a replacement — your manager will review it and the original stays on file until then.' }));
  }
  try { fs.unlinkSync(path.join(UPLOADS_DIR, path.basename(d.file_path))); } catch {}
  db.prepare('DELETE FROM documents WHERE id=?').run(d.id);
  audit(req.user, 'delete_document', d.user_id, `${categoryLabel(d.category)}${d.title ? ` — ${d.title}` : ''}`);
  res.redirect(`/staff/${d.user_id}`);
});

// ---- document review (manager-level: approve / reject) ---------------------
app.post('/documents/:id/approve', requireManager, (req, res) => {
  const d = db.prepare('SELECT * FROM documents WHERE id=?').get(req.params.id);
  if (!d) return res.status(404).send(errorPage({ user: req.user, code: 404, title: 'Record not found', message: 'That document no longer exists.' }));
  db.prepare("UPDATE documents SET status='approved', reviewed_by_email=?, reviewed_at=?, review_note='' WHERE id=?")
    .run(req.user.email, Date.now(), d.id);
  audit(req.user, 'approve_document', d.user_id, categoryLabel(d.category));
  res.redirect(`/staff/${d.user_id}`);
});
app.post('/documents/:id/reject', requireManager, (req, res) => {
  const d = db.prepare('SELECT * FROM documents WHERE id=?').get(req.params.id);
  if (!d) return res.status(404).send(errorPage({ user: req.user, code: 404, title: 'Record not found', message: 'That document no longer exists.' }));
  db.prepare("UPDATE documents SET status='rejected', reviewed_by_email=?, reviewed_at=?, review_note=? WHERE id=?")
    .run(req.user.email, Date.now(), String(req.body.note || '').slice(0, 300), d.id);
  audit(req.user, 'reject_document', d.user_id, categoryLabel(d.category));
  res.redirect(`/staff/${d.user_id}`);
});

// ---- profile photo ---------------------------------------------------------
app.get('/staff/:id/photo', requireAuth, (req, res) => {
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).end();
  const p = getProfile(req.params.id);
  if (!p.photo_path) return res.status(404).end();
  const fp = path.join(PHOTOS_DIR, path.basename(p.photo_path));
  if (!fs.existsSync(fp)) return res.status(404).end();
  res.setHeader('Cache-Control', 'private, max-age=300');
  res.sendFile(fp);
});
app.post('/staff/:id/photo', requireAuth, (req, res) => {
  if (!canEditStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to edit this record.' }));
  photoUpload.single('photo')(req, res, (err) => {
    if (err) return res.status(400).send('Upload failed: ' + err.message);
    if (!req.file) return res.status(400).send('Choose a PNG, JPG or WebP image (up to 5 MB).');
    const prev = getProfile(req.params.id).photo_path;
    db.prepare('UPDATE profiles SET photo_path=?, updated_at=? WHERE user_id=?').run(req.file.filename, Date.now(), req.params.id);
    if (prev && prev !== req.file.filename) { try { fs.unlinkSync(path.join(PHOTOS_DIR, path.basename(prev))); } catch {} }
    audit(req.user, 'update_photo', Number(req.params.id));
    res.redirect(`/staff/${req.params.id}/edit`);
  });
});
app.post('/staff/:id/photo/delete', requireAuth, (req, res) => {
  if (!canEditStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to edit this record.' }));
  const p = getProfile(req.params.id);
  if (p.photo_path) { try { fs.unlinkSync(path.join(PHOTOS_DIR, path.basename(p.photo_path))); } catch {} }
  db.prepare("UPDATE profiles SET photo_path='', updated_at=? WHERE user_id=?").run(Date.now(), req.params.id);
  audit(req.user, 'remove_photo', Number(req.params.id));
  res.redirect(`/staff/${req.params.id}/edit`);
});

// ---- exports: compliance pack (PDF summary + ZIP of documents) -------------
app.get('/staff/:id/summary.pdf', requireAuth, async (req, res) => {
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to view this record.' }));
  const u = getUser(req.params.id); if (!u) return res.status(404).send(errorPage({ user: req.user, code: 404, title: 'Record not found', message: 'That record no longer exists.' }));
  const p = getProfile(u.id); const docs = listDocs(u.id);
  audit(req.user, 'export_summary_pdf', u.id);
  const buf = await pdfBuffer((doc) => writeSummary(doc, { profile: attachEvidenceOne(p, u.id), user: u, docs, actor: req.user }));
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
  await streamZip(res, { profile: attachEvidenceOne(p, u.id), user: u, docs, actor: req.user, uploadsDir: UPLOADS_DIR });
});

// Cross-staff export: every document of one category, across all staff, in a
// single ZIP. Manager-only (contains many people's personal data at once).
app.get('/exports/documents/:category.zip', requireManager, async (req, res) => {
  const category = req.params.category;
  if (!DOCUMENT_CATEGORIES.some((c) => c.value === category))
    return res.status(400).send(errorPage({ user: req.user, code: 400, title: 'Unknown document type', message: 'That document type is not recognised.' }));
  const rows = db.prepare(
    `SELECT d.*, p.full_name, u.email
       FROM documents d
       JOIN users u ON u.id = d.user_id
       LEFT JOIN profiles p ON p.user_id = u.id
      WHERE d.category = ?
      ORDER BY p.full_name, u.email, d.uploaded_at`
  ).all(category);
  audit(req.user, 'export_category_zip', null, category);
  await streamCategoryZip(res, { category, rows, uploadsDir: UPLOADS_DIR });
});

// ---- employment history & references ---------------------------------------
app.post('/staff/:id/employment', requireAuth, (req, res) => {
  if (!canEditStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to edit this record.' }));
  db.prepare('INSERT INTO employment_history (user_id,employer,job_title,from_date,to_date,is_care_role,reason_for_leaving,gap_explanation,created_at) VALUES (?,?,?,?,?,?,?,?,?)')
    .run(req.params.id, req.body.employer || '', req.body.job_title || '', req.body.from_date || '', req.body.to_date || '', req.body.is_care_role ? 1 : 0, req.body.reason_for_leaving || '', req.body.gap_explanation || '', Date.now());
  audit(req.user, 'add_employment', Number(req.params.id));
  res.redirect(`/staff/${req.params.id}`);
});
// Employment history is CQC Schedule 3 evidence — a gap a staff member could
// quietly remove is exactly what the record exists to show. Management-only.
app.post('/staff/:id/employment/:eid/delete', requireAuth, (req, res) => {
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to view this record.' }));
  if (!canDeleteEvidence(req.user)) {
    audit(req.user, 'delete_employment_denied', Number(req.params.id));
    return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed',
      message: 'Only a manager can remove an employment history entry. If something is wrong, ask your manager to correct it.' }));
  }
  db.prepare('DELETE FROM employment_history WHERE id=? AND user_id=?').run(req.params.eid, req.params.id);
  audit(req.user, 'delete_employment', Number(req.params.id));
  res.redirect(`/staff/${req.params.id}`);
});
app.post('/staff/:id/references', requireAuth, (req, res) => {
  if (!canEditStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to edit this record.' }));
  // A staff member may supply referee details, but only management may record a
  // reference as RECEIVED. 'received' is what the compliance engine counts, so
  // letting the subject set it would be self-certification — the same thing
  // MANAGER_ONLY_KEYS already prevents for DBS and Right to Work.
  const requested = String(req.body.status || 'requested');
  const status = canVerifyEvidence(req.user) ? requested : 'requested';
  if (status !== requested) audit(req.user, 'reference_status_downgraded', Number(req.params.id), `requested "${requested}" → recorded "requested"`);
  db.prepare('INSERT INTO reference_checks (user_id,referee_name,referee_org,relationship,is_most_recent_employer,status,created_at) VALUES (?,?,?,?,?,?,?)')
    .run(req.params.id, req.body.referee_name || '', req.body.referee_org || '', req.body.relationship || '', req.body.is_most_recent_employer ? 1 : 0, status, Date.now());
  audit(req.user, 'add_reference', Number(req.params.id), `${req.body.referee_name || '(unnamed)'} — ${status}`);
  res.redirect(`/staff/${req.params.id}`);
});
// A received reference is compliance evidence; removing one changes the record's
// status. Management-only, as with documents and employment history.
app.post('/staff/:id/references/:rid/delete', requireAuth, (req, res) => {
  if (!canAccessStaff(req.user, req.params.id)) return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'You do not have permission to view this record.' }));
  if (!canDeleteEvidence(req.user)) {
    audit(req.user, 'delete_reference_denied', Number(req.params.id));
    return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed',
      message: 'Only a manager can remove a reference. If a referee’s details are wrong, ask your manager to update them.' }));
  }
  db.prepare('DELETE FROM reference_checks WHERE id=? AND user_id=?').run(req.params.rid, req.params.id);
  audit(req.user, 'delete_reference', Number(req.params.id));
  res.redirect(`/staff/${req.params.id}`);
});

// ---- completeness API (file-completeness score; manager/admin only) --------
app.get('/api/completeness', requireManager, (_req, res) => {
  res.json(scoreAllStaff());
});

// ---- alerts ----------------------------------------------------------------
app.get('/alerts', requireOversight, (req, res) => {
  const rows = [];
  for (const s of attachEvidence(listStaff())) for (const a of computeCompliance(s).alerts) rows.push({ s, a });
  // Expired first (most overdue first), then never-recorded, then due soon.
  // Missing items carry days:null and must not reach a numeric comparison.
  const RANK = { expired: 0, missing: 1, critical: 2, warning: 3 };
  rows.sort((x, y) => (RANK[x.a.level] - RANK[y.a.level])
    || (x.a.days === null || y.a.days === null
      ? String(x.s.full_name || x.s.email).localeCompare(String(y.s.full_name || y.s.email))
      : x.a.days - y.a.days));
  const nMissing = rows.filter((r) => r.a.level === 'missing').length;
  const nExpired = rows.filter((r) => r.a.level === 'expired').length;
  const view = String(req.query.show || 'all');
  const shown = view === 'missing' ? rows.filter((r) => r.a.level === 'missing')
    : view === 'expired' ? rows.filter((r) => r.a.level === 'expired')
    : rows;
  const showPill = (v, label, n) => `<a class="${view === v ? 'on' : ''}" href="/alerts?show=${v}">${label}<span class="c">${n}</span></a>`;
  const body = `
  <div class="page-head"><div><h1>Compliance alerts</h1><p class="muted">${nExpired} expired · ${nMissing} missing entirely · ${rows.length - nExpired - nMissing} due soon</p></div></div>
  <div class="filters">${showPill('all', 'All', rows.length)}${showPill('expired', 'Expired', nExpired)}${showPill('missing', 'Missing evidence', nMissing)}</div>
  ${req.query.reminder === 'sent' ? `<div class="card" style="margin-bottom:1rem"><div class="card-b" style="color:#1a7f4b">✓ Reminder digest emailed to ${esc(req.query.n || '')} recipient(s).</div></div>` : ''}
  ${req.query.reminder === 'error' ? `<div class="card" style="margin-bottom:1rem"><div class="card-b" style="color:#b42318">Could not send: ${esc(req.query.msg || '')}</div></div>` : ''}
  <div class="card" style="margin-bottom:1rem"><div class="card-h">Email reminders ${mailConfigured() ? '<span class="badge green">Active</span>' : '<span class="badge amber">Not configured</span>'}</div>
    <div class="card-b" style="display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap">
      <div class="small muted">${mailConfigured() ? `Daily digest to: ${esc(recipients().join(', '))}.${lastSentAt() ? ` Last sent ${new Date(lastSentAt()).toLocaleString('en-GB')}.` : ' Not sent yet.'}` : 'Set the RESEND_API_KEY environment variable to enable automatic daily reminders.'}</div>
      <form method="post" action="/admin/send-reminders"><button class="btn sm" ${mailConfigured() ? '' : 'disabled'}>Send reminders now</button></form>
    </div></div>
  <div class="card"><div class="card-b" style="padding:0">
  <table class="tbl"><thead><tr><th>Staff</th><th>Requirement</th><th>Date</th><th>Status</th></tr></thead><tbody>
  ${shown.map(({ s, a }) => `<tr onclick="location='/staff/${s.id}'" style="cursor:pointer">
    <td><b>${esc(s.full_name || s.email)}</b></td><td>${esc(a.label)} <span class="muted small">· ${esc(a.area)}</span></td>
    <td>${a.level === 'missing' ? '<span class="muted">—</span>' : fmtDate(a.date)}</td><td>${levelBadge(a.level, alertStatusText(a))}</td></tr>`).join('')
    || '<tr><td colspan="4" class="muted" style="padding:1rem">No alerts — everyone is up to date.</td></tr>'}
  </tbody></table></div></div>`;
  res.send(layout({ user: req.user, title: 'Alerts', active: '/alerts', body }));
});

app.post('/admin/send-reminders', requireManager, async (req, res) => {
  let r;
  try { r = await sendDigest(); } catch (e) { r = { sent: false, reason: e.message }; }
  audit(req.user, 'send_reminders', null, r.sent ? `to ${r.to.length}` : r.reason);
  res.redirect(r.sent ? `/alerts?reminder=sent&n=${r.to.length}` : `/alerts?reminder=error&msg=${encodeURIComponent(r.reason)}`);
});

// ---- manager password-reset fallback (for staff who can't receive email) ---
app.get('/manager/password-resets', requireManager, (req, res) => {
  const origin = `${req.protocol}://${req.get('host')}`;
  const now = Date.now();
  const outstanding = db.prepare(
    `SELECT pr.token, pr.created_at, pr.expires_at, u.email
       FROM password_resets pr JOIN users u ON u.id = pr.user_id
      WHERE pr.used_at IS NULL AND pr.expires_at > ?
      ORDER BY pr.created_at DESC`
  ).all(now);
  const staff = listStaff();
  const linkRows = outstanding.map((r) => {
    const url = `${origin}/reset?token=${r.token}`;
    return `<tr>
      <td><b>${esc(r.email)}</b></td>
      <td class="small">${new Date(r.created_at).toLocaleString('en-GB')}</td>
      <td class="small">${new Date(r.expires_at).toLocaleString('en-GB')}</td>
      <td><div style="display:flex;gap:.4rem;align-items:center">
        <input class="reset-url" value="${esc(url)}" readonly onclick="this.select()" style="flex:1;min-width:220px;font-size:.78rem;padding:.35rem .5rem;border:1px solid var(--line);border-radius:7px;background:#fff">
        <button type="button" class="btn ghost sm" data-copy="${esc(url)}">Copy</button></div></td></tr>`;
  }).join('') || '<tr><td colspan="4" class="muted" style="padding:1rem">No outstanding self-service reset links.</td></tr>';
  const body = `
  <div class="page-head"><div><h1>Password resets</h1><p class="muted">Help staff who can't receive the reset email</p></div></div>
  ${req.query.set ? '<div class="card" style="margin-bottom:1rem"><div class="card-b" style="color:#1a7f4b">✓ Temporary password set. The staff member must change it the next time they sign in, and any existing sessions were ended.</div></div>' : ''}
  ${req.query.err ? `<div class="card" style="margin-bottom:1rem"><div class="card-b" style="color:#b42318">${esc(req.query.err)}</div></div>` : ''}
  <div class="card" style="margin-bottom:1.2rem"><div class="card-h">Set a temporary password</div><div class="card-b">
    <p class="muted small" style="margin-top:0">Choose a staff member and a temporary password to read out to them. They'll be forced to set their own the next time they sign in, and this signs them out of any existing sessions.</p>
    <form method="post" action="/manager/reset-password"><div class="form-grid">
      <div class="field"><label>Staff member</label><select name="user_id" required>
        <option value="">Select…</option>
        ${staff.map((s) => `<option value="${s.id}">${esc(s.full_name || s.email)} — ${esc(s.email)}</option>`).join('')}
      </select></div>
      <div class="field"><label>Temporary password (min 8 characters)</label><input name="temp_password" type="text" minlength="8" required autocomplete="off"></div>
    </div><button class="btn" type="submit">Set temporary password</button></form>
  </div></div>
  <div class="card"><div class="card-h">Outstanding self-service reset links <span class="muted small" style="font-weight:400">· ${outstanding.length}</span></div>
    <div class="card-b" style="padding:0">
    <table class="tbl"><thead><tr><th>Staff email</th><th>Requested</th><th>Valid until</th><th>Reset link</th></tr></thead>
    <tbody>${linkRows}</tbody></table></div></div>`;
  const scripts = `<script>
    document.querySelectorAll('[data-copy]').forEach(function(b){
      b.addEventListener('click',function(){
        var v=b.getAttribute('data-copy');
        navigator.clipboard.writeText(v).then(function(){var t=b.textContent;b.textContent='Copied';setTimeout(function(){b.textContent=t;},1200);});
      });
    });
  </script>`;
  res.send(layout({ user: req.user, title: 'Password resets', active: '/manager/password-resets', body, scripts }));
});

app.post('/manager/reset-password', requireManager, (req, res) => {
  const uid = Number(req.body.user_id);
  const target = uid ? getUser(uid) : null;
  if (!target || target.role === 'admin') return res.redirect('/manager/password-resets?err=' + encodeURIComponent('Choose a valid staff member.'));
  const temp = String(req.body.temp_password || '');
  if (temp.length < 8) return res.redirect('/manager/password-resets?err=' + encodeURIComponent('Temporary password must be at least 8 characters.'));
  db.prepare('UPDATE users SET password=?, must_change_password=1, failed_logins=0, locked_until=0 WHERE id=?')
    .run(hashPassword(temp), uid);
  db.prepare('DELETE FROM sessions WHERE user_id=?').run(uid);
  audit(req.user, 'manager_set_temp_password', uid, target.email);
  res.redirect('/manager/password-resets?set=1');
});

// ---- offboarding: deactivate / reactivate (manager-level) ------------------
// Deactivating revokes access immediately: is_active=0 blocks all future
// requests and every existing session row is deleted, logging the user out of
// all devices at once. Reactivating restores sign-in (for rehires/corrections).
app.post('/manager/staff/:id/deactivate', requireManager, (req, res) => {
  const u = getUser(req.params.id);
  if (!u) return res.status(404).send(errorPage({ user: req.user, code: 404, title: 'Record not found', message: 'That record no longer exists.' }));
  if (u.role === 'admin') return res.status(403).send(errorPage({ user: req.user, code: 403, title: 'Not allowed', message: 'Admin accounts cannot be deactivated here.' }));
  if (u.id === req.user.id) return res.status(400).send(errorPage({ user: req.user, code: 400, title: 'Not allowed', message: 'You cannot deactivate your own account.' }));
  db.prepare('UPDATE users SET is_active=0 WHERE id=?').run(u.id);
  db.prepare('DELETE FROM sessions WHERE user_id=?').run(u.id);
  audit(req.user, 'deactivate_staff', u.id, u.email);
  res.redirect(`/staff/${u.id}`);
});
app.post('/manager/staff/:id/reactivate', requireManager, (req, res) => {
  const u = getUser(req.params.id);
  if (!u) return res.status(404).send(errorPage({ user: req.user, code: 404, title: 'Record not found', message: 'That record no longer exists.' }));
  db.prepare('UPDATE users SET is_active=1 WHERE id=?').run(u.id);
  audit(req.user, 'reactivate_staff', u.id, u.email);
  res.redirect(`/staff/${u.id}`);
});

// ---- onboarding pipeline: offer letter (stage 1) → contract + handbook (stage 2) ----
// Stage 1 requires the required onboarding documents (DBS, Right to Work, a
// reference) to be approved. Stage 2 is a distinct, later approval available only
// once the offer letter has been issued. Both generate branded PDFs stored on the
// user row; the handbook acknowledgement is regenerated on demand from its template.
const onboardingDocsApproved = (userId) => {
  const cats = new Set(db.prepare("SELECT category FROM documents WHERE user_id=? AND status='approved'").all(userId).map((r) => r.category));
  return cats.has('dbs_certificate') && (cats.has('right_to_work') || cats.has('visa_share_code')) && cats.has('employment_reference');
};
const onboardingCtx = (u, p) => ({
  staff_name: p.full_name || u.name || u.email,
  role_title: p.offer_role_title || p.job_title || '',
  start_date: p.offer_start_date || p.start_date || '',
  hourly_rate: p.offer_hourly_rate || '',
  hours_per_week: p.offer_hours_per_week || '',
  probation: p.offer_probation || '6 months',
  manager_name: DEFAULT_MANAGER,
});

app.post('/manager/staff/:id/offer-letter', requireManager, async (req, res) => {
  const u = getUser(req.params.id);
  if (!u) return res.status(404).send(errorPage({ user: req.user, code: 404, title: 'Record not found', message: 'That record no longer exists.' }));
  if (!onboardingDocsApproved(u.id)) return res.redirect(`/staff/${u.id}?onboard=needdocs`);
  const p = getProfile(u.id);
  const roleTitle = String(req.body.role_title || p.job_title || '').trim();
  const startDate = String(req.body.start_date || p.start_date || '').trim();
  const hourlyRate = String(req.body.hourly_rate || '').trim();
  const hoursPerWeek = String(req.body.hours_per_week || '').trim();
  const probation = String(req.body.probation_period || '').trim() || '6 months';
  db.prepare('UPDATE profiles SET offer_role_title=?, offer_start_date=?, offer_hourly_rate=?, offer_hours_per_week=?, offer_probation=?, updated_at=? WHERE user_id=?')
    .run(roleTitle, startDate, hourlyRate, hoursPerWeek, probation, Date.now(), u.id);
  const buf = await pdfBuffer((doc) => writeOfferLetter(doc, onboardingCtx(u, getProfile(u.id))));
  db.prepare("UPDATE users SET offer_letter_pdf=?, offer_letter_status='issued', offer_letter_issued_at=? WHERE id=?")
    .run(buf, new Date().toISOString(), u.id);
  audit(req.user, 'issue_offer_letter', u.id, roleTitle);
  res.redirect(`/staff/${u.id}?onboard=offer`);
});

app.get('/manager/staff/:id/offer-letter/pdf', requireManager, (req, res) => {
  const row = db.prepare('SELECT offer_letter_pdf FROM users WHERE id=?').get(req.params.id);
  if (!row || !row.offer_letter_pdf) return res.status(404).send(errorPage({ user: req.user, code: 404, title: 'Not generated', message: 'No offer letter has been generated for this staff member yet.' }));
  const p = getProfile(req.params.id);
  const safe = (p.full_name || 'staff').replace(/[^a-z0-9]+/gi, '_');
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${safe}_offer_letter.pdf"`);
  res.end(Buffer.from(row.offer_letter_pdf));
});

app.post('/manager/staff/:id/employment-contract', requireManager, async (req, res) => {
  const u = getUser(req.params.id);
  if (!u) return res.status(404).send(errorPage({ user: req.user, code: 404, title: 'Record not found', message: 'That record no longer exists.' }));
  if (u.offer_letter_status !== 'issued' && u.offer_letter_status !== 'accepted') return res.redirect(`/staff/${u.id}?onboard=needoffer`);
  const buf = await pdfBuffer((doc) => writeEmploymentContract(doc, onboardingCtx(u, getProfile(u.id))));
  const now = new Date().toISOString();
  db.prepare("UPDATE users SET employment_contract_pdf=?, employment_contract_status='issued', employment_contract_issued_at=?, handbook_acknowledged_at=? WHERE id=?")
    .run(buf, now, now, u.id);
  audit(req.user, 'approve_for_employment', u.id);
  res.redirect(`/staff/${u.id}?onboard=contract`);
});

app.get('/manager/staff/:id/employment-contract/pdf', requireManager, (req, res) => {
  const row = db.prepare('SELECT employment_contract_pdf FROM users WHERE id=?').get(req.params.id);
  if (!row || !row.employment_contract_pdf) return res.status(404).send(errorPage({ user: req.user, code: 404, title: 'Not generated', message: 'No employment contract has been generated for this staff member yet.' }));
  const p = getProfile(req.params.id);
  const safe = (p.full_name || 'staff').replace(/[^a-z0-9]+/gi, '_');
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${safe}_employment_contract.pdf"`);
  res.end(Buffer.from(row.employment_contract_pdf));
});

app.get('/manager/staff/:id/staff-handbook/pdf', requireManager, async (req, res) => {
  const u = getUser(req.params.id);
  if (!u || (u.employment_contract_status !== 'issued' && u.employment_contract_status !== 'signed'))
    return res.status(404).send(errorPage({ user: req.user, code: 404, title: 'Not available', message: 'The staff handbook acknowledgement is available once the staff member has been approved for employment.' }));
  const p = getProfile(u.id);
  const buf = await pdfBuffer((doc) => writeHandbookAck(doc, { staff_name: p.full_name || u.name || u.email, role_title: p.offer_role_title || p.job_title || '' }));
  const safe = (p.full_name || 'staff').replace(/[^a-z0-9]+/gi, '_');
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${safe}_staff_handbook_acknowledgement.pdf"`);
  res.end(buf);
});

// ---- invites ---------------------------------------------------------------
app.get('/admin/invites', requireManager, (req, res) => {
  const invites = db.prepare('SELECT * FROM invite_codes ORDER BY created_at DESC').all();
  const origin = `${req.protocol}://${req.get('host')}`;
  const body = `
  <div class="page-head"><div><h1>Invitations</h1><p class="muted">Invite a staff member to create their account</p></div></div>
  ${req.query.err ? `<div class="card" style="margin-bottom:1rem"><div class="card-b" style="color:#b42318">${esc(req.query.err)}</div></div>` : ''}
  <div class="card" style="margin-bottom:1.2rem"><div class="card-b">
    <form method="post" action="/admin/invites"><div class="form-grid">
      <div class="field"><label>Email</label><input name="email" type="email" required></div>
      <div class="field"><label>Full name</label><input name="full_name"></div>
      <div class="field"><label>Job title</label><input name="job_title"></div>
      <div class="field"><label>Role</label><select name="role">${ROLES.map((r) => `<option value="${r.value}"${r.value === 'carer' ? ' selected' : ''}>${esc(r.label)}</option>`).join('')}</select></div>
    </div><button class="btn">Create invite</button></div></form></div>
  <div class="card"><div class="card-b" style="padding:0">
  <table class="tbl"><thead><tr><th>Code</th><th>Email</th><th>Role</th><th>Expires</th><th>Status</th><th>Link</th></tr></thead><tbody>
  ${invites.map((i) => `<tr><td><code>${esc(i.code)}</code></td><td>${esc(i.email)}</td>
    <td>${esc(roleLabel(i.role || 'carer'))}</td>
    <td>${i.expires_at ? fmtDate(new Date(i.expires_at).toISOString()) : '—'}</td>
    <td>${i.used_at ? '<span class="badge grey">Used</span>' : (i.expires_at && i.expires_at < Date.now() ? '<span class="badge red">Expired</span>' : '<span class="badge green">Active</span>')}</td>
    <td class="small">${esc(origin)}/register</td></tr>`).join('') || '<tr><td colspan="6" class="muted" style="padding:1rem">No invites yet.</td></tr>'}
  </tbody></table></div></div>`;
  res.send(layout({ user: req.user, title: 'Invitations', active: '/admin/invites', body }));
});
app.post('/admin/invites', requireManager, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!email) return res.redirect('/admin/invites?err=' + encodeURIComponent('Email is required.'));
  if (getUserByEmail(email)) {
    return res.redirect('/admin/invites?err=' + encodeURIComponent('An account already exists for this email — no invite needed.'));
  }
  const code = `${rand4()}-${rand4()}-${rand4()}`;
  const now = Date.now();
  // Validate the requested role; only an admin may grant manager/admin.
  let role = ROLES.some((r) => r.value === req.body.role) ? req.body.role : 'carer';
  if (req.user.role !== 'admin' && (role === 'manager' || role === 'admin')) role = 'coordinator';
  // A fresh invite supersedes any prior unused one for the same email, so
  // re-inviting someone doesn't leave stale duplicate codes sitting around
  // showing as "Active" alongside the new one.
  db.prepare('DELETE FROM invite_codes WHERE email=? AND used_at IS NULL').run(email);
  db.prepare('INSERT INTO invite_codes (code,email,full_name,job_title,role,created_by_email,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?)')
    .run(code, email, req.body.full_name || '', req.body.job_title || '', role, req.user.email, now, now + 14 * 86400000);
  audit(req.user, 'create_invite', null, `${email} as ${role}`);
  res.redirect('/admin/invites');
});
const rand4 = () => randomBytes(3).toString('hex').toUpperCase().slice(0, 4);

// ---- audit -----------------------------------------------------------------
app.get('/admin/audit', requireManager, (req, res) => {
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

// ---- bulk email to staff ---------------------------------------------------
// Managers email all staff or a filtered subset. Reuses the app's shared mail
// sender (sendMail from reminders.js, via Resend) — no separate mail client. Each person
// gets their own individual message (never a shared BCC), so addresses are never
// exposed to one another. Every send is logged with per-recipient delivery
// status for the History tab.

// The recipient universe: every active user who has an email address.
const listEmailAudience = () => db.prepare(`
  SELECT u.id, u.email, u.role,
         COALESCE(NULLIF(p.full_name,''), NULLIF(u.name,''), u.email) AS name
    FROM users u LEFT JOIN profiles p ON p.user_id = u.id
   WHERE u.is_active = 1 AND u.email IS NOT NULL AND u.email != ''
   ORDER BY name COLLATE NOCASE, u.email`).all();

// urlencoded repeated fields arrive as an array (or a lone string, or absent).
const asArray = (v) => (v == null ? [] : Array.isArray(v) ? v : [v]);

function resolveEmailRecipients(mode, body) {
  const all = listEmailAudience();
  if (mode === 'role') {
    const roles = new Set(asArray(body.roles).map(String));
    return all.filter((u) => roles.has(u.role));
  }
  if (mode === 'individuals') {
    const ids = new Set(asArray(body.user_ids).map(Number));
    return all.filter((u) => ids.has(u.id));
  }
  return all; // 'all'
}

// Minimal branded HTML wrapper for the manager's plain-text message.
function bulkEmailHtml(text) {
  const safe = esc(text).replace(/\r\n|\r|\n/g, '<br>');
  return `<div style="font-family:Segoe UI,Arial,sans-serif;color:#1f2937;max-width:640px;font-size:15px;line-height:1.55">${safe}
    <p style="color:#9aa3af;font-size:12px;margin-top:26px">Sent via the Sky Home Living staff portal.</p></div>`;
}

const emailStatusBadge = (s) =>
  s === 'sent' ? '<span class="badge green">Sent</span>'
    : s === 'partial_failure' ? '<span class="badge amber">Partial failure</span>'
      : s === 'failed' ? '<span class="badge red">Failed</span>'
        : `<span class="badge grey">${esc(s || 'unknown')}</span>`;

app.get('/manager/bulk-email', requireManager, (req, res) => {
  const audience = listEmailAudience();
  const templates = db.prepare('SELECT id, name, subject, body FROM email_templates ORDER BY name COLLATE NOCASE').all();
  const activeTab = req.query.tab === 'history' ? 'history' : 'compose';

  const roleCounts = {};
  for (const u of audience) roleCounts[u.role] = (roleCounts[u.role] || 0) + 1;

  // Recent sends plus their per-recipient rows (grouped from one IN(...) query).
  const logs = db.prepare(`
    SELECT el.*, COALESCE(NULLIF(u.name,''), u.email) AS sent_by_name
      FROM email_log el LEFT JOIN users u ON u.id = el.sent_by
     ORDER BY el.sent_at DESC LIMIT 100`).all();
  const recipientsByLog = {};
  if (logs.length) {
    const ph = logs.map(() => '?').join(',');
    for (const r of db.prepare(`SELECT * FROM email_log_recipients WHERE email_log_id IN (${ph}) ORDER BY id`).all(...logs.map((l) => l.id))) {
      (recipientsByLog[r.email_log_id] ||= []).push(r);
    }
  }

  const flash = req.query.sent
    ? `<div class="flash ok">Email sent — ${esc(req.query.ok || '0')} delivered${Number(req.query.fail) ? `, ${esc(req.query.fail)} failed (see the delivery detail below)` : ''}.</div>`
    : req.query.err ? `<div class="flash err">${esc(req.query.err)}</div>` : '';

  const roleBoxes = ROLES.map((r) =>
    `<label class="cb-row"><input type="checkbox" name="roles" value="${r.value}" class="role-cb"> ${esc(r.label)} <span class="muted small">(${roleCounts[r.value] || 0})</span></label>`).join('');
  const individualItems = audience.map((u) =>
    `<label class="cb-row indiv-item" data-search="${esc((u.name + ' ' + u.email).toLowerCase())}"><input type="checkbox" name="user_ids" value="${u.id}" class="indiv-cb"> ${esc(u.name)} <span class="muted small">${esc(u.email)} · ${esc(roleLabel(u.role))}</span></label>`).join('');
  const tplOptions = templates.map((t) => `<option value="${t.id}">${esc(t.name)}</option>`).join('');

  const compose = `<div id="tab-compose" style="${activeTab === 'compose' ? '' : 'display:none'}">
    <form id="composeForm" method="post" action="/manager/bulk-email/send">
      <div class="card" style="margin-bottom:1rem"><div class="card-h">Recipients</div><div class="card-b">
        <label class="cb-row"><input type="radio" name="mode" value="all" class="mode-radio" checked> <b>All staff</b> <span class="muted small">(${audience.length})</span></label>
        <label class="cb-row"><input type="radio" name="mode" value="role" class="mode-radio"> <b>Filter by role</b></label>
        <div id="roleBox" class="mode-box" style="display:none;margin:.1rem 0 .5rem 1.6rem">${roleBoxes}</div>
        <label class="cb-row"><input type="radio" name="mode" value="individuals" class="mode-radio"> <b>Select individuals</b></label>
        <div id="individualBox" class="mode-box" style="display:none;margin:.1rem 0 .5rem 1.6rem">
          <div style="display:flex;gap:.5rem;align-items:center;margin-bottom:.5rem;flex-wrap:wrap">
            <input id="indivSearch" type="text" placeholder="Search name or email…" style="flex:1;min-width:180px;padding:.35rem .5rem;border:1px solid var(--line);border-radius:7px">
            <button type="button" class="btn ghost sm" id="selAll">Select all</button>
            <button type="button" class="btn ghost sm" id="selNone">Select none</button>
          </div>
          <div style="max-height:280px;overflow:auto;border:1px solid var(--line);border-radius:8px;padding:.4rem">${individualItems || '<div class="muted small">No staff found.</div>'}</div>
        </div>
        <p style="margin:.7rem 0 0">This email will be sent to <b id="recipientCount">0</b> recipient(s), each individually.</p>
      </div></div>

      <div class="card" style="margin-bottom:1rem"><div class="card-h">Message</div><div class="card-b">
        <div class="field"><label>Templates</label>
          <div style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:center">
            <select id="tplSelect" style="flex:1;min-width:180px;padding:.4rem .5rem;border:1px solid var(--line);border-radius:7px"><option value="">Load a template…</option>${tplOptions}</select>
            <button type="button" class="btn ghost sm" id="tplDelete">Delete template</button>
            <button type="button" class="btn ghost sm" id="tplSave">Save as template</button>
          </div>
        </div>
        <div class="field"><label>Subject</label><input id="subjectInput" name="subject" maxlength="200" required></div>
        <div class="field"><label>Message</label><textarea id="bodyInput" name="body" rows="12" required style="width:100%;font-family:inherit"></textarea></div>
      </div></div>

      <button type="submit" class="btn" id="sendBtn">Send email…</button>
    </form>
  </div>`;

  const historyRows = logs.map((l) => {
    const recs = recipientsByLog[l.id] || [];
    const detail = recs.map((r) => `<div style="padding:.2rem 0;border-bottom:1px solid var(--line)">${esc(r.email_address)} — ${r.status === 'sent' ? '<span class="chip green">Sent</span>' : '<span class="chip red">Failed</span>'} ${r.error_message ? `<span class="muted small">${esc(r.error_message)}</span>` : ''}</div>`).join('') || '<div class="muted small">No per-recipient records.</div>';
    return `<tr class="log-row" onclick="toggleLog(${l.id})" style="cursor:pointer">
        <td class="small">${new Date(l.sent_at).toLocaleString('en-GB')}</td>
        <td><b>${esc(l.subject)}</b></td>
        <td class="small">${esc(l.sent_by_name || 'system')}</td>
        <td>${l.recipient_count}</td>
        <td>${emailStatusBadge(l.status)}</td></tr>
      <tr id="log-detail-${l.id}" style="display:none"><td colspan="5" style="background:var(--panel,#f7f8fa)"><div style="padding:.5rem .3rem"><b class="small">Delivery detail</b>${detail}</div></td></tr>`;
  }).join('') || '<tr><td colspan="5" class="muted" style="padding:1rem">No bulk emails sent yet.</td></tr>';

  const history = `<div id="tab-history" style="${activeTab === 'history' ? '' : 'display:none'}">
    <div class="card"><div class="card-b" style="padding:0">
    <table class="tbl"><thead><tr><th>Date</th><th>Subject</th><th>Sent by</th><th>Recipients</th><th>Status</th></tr></thead>
    <tbody>${historyRows}</tbody></table></div></div>
  </div>`;

  const body = `
  <style>.cb-row{display:block;padding:.18rem 0}.cb-row input{margin-right:.45rem}</style>
  <div class="page-head"><div><h1>Bulk email</h1><p class="muted">Email all staff or a filtered group — each person receives their own copy</p></div></div>
  ${flash}
  ${mailConfigured() ? '' : '<div class="flash info">Email sending is not currently configured. You can prepare messages and templates, but sending is disabled until an administrator sets the RESEND_API_KEY environment variable.</div>'}
  <div style="display:flex;gap:.5rem;margin-bottom:1rem">
    <button type="button" class="btn ${activeTab === 'compose' ? '' : 'ghost'} sm" id="tabBtn-compose" onclick="showTab('compose')">Compose</button>
    <button type="button" class="btn ${activeTab === 'history' ? '' : 'ghost'} sm" id="tabBtn-history" onclick="showTab('history')">History</button>
  </div>
  ${compose}
  ${history}`;

  const audienceJson = JSON.stringify(audience.map((u) => ({ id: u.id, role: u.role }))).replace(/</g, '\\u003c');
  const templatesJson = JSON.stringify(templates).replace(/</g, '\\u003c');

  const scripts = `<script>
(function(){
  var AUDIENCE = ${audienceJson};
  var TEMPLATES = {};
  (${templatesJson}).forEach(function(t){ TEMPLATES[t.id] = t; });
  function $(id){ return document.getElementById(id); }

  window.showTab = function(name){
    $('tab-compose').style.display = name === 'compose' ? '' : 'none';
    $('tab-history').style.display = name === 'history' ? '' : 'none';
    $('tabBtn-compose').className = 'btn ' + (name === 'compose' ? '' : 'ghost') + ' sm';
    $('tabBtn-history').className = 'btn ' + (name === 'history' ? '' : 'ghost') + ' sm';
  };
  window.toggleLog = function(id){
    var d = $('log-detail-' + id);
    if (d) d.style.display = d.style.display === 'none' ? '' : 'none';
  };

  function currentMode(){ var r = document.querySelector('input[name=mode]:checked'); return r ? r.value : 'all'; }
  function selectedCount(){
    var mode = currentMode();
    if (mode === 'all') return AUDIENCE.length;
    if (mode === 'role'){
      var roles = {};
      document.querySelectorAll('.role-cb:checked').forEach(function(c){ roles[c.value] = 1; });
      return AUDIENCE.filter(function(u){ return roles[u.role]; }).length;
    }
    return document.querySelectorAll('.indiv-cb:checked').length;
  }
  function recount(){
    var n = selectedCount();
    $('recipientCount').textContent = n;
    var mode = currentMode();
    $('roleBox').style.display = mode === 'role' ? '' : 'none';
    $('individualBox').style.display = mode === 'individuals' ? '' : 'none';
    $('sendBtn').disabled = n === 0;
  }

  document.querySelectorAll('.mode-radio, .role-cb').forEach(function(el){ el.addEventListener('change', recount); });
  $('individualBox').addEventListener('change', function(e){ if (e.target.classList.contains('indiv-cb')) recount(); });

  var search = $('indivSearch');
  if (search) search.addEventListener('input', function(){
    var q = search.value.toLowerCase();
    document.querySelectorAll('.indiv-item').forEach(function(it){
      it.style.display = it.getAttribute('data-search').indexOf(q) === -1 ? 'none' : '';
    });
  });
  var selAll = $('selAll'), selNone = $('selNone');
  if (selAll) selAll.addEventListener('click', function(){ document.querySelectorAll('.indiv-cb').forEach(function(c){ c.checked = true; }); recount(); });
  if (selNone) selNone.addEventListener('click', function(){ document.querySelectorAll('.indiv-cb').forEach(function(c){ c.checked = false; }); recount(); });

  var tplSelect = $('tplSelect');
  tplSelect.addEventListener('change', function(){
    var t = TEMPLATES[tplSelect.value];
    if (t){ $('subjectInput').value = t.subject || ''; $('bodyInput').value = t.body || ''; }
  });
  $('tplSave').addEventListener('click', function(){
    var name = prompt('Save the current subject and message as a reusable template.\\n\\nTemplate name:');
    if (name === null) return;
    name = name.trim();
    if (!name){ alert('Please enter a template name.'); return; }
    fetch('/manager/email-templates', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: name, subject: $('subjectInput').value, body: $('bodyInput').value }) })
      .then(function(r){ return r.json().then(function(j){ return { ok: r.ok, j: j }; }); })
      .then(function(res){
        if (!res.ok){ alert(res.j.error || 'Could not save template.'); return; }
        TEMPLATES[res.j.id] = res.j;
        var opt = document.createElement('option');
        opt.value = res.j.id; opt.textContent = res.j.name;
        tplSelect.appendChild(opt); tplSelect.value = res.j.id;
      }).catch(function(){ alert('Could not save template.'); });
  });
  $('tplDelete').addEventListener('click', function(){
    var id = tplSelect.value;
    if (!id){ alert('Choose a template to delete first.'); return; }
    if (!confirm('Delete the template "' + TEMPLATES[id].name + '"? This cannot be undone.')) return;
    fetch('/manager/email-templates/' + id, { method: 'DELETE' })
      .then(function(r){ if (!r.ok) throw 0;
        delete TEMPLATES[id];
        var opt = tplSelect.querySelector('option[value="' + id + '"]'); if (opt) opt.remove();
        tplSelect.value = '';
      }).catch(function(){ alert('Could not delete template.'); });
  });

  $('composeForm').addEventListener('submit', function(e){
    var n = selectedCount();
    if (n === 0){ e.preventDefault(); return; }
    if (!confirm('Send this email to ' + n + ' recipient' + (n === 1 ? '' : 's') + '? Each person receives their own individual copy.')) e.preventDefault();
  });

  recount();
})();
</script>`;

  res.send(layout({ user: req.user, title: 'Bulk email', active: '/manager/bulk-email', body, scripts }));
});

app.post('/manager/bulk-email/send', requireManager, async (req, res) => {
  const bad = (msg) => res.redirect('/manager/bulk-email?err=' + encodeURIComponent(msg));
  const subject = String(req.body.subject || '').trim();
  const bodyText = String(req.body.body || '');
  const mode = ['all', 'role', 'individuals'].includes(req.body.mode) ? req.body.mode : 'all';
  if (!subject) return bad('Enter a subject before sending.');
  if (!bodyText.trim()) return bad('Enter a message before sending.');
  // Detect an unconfigured environment up front and fail clearly (no silent no-op).
  if (!mailConfigured()) return bad('Email sending is not currently configured. Ask an administrator to set the RESEND_API_KEY environment variable before sending.');

  const list = resolveEmailRecipients(mode, req.body);
  if (!list.length) return bad('No recipients matched your selection.');

  const filter = mode === 'role' ? { type: 'role', roles: asArray(req.body.roles) }
    : mode === 'individuals' ? { type: 'individuals', user_ids: list.map((u) => u.id) }
      : { type: 'all' };

  const logId = Number(db.prepare(
    'INSERT INTO email_log (sent_by, subject, body, recipient_filter, recipient_count, sent_at, status) VALUES (?,?,?,?,?,?,?)'
  ).run(req.user.id, subject, bodyText, JSON.stringify(filter), list.length, Date.now(), 'sent').lastInsertRowid);

  const html = bulkEmailHtml(bodyText);
  const insertRec = db.prepare('INSERT INTO email_log_recipients (email_log_id, user_id, email_address, status, error_message) VALUES (?,?,?,?,?)');
  let ok = 0, fail = 0;
  for (const r of list) {
    // Send one message per recipient — never a shared To/BCC — so addresses stay
    // private and each copy is personal. Failures are tracked, not fatal.
    try {
      await sendMail({ to: r.email, subject, text: bodyText, html });
      insertRec.run(logId, r.id, r.email, 'sent', null);
      ok++;
    } catch (e) {
      insertRec.run(logId, r.id, r.email, 'failed', String((e && e.message) || e).slice(0, 500));
      fail++;
    }
  }
  const status = fail === 0 ? 'sent' : ok === 0 ? 'failed' : 'partial_failure';
  db.prepare('UPDATE email_log SET status=? WHERE id=?').run(status, logId);
  audit(req.user, 'bulk_email', null, `${ok} sent, ${fail} failed · "${subject.slice(0, 80)}"`);
  res.redirect(`/manager/bulk-email?tab=history&sent=1&ok=${ok}&fail=${fail}`);
});

// ---- email templates (JSON API used by the compose page) -------------------
app.get('/manager/email-templates', requireManager, (_req, res) => {
  res.json(db.prepare('SELECT id, name, subject, body, updated_at FROM email_templates ORDER BY name COLLATE NOCASE').all());
});
app.post('/manager/email-templates', requireManager, (req, res) => {
  const name = String(req.body.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Template name is required.' });
  const subject = String(req.body.subject || '');
  const body = String(req.body.body || '');
  const now = Date.now();
  const id = Number(db.prepare('INSERT INTO email_templates (name, subject, body, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?)')
    .run(name, subject, body, req.user.id, now, now).lastInsertRowid);
  audit(req.user, 'create_email_template', null, name);
  res.json({ id, name, subject, body });
});
app.delete('/manager/email-templates/:id', requireManager, (req, res) => {
  const id = Number(req.params.id);
  const t = db.prepare('SELECT name FROM email_templates WHERE id=?').get(id);
  if (!t) return res.status(404).json({ error: 'Template not found.' });
  db.prepare('DELETE FROM email_templates WHERE id=?').run(id);
  audit(req.user, 'delete_email_template', null, t.name);
  res.json({ ok: true });
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

app.get('/admin/settings', requireAdmin, (req, res) => {
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
app.post('/admin/settings', requireAdmin, (req, res) => {
  brandMeta.set('org_name', (req.body.org_name || 'Sky Home Living').trim() || 'Sky Home Living');
  audit(req.user, 'update_settings');
  res.redirect('/admin/settings?saved=1');
});
app.post('/admin/branding/logo', requireAdmin, (req, res) => {
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
app.post('/admin/branding/logo/delete', requireAdmin, (req, res) => {
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
function changePasswordPage({ error = '', forced = false } = {}) {
  return loginPageShell(`
    <h1 style="margin-bottom:.2rem">Choose a new password</h1>
    <p class="muted" style="margin-top:0">${forced ? 'Your manager set a temporary password. Please choose your own to continue.' : 'Update the password for your account.'}</p>
    ${error ? `<div class="flash err">${esc(error)}</div>` : ''}
    <form method="post" action="/account/password">
      <div class="field"><label>${forced ? 'Temporary password' : 'Current password'}</label><input name="current_password" type="password" required></div>
      <div class="field"><label>New password</label><input name="password" type="password" minlength="8" required></div>
      <div class="field"><label>Confirm new password</label><input name="confirm" type="password" minlength="8" required></div>
      <button class="btn" style="width:100%;justify-content:center">Save new password</button>
    </form>
    <p class="small muted" style="text-align:center;margin-top:1rem"><a href="/logout">Sign out</a></p>`);
}
function loginPageShell(inner) {
  const b = getBranding();
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow"><link rel="icon" href="/favicon.png"><title>${esc(b.orgName)}</title><link rel="stylesheet" href="/styles.css"></head>
  <body><div class="auth-wrap"><div class="auth-card"><img class="login-logo" src="${b.loginLogo}" alt="${esc(b.orgName)}">${inner}</div></div></body></html>`;
}

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Sky Home Living staff portal on :${PORT}`));
