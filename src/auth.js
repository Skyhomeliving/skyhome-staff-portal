// auth.js — password hashing, session management, and access-control middleware.
import bcrypt from 'bcryptjs';
import { randomBytes } from 'node:crypto';
import { db } from './db.js';
import { errorPage } from './views.js';
import { isOversight, isManagerLevel, isAdmin } from './compliance.js';

export const SESSION_COOKIE = 'shl_session';
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 90; // 90 days
// Sliding expiry: a still-valid session is pushed out to a fresh full TTL on
// use, but at most once an hour so we don't write to the DB on every request.
const SESSION_REFRESH_AFTER_MS = 1000 * 60 * 60; // 1 hour

export const hashPassword = (pw) => bcrypt.hashSync(pw, 10);
export const verifyPassword = (pw, hash) => {
  try { return bcrypt.compareSync(pw, hash); } catch { return false; }
};

export function createSession(userId) {
  const token = randomBytes(32).toString('hex');
  const now = Date.now();
  db.prepare('INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)')
    .run(token, userId, now, now + SESSION_TTL_MS);
  return token;
}

export function getSessionUser(token) {
  if (!token) return null;
  const row = db.prepare(
    `SELECT s.expires_at, u.id, u.email, u.role, u.name, u.must_change_password, u.is_active
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token = ?`
  ).get(token);
  if (!row) return null;
  if (row.expires_at < Date.now()) { destroySession(token); return null; }
  return {
    id: row.id, email: row.email, role: row.role, name: row.name,
    must_change_password: !!row.must_change_password,
    is_active: row.is_active,
  };
}

// Sliding-expiry refresh for a still-valid session. Pushes expires_at out to a
// fresh full TTL, but only once the session hasn't been extended for at least
// SESSION_REFRESH_AFTER_MS (throttling DB writes). Returns true when it actually
// extended the session (so the caller can re-issue the cookie). Never resurrects
// an expired session — the row's own expiry is the source of truth.
export function refreshSession(token) {
  if (!token) return false;
  const now = Date.now();
  const row = db.prepare('SELECT expires_at FROM sessions WHERE token = ?').get(token);
  if (!row || row.expires_at < now) return false;
  const lastExtendedAt = row.expires_at - SESSION_TTL_MS;
  if (now - lastExtendedAt < SESSION_REFRESH_AFTER_MS) return false;
  db.prepare('UPDATE sessions SET expires_at = ? WHERE token = ?').run(now + SESSION_TTL_MS, token);
  return true;
}

export const destroySession = (token) =>
  token && db.prepare('DELETE FROM sessions WHERE token = ?').run(token);

export function setSessionCookie(res, token) {
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: SESSION_TTL_MS,
  });
}

// --- Password reset (single-use, time-limited tokens) ----------------------
const RESET_TTL_MS = 1000 * 60 * 60; // 1 hour

export function createPasswordReset(userId) {
  const token = randomBytes(32).toString('hex');
  const now = Date.now();
  db.prepare('INSERT INTO password_resets (user_id, token, created_at, expires_at) VALUES (?,?,?,?)')
    .run(userId, token, now, now + RESET_TTL_MS);
  return token;
}

export function getValidReset(token) {
  if (!token) return null;
  const row = db.prepare('SELECT * FROM password_resets WHERE token=?').get(token);
  if (!row || row.used_at || row.expires_at < Date.now()) return null;
  return row;
}

// Sets the new password, marks the token used, and revokes all of the user's
// existing sessions. Returns the user id on success, else null.
export function consumePasswordReset(token, newPassword) {
  const row = getValidReset(token);
  if (!row) return null;
  db.prepare('UPDATE users SET password=?, failed_logins=0, locked_until=0, must_change_password=0 WHERE id=?')
    .run(hashPassword(newPassword), row.user_id);
  db.prepare('UPDATE password_resets SET used_at=? WHERE id=?').run(Date.now(), row.id);
  db.prepare('DELETE FROM sessions WHERE user_id=?').run(row.user_id);
  return row.user_id;
}

// --- Account lockout (targeted brute-force protection, complements the
//     IP rate-limit on /login) ----------------------------------------------
const MAX_FAILS = Number(process.env.LOGIN_MAX_FAILS || 5);
const LOCK_MS = Number(process.env.LOGIN_LOCK_MINUTES || 15) * 60000;

// Milliseconds left on an active lock for this account, else 0.
export function loginLockRemaining(user) {
  if (!user || !user.locked_until) return 0;
  return user.locked_until > Date.now() ? user.locked_until - Date.now() : 0;
}

// Returns true if this failure tripped the lock.
export function registerLoginFailure(user) {
  if (!user) return false;
  const fails = (user.failed_logins || 0) + 1;
  const locked = fails >= MAX_FAILS;
  const lockedUntil = locked ? Date.now() + LOCK_MS : (user.locked_until || 0);
  db.prepare('UPDATE users SET failed_logins=?, locked_until=? WHERE id=?').run(fails, lockedUntil, user.id);
  return locked;
}

export function registerLoginSuccess(user) {
  db.prepare('UPDATE users SET failed_logins=0, locked_until=0, last_login_at=? WHERE id=?')
    .run(Date.now(), user.id);
}

export function audit(actor, action, targetUserId = null, details = '') {
  db.prepare(
    'INSERT INTO audit_log (actor_user_id, actor_email, action, target_user_id, details, created_at) VALUES (?,?,?,?,?,?)'
  ).run(actor?.id ?? null, actor?.email ?? 'system', action, targetUserId, details, Date.now());
}

// Middleware ----------------------------------------------------------------
export function attachUser(req, res, next) {
  const token = req.cookies?.[SESSION_COOKIE];
  const sess = getSessionUser(token);
  // Offboarding: a deactivated account is denied even if it still presents a
  // valid, unexpired session cookie. Revoke the session and clear the cookie,
  // then fall through unauthenticated with a flag so the app can explain why.
  if (sess && sess.is_active === 0) {
    destroySession(token);
    res.clearCookie(SESSION_COOKIE, { path: '/' });
    req.user = null;
    req.deactivated = true;
    return next();
  }
  req.user = sess || null;
  // Keep active users signed in: slide the expiry forward (throttled) and
  // re-issue the cookie with the same maxAge so the browser copy tracks it.
  if (req.user && refreshSession(token)) setSessionCookie(res, token);
  next();
}

export function requireAuth(req, res, next) {
  if (!req.user) return res.redirect('/login');
  next();
}

const denyArea = (req, res) => res.status(403).send(errorPage({
  user: req.user, code: 403, title: 'Not allowed',
  message: 'Your role does not have access to this area. If you think this is wrong, contact your manager.',
}));

export const requireRole = (...roles) => (req, res, next) => {
  if (!req.user) return res.redirect('/login');
  if (!roles.includes(req.user.role)) return denyArea(req, res);
  next();
};

// Tier-based guards (preferred over hard-coded role lists).
export const requireOversight = (req, res, next) =>
  !req.user ? res.redirect('/login') : isOversight(req.user.role) ? next() : denyArea(req, res);
export const requireManager = (req, res, next) =>
  !req.user ? res.redirect('/login') : isManagerLevel(req.user.role) ? next() : denyArea(req, res);
export const requireAdmin = (req, res, next) =>
  !req.user ? res.redirect('/login') : isAdmin(req.user.role) ? next() : denyArea(req, res);

// Viewing a record: oversight (coordinator) and management, plus the person
// themselves. Editing: management only, plus the person themselves — and those
// self-edits are further limited to contact fields by SELF_EDITABLE_KEYS.
export function canViewStaff(user, targetUserId) {
  return isOversight(user.role) || user.id === Number(targetUserId);
}
export function canEditStaff(user, targetUserId) {
  return isManagerLevel(user.role) || user.id === Number(targetUserId);
}
// Legacy alias — view semantics.
export const canAccessStaff = canViewStaff;
