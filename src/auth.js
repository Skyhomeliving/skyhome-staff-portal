// auth.js — password hashing, session management, and access-control middleware.
import bcrypt from 'bcryptjs';
import { randomBytes } from 'node:crypto';
import { db } from './db.js';

export const SESSION_COOKIE = 'shl_session';
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 14; // 14 days

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
    `SELECT s.expires_at, u.id, u.email, u.role, u.name
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token = ?`
  ).get(token);
  if (!row) return null;
  if (row.expires_at < Date.now()) { destroySession(token); return null; }
  return { id: row.id, email: row.email, role: row.role, name: row.name };
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

export function audit(actor, action, targetUserId = null, details = '') {
  db.prepare(
    'INSERT INTO audit_log (actor_user_id, actor_email, action, target_user_id, details, created_at) VALUES (?,?,?,?,?,?)'
  ).run(actor?.id ?? null, actor?.email ?? 'system', action, targetUserId, details, Date.now());
}

// Middleware ----------------------------------------------------------------
export function attachUser(req, _res, next) {
  req.user = getSessionUser(req.cookies?.[SESSION_COOKIE]) || null;
  next();
}

export function requireAuth(req, res, next) {
  if (!req.user) return res.redirect('/login');
  next();
}

export const requireRole = (...roles) => (req, res, next) => {
  if (!req.user) return res.redirect('/login');
  if (!roles.includes(req.user.role)) return res.status(403).send('Forbidden');
  next();
};

// A staff member may view/edit only their own record; managers/admins, anyone.
export function canAccessStaff(user, targetUserId) {
  return user.role === 'admin' || user.role === 'manager' || user.id === Number(targetUserId);
}
