// reminders.js — daily compliance-renewal email digest to managers.
// Sends from info@skyhomeliving.co.uk via the Resend API (https://resend.com).
// Switched off raw SMTP: Railway's network can't reach the shared-hosting SMTP
// server (connections time out), whereas Resend sends over HTTPS. No-ops cleanly
// until RESEND_API_KEY is configured, so the app runs fine without email set up.
import { Resend } from 'resend';
import { db } from './db.js';
import { computeCompliance } from './compliance.js';
import { attachEvidence } from './evidence.js';

// Must be an address on the Resend-verified domain (skyhomeliving.co.uk).
const FROM = 'Sky Home Living <info@skyhomeliving.co.uk>';
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

// Email is only usable when the Resend API key is present.
export const mailConfigured = () => !!process.env.RESEND_API_KEY;

// Lazily-created Resend client (constructed on first send).
let resendClient = null;
function resend() {
  if (!resendClient) resendClient = new Resend(process.env.RESEND_API_KEY);
  return resendClient;
}

const meta = {
  get: (k) => db.prepare('SELECT value FROM app_meta WHERE key=?').get(k)?.value,
  set: (k, v) => db.prepare('INSERT INTO app_meta (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(k, String(v)),
};
export const lastSentAt = () => meta.get('last_reminder_at');

export function recipients() {
  if (process.env.REMINDER_RECIPIENTS) return process.env.REMINDER_RECIPIENTS.split(',').map((s) => s.trim()).filter(Boolean);
  return db.prepare("SELECT email FROM users WHERE role IN ('admin','manager') AND is_active = 1").all().map((r) => r.email);
}

export function buildDigest(withinDays = 60) {
  const staff = db.prepare(`SELECT u.id,u.email,p.* FROM users u LEFT JOIN profiles p ON p.user_id=u.id WHERE u.role != 'admin' AND u.is_active = 1`).all();
  const items = [];
  for (const s of attachEvidence(staff)) {
    for (const a of computeCompliance(s).alerts) {
      // Missing evidence has no date: it is always in scope, and must never be
      // compared numerically against the window (null <= 60 is true by coercion,
      // which would have been right by accident — be explicit instead).
      if (a.level !== 'missing' && a.days > withinDays) continue;
      items.push({ name: s.full_name || s.email, id: s.id, ...a });
    }
  }
  const RANK = { expired: 0, missing: 1, critical: 2, warning: 3 };
  items.sort((x, y) => (RANK[x.level] - RANK[y.level])
    || (x.days === null || y.days === null ? String(x.name).localeCompare(String(y.name)) : x.days - y.days));
  return items;
}

function buildHtml(items) {
  const expired = items.filter((i) => i.level === 'expired').length;
  const missing = items.filter((i) => i.level === 'missing').length;
  const soon = items.filter((i) => i.level !== 'missing' && i.days >= 0 && i.days <= 30).length;
  const base = process.env.APP_URL || '';
  const statusText = (i) => i.level === 'missing' ? 'Missing — never recorded'
    : i.days < 0 ? `Expired ${-i.days}d ago` : i.days === 0 ? 'Expires today' : `${i.days}d left`;
  const statusColour = (i) => i.level === 'missing' ? '#6b21a8' : i.days < 0 ? '#b42318' : i.days <= 30 ? '#9a6700' : '#555';
  const rows = items.map((i) => `<tr>
    <td style="padding:6px 10px;border-bottom:1px solid #eee">${esc(i.name)}</td>
    <td style="padding:6px 10px;border-bottom:1px solid #eee">${esc(i.label)} <span style="color:#888">· ${esc(i.area)}</span></td>
    <td style="padding:6px 10px;border-bottom:1px solid #eee">${i.level === 'missing' ? '—' : esc(i.date)}</td>
    <td style="padding:6px 10px;border-bottom:1px solid #eee;color:${statusColour(i)};font-weight:600">${esc(statusText(i))}</td></tr>`).join('');
  return { expired, soon, missing, html: `<div style="font-family:Segoe UI,Arial,sans-serif;color:#1f2937;max-width:680px">
    <h2 style="color:#0c2a4d;margin-bottom:4px">Staff compliance — renewals &amp; missing evidence</h2>
    <p style="color:#555;margin-top:0">${expired} expired · ${missing} missing entirely · ${soon} due within 30 days.</p>
    <table style="border-collapse:collapse;width:100%;font-size:14px"><thead><tr>
      <th style="text-align:left;padding:6px 10px;border-bottom:2px solid #ddd">Staff</th>
      <th style="text-align:left;padding:6px 10px;border-bottom:2px solid #ddd">Requirement</th>
      <th style="text-align:left;padding:6px 10px;border-bottom:2px solid #ddd">Date</th>
      <th style="text-align:left;padding:6px 10px;border-bottom:2px solid #ddd">Status</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="4" style="padding:12px">Nothing due — all staff are up to date. 🎉</td></tr>'}</tbody></table>
    ${base ? `<p style="margin-top:18px"><a href="${base}/alerts" style="background:#0c2a4d;color:#fff;padding:9px 16px;border-radius:8px;text-decoration:none">Open the compliance portal</a></p>` : ''}
    <p style="color:#999;font-size:12px;margin-top:22px">Automated reminder from the Sky Home Living staff compliance portal. Confidential — contains personal data.</p></div>` };
}

// Generic transactional send (password reset, bulk email, etc.) via Resend.
// Resend returns { data, error } instead of throwing on API errors, so we
// surface a non-null error as an exception to match the callers' try/catch.
export async function sendMail({ to, subject, html, text }) {
  if (!mailConfigured()) throw new Error('Email is not configured (RESEND_API_KEY is not set).');
  const { error } = await resend().emails.send({ from: FROM, to, subject, html, text });
  if (error) throw new Error(`Resend ${error.name}: ${error.message}`);
}

export async function sendDigest() {
  if (!mailConfigured()) return { sent: false, reason: 'Email is not configured yet (RESEND_API_KEY is not set).' };
  const to = recipients();
  if (!to.length) return { sent: false, reason: 'No admin/manager recipients found.' };
  const items = buildDigest(60);
  const { expired, soon, missing, html } = buildHtml(items);
  const { error } = await resend().emails.send({
    from: FROM,
    to,
    subject: `Staff compliance — ${expired} expired, ${missing} missing, ${soon} due within 30 days`,
    html,
  });
  if (error) throw new Error(`Resend ${error.name}: ${error.message}`);
  meta.set('last_reminder_date', new Date().toISOString().slice(0, 10));
  meta.set('last_reminder_at', new Date().toISOString());
  return { sent: true, count: items.length, to };
}

// Daily scheduler: hourly tick, sends once per day after REMINDER_HOUR (default 07:00).
export function startScheduler() {
  const HOUR = Number(process.env.REMINDER_HOUR || 7);
  const tick = async () => {
    try {
      if (!mailConfigured()) return;
      if (meta.get('last_reminder_date') === new Date().toISOString().slice(0, 10)) return;
      if (new Date().getHours() < HOUR) return;
      const r = await sendDigest();
      if (r.sent) console.log(`[reminders] daily digest sent to ${r.to.length} recipient(s)`);
    } catch (e) { console.error('[reminders] error:', e.message); }
  };
  setInterval(tick, 60 * 60 * 1000);
  setTimeout(tick, 20000);
}
