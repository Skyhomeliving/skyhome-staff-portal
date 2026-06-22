// reminders.js — daily compliance-renewal email digest to managers.
// Sends from info@skyhomeliving.co.uk via SMTP (nodemailer). No-ops cleanly
// until SMTP env vars are configured, so the app runs fine without email set up.
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const nodemailer = require('nodemailer');
import { db } from './db.js';
import { computeCompliance } from './compliance.js';

const FROM = process.env.MAIL_FROM || 'info@skyhomeliving.co.uk';
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

export const mailConfigured = () => !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);

const meta = {
  get: (k) => db.prepare('SELECT value FROM app_meta WHERE key=?').get(k)?.value,
  set: (k, v) => db.prepare('INSERT INTO app_meta (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(k, String(v)),
};
export const lastSentAt = () => meta.get('last_reminder_at');

export function recipients() {
  if (process.env.REMINDER_RECIPIENTS) return process.env.REMINDER_RECIPIENTS.split(',').map((s) => s.trim()).filter(Boolean);
  return db.prepare("SELECT email FROM users WHERE role IN ('admin','manager')").all().map((r) => r.email);
}

export function buildDigest(withinDays = 60) {
  const staff = db.prepare(`SELECT u.id,u.email,p.* FROM users u LEFT JOIN profiles p ON p.user_id=u.id WHERE u.role IN ('staff','manager')`).all();
  const items = [];
  for (const s of staff) for (const a of computeCompliance(s).alerts) if (a.days <= withinDays) items.push({ name: s.full_name || s.email, id: s.id, ...a });
  items.sort((x, y) => x.days - y.days);
  return items;
}

function transport() {
  const port = Number(process.env.SMTP_PORT || 587);
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port,
    secure: port === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
}

function buildHtml(items) {
  const expired = items.filter((i) => i.days < 0).length;
  const soon = items.filter((i) => i.days >= 0 && i.days <= 30).length;
  const base = process.env.APP_URL || '';
  const rows = items.map((i) => `<tr>
    <td style="padding:6px 10px;border-bottom:1px solid #eee">${esc(i.name)}</td>
    <td style="padding:6px 10px;border-bottom:1px solid #eee">${esc(i.label)} <span style="color:#888">· ${esc(i.area)}</span></td>
    <td style="padding:6px 10px;border-bottom:1px solid #eee">${esc(i.date)}</td>
    <td style="padding:6px 10px;border-bottom:1px solid #eee;color:${i.days < 0 ? '#b42318' : i.days <= 30 ? '#9a6700' : '#555'};font-weight:600">${i.days < 0 ? `Expired ${-i.days}d ago` : `${i.days}d left`}</td></tr>`).join('');
  return { expired, soon, html: `<div style="font-family:Segoe UI,Arial,sans-serif;color:#1f2937;max-width:680px">
    <h2 style="color:#0c2a4d;margin-bottom:4px">Staff compliance renewals</h2>
    <p style="color:#555;margin-top:0">${expired} expired · ${soon} due within 30 days · ${items.length} in the next 60 days.</p>
    <table style="border-collapse:collapse;width:100%;font-size:14px"><thead><tr>
      <th style="text-align:left;padding:6px 10px;border-bottom:2px solid #ddd">Staff</th>
      <th style="text-align:left;padding:6px 10px;border-bottom:2px solid #ddd">Requirement</th>
      <th style="text-align:left;padding:6px 10px;border-bottom:2px solid #ddd">Date</th>
      <th style="text-align:left;padding:6px 10px;border-bottom:2px solid #ddd">Status</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="4" style="padding:12px">Nothing due — all staff are up to date. 🎉</td></tr>'}</tbody></table>
    ${base ? `<p style="margin-top:18px"><a href="${base}/alerts" style="background:#0c2a4d;color:#fff;padding:9px 16px;border-radius:8px;text-decoration:none">Open the compliance portal</a></p>` : ''}
    <p style="color:#999;font-size:12px;margin-top:22px">Automated reminder from the Sky Home Living staff compliance portal. Confidential — contains personal data.</p></div>` };
}

// Generic transactional send (password reset, etc.) reusing the SMTP transport.
export async function sendMail({ to, subject, html, text }) {
  if (!mailConfigured()) throw new Error('Email (SMTP) is not configured.');
  return transport().sendMail({ from: `"Sky Home Living" <${FROM}>`, to, subject, html, text });
}

export async function sendDigest() {
  if (!mailConfigured()) return { sent: false, reason: 'Email (SMTP) is not configured yet.' };
  const to = recipients();
  if (!to.length) return { sent: false, reason: 'No admin/manager recipients found.' };
  const items = buildDigest(60);
  const { expired, soon, html } = buildHtml(items);
  await transport().sendMail({
    from: `"Sky Home Living" <${FROM}>`,
    to: to.join(','),
    subject: `Compliance renewals — ${expired} expired, ${soon} due within 30 days`,
    html,
  });
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
