// views.js — HTML shell, reusable components, and the login page.
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export const initials = (name) =>
  String(name || '?').trim().split(/\s+/).slice(0, 2).map((w) => w[0] || '').join('').toUpperCase() || '?';

export function fmtDate(s) {
  if (!s) return '—';
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return esc(s);
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
}

const RAG_LABEL = { red: 'Action needed', amber: 'Attention', green: 'Compliant', grey: 'No data' };
export const ragBadge = (rag) =>
  `<span class="badge ${rag}"><span class="dot ${rag}"></span>${RAG_LABEL[rag] || rag}</span>`;

export function levelBadge(level, text) {
  const map = { expired: 'red', critical: 'red', warning: 'amber', ok: 'green' };
  return `<span class="badge ${map[level] || 'grey'}">${esc(text)}</span>`;
}

const ICONS = {
  dashboard: '<path d="M3 13h8V3H3v10Zm0 8h8v-6H3v6Zm10 0h8V11h-8v10Zm0-18v6h8V3h-8Z"/>',
  staff: '<path d="M16 11a4 4 0 1 0-4-4 4 4 0 0 0 4 4Zm-8 0a4 4 0 1 0-4-4 4 4 0 0 0 4 4Zm0 2c-2.7 0-8 1.3-8 4v3h10v-3c0-1 .4-1.9 1-2.6A12 12 0 0 0 8 13Zm8 0a11 11 0 0 0-1.8.2A6 6 0 0 1 16 17v3h8v-3c0-2.7-5.3-4-8-4Z"/>',
  alert: '<path d="M12 2 1 21h22L12 2Zm1 14h-2v2h2v-2Zm0-6h-2v4h2v-4Z"/>',
  badge: '<path d="M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5l-8-3Zm-1 14-4-4 1.4-1.4L11 13.2l4.6-4.6L17 10l-6 6Z"/>',
  invite: '<path d="M20 4H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2Zm0 4-8 5-8-5V6l8 5 8-5v2Z"/>',
  audit: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6Zm2 16H8v-2h8v2Zm0-4H8v-2h8v2Zm-3-5V3.5L18.5 9H13Z"/>',
  logout: '<path d="M16 17v-3H9v-4h7V7l5 5-5 5ZM14 2a2 2 0 0 1 2 2v2h-2V4H5v16h9v-2h2v2a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9Z"/>',
  download: '<path d="M5 20h14v-2H5v2ZM19 9h-4V3H9v6H5l7 7 7-7Z"/>',
  eye: '<path d="M12 5c-7 0-10 7-10 7s3 7 10 7 10-7 10-7-3-7-10-7Zm0 12a5 5 0 1 1 0-10 5 5 0 0 1 0 10Zm0-2a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z"/>',
  trash: '<path d="M6 7h12v13a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V7Zm3 2v9h2V9H9Zm4 0v9h2V9h-2ZM9 4h6l1 2h4v2H4V6h4l1-2Z"/>',
  pack: '<path d="M12 2 3 7v10l9 5 9-5V7l-9-5Zm0 2.3 6.5 3.6L12 11.5 5.5 7.9 12 4.3ZM5 9.6l6 3.3v6.8l-6-3.3V9.6Zm14 0v6.8l-6 3.3v-6.8l6-3.3Z"/>',
};
export const icon = (n) => `<svg class="ico" width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">${ICONS[n] || ''}</svg>`;
export const miniIcon = (n) => `<svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">${ICONS[n] || ''}</svg>`;

export function avatarClass(s) {
  let h = 0; const str = String(s || '');
  for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
  return 'a' + (h % 6);
}
export function fileKind(p) {
  const s = String(p || '').toLowerCase();
  if (/\.pdf$/.test(s) || s.includes('pdf')) return 'pdf';
  if (/\.(jpe?g|png|webp|heic|heif|gif)$/.test(s) || s.startsWith('image/')) return 'img';
  if (/\.docx?$/.test(s) || s.includes('word')) return 'doc';
  return 'other';
}
export const fileExt = (p) => { const m = String(p || '').match(/\.([a-z0-9]{1,5})$/i); return m ? m[1].toUpperCase() : 'FILE'; };

function navFor(user) {
  const items = [['/', 'dashboard', 'Dashboard']];
  if (user.role === 'admin' || user.role === 'manager') {
    items.push(['/staff', 'staff', 'Staff records']);
    items.push(['/alerts', 'alert', 'Compliance alerts']);
    items.push(['/admin/invites', 'invite', 'Invitations']);
    items.push(['/admin/audit', 'audit', 'Audit log']);
  } else {
    items.push([`/staff/${user.id}`, 'badge', 'My record']);
  }
  return items;
}

export function layout({ user, title = 'Compliance Records', active = '/', body = '', scripts = '' }) {
  const nav = navFor(user).map(([href, ic, label]) => {
    const on = href === active || (href !== '/' && active.startsWith(href));
    return `<a href="${href}" class="${on ? 'active' : ''}">${icon(ic)}<span>${label}</span></a>`;
  }).join('');
  return `<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><meta name="theme-color" content="#0c2a4d">
<title>${esc(title)} · Sky Home Living</title><link rel="stylesheet" href="/styles.css"></head>
<body><div class="app">
  <aside class="sidebar" id="sidebar">
    <div class="brand"><div class="logo">SH</div><div><b>Sky Home Living</b><span>Compliance Records</span></div></div>
    <nav class="nav">${nav}</nav>
    <div class="side-foot">Signed in as<br><b style="color:#fff">${esc(user.name || user.email)}</b><br>
      <a href="/logout">${icon('logout')} Sign out</a></div>
  </aside>
  <div class="main">
    <div class="topbar">
      <button class="burger" onclick="document.getElementById('sidebar').classList.toggle('open')">☰ Menu</button>
      <div></div>
      <div class="who"><span>${esc(roleLabel(user.role))}</span><div class="avatar">${initials(user.name || user.email)}</div></div>
    </div>
    <div class="content">${body}</div>
  </div>
</div>${scripts}</body></html>`;
}

export const roleLabel = (r) => ({ admin: 'Administrator', manager: 'Manager', staff: 'Staff' }[r] || r);

export function loginPage({ error = '', message = '' } = {}) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow">
<title>Sign in · Sky Home Living</title><link rel="stylesheet" href="/styles.css"></head>
<body><div class="auth-wrap"><div class="auth-card">
  <div class="logo">SH</div>
  <h1 style="margin-bottom:.2rem">Sky Home Living</h1>
  <p class="muted" style="margin-top:0">Staff Compliance Records</p>
  ${error ? `<div class="flash err">${esc(error)}</div>` : ''}
  ${message ? `<div class="flash ok">${esc(message)}</div>` : ''}
  <form method="post" action="/login">
    <div class="field"><label>Email</label><input name="email" type="email" required autofocus></div>
    <div class="field"><label>Password</label><input name="password" type="password" required></div>
    <button class="btn" style="width:100%;justify-content:center" type="submit">Sign in</button>
  </form>
  <p class="small muted" style="text-align:center;margin-top:1rem">
    Have an invite code? <a href="/register">Create an account</a></p>
</div></div></body></html>`;
}
