// branding.js — organisation name + logo. Defaults to the official Sky Home
// Living assets shipped in /public; an admin can upload a replacement (stored on
// the data volume so it survives redeploys).
import path from 'node:path';
import fs from 'node:fs';
import { db, DATA_DIR } from './db.js';

export const BRAND_DIR = path.join(DATA_DIR, 'branding');
fs.mkdirSync(BRAND_DIR, { recursive: true });

export const brandMeta = {
  get: (k) => db.prepare('SELECT value FROM app_meta WHERE key=?').get(k)?.value,
  set: (k, v) => db.prepare('INSERT INTO app_meta (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(k, String(v)),
  del: (k) => db.prepare('DELETE FROM app_meta WHERE key=?').run(k),
};

export function customLogoPath() {
  const f = brandMeta.get('logo_file');
  if (!f) return null;
  const p = path.join(BRAND_DIR, f);
  return fs.existsSync(p) ? p : null;
}

export function getBranding() {
  const orgName = brandMeta.get('org_name') || 'Sky Home Living';
  const hasCustom = !!customLogoPath();
  const ver = brandMeta.get('logo_ver') || '1';
  return {
    orgName,
    hasCustom,
    // full logo (login / large): custom if set, else official wordmark logo
    loginLogo: hasCustom ? `/branding/logo?v=${ver}` : '/sky-logo.png',
    // compact mark (sidebar): custom if set, else official icon
    markLogo: hasCustom ? `/branding/logo?v=${ver}` : '/sky-icon.png',
  };
}
