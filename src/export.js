// export.js — compliance summary PDF + ZIP document pack for sending to CQC/HMRC.
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const archiver = require('archiver');
const PDFDocument = require('pdfkit');
import fs from 'node:fs';
import path from 'node:path';
import { PROFILE_SECTIONS, categoryLabel, computeCompliance } from './compliance.js';

const NAVY = '#0c2a4d';
const fmt = (s) => { if (!s) return '—'; const d = new Date(s); return Number.isNaN(d.getTime()) ? String(s) : d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }); };

const sectionTitle = (doc, t) => { doc.moveDown(0.5).fontSize(11).fillColor(NAVY).text(t).fillColor('#000').moveDown(0.15); };
const kv = (doc, k, v) => { doc.fontSize(9.5).fillColor('#555').text(`${k}:  `, { continued: true }).fillColor('#111').text(v); };

export function writeSummary(doc, { profile, user, docs, actor, org = 'Sky Home Living Limited' }) {
  const c = computeCompliance(profile);
  // Header band
  doc.rect(0, 0, doc.page.width, 86).fill(NAVY);
  doc.fillColor('#fff').fontSize(18).text(org, 50, 26);
  doc.fillColor('#cfe0f1').fontSize(11).text('Staff Compliance Summary', 50, 52);
  // Body
  doc.fillColor('#000'); doc.y = 104; doc.x = 50;
  doc.fontSize(16).fillColor(NAVY).text(profile.full_name || user.email);
  doc.fontSize(10).fillColor('#444').text(`${profile.job_title || '—'}   ·   ${user.email}`);
  doc.fontSize(9).fillColor('#666').text(`Generated ${new Date().toLocaleString('en-GB')}${actor?.email ? ` by ${actor.email}` : ''}`);
  const st = c.rag === 'red' ? ['ACTION NEEDED', '#b42318'] : c.rag === 'amber' ? ['ATTENTION', '#9a6700'] : ['COMPLIANT', '#1a7f4b'];
  doc.moveDown(0.4).fontSize(11).fillColor(st[1]).text(`Overall status: ${st[0]}`).fillColor('#000');

  if (c.alerts.length) {
    sectionTitle(doc, 'Renewals & alerts');
    for (const a of c.alerts) doc.fontSize(9.5).fillColor('#111').text(`•  ${a.label} (${a.area}) — ${fmt(a.date)} — ${a.days < 0 ? `expired ${-a.days} days ago` : `${a.days} days left`}`);
  }

  for (const s of PROFILE_SECTIONS) {
    const fields = s.fields.filter((f) => { const v = profile[f.key]; return v !== '' && v != null && !(f.type === 'checkbox' && !v) && !(typeof v === 'number' && v === 0 && f.type === 'checkbox'); });
    if (!fields.length) continue;
    sectionTitle(doc, s.title);
    for (const f of fields) {
      let v = profile[f.key];
      if (f.type === 'checkbox') v = v ? 'Yes' : 'No';
      else if (f.type === 'date') v = fmt(v);
      kv(doc, f.label, String(v));
    }
  }

  sectionTitle(doc, `Documents on file (${docs.length})`);
  if (docs.length) for (const d of docs) doc.fontSize(9.5).fillColor('#111').text(`•  ${categoryLabel(d.category)} — ${d.title || '(untitled)'}${d.expiry_date ? ` — expires ${fmt(d.expiry_date)}` : ''}`);
  else doc.fontSize(9.5).fillColor('#777').text('No documents on file.');

  doc.moveDown(1.2).fontSize(8).fillColor('#888')
    .text('CONFIDENTIAL — contains personal data. Provided for regulatory compliance (CQC / HMRC / Home Office) only. Handle in accordance with UK GDPR.');
}

export function pdfBuffer(buildFn) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ margin: 50, size: 'A4' });
    const chunks = [];
    doc.on('data', (c) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    buildFn(doc);
    doc.end();
  });
}

export async function streamZip(res, { profile, user, docs, actor, uploadsDir }) {
  const safe = (profile.full_name || user.email).replace(/[^a-z0-9]+/gi, '_').replace(/^_+|_+$/g, '') || 'staff';
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="${safe}_compliance_pack.zip"`);
  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.on('error', () => { try { res.end(); } catch {} });
  archive.pipe(res);
  const buf = await pdfBuffer((doc) => writeSummary(doc, { profile, user, docs, actor }));
  archive.append(buf, { name: '00-Compliance-Summary.pdf' });
  let i = 1;
  for (const d of docs) {
    const fp = path.join(uploadsDir, path.basename(d.file_path));
    if (fs.existsSync(fp)) {
      const ext = path.extname(d.file_path) || '';
      const nm = `${String(i).padStart(2, '0')}_${categoryLabel(d.category)}_${d.title || 'document'}`.replace(/[^a-z0-9]+/gi, '_').replace(/_+/g, '_') + ext;
      archive.file(fp, { name: nm });
      i++;
    }
  }
  await archive.finalize();
}

// Cross-staff export: one ZIP holding every document of a single category, one
// entry per staff member. `rows` come from a documents⨝users⨝profiles query and
// carry full_name/email for naming. Mirrors streamZip's archiver setup and its
// fs.existsSync / filename-sanitising guards; skips rows whose file is missing.
export async function streamCategoryZip(res, { category, rows, uploadsDir }) {
  const label = categoryLabel(category);
  const safeCat = label.replace(/[^a-z0-9]+/gi, '_').replace(/_+/g, '_').replace(/^_+|_+$/g, '') || 'documents';
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="all_${safeCat}_documents.zip"`);
  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.on('error', () => { try { res.end(); } catch {} });
  archive.pipe(res);
  const used = new Set();
  for (const d of rows) {
    const fp = path.join(uploadsDir, path.basename(d.file_path));
    if (!fs.existsSync(fp)) continue;
    const ext = path.extname(d.file_path) || '';
    const who = d.full_name || d.email || 'staff';
    const base = `${who}_${label}`.replace(/[^a-z0-9]+/gi, '_').replace(/_+/g, '_').replace(/^_+|_+$/g, '') || 'document';
    // Guarantee unique entry names (same person can have >1 doc of a type, and
    // two staff can share a name) by suffixing on collision.
    let name = base + ext, n = 2;
    while (used.has(name)) { name = `${base}_${n}${ext}`; n++; }
    used.add(name);
    archive.file(fp, { name });
  }
  await archive.finalize();
}
