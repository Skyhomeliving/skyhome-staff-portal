// onboarding.js — PDF templates for the two-stage onboarding approval pipeline:
// a UK care-sector Offer Letter, a Written Statement of Employment Particulars
// (Employment Rights Act 1996), and a Staff Handbook acknowledgement receipt.
// Each function takes a pdfkit doc (created by export.js/pdfBuffer) + a flat ctx.
// Branding matches the compliance summary (NAVY header band, A4, 50pt margin).

const NAVY = '#0c2a4d';
const ORG = 'Sky Home Living Limited';
const ADDRESS = 'Ingenuity House, Bickenhill Lane, Birmingham, B37 7HQ';
const CONTACT = 'info@skyhomeliving.co.uk · www.skyhomeliving.co.uk';
export const DEFAULT_MANAGER = 'Joseph Onus, Managing Director & Nominated Individual';
// Full-time equivalent used to pro-rata statutory holiday for part-time staff.
const FTE_HOURS = 37.5;

const fmtDate = (s) => {
  if (!s) return '—';
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? String(s) : d.toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' });
};
const money = (r) => {
  const n = Number(r);
  return Number.isFinite(n) && String(r).trim() !== '' ? `£${n.toFixed(2)}` : String(r || '—');
};
// Statutory 5.6 weeks (28 days at 5 days/week), pro-rated by contracted hours.
export const holidayDays = (hoursPerWeek) => {
  const h = Number(hoursPerWeek);
  if (!Number.isFinite(h) || h <= 0) return 28;
  return Math.max(1, Math.min(28, Math.round((28 * h) / FTE_HOURS)));
};

// --- layout helpers ---------------------------------------------------------
function header(doc, subtitle) {
  doc.rect(0, 0, doc.page.width, 92).fill(NAVY);
  doc.fillColor('#fff').fontSize(18).text(ORG, 50, 22);
  doc.fillColor('#cfe0f1').fontSize(10.5).text(subtitle, 50, 48);
  doc.fillColor('#9fbcdb').fontSize(8).text(`${ADDRESS}  ·  ${CONTACT}`, 50, 66);
  doc.fillColor('#000');
  doc.y = 112;
  doc.x = 50;
}
const h = (doc, t) => { doc.moveDown(0.6).fontSize(11).fillColor(NAVY).text(t).fillColor('#000').moveDown(0.15); };
const p = (doc, t, opts = {}) => doc.fontSize(opts.size || 10).fillColor(opts.color || '#111').text(t, { align: opts.align || 'left', lineGap: 1.5, ...opts });
const numbered = (doc, n, title, text) => {
  doc.moveDown(0.5).fontSize(10.5).fillColor(NAVY).text(`${n}.  ${title}`).fillColor('#000');
  doc.fontSize(10).fillColor('#111').text(text, { lineGap: 1.5 });
};
function signatureBlocks(doc, employeeName) {
  doc.moveDown(1.4);
  const y = doc.y;
  const colW = (doc.page.width - 100 - 30) / 2;
  doc.fontSize(9.5).fillColor('#111');
  doc.text('For and on behalf of the Company', 50, y);
  doc.text('Signed by the employee', 50 + colW + 30, y);
  const lineY = y + 42;
  doc.moveTo(50, lineY).lineTo(50 + colW, lineY).strokeColor('#888').stroke();
  doc.moveTo(50 + colW + 30, lineY).lineTo(50 + colW + 30 + colW, lineY).strokeColor('#888').stroke();
  doc.fillColor('#555').fontSize(8.5);
  doc.text(DEFAULT_MANAGER, 50, lineY + 4, { width: colW });
  doc.text(employeeName || '', 50 + colW + 30, lineY + 4, { width: colW });
  doc.text('Date:', 50, lineY + 30);
  doc.text('Date:', 50 + colW + 30, lineY + 30);
  doc.fillColor('#000');
}

// --- 1) Offer letter (≥350 words) -------------------------------------------
export function writeOfferLetter(doc, ctx) {
  header(doc, 'Offer of Employment');
  const name = ctx.staff_name || 'Candidate';
  p(doc, new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'long', year: 'numeric' }), { size: 10, color: '#555' });
  doc.moveDown(0.5);
  p(doc, `Dear ${name},`, { size: 11 });
  doc.moveDown(0.2);
  p(doc, `RE: OFFER OF EMPLOYMENT — ${ctx.role_title || 'Care Worker'}`, { size: 11, color: NAVY });
  doc.moveDown(0.3);

  p(doc, `We are delighted to offer you the position of ${ctx.role_title || 'Care Worker'} with ${ORG}. Following your application, interview and the successful completion of our pre-employment checks, we would be very pleased to welcome you to our team, where your work will make a real difference to the people we support in their own homes.`);
  doc.moveDown(0.35);
  p(doc, `This letter sets out the principal terms of our offer. Your full terms and conditions will be provided separately in your written statement of employment particulars (your contract of employment), which you will receive on or before your first day.`);

  h(doc, 'Role and reporting line');
  p(doc, `You will be employed as ${ctx.role_title || 'Care Worker'}, reporting to ${ctx.manager_name || DEFAULT_MANAGER}. You will be expected to deliver safe, compassionate, person-centred care in line with our policies, CQC standards and your training.`);

  h(doc, 'Start date');
  p(doc, `Your employment is due to commence on ${fmtDate(ctx.start_date)}, subject to the conditions set out below. Please contact us as soon as possible if this date presents any difficulty.`);

  h(doc, 'Rate of pay');
  p(doc, `Your rate of pay will be ${money(ctx.hourly_rate)} per hour. Salary is paid monthly in arrears, on or around the last working day of each month, by BACS transfer directly into your nominated bank account, subject to deductions for income tax and National Insurance under PAYE.`);

  h(doc, 'Hours of work');
  p(doc, `Your normal contracted hours are ${ctx.hours_per_week || '—'} hours per week, worked on a rota basis across mornings, evenings, weekends and bank holidays as required to meet the needs of the people we support. Your specific rota will be agreed with your coordinator.`);

  h(doc, 'Probationary period');
  p(doc, `Your appointment is subject to a probationary period of ${ctx.probation || '6 months'}, during which your suitability for the role will be reviewed and either party may end the employment on shorter notice. Successful completion of your probation will be confirmed to you in writing.`);

  h(doc, 'Conditions of the offer');
  p(doc, `This offer has been made subject to, and following, satisfactory completion of our pre-employment checks — an enhanced DBS disclosure, verification of your right to work in the UK, and satisfactory employment references — each of which we are pleased to confirm has now been received and approved. Your continued employment remains conditional on your maintaining these checks (for example, ongoing right to work and DBS status) as required by law and our regulator.`);

  h(doc, 'Accepting this offer');
  p(doc, `To accept this offer, please sign and date one copy of this letter in the space below and return it to us, retaining a copy for your own records. If you have any questions about any aspect of this offer, please do not hesitate to contact us — we will be glad to help.`);
  doc.moveDown(0.3);
  p(doc, `We very much look forward to working with you.`);
  doc.moveDown(0.4);
  p(doc, `Yours sincerely,`);
  doc.moveDown(0.2);
  p(doc, `${ctx.manager_name || DEFAULT_MANAGER}`, { color: NAVY });
  p(doc, ORG, { size: 9, color: '#555' });

  signatureBlocks(doc, name);
  doc.moveDown(1);
  p(doc, 'CONFIDENTIAL — contains personal data. Handle in accordance with UK GDPR.', { size: 8, color: '#888' });
}

// --- 2) Written Statement of Employment Particulars (≥600 words) ------------
export function writeEmploymentContract(doc, ctx) {
  header(doc, 'Written Statement of Employment Particulars');
  const name = ctx.staff_name || 'Employee';
  // Header note — legal disclaimer.
  doc.rect(50, doc.y, doc.page.width - 100, 40).fillAndStroke('#fff7e6', '#e6c260');
  doc.fillColor('#7a5b00').fontSize(8.5).text(
    'This document should be reviewed by a qualified employment solicitor before use as a binding contract for real hires. It is drafted to reflect standard UK employment law requirements as a professional starting template.',
    56, doc.y - 34, { width: doc.page.width - 112, lineGap: 1 });
  doc.fillColor('#000');
  doc.moveDown(1.6);

  p(doc, `This statement is provided in accordance with the Employment Rights Act 1996 and sets out the particulars of your employment as at ${fmtDate(new Date().toISOString())}.`, { size: 9.5, color: '#555' });

  const hd = holidayDays(ctx.hours_per_week);
  numbered(doc, 1, 'Parties', `This is an agreement between ${ORG} of ${ADDRESS} ("the Company", "we", "us") and ${name} ("you", "the Employee").`);
  numbered(doc, 2, 'Job title and duties', `You are employed as ${ctx.role_title || 'Care Worker'}. Your duties include the delivery of personal care and support to the people we serve in their own homes, the safe administration and prompt recording of care in line with each individual's care plan, and any other reasonable duties consistent with your role and skills. Duties may be varied from time to time to meet the needs of the service.`);
  numbered(doc, 3, 'Commencement and continuous employment', `Your employment begins on ${fmtDate(ctx.start_date)}. No employment with a previous employer counts as part of your continuous period of employment, which therefore begins on that date.`);
  numbered(doc, 4, 'Pay', `Your rate of pay is ${money(ctx.hourly_rate)} per hour. You are paid monthly in arrears by BACS, on or around the last working day of each month, less deductions for PAYE income tax and National Insurance.`);
  numbered(doc, 5, 'Hours and days of work', `Your normal contracted hours are ${ctx.hours_per_week || '—'} hours per week, worked flexibly on a rota that includes days, evenings, weekends and bank holidays according to the needs of the people we support. There is no guarantee that overtime will be available.`);
  numbered(doc, 6, 'Holiday entitlement', `Your statutory paid holiday entitlement is 5.6 weeks per year (equivalent to 28 days for a full-time, five-day worker), inclusive of bank and public holidays. As you work ${ctx.hours_per_week || '—'} hours per week, this is pro-rated to approximately ${hd} days per holiday year. The holiday year runs from 1 April to 31 March. Holiday must be requested and authorised in advance; payment for accrued but untaken holiday is made on termination.`);
  numbered(doc, 7, 'Sickness absence and pay', `If you are absent from work due to sickness you must notify your coordinator as early as possible on the first day of absence. Subject to meeting the qualifying conditions, you will be entitled to Statutory Sick Pay (SSP) in accordance with the prevailing statutory scheme. The Company does not currently offer contractual sick pay above SSP.`);
  numbered(doc, 8, 'Pension', `The Company complies with its automatic-enrolment duties under the Pensions Act 2008 as regulated by The Pensions Regulator. If you meet the eligibility criteria you will be automatically enrolled into the Company's workplace pension scheme, with employer and employee contributions at the statutory minimum levels, and you may opt out in accordance with the scheme rules.`);
  numbered(doc, 9, 'Place of work', `Your place of work is the homes of the people we support within the Company's operating area, together with the Company's office at ${ADDRESS} as required. You are not required to work outside the United Kingdom.`);
  numbered(doc, 10, 'Notice', `During your probationary period, either party may terminate the employment on one week's written notice. On successful completion of probation, the Company will give you not less than one week's notice for each complete year of continuous service (up to a statutory maximum of twelve weeks), and not less than one week where you have between one month and two years' service. You are required to give the Company not less than four weeks' written notice.`);
  numbered(doc, 11, 'Disciplinary and grievance procedures', `The Company's full disciplinary and grievance procedures are set out in the Staff Handbook, which forms part of your terms of employment. If you wish to raise a grievance, or if you are dissatisfied with any disciplinary decision, you should follow the procedure set out in the Handbook. These procedures are non-contractual.`);
  numbered(doc, 12, 'Probationary period', `Your employment is subject to a probationary period of ${ctx.probation || '6 months'}. The Company may extend this period at its discretion. Satisfactory completion will be confirmed to you in writing.`);
  numbered(doc, 13, 'Confidentiality and safeguarding', `In the course of your work you will have access to highly sensitive personal and special-category information about the people we support, their families and your colleagues, including health, care and safeguarding information. You must keep all such information strictly confidential, use it only as necessary to carry out your duties, and handle it in accordance with UK GDPR, the Data Protection Act 2018 and our policies. This obligation continues after your employment ends. Any safeguarding concern must be reported immediately in line with our safeguarding policy; nothing in this clause prevents you from making a protected disclosure or reporting a concern to a regulator.`);

  signatureBlocks(doc, name);
  doc.moveDown(1);
  p(doc, 'CONFIDENTIAL — contains personal data. Handle in accordance with UK GDPR.', { size: 8, color: '#888' });
}

// --- 3) Staff Handbook acknowledgement receipt (≥200 words) -----------------
export function writeHandbookAck(doc, ctx) {
  header(doc, 'Staff Handbook — Acknowledgement of Receipt');
  const name = ctx.staff_name || 'Employee';
  p(doc, `Employee: ${name}`, { size: 11, color: NAVY });
  p(doc, `Role: ${ctx.role_title || '—'}`, { size: 10, color: '#555' });
  doc.moveDown(0.4);

  p(doc, `This form confirms that I have received a copy of the ${ORG} Staff Handbook. I understand that the Handbook contains important information about the Company's policies, procedures and my responsibilities as an employee, and that it forms part of my terms of employment. I agree to read the Handbook carefully, to ask my manager about anything I do not understand, and to comply with the policies and procedures it sets out at all times.`);
  doc.moveDown(0.3);
  p(doc, `I understand that the Handbook covers, among other things, the following key areas:`);
  doc.moveDown(0.2);
  for (const topic of [
    'Code of conduct and professional standards',
    'Safeguarding adults and children',
    'Health and safety, including lone working and moving & handling',
    'Equality, diversity and inclusion',
    'Disciplinary and grievance procedures',
    'Data protection and confidentiality (UK GDPR)',
    'Whistleblowing and raising concerns',
  ]) doc.fontSize(10).fillColor('#111').text(`•  ${topic}`, { indent: 12, lineGap: 1.5 });
  doc.moveDown(0.3);
  p(doc, `I acknowledge that the Company may update the Handbook from time to time, that the current version will be made available to me, and that I am responsible for keeping up to date with any changes notified to me.`);

  signatureBlocks(doc, name);
  doc.moveDown(0.6);
  p(doc, 'Please sign, date and return this acknowledgement to your manager.', { size: 8.5, color: '#888' });
}
