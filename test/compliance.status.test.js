// Compliance status model: three states, and the invariants that keep the
// dashboard headline from ever disagreeing with the "Incomplete files" panel.
//
// Regression cover for:
//   F-01  an empty record scored "Compliant" (green was the fallthrough branch)
//   F-02  missing-entirely fields produced no alert at all
//   F-03  headline count and completeness panel ran as independent engines
//   F-05  Right to Work risk detection
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  computeCompliance, rightToWorkRisk, REQUIRED_FIELDS, REQUIRED_DOCUMENTS, REQUIRED_TOTAL,
} from '../src/compliance.js';

const localDateStr = (offsetDays) => {
  const n = new Date();
  const d = new Date(n.getFullYear(), n.getMonth(), n.getDate() + offsetDays);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
};

// A record holding every required field and document, nothing expired.
const compliantStaff = (over = {}) => ({
  id: 1,
  full_name: 'Complete Person',
  dbs_certificate_number: '001234567890',
  dbs_issue_date: '2025-01-10',
  right_to_work_type: 'British/Irish citizen',
  right_to_work_status: 'Confirmed',
  care_certificate_date: '2025-03-01',
  health_declaration_date: '2025-01-05',
  last_supervision_date: '2026-06-01',
  last_appraisal_date: '2026-05-01',
  references_count: 2,
  document_categories: new Set(REQUIRED_DOCUMENTS.map((d) => d.category)),
  ...over,
});

// The production case that started this: nothing recorded, nothing uploaded.
const emptyStaff = () => ({ id: 2, full_name: '', references_count: 0, document_categories: new Set() });

test('F-01: a record with no evidence is NOT compliant', () => {
  const c = computeCompliance(emptyStaff());
  assert.equal(c.status, 'incomplete');
  assert.notEqual(c.rag, 'green');
  assert.equal(c.complete, false);
});

test('F-01: the production case — DBS pending, RTW pending, no docs', () => {
  const c = computeCompliance({
    id: 3, full_name: 'Pending Person',
    dbs_status: 'Pending', right_to_work_status: 'Pending', care_certificate_status: 'Not started',
    references_count: 0, document_categories: new Set(),
  });
  assert.equal(c.status, 'incomplete', 'must not be compliant on status words alone');
  assert.ok(c.missing.includes('DBS certificate number'));
  assert.ok(c.missing.includes('Right to Work confirmed'));
});

test('a fully evidenced record with nothing expired is compliant', () => {
  const c = computeCompliance(compliantStaff());
  assert.equal(c.status, 'compliant');
  assert.equal(c.rag, 'green');
  assert.deepEqual(c.missing, []);
});

test('every required field is individually load-bearing (strict: all 10)', () => {
  for (const r of REQUIRED_FIELDS) {
    const blank = r.field === 'references_count' ? 0 : '';
    const c = computeCompliance(compliantStaff({ [r.field]: blank }));
    assert.equal(c.status, 'incomplete', `blank ${r.field} must drop the record out of Compliant`);
    assert.ok(c.missing.includes(r.label), `${r.label} should be listed as missing`);
  }
});

test('an overdue appraisal alone drops the record out of Compliant (confirmed policy)', () => {
  const c = computeCompliance(compliantStaff({ last_appraisal_date: '' }));
  assert.equal(c.status, 'incomplete');
  assert.deepEqual(c.missing, ['Last appraisal recorded']);
});

test('required documents must be PRESENT, not merely status-approved', () => {
  for (const d of REQUIRED_DOCUMENTS) {
    const cats = new Set(REQUIRED_DOCUMENTS.map((x) => x.category));
    cats.delete(d.category);
    const c = computeCompliance(compliantStaff({ document_categories: cats }));
    assert.equal(c.status, 'incomplete', `${d.category} absent must block Compliant`);
    assert.ok(c.missing.includes(d.label));
  }
});

test('a record with no document_categories supplied is under-stated, never over-stated', () => {
  // A caller that forgets the evidence context must not get a falsely clean result.
  const { document_categories, ...noContext } = compliantStaff();
  const c = computeCompliance(noContext);
  assert.equal(c.status, 'incomplete');
});

test('References: 1 received is not enough, 2 is', () => {
  assert.equal(computeCompliance(compliantStaff({ references_count: 1 })).status, 'incomplete');
  assert.equal(computeCompliance(compliantStaff({ references_count: 2 })).status, 'compliant');
});

test('Right to Work must be Confirmed, not merely present', () => {
  for (const v of ['Pending', 'Not confirmed', '']) {
    assert.equal(computeCompliance(compliantStaff({ right_to_work_status: v })).status, 'incomplete', `status "${v}"`);
  }
});

test('three states: complete-but-expired is "expired", not "incomplete"', () => {
  const c = computeCompliance(compliantStaff({ dbs_expiry: localDateStr(-10) }));
  assert.equal(c.status, 'expired');
  assert.equal(c.rag, 'red');
  assert.equal(c.complete, true, 'evidence is held — it has simply lapsed');
});

test('three states: missing takes precedence over expired', () => {
  // Confirmed decision: missing evidence outranks a lapsed date, because you
  // cannot judge the currency of evidence you do not hold.
  const c = computeCompliance(compliantStaff({ dbs_certificate_number: '', dbs_expiry: localDateStr(-10) }));
  assert.equal(c.status, 'incomplete');
  assert.equal(c.counts.expired, 1, 'the expired item is still reported');
  assert.equal(c.counts.missing, 1);
});

test('a compliant record with a renewal due soon stays compliant, shaded amber', () => {
  const c = computeCompliance(compliantStaff({ dbs_expiry: localDateStr(20) }));
  assert.equal(c.status, 'compliant');
  assert.equal(c.rag, 'amber');
});

test('F-02: missing fields generate alerts with kind/level "missing"', () => {
  const c = computeCompliance(emptyStaff());
  assert.ok(c.alerts.length >= REQUIRED_TOTAL - 1, 'every unmet requirement raises an alert');
  const miss = c.alerts.filter((a) => a.level === 'missing');
  assert.equal(miss.length, c.counts.missing);
  for (const a of miss) {
    assert.equal(a.kind, 'missing');
    assert.equal(a.days, null, 'missing items have no date');
    assert.ok(a.label && a.area, 'missing alerts still carry a label and area for display');
  }
});

test('F-02: alert ordering is expired → missing → critical → warning', () => {
  const c = computeCompliance(compliantStaff({
    dbs_certificate_number: '',            // missing
    dbs_expiry: localDateStr(-5),          // expired
    visa_expiry: localDateStr(10),         // critical
    passport_expiry: localDateStr(45),     // warning
  }));
  assert.deepEqual(c.alerts.map((a) => a.level), ['expired', 'missing', 'critical', 'warning']);
});

test('F-02: null days never scramble the sort', () => {
  const c = computeCompliance(emptyStaff());
  const ordered = c.alerts.map((a) => a.level);
  assert.deepEqual(ordered, [...ordered].sort((a, b) =>
    ({ expired: 0, missing: 1, critical: 2, warning: 3 }[a] - { expired: 0, missing: 1, critical: 2, warning: 3 }[b])));
  assert.ok(c.alerts.every((a) => a.label !== undefined), 'no undefined labels from a broken comparator');
});

test('F-03 invariant: status "compliant" implies nothing missing', () => {
  const cases = [emptyStaff(), compliantStaff(), compliantStaff({ references_count: 0 }),
    compliantStaff({ dbs_expiry: localDateStr(-1) }), compliantStaff({ full_name: '' })];
  for (const s of cases) {
    const c = computeCompliance(s);
    if (c.status === 'compliant') assert.equal(c.missing.length, 0);
    if (c.missing.length > 0) assert.notEqual(c.status, 'compliant');
  }
});

test('F-03 invariant: the three states partition the population exactly', () => {
  const staff = [emptyStaff(), compliantStaff(), compliantStaff({ dbs_expiry: localDateStr(-3) }),
    compliantStaff({ last_supervision_date: '' }), compliantStaff({ dbs_expiry: localDateStr(15) })];
  const results = staff.map(computeCompliance);
  const counts = { compliant: 0, incomplete: 0, expired: 0 };
  for (const c of results) counts[c.status]++;
  assert.equal(counts.compliant + counts.incomplete + counts.expired, staff.length,
    'every record lands in exactly one state — headline figures must sum to the total');
  // "Fully compliant" can never exceed "files that are complete".
  assert.ok(counts.compliant <= results.filter((c) => c.complete).length);
});

test('F-05: Right to Work risk — overdue review', () => {
  const r = rightToWorkRisk(compliantStaff({ right_to_work_expiry: localDateStr(-664) }));
  assert.equal(r.level, 'overdue');
  assert.equal(r.days, 664, 'exact overdue count for the banner');
});

test('F-05: Right to Work risk — never confirmed / no basis', () => {
  assert.equal(rightToWorkRisk(compliantStaff({ right_to_work_type: '' })).level, 'no_basis');
  assert.equal(rightToWorkRisk(compliantStaff({ right_to_work_status: 'Pending' })).level, 'unconfirmed');
});

test('F-05: no risk flagged when Right to Work is confirmed and in date', () => {
  assert.equal(rightToWorkRisk(compliantStaff({ right_to_work_expiry: localDateStr(200) })), null);
  assert.equal(rightToWorkRisk(compliantStaff()), null, 'no review date + confirmed British citizen is fine');
});

test('counts.missing matches the missing list length', () => {
  for (const s of [emptyStaff(), compliantStaff({ full_name: '', references_count: 0 })]) {
    const c = computeCompliance(s);
    assert.equal(c.counts.missing, c.missing.length);
  }
});
