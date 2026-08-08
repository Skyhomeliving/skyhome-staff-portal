// Evidence-permission model (F-09).
//
// The rule: staff CONTRIBUTE evidence, only management REMOVES or VERIFIES it.
// Before this, canEditStaff() granted self-access, so a carer could delete their
// own DBS certificate, drop a received reference, or erase an employment gap —
// each of which now silently changes the record's own compliance status.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canViewStaff, canEditStaff, canDeleteEvidence, canVerifyEvidence } from '../src/auth.js';
import { ROLES, roleTier } from '../src/compliance.js';

const user = (role, id = 6) => ({ id, role });
const CARER = user('carer');
const SUPPORT = user('support_worker');
const COORD = user('coordinator');
const MANAGER = user('manager', 99);
const ADMIN = user('admin', 98);
const OWN_RECORD = 6;

test('a staff member may still view and edit their own record', () => {
  assert.equal(canViewStaff(CARER, OWN_RECORD), true);
  assert.equal(canEditStaff(CARER, OWN_RECORD), true, 'self-service onboarding must keep working');
});

test('F-09: a carer may NOT delete evidence, including on their own record', () => {
  assert.equal(canDeleteEvidence(CARER), false);
  assert.equal(canDeleteEvidence(SUPPORT), false);
});

test('F-09: a coordinator may not delete evidence either (read-only by design)', () => {
  // Deliberate: widening the oversight role to destructive actions would loosen
  // the permission model, not tighten it.
  assert.equal(roleTier('coordinator'), 'oversight');
  assert.equal(canDeleteEvidence(COORD), false);
});

test('F-09: management retains delete rights', () => {
  assert.equal(canDeleteEvidence(MANAGER), true);
  assert.equal(canDeleteEvidence(ADMIN), true);
});

test('only management may mark evidence verified (reference received)', () => {
  assert.equal(canVerifyEvidence(CARER), false);
  assert.equal(canVerifyEvidence(COORD), false);
  assert.equal(canVerifyEvidence(MANAGER), true);
  assert.equal(canVerifyEvidence(ADMIN), true);
});

test('no frontline role can delete or verify evidence', () => {
  for (const r of ROLES.filter((x) => x.tier === 'frontline')) {
    assert.equal(canDeleteEvidence(user(r.value)), false, `${r.value} must not delete`);
    assert.equal(canVerifyEvidence(user(r.value)), false, `${r.value} must not verify`);
  }
});

test('delete rights are strictly narrower than edit rights', () => {
  // Every role that can delete can also edit; the reverse must not hold.
  for (const r of ROLES) {
    const u = user(r.value);
    if (canDeleteEvidence(u)) assert.equal(canEditStaff(u, OWN_RECORD), true, `${r.value}`);
  }
  assert.ok(canEditStaff(CARER, OWN_RECORD) && !canDeleteEvidence(CARER),
    'a carer can edit their own record but cannot delete evidence from it');
});

test('an unknown or spoofed role gets no destructive rights', () => {
  for (const role of ['', 'superuser', 'ADMIN', 'staff', undefined]) {
    assert.equal(canDeleteEvidence({ id: 1, role }), false, `role ${JSON.stringify(role)}`);
    assert.equal(canVerifyEvidence({ id: 1, role }), false, `role ${JSON.stringify(role)}`);
  }
});
