// Date/expiry boundary tests for the compliance engine.
//
// Regression cover for F-04: daysUntil() compared a date-only string (parsed as
// midnight UTC) against the current instant, so east-of-UTC local time made every
// expiry read one day earlier than it was. An item expiring today reported
// "Expired 1d ago"; the 30- and 60-day alert bands fired a day early.
//
// These tests are timezone-agnostic on purpose: they build the input from the
// local calendar and assert an exact whole-day answer, so they hold in UTC and
// fail loudly under any offset if the UTC/local mix ever comes back.
//
// Run:  npm test          (also:  TZ=Europe/London npm test,  TZ=Pacific/Auckland npm test)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { daysUntil, levelFor } from '../src/compliance.js';

// A YYYY-MM-DD string for "N days from today" in the LOCAL calendar.
const localDateStr = (offsetDays) => {
  const n = new Date();
  const d = new Date(n.getFullYear(), n.getMonth(), n.getDate() + offsetDays);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
};

test('daysUntil: an expiry dated today is 0, not -1', () => {
  assert.equal(daysUntil(localDateStr(0)), 0);
});

test('daysUntil: adjacent days', () => {
  assert.equal(daysUntil(localDateStr(1)), 1, 'tomorrow');
  assert.equal(daysUntil(localDateStr(-1)), -1, 'yesterday');
});

test('daysUntil: alert-band boundaries are exact', () => {
  for (const d of [29, 30, 31, 59, 60, 61]) {
    assert.equal(daysUntil(localDateStr(d)), d, `${d} days ahead`);
  }
});

test('daysUntil: long-overdue item (the 664-day Right to Work case)', () => {
  assert.equal(daysUntil(localDateStr(-664)), -664);
});

// The decisive one: exact for every offset across >2 years, which necessarily
// spans DST transitions in any observing timezone.
test('daysUntil: exact for every offset from -400 to +400 (crosses DST)', () => {
  const wrong = [];
  for (let i = -400; i <= 400; i++) {
    const got = daysUntil(localDateStr(i));
    if (got !== i) wrong.push({ offset: i, got });
  }
  assert.deepEqual(wrong, [], `off-by-N at ${wrong.length} offsets, e.g. ${JSON.stringify(wrong.slice(0, 5))}`);
});

test('daysUntil: blank and unparseable input returns null', () => {
  for (const v of [null, undefined, '', '   ', 'not-a-date', 'pending', 'N/A']) {
    assert.equal(daysUntil(v), null, JSON.stringify(v));
  }
});

test('daysUntil: impossible calendar dates return null rather than rolling over', () => {
  assert.equal(daysUntil('2026-02-30'), null, '30 Feb must not become 2 Mar');
  assert.equal(daysUntil('2026-13-01'), null, 'month 13');
  assert.equal(daysUntil('2026-00-10'), null, 'month 0');
});

test('daysUntil: real leap day is valid', () => {
  assert.equal(typeof daysUntil('2028-02-29'), 'number');
});

test('daysUntil: time-of-day does not change the answer', () => {
  // Same calendar day, different clock times → identical whole-day result.
  const today = localDateStr(0);
  assert.equal(daysUntil(`${today}T00:00:00`), 0);
  assert.equal(daysUntil(`${today}T23:59:59`), 0);
});

test('levelFor: bands map correctly around the boundaries', () => {
  assert.equal(levelFor(null), null);
  assert.equal(levelFor(-1), 'expired');
  assert.equal(levelFor(-664), 'expired');
  assert.equal(levelFor(0), 'critical', 'expires today — still valid today, not yet expired');
  assert.equal(levelFor(30), 'critical');
  assert.equal(levelFor(31), 'warning');
  assert.equal(levelFor(60), 'warning');
  assert.equal(levelFor(61), 'ok');
});

test('levelFor: an item expiring today is never reported as already expired', () => {
  assert.notEqual(levelFor(daysUntil(localDateStr(0))), 'expired');
});
