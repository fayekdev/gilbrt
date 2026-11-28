import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

const context = vm.createContext({});
vm.runInContext(readFileSync(new URL('../gilbrt/gui_assets/audit-clock.js', import.meta.url), 'utf8'), context);
const clock = context.GilbrtAuditClock;

test('clock advances during a long inference without more server progress events', () => {
  const sample = clock.sample({id:'a', status:'running', elapsed:12}, null, 1000);
  assert.equal(clock.format(clock.seconds(sample, 66000)), '01:17');
});

test('server elapsed restores a running audit without depending on remote wall-clock time', () => {
  const sample = clock.sample({id:'a', status:'running', elapsed:125, started_at:1}, null, 5);
  assert.equal(clock.format(clock.seconds(sample, 5)), '02:05');
});

test('same-job polling never moves the active counter backwards', () => {
  const first = clock.sample({id:'a', status:'running', elapsed:10}, null, 0);
  const second = clock.sample({id:'a', status:'running', elapsed:10}, first, 4000);
  assert.equal(clock.seconds(second, 5000), 15);
});

test('cancellation keeps counting until the backend actually stops', () => {
  const sample = clock.sample({id:'a', status:'cancelling', elapsed:30}, null, 0);
  assert.equal(clock.seconds(sample, 7000), 37);
});

test('complete, failed and cancelled jobs freeze at the final server duration', () => {
  for (const status of ['complete','failed','cancelled']) {
    const active = clock.sample({id:'a', status:'running', elapsed:20}, null, 0);
    const terminal = clock.sample({id:'a', status, elapsed:23.2}, active, 4000);
    assert.equal(clock.seconds(terminal, 100000), 23.2);
  }
});

test('new jobs reset and missing jobs clear the old sample', () => {
  const first = clock.sample({id:'a', status:'running', elapsed:900}, null, 0);
  const second = clock.sample({id:'b', status:'running', elapsed:0}, first, 5000);
  assert.equal(clock.seconds(second, 5000), 0);
  assert.equal(clock.sample(null, second, 6000), null);
});

test('format includes hours and handles invalid durations', () => {
  assert.equal(clock.format(0), '00:00');
  assert.equal(clock.format(3599), '59:59');
  assert.equal(clock.format(3601), '01:00:01');
  assert.equal(clock.format(90061), '25:01:01');
  assert.equal(clock.format(NaN), '00:00');
  assert.equal(clock.format(-20), '00:00');
});
