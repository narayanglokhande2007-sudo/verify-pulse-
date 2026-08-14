import assert from 'node:assert/strict';
import { createRequestBudget, positiveInteger } from '../lib/request_budget.js';

let now = 1_000;
const budget = createRequestBudget({ totalMs: 2_800, clock: () => now });
assert.equal(budget.remainingMs(), 2_800);
assert.equal(budget.timeoutFor({ capMs: 1_200 }), 1_200);

now += 1_900;
assert.equal(budget.remainingMs(), 900);
assert.equal(budget.timeoutFor({ capMs: 1_200 }), 900);
assert.equal(budget.canStart(850), true);

now += 700;
assert.equal(budget.remainingMs(), 200);
assert.equal(budget.canStart(250), false);
assert.equal(budget.timeoutFor({ capMs: 1_200, minimumMs: 250 }), 0);
assert.equal(positiveInteger('5000', 2800, 10000), 5000);
assert.equal(positiveInteger('invalid', 2800, 10000), 2800);

console.log('Request-budget suite passed: bounded provider timeouts and no-start cutoff verified.');
