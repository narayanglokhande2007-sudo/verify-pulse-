import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const workflowPath = new URL('../.github/workflows/daily_scam_fetch.yml', import.meta.url);
const workflow = await readFile(workflowPath, 'utf8');

const requiredSteps = [
  {
    name: 'Collect compact bounded public indicators',
    command: 'python pipeline/fetch_indian_bulk_scams.py --max-records-per-source 600 --min-successful-sources 2'
  },
  {
    name: 'Build and validate current threat-intelligence snapshot',
    command: 'python pipeline/check_threat_intelligence_freshness.py --max-age-hours 30 --min-active-indicators 1 --require-same-day'
  },
  {
    name: 'Refresh and validate permanent historical reputation index',
    command: 'python pipeline/check_historical_reputation_index.py --require-fresh --min-successful-sources 2'
  },
  {
    name: 'Commit only validated compact artifacts',
    command: 'git diff --cached --quiet || (git commit -m "Automated validated threat-data refresh" && git push)'
  }
];

const workflowSafetyGuard = 'Verify scheduled workflow safety before data collection';
const workflowSafetyTest = 'node tests/run_daily_workflow_safety.mjs';
const trustedRestoreStep = 'Verify trusted Daily Fetcher restore point';
const trustedRestoreCommand = 'python pipeline/daily_fetcher_restore.py verify';
const reportingStep = 'Write privacy-safe Daily Fetcher run report';
const reportingCommand = 'python pipeline/daily_fetcher_report.py --outcome "$GITHUB_JOB_STATUS" --github-summary "$GITHUB_STEP_SUMMARY"';
const collectionStepName = requiredSteps[0].name;
const commitStepName = requiredSteps[3].name;
const guardIndex = workflow.indexOf(workflowSafetyGuard);
const restoreIndex = workflow.indexOf(trustedRestoreStep);
const collectionIndex = workflow.indexOf(collectionStepName);
const commitIndex = workflow.indexOf(commitStepName);
const reportIndex = workflow.indexOf(reportingStep);

assert.ok(guardIndex >= 0, 'Scheduled workflow must run its safety guard before any data operation.');
assert.ok(restoreIndex >= 0, 'Scheduled workflow must verify the trusted restore point before collection.');
assert.ok(collectionIndex >= 0, 'Scheduled workflow must retain its bounded data collection step.');
assert.ok(guardIndex < restoreIndex, 'Workflow safety guard must run before trusted restore verification.');
assert.ok(restoreIndex < collectionIndex, 'Trusted restore verification must run before data collection.');
assert.ok(
  workflow.indexOf('Set up Node.js for workflow safety guard') < guardIndex,
  'Workflow must prepare Node.js before running its safety guard.'
);

const escapedGuardName = workflowSafetyGuard.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const guardPattern = new RegExp(`- name: ${escapedGuardName}[\\s\\S]*?(?=\\n      - name:|$)`);
const guardMatch = workflow.match(guardPattern);
assert.ok(guardMatch, 'Workflow safety guard step must exist.');
assert.match(guardMatch[0], /shell:\s*bash/, 'Workflow safety guard must explicitly use Bash.');
assert.ok(guardMatch[0].includes(workflowSafetyTest), 'Workflow safety guard must run the dedicated regression test.');

const escapedRestoreName = trustedRestoreStep.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const restorePattern = new RegExp(`- name: ${escapedRestoreName}[\\s\\S]*?(?=\\n      - name:|$)`);
const restoreMatch = workflow.match(restorePattern);
assert.ok(restoreMatch, 'Trusted restore verification step must exist.');
assert.match(restoreMatch[0], /shell:\s*bash/, 'Trusted restore verification must explicitly use Bash.');
assert.ok(restoreMatch[0].includes(trustedRestoreCommand), 'Trusted restore verification must retain its exact fail-closed command.');

for (const step of requiredSteps) {
  const escapedName = step.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const stepPattern = new RegExp(`- name: ${escapedName}[\\s\\S]*?(?=\\n      - name:|$)`);
  const match = workflow.match(stepPattern);
  assert.ok(match, `Workflow step '${step.name}' must exist.`);
  assert.match(match[0], /shell:\s*bash/, `${step.name} must explicitly use Bash.`);
  assert.match(match[0], /set -euo pipefail/, `${step.name} must use strict shell error handling.`);
  assert.ok(match[0].includes(step.command), `${step.name} must preserve its validated command and arguments on one line.`);
}

assert.ok(
  workflow.includes('git add pipeline/daily-data/source_health_history.json'),
  'Validated source-health history must be committed with validated threat data.'
);
assert.ok(reportIndex > commitIndex, 'Privacy-safe run reporting must happen after all validated data steps.');
const escapedReportingName = reportingStep.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const reportingPattern = new RegExp(`- name: ${escapedReportingName}[\\s\\S]*?(?=\\n      - name:|$)`);
const reportingMatch = workflow.match(reportingPattern);
assert.ok(reportingMatch, 'Privacy-safe reporting step must exist.');
assert.match(reportingMatch[0], /if:\s*always\(\)/, 'Run report must execute even when an earlier guarded step fails.');
assert.match(reportingMatch[0], /shell:\s*bash/, 'Run report must explicitly use Bash.');
assert.ok(reportingMatch[0].includes(reportingCommand), 'Run report must retain its privacy-safe report command.');

assert.doesNotMatch(
  workflow,
  /\\\s*\n\s*\n/,
  'No workflow shell command may use a continuation followed by a blank line.'
);

console.log(`Daily workflow safety suite passed: preflight and trusted restore checks run before collection; ${requiredSteps.length}/4 strict Bash blocks, source-health persistence, and privacy-safe reporting are enforced.`);
