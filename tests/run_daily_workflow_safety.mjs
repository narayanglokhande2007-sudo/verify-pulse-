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

for (const step of requiredSteps) {
  const escapedName = step.name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const stepPattern = new RegExp(`- name: ${escapedName}[\\s\\S]*?(?=\\n      - name:|$)`);
  const match = workflow.match(stepPattern);
  assert.ok(match, `Workflow step '${step.name}' must exist.`);
  assert.match(match[0], /shell:\s*bash/, `${step.name} must explicitly use Bash.`);
  assert.match(match[0], /set -euo pipefail/, `${step.name} must use strict shell error handling.`);
  assert.ok(match[0].includes(step.command), `${step.name} must preserve its validated command and arguments on one line.`);
}

assert.doesNotMatch(
  workflow,
  /\\\s*\n\s*\n/,
  'No workflow shell command may use a continuation followed by a blank line.'
);

console.log(`Daily workflow safety suite passed: ${requiredSteps.length}/4 shell blocks retain strict Bash handling, validated arguments, and no blank-line continuation.`);
