import fs from 'node:fs';
import path from 'node:path';

const root = process.argv[2] ? path.resolve(process.argv[2]) : process.cwd();
const required = [
  'deploy/docker/Dockerfile',
  'deploy/docker/docker-compose.yml',
  'deploy/docker/AIRGAPPED_RUNBOOK.md',
  'api/status.js',
  'lib/historical_reputation.js',
  'pipeline/daily-data/historical-reputation-index/manifest.json'
];
const missing = required.filter((relative) => !fs.existsSync(path.join(root, relative)));
if (missing.length) {
  console.error(JSON.stringify({ valid: false, error: 'MISSING_REQUIRED_FILES', missing }));
  process.exit(1);
}
const compose = fs.readFileSync(path.join(root, 'deploy/docker/docker-compose.yml'), 'utf8');
const dockerfile = fs.readFileSync(path.join(root, 'deploy/docker/Dockerfile'), 'utf8');
const warnings = [];
if (/latest\b/i.test(`${compose}\n${dockerfile}`)) warnings.push('UNPINNED_IMAGE_TAG');
if (/API_KEY|SECRET|TOKEN/i.test(compose)) warnings.push('REVIEW_ENVIRONMENT_SECRETS');
console.log(JSON.stringify({
  valid: true,
  requiredFiles: required.length,
  warnings,
  note: 'This validates bundle structure only; target-environment deployment approval is still required.'
}, null, 2));
