import assert from 'node:assert/strict';
import fs from 'node:fs';
import { spawnSync } from 'node:child_process';

const root = process.cwd();
const packageJson = JSON.parse(fs.readFileSync('sdk/app-shield/package.json', 'utf8'));
assert.equal(packageJson.name, '@verifypulse/app-shield');
assert.equal(packageJson.main, './index.js');
assert.ok(fs.existsSync('sdk/app-shield/README.md'));
assert.ok(fs.existsSync('deploy/docker/AIRGAPPED_RUNBOOK.md'));

const result = spawnSync(process.execPath, ['scripts/validate_airgapped_bundle.mjs', root], { encoding: 'utf8' });
assert.equal(result.status, 0, result.stderr);
const output = JSON.parse(result.stdout);
assert.equal(output.valid, true);
assert.equal(output.requiredFiles, 6);
console.log('Deployment readiness structure passed: App-Shield package and air-gapped bundle are structurally validated.');
