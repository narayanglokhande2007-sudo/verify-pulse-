import { readFileSync, writeFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';

const root = new URL('..', import.meta.url);
const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const scripts = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)]
  .map((match) => match[1])
  .filter((content) => content.trim());

if (scripts.length === 0) throw new Error('No inline scripts found in index.html');

for (const [index, script] of scripts.entries()) {
  const file = join(root.pathname, `.inline-script-${index}.check.js`);
  try {
    writeFileSync(file, script, 'utf8');
    execFileSync(process.execPath, ['--check', file], { stdio: 'pipe' });
  } finally {
    rmSync(file, { force: true });
  }
}

console.log(`Inline script syntax check passed: ${scripts.length} scripts.`);
