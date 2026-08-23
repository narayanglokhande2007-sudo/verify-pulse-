import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const testDirectory = resolve(fileURLToPath(new URL('.', import.meta.url)));
const projectRoot = resolve(testDirectory, '..');
const preferredOrigin = 'https://www.verify-pulse.com';
const defaultVercelHost = 'verify-pulse.vercel.app';

const [vercelConfigText, sitemapText] = await Promise.all([
  readFile(resolve(projectRoot, 'vercel.json'), 'utf8'),
  readFile(resolve(projectRoot, 'sitemap.xml'), 'utf8'),
]);

const vercelConfig = JSON.parse(vercelConfigText);
assert.ok(Array.isArray(vercelConfig.redirects), 'vercel.json must contain redirect rules');

const hasRedirect = (headerKey, headerValue, destination) => vercelConfig.redirects.some((rule) => (
  rule.source === '/(.*)'
  && rule.destination === destination
  && rule.permanent === true
  && Array.isArray(rule.has)
  && rule.has.some((condition) => (
    condition.type === 'header'
    && condition.key === headerKey
    && condition.value === headerValue
  ))
));

assert.ok(
  hasRedirect('x-forwarded-proto', 'http', `${preferredOrigin}/$1`),
  'HTTP traffic must redirect permanently to the preferred production origin',
);
assert.ok(
  hasRedirect('host', defaultVercelHost, `${preferredOrigin}/$1`),
  'the public Vercel hostname must redirect permanently to the preferred production origin',
);
assert.equal(
  vercelConfig.redirects.some((rule) => String(rule.destination || '').includes('vercel.app')),
  false,
  'no redirect may send users or crawlers from the production site to a Vercel hostname',
);

const sitemapUrls = [...sitemapText.matchAll(/<loc>(https:\/\/www\.verify-pulse\.com(?:\/[^<]*)?)<\/loc>/g)]
  .map((match) => match[1]);
assert.ok(sitemapUrls.length > 0, 'sitemap must contain preferred production URLs');

for (const url of sitemapUrls) {
  const pathname = new URL(url).pathname;
  const relativeFile = pathname === '/' ? 'index.html' : pathname.replace(/^\//, '');
  const pageHtml = await readFile(resolve(projectRoot, relativeFile), 'utf8');
  const expectedCanonical = `<link rel="canonical" href="${url}">`;
  const expectedOpenGraphUrl = `<meta property="og:url" content="${url}">`;

  assert.ok(pageHtml.includes(expectedCanonical), `${relativeFile} must self-canonicalize to ${url}`);
  assert.ok(pageHtml.includes(expectedOpenGraphUrl), `${relativeFile} must expose the same preferred Open Graph URL`);
}

console.log(`SEO canonical configuration passed: ${sitemapUrls.length} sitemap pages self-canonicalize and duplicate hosts redirect to ${preferredOrigin}.`);
