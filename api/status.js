import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DATA_ROOT = path.resolve(__dirname, '..', 'pipeline', 'daily-data');

function setHeaders(res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
}

function readJson(relativePath) {
  try {
    const raw = fs.readFileSync(path.join(DATA_ROOT, relativePath), 'utf8');
    return { available: true, value: JSON.parse(raw) };
  } catch {
    return { available: false, value: null };
  }
}

function publishedStatus(dateValue, available) {
  const publishedAt = typeof dateValue === 'string' && Number.isFinite(Date.parse(dateValue)) ? dateValue : null;
  if (!available || !publishedAt) {
    return { state: 'unavailable', detail: 'Published metadata could not be read.', publishedAt: null };
  }

  const ageHours = Math.max(0, (Date.now() - Date.parse(publishedAt)) / 3_600_000);
  if (ageHours > 48) {
    return { state: 'degraded', detail: 'Published metadata is older than 48 hours; do not treat it as a real-time feed.', publishedAt };
  }
  return { state: 'operational', detail: 'Published metadata is available.', publishedAt };
}

export default function handler(req, res) {
  setHeaders(res);
  if (req.method !== 'GET') return res.status(405).json({ error: 'METHOD_NOT_ALLOWED', message: 'Only GET requests are accepted.' });

  const threatIntel = readJson('latest_threat_intel.json');
  const historicalIndex = readJson('historical-reputation-index/manifest.json');
  const threatStatus = publishedStatus(threatIntel.value?.generatedAt || threatIntel.value?.generated_at, threatIntel.available);
  const historicalStatus = publishedStatus(historicalIndex.value?.generatedAt || historicalIndex.value?.generated_at, historicalIndex.available);

  return res.status(200).json({
    service: 'VerifyPulse public status',
    checkedAt: new Date().toISOString(),
    checks: [
      {
        id: 'public_api',
        name: 'Public status endpoint',
        state: 'operational',
        detail: 'This endpoint is responding.'
      },
      {
        id: 'threat_intelligence_metadata',
        name: 'Published threat-intelligence metadata',
        ...threatStatus
      },
      {
        id: 'historical_reputation_metadata',
        name: 'Published historical-reputation metadata',
        ...historicalStatus,
        shardCount: Number.isInteger(historicalIndex.value?.shardCount) ? historicalIndex.value.shardCount : undefined
      },
      {
        id: 'external_ai_providers',
        name: 'External AI analysis providers',
        state: 'not_monitored',
        detail: 'This public page does not probe or promise external-provider availability. A scan can return a degraded/verification-needed result if live analysis is unavailable.'
      }
    ],
    limitations: [
      'Status reflects only the checks listed above at the time this endpoint responded.',
      'Operational does not mean every scan will receive an AI verdict or that every submitted item is safe.',
      'VerifyPulse does not publish an external uptime SLA on this page.'
    ]
  });
}
