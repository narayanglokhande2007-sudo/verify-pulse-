import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import verifyHandler from '../api/verify.js';

const fixturePath = new URL('./fixtures/india_scam_regression_cases.json', import.meta.url);
const adversarialExtensionPath = new URL('./fixtures/india_adversarial_extension_cases.json', import.meta.url);
const fixtureSuite = JSON.parse(await readFile(fixturePath, 'utf8'));
const adversarialExtension = JSON.parse(await readFile(adversarialExtensionPath, 'utf8'));
const allCases = [...fixtureSuite.cases, ...adversarialExtension.cases];
const caseIds = allCases.map((testCase) => testCase.id);
assert.equal(new Set(caseIds).size, caseIds.length, 'Fixture IDs must be unique across the base and adversarial suites.');
assert.ok(
  adversarialExtension.cases.length >= (adversarialExtension.coveragePolicy?.minimumAdditionalFixtures ?? 0),
  `Adversarial extension has ${adversarialExtension.cases.length} cases; the minimum required is ${adversarialExtension.coveragePolicy?.minimumAdditionalFixtures}.`
);

function createResponse() {
  return {
    statusCode: null,
    body: null,
    headers: {},
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return body; },
    end() { return this; }
  };
}

async function scanFixture(testCase, index) {
  const response = createResponse();
  await verifyHandler({
    method: 'POST',
    headers: { 'x-forwarded-for': `198.51.100.${index + 1}` },
    body: {
      text: testCase.input,
      checkType: testCase.checkType,
      ...(testCase.fileData ? { fileData: testCase.fileData } : {})
    },
    socket: {}
  }, response);
  return response;
}

const originalFetch = global.fetch;
const originalGroq = process.env.GROQ_API_KEY;
const originalGemini = process.env.GEMINI_API_KEY;
const originalSafeBrowsing = process.env.SAFE_BROWSING_API_KEY;
process.env.GROQ_API_KEY = 'fixture-only-key';
process.env.GEMINI_API_KEY = 'fixture-only-key';
process.env.SAFE_BROWSING_API_KEY = 'fixture-only-key';

global.fetch = async (url, options = {}) => {
  const target = String(url);
  if (target.includes('raw.githubusercontent.com')) return { ok: false, json: async () => ({}) };
  if (target.includes('safebrowsing.googleapis.com')) {
    const body = JSON.parse(options.body || '{}');
    const checkedUrl = body.threatInfo?.threatEntries?.[0]?.url || '';
    return {
      ok: true,
      json: async () => checkedUrl.includes('rbi-kyc.example') ? { matches: [{ threatType: 'SOCIAL_ENGINEERING' }] } : {}
    };
  }
  if (target.includes('api.groq.com')) {
    return {
      ok: true,
      json: async () => ({
        choices: [{
          message: {
            content: JSON.stringify({
              verdict: 'SAFE',
              scamType: 'Safety Advisory',
              confidence: 88,
              analysis: 'This is preventive anti-fraud advice.',
              findings: [],
              whatToDo: ['Keep following official safety guidance.']
            })
          }
        }]
      })
    };
  }
  throw new Error(`Unexpected fixture-network request: ${target}`);
};

const results = [];
try {
  for (const [index, testCase] of allCases.entries()) {
    const response = await scanFixture(testCase, index);
    const expectedHttpStatus = testCase.expectedHttpStatus || 200;
    assert.equal(response.statusCode, expectedHttpStatus, `${testCase.id}: unexpected HTTP response status.`);
    assert.equal(response.body?.verdict, testCase.expectedVerdict, `${testCase.id}: unexpected verdict.`);
    assert.ok(response.body?.explainability, `${testCase.id}: explainability must be present.`);
    assert.equal(response.body.explainability.version, 'vp-explain-1', `${testCase.id}: wrong explainability version.`);

    if (testCase.expectedEvidenceSource) {
      const acceptableEvidenceSources = testCase.expectedEvidenceSources
        || (testCase.expectedEvidenceSource === 'Local high-confidence fallback rules'
          ? ['Local high-confidence fallback rules', 'Local multilingual intent forensics']
          : testCase.expectedEvidenceSource === 'Local social-engineering rules'
            ? ['Local social-engineering rules', 'Local multilingual intent forensics']
            : [testCase.expectedEvidenceSource]);
      assert.ok(
        acceptableEvidenceSources.some((source) => response.body.evidenceSources.includes(source)),
        `${testCase.id}: missing an acceptable evidence source (${acceptableEvidenceSources.join(', ')}).`
      );
      assert.ok(
        response.body.explainability.evidence.some((item) => acceptableEvidenceSources.includes(item.source)),
        `${testCase.id}: explanation does not match an acceptable evidence source.`
      );
    } else {
      assert.equal(response.body.explainability.assessmentType, 'model-assisted', `${testCase.id}: benign advisory should remain model-assisted.`);
      assert.ok(response.body.explainability.evidence.some((item) => item.source === 'Model-assisted assessment'), `${testCase.id}: model-assisted source is missing.`);
    }
    results.push({
      id: testCase.id,
      riskClass: testCase.riskClass || 'other',
      categories: Array.isArray(testCase.categories) ? testCase.categories : [],
      verdict: response.body.verdict,
      assessmentType: response.body.explainability.assessmentType
    });
  }
} finally {
  global.fetch = originalFetch;
  if (originalGroq === undefined) delete process.env.GROQ_API_KEY; else process.env.GROQ_API_KEY = originalGroq;
  if (originalGemini === undefined) delete process.env.GEMINI_API_KEY; else process.env.GEMINI_API_KEY = originalGemini;
  if (originalSafeBrowsing === undefined) delete process.env.SAFE_BROWSING_API_KEY; else process.env.SAFE_BROWSING_API_KEY = originalSafeBrowsing;
}

const positiveAlertVerdicts = new Set(fixtureSuite.acceptancePolicy?.positiveAlertVerdicts || ['SUSPICIOUS', 'DANGEROUS', 'SCAM', 'FRAUD']);
const scamResults = results.filter((result) => result.riskClass === 'scam');
const benignResults = results.filter((result) => result.riskClass === 'benign');
const scamAlerts = scamResults.filter((result) => positiveAlertVerdicts.has(result.verdict)).length;
const benignFalsePositives = benignResults.filter((result) => positiveAlertVerdicts.has(result.verdict)).length;
const scamAlertRecall = scamResults.length ? scamAlerts / scamResults.length : 1;
const benignFalsePositiveRate = benignResults.length ? benignFalsePositives / benignResults.length : 0;
const observedCategories = new Set(results.flatMap((result) => result.categories));
const requiredCategories = adversarialExtension.coveragePolicy?.requiredCategories || [];
for (const category of requiredCategories) {
  assert.ok(observedCategories.has(category), `Required adversarial category '${category}' has no fixture coverage.`);
}
const metrics = {
  fixtureCount: results.length,
  baseFixtureCount: fixtureSuite.cases.length,
  adversarialFixtureCount: adversarialExtension.cases.length,
  coveredAdversarialCategories: requiredCategories.length,
  scamCaseCount: scamResults.length,
  scamAlerts,
  scamAlertRecall,
  benignCaseCount: benignResults.length,
  benignFalsePositives,
  benignFalsePositiveRate
};

assert.ok(
  scamAlertRecall >= (fixtureSuite.acceptancePolicy?.minimumScamAlertRecall ?? 1),
  `Scam alert recall ${scamAlertRecall} is below the configured quality gate.`
);
assert.ok(
  benignFalsePositiveRate <= (fixtureSuite.acceptancePolicy?.maximumBenignFalsePositiveRate ?? 0),
  `Benign false-positive rate ${benignFalsePositiveRate} exceeds the configured quality gate.`
);

console.table(results);
console.table([metrics]);
console.log(`India regression suite passed: ${results.length} labelled fixtures (${fixtureSuite.cases.length} base + ${adversarialExtension.cases.length} adversarial), with ${requiredCategories.length} required adversarial categories. Scam-alert recall: ${(scamAlertRecall * 100).toFixed(1)}%. Benign false-positive rate: ${(benignFalsePositiveRate * 100).toFixed(1)}%.`);
