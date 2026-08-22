// lib/url_forensics.js
// Deterministic, dependency-free URL and brand forensics for VerifyPulse.
// It does not fetch URLs, expand shorteners, or contact third parties.

const BRAND_REGISTRY = [
  'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'paytm', 'phonepe', 'gpay',
  'googlepay', 'npci', 'airtel', 'jio', 'amazon', 'flipkart', 'bluedart',
  'indiapost', 'fastag', 'irctc', 'rbi', 'uidai', 'incometax', 'verifypulse'
];

const SHORTENER_HOSTS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rb.gy', 'shorturl.at']);
const ACTION_PATTERN = /\b(?:click|tap|open|claim|redeem|verify|re-?kyc|update|install|download|pay|approve|share|submit|call|whatsapp|telegram|reply)\b|क्लिक|भुगतान|भेजें|तुरंत|చెల్లించ|క్లిక్/i;
const SENSITIVE_PATTERN = /\b(?:otp|pin|cvv|password|card details?|bank account|aadhaar|screen share|collect request)\b|ओटीपी|पिन|आधार|పిన్|ఓటీపీ/i;

function cleanCandidate(value) {
  return String(value || '').replace(/^[([{"']+|[\])},.;!?"']+$/g, '');
}

function hasScheme(value) {
  return /^https?:\/\//i.test(value);
}

function looksLikeHost(value) {
  return /^(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{1,5})?(?:\/[^\s]*)?$/i.test(value)
    || /^(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:\/[^\s]*)?$/i.test(value);
}

export function extractUrlCandidates(text) {
  const raw = String(text || '');
  const matches = raw.match(/https?:\/\/[^\s<>'"`]+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{1,5})?(?:\/[^\s<>'"`]*)?|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:\/[^\s<>'"`]*)?/gi) || [];
  // Canonicalization accepts scheme-bearing and bare URLs alike. Using it here
  // prevents valid http(s) candidates from being rejected merely because they
  // contain a protocol prefix or URL credentials.
  return [...new Set(matches.map(cleanCandidate).filter((candidate) => canonicalizeUrl(candidate)))].slice(0, 8);
}

export function canonicalizeUrl(candidate) {
  const raw = cleanCandidate(candidate);
  if (!raw) return null;
  try {
    const input = hasScheme(raw) ? raw : `https://${raw}`;
    const url = new URL(input);
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    return {
      raw,
      href: url.href,
      protocol: url.protocol,
      hostname: url.hostname.toLowerCase().replace(/\.$/, ''),
      port: url.port,
      pathname: url.pathname,
      hasCredentials: Boolean(url.username || url.password),
      queryKeys: [...url.searchParams.keys()].slice(0, 20)
    };
  } catch {
    return null;
  }
}

function isIpv4(hostname) {
  const parts = hostname.split('.');
  return parts.length === 4 && parts.every((part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function levenshtein(a, b) {
  const source = String(a || '');
  const target = String(b || '');
  const row = Array.from({ length: target.length + 1 }, (_, index) => index);
  for (let i = 1; i <= source.length; i += 1) {
    let previous = row[0];
    row[0] = i;
    for (let j = 1; j <= target.length; j += 1) {
      const temporary = row[j];
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, previous + (source[i - 1] === target[j - 1] ? 0 : 1));
      previous = temporary;
    }
  }
  return row[target.length];
}

function hostnameTokens(hostname) {
  return hostname.split(/[.\-]/).filter(Boolean).slice(0, 12);
}

function brandSimilarity(hostname) {
  const tokens = hostnameTokens(hostname);
  const matches = [];
  for (const brand of BRAND_REGISTRY) {
    for (const token of tokens) {
      if (token === brand) continue;
      const distance = levenshtein(token, brand);
      const threshold = brand.length >= 6 ? 2 : 1;
      if (distance > 0 && distance <= threshold) matches.push({ brand, token, distance });
    }
  }
  return matches.sort((left, right) => left.distance - right.distance).slice(0, 3);
}

function claimedBrands(text) {
  const normalized = String(text || '').toLowerCase();
  return BRAND_REGISTRY.filter((brand) => new RegExp(`\\b${brand.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(normalized));
}

function looksOfficialForClaim(hostname, brand) {
  const officialFragments = {
    sbi: ['sbi.co.in', 'onlinesbi.com', 'onlinesbi.sbi'],
    hdfc: ['hdfcbank.com'],
    icici: ['icicibank.com'],
    axis: ['axisbank.com'],
    kotak: ['kotak.com'],
    paytm: ['paytm.com'],
    phonepe: ['phonepe.com'],
    npci: ['npci.org.in'],
    airtel: ['airtel.in'],
    jio: ['jio.com'],
    amazon: ['amazon.in', 'amazon.com'],
    flipkart: ['flipkart.com'],
    bluedart: ['bluedart.com'],
    indiapost: ['indiapost.gov.in'],
    fastag: ['ihmcl.co.in', 'nhai.gov.in'],
    irctc: ['irctc.co.in'],
    rbi: ['rbi.org.in'],
    uidai: ['uidai.gov.in'],
    incometax: ['incometax.gov.in'],
    verifypulse: ['verify-pulse.com', 'www.verify-pulse.com']
  };
  // First-party VerifyPulse matching is stricter than the broad public-brand
  // registry: only its two production hostnames are official. This keeps an
  // unreviewed subdomain or a deceptive suffix from inheriting trust.
  if (brand === 'verifypulse') return hostname === 'verify-pulse.com' || hostname === 'www.verify-pulse.com';
  return (officialFragments[brand] || []).some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
}

function addSignal(signals, id, weight, detail) {
  if (!signals.some((signal) => signal.id === id)) signals.push({ id, weight, detail });
}

export function analyzeMessageForensics(text) {
  const candidates = extractUrlCandidates(text);
  const claims = claimedBrands(text);
  const actionRequested = ACTION_PATTERN.test(String(text || ''));
  const sensitiveRequest = SENSITIVE_PATTERN.test(String(text || ''));
  const analyses = [];

  for (const candidate of candidates) {
    const url = canonicalizeUrl(candidate);
    if (!url) continue;
    const signals = [];
    if (isIpv4(url.hostname)) addSignal(signals, 'direct_ip_host', 35, 'The link uses a direct IP address instead of a normal domain.');
    if (SHORTENER_HOSTS.has(url.hostname)) addSignal(signals, 'shortened_link', 25, 'The link uses a URL shortener that hides the final destination.');
    if (url.hostname.startsWith('xn--') || /[^\x00-\x7F]/.test(candidate)) addSignal(signals, 'idn_or_unicode_host', 30, 'The link uses an internationalized or Unicode hostname that can imitate another brand.');
    if (url.hasCredentials) addSignal(signals, 'url_credentials', 25, 'The link embeds a username or password-like segment before the hostname.');
    if (url.port && !['80', '443'].includes(url.port)) addSignal(signals, 'non_standard_port', 10, 'The link uses a non-standard network port.');
    if (url.queryKeys.some((key) => /(?:otp|pin|password|cvv|token|session|aadhaar)/i.test(key))) addSignal(signals, 'sensitive_query_key', 20, 'The link query contains a sensitive-account keyword.');

    const similarities = brandSimilarity(url.hostname);
    for (const match of similarities) {
      addSignal(signals, `brand_typo_${match.brand}`, 28, `The hostname token '${match.token}' closely resembles the brand '${match.brand}'.`);
    }

    for (const brand of claims) {
      if (!looksOfficialForClaim(url.hostname, brand)) {
        const mismatchWeight = brand === 'verifypulse' && (actionRequested || sensitiveRequest)
          ? 55
          : actionRequested || sensitiveRequest ? 30 : 15;
        addSignal(signals, `brand_host_mismatch_${brand}`, mismatchWeight, `The message claims '${brand}' but the link hostname is not in its official-domain registry.`);
      }
    }

    const score = Math.min(100, signals.reduce((total, signal) => total + signal.weight, 0));
    analyses.push({ url, score, signals, similarBrands: similarities });
  }

  const highest = analyses.sort((left, right) => right.score - left.score)[0] || null;
  const highRisk = Boolean(highest && highest.score >= 55 && (actionRequested || sensitiveRequest || highest.signals.some((signal) => ['direct_ip_host', 'idn_or_unicode_host', 'brand_typo_sbi', 'brand_typo_hdfc', 'brand_typo_icici'].includes(signal.id))));

  return {
    version: 'vp-forensics-1',
    highRisk,
    score: highest?.score || 0,
    actionRequested,
    sensitiveRequest,
    claimedBrands: claims,
    urls: analyses.map((analysis) => ({
      hostname: analysis.url.hostname,
      score: analysis.score,
      signals: analysis.signals.map((signal) => signal.id),
      similarBrands: analysis.similarBrands.map((match) => match.brand)
    })),
    findings: highest?.signals.map((signal) => signal.detail) || []
  };
}
