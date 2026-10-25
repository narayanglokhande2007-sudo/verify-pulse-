// lib/url_forensics.js
// Deterministic, dependency-free URL and brand forensics for VerifyPulse.
// It does not fetch URLs, expand shorteners, or contact third parties.

const BRAND_REGISTRY = [
  'sbi', 'onlinesbi', 'hdfc', 'hdfcbank', 'icici', 'icicibank', 'axis', 'axisbank',
  'kotak', 'kotakbank', 'kotak811', 'paytm', 'phonepe', 'gpay', 'googlepay', 'npci', 'airtel',
  'jio', 'amazon', 'flipkart', 'bluedart', 'indiapost', 'fastag', 'irctc', 'rbi',
  'uidai', 'incometax', 'verifypulse', 'kreditbee', 'navi', 'cashe', 'fibe', 'bajaj',
  'bajajfinserv', 'tata', 'tatacapital', 'poonawalla', 'muthoot', 'manappuram',
  'dmi', 'chola', 'piramal', 'lendingkart'
];

const OFFICIAL_FRAGMENTS = {
  sbi: ['sbi.co.in', 'onlinesbi.com', 'onlinesbi.sbi'],
  onlinesbi: ['onlinesbi.sbi', 'onlinesbi.com', 'sbi.co.in'],
  hdfc: ['hdfcbank.com', 'hdfc.com'],
  hdfcbank: ['hdfcbank.com'],
  icici: ['icicibank.com'],
  icicibank: ['icicibank.com'],
  axis: ['axisbank.com'],
  axisbank: ['axisbank.com'],
  kotak: ['kotak.com'],
  kotakbank: ['kotak.com'],
  kotak811: ['kotak.com'],
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
  verifypulse: ['verify-pulse.com', 'www.verify-pulse.com'],
  kreditbee: ['kreditbee.in'],
  navi: ['navi.com'],
  cashe: ['cashe.co.in'],
  fibe: ['fibe.in'],
  bajajfinserv: ['bajajfinserv.in'],
  bajaj: ['bajajfinserv.in', 'bajajauto.com'],
  tatacapital: ['tatacapital.com'],
  tata: ['tatacapital.com', 'tata.com'],
  poonawalla: ['poonawallafincorp.com'],
  muthoot: ['muthootfinance.com'],
  manappuram: ['manappuram.com'],
  dmi: ['dmifinance.in'],
  chola: ['cholamandalam.com'],
  piramal: ['piramalfinance.com'],
  lendingkart: ['lendingkart.com']
};

const GENERIC_SUBDOMAIN_WORDS = new Set(['pay', 'app', 'api', 'web', 'net', 'dev', 'portal', 'auth', 'loan', 'loans', 'mail', 'online', 'www', 'm', 'secure', 'my']);

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
    // Fallback parser for malformed or special Punycode / IDN domains that fail standard WHATWG URL constructor
    const match = String(raw).match(/^(?:https?:\/\/)?([^\/\s?#]+)(.*)$/i);
    if (!match) return null;
    const hostPart = match[1].toLowerCase();
    const [hostname, port] = hostPart.split(':');
    if (!hostname || !looksLikeHost(hostname)) return null;
    return {
      raw,
      href: hasScheme(raw) ? raw : `https://${raw}`,
      protocol: hasScheme(raw) ? (raw.startsWith('http:') ? 'http:' : 'https:') : 'https:',
      hostname,
      port: port || '',
      pathname: match[2] || '/',
      hasCredentials: false,
      queryKeys: []
    };
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
  const parts = hostname.split(/[.\-]/).filter(Boolean);
  const hostNoTld = hostname.split('.').slice(0, -1).join('.');
  const unhyphenated = hostNoTld.replace(/[\.\-]/g, '');
  const combined = new Set([...parts, unhyphenated]);
  return [...combined].slice(0, 15);
}

function normalizeTokenHomoglyphs(token) {
  return String(token || '')
    .replace(/0/g, 'o')
    .replace(/1/g, 'i')
    .replace(/3/g, 'e')
    .replace(/5/g, 's')
    .replace(/4/g, 'a')
    .replace(/@/g, 'a');
}

export function looksOfficialForClaim(hostname, brand) {
  if (brand === 'verifypulse') {
    return hostname === 'verify-pulse.com' || hostname.endsWith('.verify-pulse.com');
  }
  const fragments = OFFICIAL_FRAGMENTS[brand] || [];
  return fragments.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
}

function isOfficialDomain(hostname) {
  for (const brand of Object.keys(OFFICIAL_FRAGMENTS)) {
    if (looksOfficialForClaim(hostname, brand)) return true;
  }
  return false;
}

function brandSimilarity(hostname) {
  // Never flag a verified official domain as a typosquat
  if (isOfficialDomain(hostname)) return [];

  const tokens = hostnameTokens(hostname);
  const matches = [];
  for (const brand of BRAND_REGISTRY) {
    for (const token of tokens) {
      if (token === brand) continue;
      if (GENERIC_SUBDOMAIN_WORDS.has(token) && brand.length <= 4) continue;

      const normalizedToken = normalizeTokenHomoglyphs(token);
      const rawDistance = levenshtein(token, brand);
      const normalizedDistance = levenshtein(normalizedToken, brand);
      const isHomoglyphMatch = token !== brand && normalizedToken === brand;
      const effectiveDistance = isHomoglyphMatch ? 1 : Math.min(rawDistance, normalizedDistance);
      const threshold = brand.length >= 6 ? 2 : 1;
      if (effectiveDistance > 0 && effectiveDistance <= threshold) {
        matches.push({ brand, token, distance: effectiveDistance });
      }
    }
  }
  return matches.sort((left, right) => left.distance - right.distance).slice(0, 3);
}

function claimedBrands(text) {
  const normalized = String(text || '').toLowerCase();
  const candidates = extractUrlCandidates(text);
  const hostBrands = [];
  for (const c of candidates) {
    const u = canonicalizeUrl(c);
    if (u) {
      const tokens = hostnameTokens(u.hostname);
      for (const b of BRAND_REGISTRY) {
        if (tokens.includes(b)) hostBrands.push(b);
      }
    }
  }
  const textBrands = BRAND_REGISTRY.filter((brand) => new RegExp(`\\b${brand.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i').test(normalized));
  return [...new Set([...textBrands, ...hostBrands])];
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
    if (isIpv4(url.hostname)) addSignal(signals, 'direct_ip_host', 55, 'The link uses a direct IP address instead of a normal domain.');
    if (SHORTENER_HOSTS.has(url.hostname)) addSignal(signals, 'shortened_link', 30, 'The link uses a URL shortener that hides the final destination.');
    if (url.hostname.startsWith('xn--') || /[^\x00-\x7F]/.test(candidate)) addSignal(signals, 'idn_or_unicode_host', 55, 'The link uses an internationalized or Unicode hostname that can imitate another brand.');
    if (url.hasCredentials) addSignal(signals, 'url_credentials', 40, 'The link embeds a username or password-like segment before the hostname.');
    if (url.port && !['80', '443'].includes(url.port)) addSignal(signals, 'non_standard_port', 20, 'The link uses a non-standard network port.');
    if (url.queryKeys.some((key) => /(?:otp|pin|password|cvv|token|session|aadhaar)/i.test(key))) addSignal(signals, 'sensitive_query_key', 35, 'The link query contains a sensitive-account keyword.');

    const similarities = brandSimilarity(url.hostname);
    for (const match of similarities) {
      const typoWeight = (actionRequested || sensitiveRequest) ? 55 : 35;
      addSignal(signals, `brand_typo_${match.brand}`, typoWeight, `The hostname token '${match.token}' closely resembles the brand '${match.brand}'.`);
    }

    for (const brand of claims) {
      if (!looksOfficialForClaim(url.hostname, brand)) {
        const mismatchWeight = brand === 'verifypulse' && (actionRequested || sensitiveRequest)
          ? 55
          : actionRequested || sensitiveRequest ? 30 : 15;
        addSignal(signals, `brand_host_mismatch_${brand}`, mismatchWeight, `The message claims '${brand}' but the link hostname is not in its official-domain registry.`);
      }
    }

    // Subdomain deception detection (e.g. 'verify-pulse.com.security-check.example')
    for (const brand of BRAND_REGISTRY) {
      const officialList = OFFICIAL_FRAGMENTS[brand] || [];
      for (const offDomain of officialList) {
        if (url.hostname.includes(offDomain) && !looksOfficialForClaim(url.hostname, brand)) {
          addSignal(signals, `subdomain_spoof_${brand}`, 55, `The link attempts subdomain deception using '${offDomain}' inside an unauthorized root domain.`);
        }
      }
    }

    const score = Math.min(100, signals.reduce((total, signal) => total + signal.weight, 0));
    analyses.push({ url, score, signals, similarBrands: similarities });
  }

  const highest = analyses.sort((left, right) => right.score - left.score)[0] || null;
  const hasBrandTypo = Boolean(highest?.signals.some((signal) => signal.id.startsWith('brand_typo_')));
  const hasSubdomainSpoof = Boolean(highest?.signals.some((signal) => signal.id.startsWith('subdomain_spoof_')));
  const hasCriticalSignal = Boolean(highest?.signals.some((signal) => ['direct_ip_host', 'idn_or_unicode_host'].includes(signal.id) || signal.id.startsWith('brand_typo_')));
  const highRisk = Boolean(
    highest && (
      (highest.score >= 50 && (actionRequested || sensitiveRequest || hasCriticalSignal)) ||
      (hasBrandTypo && (actionRequested || sensitiveRequest)) ||
      (hasSubdomainSpoof) ||
      (highest.signals.some((s) => s.id === 'idn_or_unicode_host')) ||
      (highest.signals.some((s) => s.id === 'direct_ip_host'))
    )
  );

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
