// lib/intent_forensics.js
// Privacy-preserving local intent signals for Indian scam detection.
// These rules never fetch URLs or transmit text. They require multiple concrete
// signals so general safety advice and routine notifications remain non-risky.

const INVISIBLE_OR_DIRECTIONAL = /[\u00ad\u034f\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]/g;
const LATIN_LOOKALIKES = Object.freeze({
  а: 'a', А: 'A', е: 'e', Е: 'E', о: 'o', О: 'O', р: 'p', Р: 'P', с: 'c', С: 'C', х: 'x', Х: 'X',
  і: 'i', І: 'I', ј: 'j', Ј: 'J', ѕ: 's', Ѕ: 'S', у: 'y', У: 'Y',
  α: 'a', Α: 'A', β: 'b', Β: 'B', ε: 'e', Ε: 'E', ι: 'i', Ι: 'I', κ: 'k', Κ: 'K', ο: 'o', Ο: 'O',
  ρ: 'p', Ρ: 'P', τ: 't', Τ: 'T', υ: 'y', Υ: 'Y', χ: 'x', Χ: 'X'
});

const FINANCIAL_ENTITY = /\b(?:rbi|reserve bank|sbi|state bank(?: of india)?|hdfc|icici|axis|kotak|pnb|canara|bank of baroda|union bank|bank|paytm|phonepe|google ?pay|gpay|fastag|bluedart|india ?post)\b/i;
const AUTHORITY = /\b(?:rbi|reserve bank|income tax|cbi|cyber ?crime|police|trai|customs|court|government|regulation|compliance)\b|साइबर पुलिस|पुलिस|सरकार|পুলিশ|সরকার|పోలీసు|ప్రభుత్వం|காவல்|அரசு/i;
const PAYMENT = /(?:₹|\brs\.?\s*\d|\binr\s*\d|upi|collect request|verification fee|processing fee|clearance (?:charge|fee)|registration fee|activation fee|security deposit|pay now|payment|crypto|usdt|फीस|शुल्क|पैसे|भुगतान|প্রসেসিং ফি|চার্জ|ফি|পেমেন্ট|చెల్లించ|ఫీజు|డబ్బు|கட்டணம்|பணம்)/i;
const URGENCY = /\b(?:within|minutes?|hours?|immediately|urgent|today|now|expire|freeze|frozen|blocked|block|suspend|suspended|arrest|fir|penalty|last chance)\b|तुरंत|आज|अभी|बंद|गिरफ्तारी|আজ|এখনই|বাতিল|বন্ধ|వెంటనే|ఈరోజు|బ్లాక్|கடைசி வாய்ப்பு|உடனே|இன்று/i;
const RECEIVE_PROMISE = /\b(?:cash ?back|refund|reward|prize|gift|receive money|money receive|reversal)\b|कैशबैक|रिफंड|इनाम|वापस|फेरत|ক্যাশব্যাক|রিফান্ড|পুরস্কার|ফেরত|క్యాష్[\-‑]?బ్యాక్|రిఫండ్|బహుమతి|கேஷ்பேக்|பணத்தைப் பெற/i;
const QR_OR_PIN_ACTION = /\b(?:qr(?:\s*code)?|scan(?:\s+the)?\s+qr|upi\s*pin|enter\s+(?:your\s+)?pin|collect request|approve(?:\s+the)?\s+request)\b|qr\s*स्कैन|पिन\s*(?:डाल|भर)|কিউআর|স্ক্যান|upi\s*pin|పిన్\s*(?:నమోదు|ఎంటర్)|qr\s*ஸ்கேன்|upi\s*pin/i;
const REMOTE_ACCESS = /\b(?:screen share|screen-sharing|remote access|anydesk|teamviewer|quick support|support call|video call)\b|स्क्रीन\s*शेयर|रिमोट\s*एक्सेस|স্ক্রিন\s*শেয়ার|রিমোট\s*অ্যাক্সেস|స్క్రీన్\s*షేర్|రిమోట్\s*యాక్సెస్|ஸ்கிரீன்\s*ஷேர்|ரிமோட்\s*அக்சஸ்/i;
const ADVANCE_FEE_CONTEXT = /\b(?:job|work from home|salary|loan|investment|trading|profit|recruiter|telegram|whatsapp)\b|नौकरी|कर्ज|लोन|निवेश|टेलीग्राम|व्हाट्सऐप|চাকরি|ঋণ|বিনিয়োগ|টেলিগ্রাম|ఉద్యోగం|రుణం|పెట్టుబడి|టెలిగ్రామ్|வேலை|கடன்|முதலீடு/i;
const CAPTCHA_JOB = /\b(?:captcha(?:\s*[- ]?filling)?|captcha work|solve\s+(?:\d+[\s,-]*)?captchas?)\b/i;
const CAPTCHA_UPFRONT_FEE = /\b(?:registration fee|training fee|software(?:\s*\/\s*application)? charges?|application fee|joining fee|processing fee|security deposit)\b/i;
const CAPTCHA_HIGH_EARNING_LURE = /\b(?:high[- ]?paying|earn(?:ings?)?|daily income|minimal effort|easy money|work\s+(?:only\s+)?\d+\s+minutes?)\b/i;
const ACCOUNT_OR_CARD_BLOCK = /\b(?:account|a\/?c|card)\b[\s\S]{0,70}\b(?:freeze|frozen|blocked|block|suspend|suspended)\b|\b(?:freeze|frozen|blocked|block|suspend|suspended)\b[\s\S]{0,70}\b(?:account|a\/?c|card)\b|खाता[\s\S]{0,40}(?:बंद|ब्लॉक)|অ্যাকাউন্ট[\s\S]{0,40}(?:বন্ধ|ব্লক)|ఖాతా[\s\S]{0,40}బ్లాక్/i;
const UNTRUSTED_CONTACT = /\b(?:whatsapp|telegram|reply\s+(?:yes|ok)|call now|support call|video call)\b|व्हाट्सऐप|टेलीग्राम|হোয়াটসঅ্যাপ|টেলিগ্রাম|వాట్సాప్|టెలిగ్రామ్/i;
const PREVENTIVE_PAYMENT_GUIDANCE = /\b(?:never|do not|don't|avoid)\s+(?:scan|share|enter|approve|install|pay)\b|\bupi\s*pin\b[\s\S]{0,70}\b(?:only|not\s+to\s+receive)\b|\b(?:safety reminder|cyber hygiene|fraud awareness)\b|कभी\s+(?:भी\s+)?(?:स्कैन|शेयर|दर्ज|भुगतान)\s+(?:न\s+करें|मत\s+करें)|স্ক্যান করবেন না|শেয়ার করবেন না|పంచుకోవద్దు|ஸ்கேன் செய்யாதீர்கள்/i;

export function normalizeSecurityText(input) {
  const value = String(input || '').normalize('NFKC').replace(INVISIBLE_OR_DIRECTIONAL, '');
  return [...value].map((character) => LATIN_LOOKALIKES[character] || character).join('');
}

function addSignal(signals, id, weight, detail) {
  if (!signals.some((signal) => signal.id === id)) signals.push({ id, weight, detail });
}

export function analyzeIntentForensics(input) {
  const value = normalizeSecurityText(input);
  const financialEntity = FINANCIAL_ENTITY.test(value);
  const authority = AUTHORITY.test(value);
  const payment = PAYMENT.test(value);
  const urgency = URGENCY.test(value);
  const receivePromise = RECEIVE_PROMISE.test(value);
  const qrOrPinAction = QR_OR_PIN_ACTION.test(value);
  const remoteAccess = REMOTE_ACCESS.test(value);
  const advanceFeeContext = ADVANCE_FEE_CONTEXT.test(value);
  const captchaJob = CAPTCHA_JOB.test(value);
  const captchaUpfrontFee = CAPTCHA_UPFRONT_FEE.test(value);
  const captchaHighEarningLure = CAPTCHA_HIGH_EARNING_LURE.test(value);
  const accountOrCardBlock = ACCOUNT_OR_CARD_BLOCK.test(value);
  const untrustedContact = UNTRUSTED_CONTACT.test(value);
  const preventivePaymentGuidance = PREVENTIVE_PAYMENT_GUIDANCE.test(value);
  const signals = [];

  if (!preventivePaymentGuidance && receivePromise && qrOrPinAction && (urgency || payment)) {
    addSignal(signals, 'upi_receipt_payment_deception', 45, 'The message promises a reward or refund but instructs a QR/UPI PIN/collect-request action that can initiate a payment.');
  }
  if (!preventivePaymentGuidance && financialEntity && remoteAccess && (urgency || payment || accountOrCardBlock)) {
    addSignal(signals, 'financial_remote_access_trap', 42, 'A financial brand is paired with screen-sharing or remote-access instructions and a risk or payment trigger.');
  }
  if (advanceFeeContext && payment && untrustedContact) {
    addSignal(signals, 'advance_fee_contact_trap', 40, 'A job, loan, investment, or support claim requests money and moves the user to an untrusted contact channel.');
  }
  if (!preventivePaymentGuidance && captchaJob && captchaUpfrontFee && captchaHighEarningLure) {
    addSignal(signals, 'captcha_job_upfront_fee_trap', 43, 'A CAPTCHA-filling job promises easy or high earnings while demanding an explicit upfront fee, a combination associated with fake CAPTCHA job fraud.');
  }
  if (financialEntity && accountOrCardBlock && payment) {
    addSignal(signals, 'named_financial_block_fee_trap', 40, 'A named financial entity is combined with an account/card-blocking threat and a payment demand.');
  }
  if (authority && payment && (urgency || untrustedContact)) {
    addSignal(signals, 'authority_payment_extortion', 42, 'An authority claim is paired with a payment demand and urgency or an untrusted contact instruction.');
  }

  const score = Math.min(100, signals.reduce((total, signal) => total + signal.weight, 0));
  return {
    version: 'vp-intent-forensics-1',
    highRisk: score >= 40,
    score,
    findings: signals.map((signal) => signal.detail),
    signals: signals.map((signal) => signal.id),
    normalized: value !== String(input || ''),
    indicators: {
      financialEntity,
      authority,
      payment,
      urgency,
      receivePromise,
      qrOrPinAction,
      remoteAccess,
      advanceFeeContext,
      captchaJob,
      captchaUpfrontFee,
      captchaHighEarningLure,
      accountOrCardBlock,
      untrustedContact,
      preventivePaymentGuidance
    }
  };
}
