// lib/intent_forensics.js
// VerifyPulse Cognitive Social Engineering & Semantic Intent Forensics Engine
// Analyzes psychological deception archetypes in Indian cybercrime:
// 1. Advance-Fee Loan Pre-Disbursal Extortion
// 2. Coercive Authority & Digital Arrest Isolation
// 3. Essential Civic Utility / Electricity Severance Panic
// 4. Reverse UPI PIN / QR Cashback Deception
// 5. Remote Screen Surveillance / AnyDesk Exploitation
// 6. Multi-Lingual Regional Intent Normalization (Hindi, Bengali, Telugu, Tamil, Marathi)

const INVISIBLE_OR_DIRECTIONAL = /[\u00ad\u034f\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]/g;
const LATIN_LOOKALIKES = Object.freeze({
  а: 'a', А: 'A', е: 'e', Е: 'E', о: 'o', О: 'O', р: 'p', Р: 'P', с: 'c', С: 'C', х: 'x', Х: 'X',
  і: 'i', І: 'I', ј: 'j', Ј: 'J', ѕ: 's', Ѕ: 'S', у: 'y', У: 'Y',
  α: 'a', Α: 'A', β: 'b', Β: 'B', ε: 'e', Ε: 'E', ι: 'i', Ι: 'I', κ: 'k', Κ: 'K', ο: 'o', Ο: 'O',
  ρ: 'p', Ρ: 'P', τ: 't', Τ: 'T', υ: 'y', Υ: 'Y', χ: 'x', Χ: 'X',
  '0': 'o', '1': 'i', '3': 'e', '@': 'a', '$': 's'
});

// 1. Financial & Lending Entities (Banks + Top Indian NBFCs)
const FINANCIAL_ENTITY = /\b(?:rbi|reserve bank|sbi|state bank(?: of india)?|hdfc|icici|axis|kotak|pnb|canara|bank of baroda|union bank|bank|paytm|phonepe|google ?pay|gpay|fastag|bluedart|india ?post|kreditbee|cashe|navi|kissht|paysense|bajaj(?: finance| finserv)?|tata capital|piramal|muthoot|shriram|iifl|m-?pokket|fibe|earlysalary|moneytap|freo|rupeek|zestmoney|smartcoin|ring)\b/i;

// 2. State, Legal & Regulatory Authority
const AUTHORITY = /\b(?:rbi|reserve bank|income tax|cbi|cyber ?crime|cyber ?police|police|crime branch|trai|customs|court|supreme court|high court|enforcement directorate|ed\b|narcotics(?: control bureau)?|ncb\b|government|regulation|compliance|nia\b|interpol|digital arrest)\b|साइबर पुलिस|पुलिस|सरकार|नारकोटिक्स|নার্কোটিক্স|পুলিশ|সরকার|పోలీసు|ప్రభుత్వం|కస్టమ్స్|காவல்|அரசு/i;

// 3. Payment Demands & Monetary Transfers
const PAYMENT = /(?:₹|\brs\.?\s*\d|\binr\s*\d|upi|collect request|verification fee|processing fee|clearance (?:charge|fee)|registration fee|activation fee|security deposit|stamp duty|documentation fee|insurance fee|disbursal fee|file charge|pay now|payment|crypto|usdt|फीस|शुल्क|पैसे|भुगतान|প্রসেসিং ফি|চার্জ|ফি|পেমেন্ট|చెల్లించ|ఫీజు|డబ్బు|கட்டணம்|பணம்)/i;

// 4. Urgency & Deadlines
const URGENCY = /\b(?:within|minutes?|hours?|immediately|urgent|today|tonight|now|expire|freeze|frozen|blocked|block|suspend|suspended|arrest|fir|penalty|last chance|blackout|power cut|disconnected)\b|तुरंत|आज|अभी|आज रात|बंद|गिरफ्तारी|আজ|এখনই|বাতিল|বন্ধ|వెంటనే|ఈరోజు|ఈ రాత్రి|బ్లాక్|கடைசி வாய்ப்பு|உடனே|இன்று/i;

// 5. Coercive Pressure & Criminal Allegations (Digital Arrest Archetype)
const COERCIVE_CRIMINAL_PRESSURE = /\b(?:arrest warrant|warrant|non-bailable|nbw|digital arrest|money laundering|pmla|drugs?|narcotics|contraband|illegal (?:parcel|consignment|transactions?)|seized|seizure|asset freezing|police custody|custody|fir\b|penal code|summons?|penalty notice|extortion complaint)\b|गिरफ्तारी|वारंट|मनी लॉन्ड्रिंग|গ্রেপ্তার|ওয়ারেন্ট|అరెస్ట్|వారెంట్|கைது/i;

// 6. Coercive Isolation / Video Surveillance
const COERCIVE_ISOLATION_OR_VIDEO = /\b(?:video call|skype|skype call|stay on (?:camera|call)|do not disconnect|private room|camera on|whatsapp video)\b|वीडियो कॉल|ভিডিও কল|వీడియో కాల్/i;

// 7. Advance-Fee Loan Disbursal Archetype
const LOAN_APPROVAL_PROMISE = /\b(?:loan (?:approved|sanctioned|ready|offer|disbursed|disbursement)|pre-?approved loan|sanctioned|funds ready|credit limit|disbursement pending|release funds|instant (?:credit|loan approved))\b|कर्ज मंजूर|लोन अप्रूव्ड|రుణం మంజూరు/i;
const UPFRONT_LOAN_PAYWALL = /\b(?:processing (?:fee|charge|deposit)|verification (?:fee|charge|deposit)|file (?:charge|fee|verification)|insurance (?:fee|deposit|charge)|stamp duty|documentation fee|activation fee|clearance charge|security deposit)\b|प्रोसेसिंग फीस|शुल्क/i;
const EMI_REPAYMENT_ALERT = /\b(?:emi payment|emi alert|emi of|monthly emi|loan emi|installment is due|payment of rs \d+ is due|towards emi)\b/i;

// 8. Essential Civic Utility / Electricity Disconnection Archetype
const UTILITY_SERVICE = /\b(?:electricity|power supply|power connection|power|bijli|electric meter|meter reading|discom|electricity office|sub-?station|msedcl|bescom|uppcl|tpddl|bses|pspcl|wbsedcl|adani electricity|tata power|bijli vibhag)\b|बिजली|बिजली विभाग|বিদ্যুৎ|বিদ্যুৎ বিল|విద్యుత్|విద్యుత్ సరఫరా|மின்சாரம்/i;
const SERVICE_SEVERANCE = /\b(?:disconnected|disconnect|cut|power cut|suspended|blocked|blackout|tonight at \d|within \d hours?)\b|काट दिया जाएगा|काट दी जाएगी|बंद|বিচ্ছিন্ন|నిలిపివేయబడుతుంది|துண்டிக்கப்படும்/i;

// 9. Reverse UPI PIN / Reward Deception
const RECEIVE_PROMISE = /\b(?:cash ?back|refund|reward|prize|gift|receive money|money receive|reversal|won|scratch card)\b|कैशबैक|रिफंड|इनाम|वापस|ক্যাশব্যাক|রিফান্ড|পুরস্কার|ফেরত|টাকা পেতে|క్యాష్[\-‑]?బ్యాక్|రిఫండ్|பணத்தைப் பெற/i;
const QR_OR_PIN_ACTION = /\b(?:qr(?:\s*code)?|scan(?:\s+the)?\s+qr|upi\s*pin|enter\s+(?:your\s+)?pin|collect request|approve(?:\s+the)?\s+request)\b|qr\s*स्कैन|पिन\s*(?:डाल|भर)|কিউআর|স্ক্যান|upi\s*pin|పిన్\s*(?:నమోదు|ఎంటర్)|qr\s*ஸ்கேன்|upi\s*pin/i;

// 10. Remote Screen Surveillance
const REMOTE_ACCESS = /\b(?:screen share|screen-sharing|remote access|anydesk|teamviewer|quicksupport|quick support|rustdesk|airdroid|share your screen)\b|स्क्रीन\s*शेयर|रिमोट\s*एक्सेस|স্ক্রিন\s*শেয়ার|స్క్రీన్\s*షేర్|ஸ்கிரீன்\s*ஷேர்/i;

// 11. General Traps & Untrusted Contacts
const ADVANCE_FEE_CONTEXT = /\b(?:job|work from home|salary|loan|investment|trading|profit|recruiter|telegram|whatsapp)\b|नौकरी|कर्ज|लोन|निवेश|टेलीग्राम|व्हाट्सऐप|চাকরি|ঋণ|ఉద్యోగం|வேலை/i;
const CAPTCHA_JOB = /\b(?:captcha(?:\s*[- ]?filling)?|captcha work|solve\s+(?:\d+[\s,-]*)?captchas?)\b/i;
const CAPTCHA_UPFRONT_FEE = /\b(?:registration fee|training fee|software(?:\s*\/\s*application)? charges?|application fee|joining fee|processing fee|security deposit)\b/i;
const CAPTCHA_HIGH_EARNING_LURE = /\b(?:high[- ]?paying|earn(?:ings?)?|daily income|minimal effort|easy money|work\s+(?:only\s+)?\d+\s+minutes?)\b/i;
const ACCOUNT_OR_CARD_BLOCK = /\b(?:account|a\/?c|card)\b[\s\S]{0,70}\b(?:freeze|frozen|blocked|block|suspend|suspended)\b|\b(?:freeze|frozen|blocked|block|suspend|suspended)\b[\s\S]{0,70}\b(?:account|a\/?c|card)\b|खाता[\s\S]{0,40}(?:बंद|ब्लॉक)|অ্যাকাউন্ট[\s\S]{0,40}(?:বন্ধ|ব্লক)|ఖాతా[\s\S]{0,40}బ్లాక్/i;
const UNTRUSTED_CONTACT = /\b(?:whatsapp|telegram|reply\s+(?:yes|ok)|call now|support call|video call|helpline)\b|व्हाट्सऐप|टेलीग्राम|হোয়াটসঅ্যাপ|వాట్సాప్/i;

// 12. Preventive / Awareness Whitelist (Shield Against False Alarms)
const PREVENTIVE_PAYMENT_GUIDANCE = /\b(?:never|do not|don't|avoid)\s+(?:scan|share|enter|approve|install|pay)\b|\bupi\s*pin\b[\s\S]{0,70}\b(?:only|not\s+to\s+receive)\b|\b(?:safety reminder|cyber hygiene|fraud awareness|advisory from|rbi kehta hai|delhi police)\b|कभी\s+(?:भी\s+)?(?:स्कैन|शेयर|दर्ज|भुगतान)\s+(?:न\s+करें|मत\s+करें)|স্ক্যান করবেন না|শেয়ার করবেন না|పంచుకోవద్దు|ஸ்கேன் செய்யாதீர்கள்/i;

export function normalizeSecurityText(input) {
  const value = String(input || '').normalize('NFKC').replace(INVISIBLE_OR_DIRECTIONAL, '');
  return [...value].map((character) => LATIN_LOOKALIKES[character] || character).join('');
}

function addSignal(signals, id, weight, detail) {
  if (!signals.some((signal) => signal.id === id)) signals.push({ id, weight, detail });
}

export function analyzeIntentForensics(input) {
  const value = normalizeSecurityText(input);

  // Indicators
  const financialEntity = FINANCIAL_ENTITY.test(value);
  const authority = AUTHORITY.test(value);
  const payment = PAYMENT.test(value);
  const urgency = URGENCY.test(value);
  const receivePromise = RECEIVE_PROMISE.test(value);
  const qrOrPinAction = QR_OR_PIN_ACTION.test(value);
  const remoteAccess = REMOTE_ACCESS.test(value);
  const advanceFeeContext = ADVANCE_FEE_CONTEXT.test(value);
  const loanApproval = LOAN_APPROVAL_PROMISE.test(value);
  const upfrontLoanPaywall = UPFRONT_LOAN_PAYWALL.test(value);
  const utilityService = UTILITY_SERVICE.test(value);
  const serviceSeverance = SERVICE_SEVERANCE.test(value);
  const coerciveCriminal = COERCIVE_CRIMINAL_PRESSURE.test(value);
  const coerciveIsolation = COERCIVE_ISOLATION_OR_VIDEO.test(value);
  const captchaJob = CAPTCHA_JOB.test(value);
  const captchaUpfrontFee = CAPTCHA_UPFRONT_FEE.test(value);
  const captchaHighEarningLure = CAPTCHA_HIGH_EARNING_LURE.test(value);
  const accountOrCardBlock = ACCOUNT_OR_CARD_BLOCK.test(value);
  const untrustedContact = UNTRUSTED_CONTACT.test(value);
  const preventivePaymentGuidance = PREVENTIVE_PAYMENT_GUIDANCE.test(value);
  const emiRepaymentAlert = EMI_REPAYMENT_ALERT.test(value);

  const signals = [];

  if (!preventivePaymentGuidance) {
    // 1. Digital Arrest & Coercive Authority Extortion Archetype
    if (authority && (coerciveCriminal || coerciveIsolation || (urgency && (payment || untrustedContact)))) {
      addSignal(
        signals,
        'authority_digital_arrest_extortion',
        50,
        'A legal, police, or regulatory authority claim is combined with coercive criminal allegations, digital arrest threats, or urgent contact demands.'
      );
    } else if (coerciveCriminal && (coerciveIsolation || payment || urgency)) {
      addSignal(
        signals,
        'coercive_arrest_warrant_trap',
        45,
        'An arrest warrant, asset seizure, or criminal investigation claim is weaponized to pressure the user.'
      );
    }

    // 2. Pre-Disbursal Loan Advance-Fee Exploitation Archetype
    if (!emiRepaymentAlert && loanApproval && (upfrontLoanPaywall || (payment && (urgency || untrustedContact || financialEntity)))) {
      addSignal(
        signals,
        'advance_fee_loan_trap',
        45,
        'A sanctioned loan or credit approval promises funds but demands an upfront processing, verification, or stamp duty fee.'
      );
    }

    // 3. Essential Civic Utility / Electricity Disconnection Panic Archetype
    if (utilityService && serviceSeverance) {
      addSignal(
        signals,
        'utility_power_disconnection_trap',
        45,
        'An essential utility (electricity/power supply) is threatened with imminent disconnection to induce panic and force unofficial payment or contact.'
      );
    }

    // 4. Reverse UPI PIN / QR Cashback Deception Archetype
    if (receivePromise && qrOrPinAction) {
      addSignal(
        signals,
        'upi_receipt_payment_deception',
        50,
        'The message promises a reward, cashback, or refund but deceptively instructs entering a UPI PIN or scanning a QR code.'
      );
    }

    // 5. Remote Surveillance / AnyDesk Screen Share Archetype
    if (remoteAccess && (financialEntity || accountOrCardBlock || urgency || payment)) {
      addSignal(
        signals,
        'financial_remote_access_trap',
        45,
        'A financial brand, account block alert, or urgent support request instructs installing remote screen-sharing software.'
      );
    }

    // 6. Generic Advance-Fee & Job / Investment Traps
    if (advanceFeeContext && payment && untrustedContact) {
      addSignal(
        signals,
        'advance_fee_contact_trap',
        40,
        'A job, investment, trading, or recruiter claim demands money and diverts the user to an untrusted contact channel.'
      );
    }
    if (captchaJob && captchaUpfrontFee && captchaHighEarningLure) {
      addSignal(
        signals,
        'captcha_job_upfront_fee_trap',
        43,
        'A CAPTCHA-filling job promises easy high earnings while demanding an upfront registration fee.'
      );
    }
    if (financialEntity && accountOrCardBlock && payment) {
      addSignal(
        signals,
        'named_financial_block_fee_trap',
        40,
        'A named financial entity is combined with an account-blocking threat and a payment demand.'
      );
    }
  }

  const score = Math.min(100, signals.reduce((total, signal) => total + signal.weight, 0));

  return {
    version: 'vp-cognitive-intent-forensics-2',
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
      loanApproval,
      utilityService,
      serviceSeverance,
      coerciveCriminal,
      accountOrCardBlock,
      untrustedContact,
      preventivePaymentGuidance
    }
  };
}
