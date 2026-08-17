// lib/pulsecore_local_guidance.js
// Narrow local guidance for common safety questions during external AI outages.
// It intentionally does not analyse accounts, transactions, identities, or unknown open-ended topics.

function usesHindiScript(text) {
  return /[\u0900-\u097f]/.test(String(text || ''));
}

function isHinglish(text) {
  return /\b(kaise|bache|bachne|batao|kya|mera|mujhe|fraud|scam|bank|upi|otp|pin)\b/i.test(String(text || ''));
}

function language(text) {
  if (usesHindiScript(text)) return 'hi';
  if (isHinglish(text)) return 'hinglish';
  return 'en';
}

function responseFor(locale, variants) {
  return variants[locale] || variants.en;
}

const disclaimer = {
  en: '\n\n**Important:** This is general safety guidance, not proof about a specific payment, account, or sender. Use your bank’s official app or website for verification.',
  hinglish: '\n\n**Important:** Yeh general safety guidance hai; kisi specific payment, account ya sender ka proof nahi hai. Verify karne ke liye sirf bank ki official app ya website use karo.',
  hi: '\n\n**महत्वपूर्ण:** यह सामान्य सुरक्षा जानकारी है, किसी खास भुगतान, खाते या भेजने वाले का प्रमाण नहीं। सत्यापन के लिए केवल बैंक का आधिकारिक ऐप या वेबसाइट इस्तेमाल करें।'
};

export function getPulseCoreLocalGuidance(input) {
  const text = String(input || '').trim();
  if (!text || text.length > 2000) return null;
  const value = text.toLowerCase();
  const locale = language(text);
  const withDisclaimer = (message) => `${message}${disclaimer[locale]}`;

  if (/\b(upi|qr\s*code|gpay|google\s*pay|phonepe|paytm)\b/i.test(value)) {
    return withDisclaimer(responseFor(locale, {
      en: '**Three simple ways to avoid UPI fraud:**\n\n1. Never share your UPI PIN or OTP. You do **not** need to enter a PIN to receive money.\n2. Do not scan an unknown QR code or approve an unexpected collect request.\n3. Before paying, check the recipient name and amount inside the official payment app.\n\nIf money has already left your account, contact your bank through its official app or helpline and report suspected cyber fraud promptly through 1930.',
      hinglish: '**UPI fraud se bachne ke 3 simple tips:**\n\n1. UPI PIN ya OTP kabhi share mat karo. Paise receive karne ke liye PIN enter nahi karna hota.\n2. Unknown QR code scan mat karo aur unexpected collect request approve mat karo.\n3. Payment se pehle official app mein recipient ka naam aur amount check karo.\n\nAgar paise kat gaye hain, bank ki official app/helpline se contact karo aur suspected cyber fraud ko jaldi 1930 par report karo.',
      hi: '**UPI धोखाधड़ी से बचने के 3 आसान तरीके:**\n\n1. UPI PIN या OTP कभी साझा न करें। पैसे प्राप्त करने के लिए PIN डालना नहीं पड़ता।\n2. अनजान QR code स्कैन न करें और अनपेक्षित collect request स्वीकार न करें।\n3. भुगतान से पहले आधिकारिक ऐप में प्राप्तकर्ता का नाम और राशि जाँचें।\n\nयदि पैसे कट गए हैं, तो बैंक के आधिकारिक ऐप/हेल्पलाइन से संपर्क करें और संदिग्ध साइबर धोखाधड़ी की सूचना जल्दी 1930 पर दें।'
    }));
  }

  if (/\b(otp|pin|password|passcode|cvv|card\s*detail)\b/i.test(value)) {
    return withDisclaimer(responseFor(locale, {
      en: '**Protect your banking credentials:**\n\n1. Never share an OTP, PIN, password, CVV, or card number through chat, call, SMS, or a link.\n2. A bank employee should not need your PIN or OTP to help you.\n3. If you shared a secret, change the affected password/PIN through the official app and contact the bank immediately.',
      hinglish: '**Banking credentials ko safe rakho:**\n\n1. OTP, PIN, password, CVV ya card number chat, call, SMS ya link par kabhi share mat karo.\n2. Bank employee ko help ke liye tumhara PIN ya OTP nahi chahiye hota.\n3. Agar secret share ho gaya, official app se password/PIN change karo aur bank ko turant contact karo.',
      hi: '**बैंकिंग विवरण सुरक्षित रखें:**\n\n1. OTP, PIN, password, CVV या card number chat, call, SMS या link पर कभी साझा न करें।\n2. बैंक कर्मचारी को मदद के लिए आपका PIN या OTP नहीं चाहिए होता।\n3. यदि कोई गुप्त जानकारी साझा हो गई है, तो आधिकारिक ऐप से password/PIN बदलें और तुरंत बैंक से संपर्क करें।'
    }));
  }

  if (/\b(phishing|fake\s*link|suspicious\s*link|kyc|account\s*(block|freeze|closed)|parcel|delivery)\b/i.test(value)) {
    return withDisclaimer(responseFor(locale, {
      en: '**How to handle a suspected phishing message:**\n\n1. Do not open the link, download a file, or reply with personal details.\n2. Open the official bank, delivery, or service app yourself instead of using the message link.\n3. Check the sender and the full web address carefully; urgency and threats are common scam signals.\n\nYou can paste the message or URL into VerifyPulse for a risk assessment, but do not treat an unlisted link as automatically safe.',
      hinglish: '**Suspected phishing message ko kaise handle karein:**\n\n1. Link open mat karo, file download mat karo, aur personal details reply mein mat bhejo.\n2. Message ke link ke bajay khud official bank, delivery ya service app kholo.\n3. Sender aur full web address dhyan se dekho; urgency aur threats common scam signals hote hain.\n\nMessage ya URL VerifyPulse mein paste kar sakte ho, lekin unlisted link ko automatically safe mat samajhna.',
      hi: '**संदिग्ध phishing message को कैसे संभालें:**\n\n1. Link न खोलें, file डाउनलोड न करें और reply में व्यक्तिगत जानकारी न भेजें।\n2. Message के link की जगह स्वयं आधिकारिक bank, delivery या service app खोलें।\n3. Sender और पूरा web address ध्यान से देखें; जल्दबाज़ी और धमकी आम scam संकेत हैं।\n\nआप message या URL को VerifyPulse में paste कर सकते हैं, लेकिन unlisted link को अपने-आप सुरक्षित न मानें।'
    }));
  }

  if (/\b(report|complaint|cyber\s*crime|money\s*(lost|debited|gone)|fraud\s*report|1930)\b/i.test(value)) {
    return withDisclaimer(responseFor(locale, {
      en: '**If you suspect financial cyber fraud:**\n\n1. Contact the bank or payment provider immediately through the official app or number printed on your card.\n2. Preserve screenshots, transaction IDs, messages, and the time of the incident. Do not share them publicly.\n3. Report suspected cyber financial fraud promptly through 1930 and follow the official instructions you receive.\n\nDo not pay a “recovery fee” to anyone claiming they can get money back.',
      hinglish: '**Agar financial cyber fraud ka doubt hai:**\n\n1. Bank ya payment provider ko turant official app ya card par diye number se contact karo.\n2. Screenshots, transaction ID, message aur incident ka time save rakho—publicly share mat karo.\n3. Suspected cyber financial fraud ko jaldi 1930 par report karo aur official instructions follow karo.\n\nKisi bhi “recovery fee” dene wale person par bharosa mat karo.',
      hi: '**यदि financial cyber fraud का शक है:**\n\n1. Bank या payment provider से तुरंत official app या card पर दिए number से संपर्क करें।\n2. Screenshots, transaction ID, message और घटना का समय सुरक्षित रखें—इन्हें सार्वजनिक रूप से साझा न करें।\n3. संदिग्ध financial cyber fraud की सूचना जल्दी 1930 पर दें और आधिकारिक निर्देशों का पालन करें।\n\nपैसे वापस दिलाने के नाम पर किसी को “recovery fee” न दें।'
    }));
  }

  if (/\b(cyber\s*security|online\s*safety|safe\s*banking|net\s*banking|banking\s*safety)\b/i.test(value)) {
    return withDisclaimer(responseFor(locale, {
      en: '**Basic online-banking safety checklist:**\n\n1. Use a unique, strong password and enable app/device security.\n2. Install apps only from official stores and keep the phone updated.\n3. Avoid banking on unknown public Wi-Fi and never allow remote-access apps for an unverified caller.',
      hinglish: '**Basic online-banking safety checklist:**\n\n1. Unique strong password use karo aur app/device security on rakho.\n2. Apps sirf official store se install karo aur phone updated rakho.\n3. Unknown public Wi-Fi par banking avoid karo aur unverified caller ke kehne par remote-access app install mat karo.',
      hi: '**Online-banking safety checklist:**\n\n1. अलग और मजबूत password इस्तेमाल करें तथा app/device security चालू रखें।\n2. Apps केवल official store से install करें और phone updated रखें।\n3. अनजान public Wi-Fi पर banking से बचें और किसी unverified caller के कहने पर remote-access app install न करें।'
    }));
  }

  return null;
}
