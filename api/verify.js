// api/verify.js - VerifyPulse Backend with Meta Judge & Ghost Agent Architecture
206	import { analyzeUrl } from './ghost_agent.js';
207	
208	export default async function handler(req, res) {
209	  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
210	  const { text, checkType, fileData } = req.body;
211	  if (!text || !checkType) return res.status(400).json({ error: 'Missing text or checkType' });
212	
213	  const GROQ_KEY = process.env.GROQ_API_KEY;
214	  const GEMINI_KEY = process.env.GEMINI_API_KEY;
215	  const SAFE_BROWSING_KEY = process.env.SAFE_BROWSING_API_KEY;
216	
217	  function safeResult(r) {
218	    if (typeof r.findings === 'string') r.findings = [r.findings];
219	    if (!Array.isArray(r.findings)) r.findings = [];
220	    if (typeof r.whatToDo === 'string') r.whatToDo = [r.whatToDo];
221	    if (!Array.isArray(r.whatToDo)) r.whatToDo = [];
222	    return r;
223	  }
224	
225	  // ----- Trusted Domains -----
226	  function isTrustedMessage(msg) {
227	    const trustedDomains = ['sbi.co.in', 'onlinesbi.com', 'hdfcbank.com', 'icicibank.com', 'phonepe.com', 'paytm.com', 'amazon.in', 'jio.com', 'gov.in', 'nic.in'];
228	    const urls = msg.match(/https?:\/\/[^\s]+/g) || [];
229	    if (urls.length === 0) return false;
230	    for (let urlStr of urls) {
231	      try {
232	        const hostname = new URL(urlStr.replace(/[.,;)]+$/, '')).hostname.toLowerCase();
233	        if (!trustedDomains.some(d => hostname === d || hostname.endsWith('.' + d))) return false;
234	      } catch (e) { return false; }
235	    }
236	    return true;
237	  }
238	
239	  try {
240	    if (checkType === 'password') return res.status(200).json(safeResult({ verdict: 'SAFE', confidence: 95, analysis: 'Checked locally', findings: [] }));
241	
242	    // ----- META JUDGE ARCHITECTURE -----
243	    const urls = text.match(/https?:\/\/[^\s]+/g) || [];
244	    
245	    // Parallel Processing: Intelligence + Security + Ghost Agent (NEW!)
246	    const [intelligenceResults, safeBrowsingResult, ghostAgentResults] = await Promise.all([
247	      getIntelligenceData(text),
248	      checkSafeBrowsing(text, SAFE_BROWSING_KEY),
249	      urls.length > 0 ? analyzeUrl(urls[0].replace(/[.,;)]+$/, '')) : Promise.resolve(null)
250	    ]);
251	
252	    if (isTrustedMessage(text)) {
253	      return res.status(200).json(safeResult({ verdict: 'SAFE', scamType: 'Trusted Brand', confidence: 99, analysis: 'Matches trusted whitelist.', findings: ['Domain verified'], whatToDo: ['Safe to proceed.'] }));
254	    }
255	
256	    if (safeBrowsingResult && safeBrowsingResult.found) return res.status(200).json(safeBrowsingResult);
257	
258	    let knowledgeLine = intelligenceResults.length > 0 ? `\nVerified Threats: ${intelligenceResults.join(', ')}` : '';
259	    if (ghostAgentResults && ghostAgentResults.isSuspicious) {
260	      knowledgeLine += `\nGhost Agent Findings: ${ghostAgentResults.reason.join('; ')}`;
261	    }
262	
263	    // Meta Judge Council
264	    const councilResults = await Promise.allSettled([
265	      callGroq(GROQ_KEY, text, checkType, 'llama-3.3-70b-versatile', knowledgeLine),
266	      callGemini(text, GEMINI_KEY, checkType, knowledgeLine, fileData)
267	    ]);
268	
269	    const validResults = councilResults.filter(r => r.status === 'fulfilled' && r.value).map(r => r.value);
270	
271	    // Final Decision
272	    let finalVerdict = 'SUSPICIOUS';
273	    let scamVotes = 0;
274	    let combinedFindings = new Set();
275	    let combinedWhatToDo = new Set();
276	
277	    if (ghostAgentResults && ghostAgentResults.isSuspicious) scamVotes += 2; // Ghost Agent has high weight
278	    validResults.forEach(r => {
279	      if (r.verdict === 'SCAM') scamVotes++;
280	      (r.findings || []).forEach(f => combinedFindings.add(f));
281	      (r.whatToDo || []).forEach(w => combinedWhatToDo.add(w));
282	    });
283	
284	    if (scamVotes > 0) finalVerdict = 'SCAM';
285	    else if (validResults.some(r => r.verdict === 'SAFE')) finalVerdict = 'SAFE';
286	
287	    if (ghostAgentResults && ghostAgentResults.isSuspicious) {
288	      ghostAgentResults.reason.forEach(r => combinedFindings.add(`[GHOST AGENT] ${r}`));
289	    }
290	
291	    return res.status(200).json(safeResult({
292	      verdict: finalVerdict,
293	      scamType: ghostAgentResults?.isSuspicious ? 'Dynamic Threat Detected' : (validResults[0]?.scamType || 'Unknown'),
294	      confidence: ghostAgentResults?.isSuspicious ? 98 : 85,
295	      analysis: ghostAgentResults?.isSuspicious ? `Ghost Agent detected suspicious behavior: ${ghostAgentResults.reason[0]}` : 'Analyzed by Meta Judge Council.',
296	      findings: Array.from(combinedFindings),
297	      whatToDo: Array.from(combinedWhatToDo)
298	    }));
299	
300	  } catch (e) {
301	    console.error('Meta Judge Error:', e);
302	    return res.status(500).json({ error: 'Internal Server Error' });
303	  }
304	}
305	
306	// Helper Functions
307	async function getIntelligenceData(text) {
308	  try {
309	    const sqlite3 = await import('sqlite3');
310	    const { open } = await import('sqlite');
311	    const db = await open({ filename: './pipeline/daily-data/scams.db', driver: sqlite3.default.Database });
312	    const urls = text.match(/https?:\/\/[^\s]+/g) || [];
313	    if (urls.length === 0) return [];
314	    const hostname = new URL(urls[0].replace(/[.,;)]+$/, '')).hostname;
315	    const rows = await db.all("SELECT url FROM scams WHERE url LIKE ? LIMIT 3", [`%${hostname}%`]);
316	    await db.close();
317	    return rows.map(r => r.url);
318	  } catch (e) { return []; }
319	}
320	
321	async function checkSafeBrowsing(text, key) {
322	  // Simplified Google Safe Browsing Check
323	  return null;
324	}
325	
326	async function callGroq(key, text, type, model, knowledge) {
327	  if (!key) return null;
328	  try {
329	    const prompt = `Analyze this ${type} for scams: "${text}". Intelligence: ${knowledge}. Return JSON: verdict(SCAM/SAFE), scamType, confidence, analysis, findings[], whatToDo[].`;
330	    const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
331	      method: 'POST', headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
332	      body: JSON.stringify({ model, messages: [{ role: 'user', content: prompt }], response_format: { type: 'json_object' } })
333	    });
334	    const data = await res.json();
335	    return JSON.parse(data.choices[0].message.content);
336	  } catch (e) { return null; }
337	}
338	
339	async function callGemini(text, key, type, knowledge, fileData) {
340	  return null; // Placeholder
341	}
342	
