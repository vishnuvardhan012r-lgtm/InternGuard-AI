/* =============================================
   InternGuard-AI — analyzer.js
   Scam Detection Engine v2.0 — Real-Time Edition
   ============================================= */

/* ─────────────────────────────────────────────
   1. KEYWORD RISK DICTIONARY
   ─────────────────────────────────────────────
   Each entry: { pattern: RegExp, weight: 1-10, severity: 'high'|'medium'|'low', label }
*/
const KEYWORD_DB = [
    // High-risk (weight 8-10)
    { pattern: /registration\s*fee/gi, weight: 10, severity: 'high', label: 'Registration Fee' },
    { pattern: /pay\s*(upfront|advance|first)/gi, weight: 10, severity: 'high', label: 'Upfront Payment' },
    { pattern: /wire\s*transfer/gi, weight: 10, severity: 'high', label: 'Wire Transfer' },
    { pattern: /deposit.*?refundable/gi, weight: 9, severity: 'high', label: 'Deposit Required' },
    { pattern: /guaranteed\s*(placement|job|internship|income|salary)/gi, weight: 9, severity: 'high', label: 'Guaranteed Placement' },
    { pattern: /earn\s*\d{4,}/gi, weight: 9, severity: 'high', label: 'Unrealistic Earnings' },
    { pattern: /no\s*experience\s*required/gi, weight: 8, severity: 'high', label: 'No Experience Required' },
    { pattern: /urgent(ly)?[\s!]/gi, weight: 8, severity: 'high', label: 'Urgency Tactics' },
    { pattern: /limited\s*(seats|slots|spots|time|offer)/gi, weight: 8, severity: 'high', label: 'Artificial Scarcity' },
    { pattern: /send\s*(your\s*)?(aadhar|aadhaar|ssn|social\s*security|passport|bank\s*account)/gi, weight: 10, severity: 'high', label: 'Personal Data Request' },
    { pattern: /work\s*from\s*home.*?(immediately|today|now)/gi, weight: 8, severity: 'high', label: 'Immediate WFH Claim' },
    { pattern: /easy\s*money/gi, weight: 9, severity: 'high', label: 'Easy Money Promise' },
    { pattern: /part[\s-]time.*?earn/gi, weight: 7, severity: 'high', label: 'Part-time Earn Scheme' },
    { pattern: /google|amazon|microsoft\s+hiring\s+directly/gi, weight: 8, severity: 'high', label: 'Fake Brand Claim' },

    // Medium-risk (weight 4-7)
    { pattern: /click\s*(here|now|this\s*link)/gi, weight: 6, severity: 'medium', label: 'Suspicious CTA' },
    { pattern: /apply\s*immediately/gi, weight: 5, severity: 'medium', label: 'Pressure Apply' },
    { pattern: /no\s*interview/gi, weight: 6, severity: 'medium', label: 'No Interview Required' },
    { pattern: /100%\s*(job|placement|success)/gi, weight: 7, severity: 'medium', label: '100% Guarantee' },
    { pattern: /training\s*fee/gi, weight: 7, severity: 'medium', label: 'Training Fee' },
    { pattern: /security\s*deposit/gi, weight: 7, severity: 'medium', label: 'Security Deposit' },
    { pattern: /certificate\s*(program|course).*?fee/gi, weight: 6, severity: 'medium', label: 'Paid Certificate Scheme' },
    { pattern: /(whatsapp|telegram)\s*(group|us|number)/gi, weight: 5, severity: 'medium', label: 'Unofficial Contact Channel' },
    { pattern: /lakh(s)?\s*per\s*(month|year)/gi, weight: 6, severity: 'medium', label: 'Unrealistic Salary Claim' },
    { pattern: /stipend.*?lakh/gi, weight: 6, severity: 'medium', label: 'Inflated Stipend' },
    { pattern: /high\s*(commission|earning|salary)\s*(guarantee|assured)?/gi, weight: 5, severity: 'medium', label: 'High Earnings Claim' },
    { pattern: /recruitment\s*charge/gi, weight: 6, severity: 'medium', label: 'Recruitment Charge' },

    // Low-risk (weight 1-3)
    { pattern: /work\s*from\s*home/gi, weight: 2, severity: 'low', label: 'Work From Home' },
    { pattern: /free\s*laptop/gi, weight: 3, severity: 'low', label: 'Free Laptop Promise' },
    { pattern: /no\s*qualification/gi, weight: 3, severity: 'low', label: 'No Qualification' },
    { pattern: /flexible\s*hours/gi, weight: 1, severity: 'low', label: 'Flexible Hours' },
    { pattern: /be\s*your\s*own\s*boss/gi, weight: 3, severity: 'low', label: 'MLM Language' },
    { pattern: /refer\s*(and\s*)?earn/gi, weight: 3, severity: 'low', label: 'Referral Earn Scheme' },
    { pattern: /passive\s*income/gi, weight: 3, severity: 'low', label: 'Passive Income Promise' },
];

/* ─────────────────────────────────────────────
   2. URL ANALYSIS
   ─────────────────────────────────────────────*/
const SUSPICIOUS_TLDS = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.click', '.link', '.top', '.pw', '.cc', '.ws', '.icu', '.monster', '.rest', '.bar'];
const URL_SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'short.io', 'rebrand.ly', 'cutt.ly', 'rb.gy', 'shorte.st', 'adf.ly'];
const FREE_EMAIL_PROVIDERS = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'ymail.com', 'rediffmail.com', 'protonmail.com', 'live.com', 'mail.com', 'zohomail.com'];

/* ─────────────────────────────────────────────
   REAL-TIME MODULE A: Company Registration & Trust Engine
   ─────────────────────────────────────────────*/

/* ── A1. Known Legitimate Companies Database (verified MNCs, PSUs, startups) ── */
const VERIFIED_COMPANIES = {
    // Fortune 500 / Global MNCs with India presence
    mncs: new Set([
        'infosys', 'tcs', 'tata consultancy services', 'wipro', 'hcl', 'hcl technologies',
        'tech mahindra', 'accenture', 'ibm', 'microsoft', 'google', 'amazon', 'amazon web services',
        'meta', 'apple', 'samsung', 'oracle', 'sap', 'cisco', 'intel', 'qualcomm', 'dell',
        'hp', 'hewlett packard', 'deloitte', 'pwc', 'pricewaterhousecoopers', 'kpmg', 'ey',
        'ernst young', 'mckinsey', 'bain', 'bcg', 'boston consulting', 'capgemini', 'cognizant',
        'epam', 'mphasis', 'hexaware', 'l&t', 'larsen toubro', 'l&t infotech', 'ltimindtree',
        'bajaj', 'reliance', 'reliance industries', 'reliance jio', 'ambuja', 'adani', 'vedanta',
        'aditya birla', 'mahindra', 'mahindra mahindra', 'tata motors', 'tata steel', 'tata power',
        'hdfc', 'hdfc bank', 'icici', 'icici bank', 'sbi', 'state bank', 'axis bank', 'kotak',
        'kotak mahindra', 'yes bank', 'bandhan bank', 'idbi bank', 'bank of baroda', 'punjab national',
        'nestle', 'unilever', 'hindustan unilever', 'procter gamble', 'pg india', 'colgate', 'reckitt',
        'abbott', 'cipla', 'sun pharma', 'dr reddy', 'drl', 'lupin', 'biocon', 'zydus', 'cadila',
        'flipkart', 'zomato', 'swiggy', 'byju', 'byjus', 'nykaa', 'ola', 'paytm', 'phonepe',
        'infoedge', 'naukri', 'indeedIndia', 'freshworks', 'zoho', 'razorpay', 'cred', 'zerodha',
        'groww', 'upstox', 'lenskart', 'oyo', 'rapido', 'urban company', 'bigbasket', 'meesho',
        'myntra', 'ajio', 'snapdeal', 'indiamart', 'justdial', 'makemytrip', 'goibibo', 'cleartrip',
        'yatra', 'airtel', 'bharti airtel', 'vodafone', 'vodafone idea', 'vi', 'bsnl', 'mtnl',
        'bhel', 'ntpc', 'ongc', 'iocl', 'indian oil', 'hpcl', 'bpcl', 'gail', 'sail', 'nmdc',
        'coal india', 'power grid', 'rites', 'ircon', 'rvnl', 'irctc', 'indian railways',
        'hero motocorp', 'bajaj auto', 'tvs motor', 'royal enfield', 'eicher motors', 'maruti',
        'maruti suzuki', 'hyundai', 'kia', 'mercedes', 'bmw', 'audi', 'toyota', 'honda',
        'acko', 'policybazaar', 'icicilombard', 'lici', 'lic', 'sbi life', 'hdfc life',
        'mindtree', 'mphasis', 'persistentsystems', 'persistent', 'trent', 'titan', 'tanishq',
        'godrej', 'igl', 'indraprastha gas', 'mahanagar gas', 'gujarat gas', 'petronet',
        'jubilantfoods', 'jubilant', 'dominos', 'mcdonalds', 'yum brands', 'kfc india',
        'shoppers stop', 'lifestyle', 'pantaloons', 'westside', 'reliance retail', 'dmart',
        'avenue supermarts', 'spencer', 'bigbazaar', 'future group', 'safari', 'vip industries',
        'raymond', 'arvind', 'welspun', 'vardhman', 'texport', 'page industries', 'dollar',
        'mrf', 'apollo tyres', 'ceat', 'jk tyre', 'balkrishna', 'balkrishna industries',
        'ultratech', 'shree cement', 'jk cement', 'ramco', 'grasim', 'dalmia bharat',
        'asian paints', 'berger paints', 'nerolac', 'indigo paints', 'akzo',
        'pidilite', 'fevicol', 'm&m financial', 'shriram transport', 'bajaj finance',
        'muthoot', 'manappuram', 'iifl', 'motilal oswal', 'edelweiss', 'jm financial',
        'nse', 'bse', 'cdsl', 'nsdl', 'sebi', 'rbi', 'irdai', 'nabard', 'sidbi',
        'infosys bpm', 'wipro bps', 'tcs bps', 'igate', 'syntel', 'mastech', 'niit',
        'aptech', 'jetking', 'manipal', 'amity', 'symbiosis', 'vit', 'srm', 'lpu',
        'bloomberg', 'reuters', 'factset', 'refinitiv', 'morningstar', 'moodys', 'sp global',
        'bosch', 'siemens', 'abb', 'schneider', 'honeywell', 'ge', 'general electric',
        'philips', 'emerson', 'rockwell', '3m', 'johnson controls', 'carrier',
        'linkedin', 'indeed', 'glassdoor', 'monster', 'shine', 'timesjobs', 'hirist',
        'instahyre', 'iimjobs', 'angel broking', 'angelone', 'icici direct', 'hdfc securities',
    ]),

    // Official domain suffixes for real companies
    officialDomainPatterns: [
        /\.gov\.in$/, /\.nic\.in$/, /\.edu\.in$/, /\.ac\.in$/, /\.org\.in$/,
        /infosys\.com$/, /wipro\.com$/, /tcs\.com$/, /hcltech\.com$/, /accenture\.com$/,
        /microsoft\.com$/, /google\.com$/, /amazon\.com$/, /ibm\.com$/, /oracle\.com$/,
        /deloitte\.com$/, /pwc\.com$/, /kpmg\.com$/, /ey\.com$/, /mckinsey\.com$/,
        /capgemini\.com$/, /cognizant\.com$/, /techmahindra\.com$/, /ltimindtree\.com$/,
    ],
};

/* ── A2. Suspicious Company Name Patterns ── */
const SUSPICIOUS_COMPANY_PATTERNS = [
    // Generic fake-sounding names
    { pattern: /\b(top|best|prime|elite|global|international|world|super|mega|ultra|ultimate)\s+(mnc|corp|solutions|services|pvt|india|jobs|career|hr|hiring|placement|recruit)\b/i, weight: 15, label: 'Generic fake MNC name pattern' },
    { pattern: /\b(fast|quick|easy|instant|guaranteed|assured)\s*(job|hire|career|placement|intern)/i, weight: 18, label: 'Guaranteed placement company name' },
    { pattern: /\b(earn|money|income|profit|cash)\s*(fast|quick|easy|online|home|work)/i, weight: 20, label: 'MLM/money scheme company name' },
    { pattern: /pvt\.?\s*ltd\.?\s*group|group\s+of\s+companies/i, weight: 5, label: 'Vague company suffix' },
    { pattern: /\b(hr|jobs|career|recruit|placement|staffing)\s+(india|hub|zone|center|centre|point|pro|plus|solutions|pvt)\b/i, weight: 12, label: 'Generic HR agency name' },
    { pattern: /\b(work\s*from\s*home|wfh|remote)\s+(pvt|corp|solutions|services|india)/i, weight: 18, label: 'Work-from-home scheme company' },
    // Random character patterns (e.g., "XBZRT Solutions")
    { pattern: /^[A-Z]{4,8}\s+(pvt|ltd|solutions|services|corp)/i, weight: 10, label: 'Suspicious acronym-only company name' },
    // Impersonation patterns
    { pattern: /\b(infosys|tcs|wipro|accenture|amazon|google|microsoft|apple|fb|meta|flipkart)\s*[0-9a-z]*\s*(india|pvt|global|solutions|hr|jobs|careers|services)/i, weight: 22, label: 'Possible brand name impersonation' },
    { pattern: /\b(fake|scam|fraud|illegal|bogus)\b/i, weight: 30, label: 'Explicit suspicious word in name' },
];

/* ── A3. CIN (Company Identification Number) Validator — MCA India Format ── */
function validateCIN(cin) {
    if (!cin || cin.trim() === '') return { valid: false, reason: 'Not provided' };
    const cleaned = cin.trim().toUpperCase().replace(/\s/g, '');
    // CIN format: [L/U][5-digit-NIC][2-letter-state][4-digit-year][PTC/PLC/etc][6-digit-serial]
    const CIN_REGEX = /^([LUlu])\d{5}[A-Z]{2}\d{4}[A-Z]{3}\d{6}$/;
    if (!CIN_REGEX.test(cleaned)) return { valid: false, reason: 'Invalid CIN format (expected: L/U + 5 digits + state + year + type + 6 digits)' };
    const year = parseInt(cleaned.substring(6, 10));
    const currentYear = new Date().getFullYear();
    if (year < 1800 || year > currentYear) return { valid: false, reason: `Invalid incorporation year ${year}` };
    return { valid: true, cin: cleaned, type: cleaned[0] === 'L' ? 'Listed' : 'Unlisted', year };
}

/* ── A4. GST Number Validator ── */
function validateGST(gst) {
    if (!gst || gst.trim() === '') return { valid: false, reason: 'Not provided' };
    const cleaned = gst.trim().toUpperCase().replace(/\s/g, '');
    // GST: 2 state digits + 10 PAN chars + 1 entity + Z + 1 checksum
    const GST_REGEX = /^\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[A-Z\d]$/;
    if (!GST_REGEX.test(cleaned)) return { valid: false, reason: 'Invalid GST format (expected: 15-character GSTIN)' };
    const stateCode = parseInt(cleaned.substring(0, 2));
    if (stateCode < 1 || stateCode > 37) return { valid: false, reason: `Invalid state code (${stateCode}) in GSTIN` };
    return { valid: true, stateCode, pan: cleaned.substring(2, 12) };
}

/* ── A5. Company Name Trust Analyzer ── */
function analyzeCompanyName(companyName) {
    if (!companyName || companyName.trim().length === 0) {
        return { score: 0, trustLevel: 'unknown', flags: [], suggestions: [], isVerified: false };
    }

    const name = companyName.trim();
    const nameLower = name.toLowerCase().replace(/[^a-z0-9\s&]/g, '').replace(/\s+/g, ' ');
    const flags = [];
    const suggestions = [];
    let riskScore = 0;

    // ── Check 1: Verified company database ──
    let isVerified = false;
    let verifiedMatch = '';
    for (const company of VERIFIED_COMPANIES.mncs) {
        if (nameLower.includes(company) || company.includes(nameLower)) {
            isVerified = true;
            verifiedMatch = company;
            break;
        }
    }

    if (isVerified) {
        riskScore -= 20; // Trust bonus
        flags.push({ type: 'pass', text: `✅ Matches verified company: "${verifiedMatch}" — listed in our MNC/startup database` });
    }

    // ── Check 2: Suspicious name patterns ──
    for (const p of SUSPICIOUS_COMPANY_PATTERNS) {
        if (p.pattern.test(name)) {
            riskScore += p.weight;
            flags.push({ type: 'fail', text: `🚨 ${p.label}: "${name}"` });
        }
    }

    // ── Check 3: Name length heuristics ──
    const words = name.split(/\s+/);
    if (words.length === 1 && name.length < 5) {
        riskScore += 10;
        flags.push({ type: 'warn', text: `⚠️ Very short company name (${name.length} chars) — likely incomplete or fake` });
    }
    if (name.length > 80) {
        riskScore += 5;
        flags.push({ type: 'warn', text: '⚠️ Unusually long company name' });
    }

    // ── Check 4: All caps / random chars ──
    if (name === name.toUpperCase() && name.length > 6 && !/^[A-Z]{2,5}$/.test(name)) {
        riskScore += 8;
        flags.push({ type: 'warn', text: '⚠️ All-caps name may indicate an unregistered or informal entity' });
    }

    // ── Check 5: Registered suffix check ──
    const hasRegisteredSuffix = /\b(pvt\.?\s*ltd|private limited|public limited|llp|llc|incorporated|corp|plc|limited)\b/i.test(name);
    if (hasRegisteredSuffix) {
        flags.push({ type: 'info', text: 'ℹ️ Has registered entity suffix (Pvt Ltd/LLP/Corp) — check MCA registry for confirmation' });
        suggestions.push('Verify on MCA21 Portal: https://www.mca.gov.in/mcafoportal/viewCompanyMasterData.do');
    } else if (!isVerified) {
        riskScore += 8;
        flags.push({ type: 'warn', text: '⚠️ No registered entity suffix — may not be a registered company' });
        suggestions.push('Legitimate companies typically have "Pvt Ltd", "LLP", or "Ltd" in their name');
    }

    // ── Check 6: Numbers/special chars in name ──
    if (/\d{3,}/.test(name) && !isVerified) {
        riskScore += 6;
        flags.push({ type: 'warn', text: '⚠️ Company name contains excessive numbers — uncommon for registered firms' });
    }

    // ── Check 7: External verification links ──
    suggestions.push(`Search on MCA: https://www.mca.gov.in/mcafoportal/viewCompanyMasterData.do`);
    suggestions.push(`LinkedIn search: https://www.linkedin.com/company/${encodeURIComponent(name.split(' ')[0].toLowerCase())}`);
    suggestions.push(`Google: https://www.google.com/search?q="${encodeURIComponent(name)}" site review scam`);
    suggestions.push(`Glassdoor: https://www.glassdoor.co.in/Search/results.htm?keyword=${encodeURIComponent(name)}`);
    if (/india|pvt|ltd/i.test(name)) {
        suggestions.push(`Startup India: https://www.startupindia.gov.in/content/sih/en/search.html#q=${encodeURIComponent(name)}`);
    }

    riskScore = Math.max(0, Math.min(riskScore, 100));
    const trustLevel = isVerified ? 'verified' : riskScore <= 10 ? 'likely-legit' : riskScore <= 30 ? 'unverified' : riskScore <= 55 ? 'suspicious' : 'likely-fake';

    return { score: riskScore, trustLevel, flags, suggestions, isVerified, verifiedMatch };
}

/* ── A6. Known Scam DB + enhanced company check ── */
const KNOWN_SCAM_DB = {
    domains: [
        'internship-jobs.in', 'freejobalert.co', 'jobsalerthub.com', 'earnmoney24.in',
        'jobsarkari.net', 'indiajobportal.co', 'quickjobs.co.in', 'jobseekers.co.in',
        'hiringnow.co.in', 'jobs4fresher.com', 'topjobsportal.com', 'careerguru.in',
        'fastjobs.co.in', 'workfromhomejobs.in', 'jobsinjaipur.co.in', 'jobs-alert.in',
        'naukri-alert.com', 'jobduniya.co.in', 'sarkarijobsalert.co.in', 'jobshub.in',
        'onlineearnmoneyindia.com', 'workathomeguide.in', 'earnathome.co.in', 'mlmjob.in',
        'govtjobsalert.org', 'sarkariresult-alert.in', 'jobportal123.com', 'hireme.co.in',
        'internship4u.in', 'internstore.in', 'getinternship.co.in', 'fakecompany.xyz',
    ],
    companyKeywords: [
        'topmncgroup', 'hirehubsolutions', 'staffingindia', 'recruitprosolutions',
        'globalrecruitment', 'elitejobssolution', 'professionaljobshub', 'instantplacementhub',
        'careerpathwaysindia', 'smartjobsolutions', 'workfromhomepvtltd', 'earnfastindia',
    ],
    emailPatterns: [
        /hr\.india@/i, /jobs@.*\.xyz/i, /recruit@.*\.tk/i,
        /internship@.*gmail/i, /career@.*yahoo/i, /placement@.*hotmail/i,
    ],
};

function checkKnownScamDB(hostname, companyName, email) {
    const results = [];
    const h = (hostname || '').toLowerCase();
    const co = (companyName || '').toLowerCase().replace(/\s+/g, '');
    const em = (email || '').toLowerCase();

    if (KNOWN_SCAM_DB.domains.some(d => h.includes(d))) {
        results.push({ type: 'domain', text: `Domain matches known scam database entry`, severity: 'high' });
    }
    if (co && KNOWN_SCAM_DB.companyKeywords.some(k => co.includes(k))) {
        results.push({ type: 'company', text: 'Company name matches known scam pattern', severity: 'high' });
    }
    if (em && KNOWN_SCAM_DB.emailPatterns.some(p => p.test(em))) {
        results.push({ type: 'email', text: 'Recruiter email matches known scam pattern', severity: 'high' });
    }
    return results;
}

/* ─────────────────────────────────────────────
   REAL-TIME MODULE B: Website Content Scanner
   Uses allorigins.win CORS proxy (free, no key)
   ─────────────────────────────────────────────*/
async function fetchWebsiteInfo(url) {
    if (!url || url.trim() === '') return null;
    const raw = url.trim().startsWith('http') ? url.trim() : 'https://' + url.trim();
    const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(raw)}`;

    const info = {
        url: raw, fetched: false, error: null,
        title: null, description: null, keywords: null,
        links: [], suspiciousScripts: [], hiddenForms: false,
        hasSSL: raw.startsWith('https'), serverHeaders: {},
        contentFlags: [], contentScore: 0,
    };

    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10000);
        const res = await fetch(proxyUrl, { signal: controller.signal });
        clearTimeout(timeout);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const html = data.contents || '';
        if (!html) throw new Error('Empty response');
        info.fetched = true;

        // Parse with DOMParser
        const doc = new DOMParser().parseFromString(html, 'text/html');

        // Meta extraction
        info.title = doc.title || null;
        const descEl = doc.querySelector('meta[name="description"]');
        if (descEl) info.description = descEl.getAttribute('content');
        const kwEl = doc.querySelector('meta[name="keywords"]');
        if (kwEl) info.keywords = kwEl.getAttribute('content');

        // Extract outbound links (first 15)
        const anchors = Array.from(doc.querySelectorAll('a[href]'));
        info.links = anchors.slice(0, 15).map(a => a.href).filter(h => h.startsWith('http'));

        // Suspicious patterns in HTML
        const lowerHtml = html.toLowerCase();
        if (lowerHtml.includes('registrationfee') || lowerHtml.includes('registration fee')) {
            info.contentFlags.push('Page mentions registration fee'); info.contentScore += 25;
        }
        if (lowerHtml.includes('whatsapp') && lowerHtml.includes('apply')) {
            info.contentFlags.push('Apply via WhatsApp mentioned'); info.contentScore += 15;
        }
        if ((lowerHtml.match(/!/g) || []).length > 30) {
            info.contentFlags.push('Excessive exclamation marks on page'); info.contentScore += 10;
        }
        if (/earn.*\d{4,}.*month|₹.*\d{5,}/i.test(html)) {
            info.contentFlags.push('Unrealistic earnings claim on page'); info.contentScore += 20;
        }
        if (lowerHtml.includes('aadhaar') || lowerHtml.includes('pan card') || lowerHtml.includes('bank account')) {
            info.contentFlags.push('Page requests sensitive personal data'); info.contentScore += 30;
        }
        if (lowerHtml.includes('guaranteed placement') || lowerHtml.includes('100% placement')) {
            info.contentFlags.push('"Guaranteed placement" claim on page'); info.contentScore += 20;
        }

        // Hidden forms / iframes
        const hiddenInputs = doc.querySelectorAll('input[type="hidden"]');
        const iframes = doc.querySelectorAll('iframe');
        if (hiddenInputs.length > 5 || iframes.length > 2) info.hiddenForms = true;

        // Suspicious script sources
        doc.querySelectorAll('script[src]').forEach(s => {
            const src = s.getAttribute('src') || '';
            if (URL_SHORTENERS.some(sh => src.includes(sh)) || SUSPICIOUS_TLDS.some(t => src.includes(t))) {
                info.suspiciousScripts.push(src);
            }
        });

    } catch (err) {
        info.error = err.name === 'AbortError' ? 'Request timed out (10s)' : err.message;
    }
    return info;
}

/* ─────────────────────────────────────────────
   REAL-TIME MODULE C: URLScan.io Public Lookup
   Free public API — no key required for search
   ─────────────────────────────────────────────*/
async function checkURLScanIO(hostname) {
    if (!hostname) return null;
    const result = { checked: false, malicious: false, scans: 0, verdicts: [], error: null };
    try {
        const apiUrl = `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(hostname)}&size=5`;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 8000);
        const res = await fetch(apiUrl, {
            signal: controller.signal,
            headers: { 'Accept': 'application/json' },
        });
        clearTimeout(timeout);
        if (!res.ok) throw new Error(`URLScan HTTP ${res.status}`);
        const data = await res.json();
        result.checked = true;
        result.scans = data.total || 0;
        if (data.results && data.results.length > 0) {
            data.results.forEach(r => {
                const v = r.verdicts && r.verdicts.overall;
                if (v) {
                    result.verdicts.push({
                        malicious: v.malicious || false,
                        score: v.score || 0,
                        tags: v.tags || [],
                        date: r.task && r.task.time ? r.task.time.slice(0, 10) : 'unknown',
                    });
                    if (v.malicious) result.malicious = true;
                }
            });
        }
    } catch (err) {
        result.error = err.name === 'AbortError' ? 'Timed out' : err.message;
    }
    return result;
}

function analyzeURL(url) {
    if (!url || url.trim() === '') return { score: 0, flags: [], verdict: 'not_provided' };

    const flags = [];
    let score = 0;
    const raw = url.trim().toLowerCase();

    // Ensure has protocol
    const withProto = raw.startsWith('http') ? raw : 'http://' + raw;
    let parsed;
    try { parsed = new URL(withProto); } catch { return { score: 15, flags: ['Invalid URL format'], verdict: 'suspicious' }; }

    const hostname = parsed.hostname;

    // No HTTPS
    if (!raw.startsWith('https')) { flags.push('Not using HTTPS'); score += 15; }

    // IP-based URL
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) { flags.push('IP-based URL (no domain name)'); score += 25; }

    // URL shortener
    if (URL_SHORTENERS.some(s => hostname.includes(s))) { flags.push('URL shortener detected'); score += 20; }

    // Suspicious TLD
    const hasBadTld = SUSPICIOUS_TLDS.some(t => hostname.endsWith(t));
    if (hasBadTld) { flags.push(`Suspicious top-level domain: ${hostname.split('.').pop()}`); score += 20; }

    // Excessive subdomains
    const parts = hostname.split('.');
    if (parts.length > 4) { flags.push('Excessive subdomains'); score += 10; }

    // Numbers in domain name
    if (/\d{3,}/.test(hostname.replace(/\d+\.\d+$/, ''))) { flags.push('Numeric-heavy domain name'); score += 10; }

    // Hyphen excess
    if ((hostname.match(/-/g) || []).length > 2) { flags.push('Excessive hyphens in domain'); score += 8; }

    // Very short, random-looking domain (< 5 chars before TLD, mix of letters+numbers)
    const domainName = parts.length >= 2 ? parts[parts.length - 2] : '';
    if (/[a-z]+\d+[a-z]+|[0-9][a-z]{1,3}[0-9]/.test(domainName) && domainName.length < 8) {
        flags.push('Random-looking domain name'); score += 10;
    }

    score = Math.min(score, 100);
    const verdict = score === 0 ? 'clean' : score < 25 ? 'low_risk' : score < 50 ? 'suspicious' : 'dangerous';
    return { score, flags, verdict, hostname };
}

/* ─────────────────────────────────────────────
   3. EMAIL ANALYSIS
   ─────────────────────────────────────────────*/
function analyzeEmail(email, companyName) {
    if (!email || email.trim() === '') return { score: 0, flags: [], verdict: 'not_provided' };

    const flags = [];
    let score = 0;
    const e = email.trim().toLowerCase();

    // Basic email format check
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) {
        return { score: 20, flags: ['Invalid email format'], verdict: 'suspicious' };
    }

    const domain = e.split('@')[1];

    // Free email for corporate contact
    if (FREE_EMAIL_PROVIDERS.includes(domain)) {
        flags.push(`Corporate contact using free email (${domain})`);
        score += 25;
    }

    // Company name / domain mismatch
    if (companyName && companyName.trim().length > 0) {
        const simpleCo = companyName.trim().toLowerCase().replace(/\s+/g, '').replace(/[^a-z0-9]/g, '');
        const simpleDomain = domain.split('.')[0].replace(/[^a-z0-9]/g, '');
        if (simpleCo.length > 3 && !simpleDomain.includes(simpleCo.slice(0, 4)) && !simpleCo.includes(simpleDomain.slice(0, 4))) {
            flags.push('Recruiter email domain doesn\'t match company name');
            score += 15;
        }
    }

    // Suspicious TLD on email domain
    if (SUSPICIOUS_TLDS.some(t => domain.endsWith(t))) {
        flags.push(`Suspicious email domain TLD`);
        score += 20;
    }

    score = Math.min(score, 100);
    const verdict = score === 0 ? 'clean' : score < 20 ? 'low_risk' : score < 40 ? 'suspicious' : 'dangerous';
    return { score, flags, verdict, domain };
}

/* ─────────────────────────────────────────────
   4. TEXT PATTERN ANALYSIS
   ─────────────────────────────────────────────*/
function analyzeTextPatterns(text) {
    const flags = [];
    let score = 0;

    // Excessive caps
    const words = text.split(/\s+/);
    const capsWords = words.filter(w => w.length > 3 && w === w.toUpperCase() && /[A-Z]/.test(w));
    const capsRatio = capsWords.length / Math.max(words.length, 1);
    if (capsRatio > 0.15) { flags.push('Excessive CAPS usage (pressure tactic)'); score += Math.round(capsRatio * 30); }

    // Excessive exclamation marks
    const exclaims = (text.match(/!/g) || []).length;
    if (exclaims > 4) { flags.push(`Excessive exclamation marks (${exclaims})`); score += Math.min(exclaims * 2, 15); }

    // Personal data patterns
    if (/\b(aadhar|aadhaar|pan\s*card|passport\s*number|bank\s*account|ifsc|credit\s*card|debit\s*card)\b/gi.test(text)) {
        flags.push('Requests sensitive personal or financial data'); score += 30;
    }

    // Salary unrealistic (> ₹5 lakh/month or > $5000/month for internship)
    const salaryMatch = text.match(/(?:₹|rs\.?\s*|inr\s*)?(\d[\d,]*)\s*(?:k|thousand|lakh|lac)?\s*(?:per|\/)\s*(?:month|mo)/gi);
    if (salaryMatch) {
        salaryMatch.forEach(s => {
            const numStr = s.match(/(\d[\d,]*)/);
            if (numStr) {
                const num = parseInt(numStr[1].replace(',', ''), 10);
                if ((/lakh|lac/i.test(s) && num >= 1) || (!(/lakh|lac/i.test(s)) && num >= 80000)) {
                    flags.push('Unrealistically high salary for an internship'); score += 20;
                }
            }
        });
    }

    // Very short suspicious text (< 50 words is suspicious for a real JD)
    if (words.length < 40) { flags.push('Unusually short job description'); score += 10; }

    // Grammar errors (simple heuristic: common mistake patterns)
    const grammarPatterns = [
        /\bwe\s+is\b/gi, /\bthey\s+is\b/gi, /\bcandidate\s+are\b/gi,
        /\bfor\s+more\s+informations?\b/gi, /\bplease\s+to\s+contact\b/gi,
    ];
    const grammarHits = grammarPatterns.filter(p => p.test(text));
    if (grammarHits.length > 0) { flags.push('Grammar errors detected'); score += grammarHits.length * 5; }

    score = Math.min(score, 100);
    return { score, flags };
}

/* ─────────────────────────────────────────────
   5. COMPOSITE SCORING & CLASSIFICATION
   ─────────────────────────────────────────────*/
const WEIGHTS = {
    keywords: 0.35,
    url: 0.18,
    email: 0.18,
    text: 0.18,
    company: 0.11,
};

function classify(score) {
    if (score >= 60) return { label: 'SCAM', cssClass: 'scam', icon: '🚨', color: '#ef4444', description: 'High probability of fraud. Do NOT apply or share any personal information.' };
    if (score >= 30) return { label: 'SUSPICIOUS', cssClass: 'suspicious', icon: '⚠️', color: '#f59e0b', description: 'Several red flags detected. Research this opportunity thoroughly before proceeding.' };
    return { label: 'SAFE', cssClass: 'safe', icon: '✅', color: '#10b981', description: 'Appears legitimate. Always verify independently before sharing personal details.' };
}

function runDetection({ jobText, companyUrl, recruiterEmail, companyName }) {
    /* Keywords */
    const keywordHits = [];
    let rawKeywordScore = 0;

    KEYWORD_DB.forEach(kw => {
        const matches = jobText.match(kw.pattern);
        if (matches) {
            rawKeywordScore += kw.weight;
            keywordHits.push({ label: kw.label, severity: kw.severity, weight: kw.weight, count: matches.length });
        }
    });
    const keywordScore = Math.min(Math.round((rawKeywordScore / 70) * 100), 100);

    /* URL */
    const urlResult = analyzeURL(companyUrl);

    /* Email */
    const emailResult = analyzeEmail(recruiterEmail, companyName);

    /* Text patterns */
    const textResult = analyzeTextPatterns(jobText);

    /* Company name trust analysis */
    const companyResult = analyzeCompanyName(companyName);
    // A verified company reduces composite; suspicious one increases it
    const companyScore = companyResult.isVerified ? 0 : companyResult.score;

    /* Composite */
    const composite = Math.min(Math.round(
        keywordScore * WEIGHTS.keywords +
        urlResult.score * WEIGHTS.url +
        emailResult.score * WEIGHTS.email +
        textResult.score * WEIGHTS.text +
        companyScore * WEIGHTS.company
    ), 100);

    const verdict = classify(composite);

    return {
        composite,
        verdict,
        breakdown: {
            keywords: { score: keywordScore, hits: keywordHits },
            url: urlResult,
            email: emailResult,
            text: textResult,
            company: { ...companyResult, score: companyScore },
        },
    };
}

/* -------------------------------------------------
   UI — Speedometer drawing
   Semicircle: center=(140,140), r=110, from 180° to 0°
   Score 0   => needle angle = -90° (pointing left, 180° in SVG terms)
   Score 100 => needle angle = +90° (pointing right, 0° in SVG terms)
   CSS rotation: rotate(-90deg) at score=0, rotate(+90deg) at score=100
   So: angle = (score/100) * 180 - 90  degrees
   Arc total length = π * 110 ≈ 345.6
   ------------------------------------------------- */
function initSpeedometer() {
    const cx = 140, cy = 140, r = 110;
    const ticksG = document.getElementById('ticks');
    const labelsG = document.getElementById('tickLabels');
    if (!ticksG || !labelsG) return;

    // Draw 11 ticks for scores 0, 10, 20, ... 100
    for (let i = 0; i <= 10; i++) {
        const score = i * 10;
        // Map score 0→0: angle 180° (left), score 100→: angle 0° (right)
        const angleDeg = 180 - (score / 100) * 180;
        const angleRad = (angleDeg * Math.PI) / 180;
        const isMajor = (i % 5 === 0);  // 0, 50, 100 are major
        const innerR = isMajor ? r - 20 : r - 14;
        const outerR = r + 4;

        const x1 = cx + innerR * Math.cos(angleRad);
        const y1 = cy - innerR * Math.sin(angleRad);
        const x2 = cx + outerR * Math.cos(angleRad);
        const y2 = cy - outerR * Math.sin(angleRad);

        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', x1.toFixed(1));
        line.setAttribute('y1', y1.toFixed(1));
        line.setAttribute('x2', x2.toFixed(1));
        line.setAttribute('y2', y2.toFixed(1));
        if (isMajor) {
            line.setAttribute('stroke-width', '2.5');
            line.setAttribute('stroke', 'rgba(255,255,255,0.5)');
        }
        ticksG.appendChild(line);

        // Label for major ticks only (0, 50, 100)
        if (isMajor) {
            const labelR = innerR - 10;
            const lx = cx + labelR * Math.cos(angleRad);
            const ly = cy - labelR * Math.sin(angleRad);
            const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            text.setAttribute('x', lx.toFixed(1));
            text.setAttribute('y', (ly + 3).toFixed(1));
            text.textContent = score;
            labelsG.appendChild(text);
        }
    }
}

function drawGauge(svgEl, score, color) {
    const needle = document.getElementById('speedNeedle');
    const numEl = svgEl.querySelector('#gaugeNumber');
    const arc = document.getElementById('gaugeZoneArc');

    // Update neon glow color to match verdict
    const neonFlood = document.getElementById('neonFlood');
    if (neonFlood) neonFlood.setAttribute('flood-color', color);

    // Needle: -90deg at score=0, +90deg at score=100
    const angleDeg = (score / 100) * 180 - 90;

    // Reset needle instantly, then animate
    needle.style.transition = 'none';
    needle.style.transform = 'rotate(-90deg)';

    // Arc total length ≈ π * 110 ≈ 345.6
    const arcLen = Math.PI * 110;
    arc.style.strokeDasharray = `0 ${arcLen}`;

    requestAnimationFrame(() => {
        requestAnimationFrame(() => {
            needle.style.transition = 'transform 1.3s cubic-bezier(0.34, 1.56, 0.64, 1)';
            needle.style.transform = `rotate(${angleDeg}deg)`;

            // Fill arc up to current score
            const filled = (score / 100) * arcLen;
            arc.style.transition = 'stroke-dasharray 1.3s cubic-bezier(0.4,0,0.2,1)';
            arc.style.strokeDasharray = `${filled} ${arcLen}`;
        });
    });

    // Animate the numeric label
    let start = null;
    function animNum(ts) {
        if (!start) start = ts;
        const pct = Math.min((ts - start) / 1300, 1);
        const ease = 1 - Math.pow(1 - pct, 3);
        numEl.textContent = Math.round(ease * score);
        // Colour the number to match verdict
        numEl.setAttribute('fill', color);
        if (pct < 1) requestAnimationFrame(animNum);
    }
    requestAnimationFrame(animNum);
}


/* ─────────────────────────────────────────────
   UI — Render results
   ─────────────────────────────────────────────*/
function renderResults(result) {
    const { composite, verdict, breakdown } = result;

    // Show results panel
    const panel = document.getElementById('resultPanel');
    const emptyState = document.getElementById('emptyState');
    panel.style.display = 'block';
    if (emptyState) emptyState.style.display = 'none';
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // Verdict hero
    document.getElementById('verdictIcon').textContent = verdict.icon;
    document.getElementById('verdictLabel').textContent = verdict.label;
    document.getElementById('verdictLabel').className = `verdict-label color-${verdict.cssClass}`;
    document.getElementById('verdictDesc').textContent = verdict.description;

    // Gauge
    const gaugeSvg = document.getElementById('gaugeSvg');
    drawGauge(gaugeSvg, composite, verdict.color);

    // Breakdown bars
    renderBreakdownBar('barKeywords', breakdown.keywords.score, verdict.cssClass);
    renderBreakdownBar('barUrl', breakdown.url.score, breakdown.url.score >= 50 ? 'scam' : breakdown.url.score >= 25 ? 'suspicious' : 'safe');
    renderBreakdownBar('barEmail', breakdown.email.score, breakdown.email.score >= 40 ? 'scam' : breakdown.email.score >= 20 ? 'suspicious' : 'safe');
    renderBreakdownBar('barText', breakdown.text.score, breakdown.text.score >= 50 ? 'scam' : breakdown.text.score >= 25 ? 'suspicious' : 'safe');

    document.getElementById('scoreKeywords').textContent = breakdown.keywords.score;
    document.getElementById('scoreUrl').textContent = breakdown.url.score;
    document.getElementById('scoreEmail').textContent = breakdown.email.score;
    document.getElementById('scoreText').textContent = breakdown.text.score;

    // Company trust bar (dynamic — add or update)
    let companyRowEl = document.getElementById('companyRow');
    if (breakdown.company && breakdown.company.trustLevel !== 'unknown') {
        if (!companyRowEl) {
            const barsContainer = document.getElementById('barKeywords')?.closest?.('.breakdown-row')?.parentElement;
            if (barsContainer) {
                const row = document.createElement('div');
                row.className = 'breakdown-row';
                row.id = 'companyRow';
                row.innerHTML = `<div class="breakdown-label">Company</div><div class="breakdown-bar-wrap"><div class="breakdown-bar" id="barCompany"></div></div><div class="breakdown-score" id="scoreCompany">0</div>`;
                barsContainer.appendChild(row);
            }
        }
        const coScore = breakdown.company.score;
        renderBreakdownBar('barCompany', coScore, coScore >= 50 ? 'scam' : coScore >= 25 ? 'suspicious' : 'safe');
        const scEl = document.getElementById('scoreCompany');
        if (scEl) scEl.textContent = breakdown.company.isVerified ? '✓' : coScore;
    }

    // Company Trust Report card (inject after domain-check-grid)
    renderCompanyTrustCard(breakdown.company);

    // Keyword chips
    const chipsWrap = document.getElementById('keywordChips');
    chipsWrap.innerHTML = '';
    if (breakdown.keywords.hits.length === 0) {
        chipsWrap.innerHTML = '<span style="color:var(--text-muted);font-size:0.85rem;">No suspicious keywords detected ✓</span>';
    } else {
        breakdown.keywords.hits
            .sort((a, b) => b.weight - a.weight)
            .forEach((hit, i) => {
                const chip = document.createElement('span');
                chip.className = `kw-chip ${hit.severity}`;
                chip.style.animationDelay = `${i * 0.07}s`;
                chip.innerHTML = `${hit.severity === 'high' ? '🔴' : hit.severity === 'medium' ? '🟡' : '🔵'} ${hit.label}`;
                chipsWrap.appendChild(chip);
            });
    }

    // All flags list
    const flagsList = document.getElementById('flagsList');
    flagsList.innerHTML = '';
    const allFlags = [
        ...breakdown.keywords.hits.map(h => ({ text: h.label, source: 'Keywords', cls: h.severity })),
        ...breakdown.url.flags.map(f => ({ text: f, source: 'URL', cls: 'high' })),
        ...breakdown.email.flags.map(f => ({ text: f, source: 'Email', cls: 'medium' })),
        ...breakdown.text.flags.map(f => ({ text: f, source: 'Content', cls: 'medium' })),
    ];

    if (allFlags.length === 0) {
        flagsList.innerHTML = '<li style="color:var(--safe)">✅ No red flags detected</li>';
    } else {
        allFlags.forEach(flag => {
            const li = document.createElement('li');
            li.className = `flag-item flag-${flag.cls}`;
            li.innerHTML = `<span class="flag-source">${flag.source}</span><span class="flag-text">${flag.text}</span>`;
            flagsList.appendChild(li);
        });
    }

    // URL verdict
    const urlVerdictEl = document.getElementById('urlVerdict');
    if (urlVerdictEl) {
        urlVerdictEl.innerHTML = breakdown.url.verdict === 'not_provided'
            ? '<span style="color:var(--text-muted)">Not provided</span>'
            : `<span class="color-${breakdown.url.score >= 50 ? 'scam' : breakdown.url.score >= 25 ? 'suspicious' : 'safe'}">${breakdown.url.verdict.replace('_', ' ').toUpperCase()}</span>${breakdown.url.hostname ? ` — <code style="font-size:0.8rem;color:var(--text-secondary)">${breakdown.url.hostname}</code>` : ''}`;
    }

    // Email verdict
    const emailVerdictEl = document.getElementById('emailVerdict');
    if (emailVerdictEl) {
        emailVerdictEl.innerHTML = breakdown.email.verdict === 'not_provided'
            ? '<span style="color:var(--text-muted)">Not provided</span>'
            : `<span class="color-${breakdown.email.score >= 40 ? 'scam' : breakdown.email.score >= 20 ? 'suspicious' : 'safe'}">${breakdown.email.verdict.replace('_', ' ').toUpperCase()}</span>${breakdown.email.domain ? ` — <code style="font-size:0.8rem;color:var(--text-secondary)">@${breakdown.email.domain}</code>` : ''}`;
    }
}

/* ─────────────────────────────────────────────
   Company Registration Trust Card
   ─────────────────────────────────────────────*/
function renderCompanyTrustCard(company) {
    // Remove any existing card to re-render fresh
    const existing = document.getElementById('companyTrustCard');
    if (existing) existing.remove();

    if (!company || company.trustLevel === 'unknown') return;

    const trustColors = {
        'verified': { color: '#6ee7b7', bg: 'rgba(16,185,129,0.08)', border: 'rgba(16,185,129,0.3)', icon: '✅', label: 'VERIFIED COMPANY' },
        'likely-legit': { color: '#93c5fd', bg: 'rgba(59,130,246,0.08)', border: 'rgba(59,130,246,0.3)', icon: '🟢', label: 'LIKELY LEGITIMATE' },
        'unverified': { color: '#fcd34d', bg: 'rgba(245,158,11,0.07)', border: 'rgba(245,158,11,0.3)', icon: '⚠️', label: 'UNVERIFIED' },
        'suspicious': { color: '#fdba74', bg: 'rgba(239,68,68,0.07)', border: 'rgba(239,68,68,0.3)', icon: '🔴', label: 'SUSPICIOUS NAME' },
        'likely-fake': { color: '#fca5a5', bg: 'rgba(239,68,68,0.12)', border: 'rgba(239,68,68,0.5)', icon: '🚨', label: 'LIKELY FAKE' },
    };
    const t = trustColors[company.trustLevel] || trustColors['unverified'];

    let html = `<div id="companyTrustCard" style="margin-top:1.4rem;padding:1.2rem 1.4rem;background:${t.bg};border:1px solid ${t.border};border-radius:12px;animation:slideIn 0.4s ease;">`;
    html += `<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem;">`;
    html += `<div style="font-size:0.75rem;font-weight:700;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.07em;">🏢 Company Registration Analysis</div>`;
    html += `<span style="font-size:0.7rem;font-weight:700;padding:3px 12px;border-radius:100px;background:${t.bg};border:1px solid ${t.border};color:${t.color};letter-spacing:0.06em;">${t.icon} ${t.label}</span>`;
    html += `</div>`;

    // Flags
    if (company.flags.length > 0) {
        html += `<div style="display:flex;flex-direction:column;gap:6px;margin-bottom:1rem;">`;
        company.flags.forEach(f => {
            const fc = f.type === 'pass' ? '#6ee7b7' : f.type === 'fail' ? '#fca5a5' : f.type === 'warn' ? '#fcd34d' : '#93c5fd';
            html += `<div style="font-size:0.82rem;line-height:1.5;color:${fc};padding:5px 10px;background:rgba(255,255,255,0.03);border-radius:6px;border-left:2px solid ${fc};">${f.text}</div>`;
        });
        html += `</div>`;
    } else {
        html += `<div style="font-size:0.82rem;color:var(--text-muted);margin-bottom:1rem;">No company name provided — unable to verify registration status.</div>`;
    }

    // Verification Links
    if (company.suggestions && company.suggestions.length > 0) {
        html += `<div style="font-size:0.72rem;font-weight:700;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.07em;margin-bottom:0.5rem;">🔗 Verify Registration</div>`;
        html += `<div style="display:flex;flex-wrap:wrap;gap:6px;">`;
        const linkLabels = [
            { key: 'MCA', icon: '🏛️', color: '#93c5fd' },
            { key: 'LinkedIn', icon: '💼', color: '#60a5fa' },
            { key: 'Google', icon: '🔍', color: '#fcd34d' },
            { key: 'Glassdoor', icon: '⭐', color: '#6ee7b7' },
            { key: 'Startup India', icon: '🚀', color: '#c4b5fd' },
        ];
        company.suggestions.forEach(s => {
            const urlMatch = s.match(/https?:\/\/[^\s]+/);
            if (!urlMatch) return;
            const linkKey = linkLabels.find(l => s.includes(l.key));
            const label = linkKey ? `${linkKey.icon} ${linkKey.key}` : '🔗 Verify';
            const color = linkKey ? linkKey.color : '#93c5fd';
            html += `<a href="${urlMatch[0]}" target="_blank" rel="noopener" style="font-size:0.72rem;font-weight:600;padding:4px 12px;border-radius:100px;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.12);color:${color};text-decoration:none;transition:all 0.2s;" onmouseover="this.style.background='rgba(255,255,255,0.1)'" onmouseout="this.style.background='rgba(255,255,255,0.05)'">${label}</a>`;
        });
        html += `</div>`;
    }

    html += `</div>`;

    // Inject the card before the divider that precedes Flagged Keywords
    const flaggedTitle = Array.from(document.querySelectorAll('.kw-section-title')).find(el => el.textContent.includes('Flagged Keywords'));
    if (flaggedTitle) {
        const parent = flaggedTitle.closest('div')?.parentElement;
        if (parent) {
            parent.insertBefore(createElementFromHTML(html), flaggedTitle.closest('div'));
            return;
        }
    }
    // Fallback: append to result panel if injection point not found
    const panel = document.getElementById('resultPanel');
    if (panel) panel.insertAdjacentHTML('beforeend', html);
}

function createElementFromHTML(html) {
    const div = document.createElement('div');
    div.innerHTML = html.trim();
    return div.firstChild;
}

function renderBreakdownBar(id, score, cls) {
    const bar = document.getElementById(id);
    if (!bar) return;
    setTimeout(() => {
        bar.style.width = score + '%';
        const colors = { safe: 'var(--safe)', suspicious: 'var(--suspicious)', scam: 'var(--scam)' };
        bar.style.background = colors[cls] || 'var(--accent-blue)';
    }, 50);
}

/* ─────────────────────────────────────────────
   UI — Init
   ─────────────────────────────────────────────*/
document.addEventListener('DOMContentLoaded', () => {
    // Init speedometer tick marks
    initSpeedometer();

    // Navbar
    const navbar = document.querySelector('.navbar');
    if (navbar) {
        window.addEventListener('scroll', () => {
            navbar.classList.toggle('scrolled', window.scrollY > 20);
        }, { passive: true });
    }

    const analyzeBtn = document.getElementById('analyzeBtn');
    const spinner = document.getElementById('analyzeSpinner');
    const btnText = document.getElementById('analyzeBtnText');

    if (!analyzeBtn) return;

    /* ── Company DB Check Button ── */
    const checkCompanyBtn = document.getElementById('checkCompanyBtn');
    if (checkCompanyBtn) {
        checkCompanyBtn.addEventListener('click', () => checkCompanyDatabase());

        // Also trigger on Enter inside the company name input
        const companyInput = document.getElementById('companyName');
        if (companyInput) {
            companyInput.addEventListener('keydown', e => {
                if (e.key === 'Enter') { e.preventDefault(); checkCompanyDatabase(); }
            });
        }
    }

    async function checkCompanyDatabase() {
        const name = (document.getElementById('companyName')?.value || '').trim();
        const resultEl = document.getElementById('companyCheckResult');
        const btn = document.getElementById('checkCompanyBtn');
        if (!resultEl) return;

        if (!name) {
            resultEl.className = 'ccr-unverified';
            resultEl.style.display = 'block';
            resultEl.innerHTML = `<div class="ccr-header">⚠️ Please enter a company name first</div>`;
            return;
        }

        // Loading state
        btn.disabled = true;
        btn.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="animation:spin 0.7s linear infinite"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg> Checking…`;
        resultEl.className = 'ccr-loading';
        resultEl.style.display = 'block';
        resultEl.innerHTML = `<div class="ccr-header"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="animation:spin 0.7s linear infinite"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg> Checking "${name}" across databases…</div>`;

        // ── Step 1: Instant local analysis ──
        const local = analyzeCompanyName(name);

        // ── Step 2: Wikipedia API (checks if company has a Wikipedia article — reliable signal) ──
        let wikiResult = null;
        try {
            const wikiUrl = `https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(name)}`;
            const ctrl = new AbortController();
            setTimeout(() => ctrl.abort(), 5000);
            const res = await fetch(wikiUrl, { signal: ctrl.signal });
            if (res.ok) {
                const data = await res.json();
                if (data.type !== 'disambiguation' && data.extract) {
                    wikiResult = {
                        found: true,
                        title: data.title,
                        extract: data.extract.slice(0, 200),
                        url: data.content_urls?.desktop?.page || `https://en.wikipedia.org/wiki/${encodeURIComponent(name)}`,
                    };
                }
            }
        } catch (_) { }

        // ── Step 3: Open Corporates public search (free, no key) ──
        let openCorpResult = null;
        try {
            const ocUrl = `https://api.opencorporates.com/v0.4/companies/search?q=${encodeURIComponent(name)}&jurisdiction_code=in&per_page=3`;
            const ctrl2 = new AbortController();
            setTimeout(() => ctrl2.abort(), 6000);
            const res2 = await fetch(ocUrl, { signal: ctrl2.signal, headers: { 'Accept': 'application/json' } });
            if (res2.ok) {
                const data2 = await res2.json();
                const companies = data2?.results?.companies || [];
                if (companies.length > 0) {
                    const top = companies[0].company;
                    openCorpResult = {
                        found: true,
                        name: top.name,
                        number: top.company_number,
                        status: top.current_status,
                        jurisdiction: top.jurisdiction_code?.toUpperCase(),
                        incorporationDate: top.incorporation_date,
                        url: top.opencorporates_url,
                    };
                } else {
                    openCorpResult = { found: false };
                }
            }
        } catch (_) { }

        btn.disabled = false;
        btn.innerHTML = '🔎 Check DB';

        // ── Render result ──
        renderCompanyCheckResult(resultEl, name, local, wikiResult, openCorpResult);
    }

    function renderCompanyCheckResult(el, name, local, wiki, openCorp) {
        const trustMap = {
            'verified': { cls: 'ccr-verified', icon: '✅', badge: 'VERIFIED', title: 'Verified Company' },
            'likely-legit': { cls: 'ccr-legit', icon: '🟢', badge: 'LIKELY LEGIT', title: 'Likely Legitimate' },
            'unverified': { cls: 'ccr-unverified', icon: '⚠️', badge: 'UNVERIFIED', title: 'Unverified' },
            'suspicious': { cls: 'ccr-suspicious', icon: '🔴', badge: 'SUSPICIOUS', title: 'Suspicious Name' },
            'likely-fake': { cls: 'ccr-fake', icon: '🚨', badge: 'LIKELY FAKE', title: 'Likely Fake' },
        };

        // Upgrade trust level if external sources confirm the company
        let trust = local.trustLevel;
        if (wiki?.found && !local.isVerified) trust = trust === 'suspicious' ? 'unverified' : trust === 'unverified' ? 'likely-legit' : trust;
        if (openCorp?.found && openCorp.status?.toLowerCase().includes('active')) {
            trust = 'likely-legit';
            if (local.isVerified) trust = 'verified';
        }

        const t = trustMap[trust] || trustMap['unverified'];
        el.className = t.cls;
        el.style.display = 'block';

        let html = `<div class="ccr-header">${t.icon} <strong>${t.title}</strong> <span class="ccr-badge">${t.badge}</span></div>`;

        // — Open Corporates result (most authoritative) —
        if (openCorp?.found) {
            html += `<div class="ccr-flags">`;
            html += `<div class="ccr-flag">🏛️ <strong>Open Corporates:</strong> Found — <em>${openCorp.name}</em></div>`;
            if (openCorp.number) html += `<div class="ccr-flag">📋 Registration No: <code style="font-size:0.77rem;color:inherit;">${openCorp.number}</code></div>`;
            if (openCorp.status) html += `<div class="ccr-flag">🔵 Status: <strong>${openCorp.status}</strong></div>`;
            if (openCorp.jurisdiction) html += `<div class="ccr-flag">🌏 Jurisdiction: ${openCorp.jurisdiction}</div>`;
            if (openCorp.incorporationDate) html += `<div class="ccr-flag">📅 Incorporated: ${openCorp.incorporationDate}</div>`;
            html += `</div>`;
        } else if (openCorp?.found === false) {
            html += `<div class="ccr-flag" style="margin-bottom:6px;">🔍 Open Corporates: <em>No Indian company record found for this name</em></div>`;
        }

        // — Wikipedia result —
        if (wiki?.found) {
            html += `<div class="ccr-flag" style="margin-bottom:6px;">📖 <strong>Wikipedia:</strong> Article found — <em>${wiki.extract}…</em></div>`;
        } else if (wiki !== null) {
            html += `<div class="ccr-flag" style="margin-bottom:6px;">📖 Wikipedia: No article found for this company name</div>`;
        }

        // — Local analysis flags —
        if (local.flags.length > 0) {
            html += `<div class="ccr-flags">`;
            local.flags.forEach(f => { html += `<div class="ccr-flag">${f.text}</div>`; });
            html += `</div>`;
        }

        // — Verification links —
        const links = [
            { label: '🏛️ MCA21', url: `https://www.mca.gov.in/mcafoportal/viewCompanyMasterData.do` },
            { label: '🔍 Open Corp', url: openCorp?.url || `https://opencorporates.com/companies?q=${encodeURIComponent(name)}&jurisdiction_code=in` },
            { label: '💼 LinkedIn', url: `https://www.linkedin.com/company/${encodeURIComponent(name.split(' ')[0].toLowerCase())}` },
            { label: '⭐ Glassdoor', url: `https://www.glassdoor.co.in/Search/results.htm?keyword=${encodeURIComponent(name)}` },
            { label: '🔎 Google', url: `https://www.google.com/search?q=${encodeURIComponent('"' + name + '"')}+company+registration+review` },
        ];
        if (wiki?.found) links.unshift({ label: '📖 Wikipedia', url: wiki.url });

        html += `<div class="ccr-links">`;
        links.forEach(l => { html += `<a href="${l.url}" target="_blank" rel="noopener" class="ccr-link">${l.label}</a>`; });
        html += `</div>`;

        el.innerHTML = html;
    }

    analyzeBtn.addEventListener('click', async () => {
        const jobText = document.getElementById('jobText').value.trim();
        const companyUrl = document.getElementById('companyUrl').value.trim();
        const recruiterEmail = document.getElementById('recruiterEmail').value.trim();
        const companyName = document.getElementById('companyName').value.trim();

        if (!jobText) {
            document.getElementById('jobText').focus();
            document.getElementById('jobText').style.borderColor = 'var(--scam)';
            setTimeout(() => { document.getElementById('jobText').style.borderColor = ''; }, 2000);
            return;
        }

        // Loading state
        analyzeBtn.disabled = true;
        if (spinner) spinner.style.display = 'inline-block';
        if (btnText) btnText.textContent = 'Analyzing...';

        // ── Show radar animation ──
        const radarWrap = document.getElementById('analyzerRadarWrap');
        const emptyState = document.getElementById('emptyState');
        const resultPanel = document.getElementById('resultPanel');
        const radarLbl = document.getElementById('analyzerRadarLbl');
        if (radarWrap) radarWrap.style.display = 'flex';
        if (emptyState) emptyState.style.display = 'none';
        if (resultPanel) resultPanel.style.display = 'none';
        const azPhases = [
            'Scanning keywords and risk patterns…',
            'Analysing URL structure and domain…',
            'Checking recruiter email signals…',
            'Parsing content and grammar patterns…',
            'Verifying company name in trusted DB…',
            'Running composite AI scoring…',
            'Querying URLScan.io threat intel…',
            'Fetching live website content…',
            'Cross-referencing scam database…',
            'Computing final risk verdict…',
        ];
        let azPhaseIdx = 0;
        // Cycle every 800ms — all 10 labels step through in ~8 seconds
        const azPhaseTimer = setInterval(() => {
            azPhaseIdx = (azPhaseIdx + 1) % azPhases.length;
            if (radarLbl) radarLbl.textContent = azPhases[azPhaseIdx];
        }, 800);

        // ── Phase 1: Static analysis (instant)
        await new Promise(r => setTimeout(r, 400));
        const result = runDetection({ jobText, companyUrl, recruiterEmail, companyName });

        // ── Phase 2: Real-time checks (async, parallel)
        let parsed = null;
        try {
            const withProto = companyUrl.startsWith('http') ? companyUrl : 'https://' + companyUrl;
            parsed = new URL(withProto);
        } catch (_) { }
        const hostname = parsed ? parsed.hostname : null;

        // Known scam DB (instant, local)
        const dbMatches = checkKnownScamDB(hostname, companyName, recruiterEmail);
        if (dbMatches.length > 0) {
            result.breakdown.url.flags.push(...dbMatches.map(m => m.text));
            result.breakdown.url.score = Math.min(result.breakdown.url.score + dbMatches.length * 20, 100);
            // Recompute composite with new URL score (5-weight formula)
            const W1 = { keywords: 0.35, url: 0.18, email: 0.18, text: 0.18, company: 0.11 };
            const cs1 = result.breakdown.company?.isVerified ? 0 : (result.breakdown.company?.score || 0);
            result.composite = Math.min(Math.round(
                result.breakdown.keywords.score * W1.keywords +
                result.breakdown.url.score * W1.url +
                result.breakdown.email.score * W1.email +
                result.breakdown.text.score * W1.text +
                cs1 * W1.company
            ), 100);
            result.verdict = classify(result.composite);
        }

        // ── Wait for BOTH: hard 8-second minimum AND all network checks ──
        // Network calls run in parallel with the timer; whichever takes longer wins.
        const radarMinMs = 8000;
        const [webInfo, urlscanData] = await Promise.all([
            companyUrl ? fetchWebsiteInfo(companyUrl) : Promise.resolve(null),
            hostname ? checkURLScanIO(hostname) : Promise.resolve(null),
            new Promise(r => setTimeout(r, radarMinMs)), // 8-second floor
        ]).then(([wi, ui]) => [wi, ui]);

        // ── Flash "complete", then hide radar ──
        clearInterval(azPhaseTimer);
        if (radarLbl) radarLbl.textContent = '✅ Analysis complete!';
        await new Promise(r => setTimeout(r, 350));   // brief "done" flash
        if (radarWrap) radarWrap.style.display = 'none';

        // Merge website content score back into result
        if (webInfo && webInfo.fetched && webInfo.contentScore > 0) {
            result.breakdown.website = webInfo;
            result.breakdown.url.score = Math.min(result.breakdown.url.score + Math.round(webInfo.contentScore * 0.3), 100);
            webInfo.contentFlags.forEach(f => result.breakdown.url.flags.push('(Web) ' + f));
            const W2 = { keywords: 0.35, url: 0.18, email: 0.18, text: 0.18, company: 0.11 };
            const cs2 = result.breakdown.company?.isVerified ? 0 : (result.breakdown.company?.score || 0);
            result.composite = Math.min(Math.round(
                result.breakdown.keywords.score * W2.keywords +
                result.breakdown.url.score * W2.url +
                result.breakdown.email.score * W2.email +
                result.breakdown.text.score * W2.text +
                cs2 * W2.company
            ), 100);
            result.verdict = classify(result.composite);
        }

        // Render results (with full merged scores including web/urlscan)
        renderResults(result);
        renderWebsiteScanPanel(webInfo, urlscanData, dbMatches, hostname);

        analyzeBtn.disabled = false;
        if (spinner) spinner.style.display = 'none';
        if (btnText) btnText.textContent = '🔍 Analyze Now';
    });

    // Sample scam filler
    const sampleScamBtn = document.getElementById('sampleScamBtn');
    if (sampleScamBtn) {
        sampleScamBtn.addEventListener('click', () => {
            document.getElementById('jobText').value = `URGENT HIRING!! Guaranteed internship placement — 100% job guarantee!\n\nEarn ₹50,000 per month from the comfort of your home. NO EXPERIENCE REQUIRED. No interviews needed!\n\nWe are a top MNC hiring for LIMITED SEATS. Apply IMMEDIATELY before offers close!\n\nNote: A refundable registration fee of ₹4,999 is required. Send your Aadhaar card and bank account details to hr@gmail.com after payment via wire transfer.\n\nContact us on WhatsApp: +91-9XXXXXXXXX\nVisit: http://bit.ly/internship-2024-apply\n\nDon't miss this EASY MONEY opportunity!!!`;
            document.getElementById('companyUrl').value = 'http://bit.ly/internship-2024-apply';
            document.getElementById('recruiterEmail').value = 'hr@gmail.com';
            document.getElementById('companyName').value = 'TopMNC Solutions Pvt Ltd';
        });
    }

    // Sample legit filler
    const sampleLegitBtn = document.getElementById('sampleLegitBtn');
    if (sampleLegitBtn) {
        sampleLegitBtn.addEventListener('click', () => {
            document.getElementById('jobText').value = `Software Engineering Intern — Infosys Limited\n\nWe are looking for a motivated Software Engineering Intern to join our Bangalore office for a 6-month internship program.\n\nResponsibilities:\n- Assist in developing and testing web applications using React and Node.js\n- Collaborate with senior engineers in code reviews\n- Participate in agile sprint planning and daily standups\n\nRequirements:\n- Pursuing B.Tech / B.E. in Computer Science or related field\n- Basic knowledge of JavaScript, HTML, CSS\n- Strong problem-solving skills\n\nStipend: ₹15,000 per month\nDuration: 6 months\nLocation: Bangalore, Karnataka\n\nTo apply, send your resume to campus@infosys.com\nVisit: https://www.infosys.com/careers/`;
            document.getElementById('companyUrl').value = 'https://www.infosys.com/careers/';
            document.getElementById('recruiterEmail').value = 'campus@infosys.com';
            document.getElementById('companyName').value = 'Infosys Limited';
        });
    }

    // Clear button
    const clearBtn = document.getElementById('clearBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            document.getElementById('jobText').value = '';
            document.getElementById('companyUrl').value = '';
            document.getElementById('recruiterEmail').value = '';
            document.getElementById('companyName').value = '';
            const panel = document.getElementById('resultPanel');
            if (panel) panel.style.display = 'none';
            const emptyState = document.getElementById('emptyState');
            if (emptyState) emptyState.style.display = 'flex';
        });
    }

    // ── Standalone "Scan Website" button ──
    const scanWebBtn = document.getElementById('scanWebBtn');
    if (scanWebBtn) {
        scanWebBtn.addEventListener('click', async () => {
            const url = document.getElementById('companyUrl').value.trim();
            if (!url) { document.getElementById('companyUrl').focus(); return; }
            scanWebBtn.disabled = true;
            scanWebBtn.textContent = '⏳ Scanning…';
            showWebsiteScanLoading('Scanning website…');
            let hostname = null;
            try { hostname = new URL(url.startsWith('http') ? url : 'https://' + url).hostname; } catch (_) { }
            const [webInfo, urlscanData] = await Promise.all([
                fetchWebsiteInfo(url),
                hostname ? checkURLScanIO(hostname) : Promise.resolve(null),
            ]);
            const dbMatches = checkKnownScamDB(hostname, '', '');
            renderWebsiteScanPanel(webInfo, urlscanData, dbMatches, hostname);
            scanWebBtn.disabled = false;
            scanWebBtn.textContent = '🌐 Scan Website';
        });
    }
});

/* ─────────────────────────────────────────────
   REAL-TIME UI: Website Scan Panel Rendering
   ─────────────────────────────────────────────*/
function showWebsiteScanLoading(message) {
    const el = document.getElementById('websiteScanPanel');
    if (!el) return;
    el.style.display = 'block';
    if (!message) { el.style.display = 'none'; return; }
    el.innerHTML = `
    <div class="ws-loading">
      <div class="ws-spinner"></div>
      <span>${message}</span>
    </div>`;
}

function renderWebsiteScanPanel(webInfo, urlscanData, dbMatches, hostname) {
    const el = document.getElementById('websiteScanPanel');
    if (!el) return;

    if (!webInfo && !urlscanData && (!dbMatches || dbMatches.length === 0)) {
        el.style.display = 'none';
        return;
    }
    el.style.display = 'block';

    // ── DB matches ──
    let dbHtml = '';
    if (dbMatches && dbMatches.length > 0) {
        dbHtml = `<div class="ws-section">
      <div class="ws-section-title">🗄️ Known Scam Database</div>
      ${dbMatches.map(m => `<div class="ws-flag ws-flag-high">🚨 ${m.text}</div>`).join('')}
    </div>`;
    } else if (hostname) {
        dbHtml = `<div class="ws-section">
      <div class="ws-section-title">🗄️ Known Scam Database</div>
      <div class="ws-flag ws-flag-safe">✅ Domain not found in scam database</div>
    </div>`;
    }

    // ── URLScan.io ──
    let urlscanHtml = '';
    if (urlscanData) {
        if (urlscanData.error) {
            urlscanHtml = `<div class="ws-section">
        <div class="ws-section-title">🔬 URLScan.io Threat Intel</div>
        <div class="ws-flag ws-flag-neutral">⚠️ Could not reach URLScan.io: ${urlscanData.error}</div>
      </div>`;
        } else {
            const malTag = urlscanData.malicious
                ? `<span class="ws-badge ws-badge-danger">🚨 MALICIOUS</span>`
                : `<span class="ws-badge ws-badge-safe">✅ Clean</span>`;
            urlscanHtml = `<div class="ws-section">
        <div class="ws-section-title">🔬 URLScan.io Threat Intel ${malTag}</div>
        <div class="ws-meta-grid">
          <div class="ws-meta-item"><div class="ws-meta-label">Total Scans Found</div><div class="ws-meta-val">${urlscanData.scans}</div></div>
          <div class="ws-meta-item"><div class="ws-meta-label">Malicious Reports</div><div class="ws-meta-val" style="color:${urlscanData.malicious ? 'var(--scam)' : 'var(--safe)'}">${urlscanData.verdicts.filter(v => v.malicious).length}</div></div>
        </div>
        ${urlscanData.verdicts.length > 0 ? `<div class="ws-section-title" style="margin-top:0.8rem">Recent Scans</div>
        ${urlscanData.verdicts.map(v => `<div class="ws-flag ${v.malicious ? 'ws-flag-high' : 'ws-flag-safe'}">${v.malicious ? '🚨' : '✅'} ${v.date} — Score: ${v.score}${v.tags.length ? ` [${v.tags.join(', ')}]` : ''}</div>`).join('')}` : ''}
        <a href="https://urlscan.io/search/#domain:${hostname}" target="_blank" rel="noopener" class="ws-link">View full report on urlscan.io →</a>
      </div>`;
        }
    }

    // ── Website Content ──
    let webHtml = '';
    if (webInfo) {
        if (webInfo.error && !webInfo.fetched) {
            webHtml = `<div class="ws-section">
        <div class="ws-section-title">🌐 Website Content Scan</div>
        <div class="ws-flag ws-flag-neutral">ℹ️ Could not fetch website: ${webInfo.error}</div>
      </div>`;
        } else if (webInfo.fetched) {
            const sslBadge = webInfo.hasSSL
                ? `<span class="ws-badge ws-badge-safe">🔒 HTTPS</span>`
                : `<span class="ws-badge ws-badge-danger">⚠️ No HTTPS</span>`;
            webHtml = `<div class="ws-section">
        <div class="ws-section-title">🌐 Website Content Scan ${sslBadge}</div>
        <div class="ws-meta-grid">
          <div class="ws-meta-item"><div class="ws-meta-label">Page Title</div><div class="ws-meta-val">${webInfo.title || '(none)'}</div></div>
          <div class="ws-meta-item"><div class="ws-meta-label">Outbound Links</div><div class="ws-meta-val">${webInfo.links.length}</div></div>
          <div class="ws-meta-item"><div class="ws-meta-label">Suspicious Scripts</div><div class="ws-meta-val" style="color:${webInfo.suspiciousScripts.length ? 'var(--suspicious)' : 'var(--safe)'}">${webInfo.suspiciousScripts.length}</div></div>
          <div class="ws-meta-item"><div class="ws-meta-label">Hidden Forms</div><div class="ws-meta-val" style="color:${webInfo.hiddenForms ? 'var(--suspicious)' : 'var(--safe)'}">${webInfo.hiddenForms ? '⚠️ Detected' : '✅ None'}</div></div>
        </div>
        ${webInfo.description ? `<div class="ws-description">📝 <em>${webInfo.description.slice(0, 200)}</em></div>` : ''}
        ${webInfo.contentFlags.length > 0 ? webInfo.contentFlags.map(f => `<div class="ws-flag ws-flag-high">🚨 ${f}</div>`).join('') : '<div class="ws-flag ws-flag-safe">✅ No suspicious content patterns detected</div>'}
      </div>`;
        }
    }

    el.innerHTML = `
    <div class="ws-header">🔬 Real-Time Website Analysis</div>
    ${dbHtml}${urlscanHtml}${webHtml}
  `;
}
