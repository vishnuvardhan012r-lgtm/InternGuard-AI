/* ============================================================
   InternGuard Reputation Shield™ — Core Engine
   Version 1.0 | 2026
   ============================================================ */

'use strict';

/* ─── Seeded Scam Database ──────────────────────────────── */
const SCAM_DATABASE = [
  {
    id: 'sc001',
    companyName: 'TechVision Pvt Ltd',
    domain: 'techvision-internships.com',
    recruiterEmails: ['hr@techvision-internships.com', 'recruiter.techvision@gmail.com'],
    phones: ['9876543210', '8765432109'],
    upiIds: ['techvision.hr@paytm', 'tv.hrpay@okaxis'],
    domainAgeDays: 18,
    psychManipulation: true,
    reports: [
      { date: '2026-02-20', verified: true,  proofUploaded: true,  flags: ['upfront_payment','fake_offer_letter','upi_transfer'], credibility: 0.9 },
      { date: '2026-02-21', verified: true,  proofUploaded: true,  flags: ['upfront_payment','impersonation'],                    credibility: 0.85 },
      { date: '2026-02-22', verified: false, proofUploaded: false, flags: ['upfront_payment'],                                    credibility: 0.5 },
      { date: '2026-02-23', verified: true,  proofUploaded: true,  flags: ['upfront_payment','aadhaar_request'],                  credibility: 0.88 },
      { date: '2026-02-24', verified: false, proofUploaded: false, flags: ['urgency_pressure'],                                   credibility: 0.4 },
      { date: '2026-02-25', verified: true,  proofUploaded: true,  flags: ['upfront_payment','fake_offer_letter'],                credibility: 0.92 },
      { date: '2026-02-26', verified: true,  proofUploaded: false, flags: ['upfront_payment'],                                    credibility: 0.75 },
      { date: '2026-02-27', verified: true,  proofUploaded: true,  flags: ['upfront_payment','upi_transfer'],                    credibility: 0.95 },
    ],
    cluster: 'cluster_upi_paytm_01'
  },
  {
    id: 'sc002',
    companyName: 'NextGen Career Hub',
    domain: 'nextgencareerhub.in',
    recruiterEmails: ['jobs@nextgencareerhub.in', 'ngcareers@gmail.com'],
    phones: ['7654321098'],
    upiIds: ['ngcareers@paytm'],
    domainAgeDays: 45,
    psychManipulation: true,
    reports: [
      { date: '2026-01-15', verified: true,  proofUploaded: true,  flags: ['upfront_payment','impersonation'],       credibility: 0.9 },
      { date: '2026-01-18', verified: false, proofUploaded: false, flags: ['upfront_payment'],                        credibility: 0.5 },
      { date: '2026-01-22', verified: true,  proofUploaded: true,  flags: ['upfront_payment','fake_offer_letter'],    credibility: 0.85 },
      { date: '2026-02-01', verified: true,  proofUploaded: false, flags: ['aadhaar_request'],                        credibility: 0.7 },
      { date: '2026-02-10', verified: true,  proofUploaded: true,  flags: ['upfront_payment'],                        credibility: 0.88 },
    ],
    cluster: 'cluster_upi_paytm_01'
  },
  {
    id: 'sc003',
    companyName: 'Global IT Solutions LLP',
    domain: 'globalitsolutions-careers.co',
    recruiterEmails: ['career@globalitsolutions-careers.co', 'globalit.hire@gmail.com'],
    phones: ['9988776655', '8811223344'],
    upiIds: ['globalit.careers@ybl'],
    domainAgeDays: 12,
    psychManipulation: true,
    reports: [
      { date: '2026-02-24', verified: true,  proofUploaded: true,  flags: ['upfront_payment','upi_transfer','fake_offer_letter'], credibility: 0.95 },
      { date: '2026-02-25', verified: true,  proofUploaded: true,  flags: ['upfront_payment'],                                     credibility: 0.9  },
      { date: '2026-02-25', verified: false, proofUploaded: false, flags: ['urgency_pressure'],                                    credibility: 0.45 },
      { date: '2026-02-26', verified: true,  proofUploaded: true,  flags: ['upfront_payment','impersonation'],                     credibility: 0.88 },
      { date: '2026-02-27', verified: true,  proofUploaded: true,  flags: ['upfront_payment','aadhaar_request'],                   credibility: 0.92 },
      { date: '2026-02-27', verified: true,  proofUploaded: true,  flags: ['upfront_payment'],                                     credibility: 0.85 },
      { date: '2026-02-28', verified: true,  proofUploaded: true,  flags: ['upfront_payment','upi_transfer'],                      credibility: 0.97 },
    ],
    cluster: 'cluster_domain_new_01'
  },
  {
    id: 'sc004',
    companyName: 'SkillUp Pro Academy',
    domain: 'skilluppro-internship.xyz',
    recruiterEmails: ['intern@skilluppro-internship.xyz'],
    phones: ['6543210987'],
    upiIds: ['skilluppay@okicici'],
    domainAgeDays: 22,
    psychManipulation: false,
    reports: [
      { date: '2026-02-15', verified: true,  proofUploaded: false, flags: ['upfront_payment'],              credibility: 0.7  },
      { date: '2026-02-16', verified: false, proofUploaded: false, flags: ['upfront_payment'],              credibility: 0.4  },
      { date: '2026-02-18', verified: true,  proofUploaded: true,  flags: ['upfront_payment','upi_transfer'], credibility: 0.85 },
    ],
    cluster: 'cluster_domain_xyz_01'
  },
  {
    id: 'sc005',
    companyName: 'FutureTech Internships',
    domain: 'futuretechinternship.online',
    recruiterEmails: ['apply@futuretechinternship.online', 'futuretech.hr@gmail.com'],
    phones: ['9123456780'],
    upiIds: ['futuretech@paytm'],
    domainAgeDays: 8,
    psychManipulation: true,
    reports: [
      { date: '2026-02-26', verified: true,  proofUploaded: true,  flags: ['upfront_payment','fake_offer_letter','upi_transfer'], credibility: 0.95 },
      { date: '2026-02-27', verified: true,  proofUploaded: true,  flags: ['upfront_payment','impersonation'],                     credibility: 0.9  },
      { date: '2026-02-28', verified: true,  proofUploaded: true,  flags: ['upfront_payment'],                                     credibility: 0.88 },
    ],
    cluster: 'cluster_domain_new_01'
  },
  {
    id: 'sc006',
    companyName: 'InfoSys Career Bridge',
    domain: 'infosys-careerbridge.com',
    recruiterEmails: ['info@infosys-careerbridge.com'],
    phones: ['8899001122'],
    upiIds: ['isysbridge@ybl'],
    domainAgeDays: 60,
    psychManipulation: false,
    reports: [
      { date: '2026-01-05', verified: true,  proofUploaded: true,  flags: ['impersonation','fake_offer_letter'], credibility: 0.9  },
      { date: '2026-01-07', verified: true,  proofUploaded: false, flags: ['impersonation'],                     credibility: 0.75 },
      { date: '2026-01-10', verified: false, proofUploaded: false, flags: ['upfront_payment'],                   credibility: 0.5  },
    ],
    cluster: 'cluster_impersonation_01'
  },
  {
    id: 'sc007',
    companyName: 'TCS Talent Connect',
    domain: 'tcs-talentconnect.net',
    recruiterEmails: ['hr@tcs-talentconnect.net', 'tcstalent@gmail.com'],
    phones: ['7788990011'],
    upiIds: ['tcshiring@okhdfc'],
    domainAgeDays: 35,
    psychManipulation: true,
    reports: [
      { date: '2026-02-10', verified: true,  proofUploaded: true,  flags: ['impersonation','upfront_payment'],    credibility: 0.92 },
      { date: '2026-02-12', verified: true,  proofUploaded: true,  flags: ['impersonation','fake_offer_letter'],   credibility: 0.88 },
      { date: '2026-02-14', verified: false, proofUploaded: false, flags: ['upfront_payment'],                     credibility: 0.45 },
      { date: '2026-02-20', verified: true,  proofUploaded: false, flags: ['urgency_pressure'],                    credibility: 0.7  },
    ],
    cluster: 'cluster_impersonation_01'
  },
  {
    id: 'sc008',
    companyName: 'Digital Dream Internship Hub',
    domain: 'digitaldream-internhub.in',
    recruiterEmails: ['contact@digitaldream-internhub.in'],
    phones: ['9000111222'],
    upiIds: ['ddhub@paytm'],
    domainAgeDays: 90,
    psychManipulation: false,
    reports: [
      { date: '2026-01-20', verified: false, proofUploaded: false, flags: ['upfront_payment'], credibility: 0.45 },
      { date: '2026-01-25', verified: false, proofUploaded: false, flags: ['upfront_payment'], credibility: 0.4  },
    ],
    cluster: null
  }
];

/* ─── Flag Labels ───────────────────────────────────────── */
const FLAG_LABELS = {
  upfront_payment:   '💰 Upfront Payment Demanded',
  upi_transfer:      '📱 UPI Transfer Requested',
  fake_offer_letter: '📄 Fake Offer Letter',
  impersonation:     '🎭 Impersonating Known Company',
  aadhaar_request:   '🪪 Aadhaar / PAN Collected',
  urgency_pressure:  '⏰ Urgency / Pressure Tactics',
  bank_details:      '🏦 Bank Details Collected',
  whatsapp_only:     '📲 WhatsApp/Telegram Only Contact',
};

/* ─── Levenshtein Distance ──────────────────────────────── */
function levenshtein(a, b) {
  a = a.toLowerCase().trim();
  b = b.toLowerCase().trim();
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

/* ─── Normalize Domain ──────────────────────────────────── */
function normalizeDomain(str) {
  return str.toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0].trim();
}

/* ─── Normalize String ──────────────────────────────────── */
function normalizeStr(s) {
  return (s || '').toLowerCase().replace(/[^a-z0-9]/g, '').trim();
}

/* ─── Fuzzy Match Entry Against Query ──────────────────── */
function matchEntry(entry, query) {
  const q = query.trim();
  if (!q) return { matched: false, matchType: null, score: 0 };

  const qNorm      = normalizeStr(q);
  const qDomain    = normalizeDomain(q);
  const nameNorm   = normalizeStr(entry.companyName);

  // Exact domain match
  if (normalizeDomain(entry.domain) === qDomain) {
    return { matched: true, matchType: 'domain', score: 1 };
  }
  // Domain substring
  if (normalizeDomain(entry.domain).includes(qDomain) && qDomain.length > 5) {
    return { matched: true, matchType: 'domain_partial', score: 0.85 };
  }
  // Email match
  if (entry.recruiterEmails.some(e => normalizeStr(e) === qNorm || e.toLowerCase().includes(q.toLowerCase()))) {
    return { matched: true, matchType: 'email', score: 1 };
  }
  // UPI match
  if (entry.upiIds.some(u => normalizeStr(u) === qNorm || u.toLowerCase().includes(q.toLowerCase()))) {
    return { matched: true, matchType: 'upi', score: 1 };
  }
  // Phone match
  if (entry.phones.some(p => p.replace(/\D/g,'').includes(q.replace(/\D/,'')))) {
    return { matched: true, matchType: 'phone', score: 1 };
  }
  // Exact company name match
  if (nameNorm === qNorm) {
    return { matched: true, matchType: 'company_exact', score: 1 };
  }
  // Company name contains query
  if (nameNorm.includes(qNorm) && qNorm.length > 4) {
    return { matched: true, matchType: 'company_partial', score: 0.9 };
  }
  // Fuzzy company name match (Levenshtein)
  const dist = levenshtein(entry.companyName, q);
  const maxLen = Math.max(entry.companyName.length, q.length);
  const similarity = 1 - dist / maxLen;
  if (similarity >= 0.65) {
    return { matched: true, matchType: 'fuzzy', score: similarity };
  }

  return { matched: false, matchType: null, score: 0 };
}

/* ─── Weighted Scoring Engine ───────────────────────────── */
function computeScore(entry) {
  let score = 0;

  for (const r of entry.reports) {
    const weight = r.credibility || 0.5;
    if (r.verified) {
      score += 10 * weight;
    } else {
      score += 3 * weight;
    }
    if (r.proofUploaded)               score += 20 * weight;
    if (r.flags.includes('upi_transfer')) score += 15 * weight;
  }

  if (entry.domainAgeDays !== null && entry.domainAgeDays < 30) score += 25;
  if (entry.psychManipulation)                                   score += 30;

  return Math.round(score);
}

/* ─── Classify Score ────────────────────────────────────── */
function classify(score) {
  if (score <= 30) return { label: 'Safe',         emoji: '🟢', cls: 'safe',        confidence: Math.min(30, score) };
  if (score <= 70) return { label: 'Suspicious',   emoji: '🟡', cls: 'suspicious',  confidence: score };
  return               { label: 'Scam Likely',   emoji: '🔴', cls: 'scam',        confidence: Math.min(99, score) };
}

/* ─── Surge Detection (7-day vs prior 7-day) ───────────── */
function detectSurge(reports) {
  const now = new Date('2026-02-28');
  const msPer7Days = 7 * 24 * 60 * 60 * 1000;
  const recent = reports.filter(r => {
    const d = new Date(r.date);
    return (now - d) <= msPer7Days;
  }).length;
  const prior = reports.filter(r => {
    const d = new Date(r.date);
    const diff = now - d;
    return diff > msPer7Days && diff <= 2 * msPer7Days;
  }).length;
  return { recent, prior, isSurge: recent > 0 && (prior === 0 ? recent >= 3 : recent >= prior * 2) };
}

/* ─── Flag Analysis ─────────────────────────────────────── */
function analyzeFlags(reports) {
  const total = reports.length;
  if (total === 0) return {};
  const counts = {};
  for (const r of reports) {
    for (const f of r.flags) {
      counts[f] = (counts[f] || 0) + 1;
    }
  }
  const result = {};
  for (const [flag, count] of Object.entries(counts)) {
    result[flag] = Math.round((count / total) * 100);
  }
  return result;
}

/* ─── Find Similar Clusters ─────────────────────────────── */
function findClusters(entry, allEntries) {
  if (!entry.cluster) return 0;
  return allEntries.filter(e => e.cluster === entry.cluster && e.id !== entry.id).length;
}

/* ─── Load User Reports from localStorage ───────────────── */
function loadUserReports() {
  try {
    return JSON.parse(localStorage.getItem('internguard_reports') || '[]');
  } catch { return []; }
}

/* ─── Save User Report to localStorage ─────────────────── */
function saveUserReport(report) {
  const reports = loadUserReports();
  reports.unshift(report);
  localStorage.setItem('internguard_reports', JSON.stringify(reports.slice(0, 200)));
}

/* ─── Merge User Reports into DB ────────────────────────── */
function getMergedDatabase() {
  const userReports = loadUserReports();
  const db = JSON.parse(JSON.stringify(SCAM_DATABASE)); // deep clone

  for (const ur of userReports) {
    // Try to find an existing entry to merge into
    const existing = db.find(e => {
      const nameDist = levenshtein(e.companyName, ur.companyName || '');
      const nameMatch = nameDist <= 3;
      const domainMatch = ur.domain && normalizeDomain(e.domain) === normalizeDomain(ur.domain);
      const emailMatch  = ur.email  && e.recruiterEmails.some(em => em.toLowerCase() === ur.email.toLowerCase());
      const upiMatch    = ur.upiId  && e.upiIds.some(u => u.toLowerCase() === ur.upiId.toLowerCase());
      const phoneMatch  = ur.phone  && e.phones.some(p => p === ur.phone);
      return nameMatch || domainMatch || emailMatch || upiMatch || phoneMatch;
    });

    const reportObj = {
      date: ur.date || new Date().toISOString().split('T')[0],
      verified: false,
      proofUploaded: ur.proofUploaded || false,
      flags: ur.flags || [],
      credibility: ur.proofUploaded ? 0.6 : 0.4
    };

    if (existing) {
      existing.reports.push(reportObj);
      if (ur.upiId && !existing.upiIds.includes(ur.upiId)) existing.upiIds.push(ur.upiId);
      if (ur.email && !existing.recruiterEmails.includes(ur.email)) existing.recruiterEmails.push(ur.email);
      if (ur.phone && !existing.phones.includes(ur.phone)) existing.phones.push(ur.phone);
    } else {
      // Create new entry from user report
      db.push({
        id: 'user_' + Date.now() + Math.random(),
        companyName: ur.companyName || 'Unknown Company',
        domain: ur.domain || '',
        recruiterEmails: ur.email ? [ur.email] : [],
        phones: ur.phone ? [ur.phone] : [],
        upiIds: ur.upiId ? [ur.upiId] : [],
        domainAgeDays: null,
        psychManipulation: ur.flags && ur.flags.includes('urgency_pressure'),
        reports: [reportObj],
        cluster: null
      });
    }
  }
  return db;
}

/* ─── Main Search Function ──────────────────────────────── */
function searchReputation(query) {
  if (!query || query.trim().length < 2) return null;
  const db = getMergedDatabase();
  let bestEntry = null, bestMatchScore = 0, bestMatchType = null;

  for (const entry of db) {
    const { matched, matchType, score } = matchEntry(entry, query);
    if (matched && score > bestMatchScore) {
      bestEntry     = entry;
      bestMatchScore = score;
      bestMatchType = matchType;
    }
  }

  if (!bestEntry) return { found: false, query };

  const reputationScore  = computeScore(bestEntry);
  const classification   = classify(reputationScore);
  const surge            = detectSurge(bestEntry.reports);
  const flagAnalysis     = analyzeFlags(bestEntry.reports);
  const similarClusters  = findClusters(bestEntry, db);
  const firstReport      = bestEntry.reports.reduce((min, r) => r.date < min ? r.date : min, bestEntry.reports[0]?.date || '—');
  const topFlags         = Object.entries(flagAnalysis).sort((a, b) => b[1] - a[1]).slice(0, 4);
  const verifiedCount    = bestEntry.reports.filter(r => r.verified).length;

  return {
    found: true,
    entry: bestEntry,
    query,
    matchType:        bestMatchType,
    reputationScore,
    classification,
    surge,
    flagAnalysis,
    topFlags,
    totalReports:     bestEntry.reports.length,
    verifiedReports:  verifiedCount,
    firstReport,
    similarClusters,
    paymentPercent:   flagAnalysis.upfront_payment || 0,
  };
}

/* ─── Get Recent Community Reports ─────────────────────── */
function getRecentCommunityReports(limit = 6) {
  const db = getMergedDatabase();
  const userRaw = loadUserReports();

  // Seeded entries ordered by most recent report
  const seeded = SCAM_DATABASE.map(e => {
    const score = computeScore(e);
    const cls   = classify(score);
    const latest = e.reports.reduce((max, r) => r.date > max ? r.date : max, '');
    const surge  = detectSurge(e.reports);
    return { name: e.companyName, score, cls, latest, reports: e.reports.length, surge, isUser: false };
  }).sort((a, b) => b.latest.localeCompare(a.latest));

  // User submitted
  const userEntries = userRaw.slice(0, 3).map(ur => ({
    name: ur.companyName || 'Unknown',
    score: 30,
    cls: classify(30),
    latest: ur.date || '',
    reports: 1,
    surge: { isSurge: false },
    isUser: true
  }));

  return [...userEntries, ...seeded].slice(0, limit);
}

/* ─── Submit New Report ─────────────────────────────────── */
function submitReport(formData) {
  const today = new Date().toISOString().split('T')[0];
  const report = {
    companyName:   formData.companyName   || '',
    domain:        formData.domain        || '',
    email:         formData.email         || '',
    phone:         formData.phone         || '',
    upiId:         formData.upiId         || '',
    flags:         formData.flags         || [],
    proofUploaded: !!formData.proofUploaded,
    description:   formData.description  || '',
    date: today
  };
  saveUserReport(report);
  return true;
}

/* ─── Format Date ───────────────────────────────────────── */
function formatDate(dateStr) {
  if (!dateStr || dateStr === '—') return '—';
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
}

/* Expose to global scope */
window.ReputationEngine = {
  search: searchReputation,
  submit: submitReport,
  getRecentReports: getRecentCommunityReports,
  FLAG_LABELS,
  formatDate,
  classify,
};
