/* =============================================
   InternGuard-AI — chatbot.js
   AI Assistant for Internship Scam Education
   ============================================= */

(function () {
    'use strict';

    /* ── Knowledge Base ──────────────────────── */
    const KB = [
        {
            patterns: ['hi', 'hello', 'hey', 'good morning', 'good afternoon', 'good evening', 'howdy', 'greetings'],
            response: () => `👋 Hello! I'm **InternGuard AI**, your personal internship fraud detection assistant.<br><br>I can help you with:<br>• 🔍 Spotting red flags in job offers<br>• 📧 Verifying recruiter emails<br>• 💡 Understanding scam tactics<br>• 🔗 Checking suspicious URLs<br><br>What would you like help with today?`,
        },
        {
            patterns: ['what can you do', 'help', 'capabilities', 'features', 'what do you do', 'how can you help'],
            response: () => `Here's what I can help you with:<br><br>🔎 <strong>Scam Detection</strong> — Identify fake internship postings<br>📧 <strong>Email Verification</strong> — Spot suspicious recruiter contacts<br>🔗 <strong>URL Analysis</strong> — Check if a company website is legitimate<br>💰 <strong>Fee Warnings</strong> — Any internship asking for money is a scam<br>📋 <strong>Red Flag Education</strong> — Learn what to watch out for<br><br>Ask me about any internship concern!`,
        },
        {
            patterns: ['registration fee', 'pay fee', 'charging fee', 'asking money', 'upfront fee', 'deposit', 'pay to apply', 'security deposit', 'training fee'],
            response: () => `🚨 <strong>This is almost certainly a SCAM!</strong><br><br>Legitimate companies <strong>never charge</strong> candidates money to apply, get selected, or start an internship.<br><br>Common fee scams include:<br>• "Registration fee" — ₹500 to ₹5,000<br>• "Training material" charges<br>• "Security deposit" requests<br>• "ID verification" fees<br><br><strong>Rule of thumb:</strong> If they ask for money, walk away immediately and report it. 🛑`,
        },
        {
            patterns: ['guaranteed placement', 'guaranteed job', '100% placement', 'guaranteed offer', 'guaranteed internship'],
            response: () => `⚠️ <strong>"Guaranteed" is a major red flag!</strong><br><br>No legitimate company can guarantee you a job or internship before even reviewing your skills. This language is used to create false urgency and excitement.<br><br>Scammers use it to:<br>• Lower your guard<br>• Justify charging fees ("guaranteed, so worth paying")<br>• Create pressure to act fast<br><br>Always verify the company on <strong>LinkedIn</strong> or <strong>Glassdoor</strong> before proceeding.`,
        },
        {
            patterns: ['aadhaar', 'pan card', 'bank account', 'bank details', 'personal details', 'sensitive information', 'ssn', 'passport'],
            response: () => `🚨 <strong>STOP — do NOT share these documents!</strong><br><br>Legitimate recruiters <strong>never</strong> ask for Aadhaar, PAN, or banking details during the application stage. This is identity theft in disguise.<br><br>What to do:<br>1. ❌ Refuse to share any government IDs<br>2. 🔍 Verify the company on LinkedIn<br>3. 📞 Call the company's official number<br>4. 📣 Report the recruiter to authorities<br><br>Real companies only ask for documents after a formal offer letter is signed.`,
        },
        {
            patterns: ['gmail', 'yahoo', 'hotmail', 'outlook', 'free email', 'work from home email', 'recruiter email'],
            response: () => `📧 <strong>Suspicious email domain detected!</strong><br><br>Legitimate company recruiters use <strong>official company email addresses</strong> (e.g., <code>hr@company.com</code>), never free providers like Gmail or Yahoo for corporate recruitment.<br><br>Red flag scenarios:<br>• <code>google.recruiter@gmail.com</code> — Fake!<br>• <code>infosys.hr@yahoo.com</code> — Fake!<br>• <code>hr@infosys.com</code> — Likely real ✅<br><br>Always cross-reference the email domain with the official company website.`,
        },
        {
            patterns: ['whatsapp', 'telegram', 'only on whatsapp', 'message on telegram', 'chat on whatsapp'],
            response: () => `⚠️ <strong>WhatsApp/Telegram-only contact is suspicious!</strong><br><br>Real companies use official email, phone, and HR portals for recruitment. If a "recruiter" insists on communicating only through messaging apps:<br><br>• They avoid leaving an official trail<br>• They may be impersonating a real company<br>• They can disappear instantly without accountability<br><br>Always insist on an official email address or phone number you can verify.`,
        },
        {
            patterns: ['url', 'website', 'link', 'check website', 'verify website', 'suspicious link', 'company url'],
            response: () => `🔗 <strong>URL Safety Checklist:</strong><br><br>When checking a company website, look for:<br><br>✅ <strong>HTTPS</strong> — Secure connection (check for the lock icon)<br>✅ <strong>Official domain</strong> — e.g., company.com, not company-jobs.net<br>❌ <strong>IP addresses</strong> — e.g., http://192.168.1.1/apply<br>❌ <strong>Excessive hyphens</strong> — e.g., google-internship-official.com<br>❌ <strong>URL shorteners</strong> — bit.ly or t.co links to "apply"<br>❌ <strong>Suspicious TLDs</strong> — .xyz, .tk, .click for corporate sites<br><br>Use our <a href="analyzer.html" style="color:#93c5fd">Analyzer</a> to scan any URL automatically!`,
        },
        {
            patterns: ['how to verify', 'verify company', 'check company', 'is this real', 'is this legit', 'verify offer', 'how to check'],
            response: () => `🔍 <strong>6-Step Verification Guide:</strong><br><br>1. <strong>Google the company</strong> — Check reviews on Glassdoor & AmbitionBox<br>2. <strong>Verify LinkedIn</strong> — Find the recruiter's official LinkedIn profile<br>3. <strong>Check the official website</strong> — Find their careers page independently<br>4. <strong>Call the company</strong> — Use the phone number from their official website<br>5. <strong>Analyze the email</strong> — Recruiter email should match the company domain<br>6. <strong>Use InternGuard</strong> — Paste the posting into our <a href="analyzer.html" style="color:#93c5fd">Analyzer</a> for an instant risk score<br><br>When in doubt, trust your instincts! 🛡️`,
        },
        {
            patterns: ['high salary', 'unrealistic salary', 'too much money', 'earn from home', 'work from home earn', 'lakh per month', 'crore', '50000 per month', '₹50000', 'high pay'],
            response: () => `💰 <strong>Unrealistic salary? Major red flag!</strong><br><br>Entry-level internships in India typically pay:<br>• Tier 1 companies: ₹15,000–₹60,000/month<br>• Startups: ₹5,000–₹20,000/month<br>• Work-from-home roles: ₹3,000–₹15,000/month<br><br>If an "internship" promises ₹50,000+ per month for freshers with no experience, it's almost certainly bait to get your personal data or registration fees.<br><br>Rule: If it sounds too good to be true, it is. 🚩`,
        },
        {
            patterns: ['urgent', 'apply now', 'limited seats', 'hurry', 'deadline today', 'act fast', 'last chance', 'few seats left'],
            response: () => `⏰ <strong>Artificial urgency is a classic scam tactic!</strong><br><br>Scammers create pressure so you don't have time to verify. Phrases like:<br>• "Only 2 seats left!"<br>• "Offer expires in 24 hours"<br>• "Apply NOW before it's too late"<br><br>...are designed to short-circuit your critical thinking.<br><br><strong>Real companies</strong> have structured hiring timelines and won't pressure you to decide instantly. When you see urgency, slow down and verify more carefully. ⚠️`,
        },
        {
            patterns: ['red flags', 'warning signs', 'scam signs', 'how to spot', 'identify scam', 'scam indicators'],
            response: () => `🚩 <strong>Top 10 Internship Scam Red Flags:</strong><br><br>1. 💸 Asking for any kind of fee<br>2. 📧 Free email address (Gmail/Yahoo)<br>3. 🎯 "Guaranteed" placement/job<br>4. 💰 Unrealistically high pay<br>5. 🆔 Requesting Aadhaar/PAN/bank details<br>6. ⏰ Extreme urgency ("apply NOW")<br>7. 💬 WhatsApp/Telegram-only contact<br>8. 🔗 Suspicious or unofficial website<br>9. 📝 Vague job description<br>10. 🏢 Unverifiable company name<br><br>Spotted any of these? Use our <a href="analyzer.html" style="color:#93c5fd">Analyzer</a> for a full risk assessment!`,
        },
        {
            patterns: ['report scam', 'how to report', 'where to report', 'complain', 'file complaint'],
            response: () => `📣 <strong>How to Report Internship Scams in India:</strong><br><br>🌐 <strong>National Cybercrime Portal</strong><br>→ <a href="https://cybercrime.gov.in" target="_blank" style="color:#93c5fd">cybercrime.gov.in</a><br><br>📞 <strong>Cybercrime Helpline</strong><br>→ Call <strong>1930</strong> (available 24/7)<br><br>📱 <strong>Report on Job Portals</strong><br>→ Use the "Report Job" button on Naukri, LinkedIn, Internshala<br><br>👮 <strong>Local Police</strong><br>→ File an FIR at your nearest cyber cell<br><br>Reporting protects future victims — every report matters! 🛡️`,
        },
        {
            patterns: ['internshala', 'naukri', 'linkedin', 'indeed', 'job portal', 'safe job portal', 'trusted portal'],
            response: () => `✅ <strong>Trusted Internship Platforms:</strong><br><br>🟢 <strong>Internshala</strong> — Best for students in India, verified companies<br>🟢 <strong>LinkedIn</strong> — Verify recruiter profile and company page<br>🟢 <strong>Naukri</strong> — Use the "Verified Company" filter<br>🟢 <strong>AngelList/Wellfound</strong> — Great for startup internships<br>🟢 <strong>Unstop</strong> — Competitions and internships for students<br><br>⚠️ Even on trusted platforms, scammers exist. Always verify the recruiter and company independently before sharing personal details.`,
        },
        {
            patterns: ['risk score', 'score', 'what is risk score', 'how is score calculated', 'score meaning'],
            response: () => `📊 <strong>Understanding the Risk Score:</strong><br><br>InternGuard-AI scores postings from <strong>0 to 100</strong>:<br><br>🟢 <strong>0–30 — SAFE</strong><br>&nbsp;&nbsp;&nbsp;Low risk, likely legitimate<br><br>🟡 <strong>31–60 — SUSPICIOUS</strong><br>&nbsp;&nbsp;&nbsp;Proceed with caution, verify carefully<br><br>🔴 <strong>61–100 — SCAM</strong><br>&nbsp;&nbsp;&nbsp;High probability of fraud, avoid immediately<br><br>The score is calculated from 5 modules: keyword scanning, URL analysis, email verification, text pattern analysis, and composite AI scoring.<br><br>Try the <a href="analyzer.html" style="color:#93c5fd">Analyzer</a> on any suspicious posting!`,
        },
        {
            patterns: ['thank you', 'thanks', 'thank u', 'thx', 'appreciate', 'helpful'],
            response: () => `😊 Glad I could help! Remember:<br><br>🛡️ <strong>Stay vigilant</strong> — Scammers are always evolving their tactics<br>📢 <strong>Share awareness</strong> — Tell friends about InternGuard-AI<br>🔍 <strong>When in doubt</strong> — Use our <a href="analyzer.html" style="color:#93c5fd">Analyzer</a> before applying<br><br>Stay safe and good luck with your internship search! 🚀`,
        },
        {
            patterns: ['bye', 'goodbye', 'see you', 'later', 'exit'],
            response: () => `👋 Take care and stay scam-free! Remember, if you ever get a suspicious internship offer, InternGuard-AI is here to help you verify it. Good luck with your internship hunt! 🛡️`,
        },
        {
            patterns: ['analyze', 'scan', 'check posting', 'analyze posting', 'scan posting'],
            response: () => `🔍 Ready to analyze a posting? Here's how:<br><br>1. Go to our <a href="analyzer.html" style="color:#93c5fd"><strong>Analyzer page</strong></a><br>2. Paste the internship posting text<br>3. (Optional) Add the recruiter's email and company URL<br>4. Click <strong>"Analyze for Scams"</strong><br><br>You'll get an instant <strong>0–100 risk score</strong> with a detailed breakdown of every flag detected — all in under 2 seconds! ⚡`,
        },
    ];

    /* ── Fallback responses ───────────────────── */
    const FALLBACKS = [
        `I'm not sure I understand that completely, but I'm here to help with internship scam detection!<br><br>Try asking me about:<br>• 🚩 Red flags to watch out for<br>• 📧 How to verify recruiter emails<br>• 🔗 Checking suspicious URLs<br>• 💸 What to do if they ask for money<br><br>Or use our <a href="analyzer.html" style="color:#93c5fd">Analyzer</a> to scan any posting directly!`,
        `Hmm, that's outside my expertise, but I specialize in internship scam detection! 🛡️<br><br>Some things I can help with:<br>• Identifying scam tactics<br>• Verifying companies and recruiters<br>• Understanding risk scores<br>• Reporting fraudulent offers`,
        `I'd love to help more specifically! Try rephrasing your question or ask me about common internship scam warning signs, email verification, or how to use InternGuard's analyzer.`,
    ];

    let fallbackIndex = 0;

    /* ── Response engine ─────────────────────── */
    function getResponse(input) {
        const normalized = input.toLowerCase().trim();
        if (!normalized) return null;

        for (const item of KB) {
            if (item.patterns.some(p => normalized.includes(p))) {
                return item.response();
            }
        }
        const fb = FALLBACKS[fallbackIndex % FALLBACKS.length];
        fallbackIndex++;
        return fb;
    }

    /* ── DOM Builder ─────────────────────────── */
    function buildChatbot() {
        // Inject styles
        const style = document.createElement('style');
        style.textContent = `
      /* ── Chatbot FAB ── */
      #ig-chat-fab {
        position: fixed;
        bottom: 28px;
        right: 28px;
        z-index: 9999;
        width: 60px;
        height: 60px;
        border-radius: 50%;
        background: linear-gradient(135deg, #3b82f6, #8b5cf6);
        border: none;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.5rem;
        box-shadow: 0 8px 30px rgba(59, 130, 246, 0.5);
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        animation: fabPop 0.4s cubic-bezier(0.34, 1.56, 0.64, 1) both;
      }
      #ig-chat-fab:hover {
        transform: scale(1.1) translateY(-2px);
        box-shadow: 0 12px 40px rgba(59, 130, 246, 0.7);
      }
      @keyframes fabPop {
        from { transform: scale(0); opacity: 0; }
        to   { transform: scale(1); opacity: 1; }
      }

      /* ── Unread badge ── */
      #ig-chat-badge {
        position: absolute;
        top: -4px;
        right: -4px;
        width: 18px;
        height: 18px;
        background: #ef4444;
        border-radius: 50%;
        font-size: 0.65rem;
        font-weight: 700;
        color: white;
        display: flex;
        align-items: center;
        justify-content: center;
        border: 2px solid #050818;
        animation: badgePulse 2s ease infinite;
      }
      @keyframes badgePulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.15); }
      }

      /* ── Chat Window ── */
      #ig-chat-window {
        position: fixed;
        bottom: 100px;
        right: 28px;
        z-index: 9998;
        width: 380px;
        max-height: 580px;
        display: flex;
        flex-direction: column;
        background: rgba(10, 17, 40, 0.97);
        backdrop-filter: blur(24px);
        -webkit-backdrop-filter: blur(24px);
        border: 1px solid rgba(59, 130, 246, 0.25);
        border-radius: 24px;
        box-shadow: 0 20px 60px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.04);
        transform: scale(0.85) translateY(20px);
        transform-origin: bottom right;
        opacity: 0;
        pointer-events: none;
        transition: all 0.35s cubic-bezier(0.34, 1.56, 0.64, 1);
        overflow: hidden;
      }
      #ig-chat-window.open {
        transform: scale(1) translateY(0);
        opacity: 1;
        pointer-events: all;
      }

      /* ── Header ── */
      #ig-chat-header {
        padding: 18px 20px;
        background: linear-gradient(135deg, rgba(59,130,246,0.15), rgba(139,92,246,0.15));
        border-bottom: 1px solid rgba(255,255,255,0.06);
        display: flex;
        align-items: center;
        justify-content: space-between;
        flex-shrink: 0;
      }
      .ig-chat-header-info {
        display: flex;
        align-items: center;
        gap: 12px;
      }
      .ig-chat-avatar {
        width: 40px;
        height: 40px;
        border-radius: 50%;
        background: linear-gradient(135deg, #3b82f6, #8b5cf6);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 1.1rem;
        flex-shrink: 0;
        position: relative;
      }
      .ig-chat-avatar::after {
        content: '';
        position: absolute;
        bottom: 1px;
        right: 1px;
        width: 10px;
        height: 10px;
        background: #10b981;
        border-radius: 50%;
        border: 2px solid #0a1128;
      }
      .ig-chat-header-text {
        display: flex;
        flex-direction: column;
      }
      .ig-chat-name {
        font-size: 0.92rem;
        font-weight: 700;
        color: #f1f5f9;
      }
      .ig-chat-status {
        font-size: 0.72rem;
        color: #10b981;
        font-weight: 500;
      }
      #ig-chat-close {
        background: rgba(255,255,255,0.06);
        border: none;
        color: #94a3b8;
        width: 32px;
        height: 32px;
        border-radius: 50%;
        font-size: 1rem;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.2s;
      }
      #ig-chat-close:hover {
        background: rgba(255,255,255,0.12);
        color: #f1f5f9;
        transform: rotate(90deg);
      }

      /* ── Messages area ── */
      #ig-chat-messages {
        flex: 1;
        overflow-y: auto;
        padding: 20px 16px;
        display: flex;
        flex-direction: column;
        gap: 14px;
        scroll-behavior: smooth;
      }
      #ig-chat-messages::-webkit-scrollbar { width: 4px; }
      #ig-chat-messages::-webkit-scrollbar-track { background: transparent; }
      #ig-chat-messages::-webkit-scrollbar-thumb { background: rgba(59,130,246,0.3); border-radius: 2px; }

      /* ── Bubble base ── */
      .ig-bubble {
        max-width: 88%;
        padding: 12px 16px;
        border-radius: 18px;
        font-size: 0.85rem;
        line-height: 1.65;
        animation: bubbleIn 0.3s cubic-bezier(0.34, 1.56, 0.64, 1) both;
        word-break: break-word;
      }
      @keyframes bubbleIn {
        from { opacity: 0; transform: scale(0.8) translateY(8px); }
        to   { opacity: 1; transform: scale(1) translateY(0); }
      }
      .ig-bubble a { color: #93c5fd; }
      .ig-bubble code {
        background: rgba(255,255,255,0.08);
        padding: 1px 5px;
        border-radius: 4px;
        font-family: monospace;
        font-size: 0.82em;
      }

      /* Bot bubble */
      .ig-bubble-bot {
        background: rgba(255,255,255,0.05);
        border: 1px solid rgba(255,255,255,0.07);
        color: #e2e8f0;
        align-self: flex-start;
        border-bottom-left-radius: 6px;
      }

      /* User bubble */
      .ig-bubble-user {
        background: linear-gradient(135deg, #3b82f6, #8b5cf6);
        color: white;
        align-self: flex-end;
        border-bottom-right-radius: 6px;
        box-shadow: 0 4px 16px rgba(59, 130, 246, 0.3);
      }

      /* ── Typing indicator ── */
      .ig-typing {
        display: flex;
        gap: 5px;
        align-items: center;
        padding: 12px 16px;
        background: rgba(255,255,255,0.05);
        border: 1px solid rgba(255,255,255,0.07);
        border-radius: 18px;
        border-bottom-left-radius: 6px;
        align-self: flex-start;
        animation: bubbleIn 0.3s ease both;
      }
      .ig-typing span {
        width: 7px;
        height: 7px;
        background: #94a3b8;
        border-radius: 50%;
        animation: typingDot 1.2s ease infinite;
      }
      .ig-typing span:nth-child(2) { animation-delay: 0.2s; }
      .ig-typing span:nth-child(3) { animation-delay: 0.4s; }
      @keyframes typingDot {
        0%, 80%, 100% { transform: scale(0.7); opacity: 0.4; }
        40% { transform: scale(1); opacity: 1; }
      }

      /* ── Quick chips ── */
      #ig-chat-chips {
        padding: 0 16px 12px;
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
        flex-shrink: 0;
      }
      .ig-chip {
        background: rgba(59,130,246,0.08);
        border: 1px solid rgba(59,130,246,0.2);
        color: #93c5fd;
        font-size: 0.74rem;
        font-weight: 500;
        padding: 5px 12px;
        border-radius: 100px;
        cursor: pointer;
        transition: all 0.2s;
        white-space: nowrap;
        font-family: 'Inter', sans-serif;
      }
      .ig-chip:hover {
        background: rgba(59,130,246,0.18);
        border-color: rgba(59,130,246,0.4);
        transform: translateY(-1px);
      }

      /* ── Input bar ── */
      #ig-chat-input-bar {
        padding: 14px 16px;
        border-top: 1px solid rgba(255,255,255,0.06);
        display: flex;
        gap: 10px;
        align-items: center;
        flex-shrink: 0;
        background: rgba(5,8,24,0.6);
      }
      #ig-chat-input {
        flex: 1;
        background: rgba(255,255,255,0.05);
        border: 1px solid rgba(255,255,255,0.1);
        border-radius: 100px;
        padding: 10px 18px;
        color: #f1f5f9;
        font-family: 'Inter', sans-serif;
        font-size: 0.85rem;
        outline: none;
        transition: all 0.2s;
      }
      #ig-chat-input::placeholder { color: #475569; }
      #ig-chat-input:focus {
        border-color: rgba(59,130,246,0.5);
        background: rgba(59,130,246,0.06);
        box-shadow: 0 0 0 3px rgba(59,130,246,0.1);
      }
      #ig-chat-send {
        width: 40px;
        height: 40px;
        border-radius: 50%;
        background: linear-gradient(135deg, #3b82f6, #8b5cf6);
        border: none;
        color: white;
        font-size: 1rem;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.2s;
        flex-shrink: 0;
        box-shadow: 0 4px 16px rgba(59,130,246,0.3);
      }
      #ig-chat-send:hover {
        transform: scale(1.1);
        box-shadow: 0 6px 20px rgba(59,130,246,0.5);
      }
      #ig-chat-send:active { transform: scale(0.95); }

      /* ── Responsive ── */
      @media (max-width: 520px) {
        #ig-chat-window {
          width: calc(100vw - 16px);
          right: 8px;
          bottom: 90px;
          max-height: 70vh;
        }
        #ig-chat-fab {
          right: 16px;
          bottom: 16px;
        }
      }
    `;
        document.head.appendChild(style);

        // FAB button
        const fab = document.createElement('button');
        fab.id = 'ig-chat-fab';
        fab.setAttribute('aria-label', 'Open InternGuard AI Chat');
        fab.innerHTML = `
      🤖
      <div id="ig-chat-badge" title="1 unread message">1</div>
    `;

        // Chat window
        const win = document.createElement('div');
        win.id = 'ig-chat-window';
        win.setAttribute('role', 'dialog');
        win.setAttribute('aria-label', 'InternGuard AI Chatbot');
        win.innerHTML = `
      <div id="ig-chat-header">
        <div class="ig-chat-header-info">
          <div class="ig-chat-avatar">🛡️</div>
          <div class="ig-chat-header-text">
            <span class="ig-chat-name">InternGuard AI</span>
            <span class="ig-chat-status">● Online — Ready to help</span>
          </div>
        </div>
        <button id="ig-chat-close" aria-label="Close chat">✕</button>
      </div>
      <div id="ig-chat-messages" role="log" aria-live="polite"></div>
      <div id="ig-chat-chips">
        <button class="ig-chip" data-q="What are the red flags?">🚩 Red Flags</button>
        <button class="ig-chip" data-q="They asked for a registration fee">💸 Fee Scam</button>
        <button class="ig-chip" data-q="How to verify a company?">🔍 Verify Company</button>
        <button class="ig-chip" data-q="Suspicious Gmail recruiter email">📧 Email Check</button>
        <button class="ig-chip" data-q="How to report a scam?">📣 Report Scam</button>
      </div>
      <div id="ig-chat-input-bar">
        <input id="ig-chat-input" type="text" placeholder="Ask about internship scams…" autocomplete="off" maxlength="300" />
        <button id="ig-chat-send" aria-label="Send message">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"></line><polygon points="22 2 15 22 11 13 2 9 22 2"></polygon></svg>
        </button>
      </div>
    `;

        document.body.appendChild(fab);
        document.body.appendChild(win);

        /* ── References ── */
        const messagesEl = win.querySelector('#ig-chat-messages');
        const inputEl = win.querySelector('#ig-chat-input');
        const sendBtn = win.querySelector('#ig-chat-send');
        const closeBtn = win.querySelector('#ig-chat-close');
        const badge = fab.querySelector('#ig-chat-badge');
        let isOpen = false;

        /* ── Helpers ── */
        function scrollBottom() {
            setTimeout(() => { messagesEl.scrollTop = messagesEl.scrollHeight; }, 50);
        }

        function addMessage(html, role) {
            const bubble = document.createElement('div');
            bubble.className = `ig-bubble ig-bubble-${role}`;
            bubble.innerHTML = html;
            messagesEl.appendChild(bubble);
            scrollBottom();
            return bubble;
        }

        function showTyping() {
            const el = document.createElement('div');
            el.className = 'ig-typing';
            el.id = 'ig-typing-indicator';
            el.innerHTML = '<span></span><span></span><span></span>';
            messagesEl.appendChild(el);
            scrollBottom();
            return el;
        }

        function removeTyping() {
            const el = document.getElementById('ig-typing-indicator');
            if (el) el.remove();
        }

        function sendMessage(text) {
            const trimmed = text.trim();
            if (!trimmed) return;
            inputEl.value = '';
            addMessage(trimmed, 'user');

            const typingEl = showTyping();
            const delay = 600 + Math.random() * 600;

            setTimeout(() => {
                removeTyping();
                const reply = getResponse(trimmed);
                if (reply) addMessage(reply, 'bot');
            }, delay);
        }

        /* ── Open / Close ── */
        function openChat() {
            isOpen = true;
            win.classList.add('open');
            badge.style.display = 'none';
            fab.innerHTML = `<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>`;
            inputEl.focus();
        }

        function closeChat() {
            isOpen = false;
            win.classList.remove('open');
            fab.innerHTML = `🤖`;
        }

        /* ── Events ── */
        fab.addEventListener('click', () => {
            isOpen ? closeChat() : openChat();
        });
        closeBtn.addEventListener('click', closeChat);

        sendBtn.addEventListener('click', () => sendMessage(inputEl.value));
        inputEl.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage(inputEl.value);
            }
        });

        // Quick chips
        win.querySelectorAll('.ig-chip').forEach(chip => {
            chip.addEventListener('click', () => {
                sendMessage(chip.dataset.q);
            });
        });

        /* ── Greeting message (delayed) ── */
        function sendGreeting() {
            const typingEl = showTyping();
            setTimeout(() => {
                removeTyping();
                addMessage(`👋 Hi! I'm <strong>InternGuard AI</strong>, your internship fraud detection assistant.<br><br>I can help you identify scam red flags, verify companies, and stay safe. What's on your mind? 🛡️`, 'bot');
            }, 900);
        }

        // Show greeting when chat first opens
        let greeted = false;
        fab.addEventListener('click', () => {
            if (!greeted && isOpen) {
                greeted = true;
                sendGreeting();
            }
        });

        // Show badge after short delay to attract attention
        setTimeout(() => {
            if (!isOpen) {
                badge.style.display = 'flex';
            }
        }, 2000);
    }

    /* ── Init ──────────────────────────────────── */
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', buildChatbot);
    } else {
        buildChatbot();
    }
})();
