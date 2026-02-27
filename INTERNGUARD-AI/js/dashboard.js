/* =============================================
   InternGuard-AI — dashboard.js
   ============================================= */

document.addEventListener('DOMContentLoaded', () => {

    /* ── Navbar ── */
    const navbar = document.querySelector('.navbar');
    if (navbar) {
        window.addEventListener('scroll', () => {
            navbar.classList.toggle('scrolled', window.scrollY > 20);
        }, { passive: true });
    }

    /* ── Counter animation ── */
    function animateCounter(el) {
        const target = parseInt(el.dataset.target, 10);
        const suffix = el.dataset.suffix || '';
        const prefix = el.dataset.prefix || '';
        const duration = 2000;
        const start = performance.now();
        function update(now) {
            const pct = Math.min((now - start) / duration, 1);
            const ease = 1 - Math.pow(1 - pct, 3);
            el.textContent = prefix + Math.round(ease * target).toLocaleString() + suffix;
            if (pct < 1) requestAnimationFrame(update);
        }
        requestAnimationFrame(update);
    }

    const io = new IntersectionObserver((entries) => {
        entries.forEach(e => {
            if (e.isIntersecting) {
                e.target.classList.add('visible');
                io.unobserve(e.target);
            }
        });
    }, { threshold: 0.12 });

    document.querySelectorAll('.fade-up').forEach(el => io.observe(el));

    const counterIO = new IntersectionObserver((entries) => {
        entries.forEach(e => {
            if (e.isIntersecting) {
                animateCounter(e.target);
                counterIO.unobserve(e.target);
            }
        });
    }, { threshold: 0.5 });

    document.querySelectorAll('.counter').forEach(el => counterIO.observe(el));

    /* ── Chart.js defaults ── */
    if (typeof Chart !== 'undefined') {
        Chart.defaults.color = '#94a3b8';
        Chart.defaults.font.family = 'Inter';


        /* ── 1. Bar chart: Scam Categories ── */
        const barCtx = document.getElementById('scamCategoryChart');
        if (barCtx) {
            new Chart(barCtx, {
                type: 'bar',
                data: {
                    labels: ['Registration Fee', 'Fake Brand', 'Data Theft', 'Guaranteed Jobs', 'Upfront Payment', 'WFH Scam', 'MLM Scheme'],
                    datasets: [{
                        label: 'Reported Cases (%)',
                        data: [34, 22, 18, 12, 7, 5, 2],
                        backgroundColor: [
                            'rgba(239,68,68,0.7)',
                            'rgba(245,158,11,0.7)',
                            'rgba(239,68,68,0.5)',
                            'rgba(245,158,11,0.5)',
                            'rgba(239,68,68,0.4)',
                            'rgba(59,130,246,0.6)',
                            'rgba(139,92,246,0.6)',
                        ],
                        borderColor: [
                            'rgba(239,68,68,1)',
                            'rgba(245,158,11,1)',
                            'rgba(239,68,68,0.8)',
                            'rgba(245,158,11,0.8)',
                            'rgba(239,68,68,0.7)',
                            'rgba(59,130,246,1)',
                            'rgba(139,92,246,1)',
                        ],
                        borderWidth: 1.5,
                        borderRadius: 8,
                    }],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: 'rgba(10,17,40,0.95)',
                            borderColor: 'rgba(59,130,246,0.3)',
                            borderWidth: 1,
                            callbacks: {
                                label: ctx => ` ${ctx.raw}% of reported scams`,
                            },
                        },
                    },
                    scales: {
                        x: {
                            grid: { color: 'rgba(255,255,255,0.04)' },
                            ticks: { font: { size: 11 } },
                        },
                        y: {
                            grid: { color: 'rgba(255,255,255,0.04)' },
                            ticks: {
                                callback: val => val + '%',
                                font: { size: 11 },
                            },
                            max: 40,
                        },
                    },
                },
            });
        }

        /* ── 2. Doughnut: Detection Modules ── */
        const donutCtx = document.getElementById('detectionDonut');
        if (donutCtx) {
            new Chart(donutCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Keyword Risk', 'URL Analysis', 'Domain/Email', 'Text Patterns', 'Composite Score'],
                    datasets: [{
                        data: [40, 20, 20, 10, 10],
                        backgroundColor: [
                            'rgba(239,68,68,0.75)',
                            'rgba(59,130,246,0.75)',
                            'rgba(139,92,246,0.75)',
                            'rgba(245,158,11,0.75)',
                            'rgba(6,182,212,0.75)',
                        ],
                        borderColor: 'rgba(10,17,40,0.8)',
                        borderWidth: 3,
                        hoverOffset: 8,
                    }],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '68%',
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                padding: 16,
                                font: { size: 11 },
                                usePointStyle: true,
                                pointStyleWidth: 8,
                            },
                        },
                        tooltip: {
                            backgroundColor: 'rgba(10,17,40,0.95)',
                            borderColor: 'rgba(59,130,246,0.3)',
                            borderWidth: 1,
                            callbacks: {
                                label: ctx => ` ${ctx.label}: ${ctx.raw}% weight`,
                            },
                        },
                    },
                },
            });
        }

        /* ── 3. Line chart: Monthly trend ── */
        const lineCtx = document.getElementById('trendChart');
        if (lineCtx) {
            const months = ['Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec', 'Jan', 'Feb', 'Mar'];
            new Chart(lineCtx, {
                type: 'line',
                data: {
                    labels: months,
                    datasets: [
                        {
                            label: 'Scam Postings',
                            data: [210, 240, 290, 320, 380, 420, 390, 450, 510, 560, 620, 680],
                            borderColor: 'rgba(239,68,68,0.9)',
                            backgroundColor: 'rgba(239,68,68,0.08)',
                            borderWidth: 2.5,
                            pointBackgroundColor: 'rgba(239,68,68,1)',
                            pointRadius: 4,
                            tension: 0.4,
                            fill: true,
                        },
                        {
                            label: 'Flagged by InternGuard',
                            data: [140, 170, 220, 250, 300, 340, 310, 380, 440, 490, 550, 615],
                            borderColor: 'rgba(59,130,246,0.9)',
                            backgroundColor: 'rgba(59,130,246,0.07)',
                            borderWidth: 2.5,
                            pointBackgroundColor: 'rgba(59,130,246,1)',
                            pointRadius: 4,
                            tension: 0.4,
                            fill: true,
                        },
                    ],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'top',
                            labels: { font: { size: 11 }, usePointStyle: true, padding: 16 },
                        },
                        tooltip: {
                            backgroundColor: 'rgba(10,17,40,0.95)',
                            borderColor: 'rgba(59,130,246,0.3)',
                            borderWidth: 1,
                            mode: 'index',
                            intersect: false,
                        },
                    },
                    scales: {
                        x: { grid: { color: 'rgba(255,255,255,0.04)' } },
                        y: {
                            grid: { color: 'rgba(255,255,255,0.04)' },
                            ticks: { font: { size: 11 } },
                        },
                    },
                },
            });
        }
    }

    /* ── Mock feed ── */
    const feedData = [
        { label: 'SCAM', score: 91, company: 'TechHire Pvt Ltd', keywords: 'Registration Fee, Guaranteed Placement', time: '2m ago' },
        { label: 'SUSPICIOUS', score: 54, company: 'Global Interns', keywords: 'No Interview, Work From Home', time: '8m ago' },
        { label: 'SAFE', score: 12, company: 'Infosys Limited', keywords: 'None detected', time: '15m ago' },
        { label: 'SCAM', score: 87, company: 'AmazingJobs.xyz', keywords: 'Wire Transfer, Aadhar Required', time: '23m ago' },
        { label: 'SUSPICIOUS', score: 41, company: 'FastHire Solutions', keywords: 'Urgent Hiring, Limited Seats', time: '31m ago' },
        { label: 'SAFE', score: 8, company: 'Wipro Technologies', keywords: 'None detected', time: '40m ago' },
        { label: 'SCAM', score: 96, company: 'EasyMoney Internships', keywords: 'Easy Money, Upfront Payment, Data Theft', time: '55m ago' },
    ];

    const feedEl = document.getElementById('mockFeed');
    if (feedEl) {
        feedData.forEach((item, i) => {
            const cls = item.label.toLowerCase();
            const div = document.createElement('div');
            div.className = `feed-item fade-up`;
            div.style.transitionDelay = `${i * 0.06}s`;
            div.innerHTML = `
        <div class="feed-left">
          <span class="badge badge-${cls}">${item.label === 'SCAM' ? '🚨' : item.label === 'SUSPICIOUS' ? '⚠️' : '✅'} ${item.label}</span>
          <div class="feed-company">${item.company}</div>
          <div class="feed-keywords">${item.keywords}</div>
        </div>
        <div class="feed-right">
          <div class="feed-score color-${cls}">${item.score}</div>
          <div class="feed-time">${item.time}</div>
        </div>
      `;
            feedEl.appendChild(div);
            io.observe(div);
        });
    }
});
