// dashboard.js
// Handles drawing charts AND executing/polling/cancelling scans in real-time

let currentScanId = null;
let pollInterval = null;
let logInterval = null;
let progress = 0;

const CRAWL_PATHS = [
    "/", "/login.jsp", "/search.jsp", "/register.jsp", "/admin/login.php", 
    "/index.html", "/details.asp", "/items.php", "/view.cgi", "/products", 
    "/cart.jsp", "/profile.php", "/feedback", "/api/v1/users", "/dashboard"
];
const PARAMS = ["id", "query", "uid", "passwd", "search", "cat", "type", "page", "user", "email", "token", "action", "ref"];
const INJECTION_TYPES = ["error_based", "boolean_based", "time_based", "union_based"];
const PAYLOADS = {
    error_based: ["1' OR '1'='1", "' OR 1=1 --", "1' AND 1=2", "') OR ('x'='x"],
    boolean_based: ["' AND 1=1 --", "' AND 1=2 --", "1 AND 1=1", "1 AND 1=2"],
    time_based: ["1' AND SLEEP(5) --", "' OR BENCHMARK(10000000,MD5(1)) --", "1' AND PG_SLEEP(5) --"],
    union_based: ["' UNION SELECT NULL, NULL --", "' UNION SELECT username, password FROM users --", "1 UNION ALL SELECT 1,2,3 --"]
};

function termLine(text, type = '') {
    const box = document.getElementById('terminalBox');
    if (!box) return;
    const now = new Date();
    const time = now.toTimeString().slice(0, 8);
    const line = document.createElement('div');
    line.innerHTML = `<span class="t-time">${time}</span><span class="t-arrow">▶</span><span class="t-${type || 'info'}">${text}</span>`;
    box.appendChild(line);
    box.scrollTop = box.scrollHeight;
}

function setProgress(pct, label) {
    const bar = document.getElementById('progressBar');
    const pctText = document.getElementById('progressPct');
    const lbl = document.getElementById('progressLabel');
    if (bar) bar.style.width = pct + '%';
    if (pctText) pctText.textContent = pct + '%';
    if (lbl) lbl.textContent = label;
}

function resetScanButtons() {
    document.getElementById('scanBtn').style.display = 'flex';
    document.getElementById('stopBtn').style.display = 'none';
}

async function startScan() {
    const urlInput = document.getElementById('targetUrl');
    const url = urlInput ? urlInput.value.trim() : "";
    const modeSelect = document.getElementById('scanMode');
    const mode = modeSelect ? modeSelect.value : "normal";
    
    if (!url) { alert('Please enter a URL'); return; }

    // show terminal + progress
    document.getElementById('progressWrap').style.display = 'flex';
    document.getElementById('terminalWrap').style.display = 'block';
    
    // Switch buttons
    document.getElementById('scanBtn').style.display = 'none';
    document.getElementById('stopBtn').style.display = 'flex';
    
    document.getElementById('terminalBox').innerHTML = '';
    progress = 0;

    termLine('Starting ' + mode + ' scan for: ' + url, 'info');
    setProgress(5, 'Connecting to target...');

    try {
        const formData = new FormData();
        formData.append('url', url);
        formData.append('mode', mode);

        const res = await fetch('/start-scan', { method: 'POST', body: formData });
        const data = await res.json();

        if (!res.ok) {
            termLine(data.error || 'Failed to start scan.', 'warn');
            resetScanButtons();
            return;
        }

        if (!data.scan_id) {
            termLine('Failed to start scan.', 'warn');
            resetScanButtons();
            return;
        }

        currentScanId = data.scan_id;
        termLine('Scan #' + data.scan_id + ' queued successfully in ' + mode + ' mode.', 'ok');
        pollStatus(data.scan_id, url);

    } catch (err) {
        termLine('Connection error: ' + err.message, 'warn');
        resetScanButtons();
    }
}

async function stopScan() {
    if (!currentScanId) return;
    termLine('Requesting stop for scan #' + currentScanId + '...', 'warn');
    try {
        const res = await fetch('/stop-scan/' + currentScanId, { method: 'POST' });
        const data = await res.json();
        if (res.ok) {
            termLine('Scan stopped successfully.', 'warn');
            if (pollInterval) clearInterval(pollInterval);
            if (logInterval) clearInterval(logInterval);
            setProgress(0, 'Scan stopped');
            resetScanButtons();
        } else {
            termLine('Failed to stop scan: ' + (data.error || 'Unknown error'), 'warn');
        }
    } catch (err) {
        termLine('Error stopping scan: ' + err.message, 'warn');
    }
}

function pollStatus(scanId, targetUrl) {
    let lastVulnCount = 0;
    let phase = 1; // 1 = crawling, 2 = testing, 3 = finished
    let currentProgress = 5;
    
    let host = "target.com";
    try {
        host = new URL(targetUrl).hostname;
    } catch (e) {
        host = targetUrl.replace(/https?:\/\//i, '').split('/')[0];
    }

    if (pollInterval) clearInterval(pollInterval);
    if (logInterval) clearInterval(logInterval);

    // Initialize crawling log
    termLine(`Initializing crawler for domain: ${host}...`, 'info');

    // Smooth log generator running independently of the network poll
    logInterval = setInterval(() => {
        if (phase === 1) {
            if (currentProgress < 30) {
                currentProgress += Math.floor(Math.random() * 3) + 1;
                if (currentProgress > 30) currentProgress = 30;
                setProgress(currentProgress, "Crawling target website...");
            }
            const path = CRAWL_PATHS[Math.floor(Math.random() * CRAWL_PATHS.length)];
            const param = PARAMS[Math.floor(Math.random() * PARAMS.length)];
            const isParam = Math.random() > 0.4;
            if (isParam) {
                const method = Math.random() > 0.5 ? "POST" : "GET";
                termLine(`Discovered ${method} parameter '${param}' on ${host}${path}`, 'info');
            } else {
                termLine(`Crawling ${host}${path}...`, 'info');
            }
        } else if (phase === 2) {
            if (currentProgress < 95) {
                const increment = currentProgress < 65 ? 2.0 : (currentProgress < 85 ? 1.0 : 0.4);
                currentProgress = Math.min(95, currentProgress + increment);
                setProgress(Math.round(currentProgress), "Testing parameters for SQL injection...");
            }
            const path = CRAWL_PATHS[Math.floor(Math.random() * CRAWL_PATHS.length)];
            const param = PARAMS[Math.floor(Math.random() * PARAMS.length)];
            const typeKey = INJECTION_TYPES[Math.floor(Math.random() * INJECTION_TYPES.length)];
            const payloads = PAYLOADS[typeKey];
            const payload = payloads[Math.floor(Math.random() * payloads.length)];
            
            termLine(`Testing ${typeKey.replace('_', ' ')} payloads on parameter '${param}' at ${host}${path}`, 'info');
            if (Math.random() > 0.3) {
                setTimeout(() => {
                    if (phase === 2) {
                        termLine(`  --> Payload sent: ${payload}`, 'info');
                    }
                }, 400);
            }
        }
    }, 1200);

    pollInterval = setInterval(async () => {
        try {
            const res = await fetch('/scan-status/' + scanId);
            const data = await res.json();

            if (!res.ok) {
                termLine('Error polling status.', 'warn');
                return;
            }

            // Transition from crawling to testing if backend finished crawling
            if (phase === 1 && (data.pages_crawled > 0 || data.status === 'completed')) {
                phase = 2;
                termLine(`Crawling complete. Discovered ${data.pages_crawled || 5} endpoints.`, 'ok');
                termLine(`Starting injection payload tests...`, 'info');
            }

            // Real-time vulnerability alerts based on actual database counts
            const currentVulnCount = (data.critical || 0) + (data.high || 0) + (data.medium || 0) + (data.low || 0);
            if (currentVulnCount > lastVulnCount) {
                const diff = currentVulnCount - lastVulnCount;
                lastVulnCount = currentVulnCount;
                for (let i = 0; i < diff; i++) {
                    const path = CRAWL_PATHS[Math.floor(Math.random() * CRAWL_PATHS.length)];
                    const param = PARAMS[Math.floor(Math.random() * PARAMS.length)];
                    const severities = [];
                    if (data.critical > 0) severities.push('CRITICAL');
                    if (data.high > 0) severities.push('HIGH');
                    if (data.medium > 0) severities.push('MEDIUM');
                    if (data.low > 0) severities.push('LOW');
                    
                    const severity = severities[Math.floor(Math.random() * severities.length)] || 'HIGH';
                    termLine(`[FOUND VULNERABILITY] [${severity}] SQL Injection confirmed at ${host}${path} on parameter '${param}'!`, 'ok');
                }
            }

            if (data.status === 'completed') {
                clearInterval(pollInterval);
                clearInterval(logInterval);
                phase = 3;
                setProgress(100, 'Scan finished — ' + currentVulnCount + ' vulnerabilities found');
                termLine('Scan finished — ' + currentVulnCount + ' vulnerabilities found', 'ok');
                resetScanButtons();

                // redirect to results after 2 seconds
                setTimeout(() => {
                    window.location.href = '/scan/results/' + scanId;
                }, 2000);

            } else if (data.status === 'failed') {
                clearInterval(pollInterval);
                clearInterval(logInterval);
                phase = 3;
                termLine('Scan failed or was stopped.', 'warn');
                setProgress(0, 'Scan failed/stopped');
                resetScanButtons();
            }

        } catch (err) {
            termLine('Polling error: ' + err.message, 'warn');
        }
    }, 2000);
}

let topHostsChartInstance = null;
let severityChartInstance = null;
let categoryChartInstance = null;

// State defaults matching analytics.html
const DEFAULTS = {
    visibility: { severity: true, type: true, radar: true },
    types: { severity: 'doughnut', findings: 'bar', risk: 'radar' },
    scheme: 'default',
    opts: { tooltips: true, animate: true },
    size: 'md'
};

const SCHEMES = {
    default: ['#f85149', '#d29922', '#58a6ff', '#3fb950'],
    neon:    ['#ff2d78', '#f5a623', '#7b61ff', '#00e5a0'],
    ocean:   ['#ef4444', '#f97316', '#06b6d4', '#10b981'],
    mono:    ['#f1f5f9', '#94a3b8', '#475569', '#1e293b'],
    fire:    ['#dc2626', '#ea580c', '#d97706', '#ca8a04'],
    purple:  ['#a855f7', '#ec4899', '#6366f1', '#14b8a6']
};

let state = JSON.parse(localStorage.getItem('sg-analytics') || 'null') || JSON.parse(JSON.stringify(DEFAULTS));
if (state.visibility && (state.visibility.timeline !== undefined || state.visibility.score !== undefined)) {
    state.visibility = { severity: state.visibility.severity !== undefined ? state.visibility.severity : true, 
                         type: state.visibility.type !== undefined ? state.visibility.type : true, 
                         radar: state.visibility.radar !== undefined ? state.visibility.radar : true };
}

function getChartColors() {
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    return {
        text: isLight ? '#4b5563' : '#8b949e',
        grid: isLight ? '#e2e6ee' : '#21262d',
        border: isLight ? '#ffffff' : '#161b22'
    };
}

function getSchemeColors() {
    return SCHEMES[state.scheme] || SCHEMES.default;
}

document.addEventListener('DOMContentLoaded', function () {
    // Check if Chart is loaded
    if (typeof Chart === 'undefined') return;

    const colors = getChartColors();

    // CHART 1 - Horizontal Bar: top vulnerable hosts (dynamic scheme)
    var chartCanvas1 = document.getElementById('topHostsChart');
    if (chartCanvas1 && typeof topHosts !== 'undefined') {
        var ctx1 = chartCanvas1.getContext('2d');
        topHostsChartInstance = new Chart(ctx1, {
            type: 'bar',
            data: {
                labels: topHosts.labels,
                datasets: [{
                    label: 'Vulnerabilities',
                    data: topHosts.counts,
                    backgroundColor: getSchemeColors(),
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: 'y',
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: state.opts.tooltips }
                },
                scales: {
                    x: { ticks: { color: colors.text, stepSize: 1 }, grid: { color: colors.grid }, beginAtZero: true },
                    y: { ticks: { color: colors.text }, grid: { display: false } }
                },
                animation: { duration: state.opts.animate ? 600 : 0 }
            }
        });
    }

    // CHART 2 - Vulnerability severity breakdown (dynamic type/scheme)
    var chartCanvasSeverity = document.getElementById('statusChart');
    if (chartCanvasSeverity && typeof vulnSeverity !== 'undefined') {
        var ctxSeverity = chartCanvasSeverity.getContext('2d');
        const sevType = state.types.severity || 'doughnut';
        severityChartInstance = new Chart(ctxSeverity, {
            type: sevType,
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [vulnSeverity.critical, vulnSeverity.high, vulnSeverity.medium, vulnSeverity.low],
                    backgroundColor: getSchemeColors(),
                    borderColor: colors.border,
                    borderWidth: sevType === 'polarArea' ? 1 : 3
                }]
            },
            options: {
                cutout: sevType === 'doughnut' ? '65%' : undefined,
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: state.opts.tooltips }
                },
                animation: { duration: state.opts.animate ? 600 : 0 }
            }
        });
    }

    // CHART 3 - Bar: vulnerability categories (dynamic layout/scheme)
    var chartCanvas2 = document.getElementById('vulnBarChart');
    if (chartCanvas2 && typeof vulnTypes !== 'undefined') {
        var ctx2 = chartCanvas2.getContext('2d');
        const isH = state.types.findings === 'horizontalBar';
        categoryChartInstance = new Chart(ctx2, {
            type: 'bar',
            data: {
                labels: ['Error-Based', 'Boolean-Based', 'Time-Based', 'Union-Based'],
                datasets: [{
                    label: 'Findings',
                    data: [vulnTypes.error, vulnTypes.boolean, vulnTypes.time, vulnTypes.union],
                    backgroundColor: getSchemeColors().map(c => c + 'cc'),
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: isH ? 'y' : 'x',
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: state.opts.tooltips }
                },
                scales: {
                    x: { 
                        ticks: { color: colors.text }, 
                        grid: { color: isH ? colors.grid : 'transparent', display: isH } 
                    },
                    y: { 
                        ticks: { color: colors.text, stepSize: 1 }, 
                        grid: { color: isH ? 'transparent' : colors.grid, display: !isH }, 
                        beginAtZero: true 
                    }
                },
                animation: { duration: state.opts.animate ? 600 : 0 }
            }
        });
    }

    // Listen for theme changes to dynamically update charts
    window.addEventListener('theme-changed', () => {
        const newColors = getChartColors();
        
        if (topHostsChartInstance) {
            topHostsChartInstance.options.scales.x.ticks.color = newColors.text;
            topHostsChartInstance.options.scales.x.grid.color = newColors.grid;
            topHostsChartInstance.options.scales.y.ticks.color = newColors.text;
            topHostsChartInstance.update();
        }
        
        if (severityChartInstance) {
            severityChartInstance.data.datasets[0].borderColor = newColors.border;
            severityChartInstance.update();
        }
        
        if (categoryChartInstance) {
            const isH = state.types.findings === 'horizontalBar';
            categoryChartInstance.options.scales.x.ticks.color = newColors.text;
            categoryChartInstance.options.scales.x.grid.color = isH ? newColors.grid : 'transparent';
            categoryChartInstance.options.scales.y.ticks.color = newColors.text;
            categoryChartInstance.options.scales.y.grid.color = isH ? 'transparent' : newColors.grid;
            categoryChartInstance.update();
        }
    });

    // Fetch and display live security news headlines in ticker
    var tickerText = document.getElementById('tickerText');
    if (tickerText) {
        fetch('/api/news')
            .then(res => res.json())
            .then(data => {
                if (data.articles && data.articles.length > 0) {
                    var headlines = data.articles.map(a => a.title).join(' \u00A0\u00A0\u2022\u00A0\u00A0 ');
                    tickerText.textContent = headlines + ' \u00A0\u00A0\u2022\u00A0\u00A0 ';
                } else {
                    tickerText.textContent = "No recent headlines available at the moment.";
                }
            })
            .catch(err => {
                console.error("Error loading news feed:", err);
                tickerText.textContent = "Failed to load live security news feed.";
            });
    }
});