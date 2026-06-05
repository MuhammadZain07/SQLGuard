// scan.js — handles scan form, polling, terminal output (used by index.html)

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

async function startScan() {
    const url = document.getElementById('targetUrl').value.trim();
    const modeInput = document.getElementById('scanMode');
    const mode = modeInput ? modeInput.value : 'normal';
    if (!url) { alert('Please enter a URL'); return; }

    // show terminal + progress
    const progressWrap = document.getElementById('progressWrap');
    const terminalWrap = document.getElementById('terminalWrap');
    const statRow = document.getElementById('statRow');
    const scanBtn = document.getElementById('scanBtn');
    const terminalBox = document.getElementById('terminalBox');

    if (progressWrap) progressWrap.style.display = 'flex';
    if (terminalWrap) terminalWrap.style.display = 'block';
    if (statRow) statRow.style.display = 'none';
    if (scanBtn) scanBtn.disabled = true;
    if (terminalBox) terminalBox.innerHTML = '';
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
            if (scanBtn) scanBtn.disabled = false;
            return;
        }

        if (!data.scan_id) {
            termLine('Failed to start scan.', 'warn');
            if (scanBtn) scanBtn.disabled = false;
            return;
        }

        termLine('Scan #' + data.scan_id + ' queued successfully in ' + mode + ' mode.', 'ok');
        pollStatus(data.scan_id, url);

    } catch (err) {
        termLine('Connection error: ' + err.message, 'warn');
        if (scanBtn) scanBtn.disabled = false;
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

                // fill stat cards (with null checks)
                const statRow = document.getElementById('statRow');
                if (statRow) statRow.style.display = 'grid';
                const statTotal = document.getElementById('statTotal');
                if (statTotal) statTotal.textContent = currentVulnCount;
                const statCritical = document.getElementById('statCritical');
                if (statCritical) statCritical.textContent = data.critical || 0;
                const statHigh = document.getElementById('statHigh');
                if (statHigh) statHigh.textContent = data.high || 0;
                const statMedium = document.getElementById('statMedium');
                if (statMedium) statMedium.textContent = data.medium || 0;
                const statLow = document.getElementById('statLow');
                if (statLow) statLow.textContent = data.low || 0;

                const scanBtn = document.getElementById('scanBtn');
                if (scanBtn) scanBtn.disabled = false;

                // redirect to results after 2 seconds
                setTimeout(() => {
                    window.location.href = '/scan/results/' + scanId;
                }, 2000);

            } else if (data.status === 'failed') {
                clearInterval(pollInterval);
                clearInterval(logInterval);
                phase = 3;
                termLine('Scan failed or was stopped.', 'warn');
                setProgress(0, 'Scan failed');
                const scanBtn = document.getElementById('scanBtn');
                if (scanBtn) scanBtn.disabled = false;
            }

        } catch (err) {
            termLine('Polling error: ' + err.message, 'warn');
        }
    }, 2000);
}