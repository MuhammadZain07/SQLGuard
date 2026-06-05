// scan.js — handles scan form, polling, terminal output (used by index.html)

let pollInterval = null;
let progress = 0;

const SCAN_STEPS = [
    "Initializing scanner...",
    "Resolving target host...",
    "Crawling pages for forms and parameters...",
    "Loading SQL injection payloads...",
    "Running error-based tests...",
    "Running boolean-based tests...",
    "Running time-based tests...",
    "Running union-based tests...",
    "Analyzing responses...",
    "Saving results to database...",
    "Finalizing scan report..."
];

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
        pollStatus(data.scan_id);

    } catch (err) {
        termLine('Connection error: ' + err.message, 'warn');
        if (scanBtn) scanBtn.disabled = false;
    }
}

function pollStatus(scanId) {
    let stepIndex = 0;

    if (pollInterval) clearInterval(pollInterval);

    pollInterval = setInterval(async () => {
        try {
            const res = await fetch('/scan-status/' + scanId);
            const data = await res.json();

            // advance terminal and progress
            if (stepIndex < SCAN_STEPS.length) {
                termLine(SCAN_STEPS[stepIndex], 'info');
                stepIndex++;
                progress = Math.min(95, Math.round((stepIndex / SCAN_STEPS.length) * 95));
                setProgress(progress, SCAN_STEPS[stepIndex - 1]);
            }

            if (data.status === 'completed') {
                clearInterval(pollInterval);
                setProgress(100, 'Scan finished — ' + data.vuln_count + ' vulnerabilities found');
                termLine('Scan finished — ' + data.vuln_count + ' vulnerabilities found', 'ok');

                // fill stat cards (with null checks)
                const statRow = document.getElementById('statRow');
                if (statRow) statRow.style.display = 'grid';
                const statTotal = document.getElementById('statTotal');
                if (statTotal) statTotal.textContent = data.vuln_count || 0;
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
                termLine('Scan failed. Check target URL and try again.', 'warn');
                setProgress(0, 'Scan failed');
                const scanBtn = document.getElementById('scanBtn');
                if (scanBtn) scanBtn.disabled = false;
            }

        } catch (err) {
            termLine('Polling error: ' + err.message, 'warn');
        }
    }, 2000);
}