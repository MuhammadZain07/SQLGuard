// scan.js — handles scan form, polling, terminal output

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
    const now = new Date();
    const time = now.toTimeString().slice(0, 8);
    const line = document.createElement('div');
    line.innerHTML = `<span class="t-time">${time}</span><span class="t-arrow">▶</span><span class="t-${type || 'info'}">${text}</span>`;
    box.appendChild(line);
    box.scrollTop = box.scrollHeight;
}

function setProgress(pct, label) {
    document.getElementById('progressBar').style.width = pct + '%';
    document.getElementById('progressPct').textContent = pct + '%';
    document.getElementById('progressLabel').textContent = label;
}

async function startScan() {
    const url = document.getElementById('targetUrl').value.trim();
    if (!url) { alert('Please enter a URL'); return; }

    // show terminal + progress
    document.getElementById('progressWrap').style.display = 'flex';
    document.getElementById('terminalWrap').style.display = 'block';
    document.getElementById('statRow').style.display = 'none';
    document.getElementById('scanBtn').disabled = true;
    document.getElementById('terminalBox').innerHTML = '';
    progress = 0;

    termLine('Starting scan for: ' + url, 'info');
    setProgress(5, 'Connecting to target...');

    try {
        const formData = new FormData();
        formData.append('url', url);

        const res = await fetch('/start-scan', { method: 'POST', body: formData });
        const data = await res.json();

        if (!data.scan_id) {
            termLine('Failed to start scan.', 'warn');
            document.getElementById('scanBtn').disabled = false;
            return;
        }

        termLine('Scan #' + data.scan_id + ' queued successfully.', 'ok');
        pollStatus(data.scan_id);

    } catch (err) {
        termLine('Connection error: ' + err.message, 'warn');
        document.getElementById('scanBtn').disabled = false;
    }
}

function pollStatus(scanId) {
    let stepIndex = 0;

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
                setProgress(100, 'Scan finished in — ' + data.vuln_count + ' vulnerabilities found');
                termLine('Scan finished — ' + data.vuln_count + ' vulnerabilities found', 'ok');

                // fill stat cards
                document.getElementById('statRow').style.display = 'grid';
                document.getElementById('statTotal').textContent = data.vuln_count || 0;
                document.getElementById('statCritical').textContent = data.critical || 0;
                document.getElementById('statHigh').textContent = data.high || 0;
                document.getElementById('statMedium').textContent = data.medium || 0;
                document.getElementById('statLow').textContent = data.low || 0;

                document.getElementById('scanBtn').disabled = false;

                // redirect to results after 2 seconds
                setTimeout(() => {
                    window.location.href = '/scan/results/' + scanId;
                }, 2000);

            } else if (data.status === 'failed') {
                clearInterval(pollInterval);
                termLine('Scan failed. Check target URL and try again.', 'warn');
                setProgress(0, 'Scan failed');
                document.getElementById('scanBtn').disabled = false;
            }

        } catch (err) {
            termLine('Polling error: ' + err.message, 'warn');
        }
    }, 2000);
}