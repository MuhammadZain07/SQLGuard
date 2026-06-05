// dashboard.js
// Handles drawing charts AND executing/polling/cancelling scans in real-time

let currentScanId = null;
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
        pollStatus(data.scan_id);

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
            clearInterval(pollInterval);
            setProgress(0, 'Scan stopped');
            resetScanButtons();
        } else {
            termLine('Failed to stop scan: ' + (data.error || 'Unknown error'), 'warn');
        }
    } catch (err) {
        termLine('Error stopping scan: ' + err.message, 'warn');
    }
}

function pollStatus(scanId) {
    let stepIndex = 0;

    if (pollInterval) clearInterval(pollInterval);

    pollInterval = setInterval(async () => {
        try {
            const res = await fetch('/scan-status/' + scanId);
            const data = await res.json();

            if (!res.ok) {
                termLine('Error polling status.', 'warn');
                return;
            }

            // advance terminal and progress bar
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
                resetScanButtons();

                // redirect to results after 2 seconds
                setTimeout(() => {
                    window.location.href = '/scan/results/' + scanId;
                }, 2000);

            } else if (data.status === 'failed') {
                clearInterval(pollInterval);
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

function getChartColors() {
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    return {
        text: isLight ? '#4b5563' : '#8b949e',
        grid: isLight ? '#e2e6ee' : '#21262d',
        border: isLight ? '#ffffff' : '#161b22'
    };
}

document.addEventListener('DOMContentLoaded', function () {
    // Check if Chart is loaded
    if (typeof Chart === 'undefined') return;

    const colors = getChartColors();

    // CHART 1 - Horizontal Bar: top vulnerable hosts
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
                    backgroundColor: ['#ff2d78', '#7b61ff', '#06b6d4', '#10b981', '#f85149'],
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: 'y',
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: true }
                },
                scales: {
                    x: { ticks: { color: colors.text, stepSize: 1 }, grid: { color: colors.grid }, beginAtZero: true },
                    y: { ticks: { color: colors.text }, grid: { display: false } }
                }
            }
        });
    }

    // CHART 2 - Doughnut: vulnerability severity breakdown
    var chartCanvasSeverity = document.getElementById('statusChart');
    if (chartCanvasSeverity && typeof vulnSeverity !== 'undefined') {
        var ctxSeverity = chartCanvasSeverity.getContext('2d');
        severityChartInstance = new Chart(ctxSeverity, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [vulnSeverity.critical, vulnSeverity.high, vulnSeverity.medium, vulnSeverity.low],
                    backgroundColor: ['#f85149', '#d29922', '#58a6ff', '#3fb950'],
                    borderColor: colors.border,
                    borderWidth: 3
                }]
            },
            options: {
                cutout: '65%',
                plugins: {
                    legend: { display: false },
                    tooltip: { enabled: true }
                }
            }
        });
    }

    // CHART 3 - Bar: vulnerability categories
    var chartCanvas2 = document.getElementById('vulnBarChart');
    if (chartCanvas2 && typeof vulnTypes !== 'undefined') {
        var ctx2 = chartCanvas2.getContext('2d');
        categoryChartInstance = new Chart(ctx2, {
            type: 'bar',
            data: {
                labels: ['Error-Based', 'Boolean-Based', 'Time-Based', 'Union-Based'],
                datasets: [{
                    label: 'Findings',
                    data: [vulnTypes.error, vulnTypes.boolean, vulnTypes.time, vulnTypes.union],
                    backgroundColor: ['#ff2d78', '#7b61ff', '#06b6d4', '#10b981'],
                    borderRadius: 4
                }]
            },
            options: {
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: colors.text }, grid: { display: false } },
                    y: { ticks: { color: colors.text, stepSize: 1 }, grid: { color: colors.grid }, beginAtZero: true }
                }
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
            categoryChartInstance.options.scales.x.ticks.color = newColors.text;
            categoryChartInstance.options.scales.y.ticks.color = newColors.text;
            categoryChartInstance.options.scales.y.grid.color = newColors.grid;
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