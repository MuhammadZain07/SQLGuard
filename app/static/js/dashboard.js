// dashboard.js
// draws 2 charts using Chart.js
// variables come from the script tag in dashboard.html

document.addEventListener('DOMContentLoaded', function () {

    // CHART 1 - Doughnut: scan status breakdown
    var ctx1 = document.getElementById('statusChart').getContext('2d');
    new Chart(ctx1, {
        type: 'doughnut',
        data: {
            labels: ['Completed', 'Running', 'Failed'],
            datasets: [{
                data: [completedCount, runningCount, failedCount],
                backgroundColor: ['#3fb950', '#58a6ff', '#f85149'],
                borderColor: '#161b22',
                borderWidth: 3
            }]
        },
        options: {
            cutout: '65%',
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#8b949e', font: { size: 11 }, padding: 12 }
                }
            }
        }
    });

    // CHART 2 - Bar: vulnerabilities per scan
    var ctx2 = document.getElementById('vulnBarChart').getContext('2d');
    new Chart(ctx2, {
        type: 'bar',
        data: {
            labels: scanLabels,
            datasets: [{
                label: 'Vulns Found',
                data: vulnCounts,
                backgroundColor: '#1f6feb',
                borderRadius: 4
            }]
        },
        options: {
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#8b949e' }, grid: { display: false } },
                y: { ticks: { color: '#8b949e', stepSize: 1 }, grid: { color: '#21262d' }, beginAtZero: true }
            }
        }
    });

});