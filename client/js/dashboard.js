// dashboard.js

document.addEventListener('DOMContentLoaded', async () => {
    try {
        // Fetch data from the backend route we created in Step 1
        const response = await fetch('/api/statistics/summary');
        const result = await response.json();

        if (result.success) {
            const stats = result.data;

            // 1. Update the Summary Cards
            document.getElementById('totalAnalyzed').innerText = stats.totalAnalyzed;
            document.getElementById('avgRiskScore').innerText = stats.averageRiskScore;

            // 2. Render Authentication Bar Chart (SPF, DKIM, DMARC)
            const authCtx = document.getElementById('authChart').getContext('2d');
            new Chart(authCtx, {
                type: 'bar',
                data: {
                    labels: ['SPF', 'DKIM', 'DMARC'],
                    datasets: [
                        {
                            label: 'Pass',
                            data: [stats.authentication.spfPass, stats.authentication.dkimPass, stats.authentication.dmarcPass],
                            backgroundColor: 'rgba(46, 204, 113, 0.7)', // Green
                            borderColor: 'rgba(39, 174, 96, 1)',
                            borderWidth: 1
                        },
                        {
                            label: 'Fail',
                            data: [stats.authentication.spfFail, stats.authentication.dkimFail, stats.authentication.dmarcFail],
                            backgroundColor: 'rgba(231, 76, 60, 0.7)', // Red
                            borderColor: 'rgba(192, 57, 43, 1)',
                            borderWidth: 1
                        }
                    ]
                },
                options: {
                    responsive: true,
                    plugins: { title: { display: true, text: 'Authentication Alignment Rates' } },
                    scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } }
                }
            });

            // 3. Render AI Threat Classification Doughnut Chart
            const threatCtx = document.getElementById('threatChart').getContext('2d');
            new Chart(threatCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Safe', 'Phishing', 'Spoofing', 'Spam'],
                    datasets: [{
                        data: [
                            stats.aiClassifications.safe,
                            stats.aiClassifications.phishing,
                            stats.aiClassifications.spoofing,
                            stats.aiClassifications.spam
                        ],
                        backgroundColor: [
                            '#2ecc71', // Safe - Green
                            '#e74c3c', // Phishing - Red
                            '#f39c12', // Spoofing - Orange
                            '#3498db'  // Spam - Blue
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    plugins: { title: { display: true, text: 'Gemini AI Threat Classifications' } }
                }
            });
        }
    } catch (error) {
        console.error("Failed to load dashboard data:", error);
        document.getElementById('totalAnalyzed').innerText = "Error";
        document.getElementById('avgRiskScore').innerText = "Error";
    }
});