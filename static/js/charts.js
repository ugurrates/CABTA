/**
 * Chart.js Integration for MCP-FOR-SOC Reports
 * v5.1 Advanced HTML Reports
 */

// Chart configurations
const chartColors = {
    primary: '#4facfe',
    success: '#28a745',
    warning: '#ffc107',
    danger: '#dc3545',
    info: '#17a2b8',
    gray: '#6c757d'
};

/**
 * Create IOC source threat score bar chart
 */
function createSourceScoreChart(canvasId, sourcesData) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    
    // Prepare data
    const labels = sourcesData.map(s => s.name);
    const scores = sourcesData.map(s => s.score);
    const colors = scores.map(score => {
        if (score > 70) return chartColors.danger;
        if (score > 40) return chartColors.warning;
        return chartColors.success;
    });
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Threat Score',
                data: scores,
                backgroundColor: colors,
                borderColor: colors,
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    max: 100,
                    title: {
                        display: true,
                        text: 'Threat Score'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                title: {
                    display: true,
                    text: 'Threat Score by Source (22 Sources)'
                }
            }
        }
    });
}

/**
 * Create MITRE ATT&CK heatmap
 */
function createMITREHeatmap(canvasId, mitreData) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    
    // MITRE tactics
    const tactics = [
        'Initial Access',
        'Execution',
        'Persistence',
        'Privilege Escalation',
        'Defense Evasion',
        'Credential Access',
        'Discovery',
        'Lateral Movement',
        'Collection',
        'Exfiltration',
        'Command & Control'
    ];
    
    // Prepare data matrix
    const data = tactics.map((tactic, index) => {
        const tacticData = mitreData.find(m => m.tactic === tactic) || {};
        return {
            x: index,
            y: 0,
            v: tacticData.count || 0
        };
    });
    
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: tactics,
            datasets: [{
                label: 'Techniques Detected',
                data: data.map(d => d.v),
                backgroundColor: data.map(d => {
                    if (d.v > 5) return chartColors.danger;
                    if (d.v > 2) return chartColors.warning;
                    if (d.v > 0) return chartColors.info;
                    return chartColors.gray;
                })
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Technique Count'
                    }
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'MITRE ATT&CK Tactics Heatmap'
                },
                legend: {
                    display: false
                }
            }
        }
    });
}

/**
 * Create verdict distribution pie chart
 */
function createVerdictChart(canvasId, verdictData) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Malicious', 'Suspicious', 'Clean', 'Unknown'],
            datasets: [{
                data: [
                    verdictData.malicious || 0,
                    verdictData.suspicious || 0,
                    verdictData.clean || 0,
                    verdictData.unknown || 0
                ],
                backgroundColor: [
                    chartColors.danger,
                    chartColors.warning,
                    chartColors.success,
                    chartColors.gray
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Source Verdicts Distribution'
                },
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
}

/**
 * Create sandbox analysis radar chart
 */
function createSandboxRadarChart(canvasId, sandboxData) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    
    const categories = [
        'File Operations',
        'Registry',
        'Network',
        'Process',
        'API Calls'
    ];
    
    const datasets = sandboxData.map((sandbox, index) => {
        return {
            label: sandbox.name,
            data: [
                sandbox.file_ops || 0,
                sandbox.registry || 0,
                sandbox.network || 0,
                sandbox.process || 0,
                sandbox.api_calls || 0
            ],
            borderColor: Object.values(chartColors)[index],
            backgroundColor: Object.values(chartColors)[index] + '33', // Add alpha
            borderWidth: 2
        };
    });
    
    new Chart(ctx, {
        type: 'radar',
        data: {
            labels: categories,
            datasets: datasets
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    beginAtZero: true,
                    max: 100
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Sandbox Behavioral Analysis'
                }
            }
        }
    });
}

/**
 * Create timeline chart for email hops
 */
function createEmailTimelineChart(canvasId, timelineData) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    
    // Convert timeline to chart data
    const labels = timelineData.map((hop, i) => `Hop ${i + 1}`);
    const delays = timelineData.map((hop, i) => {
        if (i === 0) return 0;
        const prev = new Date(timelineData[i-1].timestamp);
        const curr = new Date(hop.timestamp);
        return (curr - prev) / 1000; // Seconds
    });
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Delay (seconds)',
                data: delays,
                borderColor: chartColors.primary,
                backgroundColor: chartColors.primary + '33',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Time Delay (s)'
                    }
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Email Relay Timeline'
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const hop = timelineData[context.dataIndex];
                            return [
                                `Delay: ${context.parsed.y}s`,
                                `Server: ${hop.from_server}`,
                                `IP: ${hop.from_ip}`
                            ];
                        }
                    }
                }
            }
        }
    });
}

/* =========================================================================
   Additional Dashboard Chart Functions
   Author: Ugur Ates
   ========================================================================= */

/**
 * Create a radar chart showing the scoring breakdown per tool / category.
 * @param {string} canvasId - The id of the target <canvas> element.
 * @param {Object} toolScores - Keys are tool/category names, values are numeric scores (0-100).
 *   Example: { "VirusTotal": 80, "AbuseIPDB": 45, "Shodan": 20, "OTX": 60, "MISP": 30 }
 */
function createScoringBreakdownRadar(canvasId, toolScores) {
    var ctx = document.getElementById(canvasId);
    if (!ctx) return;

    var labels = Object.keys(toolScores);
    var data = labels.map(function (key) { return toolScores[key]; });
    var borderColors = data.map(function (score) {
        if (score > 70) return chartColors.danger;
        if (score > 40) return chartColors.warning;
        return chartColors.success;
    });

    // Compute a single average color for the dataset fill
    var avgScore = data.reduce(function (a, b) { return a + b; }, 0) / (data.length || 1);
    var fillColor;
    if (avgScore > 70) fillColor = chartColors.danger + '33';
    else if (avgScore > 40) fillColor = chartColors.warning + '33';
    else fillColor = chartColors.success + '33';

    var borderColor;
    if (avgScore > 70) borderColor = chartColors.danger;
    else if (avgScore > 40) borderColor = chartColors.warning;
    else borderColor = chartColors.success;

    new Chart(ctx, {
        type: 'radar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Tool Score',
                data: data,
                backgroundColor: fillColor,
                borderColor: borderColor,
                borderWidth: 2,
                pointBackgroundColor: borderColors,
                pointBorderColor: borderColors,
                pointRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    beginAtZero: true,
                    max: 100,
                    ticks: {
                        stepSize: 20
                    }
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Scoring Breakdown by Tool'
                },
                legend: {
                    display: false
                }
            }
        }
    });
}

/**
 * Create a doughnut chart showing the verdict distribution across analyses.
 * @param {string} canvasId - The id of the target <canvas> element.
 * @param {Object} stats - { malicious: N, suspicious: N, clean: N, unknown: N }
 */
function createVerdictDistribution(canvasId, stats) {
    var ctx = document.getElementById(canvasId);
    if (!ctx) return;

    // Destroy any existing chart on this canvas to allow re-rendering
    var existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Malicious', 'Suspicious', 'Clean', 'Unknown'],
            datasets: [{
                data: [
                    stats.malicious || 0,
                    stats.suspicious || 0,
                    stats.clean || 0,
                    stats.unknown || 0
                ],
                backgroundColor: [
                    chartColors.danger,
                    chartColors.warning,
                    chartColors.success,
                    chartColors.gray
                ],
                borderWidth: 2,
                borderColor: 'var(--bg-secondary)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '60%',
            plugins: {
                title: {
                    display: true,
                    text: 'Verdict Distribution'
                },
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 16
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            var total = context.dataset.data.reduce(function (a, b) { return a + b; }, 0);
                            var pct = total > 0 ? Math.round((context.parsed / total) * 100) : 0;
                            return context.label + ': ' + context.parsed + ' (' + pct + '%)';
                        }
                    }
                }
            }
        }
    });
}

/**
 * Create a semi-circle gauge chart representing a single threat score (0-100).
 * Uses the Chart.js doughnut type with rotation/circumference tricks to simulate a gauge.
 * @param {string} canvasId - The id of the target <canvas> element.
 * @param {number} score - Threat score between 0 and 100.
 */
function createThreatScoreGauge(canvasId, score) {
    var ctx = document.getElementById(canvasId);
    if (!ctx) return;

    var existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    var safeScore = Math.min(Math.max(Math.round(score), 0), 100);
    var remainder = 100 - safeScore;

    var activeColor;
    if (safeScore > 70) activeColor = chartColors.danger;
    else if (safeScore > 40) activeColor = chartColors.warning;
    else activeColor = chartColors.success;

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [safeScore, remainder],
                backgroundColor: [activeColor, 'rgba(200,200,200,0.15)'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            rotation: -90,
            circumference: 180,
            cutout: '75%',
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false },
                title: { display: false }
            }
        },
        plugins: [{
            id: 'gaugeCenter',
            afterDraw: function (chart) {
                var width = chart.width;
                var height = chart.height;
                var drawCtx = chart.ctx;

                drawCtx.save();
                drawCtx.textAlign = 'center';
                drawCtx.textBaseline = 'middle';

                // Score value
                drawCtx.font = 'bold ' + Math.round(height * 0.22) + 'px "Segoe UI", sans-serif';
                drawCtx.fillStyle = activeColor;
                drawCtx.fillText(safeScore, width / 2, height * 0.62);

                // Sub-label
                drawCtx.font = Math.round(height * 0.09) + 'px "Segoe UI", sans-serif';
                drawCtx.fillStyle = '#6c757d';
                drawCtx.fillText('/ 100', width / 2, height * 0.76);

                drawCtx.restore();
            }
        }]
    });
}

/**
 * Create a doughnut chart showing IOC type distribution.
 * @param {string} canvasId - The id of the target <canvas> element.
 * @param {Object} data - Keys are IOC type names, values are counts.
 *   Example: { "IP": 42, "Domain": 28, "Hash": 15, "URL": 10, "Email": 5 }
 */
function createIOCDistributionDoughnut(canvasId, data) {
    var ctx = document.getElementById(canvasId);
    if (!ctx) return;

    var existingChart = Chart.getChart(ctx);
    if (existingChart) existingChart.destroy();

    var labels = Object.keys(data);
    var values = labels.map(function (key) { return data[key]; });

    // Generate a palette of distinct colours
    var palette = [
        chartColors.primary,
        chartColors.danger,
        chartColors.warning,
        chartColors.success,
        chartColors.info,
        '#e83e8c',
        '#6f42c1',
        '#fd7e14',
        '#20c997',
        '#6610f2'
    ];

    var bgColors = labels.map(function (_label, i) {
        return palette[i % palette.length];
    });

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: bgColors,
                borderWidth: 2,
                borderColor: 'var(--bg-secondary)'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '55%',
            plugins: {
                title: {
                    display: true,
                    text: 'IOC Type Distribution'
                },
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 14
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function (context) {
                            var total = context.dataset.data.reduce(function (a, b) { return a + b; }, 0);
                            var pct = total > 0 ? Math.round((context.parsed / total) * 100) : 0;
                            return context.label + ': ' + context.parsed + ' (' + pct + '%)';
                        }
                    }
                }
            }
        }
    });
}

// Export for use
window.MCPCharts = {
    createSourceScoreChart,
    createMITREHeatmap,
    createVerdictChart,
    createSandboxRadarChart,
    createEmailTimelineChart,
    createScoringBreakdownRadar,
    createVerdictDistribution,
    createThreatScoreGauge,
    createIOCDistributionDoughnut
};
