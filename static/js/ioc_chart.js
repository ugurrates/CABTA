/**
 * Blue Team Assistant - IOC Chart Visualizations
 * Author: Ugur Ates
 *
 * Chart.js-based visualizations for IOC analysis results.
 * Provides source score bars, threat gauge, and IOC type distribution.
 * Requires Chart.js 4.x (loaded via CDN in base.html).
 */

(function () {
    'use strict';

    /* --------------------------------------------------
       Constants
    -------------------------------------------------- */
    var COLOR_DANGER  = '#dc3545';
    var COLOR_WARNING = '#ffc107';
    var COLOR_SUCCESS = '#28a745';
    var COLOR_GRAY    = 'rgba(200,200,200,0.15)';

    /* --------------------------------------------------
       Helpers
    -------------------------------------------------- */

    /**
     * Return a colour based on the score threshold.
     * >= 70 danger, >= 40 warning, else success.
     */
    function scoreColor(score) {
        if (score >= 70) return COLOR_DANGER;
        if (score >= 40) return COLOR_WARNING;
        return COLOR_SUCCESS;
    }

    /**
     * Safely retrieve a canvas 2D context by element id.
     * Destroys any existing Chart instance on the canvas first.
     * Returns null if the canvas element does not exist.
     */
    function getCanvas(canvasId) {
        var el = document.getElementById(canvasId);
        if (!el) {
            console.warn('[BTA IOCCharts] Canvas not found: ' + canvasId);
            return null;
        }
        var existing = Chart.getChart(el);
        if (existing) existing.destroy();
        return el;
    }

    /* --------------------------------------------------
       createIOCSourceChart
       Horizontal bar chart of source scores.
       sources = [ { name: String, score: Number, status: String }, ... ]
    -------------------------------------------------- */

    function createIOCSourceChart(canvasId, sources) {
        var ctx = getCanvas(canvasId);
        if (!ctx) return;

        if (!Array.isArray(sources) || sources.length === 0) return;

        var labels = sources.map(function (s) { return s.name || 'Unknown'; });
        var scores = sources.map(function (s) { return s.score || 0; });
        var bgColors = scores.map(function (s) { return scoreColor(s); });
        var borderColors = bgColors.slice();

        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Threat Score',
                    data: scores,
                    backgroundColor: bgColors,
                    borderColor: borderColors,
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
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
                        text: 'Source Threat Scores (' + sources.length + ' sources)'
                    },
                    tooltip: {
                        callbacks: {
                            label: function (context) {
                                var src = sources[context.dataIndex];
                                var parts = ['Score: ' + context.parsed.x + '/100'];
                                if (src && src.status) {
                                    parts.push('Status: ' + src.status);
                                }
                                return parts;
                            }
                        }
                    }
                }
            }
        });
    }

    /* --------------------------------------------------
       createThreatGauge
       Half-doughnut gauge for a 0-100 threat score.
    -------------------------------------------------- */

    function createThreatGauge(canvasId, score) {
        var ctx = getCanvas(canvasId);
        if (!ctx) return;

        var safeScore = Math.min(Math.max(Math.round(score), 0), 100);
        var remainder = 100 - safeScore;
        var activeColor = scoreColor(safeScore);

        new Chart(ctx, {
            type: 'doughnut',
            data: {
                datasets: [{
                    data: [safeScore, remainder],
                    backgroundColor: [activeColor, COLOR_GRAY],
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
                id: 'btaGaugeCenter',
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

    /* --------------------------------------------------
       createIOCDistribution
       Doughnut chart for IOC type distribution.
       typeCounts = { "IP": 42, "Domain": 28, "Hash": 15, ... }
    -------------------------------------------------- */

    function createIOCDistribution(canvasId, typeCounts) {
        var ctx = getCanvas(canvasId);
        if (!ctx) return;

        if (!typeCounts || typeof typeCounts !== 'object') return;

        var labels = Object.keys(typeCounts);
        var values = labels.map(function (key) { return typeCounts[key]; });

        // Distinct colour palette
        var palette = [
            '#4facfe',
            COLOR_DANGER,
            COLOR_WARNING,
            COLOR_SUCCESS,
            '#17a2b8',
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

    /* --------------------------------------------------
       Public API
    -------------------------------------------------- */
    window.BTAIOCCharts = {
        createIOCSourceChart: createIOCSourceChart,
        createThreatGauge: createThreatGauge,
        createIOCDistribution: createIOCDistribution
    };

})();
