/**
 * Blue Team Assistant - Dashboard Page Logic
 * Author: Ugur Ates
 *
 * Handles dashboard statistics, recent analyses table,
 * auto-refresh polling, and the quick IOC submission form.
 * Vanilla JavaScript - no frameworks required.
 */

(function () {
    'use strict';

    /* --------------------------------------------------
       Constants
    -------------------------------------------------- */
    var REFRESH_INTERVAL_MS = 30000; // 30 seconds
    var refreshTimerId = null;

    /* --------------------------------------------------
       Utility helpers
    -------------------------------------------------- */

    /**
     * Perform a fetch request with standard error handling.
     * Returns the parsed JSON body on success, or null on failure.
     */
    function apiFetch(url, options) {
        return fetch(url, options)
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('HTTP ' + response.status + ' - ' + response.statusText);
                }
                return response.json();
            })
            .catch(function (err) {
                console.error('[BTA Dashboard] API error (' + url + '):', err.message);
                showToast('Request failed: ' + err.message, 'error');
                return null;
            });
    }

    /**
     * Display a small toast notification at the bottom-right of the viewport.
     */
    function showToast(message, type) {
        var container = document.getElementById('toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toast-container';
            container.className = 'toast-container';
            document.body.appendChild(container);
        }

        var toast = document.createElement('div');
        toast.className = 'toast toast-' + (type || 'info');
        toast.textContent = message;
        container.appendChild(toast);

        setTimeout(function () {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.3s ease';
            setTimeout(function () {
                if (toast.parentNode) {
                    toast.parentNode.removeChild(toast);
                }
            }, 300);
        }, 4000);
    }

    /**
     * Safely set the textContent of an element selected by id.
     */
    function setText(id, value) {
        var el = document.getElementById(id);
        if (el) {
            el.textContent = value !== undefined && value !== null ? value : '--';
        }
    }

    /**
     * Return a human-readable relative time string.
     */
    function timeAgo(dateString) {
        if (!dateString) return '--';
        var now = Date.now();
        var then = new Date(dateString).getTime();
        var diffSec = Math.floor((now - then) / 1000);

        if (diffSec < 60) return diffSec + 's ago';
        var diffMin = Math.floor(diffSec / 60);
        if (diffMin < 60) return diffMin + 'm ago';
        var diffHr = Math.floor(diffMin / 60);
        if (diffHr < 24) return diffHr + 'h ago';
        var diffDay = Math.floor(diffHr / 24);
        return diffDay + 'd ago';
    }

    /**
     * Map a verdict string to the appropriate CSS class suffix.
     */
    function verdictClass(verdict) {
        if (!verdict) return 'unknown';
        var v = verdict.toLowerCase();
        if (v === 'malicious') return 'malicious';
        if (v === 'suspicious') return 'suspicious';
        if (v === 'clean') return 'clean';
        return 'unknown';
    }

    /* --------------------------------------------------
       Dashboard Statistics
    -------------------------------------------------- */

    /**
     * Fetch overall dashboard statistics from the API and
     * update each stat-card element on the page.
     */
    function loadDashboardStats() {
        apiFetch('/api/dashboard/stats').then(function (data) {
            if (!data) return;

            setText('stat-total-analyses', data.total_analyses);
            setText('stat-malicious', data.malicious_count);
            setText('stat-suspicious', data.suspicious_count);
            setText('stat-clean', data.clean_count);

            // Optional fields the API may provide
            if (data.total_analyses_change !== undefined) {
                var changeEl = document.getElementById('stat-total-change');
                if (changeEl) {
                    var val = data.total_analyses_change;
                    changeEl.textContent = (val >= 0 ? '+' : '') + val + ' today';
                    changeEl.className = 'stat-change ' + (val >= 0 ? 'positive' : 'negative');
                }
            }

            // Update charts if helpers are available
            if (window.MCPCharts && typeof window.MCPCharts.createVerdictDistribution === 'function') {
                window.MCPCharts.createVerdictDistribution('verdict-dist-chart', {
                    malicious: data.malicious_count || 0,
                    suspicious: data.suspicious_count || 0,
                    clean: data.clean_count || 0,
                    unknown: data.unknown_count || 0
                });
            }
        });
    }

    /* --------------------------------------------------
       Recent Analyses Table
    -------------------------------------------------- */

    /**
     * Fetch the most recent analyses and populate the table body.
     */
    function loadRecentAnalyses() {
        apiFetch('/api/dashboard/recent').then(function (data) {
            if (!data) return;

            var tbody = document.getElementById('recent-analyses-body');
            if (!tbody) return;

            // Clear existing rows
            tbody.innerHTML = '';

            var analyses = Array.isArray(data) ? data : data.analyses || [];

            if (analyses.length === 0) {
                var emptyRow = document.createElement('tr');
                var emptyCell = document.createElement('td');
                emptyCell.colSpan = 5;
                emptyCell.style.textAlign = 'center';
                emptyCell.style.padding = '2rem';
                emptyCell.style.color = 'var(--text-secondary)';
                emptyCell.textContent = 'No analyses yet. Submit an IOC or upload a file to get started.';
                emptyRow.appendChild(emptyCell);
                tbody.appendChild(emptyRow);
                return;
            }

            analyses.forEach(function (item) {
                var tr = document.createElement('tr');

                // IOC / Indicator
                var tdIoc = document.createElement('td');
                tdIoc.className = 'ioc-cell';
                tdIoc.textContent = item.ioc || item.filename || '--';
                tr.appendChild(tdIoc);

                // Type
                var tdType = document.createElement('td');
                tdType.textContent = item.ioc_type || item.type || '--';
                tr.appendChild(tdType);

                // Verdict
                var tdVerdict = document.createElement('td');
                var badge = document.createElement('span');
                badge.className = 'verdict-badge verdict-' + verdictClass(item.verdict);
                badge.textContent = item.verdict || 'UNKNOWN';
                tdVerdict.appendChild(badge);
                tr.appendChild(tdVerdict);

                // Score
                var tdScore = document.createElement('td');
                tdScore.textContent = item.threat_score !== undefined ? item.threat_score + '/100' : '--';
                tr.appendChild(tdScore);

                // Time
                var tdTime = document.createElement('td');
                tdTime.textContent = timeAgo(item.created_at || item.timestamp);
                tdTime.title = item.created_at || item.timestamp || '';
                tr.appendChild(tdTime);

                tbody.appendChild(tr);
            });
        });
    }

    /* --------------------------------------------------
       Auto-Refresh
    -------------------------------------------------- */

    function startAutoRefresh() {
        stopAutoRefresh();
        refreshTimerId = setInterval(function () {
            loadDashboardStats();
            loadRecentAnalyses();
        }, REFRESH_INTERVAL_MS);
    }

    function stopAutoRefresh() {
        if (refreshTimerId) {
            clearInterval(refreshTimerId);
            refreshTimerId = null;
        }
    }

    /* --------------------------------------------------
       Quick IOC Submit
    -------------------------------------------------- */

    /**
     * Bind the quick-IOC form to POST the indicator to the analysis API.
     */
    function initQuickIOCForm() {
        var form = document.getElementById('quick-ioc-form');
        if (!form) return;

        form.addEventListener('submit', function (e) {
            e.preventDefault();

            var input = form.querySelector('input[name="ioc"]') || form.querySelector('input[type="text"]');
            if (!input) return;

            var iocValue = input.value.trim();
            if (!iocValue) {
                showToast('Please enter an IOC to analyze.', 'warning');
                return;
            }

            var submitBtn = form.querySelector('button[type="submit"]') || form.querySelector('button');
            if (submitBtn) submitBtn.disabled = true;

            apiFetch('/api/analysis/ioc', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ioc: iocValue })
            }).then(function (data) {
                if (submitBtn) submitBtn.disabled = false;

                if (data) {
                    showToast('IOC submitted successfully.', 'success');
                    input.value = '';
                    // Refresh data to reflect the new entry
                    loadDashboardStats();
                    loadRecentAnalyses();

                    // If the API returned an analysis_id, redirect to results
                    if (data.analysis_id) {
                        var analysisPage = '/analysis?id=' + encodeURIComponent(data.analysis_id);
                        window.location.href = analysisPage;
                    }
                }
            });
        });
    }

    /* --------------------------------------------------
       Sidebar Toggle (mobile)
    -------------------------------------------------- */

    function initSidebarToggle() {
        var toggleBtn = document.getElementById('sidebar-toggle');
        var sidebar = document.querySelector('.sidebar');
        var overlay = document.querySelector('.sidebar-overlay');

        if (!toggleBtn || !sidebar) return;

        toggleBtn.addEventListener('click', function () {
            sidebar.classList.toggle('open');
            if (overlay) overlay.classList.toggle('visible');
        });

        if (overlay) {
            overlay.addEventListener('click', function () {
                sidebar.classList.remove('open');
                overlay.classList.remove('visible');
            });
        }
    }

    /* --------------------------------------------------
       Initialization
    -------------------------------------------------- */

    function init() {
        loadDashboardStats();
        loadRecentAnalyses();
        initQuickIOCForm();
        initSidebarToggle();
        startAutoRefresh();

        // Pause refresh when the tab is not visible
        document.addEventListener('visibilitychange', function () {
            if (document.hidden) {
                stopAutoRefresh();
            } else {
                loadDashboardStats();
                loadRecentAnalyses();
                startAutoRefresh();
            }
        });
    }

    // Run when the DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Expose public API for other modules
    window.BTADashboard = {
        loadDashboardStats: loadDashboardStats,
        loadRecentAnalyses: loadRecentAnalyses,
        startAutoRefresh: startAutoRefresh,
        stopAutoRefresh: stopAutoRefresh,
        showToast: showToast
    };

})();
