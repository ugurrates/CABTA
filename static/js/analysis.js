/**
 * Blue Team Assistant - Analysis Page Logic
 * Author: Ugur Ates
 *
 * Handles IOC form submission, file upload with drag-and-drop,
 * WebSocket-driven progress updates, and rendering of analysis results.
 * Vanilla JavaScript - no frameworks required.
 */

(function () {
    'use strict';

    /* --------------------------------------------------
       State
    -------------------------------------------------- */
    var currentWebSocket = null; // BTAWebSocket instance

    /* --------------------------------------------------
       Utility helpers
    -------------------------------------------------- */

    /**
     * Perform a fetch with standard error handling.
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
                console.error('[BTA Analysis] API error (' + url + '):', err.message);
                showToast('Request failed: ' + err.message, 'error');
                return null;
            });
    }

    /**
     * Display a toast notification (delegates to dashboard.js if loaded,
     * otherwise provides its own minimal implementation).
     */
    function showToast(message, type) {
        if (window.BTADashboard && typeof window.BTADashboard.showToast === 'function') {
            window.BTADashboard.showToast(message, type);
            return;
        }
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
                if (toast.parentNode) toast.parentNode.removeChild(toast);
            }, 300);
        }, 4000);
    }

    /* --------------------------------------------------
       Progress helpers
    -------------------------------------------------- */

    /**
     * Show the progress container and reset its bar to 0%.
     */
    function showProgress(label) {
        var container = document.getElementById('analysis-progress');
        if (!container) return;

        container.classList.add('visible');

        var fill = container.querySelector('.progress-bar-fill');
        if (fill) {
            fill.style.width = '0%';
            fill.classList.add('animated');
        }

        var labelEl = container.querySelector('.progress-status');
        if (labelEl) {
            labelEl.textContent = label || 'Starting analysis...';
        }

        var pctEl = container.querySelector('.progress-percent');
        if (pctEl) {
            pctEl.textContent = '0%';
        }
    }

    /**
     * Update the progress bar percentage and optional status text.
     */
    function updateProgress(percent, statusText) {
        var container = document.getElementById('analysis-progress');
        if (!container) return;

        var pct = Math.min(Math.max(Math.round(percent), 0), 100);

        var fill = container.querySelector('.progress-bar-fill');
        if (fill) {
            fill.style.width = pct + '%';
        }

        var pctEl = container.querySelector('.progress-percent');
        if (pctEl) {
            pctEl.textContent = pct + '%';
        }

        if (statusText) {
            var labelEl = container.querySelector('.progress-status');
            if (labelEl) {
                labelEl.textContent = statusText;
            }
        }
    }

    /**
     * Hide the progress container and reset the animation class.
     */
    function hideProgress() {
        var container = document.getElementById('analysis-progress');
        if (!container) return;

        var fill = container.querySelector('.progress-bar-fill');
        if (fill) {
            fill.classList.remove('animated');
            fill.style.width = '100%';
        }

        // Brief delay so the user sees 100% before the bar disappears
        setTimeout(function () {
            container.classList.remove('visible');
        }, 600);
    }

    /* --------------------------------------------------
       WebSocket Progress Integration
    -------------------------------------------------- */

    /**
     * Open a WebSocket connection for the given analysis and bind
     * progress / completion / failure callbacks.
     */
    function connectProgressSocket(analysisId) {
        if (!window.BTAWebSocket) {
            console.warn('[BTA Analysis] BTAWebSocket not available, skipping live updates.');
            return;
        }

        // Tear down any previous connection
        if (currentWebSocket) {
            currentWebSocket.disconnect();
        }

        currentWebSocket = new window.BTAWebSocket();

        currentWebSocket.onProgress = function (data) {
            updateProgress(data.percent || 0, data.status || '');
        };

        currentWebSocket.onCompleted = function (data) {
            hideProgress();
            showToast('Analysis completed.', 'success');
            renderResults(data.result || data);
        };

        currentWebSocket.onFailed = function (data) {
            hideProgress();
            showToast('Analysis failed: ' + (data.error || 'Unknown error'), 'error');
        };

        currentWebSocket.connect(analysisId);
    }

    /* --------------------------------------------------
       IOC Form Submission
    -------------------------------------------------- */

    function initIOCForm() {
        var form = document.getElementById('ioc-analysis-form');
        if (!form) return;

        form.addEventListener('submit', function (e) {
            e.preventDefault();

            var input = form.querySelector('input[name="ioc"]') || form.querySelector('input[type="text"]');
            if (!input) return;

            var iocValue = input.value.trim();
            if (!iocValue) {
                showToast('Please enter an IOC value.', 'warning');
                return;
            }

            var submitBtn = form.querySelector('button[type="submit"]') || form.querySelector('button');
            if (submitBtn) submitBtn.disabled = true;

            showProgress('Submitting IOC for analysis...');

            apiFetch('/api/analysis/ioc', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ value: iocValue })
            }).then(function (data) {
                if (submitBtn) submitBtn.disabled = false;

                if (!data) {
                    hideProgress();
                    return;
                }

                showToast('IOC submitted.', 'success');

                if (data.analysis_id) {
                    connectProgressSocket(data.analysis_id);
                } else {
                    // If the result is returned synchronously
                    hideProgress();
                    renderResults(data);
                }
            });
        });
    }

    /* --------------------------------------------------
       File Upload with Drag-and-Drop
    -------------------------------------------------- */

    function initFileUpload() {
        var uploadArea = document.getElementById('file-upload-area');
        var fileInput = document.getElementById('file-upload-input');
        if (!uploadArea) return;

        // Click to open file dialog
        uploadArea.addEventListener('click', function () {
            if (fileInput) fileInput.click();
        });

        // Drag events
        uploadArea.addEventListener('dragenter', function (e) {
            e.preventDefault();
            e.stopPropagation();
            uploadArea.classList.add('drag-over');
        });

        uploadArea.addEventListener('dragover', function (e) {
            e.preventDefault();
            e.stopPropagation();
            uploadArea.classList.add('drag-over');
        });

        uploadArea.addEventListener('dragleave', function (e) {
            e.preventDefault();
            e.stopPropagation();
            uploadArea.classList.remove('drag-over');
        });

        uploadArea.addEventListener('drop', function (e) {
            e.preventDefault();
            e.stopPropagation();
            uploadArea.classList.remove('drag-over');

            var files = e.dataTransfer && e.dataTransfer.files;
            if (files && files.length > 0) {
                uploadFile(files[0]);
            }
        });

        // Standard file input change
        if (fileInput) {
            fileInput.addEventListener('change', function () {
                if (fileInput.files && fileInput.files.length > 0) {
                    uploadFile(fileInput.files[0]);
                }
            });
        }
    }

    /**
     * Upload a single file to the analysis endpoint.
     */
    function uploadFile(file) {
        if (!file) return;

        // Basic size check (50 MB)
        var MAX_SIZE = 50 * 1024 * 1024;
        if (file.size > MAX_SIZE) {
            showToast('File too large. Maximum size is 50 MB.', 'error');
            return;
        }

        showProgress('Uploading ' + file.name + '...');

        var formData = new FormData();
        formData.append('file', file);

        fetch('/api/analysis/file', {
            method: 'POST',
            body: formData
        })
        .then(function (response) {
            if (!response.ok) {
                throw new Error('HTTP ' + response.status + ' - ' + response.statusText);
            }
            return response.json();
        })
        .then(function (data) {
            if (!data) {
                hideProgress();
                return;
            }

            showToast('File uploaded successfully.', 'success');

            if (data.analysis_id) {
                connectProgressSocket(data.analysis_id);
            } else {
                hideProgress();
                renderResults(data);
            }
        })
        .catch(function (err) {
            console.error('[BTA Analysis] File upload error:', err.message);
            hideProgress();
            showToast('Upload failed: ' + err.message, 'error');
        });
    }

    /* --------------------------------------------------
       Render Analysis Results
    -------------------------------------------------- */

    /**
     * Populate the results container with structured analysis data.
     */
    function renderResults(result) {
        var container = document.getElementById('analysis-results');
        if (!container) return;

        container.classList.add('visible');
        container.innerHTML = '';

        if (!result) {
            container.innerHTML = '<p style="color:var(--text-secondary);">No results to display.</p>';
            return;
        }

        // --- Header row ---
        var header = document.createElement('div');
        header.className = 'results-header';

        var title = document.createElement('h3');
        title.textContent = 'Analysis Results';
        header.appendChild(title);

        if (result.verdict) {
            var badge = document.createElement('span');
            badge.className = 'verdict-badge verdict-' + verdictClass(result.verdict);
            badge.textContent = result.verdict;
            header.appendChild(badge);
        }
        container.appendChild(header);

        // --- Summary section ---
        if (result.threat_score !== undefined || result.ioc || result.ioc_type) {
            var summary = createSection('Summary');
            var dl = document.createElement('dl');
            dl.style.cssText = 'display:grid;grid-template-columns:auto 1fr;gap:0.35rem 1rem;margin:0;';

            if (result.ioc) addDLRow(dl, 'IOC', result.ioc);
            if (result.ioc_type) addDLRow(dl, 'Type', result.ioc_type);
            if (result.threat_score !== undefined) addDLRow(dl, 'Threat Score', result.threat_score + ' / 100');
            if (result.sources_checked) addDLRow(dl, 'Sources Checked', result.sources_checked);
            if (result.sources_flagged !== undefined) addDLRow(dl, 'Sources Flagged', result.sources_flagged);

            summary.appendChild(dl);
            container.appendChild(summary);
        }

        // --- Threat Score Gauge ---
        if (result.threat_score !== undefined && window.MCPCharts && typeof window.MCPCharts.createThreatScoreGauge === 'function') {
            var gaugeSection = createSection('Threat Score');
            var gaugeWrap = document.createElement('div');
            gaugeWrap.className = 'score-gauge';
            var gaugeCanvas = document.createElement('canvas');
            gaugeCanvas.id = 'result-threat-gauge';
            gaugeWrap.appendChild(gaugeCanvas);
            gaugeSection.appendChild(gaugeWrap);
            container.appendChild(gaugeSection);

            // Render gauge after canvas is in the DOM
            setTimeout(function () {
                window.MCPCharts.createThreatScoreGauge('result-threat-gauge', result.threat_score);
            }, 50);
        }

        // --- Scoring breakdown radar ---
        if (result.tool_scores && window.MCPCharts && typeof window.MCPCharts.createScoringBreakdownRadar === 'function') {
            var radarSection = createSection('Scoring Breakdown');
            var radarCanvas = document.createElement('canvas');
            radarCanvas.id = 'result-scoring-radar';
            radarCanvas.style.maxHeight = '350px';
            radarSection.appendChild(radarCanvas);
            container.appendChild(radarSection);

            setTimeout(function () {
                window.MCPCharts.createScoringBreakdownRadar('result-scoring-radar', result.tool_scores);
            }, 50);
        }

        // --- Source details ---
        if (result.sources && result.sources.length) {
            var sourcesSection = createSection('Source Details');
            result.sources.forEach(function (src) {
                var card = document.createElement('div');
                card.style.cssText = 'padding:0.6rem 0.85rem;margin-bottom:0.5rem;border-left:3px solid var(--color-info);background:var(--bg-tertiary);border-radius:4px;';
                var name = document.createElement('strong');
                name.textContent = src.name || 'Source';
                card.appendChild(name);

                if (src.status) {
                    var status = document.createElement('span');
                    status.style.cssText = 'margin-left:0.75rem;font-size:0.85rem;';
                    status.textContent = src.status;
                    card.appendChild(status);
                }

                if (src.details) {
                    var details = document.createElement('p');
                    details.style.cssText = 'margin:0.3rem 0 0;font-size:0.85rem;color:var(--text-secondary);';
                    details.textContent = src.details;
                    card.appendChild(details);
                }
                sourcesSection.appendChild(card);
            });
            container.appendChild(sourcesSection);
        }

        // --- LLM Analysis ---
        if (result.llm_analysis) {
            var llmSection = createSection('LLM Analysis');
            var llmPre = document.createElement('pre');
            llmPre.style.cssText = 'white-space:pre-wrap;word-break:break-word;margin:0;font-size:0.85rem;';
            llmPre.textContent = result.llm_analysis;
            llmSection.appendChild(llmPre);
            container.appendChild(llmSection);
        }

        // --- Detection Rules ---
        if (result.detection_rules && result.detection_rules.length) {
            var rulesSection = createSection('Detection Rules');
            result.detection_rules.forEach(function (rule) {
                var ruleTitle = document.createElement('h5');
                ruleTitle.style.cssText = 'margin:0 0 0.3rem;font-size:0.88rem;';
                ruleTitle.textContent = rule.type || 'Rule';
                rulesSection.appendChild(ruleTitle);

                var pre = document.createElement('pre');
                pre.style.cssText = 'white-space:pre-wrap;word-break:break-word;font-size:0.83rem;margin:0 0 0.75rem;padding:0.6rem;background:var(--bg-tertiary);border:1px solid var(--border-color);border-radius:4px;';
                pre.textContent = rule.rule || '';
                rulesSection.appendChild(pre);
            });
            container.appendChild(rulesSection);
        }

        // --- Recommendations ---
        if (result.recommendations && result.recommendations.length) {
            var recSection = createSection('Recommendations');
            var ol = document.createElement('ol');
            ol.style.cssText = 'margin:0;padding-left:1.25rem;';
            result.recommendations.forEach(function (rec) {
                var li = document.createElement('li');
                li.style.cssText = 'margin-bottom:0.3rem;font-size:0.88rem;color:var(--text-primary);';
                li.textContent = rec;
                ol.appendChild(li);
            });
            recSection.appendChild(ol);
            container.appendChild(recSection);
        }
    }

    /* --------------------------------------------------
       Rendering helpers
    -------------------------------------------------- */

    function createSection(titleText) {
        var section = document.createElement('div');
        section.className = 'result-section';
        var h4 = document.createElement('h4');
        h4.textContent = titleText;
        section.appendChild(h4);
        return section;
    }

    function addDLRow(dl, label, value) {
        var dt = document.createElement('dt');
        dt.style.cssText = 'font-weight:600;font-size:0.85rem;color:var(--text-secondary);';
        dt.textContent = label;
        dl.appendChild(dt);

        var dd = document.createElement('dd');
        dd.style.cssText = 'margin:0;font-size:0.88rem;color:var(--text-primary);';
        dd.textContent = value;
        dl.appendChild(dd);
    }

    function verdictClass(verdict) {
        if (!verdict) return 'unknown';
        var v = verdict.toLowerCase();
        if (v === 'malicious') return 'malicious';
        if (v === 'suspicious') return 'suspicious';
        if (v === 'clean') return 'clean';
        return 'unknown';
    }

    /* --------------------------------------------------
       Initialization
    -------------------------------------------------- */

    function init() {
        initIOCForm();
        initFileUpload();

        // If the page was loaded with an analysis ID in the query string,
        // immediately connect to the WebSocket for live updates.
        var params = new URLSearchParams(window.location.search);
        var analysisId = params.get('id');
        if (analysisId) {
            showProgress('Loading analysis...');
            connectProgressSocket(analysisId);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    /* --------------------------------------------------
       Email Analysis
    -------------------------------------------------- */

    /**
     * Upload an .eml file to /api/analysis/email and poll for results.
     *
     * @param {File}   file      The .eml file to analyse.
     * @param {Object} callbacks { onProgress(data), onComplete(data), onError(err) }
     */
    function startEmailAnalysis(file, callbacks) {
        callbacks = callbacks || {};

        var formData = new FormData();
        formData.append('file', file);

        // Phase 1: upload
        if (callbacks.onProgress) callbacks.onProgress({ percent: 5, message: 'Uploading email...' });

        fetch('/api/analysis/email', {
            method: 'POST',
            body: formData
        })
        .then(function (response) {
            if (!response.ok) throw new Error('HTTP ' + response.status);
            return response.json();
        })
        .then(function (data) {
            if (!data || !data.analysis_id) {
                throw new Error('No analysis ID returned');
            }

            if (callbacks.onProgress) callbacks.onProgress({ percent: 15, message: 'Email uploaded. Starting analysis...' });

            // Phase 2: poll for completion
            pollAnalysis(data.analysis_id, callbacks, 'email');
        })
        .catch(function (err) {
            if (callbacks.onError) callbacks.onError(err);
        });
    }

    // pollEmailAnalysis removed - replaced by generic pollAnalysis

    /**
     * Convert raw email analysis JSON into tab-friendly HTML fragments.
     * Returns { overview, headers, auth, links, attachments }.
     */
    function renderEmailResult(result) {
        if (!result) return {};

        var res = result.result ? (typeof result.result === 'string' ? JSON.parse(result.result) : result.result) : result;
        var output = {};

        // Overview tab
        var ov = '<div class="mb-3">';
        ov += '<h5>Verdict: <span class="badge bg-' + emailVerdictColor(res.verdict) + '">' + (res.verdict || 'UNKNOWN') + '</span></h5>';
        if (res.composite_score !== undefined) {
            ov += '<p><strong>Phishing Score:</strong> ' + res.composite_score + '/100</p>';
        }
        if (res.email_data) {
            var ed = res.email_data;
            ov += '<table class="table table-sm" style="color:var(--text-primary);">';
            if (ed.subject) ov += '<tr><td><strong>Subject</strong></td><td>' + escHtml(ed.subject) + '</td></tr>';
            if (ed.from) ov += '<tr><td><strong>From</strong></td><td>' + escHtml(ed.from) + '</td></tr>';
            if (ed.to) ov += '<tr><td><strong>To</strong></td><td>' + escHtml(ed.to) + '</td></tr>';
            if (ed.date) ov += '<tr><td><strong>Date</strong></td><td>' + escHtml(ed.date) + '</td></tr>';
            if (ed.message_id) ov += '<tr><td><strong>Message-ID</strong></td><td>' + escHtml(ed.message_id) + '</td></tr>';
            ov += '</table>';
        }
        ov += '</div>';
        output.overview = ov;

        // Headers tab
        if (res.email_data && res.email_data.headers) {
            var hdr = '<table class="table table-sm table-striped" style="color:var(--text-primary);">';
            hdr += '<thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>';
            var headers = res.email_data.headers;
            if (Array.isArray(headers)) {
                headers.forEach(function (h) {
                    hdr += '<tr><td><code>' + escHtml(h.name || h[0] || '') + '</code></td>';
                    hdr += '<td style="word-break:break-all;">' + escHtml(h.value || h[1] || '') + '</td></tr>';
                });
            } else if (typeof headers === 'object') {
                Object.keys(headers).forEach(function (k) {
                    hdr += '<tr><td><code>' + escHtml(k) + '</code></td>';
                    hdr += '<td style="word-break:break-all;">' + escHtml(String(headers[k])) + '</td></tr>';
                });
            }
            hdr += '</tbody></table>';
            output.headers = hdr;
        }

        // Authentication tab (SPF/DKIM/DMARC)
        if (res.forensics && res.forensics.authentication) {
            var auth = res.forensics.authentication;
            var at = '<div class="row g-3 mb-3">';
            ['spf', 'dkim', 'dmarc'].forEach(function (proto) {
                var d = auth[proto] || {};
                var st = (d.status || 'NONE').toUpperCase();
                var color = st === 'PASS' ? 'success' : (st === 'FAIL' ? 'danger' : 'secondary');
                at += '<div class="col-md-4"><div class="card"><div class="card-body text-center">';
                at += '<h6>' + proto.toUpperCase() + '</h6>';
                at += '<span class="badge bg-' + color + ' fs-6">' + st + '</span>';
                if (d.details) at += '<p class="mt-2 mb-0 small" style="color:var(--text-secondary);">' + escHtml(d.details) + '</p>';
                at += '</div></div></div>';
            });
            at += '</div>';
            if (auth.authentication_score !== undefined) {
                at += '<p><strong>Authentication Score:</strong> ' + auth.authentication_score + '/100</p>';
            }
            output.auth = at;
        }

        // Links tab
        if (res.email_data && res.email_data.urls && res.email_data.urls.length > 0) {
            var lt = '<table class="table table-sm" style="color:var(--text-primary);">';
            lt += '<thead><tr><th>#</th><th>URL</th></tr></thead><tbody>';
            res.email_data.urls.forEach(function (u, idx) {
                lt += '<tr><td>' + (idx + 1) + '</td><td style="word-break:break-all;">' + escHtml(u) + '</td></tr>';
            });
            lt += '</tbody></table>';
            output.links = lt;
        }

        // Attachments tab
        if (res.email_data && res.email_data.attachments && res.email_data.attachments.length > 0) {
            var att = '<table class="table table-sm" style="color:var(--text-primary);">';
            att += '<thead><tr><th>Filename</th><th>Type</th><th>Size</th></tr></thead><tbody>';
            res.email_data.attachments.forEach(function (a) {
                att += '<tr><td>' + escHtml(a.filename || 'unknown') + '</td>';
                att += '<td>' + escHtml(a.content_type || 'N/A') + '</td>';
                att += '<td>' + (a.size ? formatBytes(a.size) : 'N/A') + '</td></tr>';
            });
            att += '</tbody></table>';
            output.attachments = att;
        }

        /* --- Pass through rich data fields for template rendering --- */

        /* Phishing risk */
        // Bug 3 fix: include additional risk factors from forensics and advanced_analysis
        if (res.composite_score !== undefined || res.base_phishing_score !== undefined) {
            var factors = [];
            if (res.email_data) {
                if (res.email_data.spf) factors.push({ name: 'SPF', status: res.email_data.spf });
                if (res.email_data.dkim) factors.push({ name: 'DKIM', status: res.email_data.dkim });
                if (res.email_data.dmarc) factors.push({ name: 'DMARC', status: res.email_data.dmarc });
            }
            // Forensics score
            if (res.forensics && res.forensics.forensics_score !== undefined) {
                factors.push({ name: 'Forensics Score', status: String(res.forensics.forensics_score) });
            }
            // Advanced analysis factors
            if (res.advanced_analysis) {
                var aa = res.advanced_analysis;
                if (aa.link_mismatches && aa.link_mismatches.length > 0) {
                    factors.push({ name: 'Link Mismatches', status: String(aa.link_mismatches.length) + ' found' });
                }
                if (aa.lookalike_domains && aa.lookalike_domains.length > 0) {
                    factors.push({ name: 'Lookalike Domains', status: String(aa.lookalike_domains.length) + ' found' });
                }
                if (aa.html_obfuscation !== undefined) {
                    factors.push({ name: 'HTML Obfuscation', status: String(aa.html_obfuscation) });
                }
                if (aa.brand_impersonation && aa.brand_impersonation.length > 0) {
                    factors.push({ name: 'Brand Impersonation', status: aa.brand_impersonation.join(', ') });
                }
            }
            output.phishingRisk = {
                score: res.composite_score || res.base_phishing_score || 0,
                factors: factors
            };
        }

        /* Sender info */
        if (res.email_data && res.email_data.from) {
            output.sender = {
                email: res.email_data.from,
                display_name: res.email_data.from_display || '',
                reply_to: res.email_data.reply_to || ''
            };
            output.subject = res.email_data.subject || '';
        }

        /* Auth results for enhanced dashboard */
        if (res.forensics && res.forensics.authentication) {
            output.authResults = res.forensics.authentication;
        } else if (res.email_data) {
            output.authResults = {
                spf: { status: res.email_data.spf || 'NONE' },
                dkim: { status: res.email_data.dkim || 'NONE' },
                dmarc: { status: res.email_data.dmarc || 'NONE' }
            };
        }

        /* Links data for enhanced table */
        // Bug 2 fix: extract domain from URL so renderLinkTable has the domain field it expects
        if (res.email_data && res.email_data.urls && res.email_data.urls.length > 0) {
            output.linksData = res.email_data.urls.map(function(u) {
                var urlStr = typeof u === 'string' ? u : (u.url || u);
                var domain = '';
                try { domain = new URL(urlStr).hostname; } catch(e) {}
                return typeof u === 'object' ? u : { url: urlStr, domain: domain };
            });
        }

        /* Attachments data for enhanced cards */
        if (res.email_data && res.email_data.attachments && res.email_data.attachments.length > 0) {
            output.attachmentsData = res.email_data.attachments;
        }

        /* Advanced analysis (link mismatches, lookalike domains, HTML obfuscation, etc.) */
        if (res.advanced_analysis) {
            output.advanced_analysis = res.advanced_analysis;
        }

        /* Forensics (relay analysis, infrastructure, sender reputation, etc.) */
        if (res.forensics) {
            output.forensics = res.forensics;
        }

        /* Detection rules (8 types: KQL, SPL, Sigma, YARA, FortiMail, Proofpoint, Mimecast, M365) */
        if (res.detection_rules) {
            output.detection_rules = res.detection_rules;
        }

        /* LLM analysis */
        if (res.llm_analysis) {
            output.llm_analysis = res.llm_analysis;
        }

        /* IOCs found */
        if (res.iocs_found) {
            output.iocs_found = res.iocs_found;
        }

        /* Raw output (pipeline steps) */
        if (res.raw_output) {
            output.raw_output = res.raw_output;
        }

        return output;
    }

    function emailVerdictColor(verdict) {
        if (!verdict) return 'secondary';
        var v = verdict.toUpperCase();
        if (v === 'PHISHING' || v === 'MALICIOUS') return 'danger';
        if (v === 'SUSPICIOUS' || v === 'SPAM') return 'warning';
        if (v === 'CLEAN') return 'success';
        return 'secondary';
    }

    function escHtml(str) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(str || ''));
        return div.innerHTML;
    }

    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / 1048576).toFixed(1) + ' MB';
    }

    /* --------------------------------------------------
       IOC Analysis (callback-based, used by analysis_ioc.html)
    -------------------------------------------------- */

    /**
     * Submit an IOC value to /api/analysis/ioc and poll for results.
     *
     * @param {string} iocValue  The IOC to investigate.
     * @param {string} iocType   IOC type or 'auto'.
     * @param {Object} callbacks { onProgress(data), onComplete(data), onError(err) }
     */
    function startIOCAnalysis(iocValue, iocType, callbacks) {
        callbacks = callbacks || {};

        if (callbacks.onProgress) callbacks.onProgress({ percent: 5, message: 'Submitting IOC...' });

        fetch('/api/analysis/ioc', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ value: iocValue, ioc_type: iocType || 'auto' })
        })
        .then(function (response) {
            if (!response.ok) throw new Error('HTTP ' + response.status);
            return response.json();
        })
        .then(function (data) {
            if (!data || !data.analysis_id) {
                throw new Error('No analysis ID returned');
            }
            if (callbacks.onProgress) callbacks.onProgress({ percent: 15, message: 'IOC submitted. Starting investigation...' });
            pollAnalysis(data.analysis_id, callbacks, 'ioc');
        })
        .catch(function (err) {
            if (callbacks.onError) callbacks.onError(err);
        });
    }

    /* --------------------------------------------------
       File Analysis (callback-based, used by analysis_file.html)
    -------------------------------------------------- */

    /**
     * Upload a file to /api/analysis/file and poll for results.
     *
     * @param {File}   file      The file to analyse.
     * @param {Object} callbacks { onProgress(data), onComplete(data), onError(err) }
     */
    function startFileAnalysis(file, callbacks) {
        callbacks = callbacks || {};

        var formData = new FormData();
        formData.append('file', file);

        if (callbacks.onProgress) callbacks.onProgress({ percent: 5, message: 'Uploading file...' });

        fetch('/api/analysis/file', {
            method: 'POST',
            body: formData
        })
        .then(function (response) {
            if (!response.ok) throw new Error('HTTP ' + response.status);
            return response.json();
        })
        .then(function (data) {
            if (!data || !data.analysis_id) {
                throw new Error('No analysis ID returned');
            }
            if (callbacks.onProgress) callbacks.onProgress({ percent: 15, message: 'File uploaded. Starting analysis...' });
            pollAnalysis(data.analysis_id, callbacks, 'file');
        })
        .catch(function (err) {
            if (callbacks.onError) callbacks.onError(err);
        });
    }

    /* --------------------------------------------------
       Generic Analysis Poller
    -------------------------------------------------- */

    /**
     * Poll the analysis status endpoint until completion or failure.
     * Works for IOC, file, and email analyses.
     */
    function pollAnalysis(analysisId, callbacks, analysisType, attempt) {
        attempt = attempt || 0;
        var MAX_ATTEMPTS = 180; // ~3 min at 1s intervals
        var POLL_INTERVAL = 1000;

        if (attempt > MAX_ATTEMPTS) {
            if (callbacks.onError) callbacks.onError(new Error('Analysis timed out'));
            return;
        }

        apiFetch('/api/analysis/' + analysisId + '/status')
            .then(function (statusData) {
                if (!statusData) {
                    if (callbacks.onError) callbacks.onError(new Error('Failed to fetch status'));
                    return;
                }

                var pct = statusData.progress || 0;
                var msg = statusData.current_step || 'Analyzing...';

                if (statusData.status === 'completed' || statusData.status === 'complete') {
                    return apiFetch('/api/analysis/' + analysisId).then(function (fullResult) {
                        if (!fullResult) {
                            if (callbacks.onError) callbacks.onError(new Error('Failed to fetch analysis results'));
                            return;
                        }
                        if (callbacks.onProgress) callbacks.onProgress({ percent: 100, message: 'Analysis complete.' });
                        if (callbacks.onComplete) {
                            if (analysisType === 'ioc') {
                                /* Pass raw result data so the template's renderStructuredResult handles it */
                                var rawRes = fullResult.result ? (typeof fullResult.result === 'string' ? JSON.parse(fullResult.result) : fullResult.result) : fullResult;
                                callbacks.onComplete(rawRes);
                            } else {
                                var rendered;
                                if (analysisType === 'email') {
                                    rendered = renderEmailResult(fullResult);
                                } else if (analysisType === 'file') {
                                    rendered = renderFileResult(fullResult);
                                } else {
                                    rendered = renderIOCResult(fullResult);
                                }
                                callbacks.onComplete(rendered);
                            }
                        }
                    });
                }

                if (statusData.status === 'failed' || statusData.status === 'error') {
                    if (callbacks.onError) callbacks.onError(new Error(statusData.current_step || 'Analysis failed'));
                    return;
                }

                if (callbacks.onProgress) {
                    callbacks.onProgress({ percent: Math.max(15, pct), message: msg });
                }

                setTimeout(function () {
                    pollAnalysis(analysisId, callbacks, analysisType, attempt + 1);
                }, POLL_INTERVAL);
            });
    }

    /* --------------------------------------------------
       IOC Result Renderer
    -------------------------------------------------- */

    function renderIOCResult(result) {
        if (!result) return {};
        var res = result.result ? (typeof result.result === 'string' ? JSON.parse(result.result) : result.result) : result;

        var html = '<div class="mb-3">';

        // Verdict badge
        var verdict = res.verdict || result.verdict || 'UNKNOWN';
        var score = res.threat_score !== undefined ? res.threat_score : (result.score !== undefined ? result.score : null);
        var vColor = verdict.toUpperCase() === 'MALICIOUS' ? 'danger' : (verdict.toUpperCase() === 'SUSPICIOUS' ? 'warning' : (verdict.toUpperCase() === 'CLEAN' ? 'success' : 'secondary'));

        html += '<h5>Verdict: <span class="badge bg-' + vColor + '">' + escHtml(verdict) + '</span></h5>';
        if (score !== null) html += '<p><strong>Threat Score:</strong> ' + score + '/100</p>';

        // IOC info
        if (res.ioc) html += '<p><strong>IOC:</strong> <code>' + escHtml(res.ioc) + '</code></p>';
        if (res.ioc_type) html += '<p><strong>Type:</strong> ' + escHtml(res.ioc_type) + '</p>';

        // Sources checked
        if (res.sources_checked) html += '<p><strong>Sources Checked:</strong> ' + res.sources_checked + '</p>';
        if (res.sources_flagged !== undefined) html += '<p><strong>Sources Flagged:</strong> ' + res.sources_flagged + '</p>';

        // Source details - backend returns an object {sourceName: {status, ...}}
        var sourcesObj = res.sources || res.threat_intel_results || {};
        var sourceKeys = Object.keys(sourcesObj);
        if (sourceKeys.length > 0) {
            html += '<h6 class="mt-3">Source Details</h6>';
            html += '<div class="list-group">';
            sourceKeys.forEach(function (srcName) {
                var src = sourcesObj[srcName];
                if (!src || typeof src !== 'object') return;
                var flagged = (src.status === '✓' || (src.score && src.score > 0));
                var bColor = flagged ? 'danger' : 'success';
                html += '<div class="list-group-item" style="background-color:var(--bg-tertiary);color:var(--text-primary);border-left:3px solid var(--' + bColor + ',#198754);">';
                html += '<strong>' + escHtml(srcName) + '</strong>';
                html += ' <span class="badge bg-' + bColor + ' ms-2">' + escHtml(src.status || (flagged ? 'Flagged' : 'Clean')) + '</span>';
                // Show key details
                var details = [];
                if (src.detections) details.push('Detections: ' + src.detections);
                if (src.botnet) details.push('Botnet: ' + src.botnet);
                if (src.malware) details.push('Malware: ' + src.malware);
                if (src.threat) details.push('Threat: ' + src.threat);
                if (src.score) details.push('Score: ' + src.score);
                if (src.error) details.push('Error: ' + src.error);
                if (src.message) details.push(src.message);
                if (details.length > 0) {
                    html += '<p class="mb-0 mt-1 small" style="color:var(--text-secondary);">' + escHtml(details.join(' | ')) + '</p>';
                }
                html += '</div>';
            });
            html += '</div>';
        }

        // LLM Analysis (can be object or string)
        if (res.llm_analysis) {
            var llm = res.llm_analysis;
            html += '<h6 class="mt-3">AI Analysis</h6>';
            if (typeof llm === 'object') {
                if (llm.analysis) {
                    html += '<div style="background:var(--bg-tertiary);padding:0.75rem;border-radius:4px;color:var(--text-primary);margin-bottom:0.5rem;">';
                    if (llm.verdict) html += '<strong>LLM Verdict:</strong> <span class="badge bg-' + (llm.verdict.toUpperCase() === 'MALICIOUS' ? 'danger' : (llm.verdict.toUpperCase() === 'SUSPICIOUS' ? 'warning' : 'success')) + ' mb-2">' + escHtml(llm.verdict) + '</span><br>';
                    html += escHtml(llm.analysis);
                    html += '</div>';
                }
                if (llm.recommendations && Array.isArray(llm.recommendations)) {
                    html += '<h6 class="mt-2">AI Recommendations</h6><ol>';
                    llm.recommendations.forEach(function (r) { html += '<li>' + escHtml(r) + '</li>'; });
                    html += '</ol>';
                }
                if (llm.note) {
                    html += '<p class="text-muted small"><em>' + escHtml(llm.note) + '</em></p>';
                }
                if (llm.error) {
                    html += '<p class="text-warning small"><em>LLM Error: ' + escHtml(llm.error) + '</em></p>';
                }
            } else {
                html += '<pre style="white-space:pre-wrap;word-break:break-word;background:var(--bg-tertiary);padding:0.75rem;border-radius:4px;color:var(--text-primary);">' + escHtml(String(llm)) + '</pre>';
            }
        }

        // Detection Rules (object: {kql, sigma, yara, spl} or array)
        if (res.detection_rules) {
            var rules = res.detection_rules;
            html += '<h6 class="mt-3">Detection Rules</h6>';
            if (Array.isArray(rules)) {
                rules.forEach(function (rule) {
                    html += '<p class="mb-1"><strong>' + escHtml(rule.type || 'Rule') + '</strong></p>';
                    html += '<pre style="white-space:pre-wrap;word-break:break-word;background:var(--bg-tertiary);padding:0.75rem;border-radius:4px;font-size:0.83rem;color:var(--text-primary);">' + escHtml(rule.rule || '') + '</pre>';
                });
            } else if (typeof rules === 'object') {
                Object.keys(rules).forEach(function (ruleType) {
                    var ruleContent = rules[ruleType];
                    if (!ruleContent) return;
                    html += '<p class="mb-1"><strong>' + escHtml(ruleType.toUpperCase()) + '</strong></p>';
                    html += '<pre style="white-space:pre-wrap;word-break:break-word;background:var(--bg-tertiary);padding:0.75rem;border-radius:4px;font-size:0.83rem;color:var(--text-primary);">' + escHtml(String(ruleContent)) + '</pre>';
                });
            }
        }

        // Recommendations
        if (res.recommendations && res.recommendations.length) {
            html += '<h6 class="mt-3">Recommendations</h6><ol>';
            res.recommendations.forEach(function (r) {
                html += '<li>' + escHtml(r) + '</li>';
            });
            html += '</ol>';
        }

        // MITRE ATT&CK
        if (res.mitre_mapping && res.mitre_mapping.length) {
            html += '<h6 class="mt-3">MITRE ATT&CK Mapping</h6>';
            html += '<table class="table table-sm" style="color:var(--text-primary);"><thead><tr><th>Technique</th><th>ID</th><th>Tactic</th></tr></thead><tbody>';
            res.mitre_mapping.forEach(function (m) {
                html += '<tr><td>' + escHtml(m.name || m.technique || '') + '</td>';
                html += '<td><code>' + escHtml(m.id || m.technique_id || '') + '</code></td>';
                html += '<td>' + escHtml(m.tactic || '') + '</td></tr>';
            });
            html += '</tbody></table>';
        }

        html += '</div>';
        return { html: html };
    }

    /* --------------------------------------------------
       File Result Renderer
    -------------------------------------------------- */

    /* --------------------------------------------------
       File Result Renderer - Helper Utilities
    -------------------------------------------------- */

    function scoreBarColor(score) {
        if (score <= 25) return '#198754';
        if (score <= 50) return '#fd7e14';
        return '#dc3545';
    }

    function formatTimestamp(ts) {
        if (!ts) return 'N/A';
        if (typeof ts === 'number') {
            var d = new Date(ts > 1e12 ? ts : ts * 1000);
            return d.toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC');
        }
        return String(ts);
    }

    function machineArch(val) {
        if (!val) return 'Unknown';
        var s = String(val).toLowerCase();
        if (s === '0x14c' || s === '332') return 'x86 (i386)';
        if (s === '0x8664' || s === '34404') return 'AMD64 (x86-64)';
        if (s === '0x1c0' || s === '448') return 'ARM';
        if (s === '0xaa64' || s === '43620') return 'ARM64';
        return escHtml(String(val));
    }

    /**
     * Copy detection rule text to clipboard.
     * Called from onclick handlers in rendered detection rule blocks.
     * Content source is a pre-sanitized pre element rendered via escHtml.
     */
    function copyRuleToClipboard(btn, preId) {
        var pre = document.getElementById(preId);
        if (!pre) return;
        navigator.clipboard.writeText(pre.textContent.trim()).then(function () {
            btn.classList.add('copied');
            btn.textContent = 'Copied!';
            setTimeout(function () {
                btn.classList.remove('copied');
                /* Restore button content safely using DOM methods */
                while (btn.firstChild) btn.removeChild(btn.firstChild);
                var icon = document.createElement('i');
                icon.className = 'bi bi-clipboard';
                btn.appendChild(icon);
                btn.appendChild(document.createTextNode(' Copy'));
            }, 1500);
        });
    }
    window.copyRuleToClipboard = copyRuleToClipboard;

    function toggleStringCategory(catId) {
        var el = document.getElementById(catId);
        if (el) el.classList.toggle('show');
    }
    window.toggleStringCategory = toggleStringCategory;

    /**
     * Build the file analysis result HTML for all tabs.
     *
     * All user-sourced data is escaped through escHtml() before being
     * inserted into HTML strings. The resulting fragments are then set
     * via setSanitizedHTML() in analysis_file.html which is the
     * designated safe rendering path per the application architecture.
     */
    function renderFileResult(result) {
        if (!result) return {};
        var res = result.result ? (typeof result.result === 'string' ? JSON.parse(result.result) : result.result) : result;
        var meta = result.metadata || result.input || {};

        // Bug 1 fix: Fallback to result data for hashes and file info when history data is loaded
        if (!meta.sha256 && res.hashes) {
            meta.sha256 = res.hashes.sha256;
            meta.sha1 = res.hashes.sha1;
            meta.md5 = res.hashes.md5;
        }
        if (!meta.filename && res.file_info) {
            meta.filename = res.file_info.name || res.file_info.filename;
            meta.size = res.file_info.size || res.file_info.file_size;
        }

        var output = {};

        /* ===== OVERVIEW TAB ===== */
        var verdict = res.verdict || result.verdict || 'UNKNOWN';
        // Bug 5 fix: composite_score fallback for file analysis
        var score = res.threat_score !== undefined ? res.threat_score :
                    (res.composite_score !== undefined ? res.composite_score :
                    (result.score !== undefined ? result.score : null));
        var vColor = verdict.toUpperCase() === 'MALICIOUS' ? 'danger' : (verdict.toUpperCase() === 'SUSPICIOUS' ? 'warning' : (verdict.toUpperCase() === 'CLEAN' ? 'success' : 'secondary'));

        var ov = '';
        /* Threat gauge + verdict */
        if (score !== null && window.renderThreatGauge) {
            var confidence = 'Medium';
            if (res.scoring && res.scoring.confidence !== undefined) {
                var c = parseFloat(res.scoring.confidence);
                confidence = c >= 0.7 ? 'High' : (c >= 0.4 ? 'Medium' : 'Low');
            }
            ov += window.renderThreatGauge(score, confidence);
        } else {
            ov += '<h5>Verdict: <span class="badge bg-' + vColor + '">' + escHtml(verdict) + '</span></h5>';
            if (score !== null) ov += '<p><strong>Threat Score:</strong> ' + score + '/100</p>';
        }

        /* File info */
        var fi = res.file_info || {};
        ov += '<div class="row g-3 mt-2"><div class="col-md-6">';
        if (meta.filename) ov += '<p class="mb-1"><i class="bi bi-file-earmark me-1 text-accent"></i><strong>File:</strong> ' + escHtml(meta.filename) + '</p>';
        if (meta.size) ov += '<p class="mb-1"><i class="bi bi-hdd me-1 text-accent"></i><strong>Size:</strong> ' + formatBytes(meta.size) + '</p>';
        if (res.file_type || fi.type || fi.file_type) ov += '<p class="mb-1"><i class="bi bi-tag me-1 text-accent"></i><strong>Type:</strong> ' + escHtml(res.file_type || fi.type || fi.file_type) + '</p>';
        if (fi.mime_type || fi.mime) ov += '<p class="mb-1"><i class="bi bi-filetype-raw me-1 text-accent"></i><strong>MIME:</strong> ' + escHtml(fi.mime_type || fi.mime) + '</p>';
        if (fi.magic) ov += '<p class="mb-1"><i class="bi bi-magic me-1 text-accent"></i><strong>Magic:</strong> ' + escHtml(fi.magic) + '</p>';
        ov += '</div><div class="col-md-6">';
        if ((meta.sha256 || meta.md5 || meta.sha1) && window.renderHashCard) {
            var extraHashes = {};
            if (res.hashes) {
                extraHashes.sha512 = res.hashes.sha512 || '';
                extraHashes.ssdeep = res.hashes.ssdeep || '';
                extraHashes.tlsh = res.hashes.tlsh || '';
                extraHashes.imphash = res.hashes.imphash || '';
            }
            ov += window.renderHashCard(meta.md5 || '', meta.sha1 || '', meta.sha256 || '', extraHashes);
        }
        ov += '</div></div>';

        /* Summary */
        if (res.summary) ov += '<div class="alert alert-secondary mt-3" style="background:rgba(0,0,0,0.15);border-color:rgba(255,255,255,0.08);"><i class="bi bi-info-circle me-1"></i>' + escHtml(res.summary) + '</div>';

        /* Threat indicators */
        var sa = res.static_analysis || {};
        var threatIndicators = sa.threat_indicators || res.threat_indicators || [];
        if (threatIndicators.length > 0) {
            ov += '<div class="mt-3"><h6><i class="bi bi-exclamation-triangle text-danger me-1"></i>Threat Indicators</h6>';
            threatIndicators.forEach(function (ti) {
                var tiText = typeof ti === 'string' ? ti : (ti.description || ti.indicator || JSON.stringify(ti));
                ov += '<div class="threat-indicator-item"><i class="bi bi-exclamation-diamond-fill ti-icon"></i><span>' + escHtml(tiText) + '</span></div>';
            });
            ov += '</div>';
        }

        /* Bug 4 fix: Capabilities */
        if (res.capabilities && Array.isArray(res.capabilities) && res.capabilities.length > 0) {
            ov += '<div class="mt-3"><h6><i class="bi bi-gear me-1 text-accent"></i>Capabilities <span class="badge bg-secondary">' + res.capabilities.length + '</span></h6>';
            /* Check if capabilities have MITRE technique structure */
            var hasMitreFields = res.capabilities.some(function (cap) {
                return typeof cap === 'object' && (cap.tactic || cap.technique || cap.technique_id);
            });
            if (hasMitreFields) {
                ov += '<table class="table table-sm" style="color:var(--bs-body-color);font-size:0.83rem;">';
                ov += '<thead><tr><th>ID</th><th>Tactic</th><th>Technique</th><th>Description</th></tr></thead><tbody>';
                res.capabilities.forEach(function (cap) {
                    if (typeof cap === 'string') {
                        ov += '<tr><td colspan="4">' + escHtml(cap) + '</td></tr>';
                    } else {
                        ov += '<tr>';
                        ov += '<td><span style="font-family:monospace;font-size:0.78rem;color:var(--bs-info,#0dcaf0);background:rgba(13,202,240,0.1);padding:2px 8px;border-radius:4px;">' + escHtml(cap.technique_id || cap.id || '') + '</span></td>';
                        ov += '<td>' + escHtml(cap.tactic || '') + '</td>';
                        ov += '<td>' + escHtml(cap.technique || cap.name || '') + '</td>';
                        ov += '<td style="font-size:0.8rem;color:var(--bs-secondary-color);">' + escHtml(cap.description || '') + '</td>';
                        ov += '</tr>';
                    }
                });
                ov += '</tbody></table>';
            } else {
                ov += '<div class="d-flex flex-wrap gap-2">';
                res.capabilities.forEach(function (cap) {
                    var capText = typeof cap === 'string' ? cap : (cap.name || cap.description || JSON.stringify(cap));
                    ov += '<span class="badge bg-warning text-dark">' + escHtml(capText) + '</span>';
                });
                ov += '</div>';
            }
            ov += '</div>';
        }

        /* Capabilities as mitre_techniques format (alternative key) */
        if (res.capabilities && typeof res.capabilities === 'object' && !Array.isArray(res.capabilities) && res.capabilities.mitre_techniques) {
            var mitreT = res.capabilities.mitre_techniques;
            if (Array.isArray(mitreT) && mitreT.length > 0) {
                ov += '<div class="mt-3"><h6><i class="bi bi-diagram-3 me-1 text-accent"></i>MITRE ATT&CK Capabilities <span class="badge bg-info">' + mitreT.length + '</span></h6>';
                ov += '<table class="table table-sm" style="color:var(--bs-body-color);font-size:0.83rem;">';
                ov += '<thead><tr><th>ID</th><th>Tactic</th><th>Technique</th><th>Description</th></tr></thead><tbody>';
                mitreT.forEach(function (t) {
                    ov += '<tr>';
                    ov += '<td><span style="font-family:monospace;font-size:0.78rem;color:var(--bs-info,#0dcaf0);background:rgba(13,202,240,0.1);padding:2px 8px;border-radius:4px;">' + escHtml(t.technique_id || t.id || '') + '</span></td>';
                    ov += '<td>' + escHtml(t.tactic || '') + '</td>';
                    ov += '<td>' + escHtml(t.technique || t.name || '') + '</td>';
                    ov += '<td style="font-size:0.8rem;color:var(--bs-secondary-color);">' + escHtml(t.description || '') + '</td>';
                    ov += '</tr>';
                });
                ov += '</tbody></table></div>';
            }
        }

        /* Bug 4 fix: False positive info */
        if (res.is_false_positive) {
            ov += '<div class="alert alert-info mt-3" style="background:rgba(13,110,253,0.1);border-color:rgba(13,110,253,0.3);">';
            ov += '<i class="bi bi-info-circle me-1"></i><strong>Possible False Positive</strong>';
            if (res.false_positive_reason) ov += ': ' + escHtml(res.false_positive_reason);
            ov += '</div>';
        }

        /* LLM Analysis */
        if (res.llm_analysis) {
            var llm = res.llm_analysis;
            ov += '<div class="mt-3"><h6><i class="bi bi-robot me-1 text-accent"></i>AI Analysis</h6>';
            if (typeof llm === 'object') {
                if (llm.verdict) ov += '<p><strong>AI Verdict:</strong> <span class="badge bg-' + (llm.verdict.toUpperCase() === 'MALICIOUS' ? 'danger' : (llm.verdict.toUpperCase() === 'SUSPICIOUS' ? 'warning' : 'success')) + '">' + escHtml(llm.verdict) + '</span></p>';
                if (llm.analysis) ov += '<div style="background:rgba(0,0,0,0.15);padding:0.75rem;border-radius:8px;font-size:0.88rem;">' + escHtml(llm.analysis) + '</div>';
                if (llm.recommendations && Array.isArray(llm.recommendations)) {
                    ov += '<div class="mt-2"><strong>Recommendations:</strong><ol class="mb-0 mt-1">';
                    llm.recommendations.forEach(function (r) { ov += '<li style="font-size:0.85rem;">' + escHtml(r) + '</li>'; });
                    ov += '</ol></div>';
                }
            } else {
                ov += '<pre style="white-space:pre-wrap;word-break:break-word;background:rgba(0,0,0,0.15);padding:0.75rem;border-radius:8px;font-size:0.85rem;">' + escHtml(String(llm)) + '</pre>';
            }
            ov += '</div>';
        }

        output.overview = ov;
        output.threat_score = score;

        /* ===== STATIC ANALYSIS TAB ===== */
        var peAnalysis = (sa.pe_analysis || res.pe_analysis || {});
        var staticHtml = '';

        /* PE Headers and Security Features */
        var headers = peAnalysis.headers || {};
        if (Object.keys(headers).length > 0) {
            staticHtml += '<div class="mb-4">';
            staticHtml += '<h6><i class="bi bi-cpu me-1 text-accent"></i>PE Headers &amp; Security Features</h6>';
            staticHtml += '<table class="table table-sm pe-header-table" style="color:var(--bs-body-color);">';
            if (headers.machine !== undefined) staticHtml += '<tr><th>Architecture</th><td>' + machineArch(headers.machine) + '</td></tr>';
            if (headers.timestamp !== undefined) staticHtml += '<tr><th>Compile Time</th><td>' + escHtml(formatTimestamp(headers.timestamp)) + '</td></tr>';
            if (headers.entry_point !== undefined) staticHtml += '<tr><th>Entry Point</th><td><code>' + escHtml(String(headers.entry_point)) + '</code></td></tr>';
            if (headers.number_of_sections !== undefined) staticHtml += '<tr><th>Sections</th><td>' + escHtml(String(headers.number_of_sections)) + '</td></tr>';
            staticHtml += '</table>';

            var secFeatures = [
                { key: 'aslr', label: 'ASLR', icon: 'bi-shield-check' },
                { key: 'dep', label: 'DEP/NX', icon: 'bi-shield-lock' },
                { key: 'seh', label: 'SEH', icon: 'bi-shield-exclamation' },
                { key: 'cfg', label: 'CFG', icon: 'bi-shield-fill-check' },
                { key: 'high_entropy_va', label: 'High Entropy VA', icon: 'bi-shuffle' },
                { key: 'force_integrity', label: 'Force Integrity', icon: 'bi-lock' }
            ];
            var hasSecFeature = false;
            secFeatures.forEach(function (f) { if (headers[f.key] !== undefined) hasSecFeature = true; });
            if (hasSecFeature) {
                staticHtml += '<div class="pe-security-grid mt-2">';
                secFeatures.forEach(function (f) {
                    if (headers[f.key] === undefined) return;
                    var enabled = headers[f.key] === true || headers[f.key] === 'true';
                    staticHtml += '<div class="pe-sec-item ' + (enabled ? 'enabled' : 'disabled') + '">';
                    staticHtml += '<i class="bi ' + f.icon + '"></i>';
                    staticHtml += (enabled ? '<span>&#10003;</span>' : '<span>&#10007;</span>');
                    staticHtml += '<span>' + escHtml(f.label) + '</span>';
                    staticHtml += '</div>';
                });
                staticHtml += '</div>';
            }
            staticHtml += '</div>';
        }

        /* Suspicious Imports */
        var suspImports = peAnalysis.suspicious_imports || [];
        if (suspImports.length > 0) {
            staticHtml += '<div class="mb-4">';
            staticHtml += '<h6><i class="bi bi-exclamation-triangle text-danger me-1"></i>Suspicious Imports <span class="badge bg-danger">' + suspImports.length + '</span></h6>';
            staticHtml += '<div class="d-flex flex-wrap">';
            suspImports.forEach(function (imp) {
                var impName = typeof imp === 'string' ? imp : (imp.name || imp.function || JSON.stringify(imp));
                staticHtml += '<span class="suspicious-import"><i class="bi bi-exclamation-circle"></i>' + escHtml(impName) + '</span>';
            });
            staticHtml += '</div></div>';
        }

        /* Sections table */
        var sections = peAnalysis.sections || [];
        if (sections.length > 0) {
            staticHtml += '<div class="mb-4">';
            staticHtml += '<h6><i class="bi bi-table me-1 text-accent"></i>Sections</h6>';
            staticHtml += '<table class="table table-sm" style="color:var(--bs-body-color);font-size:0.83rem;">';
            staticHtml += '<thead><tr><th>Name</th><th>Virtual Size</th><th>Raw Size</th><th>Entropy</th><th>Characteristics</th></tr></thead><tbody>';
            sections.forEach(function (sec) {
                var secEnt = sec.entropy !== undefined ? parseFloat(sec.entropy) : null;
                var entColor = secEnt !== null ? (secEnt > 7 ? 'text-danger' : (secEnt > 6 ? 'text-warning' : '')) : '';
                staticHtml += '<tr>';
                staticHtml += '<td><code>' + escHtml(sec.name || sec.Name || '') + '</code></td>';
                staticHtml += '<td>' + escHtml(String(sec.virtual_size || sec.VirtualSize || sec.Misc_VirtualSize || '')) + '</td>';
                staticHtml += '<td>' + escHtml(String(sec.raw_size || sec.SizeOfRawData || '')) + '</td>';
                staticHtml += '<td class="' + entColor + '">' + (secEnt !== null ? secEnt.toFixed(4) : 'N/A') + '</td>';
                staticHtml += '<td style="font-size:0.75rem;">' + escHtml(String(sec.characteristics || sec.Characteristics || '')) + '</td>';
                staticHtml += '</tr>';
            });
            staticHtml += '</tbody></table></div>';
        }

        /* Imports table */
        var imports = peAnalysis.imports || [];
        if (imports.length > 0) {
            staticHtml += '<div class="mb-4">';
            staticHtml += '<h6><i class="bi bi-box-arrow-in-down me-1 text-accent"></i>Imports</h6>';
            staticHtml += '<div style="max-height:400px;overflow-y:auto;">';
            staticHtml += '<table class="table table-sm" style="color:var(--bs-body-color);font-size:0.82rem;">';
            staticHtml += '<thead><tr><th>Library</th><th>Functions</th></tr></thead><tbody>';
            var suspSet = {};
            suspImports.forEach(function (si) {
                var siName = (typeof si === 'string' ? si : (si.name || si.function || '')).toLowerCase();
                suspSet[siName] = true;
            });
            imports.forEach(function (imp) {
                var lib = imp.dll || imp.library || imp.name || '';
                var funcs = imp.functions || imp.imports || [];
                staticHtml += '<tr><td><strong>' + escHtml(lib) + '</strong></td><td>';
                if (Array.isArray(funcs)) {
                    funcs.forEach(function (fn, idx) {
                        var fnName = typeof fn === 'string' ? fn : (fn.name || fn.function || '');
                        var isSusp = suspSet[fnName.toLowerCase()];
                        if (idx > 0) staticHtml += ', ';
                        if (isSusp) {
                            staticHtml += '<span style="color:#dc3545;font-weight:600;">' + escHtml(fnName) + '</span>';
                        } else {
                            staticHtml += escHtml(fnName);
                        }
                    });
                } else {
                    staticHtml += escHtml(String(funcs));
                }
                staticHtml += '</td></tr>';
            });
            staticHtml += '</tbody></table></div></div>';
        }

        /* Exports */
        var fileExports = peAnalysis.exports || [];
        if (fileExports.length > 0) {
            staticHtml += '<div class="mb-4">';
            staticHtml += '<h6><i class="bi bi-box-arrow-up me-1 text-accent"></i>Exports <span class="badge bg-secondary">' + fileExports.length + '</span></h6>';
            staticHtml += '<div style="max-height:200px;overflow-y:auto;font-family:monospace;font-size:0.8rem;">';
            fileExports.forEach(function (exp) {
                var expName = typeof exp === 'string' ? exp : (exp.name || exp.function || JSON.stringify(exp));
                staticHtml += '<div style="padding:2px 0;border-bottom:1px solid rgba(255,255,255,0.04);">' + escHtml(expName) + '</div>';
            });
            staticHtml += '</div></div>';
        }

        /* ===== ENTROPY TAB (separate) ===== */
        var entropy = res.entropy_analysis || {};
        if (Object.keys(entropy).length > 0) {
            var entHtml = '';
            var chunk = entropy.chunk_analysis || {};
            var byteFreq = entropy.byte_frequency || {};
            var interp = entropy.interpretation || {};

            /* Classification badge */
            var classification = entropy.classification || interp.classification || '';
            if (classification) {
                var clsColor = classification.toLowerCase() === 'packed' || classification.toLowerCase() === 'encrypted' ? 'danger' : (classification.toLowerCase() === 'compressed' ? 'warning' : 'info');
                entHtml += '<div class="mb-3"><span class="badge bg-' + clsColor + ' fs-6">' + escHtml(classification) + '</span></div>';
            }

            entHtml += '<div class="entropy-stat-grid mb-3">';
            if (entropy.overall_entropy !== undefined) {
                var oeColor = parseFloat(entropy.overall_entropy) > 7 ? '#dc3545' : (parseFloat(entropy.overall_entropy) > 6 ? '#fd7e14' : '#198754');
                entHtml += '<div class="entropy-stat-card"><div class="es-value" style="color:' + oeColor + ';">' + parseFloat(entropy.overall_entropy).toFixed(4) + '</div><div class="es-label">Overall Entropy</div></div>';
            }
            if (chunk.avg !== undefined) entHtml += '<div class="entropy-stat-card"><div class="es-value">' + parseFloat(chunk.avg).toFixed(4) + '</div><div class="es-label">Chunk Avg</div></div>';
            if (chunk.max !== undefined) entHtml += '<div class="entropy-stat-card"><div class="es-value">' + parseFloat(chunk.max).toFixed(4) + '</div><div class="es-label">Chunk Max</div></div>';
            if (chunk.min !== undefined) entHtml += '<div class="entropy-stat-card"><div class="es-value">' + parseFloat(chunk.min).toFixed(4) + '</div><div class="es-label">Chunk Min</div></div>';
            if (chunk.std_dev !== undefined) entHtml += '<div class="entropy-stat-card"><div class="es-value">' + parseFloat(chunk.std_dev).toFixed(4) + '</div><div class="es-label">Std Dev</div></div>';
            if (byteFreq.unique_bytes !== undefined) entHtml += '<div class="entropy-stat-card"><div class="es-value">' + escHtml(String(byteFreq.unique_bytes)) + '</div><div class="es-label">Unique Bytes</div></div>';
            entHtml += '</div>';

            /* Per-section entropy bars */
            var sectionEntropy = entropy.sections || [];
            if (Array.isArray(sectionEntropy) && sectionEntropy.length > 0) {
                entHtml += '<div class="mb-4">';
                entHtml += '<h6><i class="bi bi-bar-chart-steps me-1 text-accent"></i>Per-Section Entropy</h6>';
                sectionEntropy.forEach(function (sec) {
                    var secName = sec.name || sec.section || 'Unknown';
                    var secEnt = parseFloat(sec.entropy || 0);
                    var barPct = Math.min((secEnt / 8) * 100, 100);
                    var barColor = secEnt > 7 ? '#dc3545' : (secEnt > 6 ? '#fd7e14' : '#198754');
                    entHtml += '<div class="score-bar-container">';
                    entHtml += '<div class="score-bar-label"><span class="sbl-name"><code>' + escHtml(secName) + '</code></span><span class="sbl-value">' + secEnt.toFixed(4) + '</span></div>';
                    entHtml += '<div class="score-bar-track"><div class="score-bar-fill" style="width:' + barPct + '%;background:' + barColor + ';"></div></div>';
                    entHtml += '</div>';
                });
                entHtml += '</div>';
            }

            /* High entropy regions */
            var highEntRegions = entropy.high_entropy_regions || [];
            if (Array.isArray(highEntRegions) && highEntRegions.length > 0) {
                entHtml += '<div class="mb-4">';
                entHtml += '<h6><i class="bi bi-exclamation-triangle text-warning me-1"></i>High Entropy Regions <span class="badge bg-warning text-dark">' + highEntRegions.length + '</span></h6>';
                entHtml += '<table class="table table-sm" style="color:var(--bs-body-color);font-size:0.83rem;">';
                entHtml += '<thead><tr><th>Offset</th><th>Size</th><th>Entropy</th><th>Description</th></tr></thead><tbody>';
                highEntRegions.forEach(function (r) {
                    var offset = r.offset !== undefined ? '0x' + Number(r.offset).toString(16).toUpperCase() : '';
                    entHtml += '<tr>';
                    entHtml += '<td><code>' + escHtml(offset) + '</code></td>';
                    entHtml += '<td>' + escHtml(String(r.size || '')) + '</td>';
                    entHtml += '<td style="color:#dc3545;font-weight:600;">' + (r.entropy !== undefined ? parseFloat(r.entropy).toFixed(4) : '') + '</td>';
                    entHtml += '<td>' + escHtml(r.description || r.name || '') + '</td>';
                    entHtml += '</tr>';
                });
                entHtml += '</tbody></table></div>';
            }

            if (byteFreq.most_common && Array.isArray(byteFreq.most_common) && byteFreq.most_common.length > 0) {
                entHtml += '<div class="mb-3"><h6><i class="bi bi-bar-chart me-1 text-accent"></i>Byte Frequency Distribution</h6>';
                entHtml += '<div class="d-flex flex-wrap gap-2">';
                byteFreq.most_common.slice(0, 16).forEach(function (b) {
                    var bVal = Array.isArray(b) ? '0x' + (b[0] !== undefined ? Number(b[0]).toString(16).toUpperCase().padStart(2, '0') : '??') : escHtml(String(b));
                    var bCount = Array.isArray(b) ? (b[1] || 0) : '';
                    entHtml += '<div class="entropy-stat-card" style="padding:6px 10px;"><div class="es-value" style="font-size:0.9rem;"><code>' + bVal + '</code></div><div class="es-label">' + bCount + '</div></div>';
                });
                entHtml += '</div></div>';
            }

            if (interp.risk_level || interp.description) {
                var riskColor = (interp.risk_level || '').toLowerCase() === 'high' ? 'danger' : ((interp.risk_level || '').toLowerCase() === 'medium' ? 'warning' : 'success');
                entHtml += '<div class="alert alert-' + riskColor + ' py-2 px-3" style="font-size:0.83rem;background:rgba(0,0,0,0.15);border-color:rgba(255,255,255,0.1);">';
                if (interp.risk_level) entHtml += '<strong>Risk Level: ' + escHtml(interp.risk_level) + '</strong> ';
                if (interp.description) entHtml += escHtml(interp.description);
                entHtml += '</div>';
            }
            output.entropy = entHtml;

            /* Also keep a brief summary in the static tab */
            if (entropy.overall_entropy !== undefined) {
                var oeColorS = parseFloat(entropy.overall_entropy) > 7 ? '#dc3545' : (parseFloat(entropy.overall_entropy) > 6 ? '#fd7e14' : '#198754');
                staticHtml += '<div class="mb-4"><h6><i class="bi bi-graph-up me-1 text-accent"></i>Entropy</h6>';
                staticHtml += '<span style="font-size:1.1rem;font-weight:700;color:' + oeColorS + ';">' + parseFloat(entropy.overall_entropy).toFixed(4) + '</span>';
                if (classification) staticHtml += ' <span class="badge bg-secondary">' + escHtml(classification) + '</span>';
                staticHtml += ' <small style="opacity:0.6;">(See Entropy tab for details)</small></div>';
            }
        }

        /* ===== PACKER TAB (separate) ===== */
        if (res.packer_detection && typeof res.packer_detection === 'object' && Object.keys(res.packer_detection).length > 0) {
            var pd = res.packer_detection;
            var pkHtml = '';

            /* Detection status badge */
            if (pd.is_packed !== undefined) {
                pkHtml += '<div class="text-center mb-4">';
                if (pd.is_packed) {
                    pkHtml += '<div class="d-inline-flex align-items-center gap-3 p-3" style="background:rgba(220,53,69,0.1);border:1px solid rgba(220,53,69,0.25);border-radius:12px;">';
                    pkHtml += '<i class="bi bi-exclamation-triangle-fill text-danger" style="font-size:2rem;"></i>';
                    pkHtml += '<div><div style="font-size:1.1rem;font-weight:700;color:#dc3545;">Packer Detected</div>';
                    if (pd.packer_name || pd.packer) pkHtml += '<div style="font-size:0.9rem;">' + escHtml(pd.packer_name || pd.packer) + '</div>';
                    pkHtml += '</div></div>';
                } else {
                    pkHtml += '<div class="d-inline-flex align-items-center gap-3 p-3" style="background:rgba(25,135,84,0.1);border:1px solid rgba(25,135,84,0.25);border-radius:12px;">';
                    pkHtml += '<i class="bi bi-check-circle-fill text-success" style="font-size:2rem;"></i>';
                    pkHtml += '<div><div style="font-size:1.1rem;font-weight:700;color:#198754;">No Packer Detected</div>';
                    pkHtml += '<div style="font-size:0.85rem;opacity:0.7;">File does not appear to be packed or protected</div>';
                    pkHtml += '</div></div>';
                }
                pkHtml += '</div>';
            }

            pkHtml += '<table class="table table-sm" style="color:var(--bs-body-color);">';
            if (pd.packer_name || pd.packer) pkHtml += '<tr><th style="width:160px;">Packer Name</th><td><strong>' + escHtml(String(pd.packer_name || pd.packer)) + '</strong></td></tr>';
            if (pd.version) pkHtml += '<tr><th>Version</th><td>' + escHtml(String(pd.version)) + '</td></tr>';
            if (pd.confidence !== undefined) {
                var confVal = parseFloat(pd.confidence);
                var confPctStr = confVal <= 1 ? (confVal * 100).toFixed(1) + '%' : confVal + '%';
                var confBarColor = confVal > 0.7 || confVal > 70 ? '#dc3545' : (confVal > 0.4 || confVal > 40 ? '#fd7e14' : '#198754');
                pkHtml += '<tr><th>Confidence</th><td>';
                pkHtml += '<div class="d-flex align-items-center gap-2">';
                pkHtml += '<strong style="color:' + confBarColor + ';">' + escHtml(confPctStr) + '</strong>';
                pkHtml += '<div class="score-bar-track" style="flex:1;max-width:200px;"><div class="score-bar-fill" style="width:' + (confVal <= 1 ? confVal * 100 : confVal) + '%;background:' + confBarColor + ';"></div></div>';
                pkHtml += '</div></td></tr>';
            }
            if (pd.method) pkHtml += '<tr><th>Detection Method</th><td>' + escHtml(String(pd.method)) + '</td></tr>';
            if (pd.details) pkHtml += '<tr><th>Details</th><td>' + escHtml(String(pd.details)) + '</td></tr>';
            Object.keys(pd).forEach(function (k) {
                if (['packer', 'packer_name', 'version', 'confidence', 'is_packed', 'method', 'details'].indexOf(k) >= 0) return;
                pkHtml += '<tr><th>' + escHtml(k.replace(/_/g, ' ').replace(/\b\w/g, function (l) { return l.toUpperCase(); })) + '</th><td>' + escHtml(String(pd[k])) + '</td></tr>';
            });
            pkHtml += '</table>';
            output.packer = pkHtml;

            /* Also keep brief summary in static tab */
            staticHtml += '<div class="mb-4"><h6><i class="bi bi-archive me-1 text-warning"></i>Packer</h6>';
            if (pd.is_packed) {
                staticHtml += '<span class="badge bg-danger">Packed</span> ';
                if (pd.packer_name || pd.packer) staticHtml += '<strong>' + escHtml(pd.packer_name || pd.packer) + '</strong>';
            } else {
                staticHtml += '<span class="badge bg-success">Not Packed</span>';
            }
            staticHtml += ' <small style="opacity:0.6;">(See Packer tab for details)</small></div>';
        }

        /* Bug 4 fix: Embedded Files */
        if (res.embedded_files && Array.isArray(res.embedded_files) && res.embedded_files.length > 0) {
            staticHtml += '<div class="mb-4">';
            staticHtml += '<h6><i class="bi bi-files me-1 text-accent"></i>Embedded Files <span class="badge bg-secondary">' + res.embedded_files.length + '</span></h6>';
            staticHtml += '<table class="table table-sm" style="color:var(--bs-body-color);font-size:0.83rem;">';
            staticHtml += '<thead><tr><th>Name</th><th>Type</th><th>Size</th></tr></thead><tbody>';
            res.embedded_files.forEach(function (ef) {
                var efName = typeof ef === 'string' ? ef : (ef.name || ef.filename || 'unknown');
                var efType = typeof ef === 'object' ? (ef.type || ef.file_type || '') : '';
                var efSize = typeof ef === 'object' && ef.size ? formatBytes(ef.size) : '';
                staticHtml += '<tr><td>' + escHtml(efName) + '</td><td>' + escHtml(efType) + '</td><td>' + escHtml(efSize) + '</td></tr>';
            });
            staticHtml += '</tbody></table></div>';
        }

        /* Fallback for static tab */
        if (!staticHtml) {
            var rawSa = res.pe_analysis || res.elf_analysis || res.pdf_analysis || sa || {};
            if (Object.keys(rawSa).length > 0) {
                staticHtml = '<pre style="white-space:pre-wrap;word-break:break-word;background:rgba(0,0,0,0.15);padding:0.75rem;border-radius:8px;color:var(--bs-body-color);max-height:500px;overflow-y:auto;">' + escHtml(JSON.stringify(rawSa, null, 2)) + '</pre>';
            }
        }
        if (staticHtml) output.static = staticHtml;

        /* ===== STRINGS TAB ===== */
        var stringData = res.string_analysis || res.suspicious_strings || {};
        if (typeof stringData === 'object' && Object.keys(stringData).length > 0) {
            var strHtml = '';

            /* Suspicious categories with badges */
            var suspCats = stringData.suspicious_categories || {};
            var catKeys = Object.keys(suspCats);
            if (catKeys.length > 0) {
                strHtml += '<div class="mb-4">';
                strHtml += '<h6><i class="bi bi-exclamation-triangle text-warning me-1"></i>Suspicious String Categories</h6>';
                strHtml += '<div class="d-flex flex-wrap gap-2 mb-2">';
                catKeys.forEach(function (cat) {
                    var items = suspCats[cat];
                    var count = Array.isArray(items) ? items.length : (typeof items === 'number' ? items : 0);
                    var catClass = 'cat-' + cat.toLowerCase().replace(/[^a-z_]/g, '');
                    if (['cat-crypto','cat-persistence','cat-process','cat-network','cat-anti_analysis','cat-injection'].indexOf(catClass) < 0) catClass = 'cat-default';
                    var catId = 'strcat-' + cat.replace(/[^a-zA-Z0-9]/g, '');
                    strHtml += '<span class="string-cat-badge ' + catClass + '" onclick="toggleStringCategory(\'' + catId + '\')">';
                    strHtml += '<i class="bi bi-tag"></i>' + escHtml(cat);
                    strHtml += '<span class="scb-count">' + count + '</span>';
                    strHtml += '</span>';
                });
                strHtml += '</div>';

                catKeys.forEach(function (cat) {
                    var items = suspCats[cat];
                    if (!Array.isArray(items) || items.length === 0) return;
                    var catId = 'strcat-' + cat.replace(/[^a-zA-Z0-9]/g, '');
                    strHtml += '<div id="' + catId + '" class="string-cat-expand">';
                    strHtml += '<strong style="font-size:0.8rem;">' + escHtml(cat) + ' (' + items.length + ')</strong>';
                    items.forEach(function (item) {
                        var itemText = typeof item === 'string' ? item : (item.value || item.string || JSON.stringify(item));
                        strHtml += '<div class="sce-item">' + escHtml(itemText) + '</div>';
                    });
                    strHtml += '</div>';
                });
                strHtml += '</div>';
            }

            /* Interesting strings */
            var interesting = stringData.interesting_strings || [];
            if (interesting.length > 0) {
                strHtml += '<div class="mb-4">';
                strHtml += '<h6><i class="bi bi-search me-1 text-accent"></i>Interesting Strings <span class="badge bg-secondary">' + interesting.length + '</span></h6>';
                strHtml += '<div style="max-height:400px;overflow-y:auto;background:rgba(0,0,0,0.15);border-radius:8px;padding:10px;">';
                interesting.forEach(function (s) {
                    var sText = typeof s === 'string' ? s : (s.value || s.string || JSON.stringify(s));
                    strHtml += '<div style="font-family:monospace;font-size:0.78rem;padding:3px 0;border-bottom:1px solid rgba(255,255,255,0.04);word-break:break-all;">' + escHtml(sText) + '</div>';
                });
                strHtml += '</div></div>';
            }

            /* FLOSS strings */
            var floss = stringData.floss_strings || stringData.decoded_strings || [];
            if (Array.isArray(floss) && floss.length > 0) {
                strHtml += '<div class="mb-4">';
                strHtml += '<h6><i class="bi bi-key me-1 text-accent"></i>FLOSS Decoded Strings <span class="badge bg-info">' + floss.length + '</span></h6>';
                strHtml += '<div style="max-height:300px;overflow-y:auto;background:rgba(0,0,0,0.15);border-radius:8px;padding:10px;">';
                floss.forEach(function (s) {
                    var sText = typeof s === 'string' ? s : (s.value || s.string || JSON.stringify(s));
                    strHtml += '<div style="font-family:monospace;font-size:0.78rem;padding:3px 0;border-bottom:1px solid rgba(255,255,255,0.04);word-break:break-all;">' + escHtml(sText) + '</div>';
                });
                strHtml += '</div></div>';
            }

            /* Bug 4 fix: String count statistics */
            var hasStrStats = stringData.total_strings !== undefined || stringData.ascii_strings !== undefined || stringData.unicode_strings !== undefined;
            if (hasStrStats) {
                strHtml += '<div class="mb-4">';
                strHtml += '<h6><i class="bi bi-123 me-1 text-accent"></i>String Statistics</h6>';
                strHtml += '<div class="d-flex flex-wrap gap-3">';
                if (stringData.total_strings !== undefined) strHtml += '<div class="entropy-stat-card"><div class="es-value">' + escHtml(String(stringData.total_strings)) + '</div><div class="es-label">Total Strings</div></div>';
                if (stringData.ascii_strings !== undefined) strHtml += '<div class="entropy-stat-card"><div class="es-value">' + escHtml(String(stringData.ascii_strings)) + '</div><div class="es-label">ASCII Strings</div></div>';
                if (stringData.unicode_strings !== undefined) strHtml += '<div class="entropy-stat-card"><div class="es-value">' + escHtml(String(stringData.unicode_strings)) + '</div><div class="es-label">Unicode Strings</div></div>';
                strHtml += '</div></div>';
            }

            /* Bug 4 fix: Registry keys, mutexes, user agents */
            var strSpecialCats = [
                { key: 'registry_keys', label: 'Registry Keys', icon: 'bi-hdd-rack' },
                { key: 'mutexes', label: 'Mutexes', icon: 'bi-lock' },
                { key: 'user_agents', label: 'User Agents', icon: 'bi-browser-chrome' }
            ];
            strSpecialCats.forEach(function (sc) {
                var items = stringData[sc.key];
                if (!items || !Array.isArray(items) || items.length === 0) return;
                strHtml += '<div class="mb-4">';
                strHtml += '<h6><i class="bi ' + sc.icon + ' me-1 text-accent"></i>' + sc.label + ' <span class="badge bg-secondary">' + items.length + '</span></h6>';
                strHtml += '<div style="max-height:200px;overflow-y:auto;background:rgba(0,0,0,0.15);border-radius:8px;padding:8px 12px;">';
                items.forEach(function (item) {
                    var text = typeof item === 'string' ? item : (item.value || item.string || JSON.stringify(item));
                    strHtml += '<div style="font-family:monospace;font-size:0.78rem;padding:3px 0;border-bottom:1px solid rgba(255,255,255,0.04);word-break:break-all;">' + escHtml(text) + '</div>';
                });
                strHtml += '</div></div>';
            });

            /* Bug 4 fix: Obfuscated / de-obfuscated strings */
            if (res.obfuscated_strings && Array.isArray(res.obfuscated_strings) && res.obfuscated_strings.length > 0) {
                strHtml += '<div class="mb-4">';
                strHtml += '<h6><i class="bi bi-shuffle me-1 text-warning"></i>De-obfuscated Strings <span class="badge bg-warning text-dark">' + res.obfuscated_strings.length + '</span></h6>';
                strHtml += '<div style="max-height:300px;overflow-y:auto;background:rgba(0,0,0,0.15);border-radius:8px;padding:10px;">';
                res.obfuscated_strings.forEach(function (s) {
                    var sText = typeof s === 'string' ? s : (s.value || s.decoded || s.string || JSON.stringify(s));
                    strHtml += '<div style="font-family:monospace;font-size:0.78rem;padding:3px 0;border-bottom:1px solid rgba(255,255,255,0.04);word-break:break-all;">' + escHtml(sText) + '</div>';
                });
                strHtml += '</div></div>';
            }

            if (!strHtml) {
                strHtml = '<pre style="white-space:pre-wrap;word-break:break-word;background:rgba(0,0,0,0.15);padding:0.75rem;border-radius:8px;color:var(--bs-body-color);max-height:500px;overflow-y:auto;">' + escHtml(JSON.stringify(stringData, null, 2)) + '</pre>';
            }
            output.strings = strHtml;
        }

        /* Bug 4 fix: Render obfuscated strings even when there's no string_analysis block */
        if (!output.strings && res.obfuscated_strings && Array.isArray(res.obfuscated_strings) && res.obfuscated_strings.length > 0) {
            var obfStrHtml = '<div class="mb-4">';
            obfStrHtml += '<h6><i class="bi bi-shuffle me-1 text-warning"></i>De-obfuscated Strings <span class="badge bg-warning text-dark">' + res.obfuscated_strings.length + '</span></h6>';
            obfStrHtml += '<div style="max-height:300px;overflow-y:auto;background:rgba(0,0,0,0.15);border-radius:8px;padding:10px;">';
            res.obfuscated_strings.forEach(function (s) {
                var sText = typeof s === 'string' ? s : (s.value || s.decoded || s.string || JSON.stringify(s));
                obfStrHtml += '<div style="font-family:monospace;font-size:0.78rem;padding:3px 0;border-bottom:1px solid rgba(255,255,255,0.04);word-break:break-all;">' + escHtml(sText) + '</div>';
            });
            obfStrHtml += '</div></div>';
            output.strings = obfStrHtml;
        }

        /* ===== YARA TAB (Enhanced) ===== */
        var yaraData = res.yara_analysis || {};
        var yaraMatches = yaraData.matches || res.yara_matches || res.yara_results || [];
        var yaraInterp = yaraData.interpretation || {};
        if (Array.isArray(yaraMatches) && yaraMatches.length > 0) {
            var yt = '';

            if (yaraInterp.severity || yaraInterp.techniques || yaraInterp.recommendations) {
                var sevClass = 'yara-severity-' + (yaraInterp.severity || 'info').toLowerCase();
                yt += '<div class="mb-3 d-flex align-items-center gap-3 flex-wrap">';
                if (yaraInterp.severity) yt += '<span class="yara-severity ' + sevClass + '">' + escHtml(yaraInterp.severity) + '</span>';
                if (yaraInterp.techniques && Array.isArray(yaraInterp.techniques)) {
                    yaraInterp.techniques.forEach(function (t) {
                        yt += '<span class="badge bg-info">' + escHtml(t) + '</span>';
                    });
                }
                yt += '</div>';
                if (yaraInterp.recommendations && Array.isArray(yaraInterp.recommendations)) {
                    yaraInterp.recommendations.forEach(function (rec) {
                        yt += '<div class="yara-recommendation"><i class="bi bi-lightbulb me-1"></i>' + escHtml(rec) + '</div>';
                    });
                }
            }

            yaraMatches.forEach(function (y) {
                yt += '<div class="yara-match-card">';
                yt += '<div class="ymc-header">';
                yt += '<span class="ymc-rule"><i class="bi bi-shield-exclamation me-1 text-danger"></i><code>' + escHtml(y.rule || y.name || '') + '</code></span>';
                if (y.severity) {
                    yt += '<span class="yara-severity yara-severity-' + escHtml((y.severity || 'info').toLowerCase()) + '">' + escHtml(y.severity) + '</span>';
                }
                yt += '</div>';
                if (y.description || y.meta) yt += '<p class="mb-1" style="font-size:0.85rem;">' + escHtml(y.description || (typeof y.meta === 'string' ? y.meta : '')) + '</p>';
                if (y.tags && y.tags.length) yt += '<div class="mb-2">' + y.tags.map(function (t) { return '<span class="badge bg-secondary me-1">' + escHtml(t) + '</span>'; }).join('') + '</div>';

                var matchedStrings = y.strings || [];
                if (matchedStrings.length > 0) {
                    yt += '<div class="mt-2"><strong style="font-size:0.8rem;">Matched Strings:</strong>';
                    yt += '<div style="max-height:150px;overflow-y:auto;margin-top:4px;">';
                    yt += '<table class="table table-sm mb-0" style="font-size:0.78rem;color:var(--bs-body-color);">';
                    yt += '<thead><tr><th>Offset</th><th>Identifier</th><th>Data</th></tr></thead><tbody>';
                    matchedStrings.forEach(function (ms) {
                        yt += '<tr>';
                        yt += '<td><code class="yara-string-offset">' + escHtml(String(ms.offset !== undefined ? '0x' + Number(ms.offset).toString(16) : '')) + '</code></td>';
                        yt += '<td><code>' + escHtml(ms.identifier || '') + '</code></td>';
                        yt += '<td style="word-break:break-all;">' + escHtml(ms.data || '') + '</td>';
                        yt += '</tr>';
                    });
                    yt += '</tbody></table></div></div>';
                }
                yt += '</div>';
            });
            output.yara = yt;
        } else {
            output.yara = '<p style="color:var(--bs-secondary-color);">No YARA matches found.</p>';
        }

        /* ===== IOCs TAB ===== */
        var iocs = res.iocs || res.extracted_iocs || {};
        if (typeof iocs === 'object' && Object.keys(iocs).length > 0) {
            var iocHtml = '';
            var iocTypes = Object.keys(iocs);
            iocTypes.forEach(function (iocType) {
                var items = iocs[iocType];
                if (!items) return;
                var itemList = Array.isArray(items) ? items : [items];
                if (itemList.length === 0) return;
                iocHtml += '<div class="mb-3">';
                iocHtml += '<h6><i class="bi bi-crosshair me-1 text-accent"></i>' + escHtml(iocType.replace(/_/g, ' ').replace(/\b\w/g, function (l) { return l.toUpperCase(); })) + ' <span class="badge bg-secondary">' + itemList.length + '</span></h6>';
                iocHtml += '<div style="max-height:200px;overflow-y:auto;background:rgba(0,0,0,0.15);border-radius:8px;padding:8px 12px;">';
                itemList.forEach(function (item) {
                    var text = typeof item === 'string' ? item : (item.value || item.ioc || JSON.stringify(item));
                    iocHtml += '<div style="font-family:monospace;font-size:0.8rem;padding:3px 0;border-bottom:1px solid rgba(255,255,255,0.04);word-break:break-all;">' + escHtml(text) + '</div>';
                });
                iocHtml += '</div></div>';
            });
            if (iocHtml) output.iocs = iocHtml;
        }

        /* ===== MITRE TAB ===== */
        var mitre = res.mitre_mapping || res.mitre_techniques || [];
        if (Array.isArray(mitre) && mitre.length > 0) {
            var mt = '<h6><i class="bi bi-diagram-3 me-1 text-accent"></i>MITRE ATT&amp;CK Techniques <span class="badge bg-info">' + mitre.length + '</span></h6>';
            mt += '<table class="table table-sm" style="color:var(--bs-body-color);font-size:0.83rem;">';
            mt += '<thead><tr><th>ID</th><th>Technique</th><th>Tactic</th></tr></thead><tbody>';
            mitre.forEach(function (m) {
                mt += '<tr>';
                mt += '<td><span style="font-family:monospace;font-size:0.78rem;color:var(--bs-info,#0dcaf0);background:rgba(13,202,240,0.1);padding:2px 8px;border-radius:4px;">' + escHtml(m.id || m.technique_id || '') + '</span></td>';
                mt += '<td>' + escHtml(m.name || m.technique || '') + '</td>';
                mt += '<td>' + escHtml(m.tactic || '') + '</td>';
                mt += '</tr>';
            });
            mt += '</tbody></table>';
            output.mitre = mt;
        } else {
            output.mitre = '<p style="color:var(--bs-secondary-color);">No MITRE ATT&amp;CK techniques mapped.</p>';
        }

        /* ===== CAPABILITIES TAB ===== */
        var caps = res.capabilities || [];
        var capsObj = null;
        if (typeof caps === 'object' && !Array.isArray(caps)) {
            capsObj = caps;
            caps = caps.mitre_techniques || caps.techniques || [];
        }
        if (Array.isArray(caps) && caps.length > 0) {
            var capHtml = '';
            var hasMitreFormat = caps.some(function (c) { return typeof c === 'object' && (c.tactic || c.technique || c.technique_id); });
            if (hasMitreFormat) {
                capHtml += '<h6><i class="bi bi-diagram-3 me-1 text-accent"></i>MITRE ATT&CK Techniques <span class="badge bg-info">' + caps.length + '</span></h6>';
                capHtml += '<table class="table table-sm" style="color:var(--bs-body-color);font-size:0.83rem;">';
                capHtml += '<thead><tr><th>ID</th><th>Tactic</th><th>Technique</th><th>Description</th></tr></thead><tbody>';
                caps.forEach(function (c) {
                    if (typeof c === 'string') {
                        capHtml += '<tr><td colspan="4">' + escHtml(c) + '</td></tr>';
                        return;
                    }
                    capHtml += '<tr>';
                    capHtml += '<td><span style="font-family:monospace;font-size:0.78rem;color:var(--bs-info,#0dcaf0);background:rgba(13,202,240,0.1);padding:2px 8px;border-radius:4px;">' + escHtml(c.technique_id || c.id || '') + '</span></td>';
                    capHtml += '<td>' + escHtml(c.tactic || '') + '</td>';
                    capHtml += '<td>' + escHtml(c.technique || c.name || '') + '</td>';
                    capHtml += '<td style="font-size:0.8rem;color:var(--bs-secondary-color);">' + escHtml(c.description || '') + '</td>';
                    capHtml += '</tr>';
                });
                capHtml += '</tbody></table>';
            } else {
                capHtml += '<h6><i class="bi bi-gear me-1 text-accent"></i>Detected Capabilities <span class="badge bg-secondary">' + caps.length + '</span></h6>';
                capHtml += '<div class="d-flex flex-wrap gap-2">';
                caps.forEach(function (c) {
                    var cText = typeof c === 'string' ? c : (c.name || c.description || JSON.stringify(c));
                    capHtml += '<span class="badge bg-warning text-dark" style="font-size:0.82rem;padding:6px 12px;">' + escHtml(cText) + '</span>';
                });
                capHtml += '</div>';
            }
            output.capabilities = capHtml;
        } else if (capsObj && Object.keys(capsObj).length > 0) {
            /* Capabilities as an object with named keys */
            var capObjHtml = '<h6><i class="bi bi-gear me-1 text-accent"></i>Capabilities</h6>';
            capObjHtml += '<table class="table table-sm" style="color:var(--bs-body-color);">';
            Object.keys(capsObj).forEach(function (k) {
                if (k === 'mitre_techniques' || k === 'techniques') return;
                var v = capsObj[k];
                capObjHtml += '<tr><th>' + escHtml(k.replace(/_/g, ' ').replace(/\b\w/g, function (l) { return l.toUpperCase(); })) + '</th>';
                if (Array.isArray(v)) {
                    capObjHtml += '<td>' + v.map(function (item) { return escHtml(typeof item === 'string' ? item : JSON.stringify(item)); }).join(', ') + '</td>';
                } else {
                    capObjHtml += '<td>' + escHtml(String(v)) + '</td>';
                }
                capObjHtml += '</tr>';
            });
            capObjHtml += '</table>';
            output.capabilities = capObjHtml;
        }

        /* ===== SANDBOX & DYNAMIC ANALYSIS TAB ===== */
        var sandbox = res.sandbox_analysis || {};
        if (Object.keys(sandbox).length > 0) {
            var sbHtml = '';

            /* Report links */
            var vtBehavior = sandbox.virustotal_behavior || {};
            var anyrun = sandbox.anyrun || {};
            var hasLinks = vtBehavior.report_url || anyrun.report_url;
            if (hasLinks) {
                sbHtml += '<div class="mb-4 d-flex flex-wrap gap-3">';
                if (vtBehavior.report_url) {
                    sbHtml += '<a href="' + escHtml(vtBehavior.report_url) + '" target="_blank" rel="noopener noreferrer" class="sandbox-report-btn vt-btn">';
                    sbHtml += '<i class="bi bi-box-arrow-up-right"></i>VirusTotal Report</a>';
                }
                if (anyrun.report_url) {
                    sbHtml += '<a href="' + escHtml(anyrun.report_url) + '" target="_blank" rel="noopener noreferrer" class="sandbox-report-btn anyrun-btn">';
                    sbHtml += '<i class="bi bi-box-arrow-up-right"></i>ANY.RUN Report</a>';
                }
                sbHtml += '</div>';
            }

            /* MITRE ATT&CK from sandbox */
            var sbMitre = vtBehavior.mitre_attck || sandbox.mitre_attck || [];
            var sbSummaryMitre = (sandbox.summary || {}).mitre_techniques || [];
            var allSbMitre = sbMitre.length > 0 ? sbMitre : sbSummaryMitre;
            if (allSbMitre.length > 0) {
                sbHtml += '<div class="mb-4">';
                sbHtml += '<h6><i class="bi bi-diagram-3 text-danger me-1"></i>MITRE ATT&amp;CK from Dynamic Analysis <span class="badge bg-danger">' + allSbMitre.length + '</span></h6>';
                sbHtml += '<div style="max-height:400px;overflow-y:auto;">';
                sbHtml += '<table class="table table-sm" style="color:var(--bs-body-color);font-size:0.82rem;">';
                sbHtml += '<thead><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Severity</th></tr></thead><tbody>';
                allSbMitre.forEach(function (m) {
                    var techId = typeof m === 'string' ? m : (m.id || m.technique_id || '');
                    var techName = typeof m === 'string' ? '' : (m.name || m.technique || m.description || '');
                    var techTactic = typeof m === 'string' ? '' : (m.tactic || '');
                    var techSev = typeof m === 'string' ? '' : (m.severity || '');
                    var sevColor = techSev.toLowerCase() === 'critical' ? 'danger' : (techSev.toLowerCase() === 'high' ? 'warning' : (techSev.toLowerCase() === 'medium' ? 'info' : 'secondary'));
                    sbHtml += '<tr>';
                    sbHtml += '<td><span style="font-family:monospace;font-size:0.78rem;color:var(--bs-info);background:rgba(13,202,240,0.1);padding:2px 8px;border-radius:4px;">' + escHtml(techId) + '</span></td>';
                    sbHtml += '<td>' + escHtml(techName) + '</td>';
                    sbHtml += '<td>' + escHtml(techTactic) + '</td>';
                    sbHtml += '<td>' + (techSev ? '<span class="badge bg-' + sevColor + '">' + escHtml(techSev) + '</span>' : '') + '</td>';
                    sbHtml += '</tr>';
                });
                sbHtml += '</tbody></table></div></div>';
            }

            /* Processes created */
            var processes = vtBehavior.processes_created || sandbox.processes_created || [];
            if (processes.length > 0) {
                sbHtml += '<div class="mb-4">';
                sbHtml += '<h6><i class="bi bi-terminal me-1 text-accent"></i>Processes Created <span class="badge bg-secondary">' + processes.length + '</span></h6>';
                sbHtml += '<div style="max-height:250px;overflow-y:auto;">';
                processes.forEach(function (p) {
                    var pText = typeof p === 'string' ? p : (p.name || p.command || p.process || JSON.stringify(p));
                    sbHtml += '<div class="process-item"><i class="bi bi-caret-right-fill" style="color:var(--bs-info);font-size:0.6rem;"></i>' + escHtml(pText) + '</div>';
                });
                sbHtml += '</div></div>';
            }

            /* Network activity */
            var dns = vtBehavior.dns_lookups || sandbox.dns_lookups || [];
            var ipTraffic = vtBehavior.ip_traffic || sandbox.ip_traffic || [];
            var httpConv = vtBehavior.http_conversations || sandbox.http_conversations || [];

            if (dns.length > 0) {
                sbHtml += '<div class="mb-4">';
                sbHtml += '<h6><i class="bi bi-globe me-1 text-accent"></i>DNS Lookups <span class="badge bg-secondary">' + dns.length + '</span></h6>';
                sbHtml += '<table class="table table-sm network-table" style="color:var(--bs-body-color);">';
                sbHtml += '<thead><tr><th>Hostname</th><th>Resolved IP</th></tr></thead><tbody>';
                dns.forEach(function (d) {
                    var hostname = typeof d === 'string' ? d : (d.hostname || d.domain || d.name || '');
                    var ip = typeof d === 'string' ? '' : (d.resolved_ip || d.ip || d.address || '');
                    sbHtml += '<tr><td>' + escHtml(hostname) + '</td><td><code>' + escHtml(ip) + '</code></td></tr>';
                });
                sbHtml += '</tbody></table></div>';
            }

            if (ipTraffic.length > 0) {
                sbHtml += '<div class="mb-4">';
                sbHtml += '<h6><i class="bi bi-arrow-left-right me-1 text-accent"></i>IP Traffic <span class="badge bg-secondary">' + ipTraffic.length + '</span></h6>';
                sbHtml += '<table class="table table-sm network-table" style="color:var(--bs-body-color);">';
                sbHtml += '<thead><tr><th>Destination IP</th><th>Port</th><th>Protocol</th></tr></thead><tbody>';
                ipTraffic.forEach(function (t) {
                    var ip = typeof t === 'string' ? t : (t.destination_ip || t.ip || t.dst || '');
                    var port = typeof t === 'string' ? '' : (t.destination_port || t.port || t.dst_port || '');
                    var proto = typeof t === 'string' ? '' : (t.transport_layer_protocol || t.protocol || '');
                    sbHtml += '<tr><td><code>' + escHtml(String(ip)) + '</code></td><td>' + escHtml(String(port)) + '</td><td>' + escHtml(String(proto)) + '</td></tr>';
                });
                sbHtml += '</tbody></table></div>';
            }

            if (httpConv.length > 0) {
                sbHtml += '<div class="mb-4">';
                sbHtml += '<h6><i class="bi bi-wifi me-1 text-accent"></i>HTTP Conversations <span class="badge bg-secondary">' + httpConv.length + '</span></h6>';
                sbHtml += '<table class="table table-sm network-table" style="color:var(--bs-body-color);">';
                sbHtml += '<thead><tr><th>Method</th><th>URL</th><th>Status</th></tr></thead><tbody>';
                httpConv.forEach(function (h) {
                    var method = typeof h === 'string' ? '' : (h.request_method || h.method || '');
                    var url = typeof h === 'string' ? h : (h.url || h.request_url || '');
                    var status = typeof h === 'string' ? '' : (h.response_status_code || h.status || '');
                    sbHtml += '<tr><td><span class="badge bg-secondary">' + escHtml(String(method)) + '</span></td>';
                    sbHtml += '<td style="word-break:break-all;">' + escHtml(String(url)) + '</td>';
                    sbHtml += '<td>' + escHtml(String(status)) + '</td></tr>';
                });
                sbHtml += '</tbody></table></div>';
            }

            if (!sbHtml && Object.keys(sandbox).length > 0) {
                sbHtml = '<pre style="white-space:pre-wrap;word-break:break-word;background:rgba(0,0,0,0.15);padding:0.75rem;border-radius:8px;color:var(--bs-body-color);max-height:500px;overflow-y:auto;">' + escHtml(JSON.stringify(sandbox, null, 2)) + '</pre>';
            }
            if (sbHtml) output.sandbox = sbHtml;
        }

        /* ===== SCORING BREAKDOWN TAB ===== */
        var scoring = res.scoring || {};
        if (Object.keys(scoring).length > 0 || score !== null) {
            var scHtml = '';

            if (scoring.composite_score !== undefined || score !== null) {
                var compositeScore = scoring.composite_score !== undefined ? scoring.composite_score : score;
                scHtml += '<div class="text-center mb-4">';
                scHtml += '<div style="font-size:3rem;font-weight:800;font-family:monospace;color:' + scoreBarColor(compositeScore) + ';">' + compositeScore + '<span style="font-size:1.2rem;opacity:0.5;">/100</span></div>';
                scHtml += '<div style="font-size:0.85rem;opacity:0.6;">Composite Threat Score</div>';
                if (scoring.confidence !== undefined) {
                    var confPct = (parseFloat(scoring.confidence) * 100).toFixed(1);
                    scHtml += '<div style="font-size:0.82rem;margin-top:4px;"><i class="bi bi-speedometer2 me-1"></i>Confidence: <strong>' + escHtml(confPct) + '%</strong></div>';
                }
                scHtml += '</div>';
            }

            var toolScores = scoring.tool_scores || res.tool_scores || {};
            var tsKeys = Object.keys(toolScores);
            if (tsKeys.length > 0) {
                scHtml += '<div class="mb-4">';
                scHtml += '<h6><i class="bi bi-bar-chart me-1 text-accent"></i>Score by Analysis Engine</h6>';
                tsKeys.forEach(function (tool) {
                    var toolScore = parseInt(toolScores[tool], 10) || 0;
                    var barColor = scoreBarColor(toolScore);
                    scHtml += '<div class="score-bar-container">';
                    scHtml += '<div class="score-bar-label"><span class="sbl-name">' + escHtml(tool.replace(/_/g, ' ')) + '</span><span class="sbl-value">' + toolScore + '/100</span></div>';
                    scHtml += '<div class="score-bar-track"><div class="score-bar-fill" style="width:' + toolScore + '%;background:' + barColor + ';"></div></div>';
                    scHtml += '</div>';
                });
                scHtml += '</div>';
            }

            var factors = scoring.contributing_factors || [];
            if (factors.length > 0) {
                scHtml += '<div class="mb-4">';
                scHtml += '<h6><i class="bi bi-list-ul me-1 text-accent"></i>Contributing Factors</h6>';
                factors.forEach(function (f) {
                    var fText = typeof f === 'string' ? f : (f.description || f.factor || f.reason || JSON.stringify(f));
                    var fScore = typeof f === 'object' ? (f.score || f.weight || f.impact || '') : '';
                    scHtml += '<div class="contributing-factor">';
                    scHtml += '<i class="bi bi-caret-right-fill" style="color:var(--bs-warning);font-size:0.6rem;"></i>';
                    scHtml += '<span style="flex:1;">' + escHtml(fText) + '</span>';
                    if (fScore) scHtml += '<span class="badge bg-warning text-dark">+' + escHtml(String(fScore)) + '</span>';
                    scHtml += '</div>';
                });
                scHtml += '</div>';
            }

            if (scHtml) output.scoring = scHtml;
        }

        /* ===== LLM ANALYSIS TAB ===== */
        if (res.llm_analysis) {
            var llm = res.llm_analysis;
            var llmHtml = '';
            if (typeof llm === 'object') {
                /* Verdict badge */
                if (llm.verdict) {
                    var llmVColor = llm.verdict.toUpperCase() === 'MALICIOUS' ? 'danger' : (llm.verdict.toUpperCase() === 'SUSPICIOUS' ? 'warning' : (llm.verdict.toUpperCase() === 'CLEAN' ? 'success' : 'secondary'));
                    llmHtml += '<div class="text-center mb-4">';
                    llmHtml += '<div class="d-inline-flex align-items-center gap-3 p-3" style="background:rgba(var(--bs-' + llmVColor + '-rgb,220,53,69),0.1);border:1px solid rgba(var(--bs-' + llmVColor + '-rgb,220,53,69),0.25);border-radius:12px;">';
                    llmHtml += '<i class="bi bi-robot" style="font-size:2rem;color:var(--bs-' + llmVColor + ');"></i>';
                    llmHtml += '<div><div style="font-size:0.75rem;text-transform:uppercase;letter-spacing:1px;opacity:0.7;">AI Verdict</div>';
                    llmHtml += '<span class="badge bg-' + llmVColor + ' fs-5">' + escHtml(llm.verdict) + '</span>';
                    llmHtml += '</div></div></div>';
                }
                /* Analysis text */
                if (llm.analysis) {
                    llmHtml += '<div class="mb-4">';
                    llmHtml += '<h6><i class="bi bi-chat-left-text me-1 text-accent"></i>Analysis</h6>';
                    llmHtml += '<div style="background:rgba(0,0,0,0.15);padding:1rem 1.25rem;border-radius:10px;border:1px solid rgba(255,255,255,0.06);line-height:1.7;font-size:0.88rem;white-space:pre-wrap;word-break:break-word;">';
                    llmHtml += escHtml(llm.analysis);
                    llmHtml += '</div></div>';
                }
                /* Recommendations */
                if (llm.recommendations && Array.isArray(llm.recommendations) && llm.recommendations.length > 0) {
                    llmHtml += '<div class="mb-4">';
                    llmHtml += '<h6><i class="bi bi-lightbulb me-1 text-warning"></i>Recommendations</h6>';
                    llmHtml += '<ol style="padding-left:1.25rem;">';
                    llm.recommendations.forEach(function (r) {
                        llmHtml += '<li style="margin-bottom:8px;font-size:0.88rem;padding:6px 10px;background:rgba(255,193,7,0.06);border-left:3px solid rgba(255,193,7,0.3);border-radius:0 6px 6px 0;">' + escHtml(r) + '</li>';
                    });
                    llmHtml += '</ol></div>';
                }
                /* Note or error */
                if (llm.note) {
                    llmHtml += '<div class="alert alert-info py-2 px-3" style="font-size:0.83rem;background:rgba(13,202,240,0.08);border-color:rgba(13,202,240,0.2);"><i class="bi bi-info-circle me-1"></i>' + escHtml(llm.note) + '</div>';
                }
                if (llm.error) {
                    llmHtml += '<div class="alert alert-warning py-2 px-3" style="font-size:0.83rem;background:rgba(255,193,7,0.08);border-color:rgba(255,193,7,0.2);"><i class="bi bi-exclamation-triangle me-1"></i>LLM Error: ' + escHtml(llm.error) + '</div>';
                }
                /* Extra keys */
                Object.keys(llm).forEach(function (k) {
                    if (['verdict', 'analysis', 'recommendations', 'note', 'error'].indexOf(k) >= 0) return;
                    llmHtml += '<div class="mb-3"><h6 style="font-size:0.85rem;">' + escHtml(k.replace(/_/g, ' ').replace(/\b\w/g, function (l) { return l.toUpperCase(); })) + '</h6>';
                    llmHtml += '<p style="font-size:0.85rem;color:var(--bs-secondary-color);">' + escHtml(String(llm[k])) + '</p></div>';
                });
            } else {
                llmHtml += '<pre style="white-space:pre-wrap;word-break:break-word;background:rgba(0,0,0,0.15);padding:1rem;border-radius:8px;font-size:0.85rem;">' + escHtml(String(llm)) + '</pre>';
            }
            if (llmHtml) output.llm = llmHtml;
        }

        /* ===== DETECTION RULES TAB ===== */
        var rules = res.detection_rules || {};
        if ((typeof rules === 'object' && !Array.isArray(rules) && Object.keys(rules).length > 0) || (Array.isArray(rules) && rules.length > 0)) {
            var drHtml = '';
            var ruleUid = 0;

            var ruleMap = {};
            if (Array.isArray(rules)) {
                rules.forEach(function (r) {
                    var rType = r.type || r.name || 'Rule ' + (ruleUid++);
                    ruleMap[rType] = r.rule || r.content || r.value || '';
                });
            } else {
                ruleMap = rules;
            }

            var ruleTypes = Object.keys(ruleMap);
            if (ruleTypes.length > 0) {
                drHtml += '<ul class="nav nav-pills sub-tabs mb-3" id="detectionSubTabs" role="tablist">';
                ruleTypes.forEach(function (rt, idx) {
                    var tabId = 'det-' + rt.toLowerCase().replace(/[^a-z0-9]/g, '');
                    drHtml += '<li class="nav-item" role="presentation">';
                    drHtml += '<button class="nav-link' + (idx === 0 ? ' active' : '') + '" id="tab-' + tabId + '" data-bs-toggle="pill" data-bs-target="#panel-' + tabId + '" type="button" role="tab">';
                    drHtml += '<i class="bi bi-code-square me-1"></i>' + escHtml(rt.toUpperCase());
                    drHtml += '</button></li>';
                });
                drHtml += '</ul>';

                drHtml += '<div class="tab-content">';
                ruleTypes.forEach(function (rt, idx) {
                    var tabId = 'det-' + rt.toLowerCase().replace(/[^a-z0-9]/g, '');
                    var preId = 'rule-pre-' + tabId;
                    var content = ruleMap[rt] || '';
                    if (typeof content !== 'string') content = JSON.stringify(content, null, 2);
                    drHtml += '<div class="tab-pane fade' + (idx === 0 ? ' show active' : '') + '" id="panel-' + tabId + '" role="tabpanel">';
                    drHtml += '<div class="detection-rule-block">';
                    drHtml += '<button class="btn-copy-rule" onclick="copyRuleToClipboard(this, \'' + preId + '\')"><i class="bi bi-clipboard"></i> Copy</button>';
                    drHtml += '<pre id="' + preId + '">' + escHtml(content) + '</pre>';
                    drHtml += '</div></div>';
                });
                drHtml += '</div>';
            }

            if (drHtml) output.detection = drHtml;
        }

        /* ===== SHELLCODE TAB ===== */
        var shellcode = res.shellcode_detection || res.shellcode || {};
        var shellPatterns = shellcode.patterns || shellcode.detections || [];
        if (Array.isArray(shellPatterns) && shellPatterns.length > 0) {
            var shHtml = '<h6><i class="bi bi-bug me-1 text-danger"></i>Shellcode Patterns Detected <span class="badge bg-danger">' + shellPatterns.length + '</span></h6>';
            shHtml += '<table class="table table-sm" style="color:var(--bs-body-color);font-size:0.83rem;">';
            shHtml += '<thead><tr><th>Technique</th><th>Offset</th><th>Confidence</th><th>Framework</th></tr></thead><tbody>';
            shellPatterns.forEach(function (p) {
                var technique = typeof p === 'string' ? p : (p.technique || p.name || p.pattern || '');
                var offset = typeof p === 'object' ? (p.offset !== undefined ? '0x' + Number(p.offset).toString(16).toUpperCase() : '') : '';
                var confidence = typeof p === 'object' ? (p.confidence || '') : '';
                var framework = typeof p === 'object' ? (p.framework || p.type || '') : '';
                var confColor = String(confidence).toLowerCase() === 'high' ? 'danger' : (String(confidence).toLowerCase() === 'medium' ? 'warning' : 'info');
                shHtml += '<tr>';
                shHtml += '<td><code>' + escHtml(technique) + '</code></td>';
                shHtml += '<td><code class="yara-string-offset">' + escHtml(offset) + '</code></td>';
                shHtml += '<td>' + (confidence ? '<span class="badge bg-' + confColor + '">' + escHtml(String(confidence)) + '</span>' : '') + '</td>';
                shHtml += '<td>' + escHtml(framework) + '</td>';
                shHtml += '</tr>';
            });
            shHtml += '</tbody></table>';
            if (shellcode.summary || shellcode.description) {
                shHtml += '<div class="alert alert-danger py-2 px-3 mt-2" style="font-size:0.83rem;background:rgba(220,53,69,0.1);border-color:rgba(220,53,69,0.25);">';
                shHtml += '<i class="bi bi-exclamation-triangle me-1"></i>' + escHtml(shellcode.summary || shellcode.description);
                shHtml += '</div>';
            }
            output.shellcode = shHtml;
        } else if (typeof shellcode === 'object' && Object.keys(shellcode).length > 0 && !shellPatterns.length) {
            /* Shellcode object exists but no patterns array - show as key-value */
            var shFallback = '<h6><i class="bi bi-bug me-1 text-accent"></i>Shellcode Detection</h6>';
            if (shellcode.detected === false || shellcode.is_shellcode === false) {
                shFallback += '<p style="color:var(--bs-secondary-color);"><i class="bi bi-check-circle text-success me-1"></i>No shellcode patterns detected.</p>';
            } else {
                shFallback += '<pre style="white-space:pre-wrap;word-break:break-word;background:rgba(0,0,0,0.15);padding:0.75rem;border-radius:8px;color:var(--bs-body-color);max-height:400px;overflow-y:auto;">' + escHtml(JSON.stringify(shellcode, null, 2)) + '</pre>';
            }
            output.shellcode = shFallback;
        }

        /* ===== OVERLAY DATA (shown in static tab) ===== */
        var overlay = res.overlay_data || res.overlay || {};
        if (typeof overlay === 'object' && Object.keys(overlay).length > 0) {
            if (!output.static) output.static = '';
            output.static += '<div class="mb-4">';
            output.static += '<h6><i class="bi bi-layers me-1 text-warning"></i>Overlay Data</h6>';
            output.static += '<table class="table table-sm" style="color:var(--bs-body-color);">';
            if (overlay.has_overlay !== undefined) output.static += '<tr><th>Has Overlay</th><td>' + (overlay.has_overlay ? '<span class="badge bg-warning text-dark">Yes</span>' : '<span class="badge bg-success">No</span>') + '</td></tr>';
            if (overlay.offset !== undefined) output.static += '<tr><th>Offset</th><td><code>0x' + Number(overlay.offset).toString(16).toUpperCase() + '</code> (' + overlay.offset + ')</td></tr>';
            if (overlay.size !== undefined) output.static += '<tr><th>Size</th><td>' + escHtml(String(overlay.size)) + ' bytes</td></tr>';
            Object.keys(overlay).forEach(function (k) {
                if (['has_overlay', 'offset', 'size'].indexOf(k) >= 0) return;
                output.static += '<tr><th>' + escHtml(k.replace(/_/g, ' ').replace(/\b\w/g, function (l) { return l.toUpperCase(); })) + '</th><td>' + escHtml(String(overlay[k])) + '</td></tr>';
            });
            output.static += '</table></div>';
        }

        /* ===== PIPELINE TAB ===== */
        var rawOutput = res.raw_output || {};
        var pipelineSteps = rawOutput.pipeline_steps || res.pipeline_steps || [];
        if (pipelineSteps.length > 0) {
            var plHtml = '<h6><i class="bi bi-list-check me-1 text-accent"></i>Analysis Pipeline</h6>';
            var totalDuration = 0;
            pipelineSteps.forEach(function (ps) { if (ps.duration_ms) totalDuration += ps.duration_ms; });
            plHtml += '<div class="mb-3" style="font-size:0.82rem;"><strong>Total Duration:</strong> ' + (totalDuration / 1000).toFixed(2) + 's | <strong>Steps:</strong> ' + pipelineSteps.length + '</div>';

            plHtml += '<div class="pipeline-timeline">';
            pipelineSteps.forEach(function (ps) {
                var statusClass = 'step-completed';
                var statusIcon = '<i class="bi bi-check-circle-fill text-success"></i>';
                if (ps.status === 'failed' || ps.status === 'error') {
                    statusClass = 'step-failed';
                    statusIcon = '<i class="bi bi-x-circle-fill text-danger"></i>';
                } else if (ps.status === 'skipped') {
                    statusClass = 'step-skipped';
                    statusIcon = '<i class="bi bi-dash-circle text-secondary"></i>';
                }

                plHtml += '<div class="pipeline-step ' + statusClass + '">';
                plHtml += '<div class="ps-header">';
                plHtml += statusIcon;
                plHtml += '<span>' + escHtml(ps.step || ps.name || 'Step') + '</span>';
                if (ps.duration_ms !== undefined) {
                    plHtml += '<span class="ps-duration">' + (ps.duration_ms >= 1000 ? (ps.duration_ms / 1000).toFixed(2) + 's' : ps.duration_ms + 'ms') + '</span>';
                }
                plHtml += '</div>';
                if (ps.phase) {
                    plHtml += '<div class="ps-meta">Phase: ' + escHtml(ps.phase) + '</div>';
                }
                plHtml += '</div>';
            });
            plHtml += '</div>';
            output.pipeline = plHtml;
        }

        return output;
    }

    // Expose public API
    window.BTAAnalysis = {
        showProgress: showProgress,
        hideProgress: hideProgress,
        updateProgress: updateProgress,
        renderResults: renderResults
    };

    // Expose callback-based analysis functions globally for template inline scripts
    window.startIOCAnalysis = startIOCAnalysis;
    window.startFileAnalysis = startFileAnalysis;
    window.startEmailAnalysis = startEmailAnalysis;
    window.renderFileResult = renderFileResult;
    window.renderEmailResult = renderEmailResult;
    window.renderIOCResult = renderIOCResult;

})();
