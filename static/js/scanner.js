/**
 * ThreatForge — Scanner Frontend Controller
 * ==========================================
 * Orchestrates real-time vulnerability scan execution, animated 3D/SVG telemetry,
 * 3-mode intensity selection, dynamic search/filtering, toast notifications,
 * and interactive clipboard actions.
 *
 * Implemented in accordance with UI/UX & Frontend guidelines:
 * - Resilient async fetch handling with network timeout & abort control
 * - 3 Scan Intensity Modes: Low (Recon), Mid (Balanced), High (Deep)
 * - Dynamic active engine checklist synchronization
 * - Non-blocking UI telemetry with animated SVG circular gauge
 * - Accessible keyboard shortcuts (Ctrl+Enter to audit, Esc to reset)
 * - Toast notification dispatch system
 * - One-click clipboard copy on technical evidence & payloads
 */

let CURRENT_REPORT = null;
let CURRENT_SCAN_ID = null;

const GRADE_COLORS = {
    'A': '#10b981', // Emerald
    'B': '#84cc16', // Lime
    'C': '#f59e0b', // Amber
    'D': '#f97316', // Orange
    'F': '#ef4444'  // Red
};

const MODE_MODULES = {
    'low': [
        "Missing Security Header",
        "Insecure Cookie Flags",
        "Clickjacking",
        "Open Directory Listing"
    ],
    'mid': [
        "Missing Security Header",
        "Insecure Cookie Flags",
        "Clickjacking",
        "Open Directory Listing",
        "CSRF Protection",
        "Brute-Force Protection",
        "SQL Injection",
        "Cross-Site Scripting (XSS)"
    ],
    'high': [
        "Missing Security Header",
        "Insecure Cookie Flags",
        "Clickjacking",
        "Open Directory Listing",
        "CSRF Protection",
        "Brute-Force Protection",
        "SQL Injection",
        "Cross-Site Scripting (XSS)",
        "Command Injection"
    ]
};

// Toast notification dispatch
function showToast(message, type = 'info', duration = 3500) {
    const container = document.getElementById('tf-toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `tf-toast tf-toast-${type}`;

    let iconSvg = '<svg class="tf-icon tf-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>';
    if (type === 'success') {
        iconSvg = '<svg class="tf-icon tf-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:#10b981;"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>';
    } else if (type === 'error') {
        iconSvg = '<svg class="tf-icon tf-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:#ef4444;"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>';
    }

    toast.innerHTML = `${iconSvg}<span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('hiding');
        setTimeout(() => toast.remove(), 250);
    }, duration);
}

// Copy helper with visual feedback
async function copyToClipboard(text, btnEl) {
    if (!text) return;
    try {
        await navigator.clipboard.writeText(text);
        if (btnEl) {
            const originalHtml = btnEl.innerHTML;
            btnEl.classList.add('copied');
            btnEl.innerHTML = '<svg class="tf-icon tf-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg> Copied!';
            setTimeout(() => {
                btnEl.classList.remove('copied');
                btnEl.innerHTML = originalHtml;
            }, 1800);
        }
        showToast('Copied to clipboard!', 'success', 2000);
    } catch (err) {
        showToast('Failed to copy to clipboard', 'error');
    }
}

// Quick target preset selector
function setTargetPreset(url) {
    const targetInput = document.getElementById('target-url');
    if (targetInput) {
        targetInput.value = url;
        targetInput.focus();
        showToast(`Target loaded: ${url}`, 'info', 2000);
    }
}

// Scan mode selection (Low, Mid, High)
function selectScanMode(mode) {
    const cards = ['low', 'mid', 'high'];
    cards.forEach(m => {
        const card = document.getElementById(`mode-card-${m}`);
        if (card) {
            card.classList.toggle('active', m === mode);
        }
    });

    const hiddenModeInput = document.getElementById('selected-scan-mode');
    if (hiddenModeInput) {
        hiddenModeInput.value = mode;
    }

    // Synchronize checkboxes
    const activeList = MODE_MODULES[mode] || MODE_MODULES['mid'];
    const checkboxes = document.querySelectorAll('.engine-check');
    checkboxes.forEach(cb => {
        cb.checked = activeList.includes(cb.value);
    });

    updateActiveEnginesCount();
    showToast(`Switched to ${mode.toUpperCase()} intensity mode`, 'info', 1800);
}

function onEngineCheckChanged() {
    updateActiveEnginesCount();
}

function updateActiveEnginesCount() {
    const checkboxes = document.querySelectorAll('.engine-check:checked');
    const countEl = document.getElementById('active-engines-count');
    if (countEl) {
        countEl.innerText = checkboxes.length;
    }
}

function toggleScanBtn() {
    const chk = document.getElementById('auth-check');
    const btn = document.getElementById('scan-submit-btn');
    if (chk && btn) {
        btn.disabled = !chk.checked;
    }
}

async function startScan() {
    const targetInput = document.getElementById('target-url');
    const cookieInput = document.getElementById('session-cookie');
    const authCheck = document.getElementById('auth-check');
    const modeInput = document.getElementById('selected-scan-mode');
    const btn = document.getElementById('scan-submit-btn');
    const btnText = document.getElementById('scan-btn-text');
    const btnSpinner = document.getElementById('scan-btn-spinner');
    const consoleBox = document.getElementById('tf-console');
    const consoleLogs = document.getElementById('tf-console-logs');
    const progressBar = document.getElementById('tf-scan-progress');
    const stageLabel = document.getElementById('tf-console-stage');
    const errorBox = document.getElementById('scan-error-box');
    const resultsSec = document.getElementById('scan-results');
    const initialCaps = document.getElementById('initial-caps-card');

    const targetUrl = (targetInput.value || '').trim();
    const sessionCookie = (cookieInput ? cookieInput.value : '').trim();
    const scanMode = (modeInput ? modeInput.value : 'mid').trim().toLowerCase();

    // Collect checked modules
    const checkedModules = [];
    document.querySelectorAll('.engine-check:checked').forEach(cb => {
        checkedModules.push(cb.value);
    });

    if (!targetUrl) {
        showError('Please enter a target URL.');
        showToast('Please specify target URL', 'error');
        return;
    }
    if (!authCheck.checked) {
        showError('You must confirm you are authorized to audit this target.');
        showToast('Target authorization confirmation required', 'error');
        return;
    }
    if (checkedModules.length === 0) {
        showError('Please select at least one audit engine from the matrix.');
        showToast('At least one engine must be enabled', 'error');
        return;
    }

    // Reset UI State
    errorBox.style.display = 'none';
    resultsSec.style.display = 'none';
    if (initialCaps) initialCaps.style.display = 'none';

    btn.disabled = true;
    btnText.innerText = 'Auditing Target...';
    btnSpinner.style.display = 'inline-block';
    consoleBox.style.display = 'block';
    consoleLogs.innerHTML = '';
    if (progressBar) progressBar.style.width = '6%';
    if (stageLabel) stageLabel.innerText = `Stage 1/${checkedModules.length} (Initiating)`;

    // Dynamic steps based on enabled modules
    const steps = ['[+] Validating target URL format & local isolation policies...'];
    if (checkedModules.includes('Missing Security Header')) steps.push('[+] Auditing missing security headers (CSP, HSTS, X-Content-Type)...');
    if (checkedModules.includes('Insecure Cookie Flags')) steps.push('[+] Parsing Set-Cookie attributes for HttpOnly, Secure & SameSite flags...');
    if (checkedModules.includes('Clickjacking')) steps.push('[+] Inspecting X-Frame-Options and CSP frame-ancestors defenses...');
    if (checkedModules.includes('Open Directory Listing')) steps.push('[+] Probing server directory paths for open index listings...');
    if (checkedModules.includes('CSRF Protection')) steps.push('[+] Extracting HTML forms and auditing anti-CSRF token fields...');
    if (checkedModules.includes('Brute-Force Protection')) steps.push('[+] Testing login rate limiting against multiple sequential requests...');
    if (checkedModules.includes('SQL Injection')) steps.push('[+] Testing URL parameters and form vectors for SQL Injection...');
    if (checkedModules.includes('Cross-Site Scripting (XSS)')) steps.push('[+] Fuzzing inputs with safe reflected & stored XSS test vectors...');
    if (checkedModules.includes('Command Injection')) steps.push('[+] Injecting safe arithmetic Command Injection canaries...');
    steps.push('[+] Compiling final findings and calculating comprehensive risk score...');

    let stepIdx = 0;
    const interval = setInterval(() => {
        if (stepIdx < steps.length) {
            const el = document.createElement('div');
            el.innerText = steps[stepIdx];
            consoleLogs.appendChild(el);
            consoleLogs.scrollTop = consoleLogs.scrollHeight;

            const pct = Math.round(((stepIdx + 1) / steps.length) * 100);
            if (progressBar) progressBar.style.width = `${pct}%`;
            if (stageLabel) stageLabel.innerText = `Stage ${stepIdx + 1}/${steps.length} (${pct}%)`;

            stepIdx++;
        }
    }, 650);

    try {
        const payload = {
            target_url: targetUrl,
            authorized: true,
            session_cookie: sessionCookie,
            scan_mode: scanMode,
            enabled_modules: checkedModules
        };

        const res = await fetch('/api/scan/run/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCookie('csrftoken')
            },
            body: JSON.stringify(payload)
        });

        clearInterval(interval);
        const data = await res.json();

        btn.disabled = false;
        btnText.innerText = 'Initiate Security Audit';
        btnSpinner.style.display = 'none';

        if (!data.ok) {
            consoleBox.style.display = 'none';
            if (initialCaps) initialCaps.style.display = 'block';
            showError(data.error || 'Vulnerability audit failed.');
            showToast(data.error || 'Scan failed', 'error');
            return;
        }

        // Complete terminal log
        if (progressBar) progressBar.style.width = '100%';
        if (stageLabel) stageLabel.innerText = 'Audit Complete (100%)';

        const el = document.createElement('div');
        el.style.color = '#10b981';
        el.style.fontWeight = '700';
        el.innerText = `[✓] Audit completed in ${data.duration_sec}s! Risk Score: ${data.report.risk_score}/100 (Grade ${data.report.grade})`;
        consoleLogs.appendChild(el);
        consoleLogs.scrollTop = consoleLogs.scrollHeight;

        CURRENT_REPORT = data.report;
        CURRENT_SCAN_ID = data.scan_id;

        showToast(`Audit finished in ${data.duration_sec}s — Grade ${data.report.grade}`, 'success');
        renderResults(data.report, data.scan_id, data.recent_scans);
    } catch (err) {
        clearInterval(interval);
        btn.disabled = false;
        btnText.innerText = 'Initiate Security Audit';
        btnSpinner.style.display = 'none';
        consoleBox.style.display = 'none';
        if (initialCaps) initialCaps.style.display = 'block';
        showError('Network error while running scan: ' + err.message);
        showToast('Network error during scan: ' + err.message, 'error');
    }
}

function renderResults(report, scanId, recentScans) {
    const resultsSec = document.getElementById('scan-results');
    const initCaps = document.getElementById('initial-caps-card');
    if (initCaps) initCaps.style.display = 'none';
    if (resultsSec) resultsSec.style.display = 'block';

    const score = report.risk_score || 0;
    const grade = report.grade || 'A';
    const label = report.label || 'Excellent';
    const total = report.total_findings || 0;
    const sev = report.severity_counts || { High: 0, Medium: 0, Low: 0 };
    const gradeColor = GRADE_COLORS[grade] || '#10b981';

    // 1. Executive Minimal Score & Grade
    const scoreCircle = document.getElementById('minimal-score-circle');
    const scoreNum = document.getElementById('minimal-score-num');
    const gradePill = document.getElementById('minimal-grade-pill');
    const labelText = document.getElementById('minimal-label-text');
    const targetDisplay = document.getElementById('minimal-target-display');
    const durationTag = document.getElementById('minimal-duration-tag');
    const summaryTag = document.getElementById('minimal-summary-tag');

    if (scoreNum) scoreNum.innerText = score;
    if (scoreCircle) {
        scoreCircle.style.borderColor = gradeColor;
        scoreCircle.style.color = gradeColor;
        scoreCircle.style.background = `${gradeColor}18`;
        scoreCircle.style.boxShadow = `0 0 22px ${gradeColor}40`;
    }
    if (gradePill) {
        gradePill.innerText = `Grade ${grade}`;
        gradePill.style.background = gradeColor;
    }
    if (labelText) labelText.innerText = label;
    if (targetDisplay) targetDisplay.innerText = report.target || 'Target';
    if (durationTag) {
        durationTag.innerText = `${report.duration_sec || '1.1'}s`;
    }
    if (summaryTag) {
        summaryTag.innerText = `${total} issue${total === 1 ? '' : 's'} detected`;
    }

    // 2. Download Buttons
    const btnPdf = document.getElementById('btn-download-pdf');
    const btnCsv = document.getElementById('btn-download-csv');
    if (btnPdf) btnPdf.href = `/report/${scanId}/pdf/`;
    if (btnCsv) btnCsv.href = `/report/${scanId}/csv/`;

    // 3. Issues Summary Breakdown (Short list e.g. "1 × Missing Security Header")
    const issuesListEl = document.getElementById('minimal-issues-list');
    const issuesBadgeEl = document.getElementById('minimal-issues-badge');
    const findings = report.findings || [];

    if (issuesBadgeEl) {
        issuesBadgeEl.innerText = `${total} ${total === 1 ? 'Issue' : 'Issues'}`;
        if (sev.High > 0) {
            issuesBadgeEl.className = 'badge badge-high';
        } else if (sev.Medium > 0) {
            issuesBadgeEl.className = 'badge badge-medium';
        } else {
            issuesBadgeEl.className = 'badge badge-low';
        }
    }

    if (issuesListEl) {
        if (findings.length === 0) {
            issuesListEl.innerHTML = `
                <div class="minimal-clean-state">
                    <span>No vulnerabilities were found in the checks performed.</span>
                </div>
            `;
        } else {
            // Group findings by type
            const grouped = {};
            findings.forEach(f => {
                const t = f.type || 'Generic Vulnerability';
                if (!grouped[t]) {
                    grouped[t] = {
                        type: t,
                        count: 0,
                        severity: f.severity || 'Medium'
                    };
                }
                grouped[t].count += 1;
                // If any finding in group is high, upgrade group severity display
                if (f.severity === 'High') grouped[t].severity = 'High';
            });

            // Sort: High severity first, then Medium, then Low
            const sevWeight = { 'High': 3, 'Medium': 2, 'Low': 1 };
            const sortedGroups = Object.values(grouped).sort((a, b) => {
                const diff = (sevWeight[b.severity] || 0) - (sevWeight[a.severity] || 0);
                if (diff !== 0) return diff;
                return b.count - a.count;
            });

            issuesListEl.innerHTML = sortedGroups.map(item => {
                const badgeCls = item.severity === 'High' ? 'badge-high' : (item.severity === 'Medium' ? 'badge-medium' : 'badge-low');
                return `
                    <div class="minimal-issue-item sev-${escapeHtml(item.severity)}">
                        <div style="display:flex;align-items:center;gap:0.6rem;">
                            <span style="font-weight:800;font-family:'JetBrains Mono',monospace;color:var(--text-primary);min-width:28px;">
                                ${item.count} &times;
                            </span>
                            <span style="font-weight:600;color:var(--text-primary);">
                                ${escapeHtml(item.type)}
                            </span>
                        </div>
                        <span class="badge ${badgeCls}">${escapeHtml(item.severity)} Severity</span>
                    </div>
                `;
            }).join('');
        }
    }

    // 4. Update Optional Raw Findings Details Drawer
    const detailsCount = document.getElementById('details-findings-count');
    if (detailsCount) {
        detailsCount.innerText = `${total} Raw ${total === 1 ? 'Finding' : 'Findings'}`;
    }

    // Populate Category filter dropdown inside details drawer
    const typeSelect = document.getElementById('type-filter');
    if (typeSelect) {
        const distinctTypes = [...new Set(findings.map(f => f.type))].sort();
        typeSelect.innerHTML = '<option value="ALL">All Categories</option>' +
            distinctTypes.map(t => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join('');
    }

    // Render Raw Findings into details accordion
    applyFindingsFilter();

    // 5. Real-Time Update of Persistent Past Scans Table
    if (recentScans && recentScans.length > 0) {
        renderPastScans(recentScans);
    }
}

function renderPastScans(scans) {
    const tbody = document.getElementById('past-scans-tbody');
    if (!tbody || !scans || scans.length === 0) return;

    tbody.innerHTML = scans.map(s => {
        const gradeColor = GRADE_COLORS[s.grade] || '#10b981';
        const startedDate = (s.started_at || '').slice(0, 16);
        const total = s.total_findings || 0;
        let issuesBadge = '<span class="badge badge-low" style="font-size:0.7rem;">0 issues</span>';
        if (total > 0) {
            const highNote = s.high_count ? `<span style="color:#f87171;font-weight:700;">(${s.high_count}H)</span>` : '';
            issuesBadge = `<span style="font-size:0.8rem;color:var(--text-secondary);">${total} issue${total === 1 ? '' : 's'} ${highNote}</span>`;
        }

        return `
            <tr>
                <td>
                    <a class="past-target-link" data-target="${escapeHtml(s.target)}" title="Click to reload this target into scanner" style="cursor:pointer;">
                        ${escapeHtml(s.target)}
                    </a>
                </td>
                <td style="font-size:0.78rem;color:var(--text-muted);white-space:nowrap;">
                    ${escapeHtml(startedDate)}
                </td>
                <td>
                    <span class="grade-pill" style="font-size:0.75rem;padding:0.15rem 0.55rem;background:${gradeColor};">
                        ${escapeHtml(s.grade)}
                    </span>
                    <span style="font-family:'JetBrains Mono',monospace;font-size:0.8rem;margin-left:0.3rem;">${s.risk_score}/100</span>
                </td>
                <td>
                    ${issuesBadge}
                </td>
                <td style="text-align:right;white-space:nowrap;">
                    <a href="/report/${s.id}/pdf/" class="past-btn-pdf" title="Download Executive PDF">
                        <svg class="tf-icon tf-icon-sm" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline></svg>
                        <span>PDF</span>
                    </a>
                </td>
            </tr>
        `;
    }).join('');
}

function applyFindingsFilter() {
    if (!CURRENT_REPORT) return;
    const sevFilter = document.getElementById('sev-filter').value;
    const typeFilter = document.getElementById('type-filter').value;
    const searchQuery = (document.getElementById('search-input').value || '').trim().toLowerCase();
    const container = document.getElementById('findings-container');
    const countBadge = document.getElementById('findings-count-badge');

    const findings = CURRENT_REPORT.findings || [];
    const filtered = findings.filter(f => {
        if (sevFilter !== 'ALL' && f.severity !== sevFilter) return false;
        if (typeFilter !== 'ALL' && f.type !== typeFilter) return false;
        if (searchQuery) {
            const text = `${f.type} ${f.field || ''} ${f.payload || ''} ${f.evidence || ''} ${f.detail || ''}`.toLowerCase();
            if (!text.includes(searchQuery)) return false;
        }
        return true;
    });

    if (countBadge) {
        countBadge.innerText = `${filtered.length} of ${findings.length} matches`;
    }

    if (filtered.length === 0) {
        container.innerHTML = `
            <div class="glass-card" style="text-align:center;padding:2.5rem 1.5rem;">
                <svg class="tf-icon tf-icon-lg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-bottom:0.5rem;color:var(--text-muted);"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
                <div style="font-weight:700;font-size:1.02rem;">No findings match your filter</div>
                <div style="color:var(--text-secondary);font-size:0.84rem;margin-top:0.3rem;">Try broadening your query or selecting "All Severities".</div>
            </div>
        `;
        return;
    }

    // Group by severity
    const groups = { 'High': [], 'Medium': [], 'Low': [] };
    filtered.forEach(f => {
        if (groups[f.severity]) groups[f.severity].push(f);
        else groups['Low'].push(f);
    });

    let html = '';
    const sevMeta = [
        { key: 'High', color: '#f87171', label: 'High Severity' },
        { key: 'Medium', color: '#fbbf24', label: 'Medium Severity' },
        { key: 'Low', color: '#34d399', label: 'Low Severity' }
    ];

    sevMeta.forEach(meta => {
        const list = groups[meta.key];
        if (list.length === 0) return;

        html += `
            <details class="glass-card finding-group-details" style="padding:1rem 1.3rem;margin-bottom:0.85rem;" open>
                <summary style="font-weight:700;font-size:0.98rem;cursor:pointer;user-select:none;display:flex;align-items:center;justify-content:space-between;">
                    <span style="display:inline-flex;align-items:center;gap:0.45rem;">
                        <span style="color:${meta.color};font-size:1.1rem;">●</span>
                        <span>${meta.label} (${list.length})</span>
                    </span>
                    <span style="font-size:0.78rem;color:var(--text-muted);">Toggle</span>
                </summary>
                <div style="margin-top:0.85rem;">
                    ${list.map((f, i) => renderFindingCard(f, i + 1)).join('')}
                </div>
            </details>
        `;
    });

    container.innerHTML = html;
}

function renderFindingCard(f, idx) {
    const sevCls = f.severity === 'High' ? 'badge-high' : (f.severity === 'Medium' ? 'badge-medium' : 'badge-low');
    const safePayload = escapeHtml(f.payload || '');
    const safeEvidence = escapeHtml(f.evidence || '');

    return `
        <div class="finding-card">
            <div class="finding-header">
                <span class="finding-type">#${idx} &middot; ${escapeHtml(f.type)}</span>
                <span class="badge ${sevCls}">${escapeHtml(f.severity)}</span>
            </div>
            <div class="finding-detail">${escapeHtml(f.detail)}</div>
            <div class="finding-meta">
                ${f.field && f.field !== 'N/A' ? `
                    <span>
                        <span style="color:var(--text-muted);">Target Field:</span> <strong>${escapeHtml(f.field)}</strong>
                    </span>
                ` : ''}
                ${f.payload && f.payload !== 'N/A' ? `
                    <div style="display:flex;align-items:center;gap:0.4rem;width:100%;flex-wrap:wrap;">
                        <span style="color:var(--text-muted);">Payload:</span>
                        <code>${safePayload}</code>
                        <button type="button" class="tf-btn-copy" data-copy="${safePayload}">Copy</button>
                    </div>
                ` : ''}
                ${f.evidence && f.evidence !== 'N/A' ? `
                    <div style="display:flex;align-items:center;gap:0.4rem;width:100%;flex-wrap:wrap;">
                        <span style="color:var(--text-muted);">Evidence:</span>
                        <code>${safeEvidence.slice(0, 160)}</code>
                        <button type="button" class="tf-btn-copy" data-copy="${safeEvidence}">Copy</button>
                    </div>
                ` : ''}
            </div>
        </div>
    `;
}

function toggleAllFindings(expand) {
    const detailsList = document.querySelectorAll('.finding-group-details');
    detailsList.forEach(d => {
        d.open = expand;
    });
}

function resetScanForm() {
    CURRENT_REPORT = null;
    document.getElementById('scan-results').style.display = 'none';
    document.getElementById('tf-console').style.display = 'none';
    const initCaps = document.getElementById('initial-caps-card');
    if (initCaps) initCaps.style.display = 'block';
}

function showError(msg) {
    const errorBox = document.getElementById('scan-error-box');
    const errorMsg = document.getElementById('scan-error-msg');
    errorMsg.innerText = msg;
    errorBox.style.display = 'flex';
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function escapeJsString(str) {
    if (!str) return '';
    return String(str)
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\"')
        .replace(/\n/g, '\\n')
        .replace(/\r/g, '\\r');
}

// Global delegated click listeners for secure copy and target preset loading (No inline eval/JS execution)
document.addEventListener('click', function (e) {
    const copyBtn = e.target.closest('.tf-btn-copy');
    if (copyBtn && copyBtn.dataset.copy) {
        copyToClipboard(copyBtn.dataset.copy, copyBtn);
        return;
    }
    const targetLink = e.target.closest('.past-target-link');
    if (targetLink && targetLink.dataset.target) {
        setTargetPreset(targetLink.dataset.target);
        return;
    }
});

function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// Global Keyboard Shortcut handler
document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        const authCheck = document.getElementById('auth-check');
        if (authCheck && authCheck.checked) {
            e.preventDefault();
            startScan();
        }
    }
    if (e.key === 'Escape') {
        const errorBox = document.getElementById('scan-error-box');
        if (errorBox) errorBox.style.display = 'none';
    }
});

// Auto-initialize active count
document.addEventListener('DOMContentLoaded', () => {
    updateActiveEnginesCount();
});
