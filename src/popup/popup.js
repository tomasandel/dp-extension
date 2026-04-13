/**
 * CT Guard - Popup Script
 *
 * Displays certificate transparency verification results with
 * live verification status updates and collapsible detail sections.
 */

let pollTimer = null;
let currentTabId = null;
let currentTabUrl = null;

document.addEventListener('DOMContentLoaded', async () => {
  await loadCertificateData();

  // Listen for tab URL changes so the popup refreshes automatically
  // when the user navigates from an internal/new-tab page to a real site.
  browser.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (tabId !== currentTabId) return;
    if (changeInfo.url || changeInfo.status === 'complete') {
      loadCertificateData();
    }
  });
});

async function loadCertificateData() {
  try {
    const tabs = await browser.tabs.query({ active: true, currentWindow: true });

    if (!tabs || tabs.length === 0) {
      showError("No active tab found");
      return;
    }

    const currentTab = tabs[0];
    currentTabId = currentTab.id;
    currentTabUrl = currentTab.url;

    const url = currentTab.url || '';
    if (!url.startsWith('https://')) {
      // Distinguish internal/blank pages from regular HTTP
      if (!url || url.startsWith('about:') || url.startsWith('moz-extension:') || url.startsWith('chrome:') || url === 'about:blank') {
        showStatus('internal');
      } else {
        showStatus('not-https');
      }
      return;
    }

    const response = await browser.runtime.sendMessage({
      action: "getCertificateData",
      tabId: currentTab.id,
      url: currentTab.url
    });

    if (response.success && response.data) {
      renderPopup(response.data);

      // If verification is still running, poll for updates
      if (response.data.verificationStatus === 'verifying') {
        startPolling();
      }
    } else {
      showStatus('no-data');
    }
  } catch (error) {
    console.error("[CT Guard Popup] Error:", error);
    showStatus('error', error.message);
  }
}

function startPolling() {
  if (pollTimer) return;
  pollTimer = setInterval(async () => {
    try {
      const response = await browser.runtime.sendMessage({
        action: "getCertificateData",
        tabId: currentTabId,
        url: currentTabUrl
      });
      if (response.success && response.data) {
        renderPopup(response.data);
        if (response.data.verificationStatus !== 'verifying') {
          clearInterval(pollTimer);
          pollTimer = null;
        }
      }
    } catch (e) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }, 400);
}

function renderPopup(data) {
  const contentDiv = document.getElementById('data');
  const loadingDiv = document.getElementById('loading');

  loadingDiv.classList.add('hidden');

  let html = '';

  // URL bar — show hostname only
  let displayHost = data.url;
  try { displayHost = new URL(data.url).hostname; } catch {}
  html += `<div class="url-bar">${escapeHtml(displayHost)}</div>`;

  // Verdict banner
  html += buildVerdictBanner(data);

  // SCT Verification section
  html += buildSCTSection(data);

  // Connection details section (collapsed by default)
  html += buildConnectionSection(data);

  // Certificate chain section (collapsed by default)
  html += buildCertChainSection(data);

  // Footer
  if (data.sctVerification?.verificationTimeMs != null) {
    html += `<div class="footer">Verified in ${data.sctVerification.verificationTimeMs}ms</div>`;
  }

  contentDiv.innerHTML = html;
  contentDiv.classList.remove('hidden');

  // Attach toggle listeners
  contentDiv.querySelectorAll('[data-toggle]').forEach(el => {
    el.addEventListener('click', () => {
      const targetId = el.getAttribute('data-toggle');
      const target = document.getElementById(targetId);
      if (target) {
        target.classList.toggle('collapsed');
        el.classList.toggle('expanded');
      }
    });
  });
}

/* ────────────────────────────────────────────
   Verdict banner
   ──────────────────────────────────────────── */
function buildVerdictBanner(data) {
  const status = data.verificationStatus;

  if (status === 'verifying') {
    return `
      <div class="verdict-banner verdict-verifying">
        <div class="verdict-icon"><div class="spinner"></div></div>
        <div class="verdict-text">
          Verifying SCTs...
          <div class="verdict-sub">Checking inclusion proofs and log consistency</div>
        </div>
      </div>`;
  }

  if (!data.sctVerification) {
    return `
      <div class="verdict-banner verdict-verifying">
        <div class="verdict-icon">?</div>
        <div class="verdict-text">
          Verification pending
          <div class="verdict-sub">Waiting for verification data</div>
        </div>
      </div>`;
  }

  const { total, verified, results } = data.sctVerification;
  const anyOk = verified >= 1;

  if (anyOk) {
    return `
      <div class="verdict-banner verdict-ok">
        <div class="verdict-icon">OK</div>
        <div class="verdict-text">
          Certificate publicly logged
          <div class="verdict-sub">${verified}/${total} SCTs passed inclusion and consistency checks</div>
        </div>
      </div>`;
  }

  // Analyze specific failures to determine title and details
  const analysis = analyzeFailures(results || []);

  return `
    <div class="verdict-banner verdict-fail">
      <div class="verdict-icon">FAIL</div>
      <div class="verdict-text">
        ${analysis.title}
        <div class="verdict-sub">${verified}/${total} SCTs verified successfully</div>
      </div>
    </div>
    <div class="warning-box">
      <div class="warning-title">CT Guard detected a problem with this connection</div>
      <div class="warning-detail">${analysis.details}</div>
    </div>`;
}

/**
 * Categorizes verification failures and produces a prioritized title + detail messages.
 * Priority (highest to lowest): proof_mismatch > not_found > inconsistent > log_error > log_unreachable > no_monitor_sth > unsupported
 */
function analyzeFailures(results) {
  // Categorize PoI failures by reason
  const poiByReason = {};
  for (const r of results) {
    if (r?.poi && !r.poi.verified && r.poi.reason) {
      const reason = r.poi.reason;
      if (!poiByReason[reason]) poiByReason[reason] = [];
      poiByReason[reason].push(r);
    }
  }

  // Categorize PoC failures by status
  const pocInconsistent = results.filter(r => r?.poc?.status === 'inconsistent');
  const pocError = results.filter(r => r?.poc?.status === 'error' || r?.poc?.status === 'no_monitor_sth');

  // Build messages and track severity
  const issues = []; // { priority, title, message }

  if (poiByReason.proof_mismatch?.length) {
    const n = poiByReason.proof_mismatch.length;
    issues.push({
      priority: 7,
      title: 'Inclusion proof invalid',
      message: `The Merkle audit proof from ${n} log${n > 1 ? 's' : ''} did not verify. The log may be serving a manipulated tree.`
    });
  }

  if (poiByReason.not_found_in_log?.length) {
    const n = poiByReason.not_found_in_log.length;
    issues.push({
      priority: 6,
      title: 'Certificate not found in log',
      message: `The certificate was not found in ${n} CT log${n > 1 ? 's' : ''}. This could indicate a fraudulently issued certificate.`
    });
  }

  if (pocInconsistent.length > 0) {
    const n = pocInconsistent.length;
    issues.push({
      priority: 5,
      title: 'Log inconsistency detected',
      message: `${n} CT log${n > 1 ? 's show' : ' shows'} inconsistent tree state. The log may be presenting different views to different observers.`
    });
  }

  if (poiByReason.log_error?.length) {
    const n = poiByReason.log_error.length;
    issues.push({
      priority: 4,
      title: 'CT log error',
      message: `${n} CT log${n > 1 ? 's' : ''} returned an error response. The log server may be experiencing issues.`
    });
  }

  if (poiByReason.log_unreachable?.length) {
    const n = poiByReason.log_unreachable.length;
    issues.push({
      priority: 3,
      title: 'CT log unreachable',
      message: `Could not connect to ${n} CT log${n > 1 ? 's' : ''}. The log server may be down or blocked.`
    });
  }

  if (pocError.length > 0) {
    const n = pocError.length;
    issues.push({
      priority: 2,
      title: 'Consistency check failed',
      message: `Consistency could not be verified for ${n} log${n > 1 ? 's' : ''}. Monitor data was unavailable or the consistency proof failed.`
    });
  }

  if (poiByReason.unsupported_log_type?.length) {
    const n = poiByReason.unsupported_log_type.length;
    issues.push({
      priority: 1,
      title: 'Unsupported log type',
      message: `${n} SCT${n > 1 ? 's are' : ' is'} from a static-ct log which is not yet supported for verification.`
    });
  }

  if (issues.length === 0) {
    return {
      title: 'Verification failed',
      details: 'SCT verification did not pass. Exercise caution with this connection.'
    };
  }

  // Sort by priority descending - highest severity first
  issues.sort((a, b) => b.priority - a.priority);

  return {
    title: issues[0].title,
    details: issues.map(i => i.message).join('<br><br>')
  };
}

/* ────────────────────────────────────────────
   Connection details
   ──────────────────────────────────────────── */
function buildConnectionSection(data) {
  let flagsHtml = '';
  if (data.securityFlags) {
    const flags = [
      { key: 'hsts', label: 'HSTS' },
      { key: 'usedOcsp', label: 'OCSP' },
      { key: 'usedEch', label: 'ECH' },
      { key: 'isExtendedValidation', label: 'EV' },
      { key: 'usedDelegatedCredentials', label: 'DC' },
    ];
    const pills = flags.map(f => {
      const on = data.securityFlags[f.key];
      return `<span class="flag-pill ${on ? 'flag-on' : 'flag-off'}">${f.label}</span>`;
    }).join('');
    flagsHtml = `<div class="security-flags">${pills}</div>`;
  }

  return `
    <div class="section">
      <div class="section-header" data-toggle="conn-body">
        <h2>Connection</h2>
        <span class="chevron">\u25B6</span>
      </div>
      <div class="section-body collapsed" id="conn-body">
        <div class="info-row">
          <span class="label">Security:</span>
          <span class="value">${escapeHtml(data.securityState)}</span>
        </div>
        <div class="info-row">
          <span class="label">Protocol:</span>
          <span class="value">${escapeHtml(data.protocolVersion)}</span>
        </div>
        <div class="info-row">
          <span class="label">Cipher:</span>
          <span class="value">${escapeHtml(data.cipherSuite)}</span>
        </div>
        ${data.ctStatus ? `
        <div class="info-row">
          <span class="label">CT Status:</span>
          <span class="value">${escapeHtml(data.ctStatus)}</span>
        </div>` : ''}
        ${flagsHtml}
      </div>
    </div>`;
}

/* ────────────────────────────────────────────
   SCT Verification
   ──────────────────────────────────────────── */
function buildSCTSection(data) {
  if (!data.scts || data.scts.length === 0) {
    return `
      <div class="section">
        <div class="section-header expanded" data-toggle="sct-body">
          <h2>Signed Certificate Timestamps</h2>
          <span class="chevron">\u25B6</span>
        </div>
        <div class="section-body" id="sct-body">
          <div class="no-data">No SCTs found in this certificate</div>
        </div>
      </div>`;
  }

  const verifying = data.verificationStatus === 'verifying';
  let headerExtra = '';
  if (data.sctVerification) {
    const { verified, total } = data.sctVerification;
    const anyOk = verified >= 1;
    headerExtra = `<span class="badge ${anyOk ? 'success' : 'error'}">${verified}/${total}</span>`;
  } else if (verifying) {
    headerExtra = `<span class="badge info">verifying</span>`;
  }

  let cardsHtml = '';
  data.scts.forEach((sct, i) => {
    const vr = data.sctVerification?.results?.[i];
    cardsHtml += buildSCTCard(sct, i, vr, verifying);
  });

  return `
    <div class="section">
      <div class="section-header expanded" data-toggle="sct-body">
        <h2>SCTs (${data.scts.length}) ${headerExtra}</h2>
        <span class="chevron">\u25B6</span>
      </div>
      <div class="section-body" id="sct-body">
        ${cardsHtml}
      </div>
    </div>`;
}

function buildSCTCard(sct, index, vr, verifying) {
  // Badges for PoI and PoC shown on the card header
  let poiBadge = '', pocBadge = '';
  if (vr?.poi) {
    poiBadge = vr.poi.verified
      ? '<span class="badge success">PoI</span>'
      : '<span class="badge error">PoI</span>';
  } else if (verifying) {
    poiBadge = '<span class="badge info">PoI</span>';
  }

  if (vr?.poc) {
    switch (vr.poc.status) {
      case 'consistent':
        pocBadge = '<span class="badge success">PoC</span>';
        break;
      case 'inconsistent':
        pocBadge = '<span class="badge error">PoC</span>';
        break;
      case 'skipped':
        pocBadge = '<span class="badge warning">PoC</span>';
        break;
      default:
        pocBadge = `<span class="badge error">PoC</span>`;
    }
  } else if (verifying) {
    pocBadge = '<span class="badge info">PoC</span>';
  }

  // Verification detail box
  let verificationHtml = '';
  if (vr?.poi) {
    const poiStatusBadge = vr.poi.verified
      ? '<span class="badge success">Verified</span>'
      : '<span class="badge error">Failed</span>';

    let pocStatusBadge;
    switch (vr.poc?.status) {
      case 'consistent':
        pocStatusBadge = '<span class="badge success">Consistent</span>';
        break;
      case 'inconsistent':
        pocStatusBadge = '<span class="badge error">Inconsistent</span>';
        break;
      case 'skipped':
        pocStatusBadge = '<span class="badge warning">Skipped</span>';
        break;
      default:
        pocStatusBadge = `<span class="badge error">${escapeHtml(vr.poc?.status || 'unknown')}</span>`;
    }

    verificationHtml = `
      <div class="verification-box">
        <div class="info-row">
          <span class="label">Proof of Inclusion:</span>
          <span class="value">${poiStatusBadge}</span>
        </div>
        ${vr.poi.detail ? `<div class="verification-detail">${escapeHtml(vr.poi.detail)}</div>` : ''}
        <div class="info-row">
          <span class="label">Proof of Consistency:</span>
          <span class="value">${pocStatusBadge}</span>
        </div>
        ${vr.poc?.detail ? `<div class="verification-detail">${escapeHtml(vr.poc.detail)}</div>` : ''}
      </div>`;
  } else if (verifying) {
    verificationHtml = `
      <div class="verification-box">
        <div class="info-row">
          <span class="label">Status:</span>
          <span class="value"><span class="badge info">Verifying...</span></span>
        </div>
      </div>`;
  }

  const operatorName = sct.logOperator || 'Unknown operator';
  const detailId = `sct-detail-${index}`;

  return `
    <div class="sct-card">
      <div class="sct-card-header" data-toggle="${detailId}">
        <div class="sct-card-title">
          <span class="sct-number">#${index + 1}</span>
          <span class="sct-operator">${escapeHtml(operatorName)}</span>
        </div>
        <div class="sct-card-badges">${poiBadge}${pocBadge}</div>
      </div>
      <div class="sct-card-detail collapsed" id="${detailId}">
        ${verificationHtml}
        ${sct.logDescription ? `
        <div class="info-row">
          <span class="label">Log Name:</span>
          <span class="value">${escapeHtml(sct.logDescription)}</span>
        </div>` : ''}
        ${sct.logUrl ? `
        <div class="info-row">
          <span class="label">Log URL:</span>
          <span class="value"><a href="${escapeHtml(sct.logUrl)}" target="_blank">${escapeHtml(sct.logUrl)}</a></span>
        </div>` : ''}
        ${sct.logState ? `
        <div class="info-row">
          <span class="label">Log State:</span>
          <span class="value">${getLogStateText(sct.logState)}</span>
        </div>` : ''}
        ${sct.logType ? `
        <div class="info-row">
          <span class="label">Log Type:</span>
          <span class="value">${escapeHtml(sct.logType)}</span>
        </div>` : ''}
        <div class="info-row">
          <span class="label">Log ID:</span>
          <span class="value" style="font-size: 10px;">${escapeHtml(sct.logId)}</span>
        </div>
        <div class="info-row">
          <span class="label">Timestamp:</span>
          <span class="value">${sct.timestampDate || 'N/A'} (${sct.timestamp})</span>
        </div>
        <div class="info-row">
          <span class="label">Origin:</span>
          <span class="value">${escapeHtml(sct.origin)}</span>
        </div>
        <div class="info-row">
          <span class="label">Signature:</span>
          <span class="value">${escapeHtml(sct.signatureAlgorithm)} / ${escapeHtml(sct.signatureHashAlgorithm)}</span>
        </div>
        <div class="info-row">
          <span class="label">Version:</span>
          <span class="value">${sct.version}</span>
        </div>
        ${sct.extensionsHex ? `
        <div class="info-row">
          <span class="label">Extensions:</span>
          <span class="value">${escapeHtml(sct.extensionsHex)}</span>
        </div>` : ''}
      </div>
    </div>`;
}

/* ────────────────────────────────────────────
   Certificate chain
   ──────────────────────────────────────────── */
function buildCertChainSection(data) {
  if (!data.certificates || data.certificates.length === 0) return '';

  let certsHtml = '';
  data.certificates.forEach((cert, i) => {
    const certType = i === 0 ? 'Leaf (Server)' :
                     i === data.certificates.length - 1 ? 'Root CA' :
                     'Intermediate CA';

    certsHtml += `
      <div class="cert-card">
        <h3>Certificate ${i} \u2014 ${certType}</h3>
        <div class="cert-field"><strong>Subject:</strong> ${escapeHtml(cert.subject)}</div>
        <div class="cert-field"><strong>Issuer:</strong> ${escapeHtml(cert.issuer)}</div>
        ${cert.validity.start && cert.validity.end ? `
        <div class="cert-field"><strong>Valid From:</strong> ${new Date(cert.validity.start).toLocaleString()}</div>
        <div class="cert-field"><strong>Valid To:</strong> ${new Date(cert.validity.end).toLocaleString()}</div>
        ` : ''}
        <div class="cert-field"><strong>Serial:</strong> ${escapeHtml(cert.serialNumber)}</div>
        ${cert.fingerprint?.sha256 ? `
        <div class="cert-field"><strong>SHA-256:</strong> <span style="font-size: 10px;">${escapeHtml(cert.fingerprint.sha256)}</span></div>
        ` : ''}
      </div>`;
  });

  return `
    <div class="section">
      <div class="section-header" data-toggle="cert-body">
        <h2>Certificate Chain (${data.certificates.length})</h2>
        <span class="chevron">\u25B6</span>
      </div>
      <div class="section-body collapsed" id="cert-body">
        ${certsHtml}
      </div>
    </div>`;
}

/* ────────────────────────────────────────────
   Helpers
   ──────────────────────────────────────────── */
function showStatus(type, detail) {
  document.getElementById('loading').classList.add('hidden');

  const states = {
    'internal': {
      icon: '\u{1F6E1}',
      title: 'CT Guard',
      message: 'Navigate to an HTTPS website to see Certificate Transparency verification results.'
    },
    'not-https': {
      icon: '\u{1F512}',
      title: 'Not an HTTPS page',
      message: 'This page uses HTTP. CT Guard verifies Certificate Transparency for HTTPS connections only.'
    },
    'no-data': {
      icon: '\u{1F50D}',
      title: 'No certificate data yet',
      message: 'No data is available for this page. Try reloading the page and opening CT Guard again.'
    },
    'error': {
      icon: '\u26A0',
      title: 'Something went wrong',
      message: detail || 'An unexpected error occurred while loading certificate data.'
    }
  };

  const s = states[type] || states['error'];

  const contentDiv = document.getElementById('data');
  contentDiv.innerHTML = `
    <div class="status-page">
      <div class="status-icon">${s.icon}</div>
      <div class="status-title">${escapeHtml(s.title)}</div>
      <div class="status-message">${escapeHtml(s.message)}</div>
    </div>`;
  contentDiv.classList.remove('hidden');
}

function getLogStateText(logState) {
  if (logState.readonly) return 'readonly';
  if (logState.usable) return 'usable';
  if (logState.retired) return 'retired';
  return 'unknown';
}

function escapeHtml(str) {
  if (str === null || str === undefined) return 'N/A';
  const div = document.createElement('div');
  div.textContent = str.toString();
  return div.innerHTML;
}
