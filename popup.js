/**
 * SCT Inspector - Popup Script
 *
 * Handles the popup UI, requesting certificate data from the background script
 * and displaying it in a user-friendly format.
 */

/**
 * Initialize popup when DOM is loaded
 */
document.addEventListener('DOMContentLoaded', async () => {
  try {
    // Get the current active tab
    const tabs = await browser.tabs.query({ active: true, currentWindow: true });

    if (!tabs || tabs.length === 0) {
      showError("No active tab found");
      return;
    }

    const currentTab = tabs[0];

    // Check if the current tab is HTTPS
    if (!currentTab.url.startsWith('https://')) {
      showError("This page does not use HTTPS. Certificate information is only available for HTTPS sites.");
      return;
    }

    // Request certificate data from background script
    const response = await browser.runtime.sendMessage({
      action: "getCertificateData",
      tabId: currentTab.id
    });

    if (response.success && response.data) {
      displayCertificateData(response.data);
    } else {
      showError(response.error || "No certificate data available. Try reloading the page.");
    }

  } catch (error) {
    console.error("[SCT Inspector Popup] Error:", error);
    showError(`Error loading certificate data: ${error.message}`);
  }
});

/**
 * Displays certificate data in the popup UI
 *
 * @param {object} data - Certificate data from background script
 */
function displayCertificateData(data) {
  const contentDiv = document.getElementById('data');
  const loadingDiv = document.getElementById('loading');

  // Hide loading indicator
  loadingDiv.classList.add('hidden');

  // Build the HTML content
  let html = '';

  // URL display
  html += `<div class="url-display">${escapeHtml(data.url)}</div>`;

  // Security information section
  html += `
    <div class="info-section">
      <h2>🔐 Security Information</h2>
      <div class="content">
        <div class="info-row">
          <span class="label">Security State:</span>
          <span class="value">${escapeHtml(data.securityState)}</span>
        </div>
        <div class="info-row">
          <span class="label">Protocol:</span>
          <span class="value">${escapeHtml(data.protocolVersion)}</span>
        </div>
        <div class="info-row">
          <span class="label">Cipher Suite:</span>
          <span class="value">${escapeHtml(data.cipherSuite)}</span>
        </div>
        ${data.ctStatus ? `
        <div class="info-row">
          <span class="label">CT Status:</span>
          <span class="value">${escapeHtml(data.ctStatus)}</span>
        </div>
        ` : ''}
      </div>
    </div>
  `;

  // SCT section
  html += `
    <div class="info-section">
      <h2>📋 Signed Certificate Timestamps (${data.scts.length})</h2>
      <div class="content">
  `;

  if (data.scts.length > 0) {
    data.scts.forEach((sct, index) => {
      html += `
        <div class="sct-item" id="sct-${index}">
          <h3>SCT #${index + 1}</h3>
          ${sct.logOperator ? `
          <div class="info-row">
            <span class="label">Log Operator:</span>
            <span class="value"><strong>${escapeHtml(sct.logOperator)}</strong></span>
          </div>
          ` : ''}
          ${sct.logDescription ? `
          <div class="info-row">
            <span class="label">Log Name:</span>
            <span class="value">${escapeHtml(sct.logDescription)}</span>
          </div>
          ` : ''}
          ${sct.logUrl ? `
          <div class="info-row">
            <span class="label">Log URL:</span>
            <span class="value"><a href="${escapeHtml(sct.logUrl)}" target="_blank">${escapeHtml(sct.logUrl)}</a></span>
          </div>
          ` : ''}
          ${sct.logState ? `
          <div class="info-row">
            <span class="label">Log State:</span>
            <span class="value">${escapeHtml(sct.logState)}</span>
          </div>
          ` : ''}
          <div class="info-row">
            <span class="label">Log ID:</span>
            <span class="value" style="word-break: break-all; font-size: 10px;">${escapeHtml(sct.logId)}</span>
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
          </div>
          ` : ''}
        </div>
      `;
    });
  } else {
    html += `<div class="no-data">⚠ No SCTs found for this certificate</div>`;
  }

  html += `
      </div>
    </div>
  `;

  // Certificate chain section
  if (data.certificates && data.certificates.length > 0) {
    html += `
      <div class="info-section">
        <h2>🔗 Certificate Chain (${data.certificates.length})</h2>
        <div class="content">
    `;

    data.certificates.forEach((cert, index) => {
      const certType = index === 0 ? 'Leaf (Server)' :
                       index === data.certificates.length - 1 ? 'Root CA' :
                       'Intermediate CA';

      html += `
        <div class="cert-item">
          <h3>Certificate ${index} - ${certType}</h3>
          <div class="cert-field">
            <strong>Subject:</strong> ${escapeHtml(cert.subject)}
          </div>
          <div class="cert-field">
            <strong>Issuer:</strong> ${escapeHtml(cert.issuer)}
          </div>
          ${cert.validity.start && cert.validity.end ? `
          <div class="cert-field">
            <strong>Valid From:</strong> ${new Date(cert.validity.start).toLocaleString()}
          </div>
          <div class="cert-field">
            <strong>Valid To:</strong> ${new Date(cert.validity.end).toLocaleString()}
          </div>
          ` : ''}
          <div class="cert-field">
            <strong>Serial:</strong> ${escapeHtml(cert.serialNumber)}
          </div>
          ${cert.fingerprint.sha256 ? `
          <div class="cert-field">
            <strong>SHA-256:</strong> <span style="font-size: 10px;">${escapeHtml(cert.fingerprint.sha256)}</span>
          </div>
          ` : ''}
        </div>
      `;
    });

    html += `
        </div>
      </div>
    `;
  }

  // Display the content
  contentDiv.innerHTML = html;
  contentDiv.classList.remove('hidden');
}

/**
 * Displays an error message in the popup
 *
 * @param {string} message - Error message to display
 */
function showError(message) {
  const loadingDiv = document.getElementById('loading');
  const errorDiv = document.getElementById('error');

  loadingDiv.classList.add('hidden');
  errorDiv.textContent = message;
  errorDiv.classList.remove('hidden');
}

/**
 * Escapes HTML to prevent XSS attacks
 *
 * @param {string} str - String to escape
 * @returns {string} Escaped string safe for HTML insertion
 */
function escapeHtml(str) {
  if (str === null || str === undefined) {
    return 'N/A';
  }

  const div = document.createElement('div');
  div.textContent = str.toString();
  return div.innerHTML;
}

