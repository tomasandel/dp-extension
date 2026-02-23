/**
 * SCT Inspector - Popup Script
 *
 * Handles the popup UI, requesting certificate data from the background script
 * and displaying it in a user-friendly format. Includes a Statistics tab that
 * fetches aggregate data from the backend API.
 */

const BACKEND_URL = "http://localhost:3000";
const STATS_REFRESH_INTERVAL_MS = 3000;

let statsLoaded = false;
let statsInterval = null;

/**
 * Initialize popup when DOM is loaded
 */
document.addEventListener('DOMContentLoaded', async () => {
  // Tab switching
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
  });

  // Load certificate data for the active tab
  await loadCertificateData();
});

/**
 * Switches between Certificate and Statistics tabs
 */
function switchTab(tabName) {
  // Update tab buttons
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelector(`.tab[data-tab="${tabName}"]`).classList.add('active');

  // Update tab panels
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
  document.getElementById(`tab-${tabName}`).classList.remove('hidden');

  if (tabName === 'statistics') {
    if (!statsLoaded) loadStatistics();
    startStatsRefresh();
  } else {
    stopStatsRefresh();
  }
}

function startStatsRefresh() {
  stopStatsRefresh();
  statsInterval = setInterval(() => loadStatistics(), STATS_REFRESH_INTERVAL_MS);
}

function stopStatsRefresh() {
  if (statsInterval) {
    clearInterval(statsInterval);
    statsInterval = null;
  }
}

/**
 * Loads certificate data from the background script
 */
async function loadCertificateData() {
  try {
    const tabs = await browser.tabs.query({ active: true, currentWindow: true });

    if (!tabs || tabs.length === 0) {
      showError("No active tab found");
      return;
    }

    const currentTab = tabs[0];

    if (!currentTab.url.startsWith('https://')) {
      showError("This page does not use HTTPS. Certificate information is only available for HTTPS sites.");
      return;
    }

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
}

/**
 * Fetches and displays statistics from the backend API
 */
async function loadStatistics() {
  const loadingDiv = document.getElementById('stats-loading');
  const errorDiv = document.getElementById('stats-error');
  const dataDiv = document.getElementById('stats-data');

  // Only show loading spinner on first load
  if (!statsLoaded) {
    loadingDiv.classList.remove('hidden');
    errorDiv.classList.add('hidden');
    dataDiv.classList.add('hidden');
  }

  try {
    const response = await fetch(`${BACKEND_URL}/api/stats`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const spinner = document.getElementById('stats-spinner');
    spinner.classList.remove('hidden');

    const stats = await response.json();
    statsLoaded = true;
    loadingDiv.classList.add('hidden');
    errorDiv.classList.add('hidden');
    displayStatistics(stats);
    setTimeout(() => spinner.classList.add('hidden'), 500);
  } catch (error) {
    setTimeout(() => document.getElementById('stats-spinner').classList.add('hidden'), 500);
    loadingDiv.classList.add('hidden');
    if (!statsLoaded) {
      errorDiv.textContent = `Failed to load statistics: ${error.message}`;
      errorDiv.classList.remove('hidden');
    }
  }
}

/**
 * Renders statistics data into the popup
 */
function displayStatistics(stats) {
  const dataDiv = document.getElementById('stats-data');
  let html = '';

  // Top-level summary cards
  html += `
    <div class="stats-grid">
      <div class="stat-card" title="Total number of Signed Tree Heads collected from all CT logs by all monitors">
        <div class="stat-value">${stats.total_sths.toLocaleString()}</div>
        <div class="stat-label">Total STHs</div>
      </div>
      <div class="stat-card" title="Number of distinct Certificate Transparency logs being monitored">
        <div class="stat-value">${stats.unique_logs}</div>
        <div class="stat-label">CT Logs</div>
      </div>
      <div class="stat-card" title="Number of distinct monitor instances reporting STHs to the backend">
        <div class="stat-value">${stats.unique_monitors}</div>
        <div class="stat-label">Monitors</div>
      </div>
    </div>
  `;

  // Recent activity
  html += `
    <div class="stats-grid-2">
      <div class="stat-card-small" title="STHs ingested in the last 1 hour">
        <div class="stat-value">${stats.recent_activity.last_1h}</div>
        <div class="stat-label">Last 1h</div>
      </div>
      <div class="stat-card-small" title="STHs ingested in the last 24 hours">
        <div class="stat-value">${stats.recent_activity.last_24h}</div>
        <div class="stat-label">Last 24h</div>
      </div>
      <div class="stat-card-small" title="STHs ingested in the last 7 days">
        <div class="stat-value">${stats.recent_activity.last_7d}</div>
        <div class="stat-label">Last 7d</div>
      </div>
    </div>
  `;

  // Ingestion rates
  html += `
    <div class="info-section">
      <h2 title="Average rate of STH ingestion over the entire data collection period">Ingestion Rates</h2>
      <div class="content">
        <div class="info-row" title="Average number of STHs received per hour since data collection started">
          <span class="label">Per hour (avg):</span>
          <span class="value">${stats.ingestion_rates.per_hour}</span>
        </div>
        <div class="info-row" title="Average number of STHs received per day since data collection started">
          <span class="label">Per day (avg):</span>
          <span class="value">${stats.ingestion_rates.per_day}</span>
        </div>
        <div class="info-row" title="Total time between the oldest and newest stored STH">
          <span class="label">Data span:</span>
          <span class="value">${stats.data_range.span_hours}h</span>
        </div>
      </div>
    </div>
  `;

  // Hourly histogram
  if (stats.hourly_histogram && stats.hourly_histogram.length > 0) {
    const maxCount = Math.max(...stats.hourly_histogram.map(b => b.count), 1);
    const bars = stats.hourly_histogram.map(b => {
      const pct = (b.count / maxCount) * 100;
      return `<div class="histogram-bar" style="height: ${Math.max(pct, 3)}%" title="${b.hour}: ${b.count} STHs"></div>`;
    }).join('');

    html += `
      <div class="info-section">
        <h2 title="Number of STHs received per hour over the last 24 hours. Hover each bar for details.">Activity (Last 24h)</h2>
        <div class="content">
          <div class="histogram">${bars}</div>
          <div class="histogram-labels">
            <span>-24h</span>
            <span>-12h</span>
            <span>now</span>
          </div>
        </div>
      </div>
    `;
  }

  // 5-minute histogram
  if (stats.five_min_histogram && stats.five_min_histogram.length > 0) {
    const maxCount5 = Math.max(...stats.five_min_histogram.map(b => b.count), 1);
    const bars5 = stats.five_min_histogram.map(b => {
      const pct = (b.count / maxCount5) * 100;
      return `<div class="histogram-bar" style="height: ${Math.max(pct, 3)}%" title="${b.time}: ${b.count} STHs"></div>`;
    }).join('');

    html += `
      <div class="info-section">
        <h2 title="Number of STHs received per 5-minute window over the last hour. Hover each bar for details.">Activity (Last 1h)</h2>
        <div class="content">
          <div class="histogram">${bars5}</div>
          <div class="histogram-labels">
            <span>-60m</span>
            <span>-30m</span>
            <span>now</span>
          </div>
        </div>
      </div>
    `;
  }

  // Per-log breakdown
  if (stats.logs && stats.logs.length > 0) {
    html += `
      <div class="info-section">
        <h2 title="Summary table of all monitored CT logs">CT Logs (${stats.logs.length})</h2>
        <div class="content">
          <table class="log-table">
            <thead>
              <tr>
                <th title="Base64-encoded CT log identifier">Log ID</th>
                <th title="Total number of STHs collected for this log">STHs</th>
                <th title="Current Merkle tree size (number of certificates in the log)">Tree Size</th>
                <th title="Difference between the smallest and largest tree size observed">Growth</th>
                <th title="Time since the last STH was received for this log">Stale</th>
              </tr>
            </thead>
            <tbody>
    `;

    for (const log of stats.logs) {
      const logShort = log.log_id.length > 16 ? log.log_id.substring(0, 16) + '...' : log.log_id;
      const staleness = formatStaleness(log.staleness_seconds);
      const treeSize = log.latest_tree_size != null ? log.latest_tree_size.toLocaleString() : '-';
      const growth = log.tree_growth_total != null ? log.tree_growth_total.toLocaleString() : '-';

      html += `
        <tr title="${escapeHtml(log.log_id)}">
          <td>${escapeHtml(logShort)}</td>
          <td>${log.sth_count}</td>
          <td>${treeSize}</td>
          <td>+${growth}</td>
          <td>${staleness}</td>
        </tr>
      `;
    }

    html += `
            </tbody>
          </table>
        </div>
      </div>
    `;

    // Per-log detail cards with ingestion lag and monitor breakdown
    for (const log of stats.logs) {
      const logShort = log.log_id.length > 20 ? log.log_id.substring(0, 20) + '...' : log.log_id;

      html += `
        <div class="info-section">
          <h2 title="${escapeHtml(log.log_id)}">${escapeHtml(logShort)}</h2>
          <div class="content">
            <div class="info-row" title="Total number of Signed Tree Heads stored for this log">
              <span class="label">STHs total:</span>
              <span class="value">${log.sth_count}</span>
            </div>
            <div class="info-row" title="STHs received for this log in the last 24 hours">
              <span class="label">STHs (24h):</span>
              <span class="value">${log.sths_last_24h}</span>
            </div>
            <div class="info-row" title="Current Merkle tree size from the most recent STH">
              <span class="label">Tree size:</span>
              <span class="value">${log.latest_tree_size != null ? log.latest_tree_size.toLocaleString() : '-'}</span>
            </div>
            <div class="info-row" title="Total tree size increase (max - min) across all stored STHs">
              <span class="label">Tree growth:</span>
              <span class="value">+${(log.tree_growth_total || 0).toLocaleString()}</span>
            </div>
            <div class="info-row" title="Average delay between the STH timestamp and when the backend received it (over last 50 STHs)">
              <span class="label">Avg lag:</span>
              <span class="value">${log.avg_ingestion_lag_ms != null ? (log.avg_ingestion_lag_ms / 1000).toFixed(1) + 's' : '-'}</span>
            </div>
            <div class="info-row" title="Timestamp of the earliest STH stored for this log">
              <span class="label">First seen:</span>
              <span class="value">${log.first_seen ? new Date(log.first_seen).toLocaleString() : '-'}</span>
            </div>
            <div class="info-row" title="Timestamp of the most recent STH stored for this log">
              <span class="label">Last seen:</span>
              <span class="value">${log.last_seen ? new Date(log.last_seen).toLocaleString() : '-'}</span>
            </div>
            <div class="info-row" title="Number of distinct monitors that have reported STHs for this log">
              <span class="label">Monitors:</span>
              <span class="value">${log.monitor_count}</span>
            </div>
          </div>
        </div>
      `;
    }
  }

  // Monitors
  if (stats.monitors && stats.monitors.length > 0) {
    html += `
      <div class="info-section">
        <h2 title="Active monitor instances reporting STHs to the backend">Monitors (${stats.monitors.length})</h2>
        <div class="content">
    `;

    for (const monitor of stats.monitors) {
      const staleness = formatStaleness(monitor.staleness_seconds);
      html += `
        <div class="monitor-item" title="Monitor '${escapeHtml(monitor.monitor_id)}': ${monitor.sth_count} STHs collected, last active ${staleness} ago">
          <span class="monitor-name">${escapeHtml(monitor.monitor_id)}</span>
          <span class="monitor-meta">${monitor.sth_count} STHs &middot; ${staleness}</span>
        </div>
      `;
    }

    html += `
        </div>
      </div>
    `;
  }

  // Cross-monitor consistency
  if (stats.consistency && stats.consistency.length > 0) {
    html += `
      <div class="info-section">
        <h2 title="Checks whether all monitors see the same root hash for the same tree size. A conflict may indicate a split-world attack.">Cross-Monitor Consistency</h2>
        <div class="content">
    `;

    for (const entry of stats.consistency) {
      const logShort = entry.log_id.length > 24 ? entry.log_id.substring(0, 24) + '...' : entry.log_id;
      const statusClass = entry.consistent ? 'consistency-ok' : 'consistency-conflict';
      const statusText = entry.consistent ? 'Consistent' : 'CONFLICT';
      const consistencyTip = entry.consistent
        ? 'All monitors agree on the same root hash for this log'
        : 'ALERT: Monitors report different root hashes for the same tree size \u2014 possible split-world attack';

      html += `
        <div class="info-row" title="${consistencyTip}">
          <span class="label" title="${escapeHtml(entry.log_id)}">${escapeHtml(logShort)}</span>
          <span class="value ${statusClass}">${statusText} (${entry.monitor_count} monitors)</span>
        </div>
      `;
    }

    html += `
        </div>
      </div>
    `;
  }

  // Data range
  html += `
    <div class="info-section">
      <h2 title="Time range of all stored STH data">Data Range</h2>
      <div class="content">
        <div class="info-row" title="Timestamp of the oldest STH stored in the database">
          <span class="label">Oldest:</span>
          <span class="value">${stats.data_range.oldest_stored_at ? new Date(stats.data_range.oldest_stored_at).toLocaleString() : '-'}</span>
        </div>
        <div class="info-row" title="Timestamp of the most recent STH stored in the database">
          <span class="label">Newest:</span>
          <span class="value">${stats.data_range.newest_stored_at ? new Date(stats.data_range.newest_stored_at).toLocaleString() : '-'}</span>
        </div>
        <div class="info-row" title="Total hours between the oldest and newest stored STH">
          <span class="label">Span:</span>
          <span class="value">${stats.data_range.span_hours}h</span>
        </div>
      </div>
    </div>
  `;

  dataDiv.innerHTML = html;
  dataDiv.classList.remove('hidden');
}

/**
 * Formats staleness seconds into a human-readable string
 */
function formatStaleness(seconds) {
  if (seconds == null) return '-';
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

// ============================================================
// Certificate tab (original functionality)
// ============================================================

/**
 * Displays certificate data in the popup UI
 */
function displayCertificateData(data) {
  const contentDiv = document.getElementById('data');
  const loadingDiv = document.getElementById('loading');

  loadingDiv.classList.add('hidden');

  let html = '';

  // URL display
  html += `<div class="url-display">${escapeHtml(data.url)}</div>`;

  // Security information section
  html += `
    <div class="info-section">
      <h2>Security Information</h2>
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

  // SCT Verification section
  if (data.sctVerification) {
    const { total, verified, failed, verificationTimeMs } = data.sctVerification;

    html += `
      <div class="info-section">
        <h2>SCT Verification Results</h2>
        <div class="content">
          <div class="info-row">
            <span class="label">Total SCTs:</span>
            <span class="value">${total}</span>
          </div>
          <div class="info-row">
            <span class="label">Verified:</span>
            <span class="value" style="color: green; font-weight: bold;">${verified}</span>
          </div>
          ${failed > 0 ? `
          <div class="info-row">
            <span class="label">Failed:</span>
            <span class="value" style="color: red; font-weight: bold;">${failed}</span>
          </div>
          ` : ''}
          <div class="info-row">
            <span class="label">Verification Time:</span>
            <span class="value">${verificationTimeMs}ms</span>
          </div>
        </div>
      </div>
    `;
  }

  // SCT section
  html += `
    <div class="info-section">
      <h2>Signed Certificate Timestamps (${data.scts.length})</h2>
      <div class="content">
  `;

  if (data.scts.length > 0) {
    data.scts.forEach((sct, index) => {
      const verificationResult = data.sctVerification?.results?.find(r => r.sct === sct);
      const verifiedStatus = verificationResult?.verified ? ' [VERIFIED]' : verificationResult?.verified === false ? ' [FAILED]' : '';

      html += `
        <div class="sct-item" id="sct-${index}">
          <h3>SCT #${index + 1}${verifiedStatus}</h3>
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
            <span class="value">${getLogStateText(sct.logState)}</span>
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
    html += `<div class="no-data">No SCTs found for this certificate</div>`;
  }

  html += `
      </div>
    </div>
  `;

  // Certificate chain section
  if (data.certificates && data.certificates.length > 0) {
    html += `
      <div class="info-section">
        <h2>Certificate Chain (${data.certificates.length})</h2>
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

  contentDiv.innerHTML = html;
  contentDiv.classList.remove('hidden');
}

/**
 * Displays an error message in the popup
 */
function showError(message) {
  const loadingDiv = document.getElementById('loading');
  const errorDiv = document.getElementById('error');

  loadingDiv.classList.add('hidden');
  errorDiv.textContent = message;
  errorDiv.classList.remove('hidden');
}

/**
 * Extracts readable log state text from log state object
 */
function getLogStateText(logState) {
  if (logState.readonly) return 'readonly';
  if (logState.usable) return 'usable';
  if (logState.retired) return 'retired';
  return 'unknown';
}

/**
 * Escapes HTML to prevent XSS attacks
 */
function escapeHtml(str) {
  if (str === null || str === undefined) {
    return 'N/A';
  }

  const div = document.createElement('div');
  div.textContent = str.toString();
  return div.innerHTML;
}
