/**
 * CT Guard - Background Script
 *
 * This background script monitors web requests and extracts SCT (Signed Certificate Timestamp)
 * information from TLS certificates. It then verifies the SCTs against known CT logs and makes
 * the results available to the popup UI.
 * 
 **/

import { Convert } from 'pvtsutils';

/**
 * Storage for certificate information indexed by tab ID
 * Structure: { tabId: { url: string, scts: Array, certificateChain: Array, timestamp: number } }
 */
const certificateCache = new Map();

/**
 * Fallback cache indexed by hostname for Service Worker requests (tabId = -1)
 */
const hostCertCache = new Map();

/**
 * Tracks hostnames that have already shown a failure toast this session,
 * so we don't spam the user with repeated notifications on every navigation.
 */
const notifiedHosts = new Set();

/**
 * CT log list cache
 */
let ctLogList = null;
let ctLogListPromise = null;
// Demo: merged list (Google's logs + attack simulation logs) served by the CT log server.
// Production: 'https://www.gstatic.com/ct/log_list/v3/log_list.json'
const CT_LOG_LIST_URL = 'https://logs.jvgc-a.com/log-list.json';

/**
 * Backend API URL for STH consistency verification
 */
const BACKEND_URL = 'https://api.jvgc-a.com';

/**
 * Listener for web requests - captures security information including certificates and SCTs
 *
 * This listener fires AFTER the server response headers are received (after TLS handshake completes),
 * allowing us to inspect the established secure connection and extract certificate transparency information.
 *
 * @param {object} details - Request details from webRequest API
 */
browser.webRequest.onHeadersReceived.addListener(
  async (details) => {
    // Only process main frame requests (page loads, not subresources)
    if (details.type !== "main_frame") {
      return;
    }

    const tabId = details.tabId;
    const hasTab = tabId >= 0;
    const hostname = new URL(details.url).hostname;

    console.log(`[CT Guard] onHeadersReceived for main_frame request: ${details.url} (tabId: ${tabId})`);

    // Only process HTTPS requests
    if (!details.url.startsWith("https://")) {
      console.log(`[CT Guard] Skipping non-HTTPS URL: ${details.url}`);
      return;
    }

    try {
      const verifyStartTime = performance.now();
      console.log(`[CT Guard] Processing request for: ${details.url}`);

      // Get security information for this request
      const securityInfo = await browser.webRequest.getSecurityInfo(
        details.requestId,
        {
          // Request certificate chain information
          certificateChain: true,
          // Request raw DER-encoded certificates to parse SCTs
          rawDER: true
        }
      );

      if (!securityInfo) {
        console.warn(`[CT Guard] No security info available for ${details.url}`);
        return;
      }

      console.log(`[CT Guard] Retrieved security info`, securityInfo);

      // Extract and process certificate information
      const certData = extractCertificateData(securityInfo, details.url);

      // Store in cache — by tab ID when available, always by hostname as fallback
      certData.verificationStatus = 'verifying';
      hostCertCache.set(hostname, certData);
      if (hasTab) {
        certificateCache.set(tabId, certData);
        updateBadge(tabId, 'verifying');
      }

      console.log(`[CT Guard] Extracted certificate data`, certData);

      const verificationResult = await ctVerify.verifyCertificateSCTs(certData, BACKEND_URL);

      const verifyEndTime = performance.now();
      const verificationTimeMs = Math.round(verifyEndTime - verifyStartTime);

      console.log(`[CT Guard] Verification: ${verificationResult.verified}/${verificationResult.total} SCTs verified in ${verificationTimeMs}ms`);

      certData.sctVerification = {
        ...verificationResult,
        verificationTimeMs
      };
      certData.verificationStatus = 'complete';

      const anyVerified = verificationResult.verified >= 1;
      if (hasTab) {
        updateBadge(tabId, anyVerified ? 'ok' : 'fail');

        if (!anyVerified && !notifiedHosts.has(hostname)) {
          notifiedHosts.add(hostname);
          notifyVerificationFailure(tabId, details.url, verificationResult);
        }
      }

    } catch (error) {
      console.error(`[CT Guard] Error processing request:`, error);

      if (hasTab) {
        updateBadge(tabId, 'fail');

        // Mark verification as complete with error so popup doesn't poll forever
        const certData = certificateCache.get(tabId);
        if (certData) {
          certData.verificationStatus = 'error';
        }

        if (!notifiedHosts.has(hostname)) {
          notifiedHosts.add(hostname);
          notifyVerificationFailure(tabId, details.url, null);
        }
      }
    }
  },
  { urls: ["<all_urls>"] },
  // blocking mode to access security info
  ["blocking"]
);

/**
 * Updates the extension icon badge for a given tab
 */
function updateBadge(tabId, status) {
  const config = {
    verifying: { text: '...', color: '#6366f1' },
    ok:        { text: '\u2713',  color: '#16a34a' },
    fail:      { text: '!',  color: '#dc2626' },
  };
  const { text, color } = config[status] || config.verifying;

  browser.browserAction.setBadgeText({ text, tabId });
  browser.browserAction.setBadgeBackgroundColor({ color, tabId });
}

/**
 * Injects an in-page warning banner into the tab when SCT verification fails.
 *
 * @param {number} tabId - The tab to inject into
 * @param {string} url - The URL that failed verification
 * @param {object|null} result - Verification result with verified/total counts, or null on error
 */
function notifyVerificationFailure(tabId, url, result) {
  const code = `
    (function() {
      if (document.getElementById('ct-guard-toast')) return;

      var toast = document.createElement('div');
      toast.id = 'ct-guard-toast';
      toast.style.cssText = 'position:fixed;top:16px;right:16px;z-index:2147483647;width:340px;background:#1e1e2e;color:#e0e0e0;font:13px/1.5 -apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,sans-serif;border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,0.4);border-left:4px solid #dc2626;overflow:hidden;transform:translateX(calc(100% + 16px));transition:transform .35s cubic-bezier(.21,1.02,.73,1);';

      var body = document.createElement('div');
      body.style.cssText = 'padding:12px 14px;display:flex;align-items:flex-start;gap:10px;';

      var icon = document.createElement('span');
      icon.textContent = '\\u26A0';
      icon.style.cssText = 'font-size:18px;flex-shrink:0;margin-top:1px;';

      var content = document.createElement('div');
      content.style.cssText = 'flex:1;min-width:0;';

      var title = document.createElement('div');
      title.textContent = 'CT Guard detected a problem';
      title.style.cssText = 'font-weight:600;color:#fff;margin-bottom:4px;font-size:13px;';

      var msg = document.createElement('div');
      msg.textContent = 'This connection has a certificate transparency issue. Click the extension icon for details.';
      msg.style.cssText = 'color:#a0a0b0;font-size:12px;line-height:1.4;';

      var btn = document.createElement('button');
      btn.textContent = '\\u2715';
      btn.style.cssText = 'background:none;border:none;color:#666;font-size:16px;cursor:pointer;padding:0;flex-shrink:0;margin-top:-1px;transition:color .15s;';
      btn.onmouseenter = function() { btn.style.color = '#fff'; };
      btn.onmouseleave = function() { btn.style.color = '#666'; };
      btn.onclick = function() {
        toast.style.transform = 'translateX(calc(100% + 16px))';
        setTimeout(function() { toast.remove(); }, 350);
      };

      var progress = document.createElement('div');
      progress.style.cssText = 'height:3px;background:#dc2626;width:100%;transform-origin:left;animation:ctGuardShrink 8s linear forwards;';

      var style = document.createElement('style');
      style.textContent = '@keyframes ctGuardShrink{from{transform:scaleX(1)}to{transform:scaleX(0)}}';

      content.appendChild(title);
      content.appendChild(msg);
      body.appendChild(icon);
      body.appendChild(content);
      body.appendChild(btn);
      toast.appendChild(body);
      toast.appendChild(progress);
      document.documentElement.appendChild(toast);
      document.documentElement.appendChild(style);

      requestAnimationFrame(function() {
        requestAnimationFrame(function() {
          toast.style.transform = 'translateX(0)';
        });
      });

      setTimeout(function() {
        if (toast.parentNode) {
          toast.style.transform = 'translateX(calc(100% + 16px))';
          setTimeout(function() { toast.remove(); style.remove(); }, 350);
        }
      }, 8000);
    })();
  `;

  injectWhenReady(tabId, code);
}

/**
 * Waits for the tab to finish loading, then injects the script.
 * If the tab is already complete, injects immediately.
 */
function injectWhenReady(tabId, code) {
  browser.tabs.get(tabId).then(tab => {
    if (tab.status === 'complete') {
      browser.tabs.executeScript(tabId, { code }).catch(err => {
        console.error('[CT Guard] Failed to inject banner:', err);
      });
    } else {
      // Tab still loading — wait for it to finish
      function onUpdated(updatedTabId, changeInfo) {
        if (updatedTabId === tabId && changeInfo.status === 'complete') {
          browser.tabs.onUpdated.removeListener(onUpdated);
          browser.tabs.executeScript(tabId, { code }).catch(err => {
            console.error('[CT Guard] Failed to inject banner:', err);
          });
        }
      }
      browser.tabs.onUpdated.addListener(onUpdated);
    }
  }).catch(err => {
    console.error('[CT Guard] Failed to get tab info:', err);
  });
}

/**
 * Extracts and structures certificate data from security info
 *
 * @param {object} securityInfo - Security information from webRequest.getSecurityInfo()
 * @param {string} url - The URL being accessed
 * @returns {object} Structured certificate data including SCTs
 */
function extractCertificateData(securityInfo, url) {
  console.log("[CT Guard] Extracting certificate data");
  const certData = {
    url: url,
    timestamp: Date.now(),
    securityState: securityInfo.state,
    certificates: [],
    scts: [],
    protocolVersion: securityInfo.protocolVersion || "unknown",
    cipherSuite: securityInfo.cipherSuite || "unknown"
  };

  if (securityInfo.certificates && securityInfo.certificates.length > 0) {
    console.log("[CT Guard] Copying certificate chain");
    certData.certificates = securityInfo.certificates;

    // Parse SCTs from the leaf certificate's rawDER data
    if (securityInfo.certificates[0].rawDER) {
      console.log("[CT Guard] Parsing SCTs from leaf certificate");
      const scts = sctParser.parseSCTFromCertificate(securityInfo.certificates[0].rawDER);
      if (scts.length > 0) {
        certData.scts = injectLogInfo(scts);
      }
    }
  }

  // Certificate Transparency status
  if (securityInfo.certificateTransparencyStatus) {
    certData.ctStatus = securityInfo.certificateTransparencyStatus;
  }

  // Additional security flags from Firefox
  certData.securityFlags = {
    hsts: securityInfo.hsts || false,
    hpkp: securityInfo.hpkp || false,
    usedEch: securityInfo.usedEch || false,
    usedOcsp: securityInfo.usedOcsp || false,
    usedDelegatedCredentials: securityInfo.usedDelegatedCredentials || false,
    isExtendedValidation: securityInfo.isExtendedValidation || false
  };

  return certData;
}

/**
 * Message handler for communication with popup
 * Allows the popup to request certificate data for the current tab
 */
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "getCertificateData") {
    const tabId = message.tabId;
    let certData = certificateCache.get(tabId);

    // Fallback: look up by hostname (handles Service Worker requests with tabId -1)
    if (!certData && message.url) {
      try {
        const hostname = new URL(message.url).hostname;
        certData = hostCertCache.get(hostname);
        if (certData) {
          // Promote to tab cache so subsequent lookups are fast
          certificateCache.set(tabId, certData);
        }
      } catch (e) { /* invalid URL, ignore */ }
    }

    if (certData) {
      sendResponse({ success: true, data: certData });
    } else {
      sendResponse({ success: false, error: "No certificate data available for this tab" });
    }
  }

  // Return true to indicate response will be sent asynchronously
  return true;
});


async function fetchCTLogList() {
  console.log('[CT Guard] Fetching CT log list');
  if (ctLogList) {
    console.log('[CT Guard] CT log list already loaded');
    return
  };

  try {
    const response = await fetch(CT_LOG_LIST_URL);
    const data = await response.json();
    console.log('[CT Guard] Fetched CT log list data', data);
    ctLogList = buildLogIdMap(data);
    console.log('[CT Guard] Built CT log ID map', ctLogList);
    console.log(`[CT Guard] Loaded ${Object.keys(ctLogList).length} CT logs`);
  } catch (error) {
    console.error('[CT Guard] Failed to fetch CT log list:', error);
  }
}


/**
 * Builds log ID to metadata map from operator-grouped CT log list
 * @param {object} logListData - CT log list grouped by operators
 * @returns {object} Map of hex log IDs to log metadata
 */
function buildLogIdMap(logListData) {
  console.log('[CT Guard] Building CT log ID map from log list data');
  const map = {};

  for (const operator of logListData.operators) {
    // RFC 6962 logs (traditional JSON API)
    for (const log of (operator.logs || [])) {
      if (log.log_id) {
        const logIdHex = Convert.ToHex(Convert.FromBase64(log.log_id));
        map[logIdHex] = {
          operator: operator.name,
          description: log.description,
          url: log.url,
          logType: 'rfc6962',
          state: log.state
        };
      }
    }

    // Static-ct / Sunlight logs (tile-based API)
    for (const log of (operator.tiled_logs || [])) {
      if (log.log_id) {
        const logIdHex = Convert.ToHex(Convert.FromBase64(log.log_id));
        map[logIdHex] = {
          operator: operator.name,
          description: log.description,
          url: log.submission_url,
          monitoringUrl: log.monitoring_url,
          logType: 'static-ct',
          state: log.state
        };
      }
    }
  }

  return map;
}

function injectLogInfo(scts) {
  return scts.map(sct => {
    const logInfo = ctLogList[sct.logId];
    if (logInfo) {
      return {
        ...sct,
        logOperator: logInfo.operator,
        logDescription: logInfo.description,
        logUrl: logInfo.url,
        logType: logInfo.logType,
        monitoringUrl: logInfo.monitoringUrl,
        logState: logInfo.state
      };
    } else {
      console.warn(`[CT Guard] No log info found for log ID: ${sct.logId}`);
    }
    return sct;
  });
}

/**
 * Re-apply badge when a tab finishes loading (Firefox resets per-tab badge on navigation)
 */
browser.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === 'complete') {
    const certData = certificateCache.get(tabId);
    if (!certData) return;

    if (certData.verificationStatus === 'verifying') {
      updateBadge(tabId, 'verifying');
    } else if (certData.verificationStatus === 'complete' && certData.sctVerification) {
      const anyOk = certData.sctVerification.verified >= 1;
      updateBadge(tabId, anyOk ? 'ok' : 'fail');
    } else if (certData.verificationStatus === 'error') {
      updateBadge(tabId, 'fail');
    }
  }
});

/**
 * Clean up certificate cache when tabs are closed
 */
browser.tabs.onRemoved.addListener((tabId) => {
  certificateCache.delete(tabId);
  console.log(`[CT Guard] Cleaned up cache for closed tab ${tabId}`);
});

// Initialize
(async () => {
  console.log("[CT Guard] Starting background script...");

  await fetchCTLogList();

  console.log("[CT Guard] Background script loaded and ready");
  console.log("[CT Guard] Waiting for onHeadersReceived...");
})();

