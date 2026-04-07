/**
 * SCT Certificate Inspector - Background Script
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
    
    console.log(`[SCT Inspector] onHeadersReceived for main_frame request: ${details.url}`);

    // Only process HTTPS requests
    if (!details.url.startsWith("https://")) {
      console.log(`[SCT Inspector] Skipping non-HTTPS URL: ${details.url}`);
      return;
    }

    try {
      const verifyStartTime = performance.now();
      console.log(`[SCT Inspector] Processing request for: ${details.url}`);

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
        console.warn(`[SCT Inspector] No security info available for ${details.url}`);
        return;
      }
      
      console.log(`[SCT Inspector] Retrieved security info`, securityInfo);

      // Extract and process certificate information
      const certData = extractCertificateData(securityInfo, details.url);

      // Store in cache indexed by tab ID for popup access
      certificateCache.set(details.tabId, certData);

      console.log(`[SCT Inspector] Extracted certificate data`, certData);

      const verificationResult = await ctVerify.verifyCertificateSCTs(certData, BACKEND_URL);

      const verifyEndTime = performance.now();
      const verificationTimeMs = Math.round(verifyEndTime - verifyStartTime);

      console.log(`[SCT Inspector] Verification: ${verificationResult.verified}/${verificationResult.total} SCTs verified in ${verificationTimeMs}ms`);

      certData.sctVerification = {
        ...verificationResult,
        verificationTimeMs
      };

    } catch (error) {
      console.error(`[SCT Inspector] Error processing request:`, error);
    }
  },
  { urls: ["<all_urls>"] },
  // blocking mode to access security info
  ["blocking"]
);

/**
 * Extracts and structures certificate data from security info
 *
 * @param {object} securityInfo - Security information from webRequest.getSecurityInfo()
 * @param {string} url - The URL being accessed
 * @returns {object} Structured certificate data including SCTs
 */
function extractCertificateData(securityInfo, url) {
  console.log("[SCT Inspector] Extracting certificate data");
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
    console.log("[SCT Inspector] Copying certificate chain");
    certData.certificates = securityInfo.certificates;

    // Parse SCTs from the leaf certificate's rawDER data
    if (securityInfo.certificates[0].rawDER) {
      console.log("[SCT Inspector] Parsing SCTs from leaf certificate");
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
    const certData = certificateCache.get(tabId);

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
  console.log('[SCT Inspector] Fetching CT log list');
  if (ctLogList) {
    console.log('[SCT Inspector] CT log list already loaded');
    return
  };

  try {
    const response = await fetch(CT_LOG_LIST_URL);
    const data = await response.json();
    console.log('[SCT Inspector] Fetched CT log list data', data);
    ctLogList = buildLogIdMap(data);
    console.log('[SCT Inspector] Built CT log ID map', ctLogList);
    console.log(`[SCT Inspector] Loaded ${Object.keys(ctLogList).length} CT logs`);
  } catch (error) {
    console.error('[SCT Inspector] Failed to fetch CT log list:', error);
  }
}


/**
 * Builds log ID to metadata map from operator-grouped CT log list
 * @param {object} logListData - CT log list grouped by operators
 * @returns {object} Map of hex log IDs to log metadata
 */
function buildLogIdMap(logListData) {
  console.log('[SCT Inspector] Building CT log ID map from log list data');
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
      console.warn(`[SCT Inspector] No log info found for log ID: ${sct.logId}`);
    }
    return sct;
  });
}

/**
 * Clean up certificate cache when tabs are closed
 */
browser.tabs.onRemoved.addListener((tabId) => {
  certificateCache.delete(tabId);
  console.log(`[SCT Inspector] Cleaned up cache for closed tab ${tabId}`);
});

// Initialize
(async () => {
  console.log("[SCT Inspector] Starting background script...");

  await fetchCTLogList();

  console.log("[SCT Inspector] Background script loaded and ready");
  console.log("[SCT Inspector] Waiting for onHeadersReceived...");
})();

