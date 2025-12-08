/**
 * SCT Certificate Inspector - Background Script
 *
 * This background script monitors web requests and extracts SCT (Signed Certificate Timestamp)
 * information from TLS certificates. SCTs are part of Certificate Transparency (CT) which
 * helps detect mis-issued certificates.
 *
 * Note: sct-parser.js is loaded first (see manifest.json), so its functions are available here.
 */

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
const CT_LOG_LIST_URL = 'https://www.gstatic.com/ct/log_list/v3/log_list.json';

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

    // Only process HTTPS requests
    if (!details.url.startsWith("https://")) {
      console.log(`[SCT Inspector] Skipping non-HTTPS URL: ${details.url}`);
      return;
    }

    try {
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

      console.log(securityInfo.certificates)

      if (!securityInfo) {
        console.warn(`[SCT Inspector] No security info available for ${details.url}`);
        return;
      }

      // Extract and process certificate information
      const certData = await extractCertificateData(securityInfo, details.url);

      // Store in cache indexed by tab ID for popup access
      certificateCache.set(details.tabId, certData);

      console.log(`[SCT Inspector] Extracted certificate data for ${details.url}`);
      console.log(certData);

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
async function extractCertificateData(securityInfo, url) {
  console.log("[SCT Inspector] Extracting certificate data for", url);
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
    certData.certificates = securityInfo.certificates;

    // Parse SCTs from the leaf certificate's rawDER data
    if (securityInfo.certificates[0].rawDER) {
      const scts = parseSCTFromCertificate(securityInfo.certificates[0].rawDER);
      if (scts.length > 0) {
        certData.scts = await injectLogInfo(scts);
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
  if (ctLogListPromise) return ctLogListPromise;

  ctLogListPromise = (async () => {
    try {
      const response = await fetch(CT_LOG_LIST_URL);
      const data = await response.json();
      ctLogList = buildLogIdMap(data);
      console.log(`[SCT Inspector] Loaded ${Object.keys(ctLogList).length} CT logs`);
    } catch (error) {
      console.error('[SCT Inspector] Failed to fetch CT log list:', error);
    }
  })();

  return ctLogListPromise;
}

// Convert listing by operators to a flat map by log ID
function buildLogIdMap(logListData) {
  const map = {};

  for (const operator of logListData.operators) {
    const logs = [...(operator.logs || []), ...(operator.tiled_logs || [])];

    for (const log of logs) {
      if (log.log_id) {
        const logIdHex = base64ToHex(log.log_id);
        map[logIdHex] = {
          operator: operator.name,
          description: log.description,
          url: log.url || log.submission_url,
          state: log.state
        };
      }
    }
  }
  console.log("[SCT Inspector] Built CT log ID map");
  console.log(map);

  return map;
}

function base64ToHex(base64) {
  const binary = atob(base64);
  let hex = '';
  for (let i = 0; i < binary.length; i++) {
    const byte = binary.charCodeAt(i).toString(16).padStart(2, '0');
    hex += byte;
  }
  return hex;
}

async function injectLogInfo(scts) {
  await fetchCTLogList();

  if (!ctLogList) return scts;

  return scts.map(sct => {
    const logInfo = ctLogList[sct.logId];
    if (logInfo) {
      return {
        ...sct,
        logOperator: logInfo.operator,
        logDescription: logInfo.description,
        logUrl: logInfo.url,
        logState: logInfo.state
      };
    } else {
      console.warn(`[SCT Inspector] No log info found for log ID: ${sct.logId}`);
    }
    return sct;
  });
}

/**
 * Clean up certificate cache when tabs are closed to prevent memory leaks
 */
browser.tabs.onRemoved.addListener((tabId) => {
  certificateCache.delete(tabId);
  console.log(`[SCT Inspector] Cleaned up cache for closed tab ${tabId}`);
});

// Fetch CT log list on startup
fetchCTLogList();

console.log("[SCT Inspector] Background script loaded and ready");
