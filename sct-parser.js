/**
 * SCT Parser Module
 *
 * Parses Signed Certificate Timestamps (SCTs) from DER-encoded certificates.
 */

import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import { Convert } from 'pvtsutils';

/**
 * Parses SCTs from a DER-encoded certificate 
 *
 * @param {Array<number>} certDER - Raw DER-encoded certificate data
 * @returns {Array} Array of parsed SCTs (empty if none found)
 */
function parseSCTFromCertificate(certDER) {
  console.log("[SCT Parser] Parsing SCTs from certificate DER data");

  try {
    // Convert to expected binary format for PKI.js
    const certBuffer = new Uint8Array(certDER).buffer;
    
    // Parse certificate
    const asn1 = asn1js.fromBER(certBuffer);
    const cert = new pkijs.Certificate({ schema: asn1.result });

    console.log("[SCT Parser] Parsed certificate:", cert);

    // Get the embedded SignedCertificateTimestampList extension (OID: 1.3.6.1.4.1.11129.2.4.2)
    const sctExt = cert.extensions?.find(ext => ext.extnID === '1.3.6.1.4.1.11129.2.4.2');

    if (!sctExt) {
      console.log("[SCT Parser] No SCT extension found in certificate");
      return [];
    }

    // Parse the OCTET STRING wrapper defined by RFC 6962
    const extAsn1 = asn1js.fromBER(sctExt.extnValue.valueBlock?.valueHexView);
    if (extAsn1.offset === -1) {
      console.error("[SCT Parser] Failed to parse extension value");
      return [];
    }

    // Finally parse the TLS-encoded SCT list
    const sctList = new pkijs.SignedCertificateTimestampList({ schema: extAsn1.result });

    // Transform to expected format
    const scts = sctList.timestamps.map(sct => {
      return {
        version: sct.version,
        logId: Convert.ToHex(sct.logID),
        timestamp: Number(sct.timestamp),
        timestampDate: new Date(Number(sct.timestamp)).toISOString(),
        extensions: Array.from(sct.extensions || []),
        extensionsHex: Convert.ToHex(sct.extensions),
        signatureHashAlgorithm: sct.hashAlgorithm,
        signatureAlgorithm: sct.signatureAlgorithm,
        signature: Convert.ToHex(sct.signature),
        origin: 'embedded'
      };
    });

    console.log("[SCT Parser] Parsed", scts.length, "SCTs");
    return scts;

  } catch (error) {
    console.error("[SCT Parser] Error parsing certificate:", error);
    return [];
  }
}

export default { parseSCTFromCertificate };
