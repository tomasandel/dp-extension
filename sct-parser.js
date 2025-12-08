/**
 * SCT Parser Module
 *
 * Handles parsing of Signed Certificate Timestamps (SCTs) from DER-encoded certificates.
 * SCTs are embedded in X.509v3 extensions with OID 1.3.6.1.4.1.11129.2.4.2 (RFC 6962).
 */

/**
 * Parses SCTs from a DER-encoded certificate
 *
 * SCTs are embedded in the certificate as an X.509v3 extension with OID 1.3.6.1.4.1.11129.2.4.2
 * The extension contains a TLS-encoded list of SCT structures (RFC 6962)
 *
 * @param {Array<number>} certDER - Raw DER-encoded certificate data
 * @returns {Array} Array of parsed SCTs (empty if none found)
 */
function parseSCTFromCertificate(certDER) {
  const bytes = new Uint8Array(certDER);

  // OID for CT Precertificate SCTs: 1.3.6.1.4.1.11129.2.4.2
  const sctOID = [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02];

  // Search for the SCT OID in the certificate
  for (let i = 0; i < bytes.length - sctOID.length; i++) {
    let match = true;
    for (let j = 0; j < sctOID.length; j++) {
      if (bytes[i + j] !== sctOID[j]) {
        match = false;
        break;
      }
    }

    if (match) {
      console.log("[SCT Parser] Found SCT extension at offset", i);

      let pos = i + sctOID.length;

      // Navigate to the OCTET STRING containing the SCT data
      // Skip to first OCTET STRING tag (0x04)
      while (pos < bytes.length && bytes[pos] !== 0x04) pos++;
      if (pos >= bytes.length) return [];

      // Parse outer OCTET STRING
      pos++;
      let len1 = parseASN1Length(bytes, pos);
      pos = len1.nextPos;

      // Parse inner OCTET STRING (SCTs are double-wrapped)
      if (bytes[pos] === 0x04) {
        pos++;
        let len2 = parseASN1Length(bytes, pos);
        pos = len2.nextPos;

        // Now we're at the TLS-encoded SCT list
        // First 2 bytes = total length of all SCTs
        const listLen = (bytes[pos] << 8) | bytes[pos + 1];
        pos += 2;

        const scts = [];
        const listEnd = pos + listLen;

        // Parse each SCT in the list
        while (pos < listEnd && pos + 2 < bytes.length) {
          const result = parseCompleteSCT(bytes, pos);
          if (result) {
            scts.push(result.sct);
            pos = result.nextPos;
          } else {
            break;
          }
        }
        return scts;
      }

      return [];
    }
  }

  return [];
}

/**
 * Parses ASN.1 length encoding
 * Handles both short form (1 byte) and long form (multi-byte)
 *
 * @param {Uint8Array} bytes - Byte array
 * @param {number} pos - Current position
 * @returns {object} Object with length and nextPos
 */
function parseASN1Length(bytes, pos) {
  let len = bytes[pos++];

  // Long form: first byte has bit 7 set, lower 7 bits indicate how many bytes follow
  if (len & 0x80) {
    const numBytes = len & 0x7f;
    len = 0;
    for (let k = 0; k < numBytes; k++) {
      len = (len << 8) | bytes[pos++];
    }
  }

  return { length: len, nextPos: pos };
}

/**
 * Parses a complete SCT structure from bytes
 *
 * SCT structure (RFC 6962):
 *   uint16 length;                     // 2 bytes - length of this SCT
 *   Version sct_version;               // 1 byte (0 = v1)
 *   LogID id;                          // 32 bytes (SHA-256 of log's public key)
 *   uint64 timestamp;                  // 8 bytes
 *   CtExtensions extensions;           // 2-byte length + variable data
 *   DigitallySigned signature;         // Hash alg (1) + Sig alg (1) + length (2) + signature
 *
 * @param {Uint8Array} bytes - Byte array containing SCT data
 * @param {number} startPos - Starting position in the array
 * @returns {object|null} Object with { sct, nextPos } or null if parsing fails
 */
function parseCompleteSCT(bytes, startPos) {
  let pos = startPos;

  // Read SCT length (2 bytes, big-endian)
  const sctLen = (bytes[pos] << 8) | bytes[pos + 1];
  pos += 2;

  if (pos + sctLen > bytes.length) {
    console.warn("[SCT Parser] SCT length exceeds available bytes");
    return null;
  }

  const sct = {};

  // 1. Version (1 byte) - should be 0 for v1
  sct.version = bytes[pos++];

  // 2. Log ID (32 bytes) - SHA-256 hash of log's public key
  sct.logId = Array.from(bytes.slice(pos, pos + 32))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  pos += 32;

  // 3. Timestamp (8 bytes, big-endian)
  sct.timestamp = 0;
  for (let i = 0; i < 8; i++) {
    sct.timestamp = (sct.timestamp * 256) + bytes[pos++];
  }
  sct.timestampDate = new Date(sct.timestamp).toISOString();

  // 4. Extensions (2-byte length + data)
  const extLen = (bytes[pos] << 8) | bytes[pos + 1];
  pos += 2;

  if (extLen > 0) {
    sct.extensions = Array.from(bytes.slice(pos, pos + extLen));
    sct.extensionsHex = sct.extensions.map(b => b.toString(16).padStart(2, '0')).join('');
  } else {
    sct.extensions = [];
    sct.extensionsHex = '';
  }
  pos += extLen;

  // 5. DigitallySigned signature
  // Hash algorithm (1 byte)
  const hashAlg = bytes[pos++];
  const hashAlgMap = {
    0: 'none', 1: 'md5', 2: 'sha1', 3: 'sha224',
    4: 'sha256', 5: 'sha384', 6: 'sha512'
  };
  sct.signatureHashAlgorithm = hashAlgMap[hashAlg] || `unknown(${hashAlg})`;

  // Signature algorithm (1 byte)
  const sigAlg = bytes[pos++];
  const sigAlgMap = {
    0: 'anonymous', 1: 'rsa', 2: 'dsa', 3: 'ecdsa'
  };
  sct.signatureAlgorithm = sigAlgMap[sigAlg] || `unknown(${sigAlg})`;

  // Signature length (2 bytes)
  const sigLen = (bytes[pos] << 8) | bytes[pos + 1];
  pos += 2;

  // Signature data
  sct.signature = Array.from(bytes.slice(pos, pos + sigLen))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  pos += sigLen;

  // Mark origin as embedded since we parsed from certificate
  sct.origin = 'embedded';

  // Return SCT data and next position separately
  return { sct, nextPos: pos };
}
