/**
 * CT Verification Module
 *
 * Verifies Proof of Inclusion.
 */

import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import { Convert, BufferSourceConverter } from 'pvtsutils';
import { createLogReader } from './ct-log-reader.js';

/**
 * Verifies all SCTs in a certificate (PoI + STH consistency)
 * @param {object} certData - Certificate data including SCTs and certificates
 * @param {string} [backendUrl] - Backend API base URL for STH consistency checks
 * @returns {Promise<object>} Verification results
 */
async function verifyCertificateSCTs(certData, backendUrl) {
  console.log('[CT Verify] Starting SCT verification');

  console.log('[CT Verify] Extracting precert TBS from leaf cert');
  const modifiedTBS = extractPrecertTBS(certData.certificates[0].rawDER);

  console.log('[CT Verify] Getting issuer key hash from issuer cert');
  const issuerKeyHash = getIssuerKeyHash(certData.certificates[1]);

  console.log('[CT Verify] Verifying SCTs -------------------');
  const results = [];
  for (const sct of certData.scts) {
    const reader = createLogReader(sct);
    const poi = await verifySCT(sct, issuerKeyHash, modifiedTBS, reader);

    let poc;
    if (poi.verified && backendUrl) {
      poc = await verifySTHConsistency(sct, poi.sthClient, backendUrl, reader);
    } else if (!poi.verified) {
      const isRetired = sct.logState && sct.logState.retired;
      poc = { status: 'skipped', detail: isRetired ? 'Log retired' : 'PoI failed, consistency check skipped' };
    } else {
      poc = { status: 'skipped', detail: 'No backend URL configured' };
    }

    results.push({ sct, poi, poc });
  }

  console.log('[CT Verify] Verification results:', results);

  // One fully verified SCT is sufficient — if a certificate is verifiably included
  // in at least one honest log whose tree is consistent with the monitor's view,
  // the certificate is publicly auditable and CT's security goal is achieved.
  // Unverifiable SCTs (retired log offline, log temporarily down, no monitor STH)
  // do not fail the verdict — they simply don't contribute to it.
  const verifiedCount = results.filter(r => r.poi.verified && (r.poc.status === 'consistent' || r.poc.status === 'skipped')).length;

  return {
    verified: verifiedCount,
    total: results.length,
    results
  };
}

/**
 * Extracts the TBS portion of a precertificate by removing SCT extension
 * @param {Array<number>} certDER - Raw DER-encoded certificate data
 * @returns {Uint8Array} TBS certificate bytes
 */
function extractPrecertTBS(certDER) {
  const asn1 = asn1js.fromBER(new Uint8Array(certDER).buffer);
  const cert = new pkijs.Certificate({ schema: asn1.result });
  
  // Remove the SCT extension (OID: 1.3.6.1.4.1.11129.2.4.2)
  if (cert.extensions) {
    cert.extensions = cert.extensions.filter(
      ext => ext.extnID !== '1.3.6.1.4.1.11129.2.4.2'
    );
  }

  // Re-encode the TBS certificate
  const tbsSchema = cert.encodeTBS();
  const tbsBytes = tbsSchema.toBER(false);
  
  return new Uint8Array(tbsBytes);
}

function getIssuerKeyHash(issuerCert) {
  return new Uint8Array(Convert.FromBase64(issuerCert.subjectPublicKeyInfoDigest.sha256));
}

/**
 * Verifies a single SCT against its CT log
 * Returns { verified, sthClient } where sthClient contains the STH used for PoI
 */
async function verifySCT(sct, issuerKeyHash, modifiedTBS, reader) {
  console.log('[CT Verify] Starting verification for SCT:', sct);
  console.log(`[CT Verify] from log: ${sct.logUrl || sct.logId}`);

  if (!reader.supported) {
    console.log(`[CT Verify] Log type not yet supported: ${sct.logType}`);
    return { verified: false, reason: 'unsupported_log_type', detail: `Log type '${sct.logType}' not yet supported`, sthClient: null };
  }

  const merkleTreeLeaf = buildMerkleTreeLeaf(sct, issuerKeyHash, modifiedTBS);

  // Compute leaf hash: SHA-256(0x00 || leaf_data)
  const leafWithPrefix = new Uint8Array(1 + merkleTreeLeaf.length);
  leafWithPrefix[0] = 0x00;
  leafWithPrefix.set(merkleTreeLeaf, 1);
  const leafHashBuffer = await crypto.subtle.digest('SHA-256', leafWithPrefix);
  const leafHash = new Uint8Array(leafHashBuffer);

  const treeHead = await reader.getTreeHead();
  if (treeHead?.error) {
    console.log(`[CT Verify] Failed to get tree head: ${treeHead.error}`);
    const isRetired = sct.logState && sct.logState.retired;
    const reason = treeHead.error === 'unreachable' ? 'log_unreachable' : 'log_error';
    const detail = isRetired
      ? 'Log is retired and no longer serves its Merkle tree'
      : `Failed to get tree head from log (${treeHead.detail})`;
    return { verified: false, reason, detail, sthClient: null };
  }
  if (!treeHead) {
    console.log('[CT Verify] Failed to get tree head info');
    return { verified: false, reason: 'log_error', detail: 'Failed to get tree head from log', sthClient: null };
  }

  const { treeSize, rootHash } = treeHead;

  const proof = await reader.getInclusionProof(leafHash, treeSize);
  if (proof?.error) {
    const reason = proof.error === 'not_found' ? 'not_found_in_log'
                 : proof.error === 'unreachable' ? 'log_unreachable'
                 : 'log_error';
    return { verified: false, reason, detail: `Failed to fetch inclusion proof (${proof.detail})`, sthClient: null };
  }
  if (!proof) {
    return { verified: false, reason: 'log_error', detail: 'Failed to fetch inclusion proof from log', sthClient: null };
  }

  // Verify the audit proof
  const isValid = await verifyAuditProof(leafHash, proof.leaf_index, proof.audit_path, treeSize, rootHash);

  return {
    verified: isValid,
    reason: isValid ? 'verified' : 'proof_mismatch',
    detail: isValid
      ? `Audit proof verified (leaf ${proof.leaf_index}, tree size ${treeSize})`
      : 'Audit proof verification failed (root hash mismatch)',
    sthClient: isValid ? { treeSize, rootHash } : null
  };
}

/**
 * Builds a MerkleTreeLeaf for precert_entry type (RFC 6962)
 * Structure: version(1) + leaf_type(1) + timestamp(8) + entry_type(2) +
 *            issuer_key_hash(32) + tbs_length(3) + tbs_certificate + extensions(2)
 */
function buildMerkleTreeLeaf(sct, issuerKeyHash, tbsCertificate) {
  console.log('[CT Verify] Building MerkleTreeLeaf');
  const leaf = [];
  leaf.push(0x00); // version
  leaf.push(0x00); // leaf_type (timestamped_entry)

  const timestampBytes = encodeBigEndian(sct.timestamp, 8);
  leaf.push(...timestampBytes);

  leaf.push(0x00, 0x01); // entry_type (precert_entry)
  leaf.push(...issuerKeyHash); // 32 bytes


  const tbsLengthBytes = encodeBigEndian(tbsCertificate.length, 3);
  leaf.push(...tbsLengthBytes);

  leaf.push(...tbsCertificate);
  leaf.push(0x00, 0x00); // extensions (empty)

  return new Uint8Array(leaf);
}


/**
 * Verifies Merkle audit proof according to RFC 9162 Section 2.1.3.2
 * @param {Uint8Array} leafHash - Hash of the leaf being verified
 * @param {number} leafIndex - Index of the leaf in the tree
 * @param {Array<string>} auditPath - Array of base64-encoded sibling hashes
 * @param {number} treeSize - Size of the Merkle tree
 * @param {Uint8Array} rootHash - Expected root hash to verify against
 * @returns {Promise<boolean>} True if proof is valid
 */
async function verifyAuditProof(leafHash, leafIndex, auditPath, treeSize, rootHash) {
  console.log('[CT Verify] Verifying audit proof');
  console.log(`[CT Verify] Leaf index: ${leafIndex}, Tree size: ${treeSize}, Path length: ${auditPath.length}`);

  // Validate leaf index
  if (leafIndex >= treeSize) {
    console.log('[CT Verify] Invalid: leaf index >= tree size');
    return false;
  }

  // Use BigInt to avoid 32-bit truncation in bitwise operations
  // (leaf indices and tree sizes routinely exceed 2^31)
  let fn = BigInt(leafIndex);
  let sn = BigInt(treeSize) - 1n;
  let r = leafHash;

  // Process each node in the audit path
  for (const pathNode of auditPath) {
    if (sn === 0n) {
      console.log('[CT Verify] Invalid: sn reached 0 before end of path');
      return false;
    }

    const p = new Uint8Array(Convert.FromBase64(pathNode));

    // Determine hash order based on LSB of fn or fn == sn
    if ((fn & 1n) === 1n || fn === sn) {
      // Hash on left: HASH(0x01 || p || r)
      r = await hashNode(p, r);

      // If LSB(fn) is not set, right-shift fn and sn until LSB(fn) is set or fn is 0
      if ((fn & 1n) === 0n) {
        while ((fn & 1n) === 0n && fn !== 0n) {
          fn >>= 1n;
          sn >>= 1n;
        }
      }
    } else {
      // Hash on right: HASH(0x01 || r || p)
      r = await hashNode(r, p);
    }

    fn >>= 1n;
    sn >>= 1n;
  }

  // Final verification
  if (sn !== 0n) {
    console.log('[CT Verify] Invalid: sn not 0 at end');
    return false;
  }

  // Compare computed root with expected root
  const isValid = BufferSourceConverter.isEqual(r, rootHash);
  console.log(`[CT Verify] Proof verification result: ${isValid}`);

  return isValid;
}

/**
 * Verifies a Merkle consistency proof per RFC 9162 Section 2.1.4.2.
 * Proves that the tree of size `first` is a prefix of the tree of size `second`.
 *
 * @param {number} first - Size of the smaller tree
 * @param {number} second - Size of the larger tree
 * @param {Uint8Array} firstHash - Root hash of the smaller tree
 * @param {Uint8Array} secondHash - Root hash of the larger tree
 * @param {Array<Uint8Array>} consistencyPath - Array of proof node hashes
 * @returns {Promise<boolean>} True if the proof is valid
 */
async function verifyConsistencyProof(first, second, firstHash, secondHash, consistencyPath) {
  console.log(`[CT Verify] Verifying consistency proof: ${first} - ${second}, path length: ${consistencyPath.length}`);

  if (first <= 0 || first >= second) {
    console.log('[CT Verify] Invalid: first must be > 0 and < second');
    return false;
  }

  if (consistencyPath.length === 0) {
    console.log('[CT Verify] Invalid: empty consistency path');
    return false;
  }

  // If first is exact power of 2, prepend firstHash to path
  const path = [...consistencyPath];
  if (isPowerOf2(first)) {
    path.unshift(firstHash);
  }

  // Use BigInt to avoid 32-bit truncation in bitwise operations
  let fn = BigInt(first) - 1n;
  let sn = BigInt(second) - 1n;

  // Right-shift both while LSB(fn) is set
  while ((fn & 1n) === 1n) {
    fn >>= 1n;
    sn >>= 1n;
  }

  let fr = path[0];
  let sr = path[0];

  for (let i = 1; i < path.length; i++) {
    const c = path[i];

    if (sn === 0n) {
      console.log('[CT Verify] Invalid: sn reached 0 before end of path');
      return false;
    }

    if ((fn & 1n) === 1n || fn === sn) {
      // HASH(0x01 || c || fr) and HASH(0x01 || c || sr)
      fr = await hashNode(c, fr);
      sr = await hashNode(c, sr);

      if ((fn & 1n) === 0n) {
        while ((fn & 1n) === 0n && fn !== 0n) {
          fn >>= 1n;
          sn >>= 1n;
        }
      }
    } else {
      // HASH(0x01 || sr || c)
      sr = await hashNode(sr, c);
    }

    fn >>= 1n;
    sn >>= 1n;
  }

  if (sn !== 0n) {
    console.log('[CT Verify] Invalid: sn not 0 at end');
    return false;
  }

  const frMatch = BufferSourceConverter.isEqual(fr, firstHash);
  const srMatch = BufferSourceConverter.isEqual(sr, secondHash);

  console.log(`[CT Verify] Consistency proof: fr matches firstHash=${frMatch}, sr matches secondHash=${srMatch}`);

  return frMatch && srMatch;
}

/**
 * Hashes two nodes together with 0x01 prefix (RFC 9162)
 * Hash = SHA-256(0x01 || left || right)
 */
async function hashNode(left, right) {
  const combined = new Uint8Array(1 + left.length + right.length);
  combined[0] = 0x01; // Internal node prefix
  combined.set(left, 1);
  combined.set(right, 1 + left.length);

  const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
  return new Uint8Array(hashBuffer);
}


/**
 * Verifies STH consistency between client-fetched STH and monitor-collected STH.
 *
 * For active (usable) logs: fetches a Merkle consistency proof when tree sizes
 * differ, verifying that the smaller tree is a prefix of the larger.
 *
 * For readonly logs: performs an exact STH comparison instead. A readonly log has
 * a frozen tree, so any difference in tree size or root hash between client and
 * monitor is an unambiguous indicator of a split-world attack. This is strictly
 * stronger than a consistency proof — it detects the append-only variant where
 * an attacker extends the frozen tree with a fraudulent certificate, which would
 * pass a standard consistency check (the original tree is a valid prefix of the
 * extended tree) but fails the exact comparison (tree sizes differ).
 *
 * @param {object} sct - SCT object with logId (hex), logUrl, logState
 * @param {object} sthClient - { treeSize: number, rootHash: Uint8Array }
 * @param {string} backendUrl - Backend API base URL
 * @param {object} reader - CT log reader instance
 * @returns {Promise<object>} Consistency result with status, detail, sthClient, sthMonitor
 */
async function verifySTHConsistency(sct, sthClient, backendUrl, reader) {
  console.log(`[CT Verify] STH consistency check for log: ${sct.logDescription || sct.logId}`);

  //Fetch monitor STH from backend
  const logIdBase64 = Convert.ToBase64(Convert.FromHex(sct.logId));
  const sthMonitorUrl = `${backendUrl}/api/sth/${encodeURIComponent(logIdBase64)}`;

  let sthMonitor;
  try {
    console.log(`[CT Verify] Fetching monitor STH from: ${sthMonitorUrl}`);
    const response = await fetch(sthMonitorUrl);

    //Backend has no STH for this log
    if (response.status === 404) {
      console.log('[CT Verify] No monitor STH found (404) - fail-closed');
      return {
        status: 'no_monitor_sth',
        detail: 'Backend has no STH for this log (fail-closed)',
        sthClient: { treeSize: sthClient.treeSize },
        sthMonitor: null
      };
    }

    if (!response.ok) {
      console.log(`[CT Verify] Backend error: ${response.status}`);
      return {
        status: 'error',
        detail: `Backend returned HTTP ${response.status}`,
        sthClient: { treeSize: sthClient.treeSize },
        sthMonitor: null
      };
    }

    const data = await response.json();
    sthMonitor = {
      treeSize: data.tree_size,
      rootHash: new Uint8Array(Convert.FromBase64(data.root_hash))
    };
    console.log(`[CT Verify] Monitor STH: tree_size=${sthMonitor.treeSize}`);
  } catch (error) {
    console.log(`[CT Verify] Backend fetch error: ${error.message}`);
    return {
      status: 'error',
      detail: `Failed to fetch monitor STH: ${error.message}`,
      sthClient: { treeSize: sthClient.treeSize },
      sthMonitor: null
    };
  }

  //Compare STH_client vs STH_monitor
  const clientSize = sthClient.treeSize;
  const monitorSize = sthMonitor.treeSize;

  console.log(`[CT Verify] Comparing: client tree_size=${clientSize}, monitor tree_size=${monitorSize}`);

  //Same tree_size - compare root hashes directly
  if (clientSize === monitorSize) {
    const hashesMatch = BufferSourceConverter.isEqual(sthClient.rootHash, sthMonitor.rootHash);
    if (hashesMatch) {
      console.log('[CT Verify] Same tree_size, hashes match - consistent');
      return {
        status: 'consistent',
        detail: `Same tree size (${clientSize}), root hashes match`,
        sthClient: { treeSize: clientSize },
        sthMonitor: { treeSize: monitorSize }
      };
    } else {
      console.log('[CT Verify] Same tree_size, hashes MISMATCH');
      return {
        status: 'inconsistent',
        detail: `Same tree size (${clientSize}) but root hashes differ`,
        sthClient: { treeSize: clientSize },
        sthMonitor: { treeSize: monitorSize }
      };
    }
  }

  //Different tree_size — readonly logs should never differ (frozen tree)
  if (sct.logState && sct.logState.readonly) {
    console.log(`[CT Verify] Readonly log tree size mismatch: client=${clientSize}, monitor=${monitorSize}`);
    return {
      status: 'inconsistent',
      detail: `Readonly log tree size mismatch (client: ${clientSize}, monitor: ${monitorSize}). A frozen tree must not differ between observers.`,
      sthClient: { treeSize: clientSize },
      sthMonitor: { treeSize: monitorSize }
    };
  }

  //Different tree_size - fetch and verify consistency proof
  const first = Math.min(clientSize, monitorSize);
  const second = Math.max(clientSize, monitorSize);
  const firstHash = clientSize < monitorSize ? sthClient.rootHash : sthMonitor.rootHash;
  const secondHash = clientSize < monitorSize ? sthMonitor.rootHash : sthClient.rootHash;

  console.log(`[CT Verify] Different sizes, fetching consistency proof (${first} - ${second})`);

  try {
    const data = await reader.getConsistencyProof(first, second);
    if (!data || data.error) {
      const errDetail = data?.detail || 'unknown error';
      console.log(`[CT Verify] Consistency proof fetch failed: ${errDetail}`);
      return {
        status: 'error',
        detail: `Failed to fetch consistency proof from log (${errDetail})`,
        sthClient: { treeSize: clientSize },
        sthMonitor: { treeSize: monitorSize }
      };
    }

    const consistencyPath = data.consistency.map(
      node => new Uint8Array(Convert.FromBase64(node))
    );

    console.log(`[CT Verify] Got consistency proof with ${consistencyPath.length} nodes`);

    // Step 4c: Verify the consistency proof
    const isConsistent = await verifyConsistencyProof(first, second, firstHash, secondHash, consistencyPath);

    if (isConsistent) {
      console.log('[CT Verify] Consistency proof VALID - consistent');
      return {
        status: 'consistent',
        detail: `Tree sizes differ (${first} - ${second}), consistency proof valid`,
        sthClient: { treeSize: clientSize },
        sthMonitor: { treeSize: monitorSize }
      };
    } else {
      console.log('[CT Verify] Consistency proof INVALID!');
      return {
        status: 'inconsistent',
        detail: `Consistency proof invalid between sizes ${first} and ${second}`,
        sthClient: { treeSize: clientSize },
        sthMonitor: { treeSize: monitorSize }
      };
    }
  } catch (error) {
    console.log(`[CT Verify] Consistency proof error: ${error.message}`);
    return {
      status: 'error',
      detail: `Failed to verify consistency: ${error.message}`,
      sthClient: { treeSize: clientSize },
      sthMonitor: { treeSize: monitorSize }
    };
  }
}

/**
 * Checks if a number is an exact power of 2.
 * @param {number} n
 * @returns {boolean}
 */
function isPowerOf2(n) {
  const b = BigInt(n);
  return b > 0n && (b & (b - 1n)) === 0n;
}

/**
 * Encodes a number as big-endian bytes
 * @param {number|bigint} value - Value to encode
 * @param {number} numBytes - Number of bytes to use
 * @returns {Array<number>} Big-endian byte array
 */
function encodeBigEndian(value, numBytes) {
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setBigUint64(0, BigInt(value), false);

  // Return only the last numBytes (big-endian = leading bytes are zeros for small values)
  return new Uint8Array(buffer.slice(8 - numBytes));
}
export default { verifyCertificateSCTs };

// Exported for testing
export {
  verifyAuditProof,
  verifyConsistencyProof,
  verifySTHConsistency,
  verifySCT,
  buildMerkleTreeLeaf,
  extractPrecertTBS,
  hashNode,
  isPowerOf2,
  encodeBigEndian,
};
