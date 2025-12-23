/**
 * CT Verification Module
 *
 * Verifies Proof of Inclusion.
 */

import * as pkijs from 'pkijs';
import * as asn1js from 'asn1js';
import { Convert, BufferSourceConverter } from 'pvtsutils';

/**
 * Verifies all SCTs in a certificate
 * @param {object} certData - Certificate data including SCTs and certificates
 * @returns {Promise<object>} Verification results
 */
async function verifyCertificateSCTs(certData) {
  console.log('[CT Verify] Starting SCT verification');

  console.log('[CT Verify] Extracting precert TBS from leaf cert');
  const modifiedTBS = extractPrecertTBS(certData.certificates[0].rawDER);

  console.log('[CT Verify] Getting issuer key hash from issuer cert');
  const issuerKeyHash = getIssuerKeyHash(certData.certificates[1]);
  
  console.log('[CT Verify] Verifying SCTs -------------------');
  // Verify each SCT
  const results = [];
  for (const sct of certData.scts) {
    const verified = await verifySCT(sct, issuerKeyHash, modifiedTBS);
    results.push({ sct, verified });
  }

  console.log('[CT Verify] Verification results:', results);

  const verifiedCount = results.filter(r => r.verified).length;

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
 * Returns true if computed Merkle root matches the log's root hash
 */
async function verifySCT(sct, issuerKeyHash, modifiedTBS) {
  console.log('[CT Verify] Starting verification for SCT:', sct);
  console.log(`[CT Verify] from log: ${sct.logUrl || sct.logId}`);
  const merkleTreeLeaf = buildMerkleTreeLeaf(sct, issuerKeyHash, modifiedTBS);
  const proofResult = await fetchAuditProof(merkleTreeLeaf, sct);

  if (!proofResult) {
    return false;
  }

  const { proof, leafHash, rootHash, treeSize } = proofResult;

  // Verify the audit proof
  const isValid = await verifyAuditProof(leafHash, proof.leaf_index, proof.audit_path, treeSize, rootHash);

  return isValid;
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
 * Hashes the MerkleTreeLeaf and fetches audit proof from CT log
 * Leaf hash = SHA-256(0x00 || leaf_data)
 */
async function fetchAuditProof(merkleTreeLeaf, sct) {
  console.log('[CT Verify] Fetching audit proof from log');
  
  // Prepend 0x00 byte for leaf hash
  const leafWithPrefix = new Uint8Array(1 + merkleTreeLeaf.length);
  leafWithPrefix[0] = 0x00;
  leafWithPrefix.set(merkleTreeLeaf, 1);

  // Compute SHA-256 hash of the leaf
  const leafHashBuffer = await crypto.subtle.digest('SHA-256', leafWithPrefix);
  const leafHash = new Uint8Array(leafHashBuffer);

  const treeHeadInfo = await getTreeHeadInfo(sct);
  if (!treeHeadInfo) {
    console.log(`[CT Verify] Failed to get tree head info`);
    return null;
  }

  const { treeSize, rootHash } = treeHeadInfo;

  // Convert leaf hash to base64 for URL
  const leafHashB64 = btoa(String.fromCharCode(...leafHash));

  // Fetch audit proof from log
  const url = `${sct.logUrl}ct/v1/get-proof-by-hash?hash=${encodeURIComponent(leafHashB64)}&tree_size=${treeSize}`;
  try {
    const response = await fetch(url);
    if (!response.ok) {
      return null;
    }
    const proof = await response.json();
    return { proof, leafHash, rootHash, treeSize };
  } catch (error) {
    console.log(`[CT Verify] Fetch error: ${error.message}`);
    return null;
  }
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

  // Initialize variables
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = leafHash;

  // Process each node in the audit path
  for (const pathNode of auditPath) {
    if (sn === 0) {
      console.log('[CT Verify] Invalid: sn reached 0 before end of path');
      return false;
    }

    const p = new Uint8Array(Convert.FromBase64(pathNode));

    // Determine hash order based on LSB of fn or fn == sn
    if ((fn & 1) === 1 || fn === sn) {
      // Hash on left: HASH(0x01 || p || r)
      r = await hashNode(p, r);

      // If LSB(fn) is not set, right-shift fn and sn until LSB(fn) is set or fn is 0
      if ((fn & 1) === 0) {
        while ((fn & 1) === 0 && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      // Hash on right: HASH(0x01 || r || p)
      r = await hashNode(r, p);
    }

    fn >>= 1;
    sn >>= 1;
  }

  // Final verification
  if (sn !== 0) {
    console.log('[CT Verify] Invalid: sn not 0 at end');
    return false;
  }

  // Compare computed root with expected root
  const isValid = BufferSourceConverter.isEqual(r, rootHash);
  console.log(`[CT Verify] Proof verification result: ${isValid}`);

  return isValid;
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
 * Gets tree head information from SCT or by fetching STH
 * For readonly logs: uses final_tree_head from log state
 * For active/retired logs: fetches current STH from log
 */
async function getTreeHeadInfo(sct) {
  console.log('[CT Verify] Getting tree head info for SCT:', sct);

  // If log is readonly, use final_tree_head from log state
  if (sct.logState && sct.logState.readonly) {
    const finalTreeHead = sct.logState.readonly.final_tree_head;
    return {
      treeSize: finalTreeHead.tree_size,
      rootHash: new Uint8Array(Convert.FromBase64(finalTreeHead.sha256_root_hash))
    };
  }

  // Otherwise, fetch current STH from log
  const sthUrl = `${sct.logUrl}ct/v1/get-sth`;
  try {
    const response = await fetch(sthUrl);
    if (!response.ok) return null;

    const sth = await response.json();
    return {
      treeSize: sth.tree_size,
      rootHash: new Uint8Array(Convert.FromBase64(sth.sha256_root_hash))
    };
  } catch (error) {
    return null;
  }
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
