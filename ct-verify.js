/**
 * CT Log Verification Module
 *
 * Verifies Certificate Transparency SCTs by:
 * 1. Extracting TBSCertificate from leaf certificate
 * 2. Removing SCT extension to reconstruct the precertificate
 * 3. Building MerkleTreeLeaf structure
 * 4. Fetching audit proofs from CT logs
 * 5. Computing and verifying Merkle tree roots
 */

/**
 * Extracts TBSCertificate from X.509 certificate
 * Certificate structure: SEQUENCE { TBSCertificate, SignatureAlgorithm, Signature }
 */
function extractTBSCertificate(certDER) {
  const bytes = new Uint8Array(certDER);
  let pos = 0;

  if (bytes[pos] !== ASN1_SEQUENCE_TAG) return null;
  pos++;

  const certLenResult = parseASN1Length(bytes, pos);
  pos = certLenResult.nextPos;

  const tbsStart = pos;
  if (bytes[pos] !== ASN1_SEQUENCE_TAG) return null;
  pos++;

  const tbsLenResult = parseASN1Length(bytes, pos);
  const tbsLength = tbsLenResult.length;
  const tbsDataStart = tbsLenResult.nextPos;
  const tbsEnd = tbsDataStart + tbsLength;

  return bytes.slice(tbsStart, tbsEnd);
}

/**
 * Removes SCT extension (OID 1.3.6.1.4.1.11129.2.4.2) from TBSCertificate
 * This reconstructs the precertificate that was originally submitted to CT logs
 */
function removeSCTExtension(tbsCert) {
  const bytes = new Uint8Array(tbsCert);

  if (bytes[0] !== ASN1_SEQUENCE_TAG) return null;

  const { nextPos: tbsContentStart } = parseASN1Length(bytes, 1);

  for (let i = tbsContentStart; i < bytes.length - SCT_OID.length; i++) {
    if (bytes[i] !== ASN1_CONTEXT_3_TAG) continue;
    if (i + 1 >= bytes.length) continue;

    const extLenResult = parseASN1Length(bytes, i + 1);
    const extSeqStart = extLenResult.nextPos;
    const extFieldEnd = extSeqStart + extLenResult.length;

    if (extLenResult.length < 0 || extLenResult.length > MAX_EXTENSION_SIZE ||
        extFieldEnd > bytes.length || bytes[extSeqStart] !== ASN1_SEQUENCE_TAG) {
      continue;
    }

    if (!containsOID(bytes, extSeqStart, extFieldEnd, SCT_OID)) continue;

    const filteredExtensions = filterSCTFromExtensions(bytes.slice(extSeqStart, extFieldEnd));
    if (!filteredExtensions) return null;

    const newExtensionsField = new Uint8Array([
      ASN1_CONTEXT_3_TAG,
      ...encodeASN1Length(filteredExtensions.length),
      ...filteredExtensions
    ]);

    const newTBSContent = new Uint8Array([
      ...bytes.slice(tbsContentStart, i),
      ...newExtensionsField,
      ...bytes.slice(extFieldEnd)
    ]);

    return new Uint8Array([
      ASN1_SEQUENCE_TAG,
      ...encodeASN1Length(newTBSContent.length),
      ...newTBSContent
    ]);
  }

  // No SCT extension found
  return tbsCert;
}

/**
 * Filters out SCT extension from the extensions SEQUENCE
 */
function filterSCTFromExtensions(extensionsBytes) {
  const bytes = extensionsBytes;
  let pos = 0;

  if (bytes[pos] !== ASN1_SEQUENCE_TAG) return null;
  pos++;

  const seqLenResult = parseASN1Length(bytes, pos);
  pos = seqLenResult.nextPos;
  const seqEnd = pos + seqLenResult.length;

  const keptExtensions = [];

  while (pos < seqEnd) {
    const extStart = pos;
    if (bytes[pos] !== ASN1_SEQUENCE_TAG) break;
    pos++;

    const extLenResult = parseASN1Length(bytes, pos);
    const extLen = extLenResult.length;
    const extContentStart = extLenResult.nextPos;
    const extEnd = extContentStart + extLen;

    if (!containsOID(bytes, extContentStart, extEnd, SCT_OID)) {
      keptExtensions.push(bytes.slice(extStart, extEnd));
    }

    pos = extEnd;
  }

  const totalKeptLength = keptExtensions.reduce((sum, ext) => sum + ext.length, 0);
  const keptExtensionsData = new Uint8Array(totalKeptLength);
  let offset = 0;
  for (const ext of keptExtensions) {
    keptExtensionsData.set(ext, offset);
    offset += ext.length;
  }

  const newSeqTag = [ASN1_SEQUENCE_TAG];
  const newSeqLen = encodeASN1Length(keptExtensionsData.length);

  return new Uint8Array([...newSeqTag, ...newSeqLen, ...keptExtensionsData]);
}

/**
 * Extracts issuer key hash from issuer certificate
 * Returns SHA-256 hash of SubjectPublicKeyInfo
 */
function getIssuerKeyHash(issuerCert) {
  return base64ToBytes(issuerCert.subjectPublicKeyInfoDigest.sha256);
}

/**
 * Builds a MerkleTreeLeaf for precert_entry type
 * Structure: version(1) + leaf_type(1) + timestamp(8) + entry_type(2) +
 *            issuer_key_hash(32) + tbs_length(3) + tbs_certificate + extensions(2)
 */
function buildPrecertEntry(sct, issuerKeyHash, tbsCertificate) {
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
 * Gets tree head information from SCT or by fetching STH
 * For readonly logs: uses final_tree_head from log state
 * For active/retired logs: fetches current STH from log
 */
async function getTreeHeadInfo(sct) {
  if (sct.logState && sct.logState.readonly) {
    return {
      treeSize: sct.logState.readonly.final_tree_head.tree_size,
      rootHash: base64ToBytes(sct.logState.readonly.final_tree_head.sha256_root_hash)
    };
  }

  const sthUrl = `${sct.logUrl}ct/v1/get-sth`;

  try {
    const response = await fetch(sthUrl);
    if (!response.ok) return null;

    const sth = await response.json();
    return {
      treeSize: sth.tree_size,
      rootHash: base64ToBytes(sth.sha256_root_hash)
    };
  } catch (error) {
    return null;
  }
}

/**
 * Hashes the MerkleTreeLeaf and fetches audit proof from CT log
 * Leaf hash = SHA-256(0x00 || leaf_data)
 */
async function fetchAuditProof(merkleTreeLeaf, sct) {
  console.log('[CT Verify] === MerkleTreeLeaf Structure Before Hashing ===');
  console.log('[CT Verify] Length:', merkleTreeLeaf.length, 'bytes');
  console.log('[CT Verify] Version:', merkleTreeLeaf[0]);
  console.log('[CT Verify] Leaf type:', merkleTreeLeaf[1]);
  console.log('[CT Verify] Timestamp:', Array.from(merkleTreeLeaf.slice(2, 10)).map(b => b.toString(16).padStart(2, '0')).join(''));
  console.log('[CT Verify] Entry type:', merkleTreeLeaf[10], merkleTreeLeaf[11]);
  console.log('[CT Verify] Issuer key hash:', Array.from(merkleTreeLeaf.slice(12, 44)).map(b => b.toString(16).padStart(2, '0')).join(''));
  const tbsLength = (merkleTreeLeaf[44] << 16) | (merkleTreeLeaf[45] << 8) | merkleTreeLeaf[46];
  console.log('[CT Verify] TBS length:', tbsLength);
  console.log('[CT Verify] Extensions:', merkleTreeLeaf[47 + tbsLength], merkleTreeLeaf[48 + tbsLength]);
  console.log('[CT Verify] Full structure (hex):', Array.from(merkleTreeLeaf).map(b => b.toString(16).padStart(2, '0')).join(''));

  const leafWithPrefix = new Uint8Array(1 + merkleTreeLeaf.length);
  leafWithPrefix[0] = 0x00;
  leafWithPrefix.set(merkleTreeLeaf, 1);

  const leafHashBuffer = await crypto.subtle.digest('SHA-256', leafWithPrefix);
  const leafHash = new Uint8Array(leafHashBuffer);

  const treeHeadInfo = await getTreeHeadInfo(sct);
  if (!treeHeadInfo) {
    console.log(`[CT Verify] Failed to get tree head info`);
    return null;
  }

  const { treeSize, rootHash } = treeHeadInfo;

  const leafHashB64 = btoa(String.fromCharCode(...leafHash));
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
 * Hashes two nodes together: SHA-256(0x01 || left || right)
 */
async function hashNodes(left, right) {
  const combined = new Uint8Array(MERKLE_NODE_SIZE);
  combined[0] = 0x01;
  combined.set(left, 1);
  combined.set(right, 1 + HASH_SIZE);
  const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
  return new Uint8Array(hashBuffer);
}

/**
 * Computes Merkle tree root from leaf hash and audit path
 */
async function computeMerkleRoot(leafHash, leafIndex, auditPath, treeSize) {
  let index = leafIndex;
  let hash = leafHash;

  for (const pathNode of auditPath) {
    const sibling = base64ToBytes(pathNode);

    if (index % 2 === 0) {
      hash = await hashNodes(hash, sibling);
    } else {
      hash = await hashNodes(sibling, hash);
    }

    index = Math.floor(index / 2);
  }

  return hash;
}

/**
 * Verifies a single SCT against its CT log
 * Returns true if computed Merkle root matches the log's root hash
 */
async function verifySCT(sct, issuerKeyHash, modifiedTBS) {
  console.log(`[CT Verify] Starting verification for SCT from log: ${sct.logUrl || sct.logId}`);
  const merkleTreeLeaf = buildPrecertEntry(sct, issuerKeyHash, modifiedTBS);
  const proofResult = await fetchAuditProof(merkleTreeLeaf, sct);

  if (!proofResult) {
    return false;
  }

  const { proof, leafHash, rootHash, treeSize } = proofResult;
  const computedRoot = await computeMerkleRoot(leafHash, proof.leaf_index, proof.audit_path, treeSize);

  return bytesEqual(computedRoot, rootHash);
}

/**
 * Verifies all SCTs in a certificate
 * Returns: { total, verified, failed, results: [{sct, verified}] }
 */
async function verifyCertificateSCTs(certData) {
  if (!certData || !certData.scts || certData.scts.length === 0) {
    return { total: 0, verified: 0, failed: 0, results: [] };
  }

  if (!certData.certificates || certData.certificates.length < 2 ||
      !certData.certificates[0].rawDER || !certData.certificates[1].rawDER) {
    return { total: 0, verified: 0, failed: 0, results: [] };
  }

  const tbsCert = extractTBSCertificate(certData.certificates[0].rawDER);
  if (!tbsCert) {
    return { total: 0, verified: 0, failed: 0, results: [] };
  }

  const modifiedTBS = removeSCTExtension(tbsCert);
  if (!modifiedTBS) {
    return { total: 0, verified: 0, failed: 0, results: [] };
  }

  const issuerKeyHash = getIssuerKeyHash(certData.certificates[1]);

  const results = [];
  for (const sct of certData.scts) {
    const verified = await verifySCT(sct, issuerKeyHash, modifiedTBS);
    results.push({ sct, verified });
  }

  const verified = results.filter(r => r.verified).length;
  const failed = results.length - verified;

  return {
    total: results.length,
    verified,
    failed,
    results
  };
}
