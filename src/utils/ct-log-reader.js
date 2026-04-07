/**
 * CT Log Reader Module
 *
 * Provides a normalized interface for reading from CT logs regardless of
 * the underlying protocol (RFC 6962 JSON API vs static-ct tile API).
 *
 * The verification module (ct-verify.js) consumes this interface and does
 * not need to know which protocol a log uses.
 */

import { Convert } from 'pvtsutils';

/**
 * Reader for RFC 6962 CT logs (traditional JSON API).
 * Wraps get-sth, get-proof-by-hash, get-sth-consistency endpoints.
 */
class RFC6962Reader {
  /**
   * @param {string} logUrl - Base URL of the CT log (with trailing slash)
   * @param {object|null} readonlyState - If non-null, the log's readonly state
   *   containing final_tree_head (frozen tree, no STH fetch needed)
   */
  constructor(logUrl, readonlyState) {
    this.logUrl = logUrl;
    this.readonlyState = readonlyState;
  }

  get supported() { return true; }

  /**
   * Gets the current tree head (STH) from the log.
   * For readonly logs, returns the final_tree_head from metadata (no network request).
   * @returns {Promise<{treeSize: number, rootHash: Uint8Array}|null>}
   */
  async getTreeHead() {
    if (this.readonlyState) {
      const fth = this.readonlyState.final_tree_head;
      return {
        treeSize: fth.tree_size,
        rootHash: new Uint8Array(Convert.FromBase64(fth.sha256_root_hash))
      };
    }

    const url = `${this.logUrl}ct/v1/get-sth`;
    try {
      const response = await fetch(url);
      if (!response.ok) return null;
      const sth = await response.json();
      return {
        treeSize: sth.tree_size,
        rootHash: new Uint8Array(Convert.FromBase64(sth.sha256_root_hash))
      };
    } catch (error) {
      console.log(`[CTLogReader] Failed to fetch STH: ${error.message}`);
      return null;
    }
  }

  /**
   * Fetches a Merkle audit proof (proof of inclusion) for a leaf.
   * @param {Uint8Array} leafHash - SHA-256 hash of the leaf
   * @param {number} treeSize - Tree size to get the proof against
   * @returns {Promise<{leaf_index: number, audit_path: string[]}|null>}
   */
  async getInclusionProof(leafHash, treeSize) {
    const leafHashB64 = btoa(String.fromCharCode(...leafHash));
    const url = `${this.logUrl}ct/v1/get-proof-by-hash?hash=${encodeURIComponent(leafHashB64)}&tree_size=${treeSize}`;
    try {
      const response = await fetch(url);
      if (!response.ok) return null;
      return await response.json();
    } catch (error) {
      console.log(`[CTLogReader] Failed to fetch inclusion proof: ${error.message}`);
      return null;
    }
  }

  /**
   * Fetches a consistency proof between two tree sizes.
   * @param {number} first - Smaller tree size
   * @param {number} second - Larger tree size
   * @returns {Promise<{consistency: string[]}|null>}
   */
  async getConsistencyProof(first, second) {
    const url = `${this.logUrl}ct/v1/get-sth-consistency?first=${first}&second=${second}`;
    try {
      const response = await fetch(url);
      if (!response.ok) return null;
      return await response.json();
    } catch (error) {
      console.log(`[CTLogReader] Failed to fetch consistency proof: ${error.message}`);
      return null;
    }
  }
}

/**
 * Reader for static-ct (Sunlight) logs (tile-based API).
 * Currently a stub - returns null for all operations.
 */
class StaticCTReader {
  /**
   * @param {string} monitoringUrl - Tile-based monitoring URL for reads
   */
  constructor(monitoringUrl) {
    this.monitoringUrl = monitoringUrl;
  }

  get supported() { return false; }

  async getTreeHead() { return null; }
  async getInclusionProof() { return null; }
  async getConsistencyProof() { return null; }
}

/**
 * Factory: creates the appropriate reader for an SCT's log type.
 * @param {object} sct - SCT object with logType, logUrl, monitoringUrl, logState
 * @returns {RFC6962Reader|StaticCTReader}
 */
function createLogReader(sct) {
  if (sct.logType === 'static-ct') {
    return new StaticCTReader(sct.monitoringUrl);
  }
  return new RFC6962Reader(sct.logUrl, sct.logState?.readonly || null);
}

export { RFC6962Reader, StaticCTReader, createLogReader };
