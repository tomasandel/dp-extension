/**
 * Utility functions
 */

// Constants
const ASN1_SEQUENCE_TAG = 0x30;
const ASN1_CONTEXT_3_TAG = 0xa3;
const SCT_OID = [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02];
const MAX_EXTENSION_SIZE = 10000;
const MERKLE_NODE_SIZE = 1 + 32 + 32; // prefix + left_hash + right_hash
const HASH_SIZE = 32;

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
 * Encodes ASN.1 length
 * @param {number} length - Length to encode
 * @returns {Array<number>} Encoded length bytes
 */
function encodeASN1Length(length) {
  if (length < 128) {
    return [length];
  }

  const bytes = [];
  let temp = length;
  while (temp > 0) {
    bytes.unshift(temp & 0xff);
    temp >>= 8;
  }

  return [0x80 | bytes.length, ...bytes];
}

/**
 * Decodes base64 string to Uint8Array
 * @param {string} base64 - Base64 encoded string
 * @returns {Uint8Array} Decoded bytes
 */
function base64ToBytes(base64) {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Converts base64 string to hex string
 * @param {string} base64 - Base64 encoded string
 * @returns {string} Hex string
 */
function base64ToHex(base64) {
  const binary = atob(base64);
  let hex = '';
  for (let i = 0; i < binary.length; i++) {
    const byte = binary.charCodeAt(i).toString(16).padStart(2, '0');
    hex += byte;
  }
  return hex;
}

/**
 * Compares two Uint8Arrays for equality
 * @param {Uint8Array} a - First array
 * @param {Uint8Array} b - Second array
 * @returns {boolean} True if arrays are equal
 */
function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * Converts bytes to hex string
 * @param {Uint8Array} bytes - Bytes to convert
 * @returns {string} Hex string
 */
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Checks if a byte sequence contains a specific OID
 * @param {Uint8Array} bytes - Bytes to search in
 * @param {number} startPos - Start position
 * @param {number} endPos - End position
 * @param {Array<number>} oid - OID bytes to search for
 * @returns {boolean} True if OID is found
 */
function containsOID(bytes, startPos, endPos, oid) {
  for (let i = startPos; i < endPos - oid.length; i++) {
    let match = true;
    for (let j = 0; j < oid.length; j++) {
      if (bytes[i + j] !== oid[j]) {
        match = false;
        break;
      }
    }
    if (match) {
      return true;
    }
  }
  return false;
}

/**
 * Encodes a number as big-endian bytes
 * @param {number|bigint} value - Value to encode
 * @param {number} numBytes - Number of bytes to use
 * @returns {Array<number>} Big-endian byte array
 */
function encodeBigEndian(value, numBytes) {
  const bytes = [];
  const bigValue = BigInt(value);
  for (let i = numBytes - 1; i >= 0; i--) {
    bytes.push(Number((bigValue >> BigInt(i * 8)) & BigInt(0xff)));
  }
  return bytes;
}

// Export for browser extension (non-module)
var utility = {
  parseASN1Length,
  encodeASN1Length,
  base64ToBytes,
  base64ToHex,
  bytesEqual,
  bytesToHex,
  containsOID,
  encodeBigEndian
};
if (typeof module !== 'undefined' && module.exports) {
  module.exports = utility;
}

