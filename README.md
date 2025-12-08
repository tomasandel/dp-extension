# SCT Certificate Inspector with Proof of Inclusion

A Firefox extension that extracts and displays Signed Certificate Timestamps (SCTs) from HTTPS certificates and verifies their inclusion in Certificate Transparency logs using Merkle tree proofs.

## Features

- 🔍 **Automatic SCT Extraction**: Monitors all HTTPS requests and extracts SCT information
- 🌲 **Merkle Proof Verification**: Verifies certificate inclusion in CT logs using RFC 6962 audit proofs
- 📋 **Console Logging**: Detailed certificate and SCT information logged to browser console
- 🎯 **Clean UI**: Simple popup interface to view certificate data for the current page
- 🔐 **Certificate Chain Display**: Shows complete certificate chain with details
- ✅ **Complete SCT Data**: Extracts log ID, timestamp, signature, hash algorithm, and more
- 🚀 **Zero Dependencies**: Pure JavaScript, no build step required

## What are SCTs?

Signed Certificate Timestamps (SCTs) are cryptographic proofs that a certificate has been submitted to a Certificate Transparency (CT) log. CT is a security mechanism that helps detect mis-issued certificates and provides an audit trail.

## Installation

1. Open Firefox
2. Navigate to `about:debugging#/runtime/this-firefox`
3. Click "Load Temporary Add-on"
4. Select the `manifest.json` file from the extension directory

## Usage

### Console Output

The extension automatically logs certificate and SCT information to the browser console for every HTTPS page you visit:

1. Open the browser console (F12 → Console tab)
2. Navigate to any HTTPS website
3. Look for `[SCT Inspector]` log entries

### Popup Interface

1. Navigate to any HTTPS website
2. Click the extension icon in the toolbar
3. View certificate details, SCTs, and the certificate chain

### Verifying Inclusion Proofs

For each SCT with a valid log URL, you can verify that the certificate is actually included in the CT log:

1. Click "Verify Inclusion Proof" button for an SCT
2. Enter the tree size from the log's Signed Tree Head (STH)
   - Get this from: `GET {log_url}/ct/v1/get-sth`
3. Enter the expected root hash (base64) from the STH
4. The extension will:
   - Build the MerkleTreeLeaf structure (certificate + timestamp)
   - Compute the leaf hash
   - Query the log for an audit proof (`get-proof-by-hash`)
   - Verify the proof by walking up the Merkle tree
   - Display whether the computed root matches the expected root

✅ If valid: Certificate is proven to be in the log
❌ If invalid: Certificate may not be in the log or parameters are incorrect

## Structure

```
extension1/
├── manifest.json       # Extension configuration and permissions
├── background.js       # Main extension logic - monitors requests and caches data
├── sct-parser.js       # SCT parsing module - extracts SCTs from certificates
├── ct-proof.js         # Merkle tree proof verification (RFC 6962)
├── popup.html          # Popup UI structure
├── popup.js            # Popup logic and data display
├── popup.css           # Popup styling
├── icon.png            # Extension icon
├── test-proof.js       # Test script for proof verification
└── README.md           # This file
```

## Technical Details

### APIs Used

- **webRequest API**: Intercepts HTTPS requests to access security information
- **webRequest.getSecurityInfo()**: Retrieves certificate chain with rawDER data
- **Browser Action**: Provides popup interface

### Permissions Required

- `webRequest`: To monitor web requests
- `webRequestBlocking`: To synchronously access security information
- `<all_urls>`: To inspect certificates on all websites

### SCT Sources

Currently extracts SCTs from:
1. **X.509v3 Extension** (OID 1.3.6.1.4.1.11129.2.4.2): Embedded in the certificate itself

*Note: TLS extension and OCSP-delivered SCTs are not accessible via Firefox WebExtension API*

## Development

### Key Components

**background.js**:
- Listens to all HTTPS requests via `webRequest.onHeadersReceived`
- Extracts rawDER certificate data using `getSecurityInfo()`
- Calls SCT parser to extract SCTs from certificates
- Caches certificate data per tab
- Handles proof verification requests from popup
- Logs detailed information to console

**sct-parser.js**:
- Parses SCTs from X.509v3 extension (OID 1.3.6.1.4.1.11129.2.4.2)
- Handles ASN.1 encoding (short/long form length)
- Parses TLS-encoded SCT structures
- Extracts: version, logId, timestamp, extensions, signature

**ct-proof.js**:
- Builds MerkleTreeLeaf structure (RFC 6962 Section 3.4)
- Computes leaf hash: `SHA-256(0x00 || MerkleTreeLeaf)`
- Computes node hash: `SHA-256(0x01 || left || right)`
- Queries CT log API for inclusion proofs (`get-proof-by-hash`)
- Verifies audit proofs by walking up the Merkle tree
- Compares computed root with expected root

**popup.js**:
- Requests certificate data for the current tab
- Renders data in a user-friendly format
- Handles error states (non-HTTPS, no data)
- Manages verification UI and displays results

### Data Structure

Certificate data is cached with the following structure:
```javascript
{
  url: string,
  timestamp: number,                    // When extension captured this data
  securityState: string,
  protocolVersion: string,
  cipherSuite: string,
  certificates: Array<{                 // Array index = position (0 = leaf)
    subject: string,
    issuer: string,
    validity: { start: Date, end: Date },
    serialNumber: string,
    fingerprint: { sha1: string, sha256: string },
    subjectPublicKeyInfoDigest: object
  }>,
  scts: Array<{
    logId: string,
    timestamp: number,                  // When CT log signed this cert
    timestampDate: string,
    signatureHashAlgorithm: string,
    signatureAlgorithm: string,
    signature: string,
    extensions: Array,
    extensionsHex: string,
    origin: string,
    version: number
  }>,
  ctStatus: string,
  securityFlags: {
    hsts: boolean,
    hpkp: boolean,
    usedEch: boolean,
    usedOcsp: boolean,
    usedDelegatedCredentials: boolean,
    isExtendedValidation: boolean
  }
}
```

## Limitations

- Only works with HTTPS websites (HTTP has no certificates)
- Requires page reload if extension is installed after page load
- SCT availability depends on the certificate and server configuration
- Some older certificates may not include SCTs

## Security

This extension:
- ✅ Only reads certificate information (no modifications)
- ✅ Operates locally (no data sent to external servers)
- ✅ Uses secure APIs provided by Firefox
- ✅ Escapes all user-facing output to prevent XSS

## License

MIT License - Free to use and modify

## References

- [RFC 6962 - Certificate Transparency](https://tools.ietf.org/html/rfc6962)
- [Mozilla WebExtensions API](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions)
- [Certificate Transparency Overview](https://certificate.transparency.dev/)
"# dp" 
