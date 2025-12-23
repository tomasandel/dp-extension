# SCT Certificate Inspector

A Firefox extension that extracts and verifies Signed Certificate Timestamps (SCTs) from HTTPS certificates using Certificate Transparency logs.

## Features

- Automatic SCT extraction from certificate X.509v3 extensions
- Merkle tree audit proof verification (proof of inclusion in CT logs)
- Enriched SCT metadata (log operator, description, state) from Google's CT log list
- Certificate chain inspection with detailed information
- Performance metrics for verification operations
- Console logging for debugging

## Installation

### Development
1. Install dependencies and build: `npm install && npx webpack`
2. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`
3. Click "Load Temporary Add-on"
4. Select the `manifest.json` file

## Usage

### Popup Interface
1. Navigate to any HTTPS website
2. Click the extension icon in the toolbar
3. View SCT verification results, certificate details, and the certificate chain

### Console Output
The extension logs detailed information to the browser console:
1. Open Firefox and navigate to `about:debugging#/runtime/this-firefox`
2. Find SCT Certificate Inspector
3. Click "Inspect" button 

## Structure

```
dp/
├── src/
│   ├── background/
│   │   └── background.js      # Request monitoring, SCT extraction, caching
│   ├── popup/
│   │   ├── popup.html         # UI structure
│   │   ├── popup.js           # UI logic and data display
│   │   └── popup.css          # Styling
│   └── utils/
│       ├── sct-parser.js      # SCT parsing from X.509v3 extensions
│       └── ct-verify.js       # Merkle tree audit proof verification
├── dist/                      # Webpack-bundled files
│   ├── sct-parser-bundled.js
│   └── ct-verify-bundled.js
├── manifest.json              # Extension configuration
├── webpack.config.js
└── package.json
```

## Technical Details

### Permissions
- `webRequest` - Monitor HTTPS requests
- `webRequestBlocking` - Access security information synchronously
- `<all_urls>` - Inspect certificates on all websites

### Dependencies
- `pkijs` - Certificate parsing, SCT list parsing, TBS certificate manipulation
- `asn1js` - ASN.1 BER/DER decoding (dependency of pkijs)
- `pvtsutils` - Utility functions for binary conversions (dependency of pkijs)
- Webpack for bundling Node.js modules into browser-compatible format

### SCT Sources
Extracts SCTs from X.509v3 extensions embedded in certificates (OID 1.3.6.1.4.1.11129.2.4.2).

## References

- [RFC 6962 - Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962)
- [RFC 9162 - Certificate Transparency Version 2.0](https://datatracker.ietf.org/doc/html/rfc9162)
- [Mozilla WebExtensions API](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions)
- [Certificate Transparency](https://certificate.transparency.dev/)
- [Google CT Log List v3](https://www.gstatic.com/ct/log_list/v3/log_list.json)
- [PKI.js Library](https://github.com/PeculiarVentures/PKI.js)

