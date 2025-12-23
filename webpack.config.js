const path = require('path');

module.exports = [
  // SCT Parser bundle
  {
    entry: './sct-parser.js',
    output: {
      filename: 'sct-parser-bundled.js',
      path: path.resolve(__dirname),
      library: {
        name: 'sctParser',
        type: 'var',
        export: 'default'
      }
    },
    mode: 'production',
    target: 'web'
  },
  // CT Verify bundle
  {
    entry: './ct-verify.js',
    output: {
      filename: 'ct-verify-bundled.js',
      path: path.resolve(__dirname),
      library: {
        name: 'ctVerify',
        type: 'var',
        export: 'default'
      }
    },
    mode: 'production',
    target: 'web'
  }
];
