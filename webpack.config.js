const path = require('path');

module.exports = {
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
};
