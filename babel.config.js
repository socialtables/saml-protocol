const presets = [
  ['@babel/env', {
    targets: {
      node: '8',
    },
    useBuiltIns: 'usage',
  }],
];

module.exports = { presets };
