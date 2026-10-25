#!/usr/bin/env node
// Copies vendored front-end dist files from node_modules into the Go embed tree.
// Run after `npm install` to update internal/web/static/vendor/ from package.json versions.

const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const vendorDest = path.join(root, 'internal', 'web', 'static', 'vendor');

const vendorFiles = [
  ['node_modules/bootstrap/dist/css/bootstrap.min.css',      'bootstrap.min.css'],
  ['node_modules/bootstrap/dist/js/bootstrap.bundle.min.js', 'bootstrap.bundle.min.js'],
  ['node_modules/htmx.org/dist/htmx.min.js',                'htmx.min.js'],
];

fs.mkdirSync(vendorDest, { recursive: true });

// The .map files are not shipped, so drop the trailing sourceMappingURL comment;
// otherwise DevTools logs a failed source-map fetch for every vendored file.
const sourceMapComment = /(?:\/\*#\s*sourceMappingURL=[^*]*\*\/|\/\/#\s*sourceMappingURL=\S*)\s*$/;

for (const [src, name] of vendorFiles) {
  const from = path.join(root, src);
  const to   = path.join(vendorDest, name);
  const text = fs.readFileSync(from, 'utf8').replace(sourceMapComment, '');
  fs.writeFileSync(to, text);
  const size = fs.statSync(to).size;
  console.log(`  vendor/${name}: ${size} bytes`);
}
