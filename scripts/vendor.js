#!/usr/bin/env node
// Copies vendored front-end dist files from node_modules into the Go embed tree.
// Run after `npm install` to update internal/web/static/ from package.json versions
// and web/ sources.

const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const dest = path.join(root, 'internal', 'web', 'static');
const vendorDest = path.join(dest, 'vendor');

fs.mkdirSync(vendorDest, { recursive: true });

// ── Vendor libs (already minified) ─────────────────────────────────────────
const vendorFiles = [
  ['node_modules/bootstrap/dist/css/bootstrap.min.css',      path.join(vendorDest, 'bootstrap.min.css')],
  ['node_modules/bootstrap/dist/js/bootstrap.bundle.min.js', path.join(vendorDest, 'bootstrap.bundle.min.js')],
  ['node_modules/htmx.org/dist/htmx.min.js',                path.join(vendorDest, 'htmx.min.js')],
];

// ── Project assets (gzip middleware handles compression at runtime) ──────────
const projectFiles = [
  ['web/app.js',    path.join(dest, 'app.js')],
  ['web/style.css', path.join(dest, 'style.css')],
];

for (const [src, to] of [...vendorFiles, ...projectFiles]) {
  const from = path.join(root, src);
  fs.copyFileSync(from, to);
  const size = fs.statSync(to).size;
  console.log(`  ${path.relative(dest, to)}: ${size} bytes`);
}
