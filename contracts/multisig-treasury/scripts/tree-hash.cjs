// sha256 over a directory tree: sorted relative paths, file contents and symlink targets. Skips node_modules/.bin
// (local plugin wrappers) and .yarn-integrity (installer bookkeeping), neither of which the build executes.
// usage: node tree-hash.cjs <dir>
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const root = path.resolve(process.argv[2]);
const entries = [];
(function walk(dir) {
  for (const name of fs.readdirSync(dir)) {
    const full = path.join(dir, name), rel = path.relative(root, full);
    if (rel === '.bin' || name === '.yarn-integrity') continue;
    const st = fs.lstatSync(full);
    if (st.isSymbolicLink()) entries.push('L ' + rel + ' ' + fs.readlinkSync(full));
    else if (st.isDirectory()) walk(full);
    else if (st.isFile()) entries.push('F ' + rel + ' ' + crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex'));
    else { console.error('unexpected file type: ' + rel); process.exit(1); }
  }
})(root);
entries.sort((a, b) => Buffer.compare(Buffer.from(a.slice(2)), Buffer.from(b.slice(2))));
process.stdout.write(crypto.createHash('sha256').update(entries.join('\n')).digest('hex') + ' ' + entries.length + '\n');
