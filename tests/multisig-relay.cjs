// Opt-in CLI exercise only: loopback relay 127.0.0.1:<port> -> the disposable chain's jsonrpc on its internal
// Docker network (kcli's local profile accepts loopback HTTP only). Bounded bodies and time; POST only.
'use strict';
const http = require('node:http');
const fs = require('node:fs');
const [port, pidFile, target = 'http://jsonrpc:8080/'] = [Number(process.argv[2]), process.argv[3], process.argv[4]];
http.createServer(async (req, res) => {
  try {
    if (req.method !== 'POST') { res.writeHead(405); res.end(); return; }
    const chunks = []; let size = 0;
    for await (const c of req) { size += c.length; if (size > 4194304) throw Error('oversized'); chunks.push(c); }
    const r = await fetch(target, { method: 'POST', headers: { 'content-type': 'application/json' }, body: Buffer.concat(chunks), redirect: 'error', signal: AbortSignal.timeout(30000) });
    const text = await r.text(); res.writeHead(r.status, { 'content-type': 'application/json' }); res.end(text);
  } catch { res.writeHead(503); res.end('relay unavailable'); }
}).listen(port, '127.0.0.1', () => fs.writeFileSync(pidFile, String(process.pid)));
