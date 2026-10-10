// Test preload: any network access (TCP, HTTP(S), fetch, DNS) fails loudly. Used to prove offline commands
// never contact an RPC. Synthetic test helper only.
const net = require('node:net'); const http = require('node:http'); const https = require('node:https'); const dns = require('node:dns');
const refuse = () => { throw new Error('network access attempted in an offline command'); };
net.connect = net.createConnection = refuse; net.Socket.prototype.connect = refuse;
http.request = http.get = https.request = https.get = refuse; dns.lookup = refuse;
globalThis.fetch = async () => refuse();
