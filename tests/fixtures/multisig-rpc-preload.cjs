// Child-process fixture only: reviewed HTTPS names route exclusively to loopback simulators.
const http = require('node:http');
const https = require('node:https');
const routes = JSON.parse(process.env.KCLI_TEST_RPC_ROUTES);
const request = http.request;
https.request = (url, options, callback) => {
  if (!Object.hasOwn(routes, url.href)) throw Error('Unlisted synthetic test RPC');
  const target = new URL(routes[url.href]);
  if (target.protocol !== 'http:' || target.hostname !== '127.0.0.1') throw Error('Non-loopback fixture');
  return request(target, { ...options, agent: false }, callback);
};
http.request = () => { throw Error('Unlisted direct HTTP request'); };
global.fetch = () => { throw Error('Unexpected fixture fetch'); };
