// Isolated installed-CLI fixture only; never contact an unlisted public endpoint.
const routes = JSON.parse(process.env.KCLI_TEST_RPC_ROUTES);
const original = global.fetch;
global.fetch = (url, options) => {
  if (!Object.hasOwn(routes, url)) throw Error('Unlisted synthetic test RPC');
  return original(routes[url], options);
};
