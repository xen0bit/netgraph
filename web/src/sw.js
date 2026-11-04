// Installs the app's own files so netgraph opens like an app and survives the
// server restarting. Only the shell is ever stored: network data stays out of
// the cache, so nothing from /api/ is touched here at all.
const CACHE = "netgraph-shell-v1";
const SHELL = ["./", "css/app.css", "icon.svg", "manifest.webmanifest", "js/main.js", "js/util.js", "js/home.js", "js/reel.js", "js/map/map.js", "js/map/layout.js", "js/map/icons.js"];
const scoped = (p) => new URL(p, self.registration.scope).pathname;

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  const url = new URL(req.url);
  if (req.method !== "GET" || url.origin !== location.origin) return;
  const paths = new Set(SHELL.map(scoped));
  const isPage = url.pathname === scoped("./") || url.pathname === scoped("index.html");
  if (!isPage && !paths.has(url.pathname)) return;
  // The server's copy when it answers, so an upgrade is seen at once.
  e.respondWith((async () => {
    const key = isPage ? scoped("./") : url.pathname;
    try {
      const resp = await fetch(req);
      if (resp.ok) {
        const copy = resp.clone();
        e.waitUntil(caches.open(CACHE).then((c) => c.put(key, copy)));
      }
      return resp;
    } catch (err) {
      const hit = await caches.match(key);
      if (hit) return hit;
      throw err;
    }
  })());
});
