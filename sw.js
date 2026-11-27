// Bump the version when publishing changes to the HTML or CSS.
const prefix = `site-diary:${self.registration.scope}:`;
const cacheName = `${prefix}v2`;
const app = new URL('index.html', self.registration.scope).href;
const css = new URL('diary.css', self.registration.scope).href;
const sync = new URL('diary-sync.js', self.registration.scope).href;

self.addEventListener('install', event => {
  event.waitUntil(caches.open(cacheName).then(cache =>
    cache.addAll([app, css, sync].map(url => new Request(url, { cache: 'reload' })))
  ));
});

self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(
    keys.filter(key => key.startsWith(prefix) && key !== cacheName).map(key => caches.delete(key))
  )).then(() => self.clients.claim()));
});

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  url.search = '';
  const key = url.href === self.registration.scope ? app : url.href;
  if (key !== app && key !== css && key !== sync) return;
  event.respondWith(caches.open(cacheName).then(async cache =>
    (await cache.match(key)) || fetch(event.request)
  ));
});
