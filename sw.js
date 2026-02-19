const CACHE_NAME = 'security-checkpoint-v1.3.2';
const ASSETS = [
  './',
  './index.html',
  './app.js',
  './styles.css',
  './vendor/bootstrap.bundle.min.js',
  './vendor/xlsx.full.min.js',
  './manifest.json',
  'https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css',
  'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css',
  'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/fonts/bootstrap-icons.woff2',
  'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/fonts/bootstrap-icons.woff'
];

// Domains and paths that should NEVER be intercepted by the service worker.
// API calls, auth endpoints, and any external data requests must pass
// straight through to the network to avoid CORS and caching issues.
const PASSTHROUGH_PATTERNS = [
  '/api/',
  '/oauth/',
  '/auth/',
  '/token'
];

function shouldPassthrough(url) {
  const path = new URL(url).pathname.toLowerCase();
  return PASSTHROUGH_PATTERNS.some(p => path.includes(p));
}

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      const settled = await Promise.allSettled(
        ASSETS.map((asset) => cache.add(asset))
      );
      const failed = settled.filter((r) => r.status === 'rejected').length;
      if (failed > 0) {
        console.warn(`SW precache completed with ${failed} failures`);
      }
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const request = event.request;

  // PASSTHROUGH: Let non-GET requests and API calls go directly to network.
  // Do NOT call event.respondWith — let the browser handle it natively.
  // This completely avoids SW interference with CORS preflight and API calls.
  if (request.method !== 'GET' || shouldPassthrough(request.url)) {
    return;
  }

  // CACHE STRATEGY: Cache-first for GET requests to static assets
  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) return cached;
      return fetch(request).then((response) => {
        if (response && response.status === 200 && (response.type === 'basic' || response.type === 'cors')) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(request, clone));
        }
        return response;
      }).catch(() => {
        // Offline fallback: serve app shell for document requests
        if (request.destination === 'document') {
          return caches.match('./index.html');
        }
        // Return a proper 503 Response instead of undefined
        return new Response('Offline', { status: 503, statusText: 'Service Unavailable' });
      });
    })
  );
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
