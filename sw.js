const CACHE = 'club-pwa-v70'; // להעלות גרסה בכל שינוי בקבצים
const ASSETS = [
  './',
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
  './icon-512-maskable.png',
  './apple-touch-icon.png'
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  const url = new URL(req.url);
  // לא נוגעים ב-Firebase / גוגל / בקשות שאינן GET
  if (req.method !== 'GET' || url.origin !== self.location.origin) return;

  // דפי HTML: קודם רשת (תמיד גרסה עדכנית), ואם אין חיבור - מהמטמון
  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req)
        .then((res) => {
          if (res.ok && !res.redirected) {
            const copy = res.clone();
            caches.open(CACHE).then((c) => c.put('./', copy));
          }
          return res;
        })
        .catch(() => caches.match('./'))
    );
    return;
  }

  // שאר הקבצים: קודם מטמון, ואז רשת
  e.respondWith(caches.match(req).then((hit) => hit || fetch(req)));
});
