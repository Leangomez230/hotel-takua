const CACHE = 'takua-v7.0.0';
const OFFLINE_ASSETS = ['/', '/index.html', '/portal.html', '/comandas.html', '/manifest.json', '/icon-192.png'];

// ── INSTALL ──────────────────────────────────────────
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE).then(cache => cache.addAll(OFFLINE_ASSETS))
  );
  self.skipWaiting();
});

// ── ACTIVATE ─────────────────────────────────────────
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// ── FETCH ─────────────────────────────────────────────
self.addEventListener('fetch', event => {
  if (event.request.url.includes('/api/')) {
    event.respondWith(
      fetch(event.request).catch(() =>
        new Response('{"error":"offline"}', { headers: { 'Content-Type': 'application/json' } })
      )
    );
    return;
  }
  // Network first para HTML — no clonar dos veces
  if (event.request.destination === 'document') {
    event.respondWith(
      fetch(event.request)
        .then(r => {
          const clone = r.clone();
          caches.open(CACHE).then(c => c.put(event.request, clone));
          return r;
        })
        .catch(() => caches.match(event.request))
    );
    return;
  }
  event.respondWith(
    fetch(event.request)
      .then(r => {
        const clone = r.clone();
        caches.open(CACHE).then(c => c.put(event.request, clone));
        return r;
      })
      .catch(() => caches.match(event.request))
  );
});

// ── PUSH — app cerrada o en segundo plano ─────────────
self.addEventListener('push', event => {
  let data = { title: 'Hotel Takuá', body: 'Nueva notificación', icon: '/icon-192.png', data: {} };
  try { if (event.data) data = { ...data, ...event.data.json() }; } catch(e) {}

  event.waitUntil(
    self.registration.showNotification(data.title, {
      body:               data.body,
      icon:               data.icon || '/icon-192.png',
      badge:              '/icon-192.png',
      vibrate:            [200, 100, 200, 100, 200],
      tag:                data.tag || 'takua-push',
      renotify:           true,
      requireInteraction: true,   // No desaparece sola en Android
      data:               data.data || {}
    })
  );
});

// ── CLICK EN NOTIFICACIÓN ─────────────────────────────
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const url = event.notification.data?.url || '/index.html';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      // Si la app ya está abierta, enfocarla y navegar
      for (const client of list) {
        if ('focus' in client) {
          client.focus();
          if ('navigate' in client) client.navigate(url);
          return;
        }
      }
      // Si no, abrir nueva ventana
      if (clients.openWindow) return clients.openWindow(url);
    })
  );
});

// ── MENSAJES DESDE LA PÁGINA (notif local cuando app está abierta) ──
self.addEventListener('message', event => {
  if (!event.data) return;
  if (event.data.type === 'SHOW_NOTIF') {
    const { title, body, tag } = event.data;
    event.waitUntil(
      self.registration.showNotification(title || 'Hotel Takuá', {
        body:    body || 'Nueva solicitud',
        icon:    '/icon-192.png',
        badge:   '/icon-192.png',
        vibrate: [200, 100, 200],
        tag:     tag || 'takua-sol',
        renotify: true
      })
    );
  }
  if (event.data.type === 'SKIP_WAITING') self.skipWaiting();
});
