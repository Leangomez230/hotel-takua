const CACHE = 'takua-v4';
const OFFLINE_ASSETS = ['/', '/index.html', '/manifest.json', '/icon-192.png'];
 
// ── INSTALL ──
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE).then(cache => cache.addAll(OFFLINE_ASSETS))
  );
  self.skipWaiting();
});
 
// ── ACTIVATE ──
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
  self.clients.claim();
});
 
// ── FETCH ──
self.addEventListener('fetch', event => {
  if (event.request.url.includes('/api/')) {
    event.respondWith(fetch(event.request).catch(() => new Response('{"error":"offline"}', {headers:{'Content-Type':'application/json'}})));
    return;
  }
  event.respondWith(
    fetch(event.request)
      .then(response => {
        const clone = response.clone();
        caches.open(CACHE).then(cache => cache.put(event.request, clone));
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});
 
// ── NOTIFICACIÓN AL TOCAR ──
self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      // Si la app está abierta en alguna pestaña, enfocarla
      for (const client of list) {
        if ('focus' in client) return client.focus();
      }
      // Si no está abierta, abrirla
      if (clients.openWindow) return clients.openWindow('/');
    })
  );
});
 
// ── MENSAJES DESDE LA PÁGINA ──
// La página llama postMessage({type:'SHOW_NOTIF',...}) cuando detecta una solicitud nueva
self.addEventListener('message', event => {
  if (!event.data) return;
 
  if (event.data.type === 'SHOW_NOTIF') {
    const { title, body, tag } = event.data;
    // event.waitUntil es CLAVE en Android — mantiene el SW vivo hasta mostrar la notif
    event.waitUntil(
      self.registration.showNotification(title || 'Hotel Takuá', {
        body: body || 'Nueva solicitud',
        icon: '/icon-192.png',
        badge: '/icon-192.png',
        vibrate: [200, 100, 200],
        tag: tag || 'takua-sol',
        renotify: true,
        requireInteraction: false,
      })
    );
  }
 
  if (event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
 
// ── SYNC EN BACKGROUND (para polling cuando la app está cerrada) ──
self.addEventListener('sync', event => {
  if (event.tag === 'check-solicitudes') {
    event.waitUntil(checkSolicitudesBackground());
  }
});
 
// ── PERIODIC SYNC (Chrome Android, requiere permiso) ──
self.addEventListener('periodicsync', event => {
  if (event.tag === 'check-solicitudes-periodic') {
    event.waitUntil(checkSolicitudesBackground());
  }
});
 
// Verificar solicitudes pendientes desde el SW (funciona con app cerrada)
async function checkSolicitudesBackground() {
  try {
    // Obtener token guardado
    const cache = await caches.open('takua-auth');
    const tokenResp = await cache.match('token');
    if (!tokenResp) return;
    const token = await tokenResp.text();
 
    // Consultar API
    const resp = await fetch('/api/solicitudes', {
      headers: { 'Authorization': 'Bearer ' + token }
    });
    if (!resp.ok) return;
    const sols = await resp.json();
    const pendientes = sols.filter(s => s.estado === 'pendiente');
    if (!pendientes.length) return;
 
    // Ver cuántas había antes
    const prevCache = await caches.open('takua-state');
    const prevResp = await prevCache.match('sol-count');
    const prevCount = prevResp ? parseInt(await prevResp.text()) : 0;
 
    if (pendientes.length > prevCount) {
      // Hay nuevas — mostrar notificación
      const nueva = pendientes[pendientes.length - 1];
      const tipo = nueva.tipo === 'servicio' ? '🧹 Limpieza solicitada' : '🍫 Pedido de frigobar';
      await self.registration.showNotification('Hotel Takuá — Hab. ' + nueva.numero, {
        body: tipo + (nueva.detalle ? ': ' + nueva.detalle : ''),
        icon: '/icon-192.png',
        badge: '/icon-192.png',
        vibrate: [200, 100, 200],
        tag: 'takua-sol-' + nueva.id,
        renotify: true,
        requireInteraction: true,
      });
    }
 
    // Guardar conteo actual
    await prevCache.put('sol-count', new Response(String(pendientes.length)));
  } catch(e) {
    console.error('SW check solicitudes:', e);
  }
}
 
