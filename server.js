const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const db = require('./database');
 
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'takua_secret_2024_changeme';
 
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
 
// ── MIDDLEWARE AUTH ──
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sin autorización' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
}
 
function adminOnly(req, res, next) {
  if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Solo administradores' });
  next();
}
 
function log(userId, userName, accion, detalle = '') {
  db.prepare('INSERT INTO log_acciones (usuario_id, usuario_nombre, accion, detalle) VALUES (?,?,?,?)')
    .run(userId, userName, accion, detalle);
}
 
// ══════════════════════════════════════
// AUTH
// ══════════════════════════════════════
 
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Datos incompletos' });
 
  const user = db.prepare('SELECT * FROM usuarios WHERE email = ? AND activo = 1').get(email);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Email o contraseña incorrectos' });
 
  const token = jwt.sign({ id: user.id, nombre: user.nombre, rol: user.rol }, JWT_SECRET, { expiresIn: '12h' });
  log(user.id, user.nombre, 'LOGIN', 'Inicio de sesión');
  res.json({ token, user: { id: user.id, nombre: user.nombre, rol: user.rol, email: user.email } });
});
 
// ══════════════════════════════════════
// USUARIOS
// ══════════════════════════════════════
 
app.get('/api/usuarios', auth, adminOnly, (req, res) => {
  const users = db.prepare('SELECT id, nombre, email, rol, activo, created_at FROM usuarios').all();
  res.json(users);
});
 
app.post('/api/usuarios', auth, adminOnly, (req, res) => {
  const { nombre, email, password, rol } = req.body;
  if (!nombre || !email || !password) return res.status(400).json({ error: 'Datos incompletos' });
  try {
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare('INSERT INTO usuarios (nombre, email, password, rol) VALUES (?,?,?,?)')
      .run(nombre, email, hash, rol || 'recepcionista');
    log(req.user.id, req.user.nombre, 'CREAR_USUARIO', `${nombre} (${rol})`);
    res.json({ id: result.lastInsertRowid, nombre, email, rol });
  } catch {
    res.status(400).json({ error: 'El email ya existe' });
  }
});
 
app.put('/api/usuarios/:id', auth, adminOnly, (req, res) => {
  const { nombre, email, rol, activo, password } = req.body;
  if (password) {
    const hash = bcrypt.hashSync(password, 10);
    db.prepare('UPDATE usuarios SET nombre=?, email=?, rol=?, activo=?, password=? WHERE id=?')
      .run(nombre, email, rol, activo, hash, req.params.id);
  } else {
    db.prepare('UPDATE usuarios SET nombre=?, email=?, rol=?, activo=? WHERE id=?')
      .run(nombre, email, rol, activo, req.params.id);
  }
  log(req.user.id, req.user.nombre, 'EDITAR_USUARIO', nombre);
  res.json({ ok: true });
});
 
// ══════════════════════════════════════
// HABITACIONES
// ══════════════════════════════════════
 
app.get('/api/habitaciones', auth, (req, res) => {
  const habs = db.prepare('SELECT * FROM habitaciones ORDER BY ala, numero').all();
  res.json(habs);
});
 
app.put('/api/habitaciones/:id/status', auth, (req, res) => {
  const { status, nota } = req.body;
  const hab = db.prepare('SELECT * FROM habitaciones WHERE id = ?').get(req.params.id);
  if (!hab) return res.status(404).json({ error: 'Habitación no encontrada' });
 
  db.prepare('UPDATE habitaciones SET status=?, nota=?, updated_at=datetime("now","localtime") WHERE id=?')
    .run(status, nota ?? hab.nota, req.params.id);
  log(req.user.id, req.user.nombre, 'CAMBIO_STATUS', `Hab ${req.params.id}: ${hab.status} → ${status}`);
  res.json({ ok: true });
});
 
app.put('/api/habitaciones/:id', auth, adminOnly, (req, res) => {
  const { nombre, tipo, capacidad, precio_noche, precio_hora } = req.body;
  db.prepare('UPDATE habitaciones SET nombre=?, tipo=?, capacidad=?, precio_noche=?, precio_hora=? WHERE id=?')
    .run(nombre || '', tipo, capacidad, precio_noche, precio_hora, req.params.id);
  log(req.user.id, req.user.nombre, 'EDITAR_HAB', `Hab ${req.params.id}: ${nombre||''}`);
  res.json({ ok: true });
});
 
// ══════════════════════════════════════
// HUÉSPEDES
// ══════════════════════════════════════
 
app.get('/api/huespedes', auth, (req, res) => {
  const q = req.query.q || '';
  const huespedes = db.prepare(`
    SELECT * FROM huespedes
    WHERE nombre LIKE ? OR documento LIKE ?
    ORDER BY nombre LIMIT 50
  `).all(`%${q}%`, `%${q}%`);
  res.json(huespedes);
});
 
app.get('/api/huespedes/doc/:doc', auth, (req, res) => {
  const h = db.prepare('SELECT * FROM huespedes WHERE documento = ?').get(req.params.doc);
  res.json(h || null);
});
 
app.post('/api/huespedes', auth, (req, res) => {
  const { documento, tipo_doc, nombre, telefono, email, nacionalidad } = req.body;
  if (!documento || !nombre) return res.status(400).json({ error: 'Documento y nombre requeridos' });
  try {
    const result = db.prepare(`
      INSERT INTO huespedes (documento, tipo_doc, nombre, telefono, email, nacionalidad)
      VALUES (?,?,?,?,?,?)
    `).run(documento, tipo_doc || 'DNI', nombre, telefono || '', email || '', nacionalidad || 'Argentina');
    res.json({ id: result.lastInsertRowid });
  } catch {
    // ya existe, actualizar
    db.prepare('UPDATE huespedes SET nombre=?, telefono=?, email=? WHERE documento=?')
      .run(nombre, telefono || '', email || '', documento);
    const h = db.prepare('SELECT * FROM huespedes WHERE documento=?').get(documento);
    res.json({ id: h.id });
  }
});
 
// ══════════════════════════════════════
// CHECK-IN / CHECK-OUT
// ══════════════════════════════════════
 
app.post('/api/checkin', auth, (req, res) => {
  const { habitacion_id, documento, tipo_doc, nombre, telefono, entrada, salida, noches, precio_total, metodo_pago, notas } = req.body;
  if (!habitacion_id || !nombre || !entrada || !salida)
    return res.status(400).json({ error: 'Datos incompletos' });
 
  const hab = db.prepare('SELECT * FROM habitaciones WHERE id = ?').get(habitacion_id);
  if (!hab) return res.status(404).json({ error: 'Habitación no encontrada' });
  if (hab.status !== 'libre' && hab.status !== 'reservada')
    return res.status(400).json({ error: 'Habitación no disponible' });
 
  // Registrar/actualizar huésped
  let huespedId = null;
  if (documento) {
    try {
      const r = db.prepare('INSERT INTO huespedes (documento, tipo_doc, nombre, telefono) VALUES (?,?,?,?)')
        .run(documento, tipo_doc || 'DNI', nombre, telefono || '');
      huespedId = r.lastInsertRowid;
    } catch {
      const h = db.prepare('SELECT id FROM huespedes WHERE documento=?').get(documento);
      huespedId = h?.id;
      db.prepare('UPDATE huespedes SET visitas=visitas+1 WHERE id=?').run(huespedId);
    }
  }
 
  // Crear reserva
  const reserva = db.prepare(`
    INSERT INTO reservas (habitacion_id, huesped_id, nombre_huesped, documento, entrada, salida, noches, precio_total, metodo_pago, notas)
    VALUES (?,?,?,?,?,?,?,?,?,?)
  `).run(habitacion_id, huespedId, nombre, documento || '', entrada, salida, noches || 1, precio_total || 0, metodo_pago || 'Efectivo', notas || '');
 
  // Cambiar status
  db.prepare('UPDATE habitaciones SET status=?, nota=?, updated_at=datetime("now","localtime") WHERE id=?')
    .run('ocupada', nombre, habitacion_id);
 
  // Registrar ingreso en caja activa
  const caja = db.prepare('SELECT id FROM cajas WHERE estado="abierta" ORDER BY id DESC LIMIT 1').get();
  if (caja && precio_total > 0) {
    db.prepare(`INSERT INTO movimientos (caja_id, tipo, categoria, descripcion, monto, metodo_pago, habitacion_id, usuario_id)
      VALUES (?,?,?,?,?,?,?,?)`)
      .run(caja.id, 'ingreso', 'hospedaje', `Check-in hab. ${habitacion_id} - ${nombre}`, precio_total, metodo_pago || 'Efectivo', habitacion_id, req.user.id);
  }
 
  log(req.user.id, req.user.nombre, 'CHECKIN', `Hab ${habitacion_id} - ${nombre}`);
  res.json({ ok: true, reserva_id: reserva.lastInsertRowid });
});
 
app.post('/api/checkout/:habitacion_id', auth, (req, res) => {
  const { habitacion_id } = req.params;
  db.prepare('UPDATE habitaciones SET status="limpieza", nota="", updated_at=datetime("now","localtime") WHERE id=?')
    .run(habitacion_id);
  db.prepare('UPDATE reservas SET estado="finalizada" WHERE habitacion_id=? AND estado="activa"')
    .run(habitacion_id);
  log(req.user.id, req.user.nombre, 'CHECKOUT', `Hab ${habitacion_id}`);
  res.json({ ok: true });
});
 
// ══════════════════════════════════════
// RESERVAS
// ══════════════════════════════════════
 
app.get('/api/reservas', auth, (req, res) => {
  const reservas = db.prepare(`
    SELECT r.*, h.nombre as hab_nombre, h.numero as hab_numero, h.ala, h.tipo
    FROM reservas r
    LEFT JOIN habitaciones h ON r.habitacion_id = h.id
    ORDER BY r.created_at DESC LIMIT 100
  `).all();
  res.json(reservas);
});
 
app.post('/api/reservas', auth, (req, res) => {
  const { habitacion_id, nombre_huesped, documento, entrada, salida, noches, precio_total, metodo_pago, notas } = req.body;
  if (!habitacion_id || !nombre_huesped || !entrada || !salida)
    return res.status(400).json({ error: 'Datos incompletos' });
 
  const hab = db.prepare('SELECT * FROM habitaciones WHERE id = ?').get(habitacion_id);
  if (!hab) return res.status(404).json({ error: 'Habitación no encontrada' });
  if (hab.status !== 'libre')
    return res.status(400).json({ error: `La habitación no está disponible (estado: ${hab.status})` });
 
  try {
    db.prepare(`
      INSERT INTO reservas (habitacion_id, nombre_huesped, documento, entrada, salida, noches, precio_total, metodo_pago, notas, estado)
      VALUES (?,?,?,?,?,?,?,?,?,'futura')
    `).run(habitacion_id, nombre_huesped, documento || '', entrada, salida, noches || 1, precio_total || 0, metodo_pago || 'Efectivo', notas || '');
 
    db.prepare('UPDATE habitaciones SET status="reservada", nota=?, updated_at=datetime("now","localtime") WHERE id=?')
      .run(nombre_huesped, habitacion_id);
 
    log(req.user.id, req.user.nombre, 'RESERVA', `Hab ${habitacion_id} - ${nombre_huesped}`);
    res.json({ ok: true });
  } catch(e) {
    console.error('Error al crear reserva:', e);
    res.status(500).json({ error: 'Error al guardar la reserva: ' + e.message });
  }
});
 
// ══════════════════════════════════════
// CAJA
// ══════════════════════════════════════
 
app.get('/api/caja/activa', auth, (req, res) => {
  const caja = db.prepare(`
    SELECT c.*, u.nombre as usuario_nombre FROM cajas c
    LEFT JOIN usuarios u ON c.usuario_id = u.id
    WHERE c.estado = 'abierta' ORDER BY c.id DESC LIMIT 1
  `).get();
  res.json(caja || null);
});
 
app.post('/api/caja/abrir', auth, (req, res) => {
  const { monto_inicial } = req.body;
  const cajaAbierta = db.prepare('SELECT id FROM cajas WHERE estado="abierta"').get();
  if (cajaAbierta) return res.status(400).json({ error: 'Ya hay una caja abierta' });
  const result = db.prepare('INSERT INTO cajas (usuario_id, monto_inicial) VALUES (?,?)').run(req.user.id, monto_inicial || 0);
  log(req.user.id, req.user.nombre, 'ABRIR_CAJA', `Monto inicial: $${monto_inicial}`);
  res.json({ id: result.lastInsertRowid });
});
 
app.post('/api/caja/cerrar', auth, (req, res) => {
  const caja = db.prepare('SELECT * FROM cajas WHERE estado="abierta" ORDER BY id DESC LIMIT 1').get();
  if (!caja) return res.status(400).json({ error: 'No hay caja abierta' });
  const movs = db.prepare('SELECT tipo, SUM(monto) as total FROM movimientos WHERE caja_id=? GROUP BY tipo').all(caja.id);
  const ingresos = movs.find(m => m.tipo === 'ingreso')?.total || 0;
  const egresos = movs.find(m => m.tipo === 'egreso')?.total || 0;
  const monto_final = caja.monto_inicial + ingresos - egresos;
  db.prepare('UPDATE cajas SET estado="cerrada", monto_final=?, cerrada_at=datetime("now","localtime") WHERE id=?')
    .run(monto_final, caja.id);
  log(req.user.id, req.user.nombre, 'CERRAR_CAJA', `Total: $${monto_final}`);
  res.json({ ok: true, monto_final, ingresos, egresos });
});
 
app.get('/api/caja/movimientos', auth, (req, res) => {
  const caja = db.prepare('SELECT id FROM cajas WHERE estado="abierta" ORDER BY id DESC LIMIT 1').get();
  if (!caja) return res.json([]);
  const movs = db.prepare('SELECT * FROM movimientos WHERE caja_id=? ORDER BY created_at DESC').all(caja.id);
  res.json(movs);
});
 
app.post('/api/caja/movimiento', auth, (req, res) => {
  const { tipo, categoria, descripcion, monto, metodo_pago } = req.body;
  const caja = db.prepare('SELECT id FROM cajas WHERE estado="abierta" ORDER BY id DESC LIMIT 1').get();
  if (!caja) return res.status(400).json({ error: 'No hay caja abierta' });
  db.prepare('INSERT INTO movimientos (caja_id, tipo, categoria, descripcion, monto, metodo_pago, usuario_id) VALUES (?,?,?,?,?,?,?)')
    .run(caja.id, tipo, categoria || 'general', descripcion, monto, metodo_pago || 'Efectivo', req.user.id);
  log(req.user.id, req.user.nombre, tipo.toUpperCase(), `${descripcion}: $${monto}`);
  res.json({ ok: true });
});
 
// ══════════════════════════════════════
// FINANZAS
// ══════════════════════════════════════
 
app.get('/api/finanzas/resumen', auth, (req, res) => {
  const { desde, hasta } = req.query;
  const filtro = desde && hasta ? `AND m.created_at BETWEEN '${desde}' AND '${hasta} 23:59:59'` : '';
  const movs = db.prepare(`
    SELECT tipo, categoria, SUM(monto) as total, COUNT(*) as cantidad
    FROM movimientos m WHERE 1=1 ${filtro} GROUP BY tipo, categoria
  `).all();
  const ingresos = movs.filter(m => m.tipo === 'ingreso').reduce((a, m) => a + m.total, 0);
  const egresos = movs.filter(m => m.tipo === 'egreso').reduce((a, m) => a + m.total, 0);
  res.json({ ingresos, egresos, balance: ingresos - egresos, detalle: movs });
});
 
app.get('/api/finanzas/movimientos', auth, (req, res) => {
  const { desde, hasta, tipo } = req.query;
  let query = 'SELECT * FROM movimientos WHERE 1=1';
  const params = [];
  if (desde && hasta) { query += ' AND created_at BETWEEN ? AND ?'; params.push(desde, `${hasta} 23:59:59`); }
  if (tipo) { query += ' AND tipo = ?'; params.push(tipo); }
  query += ' ORDER BY created_at DESC LIMIT 200';
  res.json(db.prepare(query).all(...params));
});
 
// ══════════════════════════════════════
// PRODUCTOS / TIENDA
// ══════════════════════════════════════
 
app.get('/api/productos', auth, (req, res) => {
  res.json(db.prepare('SELECT * FROM productos WHERE activo=1 ORDER BY categoria, nombre').all());
});
 
app.post('/api/productos', auth, adminOnly, (req, res) => {
  const { nombre, categoria, precio, stock, stock_minimo } = req.body;
  const r = db.prepare('INSERT INTO productos (nombre, categoria, precio, stock, stock_minimo) VALUES (?,?,?,?,?)')
    .run(nombre, categoria || 'general', precio, stock || 0, stock_minimo || 5);
  res.json({ id: r.lastInsertRowid });
});
 
app.put('/api/productos/:id', auth, adminOnly, (req, res) => {
  const { nombre, categoria, precio, stock, stock_minimo, activo } = req.body;
  db.prepare('UPDATE productos SET nombre=?, categoria=?, precio=?, stock=?, stock_minimo=?, activo=? WHERE id=?')
    .run(nombre, categoria, precio, stock, stock_minimo, activo ?? 1, req.params.id);
  res.json({ ok: true });
});
 
app.post('/api/tienda/venta', auth, (req, res) => {
  const { items } = req.body; // [{producto_id, cantidad}]
  if (!items?.length) return res.status(400).json({ error: 'Sin productos' });
  const caja = db.prepare('SELECT id FROM cajas WHERE estado="abierta" ORDER BY id DESC LIMIT 1').get();
 
  let totalVenta = 0;
  const insertVenta = db.prepare('INSERT INTO ventas_tienda (producto_id, cantidad, precio_unitario, total, caja_id, usuario_id) VALUES (?,?,?,?,?,?)');
  const updateStock = db.prepare('UPDATE productos SET stock=stock-? WHERE id=?');
 
  const doVenta = db.transaction(() => {
    for (const item of items) {
      const prod = db.prepare('SELECT * FROM productos WHERE id=?').get(item.producto_id);
      if (!prod) throw new Error(`Producto ${item.producto_id} no encontrado`);
      if (prod.stock < item.cantidad) throw new Error(`Stock insuficiente: ${prod.nombre}`);
      const total = prod.precio * item.cantidad;
      totalVenta += total;
      insertVenta.run(item.producto_id, item.cantidad, prod.precio, total, caja?.id || null, req.user.id);
      updateStock.run(item.cantidad, item.producto_id);
    }
    if (caja) {
      db.prepare('INSERT INTO movimientos (caja_id, tipo, categoria, descripcion, monto, metodo_pago, usuario_id) VALUES (?,?,?,?,?,?,?)')
        .run(caja.id, 'ingreso', 'tienda', `Venta tienda (${items.length} items)`, totalVenta, 'Efectivo', req.user.id);
    }
  });
 
  try {
    doVenta();
    log(req.user.id, req.user.nombre, 'VENTA_TIENDA', `Total: $${totalVenta}`);
    res.json({ ok: true, total: totalVenta });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});
 
// ══════════════════════════════════════
// INVENTARIO
// ══════════════════════════════════════
 
app.get('/api/inventario/alertas', auth, (req, res) => {
  const alertas = db.prepare('SELECT * FROM productos WHERE stock <= stock_minimo AND activo=1').all();
  res.json(alertas);
});
 
app.post('/api/inventario/entrada', auth, (req, res) => {
  const { producto_id, cantidad, descripcion } = req.body;
  db.prepare('UPDATE productos SET stock=stock+? WHERE id=?').run(cantidad, producto_id);
  log(req.user.id, req.user.nombre, 'ENTRADA_STOCK', `Prod ${producto_id}: +${cantidad} - ${descripcion || ''}`);
  res.json({ ok: true });
});
 
// ══════════════════════════════════════
// LOG / HISTORIAL
// ══════════════════════════════════════
 
app.get('/api/log', auth, (req, res) => {
  const entries = db.prepare('SELECT * FROM log_acciones ORDER BY created_at DESC LIMIT 100').all();
  res.json(entries);
});
 
// ══════════════════════════════════════
// DASHBOARD STATS
// ══════════════════════════════════════
 
app.get('/api/dashboard', auth, (req, res) => {
  const habs = db.prepare('SELECT status, COUNT(*) as cnt FROM habitaciones GROUP BY status').all();
  const caja = db.prepare('SELECT * FROM cajas WHERE estado="abierta" ORDER BY id DESC LIMIT 1').get();
  let ingresos = 0, egresos = 0, hospedaje = 0, tienda = 0;
  if (caja) {
    const movs = db.prepare('SELECT tipo, categoria, SUM(monto) as total FROM movimientos WHERE caja_id=? GROUP BY tipo, categoria').all(caja.id);
    hospedaje = movs.find(m => m.tipo === 'ingreso' && m.categoria === 'hospedaje')?.total || 0;
    tienda = movs.find(m => m.tipo === 'ingreso' && m.categoria === 'tienda')?.total || 0;
    ingresos = movs.filter(m => m.tipo === 'ingreso').reduce((a, m) => a + m.total, 0);
    egresos = movs.filter(m => m.tipo === 'egreso').reduce((a, m) => a + m.total, 0);
  }
  const alertas = db.prepare('SELECT COUNT(*) as c FROM productos WHERE stock <= stock_minimo AND activo=1').get();
  res.json({ habitaciones: habs, ingresos, egresos, hospedaje, tienda, balance: ingresos - egresos, alertas_stock: alertas.c, caja_abierta: !!caja });
});
 
// SPA fallback
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
 
app.listen(PORT, () => console.log(`🏨 Hotel Takuá corriendo en puerto ${PORT}`));
 
