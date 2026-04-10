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
 
// ── AUTH MIDDLEWARE ──
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sin autorización' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch(e) {
    res.status(401).json({ error: 'Token inválido' });
  }
}
function adminOnly(req, res, next) {
  if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Solo administradores' });
  next();
}
function logAction(userId, userName, accion, detalle = '') {
  try {
    db.prepare('INSERT INTO log_acciones (usuario_id, usuario_nombre, accion, detalle) VALUES (?,?,?,?)')
      .run(userId, userName, accion, detalle);
  } catch(e) { console.error('Log error:', e.message); }
}
 
// ── LOGIN ──
app.post('/api/login', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Datos incompletos' });
    const user = db.prepare('SELECT * FROM usuarios WHERE email = ? AND activo = 1').get(email);
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'Email o contraseña incorrectos' });
    const token = jwt.sign({ id: user.id, nombre: user.nombre, rol: user.rol }, JWT_SECRET, { expiresIn: '12h' });
    logAction(user.id, user.nombre, 'LOGIN', '');
    res.json({ token, user: { id: user.id, nombre: user.nombre, rol: user.rol, email: user.email } });
  } catch(e) {
    console.error('Login error:', e);
    res.status(500).json({ error: e.message });
  }
});
 
// ── USUARIOS ──
app.get('/api/usuarios', auth, adminOnly, (req, res) => {
  try {
    res.json(db.prepare('SELECT id,nombre,email,rol,activo,created_at FROM usuarios').all());
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
app.post('/api/usuarios', auth, adminOnly, (req, res) => {
  try {
    const { nombre, email, password, rol } = req.body;
    if (!nombre || !email || !password) return res.status(400).json({ error: 'Datos incompletos' });
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare('INSERT INTO usuarios (nombre,email,password,rol) VALUES (?,?,?,?)')
      .run(nombre, email, hash, rol || 'recepcionista');
    logAction(req.user.id, req.user.nombre, 'CREAR_USUARIO', `${nombre} (${rol})`);
    res.json({ id: result.lastInsertRowid, nombre, email, rol });
  } catch(e) {
    if (e.message.includes('UNIQUE')) return res.status(400).json({ error: 'El email ya existe' });
    res.status(500).json({ error: e.message });
  }
});
 
app.put('/api/usuarios/:id', auth, adminOnly, (req, res) => {
  try {
    const { nombre, email, rol, activo, password } = req.body;
    if (password) {
      const hash = bcrypt.hashSync(password, 10);
      db.prepare('UPDATE usuarios SET nombre=?,email=?,rol=?,activo=?,password=? WHERE id=?')
        .run(nombre, email, rol, activo, hash, req.params.id);
    } else {
      db.prepare('UPDATE usuarios SET nombre=?,email=?,rol=?,activo=? WHERE id=?')
        .run(nombre, email, rol, activo, req.params.id);
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── HABITACIONES ──
app.get('/api/habitaciones', auth, (req, res) => {
  try {
    res.json(db.prepare('SELECT * FROM habitaciones ORDER BY ala, numero').all());
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
app.put('/api/habitaciones/:id/status', auth, (req, res) => {
  try {
    const { status, nota } = req.body;
    const hab = db.prepare('SELECT * FROM habitaciones WHERE id=?').get(req.params.id);
    if (!hab) return res.status(404).json({ error: `Habitación ${req.params.id} no encontrada` });
    db.prepare('UPDATE habitaciones SET status=?,nota=?,updated_at=datetime("now","localtime") WHERE id=?')
      .run(status, nota ?? hab.nota, req.params.id);
    logAction(req.user.id, req.user.nombre, 'CAMBIO_STATUS', `Hab ${req.params.id}: ${hab.status}→${status}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
app.put('/api/habitaciones/:id', auth, adminOnly, (req, res) => {
  try {
    const { nombre, tipo, capacidad, precio_noche, precio_hora } = req.body;
    db.prepare('UPDATE habitaciones SET nombre=?,tipo=?,capacidad=?,precio_noche=?,precio_hora=? WHERE id=?')
      .run(nombre||'', tipo, capacidad, precio_noche, precio_hora, req.params.id);
    logAction(req.user.id, req.user.nombre, 'EDITAR_HAB', `Hab ${req.params.id}: ${nombre||''}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── HUÉSPEDES ──
app.get('/api/huespedes', auth, (req, res) => {
  try {
    const q = req.query.q || '';
    res.json(db.prepare('SELECT * FROM huespedes WHERE nombre LIKE ? OR documento LIKE ? ORDER BY nombre LIMIT 50')
      .all(`%${q}%`, `%${q}%`));
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
app.get('/api/huespedes/doc/:doc', auth, (req, res) => {
  try {
    res.json(db.prepare('SELECT * FROM huespedes WHERE documento=?').get(req.params.doc) || null);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
app.post('/api/huespedes', auth, (req, res) => {
  try {
    const { documento, tipo_doc, nombre, telefono, email, nacionalidad } = req.body;
    if (!documento || !nombre) return res.status(400).json({ error: 'Documento y nombre requeridos' });
    try {
      const r = db.prepare('INSERT INTO huespedes (documento,tipo_doc,nombre,telefono,email,nacionalidad) VALUES (?,?,?,?,?,?)')
        .run(documento, tipo_doc||'DNI', nombre, telefono||'', email||'', nacionalidad||'Argentina');
      res.json({ id: r.lastInsertRowid });
    } catch {
      db.prepare('UPDATE huespedes SET nombre=?,telefono=?,email=? WHERE documento=?')
        .run(nombre, telefono||'', email||'', documento);
      const h = db.prepare('SELECT * FROM huespedes WHERE documento=?').get(documento);
      res.json({ id: h.id });
    }
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── CHECK-IN ──
app.post('/api/checkin', auth, (req, res) => {
  try {
    const { habitacion_id, documento, tipo_doc, nombre, telefono, entrada, salida, noches, precio_total, metodo_pago, notas } = req.body;
 
    // Validar campos
    if (!habitacion_id) return res.status(400).json({ error: 'Falta habitacion_id' });
    if (!nombre)        return res.status(400).json({ error: 'Falta el nombre del huésped' });
    if (!entrada)       return res.status(400).json({ error: 'Falta la fecha de entrada' });
    if (!salida)        return res.status(400).json({ error: 'Falta la fecha de salida' });
 
    // Verificar habitación
    const hab = db.prepare('SELECT * FROM habitaciones WHERE id=?').get(habitacion_id);
    if (!hab) return res.status(404).json({ error: `Habitación ${habitacion_id} no encontrada en la base de datos` });
    if (hab.status !== 'libre' && hab.status !== 'reservada')
      return res.status(400).json({ error: `La habitación está en estado "${hab.status}", no se puede hacer check-in` });
 
    // Registrar/actualizar huésped
    let huespedId = null;
    if (documento) {
      try {
        const r = db.prepare('INSERT INTO huespedes (documento,tipo_doc,nombre,telefono) VALUES (?,?,?,?)')
          .run(documento, tipo_doc||'DNI', nombre, telefono||'');
        huespedId = r.lastInsertRowid;
      } catch {
        const h = db.prepare('SELECT id FROM huespedes WHERE documento=?').get(documento);
        if (h) { huespedId = h.id; db.prepare('UPDATE huespedes SET visitas=visitas+1 WHERE id=?').run(huespedId); }
      }
    }
 
    // Crear reserva activa
    const reserva = db.prepare(`
      INSERT INTO reservas (habitacion_id,huesped_id,nombre_huesped,documento,entrada,salida,noches,precio_total,metodo_pago,notas,estado)
      VALUES (?,?,?,?,?,?,?,?,?,?,'activa')
    `).run(habitacion_id, huespedId, nombre, documento||'', entrada, salida, noches||1, precio_total||0, metodo_pago||'Efectivo', notas||'');
 
    // Cambiar status habitación
    db.prepare('UPDATE habitaciones SET status="ocupada",nota=?,updated_at=datetime("now","localtime") WHERE id=?')
      .run(nombre, habitacion_id);
 
    // Registrar en caja activa si hay monto
    if (precio_total > 0) {
      const caja = db.prepare('SELECT id FROM cajas WHERE estado="abierta" ORDER BY id DESC LIMIT 1').get();
      if (caja) {
        db.prepare('INSERT INTO movimientos (caja_id,tipo,categoria,descripcion,monto,metodo_pago,habitacion_id,usuario_id) VALUES (?,?,?,?,?,?,?,?)')
          .run(caja.id, 'ingreso', 'hospedaje', `Check-in hab.${hab.numero} - ${nombre}`, precio_total, metodo_pago||'Efectivo', habitacion_id, req.user.id);
      }
    }
 
    logAction(req.user.id, req.user.nombre, 'CHECKIN', `Hab ${hab.numero} - ${nombre}`);
    res.json({ ok: true, reserva_id: reserva.lastInsertRowid });
 
  } catch(e) {
    console.error('CHECKIN ERROR:', e);
    res.status(500).json({ error: 'Error en check-in: ' + e.message });
  }
});
 
// ── CHECK-OUT ──
app.post('/api/checkout/:habitacion_id', auth, (req, res) => {
  try {
    const id = req.params.habitacion_id;
    const hab = db.prepare('SELECT * FROM habitaciones WHERE id=?').get(id);
    if (!hab) return res.status(404).json({ error: `Habitación ${id} no encontrada` });
    db.prepare('UPDATE habitaciones SET status="limpieza",nota="",updated_at=datetime("now","localtime") WHERE id=?').run(id);
    db.prepare('UPDATE reservas SET estado="finalizada" WHERE habitacion_id=? AND estado="activa"').run(id);
    logAction(req.user.id, req.user.nombre, 'CHECKOUT', `Hab ${hab.numero}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── RESERVAS ──
app.get('/api/reservas', auth, (req, res) => {
  try {
    res.json(db.prepare(`
      SELECT r.*, h.nombre as hab_nombre, h.numero as hab_numero, h.ala, h.tipo
      FROM reservas r LEFT JOIN habitaciones h ON r.habitacion_id=h.id
      ORDER BY r.created_at DESC LIMIT 100
    `).all());
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
app.post('/api/reservas', auth, (req, res) => {
  try {
    const { habitacion_id, nombre_huesped, documento, entrada, salida, noches, precio_total, metodo_pago, notas } = req.body;
 
    if (!habitacion_id)   return res.status(400).json({ error: 'Falta habitacion_id' });
    if (!nombre_huesped)  return res.status(400).json({ error: 'Falta el nombre del huésped' });
    if (!entrada)         return res.status(400).json({ error: 'Falta la fecha de entrada' });
    if (!salida)          return res.status(400).json({ error: 'Falta la fecha de salida' });
 
    const hab = db.prepare('SELECT * FROM habitaciones WHERE id=?').get(habitacion_id);
    if (!hab) return res.status(404).json({ error: `Habitación ${habitacion_id} no encontrada en la base de datos` });
    if (hab.status !== 'libre')
      return res.status(400).json({ error: `La habitación está en estado "${hab.status}". Solo se puede reservar una habitación libre.` });
 
    db.prepare(`
      INSERT INTO reservas (habitacion_id,nombre_huesped,documento,entrada,salida,noches,precio_total,metodo_pago,notas,estado)
      VALUES (?,?,?,?,?,?,?,?,?,'futura')
    `).run(habitacion_id, nombre_huesped, documento||'', entrada, salida, noches||1, precio_total||0, metodo_pago||'Efectivo', notas||'');
 
    db.prepare('UPDATE habitaciones SET status="reservada",nota=?,updated_at=datetime("now","localtime") WHERE id=?')
      .run(nombre_huesped, habitacion_id);
 
    logAction(req.user.id, req.user.nombre, 'RESERVA', `Hab ${hab.numero} - ${nombre_huesped}`);
    res.json({ ok: true });
  } catch(e) {
    console.error('RESERVA ERROR:', e);
    res.status(500).json({ error: 'Error al guardar la reserva: ' + e.message });
  }
});
 
// ── CAJA ──
app.get('/api/caja/activa', auth, (req, res) => {
  try {
    const caja = db.prepare('SELECT c.*,u.nombre as usuario_nombre FROM cajas c LEFT JOIN usuarios u ON c.usuario_id=u.id WHERE c.estado="abierta" ORDER BY c.id DESC LIMIT 1').get();
    res.json(caja || null);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
app.post('/api/caja/abrir', auth, (req, res) => {
  try {
    const ya = db.prepare('SELECT id FROM cajas WHERE estado="abierta"').get();
    if (ya) return res.status(400).json({ error: 'Ya hay una caja abierta' });
    const r = db.prepare('INSERT INTO cajas (usuario_id,monto_inicial) VALUES (?,?)').run(req.user.id, req.body.monto_inicial||0);
    logAction(req.user.id, req.user.nombre, 'ABRIR_CAJA', `Monto: $${req.body.monto_inicial||0}`);
    res.json({ id: r.lastInsertRowid });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
app.post('/api/caja/cerrar', auth, (req, res) => {
  try {
    const caja = db.prepare('SELECT * FROM cajas WHERE estado="abierta" ORDER BY id DESC LIMIT 1').get();
    if (!caja) return res.status(400).json({ error: 'No hay caja abierta' });
    const movs = db.prepare('SELECT tipo,SUM(monto) as total FROM movimientos WHERE caja_id=? GROUP BY tipo').all(caja.id);
    const ingresos = movs.find(m=>m.tipo==='ingreso')?.total||0;
    const egresos  = movs.find(m=>m.tipo==='egreso')?.total||0;
    const final    = caja.monto_inicial + ingresos - egresos;
    db.prepare('UPDATE cajas SET estado="cerrada",monto_final=?,cerrada_at=datetime("now","localtime") WHERE id=?').run(final, caja.id);
    logAction(req.user.id, req.user.nombre, 'CERRAR_CAJA', `Total: $${final}`);
    res.json({ ok: true, monto_final: final, ingresos, egresos });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
app.get('/api/caja/movimientos', auth, (req, res) => {
  try {
    const caja = db.prepare('SELECT id FROM cajas WHERE estado="abierta" ORDER BY id DESC LIMIT 1').get();
    if (!caja) return res.json([]);
    res.json(db.prepare('SELECT * FROM movimientos WHERE caja_id=? ORDER BY created_at DESC').all(caja.id));
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
app.post('/api/caja/movimiento', auth, (req, res) => {
  try {
    const { tipo, categoria, descripcion, monto, metodo_pago } = req.body;
    const caja = db.prepare('SELECT id FROM cajas WHERE estado="abierta" ORDER BY id DESC LIMIT 1').get();
    if (!caja) return res.status(400).json({ error: 'No hay caja abierta' });
    db.prepare('INSERT INTO movimientos (caja_id,tipo,categoria,descripcion,monto,metodo_pago,usuario_id) VALUES (?,?,?,?,?,?,?)')
      .run(caja.id, tipo, categoria||'general', descripcion, monto, metodo_pago||'Efectivo', req.user.id);
    logAction(req.user.id, req.user.nombre, tipo.toUpperCase(), `${descripcion}: $${monto}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── FINANZAS ──
app.get('/api/finanzas/resumen', auth, (req, res) => {
  try {
    const { desde, hasta } = req.query;
    const filtro = desde && hasta ? `AND m.created_at BETWEEN '${desde}' AND '${hasta} 23:59:59'` : '';
    const movs = db.prepare(`SELECT tipo,categoria,SUM(monto) as total FROM movimientos m WHERE 1=1 ${filtro} GROUP BY tipo,categoria`).all();
    const ingresos = movs.filter(m=>m.tipo==='ingreso').reduce((a,m)=>a+m.total,0);
    const egresos  = movs.filter(m=>m.tipo==='egreso').reduce((a,m)=>a+m.total,0);
    res.json({ ingresos, egresos, balance: ingresos-egresos, detalle: movs });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
app.get('/api/finanzas/movimientos', auth, (req, res) => {
  try {
    const { desde, hasta, tipo } = req.query;
    let q = 'SELECT * FROM movimientos WHERE 1=1';
    const p = [];
    if (desde && hasta) { q += ' AND created_at BETWEEN ? AND ?'; p.push(desde, `${hasta} 23:59:59`); }
    if (tipo) { q += ' AND tipo=?'; p.push(tipo); }
    q += ' ORDER BY created_at DESC LIMIT 200';
    res.json(db.prepare(q).all(...p));
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── PRODUCTOS ──
app.get('/api/productos', auth, (req, res) => {
  try {
    res.json(db.prepare('SELECT * FROM productos WHERE activo=1 ORDER BY categoria,nombre').all());
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
app.post('/api/productos', auth, adminOnly, (req, res) => {
  try {
    const { nombre, categoria, precio, stock, stock_minimo } = req.body;
    const r = db.prepare('INSERT INTO productos (nombre,categoria,precio,stock,stock_minimo) VALUES (?,?,?,?,?)')
      .run(nombre, categoria||'general', precio, stock||0, stock_minimo||5);
    res.json({ id: r.lastInsertRowid });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
app.put('/api/productos/:id', auth, adminOnly, (req, res) => {
  try {
    const { nombre, categoria, precio, stock, stock_minimo, activo } = req.body;
    db.prepare('UPDATE productos SET nombre=?,categoria=?,precio=?,stock=?,stock_minimo=?,activo=? WHERE id=?')
      .run(nombre, categoria, precio, stock, stock_minimo, activo??1, req.params.id);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── TIENDA ──
app.post('/api/tienda/venta', auth, (req, res) => {
  try {
    const { items } = req.body;
    if (!items?.length) return res.status(400).json({ error: 'Sin productos' });
    const caja = db.prepare('SELECT id FROM cajas WHERE estado="abierta" ORDER BY id DESC LIMIT 1').get();
    let totalVenta = 0;
    const doVenta = db.transaction(() => {
      for (const item of items) {
        const prod = db.prepare('SELECT * FROM productos WHERE id=?').get(item.producto_id);
        if (!prod) throw new Error(`Producto ${item.producto_id} no encontrado`);
        if (prod.stock < item.cantidad) throw new Error(`Stock insuficiente: ${prod.nombre}`);
        const total = prod.precio * item.cantidad;
        totalVenta += total;
        db.prepare('INSERT INTO ventas_tienda (producto_id,cantidad,precio_unitario,total,caja_id,usuario_id) VALUES (?,?,?,?,?,?)')
          .run(item.producto_id, item.cantidad, prod.precio, total, caja?.id||null, req.user.id);
        db.prepare('UPDATE productos SET stock=stock-? WHERE id=?').run(item.cantidad, item.producto_id);
      }
      if (caja) {
        db.prepare('INSERT INTO movimientos (caja_id,tipo,categoria,descripcion,monto,metodo_pago,usuario_id) VALUES (?,?,?,?,?,?,?)')
          .run(caja.id, 'ingreso', 'tienda', `Venta tienda (${items.length} items)`, totalVenta, 'Efectivo', req.user.id);
      }
    });
    doVenta();
    logAction(req.user.id, req.user.nombre, 'VENTA_TIENDA', `Total: $${totalVenta}`);
    res.json({ ok: true, total: totalVenta });
  } catch(e) { res.status(400).json({ error: e.message }); }
});
 
// ── INVENTARIO ──
app.get('/api/inventario/alertas', auth, (req, res) => {
  try {
    res.json(db.prepare('SELECT * FROM productos WHERE stock<=stock_minimo AND activo=1').all());
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
app.post('/api/inventario/entrada', auth, (req, res) => {
  try {
    const { producto_id, cantidad, descripcion } = req.body;
    db.prepare('UPDATE productos SET stock=stock+? WHERE id=?').run(cantidad, producto_id);
    logAction(req.user.id, req.user.nombre, 'ENTRADA_STOCK', `Prod ${producto_id}: +${cantidad}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── LOG ──
app.get('/api/log', auth, (req, res) => {
  try {
    res.json(db.prepare('SELECT * FROM log_acciones ORDER BY created_at DESC LIMIT 100').all());
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── DASHBOARD ──
app.get('/api/dashboard', auth, (req, res) => {
  try {
    const habs = db.prepare('SELECT status,COUNT(*) as cnt FROM habitaciones GROUP BY status').all();
    const caja = db.prepare('SELECT * FROM cajas WHERE estado="abierta" ORDER BY id DESC LIMIT 1').get();
    let hospedaje=0, tienda=0, ingresos=0, egresos=0;
    if (caja) {
      const movs = db.prepare('SELECT tipo,categoria,SUM(monto) as total FROM movimientos WHERE caja_id=? GROUP BY tipo,categoria').all(caja.id);
      hospedaje = movs.find(m=>m.tipo==='ingreso'&&m.categoria==='hospedaje')?.total||0;
      tienda    = movs.find(m=>m.tipo==='ingreso'&&m.categoria==='tienda')?.total||0;
      ingresos  = movs.filter(m=>m.tipo==='ingreso').reduce((a,m)=>a+m.total,0);
      egresos   = movs.filter(m=>m.tipo==='egreso').reduce((a,m)=>a+m.total,0);
    }
    const alertas = db.prepare('SELECT COUNT(*) as c FROM productos WHERE stock<=stock_minimo AND activo=1').get();
    res.json({ habitaciones: habs, ingresos, egresos, hospedaje, tienda, balance: ingresos-egresos, alertas_stock: alertas.c, caja_abierta: !!caja });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── DEBUG endpoint (solo para diagnosticar) ──
app.get('/api/debug/habitaciones', auth, (req, res) => {
  try {
    const habs = db.prepare('SELECT id, numero, ala, status FROM habitaciones ORDER BY ala, numero').all();
    res.json({ total: habs.length, habitaciones: habs });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// SPA fallback
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
 
app.listen(PORT, () => console.log(`🏨 Hotel Takuá corriendo en puerto ${PORT}`));
 
