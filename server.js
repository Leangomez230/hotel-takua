const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const db = require('./database');
 
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'takua_secret_2024';
 
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
 
// ── MIDDLEWARES ──
function auth(req, res, next) {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sin autorización' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch(e) { res.status(401).json({ error: 'Token inválido' }); }
}
function adminOnly(req, res, next) {
  if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Solo administradores' });
  next();
}
function adminOrRecep(req, res, next) {
  if (!['admin','recepcionista'].includes(req.user.rol)) return res.status(403).json({ error: 'Sin permisos' });
  next();
}
async function logAction(userId, userName, accion, detalle) {
  try { await db.query('INSERT INTO log_acciones (usuario_id,usuario_nombre,accion,detalle) VALUES ($1,$2,$3,$4)', [userId, userName, accion, detalle||'']); }
  catch(e) { console.error('Log error:', e.message); }
}
 
// ── LOGIN ──
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Datos incompletos' });
    const user = await db.getOne('SELECT * FROM usuarios WHERE email=$1 AND activo=1', [email]);
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'Email o contraseña incorrectos' });
    const token = jwt.sign({ id: user.id, nombre: user.nombre, rol: user.rol }, JWT_SECRET, { expiresIn: '12h' });
    await logAction(user.id, user.nombre, 'LOGIN', '');
    res.json({ token, user: { id: user.id, nombre: user.nombre, rol: user.rol, email: user.email } });
  } catch(e) { console.error('Login:', e); res.status(500).json({ error: e.message }); }
});
 
// ── USUARIOS ──
app.get('/api/usuarios', auth, adminOnly, async (req, res) => {
  try { res.json(await db.getAll('SELECT id,nombre,email,rol,activo,created_at FROM usuarios ORDER BY nombre')); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/usuarios', auth, adminOnly, async (req, res) => {
  try {
    const { nombre, email, password, rol } = req.body;
    if (!nombre || !email || !password) return res.status(400).json({ error: 'Datos incompletos' });
    const hash = bcrypt.hashSync(password, 10);
    const r = await db.query('INSERT INTO usuarios (nombre,email,password,rol) VALUES ($1,$2,$3,$4) RETURNING id', [nombre,email,hash,rol||'recepcionista']);
    await logAction(req.user.id, req.user.nombre, 'CREAR_USUARIO', `${nombre} (${rol})`);
    res.json({ id: r.rows[0].id });
  } catch(e) {
    if (e.message.includes('unique') || e.message.includes('duplicate')) return res.status(400).json({ error: 'El email ya existe' });
    res.status(500).json({ error: e.message });
  }
});
app.put('/api/usuarios/:id', auth, adminOnly, async (req, res) => {
  try {
    const { nombre, email, rol, activo, password } = req.body;
    if (password) {
      await db.query('UPDATE usuarios SET nombre=$1,email=$2,rol=$3,activo=$4,password=$5 WHERE id=$6',
        [nombre,email,rol,activo,bcrypt.hashSync(password,10),req.params.id]);
    } else {
      await db.query('UPDATE usuarios SET nombre=$1,email=$2,rol=$3,activo=$4 WHERE id=$5',
        [nombre,email,rol,activo,req.params.id]);
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── HABITACIONES ──
app.get('/api/habitaciones', auth, async (req, res) => {
  try { res.json(await db.getAll('SELECT * FROM habitaciones ORDER BY ala, numero')); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
 
app.put('/api/habitaciones/:id/status', auth, async (req, res) => {
  try {
    const { status, nota } = req.body;
    const hab = await db.getOne('SELECT * FROM habitaciones WHERE id=$1', [req.params.id]);
    if (!hab) return res.status(404).json({ error: 'Habitación no encontrada: ' + req.params.id });
    await db.query('UPDATE habitaciones SET status=$1,nota=$2,updated_at=NOW() WHERE id=$3',
      [status, nota !== undefined ? nota : hab.nota, req.params.id]);
    await logAction(req.user.id, req.user.nombre, 'CAMBIO_STATUS', `Hab ${req.params.id}: ${hab.status}→${status}`);
    res.json({ ok: true });
  } catch(e) { console.error('Status error:', e); res.status(500).json({ error: e.message }); }
});
 
app.put('/api/habitaciones/:id', auth, async (req, res) => {
  try {
    const { nombre, tipo, capacidad, precio_noche, precio_hora } = req.body;
    await db.query('UPDATE habitaciones SET nombre=$1,tipo=$2,capacidad=$3,precio_noche=$4,precio_hora=$5 WHERE id=$6',
      [nombre||'', tipo, capacidad, precio_noche, precio_hora, req.params.id]);
    await logAction(req.user.id, req.user.nombre, 'EDITAR_HAB', `Hab ${req.params.id}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── SERVICIO DE HABITACION (mucama) ──
app.post('/api/servicios', auth, async (req, res) => {
  try {
    const { habitacion_id, tipo_servicio, tipo_cama, necesita_mantenimiento, nota_mantenimiento, consumos, nuevo_status } = req.body;
    const hab = await db.getOne('SELECT * FROM habitaciones WHERE id=$1', [habitacion_id]);
    if (!hab) return res.status(404).json({ error: 'Habitación no encontrada' });
 
    // Calcular consumos frigobar
    let total_consumos = 0;
    let consumosCompletos = [];
    if (consumos && consumos.length > 0) {
      for (const c of consumos) {
        const prod = await db.getOne('SELECT * FROM productos WHERE id=$1', [c.producto_id]);
        if (prod && c.cantidad > 0) {
          const subtotal = prod.precio * c.cantidad;
          total_consumos += subtotal;
          consumosCompletos.push({ id: prod.id, nombre: prod.nombre, cantidad: c.cantidad, precio: prod.precio, subtotal });
          await db.query('UPDATE productos SET stock=stock-$1 WHERE id=$2 AND stock>=$1', [c.cantidad, prod.id]);
        }
      }
      // Registrar en caja
      if (total_consumos > 0) {
        const caja = await db.getOne("SELECT id FROM cajas WHERE estado='abierta' ORDER BY id DESC LIMIT 1");
        if (caja) {
          await db.query('INSERT INTO movimientos (caja_id,tipo,categoria,descripcion,monto,metodo_pago,habitacion_id,usuario_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
            [caja.id,'ingreso','frigobar',`Frigobar hab.${hab.numero} - ${req.user.nombre}`,total_consumos,'Cuenta huésped',habitacion_id,req.user.id]);
        }
      }
    }
 
    // Guardar servicio
    const r = await db.query(
      'INSERT INTO servicios_habitacion (habitacion_id,tipo_servicio,mucama_id,mucama_nombre,tipo_cama,necesita_mantenimiento,nota_mantenimiento,consumos,total_consumos) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id',
      [habitacion_id, tipo_servicio||'diario', req.user.id, req.user.nombre, tipo_cama||'', necesita_mantenimiento?1:0, nota_mantenimiento||'', JSON.stringify(consumosCompletos), total_consumos]
    );
 
    // Actualizar tipo de cama si cambió
    if (tipo_cama) await db.query('UPDATE habitaciones SET tipo=$1 WHERE id=$2', [tipo_cama, habitacion_id]);
 
    // Determinar nuevo status
    let statusFinal = nuevo_status || 'limpia';
    if (necesita_mantenimiento) statusFinal = 'mantenimiento';
 
    // Nota según estado:
    // - mantenimiento: nota del problema
    // - limpia (servicio diario): conservar nombre del huésped
    // - lista/libre: limpiar nota
    let notaFinal;
    if (necesita_mantenimiento) {
      notaFinal = nota_mantenimiento;
    } else if (statusFinal === 'limpia') {
      // Hab sigue ocupada, conservar nota (nombre del huésped)
      notaFinal = hab.nota || '';
    } else {
      notaFinal = '';
    }
    await db.query('UPDATE habitaciones SET status=$1,nota=$2,updated_at=NOW() WHERE id=$3', [statusFinal, notaFinal, habitacion_id]);
 
    await logAction(req.user.id, req.user.nombre, 'SERVICIO_HAB', `Hab ${hab.numero} - ${tipo_servicio}${necesita_mantenimiento?' [MANT]':''}`);
    res.json({ ok: true, id: r.rows[0].id, total_consumos });
  } catch(e) { console.error('Servicio error:', e); res.status(500).json({ error: e.message }); }
});
 
app.get('/api/servicios/:habitacion_id', auth, async (req, res) => {
  try {
    res.json(await db.getAll('SELECT * FROM servicios_habitacion WHERE habitacion_id=$1 ORDER BY created_at DESC LIMIT 20', [req.params.habitacion_id]));
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── HUÉSPEDES ──
app.get('/api/huespedes', auth, async (req, res) => {
  try {
    const q = req.query.q || '';
    res.json(await db.getAll("SELECT * FROM huespedes WHERE nombre ILIKE $1 OR documento ILIKE $1 ORDER BY nombre LIMIT 50", [`%${q}%`]));
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/huespedes/doc/:doc', auth, async (req, res) => {
  try { res.json(await db.getOne('SELECT * FROM huespedes WHERE documento=$1', [req.params.doc])); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/huespedes', auth, async (req, res) => {
  try {
    const { documento, tipo_doc, nombre, telefono, email, nacionalidad } = req.body;
    if (!documento || !nombre) return res.status(400).json({ error: 'Documento y nombre requeridos' });
    try {
      const r = await db.query('INSERT INTO huespedes (documento,tipo_doc,nombre,telefono,email,nacionalidad) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id',
        [documento, tipo_doc||'DNI', nombre, telefono||'', email||'', nacionalidad||'Argentina']);
      res.json({ id: r.rows[0].id });
    } catch(e2) {
      await db.query('UPDATE huespedes SET nombre=$1,telefono=$2,email=$3 WHERE documento=$4', [nombre, telefono||'', email||'', documento]);
      const h = await db.getOne('SELECT * FROM huespedes WHERE documento=$1', [documento]);
      res.json({ id: h.id });
    }
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── CHECK-IN ──
app.post('/api/checkin', auth, adminOrRecep, async (req, res) => {
  try {
    const { habitacion_id, documento, tipo_doc, nombre, telefono, entrada, salida, noches, precio_total, metodo_pago, notas } = req.body;
    if (!habitacion_id) return res.status(400).json({ error: 'Falta habitacion_id' });
    if (!nombre)        return res.status(400).json({ error: 'Falta el nombre del huésped' });
    if (!entrada)       return res.status(400).json({ error: 'Falta la fecha de entrada' });
    if (!salida)        return res.status(400).json({ error: 'Falta la fecha de salida' });
 
    const hab = await db.getOne('SELECT * FROM habitaciones WHERE id=$1', [habitacion_id]);
    if (!hab) return res.status(404).json({ error: 'Habitación no encontrada: ' + habitacion_id });
    const statusesPermitidos = ['libre','lista','reservada'];
    if (!statusesPermitidos.includes(hab.status))
      return res.status(400).json({ error: `La habitación está en estado "${hab.status}". Solo se puede hacer check-in si está Libre, Lista o Reservada.` });
 
    let huespedId = null;
    if (documento) {
      try {
        const rH = await db.query('INSERT INTO huespedes (documento,tipo_doc,nombre,telefono) VALUES ($1,$2,$3,$4) RETURNING id',
          [documento, tipo_doc||'DNI', nombre, telefono||'']);
        huespedId = rH.rows[0].id;
      } catch(e2) {
        const h2 = await db.getOne('SELECT id FROM huespedes WHERE documento=$1', [documento]);
        if (h2) { huespedId = h2.id; await db.query('UPDATE huespedes SET visitas=visitas+1 WHERE id=$1', [huespedId]); }
      }
    }
 
    const reserva = await db.query(
      'INSERT INTO reservas (habitacion_id,huesped_id,nombre_huesped,documento,entrada,salida,noches,precio_total,metodo_pago,notas,estado) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id',
      [habitacion_id, huespedId, nombre, documento||'', entrada, salida, noches||1, precio_total||0, metodo_pago||'Efectivo', notas||'', 'activa']
    );
 
    await db.query('UPDATE habitaciones SET status=$1,nota=$2,updated_at=NOW() WHERE id=$3', ['ocupada', nombre, habitacion_id]);
 
    if (precio_total > 0) {
      const caja = await db.getOne("SELECT id FROM cajas WHERE estado='abierta' ORDER BY id DESC LIMIT 1");
      if (caja) {
        await db.query('INSERT INTO movimientos (caja_id,tipo,categoria,descripcion,monto,metodo_pago,habitacion_id,usuario_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
          [caja.id,'ingreso','hospedaje',`Check-in hab.${hab.numero} - ${nombre}`,precio_total,metodo_pago||'Efectivo',habitacion_id,req.user.id]);
      }
    }
 
    await logAction(req.user.id, req.user.nombre, 'CHECKIN', `Hab ${hab.numero} - ${nombre}`);
    res.json({ ok: true, reserva_id: reserva.rows[0].id });
  } catch(e) { console.error('CHECKIN ERROR:', e); res.status(500).json({ error: 'Error en check-in: ' + e.message }); }
});
 
// ── CHECK-OUT ──
app.post('/api/checkout/:habitacion_id', auth, adminOrRecep, async (req, res) => {
  try {
    const id = req.params.habitacion_id;
    const hab = await db.getOne('SELECT * FROM habitaciones WHERE id=$1', [id]);
    if (!hab) return res.status(404).json({ error: 'Habitación no encontrada: ' + id });
    await db.query("UPDATE habitaciones SET status='limpieza',nota='',updated_at=NOW() WHERE id=$1", [id]);
    await db.query("UPDATE reservas SET estado='finalizada' WHERE habitacion_id=$1 AND estado='activa'", [id]);
    await logAction(req.user.id, req.user.nombre, 'CHECKOUT', `Hab ${hab.numero}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── RESERVAS ──
app.get('/api/reservas', auth, async (req, res) => {
  try {
    res.json(await db.getAll(`
      SELECT r.*,h.nombre as hab_nombre,h.numero as hab_numero,h.ala,h.tipo
      FROM reservas r LEFT JOIN habitaciones h ON r.habitacion_id=h.id
      ORDER BY r.created_at DESC LIMIT 100
    `));
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/reservas', auth, adminOrRecep, async (req, res) => {
  try {
    const { habitacion_id, nombre_huesped, documento, entrada, salida, noches, precio_total, metodo_pago, notas } = req.body;
    if (!habitacion_id)  return res.status(400).json({ error: 'Falta habitacion_id' });
    if (!nombre_huesped) return res.status(400).json({ error: 'Falta el nombre del huésped' });
    if (!entrada)        return res.status(400).json({ error: 'Falta fecha de entrada' });
    if (!salida)         return res.status(400).json({ error: 'Falta fecha de salida' });
 
    const hab = await db.getOne('SELECT * FROM habitaciones WHERE id=$1', [habitacion_id]);
    if (!hab) return res.status(404).json({ error: 'Habitación no encontrada: ' + habitacion_id });
    if (!['libre','lista'].includes(hab.status))
      return res.status(400).json({ error: `La habitación está en estado "${hab.status}". Solo se puede reservar si está Libre o Lista.` });
 
    await db.query(`INSERT INTO reservas (habitacion_id,nombre_huesped,documento,entrada,salida,noches,precio_total,metodo_pago,notas,estado)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'futura')`,
      [habitacion_id, nombre_huesped, documento||'', entrada, salida, noches||1, precio_total||0, metodo_pago||'Efectivo', notas||'']);
 
    await db.query("UPDATE habitaciones SET status='reservada',nota=$1,updated_at=NOW() WHERE id=$2", [nombre_huesped, habitacion_id]);
    await logAction(req.user.id, req.user.nombre, 'RESERVA', `Hab ${hab.numero} - ${nombre_huesped}`);
    res.json({ ok: true });
  } catch(e) { console.error('RESERVA ERROR:', e); res.status(500).json({ error: 'Error al guardar reserva: ' + e.message }); }
});
 
// ── CAJA ──
app.get('/api/caja/activa', auth, async (req, res) => {
  try {
    const caja = await db.getOne("SELECT c.*,u.nombre as usuario_nombre FROM cajas c LEFT JOIN usuarios u ON c.usuario_id=u.id WHERE c.estado='abierta' ORDER BY c.id DESC LIMIT 1");
    res.json(caja || null);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/caja/abrir', auth, adminOrRecep, async (req, res) => {
  try {
    const ya = await db.getOne("SELECT id FROM cajas WHERE estado='abierta'");
    if (ya) return res.status(400).json({ error: 'Ya hay una caja abierta' });
    const r = await db.query('INSERT INTO cajas (usuario_id,monto_inicial) VALUES ($1,$2) RETURNING id', [req.user.id, req.body.monto_inicial||0]);
    await logAction(req.user.id, req.user.nombre, 'ABRIR_CAJA', `Monto: $${req.body.monto_inicial||0}`);
    res.json({ id: r.rows[0].id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/caja/cerrar', auth, adminOrRecep, async (req, res) => {
  try {
    const caja = await db.getOne("SELECT * FROM cajas WHERE estado='abierta' ORDER BY id DESC LIMIT 1");
    if (!caja) return res.status(400).json({ error: 'No hay caja abierta' });
    const movs = await db.getAll('SELECT tipo,SUM(monto) as total FROM movimientos WHERE caja_id=$1 GROUP BY tipo', [caja.id]);
    let ingresos = 0, egresos = 0;
    movs.forEach(m => { if (m.tipo==='ingreso') ingresos=parseFloat(m.total); else egresos=parseFloat(m.total); });
    const final = (caja.monto_inicial||0) + ingresos - egresos;
    await db.query("UPDATE cajas SET estado='cerrada',monto_final=$1,cerrada_at=NOW() WHERE id=$2", [final, caja.id]);
    await logAction(req.user.id, req.user.nombre, 'CERRAR_CAJA', `Total: $${final}`);
    res.json({ ok: true, monto_final: final, ingresos, egresos });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/caja/movimientos', auth, async (req, res) => {
  try {
    const caja = await db.getOne("SELECT id FROM cajas WHERE estado='abierta' ORDER BY id DESC LIMIT 1");
    if (!caja) return res.json([]);
    res.json(await db.getAll('SELECT * FROM movimientos WHERE caja_id=$1 ORDER BY created_at DESC', [caja.id]));
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/caja/movimiento', auth, adminOrRecep, async (req, res) => {
  try {
    const { tipo, categoria, descripcion, monto, metodo_pago } = req.body;
    const caja = await db.getOne("SELECT id FROM cajas WHERE estado='abierta' ORDER BY id DESC LIMIT 1");
    if (!caja) return res.status(400).json({ error: 'No hay caja abierta' });
    await db.query('INSERT INTO movimientos (caja_id,tipo,categoria,descripcion,monto,metodo_pago,usuario_id) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [caja.id, tipo, categoria||'general', descripcion, monto, metodo_pago||'Efectivo', req.user.id]);
    await logAction(req.user.id, req.user.nombre, tipo.toUpperCase(), `${descripcion}: $${monto}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── FINANZAS ──
app.get('/api/finanzas/resumen', auth, async (req, res) => {
  try {
    const { desde, hasta } = req.query;
    let movs;
    if (desde && hasta) movs = await db.getAll("SELECT tipo,categoria,SUM(monto) as total FROM movimientos WHERE created_at BETWEEN $1 AND $2 GROUP BY tipo,categoria", [desde, hasta+' 23:59:59']);
    else movs = await db.getAll("SELECT tipo,categoria,SUM(monto) as total FROM movimientos GROUP BY tipo,categoria");
    let ingresos=0, egresos=0;
    movs.forEach(m => { if(m.tipo==='ingreso') ingresos+=parseFloat(m.total||0); else egresos+=parseFloat(m.total||0); });
    res.json({ ingresos, egresos, balance: ingresos-egresos, detalle: movs });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/finanzas/movimientos', auth, async (req, res) => {
  try {
    const { desde, hasta, tipo } = req.query;
    let movs;
    if (desde && hasta && tipo) movs = await db.getAll("SELECT * FROM movimientos WHERE created_at BETWEEN $1 AND $2 AND tipo=$3 ORDER BY created_at DESC LIMIT 200", [desde, hasta+' 23:59:59', tipo]);
    else if (desde && hasta) movs = await db.getAll("SELECT * FROM movimientos WHERE created_at BETWEEN $1 AND $2 ORDER BY created_at DESC LIMIT 200", [desde, hasta+' 23:59:59']);
    else movs = await db.getAll("SELECT * FROM movimientos ORDER BY created_at DESC LIMIT 200");
    res.json(movs);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── PRODUCTOS ──
app.get('/api/productos', auth, async (req, res) => {
  try { res.json(await db.getAll("SELECT * FROM productos WHERE activo=1 ORDER BY categoria,nombre")); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/productos', auth, adminOnly, async (req, res) => {
  try {
    const r = await db.query('INSERT INTO productos (nombre,categoria,precio,stock,stock_minimo) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      [req.body.nombre, req.body.categoria||'general', req.body.precio, req.body.stock||0, req.body.stock_minimo||5]);
    res.json({ id: r.rows[0].id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/productos/:id', auth, adminOnly, async (req, res) => {
  try {
    await db.query('UPDATE productos SET nombre=$1,categoria=$2,precio=$3,stock=$4,stock_minimo=$5,activo=$6 WHERE id=$7',
      [req.body.nombre, req.body.categoria, req.body.precio, req.body.stock, req.body.stock_minimo, req.body.activo!==undefined?req.body.activo:1, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── TIENDA ──
app.post('/api/tienda/venta', auth, async (req, res) => {
  try {
    const { items } = req.body;
    if (!items?.length) return res.status(400).json({ error: 'Sin productos' });
    const caja = await db.getOne("SELECT id FROM cajas WHERE estado='abierta' ORDER BY id DESC LIMIT 1");
    let totalVenta = 0;
    for (const item of items) {
      const prod = await db.getOne('SELECT * FROM productos WHERE id=$1', [item.producto_id]);
      if (!prod) throw new Error(`Producto no encontrado: ${item.producto_id}`);
      if (prod.stock < item.cantidad) throw new Error(`Stock insuficiente: ${prod.nombre}`);
      const total = prod.precio * item.cantidad;
      totalVenta += total;
      await db.query('INSERT INTO ventas_tienda (producto_id,cantidad,precio_unitario,total,caja_id,usuario_id) VALUES ($1,$2,$3,$4,$5,$6)',
        [item.producto_id, item.cantidad, prod.precio, total, caja?.id||null, req.user.id]);
      await db.query('UPDATE productos SET stock=stock-$1 WHERE id=$2', [item.cantidad, item.producto_id]);
    }
    if (caja) {
      await db.query('INSERT INTO movimientos (caja_id,tipo,categoria,descripcion,monto,metodo_pago,usuario_id) VALUES ($1,$2,$3,$4,$5,$6,$7)',
        [caja.id,'ingreso','tienda',`Venta tienda (${items.length} items)`,totalVenta,'Efectivo',req.user.id]);
    }
    await logAction(req.user.id, req.user.nombre, 'VENTA_TIENDA', `Total: $${totalVenta}`);
    res.json({ ok: true, total: totalVenta });
  } catch(e) { res.status(400).json({ error: e.message }); }
});
 
// ── INVENTARIO ──
app.get('/api/inventario/alertas', auth, async (req, res) => {
  try { res.json(await db.getAll("SELECT * FROM productos WHERE stock<=stock_minimo AND activo=1")); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/inventario/entrada', auth, async (req, res) => {
  try {
    await db.query('UPDATE productos SET stock=stock+$1 WHERE id=$2', [req.body.cantidad, req.body.producto_id]);
    await logAction(req.user.id, req.user.nombre, 'ENTRADA_STOCK', `Prod ${req.body.producto_id}: +${req.body.cantidad}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── LOG ──
app.get('/api/log', auth, async (req, res) => {
  try { res.json(await db.getAll("SELECT * FROM log_acciones ORDER BY created_at DESC LIMIT 100")); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── DASHBOARD ──
app.get('/api/dashboard', auth, async (req, res) => {
  try {
    const habs = await db.getAll("SELECT status,COUNT(*) as cnt FROM habitaciones GROUP BY status");
    const caja = await db.getOne("SELECT * FROM cajas WHERE estado='abierta' ORDER BY id DESC LIMIT 1");
    let hospedaje=0, tienda=0, frigobar=0, ingresos=0, egresos=0;
    if (caja) {
      const movs = await db.getAll("SELECT tipo,categoria,SUM(monto) as total FROM movimientos WHERE caja_id=$1 GROUP BY tipo,categoria", [caja.id]);
      movs.forEach(m => {
        const t = parseFloat(m.total||0);
        if (m.tipo==='ingreso'&&m.categoria==='hospedaje') hospedaje=t;
        if (m.tipo==='ingreso'&&m.categoria==='tienda') tienda=t;
        if (m.tipo==='ingreso'&&m.categoria==='frigobar') frigobar=t;
        if (m.tipo==='ingreso') ingresos+=t;
        if (m.tipo==='egreso') egresos+=t;
      });
    }
    const alertas = await db.getOne("SELECT COUNT(*) as c FROM productos WHERE stock<=stock_minimo AND activo=1");
    res.json({ habitaciones: habs, ingresos, egresos, hospedaje, tienda, frigobar, balance: ingresos-egresos, alertas_stock: parseInt(alertas.c), caja_abierta: !!caja });
  } catch(e) { console.error('Dashboard error:', e); res.status(500).json({ error: e.message }); }
});
 
// ── DEBUG ──
app.get('/api/debug/habitaciones', async (req, res) => {
  try {
    const habs = await db.getAll("SELECT id,numero,ala,status,tipo FROM habitaciones ORDER BY ala,numero");
    res.json({ total: habs.length, habitaciones: habs });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
 
// ── ARRANQUE ──
db.initDB().then(() => {
  app.listen(PORT, () => console.log(`🏨 Hotel Takuá corriendo en puerto ${PORT}`));
}).catch(e => {
  console.error('Error iniciando DB:', e);
  process.exit(1);
});
 
