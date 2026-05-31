const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const db = require('./database');
const webpush = require('web-push');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'takua_secret_2024';

// ── VAPID ────────────────────────────────────────────────────────────
const VAPID_PUBLIC  = process.env.VAPID_PUBLIC  || 'BGgqRVlRquUxbONf-LOZDc9dsvh9mMh-Al37U9B7XM108NA6LteBSzfmCogTbXAVbNuJULyBaymGOHwpqyjgay8';
const VAPID_PRIVATE = process.env.VAPID_PRIVATE || '5fhOAg_7L6Nnbprwb7JiFcwhMR8qn5Tm80JVDHAn2xo';
webpush.setVapidDetails('mailto:hotel@takua.com', VAPID_PUBLIC, VAPID_PRIVATE);

// Enviar push a todos los usuarios de ciertos roles
async function sendPushToRoles(roles, payload) {
  try {
    const subs = await db.getAll(
      `SELECT * FROM push_suscripciones WHERE rol = ANY($1)`,
      [roles]
    );
    for (const s of subs) {
      try {
        await webpush.sendNotification(
          { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
          JSON.stringify(payload)
        );
      } catch(e) {
        // Suscripción expirada o inválida — eliminar
        if (e.statusCode === 410 || e.statusCode === 404) {
          await db.query('DELETE FROM push_suscripciones WHERE endpoint=$1', [s.endpoint]);
        }
      }
    }
  } catch(e) { console.error('Error enviando push:', e.message); }
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── MIDDLEWARES ──────────────────────────────────────────────────────
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
function authRestaurante(req, res, next) {
  if (!['admin','mozo','cajero'].includes(req.user.rol)) return res.status(403).json({ error: 'Sin permisos para restaurante' });
  next();
}
async function logAction(userId, userName, accion, detalle) {
  try { await db.query('INSERT INTO log_acciones (usuario_id,usuario_nombre,accion,detalle) VALUES ($1,$2,$3,$4)', [userId, userName, accion, detalle||'']); }
  catch(e) { console.error('Log error:', e.message); }
}

// Registro automático en libro de novedades
async function registrarLibro(userId, userName, userRol, habitacionId, mensaje) {
  try {
    await db.query(
      `INSERT INTO libro_novedades (tipo, usuario_id, usuario_nombre, usuario_rol, habitacion_id, mensaje)
       VALUES ('auto', $1, $2, $3, $4, $5)`,
      [userId, userName, userRol, habitacionId||'', mensaje]
    );
  } catch(e) { /* silencioso — no interrumpir el flujo */ }
}

// ── LOGIN ────────────────────────────────────────────────────────────
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

// Login restaurante (por usuario + contraseña, sin email)
app.post('/api/restaurante/login', async (req, res) => {
  try {
    const { usuario, clave } = req.body;
    if (!usuario || !clave) return res.status(400).json({ error: 'Datos incompletos' });
    // Buscar por email o por nombre de usuario
    const user = await db.getOne(
      "SELECT * FROM usuarios WHERE (email=$1 OR nombre=$1) AND activo=1",
      [usuario.trim()]
    );
    if (!user || !bcrypt.compareSync(clave, user.password))
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    if (!['admin','mozo','cajero'].includes(user.rol))
      return res.status(403).json({ error: 'Este usuario no tiene acceso al restaurante' });
    const token = jwt.sign({ id: user.id, nombre: user.nombre, rol: user.rol }, JWT_SECRET, { expiresIn: '12h' });
    await logAction(user.id, user.nombre, 'LOGIN_RESTAURANTE', '');
    res.json({ token, user: { id: user.id, nombre: user.nombre, rol: user.rol } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── USUARIOS ─────────────────────────────────────────────────────────
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

// ── HABITACIONES ─────────────────────────────────────────────────────
app.get('/api/habitaciones', auth, async (req, res) => {
  try {
    const habs = await db.getAll('SELECT * FROM habitaciones ORDER BY ala, numero');
    // Agregar datos de la reserva activa a cada habitación
    const reservasActivas = await db.getAll(
      `SELECT * FROM reservas
       WHERE estado IN ('activa','futura','checkin','ocupada','confirmada','reservada')
       ORDER BY entrada ASC`
    );
    const habsEnriquecidas = habs.map(h => {
      const reserva = reservasActivas.find(r => r.habitacion_id == h.id);
      return {
        ...h,
        reserva_activa: reserva ? {
          nombre_huesped: reserva.nombre_huesped,
          entrada:        reserva.entrada,
          salida:         reserva.salida,
          notas:          reserva.notas,
          noches:         reserva.noches,
          estado:         reserva.estado,
        } : null
      };
    });
    res.json(habsEnriquecidas);
  }
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

// ── SERVICIO DE HABITACION ───────────────────────────────────────────
app.post('/api/servicios', auth, async (req, res) => {
  try {
    const { habitacion_id, tipo_servicio, tipo_cama, necesita_mantenimiento, nota_mantenimiento, consumos, nuevo_status } = req.body;
    const hab = await db.getOne('SELECT * FROM habitaciones WHERE id=$1', [habitacion_id]);
    if (!hab) return res.status(404).json({ error: 'Habitación no encontrada' });
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
      if (total_consumos > 0) {
        const caja = await db.getOne("SELECT id FROM cajas WHERE estado='abierta' ORDER BY id DESC LIMIT 1");
        if (caja) {
          await db.query('INSERT INTO movimientos (caja_id,tipo,categoria,descripcion,monto,metodo_pago,habitacion_id,usuario_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
            [caja.id,'ingreso','frigobar',`Frigobar hab.${hab.numero} - ${req.user.nombre}`,total_consumos,'Cuenta huésped',habitacion_id,req.user.id]);
        }
      }
    }
    const r = await db.query(
      'INSERT INTO servicios_habitacion (habitacion_id,tipo_servicio,mucama_id,mucama_nombre,tipo_cama,necesita_mantenimiento,nota_mantenimiento,consumos,total_consumos) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id',
      [habitacion_id, tipo_servicio||'diario', req.user.id, req.user.nombre, tipo_cama||'', necesita_mantenimiento?1:0, nota_mantenimiento||'', JSON.stringify(consumosCompletos), total_consumos]
    );
    if (tipo_cama) await db.query('UPDATE habitaciones SET tipo=$1 WHERE id=$2', [tipo_cama, habitacion_id]);

    let statusFinal = nuevo_status || 'limpia';
    if (necesita_mantenimiento) {
      statusFinal = 'mantenimiento';
    } else if (tipo_servicio === 'mantenimiento') {
      // Al finalizar mantenimiento: verificar si había huésped activo
      const reservaActiva = await db.getOne(
        `SELECT id FROM reservas WHERE habitacion_id=$1
         AND estado IN ('activa','checkin','ocupada','confirmada')
         ORDER BY created_at DESC LIMIT 1`,
        [habitacion_id]
      );
      statusFinal = reservaActiva ? 'ocupada' : 'libre';
    }

    let notaFinal;
    if (necesita_mantenimiento) notaFinal = nota_mantenimiento;
    else if (statusFinal === 'limpia' || statusFinal === 'ocupada') notaFinal = hab.nota || '';
    else notaFinal = '';
    await db.query('UPDATE habitaciones SET status=$1,nota=$2,updated_at=NOW() WHERE id=$3', [statusFinal, notaFinal, habitacion_id]);
    await logAction(req.user.id, req.user.nombre, 'SERVICIO_HAB', `Hab ${hab.numero} - ${tipo_servicio}${necesita_mantenimiento?' [MANT]':''}`);
    const msgServicio = necesita_mantenimiento
      ? `🔧 Mantenimiento reportado — Hab. ${hab.numero}: ${nota_mantenimiento||'sin detalle'}`
      : `🧹 Servicio completado — Hab. ${hab.numero} (${tipo_servicio})`;
    await registrarLibro(req.user.id, req.user.nombre, req.user.rol, habitacion_id, msgServicio);
    res.json({ ok: true, id: r.rows[0].id, total_consumos });
  } catch(e) { console.error('Servicio error:', e); res.status(500).json({ error: e.message }); }
});
app.get('/api/servicios/:habitacion_id', auth, async (req, res) => {
  try {
    res.json(await db.getAll('SELECT * FROM servicios_habitacion WHERE habitacion_id=$1 ORDER BY created_at DESC LIMIT 20', [req.params.habitacion_id]));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── HUÉSPEDES ────────────────────────────────────────────────────────
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

// ── CHECK-IN ─────────────────────────────────────────────────────────
app.post('/api/checkin', auth, adminOrRecep, async (req, res) => {
  try {
    const { habitacion_id, documento, tipo_doc, nombre, telefono, entrada, salida, noches,
            precio_total, metodo_pago, notas, reserva_id, saldo_cobrado } = req.body;
    if (!habitacion_id) return res.status(400).json({ error: 'Falta habitacion_id' });
    if (!nombre)        return res.status(400).json({ error: 'Falta el nombre del huésped' });
    if (!entrada)       return res.status(400).json({ error: 'Falta la fecha de entrada' });
    if (!salida)        return res.status(400).json({ error: 'Falta la fecha de salida' });
    const hab = await db.getOne('SELECT * FROM habitaciones WHERE id=$1', [habitacion_id]);
    if (!hab) return res.status(404).json({ error: 'Habitación no encontrada: ' + habitacion_id });
    const statusesPermitidos = ['libre','lista','reservada','libre_limpia'];
    if (!statusesPermitidos.includes(hab.status))
      return res.status(400).json({ error: `La habitación está en estado "${hab.status}".` });

    // Registrar/actualizar huésped
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

    let finalReservaId;

    if (reserva_id) {
      // ── Checkin desde reserva existente ──────────────────
      // Actualizar la reserva existente a estado 'activa'
      const saldo = Number(saldo_cobrado)||0;
      await db.query(
        `UPDATE reservas SET estado='activa', nombre_huesped=$1, documento=$2, entrada=$3, salida=$4,
         noches=$5, precio_total=$6, metodo_pago=$7, notas=$8, huesped_id=$9,
         saldo_pendiente=GREATEST(0, saldo_pendiente-$10)
         WHERE id=$11`,
        [nombre, documento||'', entrada, salida, noches||1, precio_total||0,
         metodo_pago||'Efectivo', notas||'', huespedId, saldo, reserva_id]
      );
      finalReservaId = reserva_id;
      // Registrar saldo cobrado en caja si corresponde
      if (saldo > 0) {
        const turnoHab = await db.getOne("SELECT id FROM turnos_habitaciones WHERE estado='abierto' ORDER BY id DESC LIMIT 1");
        if (turnoHab) {
          await db.query(
            `INSERT INTO movimientos_habitaciones (turno_id,tipo,concepto,monto,metodo_pago,referencia,usuario_id,usuario_nombre,habitacion_id,habitacion_numero)
             VALUES ($1,'ingreso',$2,$3,$4,$5,$6,$7,$8,$9)`,
            [turnoHab.id, `Saldo Check-in Hab. ${hab.numero} — ${nombre}`, saldo,
             metodo_pago||'Efectivo', `Reserva #${reserva_id}`,
             req.user.id, req.user.nombre, habitacion_id, hab.numero]
          );
        }
      }
    } else {
      // ── Checkin directo sin reserva previa ───────────────
      const reserva = await db.query(
        `INSERT INTO reservas (habitacion_id,huesped_id,nombre_huesped,documento,entrada,salida,noches,
          precio_total,metodo_pago,notas,estado,monto_senia,saldo_pendiente)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'activa',0,0) RETURNING id`,
        [habitacion_id, huespedId, nombre, documento||'', entrada, salida,
         noches||1, precio_total||0, metodo_pago||'Efectivo', notas||'']
      );
      finalReservaId = reserva.rows[0].id;
      // Registrar cobro total en caja
      if ((precio_total||0) > 0) {
        const turnoHab = await db.getOne("SELECT id FROM turnos_habitaciones WHERE estado='abierto' ORDER BY id DESC LIMIT 1");
        if (turnoHab) {
          await db.query(
            `INSERT INTO movimientos_habitaciones (turno_id,tipo,concepto,monto,metodo_pago,referencia,usuario_id,usuario_nombre,habitacion_id,habitacion_numero)
             VALUES ($1,'ingreso',$2,$3,$4,$5,$6,$7,$8,$9)`,
            [turnoHab.id, `Check-in Hab. ${hab.numero} — ${nombre}`, precio_total||0,
             metodo_pago||'Efectivo', `Reserva #${finalReservaId}`,
             req.user.id, req.user.nombre, habitacion_id, hab.numero]
          );
        }
        // Sistema legacy de caja
        const caja = await db.getOne("SELECT id FROM cajas WHERE estado='abierta' ORDER BY id DESC LIMIT 1");
        if (caja) {
          await db.query('INSERT INTO movimientos (caja_id,tipo,categoria,descripcion,monto,metodo_pago,habitacion_id,usuario_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
            [caja.id,'ingreso','hospedaje',`Check-in hab.${hab.numero} - ${nombre}`,precio_total,metodo_pago||'Efectivo',habitacion_id,req.user.id]);
        }
      }
    }

    await db.query('UPDATE habitaciones SET status=$1,nota=$2,updated_at=NOW() WHERE id=$3', ['ocupada', nombre, habitacion_id]);
    await logAction(req.user.id, req.user.nombre, 'CHECKIN', `Hab ${hab.numero} - ${nombre}`);
    await registrarLibro(req.user.id, req.user.nombre, req.user.rol, habitacion_id, `✅ Check-in realizado — Hab. ${hab.numero} (${nombre})`);
    res.json({ ok: true, reserva_id: finalReservaId });
  } catch(e) { console.error('CHECKIN ERROR:', e); res.status(500).json({ error: 'Error en check-in: ' + e.message }); }
});

// ── CHECK-OUT ────────────────────────────────────────────────────────
app.post('/api/checkout/:habitacion_id', auth, adminOrRecep, async (req, res) => {
  try {
    const id = req.params.habitacion_id;
    const { monto_extra, metodo_pago_extra, concepto_extra } = req.body;
    const hab = await db.getOne('SELECT * FROM habitaciones WHERE id=$1', [id]);
    if (!hab) return res.status(404).json({ error: 'Habitación no encontrada: ' + id });

    // Obtener reserva activa con su saldo
    const reserva = await db.getOne(
      "SELECT * FROM reservas WHERE habitacion_id=$1 AND estado='activa' ORDER BY id DESC LIMIT 1", [id]
    );

    // Cobrar saldo pendiente si existe
    const saldo = Number(reserva?.saldo_pendiente||0);
    const extra = Number(monto_extra||0);
    const totalCobrar = saldo + extra;

    if (totalCobrar > 0) {
      const turnoHab = await db.getOne("SELECT id FROM turnos_habitaciones WHERE estado='abierto' ORDER BY id DESC LIMIT 1");
      if (turnoHab) {
        if (saldo > 0) {
          await db.query(
            `INSERT INTO movimientos_habitaciones (turno_id,tipo,concepto,monto,metodo_pago,referencia,usuario_id,usuario_nombre,habitacion_id,habitacion_numero)
             VALUES ($1,'ingreso',$2,$3,$4,$5,$6,$7,$8,$9)`,
            [turnoHab.id, `Saldo Checkout Hab. ${hab.numero} — ${reserva.nombre_huesped||''}`,
             saldo, metodo_pago_extra||'Efectivo', reserva?`Reserva #${reserva.id}`:'',
             req.user.id, req.user.nombre, id, hab.numero]
          );
        }
        if (extra > 0) {
          await db.query(
            `INSERT INTO movimientos_habitaciones (turno_id,tipo,concepto,monto,metodo_pago,usuario_id,usuario_nombre,habitacion_id,habitacion_numero)
             VALUES ($1,'ingreso',$2,$3,$4,$5,$6,$7,$8)`,
            [turnoHab.id, concepto_extra||`Extra Checkout Hab. ${hab.numero}`,
             extra, metodo_pago_extra||'Efectivo',
             req.user.id, req.user.nombre, id, hab.numero]
          );
        }
      }
    }

    // Marcar reserva como finalizada y saldo en 0
    if (reserva) {
      await db.query("UPDATE reservas SET estado='finalizada', saldo_pendiente=0 WHERE id=$1", [reserva.id]);
    }

    await db.query("UPDATE habitaciones SET status='limpieza',nota='',updated_at=NOW() WHERE id=$1", [id]);
    await logAction(req.user.id, req.user.nombre, 'CHECKOUT', `Hab ${hab.numero}${totalCobrar>0?` · Cobrado $${totalCobrar}`:''}`);
    await registrarLibro(req.user.id, req.user.nombre, req.user.rol, id, `🚪 Check-out — Hab. ${hab.numero} (${reserva?.nombre_huesped||''})`);
    res.json({ ok: true, cobrado: totalCobrar });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Cambiar habitación — transfiere reserva y datos del huésped a otra habitación
app.post('/api/habitaciones/:id/cambiar', auth, adminOrRecep, async (req, res) => {
  try {
    const { nueva_habitacion_id, motivo, estado_origen } = req.body;
    const habOrigen = await db.getOne('SELECT * FROM habitaciones WHERE id=$1', [req.params.id]);
    const habDestino = await db.getOne('SELECT * FROM habitaciones WHERE id=$1', [nueva_habitacion_id]);
    if (!habOrigen) return res.status(404).json({ error: 'Habitación origen no encontrada' });
    if (!habDestino) return res.status(404).json({ error: 'Habitación destino no encontrada' });
    if (!['libre','lista'].includes(habDestino.status))
      return res.status(400).json({ error: `La habitación ${habDestino.numero} está ${habDestino.status}` });

    // Obtener reserva activa de origen
    const reserva = await db.getOne(
      `SELECT * FROM reservas WHERE habitacion_id=$1
       AND estado IN ('activa','checkin','ocupada','confirmada')
       ORDER BY created_at DESC LIMIT 1`,
      [req.params.id]
    );
    if (!reserva) return res.status(400).json({ error: 'No hay reserva activa en esta habitación' });

    // Transferir reserva a destino
    await db.query(
      `UPDATE reservas SET habitacion_id=$1,
       notas=COALESCE(notas,'')||$2
       WHERE id=$3`,
      [nueva_habitacion_id, motivo ? ` | Cambio hab: ${motivo}` : ' | Cambio de habitación', reserva.id]
    );

    // Habitación destino → ocupada con datos del huésped
    await db.query("UPDATE habitaciones SET status='ocupada', nota=$1, updated_at=NOW() WHERE id=$2",
      [habOrigen.nota || reserva.nombre_huesped, nueva_habitacion_id]);

    // Habitación origen → según elección del recepcionista
    const statusOrigen = estado_origen === 'mantenimiento' ? 'mantenimiento' : 'libre';
    const notaOrigen   = statusOrigen === 'mantenimiento' ? (motivo || 'Cambio de habitación') : '';
    await db.query('UPDATE habitaciones SET status=$1, nota=$2, updated_at=NOW() WHERE id=$3',
      [statusOrigen, notaOrigen, req.params.id]);

    await logAction(req.user.id, req.user.nombre, 'CAMBIO_HAB',
      `Hab ${habOrigen.numero} → ${habDestino.numero} (${reserva.nombre_huesped}) → origen: ${statusOrigen}`);
    res.json({ ok: true, nombre_huesped: reserva.nombre_huesped });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Obtener reserva vigente de una habitación (para precarga en checkin)
app.get('/api/habitaciones/:id/reserva', auth, adminOrRecep, async (req, res) => {
  try {
    const reserva = await db.getOne(
      `SELECT * FROM reservas WHERE habitacion_id=$1
       AND estado IN ('futura','activa') ORDER BY created_at DESC LIMIT 1`,
      [req.params.id]
    );
    res.json(reserva || null);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── RESERVAS HOTEL ───────────────────────────────────────────────────
app.get('/api/reservas', auth, async (req, res) => {
  try {
    res.json(await db.getAll(`
      SELECT r.*,h.nombre as hab_nombre,h.numero as hab_numero,h.ala,h.tipo
      FROM reservas r LEFT JOIN habitaciones h ON r.habitacion_id=h.id
      WHERE r.estado IN ('activa','futura')
      ORDER BY r.entrada ASC
    `));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/reservas/:id', auth, adminOrRecep, async (req, res) => {
  try {
    const { nombre_huesped, documento, entrada, salida, noches, precio_total, metodo_pago, notas, monto_senia, saldo_pendiente } = req.body;
    const reserva = await db.getOne('SELECT * FROM reservas WHERE id=$1', [req.params.id]);
    if (!reserva) return res.status(404).json({ error: 'Reserva no encontrada' });
    const senia = Number(monto_senia??reserva.monto_senia??0);
    const saldo  = Number(saldo_pendiente??Math.max(0,(precio_total||0)-senia));
    await db.query(
      `UPDATE reservas SET nombre_huesped=$1,documento=$2,entrada=$3,salida=$4,
       noches=$5,precio_total=$6,metodo_pago=$7,notas=$8,monto_senia=$9,saldo_pendiente=$10 WHERE id=$11`,
      [nombre_huesped, documento||'', entrada, salida,
       noches||1, precio_total||0, metodo_pago||'Efectivo', notas||'', senia, saldo, req.params.id]
    );
    await db.query(
      "UPDATE habitaciones SET nota=$1,updated_at=NOW() WHERE id=$2 AND status IN ('reservada','lista')",
      [nombre_huesped, reserva.habitacion_id]
    );
    await logAction(req.user.id, req.user.nombre, 'EDITAR_RESERVA', `Reserva #${req.params.id} - ${nombre_huesped}${senia?` · Seña $${senia}`:''}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/reservas/:id', auth, adminOrRecep, async (req, res) => {
  try {
    const reserva = await db.getOne('SELECT * FROM reservas WHERE id=$1', [req.params.id]);
    if (!reserva) return res.status(404).json({ error: 'Reserva no encontrada' });
    await db.query('DELETE FROM reservas WHERE id=$1', [req.params.id]);
    const otraReserva = await db.getOne(
      "SELECT id FROM reservas WHERE habitacion_id=$1 AND estado IN ('activa','futura')",
      [reserva.habitacion_id]
    );
    if (!otraReserva) {
      await db.query(
        "UPDATE habitaciones SET status='libre',nota='',updated_at=NOW() WHERE id=$1 AND status IN ('reservada','lista')",
        [reserva.habitacion_id]
      );
    }
    await logAction(req.user.id, req.user.nombre, 'ELIMINAR_RESERVA', `Reserva #${req.params.id} - ${reserva.nombre_huesped}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/reservas', auth, adminOrRecep, async (req, res) => {
  try {
    const { habitacion_id, nombre_huesped, documento, entrada, salida, noches, precio_total, metodo_pago, notas, monto_senia } = req.body;
    if (!habitacion_id)  return res.status(400).json({ error: 'Falta habitacion_id' });
    if (!nombre_huesped) return res.status(400).json({ error: 'Falta el nombre del huésped' });
    if (!entrada)        return res.status(400).json({ error: 'Falta fecha de entrada' });
    if (!salida)         return res.status(400).json({ error: 'Falta fecha de salida' });
    const hab = await db.getOne('SELECT * FROM habitaciones WHERE id=$1', [habitacion_id]);
    if (!hab) return res.status(404).json({ error: 'Habitación no encontrada: ' + habitacion_id });

    // Bloquear si está ocupada o en mantenimiento (no se puede reservar)
    if (['ocupada','mantenimiento'].includes(hab.status))
      return res.status(400).json({ error: `La habitación está actualmente ${hab.status} y no se puede reservar.` });

    // Verificar solapamiento de fechas con reservas existentes
    const solapamiento = await db.getOne(
      `SELECT id, nombre_huesped, entrada, salida FROM reservas
       WHERE habitacion_id=$1
       AND estado IN ('futura','activa')
       AND entrada < $3 AND salida > $2`,
      [habitacion_id, entrada, salida]
    );
    if (solapamiento) {
      const entStr = new Date(solapamiento.entrada).toLocaleDateString('es-AR');
      const salStr = new Date(solapamiento.salida).toLocaleDateString('es-AR');
      return res.status(400).json({
        error: `La habitación ya tiene una reserva de ${solapamiento.nombre_huesped} del ${entStr} al ${salStr}.`
      });
    }
    const senia = Number(monto_senia)||0;
    const saldo = Number(precio_total||0) - senia;
    const r = await db.query(
      `INSERT INTO reservas (habitacion_id,nombre_huesped,documento,entrada,salida,noches,precio_total,metodo_pago,notas,estado,monto_senia,saldo_pendiente)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'futura',$10,$11) RETURNING id`,
      [habitacion_id, nombre_huesped, documento||'', entrada, salida, noches||1,
       precio_total||0, metodo_pago||'Efectivo', notas||'', senia, saldo]
    );
    // Solo marcar como reservada si estaba libre/lista — si ya era reservada, dejarla
    if (['libre','lista','limpieza'].includes(hab.status)) {
      await db.query("UPDATE habitaciones SET status='reservada',nota=$1,updated_at=NOW() WHERE id=$2", [nombre_huesped, habitacion_id]);
    }
    // Si hay seña, registrarla en caja habitaciones
    if (senia > 0) {
      const turnoHab = await db.getOne("SELECT id FROM turnos_habitaciones WHERE estado='abierto' ORDER BY id DESC LIMIT 1");
      if (turnoHab) {
        await db.query(
          `INSERT INTO movimientos_habitaciones (turno_id,tipo,concepto,monto,metodo_pago,referencia,usuario_id,usuario_nombre,habitacion_id,habitacion_numero)
           VALUES ($1,'ingreso',$2,$3,$4,$5,$6,$7,$8,$9)`,
          [turnoHab.id, `Seña Reserva Hab. ${hab.numero} — ${nombre_huesped}`, senia,
           metodo_pago||'Efectivo', `Reserva #${r.rows[0].id}`,
           req.user.id, req.user.nombre, habitacion_id, hab.numero]
        );
      }
    }
    await logAction(req.user.id, req.user.nombre, 'RESERVA', `Hab ${hab.numero} - ${nombre_huesped}${senia?` · Seña $${senia}`:''}`);
    res.json({ ok: true, id: r.rows[0].id });
  } catch(e) { console.error('RESERVA ERROR:', e); res.status(500).json({ error: 'Error al guardar reserva: ' + e.message }); }
});

// ── CAJA HOTEL ───────────────────────────────────────────────────────
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

// ── FINANZAS ─────────────────────────────────────────────────────────
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

// ── PRODUCTOS ────────────────────────────────────────────────────────
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

// ── TIENDA ───────────────────────────────────────────────────────────
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

// ── INVENTARIO COMPLETO ──────────────────────────────────────────────
app.get('/api/inventario/productos', auth, async (req, res) => {
  try {
    const { modulo } = req.query;
    let q = 'SELECT * FROM productos WHERE activo=1';
    const params = [];
    if (modulo) { q += ` AND modulo=$1`; params.push(modulo); }
    q += ' ORDER BY modulo,categoria,nombre';
    res.json(await db.getAll(q, params));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/inventario/productos', auth, adminOnly, async (req, res) => {
  try {
    const { nombre, categoria, precio, costo, stock, stock_minimo, unidad, proveedor, modulo } = req.body;
    if (!nombre) return res.status(400).json({ error: 'Nombre requerido' });
    const esBebida = modulo === 'bebidas';
    let menu_id = null;

    // Si es bebida, crear también en menu_restaurante
    if (esBebida) {
      const menuExistente = await db.getOne(
        'SELECT id FROM menu_restaurante WHERE LOWER(nombre)=LOWER($1)', [nombre]
      );
      if (menuExistente) {
        menu_id = menuExistente.id;
        // Actualizar precio y marcar como bebida
        await db.query(
          'UPDATE menu_restaurante SET precio=$1,categoria=$2,es_bebida=1,disponible=1 WHERE id=$3',
          [precio||0, categoria||'Bebidas', menu_id]
        );
      } else {
        const rm = await db.query(
          'INSERT INTO menu_restaurante (nombre,categoria,precio,disponible,es_bebida) VALUES ($1,$2,$3,1,1) RETURNING id',
          [nombre, categoria||'Bebidas', precio||0]
        );
        menu_id = rm.rows[0].id;
      }
    }

    const r = await db.query(
      `INSERT INTO productos (nombre,categoria,precio,costo,stock,stock_minimo,unidad,proveedor,modulo,menu_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
      [nombre, categoria||'General', precio||0, costo||0, stock||0, stock_minimo||5,
       unidad||'unidad', proveedor||'', modulo||'general', menu_id]
    );
    await logAction(req.user.id, req.user.nombre, 'CREAR_PRODUCTO', nombre);

    if ((stock||0) > 0) {
      await db.query(
        `INSERT INTO inventario_movimientos (producto_id,tipo,cantidad,motivo,usuario_id,usuario_nombre,stock_antes,stock_despues)
         VALUES ($1,'entrada',$2,'Stock inicial',$3,$4,0,$2)`,
        [r.rows[0].id, stock||0, req.user.id, req.user.nombre]
      );
    }
    res.json({ id: r.rows[0].id, menu_id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/inventario/productos/:id', auth, adminOnly, async (req, res) => {
  try {
    const prod = await db.getOne('SELECT * FROM productos WHERE id=$1', [req.params.id]);
    if (!prod) return res.status(404).json({ error: 'Producto no encontrado' });
    const { nombre, categoria, precio, costo, stock_minimo, unidad, proveedor, modulo, activo } = req.body;
    const nuevoModulo = modulo ?? prod.modulo;
    const esBebida = nuevoModulo === 'bebidas';
    let menu_id = prod.menu_id;

    // Sincronizar con menú si es bebida
    if (esBebida) {
      if (menu_id) {
        // Actualizar el registro existente en el menú
        await db.query(
          'UPDATE menu_restaurante SET nombre=$1,categoria=$2,precio=$3,es_bebida=1 WHERE id=$4',
          [nombre??prod.nombre, categoria??prod.categoria, precio??prod.precio, menu_id]
        );
      } else {
        // Crear en el menú si no existe
        const rm = await db.query(
          'INSERT INTO menu_restaurante (nombre,categoria,precio,disponible,es_bebida) VALUES ($1,$2,$3,1,1) RETURNING id',
          [nombre??prod.nombre, categoria??prod.categoria, precio??prod.precio]
        );
        menu_id = rm.rows[0].id;
      }
      // Si se desactiva el producto, deshabilitar en el menú también
      if (activo === 0 && menu_id) {
        await db.query('UPDATE menu_restaurante SET disponible=0 WHERE id=$1', [menu_id]);
      }
    } else if (prod.modulo === 'bebidas' && nuevoModulo !== 'bebidas' && menu_id) {
      // Si cambió de bebidas a otro módulo, deshabilitar del menú
      await db.query('UPDATE menu_restaurante SET disponible=0,es_bebida=0 WHERE id=$1', [menu_id]);
      menu_id = null;
    }

    await db.query(
      `UPDATE productos SET nombre=$1,categoria=$2,precio=$3,costo=$4,stock_minimo=$5,
       unidad=$6,proveedor=$7,modulo=$8,menu_id=$9,activo=$10 WHERE id=$11`,
      [nombre??prod.nombre, categoria??prod.categoria, precio??prod.precio, costo??prod.costo,
       stock_minimo??prod.stock_minimo, unidad??prod.unidad, proveedor??prod.proveedor,
       nuevoModulo, menu_id, activo??prod.activo, req.params.id]
    );
    await logAction(req.user.id, req.user.nombre, 'EDITAR_PRODUCTO', nombre??prod.nombre);
    res.json({ ok: true, menu_id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/inventario/productos/:id', auth, adminOnly, async (req, res) => {
  try {
    const prod = await db.getOne('SELECT * FROM productos WHERE id=$1', [req.params.id]);
    if (!prod) return res.status(404).json({ error: 'Producto no encontrado' });
    // Soft delete en inventario
    await db.query('UPDATE productos SET activo=0 WHERE id=$1', [req.params.id]);
    // Si tiene vinculo con el menú, deshabilitar también
    if (prod.menu_id) {
      await db.query('UPDATE menu_restaurante SET disponible=0 WHERE id=$1', [prod.menu_id]);
    }
    await logAction(req.user.id, req.user.nombre, 'ELIMINAR_PRODUCTO', prod.nombre);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Entrada de stock
app.post('/api/inventario/entrada', auth, async (req, res) => {
  try {
    const { producto_id, cantidad, motivo } = req.body;
    const prod = await db.getOne('SELECT * FROM productos WHERE id=$1', [producto_id]);
    if (!prod) return res.status(404).json({ error: 'Producto no encontrado' });
    const stockAntes = Number(prod.stock)||0;
    const stockDespues = stockAntes + (Number(cantidad)||0);
    await db.query('UPDATE productos SET stock=$1 WHERE id=$2', [stockDespues, producto_id]);
    await db.query(
      `INSERT INTO inventario_movimientos (producto_id,tipo,cantidad,motivo,usuario_id,usuario_nombre,stock_antes,stock_despues)
       VALUES ($1,'entrada',$2,$3,$4,$5,$6,$7)`,
      [producto_id, cantidad, motivo||'Entrada manual', req.user.id, req.user.nombre, stockAntes, stockDespues]
    );
    await logAction(req.user.id, req.user.nombre, 'ENTRADA_STOCK', `${prod.nombre}: +${cantidad}`);
    res.json({ ok: true, stock: stockDespues });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Salida manual de stock
app.post('/api/inventario/salida', auth, adminOnly, async (req, res) => {
  try {
    const { producto_id, cantidad, motivo } = req.body;
    const prod = await db.getOne('SELECT * FROM productos WHERE id=$1', [producto_id]);
    if (!prod) return res.status(404).json({ error: 'Producto no encontrado' });
    const stockAntes = Number(prod.stock)||0;
    if (stockAntes < cantidad) return res.status(400).json({ error: 'Stock insuficiente' });
    const stockDespues = stockAntes - (Number(cantidad)||0);
    await db.query('UPDATE productos SET stock=$1 WHERE id=$2', [stockDespues, producto_id]);
    await db.query(
      `INSERT INTO inventario_movimientos (producto_id,tipo,cantidad,motivo,usuario_id,usuario_nombre,stock_antes,stock_despues)
       VALUES ($1,'salida',$2,$3,$4,$5,$6,$7)`,
      [producto_id, cantidad, motivo||'Salida manual', req.user.id, req.user.nombre, stockAntes, stockDespues]
    );
    await logAction(req.user.id, req.user.nombre, 'SALIDA_STOCK', `${prod.nombre}: -${cantidad}`);
    res.json({ ok: true, stock: stockDespues });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Ajuste de stock (corrección)
app.post('/api/inventario/ajuste', auth, adminOnly, async (req, res) => {
  try {
    const { producto_id, stock_nuevo, motivo } = req.body;
    const prod = await db.getOne('SELECT * FROM productos WHERE id=$1', [producto_id]);
    if (!prod) return res.status(404).json({ error: 'Producto no encontrado' });
    const stockAntes = Number(prod.stock)||0;
    await db.query('UPDATE productos SET stock=$1 WHERE id=$2', [stock_nuevo, producto_id]);
    await db.query(
      `INSERT INTO inventario_movimientos (producto_id,tipo,cantidad,motivo,usuario_id,usuario_nombre,stock_antes,stock_despues)
       VALUES ($1,'ajuste',$2,$3,$4,$5,$6,$7)`,
      [producto_id, Math.abs(stock_nuevo-stockAntes), motivo||'Ajuste manual', req.user.id, req.user.nombre, stockAntes, stock_nuevo]
    );
    res.json({ ok: true, stock: stock_nuevo });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Historial de movimientos de un producto
app.get('/api/inventario/movimientos/:producto_id', auth, async (req, res) => {
  try {
    res.json(await db.getAll(
      'SELECT * FROM inventario_movimientos WHERE producto_id=$1 ORDER BY created_at DESC LIMIT 100',
      [req.params.producto_id]
    ));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Alertas de stock bajo
app.get('/api/inventario/alertas', auth, async (req, res) => {
  try {
    res.json(await db.getAll('SELECT * FROM productos WHERE stock<=stock_minimo AND activo=1 ORDER BY modulo,nombre'));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Reporte de inventario
app.get('/api/inventario/reporte', auth, async (req, res) => {
  try {
    const { desde, hasta } = req.query;
    const productos = await db.getAll('SELECT * FROM productos WHERE activo=1 ORDER BY modulo,categoria,nombre');
    let movimientos;
    if (desde && hasta) {
      movimientos = await db.getAll(
        `SELECT im.*, p.nombre as producto_nombre, p.modulo, p.categoria
         FROM inventario_movimientos im JOIN productos p ON im.producto_id=p.id
         WHERE im.created_at BETWEEN $1 AND $2 ORDER BY im.created_at DESC`,
        [desde, hasta+' 23:59:59']
      );
    } else {
      movimientos = await db.getAll(
        `SELECT im.*, p.nombre as producto_nombre, p.modulo, p.categoria
         FROM inventario_movimientos im JOIN productos p ON im.producto_id=p.id
         ORDER BY im.created_at DESC LIMIT 200`
      );
    }
    const valorTotal = productos.reduce((s,p)=>s+(Number(p.stock)*Number(p.costo||0)),0);
    res.json({ productos, movimientos, valorTotal });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── INVENTARIO LEGACY ────────────────────────────────────────────────
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

// ── LOG ──────────────────────────────────────────────────────────────
app.get('/api/log', auth, async (req, res) => {
  try { res.json(await db.getAll("SELECT * FROM log_acciones ORDER BY created_at DESC LIMIT 100")); }
  catch(e) { res.status(500).json({ error: e.message }); }
});

// ── DASHBOARD HOTEL ──────────────────────────────────────────────────
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
        if (m.tipo==='ingreso'&&m.categoria==='tienda')    tienda=t;
        if (m.tipo==='ingreso'&&m.categoria==='frigobar')  frigobar=t;
        if (m.tipo==='ingreso') ingresos+=t;
        if (m.tipo==='egreso')  egresos+=t;
      });
    }

    // Ingresos proyectados desde reservas activas (aunque movimientos esté vacío)
    const reservasActivas = await db.getAll(
      `SELECT r.precio_total, r.noches, r.entrada, r.salida, r.nombre_huesped,
              h.numero, h.ala
       FROM reservas r
       LEFT JOIN habitaciones h ON r.habitacion_id = h.id
       WHERE r.estado IN ('activa','checkin','ocupada','confirmada')`
    );
    const hospedajeProyectado = reservasActivas.reduce((s,r) => s + parseFloat(r.precio_total||0), 0);

    // Frigobar del turno actual (servicios registrados hoy)
    const frigobarHoy = await db.getOne(
      `SELECT COALESCE(SUM(total_consumos),0) as total
       FROM servicios_habitacion
       WHERE DATE(created_at) = CURRENT_DATE AND total_consumos > 0`
    );

    // Gastos de la tienda/servicios extras
    const ventasTienda = await db.getOne(
      `SELECT COALESCE(SUM(total),0) as total FROM ventas_tienda
       WHERE DATE(created_at) = CURRENT_DATE`
    ).catch(() => ({total:0}));

    const alertas = await db.getOne("SELECT COUNT(*) as c FROM productos WHERE stock<=stock_minimo AND activo=1");

    // Si no hay movimientos registrados, usar los proyectados/calculados
    if (hospedaje === 0) hospedaje = hospedajeProyectado;
    if (frigobar === 0)  frigobar  = parseFloat(frigobarHoy?.total||0);
    if (tienda === 0)    tienda    = parseFloat(ventasTienda?.total||0);
    ingresos = hospedaje + tienda + frigobar;

    res.json({
      habitaciones: habs,
      ingresos, egresos, hospedaje, tienda, frigobar,
      balance: ingresos - egresos,
      alertas_stock: parseInt(alertas.c),
      caja_abierta: !!caja,
      reservas_activas: reservasActivas.length,
      huespedes_actuales: reservasActivas.map(r => ({
        nombre: r.nombre_huesped, numero: r.numero, ala: r.ala,
        salida: r.salida, precio_total: r.precio_total
      }))
    });
  } catch(e) { console.error('Dashboard error:', e); res.status(500).json({ error: e.message }); }
});

// ── DEBUG ────────────────────────────────────────────────────────────
app.get('/api/debug/habitaciones', async (req, res) => {
  try {
    const habs = await db.getAll("SELECT id,numero,ala,status,tipo FROM habitaciones ORDER BY ala,numero");
    res.json({ total: habs.length, habitaciones: habs });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── HUÉSPED QR ───────────────────────────────────────────────────────
app.post('/api/huesped/login', async (req, res) => {
  try {
    const { habitacion_id, password } = req.body;
    if (!habitacion_id || !password) return res.status(400).json({ error: 'Datos incompletos' });
    const hab = await db.getOne('SELECT * FROM habitaciones WHERE id=$1', [habitacion_id]);
    if (!hab) return res.status(404).json({ error: 'Habitación no encontrada' });
    if (hab.password_puerta !== password) return res.status(401).json({ error: 'Contraseña incorrecta' });
    if (!['ocupada','en_limpieza','limpia'].includes(hab.status))
      return res.status(403).json({ error: 'No hay huésped activo en esta habitación' });
    const reserva = await db.getOne("SELECT * FROM reservas WHERE habitacion_id=$1 AND estado='activa' ORDER BY id DESC LIMIT 1", [habitacion_id]);
    const token = jwt.sign({ hab_id: habitacion_id, rol: 'huesped' }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, habitacion: { id: hab.id, numero: hab.numero, tipo: hab.tipo, nombre: hab.nombre, ala: hab.ala }, reserva: reserva || null });
  } catch(e) { console.error('Huesped login:', e); res.status(500).json({ error: e.message }); }
});

function authHuesped(req, res, next) {
  const token = (req.headers.authorization || '').split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sin autorización' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.rol !== 'huesped') return res.status(403).json({ error: 'Solo huéspedes' });
    req.huesped = decoded;
    next();
  } catch(e) { res.status(401).json({ error: 'Token inválido' }); }
}

app.get('/api/huesped/info', authHuesped, async (req, res) => {
  try {
    const hab = await db.getOne('SELECT id,numero,tipo,nombre,ala,status FROM habitaciones WHERE id=$1', [req.huesped.hab_id]);
    const reserva = await db.getOne("SELECT * FROM reservas WHERE habitacion_id=$1 AND estado='activa' ORDER BY id DESC LIMIT 1", [req.huesped.hab_id]);
    const productos = await db.getAll("SELECT id,nombre,categoria,precio,stock FROM productos WHERE activo=1 AND stock>0 ORDER BY categoria,nombre");
    const solicitudes = await db.getAll("SELECT * FROM solicitudes_huesped WHERE habitacion_id=$1 ORDER BY created_at DESC LIMIT 5", [req.huesped.hab_id]);
    res.json({ habitacion: hab, reserva, productos, solicitudes });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/huesped/solicitud', authHuesped, async (req, res) => {
  try {
    const { tipo, detalle, consumos } = req.body;
    let consumosCompletos = [], total = 0;
    if (consumos && consumos.length > 0) {
      for (const c of consumos) {
        if (c.cantidad <= 0) continue;
        const prod = await db.getOne('SELECT * FROM productos WHERE id=$1', [c.producto_id]);
        if (prod) {
          const subtotal = prod.precio * c.cantidad;
          total += subtotal;
          consumosCompletos.push({ id: prod.id, nombre: prod.nombre, cantidad: c.cantidad, precio: prod.precio, subtotal });
          await db.query('UPDATE productos SET stock=stock-$1 WHERE id=$2 AND stock>=$1', [c.cantidad, prod.id]);
        }
      }
      if (total > 0) {
        const caja = await db.getOne("SELECT id FROM cajas WHERE estado='abierta' ORDER BY id DESC LIMIT 1");
        if (caja) {
          const hab = await db.getOne('SELECT numero FROM habitaciones WHERE id=$1', [req.huesped.hab_id]);
          await db.query('INSERT INTO movimientos (caja_id,tipo,categoria,descripcion,monto,metodo_pago,habitacion_id) VALUES ($1,$2,$3,$4,$5,$6,$7)',
            [caja.id,'ingreso','frigobar',`Frigobar hab.${hab.numero} (huésped)`,total,'Cuenta huésped',req.huesped.hab_id]);
        }
      }
    }
    await db.query('INSERT INTO solicitudes_huesped (habitacion_id,tipo,detalle,consumos,estado) VALUES ($1,$2,$3,$4,$5)',
      [req.huesped.hab_id, tipo||'servicio', detalle||'', JSON.stringify(consumosCompletos), 'pendiente']);

    // Push notification a recepcionistas y mucamas
    const hab = await db.getOne('SELECT numero FROM habitaciones WHERE id=$1', [req.huesped.hab_id]);
    const esLimpieza = (tipo||'servicio') === 'servicio';
    const titulo = esLimpieza ? '🧹 Solicitud de Mucama' : '🛎️ Solicitud de huésped';
    const cuerpo  = `Habitación ${hab?.numero||req.huesped.hab_id}${detalle ? ': ' + detalle : ''}`;
    const rolesDestino = esLimpieza ? ['recepcionista','mucama','admin'] : ['recepcionista','admin'];
    sendPushToRoles(rolesDestino, {
      title: titulo,
      body:  cuerpo,
      icon:  '/icon-192.png',
      badge: '/icon-192.png',
      tag:   'solicitud-huesped',
      data:  { url: '/index.html#huespedes' }
    });

    res.json({ ok: true, total });
  } catch(e) { console.error('Solicitud huesped:', e); res.status(500).json({ error: e.message }); }
});

app.get('/api/habitaciones/:id/password', auth, adminOnly, async (req, res) => {
  try {
    const hab = await db.getOne('SELECT password_puerta FROM habitaciones WHERE id=$1', [req.params.id]);
    if (!hab) return res.status(404).json({ error: 'No encontrada' });
    res.json({ password: hab.password_puerta });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/habitaciones/:id/mantenimiento', auth, async (req, res) => {
  try {
    const { accion, nota } = req.body;
    const hab = await db.getOne('SELECT * FROM habitaciones WHERE id=$1', [req.params.id]);
    if (!hab) return res.status(404).json({ error: 'Habitación no encontrada' });

    if (accion === 'iniciar') {
      // Guardar estado previo en la nota para poder restaurarlo al finalizar
      const prevStatus = hab.status || 'libre';
      const notaFinal  = `[prev:${prevStatus}] ${nota || ''}`.trim();
      await db.query(
        "UPDATE habitaciones SET status='mantenimiento', nota=$1, updated_at=NOW() WHERE id=$2",
        [notaFinal, req.params.id]
      );
      await logAction(req.user.id, req.user.nombre, 'INICIAR_MANT', `Hab ${hab.numero}: ${nota||'sin detalle'}`);
      await db.query(
        "INSERT INTO log_acciones (usuario_nombre, accion, detalle) VALUES ($1,$2,$3)",
        [req.user.nombre, 'MANTENIMIENTO', `Hab ${hab.numero} — iniciado: ${nota||'sin detalle'}`]
      );

      // Push a admin, mantenimiento y recepcionista
      sendPushToRoles(['admin', 'mantenimiento', 'recepcionista'], {
        title: `🔧 Hab. ${hab.numero} en mantenimiento`,
        body:  nota || 'Habitación puesta en mantenimiento',
        icon:  '/icon-192.png',
        tag:   `mant-${hab.id}`,
        data:  { url: '/index.html#habitaciones' }
      });

    } else if (accion === 'finalizar') {
      // Restaurar estado previo desde la nota
      const matchPrev = (hab.nota || '').match(/\[prev:(\w+)\]/);
      const statusFinal = matchPrev ? matchPrev[1] : 'libre';
      const notaLimpia  = (hab.nota || '').replace(/\[prev:\w+\]\s*/, '').trim();
      await db.query(
        'UPDATE habitaciones SET status=$1, nota=$2, updated_at=NOW() WHERE id=$3',
        [statusFinal, notaLimpia, req.params.id]
      );
      await logAction(req.user.id, req.user.nombre, 'FINALIZAR_MANT', `Hab ${hab.numero} → ${statusFinal}`);
      await db.query(
        "INSERT INTO log_acciones (usuario_nombre, accion, detalle) VALUES ($1,$2,$3)",
        [req.user.nombre, 'MANTENIMIENTO', `Hab ${hab.numero} — finalizado → ${statusFinal}`]
      );

      // Push a admin y recepcionista informando finalización
      sendPushToRoles(['admin', 'recepcionista'], {
        title: `✅ Hab. ${hab.numero} — mantenimiento finalizado`,
        body:  `Volvió a estado: ${statusFinal}`,
        icon:  '/icon-192.png',
        tag:   `mant-fin-${hab.id}`,
        data:  { url: '/index.html#habitaciones' }
      });
    }

    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/habitaciones/:id/password', auth, adminOnly, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Falta la contraseña' });
    await db.query('UPDATE habitaciones SET password_puerta=$1 WHERE id=$2', [password, req.params.id]);
    await logAction(req.user.id, req.user.nombre, 'CAMBIO_PASSWORD_HAB', `Hab ${req.params.id}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/solicitudes', auth, async (req, res) => {
  try {
    const sols = await db.getAll(`
      SELECT s.*, h.numero, h.ala FROM solicitudes_huesped s
      LEFT JOIN habitaciones h ON s.habitacion_id = h.id
      ORDER BY s.created_at DESC LIMIT 50
    `);
    res.json(sols);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/solicitudes/:id', auth, async (req, res) => {
  try {
    await db.query('UPDATE solicitudes_huesped SET estado=$1 WHERE id=$2', [req.body.estado, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════════
// ── RESTAURANTE ──────────────────────────────────────────────────────
// ════════════════════════════════════════════════════════════════════

// ── MESAS RESTAURANTE ─────────────────────────────────────────────
app.get('/api/restaurante/mesas', auth, authRestaurante, async (req, res) => {
  try {
    res.json(await db.getAll('SELECT * FROM mesas_restaurante WHERE activo=1 ORDER BY numero, id'));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/restaurante/mesas/:id', auth, authRestaurante, async (req, res) => {
  try {
    const { alias, tipo, x, y, numero, status } = req.body;

    // Traer los valores actuales para no pisar con null
    const actual = await db.getOne('SELECT * FROM mesas_restaurante WHERE id=$1', [req.params.id]);
    if (!actual) return res.status(404).json({ error: 'Mesa no encontrada' });

    await db.query(
      `UPDATE mesas_restaurante
       SET alias=$1, tipo=$2, x=$3, y=$4, numero=$5, status=COALESCE($6, status),
           ancho=COALESCE($7, ancho), alto=COALESCE($8, alto), updated_at=NOW()
       WHERE id=$9`,
      [
        alias  !== undefined ? alias  : actual.alias,
        tipo   !== undefined ? tipo   : actual.tipo,
        x      !== undefined ? x      : actual.x,
        y      !== undefined ? y      : actual.y,
        numero !== undefined ? numero : actual.numero,
        status !== undefined ? status : null,
        req.body.ancho !== undefined ? req.body.ancho : null,
        req.body.alto  !== undefined ? req.body.alto  : null,
        req.params.id
      ]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/restaurante/mesas', auth, authRestaurante, async (req, res) => {
  try {
    const { tipo, x, y, alias, numero } = req.body;
    const r = await db.query(
      'INSERT INTO mesas_restaurante (tipo, x, y, alias, numero, status, activo, ancho, alto, partes) VALUES ($1,$2,$3,$4,$5,$6,1,$7,$8,$9) RETURNING *',
      [tipo||'cuadrada', x||100, y||100, alias||'', numero||null, 'libre', req.body.ancho||null, req.body.alto||null, req.body.partes||null]
    );
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/restaurante/mesas/:id', auth, authRestaurante, async (req, res) => {
  try {
    await db.query('UPDATE mesas_restaurante SET activo=0 WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});


// Guardar layout completo del salón (posiciones de todas las mesas)
app.put('/api/restaurante/salon', auth, adminOnly, async (req, res) => {
  try {
    const { mesas } = req.body;
    for (const m of mesas) {
      await db.query('UPDATE mesas_restaurante SET alias=$1,tipo=$2,x=$3,y=$4,updated_at=NOW() WHERE id=$5',
        [m.alias||'', m.tipo, m.x, m.y, m.id]);
    }
    await logAction(req.user.id, req.user.nombre, 'GUARDAR_SALON', `${mesas.length} mesas actualizadas`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── MENÚ RESTAURANTE ─────────────────────────────────────────────────
app.get('/api/restaurante/menu', auth, authRestaurante, async (req, res) => {
  try {
    const menu = await db.getAll('SELECT * FROM menu_restaurante ORDER BY categoria,nombre');
    // Para cada producto, verificar si tiene stock vinculado
    for (const item of menu) {
      if (item.es_bebida) {
        const invProd = await db.getOne('SELECT stock FROM productos WHERE menu_id=$1 AND activo=1', [item.id]);
        if (invProd) {
          item.stock_inv = Number(invProd.stock)||0;
          item.sin_stock = item.stock_inv <= 0;
        }
      }
    }
    res.json(menu);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/restaurante/menu', auth, async (req, res) => {
  try {
    if (!['admin','cajero'].includes(req.user.rol)) return res.status(403).json({ error: 'Sin permisos' });
    const { nombre, categoria, precio, es_bebida } = req.body;
    if (!nombre || !precio) return res.status(400).json({ error: 'Nombre y precio requeridos' });
    const r = await db.query(
      'INSERT INTO menu_restaurante (nombre,categoria,precio,es_bebida) VALUES ($1,$2,$3,$4) RETURNING *',
      [nombre, categoria||'General', precio, es_bebida?1:0]
    );
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/restaurante/menu/:id', auth, async (req, res) => {
  try {
    if (!['admin','cajero'].includes(req.user.rol)) return res.status(403).json({ error: 'Sin permisos' });
    const { nombre, categoria, precio, disponible, es_bebida } = req.body;
    const prod = await db.getOne('SELECT * FROM menu_restaurante WHERE id=$1', [req.params.id]);
    if (!prod) return res.status(404).json({ error: 'Producto no encontrado' });
    await db.query(
      'UPDATE menu_restaurante SET nombre=$1,categoria=$2,precio=$3,disponible=$4,es_bebida=$5 WHERE id=$6',
      [
        nombre     !== undefined ? nombre     : prod.nombre,
        categoria  !== undefined ? categoria  : prod.categoria,
        precio     !== undefined ? precio     : prod.precio,
        disponible !== undefined ? disponible : prod.disponible,
        es_bebida  !== undefined ? (es_bebida?1:0) : prod.es_bebida,
        req.params.id
      ]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/restaurante/menu/:id', auth, async (req, res) => {
  try {
    if (!['admin','cajero'].includes(req.user.rol)) return res.status(403).json({ error: 'Sin permisos' });
    await db.query('DELETE FROM menu_restaurante WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── COMANDAS ─────────────────────────────────────────────────────────
app.get('/api/restaurante/comandas', auth, authRestaurante, async (req, res) => {
  try {
    const { estado, mozo_id } = req.query;
    let q = `SELECT c.*, m.alias as mesa_alias, m.tipo as mesa_tipo,
             u.nombre as mozo_nombre
             FROM comandas c
             LEFT JOIN mesas_restaurante m ON c.mesa_id=m.id
             LEFT JOIN usuarios u ON c.mozo_id=u.id`;
    const params = [];
    const wheres = [];
    if (estado) { wheres.push(`c.estado=$${params.length+1}`); params.push(estado); }
    else wheres.push(`c.estado IN ('abierta','cuenta')`);
    if (mozo_id) { wheres.push(`c.mozo_id=$${params.length+1}`); params.push(mozo_id); }
    if (wheres.length) q += ' WHERE ' + wheres.join(' AND ');
    q += ' ORDER BY c.abierta_at DESC';
    const comandas = await db.getAll(q, params);
    for (const cmd of comandas) {
      cmd.items = await db.getAll(
        `SELECT ci.*, ci.precio as precio_unitario,
        COALESCE(m.categoria, ci.nota, '') as categoria
        FROM comanda_items ci
        LEFT JOIN menu_restaurante m ON ci.producto_id = m.id
        WHERE ci.comanda_id=$1 ORDER BY ci.id`,
        [cmd.id]
      );
    }
    res.json(comandas);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/restaurante/comandas/:id', auth, authRestaurante, async (req, res) => {
  try {
    const cmd = await db.getOne(
      `SELECT c.*, u.nombre as mozo_nombre
       FROM comandas c LEFT JOIN usuarios u ON c.mozo_id=u.id
       WHERE c.id=$1`, [req.params.id]
    );
    if (!cmd) return res.status(404).json({ error: 'Comanda no encontrada' });
    cmd.items = await db.getAll(
      `SELECT ci.*, ci.precio as precio_unitario,
        COALESCE(m.categoria, ci.nota, '') as categoria
        FROM comanda_items ci
        LEFT JOIN menu_restaurante m ON ci.producto_id = m.id
        WHERE ci.comanda_id=$1 ORDER BY ci.id`,
      [cmd.id]
    );
    res.json(cmd);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Abrir comanda
app.post('/api/restaurante/comandas', auth, authRestaurante, async (req, res) => {
  try {
    const { mesa_id, comensales, observaciones } = req.body;
    if (!mesa_id) return res.status(400).json({ error: 'Falta mesa_id' });
    // Verificar que la mesa esté libre
    const mesa = await db.getOne('SELECT * FROM mesas_restaurante WHERE id=$1', [mesa_id]);
    if (!mesa) return res.status(404).json({ error: 'Mesa no encontrada' });
    if (mesa.status !== 'libre' && mesa.status !== 'reservada')
      return res.status(400).json({ error: `La mesa está ${mesa.status}` });
    const r = await db.query(
      'INSERT INTO comandas (mesa_id,mozo_id,mozo_nombre,comensales,observaciones) VALUES ($1,$2,$3,$4,$5) RETURNING *',
      [mesa_id, req.user.id, req.user.nombre, comensales||0, observaciones||'']
    );
    await db.query("UPDATE mesas_restaurante SET status='ocupada',updated_at=NOW() WHERE id=$1", [mesa_id]);
    await logAction(req.user.id, req.user.nombre, 'ABRIR_COMANDA', `Mesa ${mesa_id}`);
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Agregar ítem a comanda (acumula cantidad si el producto ya existe)
app.post('/api/restaurante/comandas/:id/items', auth, authRestaurante, async (req, res) => {
  try {
    const { producto_id, cantidad, nota } = req.body;
    const cmd = await db.getOne('SELECT * FROM comandas WHERE id=$1', [req.params.id]);
    if (!cmd) return res.status(404).json({ error: 'Comanda no encontrada' });
    if (cmd.estado === 'cerrada') return res.status(400).json({ error: 'La comanda está cerrada' });
    const prod = await db.getOne('SELECT * FROM menu_restaurante WHERE id=$1', [producto_id]);
    if (!prod) return res.status(404).json({ error: 'Producto no encontrado' });

    // Si ya existe el mismo producto (y misma nota), incrementar cantidad
    const itemExistente = await db.getOne(
      `SELECT * FROM comanda_items
       WHERE comanda_id=$1 AND producto_id=$2 AND COALESCE(nota,'')=COALESCE($3,'')`,
      [cmd.id, producto_id, nota||'']
    );

    let item;
    if (itemExistente) {
      const r = await db.query(
        'UPDATE comanda_items SET cantidad=cantidad+$1 WHERE id=$2 RETURNING *',
        [cantidad||1, itemExistente.id]
      );
      item = r.rows[0];
    } else {
      const r = await db.query(
        'INSERT INTO comanda_items (comanda_id,producto_id,nombre,precio,cantidad,nota) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
        [cmd.id, producto_id, prod.nombre, prod.precio, cantidad||1, nota||'']
      );
      item = r.rows[0];
    }

    // Recalcular total
    const tot = await db.getOne('SELECT SUM(precio*cantidad) as t FROM comanda_items WHERE comanda_id=$1', [cmd.id]);
    await db.query('UPDATE comandas SET total=$1 WHERE id=$2', [tot.t||0, cmd.id]);

    // Descontar stock si el producto tiene vinculo con inventario
    if (prod.es_bebida && prod.id) {
      const invProd = await db.getOne('SELECT * FROM productos WHERE menu_id=$1 AND activo=1', [prod.id]);
      if (invProd) {
        const cant = (itemExistente ? cantidad||1 : cantidad||1);
        const stockAntes = Number(invProd.stock)||0;
        const stockDespues = Math.max(0, stockAntes - cant);
        await db.query('UPDATE productos SET stock=$1 WHERE id=$2', [stockDespues, invProd.id]);
        await db.query(
          `INSERT INTO inventario_movimientos (producto_id,tipo,cantidad,motivo,referencia,usuario_id,usuario_nombre,stock_antes,stock_despues)
           VALUES ($1,'consumo',$2,'Consumo comanda','Comanda #'||$3,$4,$5,$6,$7)`,
          [invProd.id, cant, cmd.id, req.user.id, req.user.nombre, stockAntes, stockDespues]
        );
      }
    }

    res.json(item);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Cancelar comanda (solo si está vacía) — libera la mesa
app.delete('/api/restaurante/comandas/:id', auth, authRestaurante, async (req, res) => {
  try {
    const cmd = await db.getOne('SELECT * FROM comandas WHERE id=$1', [req.params.id]);
    if (!cmd) return res.status(404).json({ error: 'Comanda no encontrada' });
    const items = await db.getOne('SELECT COUNT(*) as n FROM comanda_items WHERE comanda_id=$1', [cmd.id]);
    if (Number(items.n) > 0) return res.status(400).json({ error: 'No podés cancelar una comanda con ítems' });
    await db.query('DELETE FROM comandas WHERE id=$1', [cmd.id]);
    await db.query("UPDATE mesas_restaurante SET status='libre', updated_at=NOW() WHERE id=$1", [cmd.mesa_id]);
    await logAction(req.user.id, req.user.nombre, 'CANCELAR_COMANDA', `Mesa ${cmd.mesa_id}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Quitar ítem (resta 1; elimina la fila si llega a 0)
app.delete('/api/restaurante/comandas/:id/items/:itemId', auth, authRestaurante, async (req, res) => {
  try {
    const item = await db.getOne('SELECT * FROM comanda_items WHERE id=$1 AND comanda_id=$2',
      [req.params.itemId, req.params.id]);
    if (!item) return res.status(404).json({ error: 'Ítem no encontrado' });

    if (item.cantidad > 1) {
      await db.query('UPDATE comanda_items SET cantidad=cantidad-1 WHERE id=$1', [item.id]);
    } else {
      await db.query('DELETE FROM comanda_items WHERE id=$1', [item.id]);
    }

    // Recalcular total (0 si no quedan ítems)
    const tot = await db.getOne('SELECT COALESCE(SUM(precio*cantidad),0) as t FROM comanda_items WHERE comanda_id=$1', [req.params.id]);
    await db.query('UPDATE comandas SET total=$1 WHERE id=$2', [tot.t, req.params.id]);

    // Si no quedan ítems, NO liberamos la mesa automáticamente — el mozo debe cancelar explícitamente
    // (puede que estén por agregar más ítems)
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Marcar ítem entregado
app.put('/api/restaurante/comandas/:id/items/:itemId', auth, authRestaurante, async (req, res) => {
  try {
    await db.query('UPDATE comanda_items SET entregado=$1 WHERE id=$2 AND comanda_id=$3',
      [req.body.entregado ? 1 : 0, req.params.itemId, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Pedir cuenta
app.put('/api/restaurante/comandas/:id/cuenta', auth, authRestaurante, async (req, res) => {
  try {
    const cmd = await db.getOne('SELECT * FROM comandas WHERE id=$1', [req.params.id]);
    if (!cmd) return res.status(404).json({ error: 'Comanda no encontrada' });
    await db.query("UPDATE comandas SET estado='cuenta' WHERE id=$1", [cmd.id]);
    await db.query("UPDATE mesas_restaurante SET status='cuenta',updated_at=NOW() WHERE id=$1", [cmd.mesa_id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Cerrar/cobrar comanda
app.put('/api/restaurante/comandas/:id/cerrar', auth, authRestaurante, async (req, res) => {
  try {
    const { metodo_pago, descuento, monto_recibido } = req.body;
    const cmd = await db.getOne('SELECT * FROM comandas WHERE id=$1', [req.params.id]);
    if (!cmd) return res.status(404).json({ error: 'Comanda no encontrada' });
    if (cmd.estado === 'cerrada') return res.status(400).json({ error: 'Ya está cerrada' });
    const desc = descuento || 0;
    const totalFinal = cmd.total * (1 - desc / 100);
    const esEfectivo = (metodo_pago || 'Efectivo') === 'Efectivo';
    const montoRec = esEfectivo ? (Number(monto_recibido) || totalFinal) : totalFinal;
    const vuelto = esEfectivo ? Math.max(0, montoRec - totalFinal) : 0;
    await db.query(
      `UPDATE comandas SET estado='cerrada',metodo_pago=$1,descuento=$2,total_final=$3,
       cajero_id=$4,cajero_nombre=$5,cerrada_at=NOW(),monto_recibido=$6,vuelto=$7 WHERE id=$8`,
      [metodo_pago||'Efectivo', desc, totalFinal, req.user.id, req.user.nombre, montoRec, vuelto, cmd.id]
    );
    await db.query("UPDATE mesas_restaurante SET status='libre',updated_at=NOW() WHERE id=$1", [cmd.mesa_id]);
    await logAction(req.user.id, req.user.nombre, 'CERRAR_COMANDA', `Mesa ${cmd.mesa_id} - $${totalFinal}`);
    res.json({ ok: true, total_final: totalFinal, vuelto });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Cambiar mesa
app.put('/api/restaurante/comandas/:id/cambiar-mesa', auth, authRestaurante, async (req, res) => {
  try {
    const { nueva_mesa_id } = req.body;
    const cmd = await db.getOne('SELECT * FROM comandas WHERE id=$1', [req.params.id]);
    if (!cmd) return res.status(404).json({ error: 'Comanda no encontrada' });
    const nuevaMesa = await db.getOne('SELECT * FROM mesas_restaurante WHERE id=$1', [nueva_mesa_id]);
    if (!nuevaMesa || nuevaMesa.status !== 'libre') return res.status(400).json({ error: 'Mesa destino no disponible' });
    // Liberar mesa anterior
    await db.query("UPDATE mesas_restaurante SET status='libre',updated_at=NOW() WHERE id=$1", [cmd.mesa_id]);
    // Ocupar mesa nueva
    await db.query("UPDATE mesas_restaurante SET status='ocupada',updated_at=NOW() WHERE id=$1", [nueva_mesa_id]);
    // Actualizar comanda
    await db.query('UPDATE comandas SET mesa_id=$1 WHERE id=$2', [nueva_mesa_id, cmd.id]);
    await logAction(req.user.id, req.user.nombre, 'CAMBIO_MESA', `Comanda ${cmd.id}: mesa ${cmd.mesa_id}→${nueva_mesa_id}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── TURNO CAJA RESTAURANTE ───────────────────────────────────────────
app.get('/api/restaurante/turno/activo', auth, authRestaurante, async (req, res) => {
  try {
    const turno = await db.getOne("SELECT * FROM turnos_restaurante WHERE estado='abierto' ORDER BY id DESC LIMIT 1");
    if (!turno) return res.json(null);
    const cerradas = await db.getAll(
      "SELECT * FROM comandas WHERE estado='cerrada' AND cerrada_at >= $1 ORDER BY cerrada_at DESC",
      [turno.abierto_at]
    );
    for (const c of cerradas) {
      c.items = await db.getAll('SELECT * FROM comanda_items WHERE comanda_id=$1', [c.id]);
    }
    const retiros = await db.getAll(
      "SELECT * FROM caja_retiros WHERE turno_id=$1 ORDER BY created_at DESC",
      [turno.id]
    );
    res.json({ ...turno, cerradas, retiros });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/restaurante/turno/ultimo', auth, authRestaurante, async (req, res) => {
  try {
    const turno = await db.getOne('SELECT * FROM turnos_restaurante ORDER BY id DESC LIMIT 1');
    if (!turno) return res.json(null);
    const cerradas = await db.getAll(
      "SELECT c.*, u.nombre as mozo_nombre FROM comandas c LEFT JOIN usuarios u ON c.mozo_id=u.id WHERE c.estado='cerrada' AND c.cerrada_at >= $1 ORDER BY c.cerrada_at DESC",
      [turno.abierto_at]
    );
    const retiros = await db.getAll(
      "SELECT * FROM caja_retiros WHERE turno_id=$1 ORDER BY created_at DESC",
      [turno.id]
    );
    res.json({ ...turno, cerradas, retiros });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Registrar retiro de caja
app.post('/api/restaurante/turno/retiro', auth, authRestaurante, async (req, res) => {
  try {
    const { monto, motivo } = req.body;
    if (!monto || monto <= 0) return res.status(400).json({ error: 'Monto inválido' });
    const turno = await db.getOne("SELECT * FROM turnos_restaurante WHERE estado='abierto' ORDER BY id DESC LIMIT 1");
    if (!turno) return res.status(400).json({ error: 'No hay turno abierto' });
    await db.query(
      `INSERT INTO caja_retiros (turno_id, monto, motivo, usuario_id, usuario_nombre)
       VALUES ($1,$2,$3,$4,$5)`,
      [turno.id, monto, motivo||'Sin motivo', req.user.id, req.user.nombre]
    );
    await logAction(req.user.id, req.user.nombre, 'RETIRO_CAJA', `$${monto} — ${motivo||'Sin motivo'}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/restaurante/turno/abrir', auth, authRestaurante, async (req, res) => {
  try {
    const ya = await db.getOne("SELECT id FROM turnos_restaurante WHERE estado='abierto'");
    if (ya) return res.status(400).json({ error: 'Ya hay un turno abierto' });
    const r = await db.query(
      'INSERT INTO turnos_restaurante (cajero_id,cajero_nombre,fondo_inicial) VALUES ($1,$2,$3) RETURNING *',
      [req.user.id, req.user.nombre, req.body.fondo_inicial||0]
    );
    await logAction(req.user.id, req.user.nombre, 'ABRIR_TURNO_REST', `Fondo: $${req.body.fondo_inicial||0}`);
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/restaurante/turno/cerrar', auth, authRestaurante, async (req, res) => {
  try {
    const turno = await db.getOne("SELECT * FROM turnos_restaurante WHERE estado='abierto' ORDER BY id DESC LIMIT 1");
    if (!turno) return res.status(400).json({ error: 'No hay turno abierto' });
    await db.query("UPDATE turnos_restaurante SET estado='cerrado',cerrado_at=NOW() WHERE id=$1", [turno.id]);
    // Resumen final
    const cerradas = await db.getAll(
      "SELECT metodo_pago, SUM(total_final) as total, COUNT(*) as cantidad FROM comandas WHERE estado='cerrada' AND cerrada_at >= $1 GROUP BY metodo_pago",
      [turno.abierto_at]
    );
    const totalCobrado = cerradas.reduce((s,c) => s+parseFloat(c.total||0), 0);
    await logAction(req.user.id, req.user.nombre, 'CERRAR_TURNO_REST', `Total: $${totalCobrado}`);
    res.json({ ok: true, total_cobrado: totalCobrado, por_metodo: cerradas });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── RESERVAS RESTAURANTE ─────────────────────────────────────────────
app.get('/api/restaurante/reservas', auth, authRestaurante, async (req, res) => {
  try {
    const fecha = req.query.fecha || new Date().toISOString().split('T')[0];
    res.json(await db.getAll(
      "SELECT r.*,m.alias as mesa_alias FROM reservas_restaurante r LEFT JOIN mesas_restaurante m ON r.mesa_id=m.id WHERE r.fecha=$1 AND r.estado='activa' ORDER BY r.hora",
      [fecha]
    ));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/restaurante/reservas', auth, authRestaurante, async (req, res) => {
  try {
    const { mesa_id, nombre, hora, personas, telefono, notas, fecha } = req.body;
    if (!nombre || !hora) return res.status(400).json({ error: 'Nombre y hora requeridos' });
    const r = await db.query(
      'INSERT INTO reservas_restaurante (mesa_id,nombre,hora,personas,telefono,notas,fecha) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [mesa_id||null, nombre, hora, personas||1, telefono||'', notas||'', fecha||new Date().toISOString().split('T')[0]]
    );
    if (mesa_id) await db.query("UPDATE mesas_restaurante SET status='reservada',updated_at=NOW() WHERE id=$1", [mesa_id]);
    await logAction(req.user.id, req.user.nombre, 'RESERVA_REST', `${nombre} - ${hora}`);
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/restaurante/reservas/:id', auth, authRestaurante, async (req, res) => {
  try {
    const { estado } = req.body;
    const res_ = await db.getOne('SELECT * FROM reservas_restaurante WHERE id=$1', [req.params.id]);
    await db.query('UPDATE reservas_restaurante SET estado=$1 WHERE id=$2', [estado, req.params.id]);
    if (estado === 'cancelada' && res_?.mesa_id) {
      await db.query("UPDATE mesas_restaurante SET status='libre',updated_at=NOW() WHERE id=$1 AND status='reservada'", [res_.mesa_id]);
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── USUARIOS RESTAURANTE (para admin crear mozo/cajero) ──────────────
app.post('/api/restaurante/usuarios', auth, adminOnly, async (req, res) => {
  try {
    const { nombre, email, password, rol } = req.body;
    if (!nombre || !email || !password) return res.status(400).json({ error: 'Datos incompletos' });
    if (!['mozo','cajero','admin'].includes(rol)) return res.status(400).json({ error: 'Rol inválido para restaurante' });
    const hash = bcrypt.hashSync(password, 10);
    const r = await db.query(
      'INSERT INTO usuarios (nombre,email,password,rol) VALUES ($1,$2,$3,$4) RETURNING id',
      [nombre, email, hash, rol]
    );
    await logAction(req.user.id, req.user.nombre, 'CREAR_USUARIO_REST', `${nombre} (${rol})`);
    res.json({ id: r.rows[0].id });
  } catch(e) {
    if (e.message.includes('unique')) return res.status(400).json({ error: 'El email ya existe' });
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/restaurante/usuarios', auth, adminOnly, async (req, res) => {
  try {
    res.json(await db.getAll(
      "SELECT id,nombre,email,rol,activo FROM usuarios WHERE rol IN ('mozo','cajero','admin') ORDER BY nombre"
    ));
  } catch(e) { res.status(500).json({ error: e.message }); }
});
// ── LOGIN UNIFICADO (portal) ─────────────────────────────────────────
app.post('/api/portal/login', async (req, res) => {
  try {
    const { usuario, clave } = req.body;
    if (!usuario || !clave)
      return res.status(400).json({ error: 'Completá usuario y contraseña' });
 
    // Buscar por: campo usuario, email, o nombre (en ese orden de prioridad)
    const user = await db.getOne(
      `SELECT * FROM usuarios
       WHERE activo = 1
         AND (
           usuario = $1
           OR email = $1
           OR LOWER(nombre) = LOWER($1)
         )
       LIMIT 1`,
      [usuario.trim()]
    );
 
    if (!user || !bcrypt.compareSync(clave, user.password))
      return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
 
    const token = jwt.sign(
      { id: user.id, nombre: user.nombre, rol: user.rol, email: user.email },
      JWT_SECRET,
      { expiresIn: '12h' }
    );
 
    await logAction(user.id, user.nombre, 'LOGIN_PORTAL', `rol: ${user.rol}`);
 
    res.json({
      token,
      user: {
        id:     user.id,
        nombre: user.nombre,
        usuario: user.usuario || user.email,
        rol:    user.rol,
        email:  user.email,
      }
    });
  } catch(e) {
    console.error('Portal login error:', e);
    res.status(500).json({ error: e.message });
  }
});
 
// ── GET perfil del usuario autenticado ──────────────────────────────
app.get('/api/portal/me', auth, async (req, res) => {
  try {
    const user = await db.getOne(
      'SELECT id, nombre, usuario, email, rol FROM usuarios WHERE id = $1',
      [req.user.id]
    );
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json(user);
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});
 
// ── GESTIÓN DE USUARIOS (solo admin) ────────────────────────────────
 
// Listar todos
app.get('/api/portal/usuarios', auth, adminOnly, async (req, res) => {
  try {
    const users = await db.getAll(
      'SELECT id, nombre, usuario, email, rol, activo FROM usuarios ORDER BY rol, nombre'
    );
    res.json(users);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// Crear usuario
app.post('/api/portal/usuarios', auth, adminOnly, async (req, res) => {
  try {
    const { nombre, usuario, email, password, rol } = req.body;
    if (!nombre || !password || !rol)
      return res.status(400).json({ error: 'Faltan campos obligatorios (nombre, password, rol)' });
 
    // usuario o email como identificador único
    const identificador = usuario?.trim() || email?.trim();
    if (!identificador)
      return res.status(400).json({ error: 'Se requiere usuario o email' });
 
    // Verificar duplicado
    const existe = await db.getOne(
      'SELECT id FROM usuarios WHERE usuario = $1 OR email = $1',
      [identificador]
    );
    if (existe) return res.status(400).json({ error: 'Ese usuario o email ya existe' });
 
    const hash = bcrypt.hashSync(password, 10);
    const r = await db.query(
      `INSERT INTO usuarios (nombre, usuario, email, password, rol, activo)
       VALUES ($1, $2, $3, $4, $5, 1) RETURNING id, nombre, usuario, email, rol`,
      [nombre.trim(), usuario?.trim() || null, email?.trim() || null, hash, rol]
    );
    await logAction(req.user.id, req.user.nombre, 'CREAR_USUARIO', `${nombre} (${rol})`);
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// Editar usuario
app.put('/api/portal/usuarios/:id', auth, adminOnly, async (req, res) => {
  try {
    const { nombre, usuario, email, password, rol, activo } = req.body;
    const uid = req.params.id;
 
    let query, params;
    if (password) {
      const hash = bcrypt.hashSync(password, 10);
      query = `UPDATE usuarios SET nombre=$1, usuario=$2, email=$3, password=$4, rol=$5, activo=$6 WHERE id=$7`;
      params = [nombre, usuario||null, email||null, hash, rol, activo ?? 1, uid];
    } else {
      query = `UPDATE usuarios SET nombre=$1, usuario=$2, email=$3, rol=$4, activo=$5 WHERE id=$6`;
      params = [nombre, usuario||null, email||null, rol, activo ?? 1, uid];
    }
    await db.query(query, params);
    await logAction(req.user.id, req.user.nombre, 'EDITAR_USUARIO', `id:${uid}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
// Eliminar (desactivar) usuario
app.delete('/api/portal/usuarios/:id', auth, adminOnly, async (req, res) => {
  try {
    const uid = req.params.id;
    if (Number(uid) === req.user.id) return res.status(400).json({ error: 'No podés eliminarte a vos mismo' });
    await db.query('UPDATE usuarios SET activo=0 WHERE id=$1', [uid]);
    await logAction(req.user.id, req.user.nombre, 'ELIMINAR_USUARIO', `id:${uid}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════════
// ── ALIASES FRONTEND ─────────────────────────────────────────────────
// El frontend usa POST /cerrar y PUT /pedir-cuenta
// ════════════════════════════════════════════════════════════════════

// POST /cerrar (alias de PUT /cerrar)
app.post('/api/restaurante/comandas/:id/cerrar', auth, authRestaurante, async (req, res) => {
  try {
    const { metodo_pago, descuento } = req.body;
    const cmd = await db.getOne('SELECT * FROM comandas WHERE id=$1', [req.params.id]);
    if (!cmd) return res.status(404).json({ error: 'Comanda no encontrada' });
    if (cmd.estado === 'cerrada') return res.status(400).json({ error: 'Ya está cerrada' });
    const desc = Number(descuento) || 0;
    const totalFinal = Number(cmd.total) * (1 - desc / 100);
    await db.query(
      `UPDATE comandas SET estado='cerrada', metodo_pago=$1, descuento=$2, total_final=$3,
       cajero_id=$4, cajero_nombre=$5, cerrada_at=NOW() WHERE id=$6`,
      [metodo_pago || 'Efectivo', desc, totalFinal, req.user.id, req.user.nombre, cmd.id]
    );
    await db.query("UPDATE mesas_restaurante SET status='libre', updated_at=NOW() WHERE id=$1", [cmd.mesa_id]);
    await logAction(req.user.id, req.user.nombre, 'CERRAR_COMANDA', `Mesa ${cmd.mesa_id} - $${totalFinal}`);
    res.json({ ok: true, total_final: totalFinal });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Ítem extra (fuera de menú, lo agrega el cajero al cobrar)
app.post('/api/restaurante/comandas/:id/items/extra', auth, authRestaurante, async (req, res) => {
  try {
    const { nombre, precio } = req.body;
    if (!nombre || !precio) return res.status(400).json({ error: 'Faltan nombre y precio' });
    const cmd = await db.getOne('SELECT * FROM comandas WHERE id=$1', [req.params.id]);
    if (!cmd) return res.status(404).json({ error: 'Comanda no encontrada' });
    // Insertar como ítem sin producto_id
    await db.query(
      'INSERT INTO comanda_items (comanda_id, producto_id, nombre, precio, cantidad, nota) VALUES ($1, NULL, $2, $3, 1, $4)',
      [cmd.id, nombre.trim(), Number(precio), 'ítem extra']
    );
    // Recalcular total
    const tot = await db.getOne('SELECT SUM(precio*cantidad) as t FROM comanda_items WHERE comanda_id=$1', [cmd.id]);
    await db.query('UPDATE comandas SET total=$1 WHERE id=$2', [tot.t||0, cmd.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// PUT /observaciones
app.put('/api/restaurante/comandas/:id/observaciones', auth, authRestaurante, async (req, res) => {
  try {
    const { observaciones } = req.body;
    await db.query('UPDATE comandas SET observaciones=$1 WHERE id=$2', [observaciones||'', req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// PUT /pedir-cuenta (alias de PUT /cuenta)
app.put('/api/restaurante/comandas/:id/pedir-cuenta', auth, authRestaurante, async (req, res) => {
  try {
    const cmd = await db.getOne('SELECT * FROM comandas WHERE id=$1', [req.params.id]);
    if (!cmd) return res.status(404).json({ error: 'Comanda no encontrada' });
    await db.query("UPDATE comandas SET estado='cuenta' WHERE id=$1", [cmd.id]);
    await db.query("UPDATE mesas_restaurante SET status='cuenta', updated_at=NOW() WHERE id=$1", [cmd.mesa_id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ════════════════════════════════════════════════════════════════════
// ── LIBRO DE NOVEDADES ──────────────────────────────────────────────
app.get('/api/libro-novedades', auth, async (req, res) => {
  try {
    // Últimos 7 días
    const rows = await db.getAll(
      `SELECT * FROM libro_novedades
       WHERE created_at >= NOW() - INTERVAL '7 days'
       ORDER BY created_at ASC`
    );
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/libro-novedades', auth, async (req, res) => {
  try {
    const { mensaje, tipo, habitacion_id } = req.body;
    if (!mensaje) return res.status(400).json({ error: 'Mensaje requerido' });
    // Solo mucamas pueden escribir mensajes manuales
    if (tipo === 'manual' && !['mucama','admin'].includes(req.user.rol))
      return res.status(403).json({ error: 'Sin permisos para escribir en el libro' });
    await db.query(
      `INSERT INTO libro_novedades (tipo, usuario_id, usuario_nombre, usuario_rol, habitacion_id, mensaje)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [tipo||'auto', req.user.id, req.user.nombre, req.user.rol, habitacion_id||'', mensaje]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── CAJA HABITACIONES ────────────────────────────────────────────────
app.get('/api/caja-hab/turno/activo', auth, async (req, res) => {
  try {
    const t = await db.getOne("SELECT * FROM turnos_habitaciones WHERE estado='abierto' ORDER BY id DESC LIMIT 1");
    if (!t) return res.json(null);
    const movs = await db.getAll("SELECT * FROM movimientos_habitaciones WHERE turno_id=$1 ORDER BY created_at DESC", [t.id]);
    res.json({ ...t, movimientos: movs });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/caja-hab/turno/ultimo', auth, async (req, res) => {
  try {
    const t = await db.getOne('SELECT * FROM turnos_habitaciones ORDER BY id DESC LIMIT 1');
    if (!t) return res.json(null);
    const movs = await db.getAll("SELECT * FROM movimientos_habitaciones WHERE turno_id=$1 ORDER BY created_at DESC", [t.id]);
    res.json({ ...t, movimientos: movs });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/caja-hab/turno/abrir', auth, adminOrRecep, async (req, res) => {
  try {
    const ya = await db.getOne("SELECT id FROM turnos_habitaciones WHERE estado='abierto'");
    if (ya) return res.status(400).json({ error: 'Ya hay un turno abierto' });
    const r = await db.query(
      "INSERT INTO turnos_habitaciones (cajero_id,cajero_nombre,fondo_inicial) VALUES ($1,$2,$3) RETURNING *",
      [req.user.id, req.user.nombre, req.body.fondo_inicial||0]
    );
    await logAction(req.user.id, req.user.nombre, 'ABRIR_TURNO_HAB', `Fondo: $${req.body.fondo_inicial||0}`);
    res.json(r.rows[0]);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/caja-hab/turno/cerrar', auth, adminOrRecep, async (req, res) => {
  try {
    const t = await db.getOne("SELECT * FROM turnos_habitaciones WHERE estado='abierto' ORDER BY id DESC LIMIT 1");
    if (!t) return res.status(400).json({ error: 'No hay turno abierto' });
    await db.query("UPDATE turnos_habitaciones SET estado='cerrado',cerrado_at=NOW() WHERE id=$1", [t.id]);
    await logAction(req.user.id, req.user.nombre, 'CERRAR_TURNO_HAB', `Turno #${t.id}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/caja-hab/movimiento', auth, adminOrRecep, async (req, res) => {
  try {
    const { tipo, concepto, monto, metodo_pago, referencia, habitacion_id, habitacion_numero } = req.body;
    const t = await db.getOne("SELECT * FROM turnos_habitaciones WHERE estado='abierto' ORDER BY id DESC LIMIT 1");
    if (!t) return res.status(400).json({ error: 'No hay turno abierto en habitaciones' });
    await db.query(
      `INSERT INTO movimientos_habitaciones (turno_id,tipo,concepto,monto,metodo_pago,referencia,usuario_id,usuario_nombre,habitacion_id,habitacion_numero)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [t.id, tipo||'ingreso', concepto||'', monto||0, metodo_pago||'Efectivo',
       referencia||'', req.user.id, req.user.nombre, habitacion_id||null, habitacion_numero||'']
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── CAJA GLOBAL (admin) ──────────────────────────────────────────────
app.get('/api/caja-global/resumen-dia', auth, adminOnly, async (req, res) => {
  try {
    const hoy = req.query.fecha || new Date().toISOString().split('T')[0];
    const desde = hoy + ' 00:00:00';
    const hasta  = hoy + ' 23:59:59';

    // Restaurante — comandas cerradas hoy
    const cmdHoy = await db.getAll(
      "SELECT metodo_pago, SUM(total_final) as total, COUNT(*) as cant FROM comandas WHERE estado='cerrada' AND cerrada_at BETWEEN $1 AND $2 GROUP BY metodo_pago",
      [desde, hasta]
    );
    // Restaurante — retiros hoy
    const retirosRest = await db.getAll(
      "SELECT SUM(monto) as total FROM caja_retiros WHERE created_at BETWEEN $1 AND $2",
      [desde, hasta]
    );
    // Habitaciones — movimientos hoy
    const movHab = await db.getAll(
      "SELECT tipo, metodo_pago, SUM(monto) as total FROM movimientos_habitaciones WHERE created_at BETWEEN $1 AND $2 GROUP BY tipo, metodo_pago",
      [desde, hasta]
    );

    res.json({
      fecha: hoy,
      restaurante: { por_metodo: cmdHoy, retiros: Number(retirosRest[0]?.total||0) },
      habitaciones: { movimientos: movHab }
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/caja-global/historial', auth, adminOnly, async (req, res) => {
  try {
    const { desde, hasta, limit } = req.query;
    const lim = parseInt(limit)||200;
    const d = desde || new Date(Date.now() - 30*24*60*60*1000).toISOString().split('T')[0];
    const h = hasta  || new Date().toISOString().split('T')[0];

    // Comandas restaurante
    const cmds = await db.getAll(
      `SELECT 'restaurante' as fuente, 'ingreso' as tipo, total_final as monto,
              metodo_pago, concat('Mesa ', mesa_id) as concepto,
              cajero_nombre as usuario, cerrada_at as fecha
       FROM comandas WHERE estado='cerrada' AND cerrada_at BETWEEN $1 AND $2
       ORDER BY cerrada_at DESC LIMIT $3`,
      [d+' 00:00:00', h+' 23:59:59', lim]
    );
    // Retiros restaurante
    const retRest = await db.getAll(
      `SELECT 'restaurante' as fuente, 'egreso' as tipo, monto,
              'Efectivo' as metodo_pago, motivo as concepto,
              usuario_nombre as usuario, created_at as fecha
       FROM caja_retiros WHERE created_at BETWEEN $1 AND $2
       ORDER BY created_at DESC`,
      [d+' 00:00:00', h+' 23:59:59']
    );
    // Movimientos habitaciones
    const movHab = await db.getAll(
      `SELECT 'habitaciones' as fuente, tipo, monto, metodo_pago, concepto,
              usuario_nombre as usuario, created_at as fecha
       FROM movimientos_habitaciones WHERE created_at BETWEEN $1 AND $2
       ORDER BY created_at DESC`,
      [d+' 00:00:00', h+' 23:59:59']
    );

    // Unir y ordenar por fecha desc
    const todo = [...cmds, ...retRest, ...movHab]
      .sort((a,b) => new Date(b.fecha) - new Date(a.fecha));

    res.json({ desde: d, hasta: h, movimientos: todo });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/caja-global/reporte-periodo', auth, adminOnly, async (req, res) => {
  try {
    const { desde, hasta } = req.query;
    if (!desde||!hasta) return res.status(400).json({ error: 'Falta rango de fechas' });
    const d = desde+' 00:00:00', h = hasta+' 23:59:59';

    const [cmdTotal, retTotal, habIngresos, habEgresos] = await Promise.all([
      db.getAll("SELECT metodo_pago, SUM(total_final) as total, COUNT(*) as cant FROM comandas WHERE estado='cerrada' AND cerrada_at BETWEEN $1 AND $2 GROUP BY metodo_pago", [d,h]),
      db.getAll("SELECT SUM(monto) as total, COUNT(*) as cant FROM caja_retiros WHERE created_at BETWEEN $1 AND $2", [d,h]),
      db.getAll("SELECT metodo_pago, SUM(monto) as total, COUNT(*) as cant FROM movimientos_habitaciones WHERE tipo='ingreso' AND created_at BETWEEN $1 AND $2 GROUP BY metodo_pago", [d,h]),
      db.getAll("SELECT SUM(monto) as total, COUNT(*) as cant FROM movimientos_habitaciones WHERE tipo='egreso' AND created_at BETWEEN $1 AND $2", [d,h]),
    ]);

    // Resumen por día
    const porDia = await db.getAll(`
      SELECT dia, SUM(total) as total, fuente FROM (
        SELECT DATE(cerrada_at)::text as dia, SUM(total_final) as total, 'restaurante' as fuente
        FROM comandas WHERE estado='cerrada' AND cerrada_at BETWEEN $1 AND $2 GROUP BY DATE(cerrada_at)
        UNION ALL
        SELECT DATE(created_at)::text, SUM(monto), 'habitaciones'
        FROM movimientos_habitaciones WHERE tipo='ingreso' AND created_at BETWEEN $1 AND $2 GROUP BY DATE(created_at)
      ) t GROUP BY dia, fuente ORDER BY dia DESC
    `, [d,h]);

    res.json({
      restaurante: { por_metodo: cmdTotal, retiros: Number(retTotal[0]?.total||0) },
      habitaciones: { ingresos: habIngresos, egresos: Number(habEgresos[0]?.total||0) },
      por_dia: porDia
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Historial de turnos (restaurante + habitaciones)
app.get('/api/caja-global/turnos', auth, adminOnly, async (req, res) => {
  try {
    const { fuente } = req.query;
    if (fuente === 'restaurante') {
      const turnos = await db.getAll('SELECT * FROM turnos_restaurante ORDER BY id DESC LIMIT 50');
      // Calcular total cobrado y retiros por turno
      for (const t of turnos) {
        const cobrado = await db.getOne(
          "SELECT COALESCE(SUM(total_final),0) as total FROM comandas WHERE estado='cerrada' AND cerrada_at >= $1 AND ($2::timestamp IS NULL OR cerrada_at <= $2)",
          [t.abierto_at, t.cerrado_at||null]
        );
        const retiros = await db.getOne(
          "SELECT COALESCE(SUM(monto),0) as total FROM caja_retiros WHERE turno_id=$1",
          [t.id]
        );
        t.total_cobrado = Number(cobrado?.total||0);
        t.total_retiros = Number(retiros?.total||0);
        t.total_final   = t.total_cobrado + Number(t.fondo_inicial||0) - t.total_retiros;
      }
      res.json(turnos);
    } else {
      const turnos = await db.getAll('SELECT * FROM turnos_habitaciones ORDER BY id DESC LIMIT 50');
      for (const t of turnos) {
        const ingresos = await db.getOne(
          "SELECT COALESCE(SUM(monto),0) as total FROM movimientos_habitaciones WHERE turno_id=$1 AND tipo='ingreso'",
          [t.id]
        );
        const egresos = await db.getOne(
          "SELECT COALESCE(SUM(monto),0) as total FROM movimientos_habitaciones WHERE turno_id=$1 AND tipo='egreso'",
          [t.id]
        );
        t.total_cobrado = Number(ingresos?.total||0);
        t.total_retiros = Number(egresos?.total||0);
        t.total_final   = Number(t.fondo_inicial||0) + t.total_cobrado - t.total_retiros;
      }
      res.json(turnos);
    }
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Turno completo con comandas y retiros (para reimprimir arqueo)
app.get('/api/caja-global/turno-detalle', auth, adminOnly, async (req, res) => {
  try {
    const { id, fuente } = req.query;
    if (fuente === 'restaurante') {
      const turno = await db.getOne('SELECT * FROM turnos_restaurante WHERE id=$1', [id]);
      if (!turno) return res.status(404).json({ error: 'Turno no encontrado' });
      const cerradas = await db.getAll(
        `SELECT * FROM comandas WHERE estado='cerrada' AND cerrada_at >= $1
         AND ($2::timestamp IS NULL OR cerrada_at <= $2) ORDER BY cerrada_at DESC`,
        [turno.abierto_at, turno.cerrado_at||null]
      );
      const retiros = await db.getAll(
        'SELECT * FROM caja_retiros WHERE turno_id=$1 ORDER BY created_at',
        [id]
      );
      // Por método de pago
      const porMetodo = {};
      cerradas.forEach(c => {
        porMetodo[c.metodo_pago] = (porMetodo[c.metodo_pago]||0) + Number(c.total_final||0);
      });
      res.json({ ...turno, cerradas, retiros, porMetodo });
    } else {
      const turno = await db.getOne('SELECT * FROM turnos_habitaciones WHERE id=$1', [id]);
      if (!turno) return res.status(404).json({ error: 'Turno no encontrado' });
      const movimientos = await db.getAll(
        'SELECT * FROM movimientos_habitaciones WHERE turno_id=$1 ORDER BY created_at',
        [id]
      );
      const porMetodo = {};
      movimientos.filter(m=>m.tipo==='ingreso').forEach(m => {
        porMetodo[m.metodo_pago] = (porMetodo[m.metodo_pago]||0) + Number(m.monto||0);
      });
      res.json({ ...turno, movimientos, porMetodo });
    }
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Editar fondo inicial de un turno (solo admin)
app.put('/api/caja-global/turno-fondo', auth, adminOnly, async (req, res) => {
  try {
    const { turno_id, fuente, fondo_inicial } = req.body;
    const tabla = fuente === 'restaurante' ? 'turnos_restaurante' : 'turnos_habitaciones';
    await db.query(`UPDATE ${tabla} SET fondo_inicial=$1 WHERE id=$2`, [fondo_inicial, turno_id]);
    await logAction(req.user.id, req.user.nombre, 'EDITAR_FONDO', `${fuente} turno #${turno_id}: $${fondo_inicial}`);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── PUSH NOTIFICATIONS ───────────────────────────────────────────────

// Devolver la VAPID public key al frontend
app.get('/api/push/vapid-public', (req, res) => {
  res.json({ publicKey: VAPID_PUBLIC });
});

// Suscribir dispositivo
app.post('/api/push/suscribir', auth, async (req, res) => {
  try {
    const { endpoint, keys } = req.body;
    if (!endpoint || !keys?.p256dh || !keys?.auth)
      return res.status(400).json({ error: 'Datos de suscripción incompletos' });
    // Usar endpoint+usuario_id como clave única — mismo celular, distintos usuarios
    await db.query(
      `INSERT INTO push_suscripciones (usuario_id, usuario_nombre, rol, endpoint, p256dh, auth)
       VALUES ($1,$2,$3,$4,$5,$6)
       ON CONFLICT (endpoint, usuario_id) DO UPDATE SET
         usuario_nombre=$2, rol=$3, p256dh=$5, auth=$6`,
      [req.user.id, req.user.nombre, req.user.rol, endpoint, keys.p256dh, keys.auth]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// Desuscribir dispositivo
app.post('/api/push/desuscribir', auth, async (req, res) => {
  try {
    await db.query('DELETE FROM push_suscripciones WHERE usuario_id=$1', [req.user.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── CATCH-ALL ────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// ── RESET DIARIO 8 AM ────────────────────────────────
function scheduleReset() {
  const now = new Date();
  const next8am = new Date();
  next8am.setHours(8, 0, 0, 0);
  if (now >= next8am) next8am.setDate(next8am.getDate() + 1);
  const msUntil = next8am - now;
  console.log(`⏰ Reset diario en ${Math.round(msUntil/1000/60)} minutos`);
  setTimeout(async () => {
    try {
      const result = await db.query("UPDATE habitaciones SET status='ocupada',updated_at=NOW() WHERE status='limpia'");
      console.log(`⏰ Reset 8 AM: ${result.rowCount||0} habitaciones limpia→ocupada`);
      await db.query("INSERT INTO log_acciones (usuario_nombre,accion,detalle) VALUES ($1,$2,$3)",
        ['Sistema','RESET_DIARIO',`${result.rowCount||0} hab. limpia→ocupada`]);
    } catch(e) { console.error('Error reset diario:', e.message); }
    scheduleReset();
  }, msUntil);
}

db.initDB().then(() => {
  app.listen(PORT, () => console.log(`🏨 Hotel Takuá corriendo en puerto ${PORT}`));
  scheduleReset();
}).catch(e => {
  console.error('Error iniciando DB:', e);
  process.exit(1);
});
