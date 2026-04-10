var express = require('express');
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
var cors = require('cors');
var path = require('path');
var db = require('./database');
 
var app = express();
var PORT = process.env.PORT || 3000;
var JWT_SECRET = process.env.JWT_SECRET || 'takua_secret_2024_changeme';
 
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
 
function auth(req, res, next) {
  var token = req.headers.authorization && req.headers.authorization.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Sin autorizacion' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch(e) { res.status(401).json({ error: 'Token invalido' }); }
}
function adminOnly(req, res, next) {
  if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Solo administradores' });
  next();
}
function logAction(userId, userName, accion, detalle) {
  try { db.prepare('INSERT INTO log_acciones (usuario_id,usuario_nombre,accion,detalle) VALUES (?,?,?,?)').run(userId, userName, accion, detalle||''); }
  catch(e) { console.error('Log error:', e.message); }
}
 
// ── LOGIN ──
app.post('/api/login', function(req, res) {
  try {
    var email = req.body.email, password = req.body.password;
    if (!email || !password) return res.status(400).json({ error: 'Datos incompletos' });
    var user = db.prepare('SELECT * FROM usuarios WHERE email = ? AND activo = 1').get(email);
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'Email o contrasena incorrectos' });
    var token = jwt.sign({ id: user.id, nombre: user.nombre, rol: user.rol }, JWT_SECRET, { expiresIn: '12h' });
    logAction(user.id, user.nombre, 'LOGIN', '');
    res.json({ token: token, user: { id: user.id, nombre: user.nombre, rol: user.rol, email: user.email } });
  } catch(e) { console.error('Login error:', e); res.status(500).json({ error: e.message }); }
});
 
// ── USUARIOS ──
app.get('/api/usuarios', auth, adminOnly, function(req, res) {
  try { res.json(db.prepare('SELECT id,nombre,email,rol,activo,created_at FROM usuarios').all()); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/usuarios', auth, adminOnly, function(req, res) {
  try {
    var nombre = req.body.nombre, email = req.body.email, password = req.body.password, rol = req.body.rol;
    if (!nombre || !email || !password) return res.status(400).json({ error: 'Datos incompletos' });
    var hash = bcrypt.hashSync(password, 10);
    var result = db.prepare('INSERT INTO usuarios (nombre,email,password,rol) VALUES (?,?,?,?)').run(nombre, email, hash, rol||'recepcionista');
    logAction(req.user.id, req.user.nombre, 'CREAR_USUARIO', nombre);
    res.json({ id: result.lastInsertRowid });
  } catch(e) {
    if (e.message.indexOf('UNIQUE') >= 0) return res.status(400).json({ error: 'El email ya existe' });
    res.status(500).json({ error: e.message });
  }
});
app.put('/api/usuarios/:id', auth, adminOnly, function(req, res) {
  try {
    var nombre = req.body.nombre, email = req.body.email, rol = req.body.rol, activo = req.body.activo, password = req.body.password;
    if (password) {
      db.prepare('UPDATE usuarios SET nombre=?,email=?,rol=?,activo=?,password=? WHERE id=?').run(nombre,email,rol,activo,bcrypt.hashSync(password,10),req.params.id);
    } else {
      db.prepare('UPDATE usuarios SET nombre=?,email=?,rol=?,activo=? WHERE id=?').run(nombre,email,rol,activo,req.params.id);
    }
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── HABITACIONES ──
app.get('/api/habitaciones', auth, function(req, res) {
  try { res.json(db.prepare('SELECT * FROM habitaciones ORDER BY ala, numero').all()); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/habitaciones/:id/status', auth, function(req, res) {
  try {
    var status = req.body.status, nota = req.body.nota;
    var hab = db.prepare('SELECT * FROM habitaciones WHERE id = ?').get(req.params.id);
    if (!hab) return res.status(404).json({ error: 'Habitacion no encontrada: ' + req.params.id });
    db.prepare('UPDATE habitaciones SET status=?,nota=?,updated_at=datetime(?) WHERE id=?')
      .run(status, nota !== undefined ? nota : hab.nota, 'now,localtime', req.params.id);
    logAction(req.user.id, req.user.nombre, 'CAMBIO_STATUS', 'Hab '+req.params.id+': '+hab.status+'->'+status);
    res.json({ ok: true });
  } catch(e) { console.error('Status error:', e); res.status(500).json({ error: e.message }); }
});
app.put('/api/habitaciones/:id', auth, function(req, res) {
  try {
    var nombre = req.body.nombre, tipo = req.body.tipo, capacidad = req.body.capacidad;
    var precio_noche = req.body.precio_noche, precio_hora = req.body.precio_hora;
    db.prepare('UPDATE habitaciones SET nombre=?,tipo=?,capacidad=?,precio_noche=?,precio_hora=? WHERE id=?')
      .run(nombre||'', tipo, capacidad, precio_noche, precio_hora, req.params.id);
    logAction(req.user.id, req.user.nombre, 'EDITAR_HAB', 'Hab '+req.params.id+': '+nombre);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── DEBUG ──
app.get('/api/debug/habitaciones', function(req, res) {
  try {
    var habs = db.prepare('SELECT id,numero,ala,status,tipo FROM habitaciones ORDER BY ala,numero').all();
    res.json({ total: habs.length, habitaciones: habs });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── SERVICIO DE HABITACION (mucama) ──
// Registrar servicio diario o limpieza post-checkout
app.post('/api/servicios', auth, function(req, res) {
  try {
    var habitacion_id = req.body.habitacion_id;
    var tipo_servicio = req.body.tipo_servicio || 'limpieza_diaria';
    var tipo_cama = req.body.tipo_cama || '';
    var necesita_mantenimiento = req.body.necesita_mantenimiento ? 1 : 0;
    var nota_mantenimiento = req.body.nota_mantenimiento || '';
    var consumos = req.body.consumos || [];
    var nuevo_status = req.body.nuevo_status || 'limpia';
 
    var hab = db.prepare('SELECT * FROM habitaciones WHERE id = ?').get(habitacion_id);
    if (!hab) return res.status(404).json({ error: 'Habitacion no encontrada' });
 
    // Calcular total consumos y descontar stock
    var total_consumos = 0;
    var consumosStr = '[]';
 
    if (consumos.length > 0) {
      var consumosCompletos = [];
      var descStock = db.transaction(function() {
        consumos.forEach(function(c) {
          var prod = db.prepare('SELECT * FROM productos WHERE id = ?').get(c.producto_id);
          if (prod && c.cantidad > 0) {
            var subtotal = prod.precio * c.cantidad;
            total_consumos += subtotal;
            consumosCompletos.push({ id: prod.id, nombre: prod.nombre, cantidad: c.cantidad, precio: prod.precio, subtotal: subtotal });
            // Descontar stock
            db.prepare('UPDATE productos SET stock = stock - ? WHERE id = ? AND stock >= ?').run(c.cantidad, prod.id, c.cantidad);
          }
        });
      });
      descStock();
      consumosStr = JSON.stringify(consumosCompletos);
 
      // Registrar en caja si hay consumos
      if (total_consumos > 0) {
        var caja = db.prepare('SELECT id FROM cajas WHERE estado = ? ORDER BY id DESC LIMIT 1').get('abierta');
        if (caja) {
          db.prepare('INSERT INTO movimientos (caja_id,tipo,categoria,descripcion,monto,metodo_pago,habitacion_id,usuario_id) VALUES (?,?,?,?,?,?,?,?)')
            .run(caja.id, 'ingreso', 'frigobar', 'Frigobar hab.'+hab.numero+' - '+req.user.nombre, total_consumos, 'Cuenta huesped', habitacion_id, req.user.id);
        }
      }
    }
 
    // Guardar servicio
    var r = db.prepare('INSERT INTO servicios_habitacion (habitacion_id,tipo_servicio,mucama_id,mucama_nombre,tipo_cama,necesita_mantenimiento,nota_mantenimiento,consumos,total_consumos) VALUES (?,?,?,?,?,?,?,?,?)')
      .run(habitacion_id, tipo_servicio, req.user.id, req.user.nombre, tipo_cama, necesita_mantenimiento, nota_mantenimiento, consumosStr, total_consumos);
 
    // Actualizar tipo de cama si se especificó
    if (tipo_cama) {
      db.prepare('UPDATE habitaciones SET tipo = ? WHERE id = ?').run(tipo_cama, habitacion_id);
    }
 
    // Actualizar status
    var statusFinal = nuevo_status;
    if (necesita_mantenimiento) statusFinal = 'mantenimiento';
    db.prepare('UPDATE habitaciones SET status=?,nota=?,updated_at=datetime(?) WHERE id=?')
      .run(statusFinal, necesita_mantenimiento ? nota_mantenimiento : (nuevo_status === 'lista' ? 'Lista' : ''), 'now,localtime', habitacion_id);
 
    logAction(req.user.id, req.user.nombre, 'SERVICIO_HAB', 'Hab '+hab.numero+' - '+tipo_servicio+(necesita_mantenimiento?' [MANT]':''));
    res.json({ ok: true, id: r.lastInsertRowid, total_consumos: total_consumos });
  } catch(e) {
    console.error('Servicio error:', e);
    res.status(500).json({ error: e.message });
  }
});
 
app.get('/api/servicios/:habitacion_id', auth, function(req, res) {
  try {
    var servicios = db.prepare('SELECT * FROM servicios_habitacion WHERE habitacion_id = ? ORDER BY created_at DESC LIMIT 20').all(req.params.habitacion_id);
    res.json(servicios);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── HUESPEDES ──
app.get('/api/huespedes', auth, function(req, res) {
  try {
    var q = req.query.q || '';
    res.json(db.prepare('SELECT * FROM huespedes WHERE nombre LIKE ? OR documento LIKE ? ORDER BY nombre LIMIT 50').all('%'+q+'%','%'+q+'%'));
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/huespedes/doc/:doc', auth, function(req, res) {
  try { res.json(db.prepare('SELECT * FROM huespedes WHERE documento = ?').get(req.params.doc) || null); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/huespedes', auth, function(req, res) {
  try {
    var documento=req.body.documento, tipo_doc=req.body.tipo_doc, nombre=req.body.nombre;
    var telefono=req.body.telefono, email=req.body.email, nacionalidad=req.body.nacionalidad;
    if (!documento||!nombre) return res.status(400).json({ error: 'Documento y nombre requeridos' });
    try {
      var r=db.prepare('INSERT INTO huespedes (documento,tipo_doc,nombre,telefono,email,nacionalidad) VALUES (?,?,?,?,?,?)').run(documento,tipo_doc||'DNI',nombre,telefono||'',email||'',nacionalidad||'Argentina');
      res.json({ id: r.lastInsertRowid });
    } catch(e2) {
      db.prepare('UPDATE huespedes SET nombre=?,telefono=?,email=? WHERE documento=?').run(nombre,telefono||'',email||'',documento);
      var h=db.prepare('SELECT * FROM huespedes WHERE documento=?').get(documento);
      res.json({ id: h.id });
    }
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── CHECK-IN ──
app.post('/api/checkin', auth, function(req, res) {
  try {
    var habitacion_id=req.body.habitacion_id, documento=req.body.documento, tipo_doc=req.body.tipo_doc;
    var nombre=req.body.nombre, telefono=req.body.telefono, entrada=req.body.entrada;
    var salida=req.body.salida, noches=req.body.noches, precio_total=req.body.precio_total;
    var metodo_pago=req.body.metodo_pago, notas=req.body.notas;
 
    if (!habitacion_id) return res.status(400).json({ error: 'Falta habitacion_id' });
    if (!nombre)        return res.status(400).json({ error: 'Falta el nombre del huesped' });
    if (!entrada)       return res.status(400).json({ error: 'Falta la fecha de entrada' });
    if (!salida)        return res.status(400).json({ error: 'Falta la fecha de salida' });
 
    var hab = db.prepare('SELECT * FROM habitaciones WHERE id = ?').get(habitacion_id);
    if (!hab) return res.status(404).json({ error: 'Habitacion no encontrada: '+habitacion_id });
    if (hab.status !== 'libre' && hab.status !== 'reservada' && hab.status !== 'lista')
      return res.status(400).json({ error: 'La habitacion esta en estado "'+hab.status+'", no disponible para check-in' });
 
    var huespedId = null;
    if (documento) {
      try {
        var rH=db.prepare('INSERT INTO huespedes (documento,tipo_doc,nombre,telefono) VALUES (?,?,?,?)').run(documento,tipo_doc||'DNI',nombre,telefono||'');
        huespedId=rH.lastInsertRowid;
      } catch(e2) {
        var h2=db.prepare('SELECT id FROM huespedes WHERE documento=?').get(documento);
        if (h2) { huespedId=h2.id; db.prepare('UPDATE huespedes SET visitas=visitas+1 WHERE id=?').run(huespedId); }
      }
    }
 
    var reserva=db.prepare('INSERT INTO reservas (habitacion_id,huesped_id,nombre_huesped,documento,entrada,salida,noches,precio_total,metodo_pago,notas,estado) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
      .run(habitacion_id,huespedId,nombre,documento||'',entrada,salida,noches||1,precio_total||0,metodo_pago||'Efectivo',notas||'','activa');
 
    db.prepare('UPDATE habitaciones SET status=?,nota=?,updated_at=datetime(?) WHERE id=?').run('ocupada',nombre,'now,localtime',habitacion_id);
 
    if (precio_total > 0) {
      var caja=db.prepare('SELECT id FROM cajas WHERE estado = ? ORDER BY id DESC LIMIT 1').get('abierta');
      if (caja) {
        db.prepare('INSERT INTO movimientos (caja_id,tipo,categoria,descripcion,monto,metodo_pago,habitacion_id,usuario_id) VALUES (?,?,?,?,?,?,?,?)')
          .run(caja.id,'ingreso','hospedaje','Check-in hab.'+hab.numero+' - '+nombre,precio_total,metodo_pago||'Efectivo',habitacion_id,req.user.id);
      }
    }
 
    logAction(req.user.id, req.user.nombre, 'CHECKIN', 'Hab '+hab.numero+' - '+nombre);
    res.json({ ok: true, reserva_id: reserva.lastInsertRowid });
  } catch(e) { console.error('CHECKIN ERROR:', e); res.status(500).json({ error: 'Error en check-in: '+e.message }); }
});
 
// ── CHECK-OUT ──
app.post('/api/checkout/:habitacion_id', auth, function(req, res) {
  try {
    var id=req.params.habitacion_id;
    var hab=db.prepare('SELECT * FROM habitaciones WHERE id=?').get(id);
    if (!hab) return res.status(404).json({ error: 'Habitacion no encontrada: '+id });
    db.prepare('UPDATE habitaciones SET status=?,nota=?,updated_at=datetime(?) WHERE id=?').run('limpieza','','now,localtime',id);
    db.prepare('UPDATE reservas SET estado=? WHERE habitacion_id=? AND estado=?').run('finalizada',id,'activa');
    logAction(req.user.id, req.user.nombre, 'CHECKOUT', 'Hab '+hab.numero);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── RESERVAS ──
app.get('/api/reservas', auth, function(req, res) {
  try {
    res.json(db.prepare('SELECT r.*,h.nombre as hab_nombre,h.numero as hab_numero,h.ala,h.tipo FROM reservas r LEFT JOIN habitaciones h ON r.habitacion_id=h.id ORDER BY r.created_at DESC LIMIT 100').all());
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/reservas', auth, function(req, res) {
  try {
    var habitacion_id=req.body.habitacion_id, nombre_huesped=req.body.nombre_huesped;
    var documento=req.body.documento, entrada=req.body.entrada, salida=req.body.salida;
    var noches=req.body.noches, precio_total=req.body.precio_total;
    var metodo_pago=req.body.metodo_pago, notas=req.body.notas;
 
    if (!habitacion_id)  return res.status(400).json({ error: 'Falta habitacion_id' });
    if (!nombre_huesped) return res.status(400).json({ error: 'Falta nombre del huesped' });
    if (!entrada)        return res.status(400).json({ error: 'Falta fecha de entrada' });
    if (!salida)         return res.status(400).json({ error: 'Falta fecha de salida' });
 
    var hab=db.prepare('SELECT * FROM habitaciones WHERE id=?').get(habitacion_id);
    if (!hab) return res.status(404).json({ error: 'Habitacion no encontrada: '+habitacion_id });
    if (hab.status !== 'libre' && hab.status !== 'lista')
      return res.status(400).json({ error: 'La habitacion esta en estado "'+hab.status+'". Solo se puede reservar si esta libre o lista.' });
 
    db.prepare('INSERT INTO reservas (habitacion_id,nombre_huesped,documento,entrada,salida,noches,precio_total,metodo_pago,notas,estado) VALUES (?,?,?,?,?,?,?,?,?,?)')
      .run(habitacion_id,nombre_huesped,documento||'',entrada,salida,noches||1,precio_total||0,metodo_pago||'Efectivo',notas||'','futura');
 
    db.prepare('UPDATE habitaciones SET status=?,nota=?,updated_at=datetime(?) WHERE id=?').run('reservada',nombre_huesped,'now,localtime',habitacion_id);
 
    logAction(req.user.id, req.user.nombre, 'RESERVA', 'Hab '+hab.numero+' - '+nombre_huesped);
    res.json({ ok: true });
  } catch(e) { console.error('RESERVA ERROR:', e); res.status(500).json({ error: 'Error al guardar reserva: '+e.message }); }
});
 
// ── CAJA ──
app.get('/api/caja/activa', auth, function(req, res) {
  try {
    var caja=db.prepare('SELECT c.*,u.nombre as usuario_nombre FROM cajas c LEFT JOIN usuarios u ON c.usuario_id=u.id WHERE c.estado=? ORDER BY c.id DESC LIMIT 1').get('abierta');
    res.json(caja||null);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/caja/abrir', auth, function(req, res) {
  try {
    var ya=db.prepare('SELECT id FROM cajas WHERE estado=?').get('abierta');
    if (ya) return res.status(400).json({ error: 'Ya hay una caja abierta' });
    var r=db.prepare('INSERT INTO cajas (usuario_id,monto_inicial) VALUES (?,?)').run(req.user.id,req.body.monto_inicial||0);
    logAction(req.user.id,req.user.nombre,'ABRIR_CAJA','Monto: $'+(req.body.monto_inicial||0));
    res.json({ id: r.lastInsertRowid });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/caja/cerrar', auth, function(req, res) {
  try {
    var caja=db.prepare('SELECT * FROM cajas WHERE estado=? ORDER BY id DESC LIMIT 1').get('abierta');
    if (!caja) return res.status(400).json({ error: 'No hay caja abierta' });
    var movs=db.prepare('SELECT tipo,SUM(monto) as total FROM movimientos WHERE caja_id=? GROUP BY tipo').all(caja.id);
    var ingresos=0, egresos=0;
    movs.forEach(function(m){ if(m.tipo==='ingreso') ingresos=m.total; else egresos=m.total; });
    var final=caja.monto_inicial+ingresos-egresos;
    db.prepare('UPDATE cajas SET estado=?,monto_final=?,cerrada_at=datetime(?) WHERE id=?').run('cerrada',final,'now,localtime',caja.id);
    logAction(req.user.id,req.user.nombre,'CERRAR_CAJA','Total: $'+final);
    res.json({ ok: true, monto_final: final, ingresos: ingresos, egresos: egresos });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/caja/movimientos', auth, function(req, res) {
  try {
    var caja=db.prepare('SELECT id FROM cajas WHERE estado=? ORDER BY id DESC LIMIT 1').get('abierta');
    if (!caja) return res.json([]);
    res.json(db.prepare('SELECT * FROM movimientos WHERE caja_id=? ORDER BY created_at DESC').all(caja.id));
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/caja/movimiento', auth, function(req, res) {
  try {
    var tipo=req.body.tipo,categoria=req.body.categoria,descripcion=req.body.descripcion,monto=req.body.monto,metodo_pago=req.body.metodo_pago;
    var caja=db.prepare('SELECT id FROM cajas WHERE estado=? ORDER BY id DESC LIMIT 1').get('abierta');
    if (!caja) return res.status(400).json({ error: 'No hay caja abierta' });
    db.prepare('INSERT INTO movimientos (caja_id,tipo,categoria,descripcion,monto,metodo_pago,usuario_id) VALUES (?,?,?,?,?,?,?)').run(caja.id,tipo,categoria||'general',descripcion,monto,metodo_pago||'Efectivo',req.user.id);
    logAction(req.user.id,req.user.nombre,tipo.toUpperCase(),descripcion+': $'+monto);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── FINANZAS ──
app.get('/api/finanzas/resumen', auth, function(req, res) {
  try {
    var desde=req.query.desde, hasta=req.query.hasta, movs;
    if (desde&&hasta) movs=db.prepare('SELECT tipo,categoria,SUM(monto) as total FROM movimientos WHERE created_at BETWEEN ? AND ? GROUP BY tipo,categoria').all(desde,hasta+' 23:59:59');
    else movs=db.prepare('SELECT tipo,categoria,SUM(monto) as total FROM movimientos GROUP BY tipo,categoria').all();
    var ingresos=0,egresos=0;
    movs.forEach(function(m){ if(m.tipo==='ingreso') ingresos+=m.total; else egresos+=m.total; });
    res.json({ ingresos: ingresos, egresos: egresos, balance: ingresos-egresos, detalle: movs });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/finanzas/movimientos', auth, function(req, res) {
  try {
    var desde=req.query.desde, hasta=req.query.hasta, tipo=req.query.tipo, movs;
    if (desde&&hasta&&tipo) movs=db.prepare('SELECT * FROM movimientos WHERE created_at BETWEEN ? AND ? AND tipo=? ORDER BY created_at DESC LIMIT 200').all(desde,hasta+' 23:59:59',tipo);
    else if (desde&&hasta) movs=db.prepare('SELECT * FROM movimientos WHERE created_at BETWEEN ? AND ? ORDER BY created_at DESC LIMIT 200').all(desde,hasta+' 23:59:59');
    else movs=db.prepare('SELECT * FROM movimientos ORDER BY created_at DESC LIMIT 200').all();
    res.json(movs);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── PRODUCTOS ──
app.get('/api/productos', auth, function(req, res) {
  try { res.json(db.prepare('SELECT * FROM productos WHERE activo=1 ORDER BY categoria,nombre').all()); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/productos', auth, adminOnly, function(req, res) {
  try {
    var r=db.prepare('INSERT INTO productos (nombre,categoria,precio,stock,stock_minimo) VALUES (?,?,?,?,?)').run(req.body.nombre,req.body.categoria||'general',req.body.precio,req.body.stock||0,req.body.stock_minimo||5);
    res.json({ id: r.lastInsertRowid });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.put('/api/productos/:id', auth, adminOnly, function(req, res) {
  try {
    db.prepare('UPDATE productos SET nombre=?,categoria=?,precio=?,stock=?,stock_minimo=?,activo=? WHERE id=?').run(req.body.nombre,req.body.categoria,req.body.precio,req.body.stock,req.body.stock_minimo,req.body.activo!==undefined?req.body.activo:1,req.params.id);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── TIENDA ──
app.post('/api/tienda/venta', auth, function(req, res) {
  try {
    var items=req.body.items;
    if (!items||!items.length) return res.status(400).json({ error: 'Sin productos' });
    var caja=db.prepare('SELECT id FROM cajas WHERE estado=? ORDER BY id DESC LIMIT 1').get('abierta');
    var totalVenta=0;
    var doVenta=db.transaction(function(){
      items.forEach(function(item){
        var prod=db.prepare('SELECT * FROM productos WHERE id=?').get(item.producto_id);
        if (!prod) throw new Error('Producto no encontrado: '+item.producto_id);
        if (prod.stock < item.cantidad) throw new Error('Stock insuficiente: '+prod.nombre);
        var total=prod.precio*item.cantidad; totalVenta+=total;
        db.prepare('INSERT INTO ventas_tienda (producto_id,cantidad,precio_unitario,total,caja_id,usuario_id) VALUES (?,?,?,?,?,?)').run(item.producto_id,item.cantidad,prod.precio,total,caja?caja.id:null,req.user.id);
        db.prepare('UPDATE productos SET stock=stock-? WHERE id=?').run(item.cantidad,item.producto_id);
      });
      if (caja) db.prepare('INSERT INTO movimientos (caja_id,tipo,categoria,descripcion,monto,metodo_pago,usuario_id) VALUES (?,?,?,?,?,?,?)').run(caja.id,'ingreso','tienda','Venta tienda ('+items.length+' items)',totalVenta,'Efectivo',req.user.id);
    });
    doVenta();
    logAction(req.user.id,req.user.nombre,'VENTA_TIENDA','Total: $'+totalVenta);
    res.json({ ok: true, total: totalVenta });
  } catch(e) { res.status(400).json({ error: e.message }); }
});
 
// ── INVENTARIO ──
app.get('/api/inventario/alertas', auth, function(req, res) {
  try { res.json(db.prepare('SELECT * FROM productos WHERE stock<=stock_minimo AND activo=1').all()); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/inventario/entrada', auth, function(req, res) {
  try {
    db.prepare('UPDATE productos SET stock=stock+? WHERE id=?').run(req.body.cantidad,req.body.producto_id);
    logAction(req.user.id,req.user.nombre,'ENTRADA_STOCK','Prod '+req.body.producto_id+': +'+req.body.cantidad);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── LOG ──
app.get('/api/log', auth, function(req, res) {
  try { res.json(db.prepare('SELECT * FROM log_acciones ORDER BY created_at DESC LIMIT 100').all()); }
  catch(e) { res.status(500).json({ error: e.message }); }
});
 
// ── DASHBOARD ──
app.get('/api/dashboard', auth, function(req, res) {
  try {
    var habs=db.prepare('SELECT status,COUNT(*) as cnt FROM habitaciones GROUP BY status').all();
    var caja=db.prepare('SELECT * FROM cajas WHERE estado=? ORDER BY id DESC LIMIT 1').get('abierta');
    var hospedaje=0,tienda=0,frigobar=0,ingresos=0,egresos=0;
    if (caja) {
      var movs=db.prepare('SELECT tipo,categoria,SUM(monto) as total FROM movimientos WHERE caja_id=? GROUP BY tipo,categoria').all(caja.id);
      movs.forEach(function(m){
        if (m.tipo==='ingreso'&&m.categoria==='hospedaje') hospedaje=m.total;
        if (m.tipo==='ingreso'&&m.categoria==='tienda') tienda=m.total;
        if (m.tipo==='ingreso'&&m.categoria==='frigobar') frigobar=m.total;
        if (m.tipo==='ingreso') ingresos+=m.total;
        if (m.tipo==='egreso') egresos+=m.total;
      });
    }
    var alertas=db.prepare('SELECT COUNT(*) as c FROM productos WHERE stock<=stock_minimo AND activo=1').get();
    res.json({ habitaciones: habs, ingresos: ingresos, egresos: egresos, hospedaje: hospedaje, tienda: tienda, frigobar: frigobar, balance: ingresos-egresos, alertas_stock: alertas.c, caja_abierta: !!caja });
  } catch(e) { console.error('Dashboard error:', e); res.status(500).json({ error: e.message }); }
});
 
app.get('*', function(req, res) { res.sendFile(path.join(__dirname, 'public', 'index.html')); });
app.listen(PORT, function() { console.log('Hotel Takua corriendo en puerto '+PORT); });
 
