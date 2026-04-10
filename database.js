const Database = require('better-sqlite3');
const path = require('path');
 
const db = new Database(path.join(__dirname, 'hotel.db'));
db.pragma('journal_mode = WAL');
 
// ── CREAR TABLAS ──
db.exec(`
  CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    rol TEXT NOT NULL DEFAULT 'recepcionista',
    activo INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now','localtime'))
  );
 
  CREATE TABLE IF NOT EXISTS habitaciones (
    id TEXT PRIMARY KEY,
    numero TEXT NOT NULL,
    nombre TEXT DEFAULT '',
    ala TEXT NOT NULL,
    tipo TEXT NOT NULL DEFAULT 'simple',
    piso INTEGER DEFAULT 1,
    capacidad INTEGER DEFAULT 2,
    precio_noche REAL DEFAULT 50000,
    precio_hora REAL DEFAULT 15000,
    status TEXT NOT NULL DEFAULT 'libre',
    nota TEXT DEFAULT '',
    updated_at TEXT DEFAULT (datetime('now','localtime'))
  );
 
  CREATE TABLE IF NOT EXISTS huespedes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    documento TEXT UNIQUE NOT NULL,
    tipo_doc TEXT DEFAULT 'DNI',
    nombre TEXT NOT NULL,
    telefono TEXT DEFAULT '',
    email TEXT DEFAULT '',
    nacionalidad TEXT DEFAULT 'Argentina',
    visitas INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now','localtime'))
  );
 
  CREATE TABLE IF NOT EXISTS reservas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    habitacion_id TEXT NOT NULL,
    huesped_id INTEGER,
    nombre_huesped TEXT NOT NULL,
    documento TEXT DEFAULT '',
    entrada TEXT NOT NULL,
    salida TEXT NOT NULL,
    noches INTEGER DEFAULT 1,
    precio_total REAL DEFAULT 0,
    metodo_pago TEXT DEFAULT 'Efectivo',
    estado TEXT DEFAULT 'activa',
    notas TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
  );
 
  CREATE TABLE IF NOT EXISTS cajas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER NOT NULL,
    monto_inicial REAL DEFAULT 0,
    monto_final REAL,
    estado TEXT DEFAULT 'abierta',
    abierta_at TEXT DEFAULT (datetime('now','localtime')),
    cerrada_at TEXT
  );
 
  CREATE TABLE IF NOT EXISTS movimientos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    caja_id INTEGER,
    tipo TEXT NOT NULL,
    categoria TEXT DEFAULT 'general',
    descripcion TEXT NOT NULL,
    monto REAL NOT NULL,
    metodo_pago TEXT DEFAULT 'Efectivo',
    habitacion_id TEXT,
    usuario_id INTEGER,
    created_at TEXT DEFAULT (datetime('now','localtime'))
  );
 
  CREATE TABLE IF NOT EXISTS productos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre TEXT NOT NULL,
    categoria TEXT DEFAULT 'general',
    precio REAL NOT NULL,
    stock INTEGER DEFAULT 0,
    stock_minimo INTEGER DEFAULT 5,
    activo INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now','localtime'))
  );
 
  CREATE TABLE IF NOT EXISTS ventas_tienda (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    producto_id INTEGER NOT NULL,
    cantidad INTEGER DEFAULT 1,
    precio_unitario REAL NOT NULL,
    total REAL NOT NULL,
    caja_id INTEGER,
    usuario_id INTEGER,
    created_at TEXT DEFAULT (datetime('now','localtime'))
  );
 
  CREATE TABLE IF NOT EXISTS log_acciones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id INTEGER,
    usuario_nombre TEXT,
    accion TEXT NOT NULL,
    detalle TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now','localtime'))
  );
`);
 
// ── MIGRACIONES ──
 
// Agregar columna nombre si no existe
try { db.exec("ALTER TABLE habitaciones ADD COLUMN nombre TEXT DEFAULT ''"); console.log('✅ Columna nombre agregada'); } catch(e) {}
 
// Renumerar habitaciones al formato correcto (101-114 / 201-214)
// Solo corre si detecta el formato viejo (E01, E02...)
const habVieja = db.prepare("SELECT id FROM habitaciones WHERE id='E01' OR id='E02'").get();
if (habVieja) {
  console.log('🔄 Migrando números de habitaciones...');
  const migrar = db.transaction(() => {
    for (let i = 1; i <= 14; i++) {
      const oldId = `E${i.toString().padStart(2,'0')}`;
      const newId = `E${100+i}`;
      const newNum = (100+i).toString();
      try {
        db.prepare('UPDATE habitaciones SET id=?,numero=? WHERE id=?').run(newId, newNum, oldId);
        db.prepare('UPDATE reservas SET habitacion_id=? WHERE habitacion_id=?').run(newId, oldId);
        db.prepare('UPDATE movimientos SET habitacion_id=? WHERE habitacion_id=?').run(newId, oldId);
      } catch(e) { console.log(`Skip ${oldId}:`, e.message); }
    }
    for (let i = 1; i <= 14; i++) {
      const oldId = `O${i.toString().padStart(2,'0')}`;
      const newId = `O${200+i}`;
      const newNum = (200+i).toString();
      try {
        db.prepare('UPDATE habitaciones SET id=?,numero=? WHERE id=?').run(newId, newNum, oldId);
        db.prepare('UPDATE reservas SET habitacion_id=? WHERE habitacion_id=?').run(newId, oldId);
        db.prepare('UPDATE movimientos SET habitacion_id=? WHERE habitacion_id=?').run(newId, oldId);
      } catch(e) { console.log(`Skip ${oldId}:`, e.message); }
    }
  });
  migrar();
  console.log('✅ Habitaciones renumeradas: Este 101-114, Oeste 201-214');
}
 
// ── SEED: Habitaciones (solo si no existen) ──
const countHab = db.prepare('SELECT COUNT(*) as c FROM habitaciones').get();
if (countHab.c === 0) {
  const ins = db.prepare(`
    INSERT INTO habitaciones (id,numero,nombre,ala,tipo,piso,capacidad,precio_noche,precio_hora,status)
    VALUES (?,?,?,?,?,1,?,?,?,'libre')
  `);
  const tipos   = ['simple','simple','doble','doble','doble','suite','suite','doble','simple','simple','doble','doble','suite','simple'];
  const caps    = [1,1,2,2,2,4,4,2,1,1,2,2,4,1];
  const pnoche  = [45000,45000,60000,60000,60000,120000,120000,60000,45000,45000,60000,60000,120000,45000];
  const phora   = [15000,15000,20000,20000,20000,35000,35000,20000,15000,15000,20000,20000,35000,15000];
 
  const seed = db.transaction(() => {
    for (let i = 0; i < 14; i++) {
      const num = (101+i).toString();
      ins.run(`E${num}`, num, '', 'Este', tipos[i], caps[i], pnoche[i], phora[i]);
    }
    for (let i = 0; i < 14; i++) {
      const num = (201+i).toString();
      ins.run(`O${num}`, num, '', 'Oeste', tipos[i], caps[i], pnoche[i], phora[i]);
    }
  });
  seed();
  console.log('✅ 28 habitaciones creadas: Este 101-114, Oeste 201-214');
}
 
// ── SEED: Admin por defecto ──
const countUsers = db.prepare('SELECT COUNT(*) as c FROM usuarios').get();
if (countUsers.c === 0) {
  const bcrypt = require('bcryptjs');
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO usuarios (nombre,email,password,rol) VALUES (?,?,?,?)')
    .run('Administrador', 'admin@hoteltakua.com', hash, 'admin');
  console.log('✅ Admin creado: admin@hoteltakua.com / admin123');
}
 
// ── SEED: Productos de ejemplo ──
const countProd = db.prepare('SELECT COUNT(*) as c FROM productos').get();
if (countProd.c === 0) {
  const ins = db.prepare('INSERT INTO productos (nombre,categoria,precio,stock,stock_minimo) VALUES (?,?,?,?,?)');
  [
    ['Agua mineral 500ml','Bebidas',800,50,10],
    ['Coca-Cola 500ml','Bebidas',1200,30,8],
    ['Cerveza Quilmes','Bebidas',1500,24,6],
    ['Snack chips','Snacks',900,20,5],
    ['Chocolate','Snacks',1100,15,5],
    ['Jabón individual','Higiene',500,40,10],
    ['Shampoo individual','Higiene',600,30,8],
    ['Toalla extra','Ropa de cama',2000,10,3],
  ].forEach(p => ins.run(...p));
  console.log('✅ Productos de ejemplo creados');
}
 
module.exports = db;
 
