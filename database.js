const Database = require('better-sqlite3');
const path = require('path');
 
const db = new Database(path.join(__dirname, 'hotel.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = OFF');
 
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
    tipo TEXT NOT NULL DEFAULT 'twin',
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
  CREATE TABLE IF NOT EXISTS servicios_habitacion (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    habitacion_id TEXT NOT NULL,
    tipo_servicio TEXT NOT NULL DEFAULT 'limpieza_diaria',
    mucama_id INTEGER,
    mucama_nombre TEXT,
    tipo_cama TEXT DEFAULT '',
    necesita_mantenimiento INTEGER DEFAULT 0,
    nota_mantenimiento TEXT DEFAULT '',
    consumos TEXT DEFAULT '[]',
    total_consumos REAL DEFAULT 0,
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
 
// ── MIGRACIONES SEGURAS ──
var migraciones = [
  "ALTER TABLE habitaciones ADD COLUMN nombre TEXT DEFAULT ''",
  "ALTER TABLE habitaciones ADD COLUMN tipo_cama TEXT DEFAULT 'twin'",
];
migraciones.forEach(function(sql) {
  try { db.exec(sql); } catch(e) {}
});
 
// Migrar tipos viejos (simple/doble/suite -> twin/queen)
try {
  db.prepare("UPDATE habitaciones SET tipo = 'twin' WHERE tipo IN ('simple', 'doble')").run();
  db.prepare("UPDATE habitaciones SET tipo = 'queen' WHERE tipo = 'suite'").run();
} catch(e) {}
 
// Renumerar habitaciones formato viejo E01->E101
try {
  var vieja = db.prepare("SELECT id FROM habitaciones WHERE id LIKE 'E0%' OR id LIKE 'O0%' LIMIT 1").get();
  if (vieja) {
    var migrar = db.transaction(function() {
      for (var i = 1; i <= 14; i++) {
        var pad = i.toString().padStart(2, '0');
        try { db.prepare('UPDATE habitaciones SET id=?, numero=? WHERE id=?').run('E'+(100+i), (100+i).toString(), 'E'+pad); } catch(e) {}
        try { db.prepare('UPDATE reservas SET habitacion_id=? WHERE habitacion_id=?').run('E'+(100+i), 'E'+pad); } catch(e) {}
        try { db.prepare('UPDATE habitaciones SET id=?, numero=? WHERE id=?').run('O'+(200+i), (200+i).toString(), 'O'+pad); } catch(e) {}
        try { db.prepare('UPDATE reservas SET habitacion_id=? WHERE habitacion_id=?').run('O'+(200+i), 'O'+pad); } catch(e) {}
      }
    });
    migrar();
    console.log('Habitaciones renumeradas');
  }
} catch(e) { console.error('Migracion nums:', e.message); }
 
// ── SEED HABITACIONES ──
try {
  var countH = db.prepare('SELECT COUNT(*) as c FROM habitaciones').get();
  if (countH.c === 0) {
    var insH = db.prepare('INSERT OR IGNORE INTO habitaciones (id,numero,nombre,ala,tipo,piso,capacidad,precio_noche,precio_hora,status) VALUES (?,?,?,?,?,1,?,?,?,?)');
    var tipos  = ['twin','twin','twin','queen','queen','queen','queen','twin','twin','twin','queen','queen','queen','twin'];
    var caps   = [2,2,2,2,2,2,2,2,2,2,2,2,2,2];
    var pnoche = [45000,45000,45000,60000,60000,60000,60000,45000,45000,45000,60000,60000,60000,45000];
    var phora  = [15000,15000,15000,20000,20000,20000,20000,15000,15000,15000,20000,20000,20000,15000];
    var seedH = db.transaction(function() {
      for (var i = 0; i < 14; i++) { var n=(101+i).toString(); insH.run('E'+n,n,'','Este',tipos[i],caps[i],pnoche[i],phora[i],'libre'); }
      for (var i = 0; i < 14; i++) { var n=(201+i).toString(); insH.run('O'+n,n,'','Oeste',tipos[i],caps[i],pnoche[i],phora[i],'libre'); }
    });
    seedH();
    console.log('28 habitaciones creadas (101-114 / 201-214)');
  }
} catch(e) { console.error('Seed habs:', e.message); }
 
// ── SEED ADMIN ──
try {
  var countU = db.prepare('SELECT COUNT(*) as c FROM usuarios').get();
  if (countU.c === 0) {
    var bcrypt = require('bcryptjs');
    db.prepare('INSERT INTO usuarios (nombre,email,password,rol) VALUES (?,?,?,?)')
      .run('Administrador','admin@hoteltakua.com',bcrypt.hashSync('admin123',10),'admin');
    console.log('Admin creado: admin@hoteltakua.com / admin123');
  }
} catch(e) { console.error('Seed admin:', e.message); }
 
// ── SEED PRODUCTOS FRIGOBAR ──
try {
  var countP = db.prepare('SELECT COUNT(*) as c FROM productos').get();
  if (countP.c === 0) {
    var insP = db.prepare('INSERT INTO productos (nombre,categoria,precio,stock,stock_minimo) VALUES (?,?,?,?,?)');
    var seedP = db.transaction(function() {
      [
        ['Agua mineral 500ml','Bebidas',800,50,10],
        ['Coca-Cola 500ml','Bebidas',1200,30,8],
        ['Cerveza Quilmes','Bebidas',1500,24,6],
        ['Jugo de naranja','Bebidas',900,20,8],
        ['Agua con gas 500ml','Bebidas',900,30,8],
        ['Snack chips','Frigobar',900,30,10],
        ['Chocolate','Frigobar',1100,20,8],
        ['Alfajor','Frigobar',700,30,10],
        ['Maní salado','Frigobar',600,25,8],
        ['Jabón individual','Higiene',500,50,10],
        ['Shampoo individual','Higiene',600,40,10],
        ['Toalla extra','Habitacion',2000,15,3],
        ['Amenities kit','Higiene',1500,20,5],
      ].forEach(function(p) { insP.run(p[0],p[1],p[2],p[3],p[4]); });
    });
    seedP();
    console.log('Productos creados');
  }
} catch(e) { console.error('Seed productos:', e.message); }
 
console.log('Base de datos lista');
module.exports = db;
 
