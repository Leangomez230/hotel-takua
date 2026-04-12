const { Pool } = require('pg');
 
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});
 
// Helper: ejecutar query
async function query(text, params) {
  const client = await pool.connect();
  try {
    const result = await client.query(text, params);
    return result;
  } finally {
    client.release();
  }
}
 
// Helper: get one row
async function getOne(text, params) {
  const result = await query(text, params);
  return result.rows[0] || null;
}
 
// Helper: get all rows
async function getAll(text, params) {
  const result = await query(text, params);
  return result.rows;
}
 
// Helper: run insert/update/delete
async function run(text, params) {
  const result = await query(text, params);
  return result;
}
 
// Inicializar tablas
async function initDB() {
  await query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id SERIAL PRIMARY KEY,
      nombre TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      rol TEXT NOT NULL DEFAULT 'recepcionista',
      activo INTEGER DEFAULT 1,
      created_at TIMESTAMP DEFAULT NOW()
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
      updated_at TIMESTAMP DEFAULT NOW()
    );
 
    CREATE TABLE IF NOT EXISTS huespedes (
      id SERIAL PRIMARY KEY,
      documento TEXT UNIQUE NOT NULL,
      tipo_doc TEXT DEFAULT 'DNI',
      nombre TEXT NOT NULL,
      telefono TEXT DEFAULT '',
      email TEXT DEFAULT '',
      nacionalidad TEXT DEFAULT 'Argentina',
      visitas INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );
 
    CREATE TABLE IF NOT EXISTS reservas (
      id SERIAL PRIMARY KEY,
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
      created_at TIMESTAMP DEFAULT NOW()
    );
 
    CREATE TABLE IF NOT EXISTS cajas (
      id SERIAL PRIMARY KEY,
      usuario_id INTEGER NOT NULL,
      monto_inicial REAL DEFAULT 0,
      monto_final REAL,
      estado TEXT DEFAULT 'abierta',
      abierta_at TIMESTAMP DEFAULT NOW(),
      cerrada_at TIMESTAMP
    );
 
    CREATE TABLE IF NOT EXISTS movimientos (
      id SERIAL PRIMARY KEY,
      caja_id INTEGER,
      tipo TEXT NOT NULL,
      categoria TEXT DEFAULT 'general',
      descripcion TEXT NOT NULL,
      monto REAL NOT NULL,
      metodo_pago TEXT DEFAULT 'Efectivo',
      habitacion_id TEXT,
      usuario_id INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    );
 
    CREATE TABLE IF NOT EXISTS productos (
      id SERIAL PRIMARY KEY,
      nombre TEXT NOT NULL,
      categoria TEXT DEFAULT 'general',
      precio REAL NOT NULL,
      stock INTEGER DEFAULT 0,
      stock_minimo INTEGER DEFAULT 5,
      activo INTEGER DEFAULT 1,
      created_at TIMESTAMP DEFAULT NOW()
    );
 
    CREATE TABLE IF NOT EXISTS ventas_tienda (
      id SERIAL PRIMARY KEY,
      producto_id INTEGER NOT NULL,
      cantidad INTEGER DEFAULT 1,
      precio_unitario REAL NOT NULL,
      total REAL NOT NULL,
      caja_id INTEGER,
      usuario_id INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    );
 
    CREATE TABLE IF NOT EXISTS servicios_habitacion (
      id SERIAL PRIMARY KEY,
      habitacion_id TEXT NOT NULL,
      tipo_servicio TEXT NOT NULL DEFAULT 'diario',
      mucama_id INTEGER,
      mucama_nombre TEXT,
      tipo_cama TEXT DEFAULT '',
      necesita_mantenimiento INTEGER DEFAULT 0,
      nota_mantenimiento TEXT DEFAULT '',
      consumos TEXT DEFAULT '[]',
      total_consumos REAL DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );
 
    CREATE TABLE IF NOT EXISTS log_acciones (
      id SERIAL PRIMARY KEY,
      usuario_id INTEGER,
      usuario_nombre TEXT,
      accion TEXT NOT NULL,
      detalle TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
 
  // Migración: agregar columna password_puerta si no existe
try {
  await query("ALTER TABLE habitaciones ADD COLUMN IF NOT EXISTS password_puerta TEXT DEFAULT '0000'");
  console.log('✅ Columna password_puerta lista');
} catch(e) { console.log('password_puerta ya existe'); }
 
// Migración: tabla solicitudes_huesped
await query(`
  CREATE TABLE IF NOT EXISTS solicitudes_huesped (
    id SERIAL PRIMARY KEY,
    habitacion_id TEXT NOT NULL,
    tipo TEXT NOT NULL DEFAULT 'servicio',
    detalle TEXT DEFAULT '',
    consumos TEXT DEFAULT '[]',
    estado TEXT DEFAULT 'pendiente',
    created_at TIMESTAMP DEFAULT NOW()
  );
`);
 
// Seed habitaciones
  const countH = await getOne('SELECT COUNT(*) as c FROM habitaciones');
  if (parseInt(countH.c) === 0) {
    const tipos  = ['twin','twin','twin','queen','queen','queen','queen','twin','twin','twin','queen','queen','queen','twin'];
    const caps   = [2,2,2,2,2,2,2,2,2,2,2,2,2,2];
    const pnoche = [45000,45000,45000,60000,60000,60000,60000,45000,45000,45000,60000,60000,60000,45000];
    const phora  = [15000,15000,15000,20000,20000,20000,20000,15000,15000,15000,20000,20000,20000,15000];
    for (let i = 0; i < 14; i++) {
      const n = (101+i).toString();
      await query('INSERT INTO habitaciones (id,numero,nombre,ala,tipo,piso,capacidad,precio_noche,precio_hora,status) VALUES ($1,$2,$3,$4,$5,1,$6,$7,$8,$9) ON CONFLICT DO NOTHING',
        [`E${n}`,n,'','Este',tipos[i],caps[i],pnoche[i],phora[i],'libre']);
    }
    for (let i = 0; i < 14; i++) {
      const n = (201+i).toString();
      await query('INSERT INTO habitaciones (id,numero,nombre,ala,tipo,piso,capacidad,precio_noche,precio_hora,status) VALUES ($1,$2,$3,$4,$5,1,$6,$7,$8,$9) ON CONFLICT DO NOTHING',
        [`O${n}`,n,'','Oeste',tipos[i],caps[i],pnoche[i],phora[i],'libre']);
    }
    console.log('✅ 28 habitaciones creadas (101-114 / 201-214)');
  }
 
  // Seed admin
  const countU = await getOne('SELECT COUNT(*) as c FROM usuarios');
  if (parseInt(countU.c) === 0) {
    const bcrypt = require('bcryptjs');
    const hash = bcrypt.hashSync('admin123', 10);
    await query('INSERT INTO usuarios (nombre,email,password,rol) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING',
      ['Administrador','admin@hoteltakua.com',hash,'admin']);
    console.log('✅ Admin creado: admin@hoteltakua.com / admin123');
  }
 
  // Seed productos
  const countP = await getOne('SELECT COUNT(*) as c FROM productos');
  if (parseInt(countP.c) === 0) {
    const prods = [
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
    ];
    for (const p of prods) {
      await query('INSERT INTO productos (nombre,categoria,precio,stock,stock_minimo) VALUES ($1,$2,$3,$4,$5)', p);
    }
    console.log('✅ Productos creados');
  }
 
  console.log('✅ Base de datos PostgreSQL lista');
}
 
module.exports = { query, getOne, getAll, run, initDB };
