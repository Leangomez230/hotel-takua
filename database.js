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

// Migración: tablas de comandas
  await query(`
    CREATE TABLE IF NOT EXISTS mesas (
      id SERIAL PRIMARY KEY,
      numero INTEGER NOT NULL UNIQUE,
      tipo TEXT NOT NULL DEFAULT 'cuadrada',
      capacidad INTEGER DEFAULT 4,
      status TEXT NOT NULL DEFAULT 'libre',
      mozo_id INTEGER,
      mozo_nombre TEXT DEFAULT '',
      updated_at TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS comandas (
      id SERIAL PRIMARY KEY,
      mesa_id INTEGER NOT NULL,
      mozo_id INTEGER,
      mozo_nombre TEXT DEFAULT '',
      estado TEXT NOT NULL DEFAULT 'abierta',
      subtotal REAL DEFAULT 0,
      descuento REAL DEFAULT 0,
      total REAL DEFAULT 0,
      metodo_pago TEXT DEFAULT '',
      notas TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT NOW(),
      cerrada_at TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS comanda_items (
      id SERIAL PRIMARY KEY,
      comanda_id INTEGER NOT NULL,
      producto_id INTEGER,
      nombre TEXT NOT NULL,
      cantidad INTEGER DEFAULT 1,
      precio_unitario REAL NOT NULL,
      subtotal REAL NOT NULL,
      estado TEXT DEFAULT 'pendiente',
      notas TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // Seed mesas según croquis del restaurante
  const countMesas = await getOne('SELECT COUNT(*) as c FROM mesas');
  if (parseInt(countMesas.c) === 0) {
    // Fila 1: mesas redondas 1-5
    for (let i = 1; i <= 5; i++)
      await query('INSERT INTO mesas (numero,tipo,capacidad) VALUES ($1,$2,$3)',[i,'redonda',2]);
    // Fila 2: 1 redonda + 5 cuadradas (6-11)
    await query('INSERT INTO mesas (numero,tipo,capacidad) VALUES ($1,$2,$3)',[6,'redonda',2]);
    for (let i = 7; i <= 11; i++)
      await query('INSERT INTO mesas (numero,tipo,capacidad) VALUES ($1,$2,$3)',[i,'cuadrada',4]);
    // Fila 3: 2 redondas + 5 cuadradas (12-18)
    for (let i = 12; i <= 13; i++)
      await query('INSERT INTO mesas (numero,tipo,capacidad) VALUES ($1,$2,$3)',[i,'redonda',2]);
    for (let i = 14; i <= 18; i++)
      await query('INSERT INTO mesas (numero,tipo,capacidad) VALUES ($1,$2,$3)',[i,'cuadrada',4]);
    // Barra
    await query('INSERT INTO mesas (numero,tipo,capacidad) VALUES ($1,$2,$3)',[19,'barra',8]);
    console.log('✅ 19 mesas creadas (croquis restaurante)');
  }

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

// Migración: columnas vuelto en comandas
try {
  await query('ALTER TABLE comandas ADD COLUMN IF NOT EXISTS monto_recibido REAL DEFAULT 0');
  await query('ALTER TABLE comandas ADD COLUMN IF NOT EXISTS vuelto REAL DEFAULT 0');
  console.log('✅ Columnas monto_recibido y vuelto listas');
} catch(e) { console.log('columnas vuelto ya existen'); }

// Migración: es_bebida en menu_restaurante
try {
  await query('ALTER TABLE menu_restaurante ADD COLUMN IF NOT EXISTS es_bebida INTEGER DEFAULT 0');
  await query("UPDATE menu_restaurante SET es_bebida=1 WHERE LOWER(categoria) IN ('bebidas','bebida','drinks') AND es_bebida=0");
  console.log('✅ Columna es_bebida lista');
} catch(e) { console.log('es_bebida ya existe'); }

// Migración: inventario extendido
try {
  await query("ALTER TABLE productos ADD COLUMN IF NOT EXISTS unidad TEXT DEFAULT 'unidad'");
  await query('ALTER TABLE productos ADD COLUMN IF NOT EXISTS costo REAL DEFAULT 0');
  await query("ALTER TABLE productos ADD COLUMN IF NOT EXISTS proveedor TEXT DEFAULT ''");
  await query("ALTER TABLE productos ADD COLUMN IF NOT EXISTS modulo TEXT DEFAULT 'general'");
  await query('ALTER TABLE productos ADD COLUMN IF NOT EXISTS menu_id INTEGER DEFAULT NULL');
  console.log('✅ Columnas inventario extendido listas');
} catch(e) { console.log('columnas inventario ya existen'); }

// Tabla movimientos de inventario
await query(`
  CREATE TABLE IF NOT EXISTS inventario_movimientos (
    id SERIAL PRIMARY KEY,
    producto_id INTEGER NOT NULL,
    tipo TEXT NOT NULL DEFAULT 'entrada',
    cantidad REAL NOT NULL,
    motivo TEXT DEFAULT '',
    referencia TEXT DEFAULT '',
    usuario_id INTEGER,
    usuario_nombre TEXT,
    stock_antes REAL DEFAULT 0,
    stock_despues REAL DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
  );
`);
console.log('✅ Tabla inventario_movimientos lista');

// Tabla suscripciones push
await query(`
  CREATE TABLE IF NOT EXISTS push_suscripciones (
    id SERIAL PRIMARY KEY,
    usuario_id INTEGER NOT NULL,
    usuario_nombre TEXT,
    rol TEXT,
    endpoint TEXT NOT NULL,
    p256dh TEXT NOT NULL,
    auth TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(endpoint, usuario_id)
  );
`);
// Migración: cambiar UNIQUE de solo endpoint a (endpoint, usuario_id)
// para soportar múltiples usuarios en el mismo dispositivo
try {
  await query(`
    DO $$ BEGIN
      IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'push_suscripciones_endpoint_key'
      ) THEN
        ALTER TABLE push_suscripciones DROP CONSTRAINT push_suscripciones_endpoint_key;
        ALTER TABLE push_suscripciones ADD CONSTRAINT push_suscripciones_endpoint_usuario_unique UNIQUE (endpoint, usuario_id);
      END IF;
    END $$;
  `);
} catch(e) { console.log('Constraint push ya migrado'); }
console.log('✅ Tabla push_suscripciones lista');

// Tabla retiros de caja restaurante
await query(`
  CREATE TABLE IF NOT EXISTS caja_retiros (
    id SERIAL PRIMARY KEY,
    turno_id INTEGER NOT NULL,
    monto REAL NOT NULL,
    motivo TEXT DEFAULT '',
    usuario_id INTEGER,
    usuario_nombre TEXT,
    created_at TIMESTAMP DEFAULT NOW()
  );
`);
console.log('✅ Tabla caja_retiros lista');

// Caja habitaciones — turnos
await query(`
  CREATE TABLE IF NOT EXISTS turnos_habitaciones (
    id SERIAL PRIMARY KEY,
    cajero_id INTEGER,
    cajero_nombre TEXT,
    fondo_inicial REAL DEFAULT 0,
    estado TEXT DEFAULT 'abierto',
    abierto_at TIMESTAMP DEFAULT NOW(),
    cerrado_at TIMESTAMP
  );
`);
// Caja habitaciones — movimientos
await query(`
  CREATE TABLE IF NOT EXISTS movimientos_habitaciones (
    id SERIAL PRIMARY KEY,
    turno_id INTEGER,
    tipo TEXT NOT NULL DEFAULT 'ingreso',
    concepto TEXT NOT NULL DEFAULT '',
    monto REAL NOT NULL DEFAULT 0,
    metodo_pago TEXT DEFAULT 'Efectivo',
    referencia TEXT DEFAULT '',
    usuario_id INTEGER,
    usuario_nombre TEXT,
    habitacion_id INTEGER,
    habitacion_numero TEXT,
    created_at TIMESTAMP DEFAULT NOW()
  );
`);
console.log('✅ Tablas caja habitaciones listas');

// Migración: seña y saldo en reservas
try {
  await query('ALTER TABLE reservas ADD COLUMN IF NOT EXISTS monto_senia REAL DEFAULT 0');
  await query('ALTER TABLE reservas ADD COLUMN IF NOT EXISTS saldo_pendiente REAL DEFAULT 0');
  // Inicializar saldo_pendiente = precio_total para reservas existentes sin seña
  await query(`UPDATE reservas SET saldo_pendiente=precio_total WHERE saldo_pendiente=0 AND precio_total>0`);
  console.log('✅ Columnas seña y saldo listas');
} catch(e) { console.log('columnas seña ya existen'); }

// Migración: sincronizar bebidas del menú → inventario
try {
  const bebidasMenu = await getAll(
    "SELECT * FROM menu_restaurante WHERE es_bebida=1 AND disponible=1"
  );
  for (const b of bebidasMenu) {
    // Solo migrar si no existe ya un producto con ese menu_id
    const existe = await getOne('SELECT id FROM productos WHERE menu_id=$1', [b.id]);
    if (!existe) {
      const r = await query(
        `INSERT INTO productos (nombre,categoria,precio,costo,stock,stock_minimo,unidad,modulo,menu_id,activo)
         VALUES ($1,$2,$3,0,0,5,'unidad','bebidas',$4,1) RETURNING id`,
        [b.nombre, b.categoria, b.precio, b.id]
      );
      console.log('✅ Bebida migrada al inventario:', b.nombre);
    }
  }
  console.log('✅ Migración bebidas→inventario completada');
} catch(e) { console.log('Error migrando bebidas:', e.message); }

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
