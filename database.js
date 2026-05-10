const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function query(text, params) {
  const client = await pool.connect();
  try {
    const result = await client.query(text, params);
    return result;
  } finally {
    client.release();
  }
}

async function getOne(text, params) {
  const result = await query(text, params);
  return result.rows[0] || null;
}

async function getAll(text, params) {
  const result = await query(text, params);
  return result.rows;
}

async function run(text, params) {
  const result = await query(text, params);
  return result;
}

async function initDB() {

  // ── TABLAS HOTEL ────────────────────────────────────────────────────
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

  // Migraciones hotel
  try {
    await query("ALTER TABLE habitaciones ADD COLUMN IF NOT EXISTS password_puerta TEXT DEFAULT '0000'");
    console.log('✅ Columna password_puerta lista');
  } catch(e) { console.log('password_puerta ya existe'); }

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

  await query(`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS modulos TEXT DEFAULT 'hotel'`);

  // ── TABLAS RESTAURANTE ──────────────────────────────────────────────
  await query(`
    CREATE TABLE IF NOT EXISTS mesas_restaurante (
      id         SERIAL PRIMARY KEY,
      alias      TEXT    DEFAULT '',
      tipo       TEXT    NOT NULL DEFAULT 'rectangular',
      x          REAL    NOT NULL DEFAULT 100,
      y          REAL    NOT NULL DEFAULT 100,
      status     TEXT    NOT NULL DEFAULT 'libre',
      activo     INTEGER DEFAULT 1,
      updated_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS menu_restaurante (
      id         SERIAL PRIMARY KEY,
      nombre     TEXT    NOT NULL,
      categoria  TEXT    NOT NULL DEFAULT 'General',
      precio     REAL    NOT NULL,
      disponible INTEGER DEFAULT 1,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS comandas (
      id            SERIAL PRIMARY KEY,
      mesa_id       INTEGER REFERENCES mesas_restaurante(id),
      mozo_id       INTEGER REFERENCES usuarios(id),
      mozo_nombre   TEXT    DEFAULT '',
      comensales    INTEGER DEFAULT 0,
      observaciones TEXT    DEFAULT '',
      estado        TEXT    NOT NULL DEFAULT 'abierta',
      total         REAL    DEFAULT 0,
      total_final   REAL,
      descuento     REAL    DEFAULT 0,
      metodo_pago   TEXT    DEFAULT 'Efectivo',
      cajero_id     INTEGER REFERENCES usuarios(id),
      cajero_nombre TEXT    DEFAULT '',
      abierta_at    TIMESTAMP DEFAULT NOW(),
      cerrada_at    TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS comanda_items (
      id          SERIAL PRIMARY KEY,
      comanda_id  INTEGER REFERENCES comandas(id) ON DELETE CASCADE,
      producto_id INTEGER REFERENCES menu_restaurante(id),
      nombre      TEXT    NOT NULL,
      precio      REAL    NOT NULL,
      cantidad    INTEGER DEFAULT 1,
      nota        TEXT    DEFAULT '',
      entregado   INTEGER DEFAULT 0,
      created_at  TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS reservas_restaurante (
      id       SERIAL PRIMARY KEY,
      mesa_id  INTEGER REFERENCES mesas_restaurante(id),
      nombre   TEXT    NOT NULL,
      hora     TEXT    NOT NULL,
      personas INTEGER DEFAULT 1,
      telefono TEXT    DEFAULT '',
      notas    TEXT    DEFAULT '',
      fecha    DATE    DEFAULT CURRENT_DATE,
      estado   TEXT    DEFAULT 'activa',
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS turnos_restaurante (
      id            SERIAL PRIMARY KEY,
      cajero_id     INTEGER REFERENCES usuarios(id),
      cajero_nombre TEXT    DEFAULT '',
      fondo_inicial REAL    DEFAULT 0,
      estado        TEXT    DEFAULT 'abierto',
      abierto_at    TIMESTAMP DEFAULT NOW(),
      cerrado_at    TIMESTAMP
    );
  `);

  // Seed mesas restaurante
  const countMesas = await getOne('SELECT COUNT(*) as c FROM mesas_restaurante');
  if (parseInt(countMesas.c) === 0) {
    const mesasIniciales = [
      { tipo:'redonda',     x:240, y:20  },
      { tipo:'redonda',     x:320, y:20  },
      { tipo:'redonda',     x:400, y:20  },
      { tipo:'redonda',     x:480, y:20  },
      { tipo:'redonda',     x:560, y:20  },
      { tipo:'redonda',     x:20,  y:120 },
      { tipo:'rectangular', x:160, y:120 },
      { tipo:'rectangular', x:310, y:120 },
      { tipo:'rectangular', x:460, y:120 },
      { tipo:'rectangular', x:610, y:120 },
      { tipo:'rectangular', x:760, y:120 },
      { tipo:'redonda',     x:20,  y:220 },
      { tipo:'redonda',     x:100, y:220 },
      { tipo:'rectangular', x:200, y:220 },
      { tipo:'rectangular', x:350, y:220 },
      { tipo:'rectangular', x:500, y:220 },
      { tipo:'rectangular', x:650, y:220 },
      { tipo:'rectangular', x:800, y:220 },
    ];
    for (const m of mesasIniciales) {
      await query('INSERT INTO mesas_restaurante (tipo,x,y) VALUES ($1,$2,$3)', [m.tipo, m.x, m.y]);
    }
    console.log('✅ 18 mesas de restaurante creadas');
  }

  // Seed menú restaurante
  const countMenu = await getOne('SELECT COUNT(*) as c FROM menu_restaurante');
  if (parseInt(countMenu.c) === 0) {
    const items = [
      ['Empanadas (x3)',          'Entradas',    2800],
      ['Tabla de fiambres',       'Entradas',    4500],
      ['Milanesa napolitana',     'Principales', 6800],
      ['Bife de chorizo',         'Principales', 8500],
      ['Pasta del día',           'Principales', 5200],
      ['Agua mineral',            'Bebidas',      900],
      ['Gaseosa',                 'Bebidas',     1200],
      ['Vino (copa)',              'Bebidas',     2200],
      ['Cerveza',                 'Bebidas',     1800],
      ['Flan con dulce de leche', 'Postres',     2100],
      ['Tiramisú',                'Postres',     2600],
    ];
    for (const [nombre, categoria, precio] of items) {
      await query('INSERT INTO menu_restaurante (nombre,categoria,precio) VALUES ($1,$2,$3)', [nombre, categoria, precio]);
    }
    console.log('✅ Menú restaurante creado');
  }

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
    console.log('✅ 28 habitaciones creadas');
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
