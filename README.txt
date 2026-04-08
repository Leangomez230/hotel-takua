═══════════════════════════════════════════════════════════
  HOTEL TAKUÁ — Guía de instalación en Hostinger
═══════════════════════════════════════════════════════════

ARCHIVOS INCLUIDOS:
  📁 hotel-takua/
      ├── server.js          → Backend (API)
      ├── database.js        → Base de datos
      ├── package.json       → Dependencias
      └── public/
          └── index.html     → Frontend (app web)

───────────────────────────────────────────────────────────
PASO 1 — Activar Node.js en Hostinger
───────────────────────────────────────────────────────────
1. Entrá al panel de Hostinger (hpanel.hostinger.com)
2. Andá a "Hosting" → seleccioná tu plan
3. Buscá la sección "Node.js" o "Aplicaciones Node"
4. Hacé clic en "Habilitar Node.js"
5. Elegí la versión Node.js 18 o superior
6. Anotá el puerto asignado (Hostinger lo asigna automáticamente)

───────────────────────────────────────────────────────────
PASO 2 — Subir los archivos
───────────────────────────────────────────────────────────
OPCIÓN A — Por el Administrador de archivos de Hostinger:
  1. Andá a "Administrador de archivos" en el panel
  2. Abrí la carpeta de tu dominio (public_html o la raíz)
  3. Creá una carpeta llamada "hotel-takua"
  4. Subí dentro todos los archivos manteniendo la estructura:
       hotel-takua/server.js
       hotel-takua/database.js
       hotel-takua/package.json
       hotel-takua/public/index.html

OPCIÓN B — Por SSH (si tenés acceso):
  ssh usuario@tudominio.com
  mkdir hotel-takua
  # Copiar archivos con SCP o FileZilla

───────────────────────────────────────────────────────────
PASO 3 — Instalar dependencias
───────────────────────────────────────────────────────────
En el terminal SSH de Hostinger:
  cd hotel-takua
  npm install

Esto descarga: express, better-sqlite3, bcryptjs, jsonwebtoken, cors

───────────────────────────────────────────────────────────
PASO 4 — Configurar variables de entorno
───────────────────────────────────────────────────────────
En el panel de Node.js de Hostinger, agregá estas variables:
  JWT_SECRET = una_clave_secreta_larga_y_unica_para_tu_hotel
  PORT = (el puerto que Hostinger te asignó)

⚠️ IMPORTANTE: Cambiá JWT_SECRET por una cadena larga y
   aleatoria. Por ejemplo: "takua_2024_hotel_secreto_xyz789"

───────────────────────────────────────────────────────────
PASO 5 — Iniciar la aplicación
───────────────────────────────────────────────────────────
En el panel de Node.js de Hostinger:
  - Entry point: server.js
  - Hacé clic en "Start" o "Restart"

O por SSH:
  cd hotel-takua
  npm start

───────────────────────────────────────────────────────────
PASO 6 — Acceder a la app
───────────────────────────────────────────────────────────
Abrí en el navegador: https://tudominio.com

CREDENCIALES INICIALES:
  📧 Email:      admin@hoteltakua.com
  🔑 Contraseña: admin123

⚠️ IMPORTANTE: Cambiá la contraseña del admin
   inmediatamente después del primer login.
   Andá a Configuración → Usuarios → Editar.

───────────────────────────────────────────────────────────
PASO 7 — Crear usuarios para tu equipo
───────────────────────────────────────────────────────────
Desde la app, andá a "Configuración" y creá los usuarios:
  - Para cada recepcionista: rol "Recepcionista"
  - Para las mucamas: rol "Mucama"
  - Solo el dueño: rol "Administrador"

───────────────────────────────────────────────────────────
USO DIARIO
───────────────────────────────────────────────────────────

RECEPCIONISTA:
  ✅ Abrir caja al inicio del turno
  ✅ Hacer check-in a nuevos huéspedes
  ✅ Registrar reservas
  ✅ Vender productos desde la Tienda
  ✅ Cerrar caja al final del turno

MUCAMA (desde su tablet):
  ✅ Ver habitaciones en estado "Limpieza"
  ✅ Marcarlas como "Disponible" cuando terminan
  ✅ Marcar incidencias en notas

ADMINISTRADOR:
  ✅ Ver finanzas y reportes
  ✅ Gestionar inventario
  ✅ Crear/modificar usuarios
  ✅ Ver historial completo de acciones

───────────────────────────────────────────────────────────
SOPORTE TÉCNICO
───────────────────────────────────────────────────────────
Si algo no funciona:
  1. Verificá que Node.js esté activo en el panel
  2. Revisá los logs en el panel de Hostinger
  3. Asegurate que la carpeta "public" esté dentro de "hotel-takua"
  4. Verificá que el archivo hotel.db se haya creado (la BD se crea sola)

La base de datos (hotel.db) se crea automáticamente con:
  - 28 habitaciones (14 Ala Este + 14 Ala Oeste)
  - Usuario admin por defecto
  - Productos de ejemplo para la tienda

═══════════════════════════════════════════════════════════
¡Éxitos con Hotel Takuá! 🏨
═══════════════════════════════════════════════════════════
