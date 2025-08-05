#!/usr/bin/env node
// =============================================================================
// scripts/setup.js - Script de configuración inicial del proyecto
// =============================================================================
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { execSync } from "child_process";
import crypto from "crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.join(__dirname, "..");

// Colores para la consola
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
};

const log = {
  info: (msg) => console.log(`${colors.blue}ℹ${colors.reset} ${msg}`),
  success: (msg) => console.log(`${colors.green}✅${colors.reset} ${msg}`),
  warning: (msg) => console.log(`${colors.yellow}⚠️${colors.reset} ${msg}`),
  error: (msg) => console.log(`${colors.red}❌${colors.reset} ${msg}`),
  title: (msg) =>
    console.log(`\n${colors.bright}${colors.cyan}🚀 ${msg}${colors.reset}\n`),
};

/**
 * Generar secreto JWT seguro
 */
function generateJWTSecret() {
  return crypto.randomBytes(64).toString("hex");
}

/**
 * Generar secreto de sesión
 */
function generateSessionSecret() {
  return crypto.randomBytes(32).toString("hex");
}

/**
 * Crear archivo .env desde .env.example
 */
function createEnvFile() {
  const envExamplePath = path.join(rootDir, ".env.example");
  const envPath = path.join(rootDir, ".env");

  if (fs.existsSync(envPath)) {
    log.warning("El archivo .env ya existe, no se sobrescribirá");
    return false;
  }

  if (!fs.existsSync(envExamplePath)) {
    log.error("No se encontró el archivo .env.example");
    return false;
  }

  try {
    let envContent = fs.readFileSync(envExamplePath, "utf8");

    // Reemplazar valores por defecto con valores generados
    envContent = envContent.replace(
      "JWT_SECRET=your-super-secret-jwt-key-change-in-production-minimum-32-chars",
      `JWT_SECRET=${generateJWTSecret()}`
    );

    envContent = envContent.replace(
      "SESSION_SECRET=your-session-secret-change-in-production",
      `SESSION_SECRET=${generateSessionSecret()}`
    );

    fs.writeFileSync(envPath, envContent);
    log.success("Archivo .env creado exitosamente");
    return true;
  } catch (error) {
    log.error(`Error creando archivo .env: ${error.message}`);
    return false;
  }
}

/**
 * Crear directorios necesarios
 */
function createDirectories() {
  const directories = [
    "logs",
    "uploads",
    "temp",
    "public",
    "backups",
    "coverage",
    "docs/api",
  ];

  directories.forEach((dir) => {
    const dirPath = path.join(rootDir, dir);
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true });
      log.success(`Directorio creado: ${dir}`);
    }
  });
}

/**
 * Instalar dependencias npm
 */
function installDependencies() {
  try {
    log.info("Instalando dependencias de producción...");
    execSync("npm install --production=false", {
      stdio: "inherit",
      cwd: rootDir,
    });
    log.success("Dependencias instaladas exitosamente");
    return true;
  } catch (error) {
    log.error(`Error instalando dependencias: ${error.message}`);
    return false;
  }
}

/**
 * Verificar MongoDB
 */
function checkMongoDB() {
  try {
    log.info("Verificando conexión a MongoDB...");
    execSync("mongosh --version", { stdio: "pipe" });
    log.success("MongoDB CLI encontrado");

    // Intentar conectar a MongoDB (solo verificación, no crear conexión permanente)
    try {
      execSync('mongosh --eval "db.runCommand({ping: 1})" --quiet', {
        stdio: "pipe",
        timeout: 5000,
      });
      log.success("MongoDB está corriendo y accesible");
      return true;
    } catch (mongoError) {
      log.warning("MongoDB no está corriendo o no es accesible");
      log.info(
        "Asegúrate de que MongoDB esté corriendo en: mongodb://localhost:27017"
      );
      return false;
    }
  } catch (error) {
    log.warning("MongoDB CLI no encontrado");
    log.info(
      "Instala MongoDB desde: https://www.mongodb.com/try/download/community"
    );
    return false;
  }
}

/**
 * Crear archivos de configuración adicionales
 */
function createConfigFiles() {
  // Crear .gitignore si no existe
  const gitignorePath = path.join(rootDir, ".gitignore");
  if (!fs.existsSync(gitignorePath)) {
    const gitignoreContent = `# Dependencies
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Environment variables
.env
.env.local
.env.production

# Logs
logs/
*.log

# Runtime data
pids/
*.pid
*.seed
*.pid.lock

# Coverage directory used by tools like istanbul
coverage/
.coverage/

# Uploads and temporary files
uploads/
temp/
tmp/

# IDE files
.vscode/
.idea/
*.swp
*.swo

# OS files
.DS_Store
Thumbs.db

# Database
*.db
*.sqlite

# Backups
backups/

# Docker
.dockerignore
Dockerfile
docker-compose.yml

# Build outputs
dist/
build/
`;
    fs.writeFileSync(gitignorePath, gitignoreContent);
    log.success("Archivo .gitignore creado");
  }

  // Crear README.md básico si no existe
  const readmePath = path.join(rootDir, "README.md");
  if (!fs.existsSync(readmePath)) {
    const readmeContent = `# Life Business Platform

Plataforma de geolocalización de empresas con sistema multiidioma y autenticación avanzada.

## 🚀 Inicio Rápido

1. Instalar dependencias:
   \`\`\`bash
   npm install
   \`\`\`

2. Configurar variables de entorno:
   \`\`\`bash
   cp .env.example .env
   # Editar .env con tus configuraciones
   \`\`\`

3. Iniciar MongoDB

4. Ejecutar la aplicación:
   \`\`\`bash
   npm run dev
   \`\`\`

## 📚 Documentación

- API Docs: http://localhost:3000/api
- Health Check: http://localhost:3000/health

## 🛠️ Scripts Disponibles

- \`npm start\` - Iniciar en producción
- \`npm run dev\` - Modo desarrollo con nodemon
- \`npm test\` - Ejecutar tests
- \`npm run lint\` - Verificar código
- \`npm run setup\` - Configuración inicial

## 🏗️ Arquitectura

- **Backend**: Node.js + Express
- **Base de datos**: MongoDB
- **Autenticación**: JWT + Sessions
- **Cache**: Redis (opcional)
- **Traducciones**: OpenAI GPT

## 📁 Estructura del Proyecto

\`\`\`
src/
├── config/          # Configuraciones
├── modules/         # Módulos de negocio
├── security/        # Autenticación y seguridad
├── system/          # Utilidades del sistema
└── utils/           # Funciones auxiliares
\`\`\`
`;
    fs.writeFileSync(readmePath, readmeContent);
    log.success("Archivo README.md creado");
  }
}

/**
 * Ejecutar tests básicos
 */
function runBasicTests() {
  try {
    log.info("Ejecutando verificaciones básicas...");

    // Verificar que Node.js tenga la versión correcta
    const nodeVersion = process.version;
    const majorVersion = parseInt(nodeVersion.replace("v", "").split(".")[0]);

    if (majorVersion < 18) {
      log.warning(
        `Node.js ${nodeVersion} detectado. Se recomienda Node.js 18+`
      );
    } else {
      log.success(`Node.js ${nodeVersion} ✅`);
    }

    // Verificar que los archivos principales existan
    const requiredFiles = [
      "index.js",
      "package.json",
      ".env",
      "src/config/database.mongo.js",
      "src/config/logger.js",
      "src/security/authentication/authentication.index.js",
    ];

    let allFilesExist = true;
    requiredFiles.forEach((file) => {
      const filePath = path.join(rootDir, file);
      if (fs.existsSync(filePath)) {
        log.success(`${file} ✅`);
      } else {
        log.error(`${file} ❌ (falta)`);
        allFilesExist = false;
      }
    });

    return allFilesExist;
  } catch (error) {
    log.error(`Error en verificaciones: ${error.message}`);
    return false;
  }
}

/**
 * Mostrar resumen final
 */
function showSummary(success) {
  console.log("\n" + "=".repeat(60));

  if (success) {
    log.title("🎉 CONFIGURACIÓN COMPLETADA");
    console.log("La configuración inicial se completó exitosamente.\n");

    console.log("📋 Próximos pasos:");
    console.log("   1. Editar el archivo .env con tus configuraciones");
    console.log("   2. Asegurar que MongoDB esté corriendo");
    console.log("   3. Ejecutar: npm run dev");
    console.log("   4. Visitar: http://localhost:3000/health\n");

    console.log("📚 Documentación adicional:");
    console.log("   - API: http://localhost:3000/api");
    console.log("   - Logs: ./logs/");
    console.log("   - README.md para más información\n");
  } else {
    log.title("⚠️  CONFIGURACIÓN INCOMPLETA");
    console.log("Algunos pasos fallaron. Revisa los errores arriba.\n");

    console.log("🔧 Solución de problemas:");
    console.log("   - Verifica que Node.js 18+ esté instalado");
    console.log("   - Instala MongoDB Community Edition");
    console.log("   - Ejecuta: npm install");
    console.log("   - Revisa permisos de archivos\n");
  }

  console.log("=".repeat(60));
}

/**
 * Función principal de setup
 */
async function main() {
  log.title("CONFIGURACIÓN INICIAL - Life Business Platform");

  let success = true;

  try {
    // Paso 1: Crear directorios
    log.title("Paso 1: Creando directorios necesarios");
    createDirectories();

    // Paso 2: Crear archivo .env
    log.title("Paso 2: Configurando variables de entorno");
    createEnvFile();

    // Paso 3: Instalar dependencias
    log.title("Paso 3: Instalando dependencias");
    if (!installDependencies()) {
      success = false;
    }

    // Paso 4: Verificar MongoDB
    log.title("Paso 4: Verificando MongoDB");
    if (!checkMongoDB()) {
      success = false;
    }

    // Paso 5: Crear archivos de configuración
    log.title("Paso 5: Creando archivos de configuración");
    createConfigFiles();

    // Paso 6: Ejecutar tests básicos
    log.title("Paso 6: Verificaciones finales");
    if (!runBasicTests()) {
      success = false;
    }
  } catch (error) {
    log.error(`Error durante la configuración: ${error.message}`);
    success = false;
  }

  // Mostrar resumen
  showSummary(success);

  process.exit(success ? 0 : 1);
}

// Ejecutar si este archivo es llamado directamente
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
