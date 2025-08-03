// =============================================================================
// src/config/database.mongo.js
// =============================================================================
import mongoose from "mongoose";
import mongoosePaginate from "mongoose-paginate-v2";

/**
 * Configuración y conexión a MongoDB con gestión de errores y reconexión
 */
class DatabaseManager {
  constructor() {
    this.isConnected = false;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectInterval = 5000; // 5 segundos
  }

  /**
   * Conectar a MongoDB con configuración optimizada
   */
  async connect() {
    try {
      // Configuración de mongoose
      mongoose.set("strictQuery", false);

      // Plugin global para paginación
      mongoose.plugin(mongoosePaginate);

      // Opciones de conexión optimizadas
      const options = {
        // Configuración de conexión
        maxPoolSize: 10, // Máximo 10 conexiones en el pool
        serverSelectionTimeoutMS: 5000, // Timeout para seleccionar servidor
        socketTimeoutMS: 45000, // Timeout para socket
        bufferMaxEntries: 0, // Disable mongoose buffering
        bufferCommands: false, // Disable mongoose buffering

        // Configuración de replica set y clustering
        readPreference: "primary", // Leer desde el primario
        w: "majority", // Write concern majority
        retryWrites: true, // Reintentar escrituras
        retryReads: true, // Reintentar lecturas

        // Configuración de autenticación
        authSource: "admin", // Fuente de autenticación

        // Configuración de heartbeat
        heartbeatFrequencyMS: 10000, // Frecuencia de heartbeat

        // Configuración para desarrollo vs producción
        ...(process.env.NODE_ENV === "production"
          ? {
              ssl: true, // SSL en producción
              sslValidate: true,
            }
          : {}),
      };

      // URI de conexión
      const mongoUri =
        process.env.MONGODB_URI || "mongodb://localhost:27017/life";

      console.log("🔌 Conectando a MongoDB...");
      console.log(`📍 URI: ${mongoUri.replace(/\/\/.*@/, "//***:***@")}`); // Ocultar credenciales

      // Realizar conexión
      await mongoose.connect(mongoUri, options);

      this.isConnected = true;
      this.reconnectAttempts = 0;

      console.log("✅ MongoDB conectado exitosamente");
      console.log(`📊 Base de datos: ${mongoose.connection.name}`);

      // Información de la conexión
      await this.logConnectionInfo();

      // Configurar event listeners
      this.setupEventListeners();

      return mongoose.connection;
    } catch (error) {
      console.error("❌ Error conectando a MongoDB:", error.message);
      await this.handleConnectionError(error);
      throw error;
    }
  }

  /**
   * Configurar listeners de eventos de MongoDB
   */
  setupEventListeners() {
    const db = mongoose.connection;

    // Evento de conexión exitosa
    db.on("connected", () => {
      console.log("🟢 MongoDB - Estado: Conectado");
      this.isConnected = true;
    });

    // Evento de desconexión
    db.on("disconnected", () => {
      console.log("🔴 MongoDB - Estado: Desconectado");
      this.isConnected = false;

      // Intentar reconectar si no es un cierre intencional
      if (this.reconnectAttempts < this.maxReconnectAttempts) {
        this.attemptReconnect();
      }
    });

    // Evento de error
    db.on("error", (error) => {
      console.error("❌ MongoDB - Error:", error.message);

      // Si es un error de red, intentar reconectar
      if (
        error.name === "MongoNetworkError" ||
        error.name === "MongoServerSelectionError"
      ) {
        this.handleConnectionError(error);
      }
    });

    // Evento de reconexión
    db.on("reconnected", () => {
      console.log("🔄 MongoDB - Reconectado exitosamente");
      this.isConnected = true;
      this.reconnectAttempts = 0;
    });

    // Evento de cierre de aplicación
    process.on("SIGINT", () => {
      this.gracefulShutdown("SIGINT");
    });

    process.on("SIGTERM", () => {
      this.gracefulShutdown("SIGTERM");
    });
  }

  /**
   * Manejar errores de conexión y reintentos
   */
  async handleConnectionError(error) {
    console.error(
      `💥 Error de conexión MongoDB (intento ${this.reconnectAttempts + 1}):`,
      error.message
    );

    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      await this.attemptReconnect();
    } else {
      console.error(
        "🚨 Máximo número de reintentos alcanzado. Revisar conexión a MongoDB."
      );

      // En producción, podrías querer salir del proceso
      if (process.env.NODE_ENV === "production") {
        console.error(
          "🔴 Cerrando aplicación por falta de conexión a base de datos"
        );
        process.exit(1);
      }
    }
  }

  /**
   * Intentar reconexión con backoff exponencial
   */
  async attemptReconnect() {
    this.reconnectAttempts++;
    const delay =
      this.reconnectInterval * Math.pow(2, this.reconnectAttempts - 1); // Backoff exponencial

    console.log(
      `🔄 Intentando reconectar en ${delay / 1000} segundos... (intento ${
        this.reconnectAttempts
      }/${this.maxReconnectAttempts})`
    );

    setTimeout(async () => {
      try {
        await mongoose.connect(
          process.env.MONGODB_URI || "mongodb://localhost:27017/life"
        );
        console.log("✅ Reconexión exitosa");
      } catch (error) {
        console.error("❌ Fallo en reconexión:", error.message);
      }
    }, delay);
  }

  /**
   * Cerrar conexión de forma elegante
   */
  async gracefulShutdown(signal) {
    console.log(`\n📡 Señal ${signal} recibida. Cerrando conexión MongoDB...`);

    try {
      await mongoose.connection.close();
      console.log("✅ Conexión MongoDB cerrada correctamente");
      process.exit(0);
    } catch (error) {
      console.error("❌ Error cerrando conexión MongoDB:", error.message);
      process.exit(1);
    }
  }

  /**
   * Obtener información detallada de la conexión
   */
  async logConnectionInfo() {
    try {
      const admin = mongoose.connection.db.admin();
      const serverStatus = await admin.command({ serverStatus: 1 });
      const buildInfo = await admin.command({ buildInfo: 1 });

      console.log("📋 Información de MongoDB:");
      console.log(`   🏷️  Versión: ${buildInfo.version}`);
      console.log(`   🏠 Host: ${serverStatus.host}`);
      console.log(
        `   ⏰ Uptime: ${Math.floor(serverStatus.uptime / 3600)} horas`
      );
      console.log(
        `   💾 Storage Engine: ${serverStatus.storageEngine?.name || "N/A"}`
      );

      // Verificar si es replica set
      if (serverStatus.repl) {
        console.log(`   🔗 Replica Set: ${serverStatus.repl.setName}`);
        console.log(`   👑 Es Primary: ${serverStatus.repl.ismaster}`);
      } else {
        console.log("   📍 Configuración: Standalone");
      }
    } catch (error) {
      console.warn(
        "⚠️  No se pudo obtener información del servidor:",
        error.message
      );
    }
  }

  /**
   * Verificar estado de la conexión
   */
  isConnectionHealthy() {
    return mongoose.connection.readyState === 1; // 1 = connected
  }

  /**
   * Obtener estadísticas de la conexión
   */
  getConnectionStats() {
    const connection = mongoose.connection;

    return {
      state: this.getConnectionStateString(connection.readyState),
      name: connection.name,
      host: connection.host,
      port: connection.port,
      isConnected: this.isConnected,
      reconnectAttempts: this.reconnectAttempts,
      collections: Object.keys(connection.collections),
      models: Object.keys(mongoose.models),
    };
  }

  /**
   * Convertir estado numérico a string legible
   */
  getConnectionStateString(state) {
    const states = {
      0: "disconnected",
      1: "connected",
      2: "connecting",
      3: "disconnecting",
    };
    return states[state] || "unknown";
  }

  /**
   * Limpiar todas las colecciones (solo para desarrollo/testing)
   */
  async clearDatabase() {
    if (process.env.NODE_ENV === "production") {
      throw new Error("No se puede limpiar la base de datos en producción");
    }

    console.log("🧹 Limpiando base de datos...");

    const collections = Object.keys(mongoose.connection.collections);

    for (const collectionName of collections) {
      const collection = mongoose.connection.collections[collectionName];
      await collection.deleteMany({});
      console.log(`   ✅ Colección '${collectionName}' limpiada`);
    }

    console.log("🧹 Base de datos limpiada completamente");
  }

  /**
   * Crear índices para todas las colecciones
   */
  async ensureIndexes() {
    console.log("🔍 Creando índices...");

    try {
      await mongoose.connection.db.command({
        createIndexes: "users",
        indexes: [
          { key: { email: 1 }, name: "email_1", unique: true },
          { key: { isDeleted: 1, createdAt: -1 }, name: "deleted_created_idx" },
        ],
      });

      console.log("✅ Índices creados exitosamente");
    } catch (error) {
      console.warn("⚠️  Error creando índices:", error.message);
    }
  }
}

// Instancia única del manejador de base de datos
const databaseManager = new DatabaseManager();

/**
 * Función principal para conectar a la base de datos
 */
export const connectToDatabase = async () => {
  return await databaseManager.connect();
};

/**
 * Función para obtener estadísticas de conexión
 */
export const getDatabaseStats = () => {
  return databaseManager.getConnectionStats();
};

/**
 * Función para verificar salud de la conexión
 */
export const isDatabaseHealthy = () => {
  return databaseManager.isConnectionHealthy();
};

/**
 * Función para limpiar base de datos (desarrollo)
 */
export const clearDatabase = async () => {
  return await databaseManager.clearDatabase();
};

/**
 * Función para crear índices
 */
export const ensureIndexes = async () => {
  return await databaseManager.ensureIndexes();
};

// Exportar la instancia del manejador para uso avanzado
export { databaseManager };

// Configuración de mongoose para mejores mensajes de error
mongoose.Error.messages.general.required = "El campo '{PATH}' es requerido";
mongoose.Error.messages.String.enum =
  "'{VALUE}' no es válido para el campo '{PATH}'";
mongoose.Error.messages.String.maxlength =
  "El campo '{PATH}' excede la longitud máxima de {MAXLENGTH} caracteres";
mongoose.Error.messages.String.minlength =
  "El campo '{PATH}' debe tener al menos {MINLENGTH} caracteres";

export default databaseManager;
