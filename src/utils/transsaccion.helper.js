import mongoose from "mongoose";

// Helper mejorado para detectar soporte de transacciones
export class TransactionHelper {
  static _transactionSupport = null; // Cache del soporte de transacciones

  static async checkTransactionSupport() {
    // Si ya verificamos antes, usar el cache
    if (this._transactionSupport !== null) {
      return this._transactionSupport;
    }

    try {
      // Método más eficiente: verificar la configuración del servidor
      const admin = mongoose.connection.db.admin();
      const result = await admin.command({ isMaster: 1 });

      // Verificar si es un replica set o sharded cluster
      const hasReplicaSet = !!(result.setName || result.msg === "isdbgrid");

      if (hasReplicaSet) {
        // Si parece que debería soportar transacciones, hacer una prueba real
        const session = await mongoose.startSession();
        try {
          await session.withTransaction(async () => {
            // Test básico - no hace nada real
          });
          await session.endSession();

          console.log(
            "✅ Transacciones disponibles (Replica Set/Cluster detectado)"
          );
          this._transactionSupport = true;
          return true;
        } catch (error) {
          await session.endSession();

          // Verificar si es el error específico de transacciones
          if (error.code === 20 || error.codeName === "IllegalOperation") {
            console.log(
              "⚠️  Transacciones NO disponibles (MongoDB Standalone detectado)"
            );
            this._transactionSupport = false;
            return false;
          }

          // Otro tipo de error - asumir que no hay soporte
          console.warn("⚠️  Error verificando transacciones:", error.message);
          this._transactionSupport = false;
          return false;
        }
      } else {
        console.log("⚠️  Transacciones NO disponibles (MongoDB Standalone)");
        this._transactionSupport = false;
        return false;
      }
    } catch (error) {
      console.warn(
        "⚠️  Error verificando configuración de MongoDB:",
        error.message
      );
      this._transactionSupport = false;
      return false;
    }
  }

  static async executeWithOptionalTransaction(operation) {
    const hasTransactionSupport = await this.checkTransactionSupport();

    if (hasTransactionSupport) {
      console.log("🔄 Ejecutando operación CON transacciones...");
      const session = await mongoose.startSession();

      try {
        let result;
        await session.withTransaction(async () => {
          result = await operation(session);
        });

        console.log("✅ Operación completada exitosamente con transacciones");
        return result;
      } catch (error) {
        console.error("❌ Error durante transacción:", error.message);

        // Si el error es específicamente de transacciones, marcar como no soportadas
        if (error.code === 20 || error.codeName === "IllegalOperation") {
          console.log(
            "⚠️  Transacciones no soportadas, reintentando sin transacciones..."
          );
          this._transactionSupport = false;

          // Reintentar sin transacciones
          return await operation(null);
        }

        throw error;
      } finally {
        await session.endSession();
      }
    } else {
      console.log(
        "🔄 Ejecutando operación SIN transacciones (modo standalone)..."
      );

      try {
        const result = await operation(null);
        console.log("✅ Operación completada exitosamente sin transacciones");
        return result;
      } catch (error) {
        console.error(
          "❌ Error durante operación sin transacciones:",
          error.message
        );

        // Si aún así obtenemos un error de transacciones, es un problema de configuración
        if (error.code === 20 || error.codeName === "IllegalOperation") {
          throw new Error(
            "Error de configuración: Se está intentando usar transacciones en MongoDB Standalone. " +
              "Para usar transacciones, configure MongoDB como Replica Set o use MongoDB Atlas."
          );
        }

        throw error;
      }
    }
  }

  // Método para resetear el cache (útil para testing o cambios de configuración)
  static resetTransactionSupportCache() {
    this._transactionSupport = null;
    console.log("🔄 Cache de soporte de transacciones reseteado");
  }

  // Método para obtener información detallada del estado de MongoDB
  static async getMongoDBInfo() {
    try {
      const admin = mongoose.connection.db.admin();
      const result = await admin.command({ isMaster: 1 });

      return {
        isReplicaSet: !!result.setName,
        isMongos: result.msg === "isdbgrid",
        setName: result.setName || null,
        primary: result.primary || null,
        transactionSupport: await this.checkTransactionSupport(),
        mongoVersion: result.version || "unknown",
      };
    } catch (error) {
      console.error("Error obteniendo información de MongoDB:", error);
      return {
        isReplicaSet: false,
        isMongos: false,
        setName: null,
        primary: null,
        transactionSupport: false,
        mongoVersion: "unknown",
        error: error.message,
      };
    }
  }
}
