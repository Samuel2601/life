// =============================================================================
// src/security/audit/models/AuditLog.js - VERSION MEJORADA SIMPLE
// =============================================================================
import mongoose from "mongoose";

/**
 * Schema para información contextual de la aplicación
 */
const ApplicationContextSchema = new mongoose.Schema(
  {
    module: {
      type: String,
      required: true,
      maxlength: 100,
      index: true, // Para filtrar por módulo
    },
    action: {
      type: String,
      required: true,
      maxlength: 100,
    },
    endpoint: {
      type: String,
      maxlength: 200, // Útil para debugging
    },
    method: {
      type: String,
      enum: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    },
    correlationId: {
      type: String,
      maxlength: 100,
      index: true, // Para rastrear operaciones relacionadas
    },
    sessionId: {
      type: String,
      maxlength: 100,
      index: true, // Para análisis de sesión
    },
    transactionId: {
      type: String,
      maxlength: 100, // Para operaciones transaccionales
    },
  },
  { _id: false }
);

/**
 * Schema principal de AuditLog - Optimizado para MVP
 */
const AuditLogSchema = new mongoose.Schema({
  // Identificación del registro afectado
  targetCollection: {
    type: String,
    required: true,
    index: true,
    enum: [
      "User",
      "Business",
      "Address",
      "BusinessCategory",
      "Review",
      "UserSession",
      "Role",
      "TranslationCache",
      "Media",
      "NewsArticle",
    ],
  },

  targetDocumentId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    index: true,
  },

  // Información del cambio
  changeType: {
    type: String,
    required: true,
    enum: ["create", "update", "delete", "restore", "read", "export"],
    index: true,
  },

  // ESTADO ANTERIOR (clave del sistema)
  previousValues: {
    type: mongoose.Schema.Types.Mixed,
    required: function () {
      return ["update", "delete"].includes(this.changeType);
    },
  },

  // Valores nuevos (para creates y updates)
  newValues: {
    type: mongoose.Schema.Types.Mixed,
  },

  // Campos que cambiaron
  changedFields: [
    {
      type: String,
      maxlength: 100,
    },
  ],

  // Metadatos del cambio
  changedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true,
  },

  changedAt: {
    type: Date,
    default: Date.now,
    required: true,
    index: true,
  },

  changeReason: {
    type: String,
    maxlength: 500,
  },

  // Información contextual básica pero suficiente
  ipAddress: {
    type: String,
    required: true,
    index: true,
    validate: {
      validator: function (ip) {
        // Validación básica IPv4/IPv6
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        return (
          ipv4Regex.test(ip) ||
          ipv6Regex.test(ip) ||
          ip === "::1" ||
          ip === "127.0.0.1"
        );
      },
      message: "Formato de IP inválido",
    },
  },

  userAgent: {
    type: String,
    required: true,
    maxlength: 1000,
  },

  // Información de sesión
  sessionId: {
    type: String,
    index: true,
    maxlength: 100,
  },

  deviceFingerprint: {
    type: String,
    maxlength: 64, // Para detección de dispositivos sospechosos
  },

  // Versionado (crítico para reconstrucción histórica)
  version: {
    type: Number,
    required: true,
    min: 1,
    index: true,
  },

  previousVersion: {
    type: Number,
    required: true,
    min: 0,
  },

  // Soft delete tracking
  isDeleteAction: {
    type: Boolean,
    default: false,
    index: true,
  },

  deletedAt: {
    type: Date,
  },

  restoredAt: {
    type: Date,
  },

  // Contexto de aplicación
  applicationContext: {
    type: ApplicationContextSchema,
  },

  // Nivel de riesgo básico (simple pero efectivo)
  riskLevel: {
    type: String,
    enum: ["low", "medium", "high", "critical"],
    default: "low",
    index: true,
  },

  // Categoría del evento (para reportes)
  category: {
    type: String,
    enum: [
      "authentication",
      "authorization",
      "data_access",
      "data_modification",
      "user_management",
      "business_operation",
      "security_event",
      "system_event",
    ],
    default: "data_modification",
    index: true,
  },

  // Severidad (para alertas)
  severity: {
    type: String,
    enum: ["info", "warning", "error", "critical"],
    default: "info",
    index: true,
  },

  // Etiquetas para filtrado
  tags: [String],

  // Para compliance y reportes
  retentionDate: {
    type: Date,
    index: true, // TTL index según políticas de retención
  },

  // Información básica de geolocalización (opcional)
  location: {
    country: String,
    city: String,
  },

  // Hash de integridad simple
  integrityHash: {
    type: String,
    length: 64, // SHA-256
  },

  // Para análisis de patrones
  isAutomated: {
    type: Boolean,
    default: false, // True para cambios automáticos del sistema
  },

  batchId: {
    type: String, // Para operaciones en lote
    index: true,
  },
});

// ================================
// ÍNDICES OPTIMIZADOS
// ================================

// Índices principales para reconstrucción histórica
AuditLogSchema.index({
  targetCollection: 1,
  targetDocumentId: 1,
  version: -1,
});

AuditLogSchema.index({
  targetCollection: 1,
  targetDocumentId: 1,
  changedAt: -1,
});

// Índices para consultas de usuarios
AuditLogSchema.index({
  changedBy: 1,
  changedAt: -1,
});

// Índices para análisis de seguridad
AuditLogSchema.index({
  ipAddress: 1,
  changedAt: -1,
});

AuditLogSchema.index({
  riskLevel: 1,
  severity: 1,
  changedAt: -1,
});

// Índices para reportes
AuditLogSchema.index({
  category: 1,
  changedAt: -1,
});

AuditLogSchema.index({
  changeType: 1,
  changedAt: -1,
});

// Índice para correlación de eventos
AuditLogSchema.index({
  "applicationContext.correlationId": 1,
  changedAt: -1,
});

// Índice para análisis de sesiones
AuditLogSchema.index({
  sessionId: 1,
  changedAt: -1,
});

// TTL automático para retención (7 años por defecto)
AuditLogSchema.index(
  { retentionDate: 1 },
  {
    expireAfterSeconds: 0,
    name: "audit_retention_ttl",
  }
);

// Índice de texto para búsquedas
AuditLogSchema.index(
  {
    changeReason: "text",
    "applicationContext.action": "text",
    tags: "text",
  },
  {
    name: "audit_search_index",
  }
);

// ================================
// MIDDLEWARE
// ================================

// Pre-save middleware
AuditLogSchema.pre("save", function (next) {
  try {
    // Establecer fecha de retención automática
    if (this.isNew && !this.retentionDate) {
      const retentionYears = 7; // Configurable según compliance
      this.retentionDate = new Date(
        Date.now() + retentionYears * 365 * 24 * 60 * 60 * 1000
      );
    }

    // Generar hash de integridad simple
    if (this.isNew) {
      this.integrityHash = this.generateIntegrityHash();
    }

    // Auto-detectar nivel de riesgo básico
    this.autoDetectRiskLevel();

    // Validar versionado
    if (this.version <= this.previousVersion) {
      return next(
        new Error("La versión debe ser mayor que la versión anterior")
      );
    }

    next();
  } catch (error) {
    next(error);
  }
});

// Post-save middleware
AuditLogSchema.post("save", function (doc) {
  if (doc.isNew) {
    console.log(
      `📝 Auditoría: ${doc.targetCollection}:${doc.targetDocumentId} - ${doc.changeType} (v${doc.version})`
    );

    // Alerta para eventos críticos
    if (doc.riskLevel === "critical" || doc.severity === "critical") {
      console.warn(
        `🚨 EVENTO CRÍTICO: ${doc.category} - ${doc.changeReason || "Sin razón especificada"}`
      );
    }
  }
});

// ================================
// MÉTODOS DE INSTANCIA
// ================================

/**
 * Generar hash de integridad simple
 */
AuditLogSchema.methods.generateIntegrityHash = function () {
  const crypto = require("crypto");

  const dataToHash = {
    targetCollection: this.targetCollection,
    targetDocumentId: this.targetDocumentId,
    changeType: this.changeType,
    changedBy: this.changedBy,
    changedAt: this.changedAt,
    version: this.version,
  };

  const jsonString = JSON.stringify(dataToHash, Object.keys(dataToHash).sort());
  return crypto.createHash("sha256").update(jsonString, "utf8").digest("hex");
};

/**
 * Auto-detectar nivel de riesgo
 */
AuditLogSchema.methods.autoDetectRiskLevel = function () {
  let riskLevel = "low";

  // Operaciones de eliminación = riesgo medio
  if (this.changeType === "delete") {
    riskLevel = "medium";
  }

  // Cambios en usuarios o roles = riesgo alto
  if (["User", "Role"].includes(this.targetCollection)) {
    riskLevel = "high";
  }

  // Exportación de datos = riesgo alto
  if (this.changeType === "export") {
    riskLevel = "high";
  }

  // Cambios masivos = riesgo crítico
  if (this.changedFields && this.changedFields.length > 10) {
    riskLevel = "critical";
  }

  this.riskLevel = riskLevel;
};

/**
 * Filtrar campos sensibles
 */
AuditLogSchema.methods.filterSensitiveFields = function (obj) {
  if (!obj || typeof obj !== "object") return obj;

  const sensitiveFields = [
    "passwordHash",
    "accessToken",
    "refreshToken",
    "sessionToken",
    "apiKey",
    "secret",
  ];

  const filtered = { ...obj };

  for (const [key, value] of Object.entries(filtered)) {
    if (
      sensitiveFields.some((field) =>
        key.toLowerCase().includes(field.toLowerCase())
      )
    ) {
      filtered[key] = "[FILTERED]";
    }
  }

  return filtered;
};

// ================================
// MÉTODOS ESTÁTICOS
// ================================

/**
 * Crear registro de auditoría (compatible con tu AuditRepository)
 */
AuditLogSchema.statics.createAuditLog = async function (params) {
  const {
    targetCollection,
    targetDocumentId,
    changeType,
    previousValues,
    newValues,
    changedFields,
    changedBy,
    version,
    changeReason,
    ipAddress,
    userAgent,
    sessionId,
    applicationContext,
  } = params;

  const auditRecord = new this({
    targetCollection,
    targetDocumentId,
    changeType,
    previousValues: this.prototype.filterSensitiveFields(previousValues),
    newValues: this.prototype.filterSensitiveFields(newValues),
    changedFields: changedFields || [],
    changedBy,
    changedAt: new Date(),
    version,
    previousVersion: version - 1,
    isDeleteAction: changeType === "delete",
    deletedAt: changeType === "delete" ? new Date() : undefined,
    restoredAt: changeType === "restore" ? new Date() : undefined,
    changeReason,
    ipAddress,
    userAgent,
    sessionId,
    applicationContext: applicationContext || {},
  });

  return auditRecord.save();
};

/**
 * Reconstruir estado histórico (versión simplificada pero funcional)
 */
AuditLogSchema.statics.reconstructDocumentHistory = async function (
  collection,
  documentId,
  atVersion = null
) {
  // Obtener documento actual
  const targetModel = mongoose.model(collection);
  const currentDoc = await targetModel.findById(documentId);

  if (!currentDoc && !atVersion) return null;
  if (!atVersion) return currentDoc;

  // Obtener cambios para revertir
  const auditLogs = await this.find({
    targetCollection: collection,
    targetDocumentId: documentId,
    version: { $gt: atVersion },
  }).sort({ version: -1 });

  // Aplicar cambios en reversa
  let reconstructedDoc = currentDoc ? { ...currentDoc.toObject() } : {};

  for (const log of auditLogs) {
    if (log.changeType === "update" && log.previousValues) {
      Object.assign(reconstructedDoc, log.previousValues);
    }
    reconstructedDoc.version = log.previousVersion;
  }

  return reconstructedDoc;
};

/**
 * Obtener estadísticas básicas pero útiles
 */
AuditLogSchema.statics.getSimpleStats = function (options = {}) {
  const matchStage = {
    changedAt: {
      $gte: options.fromDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
      $lte: options.toDate || new Date(),
    },
  };

  return this.aggregate([
    { $match: matchStage },
    {
      $group: {
        _id: null,
        totalEvents: { $sum: 1 },
        creates: {
          $sum: { $cond: [{ $eq: ["$changeType", "create"] }, 1, 0] },
        },
        updates: {
          $sum: { $cond: [{ $eq: ["$changeType", "update"] }, 1, 0] },
        },
        deletes: {
          $sum: { $cond: [{ $eq: ["$changeType", "delete"] }, 1, 0] },
        },
        criticalEvents: {
          $sum: { $cond: [{ $eq: ["$riskLevel", "critical"] }, 1, 0] },
        },
        uniqueUsers: { $addToSet: "$changedBy" },
        topCollections: { $addToSet: "$targetCollection" },
      },
    },
    {
      $addFields: {
        uniqueUserCount: { $size: "$uniqueUsers" },
      },
    },
  ]);
};

// ================================
// CONFIGURACIÓN JSON
// ================================

AuditLogSchema.set("toJSON", {
  transform: function (doc, ret) {
    delete ret.__v;
    delete ret.integrityHash; // No exponer hash

    // Asegurar que campos sensibles estén filtrados
    if (ret.previousValues) {
      ret.previousValues = doc.filterSensitiveFields(ret.previousValues);
    }
    if (ret.newValues) {
      ret.newValues = doc.filterSensitiveFields(ret.newValues);
    }

    return ret;
  },
});

export const AuditLog = mongoose.model("AuditLog", AuditLogSchema);
