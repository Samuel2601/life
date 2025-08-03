// =============================================================================
// src/models/system/AuditLog.js
// =============================================================================
import mongoose from "mongoose";

// Schema para información contextual de la aplicación
const ApplicationContextSchema = new mongoose.Schema(
  {
    module: {
      type: String,
      required: true,
      maxlength: 100,
    },
    action: {
      type: String,
      required: true,
      maxlength: 100,
    },
    correlationId: {
      type: String,
      maxlength: 100,
    },
  },
  { _id: false }
);

const AuditLogSchema = new mongoose.Schema({
  // Identificación del registro afectado
  targetCollection: {
    type: String,
    required: true,
    index: true,
    enum: [
      "users",
      "businesses",
      "addresses",
      "categories",
      "reviews",
      "sessions",
      "roles",
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
    enum: ["create", "update", "delete", "restore"],
    index: true,
  },
  previousValues: {
    type: mongoose.Schema.Types.Mixed,
    required: true,
  },
  changedFields: [
    {
      type: String,
      required: true,
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

  // Información contextual
  ipAddress: {
    type: String,
    required: true,
    index: true,
  },
  userAgent: {
    type: String,
    required: true,
  },
  sessionId: {
    type: String,
    index: true,
  },

  // Versionado
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
  deletedAt: Date,

  // Metadatos adicionales
  applicationContext: ApplicationContextSchema,

  // Para compliance y reportes
  retentionDate: {
    type: Date,
    index: 1, // TTL index según políticas de retención
  },
});

// Índices específicos para consultas de auditoría
AuditLogSchema.index({ targetCollection: 1, targetDocumentId: 1, version: -1 });
AuditLogSchema.index({ changedBy: 1, changedAt: -1 });
AuditLogSchema.index({ changeType: 1, changedAt: -1 });
AuditLogSchema.index({ changedAt: -1 }); // Para consultas por fecha
AuditLogSchema.index({ ipAddress: 1, changedAt: -1 }); // Para análisis de seguridad

// Índice TTL para retención automática (7 años por defecto)
AuditLogSchema.index(
  { retentionDate: 1 },
  {
    expireAfterSeconds: 0,
    name: "audit_retention_ttl",
  }
);

// Pre-save para establecer fecha de retención
AuditLogSchema.pre("save", function (next) {
  if (this.isNew && !this.retentionDate) {
    const retentionYears = 7; // Configurable según compliance
    this.retentionDate = new Date(
      Date.now() + retentionYears * 365 * 24 * 60 * 60 * 1000
    );
  }
  next();
});

export const AuditLog = mongoose.model("AuditLog", AuditLogSchema);
