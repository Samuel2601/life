// =============================================================================
// src/models/system/SecurityActivityLog.js
// =============================================================================
import mongoose from "mongoose";

// Schema para detalles específicos de actividad
const ActivityDetailsSchema = new mongoose.Schema(
  {
    attemptedAction: String,
    targetResource: String,
    failureReason: String,
    additionalData: mongoose.Schema.Types.Mixed,
  },
  { _id: false }
);

const SecurityActivityLogSchema = new mongoose.Schema({
  // Identificación del evento
  eventType: {
    type: String,
    required: true,
    enum: [
      "login_attempt",
      "login_success",
      "login_failure",
      "logout",
      "session_expired",
      "session_hijack_detected",
      "password_change",
      "password_reset_request",
      "password_reset_success",
      "account_locked",
      "account_unlocked",
      "suspicious_activity",
      "ip_banned",
      "device_change_detected",
      "permission_denied",
      "unauthorized_access_attempt",
      "data_export",
      "admin_action",
      "system_access",
    ],
    index: true,
  },
  severity: {
    type: String,
    enum: ["low", "medium", "high", "critical"],
    required: true,
    index: true,
  },

  // Usuario y sesión
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    index: true,
  },
  sessionId: {
    type: String,
    index: true,
  },

  // Información de red y dispositivo
  ipAddress: {
    type: String,
    required: true,
    index: true,
  },
  userAgent: {
    type: String,
    required: true,
  },
  deviceFingerprint: String,

  // Ubicación geográfica
  geoLocation: {
    country: String,
    city: String,
    coordinates: {
      type: [Number], // [longitude, latitude]
      index: "2dsphere",
    },
  },

  // Detalles del evento
  description: {
    type: String,
    required: true,
    maxlength: 1000,
  },
  activityDetails: ActivityDetailsSchema,

  // Timestamp y duración
  timestamp: {
    type: Date,
    default: Date.now,
    required: true,
    index: true,
  },
  duration: Number, // En milisegundos

  // Estado del evento
  isResolved: {
    type: Boolean,
    default: false,
    index: true,
  },
  resolvedAt: Date,
  resolvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },
  resolutionNotes: String,

  // Integración con sistema de baneos
  triggeredAutoAction: {
    type: String,
    enum: [
      "none",
      "account_lock",
      "ip_ban",
      "session_invalidate",
      "alert_admin",
    ],
  },
  autoBanSystemTriggered: {
    type: Boolean,
    default: false,
  },

  // Para análisis y correlación
  correlationId: String,
  riskScore: {
    type: Number,
    min: 0,
    max: 100,
    default: 0,
  },
});

// Índices específicos para consultas de seguridad
SecurityActivityLogSchema.index({ eventType: 1, severity: 1, timestamp: -1 });
SecurityActivityLogSchema.index({ userId: 1, timestamp: -1 });
SecurityActivityLogSchema.index({ ipAddress: 1, timestamp: -1 });
SecurityActivityLogSchema.index({ severity: 1, isResolved: 1, timestamp: -1 });
SecurityActivityLogSchema.index({ riskScore: -1, timestamp: -1 });

// TTL index para logs antiguos (retener 2 años)
SecurityActivityLogSchema.index(
  { timestamp: 1 },
  {
    expireAfterSeconds: 60 * 60 * 24 * 365 * 2, // 2 años
    name: "security_log_ttl",
  }
);

export const SecurityActivityLog = mongoose.model(
  "SecurityActivityLog",
  SecurityActivityLogSchema
);
