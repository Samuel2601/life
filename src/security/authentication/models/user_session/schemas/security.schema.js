// =============================================================================
// src/modules/authentication/models/user-session/schemas/security.schema.js
// =============================================================================
import mongoose from "mongoose";

/**
 * Campos de seguridad
 */
export const SecuritySchema = {
  // Device Fingerprinting para seguridad
  deviceFingerprint: {
    type: String,
    required: true,
    length: 64, // SHA-256 hash
    index: true,
  },

  originalFingerprint: {
    type: String,
    required: true,
    length: 64, // Fingerprint al crear la sesión
  },

  // Control de seguridad
  isCompromised: {
    type: Boolean,
    default: false,
    index: true,
  },

  compromisedAt: {
    type: Date,
    index: true,
  },

  invalidationReason: {
    type: String,
    enum: [
      "user_logout",
      "token_expired",
      "security_breach",
      "admin_action",
      "device_change",
      "location_change",
      "suspicious_activity",
      "max_sessions_exceeded",
      "password_changed",
      "account_locked",
      "gdpr_request",
      "compliance_violation",
    ],
  },

  // Configuración específica por tipo de usuario/rol
  sessionPolicy: {
    requireTwoFactor: {
      type: Boolean,
      default: false,
    },
    allowedDeviceTypes: [String],
    allowedCountries: [String],
    maxConcurrentSessions: {
      type: Number,
      default: 3,
      min: 1,
      max: 10,
    },
    forceLogoutOnLocationChange: {
      type: Boolean,
      default: false,
    },
  },
};
