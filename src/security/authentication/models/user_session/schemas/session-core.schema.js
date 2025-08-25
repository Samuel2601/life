// =============================================================================
// src/modules/authentication/models/user-session/schemas/session-core.schema.js
// =============================================================================
import mongoose from "mongoose";

/**
 * Campos principales de sesión
 */
export const SessionCoreSchema = {
  // Identificación de sesión
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: [true, "El ID de usuario es requerido"],
    index: true,
  },

  // CRÍTICO: Token de sesión (cookie httpOnly) - NO es un JWT
  sessionToken: {
    type: String,
    required: true,
    unique: true,
    length: 64, // Token seguro generado aleatoriamente
    index: true,
  },

  // CRÍTICO: Tokens seguros almacenados SOLO en servidor
  accessTokenHash: {
    type: String,
    required: true,
    select: false, // NUNCA incluir en queries por defecto
    length: 64, // SHA-256 hash del token de acceso
  },

  refreshTokenHash: {
    type: String,
    required: true,
    select: false, // NUNCA incluir en queries por defecto
    length: 64, // SHA-256 hash del token de refresco
  },

  // Estado de sesión
  isActive: {
    type: Boolean,
    default: true,
    index: true,
  },

  isValid: {
    type: Boolean,
    default: true,
    index: true,
  },

  // Timestamps de sesión
  createdAt: {
    type: Date,
    default: Date.now,
    required: true,
    index: true,
  },

  lastAccessedAt: {
    type: Date,
    default: Date.now,
    required: true,
    index: true,
  },

  expiresAt: {
    type: Date,
    required: true,
    index: true,
  },

  // Información del cliente
  ipAddress: {
    type: String,
    required: true,
    validate: {
      validator: function (ip) {
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
    index: true,
  },

  userAgent: {
    type: String,
    required: true,
    maxlength: 1000,
    index: true,
  },

  // OAuth provider (si aplica)
  oauthProvider: {
    type: String,
    enum: ["google", "facebook", "apple", "microsoft", "linkedin"],
    index: true,
  },

  // Configuración de sesión
  rememberMe: {
    type: Boolean,
    default: false,
  },

  maxInactivityMinutes: {
    type: Number,
    default: 30,
    min: 5,
    max: 43200, // 30 días máximo
  },

  autoLogoutWarningShown: {
    type: Date,
  },
};
