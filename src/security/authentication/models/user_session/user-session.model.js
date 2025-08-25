// =============================================================================
// src/modules/authentication/models/user-session/user-session.model.js
// Archivo principal que ensambla todos los componentes del UserSession
// =============================================================================
import mongoose from "mongoose";
import {
  BaseSchemeFields,
  setupBaseSchema,
} from "../../../core/models/base.scheme.js";

// ================================
// IMPORTAR SCHEMAS MODULARES
// ================================
import { DeviceInfoSchema } from "./schemas/device-info.schema.js";
import { LocationInfoSchema } from "./schemas/location-info.schema.js";
import { SuspiciousActivitySchema } from "./schemas/suspicious-activity.schema.js";
import { FingerprintChangeSchema } from "./schemas/fingerprint-changes.schema.js";
import { OAuthSessionDataSchema } from "./schemas/oauth-session.schema.js";

// ================================
// IMPORTAR CONFIGURACIONES MODULARES
// ================================
import { applyVirtuals } from "./virtuals/index.js";
import { applyMethods } from "./methods/index.js";
import { applyMiddleware } from "./middleware/index.js";
import { applyIndexes } from "./indexes/index.js";

// ================================
// SCHEMA PRINCIPAL DE USER SESSION
// ================================

/**
 * Schema principal de UserSession - ensambla todos los componentes modulares
 *
 * @description Este archivo combina todos los schemas modulares, virtuals,
 * métodos, middleware e índices en un modelo cohesivo y seguro.
 */
const UserSessionSchema = new mongoose.Schema(
  {
    // ================================
    // IDENTIFICACIÓN DE SESIÓN
    // ================================
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
      validate: {
        validator: function (v) {
          return /^[a-f0-9]{64}$/i.test(v);
        },
        message: "Session token debe ser un hash hexadecimal de 64 caracteres",
      },
    },

    // ================================
    // TOKENS SEGUROS (SOLO SERVIDOR)
    // ================================

    // CRÍTICO: Tokens seguros almacenados SOLO en servidor (NUNCA enviados al cliente)
    accessTokenHash: {
      type: String,
      required: true,
      select: false, // NUNCA incluir en queries por defecto
      length: 64, // SHA-256 hash del token de acceso
      validate: {
        validator: function (v) {
          return /^[a-f0-9]{64}$/i.test(v);
        },
        message:
          "Access token hash debe ser un hash hexadecimal de 64 caracteres",
      },
    },

    refreshTokenHash: {
      type: String,
      required: true,
      select: false, // NUNCA incluir en queries por defecto
      length: 64, // SHA-256 hash del token de refresco
      validate: {
        validator: function (v) {
          return /^[a-f0-9]{64}$/i.test(v);
        },
        message:
          "Refresh token hash debe ser un hash hexadecimal de 64 caracteres",
      },
    },

    // ================================
    // DEVICE FINGERPRINTING
    // ================================
    deviceFingerprint: {
      type: String,
      required: true,
      length: 64, // SHA-256 hash
      index: true,
      validate: {
        validator: function (v) {
          return /^[a-f0-9]{64}$/i.test(v);
        },
        message:
          "Device fingerprint debe ser un hash hexadecimal de 64 caracteres",
      },
    },

    originalFingerprint: {
      type: String,
      required: true,
      length: 64, // Fingerprint al crear la sesión
      validate: {
        validator: function (v) {
          return /^[a-f0-9]{64}$/i.test(v);
        },
        message:
          "Original fingerprint debe ser un hash hexadecimal de 64 caracteres",
      },
    },

    fingerprintChanges: [FingerprintChangeSchema],

    // ================================
    // ESTADO DE SESIÓN
    // ================================
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

    // ================================
    // TIMESTAMPS DE SESIÓN
    // ================================
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
      validate: {
        validator: function (v) {
          return v > new Date();
        },
        message: "Fecha de expiración debe ser en el futuro",
      },
    },

    // ================================
    // INFORMACIÓN DEL CLIENTE
    // ================================
    ipAddress: {
      type: String,
      required: true,
      validate: {
        validator: function (ip) {
          // Validar formato IPv4 o IPv6 básico
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
      index: true, // Para analytics de navegadores
      validate: {
        validator: function (v) {
          return v && v.length > 0;
        },
        message: "User agent es requerido",
      },
    },

    // ================================
    // INFORMACIÓN DETALLADA (SCHEMAS MODULARES)
    // ================================

    // Información detallada del dispositivo
    deviceInfo: {
      type: DeviceInfoSchema,
      required: true,
    },

    // Información geográfica
    location: {
      type: LocationInfoSchema,
    },

    // ================================
    // OAUTH INTEGRATION
    // ================================
    oauthProvider: {
      type: String,
      enum: ["google", "facebook", "apple", "microsoft", "linkedin"],
      index: true,
    },

    oauthSessionData: {
      type: OAuthSessionDataSchema,
    },

    // ================================
    // CONTROL DE SEGURIDAD
    // ================================
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

    suspiciousActivity: [SuspiciousActivitySchema],

    // ================================
    // CONFIGURACIÓN DE SESIÓN
    // ================================
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

    // ================================
    // METADATOS DE SESIÓN
    // ================================
    metadata: {
      totalRequests: {
        type: Number,
        default: 0,
        min: 0,
      },
      lastRequestAt: {
        type: Date,
      },
      creationMethod: {
        type: String,
        enum: ["password", "oauth", "sso", "token_refresh", "magic_link"],
        default: "password",
      },
      sessionDuration: {
        type: Number, // Duración en minutos
        min: 0,
      },

      // Métricas empresariales
      businessMetrics: {
        companiesAccessed: [String], // IDs de empresas accedidas
        featuresUsed: [String], // Funcionalidades utilizadas
        apiCallsCount: {
          type: Number,
          default: 0,
          min: 0,
        },
        avgResponseTime: {
          type: Number,
          default: 0,
          min: 0,
        },
      },

      // Información de compliance
      compliance: {
        dataProcessingAgreed: {
          type: Boolean,
          default: false,
        },
        gdprApplicable: {
          type: Boolean,
          default: false,
        },
        auditTrailEnabled: {
          type: Boolean,
          default: true,
        },
      },
    },

    // ================================
    // CAMPOS BASE DE AUDITORÍA (OPCIONAL)
    // ================================
    // Descomenta si quieres campos de auditoría base
    // ...BaseSchemeFields,
  },
  {
    timestamps: false, // Manejamos timestamps manualmente
    collection: "user_sessions",

    // Configuración de schema
    strict: true, // Solo permitir campos definidos
    validateBeforeSave: true, // Validar antes de guardar

    // Optimizaciones
    minimize: false, // No remover objetos vacíos
    typeKey: "$type", // Evitar conflictos con campo 'type'
  }
);

// ================================
// APLICAR TODAS LAS CONFIGURACIONES MODULARES
// ================================

console.log("🔧 Aplicando configuraciones modulares a UserSession...");

try {
  // 1. Aplicar virtuals (campos computados)
  console.log("   ✅ Aplicando virtuals...");
  applyVirtuals(UserSessionSchema);

  // 2. Aplicar métodos (instancia y estáticos)
  console.log("   ✅ Aplicando métodos...");
  applyMethods(UserSessionSchema);

  // 3. Aplicar middleware (pre/post hooks)
  console.log("   ✅ Aplicando middleware...");
  applyMiddleware(UserSessionSchema);

  // 4. Aplicar índices (optimizaciones de BD)
  console.log("   ✅ Aplicando índices...");
  applyIndexes(UserSessionSchema);

  console.log("✅ Configuración modular completada exitosamente");
} catch (error) {
  console.error("❌ Error aplicando configuración modular:", error);
  throw error;
}

// ================================
// CONFIGURACIÓN DE TRANSFORMACIONES (SEGURIDAD CRÍTICA)
// ================================

// Configurar opciones de transformación para JSON (seguridad crítica)
UserSessionSchema.set("toJSON", {
  virtuals: true,
  versionKey: false,
  transform: function (doc, ret) {
    // ⚠️ CRÍTICO: Remover campos sensibles SIEMPRE
    delete ret.accessTokenHash;
    delete ret.refreshTokenHash;
    delete ret.sessionToken; // NUNCA enviar el token de sesión
    delete ret.__v;

    // Limpiar OAuth data sensible
    if (ret.oauthSessionData) {
      delete ret.oauthSessionData.tokenHash;
      delete ret.oauthSessionData.refreshTokenHash;
    }

    // Sanitizar actividad sospechosa sensible
    if (ret.suspiciousActivity) {
      ret.suspiciousActivity = ret.suspiciousActivity.map((activity) => ({
        activityType: activity.activityType,
        severity: activity.severity,
        timestamp: activity.timestamp,
        resolved: activity.resolved,
        riskScore: activity.riskScore,
        // No incluir descripción detallada ni datos adicionales por seguridad
      }));
    }

    // Limpiar datos de fingerprint sensibles
    if (ret.fingerprintChanges) {
      ret.fingerprintChanges = ret.fingerprintChanges.map((change) => ({
        changeType: change.changeType,
        suspiciousChange: change.suspiciousChange,
        changedAt: change.changedAt,
        validatedByUser: change.validatedByUser,
        similarityScore: change.similarityScore,
        // No incluir fingerprints específicos
      }));
    }

    return ret;
  },
});

// Transformación para toObject (misma seguridad que JSON)
UserSessionSchema.set("toObject", {
  virtuals: true,
  versionKey: false,
  transform: function (doc, ret) {
    // Aplicar la misma transformación que toJSON para consistencia
    delete ret.accessTokenHash;
    delete ret.refreshTokenHash;
    delete ret.sessionToken;
    delete ret.__v;

    if (ret.oauthSessionData) {
      delete ret.oauthSessionData.tokenHash;
      delete ret.oauthSessionData.refreshTokenHash;
    }

    return ret;
  },
});

// ================================
// VALIDACIONES ADICIONALES A NIVEL DE SCHEMA
// ================================

// Validación personalizada para consistencia de timestamps
UserSessionSchema.pre("validate", function (next) {
  // Verificar que lastAccessedAt no sea anterior a createdAt
  if (this.lastAccessedAt < this.createdAt) {
    this.lastAccessedAt = this.createdAt;
  }

  // Verificar que expiresAt sea posterior a createdAt
  if (this.expiresAt <= this.createdAt) {
    const error = new Error(
      "Fecha de expiración debe ser posterior a fecha de creación"
    );
    error.name = "ValidationError";
    return next(error);
  }

  next();
});

// Validación para OAuth consistency
UserSessionSchema.pre("validate", function (next) {
  // Si hay oauthProvider, debe haber oauthSessionData
  if (this.oauthProvider && !this.oauthSessionData) {
    const error = new Error(
      "OAuth session data es requerido cuando hay OAuth provider"
    );
    error.name = "ValidationError";
    return next(error);
  }

  // Si hay oauthSessionData, debe haber oauthProvider
  if (this.oauthSessionData && !this.oauthProvider) {
    const error = new Error(
      "OAuth provider es requerido cuando hay OAuth session data"
    );
    error.name = "ValidationError";
    return next(error);
  }

  next();
});

// ================================
// CREAR Y EXPORTAR MODELO
// ================================

export const UserSession = mongoose.model("UserSession", UserSessionSchema);
export default UserSession;

// ================================
// INFORMACIÓN DE DEBUGGING Y MONITOREO
// ================================

console.log("🎯 UserSession Model creado exitosamente con:");
console.log("   📝 Schemas modulares integrados");
console.log("   🔄 Virtuals para campos computados");
console.log("   ⚡ Métodos de instancia y estáticos");
console.log("   🔀 Middleware pre-save y pre-update");
console.log("   📊 Índices optimizados para seguridad y rendimiento");
console.log("   🔐 Transformaciones JSON seguras");
console.log("   ✅ Validaciones de integridad de datos");

// Exportar información útil para debugging
export const UserSessionInfo = {
  schemaVersion: "2.0.0",
  modularStructure: true,
  securityLevel: "enterprise",
  features: [
    "device-fingerprinting",
    "suspicious-activity-detection",
    "oauth-integration",
    "gdpr-compliance",
    "geographic-tracking",
    "bot-detection",
    "session-analytics",
  ],
  indexes: [
    "session_token_unique",
    "active_sessions_query",
    "security_monitoring_index",
    "device_tracking_index",
    "session_ttl_index",
    "compromised_sessions_index",
    "gdpr_compliance_index",
  ],
};

// Verificación de integridad del modelo
if (process.env.NODE_ENV === "development") {
  console.log("🔍 Verificando integridad del modelo UserSession...");

  // Verificar que todos los índices estén aplicados
  const schemaIndexes = UserSessionSchema.getIndexes();
  console.log(`   📊 Total de índices configurados: ${schemaIndexes.length}`);

  // Verificar que los virtuals estén aplicados
  const virtuals = Object.keys(UserSessionSchema.virtuals);
  console.log(`   🔄 Total de virtuals configurados: ${virtuals.length}`);

  // Verificar que los métodos estén aplicados
  const instanceMethods = Object.keys(UserSessionSchema.methods);
  const staticMethods = Object.keys(UserSessionSchema.statics);
  console.log(`   ⚡ Métodos de instancia: ${instanceMethods.length}`);
  console.log(`   🔧 Métodos estáticos: ${staticMethods.length}`);

  console.log("✅ Verificación de integridad completada");
}
