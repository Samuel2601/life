// =============================================================================
// src/security/authentication/models/user_session.scheme.js - ESTANDARIZADO
// Aplicando base.scheme.js y patrones avanzados con camelCase consistente
// =============================================================================
import mongoose from "mongoose";
import crypto from "crypto";
import {
  BaseSchemaFields,
  setupBaseSchema,
  CommonValidators,
} from "../../../modules/core/models/base.scheme.js";

/**
 * CONSTANTES Y CONFIGURACIÓN
 */
export const SESSION_CONSTANTS = {
  TOKEN_LENGTH: 64,
  HASH_LENGTH: 64,
  MAX_INACTIVITY_MINUTES: 43200, // 30 días máximo
  MIN_INACTIVITY_MINUTES: 5,
  MAX_CONCURRENT_SESSIONS: 10,
  MAX_SUSPICIOUS_ACTIVITIES: 50,
  MAX_FINGERPRINT_CHANGES: 20,
  FINGERPRINT_SIMILARITY_THRESHOLD: 0.6,
  RISK_SCORE_MAX: 100,
  SESSION_CLEANUP_DAYS: 30,
};

export const DEVICE_TYPES = ["desktop", "mobile", "tablet", "unknown"];
export const OAUTH_PROVIDERS = [
  "google",
  "facebook",
  "apple",
  "microsoft",
  "linkedin",
];
export const CREATION_METHODS = [
  "password",
  "oauth",
  "sso",
  "tokenRefresh",
  "magicLink",
];

export const INVALIDATION_REASONS = [
  "userLogout",
  "tokenExpired",
  "securityBreach",
  "adminAction",
  "deviceChange",
  "locationChange",
  "suspiciousActivity",
  "maxSessionsExceeded",
  "passwordChanged",
  "accountLocked",
  "gdprRequest",
  "complianceViolation",
];

export const ACTIVITY_TYPES = [
  "deviceChange",
  "locationChange",
  "unusualAccess",
  "concurrentSession",
  "fingerprintMismatch",
  "rapidRequests",
  "unusualTiming",
  "ipChange",
  "botDetected",
  "scrapingAttempt",
  "bruteForce",
  "privilegeEscalation",
];

export const SEVERITY_LEVELS = ["low", "medium", "high", "critical"];
export const AUTOMATIC_ACTIONS = [
  "none",
  "warn",
  "block",
  "terminate",
  "escalate",
];
export const CHANGE_TYPES = ["minor", "major", "suspicious", "critical"];
export const COMPONENT_TYPES = [
  "userAgent",
  "language",
  "timezone",
  "screen",
  "plugins",
  "fonts",
  "canvas",
  "webgl",
  "audio",
  "hardware",
];

/**
 * Schema para información del dispositivo optimizado
 */
const DeviceInfoSchema = new mongoose.Schema(
  {
    browser: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
      index: true,
    },
    browserVersion: {
      type: String,
      maxlength: 50,
      trim: true,
    },
    os: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
      index: true,
    },
    osVersion: {
      type: String,
      maxlength: 50,
      trim: true,
    },
    device: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
    },
    deviceType: {
      type: String,
      enum: DEVICE_TYPES,
      default: "unknown",
      index: true,
    },
    isMobile: {
      type: Boolean,
      default: false,
      index: true,
    },
    screenResolution: {
      type: String,
      maxlength: 20,
      validate: {
        validator: function (v) {
          return !v || /^\d{3,5}x\d{3,5}$/.test(v);
        },
        message: "Formato de resolución inválido (ej: 1920x1080)",
      },
    },
    timezone: {
      type: String,
      required: true,
      default: "America/Lima",
      index: true,
      maxlength: 50,
    },
    language: {
      type: String,
      maxlength: 10,
      index: true,
      validate: {
        validator: function (v) {
          return !v || /^[a-z]{2}(-[A-Z]{2})?$/.test(v);
        },
        message: "Formato de idioma inválido (ej: es-ES)",
      },
    },
    hardwareConcurrency: {
      type: Number,
      min: 1,
      max: 128,
    },
    deviceMemory: {
      type: Number,
      min: 0.25,
      max: 1024,
    },
    maxTouchPoints: {
      type: Number,
      default: 0,
      min: 0,
    },
  },
  { _id: false }
);

/**
 * Schema para información de ubicación mejorado
 */
const LocationInfoSchema = new mongoose.Schema(
  {
    country: {
      type: String,
      maxlength: 2,
      uppercase: true,
      index: true,
      validate: {
        validator: function (v) {
          return !v || /^[A-Z]{2}$/.test(v);
        },
        message: "Código de país inválido (ISO 3166-1 alpha-2)",
      },
    },
    countryName: {
      type: String,
      maxlength: 100,
      trim: true,
    },
    city: {
      type: String,
      maxlength: 100,
      trim: true,
      index: true,
    },
    region: {
      type: String,
      maxlength: 100,
      trim: true,
      index: true,
    },
    coordinates: {
      type: [Number],
      index: "2dsphere",
      validate: CommonValidators.coordinates,
    },
    isVpnDetected: {
      type: Boolean,
      default: false,
      index: true,
    },
    vpnProvider: {
      type: String,
      maxlength: 100,
      trim: true,
    },
    isProxy: {
      type: Boolean,
      default: false,
      index: true,
    },
    isp: {
      type: String,
      maxlength: 200,
      index: true,
      trim: true,
    },
    asn: {
      type: String,
      maxlength: 20,
      trim: true,
    },
    isEuCountry: {
      type: Boolean,
      default: false,
      index: true,
    },
    dataProcessingConsent: {
      type: Boolean,
      default: false,
    },
    locationAccuracy: {
      type: String,
      enum: ["city", "region", "country", "unknown"],
      default: "city",
    },
  },
  { _id: false }
);

/**
 * Schema para actividad sospechosa expandido
 */
const SuspiciousActivitySchema = new mongoose.Schema(
  {
    activityType: {
      type: String,
      enum: ACTIVITY_TYPES,
      required: true,
      index: true,
    },
    description: {
      type: String,
      required: true,
      maxlength: 500,
      trim: true,
    },
    timestamp: {
      type: Date,
      default: Date.now,
      required: true,
      index: true,
    },
    severity: {
      type: String,
      enum: SEVERITY_LEVELS,
      default: "medium",
      index: true,
    },
    isResolved: {
      type: Boolean,
      default: false,
      index: true,
    },
    resolvedAt: {
      type: Date,
      index: true,
    },
    resolvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    additionalData: {
      type: mongoose.Schema.Types.Mixed,
    },
    riskScore: {
      type: Number,
      min: 0,
      max: SESSION_CONSTANTS.RISK_SCORE_MAX,
      default: 0,
    },
    automaticAction: {
      type: String,
      enum: AUTOMATIC_ACTIONS,
      default: "none",
    },
    // NUEVO: Tracking de acciones tomadas
    actionsTaken: [
      {
        action: {
          type: String,
          enum: AUTOMATIC_ACTIONS,
        },
        takenAt: {
          type: Date,
          default: Date.now,
        },
        takenBy: {
          type: String,
          enum: ["system", "admin", "user"],
          default: "system",
        },
        result: String,
      },
    ],
  },
  { _id: false }
);

/**
 * Schema para cambios de fingerprint mejorado
 */
const FingerprintChangeSchema = new mongoose.Schema(
  {
    newFingerprint: {
      type: String,
      required: true,
      length: SESSION_CONSTANTS.HASH_LENGTH,
    },
    previousFingerprint: {
      type: String,
      required: true,
      length: SESSION_CONSTANTS.HASH_LENGTH,
    },
    changedAt: {
      type: Date,
      default: Date.now,
      required: true,
      index: true,
    },
    changeType: {
      type: String,
      enum: CHANGE_TYPES,
      default: "minor",
    },
    isSuspiciousChange: {
      type: Boolean,
      default: false,
      index: true,
    },
    isValidatedByUser: {
      type: Boolean,
      default: false,
    },
    validatedAt: {
      type: Date,
    },
    changedComponents: [
      {
        component: {
          type: String,
          enum: COMPONENT_TYPES,
        },
        oldValue: String,
        newValue: String,
        changeSignificance: {
          type: String,
          enum: CHANGE_TYPES,
          default: "minor",
        },
      },
    ],
    similarityScore: {
      type: Number,
      min: 0,
      max: 1,
      default: 0,
    },
    isAutoBlocked: {
      type: Boolean,
      default: false,
    },
    blockedReason: {
      type: String,
      maxlength: 200,
    },
  },
  { _id: false }
);

/**
 * Schema para datos OAuth seguros
 */
const OAuthSessionDataSchema = new mongoose.Schema(
  {
    provider: {
      type: String,
      enum: OAUTH_PROVIDERS,
      required: true,
      index: true,
    },
    providerId: {
      type: String,
      required: true,
      index: true,
      maxlength: 100,
    },
    email: {
      type: String,
      required: true,
      validate: CommonValidators.email,
    },
    tokenHash: {
      type: String,
      required: true,
      select: false,
      length: SESSION_CONSTANTS.HASH_LENGTH,
    },
    refreshTokenHash: {
      type: String,
      select: false,
      length: SESSION_CONSTANTS.HASH_LENGTH,
    },
    expiresAt: {
      type: Date,
      required: true,
      index: true,
    },
    scope: [String],
    lastRefreshed: {
      type: Date,
      index: true,
    },
    providerData: {
      profilePicture: {
        type: String,
        validate: CommonValidators.url,
      },
      isVerifiedEmail: Boolean,
      accountType: String,
      locale: String,
    },
  },
  { _id: false }
);

/**
 * Schema para políticas de sesión
 */
const SessionPolicySchema = new mongoose.Schema(
  {
    requireTwoFactor: {
      type: Boolean,
      default: false,
    },
    allowedDeviceTypes: [
      {
        type: String,
        enum: DEVICE_TYPES,
      },
    ],
    allowedCountries: [String],
    maxConcurrentSessions: {
      type: Number,
      default: 3,
      min: 1,
      max: SESSION_CONSTANTS.MAX_CONCURRENT_SESSIONS,
    },
    forceLogoutOnLocationChange: {
      type: Boolean,
      default: false,
    },
    forceLogoutOnDeviceChange: {
      type: Boolean,
      default: true,
    },
    maxInactivityMinutes: {
      type: Number,
      default: 30,
      min: SESSION_CONSTANTS.MIN_INACTIVITY_MINUTES,
      max: SESSION_CONSTANTS.MAX_INACTIVITY_MINUTES,
    },
    // NUEVO: Políticas avanzadas
    riskBasedAuth: {
      type: Boolean,
      default: true,
    },
    blockHighRiskSessions: {
      type: Boolean,
      default: true,
    },
    autoLogoutOnSuspiciousActivity: {
      type: Boolean,
      default: true,
    },
  },
  { _id: false }
);

/**
 * Schema para métricas de negocio
 */
const BusinessMetricsSchema = new mongoose.Schema(
  {
    companiesAccessed: [String],
    featuresUsed: [String],
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
    pagesViewed: {
      type: Number,
      default: 0,
      min: 0,
    },
    documentsAccessed: {
      type: Number,
      default: 0,
      min: 0,
    },
    dataDownloaded: {
      type: Number, // bytes
      default: 0,
      min: 0,
    },
    errorCount: {
      type: Number,
      default: 0,
      min: 0,
    },
  },
  { _id: false }
);

/**
 * Schema para compliance
 */
const ComplianceSchema = new mongoose.Schema(
  {
    isDataProcessingAgreed: {
      type: Boolean,
      default: false,
    },
    dataProcessingAgreedAt: Date,
    isGdprApplicable: {
      type: Boolean,
      default: false,
      index: true,
    },
    isAuditTrailEnabled: {
      type: Boolean,
      default: true,
    },
    dataRetentionDays: {
      type: Number,
      default: 365,
      min: 0,
    },
    consentVersion: {
      type: String,
      default: "1.0",
    },
    privacyPolicyVersion: {
      type: String,
      default: "1.0",
    },
  },
  { _id: false }
);

/**
 * Schema para metadatos de sesión
 */
const SessionMetadataSchema = new mongoose.Schema(
  {
    totalRequests: {
      type: Number,
      default: 0,
      min: 0,
    },
    lastRequestAt: {
      type: Date,
      index: true,
    },
    creationMethod: {
      type: String,
      enum: CREATION_METHODS,
      default: "password",
    },
    sessionDuration: {
      type: Number, // en minutos
      min: 0,
    },
    businessMetrics: {
      type: BusinessMetricsSchema,
      default: () => ({}),
    },
    compliance: {
      type: ComplianceSchema,
      default: () => ({}),
    },
    // NUEVO: Métricas de seguridad
    securityMetrics: {
      suspiciousActivityCount: {
        type: Number,
        default: 0,
        min: 0,
      },
      fingerprintChangesCount: {
        type: Number,
        default: 0,
        min: 0,
      },
      loginAttemptsCount: {
        type: Number,
        default: 1,
        min: 0,
      },
      lastSecurityCheck: Date,
      riskLevel: {
        type: String,
        enum: SEVERITY_LEVELS,
        default: "low",
      },
    },
  },
  { _id: false }
);

/**
 * Schema principal UserSession estandarizado
 */
const UserSessionSchema = new mongoose.Schema({
  // Identificación básica
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: [true, "El ID de usuario es requerido"],
    index: true,
  },

  // Token de sesión seguro
  sessionToken: {
    type: String,
    required: true,
    unique: true,
    length: SESSION_CONSTANTS.TOKEN_LENGTH,
    index: true,
  },

  // Tokens seguros (NUNCA enviados al cliente)
  accessTokenHash: {
    type: String,
    required: true,
    select: false,
    length: SESSION_CONSTANTS.HASH_LENGTH,
  },

  refreshTokenHash: {
    type: String,
    required: true,
    select: false,
    length: SESSION_CONSTANTS.HASH_LENGTH,
  },

  // Device fingerprinting
  deviceFingerprint: {
    type: String,
    required: true,
    length: SESSION_CONSTANTS.HASH_LENGTH,
    index: true,
  },

  originalFingerprint: {
    type: String,
    required: true,
    length: SESSION_CONSTANTS.HASH_LENGTH,
  },

  fingerprintChanges: {
    type: [FingerprintChangeSchema],
    validate: {
      validator: function (v) {
        return v.length <= SESSION_CONSTANTS.MAX_FINGERPRINT_CHANGES;
      },
      message: `Máximo ${SESSION_CONSTANTS.MAX_FINGERPRINT_CHANGES} cambios de fingerprint permitidos`,
    },
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

  // Timestamps mejorados
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

  // Información detallada
  deviceInfo: {
    type: DeviceInfoSchema,
    required: true,
  },

  location: {
    type: LocationInfoSchema,
  },

  // OAuth (si aplica)
  oauthProvider: {
    type: String,
    enum: OAUTH_PROVIDERS,
    index: true,
  },

  oauthSessionData: {
    type: OAuthSessionDataSchema,
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
    enum: INVALIDATION_REASONS,
  },

  suspiciousActivity: {
    type: [SuspiciousActivitySchema],
    validate: {
      validator: function (v) {
        return v.length <= SESSION_CONSTANTS.MAX_SUSPICIOUS_ACTIVITIES;
      },
      message: `Máximo ${SESSION_CONSTANTS.MAX_SUSPICIOUS_ACTIVITIES} actividades sospechosas permitidas`,
    },
  },

  // Configuración
  rememberMe: {
    type: Boolean,
    default: false,
  },

  autoLogoutWarningShown: {
    type: Date,
  },

  sessionPolicy: {
    type: SessionPolicySchema,
    default: () => ({}),
  },

  // Metadatos expandidos
  metadata: {
    type: SessionMetadataSchema,
    default: () => ({}),
  },

  // Aplicar campos base de auditoría
  ...BaseSchemaFields,
});

// ================================
// ÍNDICES OPTIMIZADOS
// ================================

// Índices únicos
UserSessionSchema.index({ sessionToken: 1 }, { unique: true });

// Índices compuestos para consultas frecuentes
UserSessionSchema.index(
  {
    userId: 1,
    isActive: 1,
    isValid: 1,
    expiresAt: 1,
  },
  { name: "user_active_sessions_index" }
);

UserSessionSchema.index(
  {
    userId: 1,
    createdAt: -1,
  },
  { name: "user_sessions_timeline_index" }
);

// TTL automático para sesiones expiradas
UserSessionSchema.index(
  { expiresAt: 1 },
  { expireAfterSeconds: 0, name: "session_ttl_index" }
);

// Índices de seguridad
UserSessionSchema.index(
  {
    ipAddress: 1,
    userId: 1,
    createdAt: -1,
  },
  { name: "security_monitoring_index" }
);

UserSessionSchema.index(
  {
    deviceFingerprint: 1,
    userId: 1,
    isActive: 1,
  },
  { name: "device_tracking_index" }
);

UserSessionSchema.index(
  {
    isCompromised: 1,
    compromisedAt: -1,
  },
  { sparse: true, name: "compromised_sessions_index" }
);

// Índices para analytics
UserSessionSchema.index(
  {
    "deviceInfo.deviceType": 1,
    "location.country": 1,
    createdAt: -1,
  },
  { name: "analytics_device_location_index" }
);

UserSessionSchema.index(
  {
    oauthProvider: 1,
    createdAt: -1,
  },
  { sparse: true, name: "oauth_analytics_index" }
);

// Índice para compliance GDPR
UserSessionSchema.index(
  {
    "location.isEuCountry": 1,
    "metadata.compliance.isGdprApplicable": 1,
    createdAt: -1,
  },
  { name: "gdpr_compliance_index" }
);

// ================================
// MIDDLEWARE MEJORADO
// ================================

// Pre-save middleware
UserSessionSchema.pre("save", function (next) {
  const now = new Date();

  if (this.isNew) {
    // Configurar expiración por defecto
    if (!this.expiresAt) {
      const hoursToAdd = this.rememberMe ? 24 * 30 : 8; // 30 días o 8 horas
      this.expiresAt = new Date(now.getTime() + hoursToAdd * 60 * 60 * 1000);
    }

    // Inicializar metadatos
    if (!this.metadata) this.metadata = {};
    this.metadata.totalRequests = 1;
    this.metadata.lastRequestAt = now;

    // Configurar compliance automáticamente
    if (this.location?.isEuCountry) {
      if (!this.metadata.compliance) this.metadata.compliance = {};
      this.metadata.compliance.isGdprApplicable = true;
    }
  }

  // Validar que la sesión no haya expirado
  if (this.expiresAt < now) {
    this.isActive = false;
    this.isValid = false;
    this.invalidationReason = this.invalidationReason || "tokenExpired";
  }

  // Calcular duración de sesión
  if (this.lastAccessedAt && this.createdAt) {
    if (!this.metadata) this.metadata = {};
    this.metadata.sessionDuration = Math.floor(
      (this.lastAccessedAt - this.createdAt) / (1000 * 60)
    );
  }

  // Actualizar métricas de seguridad
  if (this.metadata && this.metadata.securityMetrics) {
    this.metadata.securityMetrics.suspiciousActivityCount =
      this.suspiciousActivity?.length || 0;
    this.metadata.securityMetrics.fingerprintChangesCount =
      this.fingerprintChanges?.length || 0;
  }

  next();
});

// Pre-update middleware
UserSessionSchema.pre(/^findOneAnd/, function (next) {
  const now = new Date();

  this.set({
    lastAccessedAt: now,
    updatedAt: now,
    $inc: {
      "metadata.totalRequests": 1,
      "metadata.businessMetrics.apiCallsCount": 1,
    },
  });

  next();
});

// ================================
// MÉTODOS DE INSTANCIA MEJORADOS
// ================================

/**
 * Verificar si la sesión ha expirado
 */
UserSessionSchema.methods.isExpired = function () {
  return this.expiresAt < new Date();
};

/**
 * Verificar si necesita renovación pronto
 */
UserSessionSchema.methods.needsRenewal = function (thresholdMinutes = 60) {
  const renewalTime = new Date(
    this.expiresAt.getTime() - thresholdMinutes * 60 * 1000
  );
  return new Date() > renewalTime;
};

/**
 * Marcar como comprometida
 */
UserSessionSchema.methods.markAsCompromised = function (reason) {
  this.isCompromised = true;
  this.compromisedAt = new Date();
  this.isActive = false;
  this.isValid = false;
  this.invalidationReason = reason || "securityBreach";
  return this.save();
};

/**
 * Registrar actividad sospechosa
 */
UserSessionSchema.methods.logSuspiciousActivity = function (
  type,
  description,
  severity = "medium",
  additionalData = null
) {
  if (!this.suspiciousActivity) {
    this.suspiciousActivity = [];
  }

  const activity = {
    activityType: type,
    description: description,
    severity: severity,
    timestamp: new Date(),
    additionalData: additionalData,
    riskScore: this.calculateRiskScore(type, severity),
    automaticAction: this.getAutomaticAction(severity),
    actionsTaken: [],
  };

  this.suspiciousActivity.push(activity);

  // Auto-marcar como comprometida si hay actividad crítica
  if (severity === "critical") {
    this.markAsCompromised("suspiciousActivity");
  }

  return this.save();
};

/**
 * Registrar cambio de fingerprint mejorado
 */
UserSessionSchema.methods.logFingerprintChange = function (
  newFingerprint,
  changedComponents = []
) {
  const previousFingerprint = this.deviceFingerprint;
  const similarityScore = this.calculateFingerprintSimilarity(
    previousFingerprint,
    newFingerprint
  );

  let changeType = "minor";
  let suspicious = false;
  let autoBlock = false;

  if (similarityScore < 0.3) {
    changeType = "critical";
    suspicious = true;
    autoBlock = true;
  } else if (similarityScore < 0.6 || changedComponents.length > 3) {
    changeType = "major";
    suspicious = true;
  } else if (
    changedComponents.some((c) =>
      ["userAgent", "screen", "timezone"].includes(c.component)
    )
  ) {
    changeType = "suspicious";
    suspicious = true;
  }

  const fingerprintChange = {
    newFingerprint: newFingerprint,
    previousFingerprint: previousFingerprint,
    changeType: changeType,
    isSuspiciousChange: suspicious,
    changedComponents: changedComponents,
    similarityScore: similarityScore,
    isAutoBlocked: autoBlock,
    blockedReason: autoBlock ? "Critical fingerprint change detected" : null,
  };

  if (!this.fingerprintChanges) {
    this.fingerprintChanges = [];
  }

  this.fingerprintChanges.push(fingerprintChange);
  this.deviceFingerprint = newFingerprint;

  // Registrar actividad sospechosa si el cambio es significativo
  if (suspicious) {
    this.logSuspiciousActivity(
      "fingerprintMismatch",
      `Cambio ${changeType} en device fingerprint: ${changedComponents.map((c) => c.component).join(", ")}`,
      changeType === "critical" ? "critical" : "high",
      { changedComponents, similarityScore }
    );
  }

  return this.save();
};

/**
 * Extender sesión
 */
UserSessionSchema.methods.extendSession = function (additionalHours = 2) {
  const newExpiration = new Date(
    this.expiresAt.getTime() + additionalHours * 60 * 60 * 1000
  );
  this.expiresAt = newExpiration;
  this.lastAccessedAt = new Date();
  return this.save();
};

/**
 * Calcular score de riesgo
 */
UserSessionSchema.methods.calculateRiskScore = function (
  activityType,
  severity
) {
  const baseScores = {
    deviceChange: 30,
    locationChange: 20,
    fingerprintMismatch: 40,
    rapidRequests: 25,
    botDetected: 60,
    bruteForce: 80,
    privilegeEscalation: 90,
  };

  const severityMultipliers = {
    low: 0.5,
    medium: 1,
    high: 1.5,
    critical: 2,
  };

  const baseScore = baseScores[activityType] || 10;
  const multiplier = severityMultipliers[severity] || 1;

  return Math.min(baseScore * multiplier, SESSION_CONSTANTS.RISK_SCORE_MAX);
};

/**
 * Determinar acción automática
 */
UserSessionSchema.methods.getAutomaticAction = function (severity) {
  switch (severity) {
    case "critical":
      return "terminate";
    case "high":
      return "block";
    case "medium":
      return "warn";
    default:
      return "none";
  }
};

/**
 * Calcular similitud de fingerprints
 */
UserSessionSchema.methods.calculateFingerprintSimilarity = function (fp1, fp2) {
  if (!fp1 || !fp2) return 0;
  if (fp1 === fp2) return 1;

  // Implementación simplificada - usar algoritmo más robusto en producción
  const maxLen = Math.max(fp1.length, fp2.length);
  let matches = 0;

  for (let i = 0; i < Math.min(fp1.length, fp2.length); i++) {
    if (fp1[i] === fp2[i]) {
      matches++;
    }
  }

  return matches / maxLen;
};

/**
 * Verificar si cumple políticas de seguridad
 */
UserSessionSchema.methods.validateSecurityPolicy = function () {
  const policy = this.sessionPolicy;
  const issues = [];

  // Verificar dispositivo permitido
  if (policy.allowedDeviceTypes?.length > 0) {
    if (!policy.allowedDeviceTypes.includes(this.deviceInfo.deviceType)) {
      issues.push({
        type: "deviceType",
        message: "Tipo de dispositivo no permitido",
        severity: "high",
      });
    }
  }

  // Verificar país permitido
  if (policy.allowedCountries?.length > 0) {
    if (!policy.allowedCountries.includes(this.location?.country)) {
      issues.push({
        type: "location",
        message: "Ubicación geográfica no permitida",
        severity: "high",
      });
    }
  }

  // Verificar inactividad
  const inactiveMinutes = (new Date() - this.lastAccessedAt) / (1000 * 60);
  if (inactiveMinutes > policy.maxInactivityMinutes) {
    issues.push({
      type: "inactivity",
      message: "Sesión inactiva por demasiado tiempo",
      severity: "medium",
    });
  }

  return {
    isValid: issues.length === 0,
    issues: issues,
  };
};

// ================================
// MÉTODOS ESTÁTICOS MEJORADOS
// ================================

/**
 * Obtener sesiones activas para un usuario
 */
UserSessionSchema.statics.getActiveSessions = function (userId) {
  return this.findActive({
    userId: userId,
    isValid: true,
    expiresAt: { $gt: new Date() },
  }).sort({ lastAccessedAt: -1 });
};

/**
 * Invalidar todas las sesiones excepto la actual
 */
UserSessionSchema.statics.invalidateAllExcept = function (
  userId,
  currentSessionId,
  reason = "adminAction"
) {
  return this.updateMany(
    {
      userId: userId,
      _id: { $ne: currentSessionId },
      isActive: true,
    },
    {
      $set: {
        isActive: false,
        isValid: false,
        invalidationReason: reason,
        updatedAt: new Date(),
        updatedBy: userId,
      },
      $inc: { version: 1 },
    }
  );
};

/**
 * Limpiar sesiones expiradas automáticamente
 */
UserSessionSchema.statics.cleanupExpiredSessions = function () {
  const cutoffDate = new Date(
    Date.now() - SESSION_CONSTANTS.SESSION_CLEANUP_DAYS * 24 * 60 * 60 * 1000
  );

  return this.softDeleteMany(
    {
      $or: [
        { expiresAt: { $lt: new Date() } },
        {
          isActive: false,
          updatedAt: { $lt: cutoffDate },
        },
      ],
    },
    null, // system delete
    "Automatic cleanup of expired sessions"
  );
};

/**
 * Obtener estadísticas mejoradas de sesiones
 */
UserSessionSchema.statics.getSessionStats = function (userId, options = {}) {
  const matchStage = { userId: new mongoose.Types.ObjectId(userId) };

  if (!options.includeDeleted) {
    matchStage.isDeleted = { $ne: true };
  }

  return this.aggregate([
    { $match: matchStage },
    {
      $group: {
        _id: null,
        totalSessions: { $sum: 1 },
        activeSessions: {
          $sum: {
            $cond: [
              {
                $and: [
                  { $eq: ["$isActive", true] },
                  { $gt: ["$expiresAt", new Date()] },
                ],
              },
              1,
              0,
            ],
          },
        },
        compromisedSessions: {
          $sum: { $cond: [{ $eq: ["$isCompromised", true] }, 1, 0] },
        },
        avgSessionDuration: { $avg: "$metadata.sessionDuration" },
        totalRequests: { $sum: "$metadata.totalRequests" },
        totalApiCalls: { $sum: "$metadata.businessMetrics.apiCallsCount" },
        uniqueDeviceTypes: { $addToSet: "$deviceInfo.deviceType" },
        uniqueCountries: { $addToSet: "$location.country" },
        avgRiskScore: {
          $avg: {
            $avg: "$suspiciousActivity.riskScore",
          },
        },
      },
    },
  ]);
};

/**
 * Obtener analytics empresariales avanzados
 */
UserSessionSchema.statics.getBusinessAnalytics = function (filters = {}) {
  const matchStage = {
    isActive: true,
    isDeleted: { $ne: true },
    ...filters,
  };

  return this.aggregate([
    { $match: matchStage },
    {
      $group: {
        _id: {
          year: { $year: "$createdAt" },
          month: { $month: "$createdAt" },
          day: { $dayOfMonth: "$createdAt" },
        },
        totalSessions: { $sum: 1 },
        uniqueUsers: { $addToSet: "$userId" },
        deviceTypes: { $push: "$deviceInfo.deviceType" },
        countries: { $push: "$location.country" },
        oauthProviders: { $push: "$oauthProvider" },
        avgSessionDuration: { $avg: "$metadata.sessionDuration" },
        totalApiCalls: { $sum: "$metadata.businessMetrics.apiCallsCount" },
        securityIncidents: { $sum: { $size: "$suspiciousActivity" } },
      },
    },
    {
      $project: {
        date: {
          $dateFromParts: {
            year: "$_id.year",
            month: "$_id.month",
            day: "$_id.day",
          },
        },
        totalSessions: 1,
        uniqueUserCount: { $size: "$uniqueUsers" },
        deviceTypeDistribution: 1,
        countryDistribution: 1,
        oauthUsage: 1,
        avgSessionDuration: 1,
        totalApiCalls: 1,
        securityIncidents: 1,
      },
    },
    { $sort: { date: 1 } },
  ]);
};

/**
 * Detectar sesiones sospechosas
 */
UserSessionSchema.statics.findSuspiciousSessions = function (criteria = {}) {
  const suspiciousPatterns = {
    // Múltiples sesiones desde IPs diferentes
    multipleIps: {
      $expr: {
        $gt: [{ $size: { $setUnion: [["$ipAddress"]] } }, 1],
      },
    },

    // Cambios frecuentes de fingerprint
    frequentFingerprintChanges: {
      $expr: {
        $gt: [{ $size: "$fingerprintChanges" }, 3],
      },
    },

    // Actividad sospechosa reciente
    recentSuspiciousActivity: {
      suspiciousActivity: {
        $elemMatch: {
          timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) },
          severity: { $in: ["high", "critical"] },
        },
      },
    },
  };

  const matchConditions = [];

  Object.keys(criteria).forEach((key) => {
    if (suspiciousPatterns[key] && criteria[key]) {
      matchConditions.push(suspiciousPatterns[key]);
    }
  });

  if (matchConditions.length === 0) {
    matchConditions.push({ $or: Object.values(suspiciousPatterns) });
  }

  return this.findActive({
    $and: [{ $or: matchConditions }, { isCompromised: { $ne: true } }],
  }).sort({ "metadata.securityMetrics.riskLevel": -1 });
};

// ================================
// CONFIGURAR ESQUEMA BASE
// ================================

// Aplicar configuración base con todas las funcionalidades
setupBaseSchema(UserSessionSchema, {
  addTimestamps: false, // Ya manejamos timestamps manualmente
  addIndexes: true,
  addVirtuals: true,
  addMethods: true,
  addStatics: true,
  addHelpers: true,
  addBaseFields: false, // Ya los agregamos manualmente
});

// Configurar transformación JSON segura
UserSessionSchema.set("toJSON", {
  virtuals: true,
  transform: function (doc, ret) {
    // Remover campos sensibles SIEMPRE
    delete ret.accessTokenHash;
    delete ret.refreshTokenHash;
    delete ret.sessionToken;
    delete ret.__v;

    // Limpiar OAuth data sensible
    if (ret.oauthSessionData) {
      delete ret.oauthSessionData.tokenHash;
      delete ret.oauthSessionData.refreshTokenHash;
    }

    // Sanitizar actividades sospechosas
    if (ret.suspiciousActivity) {
      ret.suspiciousActivity = ret.suspiciousActivity.map((activity) => ({
        activityType: activity.activityType,
        severity: activity.severity,
        timestamp: activity.timestamp,
        isResolved: activity.isResolved,
        riskScore: activity.riskScore,
        automaticAction: activity.automaticAction,
      }));
    }

    // Remover campos de auditoría sensibles si no es admin
    delete ret.deletedBy;
    delete ret.updatedBy;

    return ret;
  },
});

// ================================
// EXPORTAR MODELO Y UTILIDADES
// ================================

export const UserSession = mongoose.model("UserSession", UserSessionSchema);

export const SessionUtils = {
  generateSecureToken: () =>
    crypto.randomBytes(SESSION_CONSTANTS.TOKEN_LENGTH / 2).toString("hex"),
  hashToken: (token) => crypto.createHash("sha256").update(token).digest("hex"),
  validateFingerprint: (fingerprint) =>
    fingerprint && fingerprint.length === SESSION_CONSTANTS.HASH_LENGTH,

  createSessionHash: (userId, deviceInfo, timestamp) => {
    const data = `${userId}_${deviceInfo.browser}_${deviceInfo.os}_${timestamp}`;
    return crypto.createHash("sha256").update(data).digest("hex");
  },

  // Utility para verificar si una IP es privada/local
  isPrivateIP: (ip) => {
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^127\./,
      /^::1$/,
      /^fc00:/,
      /^fe80:/,
    ];
    return privateRanges.some((range) => range.test(ip));
  },
};

export {
  SESSION_CONSTANTS,
  DEVICE_TYPES,
  OAUTH_PROVIDERS,
  CREATION_METHODS,
  INVALIDATION_REASONS,
  ACTIVITY_TYPES,
  SEVERITY_LEVELS,
  AUTOMATIC_ACTIONS,
  CHANGE_TYPES,
  COMPONENT_TYPES,
};

export default UserSession;
