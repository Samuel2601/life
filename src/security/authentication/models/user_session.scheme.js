// =============================================================================
// src/security/authentication/models/user_session.scheme.js - OPTIMIZADO
// Mantiene toda la seguridad y funcionalidad, optimiza para tu caso de uso
// =============================================================================
import mongoose from "mongoose";
import crypto from "crypto";
import {
  BaseSchemeFields,
  setupBaseSchema,
} from "../../../modules/core/models/base.scheme.js";

/**
 * Schema para información del dispositivo (optimizado para geolocalización empresarial)
 */
const DeviceInfoSchema = new mongoose.Schema(
  {
    browser: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
      index: true, // Para analytics de dispositivos
    },
    browserVersion: {
      type: String,
      maxlength: 50,
    },
    os: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
      index: true, // Para analytics de SO
    },
    osVersion: {
      type: String,
      maxlength: 50,
    },
    device: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
    },
    deviceType: {
      type: String,
      enum: ["desktop", "mobile", "tablet", "unknown"],
      default: "unknown",
      index: true, // Para analytics mobile vs desktop
    },
    isMobile: {
      type: Boolean,
      default: false,
      index: true, // Para filtrar por tipo de dispositivo
    },
    screenResolution: {
      type: String,
      maxlength: 20, // ej: "1920x1080"
    },
    timezone: {
      type: String,
      required: true,
      default: "America/Lima",
      index: true, // Para analytics por zona horaria
    },
    language: {
      type: String,
      maxlength: 10, // ej: "es-ES"
      index: true, // Para analytics de idioma
    },
    // NUEVO: Información adicional para detección de bots
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
    },
  },
  { _id: false }
);

/**
 * Schema para información de ubicación (mejorado para plataforma empresarial)
 */
const LocationInfoSchema = new mongoose.Schema(
  {
    country: {
      type: String,
      maxlength: 2, // Código ISO de país (ej: "PE")
      uppercase: true,
      index: true, // Para analytics por país
    },
    countryName: {
      type: String,
      maxlength: 100,
    },
    city: {
      type: String,
      maxlength: 100,
      trim: true,
      index: true, // Para analytics por ciudad
    },
    region: {
      type: String,
      maxlength: 100,
      trim: true,
      index: true, // Para analytics por región
    },
    coordinates: {
      type: [Number], // [longitude, latitude]
      index: "2dsphere", // Para búsquedas geográficas
      validate: {
        validator: function (coords) {
          return (
            !coords ||
            (coords.length === 2 &&
              coords[0] >= -180 &&
              coords[0] <= 180 &&
              coords[1] >= -90 &&
              coords[1] <= 90)
          );
        },
        message: "Coordenadas inválidas",
      },
    },
    // NUEVO: Información detallada para compliance empresarial
    isVpnDetected: {
      type: Boolean,
      default: false,
      index: true, // Para filtrar VPNs
    },
    vpnProvider: {
      type: String,
      maxlength: 100,
    },
    isProxy: {
      type: Boolean,
      default: false,
      index: true,
    },
    isp: {
      type: String,
      maxlength: 200,
      index: true, // Para analytics de proveedores
    },
    asn: {
      type: String,
      maxlength: 20,
    },
    // NUEVO: Para compliance GDPR y restricciones geográficas
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
 * Schema para actividad sospechosa (expandido para empresa)
 */
const SuspiciousActivitySchema = new mongoose.Schema(
  {
    activityType: {
      type: String,
      enum: [
        "device_change",
        "location_change",
        "unusual_access",
        "concurrent_session",
        "fingerprint_mismatch",
        "rapid_requests",
        "unusual_timing",
        "ip_change",
        "bot_detected",
        "scraping_attempt",
        "brute_force",
        "privilege_escalation",
      ],
      required: true,
      index: true, // Para analytics de seguridad
    },
    description: {
      type: String,
      required: true,
      maxlength: 500,
    },
    timestamp: {
      type: Date,
      default: Date.now,
      required: true,
      index: true, // Para búsquedas temporales
    },
    severity: {
      type: String,
      enum: ["low", "medium", "high", "critical"],
      default: "medium",
      index: true, // Para filtrar por severidad
    },
    resolved: {
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
    // NUEVO: Datos adicionales para análisis forense
    additionalData: {
      type: mongoose.Schema.Types.Mixed,
    },
    riskScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
    automaticAction: {
      type: String,
      enum: ["none", "warn", "block", "terminate", "escalate"],
      default: "none",
    },
  },
  { _id: false }
);

/**
 * Schema para cambios de fingerprint (mejorado)
 */
const FingerprintChangeSchema = new mongoose.Schema(
  {
    newFingerprint: {
      type: String,
      required: true,
      length: 64, // SHA-256 hash
    },
    previousFingerprint: {
      type: String,
      required: true,
      length: 64,
    },
    changedAt: {
      type: Date,
      default: Date.now,
      required: true,
    },
    changeType: {
      type: String,
      enum: ["minor", "major", "suspicious", "critical"],
      default: "minor",
    },
    suspiciousChange: {
      type: Boolean,
      default: false,
    },
    validatedByUser: {
      type: Boolean,
      default: false,
    },
    validatedAt: {
      type: Date,
    },
    // NUEVO: Componentes específicos que cambiaron
    changedComponents: [
      {
        component: {
          type: String,
          enum: [
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
          ],
        },
        oldValue: String,
        newValue: String,
        changeSignificance: {
          type: String,
          enum: ["minor", "major", "critical"],
          default: "minor",
        },
      },
    ],
    // NUEVO: Score de similitud
    similarityScore: {
      type: Number,
      min: 0,
      max: 1,
      default: 0,
    },
    autoBlocked: {
      type: Boolean,
      default: false,
    },
  },
  { _id: false }
);

/**
 * Schema para datos OAuth (seguro - sin tokens)
 */
const OAuthSessionDataSchema = new mongoose.Schema(
  {
    provider: {
      type: String,
      enum: ["google", "facebook", "apple", "microsoft", "linkedin"],
      required: true,
      index: true,
    },
    providerId: {
      type: String,
      required: true,
      index: true,
    },
    email: {
      type: String,
      required: true,
    },
    // CRÍTICO: Solo almacenar hashes de tokens, NUNCA tokens directos
    tokenHash: {
      type: String,
      required: true,
      select: false, // NUNCA incluir en queries por defecto
      length: 64, // SHA-256 hash
    },
    refreshTokenHash: {
      type: String,
      select: false,
      length: 64,
    },
    expiresAt: {
      type: Date,
      required: true,
      index: true,
    },
    scope: [String],
    lastRefreshed: {
      type: Date,
    },
    // NUEVO: Metadatos del proveedor OAuth
    providerData: {
      profilePicture: String,
      verifiedEmail: Boolean,
      accountType: String, // personal, business, etc.
    },
  },
  { _id: false }
);

/**
 * Schema principal de UserSession (optimizado para empresa)
 */
const UserSessionSchema = new mongoose.Schema({
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

  // CRÍTICO: Tokens seguros almacenados SOLO en servidor (NUNCA enviados al cliente)
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

  fingerprintChanges: [FingerprintChangeSchema],

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
  },

  // Información detallada del dispositivo
  deviceInfo: {
    type: DeviceInfoSchema,
    required: true,
  },

  // Información geográfica
  location: {
    type: LocationInfoSchema,
  },

  // OAuth session data (si aplica)
  oauthProvider: {
    type: String,
    enum: ["google", "facebook", "apple", "microsoft", "linkedin"],
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

  // NUEVO: Configuración específica por tipo de usuario/rol
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

  // Metadatos de sesión (expandidos)
  metadata: {
    totalRequests: {
      type: Number,
      default: 0,
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
    },
    // NUEVO: Métricas empresariales
    businessMetrics: {
      companiesAccessed: [String], // IDs de empresas accedidas
      featuresUsed: [String], // Funcionalidades utilizadas
      apiCallsCount: {
        type: Number,
        default: 0,
      },
      avgResponseTime: {
        type: Number,
        default: 0,
      },
    },
    // NUEVO: Información de compliance
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

  // Campos base de auditoría
  ...BaseSchemeFields,
});

// Configurar esquema con funcionalidades base
setupBaseSchema(UserSessionSchema, {
  addTimestamps: false, // Ya manejamos timestamps manualmente
});

// ================================
// ÍNDICES ESPECÍFICOS OPTIMIZADOS
// ================================

// Índices únicos
UserSessionSchema.index({ sessionToken: 1 }, { unique: true });

// Índices para consultas de seguridad (optimizados)
UserSessionSchema.index({
  userId: 1,
  isActive: 1,
  isValid: 1,
  expiresAt: 1,
});

UserSessionSchema.index({
  userId: 1,
  createdAt: -1,
});

// TTL automático para sesiones expiradas
UserSessionSchema.index(
  { expiresAt: 1 },
  {
    expireAfterSeconds: 0,
    name: "session_ttl_index",
  }
);

// Índices para detección de seguridad (mejorados)
UserSessionSchema.index(
  {
    ipAddress: 1,
    userId: 1,
    createdAt: -1,
  },
  {
    name: "security_monitoring_index",
  }
);

UserSessionSchema.index(
  {
    deviceFingerprint: 1,
    userId: 1,
    isActive: 1,
  },
  {
    name: "device_tracking_index",
  }
);

// Índice para sesiones comprometidas
UserSessionSchema.index(
  {
    isCompromised: 1,
    compromisedAt: -1,
  },
  {
    sparse: true,
    name: "compromised_sessions_index",
  }
);

// NUEVO: Índices para analytics empresariales
UserSessionSchema.index(
  {
    "deviceInfo.deviceType": 1,
    "location.country": 1,
    createdAt: -1,
  },
  {
    name: "analytics_device_location_index",
  }
);

UserSessionSchema.index(
  {
    oauthProvider: 1,
    createdAt: -1,
  },
  {
    sparse: true,
    name: "oauth_analytics_index",
  }
);

// NUEVO: Índice para compliance y GDPR
UserSessionSchema.index(
  {
    "location.isEuCountry": 1,
    "metadata.compliance.gdprApplicable": 1,
    createdAt: -1,
  },
  {
    name: "gdpr_compliance_index",
  }
);

// ================================
// MIDDLEWARE OPTIMIZADO
// ================================

// Pre-save middleware
UserSessionSchema.pre("save", function (next) {
  if (this.isNew) {
    // Configurar expiración por defecto si no está establecida
    if (!this.expiresAt) {
      const hoursToAdd = this.rememberMe ? 24 * 30 : 8; // 30 días o 8 horas
      this.expiresAt = new Date(Date.now() + hoursToAdd * 60 * 60 * 1000);
    }

    // Inicializar metadatos
    this.metadata.totalRequests = 1;
    this.metadata.lastRequestAt = new Date();

    // NUEVO: Configurar compliance automáticamente
    if (this.location?.isEuCountry) {
      this.metadata.compliance.gdprApplicable = true;
    }
  }

  // Validar que la sesión no haya expirado
  if (this.expiresAt < new Date()) {
    this.isActive = false;
    this.isValid = false;
    this.invalidationReason = this.invalidationReason || "token_expired";
  }

  // Calcular duración de sesión
  if (this.lastAccessedAt && this.createdAt) {
    this.metadata.sessionDuration = Math.floor(
      (this.lastAccessedAt - this.createdAt) / (1000 * 60)
    );
  }

  next();
});

// Pre-update middleware para actualizar lastAccessedAt
UserSessionSchema.pre(/^findOneAnd/, function (next) {
  this.set({
    lastAccessedAt: new Date(),
    $inc: {
      "metadata.totalRequests": 1,
      "metadata.businessMetrics.apiCallsCount": 1,
    },
  });
  next();
});

// ================================
// MÉTODOS DE INSTANCIA (compatibles con tu código)
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
  this.invalidationReason = reason || "security_breach";
  return this.save();
};

/**
 * Registrar actividad sospechosa (compatible con tu código)
 */
UserSessionSchema.methods.logSuspiciousActivity = function (
  type,
  description,
  severity = "medium",
  additionalData = null
) {
  const activity = {
    activityType: type,
    description: description,
    severity: severity,
    timestamp: new Date(),
    additionalData: additionalData,
    riskScore: this.calculateRiskScore(type, severity),
    automaticAction: this.getAutomaticAction(severity),
  };

  this.suspiciousActivity.push(activity);

  // Auto-marcar como comprometida si hay actividad crítica
  if (severity === "critical") {
    this.markAsCompromised("suspicious_activity");
  }

  return this.save();
};

/**
 * Registrar cambio de fingerprint (mejorado)
 */
UserSessionSchema.methods.logFingerprintChange = function (
  newFingerprint,
  changedComponents = []
) {
  const previousFingerprint = this.deviceFingerprint;

  // Calcular similitud
  const similarityScore = this.calculateFingerprintSimilarity(
    previousFingerprint,
    newFingerprint
  );

  // Determinar tipo de cambio basado en componentes y similitud
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
    suspiciousChange: suspicious,
    changedComponents: changedComponents,
    similarityScore: similarityScore,
    autoBlocked: autoBlock,
  };

  this.fingerprintChanges.push(fingerprintChange);
  this.deviceFingerprint = newFingerprint;

  // Registrar actividad sospechosa si el cambio es significativo
  if (suspicious) {
    this.logSuspiciousActivity(
      "fingerprint_mismatch",
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
 * NUEVO: Calcular score de riesgo
 */
UserSessionSchema.methods.calculateRiskScore = function (
  activityType,
  severity
) {
  const baseScores = {
    device_change: 30,
    location_change: 20,
    fingerprint_mismatch: 40,
    rapid_requests: 25,
    bot_detected: 60,
    brute_force: 80,
  };

  const severityMultipliers = {
    low: 0.5,
    medium: 1,
    high: 1.5,
    critical: 2,
  };

  const baseScore = baseScores[activityType] || 10;
  const multiplier = severityMultipliers[severity] || 1;

  return Math.min(baseScore * multiplier, 100);
};

/**
 * NUEVO: Determinar acción automática
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
 * NUEVO: Calcular similitud de fingerprints
 */
UserSessionSchema.methods.calculateFingerprintSimilarity = function (fp1, fp2) {
  if (!fp1 || !fp2) return 0;
  if (fp1 === fp2) return 1;

  // Implementación simplificada - en producción usar algoritmo más robusto
  const maxLen = Math.max(fp1.length, fp2.length);
  let matches = 0;

  for (let i = 0; i < Math.min(fp1.length, fp2.length); i++) {
    if (fp1[i] === fp2[i]) {
      matches++;
    }
  }

  return matches / maxLen;
};

// ================================
// MÉTODOS ESTÁTICOS (compatibles con tu código)
// ================================

/**
 * Obtener sesiones activas para un usuario
 */
UserSessionSchema.statics.getActiveSessions = function (userId) {
  return this.find({
    userId: userId,
    isActive: true,
    isValid: true,
    expiresAt: { $gt: new Date() },
  }).sort({ lastAccessedAt: -1 });
};

/**
 * Invalidar todas las sesiones de un usuario excepto la actual
 */
UserSessionSchema.statics.invalidateAllExcept = function (
  userId,
  currentSessionId,
  reason = "admin_action"
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
      },
    }
  );
};

/**
 * Limpiar sesiones expiradas
 */
UserSessionSchema.statics.cleanupExpiredSessions = function () {
  return this.deleteMany({
    $or: [
      { expiresAt: { $lt: new Date() } },
      {
        isActive: false,
        updatedAt: { $lt: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) },
      },
    ],
  });
};

/**
 * Obtener estadísticas de sesiones (mejorado)
 */
UserSessionSchema.statics.getSessionStats = function (userId) {
  return this.aggregate([
    { $match: { userId: new mongoose.Types.ObjectId(userId) } },
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
      },
    },
  ]);
};

/**
 * NUEVO: Obtener analytics empresariales
 */
UserSessionSchema.statics.getBusinessAnalytics = function (filters = {}) {
  const matchStage = { isActive: true, ...filters };

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
      },
    },
    { $sort: { date: 1 } },
  ]);
};

// ================================
// CONFIGURACIÓN ADICIONAL
// ================================

// Configurar opciones de transformación para JSON (mejorado)
UserSessionSchema.set("toJSON", {
  virtuals: true,
  transform: function (doc, ret) {
    // Remover campos sensibles
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
        // No incluir descripción detallada ni datos adicionales
      }));
    }

    return ret;
  },
});

// ================================
// EXPORTAR MODELO
// ================================

export const UserSession = mongoose.model("UserSession", UserSessionSchema);
export default UserSession;
