// =============================================================================
// src/modules/authentication/models/user-session/schemas/suspicious-activity.schema.js
// Schema para actividad sospechosa expandido para empresa
// =============================================================================
import mongoose from "mongoose";

/**
 * Schema para actividad sospechosa (expandido para empresa)
 *
 * @description Sistema completo de detección y logging de actividades sospechosas
 * incluyendo análisis automatizado, escalamiento y resolución
 */
export const SuspiciousActivitySchema = new mongoose.Schema(
  {
    // ================================
    // IDENTIFICACIÓN DE LA ACTIVIDAD
    // ================================

    activityType: {
      type: String,
      enum: [
        // Cambios de dispositivo/ubicación
        "device_change",
        "location_change",
        "ip_change",
        "fingerprint_mismatch",

        // Accesos anómalos
        "unusual_access",
        "unusual_timing",
        "concurrent_session",
        "rapid_requests",

        // Detección de bots/automatización
        "bot_detected",
        "scraping_attempt",
        "automated_behavior",
        "headless_browser",

        // Ataques de seguridad
        "brute_force",
        "privilege_escalation",
        "injection_attempt",
        "xss_attempt",
        "csrf_attempt",

        // Comportamiento fraudulento
        "account_takeover",
        "identity_theft",
        "payment_fraud",
        "credential_stuffing",

        // Violaciones de política
        "policy_violation",
        "terms_violation",
        "rate_limit_exceeded",
        "banned_content",

        // Evasión de seguridad
        "vpn_usage",
        "proxy_usage",
        "tor_usage",
        "geo_restriction_bypass",

        // Otros
        "data_exfiltration",
        "suspicious_download",
        "admin_impersonation",
        "social_engineering",
        "unknown_threat",
      ],
      required: true,
      index: true, // Para analytics de seguridad
    },

    // Subcategoría para mayor granularidad
    subCategory: {
      type: String,
      maxlength: 50,
      trim: true,
    },

    // ================================
    // DESCRIPCIÓN Y CONTEXTO
    // ================================

    description: {
      type: String,
      required: true,
      maxlength: 1000, // Aumentado para más detalle
      trim: true,
    },

    // Descripción técnica detallada
    technicalDetails: {
      type: String,
      maxlength: 2000,
      trim: true,
    },

    // ================================
    // CLASIFICACIÓN DE SEVERIDAD
    // ================================

    severity: {
      type: String,
      enum: ["low", "medium", "high", "critical"],
      default: "medium",
      index: true, // Para filtrar por severidad
      required: true,
    },

    // Score numérico de severidad (0-100)
    severityScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 50,
      index: true,
    },

    // ================================
    // INFORMACIÓN TEMPORAL
    // ================================

    timestamp: {
      type: Date,
      default: Date.now,
      required: true,
      index: true, // Para búsquedas temporales
    },

    // Duración de la actividad sospechosa
    duration: {
      type: Number, // En segundos
      min: 0,
      default: 0,
    },

    // Timestamp de cuando se detectó
    detectedAt: {
      type: Date,
      default: Date.now,
    },

    // ================================
    // ESTADO Y RESOLUCIÓN
    // ================================

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

    // Método de resolución
    resolutionMethod: {
      type: String,
      enum: [
        "automatic",
        "manual_review",
        "user_verification",
        "admin_override",
        "false_positive",
        "system_update",
        "policy_change",
      ],
    },

    // Notas de resolución
    resolutionNotes: {
      type: String,
      maxlength: 1000,
      trim: true,
    },

    // ================================
    // DATOS ADICIONALES Y EVIDENCIA
    // ================================

    // Datos estructurados adicionales
    additionalData: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },

    // Evidencia forense
    evidence: {
      // Headers HTTP relevantes
      httpHeaders: {
        userAgent: String,
        referer: String,
        acceptLanguage: String,
        acceptEncoding: String,
        connection: String,
        xForwardedFor: String,
      },

      // Información de red
      networkInfo: {
        ipAddress: String,
        hostname: String,
        port: Number,
        protocol: String,
      },

      // Información del request
      requestInfo: {
        method: String,
        url: String,
        queryParams: mongoose.Schema.Types.Mixed,
        bodySize: Number,
        responseCode: Number,
        responseTime: Number,
      },

      // Patrones detectados
      patterns: [
        {
          type: String,
          pattern: String,
          matches: Number,
          confidence: {
            type: Number,
            min: 0,
            max: 1,
          },
        },
      ],
    },

    // ================================
    // ANÁLISIS DE RIESGO
    // ================================

    // Score de riesgo calculado (0-100)
    riskScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
      index: true,
    },

    // Factores que contribuyen al riesgo
    riskFactors: [
      {
        factor: {
          type: String,
          maxlength: 50,
        },
        weight: {
          type: Number,
          min: 0,
          max: 1,
        },
        contribution: {
          type: Number,
          min: 0,
          max: 100,
        },
      },
    ],

    // Confianza en la detección (0-1)
    detectionConfidence: {
      type: Number,
      min: 0,
      max: 1,
      default: 0.5,
    },

    // ================================
    // ACCIONES AUTOMÁTICAS
    // ================================

    // Acción tomada automáticamente
    automaticAction: {
      type: String,
      enum: ["none", "warn", "block", "terminate", "escalate", "quarantine"],
      default: "none",
    },

    // Razón de la acción automática
    actionReason: {
      type: String,
      maxlength: 500,
      trim: true,
    },

    // Timestamp de cuando se ejecutó la acción
    actionTimestamp: {
      type: Date,
    },

    // Resultado de la acción
    actionResult: {
      type: String,
      enum: ["success", "failure", "partial", "pending"],
    },

    // ================================
    // ESCALAMIENTO Y NOTIFICACIONES
    // ================================

    // Nivel de escalamiento
    escalationLevel: {
      type: Number,
      min: 0,
      max: 5,
      default: 0,
    },

    // Lista de personas/equipos notificados
    notified: [
      {
        recipientType: {
          type: String,
          enum: ["user", "admin", "security_team", "compliance", "external"],
        },
        recipientId: String,
        notifiedAt: {
          type: Date,
          default: Date.now,
        },
        method: {
          type: String,
          enum: ["email", "sms", "slack", "webhook", "dashboard"],
        },
        status: {
          type: String,
          enum: ["sent", "delivered", "failed", "pending"],
          default: "pending",
        },
      },
    ],

    // ================================
    // CORRELACIÓN Y AGRUPACIÓN
    // ================================

    // ID de incidente relacionado
    incidentId: {
      type: String,
      index: true,
    },

    // Actividades relacionadas
    relatedActivities: [
      {
        activityId: mongoose.Schema.Types.ObjectId,
        relationType: {
          type: String,
          enum: [
            "same_attack",
            "same_actor",
            "same_pattern",
            "consequence",
            "precursor",
          ],
        },
        confidence: {
          type: Number,
          min: 0,
          max: 1,
        },
      },
    ],

    // Hash para deduplicación
    deduplicationHash: {
      type: String,
      length: 64,
      index: true,
    },

    // ================================
    // MÉTRICAS Y ANÁLISIS
    // ================================

    // Número de veces que se ha visto esta actividad
    occurrenceCount: {
      type: Number,
      default: 1,
      min: 1,
    },

    // Primera vez vista
    firstOccurrence: {
      type: Date,
      default: Date.now,
    },

    // Última vez vista
    lastOccurrence: {
      type: Date,
      default: Date.now,
    },

    // Frecuencia (ocurrencias por hora)
    frequency: {
      type: Number,
      default: 0,
      min: 0,
    },

    // ================================
    // INFORMACIÓN DEL DETECTOR
    // ================================

    // Sistema o regla que detectó la actividad
    detectedBy: {
      system: {
        type: String,
        maxlength: 100,
        default: "session_monitor",
      },
      version: {
        type: String,
        maxlength: 20,
      },
      rule: {
        type: String,
        maxlength: 100,
      },
      ruleVersion: {
        type: String,
        maxlength: 20,
      },
    },

    // Configuración del detector en el momento de detección
    detectorConfig: {
      type: mongoose.Schema.Types.Mixed,
    },

    // ================================
    // CLASIFICACIÓN AUTOMÁTICA
    // ================================

    // Clasificación por ML si está disponible
    mlClassification: {
      model: String,
      confidence: {
        type: Number,
        min: 0,
        max: 1,
      },
      predictions: [
        {
          label: String,
          probability: {
            type: Number,
            min: 0,
            max: 1,
          },
        },
      ],
    },

    // ================================
    // INFORMACIÓN DE MITIGACIÓN
    // ================================

    // Medidas de mitigación recomendadas
    recommendedActions: [
      {
        action: String,
        priority: {
          type: String,
          enum: ["low", "medium", "high", "critical"],
        },
        effort: {
          type: String,
          enum: ["minimal", "low", "medium", "high"],
        },
        impact: {
          type: String,
          enum: ["minimal", "low", "medium", "high"],
        },
      },
    ],

    // Medidas ya implementadas
    mitigationsTaken: [
      {
        action: String,
        takenAt: {
          type: Date,
          default: Date.now,
        },
        takenBy: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "User",
        },
        result: String,
      },
    ],

    // ================================
    // METADATOS
    // ================================

    metadata: {
      // Fuente del evento
      source: {
        type: String,
        enum: ["session", "api", "web", "mobile", "system", "external"],
        default: "session",
      },

      // Tags personalizados
      tags: [String],

      // Información del environment
      environment: {
        type: String,
        enum: ["production", "staging", "development", "test"],
        default: "production",
      },

      // Version de la aplicación cuando ocurrió
      appVersion: String,

      // Información de geolocalización
      location: {
        country: String,
        city: String,
        coordinates: [Number],
      },

      // Información del dispositivo
      device: {
        type: String,
        browser: String,
        os: String,
      },
    },
  },
  {
    _id: true, // Mantener _id para referencias
    timestamps: false, // Manejamos timestamps manualmente
  }
);

// ================================
// MÉTODOS DE INSTANCIA
// ================================

/**
 * Marcar como resuelto
 */
SuspiciousActivitySchema.methods.markResolved = function (
  resolvedBy,
  method,
  notes
) {
  this.resolved = true;
  this.resolvedAt = new Date();
  this.resolvedBy = resolvedBy;
  this.resolutionMethod = method;
  this.resolutionNotes = notes;
  return this;
};

/**
 * Escalar severidad
 */
SuspiciousActivitySchema.methods.escalate = function (newSeverity, reason) {
  if (this.severity !== newSeverity) {
    this.severity = newSeverity;
    this.escalationLevel = (this.escalationLevel || 0) + 1;
    this.actionReason = reason;

    // Actualizar score numérico
    const severityScores = { low: 25, medium: 50, high: 75, critical: 100 };
    this.severityScore = severityScores[newSeverity];
  }
  return this;
};

/**
 * Agregar evidencia adicional
 */
SuspiciousActivitySchema.methods.addEvidence = function (
  evidenceType,
  evidenceData
) {
  if (!this.evidence) this.evidence = {};
  if (!this.evidence[evidenceType]) this.evidence[evidenceType] = {};

  Object.assign(this.evidence[evidenceType], evidenceData);

  // Actualizar confianza de detección
  this.detectionConfidence = Math.min(
    1,
    (this.detectionConfidence || 0.5) + 0.1
  );

  return this;
};

/**
 * Calcular hash de deduplicación
 */
SuspiciousActivitySchema.methods.calculateDeduplicationHash = function () {
  const crypto = require("crypto");

  const hashData = [
    this.activityType,
    this.subCategory || "",
    this.description,
    this.metadata?.source || "",
    this.evidence?.networkInfo?.ipAddress || "",
  ].join("|");

  this.deduplicationHash = crypto
    .createHash("sha256")
    .update(hashData)
    .digest("hex");

  return this.deduplicationHash;
};

/**
 * Verificar si es duplicado
 */
SuspiciousActivitySchema.methods.isDuplicateOf = function (otherActivity) {
  if (!this.deduplicationHash) this.calculateDeduplicationHash();
  if (!otherActivity.deduplicationHash)
    otherActivity.calculateDeduplicationHash();

  return this.deduplicationHash === otherActivity.deduplicationHash;
};

/**
 * Obtener resumen de la actividad
 */
SuspiciousActivitySchema.methods.getSummary = function () {
  const timestamp = this.timestamp
    .toISOString()
    .substring(0, 16)
    .replace("T", " ");
  return `[${this.severity.toUpperCase()}] ${this.activityType} - ${this.description.substring(0, 100)}... (${timestamp})`;
};

/**
 * Verificar si necesita escalamiento
 */
SuspiciousActivitySchema.methods.needsEscalation = function () {
  // Criterios para escalamiento automático
  if (this.severity === "critical") return true;
  if (this.riskScore >= 90) return true;
  if (this.occurrenceCount >= 10) return true;
  if (this.escalationLevel === 0 && this.severity === "high") return true;

  return false;
};

/**
 * Calcular tiempo de respuesta
 */
SuspiciousActivitySchema.methods.getResponseTime = function () {
  if (!this.resolved || !this.resolvedAt) return null;

  const responseTimeMs = this.resolvedAt.getTime() - this.timestamp.getTime();
  return Math.floor(responseTimeMs / 1000); // En segundos
};

// ================================
// MÉTODOS ESTÁTICOS
// ================================

/**
 * Crear actividad sospechosa con detección automática
 */
SuspiciousActivitySchema.statics.createFromDetection = function (
  detectionData
) {
  const activity = new this({
    activityType: detectionData.type,
    description: detectionData.description,
    severity: detectionData.severity || "medium",
    additionalData: detectionData.data || {},
    detectedBy: detectionData.detector || {},
    evidence: detectionData.evidence || {},
    metadata: detectionData.metadata || {},
  });

  // Calcular risk score
  activity.riskScore = activity.calculateRiskScore();

  // Calcular hash de deduplicación
  activity.calculateDeduplicationHash();

  return activity;
};

/**
 * Encontrar actividades similares
 */
SuspiciousActivitySchema.statics.findSimilar = function (
  activity,
  timeRangeHours = 24
) {
  const timeThreshold = new Date(Date.now() - timeRangeHours * 60 * 60 * 1000);

  return this.find({
    activityType: activity.activityType,
    timestamp: { $gte: timeThreshold },
    $or: [
      { deduplicationHash: activity.deduplicationHash },
      {
        "evidence.networkInfo.ipAddress":
          activity.evidence?.networkInfo?.ipAddress,
        severity: { $in: ["high", "critical"] },
      },
    ],
  }).sort({ timestamp: -1 });
};

/**
 * Obtener estadísticas de actividades
 */
SuspiciousActivitySchema.statics.getStats = function (timeRangeHours = 24) {
  const timeThreshold = new Date(Date.now() - timeRangeHours * 60 * 60 * 1000);

  return this.aggregate([
    { $match: { timestamp: { $gte: timeThreshold } } },
    {
      $group: {
        _id: null,
        totalActivities: { $sum: 1 },
        byType: { $push: "$activityType" },
        bySeverity: { $push: "$severity" },
        avgRiskScore: { $avg: "$riskScore" },
        resolvedCount: {
          $sum: { $cond: [{ $eq: ["$resolved", true] }, 1, 0] },
        },
        criticalCount: {
          $sum: { $cond: [{ $eq: ["$severity", "critical"] }, 1, 0] },
        },
        highCount: {
          $sum: { $cond: [{ $eq: ["$severity", "high"] }, 1, 0] },
        },
      },
    },
  ]);
};

// ================================
// ÍNDICES ESPECÍFICOS
// ================================

// Índice compuesto para búsquedas de seguridad
SuspiciousActivitySchema.index(
  {
    activityType: 1,
    severity: 1,
    timestamp: -1,
    resolved: 1,
  },
  { name: "security_analysis_index" }
);

// Índice para deduplicación
SuspiciousActivitySchema.index(
  { deduplicationHash: 1 },
  {
    name: "deduplication_index",
    sparse: true,
  }
);

// Índice para correlación
SuspiciousActivitySchema.index(
  { incidentId: 1 },
  {
    name: "incident_correlation_index",
    sparse: true,
  }
);

// Índice TTL para auto-limpieza (opcional)
SuspiciousActivitySchema.index(
  { timestamp: 1 },
  {
    name: "suspicious_activity_ttl",
    expireAfterSeconds: 365 * 24 * 60 * 60, // 1 año
  }
);

// ================================
// MIDDLEWARE
// ================================

// Pre-save: calcular scores automáticamente
SuspiciousActivitySchema.pre("save", function (next) {
  if (this.isNew) {
    // Calcular risk score si no está establecido
    if (!this.riskScore) {
      this.riskScore = this.calculateRiskScore();
    }

    // Calcular hash de deduplicación
    if (!this.deduplicationHash) {
      this.calculateDeduplicationHash();
    }

    // Establecer scores de severidad
    const severityScores = { low: 25, medium: 50, high: 75, critical: 100 };
    this.severityScore = severityScores[this.severity];
  }

  next();
});

// Post-save: notificaciones automáticas
SuspiciousActivitySchema.post("save", function (doc) {
  if (doc.isNew && (doc.severity === "high" || doc.severity === "critical")) {
    // Aquí iría la lógica de notificación automática
    console.log(`🚨 Actividad sospechosa ${doc.severity}: ${doc.activityType}`);
  }
});

// ================================
// MÉTODO PARA CALCULAR RISK SCORE
// ================================

SuspiciousActivitySchema.methods.calculateRiskScore = function () {
  const baseScores = {
    device_change: 30,
    location_change: 20,
    fingerprint_mismatch: 40,
    rapid_requests: 25,
    bot_detected: 60,
    brute_force: 80,
    privilege_escalation: 90,
    account_takeover: 95,
    data_exfiltration: 100,
  };

  const severityMultipliers = {
    low: 0.5,
    medium: 1,
    high: 1.5,
    critical: 2,
  };

  let score = baseScores[this.activityType] || 10;
  score *= severityMultipliers[this.severity] || 1;

  // Ajustes por contexto
  if (this.occurrenceCount > 5) score += 10;
  if (this.detectionConfidence > 0.9) score += 5;
  if (this.evidence?.patterns?.length > 0) score += 10;

  return Math.min(100, Math.max(0, Math.round(score)));
};

// ================================
// EXPORTAR SCHEMA
// ================================

export default SuspiciousActivitySchema;
