// =============================================================================
// src/modules/authentication/models/user-session/schemas/fingerprint-changes.schema.js
// Schema para cambios de fingerprint con análisis avanzado
// =============================================================================
import mongoose from "mongoose";

/**
 * Schema para cambios de fingerprint (mejorado con análisis de seguridad)
 *
 * @description Sistema completo de tracking de cambios de device fingerprint
 * con análisis de patrones, detección de anomalías y validación de usuario
 */
export const FingerprintChangeSchema = new mongoose.Schema(
  {
    // ================================
    // FINGERPRINTS PRINCIPAL
    // ================================

    newFingerprint: {
      type: String,
      required: true,
      length: 64, // SHA-256 hash
      validate: {
        validator: function (v) {
          return /^[a-f0-9]{64}$/i.test(v);
        },
        message:
          "New fingerprint debe ser un hash hexadecimal de 64 caracteres",
      },
    },

    previousFingerprint: {
      type: String,
      required: true,
      length: 64, // SHA-256 hash
      validate: {
        validator: function (v) {
          return /^[a-f0-9]{64}$/i.test(v);
        },
        message:
          "Previous fingerprint debe ser un hash hexadecimal de 64 caracteres",
      },
    },

    // ================================
    // INFORMACIÓN TEMPORAL
    // ================================

    changedAt: {
      type: Date,
      default: Date.now,
      required: true,
      index: true,
    },

    // Tiempo transcurrido desde el fingerprint anterior
    timeSincePrevious: {
      type: Number, // En minutos
      min: 0,
    },

    // Detección automática vs manual
    detectionMethod: {
      type: String,
      enum: [
        "automatic",
        "manual_check",
        "periodic_scan",
        "login_verification",
      ],
      default: "automatic",
    },

    // ================================
    // CLASIFICACIÓN DEL CAMBIO
    // ================================

    changeType: {
      type: String,
      enum: ["minor", "major", "suspicious", "critical"],
      default: "minor",
      index: true,
    },

    // Nivel de sospecha (0-1)
    suspicionLevel: {
      type: Number,
      min: 0,
      max: 1,
      default: 0,
    },

    suspiciousChange: {
      type: Boolean,
      default: false,
      index: true,
    },

    // ================================
    // VALIDACIÓN DE USUARIO
    // ================================

    validatedByUser: {
      type: Boolean,
      default: false,
      index: true,
    },

    validatedAt: {
      type: Date,
    },

    validationMethod: {
      type: String,
      enum: [
        "email_link",
        "sms_code",
        "push_notification",
        "security_questions",
        "biometric",
        "manual_review",
      ],
    },

    // Intentos de validación
    validationAttempts: {
      type: Number,
      default: 0,
      min: 0,
    },

    // ================================
    // COMPONENTES ESPECÍFICOS QUE CAMBIARON
    // ================================

    changedComponents: [
      {
        // Tipo de componente del fingerprint
        component: {
          type: String,
          enum: [
            // Información básica
            "userAgent",
            "language",
            "timezone",
            "screen",
            "viewport",

            // Hardware
            "hardwareConcurrency",
            "deviceMemory",
            "maxTouchPoints",
            "colorDepth",
            "pixelRatio",

            // Software
            "plugins",
            "fonts",
            "mimeTypes",

            // Rendering
            "canvas",
            "webgl",
            "webglVendor",
            "webglRenderer",

            // Audio
            "audioContext",
            "audioFingerprint",

            // Otros
            "localStorage",
            "sessionStorage",
            "indexedDB",
            "cookieEnabled",
            "doNotTrack",
            "platform",
            "cpuClass",
            "oscpu",

            // Nuevos componentes
            "batteryLevel",
            "chargingStatus",
            "connectionType",
            "effectiveType",
            "downlink",
            "rtt",
          ],
          required: true,
        },

        // Valor anterior
        oldValue: {
          type: String,
          maxlength: 500,
        },

        // Valor nuevo
        newValue: {
          type: String,
          maxlength: 500,
        },

        // Significado del cambio
        changeSignificance: {
          type: String,
          enum: ["minor", "moderate", "major", "critical"],
          default: "minor",
        },

        // Confianza en que el cambio es legítimo
        legitimacyConfidence: {
          type: Number,
          min: 0,
          max: 1,
          default: 0.5,
        },

        // Peso del componente en el fingerprint total
        componentWeight: {
          type: Number,
          min: 0,
          max: 1,
          default: 0.1,
        },

        // Frecuencia esperada de cambio para este componente
        expectedChangeFrequency: {
          type: String,
          enum: ["never", "rare", "occasional", "frequent", "constant"],
          default: "occasional",
        },
      },
    ],

    // ================================
    // ANÁLISIS DE SIMILITUD
    // ================================

    // Score de similitud (0-1)
    similarityScore: {
      type: Number,
      min: 0,
      max: 1,
      default: 0,
      index: true,
    },

    // Método de cálculo de similitud
    similarityMethod: {
      type: String,
      enum: ["hamming", "jaccard", "cosine", "custom"],
      default: "hamming",
    },

    // Análisis detallado de similitud
    similarityAnalysis: {
      // Componentes que permanecieron iguales
      unchangedComponents: [String],

      // Componentes con cambios menores
      minorChanges: [String],

      // Componentes con cambios mayores
      majorChanges: [String],

      // Score por categorías
      scores: {
        hardware: {
          type: Number,
          min: 0,
          max: 1,
          default: 1,
        },
        software: {
          type: Number,
          min: 0,
          max: 1,
          default: 1,
        },
        rendering: {
          type: Number,
          min: 0,
          max: 1,
          default: 1,
        },
        network: {
          type: Number,
          min: 0,
          max: 1,
          default: 1,
        },
      },
    },

    // ================================
    // ANÁLISIS DE CONTEXTO
    // ================================

    // Contexto del cambio
    changeContext: {
      // Información de ubicación
      location: {
        previousCountry: String,
        newCountry: String,
        locationChanged: {
          type: Boolean,
          default: false,
        },
        distanceKm: Number,
      },

      // Información temporal
      timing: {
        timeOfDay: String, // "morning", "afternoon", "evening", "night"
        dayOfWeek: String,
        isWeekend: Boolean,
        isHoliday: Boolean,
        timezoneChanged: Boolean,
      },

      // Información de red
      network: {
        ipChanged: {
          type: Boolean,
          default: false,
        },
        ispChanged: {
          type: Boolean,
          default: false,
        },
        vpnDetected: Boolean,
        proxyDetected: Boolean,
      },

      // Patrones de uso
      usage: {
        sessionCount: Number,
        avgSessionDuration: Number,
        lastActivityMinutes: Number,
        typicalUserBehavior: Boolean,
      },
    },

    // ================================
    // ACCIONES AUTOMÁTICAS
    // ================================

    autoBlocked: {
      type: Boolean,
      default: false,
      index: true,
    },

    blockReason: {
      type: String,
      maxlength: 200,
    },

    blockDuration: {
      type: Number, // En minutos
      min: 0,
    },

    // Acción recomendada
    recommendedAction: {
      type: String,
      enum: [
        "allow",
        "request_validation",
        "temporary_block",
        "permanent_block",
        "escalate_to_admin",
        "require_2fa",
        "limit_access",
      ],
      default: "allow",
    },

    // ================================
    // INFORMACIÓN DEL SISTEMA
    // ================================

    // Sistema que detectó el cambio
    detectedBy: {
      system: {
        type: String,
        default: "fingerprint_monitor",
      },
      version: String,
      algorithm: String,
      confidence: {
        type: Number,
        min: 0,
        max: 1,
        default: 0.8,
      },
    },

    // Configuración usada para la detección
    detectionConfig: {
      threshold: Number,
      sensitivity: String,
      componentsWeights: mongoose.Schema.Types.Mixed,
    },

    // ================================
    // RESOLUCIÓN Y SEGUIMIENTO
    // ================================

    // Estado de resolución
    resolution: {
      status: {
        type: String,
        enum: ["pending", "validated", "rejected", "ignored", "escalated"],
        default: "pending",
      },

      resolvedAt: Date,

      resolvedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },

      resolutionMethod: {
        type: String,
        enum: [
          "auto_validation",
          "user_validation",
          "admin_override",
          "timeout",
          "false_positive",
        ],
      },

      notes: {
        type: String,
        maxlength: 500,
      },
    },

    // ================================
    // MACHINE LEARNING Y PATRONES
    // ================================

    // Clasificación por ML
    mlClassification: {
      model: String,
      version: String,
      prediction: {
        type: String,
        enum: ["legitimate", "suspicious", "fraudulent", "bot", "uncertain"],
      },
      confidence: {
        type: Number,
        min: 0,
        max: 1,
      },
      features: mongoose.Schema.Types.Mixed,
    },

    // Patrones identificados
    patterns: [
      {
        type: {
          type: String,
          enum: [
            "sequential_changes",
            "rapid_changes",
            "coordinated_changes",
            "anomalous_timing",
          ],
        },
        confidence: {
          type: Number,
          min: 0,
          max: 1,
        },
        description: String,
      },
    ],

    // ================================
    // METADATOS ADICIONALES
    // ================================

    metadata: {
      // Información del navegador durante el cambio
      browserInfo: {
        name: String,
        version: String,
        engine: String,
        platform: String,
      },

      // Información del dispositivo
      deviceInfo: {
        type: String, // "desktop", "mobile", "tablet"
        os: String,
        osVersion: String,
      },

      // Información de la sesión
      sessionInfo: {
        duration: Number, // Duración de la sesión en minutos
        requestCount: Number,
        lastActivity: Date,
      },

      // Análisis de riesgo
      riskAssessment: {
        overallRisk: {
          type: String,
          enum: ["low", "medium", "high", "critical"],
          default: "low",
        },
        riskScore: {
          type: Number,
          min: 0,
          max: 100,
          default: 0,
        },
        riskFactors: [String],
      },
    },
  },
  {
    _id: true,
    timestamps: false,
  }
);

// ================================
// MÉTODOS DE INSTANCIA
// ================================

/**
 * Calcular score de similitud entre fingerprints
 */
FingerprintChangeSchema.methods.calculateSimilarity = function () {
  if (!this.newFingerprint || !this.previousFingerprint) return 0;
  if (this.newFingerprint === this.previousFingerprint) return 1;

  // Distancia de Hamming normalizada
  let matches = 0;
  const length = Math.min(
    this.newFingerprint.length,
    this.previousFingerprint.length
  );

  for (let i = 0; i < length; i++) {
    if (this.newFingerprint[i] === this.previousFingerprint[i]) {
      matches++;
    }
  }

  this.similarityScore = matches / length;
  return this.similarityScore;
};

/**
 * Determinar tipo de cambio basado en componentes
 */
FingerprintChangeSchema.methods.analyzeChangeType = function () {
  if (!this.changedComponents || this.changedComponents.length === 0) {
    this.changeType = "minor";
    return this.changeType;
  }

  const criticalComponents = [
    "userAgent",
    "screen",
    "hardwareConcurrency",
    "platform",
  ];
  const majorComponents = ["plugins", "fonts", "canvas", "webgl"];

  let criticalChanges = 0;
  let majorChanges = 0;
  let totalWeight = 0;

  this.changedComponents.forEach((change) => {
    totalWeight += change.componentWeight || 0.1;

    if (criticalComponents.includes(change.component)) {
      criticalChanges++;
    } else if (majorComponents.includes(change.component)) {
      majorChanges++;
    }
  });

  // Determinar tipo basado en componentes y pesos
  if (criticalChanges >= 2 || totalWeight > 0.7) {
    this.changeType = "critical";
  } else if (criticalChanges >= 1 || majorChanges >= 3 || totalWeight > 0.4) {
    this.changeType = "suspicious";
  } else if (majorChanges >= 1 || totalWeight > 0.2) {
    this.changeType = "major";
  } else {
    this.changeType = "minor";
  }

  // Actualizar suspicionLevel
  const suspicionLevels = {
    minor: 0.1,
    major: 0.3,
    suspicious: 0.7,
    critical: 0.9,
  };

  this.suspicionLevel = suspicionLevels[this.changeType];
  this.suspiciousChange = this.suspicionLevel >= 0.5;

  return this.changeType;
};

/**
 * Validar cambio por usuario
 */
FingerprintChangeSchema.methods.validateByUser = function (
  method = "email_link"
) {
  this.validatedByUser = true;
  this.validatedAt = new Date();
  this.validationMethod = method;
  this.resolution.status = "validated";
  this.resolution.resolvedAt = new Date();
  this.resolution.resolutionMethod = "user_validation";

  // Reducir nivel de sospecha
  this.suspicionLevel = Math.max(0, this.suspicionLevel - 0.3);
  this.suspiciousChange = this.suspicionLevel >= 0.5;

  return this;
};

/**
 * Marcar como falso positivo
 */
FingerprintChangeSchema.methods.markAsFalsePositive = function (reason) {
  this.resolution.status = "rejected";
  this.resolution.resolvedAt = new Date();
  this.resolution.resolutionMethod = "false_positive";
  this.resolution.notes = reason;

  this.suspicionLevel = 0;
  this.suspiciousChange = false;
  this.changeType = "minor";

  return this;
};

/**
 * Obtener resumen del cambio
 */
FingerprintChangeSchema.methods.getSummary = function () {
  const componentCount = this.changedComponents?.length || 0;
  const components = this.changedComponents
    ?.map((c) => c.component)
    .slice(0, 3)
    .join(", ");
  const etc = componentCount > 3 ? "..." : "";

  return `${this.changeType.toUpperCase()} change: ${componentCount} components (${components}${etc}) - Similarity: ${(this.similarityScore * 100).toFixed(1)}%`;
};

/**
 * Verificar si necesita validación
 */
FingerprintChangeSchema.methods.needsValidation = function () {
  return (
    this.suspiciousChange &&
    !this.validatedByUser &&
    this.resolution.status === "pending" &&
    (this.changeType === "suspicious" || this.changeType === "critical")
  );
};

/**
 * Calcular riesgo de seguridad
 */
FingerprintChangeSchema.methods.calculateSecurityRisk = function () {
  let riskScore = 0;

  // Base score por tipo de cambio
  const typeScores = { minor: 10, major: 30, suspicious: 60, critical: 90 };
  riskScore += typeScores[this.changeType] || 0;

  // Factores de contexto
  if (this.changeContext?.location?.locationChanged) riskScore += 20;
  if (this.changeContext?.network?.ipChanged) riskScore += 15;
  if (this.changeContext?.network?.vpnDetected) riskScore += 25;
  if (
    this.changeContext?.timing?.isWeekend &&
    this.changeContext?.timing?.timeOfDay === "night"
  )
    riskScore += 10;

  // Reducir score por similitud alta
  if (this.similarityScore > 0.8) riskScore -= 15;
  if (this.similarityScore > 0.9) riskScore -= 10;

  // Ajustar por ML classification
  if (this.mlClassification?.prediction === "suspicious") riskScore += 20;
  if (this.mlClassification?.prediction === "fraudulent") riskScore += 40;

  this.metadata = this.metadata || {};
  this.metadata.riskAssessment = this.metadata.riskAssessment || {};
  this.metadata.riskAssessment.riskScore = Math.min(
    100,
    Math.max(0, riskScore)
  );

  // Determinar nivel de riesgo
  if (riskScore >= 80) this.metadata.riskAssessment.overallRisk = "critical";
  else if (riskScore >= 60) this.metadata.riskAssessment.overallRisk = "high";
  else if (riskScore >= 30) this.metadata.riskAssessment.overallRisk = "medium";
  else this.metadata.riskAssessment.overallRisk = "low";

  return this.metadata.riskAssessment;
};

// ================================
// MÉTODOS ESTÁTICOS
// ================================

/**
 * Crear registro de cambio de fingerprint
 */
FingerprintChangeSchema.statics.createFromFingerprints = function (
  oldFP,
  newFP,
  changedComponents = []
) {
  const change = new this({
    previousFingerprint: oldFP,
    newFingerprint: newFP,
    changedComponents: changedComponents,
  });

  // Calcular similitud y tipo de cambio
  change.calculateSimilarity();
  change.analyzeChangeType();
  change.calculateSecurityRisk();

  return change;
};

/**
 * Encontrar patrones de cambios sospechosos
 */
FingerprintChangeSchema.statics.findSuspiciousPatterns = function (
  userId,
  timeRangeHours = 24
) {
  const timeThreshold = new Date(Date.now() - timeRangeHours * 60 * 60 * 1000);

  return this.aggregate([
    {
      $match: {
        changedAt: { $gte: timeThreshold },
        // Asumir que tenemos userId en el documento padre
      },
    },
    {
      $group: {
        _id: null,
        totalChanges: { $sum: 1 },
        suspiciousChanges: {
          $sum: { $cond: [{ $eq: ["$suspiciousChange", true] }, 1, 0] },
        },
        criticalChanges: {
          $sum: { $cond: [{ $eq: ["$changeType", "critical"] }, 1, 0] },
        },
        avgSimilarity: { $avg: "$similarityScore" },
        patterns: { $push: "$patterns" },
        changeTypes: { $push: "$changeType" },
      },
    },
  ]);
};

/**
 * Estadísticas de validación
 */
FingerprintChangeSchema.statics.getValidationStats = function (
  timeRangeHours = 24
) {
  const timeThreshold = new Date(Date.now() - timeRangeHours * 60 * 60 * 1000);

  return this.aggregate([
    { $match: { changedAt: { $gte: timeThreshold } } },
    {
      $group: {
        _id: null,
        totalChanges: { $sum: 1 },
        validatedChanges: {
          $sum: { $cond: [{ $eq: ["$validatedByUser", true] }, 1, 0] },
        },
        autoBlockedChanges: {
          $sum: { $cond: [{ $eq: ["$autoBlocked", true] }, 1, 0] },
        },
        pendingValidation: {
          $sum: { $cond: [{ $eq: ["$resolution.status", "pending"] }, 1, 0] },
        },
        avgValidationTime: { $avg: "$timeSincePrevious" },
      },
    },
  ]);
};

// ================================
// MIDDLEWARE
// ================================

// Pre-save: análisis automático
FingerprintChangeSchema.pre("save", function (next) {
  if (this.isNew) {
    // Calcular similitud si no está establecida
    if (this.similarityScore === 0) {
      this.calculateSimilarity();
    }

    // Analizar tipo de cambio
    if (!this.changeType || this.changeType === "minor") {
      this.analyzeChangeType();
    }

    // Calcular riesgo de seguridad
    this.calculateSecurityRisk();

    // Determinar acción recomendada
    if (this.changeType === "critical" || this.suspicionLevel > 0.8) {
      this.recommendedAction = "temporary_block";
    } else if (this.changeType === "suspicious" || this.suspicionLevel > 0.5) {
      this.recommendedAction = "request_validation";
    } else {
      this.recommendedAction = "allow";
    }
  }

  next();
});

// ================================
// ÍNDICES ESPECÍFICOS
// ================================

// Índice compuesto para análisis de patrones
FingerprintChangeSchema.index(
  {
    changeType: 1,
    suspiciousChange: 1,
    changedAt: -1,
    validatedByUser: 1,
  },
  { name: "fingerprint_pattern_analysis" }
);

// Índice para similitud
FingerprintChangeSchema.index(
  { similarityScore: 1 },
  { name: "similarity_analysis" }
);

// Índice para resolución
FingerprintChangeSchema.index(
  { "resolution.status": 1, changedAt: -1 },
  { name: "resolution_tracking" }
);

// ================================
// EXPORTAR SCHEMA
// ================================

export default FingerprintChangeSchema;
