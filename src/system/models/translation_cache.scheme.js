// =============================================================================
// src/modules/system/models/translation_cache.scheme.js
// =============================================================================
import mongoose from "mongoose";
import crypto from "crypto";
import {
  BaseSchemaFields,
  setupBaseSchema,
} from "../../core/models/base.scheme.js";
import {
  SUPPORTED_LANGUAGES,
  DEFAULT_LANGUAGE,
} from "../../core/models/multi_language_pattern.scheme.js";

/**
 * Schema para metadatos de traducción
 */
const TranslationMetadataSchema = new mongoose.Schema(
  {
    modelUsed: {
      type: String,
      enum: ["gpt-4", "gpt-3.5-turbo", "google-translate", "deepl", "manual"],
      default: "gpt-4",
    },
    tokensUsed: {
      type: Number,
      min: [0, "Los tokens usados no pueden ser negativos"],
    },
    cost: {
      type: Number,
      min: [0, "El costo no puede ser negativo"],
    },
    processingTime: {
      type: Number, // en milisegundos
      min: [0, "El tiempo de procesamiento no puede ser negativo"],
    },
    retryCount: {
      type: Number,
      default: 0,
      min: [0, "El contador de reintentos no puede ser negativo"],
    },
  },
  { _id: false }
);

/**
 * Schema para información de contexto
 */
const ContextInfoSchema = new mongoose.Schema(
  {
    domain: {
      type: String,
      enum: [
        "business_name",
        "description",
        "service",
        "address",
        "review",
        "category",
        "general",
      ],
      default: "general",
      index: true,
    },
    entityType: {
      type: String,
      enum: [
        "Business",
        "BusinessCategory",
        "Review",
        "Service",
        "Address",
        "User",
      ],
      index: true,
    },
    entityId: {
      type: mongoose.Schema.Types.ObjectId,
      index: true,
    },
    businessSector: {
      type: String,
      enum: [
        "restaurant",
        "retail",
        "service",
        "healthcare",
        "education",
        "technology",
        "other",
      ],
      index: true,
    },
    technicalTerms: [
      {
        type: String,
        trim: true,
        lowercase: true,
      },
    ],
    culturalContext: {
      type: String,
      enum: ["formal", "informal", "technical", "marketing", "legal"],
      default: "general",
    },
  },
  { _id: false }
);

/**
 * Schema principal de Cache de Traducción
 */
const TranslationCacheSchema = new mongoose.Schema({
  // Texto fuente y destino
  sourceText: {
    type: String,
    required: [true, "El texto fuente es requerido"],
    maxlength: [5000, "El texto fuente no puede exceder 5000 caracteres"],
    trim: true,
    index: "text",
  },

  sourceLanguage: {
    type: String,
    required: [true, "El idioma fuente es requerido"],
    enum: SUPPORTED_LANGUAGES,
    index: true,
  },

  targetLanguage: {
    type: String,
    required: [true, "El idioma destino es requerido"],
    enum: SUPPORTED_LANGUAGES,
    index: true,
  },

  // Texto traducido
  translatedText: {
    type: String,
    required: [true, "El texto traducido es requerido"],
    maxlength: [5000, "El texto traducido no puede exceder 5000 caracteres"],
    trim: true,
    index: "text",
  },

  // Metadatos de traducción
  translationService: {
    type: String,
    required: [true, "El servicio de traducción es requerido"],
    enum: ["openai", "google", "deepl", "azure", "manual", "professional"],
    index: true,
  },

  confidence: {
    type: Number,
    min: [0, "La confianza debe estar entre 0 y 1"],
    max: [1, "La confianza debe estar entre 0 y 1"],
    default: 0.8,
    index: true,
  },

  qualityScore: {
    type: Number,
    min: [0, "El puntaje de calidad debe estar entre 0 y 10"],
    max: [10, "El puntaje de calidad debe estar entre 0 y 10"],
    default: 7,
    index: true,
  },

  // Optimización y uso
  textHash: {
    type: String,
    required: [true, "El hash del texto es requerido"],
    unique: true,
    index: true,
  },

  usageCount: {
    type: Number,
    default: 1,
    min: [1, "El contador de uso debe ser al menos 1"],
    index: true,
  },

  lastUsedAt: {
    type: Date,
    default: Date.now,
    index: true,
  },

  popularityScore: {
    type: Number,
    default: 0,
    min: [0, "El puntaje de popularidad no puede ser negativo"],
    index: true,
  },

  // Calidad y verificación
  isVerified: {
    type: Boolean,
    default: false,
    index: true,
  },

  verifiedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },

  verifiedAt: {
    type: Date,
  },

  needsReview: {
    type: Boolean,
    default: false,
    index: true,
  },

  reviewNotes: {
    type: String,
    maxlength: [500, "Las notas de revisión no pueden exceder 500 caracteres"],
  },

  // Contexto y categorización
  contextInfo: ContextInfoSchema,

  // Traducciones alternativas
  alternatives: [
    {
      text: {
        type: String,
        required: true,
        maxlength: 5000,
      },
      service: {
        type: String,
        enum: ["openai", "google", "deepl", "azure", "manual"],
      },
      confidence: {
        type: Number,
        min: 0,
        max: 1,
      },
      votes: {
        type: Number,
        default: 0,
      },
      createdAt: {
        type: Date,
        default: Date.now,
      },
    },
  ],

  // Feedback y mejora
  feedback: [
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
      },
      rating: {
        type: Number,
        required: true,
        min: 1,
        max: 5,
      },
      comment: {
        type: String,
        maxlength: 200,
      },
      createdAt: {
        type: Date,
        default: Date.now,
      },
    },
  ],

  averageFeedbackRating: {
    type: Number,
    min: [1, "La calificación promedio debe estar entre 1 y 5"],
    max: [5, "La calificación promedio debe estar entre 1 y 5"],
    index: true,
  },

  // Expiración y limpieza
  expiresAt: {
    type: Date,
    index: 1, // TTL index
  },

  lastValidatedAt: {
    type: Date,
  },

  // Metadatos técnicos
  metadata: TranslationMetadataSchema,

  // Estadísticas de rendimiento
  performance: {
    cacheHits: {
      type: Number,
      default: 0,
      min: 0,
    },
    avgResponseTime: {
      type: Number, // en milisegundos
      default: 0,
      min: 0,
    },
    lastResponseTime: {
      type: Number,
      min: 0,
    },
  },

  // Campos base (auditoría, soft delete, etc.)
  ...BaseSchemaFields,
});

// Configurar el esquema con funcionalidades base
setupBaseSchema(TranslationCacheSchema, {
  addBaseFields: false, // Ya los agregamos manualmente arriba
});

// ================================
// ÍNDICES ESPECÍFICOS
// ================================

// Índice único para el hash
TranslationCacheSchema.index({ textHash: 1 }, { unique: true });

// Índice compuesto principal para búsquedas rápidas
TranslationCacheSchema.index({
  sourceLanguage: 1,
  targetLanguage: 1,
  translationService: 1,
});

// Índices para optimización de cache
TranslationCacheSchema.index({ usageCount: -1, lastUsedAt: -1 });
TranslationCacheSchema.index({ popularityScore: -1, qualityScore: -1 });
TranslationCacheSchema.index({ confidence: -1, isVerified: -1 });

// Índices para contexto y categorización
TranslationCacheSchema.index({
  "contextInfo.domain": 1,
  "contextInfo.businessSector": 1,
});
TranslationCacheSchema.index({
  "contextInfo.entityType": 1,
  "contextInfo.entityId": 1,
});

// Índices para calidad y revisión
TranslationCacheSchema.index({ needsReview: 1, qualityScore: 1 });
TranslationCacheSchema.index({ isVerified: 1, averageFeedbackRating: -1 });

// TTL index para expiración automática
TranslationCacheSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Índice de texto para búsqueda de contenido
TranslationCacheSchema.index(
  {
    sourceText: "text",
    translatedText: "text",
  },
  {
    name: "translation_content_search",
  }
);

// ================================
// VIRTUALS
// ================================

// Virtual para verificar si está expirado
TranslationCacheSchema.virtual("isExpired").get(function () {
  return this.expiresAt && this.expiresAt < new Date();
});

// Virtual para verificar si es popular
TranslationCacheSchema.virtual("isPopular").get(function () {
  return this.usageCount >= 10 && this.qualityScore >= 8;
});

// Virtual para verificar si necesita actualización
TranslationCacheSchema.virtual("needsUpdate").get(function () {
  const monthAgo = new Date();
  monthAgo.setMonth(monthAgo.getMonth() - 1);

  return !this.lastValidatedAt || this.lastValidatedAt < monthAgo;
});

// Virtual para obtener el puntaje de calidad general
TranslationCacheSchema.virtual("overallQuality").get(function () {
  let score = this.qualityScore * 0.4; // 40% del puntaje base

  if (this.confidence) score += this.confidence * 10 * 0.3; // 30% de la confianza
  if (this.averageFeedbackRating) score += this.averageFeedbackRating * 2 * 0.2; // 20% del feedback
  if (this.isVerified) score += 1; // 10% si está verificado

  return Math.min(Math.round(score * 10) / 10, 10);
});

// ================================
// MÉTODOS DE INSTANCIA
// ================================

// Método para incrementar uso
TranslationCacheSchema.methods.incrementUsage = async function () {
  this.usageCount += 1;
  this.lastUsedAt = new Date();

  // Actualizar puntaje de popularidad
  this.updatePopularityScore();

  // Incrementar cache hits
  if (!this.performance) this.performance = {};
  this.performance.cacheHits = (this.performance.cacheHits || 0) + 1;

  return this.save();
};

// Método para actualizar puntaje de popularidad
TranslationCacheSchema.methods.updatePopularityScore = function () {
  // Algoritmo de popularidad basado en uso reciente y frecuencia
  const daysSinceLastUse = Math.floor(
    (new Date() - this.lastUsedAt) / (1000 * 60 * 60 * 24)
  );

  const recencyFactor = Math.max(0, 1 - daysSinceLastUse / 30); // Decae en 30 días
  const usageFactor = Math.min(this.usageCount / 100, 1); // Normalizado a 1 en 100 usos
  const qualityFactor = this.qualityScore / 10;

  this.popularityScore =
    (recencyFactor * 0.4 + usageFactor * 0.4 + qualityFactor * 0.2) * 100;

  return this;
};

// Método para agregar feedback
TranslationCacheSchema.methods.addFeedback = function (
  userId,
  rating,
  comment = ""
) {
  if (!this.feedback) {
    this.feedback = [];
  }

  // Verificar si el usuario ya dio feedback
  const existingFeedback = this.feedback.find((f) => f.userId.equals(userId));
  if (existingFeedback) {
    throw new Error("El usuario ya proporcionó feedback para esta traducción");
  }

  this.feedback.push({
    userId,
    rating,
    comment,
    createdAt: new Date(),
  });

  // Actualizar calificación promedio
  this.updateAverageFeedbackRating();

  return this;
};

// Método para actualizar calificación promedio de feedback
TranslationCacheSchema.methods.updateAverageFeedbackRating = function () {
  if (!this.feedback || this.feedback.length === 0) {
    this.averageFeedbackRating = undefined;
    return this;
  }

  const sum = this.feedback.reduce((acc, feedback) => acc + feedback.rating, 0);
  this.averageFeedbackRating =
    Math.round((sum / this.feedback.length) * 10) / 10;

  return this;
};

// Método para agregar alternativa de traducción
TranslationCacheSchema.methods.addAlternative = function (
  text,
  service,
  confidence = 0.8
) {
  if (!this.alternatives) {
    this.alternatives = [];
  }

  // Verificar si ya existe esta alternativa
  const existingAlt = this.alternatives.find((alt) => alt.text === text);
  if (existingAlt) {
    existingAlt.votes += 1;
    return this;
  }

  this.alternatives.push({
    text,
    service,
    confidence,
    votes: 0,
    createdAt: new Date(),
  });

  return this;
};

// Método para marcar como verificado
TranslationCacheSchema.methods.markAsVerified = function (verifiedBy) {
  this.isVerified = true;
  this.verifiedBy = verifiedBy;
  this.verifiedAt = new Date();
  this.needsReview = false;
  this.lastValidatedAt = new Date();

  // Aumentar puntaje de calidad si está verificado
  this.qualityScore = Math.min(this.qualityScore + 1, 10);

  return this;
};

// Método para marcar para revisión
TranslationCacheSchema.methods.markForReview = function (reason = "") {
  this.needsReview = true;
  this.reviewNotes = reason;

  return this;
};

// Método para actualizar tiempo de respuesta
TranslationCacheSchema.methods.updateResponseTime = function (responseTime) {
  if (!this.performance) {
    this.performance = {};
  }

  this.performance.lastResponseTime = responseTime;

  // Calcular tiempo promedio de respuesta
  if (!this.performance.avgResponseTime) {
    this.performance.avgResponseTime = responseTime;
  } else {
    this.performance.avgResponseTime = Math.round(
      (this.performance.avgResponseTime + responseTime) / 2
    );
  }

  return this;
};

// ================================
// MÉTODOS ESTÁTICOS
// ================================

// Generar hash del texto para identificación única
TranslationCacheSchema.statics.generateTextHash = function (
  sourceText,
  sourceLanguage,
  targetLanguage
) {
  const hashInput = `${sourceLanguage}:${targetLanguage}:${sourceText
    .trim()
    .toLowerCase()}`;
  return crypto.createHash("sha256").update(hashInput, "utf8").digest("hex");
};

// Aplicar filtros de calidad
TranslationCacheSchema.statics.applyQualityFilters = function (
  query,
  options = {}
) {
  const {
    minConfidence = 0.7,
    minQualityScore = 6,
    preferVerified = true,
    contextInfo = null,
  } = options;

  if (minConfidence > 0) {
    query = query.where({ confidence: { $gte: minConfidence } });
  }

  if (minQualityScore > 0) {
    query = query.where({ qualityScore: { $gte: minQualityScore } });
  }

  if (preferVerified) {
    query = query.where({ isVerified: true });
  }

  if (contextInfo) {
    if (contextInfo.domain) {
      query = query.where({ "contextInfo.domain": contextInfo.domain });
    }
    if (contextInfo.businessSector) {
      query = query.where({
        "contextInfo.businessSector": contextInfo.businessSector,
      });
    }
  }

  return query;
};

// Buscar traducción exacta en cache
TranslationCacheSchema.statics.findCachedTranslation = function (
  sourceText,
  sourceLanguage,
  targetLanguage,
  options = {}
) {
  const textHash = this.generateTextHash(
    sourceText,
    sourceLanguage,
    targetLanguage
  );

  let query = this.findOne({
    textHash,
    sourceLanguage,
    targetLanguage,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  });

  // Aplicar filtros de calidad
  query = this.applyQualityFilters(query, options);

  return query;
};

// Buscar múltiples traducciones similares
TranslationCacheSchema.statics.findSimilarTranslations = function (
  sourceText,
  sourceLanguage,
  targetLanguage,
  options = {}
) {
  const { limit = 5, fuzzyMatch = true } = options;

  let query;

  if (fuzzyMatch) {
    // Búsqueda difusa usando texto
    query = this.find(
      {
        $text: { $search: sourceText },
        sourceLanguage,
        targetLanguage,
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      },
      {
        score: { $meta: "textScore" },
      }
    ).sort({ score: { $meta: "textScore" } });
  } else {
    // Búsqueda exacta
    const textHash = this.generateTextHash(
      sourceText,
      sourceLanguage,
      targetLanguage
    );
    query = this.find({
      textHash,
      sourceLanguage,
      targetLanguage,
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    });
  }

  // Aplicar filtros de calidad
  query = this.applyQualityFilters(query, options);

  return query.limit(limit);
};

// Crear nueva entrada de cache
TranslationCacheSchema.statics.createCacheEntry = async function (
  translationData,
  options = {}
) {
  const {
    sourceText,
    sourceLanguage,
    targetLanguage,
    translatedText,
    translationService,
    confidence = 0.8,
    qualityScore = 7,
    contextInfo = null,
    metadata = {},
    expiresInDays = 365,
  } = translationData;

  // Generar hash único
  const textHash = this.generateTextHash(
    sourceText,
    sourceLanguage,
    targetLanguage
  );

  // Verificar si ya existe
  const existingEntry = await this.findOne({ textHash });
  if (existingEntry && !options.forceCreate) {
    // Incrementar uso y retornar existente
    await existingEntry.incrementUsage();
    return existingEntry;
  }

  // Configurar expiración
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + expiresInDays);

  // Crear nueva entrada
  const cacheEntry = new this({
    sourceText,
    sourceLanguage,
    targetLanguage,
    translatedText,
    translationService,
    confidence,
    qualityScore,
    textHash,
    contextInfo,
    metadata,
    expiresAt,
    lastValidatedAt: new Date(),
  });

  return await cacheEntry.save();
};

// Obtener traducciones populares
TranslationCacheSchema.statics.getPopularTranslations = function (
  options = {}
) {
  const {
    limit = 20,
    sourceLanguage = null,
    targetLanguage = null,
    domain = null,
    minUsageCount = 10,
  } = options;

  let query = this.find({
    usageCount: { $gte: minUsageCount },
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  });

  if (sourceLanguage) {
    query = query.where({ sourceLanguage });
  }

  if (targetLanguage) {
    query = query.where({ targetLanguage });
  }

  if (domain) {
    query = query.where({ "contextInfo.domain": domain });
  }

  return query
    .sort({
      popularityScore: -1,
      usageCount: -1,
      qualityScore: -1,
    })
    .limit(limit);
};

// Obtener traducciones que necesitan revisión
TranslationCacheSchema.statics.getTranslationsNeedingReview = function (
  options = {}
) {
  const { limit = 50, qualityThreshold = 5 } = options;

  return this.find({
    $or: [
      { needsReview: true },
      { qualityScore: { $lt: qualityThreshold } },
      { isVerified: false, usageCount: { $gte: 20 } },
    ],
    $and: [{ $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }] }],
  })
    .sort({
      usageCount: -1,
      lastUsedAt: -1,
    })
    .limit(limit);
};

// Limpiar cache expirado y de baja calidad
TranslationCacheSchema.statics.cleanupCache = async function (options = {}) {
  const {
    removeExpired = true,
    removeLowQuality = true,
    minQualityScore = 3,
    minUsageCount = 1,
    daysUnused = 90,
  } = options;

  let deletedCount = 0;

  // Remover entradas expiradas
  if (removeExpired) {
    const expiredResult = await this.deleteMany({
      expiresAt: { $lt: new Date() },
    });
    deletedCount += expiredResult.deletedCount;
  }

  // Remover entradas de baja calidad y poco uso
  if (removeLowQuality) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysUnused);

    const lowQualityResult = await this.deleteMany({
      qualityScore: { $lt: minQualityScore },
      usageCount: { $lt: minUsageCount },
      lastUsedAt: { $lt: cutoffDate },
      isVerified: false,
    });
    deletedCount += lowQualityResult.deletedCount;
  }

  return { deletedCount };
};

// Obtener estadísticas del cache
TranslationCacheSchema.statics.getCacheStats = async function () {
  const stats = await this.aggregate([
    {
      $match: {
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      },
    },
    {
      $group: {
        _id: null,
        totalEntries: { $sum: 1 },
        verifiedEntries: {
          $sum: { $cond: [{ $eq: ["$isVerified", true] }, 1, 0] },
        },
        needingReview: {
          $sum: { $cond: [{ $eq: ["$needsReview", true] }, 1, 0] },
        },
        totalUsage: { $sum: "$usageCount" },
        avgQualityScore: { $avg: "$qualityScore" },
        avgConfidence: { $avg: "$confidence" },
        totalCacheHits: { $sum: "$performance.cacheHits" },
        avgResponseTime: { $avg: "$performance.avgResponseTime" },
      },
    },
  ]);

  // Estadísticas por idioma
  const languageStats = await this.aggregate([
    {
      $match: {
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      },
    },
    {
      $group: {
        _id: {
          source: "$sourceLanguage",
          target: "$targetLanguage",
        },
        count: { $sum: 1 },
        totalUsage: { $sum: "$usageCount" },
        avgQuality: { $avg: "$qualityScore" },
      },
    },
    {
      $sort: { count: -1 },
    },
  ]);

  // Estadísticas por servicio
  const serviceStats = await this.aggregate([
    {
      $match: {
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      },
    },
    {
      $group: {
        _id: "$translationService",
        count: { $sum: 1 },
        avgQuality: { $avg: "$qualityScore" },
        avgConfidence: { $avg: "$confidence" },
        totalUsage: { $sum: "$usageCount" },
      },
    },
    {
      $sort: { count: -1 },
    },
  ]);

  return {
    general: stats[0] || {
      totalEntries: 0,
      verifiedEntries: 0,
      needingReview: 0,
      totalUsage: 0,
      avgQualityScore: 0,
      avgConfidence: 0,
      totalCacheHits: 0,
      avgResponseTime: 0,
    },
    byLanguagePair: languageStats,
    byService: serviceStats,
  };
};

// ================================
// MIDDLEWARES
// ================================

// Pre-save middleware para generar hash y validaciones
TranslationCacheSchema.pre("save", function (next) {
  // Generar hash si no existe
  if (
    !this.textHash &&
    this.sourceText &&
    this.sourceLanguage &&
    this.targetLanguage
  ) {
    this.textHash = this.constructor.generateTextHash(
      this.sourceText,
      this.sourceLanguage,
      this.targetLanguage
    );
  }

  // Normalizar textos
  if (this.sourceText) {
    this.sourceText = this.sourceText.trim();
  }

  if (this.translatedText) {
    this.translatedText = this.translatedText.trim();
  }

  // Actualizar puntaje de popularidad
  if (this.isModified("usageCount") || this.isModified("lastUsedAt")) {
    this.updatePopularityScore();
  }

  // Configurar expiración por defecto si no está establecida
  if (!this.expiresAt) {
    this.expiresAt = new Date();
    this.expiresAt.setDate(this.expiresAt.getDate() + 365); // 1 año por defecto
  }

  next();
});

// Post-save middleware para logging
TranslationCacheSchema.post("save", function (doc, next) {
  if (doc.isNew) {
    console.log(
      `🌐 Traducción guardada en cache: ${doc.sourceLanguage} → ${doc.targetLanguage} (${doc.translationService})`
    );
  }
  next();
});

// ================================
// EXPORTAR MODELO
// ================================

export const TranslationCache = mongoose.model(
  "TranslationCache",
  TranslationCacheSchema
);
export default TranslationCache;
