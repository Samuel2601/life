// =============================================================================
// src/modules/core/models/multi_language_pattern_improved.scheme.js
// ESQUEMA MULTIIDIOMA EMPRESARIAL - VERSIÓN OPTIMIZADA Y MEJORADA
// =============================================================================
import mongoose from "mongoose";
import crypto from "crypto";

/**
 * CONSTANTES Y CONFIGURACIÓN
 */
export const SUPPORTED_LANGUAGES = [
  "es", // Español (por defecto)
  "en", // Inglés
  "fr", // Francés
  "de", // Alemán
  "pt", // Portugués
  "it", // Italiano
  "zh", // Chino
  "ja", // Japonés
  "ko", // Coreano
  "ar", // Árabe
  "ru", // Ruso
  "hi", // Hindi
];

export const DEFAULT_LANGUAGE = "es";

// Límites para producción
export const LIMITS = {
  MAX_TRANSLATIONS: 50,
  MAX_TEXT_LENGTH: 10000,
  MAX_PENDING_TRANSLATIONS: 100,
  MAX_VERSION_HISTORY: 20,
  CACHE_EXPIRY_HOURS: 24,
  RATE_LIMIT_REQUESTS_PER_HOUR: 1000,
  MAX_TRANSLATION_VARIANTS: 5,
};

/**
 * Schema para historial de versiones
 */
const VersionHistorySchema = new mongoose.Schema(
  {
    text: {
      type: String,
      required: true,
      maxlength: LIMITS.MAX_TEXT_LENGTH,
    },
    changedAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
    changedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    reason: {
      type: String,
      maxlength: 500,
    },
    changeType: {
      type: String,
      enum: ["created", "updated", "corrected", "migrated"],
      default: "updated",
    },
  },
  { _id: false }
);

/**
 * Schema para placeholders/variables dinámicas
 */
const PlaceholderSchema = new mongoose.Schema(
  {
    key: {
      type: String,
      required: true,
      match: /^[a-zA-Z_][a-zA-Z0-9_]*$/,
    },
    defaultValue: String,
    description: String,
    dataType: {
      type: String,
      enum: ["string", "number", "date", "boolean"],
      default: "string",
    },
    required: {
      type: Boolean,
      default: false,
    },
  },
  { _id: false }
);

/**
 * Schema para variantes A/B testing
 */
const TranslationVariantSchema = new mongoose.Schema(
  {
    variant: {
      type: String,
      required: true,
      match: /^[A-Z]$/,
    },
    text: {
      type: String,
      required: true,
      maxlength: LIMITS.MAX_TEXT_LENGTH,
    },
    performance: {
      impressions: { type: Number, default: 0 },
      clicks: { type: Number, default: 0 },
      conversions: { type: Number, default: 0 },
      ctr: { type: Number, default: 0 },
      conversionRate: { type: Number, default: 0 },
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    trafficAllocation: {
      type: Number,
      min: 0,
      max: 100,
      default: 50,
    },
  },
  { _id: false }
);

/**
 * Schema para contenido original mejorado
 */
const OriginalContentSchema = new mongoose.Schema(
  {
    language: {
      type: String,
      required: true,
      enum: SUPPORTED_LANGUAGES,
      default: DEFAULT_LANGUAGE,
      index: true,
    },
    text: {
      type: String,
      required: true,
      maxlength: LIMITS.MAX_TEXT_LENGTH,
      trim: true,
      validate: {
        validator: function (v) {
          return v && v.length > 0;
        },
        message: "El texto original no puede estar vacío",
      },
    },
    createdAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
    lastModified: {
      type: Date,
      default: Date.now,
      index: true,
    },
    wordCount: {
      type: Number,
      default: 0,
      min: 0,
    },
    characterCount: {
      type: Number,
      default: 0,
      min: 0,
    },
    // Historial de versiones
    versionHistory: {
      type: [VersionHistorySchema],
      default: [],
      validate: {
        validator: function (v) {
          return v.length <= LIMITS.MAX_VERSION_HISTORY;
        },
        message: `Máximo ${LIMITS.MAX_VERSION_HISTORY} versiones en historial`,
      },
    },
    // Placeholders para contenido dinámico
    placeholders: [PlaceholderSchema],
    // Hash del contenido para detección de cambios
    contentHash: {
      type: String,
      index: true,
    },
  },
  { _id: false }
);

// Índices compuestos para contenido original
OriginalContentSchema.index({ language: 1, contentHash: 1 });
OriginalContentSchema.index({ language: 1, lastModified: -1 });
OriginalContentSchema.index({ text: "text" }); // Índice de texto completo

/**
 * Schema para traducciones individuales mejorado
 */
const TranslationSchema = new mongoose.Schema(
  {
    text: {
      type: String,
      required: true,
      maxlength: LIMITS.MAX_TEXT_LENGTH,
      trim: true,
    },
    translatedAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
    translationMethod: {
      type: String,
      enum: ["ai", "manual", "auto", "professional", "hybrid"],
      default: "ai",
    },
    translationService: {
      type: String,
      enum: [
        "openai",
        "google",
        "deepl",
        "manual",
        "professional",
        "azure",
        "aws",
      ],
      default: "openai",
    },
    confidence: {
      type: Number,
      min: 0,
      max: 1,
      default: 0.8,
    },
    qualityScore: {
      type: Number,
      min: 0,
      max: 10,
      default: 7,
    },
    needsReview: {
      type: Boolean,
      default: false,
      index: true,
    },
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
      index: true,
    },
    wordCount: {
      type: Number,
      default: 0,
      min: 0,
    },
    characterCount: {
      type: Number,
      default: 0,
      min: 0,
    },
    // Hash para detectar cambios en el texto original
    sourceTextHash: {
      type: String,
      required: true,
      index: true,
    },
    // Contexto para mejores traducciones
    context: {
      type: String,
      enum: [
        "business_name",
        "description",
        "service",
        "address",
        "review",
        "general",
        "technical",
        "marketing",
        "legal",
      ],
      default: "general",
    },
    // Costo y métricas de performance
    translationCost: {
      type: Number,
      default: 0,
      min: 0,
    },
    translationTime: {
      type: Number, // en milisegundos
      default: 0,
      min: 0,
    },
    // Razón de revisión si aplica
    reviewReason: {
      type: String,
      maxlength: 500,
    },
    // Variantes para A/B testing
    variants: {
      type: Map,
      of: TranslationVariantSchema,
      default: new Map(),
      validate: {
        validator: function (v) {
          return v.size <= LIMITS.MAX_TRANSLATION_VARIANTS;
        },
        message: `Máximo ${LIMITS.MAX_TRANSLATION_VARIANTS} variantes por traducción`,
      },
    },
    // Cache de interpolaciones frecuentes
    cachedInterpolations: {
      type: Map,
      of: {
        result: String,
        cachedAt: Date,
        hitCount: { type: Number, default: 1 },
      },
      default: new Map(),
    },
  },
  { _id: false }
);

/**
 * Schema para gestión de colas de traducción
 */
const TranslationQueueSchema = new mongoose.Schema(
  {
    jobId: {
      type: String,
      unique: true,
      index: true,
    },
    status: {
      type: String,
      enum: ["queued", "processing", "completed", "failed", "cancelled"],
      default: "queued",
      index: true,
    },
    priority: {
      type: Number,
      min: 1,
      max: 10,
      default: 5,
      index: true,
    },
    estimatedDuration: Number, // en segundos
    actualDuration: Number,
    errorMessage: String,
    retryCount: {
      type: Number,
      default: 0,
      max: 3,
    },
    createdAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
    startedAt: Date,
    completedAt: Date,
  },
  { _id: false }
);

/**
 * Schema para rate limiting
 */
const RateLimitSchema = new mongoose.Schema(
  {
    lastTranslationRequest: {
      type: Date,
      default: Date.now,
    },
    requestCount: {
      type: Number,
      default: 0,
    },
    hourlyResetAt: {
      type: Date,
      default: () => new Date(Date.now() + 60 * 60 * 1000), // +1 hora
    },
    isBlocked: {
      type: Boolean,
      default: false,
    },
    blockedUntil: Date,
  },
  { _id: false }
);

/**
 * Schema principal para contenido multiidioma mejorado
 */
export const MultiLanguageContentSchema = new mongoose.Schema(
  {
    // Contenido original
    original: {
      type: OriginalContentSchema,
      required: true,
    },

    // Traducciones (Map: idioma -> traducción)
    translations: {
      type: Map,
      of: TranslationSchema,
      default: new Map(),
    },

    // Array auxiliar para indexar idiomas de traducciones
    translationLanguages: {
      type: [String],
      default: [],
      index: true,
      validate: {
        validator: function (languages) {
          // Verificar no duplicados
          return new Set(languages).size === languages.length;
        },
        message: "Idiomas duplicados no permitidos",
      },
    },

    // Configuración de traducción mejorada
    translationConfig: {
      autoTranslate: {
        type: Boolean,
        default: true,
      },
      targetLanguages: {
        type: [String],
        enum: SUPPORTED_LANGUAGES,
        validate: {
          validator: function (languages) {
            return new Set(languages).size === languages.length;
          },
          message: "Idiomas duplicados en targetLanguages",
        },
      },
      translationPriority: {
        type: String,
        enum: ["quality", "speed", "cost"],
        default: "quality",
      },
      excludeFromTranslation: {
        type: Boolean,
        default: false,
      },
      maxTranslationCost: {
        type: Number,
        default: 10,
        min: 0,
      },
      preferredServices: {
        type: [String],
        enum: ["openai", "google", "deepl", "azure", "aws"],
        default: ["openai"],
      },
    },

    // Rate limiting
    rateLimit: {
      type: RateLimitSchema,
      default: () => ({}),
    },

    // Cola de traducción
    translationQueue: [TranslationQueueSchema],

    // Metadatos generales mejorados
    lastUpdated: {
      type: Date,
      default: Date.now,
      index: true,
    },
    totalTranslations: {
      type: Number,
      default: 0,
      min: 0,
      validate: {
        validator: function (v) {
          return v <= LIMITS.MAX_TRANSLATIONS;
        },
        message: `Máximo ${LIMITS.MAX_TRANSLATIONS} traducciones permitidas`,
      },
    },
    totalTranslationCost: {
      type: Number,
      default: 0,
      min: 0,
    },

    // Traducciones pendientes optimizadas
    pendingTranslations: {
      type: [
        {
          language: {
            type: String,
            enum: SUPPORTED_LANGUAGES,
          },
          requestedAt: {
            type: Date,
            default: Date.now,
          },
          priority: {
            type: String,
            enum: ["low", "medium", "high", "urgent"],
            default: "medium",
          },
          estimatedCost: {
            type: Number,
            default: 0,
            min: 0,
          },
          requestedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
          },
          reason: String,
        },
      ],
      validate: {
        validator: function (v) {
          return v.length <= LIMITS.MAX_PENDING_TRANSLATIONS;
        },
        message: `Límite de ${LIMITS.MAX_PENDING_TRANSLATIONS} traducciones pendientes excedido`,
      },
    },

    // Cache de traducciones frecuentes
    frequentTranslations: {
      type: Map,
      of: {
        text: String,
        language: String,
        cachedAt: Date,
        hitCount: { type: Number, default: 1 },
        expiresAt: Date,
      },
      default: new Map(),
    },

    // Idiomas más solicitados
    mostRequestedLanguages: [
      {
        language: {
          type: String,
          enum: SUPPORTED_LANGUAGES,
        },
        requestCount: {
          type: Number,
          default: 1,
          min: 0,
        },
        lastRequested: {
          type: Date,
          default: Date.now,
        },
        avgResponseTime: {
          type: Number,
          default: 0,
        },
      },
    ],

    // Métricas de performance
    performanceMetrics: {
      totalRequests: { type: Number, default: 0 },
      avgTranslationTime: { type: Number, default: 0 },
      successRate: { type: Number, default: 1.0, min: 0, max: 1 },
      lastOptimized: Date,
      cacheHitRate: { type: Number, default: 0, min: 0, max: 1 },
    },
  },
  { _id: false }
);

/**
 * ÍNDICES COMPUESTOS OPTIMIZADOS
 */
// Índice compuesto para búsquedas frecuentes
MultiLanguageContentSchema.index({
  "original.language": 1,
  translationLanguages: 1,
  lastUpdated: -1,
});

// Índice para traducciones que necesitan revisión
MultiLanguageContentSchema.index({
  translationLanguages: 1,
  "translations.$**.needsReview": 1,
});

// Índice para performance metrics
MultiLanguageContentSchema.index({
  "performanceMetrics.lastOptimized": 1,
  "performanceMetrics.cacheHitRate": -1,
});

/**
 * MIDDLEWARE MEJORADO
 */
MultiLanguageContentSchema.pre("save", function () {
  const now = new Date();

  // Actualizar contadores para contenido original
  if (this.original && this.original.text) {
    this.original.wordCount = this.countWords(this.original.text);
    this.original.characterCount = this.original.text.length;
    this.original.lastModified = now;
    this.original.contentHash = this.generateTextHash(this.original.text);

    // Agregar a historial si cambió el texto
    if (this.isModified("original.text") && !this.isNew) {
      this.addToVersionHistory(this.original.text, "updated");
    }
  }

  // Actualizar contadores y metadatos para traducciones
  if (this.translations) {
    this.totalTranslations = this.translations.size;
    this.translationLanguages = Array.from(this.translations.keys());

    let totalCost = 0;
    let totalTime = 0;
    let completedTranslations = 0;

    for (const [lang, translation] of this.translations) {
      if (translation.text) {
        translation.wordCount = this.countWords(translation.text);
        translation.characterCount = translation.text.length;
        translation.sourceTextHash = this.original.contentHash;

        totalCost += translation.translationCost || 0;
        totalTime += translation.translationTime || 0;
        completedTranslations++;

        // Limpiar cache expirado de interpolaciones
        this.cleanExpiredCache(translation.cachedInterpolations);
      }
    }

    this.totalTranslationCost = totalCost;

    // Actualizar métricas de performance
    if (completedTranslations > 0) {
      this.performanceMetrics.avgTranslationTime =
        totalTime / completedTranslations;
      this.performanceMetrics.totalRequests += 1;
    }
  }

  // Limpiar cache general expirado
  this.cleanExpiredCache(this.frequentTranslations);

  this.lastUpdated = now;
});

/**
 * MÉTODOS DE INSTANCIA MEJORADOS
 */

/**
 * Obtener texto con fallback inteligente y cache
 */
MultiLanguageContentSchema.methods.getText = function (
  language = DEFAULT_LANGUAGE,
  fallbackLanguages = ["en", "es"],
  options = {}
) {
  const cacheKey = `${language}_${fallbackLanguages.join("_")}`;

  // Verificar cache si está habilitado
  if (options.useCache !== false && this.frequentTranslations.has(cacheKey)) {
    const cached = this.frequentTranslations.get(cacheKey);
    if (cached.expiresAt > new Date()) {
      cached.hitCount++;
      this.markModified("frequentTranslations");
      return {
        text: cached.text,
        language: cached.language,
        isTranslation: cached.language !== this.original.language,
        fromCache: true,
        confidence: 1.0,
      };
    }
  }

  // Lógica original de obtención de texto
  const result = this._getTextInternal(language, fallbackLanguages);

  // Guardar en cache para próximas consultas
  if (options.useCache !== false) {
    this.cacheResult(cacheKey, result);
  }

  // Actualizar estadísticas de idiomas solicitados
  this.updateLanguageStats(language);

  return result;
};

/**
 * Lógica interna de obtención de texto
 */
MultiLanguageContentSchema.methods._getTextInternal = function (
  language,
  fallbackLanguages
) {
  // Si se solicita el idioma original
  if (language === this.original.language) {
    return {
      text: this.original.text,
      language: this.original.language,
      isTranslation: false,
      confidence: 1.0,
    };
  }

  // Si existe traducción verificada
  if (this.translations && this.translations.has(language)) {
    const translation = this.translations.get(language);
    if (translation.text && !translation.needsReview) {
      return {
        text: translation.text,
        language: language,
        isTranslation: true,
        confidence: translation.confidence,
        qualityScore: translation.qualityScore,
        isVerified: translation.isVerified,
        variants: translation.variants
          ? Array.from(translation.variants.keys())
          : [],
      };
    }
  }

  // Intentar idiomas de fallback
  for (const fallbackLang of fallbackLanguages) {
    if (this.original.language === fallbackLang) {
      return {
        text: this.original.text,
        language: this.original.language,
        isTranslation: false,
        confidence: 1.0,
        isFallback: true,
      };
    }

    if (this.translations && this.translations.has(fallbackLang)) {
      const translation = this.translations.get(fallbackLang);
      if (translation.text && !translation.needsReview) {
        return {
          text: translation.text,
          language: fallbackLang,
          isTranslation: true,
          confidence: translation.confidence,
          isFallback: true,
        };
      }
    }
  }

  // Fallback final al texto original
  return {
    text: this.original.text,
    language: this.original.language,
    isTranslation: false,
    confidence: 1.0,
    isFallback: true,
  };
};

/**
 * Interpolación de placeholders con cache
 */
MultiLanguageContentSchema.methods.interpolateText = function (
  text,
  variables = {},
  language
) {
  const cacheKey = `${language}_${JSON.stringify(variables)}`;

  // Verificar cache de interpolaciones
  if (language && this.translations.has(language)) {
    const translation = this.translations.get(language);
    if (
      translation.cachedInterpolations &&
      translation.cachedInterpolations.has(cacheKey)
    ) {
      const cached = translation.cachedInterpolations.get(cacheKey);
      cached.hitCount++;
      this.markModified("translations");
      return cached.result;
    }
  }

  // Realizar interpolación
  const result = text.replace(/{(\w+)}/g, (match, key) => {
    if (variables.hasOwnProperty(key)) {
      return variables[key];
    }

    // Buscar valor por defecto en placeholders
    const placeholder = this.original.placeholders.find((p) => p.key === key);
    return placeholder?.defaultValue || match;
  });

  // Guardar en cache
  if (language && this.translations.has(language)) {
    const translation = this.translations.get(language);
    if (!translation.cachedInterpolations) {
      translation.cachedInterpolations = new Map();
    }

    translation.cachedInterpolations.set(cacheKey, {
      result,
      cachedAt: new Date(),
      hitCount: 1,
    });
    this.markModified("translations");
  }

  return result;
};

/**
 * Verificar rate limiting
 */
MultiLanguageContentSchema.methods.checkRateLimit = function () {
  const now = new Date();

  if (!this.rateLimit) {
    this.rateLimit = {
      lastTranslationRequest: now,
      requestCount: 0,
      hourlyResetAt: new Date(now.getTime() + 60 * 60 * 1000),
    };
  }

  // Reset contador si pasó una hora
  if (now > this.rateLimit.hourlyResetAt) {
    this.rateLimit.requestCount = 0;
    this.rateLimit.hourlyResetAt = new Date(now.getTime() + 60 * 60 * 1000);
    this.rateLimit.isBlocked = false;
    this.rateLimit.blockedUntil = null;
  }

  // Verificar límite
  if (this.rateLimit.requestCount >= LIMITS.RATE_LIMIT_REQUESTS_PER_HOUR) {
    this.rateLimit.isBlocked = true;
    this.rateLimit.blockedUntil = this.rateLimit.hourlyResetAt;
    return {
      allowed: false,
      resetAt: this.rateLimit.hourlyResetAt,
      remainingRequests: 0,
    };
  }

  return {
    allowed: true,
    remainingRequests:
      LIMITS.RATE_LIMIT_REQUESTS_PER_HOUR - this.rateLimit.requestCount,
  };
};

/**
 * Agregar traducción con mejoras
 */
MultiLanguageContentSchema.methods.addTranslation = function (
  language,
  text,
  options = {}
) {
  // Verificar rate limiting
  const rateLimitCheck = this.checkRateLimit();
  if (!rateLimitCheck.allowed) {
    throw new Error(`Rate limit excedido. Reset en: ${rateLimitCheck.resetAt}`);
  }

  // Verificar límites
  if (this.translations.size >= LIMITS.MAX_TRANSLATIONS) {
    throw new Error(
      `Máximo ${LIMITS.MAX_TRANSLATIONS} traducciones permitidas`
    );
  }

  if (!this.translations) {
    this.translations = new Map();
  }

  const startTime = Date.now();
  const translation = {
    text: text,
    translatedAt: new Date(),
    translationMethod: options.method || "ai",
    translationService: options.service || "openai",
    confidence: options.confidence || 0.8,
    qualityScore: options.qualityScore || 7,
    needsReview: options.needsReview || false,
    context: options.context || "general",
    translationCost: options.cost || 0,
    translationTime: options.translationTime || Date.now() - startTime,
    sourceTextHash: this.generateTextHash(this.original.text),
    variants: new Map(),
    cachedInterpolations: new Map(),
  };

  this.translations.set(language, translation);
  this.markModified("translations");

  // Actualizar rate limit
  this.rateLimit.requestCount++;
  this.rateLimit.lastTranslationRequest = new Date();

  // Limpiar cache relacionado
  this.clearCacheForLanguage(language);

  return this;
};

/**
 * Gestión de variantes A/B
 */
MultiLanguageContentSchema.methods.addTranslationVariant = function (
  language,
  variant,
  text,
  trafficAllocation = 50
) {
  if (!this.translations.has(language)) {
    throw new Error(`No existe traducción para el idioma: ${language}`);
  }

  const translation = this.translations.get(language);

  if (translation.variants.size >= LIMITS.MAX_TRANSLATION_VARIANTS) {
    throw new Error(
      `Máximo ${LIMITS.MAX_TRANSLATION_VARIANTS} variantes permitidas`
    );
  }

  translation.variants.set(variant, {
    variant,
    text,
    performance: {
      impressions: 0,
      clicks: 0,
      conversions: 0,
      ctr: 0,
      conversionRate: 0,
    },
    isActive: true,
    trafficAllocation,
  });

  this.translations.set(language, translation);
  this.markModified("translations");

  return this;
};

/**
 * Obtener texto con A/B testing
 */
MultiLanguageContentSchema.methods.getTextWithABTest = function (
  language,
  userId = null,
  options = {}
) {
  const baseResult = this.getText(language, options.fallbackLanguages, options);

  if (!this.translations.has(language)) {
    return baseResult;
  }

  const translation = this.translations.get(language);
  const activeVariants = Array.from(translation.variants.entries()).filter(
    ([_, variant]) => variant.isActive
  );

  if (activeVariants.length === 0) {
    return baseResult;
  }

  // Selección de variante basada en userId o random
  let selectedVariant;
  if (userId) {
    const hash = crypto
      .createHash("md5")
      .update(`${userId}_${language}`)
      .digest("hex");
    const hashNum = parseInt(hash.substring(0, 8), 16);
    const variantIndex = hashNum % activeVariants.length;
    selectedVariant = activeVariants[variantIndex][1];
  } else {
    const randomIndex = Math.floor(Math.random() * activeVariants.length);
    selectedVariant = activeVariants[randomIndex][1];
  }

  // Incrementar impressions
  selectedVariant.performance.impressions++;
  this.markModified("translations");

  return {
    ...baseResult,
    text: selectedVariant.text,
    variant: selectedVariant.variant,
    isABTest: true,
  };
};

/**
 * Obtener lote de traducciones (paginación)
 */
MultiLanguageContentSchema.methods.getTranslationsBatch = function (
  languages = [],
  limit = 10,
  offset = 0
) {
  const result = new Map();
  const targetLangs = languages.length
    ? languages
    : Array.from(this.translations.keys());

  const paginatedLangs = targetLangs.slice(offset, offset + limit);

  for (const lang of paginatedLangs) {
    if (this.translations.has(lang)) {
      result.set(lang, this.translations.get(lang));
    }
  }

  return {
    translations: result,
    total: targetLangs.length,
    hasMore: offset + limit < targetLangs.length,
    nextOffset: offset + limit,
  };
};

/**
 * Métodos de utilidad internos
 */
MultiLanguageContentSchema.methods.countWords = function (text) {
  return text.split(/\s+/).filter((word) => word.length > 0).length;
};

MultiLanguageContentSchema.methods.generateTextHash = function (text) {
  return crypto
    .createHash("sha256")
    .update(text.trim().toLowerCase())
    .digest("hex")
    .substring(0, 16);
};

MultiLanguageContentSchema.methods.cleanExpiredCache = function (cacheMap) {
  if (!cacheMap || typeof cacheMap.forEach !== "function") return;

  const now = new Date();
  const expiredKeys = [];

  cacheMap.forEach((value, key) => {
    if (value.expiresAt && value.expiresAt < now) {
      expiredKeys.push(key);
    }
  });

  expiredKeys.forEach((key) => cacheMap.delete(key));

  if (expiredKeys.length > 0) {
    this.markModified("frequentTranslations");
  }
};

MultiLanguageContentSchema.methods.cacheResult = function (key, result) {
  const expiresAt = new Date(
    Date.now() + LIMITS.CACHE_EXPIRY_HOURS * 60 * 60 * 1000
  );

  this.frequentTranslations.set(key, {
    text: result.text,
    language: result.language,
    cachedAt: new Date(),
    hitCount: 1,
    expiresAt,
  });

  this.markModified("frequentTranslations");
};

MultiLanguageContentSchema.methods.updateLanguageStats = function (language) {
  let langStat = this.mostRequestedLanguages.find(
    (l) => l.language === language
  );

  if (!langStat) {
    langStat = {
      language,
      requestCount: 0,
      lastRequested: new Date(),
      avgResponseTime: 0,
    };
    this.mostRequestedLanguages.push(langStat);
  }

  langStat.requestCount++;
  langStat.lastRequested = new Date();

  this.markModified("mostRequestedLanguages");
};

MultiLanguageContentSchema.methods.clearCacheForLanguage = function (language) {
  const keysToDelete = [];

  this.frequentTranslations.forEach((value, key) => {
    if (key.includes(language)) {
      keysToDelete.push(key);
    }
  });

  keysToDelete.forEach((key) => this.frequentTranslations.delete(key));

  if (keysToDelete.length > 0) {
    this.markModified("frequentTranslations");
  }
};

MultiLanguageContentSchema.methods.addToVersionHistory = function (
  text,
  changeType = "updated"
) {
  if (!this.original.versionHistory) {
    this.original.versionHistory = [];
  }

  this.original.versionHistory.push({
    text,
    changedAt: new Date(),
    changeType,
  });

  // Mantener solo las últimas versiones
  if (this.original.versionHistory.length > LIMITS.MAX_VERSION_HISTORY) {
    this.original.versionHistory.shift();
  }

  this.markModified("original.versionHistory");
};

/**
 * MÉTODOS ESTÁTICOS MEJORADOS
 */

/**
 * Crear contenido con configuración avanzada
 */
MultiLanguageContentSchema.statics.createAdvancedContent = function (
  text,
  language = DEFAULT_LANGUAGE,
  options = {}
) {
  const content = {
    original: {
      language: language,
      text: text,
      createdAt: new Date(),
      lastModified: new Date(),
      placeholders: options.placeholders || [],
      versionHistory: [],
    },
    translations: new Map(),
    translationLanguages: [],
    translationConfig: {
      autoTranslate: options.autoTranslate !== false,
      targetLanguages: options.targetLanguages || [],
      translationPriority: options.priority || "quality",
      excludeFromTranslation: options.excludeFromTranslation || false,
      maxTranslationCost: options.maxCost || 10,
      preferredServices: options.preferredServices || ["openai"],
    },
    rateLimit: {
      lastTranslationRequest: new Date(),
      requestCount: 0,
      hourlyResetAt: new Date(Date.now() + 60 * 60 * 1000),
      isBlocked: false,
    },
    translationQueue: [],
    pendingTranslations: [],
    frequentTranslations: new Map(),
    mostRequestedLanguages: [],
    performanceMetrics: {
      totalRequests: 0,
      avgTranslationTime: 0,
      successRate: 1.0,
      cacheHitRate: 0,
    },
    lastUpdated: new Date(),
    totalTranslations: 0,
    totalTranslationCost: 0,
  };

  return content;
};

/**
 * UTILIDADES AVANZADAS
 */
export const AdvancedMultiLanguageUtils = {
  /**
   * Optimización de performance
   */
  async optimizeTranslationPerformance(content) {
    const stats = this.getDetailedTranslationStats(content);
    const optimizations = [];

    // Identificar traducciones lentas
    if (stats.avgTranslationTime > 5000) {
      // > 5 segundos
      optimizations.push({
        type: "performance",
        issue: "Traducciones lentas detectadas",
        suggestion: "Considerar cambiar de servicio o usar cache",
      });
    }

    // Identificar idiomas de baja calidad
    const lowQualityLanguages = Array.from(content.translations.entries())
      .filter(([_, translation]) => translation.qualityScore < 6)
      .map(([lang, _]) => lang);

    if (lowQualityLanguages.length > 0) {
      optimizations.push({
        type: "quality",
        issue: `Idiomas con baja calidad: ${lowQualityLanguages.join(", ")}`,
        suggestion: "Revisar y mejorar traducciones de baja calidad",
      });
    }

    // Sugerir cache para idiomas frecuentes
    const frequentLanguages = content.mostRequestedLanguages
      .filter((l) => l.requestCount > 100)
      .map((l) => l.language);

    if (frequentLanguages.length > 0 && stats.cacheHitRate < 0.3) {
      optimizations.push({
        type: "cache",
        issue: "Baja tasa de cache hit",
        suggestion: `Precache idiomas frecuentes: ${frequentLanguages.join(", ")}`,
      });
    }

    return optimizations;
  },

  /**
   * Estadísticas detalladas
   */
  getDetailedTranslationStats(content) {
    if (!content || !content.original) {
      return {
        totalLanguages: 0,
        completedTranslations: 0,
        pendingTranslations: 0,
        needsReview: 0,
        totalCost: 0,
        avgQuality: 0,
        avgTranslationTime: 0,
        cacheHitRate: 0,
        topLanguages: [],
        costByService: {},
        qualityByService: {},
      };
    }

    let completedTranslations = 1;
    let needsReview = 0;
    let totalCost = content.totalTranslationCost || 0;
    let totalQuality = 10;
    let qualityCount = 1;
    let totalTime = 0;
    let totalCacheHits = 0;
    let totalCacheRequests = 0;

    const costByService = {};
    const qualityByService = {};

    if (content.translations) {
      for (const [lang, translation] of content.translations) {
        if (translation.text) {
          completedTranslations++;

          if (translation.needsReview) needsReview++;
          if (translation.qualityScore) {
            totalQuality += translation.qualityScore;
            qualityCount++;
          }
          if (translation.translationTime) {
            totalTime += translation.translationTime;
          }

          // Stats por servicio
          const service = translation.translationService || "unknown";
          if (!costByService[service]) costByService[service] = 0;
          if (!qualityByService[service]) qualityByService[service] = [];

          costByService[service] += translation.translationCost || 0;
          qualityByService[service].push(translation.qualityScore || 0);

          // Cache hits
          if (translation.cachedInterpolations) {
            for (const cached of translation.cachedInterpolations.values()) {
              totalCacheRequests += cached.hitCount;
              totalCacheHits += cached.hitCount - 1; // -1 porque el primer hit no es cache
            }
          }
        }
      }
    }

    // Cache general
    if (content.frequentTranslations) {
      for (const cached of content.frequentTranslations.values()) {
        totalCacheRequests += cached.hitCount;
        totalCacheHits += cached.hitCount - 1;
      }
    }

    // Top idiomas
    const topLanguages = (content.mostRequestedLanguages || [])
      .sort((a, b) => b.requestCount - a.requestCount)
      .slice(0, 5);

    return {
      totalLanguages: completedTranslations,
      completedTranslations,
      pendingTranslations: content.pendingTranslations?.length || 0,
      needsReview,
      totalCost,
      avgQuality: totalQuality / qualityCount,
      avgTranslationTime:
        completedTranslations > 1 ? totalTime / (completedTranslations - 1) : 0,
      cacheHitRate:
        totalCacheRequests > 0 ? totalCacheHits / totalCacheRequests : 0,
      coverage: completedTranslations / SUPPORTED_LANGUAGES.length,
      topLanguages,
      costByService,
      qualityByService: Object.keys(qualityByService).reduce((acc, service) => {
        const scores = qualityByService[service];
        acc[service] =
          scores.reduce((sum, score) => sum + score, 0) / scores.length;
        return acc;
      }, {}),
    };
  },

  /**
   * Recomendaciones inteligentes
   */
  getTranslationRecommendations(content, targetMarkets = []) {
    const recommendations = [];
    const stats = this.getDetailedTranslationStats(content);

    // Recomendar idiomas basado en mercados objetivo
    if (targetMarkets.length > 0) {
      const marketLanguageMap = {
        LATAM: ["es", "pt"],
        Europe: ["en", "fr", "de", "it"],
        Asia: ["zh", "ja", "ko"],
        "Middle East": ["ar"],
        India: ["hi", "en"],
      };

      for (const market of targetMarkets) {
        const suggestedLangs = marketLanguageMap[market] || [];
        const missingLangs = suggestedLangs.filter(
          (lang) =>
            !content.translationLanguages.includes(lang) &&
            lang !== content.original.language
        );

        if (missingLangs.length > 0) {
          recommendations.push({
            type: "market_expansion",
            priority: "high",
            message: `Para el mercado ${market}, considera traducciones a: ${missingLangs.join(", ")}`,
            languages: missingLangs,
            estimatedCost: missingLangs.length * 5, // Estimación base
          });
        }
      }
    }

    // Recomendar mejoras de calidad
    if (stats.avgQuality < 7) {
      recommendations.push({
        type: "quality_improvement",
        priority: "medium",
        message:
          "La calidad promedio de traducciones está por debajo del estándar",
        suggestion: "Revisar traducciones con puntuación menor a 6",
      });
    }

    // Recomendar optimización de costos
    const expensiveServices = Object.entries(stats.costByService)
      .filter(([_, cost]) => cost > stats.totalCost * 0.3)
      .map(([service, _]) => service);

    if (expensiveServices.length > 0) {
      recommendations.push({
        type: "cost_optimization",
        priority: "low",
        message: `Servicios costosos detectados: ${expensiveServices.join(", ")}`,
        suggestion:
          "Evaluar alternativas más económicas para traducciones rutinarias",
      });
    }

    return recommendations;
  },
};

export const MultiLanguageValidators = {
  hasOriginalText: {
    validator: function (v) {
      return v && v.original && v.original.text;
    },
    message: "El texto original no puede estar vacío",
  },
  minLength: function (minLength) {
    return {
      validator: function (v) {
        return v && v.original && v.original.text.length >= minLength;
      },
      message: `El texto original debe tener al menos ${minLength} caracteres`,
    };
  },
  maxLength: function (maxLength) {
    return {
      validator: function (v) {
        return v && v.original && v.original.text.length <= maxLength;
      },
      message: `El texto original no puede exceder ${maxLength} caracteres`,
    };
  },
};

export const createMultiLanguageField = (required = false, options = {}) => ({
  type: MultiLanguageContentSchema,
  required,
  validate: options.validator,
  index: options.textIndex ? "text" : undefined,
});

export default {
  MultiLanguageContentSchema,
  createMultiLanguageField,
  AdvancedMultiLanguageUtils,
  SUPPORTED_LANGUAGES,
  DEFAULT_LANGUAGE,
  LIMITS,
};
