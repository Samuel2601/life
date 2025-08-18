// =============================================================================
// src/modules/core/models/multi_language_pattern.scheme.js
// ESQUEMA MULTIIDIOMA EMPRESARIAL - VERSIÓN OPTIMIZADA
// =============================================================================
import mongoose from "mongoose";
import crypto from "crypto";

/**
 * Lista de idiomas soportados por el sistema
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

/**
 * Schema para contenido original
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
      maxlength: 5000,
      trim: true,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
    lastModified: {
      type: Date,
      default: Date.now,
    },
    wordCount: {
      type: Number,
      default: 0,
    },
    characterCount: {
      type: Number,
      default: 0,
    },
  },
  { _id: false }
);

/**
 * Schema para traducciones individuales
 */
const TranslationSchema = new mongoose.Schema(
  {
    text: {
      type: String,
      required: true,
      maxlength: 5000,
      trim: true,
    },
    translatedAt: {
      type: Date,
      default: Date.now,
    },
    translationMethod: {
      type: String,
      enum: ["ai", "manual", "auto", "professional"],
      default: "ai",
    },
    translationService: {
      type: String,
      enum: ["openai", "google", "deepl", "manual", "professional"],
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
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    verifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    verifiedAt: {
      type: Date,
    },
    wordCount: {
      type: Number,
      default: 0,
    },
    characterCount: {
      type: Number,
      default: 0,
    },
    // Hash para detectar cambios en el texto original
    sourceTextHash: {
      type: String,
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
      ],
      default: "general",
    },
    // Costo de la traducción (para analytics)
    translationCost: {
      type: Number,
      default: 0,
    },
  },
  { _id: false }
);

/**
 * Schema principal para contenido multiidioma
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

    // Configuración de traducción
    translationConfig: {
      autoTranslate: {
        type: Boolean,
        default: true,
      },
      targetLanguages: [
        {
          type: String,
          enum: SUPPORTED_LANGUAGES,
        },
      ],
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
        default: 10, // USD máximo por traducción
      },
    },

    // Metadatos generales
    lastUpdated: {
      type: Date,
      default: Date.now,
    },
    totalTranslations: {
      type: Number,
      default: 0,
    },
    totalTranslationCost: {
      type: Number,
      default: 0,
    },
    pendingTranslations: [
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
          enum: ["low", "medium", "high"],
          default: "medium",
        },
        estimatedCost: {
          type: Number,
          default: 0,
        },
      },
    ],
  },
  { _id: false }
);

/**
 * Middleware para actualizar metadatos automáticamente
 */
MultiLanguageContentSchema.pre("save", function () {
  // Actualizar contadores para contenido original
  if (this.original && this.original.text) {
    this.original.wordCount = this.original.text
      .split(/\s+/)
      .filter((word) => word.length > 0).length;
    this.original.characterCount = this.original.text.length;
    this.original.lastModified = new Date();
  }

  // Actualizar contadores para traducciones
  if (this.translations) {
    this.totalTranslations = this.translations.size;
    let totalCost = 0;

    for (const [lang, translation] of this.translations) {
      if (translation.text) {
        translation.wordCount = translation.text
          .split(/\s+/)
          .filter((word) => word.length > 0).length;
        translation.characterCount = translation.text.length;

        // Actualizar hash del texto original
        translation.sourceTextHash = this.generateTextHash(this.original.text);

        // Sumar costos
        totalCost += translation.translationCost || 0;
      }
    }

    this.totalTranslationCost = totalCost;
  }

  this.lastUpdated = new Date();
});

/**
 * MÉTODOS DE INSTANCIA
 */

/**
 * Obtener texto en idioma específico con fallback inteligente
 */
MultiLanguageContentSchema.methods.getText = function (
  language = DEFAULT_LANGUAGE,
  fallbackLanguages = ["en", "es"]
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
 * Verificar si tiene traducción para un idioma
 */
MultiLanguageContentSchema.methods.hasTranslation = function (language) {
  return (
    this.original.language === language ||
    (this.translations && this.translations.has(language))
  );
};

/**
 * Agregar nueva traducción
 */
MultiLanguageContentSchema.methods.addTranslation = function (
  language,
  text,
  options = {}
) {
  if (!this.translations) {
    this.translations = new Map();
  }

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
    sourceTextHash: this.generateTextHash(this.original.text),
  };

  this.translations.set(language, translation);
  this.markModified("translations");

  return this;
};

/**
 * Verificar si necesita actualización de traducción
 */
MultiLanguageContentSchema.methods.needsTranslationUpdate = function (
  language
) {
  if (!this.hasTranslation(language) || this.original.language === language) {
    return false;
  }

  const translation = this.translations.get(language);
  const currentHash = this.generateTextHash(this.original.text);

  return translation.sourceTextHash !== currentHash;
};

/**
 * Generar hash para detectar cambios
 */
MultiLanguageContentSchema.methods.generateTextHash = function (text) {
  return crypto
    .createHash("sha256")
    .update(text.trim().toLowerCase())
    .digest("hex")
    .substring(0, 16);
};

/**
 * Obtener idiomas disponibles
 */
MultiLanguageContentSchema.methods.getAvailableLanguages = function () {
  const languages = [this.original.language];

  if (this.translations) {
    for (const lang of this.translations.keys()) {
      if (!languages.includes(lang)) {
        languages.push(lang);
      }
    }
  }

  return languages;
};

/**
 * Marcar traducción para revisión
 */
MultiLanguageContentSchema.methods.markTranslationForReview = function (
  language,
  reason = ""
) {
  if (this.translations && this.translations.has(language)) {
    const translation = this.translations.get(language);
    translation.needsReview = true;
    translation.reviewReason = reason;
    this.translations.set(language, translation);
    this.markModified("translations");
  }
  return this;
};

/**
 * Aprobar traducción
 */
MultiLanguageContentSchema.methods.approveTranslation = function (
  language,
  approvedBy
) {
  if (this.translations && this.translations.has(language)) {
    const translation = this.translations.get(language);
    translation.isVerified = true;
    translation.needsReview = false;
    translation.verifiedBy = approvedBy;
    translation.verifiedAt = new Date();
    this.translations.set(language, translation);
    this.markModified("translations");
  }
  return this;
};

/**
 * UTILIDADES ESTÁTICAS
 */

/**
 * Crear contenido multiidioma inicial
 */
MultiLanguageContentSchema.statics.createContent = function (
  text,
  language = DEFAULT_LANGUAGE,
  options = {}
) {
  return {
    original: {
      language: language,
      text: text,
      createdAt: new Date(),
      lastModified: new Date(),
    },
    translations: new Map(),
    translationConfig: {
      autoTranslate: options.autoTranslate !== false,
      targetLanguages: options.targetLanguages || [],
      translationPriority: options.priority || "quality",
      excludeFromTranslation: options.excludeFromTranslation || false,
      maxTranslationCost: options.maxCost || 10,
    },
    lastUpdated: new Date(),
    totalTranslations: 0,
    totalTranslationCost: 0,
    pendingTranslations: [],
  };
};

/**
 * HELPERS DE EXPORTACIÓN
 */
export const createMultiLanguageField = (required = false, options = {}) => {
  return {
    type: MultiLanguageContentSchema,
    required,
    validate: options.validator,
    index: options.textIndex ? "text" : undefined,
  };
};

/**
 * UTILIDADES AVANZADAS
 */
export const MultiLanguageUtils = {
  /**
   * Obtener el mejor texto disponible
   */
  getBestText(
    content,
    requestedLanguage = DEFAULT_LANGUAGE,
    fallbackLanguages = ["en", "es"]
  ) {
    if (!content || !content.original) {
      return "";
    }

    // Usar el método de instancia si está disponible
    if (typeof content.getText === "function") {
      const result = content.getText(requestedLanguage, fallbackLanguages);
      return result.text;
    }

    // Fallback para objetos planos
    if (content.original.language === requestedLanguage) {
      return content.original.text;
    }

    if (content.translations && content.translations.has(requestedLanguage)) {
      const translation = content.translations.get(requestedLanguage);
      if (translation.text && !translation.needsReview) {
        return translation.text;
      }
    }

    return content.original.text;
  },

  /**
   * Calcular estadísticas de traducción
   */
  getTranslationStats(content) {
    if (!content || !content.original) {
      return {
        totalLanguages: 0,
        completedTranslations: 0,
        pendingTranslations: 0,
        needsReview: 0,
        totalCost: 0,
        avgQuality: 0,
      };
    }

    let completedTranslations = 1; // Contar original
    let needsReview = 0;
    let totalCost = content.totalTranslationCost || 0;
    let totalQuality = 10; // Original = calidad perfecta
    let qualityCount = 1;

    if (content.translations) {
      for (const [lang, translation] of content.translations) {
        if (translation.text) {
          completedTranslations++;
          if (translation.needsReview) {
            needsReview++;
          }
          if (translation.qualityScore) {
            totalQuality += translation.qualityScore;
            qualityCount++;
          }
        }
      }
    }

    return {
      totalLanguages: completedTranslations,
      completedTranslations,
      pendingTranslations: content.pendingTranslations
        ? content.pendingTranslations.length
        : 0,
      needsReview,
      totalCost,
      avgQuality: totalQuality / qualityCount,
      coverage: completedTranslations / SUPPORTED_LANGUAGES.length,
    };
  },

  /**
   * Verificar si necesita traducción
   */
  needsTranslation(content, targetLanguage) {
    if (!content || !content.original) {
      return false;
    }

    if (content.original.language === targetLanguage) {
      return false;
    }

    if (
      content.translationConfig &&
      content.translationConfig.excludeFromTranslation
    ) {
      return false;
    }

    if (content.translations && content.translations.has(targetLanguage)) {
      const translation = content.translations.get(targetLanguage);
      const currentHash = crypto
        .createHash("sha256")
        .update(content.original.text.trim().toLowerCase())
        .digest("hex")
        .substring(0, 16);

      return (
        translation.sourceTextHash !== currentHash || translation.needsReview
      );
    }

    return true;
  },

  /**
   * Validar estructura de contenido
   */
  validateContent(content) {
    const errors = [];

    if (!content) {
      errors.push("Contenido multiidioma es requerido");
      return errors;
    }

    if (!content.original) {
      errors.push("Contenido original es requerido");
      return errors;
    }

    if (!content.original.text || content.original.text.trim().length === 0) {
      errors.push("Texto original no puede estar vacío");
    }

    if (!content.original.language) {
      errors.push("Idioma original es requerido");
    } else if (!SUPPORTED_LANGUAGES.includes(content.original.language)) {
      errors.push(`Idioma '${content.original.language}' no es soportado`);
    }

    if (content.translations) {
      for (const [lang, translation] of content.translations) {
        if (!SUPPORTED_LANGUAGES.includes(lang)) {
          errors.push(`Idioma de traducción '${lang}' no es soportado`);
        }

        if (!translation.text || translation.text.trim().length === 0) {
          errors.push(`Traducción para '${lang}' no puede estar vacía`);
        }
      }
    }

    return errors;
  },
};

export default {
  MultiLanguageContentSchema,
  createMultiLanguageField,
  MultiLanguageUtils,
  SUPPORTED_LANGUAGES,
  DEFAULT_LANGUAGE,
};
