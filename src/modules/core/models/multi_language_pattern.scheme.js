// =============================================================================
// src/modules/core/models/multi_language_pattern.scheme.js
// =============================================================================
import mongoose from "mongoose";

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
  "th", // Tailandés
  "vi", // Vietnamita
  "pl", // Polaco
  "nl", // Holandés
  "sv", // Sueco
  "no", // Noruego
  "da", // Danés
  "fi", // Finlandés
];

/**
 * Idioma por defecto del sistema
 */
export const DEFAULT_LANGUAGE = "es";

/**
 * Esquema para contenido original (texto en idioma nativo del usuario)
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
    // Metadatos del contenido original
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
 * Esquema para una traducción individual
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
    // Metadatos de calidad
    qualityScore: {
      type: Number,
      min: 0,
      max: 10,
      default: 7,
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
  },
  { _id: false }
);

/**
 * Esquema principal para contenido multiidioma
 */
export const MultiLanguageContentSchema = new mongoose.Schema(
  {
    // Contenido original en el idioma nativo del usuario
    original: {
      type: OriginalContentSchema,
      required: true,
    },

    // Traducciones a otros idiomas (Map: idioma -> traducción)
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
      },
    ],
  },
  { _id: false }
);

/**
 * Middleware para actualizar contadores y metadatos
 */
MultiLanguageContentSchema.pre("save", function () {
  // Actualizar contadores de palabras y caracteres para el texto original
  if (this.original && this.original.text) {
    this.original.wordCount = this.original.text
      .split(/\s+/)
      .filter((word) => word.length > 0).length;
    this.original.characterCount = this.original.text.length;
  }

  // Actualizar contadores para traducciones
  if (this.translations) {
    this.totalTranslations = this.translations.size;

    for (const [lang, translation] of this.translations) {
      if (translation.text) {
        translation.wordCount = translation.text
          .split(/\s+/)
          .filter((word) => word.length > 0).length;
        translation.characterCount = translation.text.length;
      }
    }
  }

  this.lastUpdated = new Date();
});

/**
 * Métodos de instancia para el esquema multiidioma
 */
MultiLanguageContentSchema.methods.getText = function (
  language = DEFAULT_LANGUAGE
) {
  // Si se solicita el idioma original
  if (language === this.original.language) {
    return this.original.text;
  }

  // Si existe traducción para el idioma solicitado
  if (this.translations && this.translations.has(language)) {
    return this.translations.get(language).text;
  }

  // Fallback al idioma original
  return this.original.text;
};

MultiLanguageContentSchema.methods.hasTranslation = function (language) {
  return this.translations && this.translations.has(language);
};

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
    needsReview: options.needsReview || false,
    context: options.context || "general",
    qualityScore: options.qualityScore || 7,
  };

  this.translations.set(language, translation);
  this.totalTranslations = this.translations.size;
  this.lastUpdated = new Date();

  return this;
};

MultiLanguageContentSchema.methods.removeTranslation = function (language) {
  if (this.translations && this.translations.has(language)) {
    this.translations.delete(language);
    this.totalTranslations = this.translations.size;
    this.lastUpdated = new Date();
  }
  return this;
};

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

MultiLanguageContentSchema.methods.needsTranslationUpdate = function (
  language
) {
  if (!this.hasTranslation(language)) {
    return true;
  }

  const translation = this.translations.get(language);
  const originalHash = this.generateTextHash(this.original.text);

  return translation.sourceTextHash !== originalHash;
};

MultiLanguageContentSchema.methods.generateTextHash = function (text) {
  // Función simple de hash para detectar cambios en el texto
  let hash = 0;
  if (text.length === 0) return hash.toString();

  for (let i = 0; i < text.length; i++) {
    const char = text.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash; // Convertir a 32bit integer
  }

  return hash.toString();
};

MultiLanguageContentSchema.methods.markTranslationForReview = function (
  language,
  reason = ""
) {
  if (this.translations && this.translations.has(language)) {
    const translation = this.translations.get(language);
    translation.needsReview = true;
    translation.reviewReason = reason;
    this.translations.set(language, translation);
  }
  return this;
};

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
  }
  return this;
};

/**
 * Helper para crear campo multiidioma en otros esquemas
 * @param {boolean} required - Si el campo es requerido
 * @param {object} options - Opciones adicionales
 */
export const createMultiLanguageField = (required = false, options = {}) => {
  const field = {
    type: MultiLanguageContentSchema,
    required,
    index: options.textIndex ? "text" : undefined,
  };

  if (options.default) {
    field.default = options.default;
  }

  return field;
};

/**
 * Helper para crear contenido multiidioma inicial
 * @param {string} text - Texto original
 * @param {string} language - Idioma del texto original
 * @param {object} options - Opciones adicionales
 */
export const createMultiLanguageContent = (
  text,
  language = DEFAULT_LANGUAGE,
  options = {}
) => {
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
    },
    lastUpdated: new Date(),
    totalTranslations: 0,
    pendingTranslations: [],
  };
};

/**
 * Funciones de utilidad para trabajar con contenido multiidioma
 */
export const MultiLanguageUtils = {
  /**
   * Obtener el mejor texto disponible para un idioma
   */
  getBestText(
    content,
    requestedLanguage = DEFAULT_LANGUAGE,
    fallbackLanguages = ["en", "es"]
  ) {
    if (!content || !content.original) {
      return "";
    }

    // 1. Intentar idioma solicitado - original
    if (content.original.language === requestedLanguage) {
      return content.original.text;
    }

    // 2. Intentar idioma solicitado - traducción
    if (content.translations && content.translations.has(requestedLanguage)) {
      const translation = content.translations.get(requestedLanguage);
      if (translation.text && !translation.needsReview) {
        return translation.text;
      }
    }

    // 3. Intentar idiomas de fallback
    for (const fallbackLang of fallbackLanguages) {
      if (content.original.language === fallbackLang) {
        return content.original.text;
      }

      if (content.translations && content.translations.has(fallbackLang)) {
        const translation = content.translations.get(fallbackLang);
        if (translation.text && !translation.needsReview) {
          return translation.text;
        }
      }
    }

    // 4. Fallback final al texto original
    return content.original.text;
  },

  /**
   * Verificar si necesita traducción
   */
  needsTranslation(content, targetLanguage) {
    if (!content || !content.original) {
      return false;
    }

    // Si ya está en el idioma objetivo
    if (content.original.language === targetLanguage) {
      return false;
    }

    // Si ya tiene traducción válida
    if (content.translations && content.translations.has(targetLanguage)) {
      const translation = content.translations.get(targetLanguage);
      return translation.needsReview || !translation.text;
    }

    return true;
  },

  /**
   * Obtener estadísticas de traducción
   */
  getTranslationStats(content) {
    if (!content || !content.original) {
      return {
        totalLanguages: 0,
        completedTranslations: 0,
        pendingTranslations: 0,
        needsReview: 0,
      };
    }

    let completedTranslations = 1; // Contar el original
    let needsReview = 0;

    if (content.translations) {
      for (const [lang, translation] of content.translations) {
        if (translation.text) {
          completedTranslations++;
          if (translation.needsReview) {
            needsReview++;
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
    };
  },

  /**
   * Validar estructura de contenido multiidioma
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

    // Validar traducciones
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
  createMultiLanguageContent,
  MultiLanguageUtils,
  SUPPORTED_LANGUAGES,
  DEFAULT_LANGUAGE,
};
