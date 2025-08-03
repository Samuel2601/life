// =============================================================================
// src/models/system/TranslationCache.js
// =============================================================================
import mongoose from "mongoose";
import {
  BaseSchemeFields,
  addTimestampMiddleware,
} from "../base/BaseSchema.js";

const TranslationCacheSchema = new mongoose.Schema({
  // Texto fuente
  sourceText: {
    type: String,
    required: true,
    maxlength: 5000,
  },
  sourceLanguage: {
    type: String,
    required: true,
    enum: ["es", "en", "fr", "de", "pt", "it", "zh", "ja", "ko", "ar"],
  },
  targetLanguage: {
    type: String,
    required: true,
    enum: ["es", "en", "fr", "de", "pt", "it", "zh", "ja", "ko", "ar"],
  },

  // Texto traducido
  translatedText: {
    type: String,
    required: true,
    maxlength: 5000,
  },

  // Metadatos de traducción
  translationService: {
    type: String,
    required: true,
    enum: ["openai", "google", "deepl", "manual"],
    index: true,
  },
  confidence: {
    type: Number,
    min: 0,
    max: 1,
    default: 0.8,
  },

  // Optimización y uso
  textHash: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  usageCount: {
    type: Number,
    default: 1,
    min: 1,
  },
  lastUsedAt: {
    type: Date,
    default: Date.now,
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
  verifiedAt: Date,
  qualityScore: {
    type: Number,
    min: 0,
    max: 10,
    default: 7,
  },

  // Contexto y categorización
  context: {
    type: String,
    enum: ["business", "general", "technical", "marketing", "legal"],
    default: "general",
  },
  category: {
    type: String,
    enum: ["name", "description", "service", "address", "review"],
    index: true,
  },

  // Expiración (para traducciones que pueden volverse obsoletas)
  expiresAt: {
    type: Date,
    index: 1, // TTL index
  },

  ...BaseSchemeFields,
});

// Índice compuesto principal para búsquedas rápidas
TranslationCacheSchema.index(
  {
    sourceLanguage: 1,
    targetLanguage: 1,
    textHash: 1,
  },
  { unique: true }
);

// Índices para optimización
TranslationCacheSchema.index({ usageCount: -1, lastUsedAt: -1 });
TranslationCacheSchema.index({ translationService: 1, confidence: -1 });
TranslationCacheSchema.index({ context: 1, category: 1 });

// TTL index para expiración automática
TranslationCacheSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

addTimestampMiddleware(TranslationCacheSchema);

// Pre-save para generar hash del texto
TranslationCacheSchema.pre("save", function (next) {
  if (this.isNew || this.isModified("sourceText")) {
    const crypto = require("crypto");
    const hashInput = `${this.sourceLanguage}:${this.targetLanguage}:${this.sourceText}`;
    this.textHash = crypto.createHash("sha256").update(hashInput).digest("hex");
  }
  next();
});

// Método para incrementar uso
TranslationCacheSchema.methods.incrementUsage = function () {
  this.usageCount += 1;
  this.lastUsedAt = new Date();
  return this.save();
};

export const TranslationCache = mongoose.model(
  "TranslationCache",
  TranslationCacheSchema
);
