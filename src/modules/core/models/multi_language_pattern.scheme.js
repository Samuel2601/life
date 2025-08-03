// =============================================================================
// src/models/base/MultiLanguagePattern.js
// =============================================================================
import mongoose from "mongoose";

// Esquema para contenido original
const OriginalContentSchema = new mongoose.Schema(
  {
    language: {
      type: String,
      required: true,
      enum: ["es", "en", "fr", "de", "pt", "it", "zh", "ja", "ko", "ar"],
      default: "es",
    },
    text: {
      type: String,
      required: true,
      maxlength: 5000,
    },
  },
  { _id: false }
);

// Esquema para traducciones
const TranslationSchema = new mongoose.Schema(
  {
    text: {
      type: String,
      required: true,
      maxlength: 5000,
    },
    translatedAt: {
      type: Date,
      default: Date.now,
    },
    translationMethod: {
      type: String,
      enum: ["ai", "manual", "auto"],
      default: "ai",
    },
    confidence: {
      type: Number,
      min: 0,
      max: 1,
    },
    needsReview: {
      type: Boolean,
      default: false,
    },
  },
  { _id: false }
);

// Patrón principal multiidioma
export const MultiLanguageContentSchema = new mongoose.Schema(
  {
    original: {
      type: OriginalContentSchema,
      required: true,
    },
    translations: {
      type: Map,
      of: TranslationSchema,
      default: new Map(),
    },
    lastUpdated: {
      type: Date,
      default: Date.now,
    },
  },
  { _id: false }
);

// Helper para crear campo multiidioma
export const createMultiLanguageField = (required = false) => ({
  type: MultiLanguageContentSchema,
  required,
  index: "text", // Índice de texto para búsqueda
});
