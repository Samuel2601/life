// =============================================================================
// src/models/business/BusinessCategory.js
// =============================================================================
import mongoose from "mongoose";
import {
  BaseSchemeFields,
  addTimestampMiddleware,
  addCommonIndexes,
} from "../base/BaseSchema.js";
import { createMultiLanguageField } from "../base/MultiLanguagePattern.js";

const BusinessCategorySchema = new mongoose.Schema({
  // Información multiidioma
  categoryName: createMultiLanguageField(true),
  description: createMultiLanguageField(false),

  // Estructura jerárquica
  parentCategory: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "BusinessCategory",
    default: null,
    index: true,
  },
  categoryLevel: {
    type: Number,
    default: 0,
    min: 0,
    max: 5,
  },
  categoryPath: {
    type: String,
    index: true, // Para búsqueda jerárquica rápida
  },

  // Clasificación
  industryCode: {
    type: String,
    trim: true,
    maxlength: 20,
  },
  categorySlug: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },

  // Configuración
  isActive: {
    type: Boolean,
    default: true,
    index: true,
  },
  sortOrder: {
    type: Number,
    default: 0,
  },

  // Metadatos
  businessCount: {
    type: Number,
    default: 0,
    min: 0,
  },
  iconUrl: String,
  colorHex: {
    type: String,
    validate: {
      validator: function (v) {
        return !v || /^#[0-9A-F]{6}$/i.test(v);
      },
      message: "Color debe ser hexadecimal válido",
    },
  },

  // SEO y búsqueda
  keywords: [String],
  searchTags: [String],

  ...BaseSchemeFields,
});

// Índices específicos
BusinessCategorySchema.index({ categorySlug: 1 }, { unique: true });
BusinessCategorySchema.index({ parentCategory: 1, sortOrder: 1 });
BusinessCategorySchema.index({ categoryLevel: 1, isActive: 1 });
BusinessCategorySchema.index({ industryCode: 1 });

// Índice de texto multiidioma
BusinessCategorySchema.index({
  "categoryName.original.text": "text",
  "description.original.text": "text",
  keywords: "text",
  searchTags: "text",
});

addTimestampMiddleware(BusinessCategorySchema);
addCommonIndexes(BusinessCategorySchema);

// Pre-save para generar categoryPath
BusinessCategorySchema.pre("save", async function (next) {
  if (this.parentCategory) {
    const parent = await this.constructor.findById(this.parentCategory);
    if (parent) {
      this.categoryLevel = parent.categoryLevel + 1;
      this.categoryPath = parent.categoryPath
        ? `${parent.categoryPath}/${this.categorySlug}`
        : this.categorySlug;
    }
  } else {
    this.categoryLevel = 0;
    this.categoryPath = this.categorySlug;
  }
  next();
});

// Método para obtener subcategorías
BusinessCategorySchema.methods.getSubcategories = function () {
  return this.constructor.find({ parentCategory: this._id, isActive: true });
};

export const BusinessCategory = mongoose.model(
  "BusinessCategory",
  BusinessCategorySchema
);
