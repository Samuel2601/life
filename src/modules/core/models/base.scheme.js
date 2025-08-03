// =============================================================================
// src/models/base/BaseSchema.js
// =============================================================================
import mongoose from "mongoose";

// Patrón base para todos los schemas con auditoría y soft delete
export const BaseSchemeFields = {
  // Soft delete
  isDeleted: {
    type: Boolean,
    default: false,
    index: true,
  },
  deletedAt: {
    type: Date,
    default: null,
  },
  deletedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null,
  },
  deletionReason: {
    type: String,
    maxlength: 500,
  },

  // Auditoría automática
  createdAt: {
    type: Date,
    default: Date.now,
    index: true,
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
  updatedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },

  // Versionado
  version: {
    type: Number,
    default: 1,
    min: 1,
  },

  // Metadatos de auditoría
  lastChangeReason: {
    type: String,
    maxlength: 500,
  },
};

// Middleware para actualizar timestamps
export const addTimestampMiddleware = (schema) => {
  schema.pre("save", function (next) {
    if (this.isNew) {
      this.createdAt = new Date();
    }
    this.updatedAt = new Date();
    next();
  });

  schema.pre(["findOneAndUpdate", "updateOne", "updateMany"], function (next) {
    this.set({ updatedAt: new Date() });
    next();
  });
};

// Índices comunes para optimización
export const addCommonIndexes = (schema) => {
  schema.index({ isDeleted: 1, createdAt: -1 });
  schema.index({ createdBy: 1, createdAt: -1 });
  schema.index({ version: 1 });
};
