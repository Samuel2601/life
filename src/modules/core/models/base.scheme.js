// =============================================================================
// src/modules/core/models/base.schema.js - VERSIÓN ESTANDARIZADA
// Usando camelCase como estándar y solo isDeleted para soft delete
// =============================================================================
import mongoose from "mongoose";

/**
 * Campos base para todos los esquemas con auditoría y soft delete
 * ESTÁNDAR: camelCase para todos los nombres de campo
 */
export const BaseSchemaFields = {
  // Soft delete - SOLO usando isDeleted (no isActive para evitar confusión)
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
    required: function () {
      return (
        this.constructor.modelName !== "User" ||
        mongoose.models.User?.countDocuments?.() > 0
      );
    },
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

/**
 * Middleware para actualizar timestamps automáticamente
 */
export const addTimestampMiddleware = (schema) => {
  schema.pre("save", function (next) {
    const now = new Date();

    if (this.isNew) {
      this.createdAt = now;
      this.version = 1;
    } else {
      this.version = (this.version || 1) + 1;
    }

    this.updatedAt = now;
    next();
  });

  schema.pre(["findOneAndUpdate", "updateOne", "updateMany"], function (next) {
    const update = this.getUpdate();
    const now = new Date();

    if (!update.$set) {
      update.$set = {};
    }

    update.$set.updatedAt = now;

    if (!update.$inc) {
      update.$inc = {};
    }
    update.$inc.version = 1;

    next();
  });
};

/**
 * Agregar índices comunes
 */
export const addCommonIndexes = (schema) => {
  schema.index({ isDeleted: 1, createdAt: -1 });
  schema.index({ createdBy: 1, createdAt: -1 });
  schema.index({ version: 1 });
  schema.index({ updatedAt: -1 });
};

/**
 * Agregar métodos virtuales comunes
 */
export const addCommonVirtuals = (schema) => {
  // Virtual para verificar si está activo (inverso de isDeleted)
  schema.virtual("isActive").get(function () {
    return !this.isDeleted;
  });

  // Virtual para tiempo transcurrido desde creación
  schema.virtual("createdAgo").get(function () {
    if (!this.createdAt) return null;

    const now = new Date();
    const diffMs = now - this.createdAt;
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffDays === 0) return "Hoy";
    if (diffDays === 1) return "Ayer";
    if (diffDays < 7) return `Hace ${diffDays} días`;
    if (diffDays < 30) return `Hace ${Math.floor(diffDays / 7)} semanas`;
    if (diffDays < 365) return `Hace ${Math.floor(diffDays / 30)} meses`;
    return `Hace ${Math.floor(diffDays / 365)} años`;
  });

  // Virtual para tiempo transcurrido desde última actualización
  schema.virtual("updatedAgo").get(function () {
    if (!this.updatedAt) return null;

    const now = new Date();
    const diffMs = now - this.updatedAt;
    const diffMinutes = Math.floor(diffMs / (1000 * 60));

    if (diffMinutes < 1) return "Hace un momento";
    if (diffMinutes < 60) return `Hace ${diffMinutes} minutos`;
    if (diffMinutes < 1440) return `Hace ${Math.floor(diffMinutes / 60)} horas`;
    return `Hace ${Math.floor(diffMinutes / 1440)} días`;
  });
};

/**
 * Agregar métodos de instancia comunes
 */
export const addCommonMethods = (schema) => {
  // Método para realizar soft delete
  schema.methods.softDelete = function (deletedBy, reason = null) {
    this.isDeleted = true;
    this.deletedAt = new Date();
    this.deletedBy = deletedBy;
    this.deletionReason = reason;
    this.updatedBy = deletedBy;
    return this.save();
  };

  // Método para restaurar documento eliminado
  schema.methods.restore = function (restoredBy, reason = null) {
    this.isDeleted = false;
    this.deletedAt = null;
    this.deletedBy = null;
    this.deletionReason = null;
    this.updatedBy = restoredBy;
    this.lastChangeReason = reason || "Documento restaurado";
    return this.save();
  };

  // Método para agregar razón de cambio
  schema.methods.addChangeReason = function (reason) {
    this.lastChangeReason = reason;
    return this;
  };

  // Método para obtener información de auditoría
  schema.methods.getAuditInfo = function () {
    return {
      version: this.version,
      createdAt: this.createdAt,
      createdBy: this.createdBy,
      updatedAt: this.updatedAt,
      updatedBy: this.updatedBy,
      lastChangeReason: this.lastChangeReason,
      isDeleted: this.isDeleted,
      isActive: this.isActive, // usar el virtual
      deletedAt: this.deletedAt,
      deletedBy: this.deletedBy,
      deletionReason: this.deletionReason,
    };
  };
};

/**
 * Agregar métodos estáticos comunes
 */
export const addCommonStatics = (schema) => {
  // Encontrar solo documentos activos (no eliminados)
  schema.statics.findActive = function (filter = {}) {
    return this.find({
      ...filter,
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    });
  };

  // Encontrar solo documentos eliminados
  schema.statics.findDeleted = function (filter = {}) {
    return this.find({ ...filter, isDeleted: true });
  };

  // Contar documentos activos
  schema.statics.countActive = function (filter = {}) {
    return this.countDocuments({
      ...filter,
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    });
  };

  // Encontrar por ID solo si está activo
  schema.statics.findActiveById = function (id) {
    return this.findOne({
      _id: id,
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    });
  };

  // Soft delete múltiples documentos
  schema.statics.softDeleteMany = function (filter, deletedBy, reason = null) {
    return this.updateMany(filter, {
      $set: {
        isDeleted: true,
        deletedAt: new Date(),
        deletedBy: deletedBy,
        deletionReason: reason,
        updatedBy: deletedBy,
        updatedAt: new Date(),
      },
      $inc: { version: 1 },
    });
  };

  // Restaurar múltiples documentos
  schema.statics.restoreMany = function (filter, restoredBy, reason = null) {
    return this.updateMany(filter, {
      $set: {
        isDeleted: false,
        deletedAt: null,
        deletedBy: null,
        deletionReason: null,
        updatedBy: restoredBy,
        updatedAt: new Date(),
        lastChangeReason: reason || "Documentos restaurados",
      },
      $inc: { version: 1 },
    });
  };
};

/**
 * Query helpers para consultas comunes
 */
export const addQueryHelpers = (schema) => {
  schema.query.active = function () {
    return this.where({
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    });
  };

  schema.query.deleted = function () {
    return this.where({ isDeleted: true });
  };

  schema.query.newest = function () {
    return this.sort({ createdAt: -1 });
  };

  schema.query.oldest = function () {
    return this.sort({ createdAt: 1 });
  };

  schema.query.byCreator = function (userId) {
    return this.where({ createdBy: userId });
  };

  schema.query.createdBetween = function (startDate, endDate) {
    const filter = {};
    if (startDate) filter.$gte = startDate;
    if (endDate) filter.$lte = endDate;
    return this.where({ createdAt: filter });
  };
};

/**
 * Función principal para configurar un esquema con todas las funcionalidades base
 */
export const setupBaseSchema = (schema, options = {}) => {
  const {
    addTimestamps = true,
    addIndexes = true,
    addVirtuals = true,
    addMethods = true,
    addStatics = true,
    addHelpers = true,
    addBaseFields = true,
  } = options;

  if (addBaseFields) {
    schema.add(BaseSchemaFields);
  }

  if (addTimestamps) addTimestampMiddleware(schema);
  if (addIndexes) addCommonIndexes(schema);
  if (addVirtuals) addCommonVirtuals(schema);
  if (addMethods) addCommonMethods(schema);
  if (addStatics) addCommonStatics(schema);
  if (addHelpers) addQueryHelpers(schema);

  // Configurar opciones del esquema
  schema.set("toJSON", {
    virtuals: true,
    transform: function (doc, ret) {
      delete ret.__v;
      delete ret.deletedBy;
      delete ret.deletionReason;

      if (ret.isDeleted) {
        delete ret.updatedBy;
        delete ret.lastChangeReason;
      }

      return ret;
    },
  });

  schema.set("toObject", { virtuals: true });

  return schema;
};

/**
 * Validadores comunes
 */
export const CommonValidators = {
  objectId: {
    validator: function (v) {
      return mongoose.Types.ObjectId.isValid(v);
    },
    message: "ID no válido",
  },

  email: {
    validator: function (v) {
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
    },
    message: "Email no válido",
  },

  url: {
    validator: function (v) {
      return !v || /^https?:\/\/.+/.test(v);
    },
    message: "URL no válida",
  },

  phone: {
    validator: function (v) {
      return !v || /^\+?[1-9]\d{1,14}$/.test(v.replace(/\s/g, ""));
    },
    message: "Número de teléfono no válido",
  },

  coordinates: {
    validator: function (coords) {
      return (
        coords &&
        coords.length === 2 &&
        coords[0] >= -180 &&
        coords[0] <= 180 &&
        coords[1] >= -90 &&
        coords[1] <= 90
      );
    },
    message: "Coordenadas geográficas no válidas",
  },
};

export default {
  BaseSchemaFields,
  addTimestampMiddleware,
  addCommonIndexes,
  addCommonVirtuals,
  addCommonMethods,
  addCommonStatics,
  addQueryHelpers,
  setupBaseSchema,
  CommonValidators,
};
