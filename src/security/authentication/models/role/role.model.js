import mongoose from "mongoose";
import {
  BaseSchemaFields,
  setupBaseSchema,
} from "../../../modules/core/models/base.scheme.js";
import { createMultiLanguageField } from "../../../modules/core/models/multi_language_pattern.scheme.js";

// Importar subesquemas
import {
  PermissionSchema,
  CompanyRestrictionsSchema,
  GeographicRestrictionsSchema,
  SessionConfigSchema,
  MetadataSchema,
  StatsSchema,
  NotificationSettingsSchema,
} from "./schemas/index.js";

// Importar funcionalidades modulares
import { applyRoleVirtuals } from "./virtuals/index.js";
import { applyInstanceMethods, applyStaticMethods } from "./methods/index.js";
import {
  applyPreSaveMiddleware,
  applyPostSaveMiddleware,
} from "./middleware/index.js";
import { applyRoleIndexes } from "./indexes/index.js";

/**
 * Schema principal de Rol
 */
const RoleSchema = new mongoose.Schema({
  // Información básica del rol
  roleName: {
    type: String,
    required: [true, "El nombre del rol es requerido"],
    unique: true,
    trim: true,
    maxlength: [50, "El nombre del rol no puede exceder 50 caracteres"],
    minlength: [2, "El nombre del rol debe tener al menos 2 caracteres"],
    lowercase: true,
    match: [
      /^[a-z0-9_-]+$/,
      "El nombre del rol solo puede contener letras minúsculas, números, guiones y guiones bajos",
    ],
    index: true,
  },

  // Nombre para mostrar (multiidioma para UI)
  displayName: createMultiLanguageField(true),

  // Descripción (multiidioma para documentación)
  description: createMultiLanguageField(false),

  // Permisos del rol
  permissions: [PermissionSchema],

  // Jerarquía y tipo de rol
  hierarchy: {
    type: Number,
    default: 0,
    min: [0, "La jerarquía no puede ser negativa"],
    max: [100, "La jerarquía no puede exceder 100"],
    index: true,
  },

  roleType: {
    type: String,
    enum: ["system", "business", "customer", "moderator", "custom"],
    default: "custom",
    index: true,
  },

  parentRole: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Role",
    default: null,
    validate: {
      validator: function (v) {
        return !v || !this._id || !v.equals(this._id);
      },
      message: "Un rol no puede ser su propio padre",
    },
  },

  // Configuración del rol
  isSystemRole: {
    type: Boolean,
    default: false,
    index: true,
  },

  isDefault: {
    type: Boolean,
    default: false,
    index: true,
  },

  // Limitaciones del rol
  maxUsers: {
    type: Number,
    default: null,
    min: [0, "El máximo de usuarios no puede ser negativo"],
  },

  expiresAt: {
    type: Date,
    default: null,
    index: true,
  },

  // Restricciones específicas de empresa
  companyRestrictions: CompanyRestrictionsSchema,

  // Restricciones geográficas
  geographicRestrictions: GeographicRestrictionsSchema,

  // Configuración de sesión específica por rol
  sessionConfig: SessionConfigSchema,

  // Metadatos del rol
  metadata: MetadataSchema,

  // Estadísticas del rol
  stats: StatsSchema,

  // Configuración de notificaciones por rol
  notificationSettings: NotificationSettingsSchema,

  // Campos base (auditoría, soft delete, etc.)
  ...BaseSchemaFields,
});

// Configurar el esquema con funcionalidades base
setupBaseSchema(RoleSchema, {
  addBaseFields: false,
});

// Aplicar módulos adicionales
applyRoleVirtuals(RoleSchema);
applyInstanceMethods(RoleSchema);
applyStaticMethods(RoleSchema);
applyPreSaveMiddleware(RoleSchema);
applyPostSaveMiddleware(RoleSchema);
applyRoleIndexes(RoleSchema);

// Exportar modelo
export const Role = mongoose.model("Role", RoleSchema);
export default Role;
