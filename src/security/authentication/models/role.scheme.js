// =============================================================================
// src/models/auth/Role.js
// =============================================================================
import mongoose from "mongoose";
import {
  BaseSchemeFields,
  addTimestampMiddleware,
  addCommonIndexes,
} from "../base/BaseSchema.js";

const RoleSchema = new mongoose.Schema({
  roleName: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    maxlength: 50,
  },
  displayName: {
    type: String,
    required: true,
    maxlength: 100,
  },
  description: {
    type: String,
    maxlength: 500,
  },

  // Permisos básicos
  permissions: [
    {
      resource: {
        type: String,
        required: true,
        enum: [
          "users",
          "businesses",
          "reviews",
          "categories",
          "system",
          "reports",
        ],
      },
      actions: [
        {
          type: String,
          enum: ["create", "read", "update", "delete", "manage"],
        },
      ],
    },
  ],

  // Jerarquía de roles
  hierarchy: {
    type: Number,
    default: 0,
    min: 0,
    max: 100,
  },
  parentRole: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Role",
  },

  // Configuración
  isSystemRole: {
    type: Boolean,
    default: false,
  },
  isActive: {
    type: Boolean,
    default: true,
    index: true,
  },
  maxUsers: {
    type: Number,
    default: null, // Sin límite
  },

  // Restricciones específicas
  companyRestrictions: {
    canManageAllCompanies: {
      type: Boolean,
      default: false,
    },
    restrictedToOwnCompany: {
      type: Boolean,
      default: true,
    },
  },

  ...BaseSchemeFields,
});

// Índices específicos
RoleSchema.index({ roleName: 1 }, { unique: true });
RoleSchema.index({ hierarchy: 1 });
RoleSchema.index({ isActive: 1, isSystemRole: 1 });

addTimestampMiddleware(RoleSchema);
addCommonIndexes(RoleSchema);

// Método para verificar permiso
RoleSchema.methods.hasPermission = function (resource, action) {
  const permission = this.permissions.find((p) => p.resource === resource);
  return (
    permission &&
    (permission.actions.includes(action) ||
      permission.actions.includes("manage"))
  );
};

export const Role = mongoose.model("Role", RoleSchema);
