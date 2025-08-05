// =============================================================================
// src/modules/authentication/models/role.scheme.js
// =============================================================================
import mongoose from "mongoose";
import {
  BaseSchemeFields,
  setupBaseSchema,
} from "../../../modules/core/models/base.scheme.js";

/**
 * Schema para permisos específicos
 */
const PermissionSchema = new mongoose.Schema(
  {
    resource: {
      type: String,
      required: [true, "El recurso es requerido"],
      enum: [
        "users",
        "businesses",
        "reviews",
        "categories",
        "addresses",
        "roles",
        "permissions",
        "system",
        "reports",
        "audit",
        "translations",
        "media",
        "notifications",
        "analytics",
      ],
      index: true,
    },
    actions: [
      {
        type: String,
        required: [true, "La acción es requerida"],
        enum: [
          "create",
          "read",
          "update",
          "delete",
          "manage", // Incluye todas las acciones
          "approve",
          "reject",
          "publish",
          "unpublish",
          "export",
          "import",
          "restore",
          "archive",
        ],
      },
    ],
    conditions: {
      // Condiciones adicionales para el permiso (opcional)
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    scope: {
      type: String,
      enum: ["global", "company", "own", "none"],
      default: "own",
    },
  },
  { _id: false }
);

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
  },

  displayName: {
    type: String,
    required: [true, "El nombre para mostrar es requerido"],
    trim: true,
    maxlength: [100, "El nombre para mostrar no puede exceder 100 caracteres"],
  },

  description: {
    type: String,
    maxlength: [500, "La descripción no puede exceder 500 caracteres"],
    trim: true,
  },

  // Permisos del rol
  permissions: [PermissionSchema],

  // Jerarquía de roles
  hierarchy: {
    type: Number,
    default: 0,
    min: [0, "La jerarquía no puede ser negativa"],
    max: [100, "La jerarquía no puede exceder 100"],
    index: true,
  },

  parentRole: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Role",
    default: null,
    validate: {
      validator: function (v) {
        // No puede ser su propio padre
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
    default: null, // Sin límite
    min: [0, "El máximo de usuarios no puede ser negativo"],
  },

  expiresAt: {
    type: Date,
    default: null,
    index: true,
  },

  // Restricciones específicas de empresa
  companyRestrictions: {
    canManageAllCompanies: {
      type: Boolean,
      default: false,
    },
    restrictedToOwnCompany: {
      type: Boolean,
      default: true,
    },
    allowedCompanies: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Business",
      },
    ],
    maxCompaniesManaged: {
      type: Number,
      default: 1,
      min: [0, "El máximo de empresas no puede ser negativo"],
    },
  },

  // Restricciones geográficas
  geographicRestrictions: {
    allowedCountries: [
      {
        type: String,
        uppercase: true,
        length: 2,
      },
    ],
    allowedRegions: [
      {
        type: String,
        trim: true,
      },
    ],
    restrictToGeolocation: {
      type: Boolean,
      default: false,
    },
  },

  // Metadatos del rol
  metadata: {
    color: {
      type: String,
      validate: {
        validator: function (v) {
          return !v || /^#[0-9A-F]{6}$/i.test(v);
        },
        message: "El color debe ser un código hexadecimal válido",
      },
    },
    icon: {
      type: String,
      maxlength: 50,
    },
    category: {
      type: String,
      enum: ["admin", "business", "customer", "moderator", "support", "system"],
      default: "customer",
      index: true,
    },
    priority: {
      type: Number,
      default: 0,
      min: 0,
      max: 10,
    },
  },

  // Estadísticas del rol
  stats: {
    userCount: {
      type: Number,
      default: 0,
      min: 0,
    },
    lastAssigned: {
      type: Date,
    },
    totalAssignments: {
      type: Number,
      default: 0,
      min: 0,
    },
  },

  // Campos base (auditoría, soft delete, etc.)
  ...BaseSchemeFields,
});

// Configurar el esquema con funcionalidades base
setupBaseSchema(RoleSchema, {
  addBaseFields: false, // Ya los agregamos manualmente arriba
});

// ================================
// ÍNDICES ESPECÍFICOS
// ================================

// Índices únicos
RoleSchema.index({ roleName: 1 }, { unique: true });

// Índices compuestos
RoleSchema.index({ hierarchy: 1, isActive: 1 });
RoleSchema.index({ isActive: 1, isSystemRole: 1 });
RoleSchema.index({ "metadata.category": 1, isActive: 1 });
RoleSchema.index({ parentRole: 1, hierarchy: 1 });

// TTL index para roles con expiración
RoleSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// ================================
// VIRTUALS
// ================================

// Virtual para verificar si el rol está expirado
RoleSchema.virtual("isExpired").get(function () {
  return this.expiresAt && this.expiresAt < new Date();
});

// Virtual para verificar si puede asignar más usuarios
RoleSchema.virtual("canAssignMoreUsers").get(function () {
  if (!this.maxUsers) return true;
  return this.stats.userCount < this.maxUsers;
});

// Virtual para obtener el porcentaje de uso
RoleSchema.virtual("usagePercentage").get(function () {
  if (!this.maxUsers) return 0;
  return Math.round((this.stats.userCount / this.maxUsers) * 100);
});

// ================================
// MÉTODOS DE INSTANCIA
// ================================

// Método para verificar si tiene un permiso específico
RoleSchema.methods.hasPermission = function (resource, action, scope = "own") {
  if (!this.isActive || this.isExpired) {
    return false;
  }

  // Buscar el permiso para el recurso
  const permission = this.permissions.find((p) => p.resource === resource);

  if (!permission) {
    return false;
  }

  // Verificar si tiene la acción específica o 'manage'
  const hasAction =
    permission.actions.includes(action) ||
    permission.actions.includes("manage");

  if (!hasAction) {
    return false;
  }

  // Verificar el alcance
  const scopeHierarchy = ["none", "own", "company", "global"];
  const requiredScopeLevel = scopeHierarchy.indexOf(scope);
  const permissionScopeLevel = scopeHierarchy.indexOf(permission.scope);

  return permissionScopeLevel >= requiredScopeLevel;
};

// Método para agregar permiso
RoleSchema.methods.addPermission = function (
  resource,
  actions,
  scope = "own",
  conditions = {}
) {
  // Verificar si ya existe permiso para este recurso
  const existingPermissionIndex = this.permissions.findIndex(
    (p) => p.resource === resource
  );

  const permission = {
    resource,
    actions: Array.isArray(actions) ? actions : [actions],
    scope,
    conditions,
  };

  if (existingPermissionIndex >= 0) {
    // Actualizar permiso existente
    this.permissions[existingPermissionIndex] = permission;
  } else {
    // Agregar nuevo permiso
    this.permissions.push(permission);
  }

  return this;
};

// Método para remover permiso
RoleSchema.methods.removePermission = function (resource, action = null) {
  if (action) {
    // Remover acción específica
    const permission = this.permissions.find((p) => p.resource === resource);
    if (permission) {
      permission.actions = permission.actions.filter((a) => a !== action);
      // Si no quedan acciones, remover el permiso completo
      if (permission.actions.length === 0) {
        this.permissions = this.permissions.filter(
          (p) => p.resource !== resource
        );
      }
    }
  } else {
    // Remover todo el permiso para el recurso
    this.permissions = this.permissions.filter((p) => p.resource !== resource);
  }

  return this;
};

// Método para verificar si puede gestionar empresa
RoleSchema.methods.canManageCompany = function (companyId = null) {
  if (!this.isActive || this.isExpired) {
    return false;
  }

  // Verificar restricciones de empresa
  const restrictions = this.companyRestrictions;

  if (restrictions.canManageAllCompanies) {
    return true;
  }

  if (
    companyId &&
    restrictions.allowedCompanies &&
    restrictions.allowedCompanies.length > 0
  ) {
    return restrictions.allowedCompanies.some((id) => id.equals(companyId));
  }

  return !restrictions.restrictedToOwnCompany;
};

// Método para verificar restricciones geográficas
RoleSchema.methods.checkGeographicRestrictions = function (
  country = null,
  region = null
) {
  if (!this.geographicRestrictions.restrictToGeolocation) {
    return true;
  }

  const restrictions = this.geographicRestrictions;

  // Verificar país
  if (
    country &&
    restrictions.allowedCountries &&
    restrictions.allowedCountries.length > 0
  ) {
    if (!restrictions.allowedCountries.includes(country.toUpperCase())) {
      return false;
    }
  }

  // Verificar región
  if (
    region &&
    restrictions.allowedRegions &&
    restrictions.allowedRegions.length > 0
  ) {
    if (!restrictions.allowedRegions.includes(region)) {
      return false;
    }
  }

  return true;
};

// Método para obtener resumen de permisos
RoleSchema.methods.getPermissionsSummary = function () {
  const summary = {
    totalPermissions: this.permissions.length,
    resourcesWithFullAccess: [],
    resourcesWithLimitedAccess: [],
    scopeDistribution: { none: 0, own: 0, company: 0, global: 0 },
  };

  this.permissions.forEach((permission) => {
    // Verificar si tiene acceso completo (manage)
    if (permission.actions.includes("manage")) {
      summary.resourcesWithFullAccess.push(permission.resource);
    } else {
      summary.resourcesWithLimitedAccess.push({
        resource: permission.resource,
        actions: permission.actions,
      });
    }

    // Contar distribución de alcances
    summary.scopeDistribution[permission.scope]++;
  });

  return summary;
};

// ================================
// MÉTODOS ESTÁTICOS
// ================================

// Obtener rol por nombre
RoleSchema.statics.findByName = function (roleName) {
  return this.findOne({
    roleName: roleName.toLowerCase(),
    isActive: true,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  });
};

// Obtener roles por jerarquía
RoleSchema.statics.findByHierarchy = function (minLevel = 0, maxLevel = 100) {
  return this.find({
    hierarchy: { $gte: minLevel, $lte: maxLevel },
    isActive: true,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  }).sort({ hierarchy: 1 });
};

// Obtener roles de sistema
RoleSchema.statics.getSystemRoles = function () {
  return this.find({
    isSystemRole: true,
    isActive: true,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  }).sort({ hierarchy: 1 });
};

// Obtener rol por defecto
RoleSchema.statics.getDefaultRole = function () {
  return this.findOne({
    isDefault: true,
    isActive: true,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  });
};

// Crear roles predeterminados del sistema
RoleSchema.statics.createSystemRoles = async function () {
  const systemRoles = [
    {
      roleName: "super_admin",
      displayName: "Super Administrador",
      description: "Acceso completo al sistema",
      hierarchy: 100,
      isSystemRole: true,
      permissions: [
        { resource: "users", actions: ["manage"], scope: "global" },
        { resource: "businesses", actions: ["manage"], scope: "global" },
        { resource: "reviews", actions: ["manage"], scope: "global" },
        { resource: "categories", actions: ["manage"], scope: "global" },
        { resource: "roles", actions: ["manage"], scope: "global" },
        { resource: "system", actions: ["manage"], scope: "global" },
        { resource: "reports", actions: ["manage"], scope: "global" },
        { resource: "audit", actions: ["manage"], scope: "global" },
      ],
      companyRestrictions: {
        canManageAllCompanies: true,
        restrictedToOwnCompany: false,
      },
      metadata: {
        color: "#FF0000",
        icon: "crown",
        category: "admin",
        priority: 10,
      },
    },
    {
      roleName: "admin",
      displayName: "Administrador",
      description: "Administrador del sistema con acceso limitado",
      hierarchy: 80,
      isSystemRole: true,
      permissions: [
        {
          resource: "users",
          actions: ["create", "read", "update"],
          scope: "global",
        },
        { resource: "businesses", actions: ["manage"], scope: "global" },
        { resource: "reviews", actions: ["manage"], scope: "global" },
        { resource: "categories", actions: ["manage"], scope: "global" },
        { resource: "reports", actions: ["read", "export"], scope: "global" },
      ],
      companyRestrictions: {
        canManageAllCompanies: true,
        restrictedToOwnCompany: false,
      },
      metadata: {
        color: "#FF6600",
        icon: "shield",
        category: "admin",
        priority: 8,
      },
    },
    {
      roleName: "business_owner",
      displayName: "Propietario de Empresa",
      description: "Propietario que puede gestionar su empresa",
      hierarchy: 50,
      isSystemRole: true,
      isDefault: false,
      permissions: [
        { resource: "businesses", actions: ["read", "update"], scope: "own" },
        {
          resource: "reviews",
          actions: ["read", "approve", "reject"],
          scope: "company",
        },
        { resource: "users", actions: ["read"], scope: "company" },
        { resource: "reports", actions: ["read"], scope: "company" },
      ],
      companyRestrictions: {
        canManageAllCompanies: false,
        restrictedToOwnCompany: true,
        maxCompaniesManaged: 5,
      },
      metadata: {
        color: "#0066FF",
        icon: "building",
        category: "business",
        priority: 5,
      },
    },
    {
      roleName: "customer",
      displayName: "Cliente",
      description: "Usuario cliente con permisos básicos",
      hierarchy: 10,
      isSystemRole: true,
      isDefault: true,
      permissions: [
        { resource: "businesses", actions: ["read"], scope: "global" },
        {
          resource: "reviews",
          actions: ["create", "read", "update"],
          scope: "own",
        },
        { resource: "users", actions: ["read", "update"], scope: "own" },
      ],
      companyRestrictions: {
        canManageAllCompanies: false,
        restrictedToOwnCompany: true,
        maxCompaniesManaged: 0,
      },
      metadata: {
        color: "#00CC66",
        icon: "user",
        category: "customer",
        priority: 1,
      },
    },
  ];

  const createdRoles = [];

  for (const roleData of systemRoles) {
    try {
      const existingRole = await this.findByName(roleData.roleName);

      if (!existingRole) {
        const role = new this(roleData);
        await role.save();
        createdRoles.push(role);
        console.log(`✅ Rol del sistema creado: ${roleData.displayName}`);
      }
    } catch (error) {
      console.error(
        `❌ Error creando rol ${roleData.roleName}:`,
        error.message
      );
    }
  }

  return createdRoles;
};

// Actualizar estadísticas de rol
RoleSchema.statics.updateRoleStats = async function (roleId) {
  const User = mongoose.model("User");

  const userCount = await User.countDocuments({
    roles: roleId,
    isActive: true,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  });

  await this.findByIdAndUpdate(roleId, {
    "stats.userCount": userCount,
    "stats.lastAssigned": new Date(),
  });

  return userCount;
};

// ================================
// MIDDLEWARES
// ================================

// Pre-save middleware
RoleSchema.pre("save", async function (next) {
  // Normalizar nombre del rol
  if (this.roleName) {
    this.roleName = this.roleName.toLowerCase().trim();
  }

  // Verificar jerarquía del rol padre
  if (this.parentRole && this.hierarchy !== undefined) {
    try {
      const parentRole = await this.constructor.findById(this.parentRole);
      if (parentRole && this.hierarchy >= parentRole.hierarchy) {
        return next(
          new Error("La jerarquía del rol debe ser menor que la del rol padre")
        );
      }
    } catch (error) {
      return next(error);
    }
  }

  // Solo puede haber un rol por defecto
  if (this.isDefault && this.isModified("isDefault")) {
    await this.constructor.updateMany(
      { _id: { $ne: this._id } },
      { $set: { isDefault: false } }
    );
  }

  next();
});

// Post-save middleware
RoleSchema.post("save", function (doc, next) {
  if (doc.isNew) {
    console.log(`✅ Rol creado: ${doc.displayName} (${doc.roleName})`);
  }
  next();
});

// ================================
// EXPORTAR MODELO
// ================================

export const Role = mongoose.model("Role", RoleSchema);
export default Role;
