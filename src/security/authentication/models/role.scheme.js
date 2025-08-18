// =============================================================================
// src/modules/authentication/models/role.scheme.js - VERSIÓN OPTIMIZADA
// Mantiene la simplicidad del primer esquema + mejoras selectivas del segundo
// =============================================================================
import mongoose from "mongoose";
import {
  BaseSchemeFields,
  setupBaseSchema,
} from "../../../modules/core/models/base.scheme.js";
import { createMultiLanguageField } from "../../../modules/core/models/multi_language_pattern.scheme.js";

/**
 * Schema para permisos específicos embebidos (optimizado)
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
        "all", // Para super admins
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
          "moderate",
          "verify",
          "all", // Para permisos globales
        ],
      },
    ],
    scope: {
      type: String,
      enum: ["none", "own", "company", "global"],
      default: "own",
      index: true,
    },
    // Condiciones específicas (JSON flexible)
    conditions: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    // Restricciones geográficas básicas (del segundo esquema)
    geographicRestrictions: {
      allowedCountries: [String], // ISO codes
      allowedRegions: [String],
      restrictToLocation: {
        type: Boolean,
        default: false,
      },
    },
    // Restricciones de horario (simplificadas)
    timeRestrictions: {
      businessHoursOnly: {
        type: Boolean,
        default: false,
      },
      timezone: {
        type: String,
        default: "America/Lima",
      },
    },
  },
  { _id: false }
);

/**
 * Schema principal de Rol (optimizado)
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

  // Nombre para mostrar (NUEVO: multiidioma para UI)
  displayName: createMultiLanguageField(true),

  // Descripción (NUEVO: multiidioma para documentación)
  description: createMultiLanguageField(false),

  // Permisos del rol (mantener embebidos para rendimiento)
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

  // Restricciones específicas de empresa (mejoradas)
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
    // NUEVO: restricciones por categoría de empresa
    allowedBusinessCategories: [String],
    excludedBusinessCategories: [String],
  },

  // Restricciones geográficas (simplificadas)
  geographicRestrictions: {
    allowedCountries: [
      {
        type: String,
        uppercase: true,
        length: 2,
      },
    ],
    allowedRegions: [String],
    restrictToGeolocation: {
      type: Boolean,
      default: false,
    },
  },

  // NUEVO: Configuración de sesión específica por rol
  sessionConfig: {
    maxConcurrentSessions: {
      type: Number,
      default: 3,
      min: 1,
      max: 10,
    },
    sessionTimeoutMinutes: {
      type: Number,
      default: 480, // 8 horas
      min: 15,
      max: 43200, // 30 días
    },
    requireTwoFactor: {
      type: Boolean,
      default: false,
    },
    allowRememberMe: {
      type: Boolean,
      default: true,
    },
  },

  // Metadatos del rol (expandidos)
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
    // NUEVO: metadatos para UI
    badgeText: String,
    sortOrder: {
      type: Number,
      default: 0,
    },
  },

  // Estadísticas del rol (mejoradas)
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
    // NUEVO: estadísticas de uso
    avgSessionDuration: {
      type: Number,
      default: 0,
    },
    lastUsed: {
      type: Date,
    },
  },

  // NUEVO: Configuración de notificaciones por rol
  notificationSettings: {
    enableSystemNotifications: {
      type: Boolean,
      default: true,
    },
    enableBusinessNotifications: {
      type: Boolean,
      default: true,
    },
    notificationChannels: [
      {
        type: String,
        enum: ["email", "sms", "push", "in_app"],
      },
    ],
    dailyDigest: {
      type: Boolean,
      default: false,
    },
  },

  // Campos base (auditoría, soft delete, etc.)
  ...BaseSchemeFields,
});

// Configurar el esquema con funcionalidades base
setupBaseSchema(RoleSchema, {
  addBaseFields: false,
});

// ================================
// ÍNDICES ESPECÍFICOS (optimizados)
// ================================

// Índices únicos
RoleSchema.index({ roleName: 1 }, { unique: true });

// Índices compuestos para consultas frecuentes
RoleSchema.index({ hierarchy: 1, isActive: 1 });
RoleSchema.index({ isActive: 1, isSystemRole: 1 });
RoleSchema.index({
  "metadata.category": 1,
  isActive: 1,
  "metadata.sortOrder": 1,
});
RoleSchema.index({ parentRole: 1, hierarchy: 1 });
RoleSchema.index({ roleType: 1, isActive: 1 });

// TTL index para roles con expiración
RoleSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Índices para restricciones
RoleSchema.index({ "companyRestrictions.allowedCompanies": 1 });
RoleSchema.index({ "geographicRestrictions.allowedCountries": 1 });

// ================================
// VIRTUALS (mejorados)
// ================================

RoleSchema.virtual("isExpired").get(function () {
  return this.expiresAt && this.expiresAt < new Date();
});

RoleSchema.virtual("canAssignMoreUsers").get(function () {
  if (!this.maxUsers) return true;
  return this.stats.userCount < this.maxUsers;
});

RoleSchema.virtual("usagePercentage").get(function () {
  if (!this.maxUsers) return 0;
  return Math.round((this.stats.userCount / this.maxUsers) * 100);
});

// NUEVO: Virtual para obtener nivel de seguridad
RoleSchema.virtual("securityLevel").get(function () {
  if (this.hierarchy >= 90) return "critical";
  if (this.hierarchy >= 70) return "high";
  if (this.hierarchy >= 40) return "medium";
  return "standard";
});

// ================================
// MÉTODOS DE INSTANCIA (optimizados)
// ================================

// Método principal para verificar permisos (mantener compatibilidad)
RoleSchema.methods.hasPermission = function (resource, action, scope = "own") {
  if (!this.isActive || this.isExpired) {
    return false;
  }

  const permission = this.permissions.find(
    (p) => p.resource === resource || p.resource === "all"
  );

  if (!permission) {
    return false;
  }

  const hasAction =
    permission.actions.includes(action) ||
    permission.actions.includes("manage") ||
    permission.actions.includes("all");

  if (!hasAction) {
    return false;
  }

  // Verificar scope
  const scopeHierarchy = ["none", "own", "company", "global"];
  const requiredScopeLevel = scopeHierarchy.indexOf(scope);
  const permissionScopeLevel = scopeHierarchy.indexOf(permission.scope);

  return permissionScopeLevel >= requiredScopeLevel;
};

// NUEVO: Método para verificar permisos con contexto geográfico
RoleSchema.methods.hasPermissionWithLocation = function (
  resource,
  action,
  scope = "own",
  location = null
) {
  if (!this.hasPermission(resource, action, scope)) {
    return false;
  }

  // Verificar restricciones geográficas globales del rol
  if (this.geographicRestrictions.restrictToGeolocation && location) {
    return this.checkGeographicRestrictions(location.country, location.region);
  }

  // Verificar restricciones específicas del permiso
  const permission = this.permissions.find(
    (p) => p.resource === resource || p.resource === "all"
  );

  if (permission?.geographicRestrictions?.restrictToLocation && location) {
    const restrictions = permission.geographicRestrictions;

    if (restrictions.allowedCountries?.length > 0) {
      return restrictions.allowedCountries.includes(location.country);
    }

    if (restrictions.allowedRegions?.length > 0) {
      return restrictions.allowedRegions.includes(location.region);
    }
  }

  return true;
};

// Mantener métodos existentes para compatibilidad
RoleSchema.methods.addPermission = function (
  resource,
  actions,
  scope = "own",
  conditions = {}
) {
  const existingPermissionIndex = this.permissions.findIndex(
    (p) => p.resource === resource
  );

  const permission = {
    resource,
    actions: Array.isArray(actions) ? actions : [actions],
    scope,
    conditions,
    geographicRestrictions: {
      restrictToLocation: false,
    },
    timeRestrictions: {
      businessHoursOnly: false,
    },
  };

  if (existingPermissionIndex >= 0) {
    this.permissions[existingPermissionIndex] = permission;
  } else {
    this.permissions.push(permission);
  }

  return this;
};

RoleSchema.methods.removePermission = function (resource, action = null) {
  if (action) {
    const permission = this.permissions.find((p) => p.resource === resource);
    if (permission) {
      permission.actions = permission.actions.filter((a) => a !== action);
      if (permission.actions.length === 0) {
        this.permissions = this.permissions.filter(
          (p) => p.resource !== resource
        );
      }
    }
  } else {
    this.permissions = this.permissions.filter((p) => p.resource !== resource);
  }

  return this;
};

RoleSchema.methods.canManageCompany = function (companyId = null) {
  if (!this.isActive || this.isExpired) {
    return false;
  }

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

RoleSchema.methods.checkGeographicRestrictions = function (
  country = null,
  region = null
) {
  if (!this.geographicRestrictions.restrictToGeolocation) {
    return true;
  }

  const restrictions = this.geographicRestrictions;

  if (
    country &&
    restrictions.allowedCountries &&
    restrictions.allowedCountries.length > 0
  ) {
    if (!restrictions.allowedCountries.includes(country.toUpperCase())) {
      return false;
    }
  }

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

// NUEVO: Método para obtener configuración de sesión efectiva
RoleSchema.methods.getEffectiveSessionConfig = function () {
  const defaultConfig = {
    maxConcurrentSessions: 3,
    sessionTimeoutMinutes: 480,
    requireTwoFactor: false,
    allowRememberMe: true,
  };

  return {
    ...defaultConfig,
    ...this.sessionConfig,
  };
};

// NUEVO: Método para verificar si requiere aprobación para acciones específicas
RoleSchema.methods.requiresApprovalFor = function (resource, action) {
  const permission = this.permissions.find(
    (p) => p.resource === resource || p.resource === "all"
  );

  if (!permission) return false;

  // Acciones que siempre requieren aprobación para ciertos roles
  const criticalActions = ["delete", "manage", "admin"];
  const requiresApprovalActions = permission.conditions?.requiresApproval || [];

  return (
    (criticalActions.includes(action) && this.hierarchy < 80) ||
    requiresApprovalActions.includes(action)
  );
};

RoleSchema.methods.getPermissionsSummary = function () {
  const summary = {
    totalPermissions: this.permissions.length,
    resourcesWithFullAccess: [],
    resourcesWithLimitedAccess: [],
    scopeDistribution: { none: 0, own: 0, company: 0, global: 0 },
    securityLevel: this.securityLevel,
    requiresTwoFactor: this.sessionConfig?.requireTwoFactor || false,
  };

  this.permissions.forEach((permission) => {
    if (
      permission.actions.includes("manage") ||
      permission.actions.includes("all")
    ) {
      summary.resourcesWithFullAccess.push(permission.resource);
    } else {
      summary.resourcesWithLimitedAccess.push({
        resource: permission.resource,
        actions: permission.actions,
      });
    }

    summary.scopeDistribution[permission.scope]++;
  });

  return summary;
};

// ================================
// MÉTODOS ESTÁTICOS (mantener compatibilidad)
// ================================

RoleSchema.statics.findByName = function (roleName) {
  return this.findOne({
    roleName: roleName.toLowerCase(),
    isActive: true,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  });
};

RoleSchema.statics.findByHierarchy = function (minLevel = 0, maxLevel = 100) {
  return this.find({
    hierarchy: { $gte: minLevel, $lte: maxLevel },
    isActive: true,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  }).sort({ hierarchy: 1 });
};

RoleSchema.statics.getSystemRoles = function () {
  return this.find({
    isSystemRole: true,
    isActive: true,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  }).sort({ hierarchy: 1 });
};

RoleSchema.statics.getDefaultRole = function () {
  return this.findOne({
    isDefault: true,
    isActive: true,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  });
};

// NUEVO: Método para obtener roles por tipo con paginación
RoleSchema.statics.getRolesByType = function (roleType, options = {}) {
  const query = {
    roleType: roleType,
    isActive: true,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  };

  const queryObj = this.find(query);

  if (options.populate) {
    queryObj.populate(options.populate);
  }

  if (options.sortBy) {
    const sort = {};
    sort[options.sortBy] = options.sortOrder === "desc" ? -1 : 1;
    queryObj.sort(sort);
  } else {
    queryObj.sort({ "metadata.sortOrder": 1, hierarchy: -1 });
  }

  if (options.limit) {
    queryObj.limit(options.limit);
  }

  return queryObj;
};

// Actualizar método de creación de roles del sistema
RoleSchema.statics.createSystemRoles = async function () {
  const systemRoles = [
    {
      roleName: "super_admin",
      displayName: {
        original: { language: "es", text: "Super Administrador" },
        translations: new Map([
          ["en", { text: "Super Administrator", translatedAt: new Date() }],
        ]),
      },
      description: {
        original: { language: "es", text: "Acceso completo al sistema" },
        translations: new Map([
          ["en", { text: "Complete system access", translatedAt: new Date() }],
        ]),
      },
      hierarchy: 100,
      roleType: "system",
      isSystemRole: true,
      permissions: [{ resource: "all", actions: ["all"], scope: "global" }],
      companyRestrictions: {
        canManageAllCompanies: true,
        restrictedToOwnCompany: false,
      },
      sessionConfig: {
        maxConcurrentSessions: 5,
        sessionTimeoutMinutes: 720,
        requireTwoFactor: true,
        allowRememberMe: false,
      },
      metadata: {
        color: "#FF0000",
        icon: "crown",
        category: "admin",
        priority: 10,
        sortOrder: 1,
      },
    },
    {
      roleName: "business_owner",
      displayName: {
        original: { language: "es", text: "Propietario de Empresa" },
        translations: new Map([
          ["en", { text: "Business Owner", translatedAt: new Date() }],
        ]),
      },
      description: {
        original: {
          language: "es",
          text: "Propietario que puede gestionar su empresa",
        },
        translations: new Map([
          [
            "en",
            {
              text: "Owner who can manage their business",
              translatedAt: new Date(),
            },
          ],
        ]),
      },
      hierarchy: 50,
      roleType: "business",
      isSystemRole: true,
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
      sessionConfig: {
        maxConcurrentSessions: 3,
        sessionTimeoutMinutes: 480,
        requireTwoFactor: false,
        allowRememberMe: true,
      },
      metadata: {
        color: "#0066FF",
        icon: "building",
        category: "business",
        priority: 5,
        sortOrder: 3,
      },
    },
    {
      roleName: "customer",
      displayName: {
        original: { language: "es", text: "Cliente" },
        translations: new Map([
          ["en", { text: "Customer", translatedAt: new Date() }],
        ]),
      },
      description: {
        original: {
          language: "es",
          text: "Usuario cliente con permisos básicos",
        },
        translations: new Map([
          [
            "en",
            {
              text: "Customer user with basic permissions",
              translatedAt: new Date(),
            },
          ],
        ]),
      },
      hierarchy: 10,
      roleType: "customer",
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
      sessionConfig: {
        maxConcurrentSessions: 2,
        sessionTimeoutMinutes: 240,
        requireTwoFactor: false,
        allowRememberMe: true,
      },
      metadata: {
        color: "#00CC66",
        icon: "user",
        category: "customer",
        priority: 1,
        sortOrder: 4,
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
        console.log(
          `✅ Rol del sistema creado: ${roleData.displayName.original.text}`
        );
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
// MIDDLEWARES (mantener compatibilidad)
// ================================

RoleSchema.pre("save", async function (next) {
  if (this.roleName) {
    this.roleName = this.roleName.toLowerCase().trim();
  }

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

  if (this.isDefault && this.isModified("isDefault")) {
    await this.constructor.updateMany(
      { _id: { $ne: this._id } },
      { $set: { isDefault: false } }
    );
  }

  next();
});

RoleSchema.post("save", function (doc, next) {
  if (doc.isNew) {
    console.log(
      `✅ Rol creado: ${doc.displayName?.original?.text || doc.roleName}`
    );
  }
  next();
});

// ================================
// EXPORTAR MODELO
// ================================

export const Role = mongoose.model("Role", RoleSchema);
export default Role;
