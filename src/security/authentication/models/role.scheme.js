// =============================================================================
// src/modules/authentication/models/role.scheme.js - INTEGRACIÓN COMPLETA
// Integrado con base.scheme.js y multi_language_pattern_improved.scheme.js
// =============================================================================
import mongoose from "mongoose";
import {
  BaseSchemaFields,
  setupBaseSchema,
  CommonValidators,
} from "../../../modules/core/models/base.scheme.js";
import {
  createMultiLanguageField,
  MultiLanguageValidators,
  SUPPORTED_LANGUAGES,
  DEFAULT_LANGUAGE,
} from "../../../modules/core/models/multi_language_pattern_improved.scheme.js";

/**
 * Schema para permisos específicos embebidos
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
    // Restricciones geográficas básicas
    geographicRestrictions: {
      allowedCountries: [String], // ISO codes
      allowedRegions: [String],
      restrictToLocation: {
        type: Boolean,
        default: false,
      },
    },
    // Restricciones de horario
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
 * Schema principal de Rol - Integrado con base.scheme.js
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

  // Nombre para mostrar - Integrado con patrón multiidioma mejorado
  displayName: createMultiLanguageField(true, {
    textIndex: true,
    validator: [
      MultiLanguageValidators.hasOriginalText,
      MultiLanguageValidators.minLength(2),
      MultiLanguageValidators.maxLength(100),
    ],
  }),

  // Descripción - Integrado con patrón multiidioma mejorado
  description: createMultiLanguageField(false, {
    textIndex: true,
    validator: [
      MultiLanguageValidators.hasOriginalText,
      MultiLanguageValidators.minLength(10),
      MultiLanguageValidators.maxLength(500),
    ],
  }),

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
    validate: CommonValidators.objectId,
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

  // IMPORTANTE: isActive específico del rol (independiente del virtual del base)
  // Este controla si el rol puede ser usado/asignado
  isRoleActive: {
    type: Boolean,
    default: true,
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
        validate: CommonValidators.objectId,
      },
    ],
    maxCompaniesManaged: {
      type: Number,
      default: 1,
      min: [0, "El máximo de empresas no puede ser negativo"],
    },
    allowedBusinessCategories: [String],
    excludedBusinessCategories: [String],
  },

  // Restricciones geográficas
  geographicRestrictions: {
    allowedCountries: [
      {
        type: String,
        uppercase: true,
        match: [/^[A-Z]{2}$/, "Debe ser código de país ISO de 2 letras"],
      },
    ],
    allowedRegions: [String],
    restrictToGeolocation: {
      type: Boolean,
      default: false,
    },
  },

  // Configuración de sesión específica por rol
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
    badgeText: {
      type: String,
      maxlength: 20,
    },
    sortOrder: {
      type: Number,
      default: 0,
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
    avgSessionDuration: {
      type: Number,
      default: 0,
      min: 0,
    },
    lastUsed: {
      type: Date,
    },
  },

  // Configuración de notificaciones por rol
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
        enum: ["email", "sms", "push", "inApp"],
      },
    ],
    dailyDigest: {
      type: Boolean,
      default: false,
    },
  },
});

// =======================================
// CONFIGURAR EL ESQUEMA CON BASE SCHEME
// =======================================

// Configurar el esquema con funcionalidades base
setupBaseSchema(RoleSchema, {
  addBaseFields: true, // Agregar campos base (isDeleted, createdAt, etc.)
  addTimestamps: true, // Agregar middleware de timestamps
  addIndexes: true, // Agregar índices comunes
  addVirtuals: true, // Agregar virtuals comunes
  addMethods: true, // Agregar métodos comunes (softDelete, restore, etc.)
  addStatics: true, // Agregar métodos estáticos (findActive, etc.)
  addHelpers: true, // Agregar query helpers (active(), deleted(), etc.)
});

// ================================
// ÍNDICES ESPECÍFICOS
// ================================

// Índices únicos
RoleSchema.index({ roleName: 1 }, { unique: true });

// Índices compuestos para consultas frecuentes
RoleSchema.index({ hierarchy: 1, isRoleActive: 1 });
RoleSchema.index({ isRoleActive: 1, isSystemRole: 1 });
RoleSchema.index({
  "metadata.category": 1,
  isRoleActive: 1,
  "metadata.sortOrder": 1,
});
RoleSchema.index({ parentRole: 1, hierarchy: 1 });
RoleSchema.index({ roleType: 1, isRoleActive: 1 });

// TTL index para roles con expiración
RoleSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Índices para restricciones
RoleSchema.index({ "companyRestrictions.allowedCompanies": 1 });
RoleSchema.index({ "geographicRestrictions.allowedCountries": 1 });

// Índices para campos multiidioma
RoleSchema.index({ "displayName.original.text": "text" });
RoleSchema.index({ "description.original.text": "text" });

// ================================
// VIRTUALS ESPECÍFICOS DEL ROL
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

RoleSchema.virtual("securityLevel").get(function () {
  if (this.hierarchy >= 90) return "critical";
  if (this.hierarchy >= 70) return "high";
  if (this.hierarchy >= 40) return "medium";
  return "standard";
});

// Virtual que combina el estado del rol con el soft delete
RoleSchema.virtual("isFullyActive").get(function () {
  return this.isRoleActive && !this.isDeleted && !this.isExpired;
});

// ================================
// MÉTODOS DE INSTANCIA
// ================================

// Método principal para verificar permisos
RoleSchema.methods.hasPermission = function (resource, action, scope = "own") {
  if (!this.isFullyActive) {
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

// Método para verificar permisos con contexto geográfico
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

// Métodos para gestión de permisos
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

// Métodos para gestión de empresas
RoleSchema.methods.canManageCompany = function (companyId = null) {
  if (!this.isFullyActive) {
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

// Método para verificar restricciones geográficas
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

// Método para obtener configuración de sesión efectiva
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

// Método para verificar si requiere aprobación
RoleSchema.methods.requiresApprovalFor = function (resource, action) {
  const permission = this.permissions.find(
    (p) => p.resource === resource || p.resource === "all"
  );

  if (!permission) return false;

  const criticalActions = ["delete", "manage", "admin"];
  const requiresApprovalActions = permission.conditions?.requiresApproval || [];

  return (
    (criticalActions.includes(action) && this.hierarchy < 80) ||
    requiresApprovalActions.includes(action)
  );
};

// Método para obtener resumen de permisos
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

// Métodos para trabajar con campos multiidioma
RoleSchema.methods.getDisplayName = function (
  language = DEFAULT_LANGUAGE,
  fallbackLanguages = ["en", "es"]
) {
  if (!this.displayName) return this.roleName;

  const result = this.displayName.getText(language, fallbackLanguages);
  return result.text;
};

RoleSchema.methods.getDescription = function (
  language = DEFAULT_LANGUAGE,
  fallbackLanguages = ["en", "es"]
) {
  if (!this.description) return "";

  const result = this.description.getText(language, fallbackLanguages);
  return result.text;
};

// ================================
// MÉTODOS ESTÁTICOS
// ================================

RoleSchema.statics.findByName = function (roleName) {
  return this.findOne({
    roleName: roleName.toLowerCase(),
    isRoleActive: true,
  }).active(); // Usar query helper del base
};

RoleSchema.statics.findByHierarchy = function (minLevel = 0, maxLevel = 100) {
  return this.find({
    hierarchy: { $gte: minLevel, $lte: maxLevel },
    isRoleActive: true,
  })
    .active()
    .sort({ hierarchy: 1 });
};

RoleSchema.statics.getSystemRoles = function () {
  return this.find({
    isSystemRole: true,
    isRoleActive: true,
  })
    .active()
    .sort({ hierarchy: 1 });
};

RoleSchema.statics.getDefaultRole = function () {
  return this.findOne({
    isDefault: true,
    isRoleActive: true,
  }).active();
};

RoleSchema.statics.getRolesByType = function (roleType, options = {}) {
  const query = {
    roleType: roleType,
    isRoleActive: true,
  };

  let queryObj = this.find(query).active();

  if (options.populate) {
    queryObj = queryObj.populate(options.populate);
  }

  if (options.sortBy) {
    const sort = {};
    sort[options.sortBy] = options.sortOrder === "desc" ? -1 : 1;
    queryObj = queryObj.sort(sort);
  } else {
    queryObj = queryObj.sort({ "metadata.sortOrder": 1, hierarchy: -1 });
  }

  if (options.limit) {
    queryObj = queryObj.limit(options.limit);
  }

  return queryObj;
};

// Método para crear roles del sistema con soporte multiidioma
RoleSchema.statics.createSystemRoles = async function () {
  const { MultiLanguageContentSchema } = await import(
    "../../../modules/core/models/multi_language_pattern_improved.scheme.js"
  );

  const systemRoles = [
    {
      roleName: "super_admin",
      displayName: MultiLanguageContentSchema.statics.createAdvancedContent(
        "Super Administrador",
        "es",
        {
          targetLanguages: ["en", "fr"],
          autoTranslate: true,
        }
      ),
      description: MultiLanguageContentSchema.statics.createAdvancedContent(
        "Acceso completo al sistema con permisos administrativos totales",
        "es",
        {
          targetLanguages: ["en", "fr"],
          autoTranslate: true,
        }
      ),
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
      displayName: MultiLanguageContentSchema.statics.createAdvancedContent(
        "Propietario de Empresa",
        "es",
        {
          targetLanguages: ["en"],
          autoTranslate: true,
        }
      ),
      description: MultiLanguageContentSchema.statics.createAdvancedContent(
        "Propietario que puede gestionar completamente su empresa y ver reportes",
        "es",
        {
          targetLanguages: ["en"],
          autoTranslate: true,
        }
      ),
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
      displayName: MultiLanguageContentSchema.statics.createAdvancedContent(
        "Cliente",
        "es",
        {
          targetLanguages: ["en"],
          autoTranslate: true,
        }
      ),
      description: MultiLanguageContentSchema.statics.createAdvancedContent(
        "Usuario cliente con permisos básicos para ver empresas y crear reseñas",
        "es",
        {
          targetLanguages: ["en"],
          autoTranslate: true,
        }
      ),
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
        console.log(`✅ Rol del sistema creado: ${role.getDisplayName()}`);
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

  const userCount = await User.countActive({
    roles: roleId,
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

// Pre-save middleware específico del rol
RoleSchema.pre("save", async function (next) {
  if (this.roleName) {
    this.roleName = this.roleName.toLowerCase().trim();
  }

  // Validación de jerarquía con rol padre
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

  // Asegurar que solo hay un rol por defecto
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
    console.log(`✅ Rol creado: ${doc.getDisplayName()}`);
  }
  next();
});

// ================================
// CONFIGURACIÓN ADICIONAL
// ================================

// Configurar transformación JSON
RoleSchema.set("toJSON", {
  virtuals: true,
  transform: function (doc, ret) {
    // Eliminar campos internos
    delete ret.__v;

    // Transformar campos multiidioma para respuesta
    if (ret.displayName && typeof ret.displayName.getText === "function") {
      ret.displayNameText = ret.displayName.getText();
    }

    if (ret.description && typeof ret.description.getText === "function") {
      ret.descriptionText = ret.description.getText();
    }

    return ret;
  },
});

// ================================
// EXPORTAR MODELO
// ================================

export const Role = mongoose.model("Role", RoleSchema);
export default Role;
