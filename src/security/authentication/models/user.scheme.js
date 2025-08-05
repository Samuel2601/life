// =============================================================================
// src/modules/authentication/models/user.scheme.js
// =============================================================================
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import {
  BaseSchemeFields,
  setupBaseSchema,
  CommonValidators,
} from "../../../modules/core/models/base.scheme.js";
import {
  SUPPORTED_LANGUAGES,
  DEFAULT_LANGUAGE,
} from "../../../modules/core/models/multi_language_pattern.scheme.js";

/**
 * Schema de perfil de usuario
 */
const UserProfileSchema = new mongoose.Schema(
  {
    firstName: {
      type: String,
      required: [true, "El nombre es requerido"],
      trim: true,
      maxlength: [50, "El nombre no puede exceder 50 caracteres"],
      minlength: [2, "El nombre debe tener al menos 2 caracteres"],
    },
    lastName: {
      type: String,
      required: [true, "El apellido es requerido"],
      trim: true,
      maxlength: [50, "El apellido no puede exceder 50 caracteres"],
      minlength: [2, "El apellido debe tener al menos 2 caracteres"],
    },
    avatar: {
      type: String,
      validate: CommonValidators.url,
      default: null,
    },
    dateOfBirth: {
      type: Date,
      validate: {
        validator: function (v) {
          return !v || v <= new Date();
        },
        message: "La fecha de nacimiento no puede ser futura",
      },
    },
    phone: {
      type: String,
      trim: true,
      maxlength: [20, "El teléfono no puede exceder 20 caracteres"],
      validate: CommonValidators.phone,
    },
    bio: {
      type: String,
      maxlength: [500, "La biografía no puede exceder 500 caracteres"],
      trim: true,
    },
    website: {
      type: String,
      validate: CommonValidators.url,
    },
    // Estado de registro
    isActive: {
      type: Boolean,
      default: true,
      index: true,
    },
  },
  { _id: false }
);

/**
 * Schema para proveedores OAuth
 */
const OAuthProviderSchema = new mongoose.Schema(
  {
    providerId: {
      type: String,
      required: true,
      index: true,
    },
    email: {
      type: String,
      required: true,
      validate: CommonValidators.email,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    connectedAt: {
      type: Date,
      default: Date.now,
    },
    lastUsed: {
      type: Date,
      default: Date.now,
    },
  },
  { _id: false }
);

/**
 * Schema principal de Usuario
 */
const UserSchema = new mongoose.Schema({
  // Autenticación principal
  email: {
    type: String,
    required: [true, "El email es requerido"],
    unique: true,
    lowercase: true,
    trim: true,
    validate: CommonValidators.email,
    index: true,
  },

  passwordHash: {
    type: String,
    select: false, // No incluir en queries por defecto
    validate: {
      validator: function (v) {
        // Solo validar si se está estableciendo una contraseña
        return !v || v.length >= 6;
      },
      message: "El hash de contraseña debe tener al menos 6 caracteres",
    },
  },

  // Perfil de usuario
  profile: {
    type: UserProfileSchema,
    required: true,
  },

  // OAuth providers (sin tokens - solo información de conexión)
  oauthProviders: {
    google: OAuthProviderSchema,
    facebook: OAuthProviderSchema,
    apple: OAuthProviderSchema,
    microsoft: OAuthProviderSchema,
  },

  // Roles y permisos
  roles: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Role",
      index: true,
    },
  ],

  isEmailVerified: {
    type: Boolean,
    default: false,
    index: true,
  },

  emailVerificationToken: {
    type: String,
    select: false,
    index: { expires: "24h" }, // TTL index para tokens de verificación
  },

  emailVerificationExpires: {
    type: Date,
  },

  // Seguridad
  passwordResetToken: {
    type: String,
    select: false,
    index: { expires: "1h" }, // TTL index para tokens de reset
  },

  passwordResetExpires: {
    type: Date,
  },

  lastLoginAt: {
    type: Date,
    index: true,
  },

  lastLoginIP: {
    type: String,
  },

  loginAttempts: {
    type: Number,
    default: 0,
    max: 10,
  },

  lockUntil: {
    type: Date,
  },

  // Configuración de seguridad
  twoFactorEnabled: {
    type: Boolean,
    default: false,
  },

  twoFactorSecret: {
    type: String,
    select: false,
  },

  // Preferencias de usuario
  preferences: {
    language: {
      type: String,
      enum: SUPPORTED_LANGUAGES,
      default: DEFAULT_LANGUAGE,
      index: true,
    },
    timezone: {
      type: String,
      default: "America/Lima",
    },
    notifications: {
      email: {
        type: Boolean,
        default: true,
      },
      push: {
        type: Boolean,
        default: true,
      },
      sms: {
        type: Boolean,
        default: false,
      },
      marketing: {
        type: Boolean,
        default: false,
      },
    },
    privacy: {
      profileVisible: {
        type: Boolean,
        default: true,
      },
      allowDataCollection: {
        type: Boolean,
        default: true,
      },
      allowLocationTracking: {
        type: Boolean,
        default: false,
      },
    },
  },

  // Metadatos adicionales
  metadata: {
    registrationSource: {
      type: String,
      enum: ["web", "mobile", "api", "oauth", "invitation"],
      default: "web",
    },
    lastActiveAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
    totalLogins: {
      type: Number,
      default: 0,
      min: 0,
    },
    averageSessionDuration: {
      type: Number,
      default: 0,
      min: 0,
    },
  },

  // Campos base (auditoría, soft delete, etc.)
  ...BaseSchemeFields,
});

// Configurar el esquema con funcionalidades base
setupBaseSchema(UserSchema, {
  addBaseFields: false, // Ya los agregamos manualmente arriba
});

// ================================
// ÍNDICES ESPECÍFICOS
// ================================

// Índices únicos
UserSchema.index({ email: 1 }, { unique: true });

// Índices para OAuth
UserSchema.index({ "oauthProviders.google.providerId": 1 }, { sparse: true });
UserSchema.index({ "oauthProviders.facebook.providerId": 1 }, { sparse: true });
UserSchema.index({ "oauthProviders.apple.providerId": 1 }, { sparse: true });
UserSchema.index(
  { "oauthProviders.microsoft.providerId": 1 },
  { sparse: true }
);

// Índices para autenticación y seguridad
UserSchema.index({ isActive: 1, isEmailVerified: 1 });
UserSchema.index({ emailVerificationToken: 1 }, { sparse: true });
UserSchema.index({ passwordResetToken: 1 }, { sparse: true });
UserSchema.index({ lockUntil: 1 }, { sparse: true });

// Índices para búsqueda y filtrado
UserSchema.index({ "preferences.language": 1 });
UserSchema.index({ "metadata.lastActiveAt": -1 });
UserSchema.index({ lastLoginAt: -1 });

// Índice de texto para búsqueda
UserSchema.index(
  {
    "profile.firstName": "text",
    "profile.lastName": "text",
    email: "text",
  },
  {
    name: "user_search_index",
    weights: {
      "profile.firstName": 10,
      "profile.lastName": 10,
      email: 5,
    },
  }
);

// ================================
// VIRTUALS
// ================================

// Virtual para nombre completo
UserSchema.virtual("fullName").get(function () {
  if (!this.profile) return "";
  return `${this.profile.firstName} ${this.profile.lastName}`.trim();
});

// Virtual para edad
UserSchema.virtual("age").get(function () {
  if (!this.profile?.dateOfBirth) return null;

  const today = new Date();
  const birthDate = new Date(this.profile.dateOfBirth);
  let age = today.getFullYear() - birthDate.getFullYear();
  const monthDifference = today.getMonth() - birthDate.getMonth();

  if (
    monthDifference < 0 ||
    (monthDifference === 0 && today.getDate() < birthDate.getDate())
  ) {
    age--;
  }

  return age;
});

// Virtual para verificar si está bloqueado
UserSchema.virtual("isLocked").get(function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Virtual para verificar si tiene OAuth conectado
UserSchema.virtual("hasOAuth").get(function () {
  if (!this.oauthProviders) return false;

  return !!(
    this.oauthProviders.google?.providerId ||
    this.oauthProviders.facebook?.providerId ||
    this.oauthProviders.apple?.providerId ||
    this.oauthProviders.microsoft?.providerId
  );
});

// ================================
// MÉTODOS DE INSTANCIA
// ================================

// Método para validar contraseña
UserSchema.methods.validatePassword = async function (password) {
  if (!this.passwordHash) return false;

  try {
    return await bcrypt.compare(password, this.passwordHash);
  } catch (error) {
    console.error("Error validando contraseña:", error);
    return false;
  }
};

// Método para establecer contraseña
UserSchema.methods.setPassword = async function (password) {
  if (!password || password.length < 8) {
    throw new Error("La contraseña debe tener al menos 8 caracteres");
  }

  const saltRounds = 12;
  this.passwordHash = await bcrypt.hash(password, saltRounds);
  return this;
};

// Método para verificar si está bloqueado
UserSchema.methods.checkLockStatus = function () {
  return {
    isLocked: this.isLocked,
    lockUntil: this.lockUntil,
    canRetry: !this.isLocked,
  };
};

// Método para incrementar intentos de login
UserSchema.methods.incrementLoginAttempts = async function () {
  // Si ya está bloqueado y el bloqueo ha expirado, resetear
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 },
    });
  }

  const updates = { $inc: { loginAttempts: 1 } };

  // Bloquear después de 5 intentos fallidos
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 horas
  }

  return this.updateOne(updates);
};

// Método para resetear intentos de login exitoso
UserSchema.methods.resetLoginAttempts = async function () {
  const updates = {
    $unset: { lockUntil: 1 },
    $set: {
      loginAttempts: 0,
      lastLoginAt: new Date(),
      "metadata.lastActiveAt": new Date(),
    },
    $inc: { "metadata.totalLogins": 1 },
  };

  return this.updateOne(updates);
};

// Método para conectar proveedor OAuth
UserSchema.methods.connectOAuthProvider = function (provider, providerData) {
  const allowedProviders = ["google", "facebook", "apple", "microsoft"];

  if (!allowedProviders.includes(provider)) {
    throw new Error(`Proveedor OAuth '${provider}' no es válido`);
  }

  if (!this.oauthProviders) {
    this.oauthProviders = {};
  }

  this.oauthProviders[provider] = {
    providerId: providerData.providerId,
    email: providerData.email,
    isVerified: providerData.isVerified || false,
    connectedAt: new Date(),
    lastUsed: new Date(),
  };

  return this;
};

// Método para desconectar proveedor OAuth
UserSchema.methods.disconnectOAuthProvider = function (provider) {
  if (this.oauthProviders && this.oauthProviders[provider]) {
    this.oauthProviders[provider] = undefined;
  }
  return this;
};

// Método para actualizar preferencias
UserSchema.methods.updatePreferences = function (newPreferences) {
  if (!this.preferences) {
    this.preferences = {};
  }

  // Merge profundo de preferencias
  this.preferences = {
    ...this.preferences,
    ...newPreferences,
    notifications: {
      ...this.preferences.notifications,
      ...newPreferences.notifications,
    },
    privacy: {
      ...this.preferences.privacy,
      ...newPreferences.privacy,
    },
  };

  return this;
};

// Método para generar token de verificación de email
UserSchema.methods.generateEmailVerificationToken = function () {
  const crypto = require("crypto");
  const token = crypto.randomBytes(32).toString("hex");

  this.emailVerificationToken = token;
  this.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 horas

  return token;
};

// Método para generar token de reset de contraseña
UserSchema.methods.generatePasswordResetToken = function () {
  const crypto = require("crypto");
  const token = crypto.randomBytes(32).toString("hex");

  this.passwordResetToken = token;
  this.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hora

  return token;
};

// ================================
// MÉTODOS ESTÁTICOS
// ================================

// Buscar usuario por email
UserSchema.statics.findByEmail = function (email) {
  return this.findOne({ email: email.toLowerCase() }).select("+passwordHash");
};

// Buscar usuario por token de verificación
UserSchema.statics.findByVerificationToken = function (token) {
  return this.findOne({
    emailVerificationToken: token,
    emailVerificationExpires: { $gt: Date.now() },
  });
};

// Buscar usuario por token de reset de contraseña
UserSchema.statics.findByPasswordResetToken = function (token) {
  return this.findOne({
    passwordResetToken: token,
    passwordResetExpires: { $gt: Date.now() },
  });
};

// Buscar usuarios activos con paginación
UserSchema.statics.findActiveUsers = function (options = {}) {
  const {
    page = 1,
    limit = 10,
    sortBy = "createdAt",
    sortOrder = -1,
    search = "",
    language = null,
  } = options;

  let query = this.find({
    isActive: true,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  });

  // Búsqueda por texto
  if (search) {
    query = query.find({
      $text: { $search: search },
    });
  }

  // Filtro por idioma
  if (language) {
    query = query.find({
      "preferences.language": language,
    });
  }

  // Ordenamiento
  const sort = {};
  sort[sortBy] = sortOrder;

  return query
    .sort(sort)
    .limit(limit * 1)
    .skip((page - 1) * limit)
    .populate("roles", "roleName displayName")
    .lean();
};

// Estadísticas de usuarios
UserSchema.statics.getUserStats = async function () {
  const stats = await this.aggregate([
    {
      $group: {
        _id: null,
        totalUsers: { $sum: 1 },
        activeUsers: {
          $sum: {
            $cond: [{ $eq: ["$isActive", true] }, 1, 0],
          },
        },
        verifiedUsers: {
          $sum: {
            $cond: [{ $eq: ["$isEmailVerified", true] }, 1, 0],
          },
        },
        deletedUsers: {
          $sum: {
            $cond: [{ $eq: ["$isDeleted", true] }, 1, 0],
          },
        },
        usersWithOAuth: {
          $sum: {
            $cond: [
              {
                $or: [
                  { $exists: ["$oauthProviders.google.providerId", true] },
                  { $exists: ["$oauthProviders.facebook.providerId", true] },
                  { $exists: ["$oauthProviders.apple.providerId", true] },
                  { $exists: ["$oauthProviders.microsoft.providerId", true] },
                ],
              },
              1,
              0,
            ],
          },
        },
      },
    },
    {
      $project: {
        _id: 0,
        totalUsers: 1,
        activeUsers: 1,
        verifiedUsers: 1,
        deletedUsers: 1,
        usersWithOAuth: 1,
        inactiveUsers: { $subtract: ["$totalUsers", "$activeUsers"] },
        verificationRate: {
          $multiply: [{ $divide: ["$verifiedUsers", "$totalUsers"] }, 100],
        },
        oauthAdoptionRate: {
          $multiply: [{ $divide: ["$usersWithOAuth", "$totalUsers"] }, 100],
        },
      },
    },
  ]);

  return (
    stats[0] || {
      totalUsers: 0,
      activeUsers: 0,
      verifiedUsers: 0,
      deletedUsers: 0,
      inactiveUsers: 0,
      usersWithOAuth: 0,
      verificationRate: 0,
      oauthAdoptionRate: 0,
    }
  );
};

// Usuarios por idioma
UserSchema.statics.getUsersByLanguage = async function () {
  return await this.aggregate([
    {
      $match: {
        isActive: true,
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      },
    },
    {
      $group: {
        _id: "$preferences.language",
        count: { $sum: 1 },
        users: {
          $push: {
            id: "$_id",
            fullName: {
              $concat: ["$profile.firstName", " ", "$profile.lastName"],
            },
            email: "$email",
            lastLoginAt: "$lastLoginAt",
          },
        },
      },
    },
    {
      $sort: { count: -1 },
    },
  ]);
};

// Limpiar tokens expirados
UserSchema.statics.cleanExpiredTokens = async function () {
  const result = await this.updateMany(
    {
      $or: [
        {
          emailVerificationExpires: { $lt: new Date() },
          emailVerificationToken: { $exists: true },
        },
        {
          passwordResetExpires: { $lt: new Date() },
          passwordResetToken: { $exists: true },
        },
      ],
    },
    {
      $unset: {
        emailVerificationToken: 1,
        emailVerificationExpires: 1,
        passwordResetToken: 1,
        passwordResetExpires: 1,
      },
    }
  );

  return result;
};

// ================================
// MIDDLEWARES
// ================================

// Pre-save middleware para validaciones adicionales
UserSchema.pre("save", function (next) {
  // Normalizar email
  if (this.email) {
    this.email = this.email.toLowerCase().trim();
  }

  // Validar que tenga al menos una forma de autenticación
  if (this.isNew && !this.passwordHash && !this.hasOAuth) {
    return next(
      new Error("El usuario debe tener contraseña o proveedor OAuth")
    );
  }

  // Actualizar metadata de actividad
  if (this.isModified("lastLoginAt")) {
    this.metadata.lastActiveAt = this.lastLoginAt;
  }

  // Limpiar tokens expirados automáticamente
  if (
    this.emailVerificationExpires &&
    this.emailVerificationExpires < new Date()
  ) {
    this.emailVerificationToken = undefined;
    this.emailVerificationExpires = undefined;
  }

  if (this.passwordResetExpires && this.passwordResetExpires < new Date()) {
    this.passwordResetToken = undefined;
    this.passwordResetExpires = undefined;
  }

  next();
});

// Post-save middleware para logging
UserSchema.post("save", function (doc, next) {
  // Log de creación de usuario (sin datos sensibles)
  if (doc.isNew) {
    console.log(`✅ Usuario creado: ${doc.email} (ID: ${doc._id})`);
  }
  next();
});

// ================================
// CONFIGURACIÓN ADICIONAL
// ================================

// Configurar opciones de transformación para JSON
UserSchema.set("toJSON", {
  virtuals: true,
  transform: function (doc, ret) {
    // Remover campos sensibles
    delete ret.passwordHash;
    delete ret.emailVerificationToken;
    delete ret.passwordResetToken;
    delete ret.twoFactorSecret;
    delete ret.__v;

    // Limpiar OAuth providers (solo mostrar si están conectados)
    if (ret.oauthProviders) {
      Object.keys(ret.oauthProviders).forEach((provider) => {
        if (
          ret.oauthProviders[provider] &&
          ret.oauthProviders[provider].providerId
        ) {
          // Solo mantener información no sensible
          ret.oauthProviders[provider] = {
            isConnected: true,
            email: ret.oauthProviders[provider].email,
            connectedAt: ret.oauthProviders[provider].connectedAt,
          };
        } else {
          delete ret.oauthProviders[provider];
        }
      });
    }

    return ret;
  },
});

// ================================
// EXPORTAR MODELO
// ================================

export const User = mongoose.model("User", UserSchema);
export default User;
