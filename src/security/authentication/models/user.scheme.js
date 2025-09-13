// =============================================================================
// src/modules/authentication/models/user.scheme.js - VERSIÓN MEJORADA CON MULTIIDIOMA
// Integración completa del patrón multiidioma manteniendo camelCase
// =============================================================================
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import crypto from "crypto";
import {
  BaseSchemaFields,
  setupBaseSchema,
  CommonValidators,
} from "../../../modules/core/models/base.scheme.js";
import {
  MultiLanguageContentSchema,
  createMultiLanguageField,
  SUPPORTED_LANGUAGES,
  DEFAULT_LANGUAGE,
} from "../../../modules/core/models/multi_language_pattern.scheme.js";

/**
 * Schema de perfil de usuario con soporte multiidioma
 */
const UserProfileSchema = new mongoose.Schema(
  {
    // Nombres con soporte multiidioma
    firstName: createMultiLanguageField(true, {
      validator: {
        validator: function (v) {
          return (
            v &&
            v.original &&
            v.original.text &&
            v.original.text.trim().length >= 2
          );
        },
        message: "El nombre debe tener al menos 2 caracteres",
      },
    }),

    lastName: createMultiLanguageField(true, {
      validator: {
        validator: function (v) {
          return (
            v &&
            v.original &&
            v.original.text &&
            v.original.text.trim().length >= 2
          );
        },
        message: "El apellido debe tener al menos 2 caracteres",
      },
    }),

    // Biografía con soporte multiidioma
    bio: createMultiLanguageField(false, {
      validator: {
        validator: function (v) {
          return (
            !v ||
            !v.original ||
            !v.original.text ||
            v.original.text.length <= 500
          );
        },
        message: "La biografía no puede exceder 500 caracteres",
      },
    }),

    // Campos que NO necesitan traducción (datos específicos del usuario)
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
    website: {
      type: String,
      validate: CommonValidators.url,
    },

    // Título/profesión con soporte multiidioma
    jobTitle: createMultiLanguageField(false),

    // Ubicación con soporte multiidioma
    location: createMultiLanguageField(false),

    // Intereses con soporte multiidioma
    interests: createMultiLanguageField(false),
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
 * Schema mejorado para detalles de registro
 */
const RegistrationDetailsSchema = new mongoose.Schema(
  {
    ipAddress: {
      type: String,
      default: "unknown",
      maxlength: 45, // IPv6 max length
    },
    userAgent: {
      type: String,
      default: "unknown",
      maxlength: 500,
    },
    referrer: {
      type: String,
      maxlength: 500,
      default: null,
    },
    utmSource: {
      type: String,
      maxlength: 100,
      default: null,
    },
    utmMedium: {
      type: String,
      maxlength: 100,
      default: null,
    },
    utmCampaign: {
      type: String,
      maxlength: 100,
      default: null,
    },
    companyContext: {
      type: String,
      maxlength: 200,
      default: null,
    },
    registrationLanguage: {
      type: String,
      enum: SUPPORTED_LANGUAGES,
      default: DEFAULT_LANGUAGE,
    },
    registrationTimezone: {
      type: String,
      default: "America/Lima",
    },
  },
  { _id: false }
);

/**
 * Schema para seguimiento de actividad mejorado
 */
const ActivityTrackingSchema = new mongoose.Schema(
  {
    firstLogin: {
      type: Date,
      default: null,
    },
    lastPasswordChange: {
      type: Date,
      default: Date.now,
    },
    profileCompleteness: {
      type: Number,
      min: 0,
      max: 1,
      default: 0,
    },
    accountVerificationLevel: {
      type: Number,
      min: 0,
      max: 1,
      default: 0,
    },
    lastProfileUpdate: {
      type: Date,
      default: Date.now,
    },
    lastPreferencesUpdate: {
      type: Date,
      default: Date.now,
    },
    lastSecurityUpdate: {
      type: Date,
      default: Date.now,
    },
    lastPrivacyUpdate: {
      type: Date,
      default: Date.now,
    },
    totalLanguageSwitches: {
      type: Number,
      default: 0,
    },
    mostUsedLanguages: [
      {
        language: {
          type: String,
          enum: SUPPORTED_LANGUAGES,
        },
        usageCount: {
          type: Number,
          default: 1,
        },
        lastUsed: {
          type: Date,
          default: Date.now,
        },
      },
    ],
  },
  { _id: false }
);

/**
 * Schema para flags de privacidad mejorado
 */
const PrivacyFlagsSchema = new mongoose.Schema(
  {
    dataConsentRevoked: {
      type: Boolean,
      default: false,
    },
    dataConsentRevokedAt: {
      type: Date,
      default: null,
    },
    requiresDataDeletion: {
      type: Boolean,
      default: false,
    },
    allowTranslationLogging: {
      type: Boolean,
      default: false,
    },
    shareTranslationData: {
      type: Boolean,
      default: false,
    },
  },
  { _id: false }
);

/**
 * Schema para metadatos mejorado con soporte multiidioma
 */
const MetadataSchema = new mongoose.Schema(
  {
    registrationSource: {
      type: String,
      enum: ["web", "mobile", "api", "oauth", "admin", "import"],
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
      min: 0, // En minutos
    },
    registrationDetails: RegistrationDetailsSchema,
    activityTracking: ActivityTrackingSchema,
    privacyFlags: PrivacyFlagsSchema,

    // Métricas de uso multiidioma
    multiLanguageMetrics: {
      totalTranslationsRequested: {
        type: Number,
        default: 0,
      },
      totalTranslationCost: {
        type: Number,
        default: 0,
      },
      preferredTranslationServices: [
        {
          service: {
            type: String,
            enum: ["openai", "google", "deepl", "azure", "aws"],
          },
          usageCount: {
            type: Number,
            default: 0,
          },
          avgQuality: {
            type: Number,
            default: 0,
          },
        },
      ],
    },
  },
  { _id: false }
);

/**
 * Schema para preferencias de notificaciones
 */
const NotificationPreferencesSchema = new mongoose.Schema(
  {
    email: { type: Boolean, default: true },
    push: { type: Boolean, default: true },
    sms: { type: Boolean, default: false },
    marketing: { type: Boolean, default: false },
    newBusinessAlert: { type: Boolean, default: true },
    reviewResponses: { type: Boolean, default: true },
    weeklyDigest: { type: Boolean, default: true },
    translationUpdates: { type: Boolean, default: false },
    languageContentAvailable: { type: Boolean, default: true },
  },
  { _id: false }
);

/**
 * Schema para preferencias de privacidad mejorado
 */
const PrivacyPreferencesSchema = new mongoose.Schema(
  {
    profileVisible: { type: Boolean, default: true },
    allowDataCollection: { type: Boolean, default: true },
    allowLocationTracking: { type: Boolean, default: false },
    showInSearch: { type: Boolean, default: true },
    allowBusinessContact: { type: Boolean, default: true },
    shareAnalytics: { type: Boolean, default: false },
    allowPersonalization: { type: Boolean, default: true },
    shareWithPartners: { type: Boolean, default: false },
    allowCookies: { type: Boolean, default: true },
    dataRetentionPeriod: {
      type: String,
      enum: ["1year", "2years", "5years", "unlimited"],
      default: "2years",
    },
    // Privacidad específica de traducciones
    allowTranslationTracking: { type: Boolean, default: false },
    shareTranslationData: { type: Boolean, default: false },
    allowLanguageRecommendations: { type: Boolean, default: true },
  },
  { _id: false }
);

/**
 * Schema para preferencias de negocio mejorado con multiidioma
 */
const BusinessPreferencesSchema = new mongoose.Schema(
  {
    preferredCategories: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "BusinessCategory",
      },
    ],
    searchRadius: {
      type: Number,
      min: 1,
      max: 100,
      default: 10, // km
    },
    defaultSortBy: {
      type: String,
      enum: ["distance", "rating", "name", "newest"],
      default: "distance",
    },
    showPrices: { type: Boolean, default: true },
    autoTranslate: { type: Boolean, default: true },
    preferredLanguages: [
      {
        type: String,
        enum: SUPPORTED_LANGUAGES,
      },
    ],
    notificationRadius: {
      type: Number,
      min: 1,
      max: 50,
      default: 5, // km
    },

    // Configuración de traducciones automáticas
    autoTranslationConfig: {
      enabled: { type: Boolean, default: true },
      targetLanguages: [
        {
          type: String,
          enum: SUPPORTED_LANGUAGES,
        },
      ],
      translationQuality: {
        type: String,
        enum: ["basic", "standard", "premium"],
        default: "standard",
      },
      maxTranslationCost: {
        type: Number,
        default: 5,
        min: 0,
      },
      preferredService: {
        type: String,
        enum: ["openai", "google", "deepl", "azure", "aws"],
        default: "openai",
      },
    },
  },
  { _id: false }
);

/**
 * Schema principal de preferencias de usuario mejorado
 */
const UserPreferencesSchema = new mongoose.Schema(
  {
    language: {
      type: String,
      enum: SUPPORTED_LANGUAGES,
      default: DEFAULT_LANGUAGE,
      index: true,
    },
    fallbackLanguages: [
      {
        type: String,
        enum: SUPPORTED_LANGUAGES,
      },
    ],
    timezone: {
      type: String,
      default: "America/Lima",
    },
    notifications: NotificationPreferencesSchema,
    privacy: PrivacyPreferencesSchema,
    business: BusinessPreferencesSchema,

    // Configuración específica de multiidioma
    languagePreferences: {
      autoDetect: { type: Boolean, default: true },
      showTranslationOptions: { type: Boolean, default: true },
      cacheTranslations: { type: Boolean, default: true },
      translationQuality: {
        type: String,
        enum: ["speed", "quality", "cost"],
        default: "quality",
      },
    },
  },
  { _id: false }
);

/**
 * Schema principal de Usuario mejorado con soporte multiidioma completo
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
        return !v || v.length >= 6;
      },
      message: "El hash de contraseña debe tener al menos 6 caracteres",
    },
  },

  // Perfil de usuario con soporte multiidioma
  profile: {
    type: UserProfileSchema,
    required: true,
    default: () => ({}),
  },

  // OAuth providers
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

  // Estado de cuenta
  isActive: {
    type: Boolean,
    default: true,
    index: true,
  },

  isEmailVerified: {
    type: Boolean,
    default: false,
    index: true,
  },

  emailVerificationToken: {
    type: String,
    select: false,
    index: { expires: "24h" },
  },

  emailVerificationExpires: {
    type: Date,
    select: false,
  },

  // Seguridad
  passwordResetToken: {
    type: String,
    select: false,
    index: { expires: "1h" },
  },

  passwordResetExpires: {
    type: Date,
    select: false,
  },

  lastLoginAt: {
    type: Date,
    index: true,
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

  // Preferencias de usuario mejoradas
  preferences: {
    type: UserPreferencesSchema,
    default: () => ({}),
  },

  // Metadatos adicionales mejorados
  metadata: {
    type: MetadataSchema,
    default: () => ({}),
  },

  // Campos base heredados
  ...BaseSchemaFields,
});

// Configurar el esquema con funcionalidades base
setupBaseSchema(UserSchema, {
  addBaseFields: false, // Ya los agregamos manualmente arriba
});

// ================================
// ÍNDICES ESPECÍFICOS MEJORADOS
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

// Índices para búsqueda y filtrado multiidioma
UserSchema.index({ "preferences.language": 1 });
UserSchema.index({ "preferences.fallbackLanguages": 1 });
UserSchema.index({ "metadata.lastActiveAt": -1 });
UserSchema.index({ lastLoginAt: -1 });

// Índices compuestos para multiidioma
UserSchema.index({
  "profile.firstName.original.language": 1,
  "profile.firstName.translationLanguages": 1,
  "preferences.language": 1,
});

UserSchema.index({
  "profile.lastName.original.language": 1,
  "profile.lastName.translationLanguages": 1,
  "preferences.language": 1,
});

// Índice de texto para búsqueda multiidioma
UserSchema.index(
  {
    "profile.firstName.original.text": "text",
    "profile.lastName.original.text": "text",
    "profile.bio.original.text": "text",
    email: "text",
  },
  {
    name: "user_multilang_search_index",
    weights: {
      "profile.firstName.original.text": 10,
      "profile.lastName.original.text": 10,
      "profile.bio.original.text": 5,
      email: 5,
    },
  }
);

// ================================
// VIRTUALS MEJORADOS CON MULTIIDIOMA
// ================================

// Virtual para nombre completo con soporte multiidioma
UserSchema.virtual("fullName").get(function () {
  if (!this.profile) return "";

  const language = this.preferences?.language || DEFAULT_LANGUAGE;
  const firstName = this.getProfileText("firstName", language);
  const lastName = this.getProfileText("lastName", language);

  return `${firstName} ${lastName}`.trim();
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

// Virtual para estadísticas de idiomas
UserSchema.virtual("languageStats").get(function () {
  if (!this.metadata?.activityTracking?.mostUsedLanguages) {
    return { primaryLanguage: this.preferences?.language || DEFAULT_LANGUAGE };
  }

  const stats = this.metadata.activityTracking.mostUsedLanguages.sort(
    (a, b) => b.usageCount - a.usageCount
  );

  return {
    primaryLanguage: this.preferences?.language || DEFAULT_LANGUAGE,
    mostUsed: stats[0]?.language,
    totalLanguages: stats.length,
    languages: stats,
  };
});

// ================================
// MÉTODOS DE INSTANCIA MEJORADOS CON MULTIIDIOMA
// ================================

// Método para obtener texto de perfil en idioma específico
UserSchema.methods.getProfileText = function (
  field,
  language = null,
  options = {}
) {
  const targetLanguage =
    language || this.preferences?.language || DEFAULT_LANGUAGE;
  const fallbackLanguages = this.preferences?.fallbackLanguages || ["en", "es"];

  if (!this.profile || !this.profile[field]) {
    return "";
  }

  const multiLangContent = this.profile[field];
  if (!multiLangContent.getText) {
    // Si no es un campo multiidioma, devolver como string
    return multiLangContent.toString();
  }

  const result = multiLangContent.getText(
    targetLanguage,
    fallbackLanguages,
    options
  );
  return result.text || "";
};

// Método para obtener perfil completo en idioma específico
UserSchema.methods.getLocalizedProfile = function (
  language = null,
  options = {}
) {
  const targetLanguage =
    language || this.preferences?.language || DEFAULT_LANGUAGE;

  return {
    firstName: this.getProfileText("firstName", targetLanguage, options),
    lastName: this.getProfileText("lastName", targetLanguage, options),
    fullName:
      this.getProfileText("firstName", targetLanguage, options) +
      " " +
      this.getProfileText("lastName", targetLanguage, options),
    bio: this.getProfileText("bio", targetLanguage, options),
    jobTitle: this.getProfileText("jobTitle", targetLanguage, options),
    location: this.getProfileText("location", targetLanguage, options),
    interests: this.getProfileText("interests", targetLanguage, options),
    // Campos que no necesitan traducción
    avatar: this.profile.avatar,
    dateOfBirth: this.profile.dateOfBirth,
    phone: this.profile.phone,
    website: this.profile.website,
  };
};

// Método para actualizar texto de perfil multiidioma
UserSchema.methods.updateProfileText = function (
  field,
  text,
  language = null,
  options = {}
) {
  const targetLanguage =
    language || this.preferences?.language || DEFAULT_LANGUAGE;

  if (!this.profile[field]) {
    // Si el campo no existe, crear contenido multiidioma
    this.profile[field] = {
      original: {
        language: targetLanguage,
        text: text,
        createdAt: new Date(),
        lastModified: new Date(),
      },
      translations: new Map(),
      translationLanguages: [],
      translationConfig: {
        autoTranslate: options.autoTranslate !== false,
        targetLanguages: options.targetLanguages || [],
      },
    };
  } else if (this.profile[field].original) {
    // Si es contenido multiidioma, actualizar
    if (this.profile[field].original.language === targetLanguage) {
      // Actualizar texto original
      this.profile[field].original.text = text;
      this.profile[field].original.lastModified = new Date();
    } else {
      // Agregar como traducción
      this.profile[field].addTranslation(targetLanguage, text, options);
    }
  }

  this.markModified(`profile.${field}`);
  return this;
};

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

// Método para cambiar idioma principal
UserSchema.methods.changeLanguage = function (newLanguage) {
  if (!SUPPORTED_LANGUAGES.includes(newLanguage)) {
    throw new Error(`Idioma '${newLanguage}' no está soportado`);
  }

  const oldLanguage = this.preferences.language;
  this.preferences.language = newLanguage;

  // Actualizar estadísticas de uso de idiomas
  if (!this.metadata.activityTracking.mostUsedLanguages) {
    this.metadata.activityTracking.mostUsedLanguages = [];
  }

  let langStat = this.metadata.activityTracking.mostUsedLanguages.find(
    (l) => l.language === newLanguage
  );

  if (!langStat) {
    langStat = {
      language: newLanguage,
      usageCount: 0,
      lastUsed: new Date(),
    };
    this.metadata.activityTracking.mostUsedLanguages.push(langStat);
  }

  langStat.usageCount++;
  langStat.lastUsed = new Date();
  this.metadata.activityTracking.totalLanguageSwitches++;

  return { oldLanguage, newLanguage };
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
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 },
    });
  }

  const updates = { $inc: { loginAttempts: 1 } };

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

// Método para actualizar preferencias mejorado
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
    business: {
      ...this.preferences.business,
      ...newPreferences.business,
      autoTranslationConfig: {
        ...this.preferences.business?.autoTranslationConfig,
        ...newPreferences.business?.autoTranslationConfig,
      },
    },
    languagePreferences: {
      ...this.preferences.languagePreferences,
      ...newPreferences.languagePreferences,
    },
  };

  this.metadata.activityTracking.lastPreferencesUpdate = new Date();
  return this;
};

// Método para generar token de verificación de email
UserSchema.methods.generateEmailVerificationToken = function () {
  const token = crypto.randomBytes(32).toString("hex");

  this.emailVerificationToken = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
  this.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 horas

  return token;
};

// Método para generar token de reset de contraseña
UserSchema.methods.generatePasswordResetToken = function () {
  const token = crypto.randomBytes(32).toString("hex");

  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
  this.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hora

  return token;
};

// ================================
// MÉTODOS ESTÁTICOS MEJORADOS CON MULTIIDIOMA
// ================================

// Buscar usuario por email
UserSchema.statics.findByEmail = function (email) {
  return this.findOne({ email: email.toLowerCase() }).select("+passwordHash");
};

// Buscar usuario por token de verificación
UserSchema.statics.findByVerificationToken = function (token) {
  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

  return this.findOne({
    emailVerificationToken: hashedToken,
    emailVerificationExpires: { $gt: Date.now() },
  });
};

// Buscar usuario por token de reset de contraseña
UserSchema.statics.findByPasswordResetToken = function (token) {
  const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

  return this.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });
};

// Buscar usuarios activos con soporte multiidioma
UserSchema.statics.findActiveUsers = function (options = {}) {
  const {
    page = 1,
    limit = 10,
    sortBy = "createdAt",
    sortOrder = -1,
    search = "",
    language = null,
    preferredLanguage = null,
  } = options;

  let query = this.find({
    isActive: true,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  });

  // Búsqueda por texto multiidioma
  if (search) {
    query = query.find({
      $or: [
        { $text: { $search: search } },
        {
          "profile.firstName.original.text": { $regex: search, $options: "i" },
        },
        { "profile.lastName.original.text": { $regex: search, $options: "i" } },
        { "profile.bio.original.text": { $regex: search, $options: "i" } },
      ],
    });
  }

  // Filtro por idioma de contenido
  if (language) {
    query = query.find({
      $or: [
        { "profile.firstName.original.language": language },
        { "profile.firstName.translationLanguages": language },
      ],
    });
  }

  // Filtro por idioma preferido del usuario
  if (preferredLanguage) {
    query = query.find({
      "preferences.language": preferredLanguage,
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

// Estadísticas de usuarios mejoradas con multiidioma
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
        multiLanguageUsers: {
          $sum: {
            $cond: [
              {
                $gt: [
                  {
                    $size: { $ifNull: ["$preferences.fallbackLanguages", []] },
                  },
                  0,
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
        multiLanguageUsers: 1,
        inactiveUsers: { $subtract: ["$totalUsers", "$activeUsers"] },
        verificationRate: {
          $multiply: [{ $divide: ["$verifiedUsers", "$totalUsers"] }, 100],
        },
        oauthAdoptionRate: {
          $multiply: [{ $divide: ["$usersWithOAuth", "$totalUsers"] }, 100],
        },
        multiLanguageAdoptionRate: {
          $multiply: [{ $divide: ["$multiLanguageUsers", "$totalUsers"] }, 100],
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
      multiLanguageUsers: 0,
      verificationRate: 0,
      oauthAdoptionRate: 0,
      multiLanguageAdoptionRate: 0,
    }
  );
};

// Usuarios por idioma mejorado
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
            email: "$email",
            lastLoginAt: "$lastLoginAt",
            fallbackLanguages: "$preferences.fallbackLanguages",
            totalLanguageSwitches:
              "$metadata.activityTracking.totalLanguageSwitches",
          },
        },
      },
    },
    {
      $sort: { count: -1 },
    },
  ]);
};

// Estadísticas de uso de multiidioma
UserSchema.statics.getMultiLanguageStats = async function () {
  return await this.aggregate([
    {
      $match: {
        isActive: true,
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      },
    },
    {
      $project: {
        primaryLanguage: "$preferences.language",
        fallbackLanguages: "$preferences.fallbackLanguages",
        autoTranslate: "$preferences.business.autoTranslationConfig.enabled",
        totalTranslations:
          "$metadata.multiLanguageMetrics.totalTranslationsRequested",
        totalCost: "$metadata.multiLanguageMetrics.totalTranslationCost",
        languageSwitches: "$metadata.activityTracking.totalLanguageSwitches",
      },
    },
    {
      $group: {
        _id: null,
        languageDistribution: {
          $push: {
            language: "$primaryLanguage",
            fallbacks: "$fallbackLanguages",
          },
        },
        totalTranslations: { $sum: "$totalTranslations" },
        totalTranslationCost: { $sum: "$totalCost" },
        avgLanguageSwitches: { $avg: "$languageSwitches" },
        autoTranslateEnabled: {
          $sum: {
            $cond: [{ $eq: ["$autoTranslate", true] }, 1, 0],
          },
        },
      },
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
// MIDDLEWARES MEJORADOS
// ================================

// Pre-save middleware para validaciones adicionales y multiidioma
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

  // Inicializar campos multiidioma si es necesario
  if (this.isNew && this.profile) {
    const userLanguage = this.preferences?.language || DEFAULT_LANGUAGE;

    // Inicializar firstName si no está configurado como multiidioma
    if (this.profile.firstName && typeof this.profile.firstName === "string") {
      const originalFirstName = this.profile.firstName;
      this.profile.firstName = {
        original: {
          language: userLanguage,
          text: originalFirstName,
          createdAt: new Date(),
          lastModified: new Date(),
        },
        translations: new Map(),
        translationLanguages: [],
        translationConfig: {
          autoTranslate: true,
          targetLanguages: [],
        },
      };
    }

    // Inicializar lastName si no está configurado como multiidioma
    if (this.profile.lastName && typeof this.profile.lastName === "string") {
      const originalLastName = this.profile.lastName;
      this.profile.lastName = {
        original: {
          language: userLanguage,
          text: originalLastName,
          createdAt: new Date(),
          lastModified: new Date(),
        },
        translations: new Map(),
        translationLanguages: [],
        translationConfig: {
          autoTranslate: true,
          targetLanguages: [],
        },
      };
    }
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
    console.log(
      `🌐 Idioma principal: ${doc.preferences?.language || DEFAULT_LANGUAGE}`
    );
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

    // Transformar campos multiidioma para respuesta simple
    if (ret.profile) {
      const userLanguage = doc.preferences?.language || DEFAULT_LANGUAGE;

      // Simplificar firstName si es multiidioma
      if (ret.profile.firstName && ret.profile.firstName.original) {
        ret.profile.firstName = doc.getProfileText("firstName", userLanguage);
      }

      // Simplificar lastName si es multiidioma
      if (ret.profile.lastName && ret.profile.lastName.original) {
        ret.profile.lastName = doc.getProfileText("lastName", userLanguage);
      }

      // Simplificar bio si es multiidioma
      if (ret.profile.bio && ret.profile.bio.original) {
        ret.profile.bio = doc.getProfileText("bio", userLanguage);
      }

      // Agregar fullName localizado
      ret.profile.fullName = doc.fullName;
    }

    // Limpiar OAuth providers (solo mostrar si están conectados)
    if (ret.oauthProviders) {
      Object.keys(ret.oauthProviders).forEach((provider) => {
        if (
          ret.oauthProviders[provider] &&
          ret.oauthProviders[provider].providerId
        ) {
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

    // Agregar estadísticas de idioma
    ret.languageStats = doc.languageStats;

    return ret;
  },
});

// ================================
// EXPORTAR MODELO
// ================================

export const User = mongoose.model("User", UserSchema);
export default User;
