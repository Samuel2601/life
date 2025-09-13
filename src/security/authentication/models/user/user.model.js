// =============================================================================
// src/modules/authentication/models/user/user.model.js
// =============================================================================
import mongoose from "mongoose";
import {
  BaseSchemaFields,
  setupBaseSchema,
  CommonValidators,
} from "../../../core/models/base.scheme.js";

// Importar schemas
import {
  UserProfileSchema,
  OAuthProviderSchema,
  UserPreferencesSchema,
  MetadataSchema,
} from "./schemas/index.js";

// Importar configuraciones
import { setupUserVirtuals } from "./virtuals/index.js";
import { setupInstanceMethods, setupStaticMethods } from "./methods/index.js";
import {
  setupPreSaveMiddleware,
  setupPostSaveMiddleware,
} from "./middleware/index.js";
import { setupUserIndexes } from "./indexes/index.js";

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
    default: () => ({}),
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
    index: { expires: "24h" }, // TTL index para tokens de verificación
  },

  emailVerificationExpires: {
    type: Date,
    select: false,
  },

  // Seguridad
  passwordResetToken: {
    type: String,
    select: false,
    index: { expires: "1h" }, // TTL index para tokens de reset
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

  // Preferencias de usuario
  preferences: {
    type: UserPreferencesSchema,
    default: () => ({}),
  },

  // Metadatos adicionales
  metadata: {
    type: MetadataSchema,
    default: () => ({}),
  },

  // Campos base (auditoría, soft delete, etc.)
  ...BaseSchemaFields,
});

// ================================
// CONFIGURAR FUNCIONALIDADES
// ================================

// Configurar el esquema con funcionalidades base
setupBaseSchema(UserSchema, {
  addBaseFields: false, // Ya los agregamos manualmente arriba
});

// Configurar índices
setupUserIndexes(UserSchema);

// Configurar virtuals
setupUserVirtuals(UserSchema);

// Configurar métodos
setupInstanceMethods(UserSchema);
setupStaticMethods(UserSchema);

// Configurar middlewares
setupPreSaveMiddleware(UserSchema);
setupPostSaveMiddleware(UserSchema);

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
