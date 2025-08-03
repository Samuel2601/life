// =============================================================================
// src/models/auth/User.js
// =============================================================================
import mongoose from "mongoose";
import {
  BaseSchemeFields,
  addTimestampMiddleware,
  addCommonIndexes,
} from "../base/BaseSchema.js";

// Schema de perfil de usuario
const UserProfileSchema = new mongoose.Schema(
  {
    firstName: {
      type: String,
      required: true,
      trim: true,
      maxlength: 50,
    },
    lastName: {
      type: String,
      required: true,
      trim: true,
      maxlength: 50,
    },
    avatar: {
      type: String,
      validate: {
        validator: function (v) {
          return !v || /^https?:\/\/.+/.test(v);
        },
        message: "Avatar debe ser una URL válida",
      },
    },
    dateOfBirth: {
      type: Date,
    },
    phone: {
      type: String,
      trim: true,
      maxlength: 20,
    },
  },
  { _id: false }
);

// Schema para proveedores OAuth
const OAuthProviderSchema = new mongoose.Schema(
  {
    providerId: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
  },
  { _id: false }
);

const UserSchema = new mongoose.Schema({
  // Autenticación principal
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    validate: {
      validator: function (v) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
      },
      message: "Email inválido",
    },
  },
  passwordHash: {
    type: String,
    select: false, // No incluir en queries por defecto
  },

  // Perfil de usuario
  profile: {
    type: UserProfileSchema,
    required: true,
  },

  // OAuth providers (sin tokens)
  oauthProviders: {
    google: OAuthProviderSchema,
    facebook: OAuthProviderSchema,
    apple: OAuthProviderSchema,
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
  },
  emailVerificationToken: {
    type: String,
    select: false,
  },
  emailVerificationExpires: {
    type: Date,
  },

  // Seguridad
  passwordResetToken: {
    type: String,
    select: false,
  },
  passwordResetExpires: {
    type: Date,
  },
  lastLoginAt: {
    type: Date,
    index: true,
  },
  loginAttempts: {
    type: Number,
    default: 0,
  },
  lockUntil: {
    type: Date,
  },

  // Preferencias
  preferredLanguage: {
    type: String,
    enum: ["es", "en", "fr", "de", "pt", "it", "zh", "ja", "ko", "ar"],
    default: "es",
  },
  timezone: {
    type: String,
    default: "America/Lima",
  },

  ...BaseSchemeFields,
});

// Índices específicos
UserSchema.index({ email: 1 }, { unique: true });
UserSchema.index({ "oauthProviders.google.providerId": 1 }, { sparse: true });
UserSchema.index({ "oauthProviders.facebook.providerId": 1 }, { sparse: true });
UserSchema.index({ isActive: 1, isEmailVerified: 1 });
UserSchema.index({ preferredLanguage: 1 });

// Middleware y índices comunes
addTimestampMiddleware(UserSchema);
addCommonIndexes(UserSchema);

// Virtual para nombre completo
UserSchema.virtual("fullName").get(function () {
  return `${this.profile.firstName} ${this.profile.lastName}`;
});

// Método para verificar si está bloqueado
UserSchema.methods.isLocked = function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

export const User = mongoose.model("User", UserSchema);
