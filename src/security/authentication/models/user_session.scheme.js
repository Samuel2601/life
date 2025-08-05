// =============================================================================
// src/models/auth/UserSession.js
// =============================================================================
import mongoose from "mongoose";
import {
  BaseSchemeFields,
  addTimestampMiddleware,
} from "../../../modules/core/models/base.scheme.js";

// Schema para información del dispositivo
const DeviceInfoSchema = new mongoose.Schema(
  {
    browser: String,
    os: String,
    device: String,
    isMobile: {
      type: Boolean,
      default: false,
    },
    screenResolution: String,
    timezone: String,
  },
  { _id: false }
);

// Schema para información geográfica
const LocationInfoSchema = new mongoose.Schema(
  {
    country: String,
    city: String,
    coordinates: {
      type: [Number], // [longitude, latitude]
      index: "2dsphere",
    },
    isVpnDetected: {
      type: Boolean,
      default: false,
    },
  },
  { _id: false }
);

// Schema para actividad sospechosa
const SuspiciousActivitySchema = new mongoose.Schema(
  {
    activityType: {
      type: String,
      enum: [
        "device_change",
        "location_change",
        "unusual_access",
        "concurrent_session",
      ],
      required: true,
    },
    description: {
      type: String,
      required: true,
      maxlength: 500,
    },
    timestamp: {
      type: Date,
      default: Date.now,
    },
    severity: {
      type: String,
      enum: ["low", "medium", "high"],
      default: "medium",
    },
    resolved: {
      type: Boolean,
      default: false,
    },
  },
  { _id: false }
);

// Schema para cambios de fingerprint
const FingerprintChangeSchema = new mongoose.Schema(
  {
    newFingerprint: {
      type: String,
      required: true,
    },
    changedAt: {
      type: Date,
      default: Date.now,
    },
    suspiciousChange: {
      type: Boolean,
      default: false,
    },
    validatedByUser: {
      type: Boolean,
      default: false,
    },
  },
  { _id: false }
);

// Schema para datos OAuth
const OAuthSessionDataSchema = new mongoose.Schema(
  {
    accessToken: {
      type: String,
      required: true,
      select: false, // Nunca incluir en queries
    },
    refreshToken: {
      type: String,
      select: false,
    },
    expiresAt: {
      type: Date,
      required: true,
    },
    scope: [String],
  },
  { _id: false }
);

const UserSessionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true,
  },

  // Tokens seguros (nunca en requests)
  accessToken: {
    type: String,
    required: true,
    select: false, // Nunca incluir en queries por defecto
  },
  refreshToken: {
    type: String,
    required: true,
    select: false,
  },
  sessionToken: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },

  // Device Fingerprinting
  deviceFingerprint: {
    type: String,
    required: true,
    index: true,
  },
  originalFingerprint: {
    type: String,
    required: true,
  },
  fingerprintChanges: [FingerprintChangeSchema],

  // Estado de sesión
  isActive: {
    type: Boolean,
    default: true,
    index: true,
  },
  expiresAt: {
    type: Date,
    required: true,
    index: 1, // TTL index
  },
  lastAccessedAt: {
    type: Date,
    default: Date.now,
    index: true,
  },

  // Información del cliente
  ipAddress: {
    type: String,
    required: true,
    index: true,
  },
  userAgent: {
    type: String,
    required: true,
  },
  deviceInfo: DeviceInfoSchema,
  location: LocationInfoSchema,

  // OAuth session data (si aplica)
  oauthProvider: {
    type: String,
    enum: ["google", "facebook", "apple", "microsoft"],
  },
  oauthSessionData: OAuthSessionDataSchema,

  // Control de seguridad
  isCompromised: {
    type: Boolean,
    default: false,
    index: true,
  },
  invalidationReason: String,
  suspiciousActivity: [SuspiciousActivitySchema],

  // Configuración de sesión
  rememberMe: {
    type: Boolean,
    default: false,
  },
  maxInactivityMinutes: {
    type: Number,
    default: 60,
  },
  autoLogoutWarningShown: Date,

  ...BaseSchemeFields,
});

// Índices específicos para seguridad y rendimiento
UserSessionSchema.index({ sessionToken: 1 }, { unique: true });
UserSessionSchema.index({ userId: 1, isActive: 1 });
UserSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // TTL automático
UserSessionSchema.index({ userId: 1, createdAt: -1 });
UserSessionSchema.index({ ipAddress: 1, userId: 1, createdAt: -1 }); // Monitoreo seguridad
UserSessionSchema.index({ deviceFingerprint: 1, userId: 1 });

addTimestampMiddleware(UserSessionSchema);

// Método para verificar si la sesión es válida
UserSessionSchema.methods.isValid = function () {
  return (
    this.isActive &&
    !this.isCompromised &&
    this.expiresAt > new Date() &&
    (!this.lockUntil || this.lockUntil < new Date())
  );
};

// Método para marcar actividad sospechosa
UserSessionSchema.methods.flagSuspiciousActivity = function (
  activityType,
  description,
  severity = "medium"
) {
  this.suspiciousActivity.push({
    activityType,
    description,
    severity,
    timestamp: new Date(),
  });

  if (severity === "high") {
    this.isCompromised = true;
  }
};

export const UserSession = mongoose.model("UserSession", UserSessionSchema);
