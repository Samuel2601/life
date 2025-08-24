// =============================================================================
// src/modules/authentication/models/user/schemas/metadata.schema.js
// =============================================================================
import mongoose from "mongoose";

/**
 * Schema de detalles de registro
 */
export const RegistrationDetailsSchema = new mongoose.Schema(
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
  },
  { _id: false }
);

/**
 * Schema de seguimiento de actividad
 */
export const ActivityTrackingSchema = new mongoose.Schema(
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
  },
  { _id: false }
);

/**
 * Schema de flags de privacidad
 */
export const PrivacyFlagsSchema = new mongoose.Schema(
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
  },
  { _id: false }
);

/**
 * Schema principal de metadata
 */
export const MetadataSchema = new mongoose.Schema(
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
  },
  { _id: false }
);
