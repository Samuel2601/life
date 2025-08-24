// =============================================================================
// src/modules/authentication/models/user/schemas/preferences.schema.js
// =============================================================================
import mongoose from "mongoose";
import {
  SUPPORTED_LANGUAGES,
  DEFAULT_LANGUAGE,
} from "../../../../core/models/multi_language_pattern.scheme.js";

/**
 * Schema de preferencias de notificaciones
 */
export const NotificationPreferencesSchema = new mongoose.Schema(
  {
    email: { type: Boolean, default: true },
    push: { type: Boolean, default: true },
    sms: { type: Boolean, default: false },
    marketing: { type: Boolean, default: false },
    newBusinessAlert: { type: Boolean, default: true },
    reviewResponses: { type: Boolean, default: true },
    weeklyDigest: { type: Boolean, default: true },
  },
  { _id: false }
);

/**
 * Schema de preferencias de privacidad
 */
export const PrivacyPreferencesSchema = new mongoose.Schema(
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
  },
  { _id: false }
);

/**
 * Schema de preferencias de negocio
 */
export const BusinessPreferencesSchema = new mongoose.Schema(
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
  },
  { _id: false }
);

/**
 * Schema principal de preferencias de usuario
 */
export const UserPreferencesSchema = new mongoose.Schema(
  {
    language: {
      type: String,
      enum: SUPPORTED_LANGUAGES,
      default: DEFAULT_LANGUAGE,
    },
    timezone: {
      type: String,
      default: "America/Lima",
    },
    notifications: NotificationPreferencesSchema,
    privacy: PrivacyPreferencesSchema,
    business: BusinessPreferencesSchema,
  },
  { _id: false }
);
