// =============================================================================
// src/modules/authentication/models/user/schemas/index.js
// =============================================================================

export { UserProfileSchema } from "./profile.schema.js";
export { OAuthProviderSchema } from "./oauth.schema.js";
export {
  NotificationPreferencesSchema,
  PrivacyPreferencesSchema,
  BusinessPreferencesSchema,
  UserPreferencesSchema,
} from "./preferences.schema.js";
export {
  RegistrationDetailsSchema,
  ActivityTrackingSchema,
  PrivacyFlagsSchema,
  MetadataSchema,
} from "./metadata.schema.js";
