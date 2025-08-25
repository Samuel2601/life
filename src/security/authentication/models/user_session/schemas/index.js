// =============================================================================
// src/modules/authentication/models/user-session/schemas/index.js
// =============================================================================

// Exportar todos los schemas
export { DeviceInfoSchema } from "./device-info.schema.js";
export { LocationInfoSchema } from "./location-info.schema.js";
export { SuspiciousActivitySchema } from "./suspicious-activity.schema.js";
export { FingerprintChangeSchema } from "./fingerprint-changes.schema.js";
export { OAuthSessionDataSchema } from "./oauth-session.schema.js";
export { SessionCoreSchema } from "./session-core.schema.js";
export { SecuritySchema } from "./security.schema.js";
export { MetadataSchema } from "./metadata.schema.js";

// Función para combinar todos los schemas
export const combineUserSessionSchemas = () => {
  return {
    ...DeviceInfoSchema,
    ...LocationInfoSchema,
    ...SuspiciousActivitySchema,
    ...FingerprintChangeSchema,
    ...OAuthSessionDataSchema,
    ...SessionCoreSchema,
    ...SecuritySchema,
    ...MetadataSchema,
  };
};
