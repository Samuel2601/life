// =============================================================================
// src/modules/authentication/models/user/index.js
// =============================================================================

// Exportar el modelo principal
export { User, default } from "./user.model.js";

// Exportar schemas individuales si se necesitan en otros lugares
export * from "./schemas/index.js";

// Exportar funciones de configuración si se necesitan para otros modelos
export { setupUserVirtuals } from "./virtuals/index.js";
export { setupInstanceMethods, setupStaticMethods } from "./methods/index.js";
export {
  setupPreSaveMiddleware,
  setupPostSaveMiddleware,
} from "./middleware/index.js";
export { setupUserIndexes } from "./indexes/index.js";
