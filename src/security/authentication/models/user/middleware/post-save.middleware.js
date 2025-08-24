// =============================================================================
// src/modules/authentication/models/user/middleware/post-save.middleware.js
// =============================================================================

/**
 * Configurar middleware post-save para el schema de Usuario
 * @param {mongoose.Schema} schema - El schema al que agregar el middleware
 */
export function setupPostSaveMiddleware(schema) {
  schema.post("save", function (doc, next) {
    // Log de creación de usuario (sin datos sensibles)
    if (doc.isNew) {
      console.log(`✅ Usuario creado: ${doc.email} (ID: ${doc._id})`);
    }
    next();
  });
}
