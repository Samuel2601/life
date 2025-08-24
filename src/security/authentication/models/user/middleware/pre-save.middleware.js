// =============================================================================
// src/modules/authentication/models/user/middleware/pre-save.middleware.js
// =============================================================================

/**
 * Configurar middleware pre-save para el schema de Usuario
 * @param {mongoose.Schema} schema - El schema al que agregar el middleware
 */
export function setupPreSaveMiddleware(schema) {
  schema.pre("save", function (next) {
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
}
