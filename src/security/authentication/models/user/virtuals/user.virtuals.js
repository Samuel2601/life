// =============================================================================
// src/modules/authentication/models/user/virtuals/user.virtuals.js
// =============================================================================

/**
 * Configurar virtuals para el schema de Usuario
 * @param {mongoose.Schema} schema - El schema al que agregar los virtuals
 */
export function setupUserVirtuals(schema) {
  // Virtual para nombre completo
  schema.virtual("fullName").get(function () {
    if (!this.profile) return "";
    return `${this.profile.firstName} ${this.profile.lastName}`.trim();
  });

  // Virtual para edad
  schema.virtual("age").get(function () {
    if (!this.profile?.dateOfBirth) return null;

    const today = new Date();
    const birthDate = new Date(this.profile.dateOfBirth);
    let age = today.getFullYear() - birthDate.getFullYear();
    const monthDifference = today.getMonth() - birthDate.getMonth();

    if (
      monthDifference < 0 ||
      (monthDifference === 0 && today.getDate() < birthDate.getDate())
    ) {
      age--;
    }

    return age;
  });

  // Virtual para verificar si está bloqueado
  schema.virtual("isLocked").get(function () {
    return !!(this.lockUntil && this.lockUntil > Date.now());
  });

  // Virtual para verificar si tiene OAuth conectado
  schema.virtual("hasOAuth").get(function () {
    if (!this.oauthProviders) return false;

    return !!(
      this.oauthProviders.google?.providerId ||
      this.oauthProviders.facebook?.providerId ||
      this.oauthProviders.apple?.providerId ||
      this.oauthProviders.microsoft?.providerId
    );
  });
}
