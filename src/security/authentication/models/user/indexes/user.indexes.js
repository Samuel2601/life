// =============================================================================
// src/modules/authentication/models/user/indexes/user.indexes.js
// =============================================================================

/**
 * Configurar índices para el schema de Usuario
 * @param {mongoose.Schema} schema - El schema al que agregar los índices
 */
export function setupUserIndexes(schema) {
  // Índices únicos
  schema.index({ email: 1 }, { unique: true });

  // Índices para OAuth
  schema.index({ "oauthProviders.google.providerId": 1 }, { sparse: true });
  schema.index({ "oauthProviders.facebook.providerId": 1 }, { sparse: true });
  schema.index({ "oauthProviders.apple.providerId": 1 }, { sparse: true });
  schema.index({ "oauthProviders.microsoft.providerId": 1 }, { sparse: true });

  // Índices para autenticación y seguridad
  schema.index({ isActive: 1, isEmailVerified: 1 });
  schema.index({ emailVerificationToken: 1 }, { sparse: true });
  schema.index({ passwordResetToken: 1 }, { sparse: true });
  schema.index({ lockUntil: 1 }, { sparse: true });

  // Índices para búsqueda y filtrado
  schema.index({ "preferences.language": 1 });
  schema.index({ "metadata.lastActiveAt": -1 });
  schema.index({ lastLoginAt: -1 });

  schema.index({
    "profile.firstName": 1,
    "profile.lastName": 1,
    email: 1,
  });

  // Índice de texto para búsqueda
  schema.index(
    {
      "profile.firstName": "text",
      "profile.lastName": "text",
      email: "text",
    },
    {
      name: "user_search_index",
      weights: {
        "profile.firstName": 10,
        "profile.lastName": 10,
        email: 5,
      },
    }
  );
}
