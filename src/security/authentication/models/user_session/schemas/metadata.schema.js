// =============================================================================
// src/modules/authentication/models/user-session/schemas/metadata.schema.js
// =============================================================================

/**
 * Metadatos de sesión (expandidos)
 */
export const MetadataSchema = {
  metadata: {
    totalRequests: {
      type: Number,
      default: 0,
    },
    lastRequestAt: {
      type: Date,
    },
    creationMethod: {
      type: String,
      enum: ["password", "oauth", "sso", "token_refresh", "magic_link"],
      default: "password",
    },
    sessionDuration: {
      type: Number, // Duración en minutos
    },
    // Métricas empresariales
    businessMetrics: {
      companiesAccessed: [String], // IDs de empresas accedidas
      featuresUsed: [String], // Funcionalidades utilizadas
      apiCallsCount: {
        type: Number,
        default: 0,
      },
      avgResponseTime: {
        type: Number,
        default: 0,
      },
    },
    // Información de compliance
    compliance: {
      dataProcessingAgreed: {
        type: Boolean,
        default: false,
      },
      gdprApplicable: {
        type: Boolean,
        default: false,
      },
      auditTrailEnabled: {
        type: Boolean,
        default: true,
      },
    },
  },
};
