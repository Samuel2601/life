// =============================================================================
// src/modules/authentication/models/user-session/schemas/oauth-session.schema.js
// Schema para datos OAuth seguros - NUNCA almacena tokens directos
// =============================================================================
import mongoose from "mongoose";

/**
 * Schema para datos OAuth (seguro - sin tokens directos)
 *
 * @description Maneja información de sesiones OAuth de forma segura,
 * almacenando solo hashes de tokens y metadatos necesarios.
 * NUNCA almacena tokens de acceso o refresh tokens en texto plano.
 */
export const OAuthSessionDataSchema = new mongoose.Schema(
  {
    // ================================
    // IDENTIFICACIÓN DEL PROVEEDOR
    // ================================

    provider: {
      type: String,
      enum: [
        "google",
        "facebook",
        "apple",
        "microsoft",
        "linkedin",
        "github",
        "twitter",
      ],
      required: true,
      index: true,
    },

    // ID único del usuario en el proveedor OAuth
    providerId: {
      type: String,
      required: true,
      index: true,
      maxlength: 100,
      validate: {
        validator: function (v) {
          return v && v.length > 0;
        },
        message: "Provider ID es requerido",
      },
    },

    // Email asociado con la cuenta OAuth
    email: {
      type: String,
      required: true,
      lowercase: true,
      trim: true,
      validate: {
        validator: function (v) {
          return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
        },
        message: "Email OAuth inválido",
      },
    },

    // ================================
    // TOKENS SEGUROS (SOLO HASHES)
    // ================================

    // CRÍTICO: Solo almacenar hashes de tokens, NUNCA tokens directos
    tokenHash: {
      type: String,
      required: true,
      select: false, // NUNCA incluir en queries por defecto
      length: 64, // SHA-256 hash
      validate: {
        validator: function (v) {
          return /^[a-f0-9]{64}$/i.test(v);
        },
        message: "Token hash debe ser hexadecimal de 64 caracteres",
      },
    },

    refreshTokenHash: {
      type: String,
      select: false, // NUNCA incluir en queries por defecto
      length: 64, // SHA-256 hash
      validate: {
        validator: function (v) {
          return !v || /^[a-f0-9]{64}$/i.test(v);
        },
        message: "Refresh token hash debe ser hexadecimal de 64 caracteres",
      },
    },

    // ================================
    // INFORMACIÓN DE EXPIRACIÓN
    // ================================

    expiresAt: {
      type: Date,
      required: true,
      index: true,
      validate: {
        validator: function (v) {
          return v > new Date();
        },
        message: "Token debe expirar en el futuro",
      },
    },

    // Tiempo de expiración del refresh token
    refreshExpiresAt: {
      type: Date,
      index: true,
    },

    // Última vez que se refrescó el token
    lastRefreshed: {
      type: Date,
      index: true,
    },

    // Número de veces que se ha refrescado
    refreshCount: {
      type: Number,
      default: 0,
      min: 0,
    },

    // ================================
    // SCOPES Y PERMISOS
    // ================================

    // Permisos otorgados por el usuario
    scope: [
      {
        type: String,
        maxlength: 100,
      },
    ],

    // Permisos solicitados originalmente
    requestedScope: [
      {
        type: String,
        maxlength: 100,
      },
    ],

    // Permisos denegados por el usuario
    deniedPermissions: [
      {
        type: String,
        maxlength: 100,
      },
    ],

    // ================================
    // METADATOS DEL PROVEEDOR OAUTH
    // ================================

    providerData: {
      // URL del perfil público (si está disponible)
      profileUrl: {
        type: String,
        maxlength: 500,
        validate: {
          validator: function (v) {
            return !v || /^https?:\/\/.+/.test(v);
          },
          message: "Profile URL debe ser una URL válida",
        },
      },

      // URL de imagen de perfil
      profilePicture: {
        type: String,
        maxlength: 500,
        validate: {
          validator: function (v) {
            return (
              !v || /^https?:\/\/.+\.(jpg|jpeg|png|gif|webp)(\?.*)?$/i.test(v)
            );
          },
          message: "Profile picture debe ser una URL de imagen válida",
        },
      },

      // Email verificado en el proveedor
      verifiedEmail: {
        type: Boolean,
        default: false,
      },

      // Tipo de cuenta (personal, business, etc.)
      accountType: {
        type: String,
        enum: ["personal", "business", "organization", "developer", "unknown"],
        default: "unknown",
      },

      // Información de la organización (si aplica)
      organization: {
        name: String,
        domain: String,
        verified: Boolean,
      },

      // Locale/idioma del usuario en el proveedor
      locale: {
        type: String,
        maxlength: 10,
      },

      // Información de verificación de identidad
      verification: {
        phoneVerified: Boolean,
        emailVerified: Boolean,
        identityVerified: Boolean,
      },
    },

    // ================================
    // INFORMACIÓN DE AUTORIZACIÓN
    // ================================

    // Método de autorización usado
    authorizationMethod: {
      type: String,
      enum: [
        "authorization_code",
        "implicit",
        "client_credentials",
        "password",
      ],
      default: "authorization_code",
    },

    // Flow de OAuth usado
    oauthFlow: {
      type: String,
      enum: ["web", "mobile", "desktop", "server-to-server"],
      default: "web",
    },

    // Estado de autorización original (hash para seguridad)
    stateHash: {
      type: String,
      length: 64,
    },

    // Nonce usado en OpenID Connect
    nonceHash: {
      type: String,
      length: 64,
    },

    // ================================
    // INFORMACIÓN DE APLICACIÓN OAUTH
    // ================================

    // ID de la aplicación OAuth (client_id)
    clientId: {
      type: String,
      required: true,
      maxlength: 200,
    },

    // Información del client
    clientInfo: {
      name: String,
      version: String,
      type: {
        type: String,
        enum: ["web", "mobile", "desktop", "service"],
        default: "web",
      },
    },

    // ================================
    // OPENID CONNECT (Si aplica)
    // ================================

    // ID Token hash (para OpenID Connect)
    idTokenHash: {
      type: String,
      select: false,
      length: 64,
    },

    // Claims del ID Token (información no sensible)
    idTokenClaims: {
      iss: String, // Issuer
      aud: String, // Audience
      sub: String, // Subject
      exp: Date, // Expiration
      iat: Date, // Issued at
      auth_time: Date, // Authentication time
      nonce: String,

      // Claims estándar (no sensibles)
      name: String,
      given_name: String,
      family_name: String,
      nickname: String,
      preferred_username: String,
      picture: String,
      locale: String,
      updated_at: Date,
    },

    // ================================
    // SEGURIDAD Y VALIDACIÓN
    // ================================

    // Información de validación del certificado
    certificateValidation: {
      validated: {
        type: Boolean,
        default: false,
      },
      validatedAt: Date,
      issuer: String,
      serialNumber: String,
      fingerprint: String,
    },

    // Validación de firma JWT
    signatureValidation: {
      algorithm: String,
      keyId: String,
      validated: Boolean,
      validatedAt: Date,
    },

    // ================================
    // GESTIÓN DE CONSENTIMIENTO
    // ================================

    // Información de consentimiento
    consent: {
      // Timestamp del consentimiento original
      grantedAt: {
        type: Date,
        default: Date.now,
        required: true,
      },

      // IP desde donde se otorgó el consentimiento
      grantedFromIP: String,

      // User agent usado para otorgar consentimiento
      grantedUserAgent: String,

      // Versión de términos y condiciones aceptada
      termsVersion: String,

      // Versión de política de privacidad aceptada
      privacyPolicyVersion: String,

      // Consentimientos específicos
      dataProcessingConsent: {
        type: Boolean,
        default: false,
      },

      marketingConsent: {
        type: Boolean,
        default: false,
      },

      // Tiempo de expiración del consentimiento
      consentExpiresAt: Date,

      // Consentimiento renovado
      renewed: [
        {
          renewedAt: Date,
          reason: String,
          previousVersion: String,
        },
      ],
    },

    // ================================
    // AUDITORÍA Y LOGGING
    // ================================

    // Registro de cambios en la sesión OAuth
    auditLog: [
      {
        action: {
          type: String,
          enum: [
            "created",
            "token_refreshed",
            "scope_modified",
            "permissions_revoked",
            "expired",
            "revoked_by_user",
            "revoked_by_admin",
            "revoked_by_provider",
            "security_incident",
          ],
        },
        timestamp: {
          type: Date,
          default: Date.now,
        },
        details: String,
        initiatedBy: {
          type: String,
          enum: ["user", "system", "admin", "provider"],
        },
        ipAddress: String,
        userAgent: String,
      },
    ],

    // ================================
    // INFORMACIÓN DE REVOCACIÓN
    // ================================

    // Estado de revocación
    revoked: {
      type: Boolean,
      default: false,
      index: true,
    },

    revokedAt: {
      type: Date,
      index: true,
    },

    revokedBy: {
      type: String,
      enum: ["user", "admin", "provider", "system", "security"],
    },

    revocationReason: {
      type: String,
      enum: [
        "user_request",
        "admin_action",
        "security_breach",
        "expired",
        "provider_revoked",
        "terms_violation",
        "suspicious_activity",
        "account_deletion",
      ],
    },

    // ================================
    // MÉTRICAS DE USO
    // ================================

    usage: {
      // Número total de requests usando este token
      apiCallsCount: {
        type: Number,
        default: 0,
        min: 0,
      },

      // Última vez que se usó el token
      lastUsedAt: Date,

      // Endpoints más usados
      topEndpoints: [
        {
          endpoint: String,
          count: Number,
        },
      ],

      // Datos transferidos (en bytes)
      dataTransferred: {
        type: Number,
        default: 0,
        min: 0,
      },

      // Rate limiting info
      rateLimiting: {
        requestsPerHour: Number,
        remainingQuota: Number,
        quotaResetAt: Date,
      },
    },

    // ================================
    // METADATOS ADICIONALES
    // ================================

    metadata: {
      // Versión del protocolo OAuth usado
      oauthVersion: {
        type: String,
        enum: ["2.0", "1.0a"],
        default: "2.0",
      },

      // Información del dispositivo usado para autorizar
      authorizationDevice: {
        type: String,
        browser: String,
        os: String,
        deviceType: String,
      },

      // Información de calidad de los datos
      dataQuality: {
        completeness: {
          type: Number,
          min: 0,
          max: 1,
          default: 1,
        },
        lastValidated: Date,
        validationErrors: [String],
      },

      // Información de sincronización
      sync: {
        lastSyncAt: Date,
        syncStatus: {
          type: String,
          enum: ["synced", "pending", "failed", "disabled"],
          default: "synced",
        },
        syncErrors: [String],
      },
    },
  },
  {
    _id: false,
    timestamps: false,
  }
);

// ================================
// MÉTODOS DE INSTANCIA
// ================================

/**
 * Verificar si el token ha expirado
 */
OAuthSessionDataSchema.methods.isExpired = function () {
  return this.expiresAt < new Date();
};

/**
 * Verificar si necesita renovación
 */
OAuthSessionDataSchema.methods.needsRefresh = function (thresholdMinutes = 30) {
  const refreshTime = new Date(
    this.expiresAt.getTime() - thresholdMinutes * 60 * 1000
  );
  return new Date() > refreshTime;
};

/**
 * Marcar token como usado
 */
OAuthSessionDataSchema.methods.recordUsage = function (endpoint = null) {
  this.usage.apiCallsCount = (this.usage.apiCallsCount || 0) + 1;
  this.usage.lastUsedAt = new Date();

  if (endpoint) {
    if (!this.usage.topEndpoints) this.usage.topEndpoints = [];

    const existing = this.usage.topEndpoints.find(
      (e) => e.endpoint === endpoint
    );
    if (existing) {
      existing.count++;
    } else {
      this.usage.topEndpoints.push({ endpoint, count: 1 });
    }

    // Mantener solo top 10 endpoints
    this.usage.topEndpoints = this.usage.topEndpoints
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  }

  return this;
};

/**
 * Revocar token
 */
OAuthSessionDataSchema.methods.revoke = function (revokedBy, reason) {
  this.revoked = true;
  this.revokedAt = new Date();
  this.revokedBy = revokedBy;
  this.revocationReason = reason;

  // Agregar al audit log
  this.auditLog.push({
    action: "revoked_by_" + revokedBy,
    details: `Token revoked: ${reason}`,
    initiatedBy: revokedBy,
  });

  return this;
};

/**
 * Actualizar después de refresh del token
 */
OAuthSessionDataSchema.methods.updateAfterRefresh = function (
  newTokenHash,
  newExpiresAt,
  newRefreshTokenHash = null
) {
  this.tokenHash = newTokenHash;
  this.expiresAt = newExpiresAt;
  this.lastRefreshed = new Date();
  this.refreshCount = (this.refreshCount || 0) + 1;

  if (newRefreshTokenHash) {
    this.refreshTokenHash = newRefreshTokenHash;
  }

  // Agregar al audit log
  this.auditLog.push({
    action: "token_refreshed",
    details: `Token refreshed (count: ${this.refreshCount})`,
    initiatedBy: "system",
  });

  return this;
};

/**
 * Verificar permisos
 */
OAuthSessionDataSchema.methods.hasScope = function (requiredScope) {
  if (typeof requiredScope === "string") {
    return this.scope && this.scope.includes(requiredScope);
  }

  if (Array.isArray(requiredScope)) {
    return requiredScope.every(
      (scope) => this.scope && this.scope.includes(scope)
    );
  }

  return false;
};

/**
 * Obtener información básica (sin datos sensibles)
 */
OAuthSessionDataSchema.methods.getPublicInfo = function () {
  return {
    provider: this.provider,
    email: this.email,
    expiresAt: this.expiresAt,
    scope: this.scope,
    accountType: this.providerData?.accountType,
    verifiedEmail: this.providerData?.verifiedEmail,
    lastUsedAt: this.usage?.lastUsedAt,
    apiCallsCount: this.usage?.apiCallsCount || 0,
    revoked: this.revoked,
  };
};

/**
 * Validar integridad de los datos OAuth
 */
OAuthSessionDataSchema.methods.validateIntegrity = function () {
  const issues = [];

  // Validar tokens
  if (!this.tokenHash || this.tokenHash.length !== 64) {
    issues.push("Token hash inválido");
  }

  if (this.refreshTokenHash && this.refreshTokenHash.length !== 64) {
    issues.push("Refresh token hash inválido");
  }

  // Validar expiración
  if (this.expiresAt <= new Date()) {
    issues.push("Token expirado");
  }

  // Validar email
  if (!this.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(this.email)) {
    issues.push("Email inválido");
  }

  // Validar provider
  const validProviders = [
    "google",
    "facebook",
    "apple",
    "microsoft",
    "linkedin",
    "github",
    "twitter",
  ];
  if (!validProviders.includes(this.provider)) {
    issues.push("Provider no soportado");
  }

  return {
    isValid: issues.length === 0,
    issues: issues,
  };
};

// ================================
// MÉTODOS ESTÁTICOS
// ================================

/**
 * Crear sesión OAuth desde datos del proveedor
 */
OAuthSessionDataSchema.statics.createFromProviderData = function (
  providerResponse,
  clientInfo
) {
  const crypto = require("crypto");

  // Hash del access token
  const tokenHash = crypto
    .createHash("sha256")
    .update(providerResponse.access_token)
    .digest("hex");

  // Hash del refresh token (si existe)
  let refreshTokenHash = null;
  if (providerResponse.refresh_token) {
    refreshTokenHash = crypto
      .createHash("sha256")
      .update(providerResponse.refresh_token)
      .digest("hex");
  }

  // Calcular expiración
  const expiresAt = new Date(Date.now() + providerResponse.expires_in * 1000);

  const sessionData = {
    provider: clientInfo.provider,
    providerId: providerResponse.user_info.id,
    email: providerResponse.user_info.email,
    tokenHash: tokenHash,
    refreshTokenHash: refreshTokenHash,
    expiresAt: expiresAt,
    scope: providerResponse.scope ? providerResponse.scope.split(" ") : [],
    clientId: clientInfo.client_id,

    providerData: {
      profileUrl: providerResponse.user_info.profile_url,
      profilePicture: providerResponse.user_info.picture,
      verifiedEmail: providerResponse.user_info.email_verified,
      accountType: providerResponse.user_info.account_type || "unknown",
      locale: providerResponse.user_info.locale,
    },

    consent: {
      grantedAt: new Date(),
      grantedFromIP: clientInfo.ip,
      grantedUserAgent: clientInfo.userAgent,
    },

    auditLog: [
      {
        action: "created",
        details: `OAuth session created via ${clientInfo.provider}`,
        initiatedBy: "user",
        ipAddress: clientInfo.ip,
        userAgent: clientInfo.userAgent,
      },
    ],
  };

  return new this(sessionData);
};

/**
 * Limpiar tokens expirados
 */
OAuthSessionDataSchema.statics.cleanupExpired = function () {
  return this.updateMany(
    {
      expiresAt: { $lt: new Date() },
      revoked: false,
    },
    {
      $set: {
        revoked: true,
        revokedAt: new Date(),
        revokedBy: "system",
        revocationReason: "expired",
      },
    }
  );
};

/**
 * Obtener estadísticas de uso
 */
OAuthSessionDataSchema.statics.getUsageStats = function (provider = null) {
  const matchStage = { revoked: false };
  if (provider) matchStage.provider = provider;

  return this.aggregate([
    { $match: matchStage },
    {
      $group: {
        _id: "$provider",
        totalSessions: { $sum: 1 },
        totalAPICalls: { $sum: "$usage.apiCallsCount" },
        avgAPICalls: { $avg: "$usage.apiCallsCount" },
        activeTokens: {
          $sum: { $cond: [{ $gt: ["$expiresAt", new Date()] }, 1, 0] },
        },
        expiredTokens: {
          $sum: { $cond: [{ $lt: ["$expiresAt", new Date()] }, 1, 0] },
        },
      },
    },
  ]);
};

// ================================
// ÍNDICES ESPECÍFICOS
// ================================

// Índice compuesto para búsquedas por proveedor y usuario
OAuthSessionDataSchema.index(
  {
    provider: 1,
    providerId: 1,
    revoked: 1,
  },
  { name: "provider_user_index" }
);

// Índice para tokens expirados
OAuthSessionDataSchema.index(
  {
    expiresAt: 1,
    revoked: 1,
  },
  { name: "expiration_cleanup_index" }
);

// Índice para auditoría
OAuthSessionDataSchema.index(
  {
    "auditLog.timestamp": -1,
    "auditLog.action": 1,
  },
  {
    name: "audit_log_index",
    sparse: true,
  }
);

// ================================
// MIDDLEWARE DE SEGURIDAD
// ================================

// Pre-save: validaciones de seguridad
OAuthSessionDataSchema.pre("validate", function (next) {
  // Asegurar que tokens nunca se almacenen en texto plano
  const sensitiveFields = ["access_token", "refresh_token", "id_token"];

  sensitiveFields.forEach((field) => {
    if (
      this[field] &&
      typeof this[field] === "string" &&
      this[field].length < 64
    ) {
      const error = new Error(
        `¡CRÍTICO! ${field} debe ser hash, no token directo`
      );
      return next(error);
    }
  });

  // Validar que el email coincida con el proveedor
  if (this.provider === "google" && this.email && !this.email.includes("@")) {
    return next(new Error("Email de Google inválido"));
  }

  next();
});

// Pre-save: auto cleanup de audit log
OAuthSessionDataSchema.pre("save", function (next) {
  // Mantener solo últimos 50 eventos en audit log
  if (this.auditLog && this.auditLog.length > 50) {
    this.auditLog = this.auditLog
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, 50);
  }

  next();
});

// ================================
// EXPORTAR SCHEMA
// ================================

export default OAuthSessionDataSchema;
