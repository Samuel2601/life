// =============================================================================
// src/modules/authentication/authentication.index.js
// =============================================================================

// Repositorios
export { UserRepository } from "./repositories/user.repository.js";
export { UserSessionRepository } from "./repositories/user_session.repository.js";
export { RoleRepository } from "./repositories/role.repository.js";

// Modelos
export { User } from "./models/user.scheme.js";
export { UserSession } from "./models/user_session.scheme.js";
export { Role } from "./models/role.scheme.js";

// Servicios de autenticación (cuando se implementen)
export { AuthService } from "./services/auth.service.js";
export { SessionService } from "./services/session.service.js";
export { RoleService } from "./services/role.service.js";

// Middlewares de autenticación (cuando se implementen)
// export { authMiddleware } from "./middlewares/auth.middleware.js";
// export { roleMiddleware } from "./middlewares/role.middleware.js";
// export { sessionMiddleware } from "./middlewares/session.middleware.js";

// Utilidades de autenticación
export const AuthUtils = {
  /**
   * Generar fingerprint de dispositivo desde request
   * @param {Object} req - Request de Express
   */
  generateDeviceFingerprint(req) {
    const components = [
      req.get("User-Agent") || "",
      req.get("Accept-Language") || "",
      req.get("Accept-Encoding") || "",
      req.connection?.remoteAddress || "",
      // Agregar más componentes según necesidades
    ];

    const crypto = require("crypto");
    return crypto
      .createHash("sha256")
      .update(components.join("|"))
      .digest("hex");
  },

  /**
   * Extraer IP real del request
   * @param {Object} req - Request de Express
   */
  getRealIP(req) {
    return (
      req.get("X-Real-IP") ||
      req.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
      req.connection?.remoteAddress ||
      req.ip ||
      "unknown"
    );
  },

  /**
   * Preparar datos de usuario para sesión
   * @param {Object} req - Request de Express
   * @param {string} userId - ID del usuario
   */
  prepareUserData(req, userId) {
    return {
      userId,
      ip: this.getRealIP(req),
      userAgent: req.get("User-Agent") || "Unknown",
      location: req.location || null, // Si tienes middleware de geolocalización
    };
  },

  /**
   * Validar formato de email
   * @param {string} email - Email a validar
   */
  isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  },

  /**
   * Validar fortaleza de contraseña
   * @param {string} password - Contraseña a validar
   */
  validatePasswordStrength(password) {
    const errors = [];

    if (!password || password.length < 8) {
      errors.push("La contraseña debe tener al menos 8 caracteres");
    }

    if (!/[a-z]/.test(password)) {
      errors.push("La contraseña debe contener al menos una letra minúscula");
    }

    if (!/[A-Z]/.test(password)) {
      errors.push("La contraseña debe contener al menos una letra mayúscula");
    }

    if (!/\d/.test(password)) {
      errors.push("La contraseña debe contener al menos un número");
    }

    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push("La contraseña debe contener al menos un carácter especial");
    }

    return {
      isValid: errors.length === 0,
      errors,
      strength: this.calculatePasswordStrength(password),
    };
  },

  /**
   * Calcular fortaleza de contraseña (0-100)
   * @param {string} password - Contraseña
   */
  calculatePasswordStrength(password) {
    let score = 0;

    // Longitud
    if (password.length >= 8) score += 25;
    if (password.length >= 12) score += 15;
    if (password.length >= 16) score += 10;

    // Variedad de caracteres
    if (/[a-z]/.test(password)) score += 10;
    if (/[A-Z]/.test(password)) score += 10;
    if (/\d/.test(password)) score += 10;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 10;

    // Patrones complejos
    if (/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) score += 10;
    if (/(?=.*[!@#$%^&*(),.?":{}|<>])/.test(password)) score += 10;

    return Math.min(score, 100);
  },

  /**
   * Generar nombre de usuario único
   * @param {string} email - Email del usuario
   * @param {string} firstName - Nombre
   * @param {string} lastName - Apellido
   */
  generateUsername(email, firstName = "", lastName = "") {
    // Intentar con nombre y apellido
    if (firstName && lastName) {
      const base = `${firstName.toLowerCase()}${lastName.toLowerCase()}`;
      return base.replace(/[^a-z0-9]/g, "");
    }

    // Fallback al email
    return email
      .split("@")[0]
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "");
  },

  /**
   * Formatear datos de sesión para respuesta
   * @param {Object} session - Datos de sesión
   */
  formatSessionResponse(session) {
    return {
      sessionId: session._id,
      userId: session.userId,
      isActive: session.isActive,
      createdAt: session.createdAt,
      lastAccessedAt: session.lastAccessedAt,
      expiresAt: session.expiresAt,
      deviceInfo: session.deviceInfo,
      location: session.location,
      rememberMe: session.rememberMe,
      // No incluir tokens sensibles
    };
  },
};

// Constantes de autenticación
export const AuthConstants = {
  // Tipos de sesión
  SESSION_TYPES: {
    WEB: "web",
    MOBILE: "mobile",
    API: "api",
  },

  // Proveedores OAuth
  OAUTH_PROVIDERS: {
    GOOGLE: "google",
    FACEBOOK: "facebook",
    APPLE: "apple",
    MICROSOFT: "microsoft",
  },

  // Tipos de actividad sospechosa
  SUSPICIOUS_ACTIVITY_TYPES: {
    DEVICE_CHANGE: "device_change",
    LOCATION_CHANGE: "location_change",
    UNUSUAL_ACCESS: "unusual_access",
    CONCURRENT_SESSION: "concurrent_session",
    FAILED_LOGIN: "failed_login",
    BRUTE_FORCE: "brute_force",
  },

  // Severidades
  SEVERITY_LEVELS: {
    LOW: "low",
    MEDIUM: "medium",
    HIGH: "high",
    CRITICAL: "critical",
  },

  // Alcances de permisos
  PERMISSION_SCOPES: {
    NONE: "none",
    OWN: "own",
    COMPANY: "company",
    GLOBAL: "global",
  },

  // Recursos del sistema
  RESOURCES: {
    USERS: "users",
    BUSINESSES: "businesses",
    REVIEWS: "reviews",
    CATEGORIES: "categories",
    ADDRESSES: "addresses",
    ROLES: "roles",
    PERMISSIONS: "permissions",
    SYSTEM: "system",
    REPORTS: "reports",
    AUDIT: "audit",
    TRANSLATIONS: "translations",
    MEDIA: "media",
    NOTIFICATIONS: "notifications",
    ANALYTICS: "analytics",
  },

  // Acciones de permisos
  ACTIONS: {
    CREATE: "create",
    READ: "read",
    UPDATE: "update",
    DELETE: "delete",
    MANAGE: "manage",
    APPROVE: "approve",
    REJECT: "reject",
    PUBLISH: "publish",
    UNPUBLISH: "unpublish",
    EXPORT: "export",
    IMPORT: "import",
    RESTORE: "restore",
    ARCHIVE: "archive",
  },

  // Configuración de cookies de sesión
  SESSION_COOKIE: {
    NAME: "session_token",
    HTTP_ONLY: true,
    SECURE: process.env.NODE_ENV === "production",
    SAME_SITE: "strict",
    MAX_AGE: 8 * 60 * 60 * 1000, // 8 horas
    DOMAIN: process.env.COOKIE_DOMAIN || undefined,
    PATH: "/",
  },

  // Configuración de tokens
  TOKEN_CONFIG: {
    ACCESS_TOKEN_TTL: 15 * 60, // 15 minutos en segundos
    REFRESH_TOKEN_TTL: 7 * 24 * 60 * 60, // 7 días en segundos
    SESSION_TOKEN_TTL: 8 * 60 * 60, // 8 horas en segundos
    EMAIL_VERIFICATION_TTL: 24 * 60 * 60, // 24 horas en segundos
    PASSWORD_RESET_TTL: 60 * 60, // 1 hora en segundos
  },

  // Límites de seguridad
  SECURITY_LIMITS: {
    MAX_LOGIN_ATTEMPTS: 5,
    LOCKOUT_DURATION: 2 * 60 * 60 * 1000, // 2 horas en ms
    MAX_CONCURRENT_SESSIONS: 5,
    MAX_FINGERPRINT_CHANGES: 3,
    SESSION_CLEANUP_INTERVAL: 60 * 60 * 1000, // 1 hora en ms
  },
};

// Errores de autenticación
export class AuthError extends Error {
  constructor(message, code, statusCode = 401) {
    super(message);
    this.name = "AuthError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

export const AuthErrorCodes = {
  INVALID_CREDENTIALS: "INVALID_CREDENTIALS",
  ACCOUNT_LOCKED: "ACCOUNT_LOCKED",
  ACCOUNT_DISABLED: "ACCOUNT_DISABLED",
  EMAIL_NOT_VERIFIED: "EMAIL_NOT_VERIFIED",
  SESSION_EXPIRED: "SESSION_EXPIRED",
  SESSION_INVALID: "SESSION_INVALID",
  SESSION_COMPROMISED: "SESSION_COMPROMISED",
  DEVICE_NOT_RECOGNIZED: "DEVICE_NOT_RECOGNIZED",
  PERMISSION_DENIED: "PERMISSION_DENIED",
  ROLE_NOT_FOUND: "ROLE_NOT_FOUND",
  TOKEN_EXPIRED: "TOKEN_EXPIRED",
  TOKEN_INVALID: "TOKEN_INVALID",
  OAUTH_ERROR: "OAUTH_ERROR",
  TOO_MANY_ATTEMPTS: "TOO_MANY_ATTEMPTS",
};

// Función de inicialización del módulo
export const initializeAuthModule = async () => {
  try {
    console.log("🔐 Inicializando módulo de autenticación...");

    // Crear roles del sistema si no existen
    const roleRepository = new RoleRepository();
    await roleRepository.createSystemRoles();

    // Limpiar sesiones expiradas
    const sessionRepository = new UserSessionRepository();
    await sessionRepository.cleanExpiredSessions();

    // Limpiar tokens expirados
    const userRepository = new UserRepository();
    await userRepository.cleanExpiredTokens();

    console.log("✅ Módulo de autenticación inicializado correctamente");

    return true;
  } catch (error) {
    console.error("❌ Error inicializando módulo de autenticación:", error);
    throw error;
  }
};

// Función de limpieza programada
export const scheduleAuthCleanup = () => {
  const { SECURITY_LIMITS } = AuthConstants;

  // Limpiar sesiones expiradas cada hora
  setInterval(async () => {
    try {
      const sessionRepository = new UserSessionRepository();
      await sessionRepository.cleanExpiredSessions();
    } catch (error) {
      console.error("Error en limpieza de sesiones:", error);
    }
  }, SECURITY_LIMITS.SESSION_CLEANUP_INTERVAL);

  // Limpiar tokens expirados cada 6 horas
  setInterval(
    async () => {
      try {
        const userRepository = new UserRepository();
        await userRepository.cleanExpiredTokens();
      } catch (error) {
        console.error("Error en limpieza de tokens:", error);
      }
    },
    6 * 60 * 60 * 1000
  );

  console.log("🕐 Tareas de limpieza de autenticación programadas");
};

console.log("📦 Módulo de autenticación cargado");
