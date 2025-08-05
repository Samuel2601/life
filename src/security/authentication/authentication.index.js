// =============================================================================
// src/security/authentication/authentication.index.js
// =============================================================================

// Repositorios
export { UserRepository } from "./repositories/user.repository.js";
export { UserSessionRepository } from "./repositories/user_session.repository.js";
export { RoleRepository } from "./repositories/role.repository.js";

// Modelos
export { User } from "./models/user.scheme.js";
export { UserSession } from "./models/user_session.scheme.js";
export { Role } from "./models/role.scheme.js";

// Servicios de autenticación
export { AuthService } from "./services/auth.service.js";
export { SessionService } from "./services/session.service.js";
export { RoleService } from "./services/role.service.js";
export { AuthenticationServices, authServices } from "./services/index.js";

// Constantes de autenticación
export const AuthConstants = {
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

  // Configuración de cookies
  COOKIE_CONFIG: {
    SESSION_COOKIE_NAME: 'session_token',
    SECURE: process.env.NODE_ENV === 'production',
    HTTP_ONLY: true,
    SAME_SITE: 'strict',
    MAX_AGE: 8 * 60 * 60 * 1000, // 8 horas en ms
  },

  // Configuración de passwords
  PASSWORD_CONFIG: {
    MIN_LENGTH: 8,
    REQUIRE_UPPERCASE: true,
    REQUIRE_LOWERCASE: true,
    REQUIRE_NUMBERS: true,
    REQUIRE_SYMBOLS: true,
    BCRYPT_ROUNDS: 12,
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
  // Errores de credenciales
  INVALID_CREDENTIALS: "INVALID_CREDENTIALS",
  EMAIL_ALREADY_EXISTS: "EMAIL_ALREADY_EXISTS",
  USER_NOT_FOUND: "USER_NOT_FOUND",
  INVALID_EMAIL: "INVALID_EMAIL",
  WEAK_PASSWORD: "WEAK_PASSWORD",
  
  // Errores de cuenta
  ACCOUNT_LOCKED: "ACCOUNT_LOCKED",
  ACCOUNT_DISABLED: "ACCOUNT_DISABLED",
  EMAIL_NOT_VERIFIED: "EMAIL_NOT_VERIFIED",
  
  // Errores de sesión
  SESSION_EXPIRED: "SESSION_EXPIRED",
  SESSION_INVALID: "SESSION_INVALID",
  SESSION_COMPROMISED: "SESSION_COMPROMISED",
  DEVICE_NOT_RECOGNIZED: "DEVICE_NOT_RECOGNIZED",
  
  // Errores de tokens
  TOKEN_EXPIRED: "TOKEN_EXPIRED",
  TOKEN_INVALID: "TOKEN_INVALID",
  TOKEN_MISSING: "TOKEN_MISSING",
  
  // Errores de permisos
  PERMISSION_DENIED: "PERMISSION_DENIED",
  ROLE_NOT_FOUND: "ROLE_NOT_FOUND",
  INSUFFICIENT_PERMISSIONS: "INSUFFICIENT_PERMISSIONS",
  
  // Errores OAuth
  OAUTH_ERROR: "OAUTH_ERROR",
  OAUTH_STATE_MISMATCH: "OAUTH_STATE_MISMATCH",
  
  // Errores de rate limiting
  TOO_MANY_ATTEMPTS: "TOO_MANY_ATTEMPTS",
  RATE_LIMIT_EXCEEDED: "RATE_LIMIT_EXCEEDED",
  
  // Errores internos
  INTERNAL_ERROR: "INTERNAL_ERROR",
  DATABASE_ERROR: "DATABASE_ERROR",
  NETWORK_ERROR: "NETWORK_ERROR",
};

// Utilidades de autenticación
export const AuthUtils = {
  /**
   * Generar fingerprint de dispositivo desde request
   * @param {Object} req - Request de Express
   */
  async generateDeviceFingerprint(req) {
    const crypto = await import('crypto');
    const components = [
      req.get("User-Agent") || "",
      req.get("Accept-Language") || "",
      req.get("Accept-Encoding") || "",
      req.connection?.remoteAddress || "",
      req.get("Accept") || "",
    ];

    return crypto.default
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
    const config = AuthConstants.PASSWORD_CONFIG;
    const errors = [];

    if (!password || password.length < config.MIN_LENGTH) {
      errors.push(`La contraseña debe tener al menos ${config.MIN_LENGTH} caracteres`);
    }

    if (config.REQUIRE_LOWERCASE && !/[a-z]/.test(password)) {
      errors.push("Debe contener al menos una letra minúscula");
    }

    if (config.REQUIRE_UPPERCASE && !/[A-Z]/.test(password)) {
      errors.push("Debe contener al menos una letra mayúscula");
    }

    if (config.REQUIRE_NUMBERS && !/\d/.test(password)) {
      errors.push("Debe contener al menos un número");
    }

    if (config.REQUIRE_SYMBOLS && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push("Debe contener al menos un símbolo especial");
    }

    return {
      isValid: errors.length === 0,
      errors,
      score: this.calculatePasswordScore(password)
    };
  },

  /**
   * Calcular puntuación de fortaleza de contraseña
   * @param {string} password - Contraseña
   * @returns {number} Puntuación del 0 al 100
   */
  calculatePasswordScore(password) {
    if (!password) return 0;

    let score = 0;
    
    // Longitud
    score += Math.min(password.length * 4, 25);
    
    // Variedad de caracteres
    if (/[a-z]/.test(password)) score += 5;
    if (/[A-Z]/.test(password)) score += 5;
    if (/\d/.test(password)) score += 5;
    if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) score += 10;
    
    // Penalizar patrones comunes
    if (/(.)\1{2,}/.test(password)) score -= 10; // Caracteres repetidos
    if (/123|abc|qwe/i.test(password)) score -= 10; // Secuencias
    if (/password|admin|user/i.test(password)) score -= 20; // Palabras comunes
    
    return Math.max(0, Math.min(100, score));
  },

  /**
   * Generar token seguro
   * @param {number} length - Longitud del token
   */
  async generateSecureToken(length = 32) {
    const crypto = await import('crypto');
    return crypto.default.randomBytes(length).toString('hex');
  },

  /**
   * Sanitizar datos de usuario para logging
   * @param {Object} userData - Datos del usuario
   */
  sanitizeUserData(userData) {
    const sanitized = { ...userData };
    delete sanitized.password;
    delete sanitized.passwordHash;
    delete sanitized.accessToken;
    delete sanitized.refreshToken;
    delete sanitized.sessionToken;
    return sanitized;
  },
};

// Configuraciones del módulo de autenticación
export const AuthConfig = {
  // Configuración de sesiones
  session: {
    cleanupInterval: AuthConstants.SECURITY_LIMITS.SESSION_CLEANUP_INTERVAL,
    maxConcurrent: AuthConstants.SECURITY_LIMITS.MAX_CONCURRENT_SESSIONS,
    cookieName: AuthConstants.COOKIE_CONFIG.SESSION_COOKIE_NAME,
    secure: AuthConstants.COOKIE_CONFIG.SECURE,
    httpOnly: AuthConstants.COOKIE_CONFIG.HTTP_ONLY,
    sameSite: AuthConstants.COOKIE_CONFIG.SAME_SITE,
    maxAge: AuthConstants.COOKIE_CONFIG.MAX_AGE,
  },

  // Configuración OAuth (placeholder para futuro)
  oauth: {
    enabled: process.env.OAUTH_ENABLED === 'true',
    autoCreateUser: true,
    autoVerifyEmail: true,
    defaultRole: "customer",
  },

  // Configuración de tokens
  tokens: {
    accessTokenTTL: AuthConstants.TOKEN_CONFIG.ACCESS_TOKEN_TTL,
    refreshTokenTTL: AuthConstants.TOKEN_CONFIG.REFRESH_TOKEN_TTL,
    emailVerificationTTL: AuthConstants.TOKEN_CONFIG.EMAIL_VERIFICATION_TTL,
    passwordResetTTL: AuthConstants.TOKEN_CONFIG.PASSWORD_RESET_TTL,
  },

  // Configuración de roles
  roles: {
    defaultRole: "customer",
    createSystemRoles: true,
    allowCustomRoles: true,
    maxRolesPerUser: 10,
  },
};

// Funciones de ciclo de vida del módulo
export const AuthLifecycle = {
  /**
   * Inicializar el módulo de autenticación
   */
  async initialize() {
    try {
      console.log("🔐 Iniciando módulo de autenticación...");

      // Validar variables de entorno críticas
      await this.validateEnvironment();

      // Inicializar servicios
      await authServices.initialize();

      // Programar tareas de limpieza
      this.scheduleCleanupTasks();

      // Validar configuración
      await this.validateConfiguration();

      console.log("✅ Módulo de autenticación iniciado exitosamente");
      return true;
    } catch (error) {
      console.error("❌ Error iniciando módulo de autenticación:", error);
      throw error;
    }
  },

  /**
   * Validar variables de entorno necesarias
   */
  async validateEnvironment() {
    const requiredEnvVars = [
      'JWT_SECRET',
      'MONGODB_URI'
    ];

    const missing = requiredEnvVars.filter(envVar => !process.env[envVar]);
    
    if (missing.length > 0) {
      throw new Error(`Variables de entorno faltantes: ${missing.join(', ')}`);
    }

    // Validar JWT_SECRET en producción
    if (process.env.NODE_ENV === 'production') {
      if (process.env.JWT_SECRET.length < 32) {
        throw new Error('JWT_SECRET debe tener al menos 32 caracteres en producción');
      }
    }

    console.log("✅ Variables de entorno validadas");
  },

  /**
   * Programar tareas de limpieza automática
   */
  scheduleCleanupTasks() {
    const { session } = AuthConfig;

    // Limpiar sesiones expiradas cada hora
    setInterval(async () => {
      try {
        const sessionService = authServices.getSessionService();
        const cleaned = await sessionService.sessionRepository.cleanExpiredSessions();
        if (cleaned > 0) {
          console.log(`🧹 ${cleaned} sesiones expiradas limpiadas`);
        }
      } catch (error) {
        console.error("Error en limpieza de sesiones:", error);
      }
    }, session.cleanupInterval);

    // Limpiar tokens expirados cada 6 horas
    setInterval(async () => {
      try {
        const authService = authServices.getAuthService();
        const cleaned = await authService.userRepository.cleanExpiredTokens();
        if (cleaned > 0) {
          console.log(`🧹 ${cleaned} tokens expirados limpiados`);
        }
      } catch (error) {
        console.error("Error en limpieza de tokens:", error);
      }
    }, 6 * 60 * 60 * 1000); // Cada 6 horas

    console.log("🕐 Tareas de limpieza de autenticación programadas");
  },

  /**
   * Validar configuración del módulo
   */
  async validateConfiguration() {
    const errors = [];

    try {
      // Validar roles del sistema
      const roleService = authServices.getRoleService();
      const defaultRole = await roleService.roleRepository.getDefaultRole();
      if (!defaultRole) {
        console.warn("⚠️  Rol por defecto no encontrado, se creará automáticamente");
      }
    } catch (error) {
      errors.push(`Error validando roles: ${error.message}`);
    }

    if (errors.length > 0) {
      throw new Error(`Errores de configuración: ${errors.join(", ")}`);
    }

    console.log("✅ Configuración de autenticación validada");
  },

  /**
   * Cerrar el módulo de forma elegante
   */
  async shutdown() {
    try {
      console.log("🛑 Cerrando módulo de autenticación...");

      // Cancelar intervalos de limpieza
      // TODO: Implementar registro de intervalos para poder cancelarlos

      console.log("✅ Módulo de autenticación cerrado correctamente");
    } catch (error) {
      console.error("❌ Error cerrando módulo de autenticación:", error);
      throw error;
    }
  },
};

// Función de inicialización legacy (mantener compatibilidad)
export const initializeAuthModule = async () => {
  return await AuthLifecycle.initialize();
};

// Exportar todo como objeto por defecto también
export default {
  // Servicios
  AuthService,
  SessionService,
  RoleService,
  AuthenticationServices,
  authServices,
  
  // Modelos
  User,
  UserSession,
  Role,
  
  // Repositorios
  UserRepository,
  UserSessionRepository,
  RoleRepository,
  
  // Constantes y configuración
  AuthConstants,
  AuthConfig,
  AuthError,
  AuthErrorCodes,
  AuthUtils,
  AuthLifecycle,
  
  // Función de inicialización
  initializeAuthModule,
};

console.log("📦 Módulo de autenticación cargado");