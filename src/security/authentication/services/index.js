// =============================================================================
// src/security/authentication/services/index.js
// =============================================================================

import { UserRepository } from "../repositories/user.repository.js";
import { UserSessionRepository } from "../repositories/user_session.repository.js";
import { RoleRepository } from "../repositories/role.repository.js";

// IMPORTANTE: Importar las clases directamente para evitar dependencias circulares
import { AuthService } from "./auth.service.js";
import { SessionService } from "./session.service.js";
import { RoleService } from "./role.service.js";

// Clase unificada de servicios de autenticación
export class AuthenticationServices {
  constructor() {
    // Inicializar como null y crear instancias bajo demanda
    this._authService = null;
    this._sessionService = null;
    this._roleService = null;
  }

  /**
   * Getter para AuthService (lazy loading)
   */
  get authService() {
    if (!this._authService) {
      this._authService = new AuthService();
    }
    return this._authService;
  }

  /**
   * Getter para SessionService (lazy loading)
   */
  get sessionService() {
    if (!this._sessionService) {
      this._sessionService = new SessionService();
    }
    return this._sessionService;
  }

  /**
   * Getter para RoleService (lazy loading)
   */
  get roleService() {
    if (!this._roleService) {
      this._roleService = new RoleService();
    }
    return this._roleService;
  }

  /**
   * Inicializar todos los servicios
   */
  async initialize() {
    try {
      console.log("🔐 Inicializando servicios de autenticación...");

      // Inicializar servicios (esto creará las instancias si no existen)
      await this.authService.initialize?.();
      await this.sessionService.initialize?.();
      await this.roleService.initialize?.();

      // Crear roles del sistema si no existen
      const roleRepository = new RoleRepository();
      await roleRepository.createSystemRoles();

      // Limpiar sesiones expiradas
      const sessionRepository = new UserSessionRepository();
      await sessionRepository.cleanExpiredSessions();

      console.log("✅ Servicios de autenticación inicializados");
      return true;
    } catch (error) {
      console.error(
        "❌ Error inicializando servicios de autenticación:",
        error
      );
      throw error;
    }
  }

  /**
   * Obtener instancia del servicio de autenticación
   */
  getAuthService() {
    return this.authService;
  }

  /**
   * Obtener instancia del servicio de sesiones
   */
  getSessionService() {
    return this.sessionService;
  }

  /**
   * Obtener instancia del servicio de roles
   */
  getRoleService() {
    return this.roleService;
  }

  /**
   * Método de conveniencia para registro
   */
  async register(registrationData, requestInfo) {
    return await this.authService.register(registrationData, requestInfo);
  }

  /**
   * Método de conveniencia para login
   */
  async login(loginData, requestInfo) {
    return await this.authService.login(loginData, requestInfo);
  }

  /**
   * Método de conveniencia para OAuth
   */
  async oauthLogin(oauthData, requestInfo) {
    return await this.authService.oauthLogin(oauthData, requestInfo);
  }

  /**
   * Método de conveniencia para validar sesión
   */
  async validateSession(sessionToken, requestInfo) {
    return await this.authService.validateSession(sessionToken, requestInfo);
  }

  /**
   * Método de conveniencia para logout
   */
  async logout(sessionToken, requestInfo) {
    return await this.authService.logout(sessionToken, requestInfo);
  }

  /**
   * Método de conveniencia para verificar permisos
   */
  async checkPermission(userId, resource, action, scope = "own", context = {}) {
    return await this.roleService.checkUserPermission(
      userId,
      resource,
      action,
      scope,
      context
    );
  }

  /**
   * Método de conveniencia para obtener sesiones activas
   */
  async getUserSessions(userId, options = {}) {
    return await this.sessionService.getUserActiveSessions(userId, options);
  }

  /**
   * Obtener métricas consolidadas de autenticación
   */
  async getAuthMetrics() {
    try {
      return {
        timestamp: new Date(),
        services: {
          auth: "active",
          session: "active",
          role: "active",
        },
        metrics: {
          authServiceInitialized: !!this._authService,
          sessionServiceInitialized: !!this._sessionService,
          roleServiceInitialized: !!this._roleService,
        },
      };
    } catch (error) {
      console.error("Error obteniendo métricas de autenticación:", error);
      throw error;
    }
  }
}

// Instancia singleton para uso global (lazy loading)
let _authServicesInstance = null;

export const authServices = (() => {
  if (!_authServicesInstance) {
    _authServicesInstance = new AuthenticationServices();
  }
  return _authServicesInstance;
})();

// Funciones de utilidad para middleware
export const AuthMiddlewareHelpers = {
  /**
   * Extraer token de sesión de las cookies
   * @param {Object} req - Request de Express
   */
  extractSessionToken(req) {
    return (
      req.cookies?.session_token ||
      req.headers?.["x-session-token"] ||
      req.headers?.authorization?.replace("Bearer ", "")
    );
  },

  /**
   * Extraer información del request
   * @param {Object} req - Request de Express
   */
  extractRequestInfo(req) {
    return {
      ipAddress: req.ip || req.connection.remoteAddress || "unknown",
      userAgent: req.get("User-Agent") || "unknown",
      deviceFingerprint: req.headers["x-device-fingerprint"] || null,
    };
  },

  /**
   * Crear respuesta de error de autenticación
   * @param {Object} res - Response de Express
   * @param {Error} error - Error de autenticación
   */
  sendAuthError(res, error) {
    const statusCode = error.statusCode || 500;
    const errorCode = error.errorCode || "AUTH_ERROR";

    res.status(statusCode).json({
      success: false,
      error: {
        code: errorCode,
        message: error.message,
        timestamp: new Date().toISOString(),
      },
    });
  },
};

// Configuración de autenticación
export const AuthConfig = {
  /**
   * Obtener configuración de cookies
   */
  getCookieConfig() {
    return {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 8 * 60 * 60 * 1000, // 8 horas
      domain: process.env.COOKIE_DOMAIN || undefined,
      path: "/",
    };
  },

  /**
   * Obtener configuración JWT
   */
  getJwtConfig() {
    return {
      secret: process.env.JWT_SECRET || "default_secret_change_in_production",
      accessTokenTTL: 15 * 60, // 15 minutos
      refreshTokenTTL: 7 * 24 * 60 * 60, // 7 días
      sessionTokenTTL: 8 * 60 * 60, // 8 horas
    };
  },

  /**
   * Obtener límites de seguridad
   */
  getSecurityLimits() {
    return {
      maxLoginAttempts: 5,
      lockoutDuration: 2 * 60 * 60 * 1000, // 2 horas
      maxConcurrentSessions: 5,
      maxFingerprintChanges: 3,
    };
  },
};

// Métricas de autenticación
export const AuthMetrics = {
  /**
   * Incrementar contador de login exitoso
   */
  async incrementSuccessfulLogin() {
    // Implementar métricas aquí (ej: Prometheus, StatsD)
    console.log("📊 Login exitoso registrado");
  },

  /**
   * Incrementar contador de login fallido
   */
  async incrementFailedLogin() {
    // Implementar métricas aquí
    console.log("📊 Login fallido registrado");
  },

  /**
   * Registrar creación de sesión
   */
  async recordSessionCreation(deviceInfo) {
    // Implementar métricas aquí
    console.log("📊 Nueva sesión creada:", deviceInfo?.device || "unknown");
  },

  /**
   * Registrar terminación de sesión
   */
  async recordSessionTermination(reason) {
    // Implementar métricas aquí
    console.log("📊 Sesión terminada:", reason);
  },
};

// Gestión del ciclo de vida del módulo
export const AuthLifecycle = {
  /**
   * Inicializar el módulo de autenticación
   */
  async initialize() {
    try {
      console.log("🚀 Inicializando módulo de autenticación...");

      // Validar configuración
      await this.validateConfiguration();

      // Inicializar servicios
      await authServices.initialize();

      // Programar tareas de limpieza
      this.scheduleCleanupTasks();

      console.log("✅ Módulo de autenticación inicializado exitosamente");
      return true;
    } catch (error) {
      console.error("❌ Error inicializando módulo de autenticación:", error);
      throw error;
    }
  },

  /**
   * Programar tareas de limpieza automática
   */
  scheduleCleanupTasks() {
    // Limpiar sesiones expiradas cada hora
    setInterval(
      async () => {
        try {
          const sessionRepository = new UserSessionRepository();
          await sessionRepository.cleanExpiredSessions();
        } catch (error) {
          console.error("Error en limpieza de sesiones:", error);
        }
      },
      60 * 60 * 1000
    ); // Cada hora

    // Limpiar tokens expirados cada 6 horas
    setInterval(
      async () => {
        try {
          const authService = authServices.getAuthService();
          await authService.userRepository.cleanExpiredTokens();
        } catch (error) {
          console.error("Error en limpieza de tokens:", error);
        }
      },
      6 * 60 * 60 * 1000
    ); // Cada 6 horas

    console.log("🕐 Tareas de limpieza programadas");
  },

  /**
   * Validar configuración del módulo
   */
  async validateConfiguration() {
    const errors = [];

    // Validar variables de entorno críticas
    if (!process.env.JWT_SECRET) {
      errors.push("JWT_SECRET no configurado");
    }

    if (process.env.NODE_ENV === "production") {
      if (!process.env.COOKIE_DOMAIN) {
        errors.push("COOKIE_DOMAIN no configurado para producción");
      }
    }

    // Validar roles del sistema
    try {
      const roleService = authServices.getRoleService();
      const defaultRole = await roleService.roleRepository.getDefaultRole();
      if (!defaultRole) {
        console.warn(
          "⚠️  Rol por defecto no encontrado, se creará automáticamente"
        );
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

      // Aquí podrías agregar lógica de cierre si es necesaria
      // Por ejemplo, cerrar conexiones, guardar datos en cache, etc.

      console.log("✅ Módulo de autenticación cerrado correctamente");
    } catch (error) {
      console.error("❌ Error cerrando módulo de autenticación:", error);
      throw error;
    }
  },
};

// Utilidades para testing
export const AuthTestUtils = {
  /**
   * Crear usuario de prueba
   * @param {Object} overrides - Datos para override
   */
  async createTestUser(overrides = {}) {
    if (process.env.NODE_ENV === "production") {
      throw new Error("No se pueden crear usuarios de prueba en producción");
    }

    const authService = authServices.getAuthService();

    const testUserData = {
      email: `test-${Date.now()}@example.com`,
      password: "Test123!@#",
      profile: {
        firstName: "Test",
        lastName: "User",
      },
      ...overrides,
    };

    const requestInfo = {
      ipAddress: "127.0.0.1",
      userAgent: "Test-Agent",
      deviceFingerprint: "test-fingerprint",
    };

    return await authService.register(testUserData, requestInfo);
  },

  /**
   * Limpiar datos de prueba
   */
  async cleanTestData() {
    if (process.env.NODE_ENV === "production") {
      throw new Error("No se pueden limpiar datos en producción");
    }

    const authService = authServices.getAuthService();

    // Eliminar usuarios de prueba
    await authService.userRepository.model.deleteMany({
      email: { $regex: /^test-.*@example\.com$/ },
    });

    // Eliminar sesiones de prueba
    await authService.sessionRepository.model.deleteMany({
      userAgent: "Test-Agent",
    });

    console.log("🧹 Datos de prueba limpiados");
  },

  /**
   * Generar token de sesión de prueba
   * @param {string} userId - ID del usuario
   */
  async generateTestSession(userId) {
    if (process.env.NODE_ENV === "production") {
      throw new Error("No se pueden generar sesiones de prueba en producción");
    }

    const sessionService = authServices.getSessionService();
    const authService = authServices.getAuthService();

    const tokens = authService.generateTokens(userId);

    return await sessionService.sessionRepository.createSession(
      {
        userId,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        deviceFingerprint: "test-fingerprint",
        ipAddress: "127.0.0.1",
        userAgent: "Test-Agent",
        rememberMe: false,
      },
      {
        userId,
        ip: "127.0.0.1",
        userAgent: "Test-Agent",
      }
    );
  },
};

// Exportar servicios individuales también
export { AuthService } from "./auth.service.js";
export { SessionService } from "./session.service.js";
export { RoleService } from "./role.service.js";

// Exportar todo como módulo principal
export default {
  AuthService,
  SessionService,
  RoleService,
  AuthenticationServices,
  authServices,
  AuthMiddlewareHelpers,
  AuthConfig,
  AuthLifecycle,
  AuthMetrics,
  AuthTestUtils,
};

console.log("📦 Servicios de autenticación cargados correctamente");
