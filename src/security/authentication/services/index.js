// =============================================================================
// src/modules/authentication/services/index.js
// =============================================================================

// Servicios principales
export { AuthService } from "./auth.service.js";
export { SessionService } from "./session.service.js";
export { RoleService } from "./role.service.js";

// Clase unificada de servicios de autenticación
export class AuthenticationServices {
  constructor() {
    this.authService = new AuthService();
    this.sessionService = new SessionService();
    this.roleService = new RoleService();
  }

  /**
   * Inicializar todos los servicios
   */
  async initialize() {
    try {
      console.log("🔐 Inicializando servicios de autenticación...");

      // Aquí podrías agregar inicializaciones específicas
      // Por ejemplo, verificar configuraciones, crear roles por defecto, etc.
      await this.authService.initialize();
      await this.sessionService.initialize();
      await this.roleService.initialize();

      //Crear roles del sistema si no existen
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
      // Podrías implementar métricas consolidadas aquí
      return {
        timestamp: new Date(),
        services: {
          auth: "active",
          session: "active",
          role: "active",
        },
        // Agregar más métricas según necesidades
      };
    } catch (error) {
      console.error("Error obteniendo métricas de autenticación:", error);
      throw error;
    }
  }
}

// Instancia singleton para uso global
export const authServices = new AuthenticationServices();

// Funciones de utilidad para middleware
export const AuthMiddlewareHelpers = {
  /**
   * Extraer token de sesión de las cookies
   * @param {Object} req - Request de Express
   */
  extractSessionToken(req) {
    return (
      req.cookies?.session_token || req.headers?.["x-session-token"] || null
    );
  },

  /**
   * Extraer información del request
   * @param {Object} req - Request de Express
   */
  extractRequestInfo(req) {
    return {
      ipAddress: this.getRealIP(req),
      userAgent: req.get("User-Agent") || "Unknown",
      deviceFingerprint: this.generateDeviceFingerprint(req),
    };
  },

  /**
   * Obtener IP real del request
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
   * Generar fingerprint básico del dispositivo
   * @param {Object} req - Request de Express
   */
  generateDeviceFingerprint(req) {
    const components = [
      req.get("User-Agent") || "",
      req.get("Accept-Language") || "",
      req.get("Accept-Encoding") || "",
      this.getRealIP(req),
    ];

    const crypto = require("crypto");
    return crypto
      .createHash("sha256")
      .update(components.join("|"))
      .digest("hex");
  },

  /**
   * Configurar cookie de sesión segura
   * @param {Object} res - Response de Express
   * @param {string} sessionToken - Token de sesión
   * @param {Object} options - Opciones de cookie
   */
  setSessionCookie(res, sessionToken, options = {}) {
    const {
      maxAge = 8 * 60 * 60 * 1000, // 8 horas por defecto
      rememberMe = false,
      secure = process.env.NODE_ENV === "production",
      domain = process.env.COOKIE_DOMAIN,
    } = options;

    const cookieOptions = {
      httpOnly: true,
      secure,
      sameSite: "strict",
      maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : maxAge, // 30 días si remember me
      domain,
      path: "/",
    };

    res.cookie("session_token", sessionToken, cookieOptions);
  },

  /**
   * Limpiar cookie de sesión
   * @param {Object} res - Response de Express
   */
  clearSessionCookie(res) {
    res.clearCookie("session_token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      domain: process.env.COOKIE_DOMAIN,
      path: "/",
    });
  },

  /**
   * Formatear respuesta de error de autenticación
   * @param {Error} error - Error de autenticación
   */
  formatAuthError(error) {
    if (error.name === "AuthError") {
      return {
        success: false,
        error: {
          code: error.code,
          message: error.message,
          statusCode: error.statusCode,
        },
        timestamp: new Date().toISOString(),
      };
    }

    // Error genérico
    return {
      success: false,
      error: {
        code: "INTERNAL_ERROR",
        message: "Error interno del servidor",
        statusCode: 500,
      },
      timestamp: new Date().toISOString(),
    };
  },

  /**
   * Formatear respuesta exitosa
   * @param {Object} data - Datos de respuesta
   * @param {string} message - Mensaje opcional
   */
  formatSuccessResponse(data, message = null) {
    return {
      success: true,
      data,
      message,
      timestamp: new Date().toISOString(),
    };
  },

  /**
   * Validar y sanitizar datos de entrada
   * @param {Object} data - Datos a validar
   * @param {Array} requiredFields - Campos requeridos
   */
  validateAndSanitize(data, requiredFields = []) {
    const errors = [];
    const sanitized = {};

    // Verificar campos requeridos
    requiredFields.forEach((field) => {
      if (!data[field]) {
        errors.push(`Campo requerido: ${field}`);
      }
    });

    // Sanitizar campos comunes
    if (data.email) {
      sanitized.email = data.email.toLowerCase().trim();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(sanitized.email)) {
        errors.push("Email inválido");
      }
    }

    if (data.password) {
      sanitized.password = data.password;
      if (data.password.length < 8) {
        errors.push("La contraseña debe tener al menos 8 caracteres");
      }
    }

    // Sanitizar strings
    Object.keys(data).forEach((key) => {
      if (typeof data[key] === "string" && !sanitized[key]) {
        sanitized[key] = data[key].trim();
      } else if (!sanitized[key]) {
        sanitized[key] = data[key];
      }
    });

    return {
      isValid: errors.length === 0,
      errors,
      data: sanitized,
    };
  },
};

// Configuración por defecto de autenticación
export const AuthConfig = {
  // Configuración de sesiones
  session: {
    defaultTTL: 8 * 60 * 60 * 1000, // 8 horas
    rememberMeTTL: 30 * 24 * 60 * 60 * 1000, // 30 días
    cleanupInterval: 60 * 60 * 1000, // 1 hora
    maxConcurrent: 5, // Máximo de sesiones concurrentes por usuario
  },

  // Configuración de seguridad
  security: {
    maxLoginAttempts: 5,
    lockoutDuration: 2 * 60 * 60 * 1000, // 2 horas
    passwordMinLength: 8,
    requireEmailVerification: false, // Configurable según necesidades
    enableDeviceFingerprinting: true,
    enableSuspiciousActivityDetection: true,
  },

  // Configuración de cookies
  cookies: {
    name: "session_token",
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    domain: process.env.COOKIE_DOMAIN,
    path: "/",
  },

  // Configuración de OAuth
  oauth: {
    enabledProviders: ["google", "facebook"], // Configurar según necesidades
    autoCreateUser: true,
    autoVerifyEmail: true,
    defaultRole: "customer",
  },

  // Configuración de tokens
  tokens: {
    accessTokenTTL: 15 * 60, // 15 minutos
    refreshTokenTTL: 7 * 24 * 60 * 60, // 7 días
    emailVerificationTTL: 24 * 60 * 60, // 24 horas
    passwordResetTTL: 60 * 60, // 1 hora
  },

  // Configuración de roles
  roles: {
    defaultRole: "customer",
    createSystemRoles: true,
    allowCustomRoles: true,
    maxRolesPerUser: 10,
  },
};

// Funciones de inicialización y limpieza
export const AuthLifecycle = {
  /**
   * Inicializar el módulo de autenticación
   */
  async initialize() {
    try {
      console.log("🚀 Iniciando módulo de autenticación...");

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
   * Programar tareas de limpieza automática
   */
  scheduleCleanupTasks() {
    const { session } = AuthConfig;

    // Limpiar sesiones expiradas
    setInterval(async () => {
      try {
        const sessionService = authServices.getSessionService();
        await sessionService.sessionRepository.cleanExpiredSessions();
      } catch (error) {
        console.error("Error en limpieza de sesiones:", error);
      }
    }, session.cleanupInterval);

    // Limpiar tokens expirados
    setInterval(async () => {
      try {
        const authService = authServices.getAuthService();
        await authService.userRepository.cleanExpiredTokens();
      } catch (error) {
        console.error("Error en limpieza de tokens:", error);
      }
    }, 6 * 60 * 60 * 1000); // Cada 6 horas

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
        errors.push("Rol por defecto no encontrado");
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

// Métricas y monitoreo
export const AuthMetrics = {
  /**
   * Obtener métricas generales del sistema de autenticación
   */
  async getSystemMetrics() {
    try {
      const authService = authServices.getAuthService();
      const sessionService = authServices.getSessionService();
      const roleService = authServices.getRoleService();

      // Obtener estadísticas de usuarios
      const userStats = await authService.userRepository.getUserStats();

      // Obtener estadísticas de sesiones (ejemplo con usuario null para estadísticas globales)
      const sessionStats =
        await sessionService.sessionRepository.getSessionStats();

      // Obtener estadísticas de roles
      const roleStats = await roleService.roleRepository.getRoleStats();

      return {
        timestamp: new Date(),
        users: userStats,
        sessions: sessionStats,
        roles: roleStats,
        system: {
          uptime: process.uptime(),
          memoryUsage: process.memoryUsage(),
          nodeVersion: process.version,
        },
      };
    } catch (error) {
      console.error("Error obteniendo métricas del sistema:", error);
      throw error;
    }
  },

  /**
   * Obtener métricas de seguridad
   */
  async getSecurityMetrics() {
    try {
      const sessionService = authServices.getSessionService();

      // Obtener actividad sospechosa reciente (últimos 7 días)
      const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

      const securityStats =
        await sessionService.sessionRepository.model.aggregate([
          {
            $match: {
              suspiciousActivity: { $exists: true, $not: { $size: 0 } },
              createdAt: { $gte: sevenDaysAgo },
            },
          },
          {
            $unwind: "$suspiciousActivity",
          },
          {
            $group: {
              _id: "$suspiciousActivity.activityType",
              count: { $sum: 1 },
              severityBreakdown: {
                $push: "$suspiciousActivity.severity",
              },
            },
          },
          {
            $sort: { count: -1 },
          },
        ]);

      return {
        timestamp: new Date(),
        period: {
          from: sevenDaysAgo,
          to: new Date(),
        },
        suspiciousActivity: securityStats,
        summary: {
          totalIncidents: securityStats.reduce(
            (sum, stat) => sum + stat.count,
            0
          ),
          topThreat: securityStats[0]?.activityType || "none",
        },
      };
    } catch (error) {
      console.error("Error obteniendo métricas de seguridad:", error);
      throw error;
    }
  },

  /**
   * Obtener métricas de rendimiento
   */
  async getPerformanceMetrics() {
    try {
      const sessionService = authServices.getSessionService();

      // Obtener estadísticas de rendimiento de sesiones
      const performanceStats =
        await sessionService.sessionRepository.model.aggregate([
          {
            $match: {
              createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }, // Últimas 24 horas
            },
          },
          {
            $group: {
              _id: null,
              totalSessions: { $sum: 1 },
              avgSessionDuration: {
                $avg: {
                  $subtract: ["$lastAccessedAt", "$createdAt"],
                },
              },
              sessionsWithSuspiciousActivity: {
                $sum: {
                  $cond: [
                    {
                      $gt: [
                        { $size: { $ifNull: ["$suspiciousActivity", []] } },
                        0,
                      ],
                    },
                    1,
                    0,
                  ],
                },
              },
            },
          },
        ]);

      return {
        timestamp: new Date(),
        period: "24h",
        sessions: performanceStats[0] || {
          totalSessions: 0,
          avgSessionDuration: 0,
          sessionsWithSuspiciousActivity: 0,
        },
        healthScore: this.calculateHealthScore(performanceStats[0]),
      };
    } catch (error) {
      console.error("Error obteniendo métricas de rendimiento:", error);
      throw error;
    }
  },

  /**
   * Calcular puntaje de salud del sistema
   * @param {Object} stats - Estadísticas del sistema
   */
  calculateHealthScore(stats) {
    if (!stats) return 0;

    let score = 100;

    // Penalizar por actividad sospechosa
    const suspiciousRate =
      stats.sessionsWithSuspiciousActivity / Math.max(stats.totalSessions, 1);
    score -= suspiciousRate * 50; // Hasta -50 puntos por actividad sospechosa

    // Penalizar por sesiones muy cortas (posibles fallos)
    const avgDurationHours = stats.avgSessionDuration / (1000 * 60 * 60);
    if (avgDurationHours < 0.1) {
      // Menos de 6 minutos promedio
      score -= 20;
    }

    return Math.max(0, Math.round(score));
  },
};

// Utilidades de testing y desarrollo
export const AuthTestUtils = {
  /**
   * Crear usuario de prueba
   * @param {Object} userData - Datos del usuario de prueba
   */
  async createTestUser(userData = {}) {
    if (process.env.NODE_ENV === "production") {
      throw new Error("No se pueden crear usuarios de prueba en producción");
    }

    const defaultData = {
      email: `test_${Date.now()}@example.com`,
      password: "TestPassword123!",
      profile: {
        firstName: "Usuario",
        lastName: "Prueba",
      },
      preferences: {
        language: "es",
      },
    };

    const authService = authServices.getAuthService();
    return await authService.register(
      { ...defaultData, ...userData },
      {
        ipAddress: "127.0.0.1",
        userAgent: "Test-Agent",
        deviceFingerprint: "test-fingerprint",
      }
    );
  },

  /**
   * Limpiar datos de prueba
   */
  async cleanupTestData() {
    if (process.env.NODE_ENV === "production") {
      throw new Error("No se pueden limpiar datos en producción");
    }

    const authService = authServices.getAuthService();

    // Eliminar usuarios de prueba
    await authService.userRepository.model.deleteMany({
      email: { $regex: /^test_.*@example\.com$/ },
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

console.log("📦 Servicios de autenticación cargados");
