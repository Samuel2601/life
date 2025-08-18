// =============================================================================
// src/security/authentication/controllers/session.controller.js
// =============================================================================
import { SessionService } from "../services/session.service.js";
import {
  AuthUtils,
  AuthError,
  AuthErrorCodes,
} from "../authentication.index.js";

export class SessionController {
  constructor() {
    this.sessionService = new SessionService();
  }

  /**
   * Obtener sesiones activas del usuario
   */
  async getActiveSessions(req, res) {
    try {
      if (!req.user || !req.session) {
        return res.status(401).json({
          success: false,
          error: "Autenticación requerida",
          code: AuthErrorCodes.PERMISSION_DENIED,
        });
      }

      const { includeCompromised = false, limit = 10 } = req.query;

      // Obtener sesiones activas
      const sessionsData = await this.sessionService.getUserActiveSessions(
        req.user.id,
        {
          includeCompromised: includeCompromised === "true",
          limit: parseInt(limit) || 10,
          currentSessionId: req.session.id,
        }
      );

      // Agregar estadísticas adicionales
      const stats = await this.sessionService.getSessionStats({
        userId: req.user.id,
        timeRange: 30, // últimos 30 días
      });

      res.status(200).json({
        success: true,
        data: {
          sessions: sessionsData.sessions,
          totalActive: sessionsData.totalActive,
          stats: {
            totalSessions: stats.totalSessions,
            averageSessionDuration: stats.averageSessionDurationHours,
            deviceTypes: stats.deviceTypes,
            browsers: stats.browsers,
          },
        },
      });
    } catch (error) {
      console.error("Error obteniendo sesiones activas:", error);

      if (error instanceof AuthError) {
        return res.status(error.statusCode).json({
          success: false,
          error: error.message,
          code: error.code,
        });
      }

      res.status(500).json({
        success: false,
        error: "Error interno obteniendo sesiones",
        code: "SESSION_RETRIEVAL_ERROR",
      });
    }
  }

  /**
   * Invalidar sesión específica
   */
  async invalidateSession(req, res) {
    try {
      if (!req.user || !req.session) {
        return res.status(401).json({
          success: false,
          error: "Autenticación requerida",
          code: AuthErrorCodes.PERMISSION_DENIED,
        });
      }

      const { sessionId } = req.params;

      if (!sessionId) {
        return res.status(400).json({
          success: false,
          error: "ID de sesión requerido",
          code: "MISSING_SESSION_ID",
        });
      }

      // Verificar que no trate de invalidar su propia sesión actual
      if (sessionId === req.session.id.toString()) {
        return res.status(400).json({
          success: false,
          error: "No puedes invalidar tu sesión actual",
          code: "CANNOT_INVALIDATE_CURRENT_SESSION",
          hint: "Usa /logout para cerrar la sesión actual",
        });
      }

      // Preparar información del request
      const requestInfo = {
        ipAddress: AuthUtils.getRealIP(req),
        userAgent: req.get("User-Agent") || "Unknown",
        reason: "terminated_by_user",
      };

      // Invalidar sesión específica
      await this.sessionService.terminateSession(
        req.user.id,
        sessionId,
        requestInfo
      );

      res.status(200).json({
        success: true,
        message: "Sesión invalidada exitosamente",
        sessionId,
      });
    } catch (error) {
      console.error("Error invalidando sesión:", error);

      if (error instanceof AuthError) {
        return res.status(error.statusCode).json({
          success: false,
          error: error.message,
          code: error.code,
        });
      }

      res.status(500).json({
        success: false,
        error: "Error interno invalidando sesión",
        code: "SESSION_INVALIDATION_ERROR",
      });
    }
  }

  /**
   * Invalidar todas las otras sesiones
   */
  async invalidateOtherSessions(req, res) {
    try {
      if (!req.user || !req.session) {
        return res.status(401).json({
          success: false,
          error: "Autenticación requerida",
          code: AuthErrorCodes.PERMISSION_DENIED,
        });
      }

      // Preparar información del request
      const requestInfo = {
        ipAddress: AuthUtils.getRealIP(req),
        userAgent: req.get("User-Agent") || "Unknown",
        reason: "terminated_other_sessions_by_user",
      };

      // Invalidar todas las otras sesiones
      const result = await this.sessionService.terminateOtherSessions(
        req.user.id,
        req.session.id,
        requestInfo
      );

      res.status(200).json({
        success: true,
        message: "Otras sesiones invalidadas exitosamente",
        data: {
          terminatedSessions: result.terminatedSessions,
          currentSessionPreserved: result.currentSessionPreserved,
        },
      });
    } catch (error) {
      console.error("Error invalidando otras sesiones:", error);

      if (error instanceof AuthError) {
        return res.status(error.statusCode).json({
          success: false,
          error: error.message,
          code: error.code,
        });
      }

      res.status(500).json({
        success: false,
        error: "Error interno invalidando sesiones",
        code: "SESSIONS_INVALIDATION_ERROR",
      });
    }
  }

  /**
   * Obtener detalles de la sesión actual
   */
  async getCurrentSession(req, res) {
    try {
      if (!req.user || !req.session) {
        return res.status(401).json({
          success: false,
          error: "Autenticación requerida",
          code: AuthErrorCodes.PERMISSION_DENIED,
        });
      }

      // Información adicional de la sesión actual
      const sessionInfo = {
        id: req.session.id,
        createdAt: req.session.createdAt,
        lastAccessedAt: req.session.lastAccessedAt,
        expiresAt: req.session.expiresAt,
        rememberMe: req.session.rememberMe,
        currentActivity: {
          ipAddress: AuthUtils.getRealIP(req),
          userAgent: req.get("User-Agent") || "Unknown",
          timestamp: new Date().toISOString(),
        },
      };

      res.status(200).json({
        success: true,
        data: {
          session: sessionInfo,
          user: {
            id: req.user.id,
            email: req.user.email,
            profile: req.user.profile,
          },
        },
      });
    } catch (error) {
      console.error("Error obteniendo sesión actual:", error);

      res.status(500).json({
        success: false,
        error: "Error interno obteniendo información de sesión",
        code: "SESSION_INFO_ERROR",
      });
    }
  }

  /**
   * Obtener estadísticas de sesiones
   */
  async getSessionStats(req, res) {
    try {
      if (!req.user || !req.session) {
        return res.status(401).json({
          success: false,
          error: "Autenticación requerida",
          code: AuthErrorCodes.PERMISSION_DENIED,
        });
      }

      const { timeRange = 30 } = req.query;

      // Obtener estadísticas
      const stats = await this.sessionService.getSessionStats({
        userId: req.user.id,
        timeRange: parseInt(timeRange) || 30,
      });

      // Análisis de actividad sospechosa
      const suspiciousAnalysis =
        await this.sessionService.analyzeSuspiciousActivity(req.user.id, {
          timeWindow: 24,
        });

      res.status(200).json({
        success: true,
        data: {
          stats,
          security: {
            suspiciousIndicators: suspiciousAnalysis.suspiciousIndicators,
            riskLevel: suspiciousAnalysis.riskLevel,
            recommendations: suspiciousAnalysis.recommendations,
          },
          timeRange: parseInt(timeRange) || 30,
        },
      });
    } catch (error) {
      console.error("Error obteniendo estadísticas de sesiones:", error);

      res.status(500).json({
        success: false,
        error: "Error interno obteniendo estadísticas",
        code: "SESSION_STATS_ERROR",
      });
    }
  }

  /**
   * Extender tiempo de vida de la sesión actual
   */
  async extendSession(req, res) {
    try {
      if (!req.user || !req.session) {
        return res.status(401).json({
          success: false,
          error: "Autenticación requerida",
          code: AuthErrorCodes.PERMISSION_DENIED,
        });
      }

      const { hours = 8 } = req.body;

      // Validar horas solicitadas
      const extendHours = parseInt(hours);
      if (isNaN(extendHours) || extendHours < 1 || extendHours > 48) {
        return res.status(400).json({
          success: false,
          error: "Horas de extensión deben estar entre 1 y 48",
          code: "INVALID_EXTEND_HOURS",
        });
      }

      // Calcular nueva fecha de expiración
      const newExpiresAt = new Date(Date.now() + extendHours * 60 * 60 * 1000);

      // Actualizar sesión
      await this.sessionService.sessionRepository.model.findByIdAndUpdate(
        req.session.id,
        {
          $set: {
            expiresAt: newExpiresAt,
            updatedAt: new Date(),
          },
        }
      );

      // Actualizar cookie si es necesario
      if (req.cookies?.sessionToken) {
        res.cookie("sessionToken", req.sessionToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === "production",
          sameSite: "strict",
          maxAge: extendHours * 60 * 60 * 1000,
          path: "/",
        });
      }

      res.status(200).json({
        success: true,
        message: "Sesión extendida exitosamente",
        data: {
          newExpiresAt,
          extendedHours: extendHours,
        },
      });
    } catch (error) {
      console.error("Error extendiendo sesión:", error);

      res.status(500).json({
        success: false,
        error: "Error interno extendiendo sesión",
        code: "SESSION_EXTEND_ERROR",
      });
    }
  }

  /**
   * Obtener actividad de seguridad de las sesiones
   */
  async getSecurityActivity(req, res) {
    try {
      if (!req.user || !req.session) {
        return res.status(401).json({
          success: false,
          error: "Autenticación requerida",
          code: AuthErrorCodes.PERMISSION_DENIED,
        });
      }

      const { timeWindow = 24, limit = 50 } = req.query;

      // Análisis de actividad sospechosa detallado
      const analysis = await this.sessionService.analyzeSuspiciousActivity(
        req.user.id,
        {
          timeWindow: parseInt(timeWindow) || 24,
          limit: parseInt(limit) || 50,
        }
      );

      // Obtener sesiones con actividad sospechosa
      const suspiciousSessions =
        await this.sessionService.sessionRepository.model
          .find({
            userId: req.user.id,
            "suspiciousActivity.0": { $exists: true },
          })
          .select(
            "deviceInfo location suspiciousActivity createdAt lastAccessedAt"
          )
          .sort({ "suspiciousActivity.timestamp": -1 })
          .limit(parseInt(limit) || 50)
          .lean();

      res.status(200).json({
        success: true,
        data: {
          analysis,
          suspiciousSessions,
          timeWindow: parseInt(timeWindow) || 24,
        },
      });
    } catch (error) {
      console.error("Error obteniendo actividad de seguridad:", error);

      res.status(500).json({
        success: false,
        error: "Error interno obteniendo actividad de seguridad",
        code: "SECURITY_ACTIVITY_ERROR",
      });
    }
  }
}
