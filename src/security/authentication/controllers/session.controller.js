// =============================================================================
// src/security/authentication/controllers/session.controller.js
// =============================================================================
import { SessionService } from "../services/session.service.js";
import { AuthUtils } from "../authentication.index.js";

export class SessionController {
  constructor() {
    this.sessionService = new SessionService();
  }

  /**
   * Obtener sesiones activas del usuario
   */
  async getActiveSessions(req, res) {
    try {
      const userId = req.user.userId;
      const sessions = await this.sessionService.getUserActiveSessions(userId);

      res.json({
        success: true,
        sessions: sessions.map((session) => ({
          sessionId: session.sessionId,
          deviceInfo: session.deviceInfo,
          location: session.location,
          createdAt: session.createdAt,
          lastAccessedAt: session.lastAccessedAt,
          isCurrent: session.sessionToken === req.cookies?.sessionToken,
        })),
      });
    } catch (error) {
      console.error("Error obteniendo sesiones activas:", error);
      res.status(500).json({
        success: false,
        error: "Error interno del servidor",
      });
    }
  }

  /**
   * Invalidar sesión específica
   */
  async invalidateSession(req, res) {
    try {
      const { sessionId } = req.params;
      const userId = req.user.userId;

      await this.sessionService.invalidateUserSession(
        userId,
        sessionId,
        "user_action"
      );

      res.json({
        success: true,
        message: "Sesión invalidada exitosamente",
      });
    } catch (error) {
      console.error("Error invalidando sesión:", error);
      res.status(error.statusCode || 500).json({
        success: false,
        error: error.message || "Error interno del servidor",
      });
    }
  }

  /**
   * Invalidar todas las sesiones excepto la actual
   */
  async invalidateOtherSessions(req, res) {
    try {
      const userId = req.user.userId;
      const currentSessionToken = req.cookies?.sessionToken;

      await this.sessionService.invalidateOtherSessions(
        userId,
        currentSessionToken,
        "user_action"
      );

      res.json({
        success: true,
        message: "Todas las otras sesiones han sido invalidadas",
      });
    } catch (error) {
      console.error("Error invalidando otras sesiones:", error);
      res.status(500).json({
        success: false,
        error: "Error interno del servidor",
      });
    }
  }
}
