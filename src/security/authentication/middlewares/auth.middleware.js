// Uso con tu AutoBanSystem existente
import { getAutoBanSystem } from "../../securityservice/auto_ban.js";
import { AuthService } from "../services/auth.service.js";

// En tu middleware de autenticación
export const authMiddleware = async (req, res, next) => {
  try {
    // 1. Tu AutoBan analysis
    const autoBanSystem = getAutoBanSystem();
    const banAnalysis = autoBanSystem.analyzeRequest(req);

    if (banAnalysis.shouldBan || banAnalysis.isBanned) {
      return res.status(403).json({
        success: false,
        error: "Acceso bloqueado",
      });
    }

    // 2. Validación de sesión con nuestros servicios
    const sessionToken = AuthMiddlewareHelpers.extractSessionToken(req);
    if (!sessionToken) {
      return res.status(401).json({
        success: false,
        error: "No hay sesión activa",
      });
    }

    const requestInfo = AuthMiddlewareHelpers.extractRequestInfo(req);
    const sessionValidation = await AuthService.validateSession(
      sessionToken,
      requestInfo
    );

    // 3. Agregar datos al request
    req.user = sessionValidation.user;
    req.session = sessionValidation.session;

    next();
  } catch (error) {
    const formattedError = AuthMiddlewareHelpers.formatAuthError(error);
    res.status(formattedError.error.statusCode).json(formattedError);
  }
};

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
