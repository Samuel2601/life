// Uso con tu AutoBanSystem existente
import { getAutoBanSystem } from "../../securityservice/auto_ban.js";
import {
  authServices,
  AuthMiddlewareHelpers,
} from "./modules/authentication/services/index.js";

// En tu middleware de autenticación
export const authMiddleware = async (req, res, next) => {
  try {
    // 1. Tu AutoBan analysis
    const autoBanSystem = getAutoBanSystem();
    const banAnalysis = autoBanSystem.analyzeRequest(req);

    if (banAnalysis.shouldBan || banAnalysis.isBanned) {
      return res.status(403).json({ error: "IP blocked" });
    }

    // 2. Validación de sesión con nuestros servicios
    const sessionToken = AuthMiddlewareHelpers.extractSessionToken(req);
    if (!sessionToken) {
      return res.status(401).json({ error: "No session token" });
    }

    const requestInfo = AuthMiddlewareHelpers.extractRequestInfo(req);
    const sessionValidation = await authServices.validateSession(
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
