// =============================================================================
// src/security/authentication/routes/auth.routes.js
// =============================================================================
import { Router } from "express";
import { AuthController } from "../controllers/auth.controller.js";
import { SessionController } from "../controllers/session.controller.js";
import { authMiddleware } from "../middlewares/auth.middleware.js";
import { validateRequest } from "../middlewares/validation.middleware.js";
import { body, param } from "express-validator";

const router = Router();
const authController = new AuthController();
const sessionController = new SessionController();

// =============================================================================
// RUTAS PÚBLICAS (Sin autenticación)
// =============================================================================

/**
 * @route POST /auth/login
 * @desc Login de usuario
 * @access Public
 */
router.post(
  "/login",
  [
    body("email")
      .isEmail()
      .withMessage("Email debe ser válido")
      .normalizeEmail(),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Contraseña debe tener al menos 6 caracteres"),
    body("rememberMe")
      .optional()
      .isBoolean()
      .withMessage("rememberMe debe ser boolean"),
    validateRequest,
  ],
  authController.login.bind(authController)
);

/**
 * @route POST /auth/register
 * @desc Registro de nuevo usuario
 * @access Public
 */
router.post(
  "/register",
  [
    body("email")
      .isEmail()
      .withMessage("Email debe ser válido")
      .normalizeEmail(),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Contraseña debe tener al menos 6 caracteres")
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
      .withMessage(
        "Contraseña debe contener al menos: 1 minúscula, 1 mayúscula, 1 número"
      ),
    body("firstName")
      .trim()
      .isLength({ min: 2 })
      .withMessage("Nombre debe tener al menos 2 caracteres"),
    body("lastName")
      .trim()
      .isLength({ min: 2 })
      .withMessage("Apellido debe tener al menos 2 caracteres"),
    body("preferredLanguage")
      .optional()
      .isIn(["es", "en", "fr", "pt"])
      .withMessage("Idioma debe ser: es, en, fr, pt"),
    validateRequest,
  ],
  authController.register.bind(authController)
);

/**
 * @route POST /auth/logout
 * @desc Logout de usuario
 * @access Public (pero requiere cookie de sesión)
 */
router.post("/logout", authController.logout.bind(authController));

/**
 * @route GET /auth/check
 * @desc Verificar estado de autenticación
 * @access Public (pero requiere cookie de sesión)
 */
router.get("/check", authController.checkAuth.bind(authController));

/**
 * @route GET /auth/verify-email/:token
 * @desc Verificar email con token
 * @access Public
 */
router.get(
  "/verify-email/:token",
  [
    param("token")
      .isLength({ min: 10 })
      .withMessage("Token de verificación inválido"),
    validateRequest,
  ],
  authController.verifyEmail.bind(authController)
);

/**
 * @route POST /auth/forgot-password
 * @desc Solicitar reset de contraseña
 * @access Public
 */
router.post(
  "/forgot-password",
  [
    body("email")
      .isEmail()
      .withMessage("Email debe ser válido")
      .normalizeEmail(),
    validateRequest,
  ],
  authController.requestPasswordReset.bind(authController)
);

/**
 * @route POST /auth/reset-password/:token
 * @desc Resetear contraseña con token
 * @access Public
 */
router.post(
  "/reset-password/:token",
  [
    param("token").isLength({ min: 10 }).withMessage("Token de reset inválido"),
    body("newPassword")
      .isLength({ min: 6 })
      .withMessage("Nueva contraseña debe tener al menos 6 caracteres")
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
      .withMessage(
        "Nueva contraseña debe contener al menos: 1 minúscula, 1 mayúscula, 1 número"
      ),
    validateRequest,
  ],
  authController.resetPassword.bind(authController)
);

// =============================================================================
// RUTAS PROTEGIDAS (Requieren autenticación)
// =============================================================================

/**
 * @route GET /auth/sessions
 * @desc Obtener sesiones activas del usuario
 * @access Private
 */
router.get(
  "/sessions",
  authMiddleware,
  sessionController.getActiveSessions.bind(sessionController)
);

/**
 * @route DELETE /auth/sessions/:sessionId
 * @desc Invalidar sesión específica
 * @access Private
 */
router.delete(
  "/sessions/:sessionId",
  [
    authMiddleware,
    param("sessionId").isMongoId().withMessage("ID de sesión inválido"),
    validateRequest,
  ],
  sessionController.invalidateSession.bind(sessionController)
);

/**
 * @route DELETE /auth/sessions/others
 * @desc Invalidar todas las otras sesiones
 * @access Private
 */
router.delete(
  "/sessions/others",
  authMiddleware,
  sessionController.invalidateOtherSessions.bind(sessionController)
);

export default router;
