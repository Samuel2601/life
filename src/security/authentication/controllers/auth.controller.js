// =============================================================================
// src/security/authentication/controllers/auth.controller.js
// =============================================================================
import { AuthService } from "../services/auth.service.js";
import { SessionService } from "../services/session.service.js";
import { AuthUtils } from "../authentication.index.js";

export class AuthController {
  constructor() {
    this.authService = new AuthService();
    this.sessionService = new SessionService();
  }

  /**
   * Login de usuario
   */
  async login(req, res) {
    try {
      const { email, password, rememberMe = false } = req.body;

      // Validaciones básicas
      if (!email || !password) {
        return res.status(400).json({
          success: false,
          error: "Email y contraseña son requeridos",
        });
      }

      // Preparar datos del request
      const requestInfo = {
        ipAddress: AuthUtils.getRealIP(req),
        userAgent: req.get("User-Agent") || "Unknown",
        deviceFingerprint: AuthUtils.generateDeviceFingerprint(req),
      };

      // Realizar login
      const loginResult = await this.authService.login(
        email,
        password,
        requestInfo,
        rememberMe
      );

      // Configurar cookie de sesión
      res.cookie("sessionToken", loginResult.sessionToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000, // 30 días o 1 día
      });

      res.json({
        success: true,
        message: "Login exitoso",
        user: loginResult.user,
        expiresAt: loginResult.expiresAt,
      });
    } catch (error) {
      console.error("Error en login:", error);
      res.status(error.statusCode || 500).json({
        success: false,
        error: error.message || "Error interno del servidor",
        code: error.code,
      });
    }
  }

  /**
   * Registro de usuario
   */
  async register(req, res) {
    try {
      const {
        email,
        password,
        firstName,
        lastName,
        preferredLanguage = "es",
      } = req.body;

      // Validaciones básicas
      if (!email || !password || !firstName || !lastName) {
        return res.status(400).json({
          success: false,
          error: "Todos los campos son requeridos",
        });
      }

      // Preparar datos del request
      const requestInfo = {
        ipAddress: AuthUtils.getRealIP(req),
        userAgent: req.get("User-Agent") || "Unknown",
        deviceFingerprint: AuthUtils.generateDeviceFingerprint(req),
      };

      // Preparar datos del usuario
      const userData = {
        email,
        password,
        profile: {
          firstName,
          lastName,
        },
        preferredLanguage,
      };

      // Realizar registro
      const registerResult = await this.authService.register(
        userData,
        requestInfo
      );

      res.status(201).json({
        success: true,
        message: "Usuario registrado exitosamente",
        user: registerResult.user,
        requiresEmailVerification: true,
      });
    } catch (error) {
      console.error("Error en registro:", error);
      res.status(error.statusCode || 500).json({
        success: false,
        error: error.message || "Error interno del servidor",
        code: error.code,
      });
    }
  }

  /**
   * Logout de usuario
   */
  async logout(req, res) {
    try {
      const sessionToken = req.cookies?.sessionToken;

      if (sessionToken) {
        await this.sessionService.invalidateSession(
          sessionToken,
          "user_logout"
        );
      }

      // Limpiar cookie
      res.clearCookie("sessionToken");

      res.json({
        success: true,
        message: "Logout exitoso",
      });
    } catch (error) {
      console.error("Error en logout:", error);
      res.status(500).json({
        success: false,
        error: "Error interno del servidor",
      });
    }
  }

  /**
   * Verificar estado de autenticación
   */
  async checkAuth(req, res) {
    try {
      const sessionToken = req.cookies?.sessionToken;

      if (!sessionToken) {
        return res.status(401).json({
          success: false,
          error: "No hay sesión activa",
        });
      }

      const requestInfo = {
        ipAddress: AuthUtils.getRealIP(req),
        userAgent: req.get("User-Agent") || "Unknown",
        deviceFingerprint: AuthUtils.generateDeviceFingerprint(req),
      };

      const sessionValidation = await this.sessionService.validateSession(
        sessionToken,
        requestInfo
      );

      res.json({
        success: true,
        user: sessionValidation.user,
        session: {
          isActive: sessionValidation.session.isActive,
          expiresAt: sessionValidation.session.expiresAt,
          lastAccessedAt: sessionValidation.session.lastAccessedAt,
        },
      });
    } catch (error) {
      console.error("Error verificando autenticación:", error);
      res.status(error.statusCode || 401).json({
        success: false,
        error: error.message || "Sesión inválida",
      });
    }
  }

  /**
   * Verificar email
   */
  async verifyEmail(req, res) {
    try {
      const { token } = req.params;

      const result = await this.authService.verifyEmail(token);

      res.json({
        success: true,
        message: "Email verificado exitosamente",
        user: result.user,
      });
    } catch (error) {
      console.error("Error verificando email:", error);
      res.status(error.statusCode || 400).json({
        success: false,
        error: error.message || "Token de verificación inválido",
      });
    }
  }

  /**
   * Solicitar reset de contraseña
   */
  async requestPasswordReset(req, res) {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({
          success: false,
          error: "Email es requerido",
        });
      }

      await this.authService.requestPasswordReset(email);

      res.json({
        success: true,
        message:
          "Si el email existe, recibirás instrucciones para resetear tu contraseña",
      });
    } catch (error) {
      console.error("Error solicitando reset de contraseña:", error);
      res.status(500).json({
        success: false,
        error: "Error interno del servidor",
      });
    }
  }

  /**
   * Resetear contraseña
   */
  async resetPassword(req, res) {
    try {
      const { token } = req.params;
      const { newPassword } = req.body;

      if (!newPassword) {
        return res.status(400).json({
          success: false,
          error: "Nueva contraseña es requerida",
        });
      }

      await this.authService.resetPassword(token, newPassword);

      res.json({
        success: true,
        message: "Contraseña actualizada exitosamente",
      });
    } catch (error) {
      console.error("Error reseteando contraseña:", error);
      res.status(error.statusCode || 400).json({
        success: false,
        error: error.message || "Token de reset inválido",
      });
    }
  }
}
