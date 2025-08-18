// =============================================================================
// src/security/authentication/controllers/auth.controller.js
// =============================================================================
import { AuthService } from "../services/auth.service.js";
import { SessionService } from "../services/session.service.js";
import {
  AuthUtils,
  AuthError,
  AuthErrorCodes,
} from "../authentication.index.js";

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
        maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 8 * 60 * 60 * 1000, // 30 días o 8 horas
        path: "/",
      });

      // Respuesta exitosa (sin tokens sensibles)
      res.status(200).json({
        success: true,
        message: "Login exitoso",
        user: {
          id: loginResult.user.id,
          email: loginResult.user.email,
          profile: loginResult.user.profile,
          roles: loginResult.user.roles,
          preferences: loginResult.user.preferences,
        },
        session: {
          expiresAt: loginResult.session.expiresAt,
          rememberMe: loginResult.session.rememberMe,
        },
      });
    } catch (error) {
      console.error("Error en login:", error);

      // Manejar errores específicos de autenticación
      if (error instanceof AuthError) {
        return res.status(error.statusCode).json({
          success: false,
          error: error.message,
          code: error.code,
        });
      }

      // Error genérico
      res.status(500).json({
        success: false,
        error: "Error interno del servidor",
      });
    }
  }

  /**
   * Registro de nuevo usuario
   */
  async register(req, res) {
    try {
      const {
        email,
        password,
        firstName,
        lastName,
        preferredLanguage = "es",
        timezone = "America/Lima",
      } = req.body;

      // Validaciones básicas
      if (!email || !password || !firstName || !lastName) {
        return res.status(400).json({
          success: false,
          error: "Email, contraseña, nombre y apellido son requeridos",
        });
      }

      // Preparar datos de registro
      const registrationData = {
        email: email.toLowerCase(),
        password,
        profile: {
          firstName: firstName.trim(),
          lastName: lastName.trim(),
        },
        preferences: {
          language: preferredLanguage,
          timezone,
        },
        registrationSource: "web",
      };

      // Preparar datos del request
      const requestInfo = {
        ipAddress: AuthUtils.getRealIP(req),
        userAgent: req.get("User-Agent") || "Unknown",
        deviceFingerprint: AuthUtils.generateDeviceFingerprint(req),
      };

      // Realizar registro
      const registerResult = await this.authService.register(
        registrationData,
        requestInfo
      );

      // Configurar cookie de sesión automática
      res.cookie("sessionToken", registerResult.sessionToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        maxAge: 8 * 60 * 60 * 1000, // 8 horas por defecto
        path: "/",
      });

      // Respuesta exitosa
      res.status(201).json({
        success: true,
        message: "Usuario registrado exitosamente",
        user: {
          id: registerResult.user.id,
          email: registerResult.user.email,
          profile: registerResult.user.profile,
          isEmailVerified: registerResult.user.isEmailVerified,
        },
        session: {
          expiresAt: registerResult.session.expiresAt,
        },
      });
    } catch (error) {
      console.error("Error en registro:", error);

      if (error instanceof AuthError) {
        return res.status(error.statusCode).json({
          success: false,
          error: error.message,
          code: error.code,
        });
      }

      res.status(500).json({
        success: false,
        error: "Error interno del servidor",
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
        // Invalidar sesión en el servidor
        try {
          await this.sessionService.invalidateSessionByToken(sessionToken);
        } catch (sessionError) {
          console.error("Error invalidando sesión:", sessionError);
          // Continuar con logout aunque falle la invalidación
        }
      }

      // Limpiar cookie
      res.clearCookie("sessionToken", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict",
        path: "/",
      });

      res.status(200).json({
        success: true,
        message: "Logout exitoso",
      });
    } catch (error) {
      console.error("Error en logout:", error);

      // Aunque haya error, limpiar cookie
      res.clearCookie("sessionToken");

      res.status(200).json({
        success: true,
        message: "Logout realizado",
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
          authenticated: false,
          error: "No hay sesión activa",
        });
      }

      // Preparar información del request
      const requestInfo = {
        ipAddress: AuthUtils.getRealIP(req),
        userAgent: req.get("User-Agent") || "Unknown",
        deviceFingerprint: AuthUtils.generateDeviceFingerprint(req),
      };

      // Validar sesión
      const validation = await this.authService.validateSession(
        sessionToken,
        requestInfo
      );

      if (!validation.isValid) {
        // Limpiar cookie inválida
        res.clearCookie("sessionToken");

        return res.status(401).json({
          success: false,
          authenticated: false,
          error: validation.reason || "Sesión inválida",
        });
      }

      // Sesión válida
      res.status(200).json({
        success: true,
        authenticated: true,
        user: {
          id: validation.user.id,
          email: validation.user.email,
          profile: validation.user.profile,
          roles: validation.user.roles,
          preferences: validation.user.preferences,
        },
        session: {
          expiresAt: validation.session.expiresAt,
          lastAccessedAt: validation.session.lastAccessedAt,
        },
      });
    } catch (error) {
      console.error("Error verificando autenticación:", error);

      res.status(500).json({
        success: false,
        authenticated: false,
        error: "Error verificando sesión",
      });
    }
  }

  /**
   * Verificar email con token
   */
  async verifyEmail(req, res) {
    try {
      const { token } = req.params;

      if (!token) {
        return res.status(400).json({
          success: false,
          error: "Token de verificación requerido",
        });
      }

      // Verificar email
      const result = await this.authService.verifyEmail(token);

      res.status(200).json({
        success: true,
        message: "Email verificado exitosamente",
        user: {
          id: result.user.id,
          email: result.user.email,
          isEmailVerified: result.user.isEmailVerified,
        },
      });
    } catch (error) {
      console.error("Error verificando email:", error);

      if (error instanceof AuthError) {
        return res.status(error.statusCode).json({
          success: false,
          error: error.message,
          code: error.code,
        });
      }

      res.status(500).json({
        success: false,
        error: "Error verificando email",
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

      // Preparar información del request
      const requestInfo = {
        ipAddress: AuthUtils.getRealIP(req),
        userAgent: req.get("User-Agent") || "Unknown",
      };

      // Solicitar reset (siempre respuesta exitosa por seguridad)
      await this.authService.requestPasswordReset(email, requestInfo);

      res.status(200).json({
        success: true,
        message:
          "Si el email existe, recibirás instrucciones para resetear tu contraseña",
      });
    } catch (error) {
      console.error("Error solicitando reset:", error);

      // Siempre respuesta exitosa por seguridad
      res.status(200).json({
        success: true,
        message:
          "Si el email existe, recibirás instrucciones para resetear tu contraseña",
      });
    }
  }

  /**
   * Resetear contraseña con token
   */
  async resetPassword(req, res) {
    try {
      const { token } = req.params;
      const { newPassword } = req.body;

      if (!token || !newPassword) {
        return res.status(400).json({
          success: false,
          error: "Token y nueva contraseña son requeridos",
        });
      }

      // Preparar información del request
      const requestInfo = {
        ipAddress: AuthUtils.getRealIP(req),
        userAgent: req.get("User-Agent") || "Unknown",
      };

      // Resetear contraseña
      const result = await this.authService.resetPassword(
        token,
        newPassword,
        requestInfo
      );

      res.status(200).json({
        success: true,
        message: "Contraseña actualizada exitosamente",
        user: {
          id: result.user.id,
          email: result.user.email,
        },
      });
    } catch (error) {
      console.error("Error reseteando contraseña:", error);

      if (error instanceof AuthError) {
        return res.status(error.statusCode).json({
          success: false,
          error: error.message,
          code: error.code,
        });
      }

      res.status(500).json({
        success: false,
        error: "Error reseteando contraseña",
      });
    }
  }
}
