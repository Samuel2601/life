// =============================================================================
// src/modules/authentication/services/auth.service.js
// =============================================================================
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { UserRepository } from "../repositories/user.repository.js";
import { UserSessionRepository } from "../repositories/user_session.repository.js";
import { RoleRepository } from "../repositories/role.repository.js";
import {
  AuthError,
  AuthErrorCodes,
  AuthConstants,
} from "../authentication.index.js";
import { TransactionHelper } from "../../../utils/transsaccion.helper.js";

export class AuthService {
  constructor() {
    this.userRepository = new UserRepository();
    this.sessionRepository = new UserSessionRepository();
    this.roleRepository = new RoleRepository();
    this.jwtSecret =
      process.env.JWT_SECRET || "default_secret_change_in_production";
  }

  /**
   * Registrar nuevo usuario
   * @param {Object} registrationData - Datos de registro
   * @param {Object} requestInfo - Información del request
   */
  async register(registrationData, requestInfo) {
    return await TransactionHelper.executeWithOptionalTransaction(
      async (session) => {
        try {
          const {
            email,
            password,
            profile,
            preferences = {},
            registrationSource = "web",
            oauthProvider = null,
            oauthData = null,
          } = registrationData;

          const { ipAddress, userAgent, deviceFingerprint } = requestInfo;

          // Validar datos básicos
          this.validateRegistrationData(registrationData);

          // Verificar si el email ya existe
          const existingUser = await this.userRepository.findByEmail(email);
          if (existingUser) {
            throw new AuthError(
              "El email ya está registrado",
              AuthErrorCodes.EMAIL_ALREADY_EXISTS,
              409
            );
          }

          // Obtener rol por defecto
          const defaultRole = await this.roleRepository.getDefaultRole();
          if (!defaultRole) {
            throw new AuthError(
              "Error de configuración: rol por defecto no encontrado",
              AuthErrorCodes.ROLE_NOT_FOUND,
              500
            );
          }

          // Preparar datos del usuario
          const userData = {
            email: email.toLowerCase(),
            profile: {
              firstName: profile.firstName,
              lastName: profile.lastName,
              avatar: profile.avatar || null,
              dateOfBirth: profile.dateOfBirth || null,
              phone: profile.phone || null,
              bio: profile.bio || null,
            },
            roles: [defaultRole._id],
            preferences: {
              language: preferences.language || "es",
              timezone: preferences.timezone || "America/Lima",
              ...preferences,
            },
            registrationSource,
            isEmailVerified: oauthProvider ? true : false, // OAuth emails son pre-verificados
          };

          // Crear usuario
          const sessionData = {
            userId: null, // Se establece después de crear el usuario
            ip: ipAddress,
            userAgent,
          };

          const newUser = await this.userRepository.createUser(
            { ...userData, password },
            sessionData,
            { session }
          );

          // Conectar OAuth si aplica
          if (oauthProvider && oauthData) {
            await this.userRepository.connectOAuthProvider(
              newUser._id,
              oauthProvider,
              oauthData,
              { ...sessionData, userId: newUser._id }
            );
          }

          // Generar token de verificación de email si no es OAuth
          let verificationToken = null;
          if (!oauthProvider) {
            verificationToken =
              await this.userRepository.generateEmailVerificationToken(
                newUser._id,
                { session }
              );
          }

          console.log(`✅ Usuario registrado: ${email} (ID: ${newUser._id})`);

          return {
            user: this.sanitizeUser(newUser),
            verificationToken,
            requiresEmailVerification: !oauthProvider,
          };
        } catch (error) {
          console.error("Error en registro:", error);
          if (error instanceof AuthError) {
            throw error;
          }
          throw new AuthError(
            "Error interno durante el registro",
            AuthErrorCodes.REGISTRATION_FAILED,
            500
          );
        }
      }
    );
  }

  /**
   * Iniciar sesión con email y contraseña
   * @param {Object} loginData - Datos de login
   * @param {Object} requestInfo - Información del request
   */
  async login(loginData, requestInfo) {
    try {
      const { email, password, rememberMe = false } = loginData;
      const { ipAddress, userAgent, deviceFingerprint } = requestInfo;

      // Validar credenciales
      const user = await this.userRepository.validateCredentials(
        email,
        password
      );
      if (!user) {
        throw new AuthError(
          "Credenciales inválidas",
          AuthErrorCodes.INVALID_CREDENTIALS,
          401
        );
      }

      // Verificar estado de la cuenta
      this.validateUserStatus(user);

      // Generar tokens
      const tokens = this.generateTokens(user._id);

      // Crear sesión
      const sessionData = {
        userId: user._id,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        deviceFingerprint,
        ipAddress,
        userAgent,
        rememberMe,
      };

      const userDataForAudit = {
        userId: user._id,
        ip: ipAddress,
        userAgent,
      };

      const session = await this.sessionRepository.createSession(
        sessionData,
        userDataForAudit
      );

      // Actualizar estadísticas de login
      await this.userRepository.resetLoginAttempts(user._id);

      console.log(
        `✅ Usuario autenticado: ${email} (Sesión: ${session.sessionId})`
      );

      return {
        user: this.sanitizeUser(user),
        session: {
          sessionToken: session.sessionToken,
          expiresAt: session.expiresAt,
          rememberMe: session.rememberMe,
        },
        // Los access/refresh tokens NO se devuelven al cliente
      };
    } catch (error) {
      console.error("Error en login:", error);
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        "Error interno durante el login",
        AuthErrorCodes.LOGIN_FAILED,
        500
      );
    }
  }

  /**
   * Autenticación OAuth
   * @param {Object} oauthData - Datos de OAuth
   * @param {Object} requestInfo - Información del request
   */
  async oauthLogin(oauthData, requestInfo) {
    return await TransactionHelper.executeWithOptionalTransaction(
      async (session) => {
        try {
          const {
            provider,
            providerId,
            email,
            profile,
            accessToken,
            refreshToken,
            expiresIn,
          } = oauthData;

          const { ipAddress, userAgent, deviceFingerprint } = requestInfo;

          // Buscar usuario existente por email
          let user = await this.userRepository.findByEmail(email);

          if (user) {
            // Usuario existe - conectar OAuth si no está conectado
            if (!user.oauthProviders?.[provider]?.providerId) {
              await this.userRepository.connectOAuthProvider(
                user._id,
                provider,
                {
                  providerId,
                  email,
                  isVerified: true,
                },
                {
                  userId: user._id,
                  ip: ipAddress,
                  userAgent,
                }
              );
            }

            // Marcar email como verificado si viene de OAuth
            if (!user.isEmailVerified) {
              await this.userRepository.update(
                user._id,
                { isEmailVerified: true },
                {
                  userId: user._id,
                  ip: ipAddress,
                  userAgent,
                }
              );
            }
          } else {
            // Usuario nuevo - registrar automáticamente
            const registrationData = {
              email,
              profile: {
                firstName:
                  profile.firstName || profile.name?.split(" ")[0] || "Usuario",
                lastName:
                  profile.lastName ||
                  profile.name?.split(" ").slice(1).join(" ") ||
                  "OAuth",
                avatar: profile.avatar || profile.picture,
              },
              registrationSource: "oauth",
              oauthProvider: provider,
              oauthData: {
                providerId,
                email,
                isVerified: true,
              },
            };

            const registrationResult = await this.register(
              registrationData,
              requestInfo
            );
            user = registrationResult.user;
          }

          // Verificar estado de la cuenta
          this.validateUserStatus(user);

          // Generar tokens JWT
          const tokens = this.generateTokens(user._id);

          // Crear sesión con datos OAuth
          const sessionData = {
            userId: user._id,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            deviceFingerprint,
            ipAddress,
            userAgent,
            rememberMe: true, // OAuth sessions son persistentes por defecto
            oauthProvider: provider,
            oauthSessionData: {
              accessToken,
              refreshToken,
              expiresAt: new Date(Date.now() + expiresIn * 1000),
              scope: [], // Agregar scopes si es necesario
            },
          };

          const userSession = await this.sessionRepository.createSession(
            sessionData,
            {
              userId: user._id,
              ip: ipAddress,
              userAgent,
            }
          );

          console.log(`✅ OAuth login exitoso: ${email} via ${provider}`);

          return {
            user: this.sanitizeUser(user),
            session: {
              sessionToken: userSession.sessionToken,
              expiresAt: userSession.expiresAt,
              rememberMe: userSession.rememberMe,
            },
            isNewUser:
              !user.createdAt ||
              Date.now() - new Date(user.createdAt).getTime() < 60000, // Nuevo si se creó hace menos de 1 minuto
          };
        } catch (error) {
          console.error("Error en OAuth login:", error);
          if (error instanceof AuthError) {
            throw error;
          }
          throw new AuthError(
            "Error en autenticación OAuth",
            AuthErrorCodes.OAUTH_ERROR,
            500
          );
        }
      }
    );
  }

  /**
   * Validar sesión activa
   * @param {string} sessionToken - Token de sesión
   * @param {Object} requestInfo - Información del request
   */
  async validateSession(sessionToken, requestInfo) {
    try {
      const { ipAddress, userAgent, deviceFingerprint } = requestInfo;

      const session = await this.sessionRepository.validateSession(
        sessionToken,
        deviceFingerprint,
        ipAddress
      );

      if (!session) {
        throw new AuthError(
          "Sesión inválida o expirada",
          AuthErrorCodes.SESSION_INVALID,
          401
        );
      }

      // Obtener información completa del usuario
      const user = await this.userRepository.findById(session.userId, {
        populate: ["roles"],
      });

      if (!user) {
        throw new AuthError(
          "Usuario de sesión no encontrado",
          AuthErrorCodes.SESSION_INVALID,
          401
        );
      }

      this.validateUserStatus(user);

      return {
        user: this.sanitizeUser(user),
        session: {
          sessionId: session.sessionId,
          expiresAt: session.expiresAt,
          lastAccessedAt: session.lastAccessedAt,
          deviceInfo: session.deviceInfo,
        },
      };
    } catch (error) {
      console.error("Error validando sesión:", error);
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        "Error interno validando sesión",
        AuthErrorCodes.SESSION_INVALID,
        500
      );
    }
  }

  /**
   * Cerrar sesión
   * @param {string} sessionToken - Token de sesión
   * @param {Object} requestInfo - Información del request
   */
  async logout(sessionToken, requestInfo) {
    try {
      const { ipAddress, userAgent } = requestInfo;

      // Buscar sesión por token
      const session = await this.sessionRepository.model.findOne({
        sessionToken,
        isActive: true,
      });

      if (session) {
        await this.sessionRepository.invalidateSession(
          session._id,
          "manual_logout"
        );

        console.log(
          `✅ Logout exitoso: Usuario ${session.userId} desde ${ipAddress}`
        );
        return { success: true };
      }

      return { success: false, message: "Sesión no encontrada" };
    } catch (error) {
      console.error("Error en logout:", error);
      throw new AuthError(
        "Error interno durante logout",
        AuthErrorCodes.LOGOUT_FAILED,
        500
      );
    }
  }

  /**
   * Cerrar todas las sesiones de un usuario
   * @param {string} userId - ID del usuario
   * @param {string} exceptSessionId - ID de sesión a conservar (opcional)
   * @param {Object} requestInfo - Información del request
   */
  async logoutAllDevices(userId, exceptSessionId = null, requestInfo) {
    try {
      const { ipAddress } = requestInfo;

      const invalidatedCount =
        await this.sessionRepository.invalidateUserSessions(userId, {
          exceptSessionId,
          reason: "logout_all_devices",
        });

      console.log(
        `✅ Logout masivo: ${invalidatedCount} sesiones cerradas para usuario ${userId}`
      );

      return {
        success: true,
        invalidatedSessions: invalidatedCount,
      };
    } catch (error) {
      console.error("Error en logout masivo:", error);
      throw new AuthError(
        "Error cerrando todas las sesiones",
        AuthErrorCodes.LOGOUT_FAILED,
        500
      );
    }
  }

  /**
   * Refrescar tokens de acceso
   * @param {string} sessionToken - Token de sesión
   * @param {Object} requestInfo - Información del request
   */
  async refreshTokens(sessionToken, requestInfo) {
    try {
      const { ipAddress, userAgent, deviceFingerprint } = requestInfo;

      // Validar sesión actual
      const session = await this.sessionRepository.validateSession(
        sessionToken,
        deviceFingerprint,
        ipAddress
      );

      if (!session) {
        throw new AuthError(
          "Sesión inválida para renovación",
          AuthErrorCodes.SESSION_INVALID,
          401
        );
      }

      // Generar nuevos tokens
      const newTokens = this.generateTokens(session.userId);

      // Actualizar sesión con nuevos tokens
      await this.sessionRepository.rotateTokens(
        session.sessionId,
        newTokens.accessToken,
        newTokens.refreshToken,
        {
          userId: session.userId,
          ip: ipAddress,
          userAgent,
        }
      );

      console.log(`🔄 Tokens renovados para sesión: ${session.sessionId}`);

      return {
        success: true,
        expiresAt: session.expiresAt,
      };
    } catch (error) {
      console.error("Error renovando tokens:", error);
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        "Error renovando tokens",
        AuthErrorCodes.TOKEN_REFRESH_FAILED,
        500
      );
    }
  }

  /**
   * Verificar email con token
   * @param {string} token - Token de verificación
   * @param {Object} requestInfo - Información del request
   */
  async verifyEmail(token, requestInfo) {
    try {
      const { ipAddress, userAgent } = requestInfo;

      const user = await this.userRepository.verifyEmailWithToken(token, {
        userId: null, // Usuario del sistema
        ip: ipAddress,
        userAgent,
      });

      console.log(`✅ Email verificado: ${user.email}`);

      return {
        success: true,
        user: this.sanitizeUser(user),
      };
    } catch (error) {
      console.error("Error verificando email:", error);
      throw new AuthError(
        "Token de verificación inválido o expirado",
        AuthErrorCodes.TOKEN_INVALID,
        400
      );
    }
  }

  /**
   * Solicitar reset de contraseña
   * @param {string} email - Email del usuario
   * @param {Object} requestInfo - Información del request
   */
  async requestPasswordReset(email, requestInfo) {
    try {
      const { ipAddress, userAgent } = requestInfo;

      const result = await this.userRepository.generatePasswordResetToken(
        email
      );

      console.log(`📧 Reset de contraseña solicitado: ${email}`);

      return {
        success: true,
        token: result.token, // En producción, enviar por email
        email: result.email,
      };
    } catch (error) {
      // Por seguridad, no revelar si el email existe o no
      console.error("Error solicitando reset:", error);
      return {
        success: true,
        message: "Si el email existe, recibirás instrucciones de reset",
      };
    }
  }

  /**
   * Resetear contraseña con token
   * @param {string} token - Token de reset
   * @param {string} newPassword - Nueva contraseña
   * @param {Object} requestInfo - Información del request
   */
  async resetPassword(token, newPassword, requestInfo) {
    try {
      const { ipAddress, userAgent } = requestInfo;

      // Validar fortaleza de contraseña
      const passwordValidation = this.validatePasswordStrength(newPassword);
      if (!passwordValidation.isValid) {
        throw new AuthError(
          `Contraseña débil: ${passwordValidation.errors.join(", ")}`,
          AuthErrorCodes.WEAK_PASSWORD,
          400
        );
      }

      const user = await this.userRepository.resetPasswordWithToken(
        token,
        newPassword,
        {
          userId: null, // Usuario del sistema
          ip: ipAddress,
          userAgent,
        }
      );

      // Invalidar todas las sesiones del usuario por seguridad
      await this.sessionRepository.invalidateUserSessions(user._id, {
        reason: "password_reset",
      });

      console.log(`✅ Contraseña reseteada: ${user.email}`);

      return {
        success: true,
        message: "Contraseña actualizada exitosamente",
      };
    } catch (error) {
      console.error("Error reseteando contraseña:", error);
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        "Token de reset inválido o expirado",
        AuthErrorCodes.TOKEN_INVALID,
        400
      );
    }
  }

  /**
   * Cambiar contraseña (usuario autenticado)
   * @param {string} userId - ID del usuario
   * @param {string} currentPassword - Contraseña actual
   * @param {string} newPassword - Nueva contraseña
   * @param {Object} requestInfo - Información del request
   */
  async changePassword(userId, currentPassword, newPassword, requestInfo) {
    try {
      const { ipAddress, userAgent } = requestInfo;

      // Obtener usuario con contraseña
      const user = await this.userRepository.model
        .findById(userId)
        .select("+passwordHash");
      if (!user) {
        throw new AuthError(
          "Usuario no encontrado",
          AuthErrorCodes.USER_NOT_FOUND,
          404
        );
      }

      // Validar contraseña actual
      const bcrypt = require("bcrypt");
      const isCurrentValid = await bcrypt.compare(
        currentPassword,
        user.passwordHash
      );
      if (!isCurrentValid) {
        throw new AuthError(
          "Contraseña actual incorrecta",
          AuthErrorCodes.INVALID_CREDENTIALS,
          401
        );
      }

      // Validar nueva contraseña
      const passwordValidation = this.validatePasswordStrength(newPassword);
      if (!passwordValidation.isValid) {
        throw new AuthError(
          `Contraseña débil: ${passwordValidation.errors.join(", ")}`,
          AuthErrorCodes.WEAK_PASSWORD,
          400
        );
      }

      // Cambiar contraseña
      await this.userRepository.setPassword(userId, newPassword, {
        userId,
        ip: ipAddress,
        userAgent,
      });

      console.log(`✅ Contraseña cambiada: Usuario ${userId}`);

      return {
        success: true,
        message: "Contraseña actualizada exitosamente",
      };
    } catch (error) {
      console.error("Error cambiando contraseña:", error);
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        "Error interno cambiando contraseña",
        AuthErrorCodes.PASSWORD_CHANGE_FAILED,
        500
      );
    }
  }

  // =============================================================================
  // MÉTODOS AUXILIARES
  // =============================================================================

  /**
   * Validar datos de registro
   * @param {Object} data - Datos de registro
   */
  validateRegistrationData(data) {
    const { email, password, profile } = data;

    if (!email || !this.isValidEmail(email)) {
      throw new AuthError("Email inválido", AuthErrorCodes.INVALID_EMAIL, 400);
    }

    if (!profile?.firstName || !profile?.lastName) {
      throw new AuthError(
        "Nombre y apellido son requeridos",
        AuthErrorCodes.INVALID_PROFILE,
        400
      );
    }

    if (password) {
      const passwordValidation = this.validatePasswordStrength(password);
      if (!passwordValidation.isValid) {
        throw new AuthError(
          `Contraseña débil: ${passwordValidation.errors.join(", ")}`,
          AuthErrorCodes.WEAK_PASSWORD,
          400
        );
      }
    }
  }

  /**
   * Validar estado del usuario
   * @param {Object} user - Usuario
   */
  validateUserStatus(user) {
    if (!user.isActive) {
      throw new AuthError(
        "Cuenta desactivada",
        AuthErrorCodes.ACCOUNT_DISABLED,
        403
      );
    }

    if (user.lockUntil && user.lockUntil > Date.now()) {
      throw new AuthError(
        "Cuenta temporalmente bloqueada",
        AuthErrorCodes.ACCOUNT_LOCKED,
        423
      );
    }

    // Opcional: requerir verificación de email
    // if (!user.isEmailVerified) {
    //   throw new AuthError(
    //     "Email no verificado",
    //     AuthErrorCodes.EMAIL_NOT_VERIFIED,
    //     403
    //   );
    // }
  }

  /**
   * Generar tokens JWT
   * @param {string} userId - ID del usuario
   */
  generateTokens(userId) {
    const { TOKEN_CONFIG } = AuthConstants;

    const accessToken = jwt.sign({ userId, type: "access" }, this.jwtSecret, {
      expiresIn: TOKEN_CONFIG.ACCESS_TOKEN_TTL,
    });

    const refreshToken = jwt.sign({ userId, type: "refresh" }, this.jwtSecret, {
      expiresIn: TOKEN_CONFIG.REFRESH_TOKEN_TTL,
    });

    return { accessToken, refreshToken };
  }

  /**
   * Validar formato de email
   * @param {string} email - Email
   */
  isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Validar fortaleza de contraseña
   * @param {string} password - Contraseña
   */
  validatePasswordStrength(password) {
    const errors = [];

    if (!password || password.length < 8) {
      errors.push("La contraseña debe tener al menos 8 caracteres");
    }

    if (!/[a-z]/.test(password)) {
      errors.push("Debe contener al menos una letra minúscula");
    }

    if (!/[A-Z]/.test(password)) {
      errors.push("Debe contener al menos una letra mayúscula");
    }

    if (!/\d/.test(password)) {
      errors.push("Debe contener al menos un número");
    }

    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push("Debe contener al menos un carácter especial");
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  /**
   * Sanitizar datos de usuario para respuesta
   * @param {Object} user - Usuario
   */
  sanitizeUser(user) {
    const sanitized = { ...user };

    // Remover campos sensibles
    delete sanitized.passwordHash;
    delete sanitized.emailVerificationToken;
    delete sanitized.passwordResetToken;
    delete sanitized.loginAttempts;
    delete sanitized.lockUntil;

    return sanitized;
  }
}
