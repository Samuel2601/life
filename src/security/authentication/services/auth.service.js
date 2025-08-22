// =============================================================================
// src/modules/authentication/services/auth.service.js - VERSIÓN MEJORADA
// Aprovecha al 100% las funcionalidades de tus repositories y schemas existentes
// =============================================================================
import jwt from "jsonwebtoken";
import crypto from "crypto";
import bcrypt from "bcrypt";
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

  // =============================================================================
  // MÉTODOS PRINCIPALES DE AUTENTICACIÓN (MEJORADOS)
  // =============================================================================

  /**
   * Registrar nuevo usuario con funcionalidades empresariales completas
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
            businessPreferences = {},
            registrationSource = "web",
            oauthProvider = null,
            oauthData = null,
            companyContext = null,
          } = registrationData;

          const { ipAddress, userAgent } = requestInfo;

          // Validar datos básicos (método mejorado)
          await this.validateRegistrationDataEnhanced(registrationData);

          // Verificar email único usando método del repository
          const existingUser = await this.userRepository.findByEmail(email);
          if (existingUser) {
            throw new AuthError(
              "El email ya está registrado",
              AuthErrorCodes.EMAIL_ALREADY_EXISTS,
              409
            );
          }

          // Obtener rol por defecto usando funcionalidad del repository
          const defaultRole = await this.roleRepository.getDefaultRole();
          if (!defaultRole) {
            throw new AuthError(
              "Error de configuración: rol por defecto no encontrado",
              AuthErrorCodes.ROLE_NOT_FOUND,
              500
            );
          }

          // Preparar datos completos del usuario (aprovechando schema completo)
          const userData = {
            email: email.toLowerCase(),
            profile: {
              firstName: profile.firstName,
              lastName: profile.lastName,
              avatar: profile.avatar || null,
              dateOfBirth: profile.dateOfBirth || null,
              phone: profile.phone || null,
              bio: profile.bio || null,
              website: profile.website || null,
              isActive: true,
            },
            roles: [defaultRole._id],

            // Preferencias empresariales completas
            preferences: {
              language: preferences.language || "es",
              timezone: preferences.timezone || "America/Lima",
              notifications: {
                email: preferences.notifications?.email !== false,
                push: preferences.notifications?.push !== false,
                sms: preferences.notifications?.sms || false,
                marketing: preferences.notifications?.marketing || false,
              },
              privacy: {
                profileVisible: preferences.privacy?.profileVisible !== false,
                allowDataCollection:
                  preferences.privacy?.allowDataCollection !== false,
                allowLocationTracking:
                  preferences.privacy?.allowLocationTracking || false,
                showInSearch: preferences.privacy?.showInSearch !== false,
                allowBusinessContact:
                  preferences.privacy?.allowBusinessContact !== false,
                shareAnalytics: preferences.privacy?.shareAnalytics !== false,
                allowPersonalization:
                  preferences.privacy?.allowPersonalization !== false,
                shareWithPartners:
                  preferences.privacy?.shareWithPartners || false,
                allowCookies: preferences.privacy?.allowCookies !== false,
                dataRetentionPeriod:
                  preferences.privacy?.dataRetentionPeriod || "2years",
              },
            },
            registrationSource: registrationSource || "web",
            isEmailVerified: oauthProvider ? true : false,

            // Metadata empresarial completo (usando funcionalidad del schema)
            metadata: {
              registrationDetails: {
                ipAddress: ipAddress || "unknown",
                userAgent: userAgent || "unknown",
                referrer: registrationData.referrer || null,
                utmSource: registrationData.utmSource || null,
                utmMedium: registrationData.utmMedium || null,
                utmCampaign: registrationData.utmCampaign || null,
                companyContext: companyContext || null,
              },
            },
          };

          // Crear usuario usando funcionalidad completa del repository
          const sessionData = {
            userId: null,
            ip: ipAddress,
            userAgent,
            action: "user_registration",
          };

          const newUser = await this.userRepository.createUser(
            { ...userData, password },
            sessionData,
            { session }
          );

          // Conectar OAuth si aplica (usando método del repository)
          if (oauthProvider && oauthData) {
            await this.userRepository.connectOAuthProvider(
              newUser._id,
              oauthProvider,
              oauthData,
              { ...sessionData, userId: newUser._id }
            );
          }

          // Generar token de verificación usando funcionalidad del repository
          let verificationToken = null;
          if (!oauthProvider) {
            verificationToken =
              await this.userRepository.generateEmailVerificationToken(
                newUser._id,
                { session }
              );
          }

          console.log(
            `✅ Usuario registrado con funcionalidades empresariales: ${email} (ID: ${newUser._id})`
          );

          return {
            user: this.sanitizeUserEnhanced(newUser),
            verificationToken,
            requiresEmailVerification: !oauthProvider,
            profileCompleteness:
              this.userRepository.calculateProfileCompleteness(userData),
            recommendedActions: this.getRecommendedActionsForNewUser(newUser),
          };
        } catch (error) {
          console.error("Error en registro empresarial:", error);
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
   * Login con análisis de seguridad avanzado
   * @param {Object} loginData - Datos de login
   * @param {Object} requestInfo - Información del request
   */
  async login(loginData, requestInfo) {
    try {
      const {
        email,
        password,
        rememberMe = false,
        twoFactorCode = null,
        companyId = null,
        businessContext = {},
      } = loginData;

      const { ipAddress, userAgent, deviceFingerprint } = requestInfo;

      // Validar credenciales usando funcionalidad completa del repository
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

      // Verificar estado completo del usuario
      await this.validateUserStatusEnhanced(user);

      // Verificar 2FA si está habilitado
      if (user.twoFactorEnabled && !twoFactorCode) {
        return {
          requiresTwoFactor: true,
          message: "Código de autenticación de dos factores requerido",
        };
      }

      if (user.twoFactorEnabled && twoFactorCode) {
        const isValidCode = this.userRepository.verifyTwoFactorCode(
          user.twoFactorSecret,
          twoFactorCode
        );
        if (!isValidCode) {
          throw new AuthError(
            "Código de autenticación inválido",
            AuthErrorCodes.INVALID_2FA_CODE,
            401
          );
        }
      }

      // Generar tokens seguros
      const tokens = this.generateSecureTokens();

      // Crear sesión usando funcionalidad empresarial completa
      const sessionData = {
        userId: user._id,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        deviceFingerprint,
        ipAddress,
        userAgent,
        rememberMe,
        companyId,
        businessContext,

        // Datos adicionales para analytics empresariales
        dataProcessingConsent: loginData.dataProcessingConsent || false,
        cookiesAccepted: loginData.cookiesAccepted || false,
        marketingConsent: loginData.marketingConsent || false,
        analyticsConsent: loginData.analyticsConsent || false,
      };

      const userDataForAudit = {
        userId: user._id,
        ip: ipAddress,
        userAgent,
        action: "user_login",
      };

      // Crear sesión con funcionalidades empresariales
      const session = await this.sessionRepository.createSession(
        sessionData,
        userDataForAudit
      );

      // Actualizar estadísticas usando funcionalidad del repository
      await this.userRepository.updateLoginAttempts(user._id, true);

      // Obtener permisos del usuario usando funcionalidad del role repository
      const userPermissions = await this.roleRepository.getUserPermissions(
        user._id
      );

      console.log(
        `✅ Login empresarial exitoso: ${email} (Sesión: ${session._id})`
      );

      return {
        user: this.sanitizeUserEnhanced(user),
        session: {
          sessionToken: session.sessionToken,
          expiresAt: session.expiresAt,
          rememberMe: session.rememberMe,
          sessionId: session._id,
        },
        permissions: userPermissions,
        businessContext: companyId ? { companyId, ...businessContext } : null,
        // Los tokens NO se devuelven al cliente por seguridad
      };
    } catch (error) {
      console.error("Error en login empresarial:", error);
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
   * Validación de sesión con políticas empresariales
   * @param {string} sessionToken - Token de sesión
   * @param {Object} requestInfo - Información del request
   */
  async validateSession(sessionToken, requestInfo) {
    try {
      const { ipAddress, userAgent, deviceFingerprint } = requestInfo;

      // Usar validación avanzada del repository
      const validationResult =
        await this.sessionRepository.validateSessionWithPolicy(sessionToken, {
          deviceFingerprint,
          ipAddress,
          userAgent,
          location: requestInfo.location,
        });

      if (!validationResult.valid) {
        return {
          isValid: false,
          reason: validationResult.reason,
          code: this.mapValidationReasonToErrorCode(validationResult.reason),
        };
      }

      const { session, userId, businessMetrics } = validationResult;

      // Obtener datos completos del usuario
      const user = await this.userRepository.findById(userId, {
        includeRoles: true,
      });

      if (!user) {
        await this.sessionRepository.invalidateSession(
          session.sessionId,
          "user_not_found"
        );
        return {
          isValid: false,
          reason: "Usuario no encontrado",
          code: AuthErrorCodes.SESSION_INVALID,
        };
      }

      // Validar estado empresarial del usuario
      await this.validateUserStatusEnhanced(user);

      // Actualizar métricas empresariales si hay actividad
      if (requestInfo.activityData) {
        await this.sessionRepository.updateBusinessMetrics(
          session.sessionId,
          requestInfo.activityData,
          { userId }
        );
      }

      return {
        isValid: true,
        user: {
          id: user._id,
          email: user.email,
          profile: user.profile,
          roles: user.roles,
          preferences: user.preferences,
          isEmailVerified: user.isEmailVerified,
          twoFactorEnabled: user.twoFactorEnabled,
          profileCompleteness:
            user.metadata?.activityTracking?.profileCompleteness || 0,
          verificationLevel:
            user.metadata?.activityTracking?.accountVerificationLevel || 0,
        },
        session: {
          id: session.sessionId,
          expiresAt: session.expiresAt,
          lastAccessedAt: new Date(),
          rememberMe: session.rememberMe,
          businessMetrics,
        },
        permissions: await this.roleRepository.getUserPermissions(user._id),
        requiresTwoFactor: validationResult.requiresTwoFactor,
      };
    } catch (error) {
      console.error("Error validando sesión empresarial:", error);
      return {
        isValid: false,
        reason: "Error interno validando sesión",
        code: AuthErrorCodes.SESSION_INVALID,
      };
    }
  }

  /**
   * OAuth con funcionalidades empresariales completas
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
            scope = [],
          } = oauthData;

          const { ipAddress, userAgent, deviceFingerprint } = requestInfo;

          // Buscar usuario existente usando funcionalidad del repository
          let user = await this.userRepository.findByEmail(email);

          if (user) {
            // Usuario existe - conectar OAuth usando método del repository
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
                  action: "oauth_connect",
                }
              );
            }

            // Marcar email como verificado
            if (!user.isEmailVerified) {
              await this.userRepository.update(
                user._id,
                {
                  isEmailVerified: true,
                  "metadata.activityTracking.accountVerificationLevel":
                    this.userRepository.calculateVerificationLevel({
                      ...user,
                      isEmailVerified: true,
                    }),
                },
                {
                  userId: user._id,
                  ip: ipAddress,
                  userAgent,
                  action: "email_verification_oauth",
                }
              );
            }
          } else {
            // Usuario nuevo - usar registro empresarial completo
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
            user = await this.userRepository.findById(
              registrationResult.user.id
            );
          }

          // Validar estado empresarial
          await this.validateUserStatusEnhanced(user);

          // Generar tokens seguros
          const tokens = this.generateSecureTokens();

          // Crear sesión OAuth empresarial
          const sessionData = {
            userId: user._id,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            deviceFingerprint,
            ipAddress,
            userAgent,
            rememberMe: true,
            oauthProvider: provider,
            oauthSessionData: {
              accessToken,
              refreshToken,
              expiresAt: new Date(Date.now() + (expiresIn || 3600) * 1000),
              scope,
            },
          };

          const userSession = await this.sessionRepository.createSession(
            sessionData,
            {
              userId: user._id,
              ip: ipAddress,
              userAgent,
              action: "oauth_login",
            }
          );

          console.log(`✅ OAuth empresarial exitoso: ${email} via ${provider}`);

          return {
            user: this.sanitizeUserEnhanced(user),
            session: {
              sessionToken: userSession.sessionToken,
              expiresAt: userSession.expiresAt,
              rememberMe: userSession.rememberMe,
              sessionId: userSession._id,
            },
            permissions: await this.roleRepository.getUserPermissions(user._id),
            oauth: {
              provider,
              connected: true,
              scope,
            },
            isNewUser: !user.metadata?.activityTracking?.firstLogin,
          };
        } catch (error) {
          console.error("Error en OAuth empresarial:", error);
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

  // =============================================================================
  // NUEVOS MÉTODOS EMPRESARIALES
  // =============================================================================

  /**
   * Habilitar 2FA usando funcionalidad del repository
   * @param {string} userId - ID del usuario
   * @param {Object} requestInfo - Información del request
   */
  async enableTwoFactor(userId, requestInfo) {
    try {
      const { ipAddress, userAgent } = requestInfo;

      const userData = {
        userId,
        ip: ipAddress,
        userAgent,
        action: "enable_2fa",
      };

      const result = await this.userRepository.enableTwoFactor(
        userId,
        userData
      );

      return {
        success: true,
        backupCodes: result.backupCodes,
        qrCodeUrl: result.qrCodeUrl,
        secretKey: result.secretKey, // Solo se muestra una vez
        message: "Autenticación de dos factores habilitada exitosamente",
      };
    } catch (error) {
      console.error("Error habilitando 2FA:", error);
      throw new AuthError(
        "Error habilitando autenticación de dos factores",
        AuthErrorCodes.TWO_FACTOR_SETUP_FAILED,
        500
      );
    }
  }

  /**
   * Actualizar preferencias empresariales
   * @param {string} userId - ID del usuario
   * @param {Object} preferences - Nuevas preferencias
   * @param {Object} requestInfo - Información del request
   */
  async updateBusinessPreferences(userId, preferences, requestInfo) {
    try {
      const { ipAddress, userAgent } = requestInfo;

      const userData = {
        userId,
        ip: ipAddress,
        userAgent,
        action: "update_business_preferences",
      };

      await this.userRepository.updateBusinessPreferences(
        userId,
        preferences,
        userData
      );

      return {
        success: true,
        message: "Preferencias empresariales actualizadas exitosamente",
      };
    } catch (error) {
      console.error("Error actualizando preferencias empresariales:", error);
      throw new AuthError(
        "Error actualizando preferencias",
        AuthErrorCodes.PREFERENCES_UPDATE_FAILED,
        500
      );
    }
  }

  /**
   * Obtener análisis de actividad del usuario
   * @param {string} userId - ID del usuario
   * @param {Object} options - Opciones de análisis
   */
  async getUserActivityAnalysis(userId, options = {}) {
    try {
      const analysis = await this.userRepository.getUserActivityAnalysis(
        userId,
        options
      );
      return {
        success: true,
        data: analysis,
      };
    } catch (error) {
      console.error("Error obteniendo análisis de actividad:", error);
      throw new AuthError(
        "Error obteniendo análisis de usuario",
        AuthErrorCodes.ANALYSIS_FAILED,
        500
      );
    }
  }

  // =============================================================================
  // MÉTODOS AUXILIARES MEJORADOS
  // =============================================================================

  /**
   * Validación de datos de registro mejorada
   * @param {Object} data - Datos de registro
   */
  async validateRegistrationDataEnhanced(data) {
    const { email, password, profile, businessPreferences } = data;

    // Validaciones básicas
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

    // Validación de contraseña si se proporciona
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

    // Validaciones empresariales adicionales
    if (
      businessPreferences?.searchRadius &&
      (businessPreferences.searchRadius < 1 ||
        businessPreferences.searchRadius > 100)
    ) {
      throw new AuthError(
        "Radio de búsqueda debe estar entre 1 y 100 km",
        AuthErrorCodes.INVALID_BUSINESS_PREFERENCES,
        400
      );
    }

    if (profile.phone && !this.isValidPhone(profile.phone)) {
      throw new AuthError(
        "Formato de teléfono inválido",
        AuthErrorCodes.INVALID_PHONE,
        400
      );
    }

    if (profile.website && !this.isValidUrl(profile.website)) {
      throw new AuthError(
        "URL de sitio web inválida",
        AuthErrorCodes.INVALID_URL,
        400
      );
    }
  }

  /**
   * Validación de estado de usuario mejorada
   * @param {Object} user - Usuario
   */
  async validateUserStatusEnhanced(user) {
    if (!user.isActive || !user.profile?.isActive) {
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

    // Verificar si el usuario ha sido marcado para eliminación por GDPR
    if (user.metadata?.privacyFlags?.requiresDataDeletion) {
      throw new AuthError(
        "Cuenta programada para eliminación",
        AuthErrorCodes.ACCOUNT_SCHEDULED_DELETION,
        403
      );
    }

    // Opcional: requerir verificación de email para ciertas acciones
    if (user.metadata?.activityTracking?.accountVerificationLevel < 0.3) {
      console.log(`⚠️ Usuario con verificación baja: ${user.email}`);
    }
  }

  /**
   * Generar tokens seguros usando crypto en lugar de JWT para sesiones
   */
  generateSecureTokens() {
    return {
      accessToken: crypto.randomBytes(32).toString("hex"),
      refreshToken: crypto.randomBytes(32).toString("hex"),
    };
  }

  /**
   * Sanitización de usuario mejorada
   * @param {Object} user - Usuario
   */
  sanitizeUserEnhanced(user) {
    const sanitized = { ...user };

    // Remover campos sensibles
    delete sanitized.passwordHash;
    delete sanitized.emailVerificationToken;
    delete sanitized.passwordResetToken;
    delete sanitized.twoFactorSecret;
    delete sanitized.loginAttempts;
    delete sanitized.lockUntil;

    // Limpiar OAuth providers (mantener solo info no sensible)
    if (sanitized.oauthProviders) {
      Object.keys(sanitized.oauthProviders).forEach((provider) => {
        if (sanitized.oauthProviders[provider]?.providerId) {
          sanitized.oauthProviders[provider] = {
            isConnected: true,
            email: sanitized.oauthProviders[provider].email,
            connectedAt: sanitized.oauthProviders[provider].connectedAt,
            lastUsed: sanitized.oauthProviders[provider].lastUsed,
          };
        } else {
          delete sanitized.oauthProviders[provider];
        }
      });
    }

    return sanitized;
  }

  /**
   * Mapear razones de validación a códigos de error
   */
  mapValidationReasonToErrorCode(reason) {
    const mapping = {
      session_not_found: AuthErrorCodes.SESSION_INVALID,
      session_expired_inactivity: AuthErrorCodes.SESSION_EXPIRED,
      user_inactive: AuthErrorCodes.ACCOUNT_DISABLED,
      device_fingerprint_changed: AuthErrorCodes.DEVICE_NOT_RECOGNIZED,
      location_change_not_allowed: AuthErrorCodes.LOCATION_RESTRICTED,
      country_not_allowed: AuthErrorCodes.LOCATION_RESTRICTED,
      device_type_not_allowed: AuthErrorCodes.DEVICE_NOT_RECOGNIZED,
    };

    return mapping[reason] || AuthErrorCodes.SESSION_INVALID;
  }

  /**
   * Obtener acciones recomendadas para nuevo usuario
   */
  getRecommendedActionsForNewUser(user) {
    const actions = [];

    if (!user.isEmailVerified) {
      actions.push({
        type: "verify_email",
        priority: "high",
        message: "Verifica tu email para acceder a todas las funcionalidades",
      });
    }

    if (!user.twoFactorEnabled) {
      actions.push({
        type: "enable_2fa",
        priority: "medium",
        message:
          "Habilita la autenticación de dos factores para mayor seguridad",
      });
    }

    const completeness = this.userRepository.calculateProfileCompleteness(user);
    if (completeness < 0.8) {
      actions.push({
        type: "complete_profile",
        priority: "medium",
        message: "Completa tu perfil para una mejor experiencia",
        completeness: Math.round(completeness * 100),
      });
    }

    return actions;
  }

  // =============================================================================
  // MÉTODOS DE VALIDACIÓN ADICIONALES
  // =============================================================================

  /**
   * Validar formato de teléfono
   */
  isValidPhone(phone) {
    const phoneRegex = /^\+?[1-9]\d{1,14}$/;
    const cleanPhone = phone.replace(/\s/g, "");
    return phoneRegex.test(cleanPhone);
  }

  /**
   * Validar URL
   */
  isValidUrl(url) {
    const urlRegex = /^https?:\/\/.+/;
    return urlRegex.test(url);
  }

  /**
   * Validar formato de email (heredado)
   */
  isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  /**
   * Validar fortaleza de contraseña (heredado)
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

  // =============================================================================
  // MÉTODOS HEREDADOS (MANTENER COMPATIBILIDAD)
  // =============================================================================

  /**
   * Cerrar sesión (mejorado)
   */
  async logout(sessionToken, requestInfo) {
    try {
      const { ipAddress, userAgent } = requestInfo;

      const result = await this.sessionRepository.invalidateSessionByToken(
        sessionToken,
        "user_logout"
      );

      console.log(`✅ Logout empresarial exitoso desde ${ipAddress}`);
      return result;
    } catch (error) {
      console.error("Error en logout empresarial:", error);
      throw new AuthError(
        "Error interno durante logout",
        AuthErrorCodes.LOGOUT_FAILED,
        500
      );
    }
  }

  /**
   * Cerrar todas las sesiones (usando funcionalidad del repository)
   */
  async logoutAllDevices(userId, exceptSessionId = null, requestInfo) {
    try {
      const { ipAddress } = requestInfo;

      const result = await this.sessionRepository.invalidateUserSessions(
        userId,
        "logout_all_devices",
        { excludeSessionId: exceptSessionId }
      );

      console.log(
        `✅ Logout masivo empresarial: ${result.modifiedCount} sesiones cerradas`
      );

      return {
        success: true,
        invalidatedSessions: result.modifiedCount,
      };
    } catch (error) {
      console.error("Error en logout masivo empresarial:", error);
      throw new AuthError(
        "Error cerrando todas las sesiones",
        AuthErrorCodes.LOGOUT_FAILED,
        500
      );
    }
  }

  /**
   * Verificar email con token (usando funcionalidad del repository)
   */
  async verifyEmail(token) {
    try {
      if (!token) {
        throw new AuthError(
          "Token de verificación requerido",
          AuthErrorCodes.VERIFICATION_TOKEN_INVALID,
          400
        );
      }

      const userData = {
        userId: null, // Se establece en el repository
        ip: "unknown",
        userAgent: "Email Verification",
        action: "email_verification",
      };

      const result = await this.userRepository.verifyEmailWithToken(
        token,
        userData
      );

      console.log(`✅ Email verificado empresarialmente: ${result.email}`);

      return {
        user: result,
        message: "Email verificado exitosamente",
      };
    } catch (error) {
      console.error("Error verificando email empresarial:", error);
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        "Error verificando email",
        AuthErrorCodes.VERIFICATION_FAILED,
        500
      );
    }
  }

  /**
   * Solicitar reset de contraseña (usando funcionalidad del repository)
   */
  async requestPasswordReset(email, requestInfo) {
    try {
      const { ipAddress, userAgent } = requestInfo;

      const result =
        await this.userRepository.generatePasswordResetToken(email);

      // TODO: Integrar con servicio de email
      console.log(
        `📧 Token de reset empresarial generado para: ${result.email}`
      );
      console.log(`🔐 Token (desarrollo): ${result.token}`);

      return {
        success: true,
        message: "Si el email existe, recibirás un enlace de recuperación",
      };
    } catch (error) {
      console.error("Error solicitando reset empresarial:", error);
      // Por seguridad, siempre devolver éxito
      return {
        success: true,
        message: "Si el email existe, recibirás un enlace de recuperación",
      };
    }
  }

  /**
   * Resetear contraseña con token (usando funcionalidad del repository)
   */
  async resetPassword(token, newPassword, requestInfo) {
    try {
      const { ipAddress, userAgent } = requestInfo;

      // Validar nueva contraseña
      const passwordValidation = this.validatePasswordStrength(newPassword);
      if (!passwordValidation.isValid) {
        throw new AuthError(
          `Contraseña débil: ${passwordValidation.errors.join(", ")}`,
          AuthErrorCodes.WEAK_PASSWORD,
          400
        );
      }

      const sessionData = {
        userId: null, // Se establece en el repository
        ip: ipAddress,
        userAgent,
        action: "password_reset",
      };

      const result = await this.userRepository.resetPasswordWithToken(
        token,
        newPassword,
        sessionData
      );

      // Invalidar todas las sesiones por seguridad
      await this.sessionRepository.invalidateUserSessions(
        result._id,
        "password_reset"
      );

      console.log(`🔐 Contraseña reseteada empresarialmente: ${result.email}`);

      return {
        success: true,
        message: "Contraseña reseteada exitosamente",
        user: {
          id: result._id,
          email: result.email,
        },
      };
    } catch (error) {
      console.error("Error reseteando contraseña empresarial:", error);
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        "Error reseteando contraseña",
        AuthErrorCodes.PASSWORD_RESET_FAILED,
        500
      );
    }
  }

  /**
   * Cambiar contraseña (usando funcionalidad del repository)
   */
  async changePassword(userId, currentPassword, newPassword, requestInfo) {
    try {
      const { ipAddress, userAgent } = requestInfo;

      // Obtener usuario con contraseña para validar
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

      // Cambiar contraseña usando repository
      const sessionData = {
        userId,
        ip: ipAddress,
        userAgent,
        action: "password_change",
      };

      await this.userRepository.setPassword(userId, newPassword, sessionData);

      console.log(`✅ Contraseña cambiada empresarialmente: Usuario ${userId}`);

      return {
        success: true,
        message: "Contraseña actualizada exitosamente",
      };
    } catch (error) {
      console.error("Error cambiando contraseña empresarial:", error);
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

  /**
   * Refrescar tokens (mejorado con validación de políticas)
   */
  async refreshTokens(sessionToken, requestInfo) {
    try {
      const { ipAddress, userAgent, deviceFingerprint } = requestInfo;

      // Usar validación avanzada del repository
      const validationResult =
        await this.sessionRepository.validateSessionWithPolicy(sessionToken, {
          deviceFingerprint,
          ipAddress,
          userAgent,
        });

      if (!validationResult.valid) {
        throw new AuthError(
          "Sesión inválida para renovación",
          AuthErrorCodes.SESSION_INVALID,
          401
        );
      }

      // Generar nuevos tokens
      const newTokens = this.generateSecureTokens();

      // Actualizar tokens usando funcionalidad del repository
      await this.sessionRepository.rotateTokens(
        validationResult.session.sessionId,
        newTokens.accessToken,
        newTokens.refreshToken,
        {
          userId: validationResult.userId,
          ip: ipAddress,
          userAgent,
          action: "token_refresh",
        }
      );

      console.log(
        `🔄 Tokens empresariales renovados para sesión: ${validationResult.session.sessionId}`
      );

      return {
        success: true,
        expiresAt: validationResult.session.expiresAt,
        message: "Tokens renovados exitosamente",
      };
    } catch (error) {
      console.error("Error renovando tokens empresariales:", error);
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
}
