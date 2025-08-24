// =============================================================================
// src/modules/authentication/repositories/user.repository.js - VERSIÓN COMPLETA UNIFICADA
// Utiliza al 100% las funcionalidades del User Schema + BaseRepository mejorado
// =============================================================================
import { Types } from "mongoose";
import bcrypt from "bcrypt";
import crypto from "crypto";
import { User } from "../models/user/index.js";
import { TransactionHelper } from "../../../utils/transsaccion.helper.js";
import { BaseRepository } from "../../../modules/core/repositories/base.repository.js";

export class UserRepository extends BaseRepository {
  constructor() {
    super(User);
  }

  // ===== MÉTODOS PRINCIPALES DE GESTIÓN DE USUARIOS =====

  /**
   * Crear usuario con configuración empresarial completa
   * @param {Object} userData - Datos del usuario
   * @param {Object} sessionData - Datos de la sesión de creación
   * @param {Object} options - Opciones adicionales
   */
  async createUser(userData, sessionData, options = {}) {
    return await TransactionHelper.executeWithOptionalTransaction(
      async (session) => {
        try {
          const { password, ...userDataWithoutPassword } = userData;

          // Verificar email único
          const existingUser = await this.model
            .findOne({
              email: userData.email.toLowerCase(),
            })
            .session(session);

          if (existingUser) {
            throw new Error("El email ya está registrado");
          }

          // Preparar datos completos del usuario
          const newUserData = {
            ...userDataWithoutPassword,
            email: userData.email.toLowerCase(),

            // Perfil completo
            profile: {
              firstName: userData.profile?.firstName || userData.firstName,
              lastName: userData.profile?.lastName || userData.lastName,
              avatar: userData.profile?.avatar || null,
              dateOfBirth: userData.profile?.dateOfBirth || null,
              phone: userData.profile?.phone || null,
              bio: userData.profile?.bio || null,
              website: userData.profile?.website || null,
            },
            isActive: true,
            // Metadatos empresariales completos
            metadata: {
              registrationSource: userData.registrationSource || "web",
              lastActiveAt: new Date(),
              totalLogins: 0,
              averageSessionDuration: 0,

              // Detalles de registro
              registrationDetails: {
                ipAddress: sessionData.ipAddress || "unknown",
                userAgent: sessionData.userAgent || "unknown",
                referrer: userData.referrer || null,
                utmSource: userData.utmSource || null,
                utmMedium: userData.utmMedium || null,
                utmCampaign: userData.utmCampaign || null,
                companyContext: userData.companyContext || null,
              },

              // Configuración de actividad
              activityTracking: {
                firstLogin: null,
                lastPasswordChange: new Date(),
                profileCompleteness:
                  this.calculateProfileCompleteness(userData),
                accountVerificationLevel:
                  this.calculateVerificationLevel(userData),
                lastProfileUpdate: new Date(),
                lastPreferencesUpdate: new Date(),
                lastSecurityUpdate: new Date(),
                lastPrivacyUpdate: new Date(),
              },

              privacyFlags: {
                dataConsentRevoked:
                  userData.privacyFlags?.dataConsentRevoked || false,
                dataConsentRevokedAt:
                  userData.privacyFlags?.dataConsentRevokedAt || null,
                requiresDataDeletion:
                  userData.privacyFlags?.requiresDataDeletion || false,
              },
            },

            // Preferencias empresariales completas
            preferences: {
              language: userData.preferredLanguage || "es",
              timezone: userData.timezone || "America/Lima",

              // Notificaciones empresariales
              notifications: {
                email: userData.notifications?.email !== false,
                push: userData.notifications?.push !== false,
                sms: userData.notifications?.sms || false,
                marketing: userData.notifications?.marketing || false,
                newBusinessAlert:
                  userData.notifications?.newBusinessAlert !== false,
                reviewResponses:
                  userData.notifications?.reviewResponses !== false,
                weeklyDigest: userData.notifications?.weeklyDigest !== false,
              },

              // Privacidad avanzada
              privacy: {
                profileVisible: userData.privacy?.profileVisible !== false,
                allowDataCollection:
                  userData.privacy?.allowDataCollection !== false,
                allowLocationTracking:
                  userData.privacy?.allowLocationTracking || false,
                showInSearch: userData.privacy?.showInSearch !== false,
                allowBusinessContact:
                  userData.privacy?.allowBusinessContact !== false,
                shareAnalytics: userData.privacy?.shareAnalytics !== false,
                allowPersonalization:
                  userData.privacy?.allowPersonalization !== false,
                shareWithPartners: userData.privacy?.shareWithPartners || false,
                allowCookies: userData.privacy?.allowCookies !== false,
                dataRetentionPeriod:
                  userData.privacy?.dataRetentionPeriod || "2years",
              },

              // Preferencias empresariales
              business: {
                preferredCategories:
                  userData.businessPreferences?.categories || [],
                searchRadius: userData.businessPreferences?.searchRadius || 10,
                defaultSortBy:
                  userData.businessPreferences?.sortBy || "distance",
                showPrices: userData.businessPreferences?.showPrices !== false,
                autoTranslate:
                  userData.businessPreferences?.autoTranslate !== false,
                preferredLanguages: userData.businessPreferences
                  ?.preferredLanguages || [userData.preferredLanguage || "es"],
                notificationRadius:
                  userData.businessPreferences?.notificationRadius || 5,
              },
            },

            // Configuración de seguridad inicial
            twoFactorEnabled: false,
            twoFactorSecret: null,

            // Roles iniciales
            roles: userData.roles || [],
            isEmailVerified: userData.isEmailVerified || false,

            //Campos de seguridad
            loginAttempts: 0,
            lockUntil: null,
            passwordResetToken: null,
            passwordResetExpires: null,
            emailVerificationToken: null,
            emailVerificationExpires: null,
          };

          const user = await this.create(newUserData, sessionData, { session });

          // Establecer contraseña si se proporciona
          if (password) {
            await this.setPassword(user._id, password, sessionData, {
              session,
            });
          }

          // Generar token de verificación de email
          if (!userData.isEmailVerified) {
            await this.generateEmailVerificationToken(user._id, { session });
          }

          console.log(`✅ Usuario creado: ${user.email} (ID: ${user._id})`);
          return user;
        } catch (error) {
          console.error("Error creando usuario:", error);
          throw error;
        }
      }
    );
  }

  /**
   * Actualizar usuario con validaciones completas
   * @param {string} userId - ID del usuario
   * @param {Object} updateData - Datos a actualizar
   * @param {Object} userData - Datos del usuario que actualiza
   */
  async updateUser(userId, updateData, userData) {
    try {
      const user = await this.findById(userId);
      if (!user) {
        throw new Error("Usuario no encontrado");
      }

      // Validar email único si se cambia
      if (updateData.email && updateData.email !== user.email) {
        const existingUser = await this.model.findOne({
          email: updateData.email.toLowerCase(),
          _id: { $ne: userId },
        });

        if (existingUser) {
          throw new Error("El email ya está en uso");
        }

        updateData.email = updateData.email.toLowerCase();
        updateData.isEmailVerified = false; // Requerir verificación del nuevo email
      }

      return await this.update(userId, updateData, userData);
    } catch (error) {
      console.error("Error actualizando usuario:", error);
      throw error;
    }
  }

  // ===== GESTIÓN DE 2FA COMPLETA =====

  /**
   * Habilitar autenticación de dos factores
   * @param {string} userId - ID del usuario
   * @param {Object} userData - Datos del usuario que habilita
   */
  async enableTwoFactor(userId, userData) {
    try {
      const user = await this.findById(userId);
      if (!user) {
        throw new Error("Usuario no encontrado");
      }

      if (user.twoFactorEnabled) {
        throw new Error("2FA ya está habilitado para este usuario");
      }

      // Generar secreto para 2FA (TOTP)
      const secret = this.generateTwoFactorSecret();

      const updateData = {
        twoFactorEnabled: true,
        twoFactorSecret: secret,
        "metadata.activityTracking.lastSecurityUpdate": new Date(),
        "metadata.activityTracking.accountVerificationLevel":
          this.calculateVerificationLevel({
            ...user,
            twoFactorEnabled: true,
          }),
      };

      await this.update(userId, updateData, userData);

      // Retornar información para QR code (sin el secreto por seguridad)
      return {
        backupCodes: this.generateBackupCodes(),
        qrCodeUrl: this.generateQRCodeUrl(user.email, secret),
        secretKey: secret, // Solo para mostrar una vez
      };
    } catch (error) {
      console.error("Error habilitando 2FA:", error);
      throw error;
    }
  }

  /**
   * Deshabilitar autenticación de dos factores
   * @param {string} userId - ID del usuario
   * @param {string} verificationCode - Código de verificación
   * @param {Object} userData - Datos del usuario que deshabilita
   */
  async disableTwoFactor(userId, verificationCode, userData) {
    try {
      const user = await this.findById(userId, { includeSecrets: true });
      if (!user) {
        throw new Error("Usuario no encontrado");
      }

      if (!user.twoFactorEnabled) {
        throw new Error("2FA no está habilitado para este usuario");
      }

      // Verificar código antes de deshabilitar
      const isValidCode = this.verifyTwoFactorCode(
        user.twoFactorSecret,
        verificationCode
      );
      if (!isValidCode) {
        throw new Error("Código de verificación inválido");
      }

      const updateData = {
        twoFactorEnabled: false,
        twoFactorSecret: null,
        "metadata.activityTracking.lastSecurityUpdate": new Date(),
        "metadata.activityTracking.accountVerificationLevel":
          this.calculateVerificationLevel({
            ...user,
            twoFactorEnabled: false,
          }),
      };

      return await this.update(userId, updateData, userData);
    } catch (error) {
      console.error("Error deshabilitando 2FA:", error);
      throw error;
    }
  }

  /**
   * Verificar código 2FA
   * @param {string} secret - Secreto 2FA
   * @param {string} code - Código a verificar
   */
  verifyTwoFactorCode(secret, code) {
    try {
      // TODO: Implementar verificación TOTP real con librería como 'speakeasy'
      // const verified = speakeasy.totp.verify({
      //   secret: secret,
      //   encoding: 'base32',
      //   token: code,
      //   window: 1
      // });

      // Por ahora, código de prueba simple
      return code && code.length === 6 && /^\d+$/.test(code);
    } catch (error) {
      console.error("Error verificando código 2FA:", error);
      return false;
    }
  }

  // ===== GESTIÓN DE PERFILES AVANZADA =====

  /**
   * Actualizar perfil completo con validaciones
   * @param {string} userId - ID del usuario
   * @param {Object} profileData - Datos del perfil
   * @param {Object} userData - Datos del usuario que actualiza
   */
  async updateCompleteProfile(userId, profileData, userData) {
    try {
      const user = await this.findById(userId);
      if (!user) {
        throw new Error("Usuario no encontrado");
      }

      // Validar y limpiar datos del perfil
      const validatedProfile = this.validateProfileData(profileData);

      // Calcular nueva completitud del perfil
      const newProfileCompleteness = this.calculateProfileCompleteness({
        profile: {
          ...user.profile,
          ...validatedProfile,
        },
      });

      const updateData = {
        profile: {
          ...user.profile,
          ...validatedProfile,
        },
        "metadata.activityTracking.profileCompleteness": newProfileCompleteness,
        "metadata.activityTracking.lastProfileUpdate": new Date(),
        "metadata.activityTracking.accountVerificationLevel":
          this.calculateVerificationLevel({
            ...user,
            profile: { ...user.profile, ...validatedProfile },
          }),
      };

      const updatedUser = await this.update(userId, updateData, userData);

      // Emitir evento si el perfil se completó
      if (
        newProfileCompleteness >= 0.8 &&
        user.metadata?.activityTracking?.profileCompleteness < 0.8
      ) {
        console.log(`🎉 Perfil completado para usuario ${userId}`);
        // TODO: Emitir evento 'profile_completed'
      }

      return updatedUser;
    } catch (error) {
      console.error("Error actualizando perfil completo:", error);
      throw error;
    }
  }

  /**
   * Actualizar preferencias empresariales
   * @param {string} userId - ID del usuario
   * @param {Object} businessPrefs - Preferencias empresariales
   * @param {Object} userData - Datos del usuario que actualiza
   */
  async updateBusinessPreferences(userId, businessPrefs, userData) {
    try {
      const user = await this.findById(userId);
      if (!user) {
        throw new Error("Usuario no encontrado");
      }

      const validatedPrefs = {
        preferredCategories: businessPrefs.preferredCategories || [],
        searchRadius: Math.min(
          Math.max(businessPrefs.searchRadius || 10, 1),
          100
        ),
        defaultSortBy: ["distance", "rating", "name", "newest"].includes(
          businessPrefs.defaultSortBy
        )
          ? businessPrefs.defaultSortBy
          : "distance",
        showPrices: Boolean(businessPrefs.showPrices),
        autoTranslate: Boolean(businessPrefs.autoTranslate),
        preferredLanguages: businessPrefs.preferredLanguages || [
          user.preferences.language,
        ],
        notificationRadius: Math.min(
          Math.max(businessPrefs.notificationRadius || 5, 1),
          50
        ),
      };

      const updateData = {
        "preferences.business": validatedPrefs,
        "metadata.activityTracking.lastPreferencesUpdate": new Date(),
      };

      return await this.update(userId, updateData, userData);
    } catch (error) {
      console.error("Error actualizando preferencias empresariales:", error);
      throw error;
    }
  }

  /**
   * Actualizar configuraciones de privacidad avanzadas
   * @param {string} userId - ID del usuario
   * @param {Object} privacySettings - Configuraciones de privacidad
   * @param {Object} userData - Datos del usuario que actualiza
   */
  async updateAdvancedPrivacySettings(userId, privacySettings, userData) {
    try {
      const user = await this.findById(userId);
      if (!user) {
        throw new Error("Usuario no encontrado");
      }

      const validatedPrivacy = {
        profileVisible: Boolean(privacySettings.profileVisible),
        allowDataCollection: Boolean(privacySettings.allowDataCollection),
        allowLocationTracking: Boolean(privacySettings.allowLocationTracking),
        showInSearch: Boolean(privacySettings.showInSearch),
        allowBusinessContact: Boolean(privacySettings.allowBusinessContact),
        shareAnalytics: Boolean(privacySettings.shareAnalytics),
        allowPersonalization: Boolean(privacySettings.allowPersonalization),
        shareWithPartners: Boolean(privacySettings.shareWithPartners),
        allowCookies: Boolean(privacySettings.allowCookies),
        dataRetentionPeriod: privacySettings.dataRetentionPeriod || "2years",
      };

      const updateData = {
        "preferences.privacy": validatedPrivacy,
        "metadata.activityTracking.lastPrivacyUpdate": new Date(),
      };

      // Si se revoca el consentimiento de datos, marcar para revisión
      if (
        !validatedPrivacy.allowDataCollection &&
        user.preferences?.privacy?.allowDataCollection
      ) {
        updateData["metadata.privacyFlags"] = {
          dataConsentRevoked: true,
          dataConsentRevokedAt: new Date(),
          requiresDataDeletion: true,
        };
      }

      return await this.update(userId, updateData, userData);
    } catch (error) {
      console.error("Error actualizando configuraciones de privacidad:", error);
      throw error;
    }
  }

  // ===== ANÁLISIS DE ACTIVIDAD Y MÉTRICAS =====

  /**
   * Análisis completo de actividad de usuario
   * @param {string} userId - ID del usuario
   * @param {Object} options - Opciones de análisis
   */
  async getUserActivityAnalysis(userId, options = {}) {
    try {
      const { dateFrom, dateTo, includeDetailedMetrics = false } = options;

      const pipeline = [
        { $match: { _id: new Types.ObjectId(userId) } },

        // Lookup con sesiones de usuario
        {
          $lookup: {
            from: "usersessions",
            localField: "_id",
            foreignField: "userId",
            pipeline: [
              ...(dateFrom || dateTo
                ? [
                    {
                      $match: {
                        createdAt: {
                          ...(dateFrom && { $gte: new Date(dateFrom) }),
                          ...(dateTo && { $lte: new Date(dateTo) }),
                        },
                      },
                    },
                  ]
                : []),
              {
                $group: {
                  _id: null,
                  totalSessions: { $sum: 1 },
                  activeSessions: {
                    $sum: { $cond: [{ $eq: ["$isActive", true] }, 1, 0] },
                  },
                  avgSessionDuration: { $avg: "$metadata.sessionDuration" },
                  totalRequests: { $sum: "$metadata.totalRequests" },
                  uniqueDevices: { $addToSet: "$deviceFingerprint" },
                  uniqueLocations: { $addToSet: "$location.city" },
                  suspiciousActivities: {
                    $sum: { $size: { $ifNull: ["$suspiciousActivity", []] } },
                  },

                  // Métricas empresariales
                  businessMetrics: {
                    searchesPerformed: {
                      $sum: "$metadata.businessMetrics.searchesPerformed",
                    },
                    businessesViewed: {
                      $sum: {
                        $size: {
                          $ifNull: [
                            "$metadata.businessMetrics.businessesViewed",
                            [],
                          ],
                        },
                      },
                    },
                    reviewsSubmitted: {
                      $sum: "$metadata.businessMetrics.reviewsSubmitted",
                    },
                    translationsRequested: {
                      $sum: "$metadata.businessMetrics.translationsRequested",
                    },
                    companiesAccessed: {
                      $addToSet: "$metadata.businessMetrics.companiesAccessed",
                    },
                  },
                },
              },
            ],
            as: "sessionAnalysis",
          },
        },

        // Lookup con reseñas del usuario
        {
          $lookup: {
            from: "reviews",
            localField: "_id",
            foreignField: "userId",
            pipeline: [
              ...(dateFrom || dateTo
                ? [
                    {
                      $match: {
                        createdAt: {
                          ...(dateFrom && { $gte: new Date(dateFrom) }),
                          ...(dateTo && { $lte: new Date(dateTo) }),
                        },
                      },
                    },
                  ]
                : []),
              {
                $group: {
                  _id: null,
                  totalReviews: { $sum: 1 },
                  avgRating: { $avg: "$rating" },
                  helpfulVotes: { $sum: "$helpfulVotes" },
                  businessesReviewed: { $addToSet: "$businessId" },
                },
              },
            ],
            as: "reviewAnalysis",
          },
        },

        // Lookup con favoritos del usuario
        {
          $lookup: {
            from: "favorites",
            localField: "_id",
            foreignField: "userId",
            pipeline: [
              {
                $group: {
                  _id: null,
                  totalFavorites: { $sum: 1 },
                  favoriteCategories: { $addToSet: "$businessCategory" },
                },
              },
            ],
            as: "favoriteAnalysis",
          },
        },

        // Proyección final
        {
          $project: {
            userId: "$_id",
            profile: 1,
            preferences: 1,
            metadata: 1,
            isActive: 1,
            isEmailVerified: 1,
            twoFactorEnabled: 1,
            roles: 1,
            createdAt: 1,
            lastLoginAt: 1,

            // Análisis de actividad
            activitySummary: {
              profileCompleteness:
                "$metadata.activityTracking.profileCompleteness",
              verificationLevel:
                "$metadata.activityTracking.accountVerificationLevel",
              totalLogins: "$metadata.totalLogins",
              averageSessionDuration: "$metadata.averageSessionDuration",
              lastActiveAt: "$metadata.lastActiveAt",

              // Datos de sesiones
              sessionMetrics: { $arrayElemAt: ["$sessionAnalysis", 0] },

              // Datos de reseñas
              reviewMetrics: { $arrayElemAt: ["$reviewAnalysis", 0] },

              // Datos de favoritos
              favoriteMetrics: { $arrayElemAt: ["$favoriteAnalysis", 0] },

              // Métricas calculadas
              engagementScore: {
                $divide: [
                  {
                    $add: [
                      {
                        $multiply: [
                          {
                            $ifNull: [
                              {
                                $arrayElemAt: [
                                  "$sessionAnalysis.totalSessions",
                                  0,
                                ],
                              },
                              0,
                            ],
                          },
                          1,
                        ],
                      },
                      {
                        $multiply: [
                          {
                            $ifNull: [
                              {
                                $arrayElemAt: [
                                  "$reviewAnalysis.totalReviews",
                                  0,
                                ],
                              },
                              0,
                            ],
                          },
                          3,
                        ],
                      },
                      { $multiply: ["$metadata.totalLogins", 0.5] },
                    ],
                  },
                  {
                    $max: [
                      {
                        $divide: [
                          { $subtract: [new Date(), "$createdAt"] },
                          1000 * 60 * 60 * 24,
                        ],
                      },
                      1,
                    ],
                  },
                ],
              },
            },
          },
        },
      ];

      const result = await this.model.aggregate(pipeline);

      if (!result || result.length === 0) {
        throw new Error("Usuario no encontrado");
      }

      const analysis = result[0];

      // Calcular métricas adicionales si se solicita
      if (includeDetailedMetrics) {
        analysis.detailedMetrics = await this.calculateDetailedUserMetrics(
          userId,
          options
        );
      }

      return analysis;
    } catch (error) {
      console.error("Error obteniendo análisis de actividad:", error);
      throw error;
    }
  }

  // ===== BÚSQUEDAS AVANZADAS =====

  /**
   * Búsqueda avanzada de usuarios con agregación
   * @param {Object} filters - Filtros de búsqueda
   * @param {Object} options - Opciones de paginación
   */
  async findUsersWithAdvancedFilters(filters = {}, options = {}) {
    try {
      const {
        search,
        language,
        hasCompletedProfile,
        has2FA,
        businessPreferences,
        activityLevel,
        registrationSource,
        verificationLevel,
        hasOAuth,
        dateRange,
      } = filters;

      const searchConfig = {
        filters: {
          // Filtros básicos de texto
          ...(search && {
            $or: [
              { "profile.firstName": { $regex: search, $options: "i" } },
              { "profile.lastName": { $regex: search, $options: "i" } },
              { email: { $regex: search, $options: "i" } },
            ],
          }),

          // Filtros específicos
          ...(language && { "preferences.language": language }),
          ...(has2FA !== undefined && { twoFactorEnabled: has2FA }),
          ...(registrationSource && {
            "metadata.registrationSource": registrationSource,
          }),
          ...(hasOAuth !== undefined && this.buildOAuthFilter(hasOAuth)),

          // Filtro por completitud de perfil
          ...(hasCompletedProfile !== undefined && {
            "metadata.activityTracking.profileCompleteness": hasCompletedProfile
              ? { $gte: 0.8 }
              : { $lt: 0.8 },
          }),

          // Filtro por nivel de verificación
          ...(verificationLevel && {
            "metadata.activityTracking.accountVerificationLevel": {
              $gte: verificationLevel,
            },
          }),

          // Filtro por rango de fechas
          ...(dateRange && {
            createdAt: {
              $gte: new Date(dateRange.from),
              $lte: new Date(dateRange.to),
            },
          }),
        },

        options,

        lookups: [
          // Lookup con roles
          {
            from: "roles",
            localField: "roles",
            foreignField: "_id",
            as: "userRoles",
            pipeline: [
              { $project: { roleName: 1, displayName: 1, hierarchy: 1 } },
            ],
          },

          // Lookup con estadísticas de sesiones
          {
            from: "usersessions",
            let: { userId: "$_id" },
            pipeline: [
              { $match: { $expr: { $eq: ["$userId", "$$userId"] } } },
              {
                $group: {
                  _id: null,
                  totalSessions: { $sum: 1 },
                  activeSessions: {
                    $sum: { $cond: [{ $eq: ["$isActive", true] }, 1, 0] },
                  },
                  lastSessionAt: { $max: "$lastAccessedAt" },
                  totalBusinessMetrics: {
                    searchesPerformed: {
                      $sum: "$metadata.businessMetrics.searchesPerformed",
                    },
                    businessesViewed: {
                      $sum: {
                        $size: {
                          $ifNull: [
                            "$metadata.businessMetrics.businessesViewed",
                            [],
                          ],
                        },
                      },
                    },
                  },
                },
              },
            ],
            as: "sessionStats",
          },

          // Lookup con reseñas
          {
            from: "reviews",
            let: { userId: "$_id" },
            pipeline: [
              { $match: { $expr: { $eq: ["$userId", "$$userId"] } } },
              {
                $group: {
                  _id: null,
                  totalReviews: { $sum: 1 },
                  avgRating: { $avg: "$rating" },
                },
              },
            ],
            as: "reviewStats",
          },
        ],

        customPipeline: [
          // Agregar estadísticas calculadas
          {
            $addFields: {
              sessionSummary: { $arrayElemAt: ["$sessionStats", 0] },
              reviewSummary: { $arrayElemAt: ["$reviewStats", 0] },
              roleHierarchy: { $max: "$userRoles.hierarchy" },
              hasOAuthConnection: {
                $or: [
                  { $ne: ["$oauthProviders.google.providerId", null] },
                  { $ne: ["$oauthProviders.facebook.providerId", null] },
                  { $ne: ["$oauthProviders.apple.providerId", null] },
                  { $ne: ["$oauthProviders.microsoft.providerId", null] },
                ],
              },
            },
          },

          // Filtrar por nivel de actividad
          ...(activityLevel
            ? [
                {
                  $match: {
                    "sessionSummary.totalSessions":
                      activityLevel === "high"
                        ? { $gte: 10 }
                        : activityLevel === "medium"
                          ? { $gte: 3, $lt: 10 }
                          : { $lt: 3 },
                  },
                },
              ]
            : []),

          // Filtrar por preferencias empresariales
          ...(businessPreferences?.length
            ? [
                {
                  $match: {
                    "preferences.business.preferredCategories": {
                      $in: businessPreferences,
                    },
                  },
                },
              ]
            : []),
        ],
      };

      return await this.searchWithAggregation(searchConfig);
    } catch (error) {
      console.error("Error en búsqueda avanzada de usuarios:", error);
      throw error;
    }
  }

  // ===== AUTENTICACIÓN Y CREDENCIALES =====

  /**
   * Buscar usuario por email
   * @param {string} email - Email del usuario
   * @param {Object} options - Opciones de búsqueda
   */
  async findByEmail(email, options = {}) {
    try {
      const { includePassword = false, session } = options;

      let query = this.model.findOne({
        email: email.toLowerCase(),
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      });

      if (session) {
        query = query.session(session);
      }

      if (!includePassword) {
        query = query.select("-passwordHash");
      }

      return await query.lean();
    } catch (error) {
      console.error("Error buscando usuario por email:", error);
      throw error;
    }
  }

  /**
   * Validar credenciales de usuario
   * @param {string} email - Email del usuario
   * @param {string} password - Contraseña a validar
   */
  async validateCredentials(email, password) {
    try {
      const user = await this.findByEmail(email, { includePassword: true });

      if (!user || !user.passwordHash) {
        return null;
      }

      if (!user.isActive || !user.profile?.isActive) {
        throw new Error("Cuenta desactivada");
      }

      if (user.lockUntil && user.lockUntil > new Date()) {
        throw new Error("Cuenta bloqueada temporalmente");
      }

      const isValidPassword = await bcrypt.compare(password, user.passwordHash);

      if (!isValidPassword) {
        await this.incrementLoginAttempts(user._id);
        return null;
      }

      await this.resetLoginAttempts(user._id);

      const { passwordHash, ...userWithoutPassword } = user;
      return userWithoutPassword;
    } catch (error) {
      console.error("Error validando credenciales:", error);
      throw error;
    }
  }

  /**
   * Establecer contraseña de usuario
   * @param {string} userId - ID del usuario
   * @param {string} password - Nueva contraseña
   * @param {Object} sessionData - Datos de sesión
   * @param {Object} options - Opciones adicionales
   */
  async setPassword(userId, password, sessionData, options = {}) {
    try {
      if (!password || password.length < 8) {
        throw new Error("La contraseña debe tener al menos 8 caracteres");
      }

      const saltRounds = 12;
      const passwordHash = await bcrypt.hash(password, saltRounds);

      const updateData = {
        passwordHash,
        "metadata.activityTracking.lastPasswordChange": new Date(),
      };

      const updatedUser = await this.update(
        userId,
        updateData,
        sessionData,
        options
      );

      return updatedUser;
    } catch (error) {
      console.error("Error estableciendo contraseña:", error);
      throw error;
    }
  }

  /**
   * Actualizar intentos de login
   * @param {string} userId - ID del usuario
   * @param {boolean} success - Si el login fue exitoso
   */
  async updateLoginAttempts(userId, success) {
    try {
      if (success) {
        return await this.model.findByIdAndUpdate(
          userId,
          {
            $unset: { loginAttempts: 1, lockUntil: 1 },
            $set: {
              lastLoginAt: new Date(),
              updatedAt: new Date(),
              "metadata.lastActiveAt": new Date(),
              "metadata.activityTracking.firstLogin": {
                $cond: {
                  if: { $eq: ["$metadata.activityTracking.firstLogin", null] },
                  then: new Date(),
                  else: "$metadata.activityTracking.firstLogin",
                },
              },
            },
            $inc: { "metadata.totalLogins": 1 },
          },
          { new: true }
        );
      } else {
        const user = await this.model.findById(userId);
        if (!user) return null;

        const attempts = (user.loginAttempts || 0) + 1;
        const updates = {
          loginAttempts: attempts,
          updatedAt: new Date(),
        };

        if (attempts >= 5) {
          updates.lockUntil = new Date(Date.now() + 2 * 60 * 60 * 1000);
        }

        return await this.model.findByIdAndUpdate(userId, updates, {
          new: true,
        });
      }
    } catch (error) {
      console.error("Error actualizando intentos de login:", error);
      throw error;
    }
  }

  /**
   * Incrementar intentos de login fallidos
   * @param {string} userId - ID del usuario
   */
  async incrementLoginAttempts(userId) {
    try {
      const user = await this.model.findById(userId);
      if (!user) return;

      if (user.lockUntil && user.lockUntil < Date.now()) {
        await this.model.updateOne(
          { _id: userId },
          {
            $unset: { lockUntil: 1 },
            $set: { loginAttempts: 1 },
          }
        );
        return;
      }

      const updates = { $inc: { loginAttempts: 1 } };

      if (user.loginAttempts + 1 >= 5 && !user.lockUntil) {
        updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 };
      }

      await this.model.updateOne({ _id: userId }, updates);
    } catch (error) {
      console.error("Error incrementando intentos de login:", error);
      throw error;
    }
  }

  /**
   * Resetear intentos de login fallidos
   * @param {string} userId - ID del usuario
   */
  async resetLoginAttempts(userId) {
    try {
      const updates = {
        $unset: { lockUntil: 1 },
        $set: {
          loginAttempts: 0,
          lastLoginAt: new Date(),
          "metadata.lastActiveAt": new Date(),
        },
        $inc: { "metadata.totalLogins": 1 },
      };

      await this.model.updateOne({ _id: userId }, updates);
    } catch (error) {
      console.error("Error reseteando intentos de login:", error);
      throw error;
    }
  }

  // ===== OAUTH Y PROVEEDORES EXTERNOS =====

  /**
   * Conectar proveedor OAuth
   * @param {string} userId - ID del usuario
   * @param {string} provider - Proveedor OAuth
   * @param {Object} providerData - Datos del proveedor
   * @param {Object} sessionData - Datos de sesión
   */
  async connectOAuthProvider(userId, provider, providerData, sessionData) {
    try {
      const allowedProviders = ["google", "facebook", "apple", "microsoft"];

      if (!allowedProviders.includes(provider)) {
        throw new Error(`Proveedor OAuth '${provider}' no válido`);
      }

      const user = await this.findById(userId);
      if (!user) {
        throw new Error("Usuario no encontrado");
      }

      if (user.oauthProviders?.[provider]?.providerId) {
        throw new Error(`Proveedor ${provider} ya está conectado`);
      }

      const updateData = {
        [`oauthProviders.${provider}`]: {
          providerId: providerData.providerId,
          email: providerData.email,
          isVerified: providerData.isVerified || false,
          connectedAt: new Date(),
          lastUsed: new Date(),
        },
        "metadata.activityTracking.accountVerificationLevel":
          this.calculateVerificationLevel({
            ...user,
            oauthProviders: {
              ...user.oauthProviders,
              [provider]: providerData,
            },
          }),
      };

      return await this.update(userId, updateData, sessionData);
    } catch (error) {
      console.error("Error conectando proveedor OAuth:", error);
      throw error;
    }
  }

  /**
   * Desconectar proveedor OAuth
   * @param {string} userId - ID del usuario
   * @param {string} provider - Proveedor OAuth
   * @param {Object} sessionData - Datos de sesión
   */
  async disconnectOAuthProvider(userId, provider, sessionData) {
    try {
      const user = await this.findById(userId);
      if (!user) {
        throw new Error("Usuario no encontrado");
      }

      const updateData = {
        [`oauthProviders.${provider}`]: undefined,
        "metadata.activityTracking.accountVerificationLevel":
          this.calculateVerificationLevel({
            ...user,
            oauthProviders: { ...user.oauthProviders, [provider]: null },
          }),
      };

      return await this.update(userId, updateData, sessionData, {
        $unset: { [`oauthProviders.${provider}`]: 1 },
      });
    } catch (error) {
      console.error("Error desconectando proveedor OAuth:", error);
      throw error;
    }
  }

  // ===== VERIFICACIÓN DE EMAIL =====

  /**
   * Generar token de verificación de email
   * @param {string} userId - ID del usuario
   * @param {Object} options - Opciones adicionales
   */
  async generateEmailVerificationToken(userId, options = {}) {
    try {
      const token = crypto.randomBytes(32).toString("hex");
      const expires = new Date(Date.now() + 24 * 60 * 60 * 1000);

      await this.model.updateOne(
        { _id: userId },
        {
          emailVerificationToken: token,
          emailVerificationExpires: expires,
        },
        options
      );

      return token;
    } catch (error) {
      console.error("Error generando token de verificación:", error);
      throw error;
    }
  }

  /**
   * Verificar email con token
   * @param {string} token - Token de verificación
   * @param {Object} sessionData - Datos de sesión
   */
  async verifyEmailWithToken(token, sessionData) {
    try {
      const user = await this.model.findOne({
        emailVerificationToken: token,
        emailVerificationExpires: { $gt: new Date() },
      });

      if (!user) {
        throw new Error("Token de verificación inválido o expirado");
      }

      const updateData = {
        isEmailVerified: true,
        "metadata.activityTracking.accountVerificationLevel":
          this.calculateVerificationLevel({
            ...user.toObject(),
            isEmailVerified: true,
          }),
        $unset: {
          emailVerificationToken: 1,
          emailVerificationExpires: 1,
        },
      };

      return await this.update(user._id, updateData, sessionData);
    } catch (error) {
      console.error("Error verificando email:", error);
      throw error;
    }
  }

  // ===== RESET DE CONTRASEÑA =====

  /**
   * Generar token de reset de contraseña
   * @param {string} email - Email del usuario
   */
  async generatePasswordResetToken(email) {
    try {
      const user = await this.findByEmail(email);
      if (!user) {
        throw new Error("Usuario no encontrado");
      }

      const token = crypto.randomBytes(32).toString("hex");
      const expires = new Date(Date.now() + 60 * 60 * 1000);

      await this.model.updateOne(
        { _id: user._id },
        {
          passwordResetToken: token,
          passwordResetExpires: expires,
        }
      );

      return { token, userId: user._id, email: user.email };
    } catch (error) {
      console.error("Error generando token de reset:", error);
      throw error;
    }
  }

  /**
   * Resetear contraseña con token
   * @param {string} token - Token de reset
   * @param {string} newPassword - Nueva contraseña
   * @param {Object} sessionData - Datos de sesión
   */
  async resetPasswordWithToken(token, newPassword, sessionData) {
    try {
      const user = await this.model.findOne({
        passwordResetToken: token,
        passwordResetExpires: { $gt: new Date() },
      });

      if (!user) {
        throw new Error("Token de reset inválido o expirado");
      }

      await this.setPassword(user._id, newPassword, sessionData);

      await this.model.updateOne(
        { _id: user._id },
        {
          $unset: {
            passwordResetToken: 1,
            passwordResetExpires: 1,
          },
        }
      );

      return user;
    } catch (error) {
      console.error("Error reseteando contraseña:", error);
      throw error;
    }
  }

  // ===== PREFERENCIAS DE USUARIO =====

  /**
   * Actualizar preferencias de usuario (método legacy compatible)
   * @param {string} userId - ID del usuario
   * @param {Object} preferences - Nuevas preferencias
   * @param {Object} sessionData - Datos de sesión
   */
  async updatePreferences(userId, preferences, sessionData) {
    try {
      const user = await this.findById(userId);
      if (!user) {
        throw new Error("Usuario no encontrado");
      }

      const currentPreferences = user.preferences || {};
      const updatedPreferences = {
        ...currentPreferences,
        ...preferences,
        notifications: {
          ...currentPreferences.notifications,
          ...preferences.notifications,
        },
        privacy: {
          ...currentPreferences.privacy,
          ...preferences.privacy,
        },
        business: {
          ...currentPreferences.business,
          ...preferences.business,
        },
      };

      const updateData = {
        preferences: updatedPreferences,
        "metadata.activityTracking.lastPreferencesUpdate": new Date(),
      };

      return await this.update(userId, updateData, sessionData);
    } catch (error) {
      console.error("Error actualizando preferencias:", error);
      throw error;
    }
  }

  // ===== BÚSQUEDAS COMPATIBLES =====

  /**
   * Buscar usuarios con filtros (método legacy compatible)
   * @param {Object} filters - Filtros de búsqueda
   * @param {Object} options - Opciones de paginación
   */
  async findWithFilters(filters = {}, options = {}) {
    try {
      const {
        search,
        language,
        isActive,
        isEmailVerified,
        registrationSource,
        hasOAuth,
        dateFrom,
        dateTo,
      } = filters;

      const {
        page = 1,
        limit = 10,
        sortBy = "createdAt",
        sortOrder = -1,
        populate = ["roles"],
      } = options;

      let query = {
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      };

      if (search) {
        query.$and = query.$and || [];
        query.$and.push({
          $or: [
            { "profile.firstName": { $regex: search, $options: "i" } },
            { "profile.lastName": { $regex: search, $options: "i" } },
            { email: { $regex: search, $options: "i" } },
          ],
        });
      }

      if (language) query["preferences.language"] = language;
      if (isActive !== undefined) query.isActive = isActive;
      if (isEmailVerified !== undefined)
        query.isEmailVerified = isEmailVerified;
      if (registrationSource)
        query["metadata.registrationSource"] = registrationSource;

      if (hasOAuth !== undefined) {
        if (hasOAuth) {
          query.$or = [
            { "oauthProviders.google.providerId": { $exists: true } },
            { "oauthProviders.facebook.providerId": { $exists: true } },
            { "oauthProviders.apple.providerId": { $exists: true } },
            { "oauthProviders.microsoft.providerId": { $exists: true } },
          ];
        } else {
          query.$and = query.$and || [];
          query.$and.push({
            "oauthProviders.google.providerId": { $exists: false },
            "oauthProviders.facebook.providerId": { $exists: false },
            "oauthProviders.apple.providerId": { $exists: false },
            "oauthProviders.microsoft.providerId": { $exists: false },
          });
        }
      }

      if (dateFrom || dateTo) {
        query.createdAt = {};
        if (dateFrom) query.createdAt.$gte = new Date(dateFrom);
        if (dateTo) query.createdAt.$lte = new Date(dateTo);
      }

      return await this.findAll(query, {
        page,
        limit,
        sort: { [sortBy]: sortOrder },
        populate,
      });
    } catch (error) {
      console.error("Error buscando usuarios con filtros:", error);
      throw error;
    }
  }

  // ===== ESTADÍSTICAS Y ANÁLISIS =====

  /**
   * Obtener estadísticas de usuarios
   */
  async getUserStats() {
    try {
      const stats = await this.model.aggregate([
        {
          $match: {
            $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
          },
        },
        {
          $group: {
            _id: null,
            totalUsers: { $sum: 1 },
            activeUsers: {
              $sum: { $cond: [{ $eq: ["$isActive", true] }, 1, 0] },
            },
            verifiedUsers: {
              $sum: { $cond: [{ $eq: ["$isEmailVerified", true] }, 1, 0] },
            },
            usersWithOAuth: {
              $sum: {
                $cond: [
                  {
                    $or: [
                      { $exists: ["$oauthProviders.google.providerId", true] },
                      {
                        $exists: ["$oauthProviders.facebook.providerId", true],
                      },
                      { $exists: ["$oauthProviders.apple.providerId", true] },
                      {
                        $exists: ["$oauthProviders.microsoft.providerId", true],
                      },
                    ],
                  },
                  1,
                  0,
                ],
              },
            },
            usersWithCompletedProfiles: {
              $sum: {
                $cond: [
                  {
                    $gte: [
                      "$metadata.activityTracking.profileCompleteness",
                      0.8,
                    ],
                  },
                  1,
                  0,
                ],
              },
            },
            usersWithTwoFactor: {
              $sum: { $cond: [{ $eq: ["$twoFactorEnabled", true] }, 1, 0] },
            },
            avgTotalLogins: { $avg: "$metadata.totalLogins" },
            avgSessionDuration: { $avg: "$metadata.averageSessionDuration" },
            avgProfileCompleteness: {
              $avg: "$metadata.activityTracking.profileCompleteness",
            },
            avgVerificationLevel: {
              $avg: "$metadata.activityTracking.accountVerificationLevel",
            },
          },
        },
      ]);

      const languageStats = await this.model.aggregate([
        {
          $match: {
            isActive: true,
            $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
          },
        },
        {
          $group: {
            _id: "$preferences.language",
            count: { $sum: 1 },
          },
        },
        { $sort: { count: -1 } },
      ]);

      const sourceStats = await this.model.aggregate([
        {
          $match: {
            $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
          },
        },
        {
          $group: {
            _id: "$metadata.registrationSource",
            count: { $sum: 1 },
          },
        },
        { $sort: { count: -1 } },
      ]);

      // Estadísticas empresariales
      const businessStats = await this.model.aggregate([
        {
          $match: {
            isActive: true,
            $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
          },
        },
        {
          $group: {
            _id: null,
            avgSearchRadius: { $avg: "$preferences.business.searchRadius" },
            autoTranslateUsers: {
              $sum: {
                $cond: [
                  { $eq: ["$preferences.business.autoTranslate", true] },
                  1,
                  0,
                ],
              },
            },
            usersWithBusinessPrefs: {
              $sum: {
                $cond: [
                  {
                    $gt: [
                      {
                        $size: {
                          $ifNull: [
                            "$preferences.business.preferredCategories",
                            [],
                          ],
                        },
                      },
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
        general: stats[0] || {
          totalUsers: 0,
          activeUsers: 0,
          verifiedUsers: 0,
          usersWithOAuth: 0,
          usersWithCompletedProfiles: 0,
          usersWithTwoFactor: 0,
          avgTotalLogins: 0,
          avgSessionDuration: 0,
          avgProfileCompleteness: 0,
          avgVerificationLevel: 0,
        },
        byLanguage: languageStats,
        byRegistrationSource: sourceStats,
        businessMetrics: businessStats[0] || {
          avgSearchRadius: 0,
          autoTranslateUsers: 0,
          usersWithBusinessPrefs: 0,
        },
      };
    } catch (error) {
      console.error("Error obteniendo estadísticas de usuarios:", error);
      throw error;
    }
  }

  /**
   * Limpiar tokens expirados
   */
  async cleanExpiredTokens() {
    try {
      const result = await this.model.updateMany(
        {
          $or: [
            {
              emailVerificationExpires: { $lt: new Date() },
              emailVerificationToken: { $exists: true },
            },
            {
              passwordResetExpires: { $lt: new Date() },
              passwordResetToken: { $exists: true },
            },
          ],
        },
        {
          $unset: {
            emailVerificationToken: 1,
            emailVerificationExpires: 1,
            passwordResetToken: 1,
            passwordResetExpires: 1,
          },
        }
      );

      console.log(`✅ Tokens expirados limpiados: ${result.modifiedCount}`);
      return result;
    } catch (error) {
      console.error("Error limpiando tokens expirados:", error);
      throw error;
    }
  }

  // ===== MÉTODOS AUXILIARES =====

  /**
   * Calcular completitud del perfil
   * @param {Object} userData - Datos del usuario
   */
  calculateProfileCompleteness(userData) {
    const fields = [
      "firstName",
      "lastName",
      "dateOfBirth",
      "phone",
      "bio",
      "avatar",
    ];

    const completedFields = fields.filter((field) => {
      const value = userData.profile?.[field] || userData[field];
      return value && value.toString().trim().length > 0;
    });

    return Math.round((completedFields.length / fields.length) * 100) / 100;
  }

  /**
   * Calcular nivel de verificación
   * @param {Object} userData - Datos del usuario
   */
  calculateVerificationLevel(userData) {
    let level = 0;

    if (userData.isEmailVerified) level += 0.3;
    if (userData.profile?.phone || userData.phone) level += 0.2;
    if (userData.profile?.avatar || userData.avatar) level += 0.15;
    if (userData.twoFactorEnabled) level += 0.25;
    if (
      userData.oauthProviders &&
      Object.keys(userData.oauthProviders).some(
        (p) => userData.oauthProviders[p]?.providerId
      )
    )
      level += 0.1;

    return Math.min(1, level);
  }

  /**
   * Validar datos del perfil
   * @param {Object} profileData - Datos del perfil a validar
   */
  validateProfileData(profileData) {
    const validated = {};

    if (profileData.firstName) {
      validated.firstName = profileData.firstName.trim().substring(0, 50);
    }

    if (profileData.lastName) {
      validated.lastName = profileData.lastName.trim().substring(0, 50);
    }

    if (profileData.dateOfBirth) {
      const birthDate = new Date(profileData.dateOfBirth);
      const today = new Date();
      const age = today.getFullYear() - birthDate.getFullYear();

      if (age >= 13 && age <= 120) {
        validated.dateOfBirth = birthDate;
      }
    }

    if (profileData.phone) {
      const phoneRegex = /^\+?[1-9]\d{1,14}$/;
      const cleanPhone = profileData.phone.replace(/\s/g, "");
      if (phoneRegex.test(cleanPhone)) {
        validated.phone = cleanPhone;
      }
    }

    if (profileData.bio) {
      validated.bio = profileData.bio.trim().substring(0, 500);
    }

    if (profileData.website) {
      const urlRegex = /^https?:\/\/.+/;
      if (urlRegex.test(profileData.website)) {
        validated.website = profileData.website;
      }
    }

    if (profileData.avatar) {
      const urlRegex = /^https?:\/\/.+/;
      if (urlRegex.test(profileData.avatar)) {
        validated.avatar = profileData.avatar;
      }
    }

    return validated;
  }

  /**
   * Construir filtro OAuth
   * @param {boolean} hasOAuth - Si tiene OAuth o no
   */
  buildOAuthFilter(hasOAuth) {
    if (hasOAuth) {
      return {
        $or: [
          { "oauthProviders.google.providerId": { $exists: true } },
          { "oauthProviders.facebook.providerId": { $exists: true } },
          { "oauthProviders.apple.providerId": { $exists: true } },
          { "oauthProviders.microsoft.providerId": { $exists: true } },
        ],
      };
    } else {
      return {
        $and: [
          { "oauthProviders.google.providerId": { $exists: false } },
          { "oauthProviders.facebook.providerId": { $exists: false } },
          { "oauthProviders.apple.providerId": { $exists: false } },
          { "oauthProviders.microsoft.providerId": { $exists: false } },
        ],
      };
    }
  }

  /**
   * Generar secreto para 2FA
   */
  generateTwoFactorSecret() {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let secret = "";
    for (let i = 0; i < 32; i++) {
      secret += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return secret;
  }

  /**
   * Generar códigos de respaldo para 2FA
   */
  generateBackupCodes() {
    const codes = [];
    for (let i = 0; i < 10; i++) {
      const code = Math.floor(100000 + Math.random() * 900000).toString();
      codes.push(code);
    }
    return codes;
  }

  /**
   * Generar URL para código QR de 2FA
   * @param {string} email - Email del usuario
   * @param {string} secret - Secreto 2FA
   */
  generateQRCodeUrl(email, secret) {
    const appName = encodeURIComponent("Business Locator");
    const accountName = encodeURIComponent(email);
    return `otpauth://totp/${appName}:${accountName}?secret=${secret}&issuer=${appName}`;
  }

  /**
   * Calcular métricas detalladas de usuario
   * @param {string} userId - ID del usuario
   * @param {Object} options - Opciones de cálculo
   */
  async calculateDetailedUserMetrics(userId, options = {}) {
    try {
      // Implementar métricas detalladas específicas para la plataforma empresarial
      const metrics = await this.model.aggregate([
        { $match: { _id: new Types.ObjectId(userId) } },
        {
          $lookup: {
            from: "usersessions",
            let: { userId: "$_id" },
            pipeline: [
              { $match: { $expr: { $eq: ["$userId", "$$userId"] } } },
              {
                $group: {
                  _id: { $dayOfWeek: "$createdAt" },
                  count: { $sum: 1 },
                  avgDuration: { $avg: "$metadata.sessionDuration" },
                },
              },
            ],
            as: "weeklyPatterns",
          },
        },
      ]);

      return {
        weeklyUsagePatterns: metrics[0]?.weeklyPatterns || [],
        // TODO: Agregar más métricas detalladas según necesidades empresariales
        calculatedAt: new Date(),
      };
    } catch (error) {
      console.error("Error calculando métricas detalladas:", error);
      return {};
    }
  }
}
