// =============================================================================
// src/modules/authentication/repositories/user.repository.js
// Repositorio específico para User con soporte multiidioma y funciones especializadas
// =============================================================================
import { Types } from "mongoose";
import { BaseRepository } from "../../core/repositories/base.repository.js";
import { User } from "../models/user.scheme.js";
import {
  SUPPORTED_LANGUAGES,
  DEFAULT_LANGUAGE,
} from "../../core/models/multi_language_pattern.scheme.js";

export class UserRepository extends BaseRepository {
  constructor() {
    super(User);
  }

  // =============================================================================
  // 🔐 MÉTODOS DE AUTENTICACIÓN Y SEGURIDAD
  // =============================================================================

  /**
   * Buscar usuario por email para autenticación
   */
  async findByEmailForAuth(email) {
    try {
      const user = await this.model
        .findOne({
          email: email.toLowerCase().trim(),
          $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
          isActive: true,
        })
        .select("+passwordHash +emailVerificationToken +passwordResetToken")
        .populate("roles", "roleName displayName permissions")
        .lean();

      return user;
    } catch (error) {
      console.error("Error buscando usuario por email:", error);
      throw new Error(`Error en autenticación: ${error.message}`);
    }
  }

  /**
   * Validar credenciales de login
   */
  async validateCredentials(email, password) {
    try {
      const user = await this.findByEmailForAuth(email);

      if (!user) {
        throw new Error("Usuario no encontrado");
      }

      // Verificar si está bloqueado
      if (user.lockUntil && user.lockUntil > new Date()) {
        throw new Error(
          "Cuenta temporalmente bloqueada por múltiples intentos fallidos"
        );
      }

      // Crear instancia para usar método validatePassword
      const userInstance = this.model.hydrate(user);
      const isValidPassword = await userInstance.validatePassword(password);

      if (!isValidPassword) {
        // Incrementar intentos fallidos
        await this.model.findByIdAndUpdate(user._id, {
          $inc: { loginAttempts: 1 },
          $set:
            user.loginAttempts >= 4
              ? { lockUntil: new Date(Date.now() + 2 * 60 * 60 * 1000) }
              : {},
        });

        throw new Error("Contraseña incorrecta");
      }

      // Reset intentos de login exitoso
      await this.model.findByIdAndUpdate(user._id, {
        $unset: { lockUntil: 1 },
        $set: {
          loginAttempts: 0,
          lastLoginAt: new Date(),
          "metadata.lastActiveAt": new Date(),
        },
        $inc: { "metadata.totalLogins": 1 },
      });

      return user;
    } catch (error) {
      console.error("Error validando credenciales:", error);
      throw error;
    }
  }

  /**
   * Crear usuario con configuración inicial multiidioma
   */
  async createUser(userData, options = {}) {
    try {
      const {
        language = DEFAULT_LANGUAGE,
        autoSetupMultiLanguage = true,
        targetLanguages = [],
      } = options;

      // Preparar datos del perfil multiidioma
      const profileData = { ...userData.profile };

      if (autoSetupMultiLanguage && profileData.firstName) {
        profileData.firstName = {
          original: {
            language: language,
            text: profileData.firstName,
            createdAt: new Date(),
            lastModified: new Date(),
          },
          translations: new Map(),
          translationLanguages: [],
          translationConfig: {
            autoTranslate: targetLanguages.length > 0,
            targetLanguages: targetLanguages,
          },
        };
      }

      if (autoSetupMultiLanguage && profileData.lastName) {
        profileData.lastName = {
          original: {
            language: language,
            text: profileData.lastName,
            createdAt: new Date(),
            lastModified: new Date(),
          },
          translations: new Map(),
          translationLanguages: [],
          translationConfig: {
            autoTranslate: targetLanguages.length > 0,
            targetLanguages: targetLanguages,
          },
        };
      }

      // Configurar preferencias de idioma
      const preferences = {
        language: language,
        fallbackLanguages:
          targetLanguages.length > 0 ? targetLanguages : ["en", "es"],
        ...userData.preferences,
        business: {
          autoTranslationConfig: {
            enabled: true,
            targetLanguages: targetLanguages,
            translationQuality: "standard",
          },
          ...userData.preferences?.business,
        },
      };

      const newUserData = {
        ...userData,
        profile: profileData,
        preferences: preferences,
        metadata: {
          registrationDetails: {
            registrationLanguage: language,
            ...userData.metadata?.registrationDetails,
          },
          activityTracking: {
            mostUsedLanguages: [
              {
                language: language,
                usageCount: 1,
                lastUsed: new Date(),
              },
            ],
          },
          ...userData.metadata,
        },
      };

      const user = await this.create(newUserData, { userId: "system" });
      return user;
    } catch (error) {
      console.error("Error creando usuario:", error);
      throw new Error(`Error creando usuario: ${error.message}`);
    }
  }

  /**
   * Gestión de tokens de verificación
   */
  async generateEmailVerificationToken(userId) {
    try {
      const user = await this.findById(userId);
      if (!user) throw new Error("Usuario no encontrado");

      const userInstance = this.model.hydrate(user);
      const token = userInstance.generateEmailVerificationToken();

      await userInstance.save();
      return token;
    } catch (error) {
      console.error("Error generando token de verificación:", error);
      throw error;
    }
  }

  async verifyEmail(token) {
    try {
      const user = await this.model.findByVerificationToken(token);
      if (!user) {
        throw new Error("Token de verificación inválido o expirado");
      }

      await this.model.findByIdAndUpdate(user._id, {
        $set: {
          isEmailVerified: true,
          "metadata.activityTracking.accountVerificationLevel": 1,
        },
        $unset: {
          emailVerificationToken: 1,
          emailVerificationExpires: 1,
        },
      });

      return { message: "Email verificado exitosamente" };
    } catch (error) {
      console.error("Error verificando email:", error);
      throw error;
    }
  }

  /**
   * Reset de contraseña
   */
  async generatePasswordResetToken(email) {
    try {
      const user = await this.model.findByEmail(email);
      if (!user) {
        throw new Error("Usuario no encontrado");
      }

      const token = user.generatePasswordResetToken();
      await user.save();

      return { token, user: { email: user.email, id: user._id } };
    } catch (error) {
      console.error("Error generando token de reset:", error);
      throw error;
    }
  }

  async resetPassword(token, newPassword) {
    try {
      const user = await this.model.findByPasswordResetToken(token);
      if (!user) {
        throw new Error("Token de reset inválido o expirado");
      }

      await user.setPassword(newPassword);
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      user.metadata.activityTracking.lastPasswordChange = new Date();

      await user.save();
      return { message: "Contraseña actualizada exitosamente" };
    } catch (error) {
      console.error("Error reseteando contraseña:", error);
      throw error;
    }
  }

  // =============================================================================
  // 🌐 MÉTODOS ESPECÍFICOS MULTIIDIOMA
  // =============================================================================

  /**
   * Obtener perfil localizado de usuario
   */
  async getLocalizedProfile(userId, language = null, options = {}) {
    try {
      const user = await this.findById(userId, {
        populate: "roles",
        lean: false,
        returnInstance: true,
      });

      if (!user) throw new Error("Usuario no encontrado");

      const targetLanguage =
        language || user.preferences?.language || DEFAULT_LANGUAGE;
      const localizedProfile = user.getLocalizedProfile(
        targetLanguage,
        options
      );

      return {
        ...localizedProfile,
        id: user._id,
        email: user.email,
        preferences: user.preferences,
        languageStats: user.languageStats,
        isEmailVerified: user.isEmailVerified,
        roles: user.roles,
      };
    } catch (error) {
      console.error("Error obteniendo perfil localizado:", error);
      throw error;
    }
  }

  /**
   * Actualizar texto de perfil multiidioma
   */
  async updateProfileText(
    userId,
    field,
    text,
    language = null,
    userData,
    options = {}
  ) {
    try {
      const user = await this.findById(userId, {
        lean: false,
        returnInstance: true,
      });
      if (!user) throw new Error("Usuario no encontrado");

      const targetLanguage =
        language || user.preferences?.language || DEFAULT_LANGUAGE;
      user.updateProfileText(field, text, targetLanguage, options);
      user.updatedBy = userData.userId;

      await user.save();

      // Registrar actividad de actualización de idioma
      if (language && language !== user.preferences?.language) {
        await this.trackLanguageUsage(userId, language);
      }

      return user.getLocalizedProfile(targetLanguage);
    } catch (error) {
      console.error(`Error actualizando ${field}:`, error);
      throw error;
    }
  }

  /**
   * Cambiar idioma principal del usuario
   */
  async changeUserLanguage(userId, newLanguage, userData) {
    try {
      if (!SUPPORTED_LANGUAGES.includes(newLanguage)) {
        throw new Error(`Idioma '${newLanguage}' no está soportado`);
      }

      const user = await this.findById(userId, {
        lean: false,
        returnInstance: true,
      });
      if (!user) throw new Error("Usuario no encontrado");

      const result = user.changeLanguage(newLanguage);
      user.updatedBy = userData.userId;

      await user.save();

      return {
        message: "Idioma cambiado exitosamente",
        oldLanguage: result.oldLanguage,
        newLanguage: result.newLanguage,
        languageStats: user.languageStats,
      };
    } catch (error) {
      console.error("Error cambiando idioma:", error);
      throw error;
    }
  }

  /**
   * Registrar uso de idioma
   */
  async trackLanguageUsage(userId, language) {
    try {
      await this.model.findByIdAndUpdate(
        userId,
        {
          $inc: { "metadata.activityTracking.totalLanguageSwitches": 1 },
          $set: {
            "metadata.activityTracking.mostUsedLanguages.$[elem].usageCount": 1,
            "metadata.activityTracking.mostUsedLanguages.$[elem].lastUsed":
              new Date(),
          },
        },
        {
          arrayFilters: [{ "elem.language": language }],
          upsert: false,
        }
      );

      // Si el idioma no existe, agregarlo
      await this.model.findByIdAndUpdate(userId, {
        $addToSet: {
          "metadata.activityTracking.mostUsedLanguages": {
            language: language,
            usageCount: 1,
            lastUsed: new Date(),
          },
        },
      });
    } catch (error) {
      console.error("Error registrando uso de idioma:", error);
    }
  }

  // =============================================================================
  // 🔧 GESTIÓN DE OAUTH
  // =============================================================================

  /**
   * Conectar proveedor OAuth
   */
  async connectOAuthProvider(userId, provider, providerData, userData) {
    try {
      const user = await this.findById(userId, {
        lean: false,
        returnInstance: true,
      });
      if (!user) throw new Error("Usuario no encontrado");

      user.connectOAuthProvider(provider, providerData);
      user.updatedBy = userData.userId;
      user.metadata.activityTracking.lastSecurityUpdate = new Date();

      await user.save();

      return {
        message: `Proveedor ${provider} conectado exitosamente`,
        connectedProviders: Object.keys(user.oauthProviders || {}).filter(
          (key) => user.oauthProviders[key]?.providerId
        ),
      };
    } catch (error) {
      console.error(`Error conectando ${provider}:`, error);
      throw error;
    }
  }

  /**
   * Desconectar proveedor OAuth
   */
  async disconnectOAuthProvider(userId, provider, userData) {
    try {
      const user = await this.findById(userId, {
        lean: false,
        returnInstance: true,
      });
      if (!user) throw new Error("Usuario no encontrado");

      // Verificar que no sea la única forma de autenticación
      if (!user.passwordHash && user.hasOAuth) {
        const connectedProviders = Object.keys(
          user.oauthProviders || {}
        ).filter((key) => user.oauthProviders[key]?.providerId);

        if (
          connectedProviders.length === 1 &&
          connectedProviders[0] === provider
        ) {
          throw new Error(
            "No puedes desconectar el único método de autenticación. Configura una contraseña primero."
          );
        }
      }

      user.disconnectOAuthProvider(provider);
      user.updatedBy = userData.userId;
      user.metadata.activityTracking.lastSecurityUpdate = new Date();

      await user.save();

      return {
        message: `Proveedor ${provider} desconectado exitosamente`,
      };
    } catch (error) {
      console.error(`Error desconectando ${provider}:`, error);
      throw error;
    }
  }

  /**
   * Buscar o crear usuario por OAuth
   */
  async findOrCreateByOAuth(
    provider,
    providerData,
    language = DEFAULT_LANGUAGE
  ) {
    try {
      // Buscar usuario existente por email o provider ID
      let user = await this.model.findOne({
        $or: [
          { email: providerData.email },
          {
            [`oauthProviders.${provider}.providerId`]: providerData.providerId,
          },
        ],
        $and: [
          { $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }] },
          { isActive: true },
        ],
      });

      if (user) {
        // Actualizar información del proveedor
        const userInstance = this.model.hydrate(user);
        userInstance.connectOAuthProvider(provider, {
          ...providerData,
          lastUsed: new Date(),
        });
        await userInstance.save();
        return userInstance.toObject();
      }

      // Crear nuevo usuario
      const names = providerData.name
        ? providerData.name.split(" ")
        : ["Usuario", "Oauth"];
      const userData = {
        email: providerData.email,
        profile: {
          firstName: names[0] || "Usuario",
          lastName: names.slice(1).join(" ") || "OAuth",
          avatar: providerData.picture || null,
        },
        isEmailVerified: providerData.emailVerified || false,
        oauthProviders: {
          [provider]: {
            providerId: providerData.providerId,
            email: providerData.email,
            isVerified: providerData.emailVerified || false,
            connectedAt: new Date(),
            lastUsed: new Date(),
          },
        },
        metadata: {
          registrationSource: "oauth",
          registrationDetails: {
            registrationLanguage: language,
          },
        },
      };

      return await this.createUser(userData, {
        language,
        autoSetupMultiLanguage: true,
        targetLanguages: ["en", "es"],
      });
    } catch (error) {
      console.error("Error en OAuth:", error);
      throw error;
    }
  }

  // =============================================================================
  // 👥 BÚSQUEDAS Y CONSULTAS ESPECÍFICAS
  // =============================================================================

  /**
   * Búsqueda avanzada de usuarios con filtros multiidioma
   */
  async searchUsers(filters = {}, options = {}) {
    try {
      const {
        text = "",
        language = null,
        preferredLanguage = null,
        roles = [],
        isVerified = null,
        dateFrom = null,
        dateTo = null,
        includeProfile = true,
        ...otherFilters
      } = filters;

      const config = {
        filters: {
          ...otherFilters,
          searchText: text,
          searchFields: [
            "profile.firstName.original.text",
            "profile.lastName.original.text",
            "profile.bio.original.text",
            "email",
          ],
          dateFrom,
          dateTo,
        },
        options: {
          ...options,
          enablePagination: true,
        },
        autoLookups: includeProfile,
        customLookups:
          roles.length > 0
            ? [
                {
                  from: "roles",
                  localField: "roles",
                  foreignField: "_id",
                  as: "rolesData",
                  pipeline: [
                    { $match: { roleName: { $in: roles } } },
                    { $project: { roleName: 1, displayName: 1 } },
                  ],
                },
              ]
            : [],
      };

      // Filtros específicos
      if (preferredLanguage) {
        config.filters["preferences.language"] = preferredLanguage;
      }

      if (language) {
        config.filters.$or = [
          { "profile.firstName.original.language": language },
          { "profile.firstName.translationLanguages": language },
        ];
      }

      if (isVerified !== null) {
        config.filters.isEmailVerified = isVerified;
      }

      if (roles.length > 0) {
        config.filters["rolesData.roleName"] = { $in: roles };
      }

      return await this.executeAggregationPipeline(config);
    } catch (error) {
      console.error("Error en búsqueda de usuarios:", error);
      throw error;
    }
  }

  /**
   * Obtener usuarios por idioma con estadísticas
   */
  async getUsersByLanguageStats(options = {}) {
    try {
      const { includeInactive = false } = options;

      const config = {
        pipeline: [
          ...(includeInactive
            ? []
            : [
                {
                  $match: {
                    isActive: true,
                    $or: [
                      { isDeleted: false },
                      { isDeleted: { $exists: false } },
                    ],
                  },
                },
              ]),
          {
            $group: {
              _id: "$preferences.language",
              totalUsers: { $sum: 1 },
              verifiedUsers: {
                $sum: { $cond: [{ $eq: ["$isEmailVerified", true] }, 1, 0] },
              },
              oauthUsers: {
                $sum: {
                  $cond: [
                    {
                      $or: [
                        {
                          $exists: ["$oauthProviders.google.providerId", true],
                        },
                        {
                          $exists: [
                            "$oauthProviders.facebook.providerId",
                            true,
                          ],
                        },
                        { $exists: ["$oauthProviders.apple.providerId", true] },
                        {
                          $exists: [
                            "$oauthProviders.microsoft.providerId",
                            true,
                          ],
                        },
                      ],
                    },
                    1,
                    0,
                  ],
                },
              },
              avgLanguageSwitches: {
                $avg: "$metadata.activityTracking.totalLanguageSwitches",
              },
              lastActivity: { $max: "$metadata.lastActiveAt" },
              users: {
                $push: {
                  id: "$_id",
                  email: "$email",
                  lastLoginAt: "$lastLoginAt",
                  totalLogins: "$metadata.totalLogins",
                },
              },
            },
          },
          {
            $project: {
              language: "$_id",
              _id: 0,
              totalUsers: 1,
              verifiedUsers: 1,
              oauthUsers: 1,
              verificationRate: {
                $multiply: [
                  { $divide: ["$verifiedUsers", "$totalUsers"] },
                  100,
                ],
              },
              oauthAdoptionRate: {
                $multiply: [{ $divide: ["$oauthUsers", "$totalUsers"] }, 100],
              },
              avgLanguageSwitches: { $round: ["$avgLanguageSwitches", 2] },
              lastActivity: 1,
              sampleUsers: { $slice: ["$users", 5] },
            },
          },
          { $sort: { totalUsers: -1 } },
        ],
        options: { enablePagination: false },
      };

      const result = await this.executeAggregationPipeline(config);
      return result;
    } catch (error) {
      console.error("Error obteniendo estadísticas por idioma:", error);
      throw error;
    }
  }

  /**
   * Dashboard de estadísticas de usuario
   */
  async getDashboardStats() {
    try {
      const config = {
        facets: {
          // Estadísticas generales
          general: [
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
                oauthUsers: {
                  $sum: {
                    $cond: [
                      {
                        $gt: [
                          {
                            $size: {
                              $objectToArray: {
                                $ifNull: ["$oauthProviders", {}],
                              },
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
          ],

          // Distribución por idiomas
          languageDistribution: [
            {
              $group: {
                _id: "$preferences.language",
                count: { $sum: 1 },
              },
            },
            { $sort: { count: -1 } },
            { $limit: 10 },
          ],

          // Registros por mes
          registrationTrend: [
            {
              $group: {
                _id: {
                  year: { $year: "$createdAt" },
                  month: { $month: "$createdAt" },
                },
                count: { $sum: 1 },
              },
            },
            { $sort: { "_id.year": -1, "_id.month": -1 } },
            { $limit: 12 },
          ],

          // Usuarios más activos multiidioma
          multiLanguageUsers: [
            {
              $match: {
                "metadata.activityTracking.totalLanguageSwitches": { $gt: 0 },
              },
            },
            {
              $project: {
                email: 1,
                totalSwitches:
                  "$metadata.activityTracking.totalLanguageSwitches",
                primaryLanguage: "$preferences.language",
                mostUsedLanguages:
                  "$metadata.activityTracking.mostUsedLanguages",
              },
            },
            { $sort: { totalSwitches: -1 } },
            { $limit: 10 },
          ],
        },
        options: { enablePagination: false },
      };

      return await this.executeAggregationPipeline(config);
    } catch (error) {
      console.error("Error obteniendo estadísticas del dashboard:", error);
      throw error;
    }
  }

  // =============================================================================
  // ⚙️ GESTIÓN DE PREFERENCIAS
  // =============================================================================

  /**
   * Actualizar preferencias de usuario
   */
  async updateUserPreferences(userId, preferences, userData) {
    try {
      const user = await this.findById(userId, {
        lean: false,
        returnInstance: true,
      });
      if (!user) throw new Error("Usuario no encontrado");

      const oldLanguage = user.preferences?.language;
      user.updatePreferences(preferences);
      user.updatedBy = userData.userId;

      await user.save();

      // Registrar cambio de idioma si aplica
      if (preferences.language && preferences.language !== oldLanguage) {
        await this.trackLanguageUsage(userId, preferences.language);
      }

      return {
        message: "Preferencias actualizadas exitosamente",
        preferences: user.preferences,
        languageChanged:
          preferences.language && preferences.language !== oldLanguage,
        languageStats: user.languageStats,
      };
    } catch (error) {
      console.error("Error actualizando preferencias:", error);
      throw error;
    }
  }

  // =============================================================================
  // 📊 REPORTES Y ANÁLISIS
  // =============================================================================

  /**
   * Reporte de adopción multiidioma
   */
  async getMultiLanguageAdoptionReport(dateRange = {}) {
    try {
      const { startDate, endDate } = dateRange;
      const matchStage = {
        isActive: true,
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      };

      if (startDate || endDate) {
        matchStage.createdAt = {};
        if (startDate) matchStage.createdAt.$gte = new Date(startDate);
        if (endDate) matchStage.createdAt.$lte = new Date(endDate);
      }

      const config = {
        pipeline: [
          { $match: matchStage },
          {
            $project: {
              primaryLanguage: "$preferences.language",
              fallbackLanguagesCount: {
                $size: { $ifNull: ["$preferences.fallbackLanguages", []] },
              },
              totalLanguageSwitches:
                "$metadata.activityTracking.totalLanguageSwitches",
              hasMultiLanguageProfile: {
                $or: [
                  { $exists: ["$profile.firstName.translations", true] },
                  { $exists: ["$profile.lastName.translations", true] },
                  { $exists: ["$profile.bio.translations", true] },
                ],
              },
              autoTranslateEnabled:
                "$preferences.business.autoTranslationConfig.enabled",
              createdAt: 1,
            },
          },
          {
            $group: {
              _id: null,
              totalUsers: { $sum: 1 },
              multiLanguageUsers: {
                $sum: {
                  $cond: [{ $gt: ["$fallbackLanguagesCount", 0] }, 1, 0],
                },
              },
              usersWithLanguageSwitches: {
                $sum: { $cond: [{ $gt: ["$totalLanguageSwitches", 0] }, 1, 0] },
              },
              usersWithMultiLanguageProfile: {
                $sum: { $cond: ["$hasMultiLanguageProfile", 1, 0] },
              },
              autoTranslateUsers: {
                $sum: {
                  $cond: [{ $eq: ["$autoTranslateEnabled", true] }, 1, 0],
                },
              },
              avgLanguageSwitches: { $avg: "$totalLanguageSwitches" },
              languageDistribution: {
                $push: "$primaryLanguage",
              },
            },
          },
        ],
        options: { enablePagination: false },
      };

      const result = await this.executeAggregationPipeline(config);

      if (result.length > 0) {
        const stats = result[0];

        // Calcular distribución de idiomas
        const languageCount = {};
        stats.languageDistribution.forEach((lang) => {
          languageCount[lang] = (languageCount[lang] || 0) + 1;
        });

        return {
          ...stats,
          multiLanguageAdoptionRate:
            (stats.multiLanguageUsers / stats.totalUsers) * 100,
          languageSwitchAdoptionRate:
            (stats.usersWithLanguageSwitches / stats.totalUsers) * 100,
          profileTranslationRate:
            (stats.usersWithMultiLanguageProfile / stats.totalUsers) * 100,
          autoTranslateAdoptionRate:
            (stats.autoTranslateUsers / stats.totalUsers) * 100,
          languageDistribution: Object.entries(languageCount)
            .sort(([, a], [, b]) => b - a)
            .reduce((obj, [lang, count]) => ({ ...obj, [lang]: count }), {}),
        };
      }

      return null;
    } catch (error) {
      console.error("Error generando reporte multiidioma:", error);
      throw error;
    }
  }

  // =============================================================================
  // 🧹 UTILIDADES Y MANTENIMIENTO
  // =============================================================================

  /**
   * Limpiar tokens expirados
   */
  async cleanExpiredTokens() {
    try {
      return await this.model.cleanExpiredTokens();
    } catch (error) {
      console.error("Error limpiando tokens:", error);
      throw error;
    }
  }

  /**
   * Migrar usuarios a multiidioma
   */
  async migrateToMultiLanguage(batchSize = 100) {
    try {
      let migrated = 0;
      let skip = 0;

      while (true) {
        const users = await this.model
          .find({
            $and: [
              {
                $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
              },
              {
                $or: [
                  { "profile.firstName": { $type: "string" } },
                  { "profile.lastName": { $type: "string" } },
                ],
              },
            ],
          })
          .limit(batchSize)
          .skip(skip)
          .lean();

        if (users.length === 0) break;

        const bulkOps = users.map((user) => {
          const updates = {};
          const userLanguage = user.preferences?.language || DEFAULT_LANGUAGE;

          if (typeof user.profile?.firstName === "string") {
            updates["profile.firstName"] = {
              original: {
                language: userLanguage,
                text: user.profile.firstName,
                createdAt: new Date(),
                lastModified: new Date(),
              },
              translations: {},
              translationLanguages: [],
              translationConfig: {
                autoTranslate: true,
                targetLanguages: [],
              },
            };
          }

          if (typeof user.profile?.lastName === "string") {
            updates["profile.lastName"] = {
              original: {
                language: userLanguage,
                text: user.profile.lastName,
                createdAt: new Date(),
                lastModified: new Date(),
              },
              translations: {},
              translationLanguages: [],
              translationConfig: {
                autoTranslate: true,
                targetLanguages: [],
              },
            };
          }

          return {
            updateOne: {
              filter: { _id: user._id },
              update: { $set: updates },
            },
          };
        });

        if (bulkOps.length > 0) {
          await this.model.bulkWrite(bulkOps);
          migrated += bulkOps.length;
        }

        skip += batchSize;
        console.log(`Migrados ${migrated} usuarios a multiidioma...`);
      }

      return {
        message: "Migración completada",
        totalMigrated: migrated,
      };
    } catch (error) {
      console.error("Error en migración multiidioma:", error);
      throw error;
    }
  }

  /**
   * Validar integridad de datos multiidioma
   */
  async validateMultiLanguageIntegrity() {
    try {
      const issues = [];

      // Buscar usuarios con campos multiidioma malformados
      const malformedUsers = await this.model.find(
        {
          $or: [
            { "profile.firstName.original.text": { $exists: false } },
            { "profile.lastName.original.text": { $exists: false } },
            {
              "profile.firstName.original.language": {
                $nin: SUPPORTED_LANGUAGES,
              },
            },
            {
              "profile.lastName.original.language": {
                $nin: SUPPORTED_LANGUAGES,
              },
            },
          ],
          $and: [
            { $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }] },
            { isActive: true },
          ],
        },
        { _id: 1, email: 1, "profile.firstName": 1, "profile.lastName": 1 }
      );

      if (malformedUsers.length > 0) {
        issues.push({
          type: "malformed_multilang_fields",
          count: malformedUsers.length,
          users: malformedUsers.slice(0, 5), // Solo primeros 5 como muestra
        });
      }

      // Verificar idiomas no soportados
      const unsupportedLanguageUsers = await this.model.find(
        {
          "preferences.language": { $nin: SUPPORTED_LANGUAGES },
        },
        { _id: 1, email: 1, "preferences.language": 1 }
      );

      if (unsupportedLanguageUsers.length > 0) {
        issues.push({
          type: "unsupported_languages",
          count: unsupportedLanguageUsers.length,
          users: unsupportedLanguageUsers.slice(0, 5),
        });
      }

      return {
        isValid: issues.length === 0,
        issues: issues,
        summary: `Encontrados ${issues.length} tipos de problemas en integridad multiidioma`,
      };
    } catch (error) {
      console.error("Error validando integridad multiidioma:", error);
      throw error;
    }
  }
}

export default UserRepository;
