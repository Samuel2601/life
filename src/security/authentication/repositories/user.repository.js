// =============================================================================
// src/modules/authentication/repositories/user.repository.js
// =============================================================================
import { Types } from "mongoose";
import bcrypt from "bcrypt";
import crypto from "crypto";
import { User } from "../models/user.scheme.js";
import { TransactionHelper } from "../../../utils/transsaccion.helper.js";
import { BaseRepository } from "../../../modules/core/repositories/base.repository.js";

export class UserRepository extends BaseRepository {
  constructor() {
    super(User);
  }

  /**
   * Crear usuario con hash de contraseña
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

          // Crear datos del usuario
          const newUserData = {
            ...userDataWithoutPassword,
            email: userData.email.toLowerCase(),
            metadata: {
              registrationSource: userData.registrationSource || "web",
              lastActiveAt: new Date(),
              totalLogins: 0,
              averageSessionDuration: 0,
            },
            preferences: {
              language: userData.preferredLanguage || "es",
              timezone: userData.timezone || "America/Lima",
              notifications: {
                email: true,
                push: true,
                sms: false,
                marketing: false,
              },
              privacy: {
                profileVisible: true,
                allowDataCollection: true,
                allowLocationTracking: false,
              },
            },
          };

          // Crear usuario
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

          return user;
        } catch (error) {
          console.error("Error creando usuario:", error);
          throw error;
        }
      }
    );
  }

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
   * Actualizar intentos de login
   * @param {string} userId - ID del usuario
   * @param {boolean} success - Si el login fue exitoso
   */
  async updateLoginAttempts(userId, success) {
    try {
      if (success) {
        // Reset intentos y actualizar estadísticas
        return await this.model.findByIdAndUpdate(
          userId,
          {
            $unset: { loginAttempts: 1, lockUntil: 1 },
            $set: {
              lastLoginAt: new Date(),
              updatedAt: new Date(),
            },
            $inc: { "metadata.totalLogins": 1 },
          },
          { new: true }
        );
      } else {
        // Incrementar intentos fallidos
        const user = await this.model.findById(userId);
        if (!user) return null;

        const attempts = (user.loginAttempts || 0) + 1;
        const updates = {
          loginAttempts: attempts,
          updatedAt: new Date(),
        };

        // Bloquear cuenta si excede intentos máximos
        if (attempts >= 5) {
          updates.lockUntil = new Date(Date.now() + 2 * 60 * 60 * 1000); // 2 horas
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

      if (!user.isActive) {
        throw new Error("Cuenta desactivada");
      }

      if (user.isLocked) {
        throw new Error("Cuenta bloqueada temporalmente");
      }

      const isValidPassword = await bcrypt.compare(password, user.passwordHash);

      if (!isValidPassword) {
        // Incrementar intentos fallidos
        await this.incrementLoginAttempts(user._id);
        return null;
      }

      // Resetear intentos fallidos en login exitoso
      await this.resetLoginAttempts(user._id);

      // Remover passwordHash del objeto retornado
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

      const updatedUser = await this.update(
        userId,
        { passwordHash },
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
   * Incrementar intentos de login fallidos
   * @param {string} userId - ID del usuario
   */
  async incrementLoginAttempts(userId) {
    try {
      const user = await this.model.findById(userId);
      if (!user) return;

      // Si ya está bloqueado y el bloqueo ha expirado, resetear
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

      // Bloquear después de 5 intentos fallidos
      if (user.loginAttempts + 1 >= 5 && !user.lockUntil) {
        updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 horas
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

      // Verificar si ya está conectado
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
      const updateData = {
        [`oauthProviders.${provider}`]: undefined,
      };

      return await this.update(userId, updateData, sessionData, {
        $unset: { [`oauthProviders.${provider}`]: 1 },
      });
    } catch (error) {
      console.error("Error desconectando proveedor OAuth:", error);
      throw error;
    }
  }

  /**
   * Generar token de verificación de email
   * @param {string} userId - ID del usuario
   * @param {Object} options - Opciones adicionales
   */
  async generateEmailVerificationToken(userId, options = {}) {
    try {
      const token = crypto.randomBytes(32).toString("hex");
      const expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 horas

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
      const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hora

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

      // Establecer nueva contraseña
      await this.setPassword(user._id, newPassword, sessionData);

      // Limpiar token de reset
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

  /**
   * Actualizar preferencias de usuario
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

      // Merge profundo de preferencias
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
      };

      return await this.update(
        userId,
        { preferences: updatedPreferences },
        sessionData
      );
    } catch (error) {
      console.error("Error actualizando preferencias:", error);
      throw error;
    }
  }

  /**
   * Buscar usuarios con filtros avanzados
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

      // Filtro por búsqueda de texto
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

      // Filtros específicos
      if (language) query["preferences.language"] = language;
      if (isActive !== undefined) query.isActive = isActive;
      if (isEmailVerified !== undefined)
        query.isEmailVerified = isEmailVerified;
      if (registrationSource)
        query["metadata.registrationSource"] = registrationSource;

      // Filtro por OAuth
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

      // Filtro por rango de fechas
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
            avgTotalLogins: { $avg: "$metadata.totalLogins" },
            avgSessionDuration: { $avg: "$metadata.averageSessionDuration" },
          },
        },
      ]);

      // Estadísticas por idioma
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

      // Estadísticas por fuente de registro
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

      return {
        general: stats[0] || {
          totalUsers: 0,
          activeUsers: 0,
          verifiedUsers: 0,
          usersWithOAuth: 0,
          avgTotalLogins: 0,
          avgSessionDuration: 0,
        },
        byLanguage: languageStats,
        byRegistrationSource: sourceStats,
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
}
