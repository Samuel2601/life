// =============================================================================
// src/modules/authentication/repositories/user_session.repository.js
// =============================================================================
import { Types } from "mongoose";
import crypto from "crypto";
import { UserSession } from "../models/user_session.scheme.js";
import { TransactionHelper } from "../../../utils/transsaccion.helper.js";
import { BaseRepository } from "../../../modules/core/repositories/base.repository.js";

export class UserSessionRepository extends BaseRepository {
  constructor() {
    super(UserSession);
  }

  /**
   * Crear nueva sesión de usuario
   * @param {Object} sessionData - Datos de la sesión
   * @param {Object} userData - Datos del usuario que autentica
   * @param {Object} options - Opciones adicionales
   */
  async createSession(sessionData, userData, options = {}) {
    return await TransactionHelper.executeWithOptionalTransaction(
      async (session) => {
        try {
          const {
            userId,
            accessToken,
            refreshToken,
            deviceFingerprint,
            ipAddress,
            userAgent,
            rememberMe = false,
            oauthProvider,
            oauthSessionData,
          } = sessionData;

          // Generar token de sesión único
          const sessionToken = this.generateSecureToken();

          // Detectar información del dispositivo
          const deviceInfo = this.parseUserAgent(userAgent);

          // Obtener información geográfica (opcional)
          const location = await this.getLocationFromIP(ipAddress);

          // Configurar tiempo de expiración
          const expirationTime = rememberMe
            ? 30 * 24 * 60 * 60 * 1000 // 30 días
            : 8 * 60 * 60 * 1000; // 8 horas

          const expiresAt = new Date(Date.now() + expirationTime);

          // Invalidar sesiones anteriores si se especifica
          if (options.singleSession) {
            await this.invalidateUserSessions(userId, { session });
          }

          // Crear datos de la sesión
          const newSessionData = {
            userId: new Types.ObjectId(userId),
            accessToken, // Se almacena en servidor, NO se envía al cliente
            refreshToken,
            sessionToken, // Este es el que va en la cookie
            deviceFingerprint,
            originalFingerprint: deviceFingerprint,
            fingerprintChanges: [],
            isActive: true,
            expiresAt,
            lastAccessedAt: new Date(),
            ipAddress,
            userAgent,
            deviceInfo,
            location,
            oauthProvider,
            oauthSessionData,
            rememberMe,
            maxInactivityMinutes: rememberMe ? 30 * 24 * 60 : 480, // 30 días o 8 horas
            isCompromised: false,
            suspiciousActivity: [],
          };

          const createdSession = await this.create(newSessionData, userData, {
            session,
          });

          // Solo devolver datos seguros (sin tokens sensibles)
          return this.sanitizeSessionData(createdSession);
        } catch (error) {
          console.error("Error creando sesión:", error);
          throw error;
        }
      }
    );
  }

  /**
   * Buscar sesión por token
   * @param {string} sessionToken - Token de sesión
   * @param {Object} options - Opciones de búsqueda
   */
  async findBySessionToken(sessionToken, options = {}) {
    try {
      const { includeExpired = false } = options;

      let query = {
        sessionToken,
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      };

      if (!includeExpired) {
        query.expiresAt = { $gt: new Date() };
      }

      return await this.model.findOne(query).lean();
    } catch (error) {
      console.error("Error buscando sesión por token:", error);
      throw error;
    }
  }

  /**
   * Invalidar sesión por token
   * @param {string} sessionToken - Token de sesión
   * @param {string} reason - Razón de invalidación
   */
  async invalidateSessionByToken(sessionToken, reason = "logout") {
    try {
      if (!sessionToken) {
        throw new AuthError(
          "Token de sesión requerido",
          AuthErrorCodes.SESSION_INVALID,
          400
        );
      }

      // Buscar y invalidar sesión
      const session = await this.sessionRepository.model.findOneAndUpdate(
        {
          sessionToken,
          isActive: true,
        },
        {
          $set: {
            isActive: false,
            invalidationReason: reason,
            updatedAt: new Date(),
          },
        },
        { new: true }
      );

      if (!session) {
        throw new AuthError(
          "Sesión no encontrada o ya invalidada",
          AuthErrorCodes.SESSION_NOT_FOUND,
          404
        );
      }

      console.log(`✅ Sesión invalidada: ${session._id} (${reason})`);
      return { success: true, sessionId: session._id };
    } catch (error) {
      console.error("Error invalidando sesión por token:", error);
      throw error;
    }
  }

  /**
   * Validar sesión por token
   * @param {string} sessionToken - Token de sesión
   * @param {string} deviceFingerprint - Huella del dispositivo
   * @param {string} ipAddress - Dirección IP actual
   */
  async validateSession(sessionToken, deviceFingerprint, ipAddress) {
    try {
      const session = await this.model
        .findOne({
          sessionToken,
          isActive: true,
          expiresAt: { $gt: new Date() },
          isCompromised: false,
        })
        .populate("userId", "isActive isEmailVerified roles");

      if (!session) {
        return null;
      }

      // Verificar que el usuario esté activo
      if (!session.userId || !session.userId.isActive) {
        await this.invalidateSession(session._id, "user_inactive");
        return null;
      }

      // Verificar fingerprint del dispositivo
      const fingerprintValid = await this.validateDeviceFingerprint(
        session,
        deviceFingerprint
      );

      if (!fingerprintValid) {
        await this.flagSuspiciousActivity(
          session._id,
          "device_change",
          "Device fingerprint cambió",
          "high"
        );
        return null;
      }

      // Verificar cambio significativo de IP
      if (this.isSignificantIPChange(session.ipAddress, ipAddress)) {
        await this.flagSuspiciousActivity(
          session._id,
          "location_change",
          `IP cambió de ${session.ipAddress} a ${ipAddress}`,
          "medium"
        );
      }

      // Verificar inactividad
      const inactivityMinutes =
        (Date.now() - session.lastAccessedAt.getTime()) / (1000 * 60);
      if (inactivityMinutes > session.maxInactivityMinutes) {
        await this.invalidateSession(session._id, "inactivity_timeout");
        return null;
      }

      // Actualizar última actividad
      await this.updateLastActivity(session._id, ipAddress);

      return this.sanitizeSessionData(session);
    } catch (error) {
      console.error("Error validando sesión:", error);
      throw error;
    }
  }

  /**
   * Actualizar tokens de sesión (rotación)
   * @param {string} sessionId - ID de la sesión
   * @param {string} newAccessToken - Nuevo access token
   * @param {string} newRefreshToken - Nuevo refresh token
   * @param {Object} userData - Datos del usuario
   */
  async rotateTokens(sessionId, newAccessToken, newRefreshToken, userData) {
    try {
      const updateData = {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        lastAccessedAt: new Date(),
      };

      return await this.update(sessionId, updateData, userData);
    } catch (error) {
      console.error("Error rotando tokens:", error);
      throw error;
    }
  }

  /**
   * Invalidar sesión específica
   * @param {string} sessionId - ID de la sesión
   * @param {string} reason - Razón de invalidación
   */
  async invalidateSession(sessionId, reason = "manual") {
    try {
      return await this.model.findByIdAndUpdate(
        sessionId,
        {
          $set: {
            isActive: false,
            invalidationReason: reason,
            updatedAt: new Date(),
          },
        },
        { new: true }
      );
    } catch (error) {
      console.error("Error invalidando sesión:", error);
      throw error;
    }
  }

  /**
   * Invalidar todas las sesiones de un usuario
   * @param {string} userId - ID del usuario
   * @param {string} reason - Razón de invalidación
   * @param {Object} options - Opciones adicionales
   */
  async invalidateUserSessions(userId, reason = "manual", options = {}) {
    try {
      const { session, excludeSessionId } = options;

      let query = {
        userId: new Types.ObjectId(userId),
        isActive: true,
      };

      if (excludeSessionId) {
        query._id = { $ne: new Types.ObjectId(excludeSessionId) };
      }

      const updateOptions = { session };

      return await this.model.updateMany(
        query,
        {
          $set: {
            isActive: false,
            invalidationReason: reason,
            updatedAt: new Date(),
          },
        },
        updateOptions
      );
    } catch (error) {
      console.error("Error invalidando sesiones de usuario:", error);
      throw error;
    }
  }

  /**
   * Marcar actividad sospechosa
   * @param {string} sessionId - ID de la sesión
   * @param {string} activityType - Tipo de actividad
   * @param {Object} details - Detalles de la actividad
   */
  async flagSuspiciousActivity(
    sessionId,
    activityType,
    details = {},
    severity = "medium"
  ) {
    try {
      const suspiciousActivity = {
        activityType,
        description:
          details.description || `Actividad sospechosa: ${activityType}`,
        timestamp: new Date(),
        severity: details.severity || severity,
        resolved: false,
        details,
      };

      return await this.model.findByIdAndUpdate(
        sessionId,
        {
          $push: { suspiciousActivity },
          $set: {
            isCompromised: details.autoBlock || false,
            updatedAt: new Date(),
          },
        },
        { new: true }
      );
    } catch (error) {
      console.error("Error marcando actividad sospechosa:", error);
      throw error;
    }
  }

  /**
   * Validar fingerprint del dispositivo
   * @param {Object} session - Sesión actual
   * @param {string} currentFingerprint - Fingerprint actual
   */
  async validateDeviceFingerprint(session, currentFingerprint) {
    try {
      // Si el fingerprint es exactamente el mismo, es válido
      if (session.deviceFingerprint === currentFingerprint) {
        return true;
      }

      // Verificar si es un cambio menor aceptable
      const similarity = this.calculateFingerprintSimilarity(
        session.deviceFingerprint,
        currentFingerprint
      );

      // Si la similitud es alta (>85%), considerar válido pero registrar cambio
      if (similarity > 0.85) {
        await this.recordFingerprintChange(
          session._id,
          currentFingerprint,
          false
        );
        return true;
      }

      // Si la similitud es baja, es sospechoso
      await this.recordFingerprintChange(session._id, currentFingerprint, true);
      return false;
    } catch (error) {
      console.error("Error validando fingerprint:", error);
      return false;
    }
  }

  /**
   * Registrar cambio de fingerprint
   * @param {string} sessionId - ID de la sesión
   * @param {string} newFingerprint - Nuevo fingerprint
   * @param {boolean} suspicious - Si es sospechoso
   */
  async recordFingerprintChange(sessionId, newFingerprint, suspicious = false) {
    try {
      const fingerprintChange = {
        newFingerprint,
        changedAt: new Date(),
        suspiciousChange: suspicious,
        validatedByUser: false,
      };

      const updateData = {
        $push: { fingerprintChanges: fingerprintChange },
        deviceFingerprint: newFingerprint, // Actualizar fingerprint actual
      };

      await this.model.updateOne({ _id: sessionId }, updateData);
    } catch (error) {
      console.error("Error registrando cambio de fingerprint:", error);
      throw error;
    }
  }

  /**
   * Actualizar última actividad de sesión
   * @param {string} sessionId - ID de la sesión
   * @param {Object} activityData - Datos de actividad
   */
  async updateLastActivity(sessionId, activityData = {}) {
    try {
      const { ipAddress, userAgent } = activityData;

      const updateData = {
        lastAccessedAt: new Date(),
        updatedAt: new Date(),
      };

      // Actualizar IP si cambió (para tracking)
      if (ipAddress && ipAddress !== "unknown") {
        updateData.ipAddress = ipAddress;
      }

      return await this.model.findByIdAndUpdate(
        sessionId,
        { $set: updateData },
        { new: true }
      );
    } catch (error) {
      console.error("Error actualizando actividad de sesión:", error);
      throw error;
    }
  }

  /**
   * Obtener sesiones activas de un usuario
   * @param {string} userId - ID del usuario
   * @param {Object} options - Opciones de filtrado
   */
  async getUserActiveSessions(userId, options = {}) {
    try {
      const { includeCompromised = false, limit = 10 } = options;

      let query = {
        userId: new Types.ObjectId(userId),
        isActive: true,
        expiresAt: { $gt: new Date() },
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      };

      if (!includeCompromised) {
        query.isCompromised = { $ne: true };
      }

      return await this.model
        .find(query)
        .sort({ lastAccessedAt: -1 })
        .limit(limit)
        .lean();
    } catch (error) {
      console.error("Error obteniendo sesiones activas:", error);
      throw error;
    }
  }

  /**
   * Limpiar sesiones expiradas
   */
  async cleanExpiredSessions() {
    try {
      const result = await this.model.deleteMany({
        $or: [
          { expiresAt: { $lt: new Date() } },
          {
            isActive: false,
            updatedAt: { $lt: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
          }, // 7 días
        ],
      });

      console.log(`🧹 Sesiones expiradas limpiadas: ${result.deletedCount}`);
      return result.deletedCount;
    } catch (error) {
      console.error("Error limpiando sesiones expiradas:", error);
      throw error;
    }
  }

  /**
   * Obtener estadísticas de sesiones
   * @param {string} userId - ID del usuario (opcional)
   */
  async getSessionStats(userId = null) {
    try {
      const matchFilter = userId ? { userId: new Types.ObjectId(userId) } : {};

      const stats = await this.model.aggregate([
        { $match: matchFilter },
        {
          $group: {
            _id: null,
            totalSessions: { $sum: 1 },
            activeSessions: {
              $sum: { $cond: [{ $eq: ["$isActive", true] }, 1, 0] },
            },
            compromisedSessions: {
              $sum: { $cond: [{ $eq: ["$isCompromised", true] }, 1, 0] },
            },
            avgSessionDuration: {
              $avg: {
                $subtract: ["$lastAccessedAt", "$createdAt"],
              },
            },
            suspiciousActivities: {
              $sum: { $size: "$suspiciousActivity" },
            },
          },
        },
      ]);

      // Estadísticas por dispositivo
      const deviceStats = await this.model.aggregate([
        { $match: { ...matchFilter, isActive: true } },
        {
          $group: {
            _id: "$deviceInfo.device",
            count: { $sum: 1 },
            browsers: { $addToSet: "$deviceInfo.browser" },
            os: { $addToSet: "$deviceInfo.os" },
          },
        },
        { $sort: { count: -1 } },
      ]);

      // Estadísticas por ubicación
      const locationStats = await this.model.aggregate([
        { $match: { ...matchFilter, "location.country": { $exists: true } } },
        {
          $group: {
            _id: "$location.country",
            count: { $sum: 1 },
            cities: { $addToSet: "$location.city" },
          },
        },
        { $sort: { count: -1 } },
      ]);

      return {
        general: stats[0] || {
          totalSessions: 0,
          activeSessions: 0,
          compromisedSessions: 0,
          avgSessionDuration: 0,
          suspiciousActivities: 0,
        },
        byDevice: deviceStats,
        byLocation: locationStats,
      };
    } catch (error) {
      console.error("Error obteniendo estadísticas de sesiones:", error);
      throw error;
    }
  }

  // =============================================================================
  // MÉTODOS AUXILIARES
  // =============================================================================

  /**
   * Generar token seguro
   */
  generateSecureToken() {
    return crypto.randomBytes(32).toString("hex");
  }

  /**
   * Parsear User-Agent para extraer información del dispositivo
   * @param {string} userAgent - User-Agent string
   */
  parseUserAgent(userAgent) {
    if (!userAgent) {
      return {
        browser: "Unknown",
        os: "Unknown",
        device: "Unknown",
        isMobile: false,
        isTablet: false,
      };
    }

    const isMobile = /mobile|android|iphone/i.test(userAgent);
    const isTablet = /tablet|ipad/i.test(userAgent);

    let browser = "Unknown";
    let os = "Unknown";

    // Detectar navegador
    if (userAgent.includes("Chrome")) browser = "Chrome";
    else if (userAgent.includes("Firefox")) browser = "Firefox";
    else if (userAgent.includes("Safari")) browser = "Safari";
    else if (userAgent.includes("Edge")) browser = "Edge";
    else if (userAgent.includes("Opera")) browser = "Opera";

    // Detectar OS
    if (userAgent.includes("Windows")) os = "Windows";
    else if (userAgent.includes("Mac")) os = "macOS";
    else if (userAgent.includes("Linux")) os = "Linux";
    else if (userAgent.includes("Android")) os = "Android";
    else if (userAgent.includes("iOS")) os = "iOS";

    return {
      browser,
      os,
      device: isTablet ? "tablet" : isMobile ? "mobile" : "desktop",
      isMobile,
      isTablet,
      userAgent,
    };
  }

  /**
   * Obtener ubicación aproximada desde IP
   * @param {string} ipAddress - Dirección IP
   */
  async getLocationFromIP(ipAddress) {
    try {
      // Implementación básica - en producción usar servicio como MaxMind
      if (
        !ipAddress ||
        ipAddress === "unknown" ||
        ipAddress.startsWith("127.") ||
        ipAddress.startsWith("192.168.")
      ) {
        return {
          country: "Unknown",
          city: "Unknown",
          coordinates: null,
          isVpnDetected: false,
        };
      }

      // TODO: Integrar con servicio de geolocalización real
      return {
        country: "Unknown",
        city: "Unknown",
        coordinates: null,
        isVpnDetected: false,
      };
    } catch (error) {
      console.error("Error obteniendo ubicación:", error);
      return {
        country: "Unknown",
        city: "Unknown",
        coordinates: null,
        isVpnDetected: false,
      };
    }
  }

  /**
   * Verificar si hay cambio significativo de IP
   * @param {string} oldIP - IP anterior
   * @param {string} newIP - IP nueva
   */
  isSignificantIPChange(oldIP, newIP) {
    if (!oldIP || !newIP) return false;

    // Si son IPs completamente diferentes
    if (oldIP !== newIP) {
      // Verificar si están en la misma subred (opcional)
      const oldParts = oldIP.split(".").slice(0, 3).join(".");
      const newParts = newIP.split(".").slice(0, 3).join(".");

      // Si están en diferentes subredes /24, es significativo
      return oldParts !== newParts;
    }

    return false;
  }

  /**
   * Calcular similitud entre fingerprints
   * @param {string} fp1 - Fingerprint 1
   * @param {string} fp2 - Fingerprint 2
   */
  calculateFingerprintSimilarity(fp1, fp2) {
    if (!fp1 || !fp2) return 0;

    // Implementación básica usando distancia de Levenshtein normalizada
    const maxLen = Math.max(fp1.length, fp2.length);
    const distance = this.levenshteinDistance(fp1, fp2);

    return 1 - distance / maxLen;
  }

  /**
   * Calcular distancia de Levenshtein
   * @param {string} str1 - String 1
   * @param {string} str2 - String 2
   */
  levenshteinDistance(str1, str2) {
    const matrix = [];

    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  /**
   * Sanitizar datos de sesión para respuesta
   * @param {Object} session - Datos de sesión
   */
  sanitizeSessionData(session) {
    const sanitized = { ...session };

    // Remover datos sensibles
    delete sanitized.accessToken;
    delete sanitized.refreshToken;
    delete sanitized.oauthSessionData;

    return sanitized;
  }
}
