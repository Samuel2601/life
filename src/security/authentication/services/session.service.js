// =============================================================================
// src/modules/authentication/services/session.service.js
// =============================================================================
import { UserSessionRepository } from "../repositories/user_session.repository.js";
import { UserRepository } from "../repositories/user.repository.js";
import {
  AuthError,
  AuthErrorCodes,
  AuthConstants,
} from "../authentication.index.js";

export class SessionService {
  constructor() {
    this.sessionRepository = new UserSessionRepository();
    this.userRepository = new UserRepository();
  }

  /**
   * Obtener sesiones activas de un usuario
   * @param {string} userId - ID del usuario
   * @param {Object} options - Opciones de filtrado
   */
  async getUserActiveSessions(userId, options = {}) {
    try {
      const {
        includeCompromised = false,
        limit = 10,
        currentSessionId = null,
      } = options;

      const sessions = await this.sessionRepository.getUserActiveSessions(
        userId,
        {
          includeCompromised,
          limit,
        }
      );

      // Marcar la sesión actual
      const sessionsWithCurrent = sessions.map((session) => ({
        ...session,
        isCurrent: currentSessionId && session.sessionId === currentSessionId,
        lastActivity: this.formatLastActivity(session.lastAccessedAt),
        deviceSummary: this.formatDeviceSummary(session.deviceInfo),
        locationSummary: this.formatLocationSummary(session.location),
      }));

      return {
        sessions: sessionsWithCurrent,
        totalActive: sessions.length,
      };
    } catch (error) {
      console.error("Error obteniendo sesiones activas:", error);
      throw new AuthError(
        "Error obteniendo sesiones del usuario",
        AuthErrorCodes.SESSION_RETRIEVAL_FAILED,
        500
      );
    }
  }

  /**
   * Terminar sesión específica
   * @param {string} userId - ID del usuario
   * @param {string} sessionId - ID de la sesión a terminar
   * @param {Object} requestInfo - Información del request
   */
  async terminateSession(userId, sessionId, requestInfo) {
    try {
      const { ipAddress, userAgent } = requestInfo;

      // Verificar que la sesión pertenece al usuario
      const session = await this.sessionRepository.model.findOne({
        _id: sessionId,
        userId,
        isActive: true,
      });

      if (!session) {
        throw new AuthError(
          "Sesión no encontrada o no autorizada",
          AuthErrorCodes.SESSION_NOT_FOUND,
          404
        );
      }

      await this.sessionRepository.invalidateSession(
        sessionId,
        "terminated_by_user"
      );

      console.log(
        `✅ Sesión terminada por usuario: ${sessionId} (Usuario: ${userId})`
      );

      return {
        success: true,
        terminatedSession: {
          sessionId,
          deviceInfo: session.deviceInfo,
          lastAccessedAt: session.lastAccessedAt,
        },
      };
    } catch (error) {
      console.error("Error terminando sesión:", error);
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        "Error terminando sesión",
        AuthErrorCodes.SESSION_TERMINATION_FAILED,
        500
      );
    }
  }

  /**
   * Terminar todas las otras sesiones del usuario
   * @param {string} userId - ID del usuario
   * @param {string} currentSessionId - ID de la sesión actual a preservar
   * @param {Object} requestInfo - Información del request
   */
  async terminateOtherSessions(userId, currentSessionId, requestInfo) {
    try {
      const { ipAddress, userAgent } = requestInfo;

      // Invalidar todas las sesiones excepto la actual
      const result = await this.sessionRepository.model.updateMany(
        {
          userId,
          _id: { $ne: currentSessionId },
          isActive: true,
        },
        {
          $set: {
            isActive: false,
            invalidationReason: "terminated_by_user_other_sessions",
            updatedAt: new Date(),
          },
        }
      );

      console.log(
        `✅ ${result.modifiedCount} sesiones terminadas para usuario ${userId}`
      );

      return {
        terminatedSessions: result.modifiedCount,
        currentSessionPreserved: true,
      };
    } catch (error) {
      console.error("Error terminando otras sesiones:", error);
      throw new AuthError(
        "Error terminando otras sesiones",
        AuthErrorCodes.SESSION_RETRIEVAL_FAILED,
        500
      );
    }
  }

  /**
   * Limpiar sesiones expiradas del sistema
   * @param {Object} options - Opciones de limpieza
   */
  async cleanupExpiredSessions(options = {}) {
    try {
      const { batchSize = 1000 } = options;
      const currentTime = new Date();

      // Marcar sesiones expiradas como inactivas
      const expiredSessions = await this.sessionRepository.model.updateMany(
        {
          $or: [
            { expiresAt: { $lt: currentTime } },
            {
              isActive: true,
              lastAccessedAt: {
                $lt: new Date(currentTime - 7 * 24 * 60 * 60 * 1000),
              },
            }, // 7 días sin actividad
          ],
          isActive: true,
        },
        {
          $set: {
            isActive: false,
            invalidationReason: "expired_auto_cleanup",
            updatedAt: currentTime,
          },
        },
        { limit: batchSize }
      );

      // Eliminar físicamente sesiones muy antiguas (opcional)
      const veryOldDate = new Date(currentTime - 90 * 24 * 60 * 60 * 1000); // 90 días
      const deletedSessions = await this.sessionRepository.model.deleteMany({
        updatedAt: { $lt: veryOldDate },
        isActive: false,
      });

      console.log(
        `🧹 Sesiones limpiadas: ${expiredSessions.modifiedCount} expiradas, ${deletedSessions.deletedCount} eliminadas`
      );

      return {
        expiredSessions: expiredSessions.modifiedCount,
        deletedSessions: deletedSessions.deletedCount,
        cleanupTime: currentTime,
      };
    } catch (error) {
      console.error("Error limpiando sesiones expiradas:", error);
      throw error;
    }
  }

  /**
   * Validar y actualizar fingerprint de dispositivo
   * @param {string} sessionId - ID de la sesión
   * @param {string} newFingerprint - Nuevo fingerprint del dispositivo
   * @param {Object} requestInfo - Información del request
   */
  async validateAndUpdateFingerprint(sessionId, newFingerprint, requestInfo) {
    try {
      const { ipAddress, userAgent } = requestInfo;

      const session = await this.sessionRepository.model.findById(sessionId);
      if (!session) {
        throw new AuthError(
          "Sesión no encontrada",
          AuthErrorCodes.SESSION_NOT_FOUND,
          404
        );
      }

      const isValid = await this.sessionRepository.validateDeviceFingerprint(
        session,
        newFingerprint
      );

      if (!isValid) {
        // Marcar como actividad sospechosa
        await this.sessionRepository.flagSuspiciousActivity(
          sessionId,
          "device_change",
          `Fingerprint cambió significativamente. Original: ${session.originalFingerprint}, Nuevo: ${newFingerprint}`,
          "high"
        );

        return {
          isValid: false,
          requiresRevalidation: true,
          suspiciousActivity: true,
          message: "Dispositivo no reconocido. Se requiere revalidación.",
        };
      }

      return {
        isValid: true,
        requiresRevalidation: false,
        suspiciousActivity: false,
        message: "Dispositivo validado exitosamente",
      };
    } catch (error) {
      console.error("Error validando fingerprint:", error);
      throw new AuthError(
        "Error validando dispositivo",
        AuthErrorCodes.DEVICE_VALIDATION_FAILED,
        500
      );
    }
  }

  /**
   * Marcar cambio de fingerprint como validado por el usuario
   * @param {string} sessionId - ID de la sesión
   * @param {string} fingerprintToValidate - Fingerprint a validar
   * @param {Object} requestInfo - Información del request
   */
  async validateFingerprintChange(
    sessionId,
    fingerprintToValidate,
    requestInfo
  ) {
    try {
      const { ipAddress, userAgent } = requestInfo;

      const session = await this.sessionRepository.model.findById(sessionId);
      if (!session) {
        throw new AuthError(
          "Sesión no encontrada",
          AuthErrorCodes.SESSION_NOT_FOUND,
          404
        );
      }

      // Buscar el cambio de fingerprint pendiente
      const fingerprintChange = session.fingerprintChanges.find(
        (change) =>
          change.newFingerprint === fingerprintToValidate &&
          !change.validatedByUser
      );

      if (!fingerprintChange) {
        throw new AuthError(
          "Cambio de fingerprint no encontrado",
          AuthErrorCodes.FINGERPRINT_CHANGE_NOT_FOUND,
          404
        );
      }

      // Marcar como validado
      await this.sessionRepository.model.updateOne(
        {
          _id: sessionId,
          "fingerprintChanges.newFingerprint": fingerprintToValidate,
        },
        {
          $set: {
            "fingerprintChanges.$.validatedByUser": true,
            "fingerprintChanges.$.suspiciousChange": false,
          },
        }
      );

      console.log(`✅ Cambio de fingerprint validado: ${sessionId}`);

      return {
        success: true,
        message: "Dispositivo validado exitosamente",
      };
    } catch (error) {
      console.error("Error validando cambio de fingerprint:", error);
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        "Error validando cambio de dispositivo",
        AuthErrorCodes.FINGERPRINT_VALIDATION_FAILED,
        500
      );
    }
  }

  /**
   * Obtener actividad sospechosa de sesiones
   * @param {string} userId - ID del usuario
   * @param {Object} options - Opciones de filtrado
   */
  async getSuspiciousActivity(userId, options = {}) {
    try {
      const {
        limit = 20,
        severity = null,
        resolved = null,
        dateFrom = null,
        dateTo = null,
      } = options;

      const pipeline = [
        {
          $match: {
            userId: new Types.ObjectId(userId),
            suspiciousActivity: { $exists: true, $not: { $size: 0 } },
          },
        },
        {
          $unwind: "$suspiciousActivity",
        },
        {
          $match: {
            ...(severity && { "suspiciousActivity.severity": severity }),
            ...(resolved !== null && {
              "suspiciousActivity.resolved": resolved,
            }),
            ...(dateFrom && {
              "suspiciousActivity.timestamp": { $gte: new Date(dateFrom) },
            }),
            ...(dateTo && {
              "suspiciousActivity.timestamp": { $lte: new Date(dateTo) },
            }),
          },
        },
        {
          $sort: { "suspiciousActivity.timestamp": -1 },
        },
        {
          $limit: limit,
        },
        {
          $project: {
            sessionId: "$_id",
            deviceInfo: 1,
            location: 1,
            ipAddress: 1,
            createdAt: 1,
            activity: "$suspiciousActivity",
          },
        },
      ];

      const suspiciousActivities =
        await this.sessionRepository.model.aggregate(pipeline);

      // Obtener resumen de estadísticas
      const statsPipeline = [
        {
          $match: {
            userId: new Types.ObjectId(userId),
            suspiciousActivity: { $exists: true, $not: { $size: 0 } },
          },
        },
        {
          $unwind: "$suspiciousActivity",
        },
        {
          $group: {
            _id: null,
            totalActivities: { $sum: 1 },
            bySeverity: {
              $push: "$suspiciousActivity.severity",
            },
            unresolvedCount: {
              $sum: {
                $cond: [{ $eq: ["$suspiciousActivity.resolved", false] }, 1, 0],
              },
            },
          },
        },
      ];

      const stats = await this.sessionRepository.model.aggregate(statsPipeline);
      const statistics = stats[0] || {
        totalActivities: 0,
        bySeverity: [],
        unresolvedCount: 0,
      };

      // Procesar estadísticas por severidad
      const severityStats = statistics.bySeverity.reduce((acc, severity) => {
        acc[severity] = (acc[severity] || 0) + 1;
        return acc;
      }, {});

      return {
        activities: suspiciousActivities,
        statistics: {
          total: statistics.totalActivities,
          unresolved: statistics.unresolvedCount,
          bySeverity: severityStats,
        },
      };
    } catch (error) {
      console.error("Error obteniendo actividad sospechosa:", error);
      throw new AuthError(
        "Error obteniendo actividad sospechosa",
        AuthErrorCodes.SUSPICIOUS_ACTIVITY_RETRIEVAL_FAILED,
        500
      );
    }
  }

  /**
   * Marcar actividad sospechosa como resuelta
   * @param {string} sessionId - ID de la sesión
   * @param {string} activityId - ID de la actividad (timestamp)
   * @param {Object} requestInfo - Información del request
   */
  async resolveSuspiciousActivity(sessionId, activityTimestamp, requestInfo) {
    try {
      const { ipAddress, userAgent } = requestInfo;

      const result = await this.sessionRepository.model.updateOne(
        {
          _id: sessionId,
          "suspiciousActivity.timestamp": new Date(activityTimestamp),
        },
        {
          $set: {
            "suspiciousActivity.$.resolved": true,
          },
        }
      );

      if (result.modifiedCount === 0) {
        throw new AuthError(
          "Actividad sospechosa no encontrada",
          AuthErrorCodes.SUSPICIOUS_ACTIVITY_NOT_FOUND,
          404
        );
      }

      console.log(
        `✅ Actividad sospechosa marcada como resuelta: ${sessionId}`
      );

      return {
        success: true,
        message: "Actividad marcada como resuelta",
      };
    } catch (error) {
      console.error("Error resolviendo actividad sospechosa:", error);
      if (error instanceof AuthError) {
        throw error;
      }
      throw new AuthError(
        "Error resolviendo actividad sospechosa",
        AuthErrorCodes.SUSPICIOUS_ACTIVITY_RESOLUTION_FAILED,
        500
      );
    }
  }

  /**
   * Configurar límites de sesión para usuario
   * @param {string} userId - ID del usuario
   * @param {Object} sessionLimits - Límites de sesión
   * @param {Object} requestInfo - Información del request
   */
  async configureSessionLimits(userId, sessionLimits, requestInfo) {
    try {
      const {
        maxConcurrentSessions = 5,
        maxInactivityMinutes = 480, // 8 horas
        allowRememberMe = true,
        requireReauthForSensitive = true,
      } = sessionLimits;

      const { ipAddress, userAgent } = requestInfo;

      // Actualizar configuración del usuario
      await this.userRepository.update(
        userId,
        {
          "sessionConfig.maxConcurrentSessions": maxConcurrentSessions,
          "sessionConfig.maxInactivityMinutes": maxInactivityMinutes,
          "sessionConfig.allowRememberMe": allowRememberMe,
          "sessionConfig.requireReauthForSensitive": requireReauthForSensitive,
        },
        {
          userId,
          ip: ipAddress,
          userAgent,
        }
      );

      // Aplicar nuevos límites a sesiones existentes
      await this.sessionRepository.model.updateMany(
        { userId, isActive: true },
        {
          $set: {
            maxInactivityMinutes,
          },
        }
      );

      // Si se redujo el límite de sesiones concurrentes, invalidar las más antiguas
      const activeSessions =
        await this.sessionRepository.getUserActiveSessions(userId);
      if (activeSessions.length > maxConcurrentSessions) {
        const sessionsToInvalidate = activeSessions
          .sort(
            (a, b) => new Date(a.lastAccessedAt) - new Date(b.lastAccessedAt)
          )
          .slice(0, activeSessions.length - maxConcurrentSessions);

        for (const session of sessionsToInvalidate) {
          await this.sessionRepository.invalidateSession(
            session.sessionId,
            "concurrent_limit_exceeded"
          );
        }

        console.log(
          `🔒 ${sessionsToInvalidate.length} sesiones invalidadas por límite concurrente`
        );
      }

      return {
        success: true,
        appliedLimits: sessionLimits,
        invalidatedSessions: Math.max(
          0,
          activeSessions.length - maxConcurrentSessions
        ),
      };
    } catch (error) {
      console.error("Error configurando límites de sesión:", error);
      throw new AuthError(
        "Error configurando límites de sesión",
        AuthErrorCodes.SESSION_CONFIG_FAILED,
        500
      );
    }
  }

  /**
   * Obtener estadísticas de sesiones
   * @param {Object} filters - Filtros opcionales
   */
  async getSessionStats(filters = {}) {
    try {
      const { userId, timeRange = 30 } = filters;
      const startDate = new Date(Date.now() - timeRange * 24 * 60 * 60 * 1000);

      const pipeline = [
        {
          $match: {
            createdAt: { $gte: startDate },
            ...(userId && { userId: new Types.ObjectId(userId) }),
          },
        },
        {
          $group: {
            _id: null,
            totalSessions: { $sum: 1 },
            activeSessions: {
              $sum: { $cond: [{ $eq: ["$isActive", true] }, 1, 0] },
            },
            expiredSessions: {
              $sum: { $cond: [{ $lt: ["$expiresAt", new Date()] }, 1, 0] },
            },
            compromisedSessions: {
              $sum: { $cond: [{ $eq: ["$isCompromised", true] }, 1, 0] },
            },
            averageSessionDuration: {
              $avg: {
                $subtract: [
                  { $ifNull: ["$lastAccessedAt", "$createdAt"] },
                  "$createdAt",
                ],
              },
            },
            deviceTypes: {
              $addToSet: "$deviceInfo.device",
            },
            browsers: {
              $addToSet: "$deviceInfo.browser",
            },
          },
        },
        {
          $project: {
            _id: 0,
            totalSessions: 1,
            activeSessions: 1,
            expiredSessions: 1,
            compromisedSessions: 1,
            inactiveSessions: {
              $subtract: ["$totalSessions", "$activeSessions"],
            },
            averageSessionDurationHours: {
              $divide: ["$averageSessionDuration", 1000 * 60 * 60],
            },
            deviceTypes: 1,
            browsers: 1,
          },
        },
      ];

      const stats = await this.sessionRepository.model.aggregate(pipeline);

      return (
        stats[0] || {
          totalSessions: 0,
          activeSessions: 0,
          expiredSessions: 0,
          compromisedSessions: 0,
          inactiveSessions: 0,
          averageSessionDurationHours: 0,
          deviceTypes: [],
          browsers: [],
        }
      );
    } catch (error) {
      console.error("Error obteniendo estadísticas de sesiones:", error);
      throw error;
    }
  }

  /**
   * Verificar actividad sospechosa en sesiones
   * @param {string} userId - ID del usuario
   * @param {Object} options - Opciones de análisis
   */
  async analyzeSuspiciousActivity(userId, options = {}) {
    try {
      const { timeWindow = 24 } = options; // horas
      const startTime = new Date(Date.now() - timeWindow * 60 * 60 * 1000);

      const sessions = await this.sessionRepository.model
        .find({
          userId,
          createdAt: { $gte: startTime },
        })
        .sort({ createdAt: -1 });

      const analysis = {
        suspiciousIndicators: [],
        riskLevel: "low",
        recommendations: [],
        sessionAnalysis: {
          totalSessions: sessions.length,
          activeSessions: sessions.filter((s) => s.isActive).length,
          compromisedSessions: sessions.filter((s) => s.isCompromised).length,
        },
      };

      // Análisis de múltiples ubicaciones
      const uniqueIPs = new Set(sessions.map((s) => s.ipAddress));
      if (uniqueIPs.size > 3) {
        analysis.suspiciousIndicators.push("multiple_locations");
        analysis.riskLevel = "medium";
        analysis.recommendations.push("Verificar ubicaciones de acceso");
      }

      // Análisis de múltiples dispositivos
      const uniqueFingerprints = new Set(
        sessions.map((s) => s.deviceFingerprint)
      );
      if (uniqueFingerprints.size > 2) {
        analysis.suspiciousIndicators.push("multiple_devices");
        analysis.riskLevel = "medium";
        analysis.recommendations.push("Verificar dispositivos utilizados");
      }

      // Análisis de frecuencia de sesiones
      if (sessions.length > 10) {
        analysis.suspiciousIndicators.push("high_frequency");
        analysis.riskLevel = "high";
        analysis.recommendations.push("Posible actividad automatizada");
      }

      // Análisis de cambios de fingerprint
      const fingerprintChanges = sessions.reduce((acc, session) => {
        return acc + (session.fingerprintChanges?.length || 0);
      }, 0);

      if (fingerprintChanges > 5) {
        analysis.suspiciousIndicators.push("frequent_fingerprint_changes");
        analysis.riskLevel = "high";
        analysis.recommendations.push("Dispositivo posiblemente comprometido");
      }

      return analysis;
    } catch (error) {
      console.error("Error analizando actividad sospechosa:", error);
      throw error;
    }
  }

  /**
   * Exportar historial de sesiones
   * @param {string} userId - ID del usuario
   * @param {Object} options - Opciones de exportación
   */
  async exportSessionHistory(userId, options = {}) {
    try {
      const {
        format = "json", // json, csv
        includeInactive = true,
        dateFrom = null,
        dateTo = null,
        limit = 1000,
      } = options;

      const filter = { userId: new Types.ObjectId(userId) };

      if (!includeInactive) {
        filter.isActive = true;
      }

      if (dateFrom || dateTo) {
        filter.createdAt = {};
        if (dateFrom) filter.createdAt.$gte = new Date(dateFrom);
        if (dateTo) filter.createdAt.$lte = new Date(dateTo);
      }

      const sessions = await this.sessionRepository.model
        .find(filter)
        .sort({ createdAt: -1 })
        .limit(limit)
        .lean();

      // Sanitizar datos sensibles
      const sanitizedSessions = sessions.map((session) => ({
        sessionId: session._id,
        createdAt: session.createdAt,
        lastAccessedAt: session.lastAccessedAt,
        expiresAt: session.expiresAt,
        isActive: session.isActive,
        deviceInfo: session.deviceInfo,
        location: session.location,
        ipAddress: session.ipAddress,
        invalidationReason: session.invalidationReason,
        suspiciousActivityCount: session.suspiciousActivity?.length || 0,
        fingerprintChanges: session.fingerprintChanges?.length || 0,
      }));

      return {
        format,
        exportDate: new Date(),
        totalSessions: sanitizedSessions.length,
        period: { from: dateFrom, to: dateTo },
        sessions: sanitizedSessions,
      };
    } catch (error) {
      console.error("Error exportando historial de sesiones:", error);
      throw new AuthError(
        "Error exportando historial de sesiones",
        AuthErrorCodes.SESSION_EXPORT_FAILED,
        500
      );
    }
  }

  // =============================================================================
  // MÉTODOS AUXILIARES
  // =============================================================================

  /**
   * Formatear última actividad de forma legible
   * @param {Date} lastAccessedAt - Fecha de último acceso
   */
  formatLastActivity(lastAccessedAt) {
    if (!lastAccessedAt) return "Nunca";

    const now = new Date();
    const diffMs = now - lastAccessedAt;
    const diffMinutes = Math.floor(diffMs / (1000 * 60));
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffMinutes < 1) return "Ahora mismo";
    if (diffMinutes < 60) return `Hace ${diffMinutes} minutos`;
    if (diffHours < 24) return `Hace ${diffHours} horas`;
    if (diffDays < 7) return `Hace ${diffDays} días`;

    return lastAccessedAt.toLocaleDateString();
  }

  /**
   * Formatear información del dispositivo
   * @param {Object} deviceInfo - Información del dispositivo
   */
  formatDeviceSummary(deviceInfo) {
    if (!deviceInfo) return "Dispositivo desconocido";

    const { browser, os, device } = deviceInfo;
    return `${browser || "Navegador"} en ${os || "SO"} (${device || "dispositivo"})`;
  }

  /**
   * Formatear información de ubicación
   * @param {Object} location - Información de ubicación
   */
  formatLocationSummary(location) {
    if (!location) return "Ubicación desconocida";

    const { city, country } = location;
    if (city && country) return `${city}, ${country}`;
    if (country) return country;

    return "Ubicación desconocida";
  }

  /**
   * Validar configuración de sesión
   * @param {Object} config - Configuración de sesión
   */
  validateSessionConfig(config) {
    const errors = [];

    if (
      config.maxConcurrentSessions &&
      (config.maxConcurrentSessions < 1 || config.maxConcurrentSessions > 20)
    ) {
      errors.push("El máximo de sesiones concurrentes debe estar entre 1 y 20");
    }

    if (
      config.maxInactivityMinutes &&
      (config.maxInactivityMinutes < 5 || config.maxInactivityMinutes > 43200)
    ) {
      errors.push(
        "El tiempo de inactividad debe estar entre 5 minutos y 30 días"
      );
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }
}
