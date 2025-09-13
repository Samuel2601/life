// =============================================================================
// src/security/authentication/repositories/user_session.repository.js
// Repositorio especializado para gestión de sesiones de usuario
// =============================================================================
import { Types } from "mongoose";
import { BaseRepository } from "../../../modules/core/repositories/base.repository.js";
import {
  UserSession,
  SessionUtils,
  SESSION_CONSTANTS,
  ACTIVITY_TYPES,
  SEVERITY_LEVELS,
  INVALIDATION_REASONS,
} from "../models/user_session.scheme.js";

export class UserSessionRepository extends BaseRepository {
  constructor() {
    super(UserSession);
    this.initializeSessionConfig();
  }

  /**
   * Inicializar configuración específica de sesiones
   */
  initializeSessionConfig() {
    // Configurar lookups específicos para sesiones
    this.sessionLookups = {
      user: {
        from: "users",
        localField: "userId",
        foreignField: "_id",
        as: "user",
        pipeline: [
          {
            $project: {
              username: 1,
              email: 1,
              profile: 1,
              roles: 1,
              isActive: 1,
              lastLoginAt: 1,
            },
          },
        ],
      },
      resolvedBy: {
        from: "users",
        localField: "suspiciousActivity.resolvedBy",
        foreignField: "_id",
        as: "suspiciousActivity.resolvedByUser",
      },
    };
  }

  // =============================================================================
  // 🔐 GESTIÓN DE SESIONES ACTIVAS
  // =============================================================================

  /**
   * Obtener sesiones activas para un usuario específico
   */
  async getActiveSessions(userId, options = {}) {
    try {
      if (!Types.ObjectId.isValid(userId)) {
        throw new Error("ID de usuario no válido");
      }

      const { includeMetrics = false, populate = false } = options;

      const pipeline = [
        {
          $match: {
            userId: new Types.ObjectId(userId),
            isActive: true,
            isValid: true,
            expiresAt: { $gt: new Date() },
            $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
          },
        },
      ];

      // Agregar lookup de usuario si se solicita
      if (populate) {
        pipeline.push({
          $lookup: this.sessionLookups.user,
        });

        pipeline.push({
          $unwind: {
            path: "$user",
            preserveNullAndEmptyArrays: true,
          },
        });
      }

      // Agregar métricas si se solicitan
      if (includeMetrics) {
        pipeline.push({
          $addFields: {
            sessionAge: {
              $divide: [
                { $subtract: [new Date(), "$createdAt"] },
                1000 * 60, // minutos
              ],
            },
            inactiveTime: {
              $divide: [
                { $subtract: [new Date(), "$lastAccessedAt"] },
                1000 * 60, // minutos
              ],
            },
            securityRiskLevel: {
              $cond: {
                if: { $gt: [{ $size: "$suspiciousActivity" }, 0] },
                then: "high",
                else: "low",
              },
            },
          },
        });
      }

      pipeline.push({ $sort: { lastAccessedAt: -1 } });

      const sessions = await this.model.aggregate(pipeline);

      console.log(
        `✅ Encontradas ${sessions.length} sesiones activas para usuario ${userId}`
      );

      return sessions;
    } catch (error) {
      console.error("❌ Error obteniendo sesiones activas:", error);
      throw new Error(`Error obteniendo sesiones activas: ${error.message}`);
    }
  }

  /**
   * Crear nueva sesión con validaciones de seguridad
   */
  async createSession(sessionData, userData, options = {}) {
    try {
      const { validateConcurrentSessions = true, maxSessions = 3 } = options;

      // Validar sesiones concurrentes si está habilitado
      if (validateConcurrentSessions) {
        const activeSessions = await this.getActiveSessions(sessionData.userId);

        if (activeSessions.length >= maxSessions) {
          // Invalidar la sesión más antigua
          const oldestSession = activeSessions[activeSessions.length - 1];
          await this.invalidateSession(
            oldestSession._id,
            userData,
            "maxSessionsExceeded"
          );

          console.log(
            `⚠️ Sesión antigua invalidada por límite de sesiones concurrentes`
          );
        }
      }

      // Preparar datos de sesión con hashing de tokens
      const sessionToCreate = {
        ...sessionData,
        sessionToken: SessionUtils.generateSecureToken(),
        accessTokenHash: SessionUtils.hashToken(
          sessionData.accessToken || SessionUtils.generateSecureToken()
        ),
        refreshTokenHash: SessionUtils.hashToken(
          sessionData.refreshToken || SessionUtils.generateSecureToken()
        ),
        deviceFingerprint: sessionData.deviceFingerprint,
        originalFingerprint: sessionData.deviceFingerprint,
      };

      // Crear la sesión usando el método base
      const newSession = await this.create(sessionToCreate, userData, options);

      console.log(`✅ Nueva sesión creada para usuario ${sessionData.userId}`);

      return {
        ...newSession.toObject(),
        // Retornar tokens originales (no hasheados) solo en creación
        accessToken: sessionData.accessToken,
        refreshToken: sessionData.refreshToken,
      };
    } catch (error) {
      console.error("❌ Error creando sesión:", error);
      throw new Error(`Error creando sesión: ${error.message}`);
    }
  }

  /**
   * Invalidar sesión específica
   */
  async invalidateSession(sessionId, userData, reason = "userLogout") {
    try {
      if (!Types.ObjectId.isValid(sessionId)) {
        throw new Error("ID de sesión no válido");
      }

      if (!INVALIDATION_REASONS.includes(reason)) {
        throw new Error("Razón de invalidación no válida");
      }

      const updateData = {
        isActive: false,
        isValid: false,
        invalidationReason: reason,
        updatedAt: new Date(),
      };

      const invalidatedSession = await this.update(
        sessionId,
        updateData,
        userData
      );

      console.log(`✅ Sesión ${sessionId} invalidada por: ${reason}`);

      return invalidatedSession;
    } catch (error) {
      console.error("❌ Error invalidando sesión:", error);
      throw new Error(`Error invalidando sesión: ${error.message}`);
    }
  }

  /**
   * Invalidar todas las sesiones de un usuario excepto la actual
   */
  async invalidateAllUserSessionsExcept(
    userId,
    currentSessionId,
    userData,
    reason = "adminAction"
  ) {
    try {
      if (!Types.ObjectId.isValid(userId)) {
        throw new Error("ID de usuario no válido");
      }

      const filter = {
        userId: new Types.ObjectId(userId),
        _id: { $ne: new Types.ObjectId(currentSessionId) },
        isActive: true,
      };

      const updateData = {
        isActive: false,
        isValid: false,
        invalidationReason: reason,
      };

      const result = await this.updateMany(filter, updateData, userData);

      console.log(
        `✅ ${result.modifiedCount} sesiones invalidadas para usuario ${userId}`
      );

      return result;
    } catch (error) {
      console.error("❌ Error invalidando sesiones del usuario:", error);
      throw new Error(`Error invalidando sesiones: ${error.message}`);
    }
  }

  /**
   * Extender duración de sesión
   */
  async extendSession(sessionId, additionalHours = 2, userData) {
    try {
      const session = await this.findById(sessionId, { returnInstance: true });

      if (!session || !session.isActive || session.isExpired()) {
        throw new Error("Sesión no válida o expirada");
      }

      const newExpiration = new Date(
        session.expiresAt.getTime() + additionalHours * 60 * 60 * 1000
      );

      const updateData = {
        expiresAt: newExpiration,
        lastAccessedAt: new Date(),
      };

      const extendedSession = await this.update(
        sessionId,
        updateData,
        userData
      );

      console.log(
        `✅ Sesión ${sessionId} extendida por ${additionalHours} horas`
      );

      return extendedSession;
    } catch (error) {
      console.error("❌ Error extendiendo sesión:", error);
      throw new Error(`Error extendiendo sesión: ${error.message}`);
    }
  }

  // =============================================================================
  // 🛡️ SEGURIDAD Y DETECCIÓN DE ACTIVIDADES SOSPECHOSAS
  // =============================================================================

  /**
   * Registrar actividad sospechosa en sesión
   */
  async logSuspiciousActivity(sessionId, activityData, userData) {
    try {
      const {
        type,
        description,
        severity = "medium",
        additionalData = null,
      } = activityData;

      if (!ACTIVITY_TYPES.includes(type)) {
        throw new Error("Tipo de actividad no válido");
      }

      if (!SEVERITY_LEVELS.includes(severity)) {
        throw new Error("Nivel de severidad no válido");
      }

      const session = await this.findById(sessionId, { returnInstance: true });

      if (!session) {
        throw new Error("Sesión no encontrada");
      }

      // Usar el método del modelo para registrar actividad
      await session.logSuspiciousActivity(
        type,
        description,
        severity,
        additionalData
      );

      console.log(
        `🚨 Actividad sospechosa registrada en sesión ${sessionId}: ${type} (${severity})`
      );

      // Si es crítica, también invalidar la sesión
      if (severity === "critical") {
        await this.invalidateSession(sessionId, userData, "suspiciousActivity");
      }

      return session;
    } catch (error) {
      console.error("❌ Error registrando actividad sospechosa:", error);
      throw new Error(
        `Error registrando actividad sospechosa: ${error.message}`
      );
    }
  }

  /**
   * Registrar cambio de device fingerprint
   */
  async logFingerprintChange(sessionId, fingerprintData, userData) {
    try {
      const { newFingerprint, changedComponents = [] } = fingerprintData;

      if (!SessionUtils.validateFingerprint(newFingerprint)) {
        throw new Error("Fingerprint no válido");
      }

      const session = await this.findById(sessionId, { returnInstance: true });

      if (!session) {
        throw new Error("Sesión no encontrada");
      }

      // Usar el método del modelo para registrar cambio
      await session.logFingerprintChange(newFingerprint, changedComponents);

      console.log(`🔍 Cambio de fingerprint registrado en sesión ${sessionId}`);

      return session;
    } catch (error) {
      console.error("❌ Error registrando cambio de fingerprint:", error);
      throw new Error(
        `Error registrando cambio de fingerprint: ${error.message}`
      );
    }
  }

  /**
   * Detectar sesiones sospechosas con criterios avanzados
   */
  async findSuspiciousSessions(criteria = {}, options = {}) {
    try {
      const {
        multipleIps = true,
        frequentFingerprintChanges = true,
        recentSuspiciousActivity = true,
        includeUser = false,
      } = criteria;

      const pipeline = [
        {
          $match: {
            isActive: true,
            isCompromised: { $ne: true },
            $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
          },
        },
      ];

      // Construir condiciones de detección
      const suspiciousConditions = [];

      if (frequentFingerprintChanges) {
        suspiciousConditions.push({
          $expr: { $gt: [{ $size: "$fingerprintChanges" }, 3] },
        });
      }

      if (recentSuspiciousActivity) {
        const last24Hours = new Date(Date.now() - 24 * 60 * 60 * 1000);
        suspiciousConditions.push({
          suspiciousActivity: {
            $elemMatch: {
              timestamp: { $gte: last24Hours },
              severity: { $in: ["high", "critical"] },
            },
          },
        });
      }

      if (suspiciousConditions.length > 0) {
        pipeline.push({
          $match: { $or: suspiciousConditions },
        });
      }

      // Agregar información adicional de riesgo
      pipeline.push({
        $addFields: {
          riskScore: {
            $add: [
              { $multiply: [{ $size: "$fingerprintChanges" }, 10] },
              { $multiply: [{ $size: "$suspiciousActivity" }, 15] },
              {
                $cond: {
                  if: {
                    $lt: [
                      "$lastAccessedAt",
                      { $subtract: [new Date(), 60 * 60 * 1000] },
                    ],
                  },
                  then: 5,
                  else: 0,
                },
              },
            ],
          },
          lastSuspiciousActivity: {
            $max: "$suspiciousActivity.timestamp",
          },
        },
      });

      // Incluir información de usuario si se solicita
      if (includeUser) {
        pipeline.push({
          $lookup: this.sessionLookups.user,
        });

        pipeline.push({
          $unwind: {
            path: "$user",
            preserveNullAndEmptyArrays: true,
          },
        });
      }

      pipeline.push({
        $sort: { riskScore: -1, lastSuspiciousActivity: -1 },
      });

      const suspiciousSessions = await this.executeAggregationPipeline({
        pipeline,
        options: {
          enablePagination: true,
          ...options,
        },
      });

      console.log(
        `🔍 Detectadas ${suspiciousSessions.totalDocs} sesiones sospechosas`
      );

      return suspiciousSessions;
    } catch (error) {
      console.error("❌ Error detectando sesiones sospechosas:", error);
      throw new Error(
        `Error detectando sesiones sospechosas: ${error.message}`
      );
    }
  }

  /**
   * Validar políticas de seguridad para sesiones
   */
  async validateSessionSecurityPolicies(userId, options = {}) {
    try {
      const activeSessions = await this.getActiveSessions(userId);
      const violations = [];

      for (const session of activeSessions) {
        const sessionInstance = this.model.hydrate(session);
        const validation = sessionInstance.validateSecurityPolicy();

        if (!validation.isValid) {
          violations.push({
            sessionId: session._id,
            issues: validation.issues,
            session: session,
          });
        }
      }

      console.log(
        `🛡️ Validación de políticas completada. ${violations.length} violaciones encontradas`
      );

      return {
        totalSessions: activeSessions.length,
        violations: violations,
        isCompliant: violations.length === 0,
      };
    } catch (error) {
      console.error("❌ Error validando políticas de seguridad:", error);
      throw new Error(`Error validando políticas: ${error.message}`);
    }
  }

  // =============================================================================
  // 📊 MÉTRICAS Y ANALYTICS
  // =============================================================================

  /**
   * Obtener estadísticas completas de sesiones para un usuario
   */
  async getUserSessionStats(userId, options = {}) {
    try {
      if (!Types.ObjectId.isValid(userId)) {
        throw new Error("ID de usuario no válido");
      }

      const { includeDeleted = false, period = 30 } = options;
      const fromDate = new Date(Date.now() - period * 24 * 60 * 60 * 1000);

      const pipeline = [
        {
          $match: {
            userId: new Types.ObjectId(userId),
            createdAt: { $gte: fromDate },
          },
        },
      ];

      if (!includeDeleted) {
        pipeline[0].$match.$or = [
          { isDeleted: false },
          { isDeleted: { $exists: false } },
        ];
      }

      pipeline.push({
        $group: {
          _id: null,
          totalSessions: { $sum: 1 },
          activeSessions: {
            $sum: {
              $cond: [
                {
                  $and: [
                    { $eq: ["$isActive", true] },
                    { $gt: ["$expiresAt", new Date()] },
                  ],
                },
                1,
                0,
              ],
            },
          },
          compromisedSessions: {
            $sum: { $cond: [{ $eq: ["$isCompromised", true] }, 1, 0] },
          },
          avgSessionDuration: { $avg: "$metadata.sessionDuration" },
          totalRequests: { $sum: "$metadata.totalRequests" },
          totalApiCalls: { $sum: "$metadata.businessMetrics.apiCallsCount" },
          uniqueDeviceTypes: { $addToSet: "$deviceInfo.deviceType" },
          uniqueCountries: { $addToSet: "$location.country" },
          avgRiskScore: {
            $avg: {
              $avg: {
                $map: {
                  input: "$suspiciousActivity",
                  as: "activity",
                  in: "$$activity.riskScore",
                },
              },
            },
          },
          securityIncidents: {
            $sum: { $size: "$suspiciousActivity" },
          },
        },
      });

      const result = await this.model.aggregate(pipeline);
      const stats = result[0] || {
        totalSessions: 0,
        activeSessions: 0,
        compromisedSessions: 0,
        avgSessionDuration: 0,
        totalRequests: 0,
        totalApiCalls: 0,
        uniqueDeviceTypes: [],
        uniqueCountries: [],
        avgRiskScore: 0,
        securityIncidents: 0,
      };

      console.log(`📊 Estadísticas generadas para usuario ${userId}`);

      return stats;
    } catch (error) {
      console.error("❌ Error obteniendo estadísticas:", error);
      throw new Error(`Error obteniendo estadísticas: ${error.message}`);
    }
  }

  /**
   * Analytics empresariales avanzados con filtros dinámicos
   */
  async getBusinessAnalytics(filters = {}, options = {}) {
    try {
      const {
        dateFrom,
        dateTo,
        country,
        deviceType,
        groupBy = "day",
      } = filters;

      const { aggregateBy = "createdAt" } = options;

      const matchStage = {
        isActive: true,
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      };

      // Aplicar filtros de fecha
      if (dateFrom || dateTo) {
        matchStage.createdAt = {};
        if (dateFrom) matchStage.createdAt.$gte = new Date(dateFrom);
        if (dateTo) matchStage.createdAt.$lte = new Date(dateTo);
      }

      // Filtros específicos
      if (country) matchStage["location.country"] = country;
      if (deviceType) matchStage["deviceInfo.deviceType"] = deviceType;

      const pipeline = [{ $match: matchStage }];

      // Configurar agrupación temporal
      const dateGrouping = this.buildDateGrouping(groupBy, aggregateBy);

      pipeline.push({
        $group: {
          _id: dateGrouping,
          totalSessions: { $sum: 1 },
          uniqueUsers: { $addToSet: "$userId" },
          deviceTypes: { $push: "$deviceInfo.deviceType" },
          countries: { $push: "$location.country" },
          oauthProviders: { $push: "$oauthProvider" },
          avgSessionDuration: { $avg: "$metadata.sessionDuration" },
          totalApiCalls: { $sum: "$metadata.businessMetrics.apiCallsCount" },
          securityIncidents: {
            $sum: { $size: "$suspiciousActivity" },
          },
          // Nuevas métricas empresariales
          totalPagesViewed: { $sum: "$metadata.businessMetrics.pagesViewed" },
          totalDocumentsAccessed: {
            $sum: "$metadata.businessMetrics.documentsAccessed",
          },
          totalDataDownloaded: {
            $sum: "$metadata.businessMetrics.dataDownloaded",
          },
          avgResponseTime: {
            $avg: "$metadata.businessMetrics.avgResponseTime",
          },
          errorRate: {
            $avg: {
              $cond: {
                if: { $gt: ["$metadata.totalRequests", 0] },
                then: {
                  $divide: [
                    "$metadata.businessMetrics.errorCount",
                    "$metadata.totalRequests",
                  ],
                },
                else: 0,
              },
            },
          },
        },
      });

      // Proyección final con cálculos adicionales
      pipeline.push({
        $project: {
          date: "$_id",
          totalSessions: 1,
          uniqueUserCount: { $size: "$uniqueUsers" },
          deviceTypeDistribution: this.buildArrayDistribution("$deviceTypes"),
          countryDistribution: this.buildArrayDistribution("$countries"),
          oauthUsage: this.buildArrayDistribution("$oauthProviders"),
          avgSessionDuration: { $round: ["$avgSessionDuration", 2] },
          totalApiCalls: 1,
          securityIncidents: 1,
          totalPagesViewed: 1,
          totalDocumentsAccessed: 1,
          totalDataDownloaded: 1,
          avgResponseTime: { $round: ["$avgResponseTime", 2] },
          errorRate: { $round: ["$errorRate", 4] },
          sessionQuality: {
            $cond: {
              if: { $gt: ["$securityIncidents", 0] },
              then: "risky",
              else: "normal",
            },
          },
        },
      });

      pipeline.push({ $sort: { date: 1 } });

      const analytics = await this.model.aggregate(pipeline);

      console.log(
        `📈 Analytics empresariales generados: ${analytics.length} períodos`
      );

      return analytics;
    } catch (error) {
      console.error("❌ Error generando analytics empresariales:", error);
      throw new Error(`Error en analytics empresariales: ${error.message}`);
    }
  }

  // =============================================================================
  // 🧹 LIMPIEZA Y MANTENIMIENTO
  // =============================================================================

  /**
   * Limpiar sesiones expiradas automáticamente
   */
  async cleanupExpiredSessions(options = {}) {
    try {
      const { dryRun = false, batchSize = 1000 } = options;
      const cutoffDate = new Date(
        Date.now() -
          SESSION_CONSTANTS.SESSION_CLEANUP_DAYS * 24 * 60 * 60 * 1000
      );

      const filter = {
        $or: [
          { expiresAt: { $lt: new Date() } },
          {
            isActive: false,
            updatedAt: { $lt: cutoffDate },
          },
        ],
      };

      if (dryRun) {
        const count = await this.model.countDocuments(filter);
        console.log(`🧹 [DRY RUN] Se eliminarían ${count} sesiones expiradas`);
        return { deletedCount: count, dryRun: true };
      }

      // Procesar en lotes para evitar sobrecarga
      let totalDeleted = 0;
      let batch = await this.model.find(filter).limit(batchSize).select("_id");

      while (batch.length > 0) {
        const ids = batch.map((doc) => doc._id);

        const result = await this.softDeleteMany(
          { _id: { $in: ids } },
          { userId: "system", username: "system" },
          "Automatic cleanup of expired sessions"
        );

        totalDeleted += result.modifiedCount;

        console.log(
          `🧹 Lote procesado: ${result.modifiedCount} sesiones marcadas para eliminación`
        );

        // Siguiente lote
        batch = await this.model
          .find({
            ...filter,
            _id: { $nin: ids },
          })
          .limit(batchSize)
          .select("_id");
      }

      console.log(
        `✅ Limpieza completada: ${totalDeleted} sesiones expiradas procesadas`
      );

      return { deletedCount: totalDeleted };
    } catch (error) {
      console.error("❌ Error en limpieza de sesiones:", error);
      throw new Error(`Error en limpieza: ${error.message}`);
    }
  }

  /**
   * Optimizar rendimiento de la colección de sesiones
   */
  async optimizeSessionCollection(options = {}) {
    try {
      const {
        compactDatabase = false,
        rebuildIndexes = false,
        analyzeQueries = true,
      } = options;

      const optimizationResults = {
        indexes: null,
        queries: null,
        compaction: null,
      };

      // Análisis de índices
      if (rebuildIndexes) {
        const indexStats = await this.model.collection.indexStats();
        optimizationResults.indexes = {
          message: "Índices analizados",
          stats: indexStats,
        };
        console.log("📊 Análisis de índices completado");
      }

      // Análisis de consultas frecuentes
      if (analyzeQueries) {
        const recentSessions = await this.model
          .find({
            createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
          })
          .limit(1000)
          .lean();

        optimizationResults.queries = {
          message: "Consultas analizadas",
          totalAnalyzed: recentSessions.length,
          recommendations: this.generateQueryOptimizationTips(recentSessions),
        };
        console.log("🔍 Análisis de consultas completado");
      }

      // Compactación (solo si se solicita explícitamente)
      if (compactDatabase) {
        console.log(
          "⚠️ Compactación de base de datos solicitada (operación costosa)"
        );
        optimizationResults.compaction = {
          message: "Compactación programada",
          note: "Ejecutar durante mantenimiento programado",
        };
      }

      return optimizationResults;
    } catch (error) {
      console.error("❌ Error en optimización:", error);
      throw new Error(`Error en optimización: ${error.message}`);
    }
  }

  // =============================================================================
  // 🛠️ MÉTODOS AUXILIARES ESPECIALIZADOS
  // =============================================================================

  /**
   * Construir agrupación de fechas para analytics
   */
  buildDateGrouping(groupBy, dateField) {
    const dateExpressions = {
      hour: {
        year: { $year: `$${dateField}` },
        month: { $month: `$${dateField}` },
        day: { $dayOfMonth: `$${dateField}` },
        hour: { $hour: `$${dateField}` },
      },
      day: {
        year: { $year: `$${dateField}` },
        month: { $month: `$${dateField}` },
        day: { $dayOfMonth: `$${dateField}` },
      },
      week: {
        year: { $year: `$${dateField}` },
        week: { $week: `$${dateField}` },
      },
      month: {
        year: { $year: `$${dateField}` },
        month: { $month: `$${dateField}` },
      },
    };

    return dateExpressions[groupBy] || dateExpressions.day;
  }

  /**
   * Construir distribución de arrays para analytics
   */
  buildArrayDistribution(arrayField) {
    return {
      $arrayToObject: {
        $map: {
          input: {
            $setUnion: arrayField,
          },
          as: "item",
          in: {
            k: "$$item",
            v: {
              $size: {
                $filter: {
                  input: arrayField,
                  cond: { $eq: ["$$this", "$$item"] },
                },
              },
            },
          },
        },
      },
    };
  }

  /**
   * Generar recomendaciones de optimización
   */
  generateQueryOptimizationTips(sessions) {
    const tips = [];

    if (sessions.length === 0) {
      return ["No hay suficientes datos para generar recomendaciones"];
    }

    // Análisis de patrones de acceso
    const deviceTypes = sessions
      .map((s) => s.deviceInfo?.deviceType)
      .filter(Boolean);
    const uniqueDeviceTypes = [...new Set(deviceTypes)];

    if (uniqueDeviceTypes.length > 3) {
      tips.push(
        "Considerar índice compuesto en deviceInfo.deviceType para filtros frecuentes"
      );
    }

    // Análisis de ubicaciones
    const countries = sessions.map((s) => s.location?.country).filter(Boolean);
    const uniqueCountries = [...new Set(countries)];

    if (uniqueCountries.length > 10) {
      tips.push(
        "Considerar particionamiento geográfico para consultas por país"
      );
    }

    // Análisis de actividad sospechosa
    const withSuspiciousActivity = sessions.filter(
      (s) => s.suspiciousActivity?.length > 0
    );

    if (withSuspiciousActivity.length > sessions.length * 0.1) {
      tips.push(
        "Alta frecuencia de actividad sospechosa - considerar índice especializado"
      );
    }

    return tips.length > 0
      ? tips
      : ["Sin recomendaciones específicas basadas en los datos actuales"];
  }

  /**
   * Validar datos de sesión antes de operaciones críticas
   */
  validateSessionData(sessionData, operation = "create") {
    const errors = [];

    // Validaciones comunes
    if (!sessionData.userId || !Types.ObjectId.isValid(sessionData.userId)) {
      errors.push("ID de usuario requerido y válido");
    }

    if (
      !sessionData.deviceFingerprint ||
      !SessionUtils.validateFingerprint(sessionData.deviceFingerprint)
    ) {
      errors.push("Device fingerprint requerido y válido");
    }

    if (!sessionData.ipAddress) {
      errors.push("Dirección IP requerida");
    }

    // Validaciones específicas por operación
    if (operation === "create") {
      if (!sessionData.userAgent || sessionData.userAgent.length < 10) {
        errors.push("User agent requerido y válido");
      }

      if (!sessionData.deviceInfo || !sessionData.deviceInfo.browser) {
        errors.push("Información de dispositivo requerida");
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  /**
   * Obtener campos de búsqueda de texto específicos para sesiones
   */
  getTextSearchFields() {
    return [
      "userAgent",
      "deviceInfo.browser",
      "deviceInfo.os",
      "deviceInfo.device",
      "location.city",
      "location.country",
      "location.isp",
      "invalidationReason",
    ];
  }
}

// Instancia singleton del repositorio
export const userSessionRepository = new UserSessionRepository();
export default userSessionRepository;
