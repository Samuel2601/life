// =============================================================================
// src/modules/authentication/repositories/user_session.repository.js - VERSIÓN COMPLETA UNIFICADA
// Utiliza al 100% las funcionalidades del UserSession Schema optimizado + BaseRepository mejorado
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

  // ===== MÉTODOS PRINCIPALES DE GESTIÓN DE SESIONES =====

  /**
   * Crear nueva sesión con funcionalidades empresariales completas
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
            companyId = null,
            businessContext = {},
          } = sessionData;

          // Generar token de sesión único y seguro
          const sessionToken = this.generateSecureToken();

          // Parsear información del dispositivo
          const deviceInfo = this.parseUserAgent(userAgent);

          // Obtener información geográfica mejorada
          const location = await this.getLocationFromIP(ipAddress);

          // Obtener política de sesión basada en roles de usuario
          const sessionPolicy = await this.getSessionPolicyForUser(userId);

          // Configurar tiempo de expiración basado en política y remember me
          const expirationTime = rememberMe
            ? Math.min(
                30 * 24 * 60 * 60 * 1000,
                sessionPolicy.sessionTimeoutMinutes * 60 * 1000
              ) // Máximo 30 días o política
            : sessionPolicy.sessionTimeoutMinutes * 60 * 1000;

          const expiresAt = new Date(Date.now() + expirationTime);

          // Invalidar sesiones anteriores si se especifica o si se excede el límite
          const activeSessions = await this.getUserActiveSessions(userId);
          if (
            options.singleSession ||
            activeSessions.length >= sessionPolicy.maxConcurrentSessions
          ) {
            await this.invalidateUserSessions(userId, "max_sessions_exceeded", {
              session,
            });
          }

          // Preparar datos de la nueva sesión
          const newSessionData = {
            userId: new Types.ObjectId(userId),

            // Tokens seguros (hasheados)
            sessionToken,
            accessTokenHash: this.hashToken(accessToken),
            refreshTokenHash: this.hashToken(refreshToken),

            // Device fingerprinting
            deviceFingerprint,
            originalFingerprint: deviceFingerprint,
            fingerprintChanges: [],

            // Estado de sesión
            isActive: true,
            isValid: true,
            expiresAt,
            lastAccessedAt: new Date(),

            // Información del cliente
            ipAddress,
            userAgent,
            deviceInfo: {
              ...deviceInfo,
              // Información adicional para detección de bots
              hardwareConcurrency: sessionData.hardwareConcurrency || null,
              deviceMemory: sessionData.deviceMemory || null,
              maxTouchPoints: sessionData.maxTouchPoints || 0,
            },

            // Información de ubicación mejorada
            location: {
              ...location,
              // Detección avanzada de VPN y proxy
              isVpnDetected: await this.detectVPN(ipAddress),
              isProxy: await this.detectProxy(ipAddress),
              isp: await this.getISP(ipAddress),
              // Compliance automático
              isEuCountry: this.isEuropeanUnion(location.country),
              dataProcessingConsent: sessionData.dataProcessingConsent || false,
              locationAccuracy: location.accuracy || "city",
            },

            // OAuth data si aplica
            oauthProvider,
            oauthSessionData: oauthSessionData
              ? {
                  ...oauthSessionData,
                  tokenHash: this.hashToken(oauthSessionData.accessToken || ""),
                  refreshTokenHash: this.hashToken(
                    oauthSessionData.refreshToken || ""
                  ),
                  // Remover tokens originales
                  accessToken: undefined,
                  refreshToken: undefined,
                }
              : undefined,

            // Configuración de sesión
            rememberMe,
            maxInactivityMinutes: sessionPolicy.sessionTimeoutMinutes,
            isCompromised: false,
            suspiciousActivity: [],

            // Política de sesión específica
            sessionPolicy: {
              requireTwoFactor: sessionPolicy.requireTwoFactor,
              allowedDeviceTypes: sessionPolicy.allowedDeviceTypes || [],
              allowedCountries: sessionPolicy.allowedCountries || [],
              maxConcurrentSessions: sessionPolicy.maxConcurrentSessions,
              forceLogoutOnLocationChange:
                sessionPolicy.forceLogoutOnLocationChange || false,
            },

            // Metadatos empresariales completos
            metadata: {
              totalRequests: 1,
              lastRequestAt: new Date(),
              creationMethod: oauthProvider ? "oauth" : "password",
              sessionDuration: 0,

              // Métricas empresariales
              businessMetrics: {
                companiesAccessed: companyId ? [companyId] : [],
                featuresUsed: businessContext.initialFeatures || [],
                apiCallsCount: 0,
                avgResponseTime: 0,
                searchesPerformed: 0,
                businessesViewed: [],
                reviewsSubmitted: 0,
                translationsRequested: 0,
              },

              // Compliance completo
              compliance: {
                dataProcessingAgreed:
                  sessionData.dataProcessingConsent || false,
                gdprApplicable: this.isEuropeanUnion(location.country),
                auditTrailEnabled: true,
                cookiesAccepted: sessionData.cookiesAccepted || false,
                marketingConsent: sessionData.marketingConsent || false,
                analyticsConsent: sessionData.analyticsConsent || false,
                consentTimestamp: new Date(),
              },
            },
          };

          const createdSession = await this.create(newSessionData, userData, {
            session,
          });

          console.log(
            `✅ Sesión creada para usuario ${userId}: ${createdSession._id}`
          );
          return this.sanitizeSessionData(createdSession);
        } catch (error) {
          console.error("Error creando sesión:", error);
          throw error;
        }
      }
    );
  }

  /**
   * Actualizar sesión existente con datos empresariales
   * @param {string} sessionId - ID de la sesión
   * @param {Object} updateData - Datos a actualizar
   * @param {Object} userData - Datos del usuario
   */
  async updateSession(sessionId, updateData, userData) {
    try {
      const session = await this.findById(sessionId);
      if (!session) {
        throw new Error("Sesión no encontrada");
      }

      // Validar que la sesión esté activa
      if (!session.isActive || session.isExpired()) {
        throw new Error("Sesión inactiva o expirada");
      }

      // Preparar datos de actualización
      const finalUpdateData = {
        ...updateData,
        lastAccessedAt: new Date(),
        $inc: {
          "metadata.totalRequests": 1,
        },
      };

      return await this.update(sessionId, finalUpdateData, userData);
    } catch (error) {
      console.error("Error actualizando sesión:", error);
      throw error;
    }
  }

  // ===== POLÍTICAS DE SESIÓN Y CONFIGURACIÓN =====

  /**
   * Obtener política de sesión basada en roles de usuario
   * @param {string} userId - ID del usuario
   */
  async getSessionPolicyForUser(userId) {
    try {
      const pipeline = [
        { $match: { _id: new Types.ObjectId(userId) } },
        {
          $lookup: {
            from: "roles",
            localField: "roles",
            foreignField: "_id",
            as: "userRoles",
          },
        },
        {
          $project: {
            maxHierarchy: { $max: "$userRoles.hierarchy" },
            sessionConfigs: "$userRoles.sessionConfig",
            geographicRestrictions: "$userRoles.geographicRestrictions",
          },
        },
      ];

      const result = await this.model.db
        .collection("users")
        .aggregate(pipeline)
        .toArray();
      const userData = result[0];

      if (!userData || !userData.sessionConfigs?.length) {
        return this.getDefaultSessionPolicy();
      }

      // Combinar políticas de todos los roles (tomar la más restrictiva)
      const combinedPolicy = userData.sessionConfigs.reduce(
        (policy, config) => ({
          maxConcurrentSessions: Math.min(
            policy.maxConcurrentSessions,
            config.maxConcurrentSessions || 3
          ),
          sessionTimeoutMinutes: Math.min(
            policy.sessionTimeoutMinutes,
            config.sessionTimeoutMinutes || 480
          ),
          requireTwoFactor: policy.requireTwoFactor || config.requireTwoFactor,
          allowRememberMe: policy.allowRememberMe && config.allowRememberMe,
          allowedCountries:
            policy.allowedCountries.length > 0
              ? policy.allowedCountries.filter((c) =>
                  config.allowedCountries?.includes(c)
                )
              : config.allowedCountries || [],
          forceLogoutOnLocationChange:
            policy.forceLogoutOnLocationChange ||
            config.forceLogoutOnLocationChange,
        }),
        this.getDefaultSessionPolicy()
      );

      return combinedPolicy;
    } catch (error) {
      console.error("Error obteniendo política de sesión:", error);
      return this.getDefaultSessionPolicy();
    }
  }

  /**
   * Política de sesión por defecto
   */
  getDefaultSessionPolicy() {
    return {
      maxConcurrentSessions: 3,
      sessionTimeoutMinutes: 480, // 8 horas
      requireTwoFactor: false,
      allowRememberMe: true,
      allowedDeviceTypes: [],
      allowedCountries: [],
      forceLogoutOnLocationChange: false,
    };
  }

  // ===== VALIDACIÓN DE SESIONES AVANZADA =====

  /**
   * Validar sesión con política empresarial completa
   * @param {string} sessionToken - Token de sesión
   * @param {Object} context - Contexto de validación
   */
  async validateSessionWithPolicy(sessionToken, context = {}) {
    try {
      const session = await this.model
        .findOne({
          sessionToken,
          isActive: true,
          isValid: true,
          expiresAt: { $gt: new Date() },
          isCompromised: false,
        })
        .populate("userId", "isActive isEmailVerified roles");

      if (!session) {
        return { valid: false, reason: "session_not_found" };
      }

      if (!session.userId || !session.userId.isActive) {
        await this.invalidateSession(session._id, "user_inactive");
        return { valid: false, reason: "user_inactive" };
      }

      // Validar política de sesión
      const policyValidation = this.validateSessionPolicy(session, context);
      if (!policyValidation.valid) {
        if (policyValidation.terminate) {
          await this.invalidateSession(session._id, policyValidation.reason);
        }
        return policyValidation;
      }

      // Validar fingerprint del dispositivo
      if (context.deviceFingerprint) {
        const fingerprintValidation = await this.validateDeviceFingerprint(
          session,
          context.deviceFingerprint,
          context.fingerprintComponents
        );

        if (!fingerprintValidation.valid) {
          await this.flagSuspiciousActivity(
            session._id,
            "device_change",
            fingerprintValidation.reason,
            fingerprintValidation.severity
          );

          if (fingerprintValidation.terminate) {
            await this.invalidateSession(
              session._id,
              "device_fingerprint_changed"
            );
            return { valid: false, reason: "device_fingerprint_changed" };
          }
        }
      }

      // Verificar cambio de ubicación
      if (
        context.ipAddress &&
        this.isSignificantIPChange(session.ipAddress, context.ipAddress)
      ) {
        if (session.sessionPolicy.forceLogoutOnLocationChange) {
          await this.invalidateSession(session._id, "location_change_policy");
          return { valid: false, reason: "location_change_not_allowed" };
        }

        await this.flagSuspiciousActivity(
          session._id,
          "location_change",
          `IP cambió de ${session.ipAddress} a ${context.ipAddress}`,
          "medium"
        );
      }

      // Verificar inactividad
      const inactivityMinutes =
        (Date.now() - session.lastAccessedAt.getTime()) / (1000 * 60);
      if (inactivityMinutes > session.maxInactivityMinutes) {
        await this.invalidateSession(session._id, "inactivity_timeout");
        return { valid: false, reason: "session_expired_inactivity" };
      }

      // Actualizar actividad de la sesión
      await this.updateLastActivity(session._id, context);

      return {
        valid: true,
        session: this.sanitizeSessionData(session),
        requiresTwoFactor: session.sessionPolicy.requireTwoFactor,
        businessMetrics: session.metadata?.businessMetrics,
        userId: session.userId._id,
      };
    } catch (error) {
      console.error("Error validando sesión con política:", error);
      return { valid: false, reason: "validation_error" };
    }
  }

  /**
   * Validar política de sesión específica
   * @param {Object} session - Sesión actual
   * @param {Object} context - Contexto de validación
   */
  validateSessionPolicy(session, context) {
    const policy = session.sessionPolicy;

    if (!policy) {
      return { valid: true };
    }

    // Validar tipos de dispositivo permitidos
    if (policy.allowedDeviceTypes?.length > 0) {
      const deviceType = session.deviceInfo.deviceType;
      if (!policy.allowedDeviceTypes.includes(deviceType)) {
        return {
          valid: false,
          reason: "device_type_not_allowed",
          terminate: true,
        };
      }
    }

    // Validar países permitidos
    if (policy.allowedCountries?.length > 0) {
      const currentCountry =
        context.location?.country || session.location?.country;
      if (currentCountry && !policy.allowedCountries.includes(currentCountry)) {
        return {
          valid: false,
          reason: "country_not_allowed",
          terminate: true,
        };
      }
    }

    return { valid: true };
  }

  /**
   * Validar sesión simple (compatibilidad hacia atrás)
   * @param {string} sessionToken - Token de sesión
   * @param {string} deviceFingerprint - Huella del dispositivo
   * @param {string} ipAddress - Dirección IP actual
   */
  async validateSession(sessionToken, deviceFingerprint, ipAddress) {
    return await this.validateSessionWithPolicy(sessionToken, {
      deviceFingerprint,
      ipAddress,
    });
  }

  // ===== DEVICE FINGERPRINTING AVANZADO =====

  /**
   * Validar fingerprint del dispositivo con análisis avanzado
   * @param {Object} session - Sesión actual
   * @param {string} currentFingerprint - Fingerprint actual
   * @param {Array} components - Componentes del fingerprint
   */
  async validateDeviceFingerprint(
    session,
    currentFingerprint,
    components = []
  ) {
    try {
      // Si el fingerprint es exactamente el mismo, es válido
      if (session.deviceFingerprint === currentFingerprint) {
        return { valid: true };
      }

      // Analizar cambios específicos por componente
      const analysis = await this.analyzeDetailedFingerprintChange(
        session,
        currentFingerprint,
        components
      );

      // Determinar si es válido basado en el análisis
      if (analysis.changeType === "critical" || analysis.autoBlocked) {
        return {
          valid: false,
          reason: `Cambio crítico en device fingerprint: ${analysis.reason}`,
          severity: "critical",
          terminate: true,
        };
      }

      if (analysis.changeType === "major") {
        return {
          valid: false,
          reason: `Cambio mayor en device fingerprint: ${analysis.reason}`,
          severity: "high",
          terminate: false,
        };
      }

      // Cambios menores son aceptables pero se registran
      if (analysis.changeType === "suspicious") {
        return {
          valid: true,
          reason: `Cambio sospechoso pero aceptable: ${analysis.reason}`,
          severity: "medium",
          terminate: false,
        };
      }

      return { valid: true };
    } catch (error) {
      console.error("Error validando fingerprint:", error);
      return {
        valid: false,
        reason: "fingerprint_validation_error",
        severity: "high",
        terminate: false,
      };
    }
  }

  /**
   * Análisis detallado de cambio de fingerprint
   * @param {Object} session - Sesión actual
   * @param {string} newFingerprint - Nuevo fingerprint
   * @param {Array} components - Componentes que cambiaron
   */
  async analyzeDetailedFingerprintChange(
    session,
    newFingerprint,
    components = []
  ) {
    try {
      const previousFingerprint = session.deviceFingerprint;

      // Analizar componentes específicos
      const changedComponents = components.map((component) => {
        const significance = this.calculateComponentSignificance(component);
        return {
          ...component,
          changeSignificance: significance,
        };
      });

      // Calcular score de similitud avanzado
      const similarityScore = this.calculateAdvancedFingerprintSimilarity(
        previousFingerprint,
        newFingerprint,
        changedComponents
      );

      // Determinar tipo de cambio y acciones
      const analysis = this.analyzeFingerprintRisk(
        similarityScore,
        changedComponents
      );

      const fingerprintChange = {
        newFingerprint,
        previousFingerprint,
        changedAt: new Date(),
        changeType: analysis.changeType,
        suspiciousChange: analysis.suspicious,
        validatedByUser: false,
        changedComponents,
        similarityScore,
        autoBlocked: analysis.autoBlock,
      };

      // Registrar el cambio en la sesión
      await this.model.findByIdAndUpdate(session._id, {
        $push: { fingerprintChanges: fingerprintChange },
        deviceFingerprint: newFingerprint,
      });

      if (analysis.suspicious) {
        await this.flagSuspiciousActivity(
          session._id,
          "fingerprint_mismatch",
          `Cambio ${analysis.changeType} en device fingerprint`,
          analysis.severity,
          { changedComponents, similarityScore, analysis }
        );
      }

      return {
        changeType: analysis.changeType,
        suspicious: analysis.suspicious,
        autoBlocked: analysis.autoBlock,
        reason: analysis.reason,
        severity: analysis.severity,
        fingerprintChange,
      };
    } catch (error) {
      console.error("Error analizando cambio de fingerprint:", error);
      throw error;
    }
  }

  /**
   * Calcular significancia de cambio por componente
   */
  calculateComponentSignificance(component) {
    const significanceWeights = {
      userAgent: "critical", // Cambio de navegador/OS
      screen: "major", // Cambio de resolución
      timezone: "major", // Cambio de zona horaria
      language: "minor", // Cambio de idioma
      plugins: "minor", // Cambios en plugins
      fonts: "minor", // Cambios en fuentes
      canvas: "major", // Cambio de capacidades gráficas
      webgl: "major", // Cambio de GPU
      audio: "minor", // Cambio de capacidades de audio
      hardware: "critical", // Cambio de hardware
    };

    return significanceWeights[component.component] || "minor";
  }

  /**
   * Similitud avanzada de fingerprint considerando componentes
   */
  calculateAdvancedFingerprintSimilarity(oldFp, newFp, components) {
    const baseScore = this.calculateFingerprintSimilarity(oldFp, newFp);

    // Ajustar score basado en componentes específicos
    const criticalChanges = components.filter(
      (c) => c.changeSignificance === "critical"
    ).length;
    const majorChanges = components.filter(
      (c) => c.changeSignificance === "major"
    ).length;

    let adjustedScore = baseScore;
    adjustedScore -= criticalChanges * 0.3;
    adjustedScore -= majorChanges * 0.15;

    return Math.max(0, Math.min(1, adjustedScore));
  }

  /**
   * Analizar riesgo de cambio de fingerprint
   */
  analyzeFingerprintRisk(similarityScore, components) {
    const criticalChanges = components.filter(
      (c) => c.changeSignificance === "critical"
    ).length;
    const majorChanges = components.filter(
      (c) => c.changeSignificance === "major"
    ).length;

    if (similarityScore < 0.2 || criticalChanges >= 2) {
      return {
        changeType: "critical",
        suspicious: true,
        severity: "critical",
        autoBlock: true,
        reason: "Dispositivo completamente diferente detectado",
      };
    }

    if (similarityScore < 0.5 || criticalChanges >= 1 || majorChanges >= 3) {
      return {
        changeType: "major",
        suspicious: true,
        severity: "high",
        autoBlock: false,
        reason: "Cambios significativos en el dispositivo",
      };
    }

    if (similarityScore < 0.8 || majorChanges >= 1) {
      return {
        changeType: "suspicious",
        suspicious: true,
        severity: "medium",
        autoBlock: false,
        reason: "Cambios menores pero detectables",
      };
    }

    return {
      changeType: "minor",
      suspicious: false,
      severity: "low",
      autoBlock: false,
      reason: "Cambios mínimos normales",
    };
  }

  // ===== MÉTRICAS EMPRESARIALES =====

  /**
   * Actualizar métricas empresariales de la sesión
   * @param {string} sessionId - ID de la sesión
   * @param {Object} metrics - Métricas a actualizar
   * @param {Object} userData - Datos del usuario
   */
  async updateBusinessMetrics(sessionId, metrics, userData = {}) {
    try {
      const updateData = {};

      // Actualizar métricas específicas usando arrays
      if (metrics.companyAccessed) {
        updateData["$addToSet"] = {
          "metadata.businessMetrics.companiesAccessed": metrics.companyAccessed,
        };
      }

      if (metrics.featureUsed) {
        updateData["$addToSet"] = updateData["$addToSet"] || {};
        updateData["$addToSet"]["metadata.businessMetrics.featuresUsed"] =
          metrics.featureUsed;
      }

      if (metrics.businessViewed) {
        updateData["$addToSet"] = updateData["$addToSet"] || {};
        updateData["$addToSet"]["metadata.businessMetrics.businessesViewed"] =
          metrics.businessViewed;
      }

      // Incrementar contadores
      const incrementFields = {};
      if (metrics.apiCall)
        incrementFields["metadata.businessMetrics.apiCallsCount"] = 1;
      if (metrics.search)
        incrementFields["metadata.businessMetrics.searchesPerformed"] = 1;
      if (metrics.review)
        incrementFields["metadata.businessMetrics.reviewsSubmitted"] = 1;
      if (metrics.translation)
        incrementFields["metadata.businessMetrics.translationsRequested"] = 1;

      incrementFields["metadata.totalRequests"] = 1;

      if (Object.keys(incrementFields).length > 0) {
        updateData["$inc"] = incrementFields;
      }

      // Actualizar tiempos y respuestas
      updateData["$set"] = updateData["$set"] || {};
      if (metrics.responseTime) {
        updateData["$set"]["metadata.businessMetrics.avgResponseTime"] =
          metrics.responseTime;
      }
      updateData["$set"]["lastAccessedAt"] = new Date();
      updateData["$set"]["metadata.lastRequestAt"] = new Date();

      await this.model.updateOne({ _id: sessionId }, updateData);

      return true;
    } catch (error) {
      console.error("Error actualizando métricas empresariales:", error);
      throw error;
    }
  }

  /**
   * Obtener analytics empresariales con agregación
   * @param {Object} filters - Filtros de búsqueda
   */
  async getBusinessSessionAnalytics(filters = {}) {
    try {
      const {
        userId,
        companyId,
        dateFrom,
        dateTo,
        deviceType,
        country,
        feature,
      } = filters;

      const searchConfig = {
        filters: {
          isActive: true,
          ...(userId && { userId: new Types.ObjectId(userId) }),
          ...((dateFrom || dateTo) && {
            createdAt: {
              ...(dateFrom && { $gte: new Date(dateFrom) }),
              ...(dateTo && { $lte: new Date(dateTo) }),
            },
          }),
          ...(deviceType && { "deviceInfo.deviceType": deviceType }),
          ...(country && { "location.country": country }),
          ...(companyId && {
            "metadata.businessMetrics.companiesAccessed": companyId,
          }),
          ...(feature && { "metadata.businessMetrics.featuresUsed": feature }),
        },
        options: { limit: 1000 },
        customPipeline: [
          {
            $group: {
              _id: {
                year: { $year: "$createdAt" },
                month: { $month: "$createdAt" },
                day: { $dayOfMonth: "$createdAt" },
              },
              totalSessions: { $sum: 1 },
              uniqueUsers: { $addToSet: "$userId" },
              deviceTypes: { $push: "$deviceInfo.deviceType" },
              countries: { $push: "$location.country" },
              avgSessionDuration: { $avg: "$metadata.sessionDuration" },
              totalRequests: { $sum: "$metadata.totalRequests" },
              totalApiCalls: {
                $sum: "$metadata.businessMetrics.apiCallsCount",
              },
              totalSearches: {
                $sum: "$metadata.businessMetrics.searchesPerformed",
              },
              totalTranslations: {
                $sum: "$metadata.businessMetrics.translationsRequested",
              },
              avgResponseTime: {
                $avg: "$metadata.businessMetrics.avgResponseTime",
              },
              suspiciousActivityCount: {
                $sum: { $size: { $ifNull: ["$suspiciousActivity", []] } },
              },
              gdprSessions: {
                $sum: {
                  $cond: [
                    { $eq: ["$metadata.compliance.gdprApplicable", true] },
                    1,
                    0,
                  ],
                },
              },
            },
          },
          {
            $project: {
              date: {
                $dateFromParts: {
                  year: "$_id.year",
                  month: "$_id.month",
                  day: "$_id.day",
                },
              },
              totalSessions: 1,
              uniqueUserCount: { $size: "$uniqueUsers" },
              deviceTypeDistribution: 1,
              countryDistribution: 1,
              avgSessionDuration: 1,
              totalRequests: 1,
              totalApiCalls: 1,
              totalSearches: 1,
              totalTranslations: 1,
              avgResponseTime: 1,
              suspiciousActivityCount: 1,
              gdprSessions: 1,
              conversionMetrics: {
                searchToView: { $divide: ["$totalSearches", "$totalSessions"] },
                sessionToApi: { $divide: ["$totalApiCalls", "$totalSessions"] },
              },
            },
          },
          { $sort: { date: 1 } },
        ],
      };

      return await this.searchWithAggregation(searchConfig);
    } catch (error) {
      console.error("Error obteniendo analytics empresariales:", error);
      throw error;
    }
  }

  // ===== COMPLIANCE Y CONFIGURACIÓN =====

  /**
   * Actualizar configuración de compliance
   * @param {string} sessionId - ID de la sesión
   * @param {Object} complianceData - Datos de compliance
   * @param {Object} userData - Datos del usuario
   */
  async updateComplianceSettings(sessionId, complianceData, userData) {
    try {
      const updateData = {
        "metadata.compliance.dataProcessingAgreed": Boolean(
          complianceData.dataProcessing
        ),
        "metadata.compliance.cookiesAccepted": Boolean(complianceData.cookies),
        "metadata.compliance.marketingConsent": Boolean(
          complianceData.marketing
        ),
        "metadata.compliance.analyticsConsent": Boolean(
          complianceData.analytics
        ),
        "metadata.compliance.consentTimestamp": new Date(),
        updatedAt: new Date(),
      };

      const result = await this.model.updateOne(
        { _id: sessionId },
        { $set: updateData }
      );

      if (result.modifiedCount > 0) {
        console.log(
          `✅ Consentimientos actualizados para sesión ${sessionId}:`,
          complianceData
        );
      }

      return result.modifiedCount > 0;
    } catch (error) {
      console.error("Error actualizando configuración de compliance:", error);
      throw error;
    }
  }

  // ===== BÚSQUEDAS Y CONSULTAS =====

  /**
   * Buscar sesión por token
   * @param {string} sessionToken - Token de sesión
   * @param {Object} options - Opciones de búsqueda
   */
  async findBySessionToken(sessionToken, options = {}) {
    try {
      const { includeExpired = false, includeInactive = false } = options;

      let query = {
        sessionToken,
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      };

      if (!includeExpired) {
        query.expiresAt = { $gt: new Date() };
      }

      if (!includeInactive) {
        query.isActive = true;
        query.isValid = true;
      }

      return await this.model.findOne(query).lean();
    } catch (error) {
      console.error("Error buscando sesión por token:", error);
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
        isValid: true,
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
   * Buscar sesiones con filtros avanzados usando agregación
   * @param {Object} filters - Filtros de búsqueda
   * @param {Object} options - Opciones de paginación
   */
  async findSessionsWithAggregation(filters = {}, options = {}) {
    try {
      const {
        userId,
        deviceType,
        country,
        isCompromised,
        hasOAuth,
        suspiciousActivity,
        dateRange,
      } = filters;

      const searchConfig = {
        filters: {
          ...(userId && { userId: new Types.ObjectId(userId) }),
          ...(deviceType && { "deviceInfo.deviceType": deviceType }),
          ...(country && { "location.country": country }),
          ...(isCompromised !== undefined && { isCompromised }),
          ...(hasOAuth !== undefined && {
            oauthProvider: hasOAuth
              ? { $exists: true, $ne: null }
              : { $exists: false },
          }),
          ...(dateRange && {
            createdAt: {
              $gte: new Date(dateRange.from),
              $lte: new Date(dateRange.to),
            },
          }),
        },
        options,
        lookups: [
          {
            from: "users",
            localField: "userId",
            foreignField: "_id",
            as: "user",
            pipeline: [
              {
                $project: {
                  email: 1,
                  firstName: 1,
                  lastName: 1,
                  isActive: 1,
                  roles: 1,
                },
              },
            ],
          },
        ],
        customPipeline: [
          {
            $unwind: {
              path: "$user",
              preserveNullAndEmptyArrays: true,
            },
          },
          ...(suspiciousActivity && [
            {
              $match: {
                suspiciousActivity: { $ne: [] },
              },
            },
          ]),
          {
            $addFields: {
              suspiciousActivityCount: {
                $size: { $ifNull: ["$suspiciousActivity", []] },
              },
              sessionAge: {
                $divide: [
                  { $subtract: [new Date(), "$createdAt"] },
                  1000 * 60 * 60 * 24, // Días
                ],
              },
            },
          },
        ],
      };

      return await this.searchWithAggregation(searchConfig);
    } catch (error) {
      console.error("Error en búsqueda de sesiones con agregación:", error);
      throw error;
    }
  }

  // ===== GESTIÓN DE SESIONES =====

  /**
   * Invalidar sesión específica
   * @param {string} sessionId - ID de la sesión
   * @param {string} reason - Razón de invalidación
   */
  async invalidateSession(sessionId, reason = "manual") {
    try {
      const result = await this.model.findByIdAndUpdate(
        sessionId,
        {
          $set: {
            isActive: false,
            isValid: false,
            invalidationReason: reason,
            updatedAt: new Date(),
          },
        },
        { new: true }
      );

      if (result) {
        console.log(`✅ Sesión invalidada: ${sessionId} (${reason})`);
      }

      return result;
    } catch (error) {
      console.error("Error invalidando sesión:", error);
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
        throw new Error("Token de sesión requerido");
      }

      const session = await this.model.findOneAndUpdate(
        {
          sessionToken,
          isActive: true,
        },
        {
          $set: {
            isActive: false,
            isValid: false,
            invalidationReason: reason,
            updatedAt: new Date(),
          },
        },
        { new: true }
      );

      if (!session) {
        throw new Error("Sesión no encontrada o ya invalidada");
      }

      console.log(`✅ Sesión invalidada por token: ${session._id} (${reason})`);
      return { success: true, sessionId: session._id };
    } catch (error) {
      console.error("Error invalidando sesión por token:", error);
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

      const result = await this.model.updateMany(
        query,
        {
          $set: {
            isActive: false,
            isValid: false,
            invalidationReason: reason,
            updatedAt: new Date(),
          },
        },
        updateOptions
      );

      console.log(
        `✅ ${result.modifiedCount} sesiones invalidadas para usuario ${userId} (${reason})`
      );
      return result;
    } catch (error) {
      console.error("Error invalidando sesiones de usuario:", error);
      throw error;
    }
  }

  /**
   * Rotar tokens de sesión
   * @param {string} sessionId - ID de la sesión
   * @param {string} newAccessToken - Nuevo access token
   * @param {string} newRefreshToken - Nuevo refresh token
   * @param {Object} userData - Datos del usuario
   */
  async rotateTokens(sessionId, newAccessToken, newRefreshToken, userData) {
    try {
      const updateData = {
        accessTokenHash: this.hashToken(newAccessToken),
        refreshTokenHash: this.hashToken(newRefreshToken),
        lastAccessedAt: new Date(),
      };

      return await this.update(sessionId, updateData, userData);
    } catch (error) {
      console.error("Error rotando tokens:", error);
      throw error;
    }
  }

  /**
   * Extender sesión
   * @param {string} sessionId - ID de la sesión
   * @param {number} additionalHours - Horas adicionales
   */
  async extendSession(sessionId, additionalHours = 2) {
    try {
      const session = await this.findById(sessionId);
      if (!session || !session.isActive) {
        throw new Error("Sesión no encontrada o inactiva");
      }

      const newExpiration = new Date(
        session.expiresAt.getTime() + additionalHours * 60 * 60 * 1000
      );

      return await this.model.findByIdAndUpdate(
        sessionId,
        {
          $set: {
            expiresAt: newExpiration,
            lastAccessedAt: new Date(),
            updatedAt: new Date(),
          },
        },
        { new: true }
      );
    } catch (error) {
      console.error("Error extendiendo sesión:", error);
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
      const { ipAddress, userAgent, location } = activityData;

      const updateData = {
        lastAccessedAt: new Date(),
        updatedAt: new Date(),
        $inc: {
          "metadata.totalRequests": 1,
        },
      };

      // Actualizar IP si cambió
      if (ipAddress && ipAddress !== "unknown") {
        updateData.ipAddress = ipAddress;
      }

      // Actualizar ubicación si se proporciona
      if (location) {
        updateData["location.city"] = location.city;
        updateData["location.country"] = location.country;
      }

      return await this.model.findByIdAndUpdate(sessionId, updateData, {
        new: true,
      });
    } catch (error) {
      console.error("Error actualizando actividad de sesión:", error);
      throw error;
    }
  }

  // ===== ACTIVIDAD SOSPECHOSA =====

  /**
   * Marcar actividad sospechosa
   * @param {string} sessionId - ID de la sesión
   * @param {string} activityType - Tipo de actividad
   * @param {string} description - Descripción
   * @param {string} severity - Severidad
   * @param {Object} additionalData - Datos adicionales
   */
  async flagSuspiciousActivity(
    sessionId,
    activityType,
    description,
    severity = "medium",
    additionalData = {}
  ) {
    try {
      const suspiciousActivity = {
        activityType,
        description,
        timestamp: new Date(),
        severity,
        resolved: false,
        additionalData,
        riskScore: this.calculateRiskScore(activityType, severity),
        automaticAction: this.getAutomaticAction(severity),
      };

      const updateData = {
        $push: { suspiciousActivity },
        $set: {
          updatedAt: new Date(),
        },
      };

      // Auto-marcar como comprometida si es crítica
      if (severity === "critical") {
        updateData.$set.isCompromised = true;
        updateData.$set.compromisedAt = new Date();
        updateData.$set.invalidationReason = "suspicious_activity";
      }

      const result = await this.model.findByIdAndUpdate(sessionId, updateData, {
        new: true,
      });

      console.log(
        `⚠️ Actividad sospechosa registrada en sesión ${sessionId}: ${activityType} (${severity})`
      );
      return result;
    } catch (error) {
      console.error("Error marcando actividad sospechosa:", error);
      throw error;
    }
  }

  // ===== ESTADÍSTICAS Y ANÁLISIS =====

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
            suspiciousActivities: {
              $sum: { $size: { $ifNull: ["$suspiciousActivity", []] } },
            },
          },
        },
      ]);

      // Estadísticas por dispositivo
      const deviceStats = await this.model.aggregate([
        { $match: { ...matchFilter, isActive: true } },
        {
          $group: {
            _id: "$deviceInfo.deviceType",
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
          totalRequests: 0,
          totalApiCalls: 0,
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

  // ===== MÉTODOS AUXILIARES =====

  /**
   * Generar token seguro
   */
  generateSecureToken() {
    return crypto.randomBytes(32).toString("hex");
  }

  /**
   * Hash de token para almacenamiento seguro
   */
  hashToken(token) {
    return crypto.createHash("sha256").update(token).digest("hex");
  }

  /**
   * Verificar hash de token
   */
  verifyTokenHash(token, hash) {
    return this.hashToken(token) === hash;
  }

  /**
   * Parsear User-Agent mejorado
   */
  parseUserAgent(userAgent) {
    if (!userAgent) {
      return {
        browser: "Unknown",
        browserVersion: "Unknown",
        os: "Unknown",
        osVersion: "Unknown",
        device: "Unknown",
        deviceType: "unknown",
        isMobile: false,
        timezone: "UTC",
        language: "en",
      };
    }

    const isMobile = /mobile|android|iphone/i.test(userAgent);
    const isTablet = /tablet|ipad/i.test(userAgent);

    let browser = "Unknown";
    let browserVersion = "Unknown";
    let os = "Unknown";
    let osVersion = "Unknown";

    // Detectar navegador con versión
    if (userAgent.includes("Chrome")) {
      browser = "Chrome";
      const match = userAgent.match(/Chrome\/([0-9.]+)/);
      browserVersion = match ? match[1] : "Unknown";
    } else if (userAgent.includes("Firefox")) {
      browser = "Firefox";
      const match = userAgent.match(/Firefox\/([0-9.]+)/);
      browserVersion = match ? match[1] : "Unknown";
    } else if (userAgent.includes("Safari")) {
      browser = "Safari";
      const match = userAgent.match(/Version\/([0-9.]+)/);
      browserVersion = match ? match[1] : "Unknown";
    }

    // Detectar OS con versión
    if (userAgent.includes("Windows NT")) {
      os = "Windows";
      const match = userAgent.match(/Windows NT ([0-9.]+)/);
      osVersion = match ? match[1] : "Unknown";
    } else if (userAgent.includes("Mac OS X")) {
      os = "macOS";
      const match = userAgent.match(/Mac OS X ([0-9_]+)/);
      osVersion = match ? match[1].replace(/_/g, ".") : "Unknown";
    } else if (userAgent.includes("Android")) {
      os = "Android";
      const match = userAgent.match(/Android ([0-9.]+)/);
      osVersion = match ? match[1] : "Unknown";
    }

    return {
      browser,
      browserVersion,
      os,
      osVersion,
      device: isTablet ? "tablet" : isMobile ? "mobile" : "desktop",
      deviceType: isTablet ? "tablet" : isMobile ? "mobile" : "desktop",
      isMobile,
      userAgent,
      timezone: "UTC",
      language: "en",
    };
  }

  /**
   * Obtener ubicación desde IP (mejorado)
   */
  async getLocationFromIP(ipAddress) {
    try {
      if (
        !ipAddress ||
        ipAddress === "unknown" ||
        ipAddress.startsWith("127.") ||
        ipAddress.startsWith("192.168.")
      ) {
        return {
          country: "Unknown",
          countryName: "Unknown",
          city: "Unknown",
          region: "Unknown",
          coordinates: null,
          accuracy: "unknown",
        };
      }

      // TODO: Integrar con servicio de geolocalización real (MaxMind, IPStack, etc.)
      return {
        country: "Unknown",
        countryName: "Unknown",
        city: "Unknown",
        region: "Unknown",
        coordinates: null,
        accuracy: "city",
      };
    } catch (error) {
      console.error("Error obteniendo ubicación:", error);
      return {
        country: "Unknown",
        countryName: "Unknown",
        city: "Unknown",
        region: "Unknown",
        coordinates: null,
        accuracy: "unknown",
      };
    }
  }

  /**
   * Detectar VPN
   */
  async detectVPN(ipAddress) {
    try {
      // TODO: Integrar con servicio real de detección de VPN
      return false;
    } catch (error) {
      console.error("Error detectando VPN:", error);
      return false;
    }
  }

  /**
   * Detectar proxy
   */
  async detectProxy(ipAddress) {
    try {
      // TODO: Integrar con servicio real de detección de proxy
      return false;
    } catch (error) {
      console.error("Error detectando proxy:", error);
      return false;
    }
  }

  /**
   * Obtener ISP
   */
  async getISP(ipAddress) {
    try {
      // TODO: Integrar con servicio de geolocalización que incluya ISP
      return "Unknown ISP";
    } catch (error) {
      console.error("Error obteniendo ISP:", error);
      return "Unknown ISP";
    }
  }

  /**
   * Verificar si es país de la Unión Europea
   */
  isEuropeanUnion(countryCode) {
    const euCountries = [
      "AT",
      "BE",
      "BG",
      "HR",
      "CY",
      "CZ",
      "DK",
      "EE",
      "FI",
      "FR",
      "DE",
      "GR",
      "HU",
      "IE",
      "IT",
      "LV",
      "LT",
      "LU",
      "MT",
      "NL",
      "PL",
      "PT",
      "RO",
      "SK",
      "SI",
      "ES",
      "SE",
    ];

    return euCountries.includes(countryCode?.toUpperCase());
  }

  /**
   * Verificar cambio significativo de IP
   */
  isSignificantIPChange(oldIP, newIP) {
    if (!oldIP || !newIP) return false;

    // Si son IPs completamente diferentes
    if (oldIP !== newIP) {
      // Verificar si están en la misma subred
      const oldParts = oldIP.split(".").slice(0, 3).join(".");
      const newParts = newIP.split(".").slice(0, 3).join(".");

      // Si están en diferentes subredes /24, es significativo
      return oldParts !== newParts;
    }

    return false;
  }

  /**
   * Calcular similitud entre fingerprints
   */
  calculateFingerprintSimilarity(fp1, fp2) {
    if (!fp1 || !fp2) return 0;
    if (fp1 === fp2) return 1;

    // Implementación usando distancia de Levenshtein normalizada
    const maxLen = Math.max(fp1.length, fp2.length);
    const distance = this.levenshteinDistance(fp1, fp2);

    return Math.max(0, 1 - distance / maxLen);
  }

  /**
   * Calcular distancia de Levenshtein
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
   * Calcular score de riesgo
   */
  calculateRiskScore(activityType, severity) {
    const baseScores = {
      device_change: 30,
      location_change: 20,
      fingerprint_mismatch: 40,
      rapid_requests: 25,
      bot_detected: 60,
      brute_force: 80,
      unusual_access: 35,
      concurrent_session: 15,
    };

    const severityMultipliers = {
      low: 0.5,
      medium: 1,
      high: 1.5,
      critical: 2,
    };

    const baseScore = baseScores[activityType] || 10;
    const multiplier = severityMultipliers[severity] || 1;

    return Math.min(baseScore * multiplier, 100);
  }

  /**
   * Determinar acción automática
   */
  getAutomaticAction(severity) {
    switch (severity) {
      case "critical":
        return "terminate";
      case "high":
        return "block";
      case "medium":
        return "warn";
      default:
        return "none";
    }
  }

  /**
   * Sanitizar datos de sesión para respuesta
   */
  sanitizeSessionData(session) {
    const sanitized = { ...session };

    // Remover datos sensibles
    delete sanitized.accessTokenHash;
    delete sanitized.refreshTokenHash;
    delete sanitized.sessionToken; // NUNCA enviar el token de sesión

    // Limpiar OAuth data sensible
    if (sanitized.oauthSessionData) {
      delete sanitized.oauthSessionData.tokenHash;
      delete sanitized.oauthSessionData.refreshTokenHash;
    }

    // Simplificar actividad sospechosa
    if (sanitized.suspiciousActivity) {
      sanitized.suspiciousActivity = sanitized.suspiciousActivity.map(
        (activity) => ({
          activityType: activity.activityType,
          severity: activity.severity,
          timestamp: activity.timestamp,
          resolved: activity.resolved,
        })
      );
    }

    return sanitized;
  }
}
