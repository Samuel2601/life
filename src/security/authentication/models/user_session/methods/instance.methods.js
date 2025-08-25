// =============================================================================
// src/modules/authentication/models/user-session/methods/instance.methods.js
// Métodos de instancia para UserSession - operaciones sobre documentos individuales
// =============================================================================
import crypto from "crypto";

/**
 * Configurar métodos de instancia para UserSession
 *
 * @description Métodos que operan sobre instancias individuales de sesión
 * Incluye validaciones, cálculos de seguridad, y operaciones de estado
 *
 * @param {mongoose.Schema} schema - Schema de UserSession
 */
export const setupInstanceMethods = (schema) => {
  // ================================
  // MÉTODOS DE VALIDACIÓN DE SESIÓN
  // ================================

  /**
   * Verificar si la sesión ha expirado
   * @returns {boolean} true si la sesión ha expirado
   */
  schema.methods.isExpired = function () {
    return this.expiresAt < new Date();
  };

  /**
   * Verificar si necesita renovación pronto
   * @param {number} thresholdMinutes - Minutos antes de expiración para considerar renovación
   * @returns {boolean} true si necesita renovación
   */
  schema.methods.needsRenewal = function (thresholdMinutes = 60) {
    const renewalTime = new Date(
      this.expiresAt.getTime() - thresholdMinutes * 60 * 1000
    );
    return new Date() > renewalTime;
  };

  /**
   * Verificar si la sesión está activa y válida
   * @returns {boolean} true si la sesión es usable
   */
  schema.methods.isUsable = function () {
    return (
      this.isActive && this.isValid && !this.isCompromised && !this.isExpired()
    );
  };

  /**
   * Verificar si puede acceder desde la ubicación especificada
   * @param {string} country - Código de país ISO
   * @returns {boolean} true si puede acceder
   */
  schema.methods.canAccessFromLocation = function (country) {
    const policy = this.sessionPolicy;
    if (!policy?.allowedCountries?.length) return true;
    return policy.allowedCountries.includes(country);
  };

  /**
   * Verificar si puede acceder desde el tipo de dispositivo
   * @param {string} deviceType - Tipo de dispositivo
   * @returns {boolean} true si puede acceder
   */
  schema.methods.canAccessFromDevice = function (deviceType) {
    const policy = this.sessionPolicy;
    if (!policy?.allowedDeviceTypes?.length) return true;
    return policy.allowedDeviceTypes.includes(deviceType);
  };

  // ================================
  // MÉTODOS DE GESTIÓN DE ESTADO
  // ================================

  /**
   * Marcar sesión como comprometida
   * @param {string} reason - Razón del compromiso
   * @returns {Promise} Promesa de guardado
   */
  schema.methods.markAsCompromised = function (reason = "security_breach") {
    console.log(`⚠️ Marcando sesión ${this._id} como comprometida: ${reason}`);

    this.isCompromised = true;
    this.compromisedAt = new Date();
    this.isActive = false;
    this.isValid = false;
    this.invalidationReason = reason;

    // Registrar como actividad crítica
    this.logSuspiciousActivity(
      "security_breach",
      `Sesión marcada como comprometida: ${reason}`,
      "critical",
      { compromiseReason: reason }
    );

    return this.save();
  };

  /**
   * Invalidar sesión
   * @param {string} reason - Razón de invalidación
   * @returns {Promise} Promesa de guardado
   */
  schema.methods.invalidate = function (reason = "user_logout") {
    console.log(`🔒 Invalidando sesión ${this._id}: ${reason}`);

    this.isActive = false;
    this.isValid = false;
    this.invalidationReason = reason;

    return this.save();
  };

  /**
   * Extender sesión
   * @param {number} additionalHours - Horas adicionales
   * @returns {Promise} Promesa de guardado
   */
  schema.methods.extendSession = function (additionalHours = 2) {
    if (!this.isUsable()) {
      throw new Error("No se puede extender una sesión no válida");
    }

    const newExpiration = new Date(
      this.expiresAt.getTime() + additionalHours * 60 * 60 * 1000
    );

    console.log(`⏰ Extendiendo sesión ${this._id} hasta ${newExpiration}`);

    this.expiresAt = newExpiration;
    this.lastAccessedAt = new Date();

    return this.save();
  };

  /**
   * Actualizar última actividad
   * @returns {Promise} Promesa de guardado
   */
  schema.methods.updateActivity = function () {
    this.lastAccessedAt = new Date();
    this.metadata.totalRequests = (this.metadata.totalRequests || 0) + 1;
    this.metadata.lastRequestAt = new Date();
    this.metadata.businessMetrics.apiCallsCount =
      (this.metadata.businessMetrics.apiCallsCount || 0) + 1;

    return this.save();
  };

  // ================================
  // MÉTODOS DE SEGURIDAD Y DETECCIÓN
  // ================================

  /**
   * Registrar actividad sospechosa
   * @param {string} type - Tipo de actividad sospechosa
   * @param {string} description - Descripción de la actividad
   * @param {string} severity - Nivel de severidad
   * @param {Object} additionalData - Datos adicionales
   * @returns {Promise} Promesa de guardado
   */
  schema.methods.logSuspiciousActivity = function (
    type,
    description,
    severity = "medium",
    additionalData = null
  ) {
    const activity = {
      activityType: type,
      description: description,
      severity: severity,
      timestamp: new Date(),
      additionalData: additionalData,
      riskScore: this.calculateRiskScore(type, severity),
      automaticAction: this.getAutomaticAction(severity),
    };

    this.suspiciousActivity.push(activity);

    console.log(
      `🚨 Actividad sospechosa en sesión ${this._id}: ${type} (${severity})`
    );

    // Auto-marcar como comprometida si hay actividad crítica
    if (severity === "critical" && !this.isCompromised) {
      return this.markAsCompromised("suspicious_activity");
    }

    return this.save();
  };

  /**
   * Registrar cambio de fingerprint
   * @param {string} newFingerprint - Nuevo fingerprint
   * @param {Array} changedComponents - Componentes que cambiaron
   * @returns {Promise} Promesa de guardado
   */
  schema.methods.logFingerprintChange = function (
    newFingerprint,
    changedComponents = []
  ) {
    if (!newFingerprint || newFingerprint === this.deviceFingerprint) {
      return Promise.resolve(this);
    }

    const previousFingerprint = this.deviceFingerprint;

    // Calcular similitud
    const similarityScore = this.calculateFingerprintSimilarity(
      previousFingerprint,
      newFingerprint
    );

    // Determinar tipo de cambio basado en componentes y similitud
    let changeType = "minor";
    let suspicious = false;
    let autoBlock = false;

    if (similarityScore < 0.3) {
      changeType = "critical";
      suspicious = true;
      autoBlock = true;
    } else if (similarityScore < 0.6 || changedComponents.length > 3) {
      changeType = "major";
      suspicious = true;
    } else if (
      changedComponents.some((c) =>
        ["userAgent", "screen", "timezone"].includes(c.component)
      )
    ) {
      changeType = "suspicious";
      suspicious = true;
    }

    const fingerprintChange = {
      newFingerprint: newFingerprint,
      previousFingerprint: previousFingerprint,
      changeType: changeType,
      suspiciousChange: suspicious,
      changedComponents: changedComponents,
      similarityScore: similarityScore,
      autoBlocked: autoBlock,
    };

    this.fingerprintChanges.push(fingerprintChange);
    this.deviceFingerprint = newFingerprint;

    console.log(
      `🔍 Cambio de fingerprint en sesión ${this._id}: ${changeType} (similitud: ${similarityScore})`
    );

    // Registrar actividad sospechosa si el cambio es significativo
    if (suspicious) {
      this.logSuspiciousActivity(
        "fingerprint_mismatch",
        `Cambio ${changeType} en device fingerprint: ${changedComponents.map((c) => c.component).join(", ")}`,
        changeType === "critical" ? "critical" : "high",
        { changedComponents, similarityScore, autoBlocked: autoBlock }
      );
    }

    return this.save();
  };

  /**
   * Validar cambio de ubicación
   * @param {Object} newLocation - Nueva ubicación
   * @returns {Promise} Promesa de guardado
   */
  schema.methods.validateLocationChange = function (newLocation) {
    if (!this.location || !newLocation) return Promise.resolve(this);

    const oldLocation = this.location;
    let suspicious = false;
    let severity = "low";

    // Cambio de país es sospechoso
    if (oldLocation.country !== newLocation.country) {
      suspicious = true;
      severity = "medium";

      // Cambio a país no permitido es crítico
      if (!this.canAccessFromLocation(newLocation.country)) {
        severity = "critical";
      }
    }

    // Cambio de continente es muy sospechoso
    if (this.isDifferentContinent(oldLocation, newLocation)) {
      suspicious = true;
      severity = "high";
    }

    if (suspicious) {
      return this.logSuspiciousActivity(
        "location_change",
        `Cambio de ubicación: ${oldLocation.country} → ${newLocation.country}`,
        severity,
        { oldLocation, newLocation }
      );
    }

    return Promise.resolve(this);
  };

  // ================================
  // MÉTODOS DE CÁLCULO Y ANÁLISIS
  // ================================

  /**
   * Calcular score de riesgo para una actividad
   * @param {string} activityType - Tipo de actividad
   * @param {string} severity - Severidad
   * @returns {number} Score de riesgo (0-100)
   */
  schema.methods.calculateRiskScore = function (activityType, severity) {
    const baseScores = {
      device_change: 30,
      location_change: 20,
      fingerprint_mismatch: 40,
      rapid_requests: 25,
      bot_detected: 60,
      brute_force: 80,
      privilege_escalation: 90,
      unusual_access: 35,
      concurrent_session: 15,
      unusual_timing: 20,
      ip_change: 25,
      scraping_attempt: 70,
      security_breach: 100,
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
  };

  /**
   * Determinar acción automática basada en severidad
   * @param {string} severity - Nivel de severidad
   * @returns {string} Acción a tomar
   */
  schema.methods.getAutomaticAction = function (severity) {
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
  };

  /**
   * Calcular similitud entre fingerprints
   * @param {string} fp1 - Primer fingerprint
   * @param {string} fp2 - Segundo fingerprint
   * @returns {number} Similitud (0-1)
   */
  schema.methods.calculateFingerprintSimilarity = function (fp1, fp2) {
    if (!fp1 || !fp2) return 0;
    if (fp1 === fp2) return 1;

    // Implementación usando distancia de Hamming
    if (fp1.length !== fp2.length) return 0;

    let matches = 0;
    for (let i = 0; i < fp1.length; i++) {
      if (fp1[i] === fp2[i]) {
        matches++;
      }
    }

    return matches / fp1.length;
  };

  /**
   * Verificar si dos ubicaciones están en continentes diferentes
   * @param {Object} loc1 - Primera ubicación
   * @param {Object} loc2 - Segunda ubicación
   * @returns {boolean} true si están en continentes diferentes
   */
  schema.methods.isDifferentContinent = function (loc1, loc2) {
    const continentMap = {
      US: "North America",
      CA: "North America",
      MX: "North America",
      BR: "South America",
      AR: "South America",
      PE: "South America",
      GB: "Europe",
      DE: "Europe",
      FR: "Europe",
      ES: "Europe",
      CN: "Asia",
      JP: "Asia",
      IN: "Asia",
      KR: "Asia",
      AU: "Oceania",
      NZ: "Oceania",
      EG: "Africa",
      ZA: "Africa",
      NG: "Africa",
    };

    const continent1 = continentMap[loc1.country] || "Unknown";
    const continent2 = continentMap[loc2.country] || "Unknown";

    return (
      continent1 !== continent2 &&
      continent1 !== "Unknown" &&
      continent2 !== "Unknown"
    );
  };

  // ================================
  // MÉTODOS DE BUSINESS METRICS
  // ================================

  /**
   * Agregar empresa accedida a las métricas
   * @param {string} companyId - ID de la empresa
   */
  schema.methods.addCompanyAccessed = function (companyId) {
    if (!this.metadata.businessMetrics.companiesAccessed.includes(companyId)) {
      this.metadata.businessMetrics.companiesAccessed.push(companyId);
    }
  };

  /**
   * Agregar funcionalidad utilizada
   * @param {string} feature - Nombre de la funcionalidad
   */
  schema.methods.addFeatureUsed = function (feature) {
    if (!this.metadata.businessMetrics.featuresUsed.includes(feature)) {
      this.metadata.businessMetrics.featuresUsed.push(feature);
    }
  };

  /**
   * Actualizar tiempo promedio de respuesta
   * @param {number} responseTime - Tiempo de respuesta en ms
   */
  schema.methods.updateAvgResponseTime = function (responseTime) {
    const current = this.metadata.businessMetrics.avgResponseTime || 0;
    const requests = this.metadata.totalRequests || 1;

    // Calcular promedio móvil
    this.metadata.businessMetrics.avgResponseTime =
      (current * (requests - 1) + responseTime) / requests;
  };

  // ================================
  // MÉTODOS DE INFORMACIÓN Y RESUMEN
  // ================================

  /**
   * Obtener resumen de la sesión para logs
   * @returns {string} Resumen de la sesión
   */
  schema.methods.getSummary = function () {
    const device = this.deviceInfo?.deviceType || "unknown";
    const browser = this.deviceInfo?.browser || "unknown";
    const location = this.location?.country || "unknown";
    const duration = this.currentDurationMinutes || 0;

    return `Session ${this._id.toString().substring(0, 8)}... - ${device}/${browser} from ${location} (${duration}min)`;
  };

  /**
   * Obtener información de auditoría
   * @returns {Object} Información de auditoría
   */
  schema.methods.getAuditInfo = function () {
    return {
      sessionId: this._id,
      userId: this.userId,
      createdAt: this.createdAt,
      lastAccessedAt: this.lastAccessedAt,
      ipAddress: this.ipAddress,
      deviceSummary: this.deviceSummary,
      locationSummary: this.locationSummary,
      totalRequests: this.metadata?.totalRequests || 0,
      suspiciousActivities: (this.suspiciousActivity || []).length,
      fingerprintChanges: (this.fingerprintChanges || []).length,
      riskLevel: this.riskLevel,
      isCompromised: this.isCompromised,
      invalidationReason: this.invalidationReason,
    };
  };

  /**
   * Obtener estadísticas de actividad
   * @returns {Object} Estadísticas de la sesión
   */
  schema.methods.getActivityStats = function () {
    return {
      totalRequests: this.metadata?.totalRequests || 0,
      apiCalls: this.metadata?.businessMetrics?.apiCallsCount || 0,
      avgResponseTime: this.metadata?.businessMetrics?.avgResponseTime || 0,
      companiesAccessed: (
        this.metadata?.businessMetrics?.companiesAccessed || []
      ).length,
      featuresUsed: (this.metadata?.businessMetrics?.featuresUsed || []).length,
      durationMinutes: this.currentDurationMinutes || 0,
      securityEvents: (this.suspiciousActivity || []).length,
      fingerprintChanges: (this.fingerprintChanges || []).length,
    };
  };

  // ================================
  // MÉTODOS DE VALIDACIÓN AVANZADA
  // ================================

  /**
   * Validar integridad de la sesión
   * @returns {Object} Resultado de validación
   */
  schema.methods.validateIntegrity = function () {
    const issues = [];

    // Validar timestamps
    if (this.lastAccessedAt < this.createdAt) {
      issues.push("lastAccessedAt anterior a createdAt");
    }

    if (this.expiresAt <= this.createdAt) {
      issues.push("expiresAt no es posterior a createdAt");
    }

    // Validar fingerprints
    if (!this.deviceFingerprint || this.deviceFingerprint.length !== 64) {
      issues.push("deviceFingerprint inválido");
    }

    if (!this.originalFingerprint || this.originalFingerprint.length !== 64) {
      issues.push("originalFingerprint inválido");
    }

    // Validar OAuth consistency
    if (this.oauthProvider && !this.oauthSessionData) {
      issues.push("OAuth provider sin OAuth session data");
    }

    if (this.oauthSessionData && !this.oauthProvider) {
      issues.push("OAuth session data sin OAuth provider");
    }

    // Validar estados lógicos
    if (this.isCompromised && (this.isActive || this.isValid)) {
      issues.push("Sesión comprometida pero activa o válida");
    }

    return {
      isValid: issues.length === 0,
      issues: issues,
    };
  };

  console.log("✅ Métodos de instancia aplicados al UserSession schema");
};

// ================================
// EXPORTAR CONFIGURACIÓN
// ================================

export default setupInstanceMethods;

// Información de debugging
export const InstanceMethodsInfo = {
  methodCount: 25,
  categories: [
    "validation",
    "state-management",
    "security-detection",
    "calculation-analysis",
    "business-metrics",
    "information-summary",
    "advanced-validation",
  ],
  features: [
    "session-expiration-check",
    "suspicious-activity-logging",
    "fingerprint-change-tracking",
    "location-validation",
    "risk-score-calculation",
    "business-metrics-tracking",
    "audit-trail-generation",
  ],
};
