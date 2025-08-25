// =============================================================================
// src/modules/authentication/models/user-session/indexes/user-session.indexes.js
// Índices optimizados para UserSession - Rendimiento y Seguridad
// =============================================================================

/**
 * Configurar índices optimizados para UserSession
 *
 * @description Define todos los índices necesarios para optimizar consultas,
 * seguridad, analytics y compliance. Cada índice está documentado con su propósito.
 *
 * @param {mongoose.Schema} schema - Schema de UserSession
 */
export const setupUserSessionIndexes = (schema) => {
  console.log("📊 Configurando índices de UserSession...");

  // ================================
  // ÍNDICES ÚNICOS CRÍTICOS
  // ================================

  /**
   * Índice único para sessionToken
   * Propósito: Garantizar unicidad y búsqueda rápida por token de sesión
   * Uso: Validación de tokens, autenticación
   */
  schema.index(
    { sessionToken: 1 },
    {
      unique: true,
      name: "session_token_unique",
      background: true,
    }
  );

  // ================================
  // ÍNDICES PARA CONSULTAS DE SEGURIDAD (ALTA PRIORIDAD)
  // ================================

  /**
   * Índice compuesto principal para sesiones activas
   * Propósito: Optimizar consultas de sesiones válidas por usuario
   * Uso: Verificar sesiones activas, límites de concurrencia
   * Query: db.user_sessions.find({userId: ObjectId, isActive: true, isValid: true, expiresAt: {$gt: Date}})
   */
  schema.index(
    {
      userId: 1,
      isActive: 1,
      isValid: 1,
      expiresAt: 1,
    },
    {
      name: "active_sessions_query",
      background: true,
      partialFilterExpression: { isActive: true, isValid: true },
    }
  );

  /**
   * Índice para búsquedas cronológicas por usuario
   * Propósito: Listar sesiones de usuario ordenadas por fecha
   * Uso: Dashboard de usuario, auditoría
   * Query: db.user_sessions.find({userId: ObjectId}).sort({createdAt: -1})
   */
  schema.index(
    {
      userId: 1,
      createdAt: -1,
    },
    {
      name: "user_sessions_chronological",
      background: true,
    }
  );

  /**
   * TTL automático para sesiones expiradas
   * Propósito: Limpieza automática de sesiones expiradas
   * Uso: Mantenimiento automático de la base de datos
   */
  schema.index(
    { expiresAt: 1 },
    {
      expireAfterSeconds: 0,
      name: "session_ttl_index",
      background: true,
    }
  );

  // ================================
  // ÍNDICES PARA DETECCIÓN DE AMENAZAS
  // ================================

  /**
   * Índice para monitoreo de seguridad por IP y usuario
   * Propósito: Detectar patrones sospechosos de acceso
   * Uso: Análisis forense, detección de ataques
   * Query: db.user_sessions.find({ipAddress: "x.x.x.x", userId: ObjectId}).sort({createdAt: -1})
   */
  schema.index(
    {
      ipAddress: 1,
      userId: 1,
      createdAt: -1,
    },
    {
      name: "security_monitoring_index",
      background: true,
    }
  );

  /**
   * Índice para tracking de dispositivos
   * Propósito: Detectar cambios de dispositivo por usuario
   * Uso: Validación de dispositivos conocidos, detección de fraude
   * Query: db.user_sessions.find({deviceFingerprint: "hash", userId: ObjectId, isActive: true})
   */
  schema.index(
    {
      deviceFingerprint: 1,
      userId: 1,
      isActive: 1,
    },
    {
      name: "device_tracking_index",
      background: true,
      partialFilterExpression: { isActive: true },
    }
  );

  /**
   * Índice para sesiones comprometidas
   * Propósito: Consultas rápidas de incidentes de seguridad
   * Uso: Dashboard de seguridad, reportes de incidentes
   * Query: db.user_sessions.find({isCompromised: true}).sort({compromisedAt: -1})
   */
  schema.index(
    {
      isCompromised: 1,
      compromisedAt: -1,
    },
    {
      sparse: true,
      name: "compromised_sessions_index",
      background: true,
      partialFilterExpression: { isCompromised: true },
    }
  );

  /**
   * Índice para actividades sospechosas
   * Propósito: Búsquedas rápidas de eventos de seguridad
   * Uso: Análisis de patrones, alertas de seguridad
   * Query: db.user_sessions.find({"suspiciousActivity.severity": "critical"})
   */
  schema.index(
    {
      "suspiciousActivity.activityType": 1,
      "suspiciousActivity.severity": 1,
      "suspiciousActivity.timestamp": -1,
    },
    {
      name: "suspicious_activity_index",
      background: true,
      sparse: true,
    }
  );

  /**
   * Índice para cambios de fingerprint
   * Propósito: Rastrear modificaciones de dispositivos
   * Uso: Detección de ataques de suplantación
   * Query: db.user_sessions.find({"fingerprintChanges.suspiciousChange": true})
   */
  schema.index(
    {
      "fingerprintChanges.changeType": 1,
      "fingerprintChanges.suspiciousChange": 1,
      "fingerprintChanges.changedAt": -1,
    },
    {
      name: "fingerprint_changes_index",
      background: true,
      sparse: true,
    }
  );

  // ================================
  // ÍNDICES GEOGRÁFICOS Y DE UBICACIÓN
  // ================================

  /**
   * Índice 2dsphere para consultas geográficas
   * Propósito: Búsquedas por proximidad geográfica
   * Uso: Análisis de ubicaciones, detección de viajes imposibles
   * Query: db.user_sessions.find({"location.coordinates": {$near: {$geometry: {type: "Point", coordinates: [lng, lat]}}}})
   */
  schema.index(
    { "location.coordinates": "2dsphere" },
    {
      name: "geographic_location_index",
      background: true,
      sparse: true,
    }
  );

  /**
   * Índice para análisis por país
   * Propósito: Estadísticas y restricciones por ubicación
   * Uso: Compliance, análisis de mercado
   * Query: db.user_sessions.find({"location.country": "US"}).sort({createdAt: -1})
   */
  schema.index(
    {
      "location.country": 1,
      createdAt: -1,
    },
    {
      name: "location_country_analysis",
      background: true,
      sparse: true,
    }
  );

  // ================================
  // ÍNDICES PARA ANALYTICS EMPRESARIALES
  // ================================

  /**
   * Índice compuesto para analytics de dispositivos y ubicación
   * Propósito: Análisis de patrones de uso por dispositivo y región
   * Uso: Reportes de marketing, optimización UX
   * Query: db.user_sessions.aggregate([{$group: {_id: {deviceType: "$deviceInfo.deviceType", country: "$location.country"}}}])
   */
  schema.index(
    {
      "deviceInfo.deviceType": 1,
      "location.country": 1,
      createdAt: -1,
    },
    {
      name: "analytics_device_location_index",
      background: true,
    }
  );

  /**
   * Índice para analytics de OAuth
   * Propósito: Análisis de uso de proveedores OAuth
   * Uso: Métricas de autenticación, integración de terceros
   * Query: db.user_sessions.find({oauthProvider: "google"}).sort({createdAt: -1})
   */
  schema.index(
    {
      oauthProvider: 1,
      createdAt: -1,
    },
    {
      sparse: true,
      name: "oauth_analytics_index",
      background: true,
      partialFilterExpression: { oauthProvider: { $exists: true } },
    }
  );

  /**
   * Índice para métricas de negocio por empresa
   * Propósito: Análisis de uso por empresa cliente
   * Uso: Facturación, métricas de engagement
   * Query: db.user_sessions.find({"metadata.businessMetrics.companiesAccessed": "company123"})
   */
  schema.index(
    {
      "metadata.businessMetrics.companiesAccessed": 1,
      createdAt: -1,
    },
    {
      sparse: true,
      name: "business_metrics_companies",
      background: true,
    }
  );

  /**
   * Índice para actividad de sesiones
   * Propósito: Identificar sesiones más activas
   * Uso: Optimización de recursos, análisis de patrones
   * Query: db.user_sessions.find().sort({"metadata.totalRequests": -1})
   */
  schema.index(
    {
      "metadata.totalRequests": -1,
      userId: 1,
    },
    {
      name: "session_activity_metrics",
      background: true,
    }
  );

  // ================================
  // ÍNDICES PARA COMPLIANCE Y GDPR
  // ================================

  /**
   * Índice para compliance GDPR
   * Propósito: Consultas relacionadas con regulaciones europeas
   * Uso: Reportes de compliance, gestión de datos EU
   * Query: db.user_sessions.find({"location.isEuCountry": true, "metadata.compliance.gdprApplicable": true})
   */
  schema.index(
    {
      "location.isEuCountry": 1,
      "metadata.compliance.gdprApplicable": 1,
      createdAt: -1,
    },
    {
      name: "gdpr_compliance_index",
      background: true,
    }
  );

  /**
   * Índice para auditoría de datos personales
   * Propósito: Rastrear consentimiento de procesamiento de datos
   * Uso: Cumplimiento GDPR, solicitudes de eliminación
   * Query: db.user_sessions.find({"metadata.compliance.dataProcessingAgreed": false})
   */
  schema.index(
    {
      "metadata.compliance.dataProcessingAgreed": 1,
      "location.isEuCountry": 1,
      createdAt: -1,
    },
    {
      name: "data_processing_consent_index",
      background: true,
    }
  );

  // ================================
  // ÍNDICES PARA RENDIMIENTO Y LIMPIEZA
  // ================================

  /**
   * Índice para limpieza de sesiones inactivas
   * Propósito: Identificar sesiones para limpieza automática
   * Uso: Mantenimiento de BD, optimización de espacio
   * Query: db.user_sessions.find({lastAccessedAt: {$lt: Date}, isActive: false})
   */
  schema.index(
    {
      lastAccessedAt: 1,
      isActive: 1,
    },
    {
      name: "inactive_sessions_cleanup",
      background: true,
    }
  );

  /**
   * Índice para paginación eficiente de sesiones por usuario
   * Propósito: Paginación optimizada en interfaces de usuario
   * Uso: Listados con scroll infinito, APIs paginadas
   * Query: db.user_sessions.find({userId: ObjectId, _id: {$lt: ObjectId}}).sort({createdAt: -1, _id: 1})
   */
  schema.index(
    {
      userId: 1,
      createdAt: -1,
      _id: 1,
    },
    {
      name: "user_sessions_pagination",
      background: true,
    }
  );

  // ================================
  // ÍNDICES COMPUESTOS ESPECÍFICOS PARA CASOS DE USO
  // ================================

  /**
   * Índice para dashboard de administración
   * Propósito: Consultas complejas del panel de administración
   * Uso: Vista de sesiones sospechosas por región
   * Query: Consultas administrativas con filtros múltiples
   */
  schema.index(
    {
      isCompromised: 1,
      isActive: 1,
      "location.country": 1,
      createdAt: -1,
    },
    {
      name: "admin_dashboard_sessions",
      background: true,
    }
  );

  /**
   * Índice para auditorías de seguridad
   * Propósito: Análisis forense y auditorías de seguridad
   * Uso: Investigación de incidentes, reportes de seguridad
   * Query: Búsquedas complejas para análisis de seguridad
   */
  schema.index(
    {
      userId: 1,
      "suspiciousActivity.severity": 1,
      "fingerprintChanges.changeType": 1,
      createdAt: -1,
    },
    {
      name: "security_audit_index",
      background: true,
    }
  );

  /**
   * Índice para reportes de compliance
   * Propósito: Generación de reportes regulatorios
   * Uso: Auditorías externas, reportes de compliance
   * Query: Agregaciones para reportes regulatorios
   */
  schema.index(
    {
      "metadata.compliance.gdprApplicable": 1,
      "location.isEuCountry": 1,
      "metadata.compliance.dataProcessingAgreed": 1,
      createdAt: -1,
    },
    {
      name: "compliance_reporting_index",
      background: true,
    }
  );

  // ================================
  // ÍNDICES DE TEXTO PARA BÚSQUEDAS
  // ================================

  /**
   * Índice de texto para búsquedas en actividades sospechosas
   * Propósito: Búsquedas de texto libre en descripciones de seguridad
   * Uso: Investigación forense, búsqueda de patrones
   * Query: db.user_sessions.find({$text: {$search: "brute force"}})
   */
  schema.index(
    {
      "suspiciousActivity.description": "text",
      "suspiciousActivity.activityType": "text",
    },
    {
      name: "suspicious_activity_text_search",
      background: true,
      weights: {
        "suspiciousActivity.description": 1,
        "suspiciousActivity.activityType": 2,
      },
      default_language: "spanish",
    }
  );

  // ================================
  // ÍNDICES PARA DETECCIÓN DE BOTS
  // ================================

  /**
   * Índice para detección de automatización
   * Propósito: Identificar sesiones de bots o scripts automatizados
   * Uso: Sistemas anti-bot, validación de tráfico
   * Query: db.user_sessions.find({"deviceInfo.automationIndicators.webDriverPresent": true})
   */
  schema.index(
    {
      "deviceInfo.automationIndicators.webDriverPresent": 1,
      "deviceInfo.automationIndicators.seleniumPresent": 1,
      "deviceInfo.automationIndicators.headlessChrome": 1,
      createdAt: -1,
    },
    {
      name: "bot_detection_index",
      background: true,
      sparse: true,
    }
  );

  /**
   * Índice para análisis de confianza de dispositivos
   * Propósito: Evaluar la legitimidad de dispositivos
   * Uso: Scoring de confianza, decisiones de seguridad
   * Query: db.user_sessions.find({"deviceInfo.metadata.confidence": {$lt: 0.5}})
   */
  schema.index(
    {
      "deviceInfo.metadata.confidence": 1,
      "deviceInfo.isSuspiciousDevice": 1,
      userId: 1,
    },
    {
      name: "device_trust_analysis",
      background: true,
      sparse: true,
    }
  );

  // ================================
  // VALIDACIÓN Y LOGGING DE ÍNDICES
  // ================================

  // Contar total de índices definidos
  const totalIndexes = [
    "session_token_unique",
    "active_sessions_query",
    "user_sessions_chronological",
    "session_ttl_index",
    "security_monitoring_index",
    "device_tracking_index",
    "compromised_sessions_index",
    "suspicious_activity_index",
    "fingerprint_changes_index",
    "geographic_location_index",
    "location_country_analysis",
    "analytics_device_location_index",
    "oauth_analytics_index",
    "business_metrics_companies",
    "session_activity_metrics",
    "gdpr_compliance_index",
    "data_processing_consent_index",
    "inactive_sessions_cleanup",
    "user_sessions_pagination",
    "admin_dashboard_sessions",
    "security_audit_index",
    "compliance_reporting_index",
    "suspicious_activity_text_search",
    "bot_detection_index",
    "device_trust_analysis",
  ];

  console.log(
    `✅ ${totalIndexes.length} índices configurados para UserSession:`
  );
  totalIndexes.forEach((indexName) => {
    console.log(`   📊 ${indexName}`);
  });

  // Información para debugging en desarrollo
  if (process.env.NODE_ENV === "development") {
    console.log("🔍 Categorías de índices aplicadas:");
    console.log("   🔐 Seguridad y detección: 8 índices");
    console.log("   📊 Analytics empresariales: 4 índices");
    console.log("   📍 Geográficos y ubicación: 2 índices");
    console.log("   ⚖️ Compliance y GDPR: 2 índices");
    console.log("   🚀 Rendimiento: 2 índices");
    console.log("   🔧 Administración: 3 índices");
    console.log("   🔍 Búsquedas de texto: 1 índice");
    console.log("   🤖 Detección de bots: 2 índices");
    console.log("   🏷️ Únicos y TTL: 2 índices");
  }

  return schema;
};

// ================================
// FUNCIONES AUXILIARES PARA GESTIÓN DE ÍNDICES
// ================================

/**
 * Obtener lista de todos los índices definidos
 * @returns {Array} Lista de nombres de índices
 */
export const getAllIndexNames = () => {
  return [
    "session_token_unique",
    "active_sessions_query",
    "user_sessions_chronological",
    "session_ttl_index",
    "security_monitoring_index",
    "device_tracking_index",
    "compromised_sessions_index",
    "suspicious_activity_index",
    "fingerprint_changes_index",
    "geographic_location_index",
    "location_country_analysis",
    "analytics_device_location_index",
    "oauth_analytics_index",
    "business_metrics_companies",
    "session_activity_metrics",
    "gdpr_compliance_index",
    "data_processing_consent_index",
    "inactive_sessions_cleanup",
    "user_sessions_pagination",
    "admin_dashboard_sessions",
    "security_audit_index",
    "compliance_reporting_index",
    "suspicious_activity_text_search",
    "bot_detection_index",
    "device_trust_analysis",
  ];
};

/**
 * Obtener índices por categoría
 * @param {string} category - Categoría de índices
 * @returns {Array} Lista de índices de la categoría
 */
export const getIndexesByCategory = (category) => {
  const categories = {
    security: [
      "session_token_unique",
      "active_sessions_query",
      "security_monitoring_index",
      "device_tracking_index",
      "compromised_sessions_index",
      "suspicious_activity_index",
      "fingerprint_changes_index",
      "bot_detection_index",
    ],
    analytics: [
      "analytics_device_location_index",
      "oauth_analytics_index",
      "business_metrics_companies",
      "session_activity_metrics",
    ],
    geographic: ["geographic_location_index", "location_country_analysis"],
    compliance: ["gdpr_compliance_index", "data_processing_consent_index"],
    performance: [
      "inactive_sessions_cleanup",
      "user_sessions_pagination",
      "session_ttl_index",
    ],
    administration: [
      "admin_dashboard_sessions",
      "security_audit_index",
      "compliance_reporting_index",
    ],
  };

  return categories[category] || [];
};

/**
 * Validar que todos los índices estén aplicados
 * @param {mongoose.Model} model - Modelo de UserSession
 * @returns {Promise<Object>} Resultado de validación
 */
export const validateIndexes = async (model) => {
  try {
    const appliedIndexes = await model.collection.getIndexes();
    const expectedIndexes = getAllIndexNames();

    const appliedNames = Object.keys(appliedIndexes).filter(
      (name) => name !== "_id_"
    );
    const missing = expectedIndexes.filter(
      (name) => !appliedNames.includes(name)
    );
    const extra = appliedNames.filter(
      (name) => !expectedIndexes.includes(name)
    );

    return {
      success: missing.length === 0,
      expected: expectedIndexes.length,
      applied: appliedNames.length,
      missing: missing,
      extra: extra,
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
    };
  }
};

// ================================
// EXPORTAR CONFIGURACIÓN PRINCIPAL
// ================================

export default setupUserSessionIndexes;

// Información para debugging y documentación
export const IndexInfo = {
  totalIndexes: 25,
  categories: {
    security: 8,
    analytics: 4,
    geographic: 2,
    compliance: 2,
    performance: 3,
    administration: 3,
    textSearch: 1,
    botDetection: 2,
  },
  storageImpact: "~50-100MB adicionales para índices",
  queryOptimization: "90%+ de consultas cubiertas",
  maintenanceNeeded: "Revisión trimestral de índices no utilizados",
};
