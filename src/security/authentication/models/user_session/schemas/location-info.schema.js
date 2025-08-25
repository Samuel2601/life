// =============================================================================
// src/modules/authentication/models/user-session/schemas/location-info.schema.js
// Información de ubicación mejorada para plataforma empresarial
// =============================================================================
import mongoose from "mongoose";

/**
 * Schema para información de ubicación (mejorado para plataforma empresarial)
 *
 * @description Almacena información detallada de geolocalización incluyendo
 * detección de VPN/Proxy, compliance GDPR, y análisis geográficos
 */
export const LocationInfoSchema = new mongoose.Schema(
  {
    // ================================
    // INFORMACIÓN GEOGRÁFICA BÁSICA
    // ================================
    country: {
      type: String,
      maxlength: 2, // Código ISO de país (ej: "PE", "US")
      uppercase: true,
      index: true, // Para analytics por país
      validate: {
        validator: function (v) {
          return !v || /^[A-Z]{2}$/.test(v);
        },
        message:
          "Código de país debe ser ISO 3166-1 alpha-2 (2 letras mayúsculas)",
      },
    },

    countryName: {
      type: String,
      maxlength: 100,
      trim: true,
    },

    city: {
      type: String,
      maxlength: 100,
      trim: true,
      index: true, // Para analytics por ciudad
    },

    region: {
      type: String,
      maxlength: 100,
      trim: true,
      index: true, // Para analytics por región
    },

    // Subdivisión administrativa (estado, provincia, etc.)
    subdivision: {
      type: String,
      maxlength: 100,
      trim: true,
    },

    // Código postal si está disponible
    postalCode: {
      type: String,
      maxlength: 20,
      trim: true,
    },

    // ================================
    // COORDENADAS GEOGRÁFICAS
    // ================================
    coordinates: {
      type: [Number], // [longitude, latitude] - Formato GeoJSON
      index: "2dsphere", // Para búsquedas geográficas
      validate: {
        validator: function (coords) {
          return (
            !coords ||
            coords.length === 0 ||
            (coords.length === 2 &&
              coords[0] >= -180 &&
              coords[0] <= 180 &&
              coords[1] >= -90 &&
              coords[1] <= 90)
          );
        },
        message: "Coordenadas inválidas. Formato: [longitude, latitude]",
      },
    },

    // Precisión de la geolocalización
    accuracy: {
      type: Number,
      min: 0,
      max: 50000, // 50km máximo de precisión
    },

    // ================================
    // DETECCIÓN DE VPN Y PROXY
    // ================================
    isVpnDetected: {
      type: Boolean,
      default: false,
      index: true, // Para filtrar VPNs
    },

    vpnProvider: {
      type: String,
      maxlength: 100,
      trim: true,
    },

    vpnConfidence: {
      type: Number,
      min: 0,
      max: 1,
      default: 0,
    },

    isProxy: {
      type: Boolean,
      default: false,
      index: true, // Para filtrar proxies
    },

    proxyType: {
      type: String,
      enum: [
        "http",
        "https",
        "socks4",
        "socks5",
        "transparent",
        "anonymous",
        "elite",
        "unknown",
      ],
    },

    // Detectar Tor
    isTorExit: {
      type: Boolean,
      default: false,
      index: true,
    },

    // ================================
    // INFORMACIÓN DEL PROVEEDOR DE INTERNET
    // ================================
    isp: {
      type: String,
      maxlength: 200,
      trim: true,
      index: true, // Para analytics de proveedores
    },

    // Autonomous System Number
    asn: {
      type: String,
      maxlength: 20,
      validate: {
        validator: function (v) {
          return !v || /^AS\d+$/i.test(v);
        },
        message: "ASN debe tener formato AS#### (ej: AS15169)",
      },
    },

    asnOrganization: {
      type: String,
      maxlength: 200,
      trim: true,
    },

    // Tipo de conexión
    connectionType: {
      type: String,
      enum: [
        "residential",
        "business",
        "hosting",
        "mobile",
        "satellite",
        "unknown",
      ],
      default: "unknown",
    },

    // ================================
    // COMPLIANCE Y REGULACIONES
    // ================================

    // Para compliance GDPR
    isEuCountry: {
      type: Boolean,
      default: false,
      index: true, // Para queries de GDPR
    },

    // Consentimiento de procesamiento de datos
    dataProcessingConsent: {
      type: Boolean,
      default: false,
    },

    // Fecha del consentimiento
    consentTimestamp: {
      type: Date,
    },

    // ================================
    // RESTRICCIONES GEOGRÁFICAS
    // ================================

    // Países con restricciones especiales
    isRestrictedCountry: {
      type: Boolean,
      default: false,
      index: true,
    },

    // Razones de restricción
    restrictionReasons: [
      {
        type: String,
        enum: ["sanctions", "legal", "business", "security", "compliance"],
      },
    ],

    // Nivel de riesgo geográfico
    riskLevel: {
      type: String,
      enum: ["low", "medium", "high", "critical"],
      default: "low",
      index: true,
    },

    // ================================
    // PRECISIÓN Y CONFIABILIDAD
    // ================================

    locationAccuracy: {
      type: String,
      enum: ["exact", "city", "region", "country", "unknown"],
      default: "city",
    },

    // Fuente de la información de ubicación
    dataSource: {
      type: String,
      enum: ["gps", "wifi", "cell", "ip", "manual", "unknown"],
      default: "ip",
    },

    // Nivel de confianza en la ubicación (0-1)
    confidence: {
      type: Number,
      min: 0,
      max: 1,
      default: 0.5,
      validate: {
        validator: function (v) {
          return v >= 0 && v <= 1;
        },
        message: "Confidence debe estar entre 0 y 1",
      },
    },

    // ================================
    // INFORMACIÓN TEMPORAL Y ZONA HORARIA
    // ================================

    timezone: {
      type: String,
      maxlength: 50,
      validate: {
        validator: function (v) {
          // Validación básica de timezone
          return !v || /^[A-Z][a-z]+\/[A-Z][a-z_]+$/.test(v) || v === "UTC";
        },
        message: "Formato de timezone inválido",
      },
    },

    timezoneOffset: {
      type: Number,
      min: -12,
      max: 14, // UTC+14 es el offset máximo
    },

    // ================================
    // INFORMACIÓN ADICIONAL DE CONTEXTO
    // ================================

    // Lenguaje/cultura predominante en la región
    language: {
      type: String,
      maxlength: 10, // ej: "es-ES", "en-US"
    },

    currency: {
      type: String,
      maxlength: 3, // Código ISO 4217 (ej: "USD", "EUR")
      uppercase: true,
    },

    // Indicadores económicos básicos
    economicData: {
      gdpPerCapita: {
        type: Number,
        min: 0,
      },
      developmentIndex: {
        type: Number,
        min: 0,
        max: 1,
      },
    },

    // ================================
    // METADATOS Y AUDITORÍA
    // ================================

    metadata: {
      firstDetected: {
        type: Date,
        default: Date.now,
      },
      lastUpdated: {
        type: Date,
        default: Date.now,
      },
      updateCount: {
        type: Number,
        default: 1,
        min: 1,
      },
      dataProvider: {
        type: String,
        maxlength: 50,
        default: "internal",
      },
      // Costo de la consulta de geolocalización (si aplica)
      queryCost: {
        type: Number,
        min: 0,
        default: 0,
      },
    },

    // ================================
    // DETECCIÓN DE PATRONES SOSPECHOSOS
    // ================================

    suspiciousIndicators: {
      // Cambio de ubicación muy rápido
      rapidLocationChange: {
        type: Boolean,
        default: false,
      },

      // Ubicación imposible (viaje muy rápido)
      impossibleTravel: {
        type: Boolean,
        default: false,
      },

      // Múltiples países en poco tiempo
      multipleCountries: {
        type: Boolean,
        default: false,
      },

      // Ubicación inconsistente con timezone
      timezoneInconsistency: {
        type: Boolean,
        default: false,
      },
    },
  },
  {
    _id: false,
    timestamps: false, // Manejamos timestamps en metadata
  }
);

// ================================
// MÉTODOS DEL SCHEMA
// ================================

/**
 * Determina si la ubicación es sospechosa
 */
LocationInfoSchema.methods.isSuspiciousLocation = function () {
  // VPN o Proxy detectado
  if (this.isVpnDetected || this.isProxy || this.isTorExit) return true;

  // País con restricciones
  if (this.isRestrictedCountry) return true;

  // Nivel de riesgo alto
  if (this.riskLevel === "high" || this.riskLevel === "critical") return true;

  // Indicadores sospechosos
  const indicators = this.suspiciousIndicators;
  if (
    indicators?.rapidLocationChange ||
    indicators?.impossibleTravel ||
    indicators?.multipleCountries
  )
    return true;

  // Confianza muy baja
  if (this.confidence < 0.3) return true;

  return false;
};

/**
 * Calcula la distancia a otra ubicación en kilómetros
 */
LocationInfoSchema.methods.distanceTo = function (otherLocation) {
  if (
    !this.coordinates ||
    !otherLocation.coordinates ||
    this.coordinates.length !== 2 ||
    otherLocation.coordinates.length !== 2
  ) {
    return null;
  }

  const [lon1, lat1] = this.coordinates;
  const [lon2, lat2] = otherLocation.coordinates;

  // Fórmula de Haversine
  const R = 6371; // Radio de la Tierra en km
  const dLat = ((lat2 - lat1) * Math.PI) / 180;
  const dLon = ((lon2 - lon1) * Math.PI) / 180;

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos((lat1 * Math.PI) / 180) *
      Math.cos((lat2 * Math.PI) / 180) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c; // Distancia en km
};

/**
 * Verifica si el cambio de ubicación es físicamente posible
 */
LocationInfoSchema.methods.isPossibleTravelFrom = function (
  previousLocation,
  timeDiffMinutes
) {
  if (!previousLocation || !timeDiffMinutes) return true;

  const distance = this.distanceTo(previousLocation);
  if (!distance) return true; // No podemos verificar sin coordenadas

  // Velocidad máxima teórica: 1000 km/h (avión comercial)
  const maxSpeed = 1000; // km/h
  const timeHours = timeDiffMinutes / 60;
  const maxPossibleDistance = maxSpeed * timeHours;

  return distance <= maxPossibleDistance;
};

/**
 * Obtiene un resumen de la ubicación
 */
LocationInfoSchema.methods.getSummary = function () {
  const parts = [this.city, this.region, this.countryName].filter(Boolean);
  return parts.join(", ") || "Ubicación desconocida";
};

/**
 * Verifica si requiere consentimiento GDPR
 */
LocationInfoSchema.methods.requiresGdprConsent = function () {
  return this.isEuCountry && !this.dataProcessingConsent;
};

/**
 * Calcula un score de confianza de la ubicación
 */
LocationInfoSchema.methods.calculateTrustScore = function () {
  let score = this.confidence || 0.5;

  // Penalizar VPN/Proxy
  if (this.isVpnDetected) score -= 0.3;
  if (this.isProxy) score -= 0.2;
  if (this.isTorExit) score -= 0.4;

  // Penalizar indicadores sospechosos
  const indicators = this.suspiciousIndicators;
  if (indicators?.rapidLocationChange) score -= 0.2;
  if (indicators?.impossibleTravel) score -= 0.3;
  if (indicators?.multipleCountries) score -= 0.1;

  // Bonificar ubicaciones verificadas
  if (this.dataSource === "gps") score += 0.1;
  if (this.locationAccuracy === "exact") score += 0.1;

  return Math.max(0, Math.min(1, score));
};

// ================================
// MÉTODOS ESTÁTICOS
// ================================

/**
 * Lista de países de la UE para GDPR
 */
LocationInfoSchema.statics.getEuCountries = function () {
  return [
    "AT",
    "BE",
    "BG",
    "CY",
    "CZ",
    "DE",
    "DK",
    "EE",
    "ES",
    "FI",
    "FR",
    "GR",
    "HR",
    "HU",
    "IE",
    "IT",
    "LT",
    "LU",
    "LV",
    "MT",
    "NL",
    "PL",
    "PT",
    "RO",
    "SE",
    "SI",
    "SK",
  ];
};

/**
 * Verifica si un país está en la UE
 */
LocationInfoSchema.statics.isEuCountry = function (countryCode) {
  return this.getEuCountries().includes(countryCode?.toUpperCase());
};

/**
 * Lista de países con restricciones comunes
 */
LocationInfoSchema.statics.getRestrictedCountries = function () {
  // Esta lista debería ser configurable por cada empresa
  return ["KP", "IR", "SY"]; // Ejemplo básico
};

/**
 * Crear información de ubicación desde IP
 */
LocationInfoSchema.statics.createFromIP = async function (
  ipAddress,
  geoService = null
) {
  // Esta función integraría con servicios como MaxMind, IPGeolocation, etc.
  // Por ahora retorna estructura básica

  const locationData = {
    country: null,
    countryName: null,
    city: null,
    region: null,
    coordinates: null,
    isp: null,
    asn: null,
    timezone: null,
    isVpnDetected: false,
    isProxy: false,
    dataSource: "ip",
    confidence: 0.7,
    metadata: {
      dataProvider: geoService || "internal",
      queryCost: 0,
    },
  };

  // Aquí iría la lógica de integración con el servicio de geolocalización
  // if (geoService) {
  //   const result = await geoService.lookup(ipAddress);
  //   Object.assign(locationData, result);
  // }

  // Determinar si es país EU
  if (locationData.country) {
    locationData.isEuCountry = this.isEuCountry(locationData.country);
    locationData.isRestrictedCountry = this.getRestrictedCountries().includes(
      locationData.country
    );
  }

  return locationData;
};

/**
 * Validar cambio de ubicación
 */
LocationInfoSchema.statics.validateLocationChange = function (
  oldLocation,
  newLocation,
  timeDiffMinutes
) {
  if (!oldLocation || !newLocation)
    return { valid: true, reason: "insufficient_data" };

  // Mismo país - probablemente válido
  if (oldLocation.country === newLocation.country) {
    return { valid: true, reason: "same_country" };
  }

  // Verificar viaje físicamente posible
  const isPossible = newLocation.isPossibleTravelFrom(
    oldLocation,
    timeDiffMinutes
  );
  if (!isPossible) {
    return {
      valid: false,
      reason: "impossible_travel",
      distance: newLocation.distanceTo(oldLocation),
      timeMinutes: timeDiffMinutes,
    };
  }

  // Cambio sospechoso pero posible
  const distance = newLocation.distanceTo(oldLocation);
  if (distance > 1000 && timeDiffMinutes < 120) {
    // >1000km en <2h
    return {
      valid: true,
      reason: "possible_but_suspicious",
      suspiciousScore: 0.8,
      distance,
      timeMinutes: timeDiffMinutes,
    };
  }

  return { valid: true, reason: "normal_travel" };
};

// ================================
// ÍNDICES ESPECÍFICOS
// ================================

// Índice compuesto para análisis geográfico
LocationInfoSchema.index(
  {
    country: 1,
    region: 1,
    city: 1,
  },
  { name: "geographic_hierarchy_index" }
);

// Índice para detección VPN/Proxy
LocationInfoSchema.index(
  {
    isVpnDetected: 1,
    isProxy: 1,
    isTorExit: 1,
  },
  {
    name: "vpn_proxy_detection_index",
    sparse: true,
    partialFilterExpression: {
      $or: [{ isVpnDetected: true }, { isProxy: true }, { isTorExit: true }],
    },
  }
);

// Índice para compliance
LocationInfoSchema.index(
  {
    isEuCountry: 1,
    dataProcessingConsent: 1,
  },
  { name: "gdpr_compliance_location_index" }
);

// ================================
// VALIDACIONES ADICIONALES
// ================================

// Validar que si hay coordenadas, la precisión sea razonable
LocationInfoSchema.pre("validate", function (next) {
  if (this.coordinates && this.coordinates.length === 2) {
    if (!this.locationAccuracy || this.locationAccuracy === "unknown") {
      this.locationAccuracy = "city"; // Default razonable
    }
  }

  // Auto-detectar EU country
  if (this.country && this.isEuCountry === undefined) {
    this.isEuCountry = LocationInfoSchema.statics.isEuCountry(this.country);
  }

  next();
});

// ================================
// EXPORTAR SCHEMA
// ================================

export default LocationInfoSchema;
