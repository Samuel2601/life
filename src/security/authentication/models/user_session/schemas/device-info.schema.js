// =============================================================================
// src/modules/authentication/models/user-session/schemas/device-info.schema.js
// Información del dispositivo optimizada para geolocalización empresarial
// =============================================================================
import mongoose from "mongoose";

/**
 * Schema para información del dispositivo (optimizado para geolocalización empresarial)
 *
 * @description Almacena información detallada del dispositivo del usuario
 * incluyendo datos para detección de bots y análisis de seguridad
 */
export const DeviceInfoSchema = new mongoose.Schema(
  {
    browser: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
      index: true, // Para analytics de navegadores
    },
    browserVersion: {
      type: String,
      maxlength: 50,
    },
    os: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
      index: true, // Para analytics de SO
    },
    osVersion: {
      type: String,
      maxlength: 50,
    },
    device: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
    },
    deviceType: {
      type: String,
      enum: ["desktop", "mobile", "tablet", "unknown"],
      default: "unknown",
      index: true, // Para analytics mobile vs desktop
    },
    isMobile: {
      type: Boolean,
      default: false,
      index: true, // Para filtrar por tipo de dispositivo
    },
    screenResolution: {
      type: String,
      maxlength: 20, // ej: "1920x1080"
    },
    timezone: {
      type: String,
      required: true,
      default: "America/Lima",
      index: true, // Para analytics por zona horaria
    },
    language: {
      type: String,
      maxlength: 10, // ej: "es-ES"
      index: true, // Para analytics de idioma
    },

    // ================================
    // INFORMACIÓN ADICIONAL PARA DETECCIÓN DE BOTS
    // ================================
    hardwareConcurrency: {
      type: Number,
      min: 1,
      max: 128,
      validate: {
        validator: function (v) {
          return v === null || v === undefined || (v >= 1 && v <= 128);
        },
        message: "Hardware concurrency debe estar entre 1 y 128",
      },
    },
    deviceMemory: {
      type: Number,
      min: 0.25,
      max: 1024,
      validate: {
        validator: function (v) {
          return v === null || v === undefined || (v >= 0.25 && v <= 1024);
        },
        message: "Device memory debe estar entre 0.25 y 1024 GB",
      },
    },
    maxTouchPoints: {
      type: Number,
      default: 0,
      min: 0,
      max: 10,
    },

    // ================================
    // INFORMACIÓN DE PANTALLA AVANZADA
    // ================================
    colorDepth: {
      type: Number,
      min: 1,
      max: 48,
    },
    pixelRatio: {
      type: Number,
      min: 0.1,
      max: 10,
    },

    // ================================
    // CAPACIDADES DEL NAVEGADOR
    // ================================
    capabilities: {
      webGL: {
        type: Boolean,
        default: false,
      },
      webGL2: {
        type: Boolean,
        default: false,
      },
      canvas: {
        type: Boolean,
        default: false,
      },
      audioContext: {
        type: Boolean,
        default: false,
      },
      localStorage: {
        type: Boolean,
        default: false,
      },
      sessionStorage: {
        type: Boolean,
        default: false,
      },
      webRTC: {
        type: Boolean,
        default: false,
      },
      geolocation: {
        type: Boolean,
        default: false,
      },
    },

    // ================================
    // PLUGINS Y EXTENSIONES
    // ================================
    pluginsCount: {
      type: Number,
      default: 0,
      min: 0,
      max: 100,
    },
    fontsCount: {
      type: Number,
      default: 0,
      min: 0,
      max: 1000,
    },

    // ================================
    // INDICADORES DE BOT/AUTOMATIZACIÓN
    // ================================
    automationIndicators: {
      webDriverPresent: {
        type: Boolean,
        default: false,
      },
      phantomJS: {
        type: Boolean,
        default: false,
      },
      seleniumPresent: {
        type: Boolean,
        default: false,
      },
      puppeteerPresent: {
        type: Boolean,
        default: false,
      },
      headlessChrome: {
        type: Boolean,
        default: false,
      },
      unusualUserAgent: {
        type: Boolean,
        default: false,
      },
    },

    // ================================
    // METADATOS DEL DISPOSITIVO
    // ================================
    metadata: {
      firstSeen: {
        type: Date,
        default: Date.now,
      },
      lastUpdated: {
        type: Date,
        default: Date.now,
      },
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
      source: {
        type: String,
        enum: ["user-agent-parser", "client-hints", "manual", "fingerprint"],
        default: "user-agent-parser",
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
 * Determina si el dispositivo parece ser un bot
 */
DeviceInfoSchema.methods.isSuspiciousDevice = function () {
  const automation = this.automationIndicators;
  const suspiciousCount = Object.values(automation).filter(Boolean).length;

  // Si tiene más de 2 indicadores de automatización, es sospechoso
  if (suspiciousCount >= 2) return true;

  // Hardware poco realista para un usuario normal
  if (this.hardwareConcurrency && this.hardwareConcurrency > 32) return true;
  if (this.deviceMemory && this.deviceMemory > 32) return true;

  // Sin capacidades básicas del navegador
  const caps = this.capabilities;
  if (!caps.canvas && !caps.localStorage && !caps.sessionStorage) return true;

  return false;
};

/**
 * Calcula un score de confianza para el dispositivo
 */
DeviceInfoSchema.methods.calculateTrustScore = function () {
  let score = 0.5; // Score base

  // Puntos positivos
  if (this.capabilities.canvas) score += 0.1;
  if (this.capabilities.webGL) score += 0.1;
  if (this.capabilities.localStorage) score += 0.1;
  if (this.fontsCount > 10) score += 0.1;
  if (this.pluginsCount > 0 && this.pluginsCount < 20) score += 0.1;

  // Puntos negativos
  const automation = this.automationIndicators;
  const automationCount = Object.values(automation).filter(Boolean).length;
  score -= automationCount * 0.2;

  if (this.hardwareConcurrency > 64) score -= 0.2;
  if (this.deviceMemory > 64) score -= 0.2;
  if (this.pluginsCount === 0) score -= 0.1;
  if (this.fontsCount < 5) score -= 0.1;

  // Mantener score entre 0 y 1
  return Math.max(0, Math.min(1, score));
};

/**
 * Obtiene un resumen del dispositivo para logs
 */
DeviceInfoSchema.methods.getSummary = function () {
  return `${this.browser} ${this.browserVersion} on ${this.os} (${this.deviceType})`;
};

/**
 * Verifica si es un dispositivo móvil moderno
 */
DeviceInfoSchema.methods.isModernMobile = function () {
  if (!this.isMobile) return false;

  // Verificar capacidades modernas
  return (
    this.capabilities.webGL &&
    this.capabilities.canvas &&
    this.maxTouchPoints > 0
  );
};

// ================================
// MÉTODOS ESTÁTICOS
// ================================

/**
 * Crea un DeviceInfo desde User-Agent y Client Hints
 */
DeviceInfoSchema.statics.createFromRequest = function (req) {
  const userAgent = req.get("User-Agent") || "";
  const acceptLanguage = req.get("Accept-Language") || "en-US";

  // Parsing básico del User-Agent (en producción usar una librería)
  const deviceInfo = {
    browser: this.parseBrowser(userAgent),
    browserVersion: this.parseBrowserVersion(userAgent),
    os: this.parseOS(userAgent),
    osVersion: this.parseOSVersion(userAgent),
    device: this.parseDevice(userAgent),
    deviceType: this.parseDeviceType(userAgent),
    isMobile: this.isMobileUA(userAgent),
    language: acceptLanguage.split(",")[0].trim(),
    timezone: req.body?.timezone || "America/Lima",

    // Client Hints si están disponibles
    hardwareConcurrency: req.get("Sec-CH-UA-Platform-Version"),
    deviceMemory: req.get("Sec-CH-UA-Model"),

    // Capabilities básicas (esto vendría del frontend)
    capabilities: {
      webGL: true, // Asumir true por defecto
      canvas: true,
      localStorage: true,
      sessionStorage: true,
    },

    metadata: {
      source: req.get("Sec-CH-UA") ? "client-hints" : "user-agent-parser",
      confidence: req.get("Sec-CH-UA") ? 0.8 : 0.6,
    },
  };

  return deviceInfo;
};

/**
 * Helper para parsear navegador del User-Agent
 */
DeviceInfoSchema.statics.parseBrowser = function (userAgent) {
  if (userAgent.includes("Chrome")) return "Chrome";
  if (userAgent.includes("Firefox")) return "Firefox";
  if (userAgent.includes("Safari")) return "Safari";
  if (userAgent.includes("Edge")) return "Edge";
  if (userAgent.includes("Opera")) return "Opera";
  return "Unknown";
};

/**
 * Helper para detectar si es móvil
 */
DeviceInfoSchema.statics.isMobileUA = function (userAgent) {
  return /Mobile|Android|iPhone|iPad/i.test(userAgent);
};

/**
 * Helper para detectar tipo de dispositivo
 */
DeviceInfoSchema.statics.parseDeviceType = function (userAgent) {
  if (/tablet|iPad/i.test(userAgent)) return "tablet";
  if (/Mobile|Android|iPhone/i.test(userAgent)) return "mobile";
  return "desktop";
};

/**
 * Helper para parsear SO
 */
DeviceInfoSchema.statics.parseOS = function (userAgent) {
  if (userAgent.includes("Windows")) return "Windows";
  if (userAgent.includes("Mac")) return "macOS";
  if (userAgent.includes("Linux")) return "Linux";
  if (userAgent.includes("Android")) return "Android";
  if (userAgent.includes("iPhone") || userAgent.includes("iPad")) return "iOS";
  return "Unknown";
};

// Métodos adicionales de parsing...
DeviceInfoSchema.statics.parseBrowserVersion = function (userAgent) {
  // Implementación básica - usar librería en producción
  return "Unknown";
};

DeviceInfoSchema.statics.parseOSVersion = function (userAgent) {
  // Implementación básica - usar librería en producción
  return "Unknown";
};

DeviceInfoSchema.statics.parseDevice = function (userAgent) {
  // Implementación básica - usar librería en producción
  return "Unknown Device";
};

// ================================
// VALIDACIONES PERSONALIZADAS
// ================================

// Validación para timezone válido
DeviceInfoSchema.path("timezone").validate(function (value) {
  // Lista básica de timezones válidos (en producción usar Intl.supportedValuesOf)
  const validTimezones = [
    "America/Lima",
    "America/New_York",
    "Europe/London",
    "Asia/Tokyo",
    "UTC",
    "America/Los_Angeles",
    "Europe/Madrid",
    "America/Mexico_City",
  ];

  return (
    !value ||
    validTimezones.includes(value) ||
    /^[A-Z][a-z]+\/[A-Z][a-z_]+$/.test(value)
  );
}, "Timezone inválido");

// Validación para language code
DeviceInfoSchema.path("language").validate(function (value) {
  return !value || /^[a-z]{2}(-[A-Z]{2})?$/.test(value);
}, "Código de idioma inválido");

// ================================
// INDICES ESPECÍFICOS DE ESTE SCHEMA
// ================================

// Índice compuesto para búsquedas de análisis de dispositivos
DeviceInfoSchema.index(
  {
    deviceType: 1,
    browser: 1,
    os: 1,
  },
  { name: "device_analysis_index" }
);

// Índice para detección de bots
DeviceInfoSchema.index(
  {
    "automationIndicators.webDriverPresent": 1,
    "automationIndicators.seleniumPresent": 1,
    "automationIndicators.headlessChrome": 1,
  },
  {
    name: "bot_detection_index",
    sparse: true,
  }
);

// ================================
// EXPORTAR SCHEMA
// ================================

export default DeviceInfoSchema;
