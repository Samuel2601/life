// =============================================================================
// src/modules/business/models/address.scheme.js
// =============================================================================
import mongoose from "mongoose";
import {
  BaseSchemeFields,
  setupBaseSchema,
} from "../../core/models/base.scheme.js";
import {
  MultiLanguageContentSchema,
  createMultiLanguageField,
} from "../../core/models/multi_language_pattern.scheme.js";

/**
 * Schema para coordenadas geográficas con precisión
 */
const CoordinatesSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      enum: ["Point"],
      default: "Point",
      required: true,
    },
    coordinates: {
      type: [Number], // [longitude, latitude]
      required: true,
      validate: {
        validator: function (coords) {
          return (
            coords.length === 2 &&
            coords[0] >= -180 &&
            coords[0] <= 180 && // longitude
            coords[1] >= -90 &&
            coords[1] <= 90 // latitude
          );
        },
        message: "Coordenadas inválidas. Formato: [longitude, latitude]",
      },
      index: "2dsphere",
    },
    accuracy: {
      type: Number,
      min: 0,
      max: 10000, // metros
      default: 10,
    },
    source: {
      type: String,
      enum: ["gps", "geocoding", "manual", "ip_geolocation", "user_input"],
      default: "geocoding",
    },
    verifiedAt: {
      type: Date,
    },
    verifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
  },
  { _id: false }
);

/**
 * Schema para dirección formateada según estándares internacionales
 */
const FormattedAddressSchema = new mongoose.Schema(
  {
    // Dirección completa para cada idioma
    fullAddress: createMultiLanguageField({
      required: true,
    }),

    // Dirección corta (solo elementos principales)
    shortAddress: createMultiLanguageField({
      required: true,
    }),

    // Dirección para navegación
    navigationAddress: {
      type: String,
      trim: true,
      maxlength: 500,
    },

    lastFormatted: {
      type: Date,
      default: Date.now,
    },

    formattingSource: {
      type: String,
      enum: ["google_maps", "openstreetmap", "manual", "system"],
      default: "system",
    },
  },
  { _id: false }
);

/**
 * Schema para información de validación de dirección
 */
const AddressValidationSchema = new mongoose.Schema(
  {
    isValidated: {
      type: Boolean,
      default: false,
      index: true,
    },

    validationScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },

    validationMethod: {
      type: String,
      enum: ["google_maps", "postal_service", "manual", "user_confirmed"],
    },

    validatedAt: {
      type: Date,
    },

    validatedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },

    validationErrors: [
      {
        field: String,
        error: String,
        severity: {
          type: String,
          enum: ["low", "medium", "high"],
          default: "medium",
        },
      },
    ],

    validationWarnings: [
      {
        field: String,
        warning: String,
        autoFixApplied: {
          type: Boolean,
          default: false,
        },
      },
    ],

    lastValidationCheck: {
      type: Date,
      default: Date.now,
    },
  },
  { _id: false }
);

/**
 * Schema para metadatos adicionales de ubicación
 */
const LocationMetadataSchema = new mongoose.Schema(
  {
    // Información de zona horaria
    timezone: {
      type: String,
      required: true,
      default: "America/Lima",
    },

    utcOffset: {
      type: String, // ej: "-05:00"
      required: true,
      default: "-05:00",
    },

    // Información demográfica básica
    population: {
      type: Number,
      min: 0,
    },

    elevationMeters: {
      type: Number,
    },

    // Códigos postales adicionales
    alternativePostalCodes: [String],

    // Información de calidad del área
    areaQuality: {
      residential: {
        type: String,
        enum: ["low", "medium", "high", "luxury"],
      },
      commercial: {
        type: String,
        enum: ["low", "medium", "high"],
      },
      safety: {
        type: String,
        enum: ["low", "medium", "high"],
      },
      accessibility: {
        type: String,
        enum: ["low", "medium", "high"],
      },
    },

    // Servicios cercanos
    nearbyServices: {
      hasPublicTransport: {
        type: Boolean,
        default: false,
      },
      hasParking: {
        type: Boolean,
        default: false,
      },
      hasBankAccess: {
        type: Boolean,
        default: false,
      },
      hasHospitalNearby: {
        type: Boolean,
        default: false,
      },
      distance: {
        toMainRoad: Number, // metros
        toPublicTransport: Number,
        toCityCenter: Number,
      },
    },

    lastUpdated: {
      type: Date,
      default: Date.now,
    },
  },
  { _id: false }
);

/**
 * Schema principal de Address
 */
const AddressSchema = new mongoose.Schema({
  // Identificación
  addressId: {
    type: mongoose.Schema.Types.ObjectId,
    default: () => new mongoose.Types.ObjectId(),
    unique: true,
    index: true,
  },

  // Información de dirección básica
  streetAddress: {
    type: String,
    required: [true, "La dirección de calle es requerida"],
    trim: true,
    maxlength: [200, "La dirección no puede exceder 200 caracteres"],
    index: true,
  },

  streetNumber: {
    type: String,
    trim: true,
    maxlength: 20,
  },

  floor: {
    type: String,
    trim: true,
    maxlength: 10,
  },

  apartment: {
    type: String,
    trim: true,
    maxlength: 20,
  },

  building: {
    type: String,
    trim: true,
    maxlength: 100,
  },

  // División administrativa
  neighborhood: {
    type: String,
    trim: true,
    maxlength: 100,
    index: true,
  },

  district: {
    type: String,
    trim: true,
    maxlength: 100,
    index: true,
  },

  city: {
    type: String,
    required: [true, "La ciudad es requerida"],
    trim: true,
    maxlength: 100,
    index: true,
  },

  state: {
    type: String,
    required: [true, "El estado/provincia es requerido"],
    trim: true,
    maxlength: 100,
    index: true,
  },

  country: {
    type: String,
    required: [true, "El país es requerido"],
    uppercase: true,
    length: 2, // Código ISO de país
    match: /^[A-Z]{2}$/,
    default: "PE",
    index: true,
  },

  countryName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100,
    default: "Perú",
  },

  postalCode: {
    type: String,
    trim: true,
    maxlength: 20,
    index: true,
    validate: {
      validator: function (code) {
        if (!code) return true; // Postal code es opcional

        // Validaciones por país
        const patterns = {
          PE: /^\d{5}$/, // Perú: 5 dígitos
          US: /^\d{5}(-\d{4})?$/, // USA: 12345 o 12345-6789
          ES: /^\d{5}$/, // España: 5 dígitos
          MX: /^\d{5}$/, // México: 5 dígitos
        };

        const pattern = patterns[this.country];
        return pattern ? pattern.test(code) : true;
      },
      message: "Formato de código postal inválido para el país especificado",
    },
  },

  // Coordenadas geográficas
  location: {
    type: CoordinatesSchema,
    required: true,
  },

  // Dirección formateada
  formattedAddress: {
    type: FormattedAddressSchema,
    required: true,
  },

  // Validación
  validation: {
    type: AddressValidationSchema,
    default: () => ({}),
  },

  // Metadatos de ubicación
  metadata: {
    type: LocationMetadataSchema,
    default: () => ({}),
  },

  // Tipo de dirección
  addressType: {
    type: String,
    enum: [
      "business",
      "residential",
      "commercial",
      "industrial",
      "government",
      "educational",
      "healthcare",
      "mixed_use",
      "other",
    ],
    default: "business",
    index: true,
  },

  // Estado de la dirección
  isActive: {
    type: Boolean,
    default: true,
    index: true,
  },

  isPrimary: {
    type: Boolean,
    default: false,
  },

  isPublic: {
    type: Boolean,
    default: true, // false para direcciones privadas
  },

  // Referencias
  businessId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Business",
    index: true,
  },

  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    index: true,
  },

  // Configuración de privacidad
  privacySettings: {
    showFullAddress: {
      type: Boolean,
      default: true,
    },
    showExactLocation: {
      type: Boolean,
      default: true,
    },
    proximityRadius: {
      type: Number,
      min: 0,
      max: 5000, // metros
      default: 0, // 0 = ubicación exacta
    },
  },

  // Notas adicionales
  notes: {
    type: String,
    maxlength: 500,
    trim: true,
  },

  deliveryInstructions: {
    type: String,
    maxlength: 300,
    trim: true,
  },

  landmarks: [
    {
      type: String,
      maxlength: 100,
      trim: true,
    },
  ],

  // Campos base de auditoría
  ...BaseSchemeFields,
});

// Configurar esquema con funcionalidades base
setupBaseSchema(AddressSchema, {
  addTimestamps: false, // Ya incluidos en BaseSchemeFields
});

// ================================
// ÍNDICES ESPECÍFICOS
// ================================

// Índice geoespacial principal (ya definido en coordinates)
AddressSchema.index({ "location.coordinates": "2dsphere" });

// Índices compuestos para búsquedas geográficas
AddressSchema.index({
  country: 1,
  state: 1,
  city: 1,
  isActive: 1,
});

AddressSchema.index({
  addressType: 1,
  "location.coordinates": "2dsphere",
  isActive: 1,
});

// Índices para validación
AddressSchema.index({
  "validation.isValidated": 1,
  "validation.validationScore": -1,
});

// Índices para búsqueda de texto
AddressSchema.index(
  {
    streetAddress: "text",
    neighborhood: "text",
    city: "text",
    state: "text",
  },
  {
    name: "address_search_index",
    weights: {
      streetAddress: 10,
      neighborhood: 8,
      city: 6,
      state: 4,
    },
  }
);

// Índices para referencias
AddressSchema.index({ businessId: 1, isPrimary: 1 });
AddressSchema.index({ userId: 1, addressType: 1 });

// ================================
// MIDDLEWARE
// ================================

// Pre-save middleware
AddressSchema.pre("save", async function (next) {
  try {
    // Auto-formatear dirección si es nueva o cambió
    if (
      this.isNew ||
      this.isModified(["streetAddress", "city", "state", "country"])
    ) {
      await this.autoFormatAddress();
    }

    // Validar coordenadas
    if (this.location?.coordinates) {
      const [lng, lat] = this.location.coordinates;
      if (lng < -180 || lng > 180 || lat < -90 || lat > 90) {
        return next(new Error("Coordenadas geográficas inválidas"));
      }
    }

    // Auto-detectar timezone si no está establecido
    if (!this.metadata.timezone && this.location?.coordinates) {
      this.metadata.timezone = await this.detectTimezone();
    }

    // Actualizar timestamp de metadatos
    this.metadata.lastUpdated = new Date();

    next();
  } catch (error) {
    next(error);
  }
});

// Post-save middleware
AddressSchema.post("save", function (doc) {
  if (doc.isNew) {
    console.log(
      `✅ Dirección creada: ${doc.city}, ${doc.state} (${doc.location.coordinates})`
    );
  }
});

// ================================
// MÉTODOS DE INSTANCIA
// ================================

/**
 * Auto-formatear dirección según estándares locales
 */
AddressSchema.methods.autoFormatAddress = async function () {
  const addressParts = [];

  // Construir dirección según país
  if (this.streetAddress) {
    let streetPart = this.streetAddress;
    if (this.streetNumber) {
      streetPart = `${this.streetAddress} ${this.streetNumber}`;
    }
    addressParts.push(streetPart);
  }

  if (this.apartment || this.floor) {
    const unitParts = [];
    if (this.floor) unitParts.push(`Piso ${this.floor}`);
    if (this.apartment) unitParts.push(`Apt. ${this.apartment}`);
    if (unitParts.length > 0) {
      addressParts.push(unitParts.join(", "));
    }
  }

  if (this.neighborhood) addressParts.push(this.neighborhood);
  if (this.district && this.district !== this.city)
    addressParts.push(this.district);
  if (this.city) addressParts.push(this.city);
  if (this.state) addressParts.push(this.state);
  if (this.postalCode) addressParts.push(this.postalCode);
  if (this.countryName) addressParts.push(this.countryName);

  const fullAddress = addressParts.join(", ");
  const shortAddress = [this.streetAddress, this.city, this.state]
    .filter(Boolean)
    .join(", ");

  this.formattedAddress = {
    fullAddress: {
      original: { language: "es", text: fullAddress },
      translations: new Map(),
      availableLanguages: ["es"],
      lastUpdated: new Date(),
    },
    shortAddress: {
      original: { language: "es", text: shortAddress },
      translations: new Map(),
      availableLanguages: ["es"],
      lastUpdated: new Date(),
    },
    navigationAddress: fullAddress,
    lastFormatted: new Date(),
    formattingSource: "system",
  };
};

/**
 * Detectar zona horaria basada en coordenadas
 */
AddressSchema.methods.detectTimezone = async function () {
  // Implementación simplificada - en producción usar servicio como TimeZoneDB
  const timezones = {
    PE: "America/Lima",
    US: "America/New_York", // Default, debería ser más específico
    MX: "America/Mexico_City",
    ES: "Europe/Madrid",
    AR: "America/Argentina/Buenos_Aires",
    CL: "America/Santiago",
    CO: "America/Bogota",
  };

  return timezones[this.country] || "UTC";
};

/**
 * Calcular distancia a otra dirección
 */
AddressSchema.methods.distanceTo = function (otherAddress) {
  if (!this.location?.coordinates || !otherAddress.location?.coordinates) {
    throw new Error("Ambas direcciones deben tener coordenadas");
  }

  const [lng1, lat1] = this.location.coordinates;
  const [lng2, lat2] = otherAddress.location.coordinates;

  return this.calculateHaversineDistance(lat1, lng1, lat2, lng2);
};

/**
 * Calcular distancia usando fórmula de Haversine
 */
AddressSchema.methods.calculateHaversineDistance = function (
  lat1,
  lon1,
  lat2,
  lon2
) {
  const R = 6371000; // Radio de la Tierra en metros
  const dLat = this.toRadians(lat2 - lat1);
  const dLon = this.toRadians(lon2 - lon1);

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(this.toRadians(lat1)) *
      Math.cos(this.toRadians(lat2)) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c; // Distancia en metros
};

/**
 * Convertir grados a radianes
 */
AddressSchema.methods.toRadians = function (degrees) {
  return (degrees * Math.PI) / 180;
};

/**
 * Validar dirección con servicio externo
 */
AddressSchema.methods.validateWithService = async function (
  service = "google_maps"
) {
  try {
    // Simular validación - implementar con servicio real
    const validationResult = {
      isValid: true,
      score: 95,
      errors: [],
      warnings: [],
    };

    this.validation = {
      isValidated: validationResult.isValid,
      validationScore: validationResult.score,
      validationMethod: service,
      validatedAt: new Date(),
      validationErrors: validationResult.errors,
      validationWarnings: validationResult.warnings,
      lastValidationCheck: new Date(),
    };

    return this.save();
  } catch (error) {
    console.error("Error validando dirección:", error);
    return false;
  }
};

/**
 * Obtener dirección formateada en idioma específico
 */
AddressSchema.methods.getFormattedAddress = function (
  language = "es",
  format = "full"
) {
  const addressField = format === "full" ? "fullAddress" : "shortAddress";

  if (this.formattedAddress?.[addressField]) {
    const content = this.formattedAddress[addressField];
    return content.getText ? content.getText(language) : content;
  }

  // Fallback a formateo dinámico
  return format === "full"
    ? `${this.streetAddress}, ${this.city}, ${this.state}, ${this.countryName}`
    : `${this.streetAddress}, ${this.city}`;
};

/**
 * Verificar si está dentro de un radio específico
 */
AddressSchema.methods.isWithinRadius = function (
  centerCoordinates,
  radiusInMeters
) {
  if (!this.location?.coordinates) return false;

  const [centerLng, centerLat] = centerCoordinates;
  const [thisLng, thisLat] = this.location.coordinates;

  const distance = this.calculateHaversineDistance(
    centerLat,
    centerLng,
    thisLat,
    thisLng
  );
  return distance <= radiusInMeters;
};

// ================================
// MÉTODOS ESTÁTICOS
// ================================

/**
 * Buscar direcciones cerca de un punto
 */
AddressSchema.statics.findNearby = function (
  coordinates,
  maxDistanceMeters = 5000,
  options = {}
) {
  const query = {
    "location.coordinates": {
      $near: {
        $geometry: {
          type: "Point",
          coordinates: coordinates, // [longitude, latitude]
        },
        $maxDistance: maxDistanceMeters,
      },
    },
    isActive: true,
  };

  // Aplicar filtros adicionales
  if (options.addressType) query.addressType = options.addressType;
  if (options.country) query.country = options.country;
  if (options.state) query.state = options.state;
  if (options.city) query.city = options.city;

  return this.find(query).limit(options.limit || 50);
};

/**
 * Buscar direcciones dentro de un área rectangular
 */
AddressSchema.statics.findInBoundingBox = function (
  northEast,
  southWest,
  options = {}
) {
  const query = {
    "location.coordinates": {
      $geoWithin: {
        $box: [
          [southWest.lng, southWest.lat], // esquina inferior izquierda
          [northEast.lng, northEast.lat], // esquina superior derecha
        ],
      },
    },
    isActive: true,
  };

  if (options.addressType) query.addressType = options.addressType;

  return this.find(query).limit(options.limit || 100);
};

/**
 * Geocodificar dirección (integración futura)
 */
AddressSchema.statics.geocodeAddress = async function (addressString) {
  // Placeholder para integración con servicio de geocodificación
  console.log(`Geocodificando: ${addressString}`);

  // Retornar coordenadas de ejemplo (Lima, Perú)
  return {
    coordinates: [-77.0428, -12.0464], // [longitude, latitude]
    accuracy: 10,
    source: "geocoding",
  };
};

/**
 * Obtener estadísticas por región
 */
AddressSchema.statics.getRegionStats = function (country, state = null) {
  const matchConditions = { country, isActive: true };
  if (state) matchConditions.state = state;

  return this.aggregate([
    { $match: matchConditions },
    {
      $group: {
        _id: state ? "$city" : "$state",
        totalAddresses: { $sum: 1 },
        businessAddresses: {
          $sum: { $cond: [{ $eq: ["$addressType", "business"] }, 1, 0] },
        },
        validatedAddresses: {
          $sum: { $cond: ["$validation.isValidated", 1, 0] },
        },
        avgValidationScore: { $avg: "$validation.validationScore" },
      },
    },
    { $sort: { totalAddresses: -1 } },
  ]);
};

// ================================
// VIRTUALES
// ================================

/**
 * Virtual para obtener coordenadas como array simple
 */
AddressSchema.virtual("coordinates").get(function () {
  return this.location?.coordinates || null;
});

/**
 * Virtual para obtener latitud
 */
AddressSchema.virtual("latitude").get(function () {
  return this.location?.coordinates?.[1] || null;
});

/**
 * Virtual para obtener longitud
 */
AddressSchema.virtual("longitude").get(function () {
  return this.location?.coordinates?.[0] || null;
});

/**
 * Virtual para dirección completa simple
 */
AddressSchema.virtual("fullAddressSimple").get(function () {
  return this.getFormattedAddress("es", "full");
});

// ================================
// CONFIGURACIÓN ADICIONAL
// ================================

// Configurar opciones de transformación para JSON
AddressSchema.set("toJSON", {
  virtuals: true,
  transform: function (doc, ret) {
    delete ret.__v;

    // Aplicar configuración de privacidad
    if (!doc.privacySettings?.showFullAddress) {
      ret.streetAddress = "Dirección no disponible";
      ret.streetNumber = undefined;
      ret.apartment = undefined;
      ret.floor = undefined;
    }

    if (
      !doc.privacySettings?.showExactLocation &&
      doc.privacySettings?.proximityRadius > 0
    ) {
      // Aplicar ruido a las coordenadas para privacidad
      const radius = doc.privacySettings.proximityRadius / 111000; // Aproximado en grados
      ret.location.coordinates[0] += (Math.random() - 0.5) * radius;
      ret.location.coordinates[1] += (Math.random() - 0.5) * radius;
      ret.location.accuracy = doc.privacySettings.proximityRadius;
    }

    return ret;
  },
});

// ================================
// EXPORTAR MODELO
// ================================

export const Address = mongoose.model("Address", AddressSchema);
export default Address;
