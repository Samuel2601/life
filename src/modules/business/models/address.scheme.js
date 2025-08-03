// =============================================================================
// src/modules/business/models/address.scheme.js
// =============================================================================
import mongoose from "mongoose";
import {
  BaseSchemeFields,
  setupBaseSchema,
  CommonValidators,
} from "../../core/models/base.scheme.js";

// =============================================================================
// src/modules/business/models/address.scheme.js
// =============================================================================
import mongoose from "mongoose";
import {
  BaseSchemeFields,
  setupBaseSchema,
  CommonValidators,
} from "../../core/models/base.scheme.js";

/**
 * Schema para componentes de dirección estructurada
 */
const AddressComponentsSchema = new mongoose.Schema(
  {
    streetNumber: {
      type: String,
      trim: true,
      maxlength: [20, "El número de calle no puede exceder 20 caracteres"],
    },
    route: {
      type: String,
      trim: true,
      maxlength: [200, "La ruta no puede exceder 200 caracteres"],
    },
    neighborhood: {
      type: String,
      trim: true,
      maxlength: [100, "El barrio no puede exceder 100 caracteres"],
      index: true,
    },
    locality: {
      type: String,
      trim: true,
      maxlength: [100, "La localidad no puede exceder 100 caracteres"],
      index: true,
    },
    sublocality: {
      type: String,
      trim: true,
      maxlength: [100, "La sublocalidad no puede exceder 100 caracteres"],
    },
    administrativeAreaLevel1: {
      type: String,
      trim: true,
      maxlength: [
        100,
        "El área administrativa nivel 1 no puede exceder 100 caracteres",
      ],
      index: true,
    },
    administrativeAreaLevel2: {
      type: String,
      trim: true,
      maxlength: [
        100,
        "El área administrativa nivel 2 no puede exceder 100 caracteres",
      ],
    },
    premise: {
      type: String,
      trim: true,
      maxlength: [50, "La premisa no puede exceder 50 caracteres"],
    },
    subpremise: {
      type: String,
      trim: true,
      maxlength: [50, "La subpremisa no puede exceder 50 caracteres"],
    },
  },
  { _id: false }
);

/**
 * Schema para metadatos de geolocalización
 */
const GeolocationMetadataSchema = new mongoose.Schema(
  {
    accuracy: {
      type: Number,
      min: [0, "La precisión no puede ser negativa"],
      max: [100, "La precisión no puede exceder 100"],
    },
    locationType: {
      type: String,
      enum: [
        "ROOFTOP",
        "RANGE_INTERPOLATED",
        "GEOMETRIC_CENTER",
        "APPROXIMATE",
      ],
      default: "APPROXIMATE",
    },
    viewportBounds: {
      northeast: {
        lat: { type: Number },
        lng: { type: Number },
      },
      southwest: {
        lat: { type: Number },
        lng: { type: Number },
      },
    },
    elevation: {
      type: Number,
      default: null,
    },
    heading: {
      type: Number,
      min: [0, "El rumbo debe estar entre 0 y 360"],
      max: [360, "El rumbo debe estar entre 0 y 360"],
    },
  },
  { _id: false }
);

/**
 * Schema principal de Dirección
 */
const AddressSchema = new mongoose.Schema({
  // Dirección estructurada básica
  streetAddress: {
    type: String,
    required: [true, "La dirección de calle es requerida"],
    trim: true,
    maxlength: [200, "La dirección no puede exceder 200 caracteres"],
    index: "text",
  },

  apartment: {
    type: String,
    trim: true,
    maxlength: [50, "El apartamento/unidad no puede exceder 50 caracteres"],
  },

  city: {
    type: String,
    required: [true, "La ciudad es requerida"],
    trim: true,
    maxlength: [100, "La ciudad no puede exceder 100 caracteres"],
    index: true,
  },

  state: {
    type: String,
    required: [true, "El estado/provincia es requerido"],
    trim: true,
    maxlength: [100, "El estado no puede exceder 100 caracteres"],
    index: true,
  },

  country: {
    type: String,
    required: [true, "El país es requerido"],
    trim: true,
    maxlength: [100, "El país no puede exceder 100 caracteres"],
    index: true,
    default: "Perú",
  },

  postalCode: {
    type: String,
    trim: true,
    maxlength: [20, "El código postal no puede exceder 20 caracteres"],
    index: true,
  },

  // Coordenadas geográficas (CRÍTICO para geolocalización)
  coordinates: {
    type: {
      type: String,
      enum: ["Point"],
      default: "Point",
    },
    coordinates: {
      type: [Number], // [longitude, latitude]
      required: [true, "Las coordenadas son requeridas"],
      validate: {
        validator: function (coords) {
          return (
            coords &&
            coords.length === 2 &&
            coords[0] >= -180 &&
            coords[0] <= 180 && // Longitude
            coords[1] >= -90 &&
            coords[1] <= 90
          ); // Latitude
        },
        message:
          "Las coordenadas deben estar en formato [longitude, latitude] válido",
      },
      index: "2dsphere",
    },
  },

  // Componentes estructurados de la dirección
  components: AddressComponentsSchema,

  // Dirección formateada
  formattedAddress: {
    type: String,
    required: [true, "La dirección formateada es requerida"],
    maxlength: [500, "La dirección formateada no puede exceder 500 caracteres"],
    index: "text",
  },

  // Información adicional
  addressType: {
    type: String,
    enum: [
      "business",
      "residential",
      "office",
      "warehouse",
      "store",
      "industrial",
      "commercial",
    ],
    default: "business",
    index: true,
  },

  // Validación y calidad de datos
  isValidated: {
    type: Boolean,
    default: false,
    index: true,
  },

  validationSource: {
    type: String,
    enum: [
      "google_maps",
      "openstreetmap",
      "manual",
      "user_input",
      "gps",
      "api_service",
    ],
    index: true,
  },

  validatedAt: {
    type: Date,
  },

  validationScore: {
    type: Number,
    min: [0, "El puntaje de validación debe ser entre 0 y 100"],
    max: [100, "El puntaje de validación debe ser entre 0 y 100"],
    default: 50,
  },

  // Metadatos geográficos
  geolocationMetadata: GeolocationMetadataSchema,

  timezone: {
    type: String,
    default: "America/Lima",
    validate: {
      validator: function (v) {
        // Validación básica de timezone
        return /^[A-Za-z_\/]+$/.test(v);
      },
      message: "Zona horaria no válida",
    },
  },

  plusCode: {
    type: String,
    trim: true,
    maxlength: [20, "El Plus Code no puede exceder 20 caracteres"],
    validate: {
      validator: function (v) {
        // Validación básica de Google Plus Code
        return (
          !v ||
          /^[23456789CFGHJMPQRVWX]{8}\+[23456789CFGHJMPQRVWX]{2,3}$/.test(v)
        );
      },
      message: "Plus Code no válido",
    },
  },

  // Referencias y relaciones
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

  // Información de accesibilidad
  accessibility: {
    wheelchairAccessible: {
      type: Boolean,
      default: null,
    },
    hasParking: {
      type: Boolean,
      default: null,
    },
    parkingDetails: {
      type: String,
      maxlength: [
        200,
        "Los detalles de estacionamiento no pueden exceder 200 caracteres",
      ],
    },
    publicTransportNearby: {
      type: Boolean,
      default: null,
    },
    nearestStation: {
      name: String,
      distance: Number, // en metros
      type: {
        type: String,
        enum: ["bus", "metro", "train", "taxi", "bike_share"],
      },
    },
  },

  // Información de entorno
  environment: {
    isUrban: {
      type: Boolean,
      default: true,
    },
    populationDensity: {
      type: String,
      enum: ["low", "medium", "high"],
      default: "medium",
    },
    safetyRating: {
      type: Number,
      min: [1, "El rating de seguridad debe estar entre 1 y 5"],
      max: [5, "El rating de seguridad debe estar entre 1 y 5"],
    },
    noiseLevel: {
      type: String,
      enum: ["quiet", "moderate", "noisy"],
      default: "moderate",
    },
  },

  // Cache de direcciones alternativas
  alternativeFormats: {
    short: String,
    long: String,
    international: String,
    local: String,
  },

  // Metadatos de uso
  usage: {
    searchCount: {
      type: Number,
      default: 0,
      min: 0,
    },
    lastSearched: Date,
    clickCount: {
      type: Number,
      default: 0,
      min: 0,
    },
    lastClicked: Date,
    isPopular: {
      type: Boolean,
      default: false,
      index: true,
    },
  },

  // Campos base (auditoría, soft delete, etc.)
  ...BaseSchemeFields,
});

// Configurar el esquema con funcionalidades base
setupBaseSchema(AddressSchema, {
  addBaseFields: false, // Ya los agregamos manualmente arriba
});

// ================================
// ÍNDICES ESPECÍFICOS
// ================================

// Índice geográfico principal (CRÍTICO para geolocalización)
AddressSchema.index({ coordinates: "2dsphere" });

// Índices para búsqueda geográfica optimizada
AddressSchema.index({ city: 1, state: 1, country: 1 });
AddressSchema.index({ postalCode: 1, country: 1 });
AddressSchema.index({ country: 1, state: 1, city: 1 });

// Índices para relaciones
AddressSchema.index({ businessId: 1 });
AddressSchema.index({ userId: 1 });

// Índices para filtrado
AddressSchema.index({ addressType: 1, isValidated: 1 });
AddressSchema.index({ validationSource: 1, validatedAt: -1 });
AddressSchema.index({ "usage.isPopular": 1, "usage.searchCount": -1 });

// Índice de texto para búsqueda
AddressSchema.index(
  {
    formattedAddress: "text",
    streetAddress: "text",
    city: "text",
    "components.neighborhood": "text",
  },
  {
    name: "address_search_index",
    weights: {
      formattedAddress: 10,
      streetAddress: 8,
      city: 6,
      "components.neighborhood": 4,
    },
  }
);

// ================================
// VIRTUALS
// ================================

// Virtual para latitud
AddressSchema.virtual("latitude").get(function () {
  return this.coordinates?.coordinates[1];
});

// Virtual para longitud
AddressSchema.virtual("longitude").get(function () {
  return this.coordinates?.coordinates[0];
});

// Virtual para dirección corta
AddressSchema.virtual("shortAddress").get(function () {
  if (this.alternativeFormats?.short) {
    return this.alternativeFormats.short;
  }
  return `${this.streetAddress}, ${this.city}`;
});

// Virtual para dirección completa
AddressSchema.virtual("fullAddress").get(function () {
  let parts = [this.streetAddress];

  if (this.apartment) parts.push(`Apt ${this.apartment}`);
  parts.push(this.city);
  parts.push(this.state);
  if (this.postalCode) parts.push(this.postalCode);
  parts.push(this.country);

  return parts.join(", ");
});

// Virtual para verificar calidad de datos
AddressSchema.virtual("dataQuality").get(function () {
  let score = 0;

  // Factores de calidad
  if (this.isValidated) score += 30;
  if (this.coordinates && this.geolocationMetadata?.accuracy > 80) score += 25;
  if (this.postalCode) score += 15;
  if (this.components?.neighborhood) score += 10;
  if (this.plusCode) score += 10;
  if (this.validationSource && this.validationSource !== "user_input")
    score += 10;

  return Math.min(score, 100);
});

// ================================
// MÉTODOS DE INSTANCIA
// ================================

// Método para calcular distancia a otro punto
AddressSchema.methods.distanceTo = function (otherCoordinates, unit = "km") {
  if (!this.coordinates?.coordinates || !otherCoordinates) {
    return null;
  }

  const [lon1, lat1] = this.coordinates.coordinates;
  const [lon2, lat2] = Array.isArray(otherCoordinates)
    ? otherCoordinates
    : [otherCoordinates.longitude, otherCoordinates.latitude];

  const R = unit === "km" ? 6371 : 3959; // Radio de la Tierra en km o millas
  const dLat = this.toRadians(lat2 - lat1);
  const dLon = this.toRadians(lon2 - lon1);

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(this.toRadians(lat1)) *
      Math.cos(this.toRadians(lat2)) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  const distance = R * c;

  return Math.round(distance * 100) / 100; // Redondear a 2 decimales
};

// Método auxiliar para convertir grados a radianes
AddressSchema.methods.toRadians = function (degrees) {
  return degrees * (Math.PI / 180);
};

// Método para validar dirección
AddressSchema.methods.validateAddress = async function (source = "manual") {
  // Aquí iría la lógica de validación con servicios externos
  // Por ahora, marcamos como validado
  this.isValidated = true;
  this.validationSource = source;
  this.validatedAt = new Date();
  this.validationScore = this.dataQuality;

  return this;
};

// Método para actualizar coordenadas
AddressSchema.methods.updateCoordinates = function (
  longitude,
  latitude,
  metadata = {}
) {
  this.coordinates = {
    type: "Point",
    coordinates: [longitude, latitude],
  };

  if (metadata.accuracy !== undefined) {
    if (!this.geolocationMetadata) this.geolocationMetadata = {};
    this.geolocationMetadata.accuracy = metadata.accuracy;
    this.geolocationMetadata.locationType =
      metadata.locationType || "APPROXIMATE";
  }

  return this;
};

// Método para incrementar contadores de uso
AddressSchema.methods.recordUsage = function (type = "search") {
  if (!this.usage) {
    this.usage = { searchCount: 0, clickCount: 0 };
  }

  if (type === "search") {
    this.usage.searchCount++;
    this.usage.lastSearched = new Date();
  } else if (type === "click") {
    this.usage.clickCount++;
    this.usage.lastClicked = new Date();
  }

  // Marcar como popular si tiene muchas búsquedas
  this.usage.isPopular = this.usage.searchCount > 50;

  return this;
};

// Método para obtener dirección en formato específico
AddressSchema.methods.getFormattedAddress = function (format = "standard") {
  switch (format) {
    case "short":
      return this.shortAddress;
    case "full":
      return this.fullAddress;
    case "international":
      return this.alternativeFormats?.international || this.formattedAddress;
    case "local":
      return (
        this.alternativeFormats?.local || `${this.streetAddress}, ${this.city}`
      );
    default:
      return this.formattedAddress;
  }
};

// ================================
// MÉTODOS ESTÁTICOS
// ================================

// Buscar direcciones por proximidad
AddressSchema.statics.findNearby = function (
  longitude,
  latitude,
  maxDistance = 5000,
  options = {}
) {
  const {
    limit = 20,
    addressType = null,
    isValidated = null,
    minValidationScore = 0,
  } = options;

  let query = this.find({
    coordinates: {
      $near: {
        $geometry: {
          type: "Point",
          coordinates: [longitude, latitude],
        },
        $maxDistance: maxDistance, // en metros
      },
    },
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  });

  // Aplicar filtros adicionales
  if (addressType) {
    query = query.where({ addressType });
  }

  if (isValidated !== null) {
    query = query.where({ isValidated });
  }

  if (minValidationScore > 0) {
    query = query.where({ validationScore: { $gte: minValidationScore } });
  }

  return query.limit(limit);
};

// Buscar direcciones dentro de un área
AddressSchema.statics.findWithinBounds = function (bounds, options = {}) {
  const { southwest, northeast } = bounds;
  const { limit = 50, addressType = null } = options;

  let query = this.find({
    coordinates: {
      $geoWithin: {
        $box: [
          [southwest.lng, southwest.lat],
          [northeast.lng, northeast.lat],
        ],
      },
    },
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  });

  if (addressType) {
    query = query.where({ addressType });
  }

  return query.limit(limit);
};

// Buscar direcciones por ciudad
AddressSchema.statics.findByCity = function (city, options = {}) {
  const { limit = 50, state = null, country = "Perú" } = options;

  let query = this.find({
    city: new RegExp(city, "i"),
    country: country,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  });

  if (state) {
    query = query.where({ state: new RegExp(state, "i") });
  }

  return query.limit(limit).sort({ "usage.searchCount": -1 });
};

// Obtener estadísticas de direcciones
AddressSchema.statics.getAddressStats = async function () {
  const stats = await this.aggregate([
    {
      $match: {
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      },
    },
    {
      $group: {
        _id: null,
        totalAddresses: { $sum: 1 },
        validatedAddresses: {
          $sum: { $cond: [{ $eq: ["$isValidated", true] }, 1, 0] },
        },
        businessAddresses: {
          $sum: { $cond: [{ $ne: ["$businessId", null] }, 1, 0] },
        },
        avgValidationScore: { $avg: "$validationScore" },
        totalSearches: { $sum: "$usage.searchCount" },
      },
    },
  ]);

  return (
    stats[0] || {
      totalAddresses: 0,
      validatedAddresses: 0,
      businessAddresses: 0,
      avgValidationScore: 0,
      totalSearches: 0,
    }
  );
};

// Obtener direcciones populares
AddressSchema.statics.getPopularAddresses = function (limit = 10) {
  return this.find({
    "usage.isPopular": true,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  })
    .sort({ "usage.searchCount": -1 })
    .limit(limit)
    .populate("businessId", "businessName");
};

// Limpiar direcciones no validadas antiguas
AddressSchema.statics.cleanupUnvalidatedAddresses = async function (
  daysOld = 30
) {
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - daysOld);

  const result = await this.updateMany(
    {
      isValidated: false,
      createdAt: { $lt: cutoffDate },
      "usage.searchCount": { $lt: 5 }, // Direcciones poco usadas
    },
    {
      $set: { isDeleted: true, deletedAt: new Date() },
    }
  );

  return result;
};

// ================================
// MIDDLEWARES
// ================================

// Pre-save middleware
AddressSchema.pre("save", function (next) {
  // Normalizar datos
  if (this.city) this.city = this.city.trim();
  if (this.state) this.state = this.state.trim();
  if (this.country) this.country = this.country.trim();

  // Generar dirección formateada si no existe
  if (!this.formattedAddress) {
    this.formattedAddress = this.fullAddress;
  }

  // Generar formatos alternativos
  if (!this.alternativeFormats) {
    this.alternativeFormats = {};
  }

  if (!this.alternativeFormats.short) {
    this.alternativeFormats.short = this.shortAddress;
  }

  // Actualizar puntaje de validación
  if (!this.validationScore) {
    this.validationScore = this.dataQuality;
  }

  next();
});

// Post-save middleware
AddressSchema.post("save", function (doc, next) {
  if (doc.isNew) {
    console.log(
      `📍 Dirección creada: ${doc.city}, ${doc.state} (ID: ${doc._id})`
    );
  }
  next();
});

// ================================
// EXPORTAR MODELO
// ================================

export const Address = mongoose.model("Address", AddressSchema);
export default Address;
