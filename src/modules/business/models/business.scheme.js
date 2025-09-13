// =============================================================================
// src/modules/business/models/business.scheme.js
// =============================================================================
import mongoose from "mongoose";
import {
  BaseSchemaFields,
  setupBaseSchema,
  CommonValidators,
} from "../../core/models/base.scheme.js";
import {
  createMultiLanguageField,
  createMultiLanguageContent,
} from "../../core/models/multi_language_pattern.scheme.js";

/**
 * Schema para horarios de operación
 */
const BusinessHoursSchema = new mongoose.Schema(
  {
    dayOfWeek: {
      type: Number,
      required: [true, "El día de la semana es requerido"],
      min: [0, "El día debe estar entre 0 (domingo) y 6 (sábado)"],
      max: [6, "El día debe estar entre 0 (domingo) y 6 (sábado)"],
    },
    openTime: {
      type: String,
      required: [true, "La hora de apertura es requerida"],
      validate: {
        validator: function (v) {
          return /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(v);
        },
        message: "Formato de hora inválido (debe ser HH:MM)",
      },
    },
    closeTime: {
      type: String,
      required: [true, "La hora de cierre es requerida"],
      validate: {
        validator: function (v) {
          return /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(v);
        },
        message: "Formato de hora inválido (debe ser HH:MM)",
      },
    },
    isClosed: {
      type: Boolean,
      default: false,
    },
    is24Hours: {
      type: Boolean,
      default: false,
    },
  },
  { _id: false }
);

/**
 * Schema para información de contacto
 */
const ContactInfoSchema = new mongoose.Schema(
  {
    primaryPhone: {
      type: String,
      trim: true,
      maxlength: [20, "El teléfono principal no puede exceder 20 caracteres"],
      validate: CommonValidators.phone,
    },
    secondaryPhone: {
      type: String,
      trim: true,
      maxlength: [20, "El teléfono secundario no puede exceder 20 caracteres"],
      validate: CommonValidators.phone,
    },
    whatsapp: {
      type: String,
      trim: true,
      maxlength: [20, "El WhatsApp no puede exceder 20 caracteres"],
      validate: CommonValidators.phone,
    },
    email: {
      type: String,
      lowercase: true,
      trim: true,
      validate: CommonValidators.email,
    },
    website: {
      type: String,
      validate: CommonValidators.url,
    },
    socialMedia: {
      facebook: {
        type: String,
        validate: {
          validator: function (v) {
            return !v || /^https?:\/\/(www\.)?facebook\.com\//.test(v);
          },
          message: "URL de Facebook no válida",
        },
      },
      instagram: {
        type: String,
        validate: {
          validator: function (v) {
            return !v || /^https?:\/\/(www\.)?instagram\.com\//.test(v);
          },
          message: "URL de Instagram no válida",
        },
      },
      twitter: {
        type: String,
        validate: {
          validator: function (v) {
            return !v || /^https?:\/\/(www\.)?(twitter\.com|x\.com)\//.test(v);
          },
          message: "URL de Twitter/X no válida",
        },
      },
    },
  },
  { _id: false }
);

/**
 * Schema para documentos de verificación
 */
const VerificationDocumentSchema = new mongoose.Schema(
  {
    documentType: {
      type: String,
      required: [true, "El tipo de documento es requerido"],
      enum: [
        "business_license",
        "tax_id",
        "identity_card",
        "permit",
        "certificate",
        "other",
      ],
    },
    documentUrl: {
      type: String,
      required: [true, "La URL del documento es requerida"],
      validate: CommonValidators.url,
    },
    uploadedAt: {
      type: Date,
      default: Date.now,
    },
    verifiedAt: {
      type: Date,
    },
    verifiedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    verificationStatus: {
      type: String,
      enum: ["pending", "approved", "rejected", "expired"],
      default: "pending",
    },
  },
  { _id: false }
);

/**
 * Schema para métricas de empresa
 */
const BusinessMetricsSchema = new mongoose.Schema(
  {
    totalViews: {
      type: Number,
      default: 0,
      min: [0, "Las vistas totales no pueden ser negativas"],
    },
    totalContacts: {
      type: Number,
      default: 0,
      min: [0, "Los contactos totales no pueden ser negativos"],
    },
    phoneClicks: {
      type: Number,
      default: 0,
      min: [0, "Los clics en teléfono no pueden ser negativos"],
    },
    websiteClicks: {
      type: Number,
      default: 0,
      min: [0, "Los clics en sitio web no pueden ser negativos"],
    },
    averageRating: {
      type: Number,
      default: 0,
      min: [0, "La calificación promedio no puede ser negativa"],
      max: [5, "La calificación promedio no puede exceder 5"],
    },
    totalReviews: {
      type: Number,
      default: 0,
      min: [0, "El total de reseñas no puede ser negativo"],
    },
  },
  { _id: false }
);

/**
 * Schema para galería de imágenes
 */
const GalleryImageSchema = new mongoose.Schema(
  {
    url: {
      type: String,
      required: true,
      validate: CommonValidators.url,
    },
    caption: createMultiLanguageField(false),
    uploadedAt: {
      type: Date,
      default: Date.now,
    },
    uploadedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    isMain: {
      type: Boolean,
      default: false,
    },
    order: {
      type: Number,
      default: 0,
    },
  },
  { _id: false }
);

/**
 * Schema para managers de empresa
 */
const BusinessManagerSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    role: {
      type: String,
      enum: ["manager", "editor", "viewer"],
      default: "manager",
    },
    permissions: [
      {
        type: String,
        enum: [
          "edit_info",
          "manage_reviews",
          "view_analytics",
          "manage_hours",
          "manage_photos",
        ],
      },
    ],
    addedAt: {
      type: Date,
      default: Date.now,
    },
    addedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
  },
  { _id: false }
);

/**
 * Schema principal de Empresa
 */
const BusinessSchema = new mongoose.Schema({
  // Información principal multiidioma
  businessName: createMultiLanguageField(true, { textIndex: true }),
  description: createMultiLanguageField(true, { textIndex: true }),
  shortDescription: createMultiLanguageField(false, { textIndex: true }),

  // Servicios y especialidades (multiidioma)
  services: [createMultiLanguageField(false)],
  specializations: [createMultiLanguageField(false)],

  // Palabras clave para búsqueda
  keywords: [
    {
      type: String,
      trim: true,
      lowercase: true,
      maxlength: [50, "Las palabras clave no pueden exceder 50 caracteres"],
    },
  ],

  // Propiedad y gestión
  ownerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: [true, "El propietario de la empresa es requerido"],
    index: true,
  },

  managers: [BusinessManagerSchema],

  // Categorización
  categories: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "BusinessCategory",
      required: true,
      index: true,
    },
  ],

  primaryCategory: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "BusinessCategory",
    required: [true, "La categoría principal es requerida"],
    index: true,
  },

  tags: [
    {
      type: String,
      trim: true,
      lowercase: true,
      maxlength: [30, "Las etiquetas no pueden exceder 30 caracteres"],
    },
  ],

  // Ubicación
  address: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Address",
    required: [true, "La dirección es requerida"],
    index: true,
  },

  // Coordenadas duplicadas para consultas rápidas sin populate
  coordinates: {
    type: {
      type: String,
      enum: ["Point"],
      default: "Point",
    },
    coordinates: {
      type: [Number], // [longitude, latitude]
      index: "2dsphere",
    },
  },

  // Información de contacto
  contactInfo: ContactInfoSchema,

  // Horarios de operación
  operatingHours: [BusinessHoursSchema],

  timezone: {
    type: String,
    default: "America/Lima",
  },

  // Estado y verificación
  verificationStatus: {
    type: String,
    enum: ["pending", "verified", "rejected", "suspended", "under_review"],
    default: "pending",
    index: true,
  },

  verificationDocuments: [VerificationDocumentSchema],

  verifiedAt: {
    type: Date,
  },

  verifiedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },

  // Estado del negocio
  businessStatus: {
    type: String,
    enum: [
      "active",
      "inactive",
      "temporarily_closed",
      "permanently_closed",
      "coming_soon",
    ],
    default: "active",
    index: true,
  },

  isPublic: {
    type: Boolean,
    default: true,
    index: true,
  },

  isFeatured: {
    type: Boolean,
    default: false,
    index: true,
  },

  // Métricas y estadísticas
  metrics: BusinessMetricsSchema,

  // Multimedia
  logo: {
    type: String,
    validate: CommonValidators.url,
  },

  coverImage: {
    type: String,
    validate: CommonValidators.url,
  },

  gallery: [GalleryImageSchema],

  // SEO y búsqueda
  slug: {
    type: String,
    unique: true,
    lowercase: true,
    trim: true,
    maxlength: [150, "El slug no puede exceder 150 caracteres"],
    match: [
      /^[a-z0-9-]+$/,
      "El slug solo puede contener letras minúsculas, números y guiones",
    ],
    index: true,
  },

  metaDescription: createMultiLanguageField(false),

  // Configuración de negocio
  businessConfig: {
    allowReviews: {
      type: Boolean,
      default: true,
    },
    autoApproveReviews: {
      type: Boolean,
      default: false,
    },
    hasDelivery: {
      type: Boolean,
      default: false,
    },
    hasPickup: {
      type: Boolean,
      default: false,
    },
    acceptsCreditCards: {
      type: Boolean,
      default: true,
    },
    hasWifi: {
      type: Boolean,
      default: false,
    },
    hasParking: {
      type: Boolean,
      default: false,
    },
    isWheelchairAccessible: {
      type: Boolean,
      default: false,
    },
  },

  // Información adicional
  establishedDate: {
    type: Date,
    validate: {
      validator: function (v) {
        return !v || v <= new Date();
      },
      message: "La fecha de establecimiento no puede ser futura",
    },
  },

  employeeCount: {
    type: String,
    enum: ["1", "2-10", "11-50", "51-200", "201-500", "500+"],
  },

  priceRange: {
    type: String,
    enum: ["$", "$$", "$$$", "$$$$"],
  },

  // Fechas importantes
  lastActivityAt: {
    type: Date,
    default: Date.now,
    index: true,
  },

  // Campos base (auditoría, soft delete, etc.)
  ...BaseSchemaFields,
});

// Configurar el esquema con funcionalidades base
setupBaseSchema(BusinessSchema, {
  addBaseFields: false, // Ya los agregamos manualmente arriba
});

// ================================
// ÍNDICES ESPECÍFICOS
// ================================

// Índices únicos
BusinessSchema.index({ slug: 1 }, { unique: true });

// Índices geográficos
BusinessSchema.index({ coordinates: "2dsphere" });

// Índices de relaciones
BusinessSchema.index({ ownerId: 1, businessStatus: 1 });
BusinessSchema.index({ categories: 1, businessStatus: 1, isPublic: 1 });
BusinessSchema.index({ primaryCategory: 1, businessStatus: 1, isPublic: 1 });

// Índices de estado
BusinessSchema.index({ verificationStatus: 1, businessStatus: 1 });
BusinessSchema.index({ businessStatus: 1, isPublic: 1, isFeatured: 1 });

// Índices para métricas
BusinessSchema.index({
  "metrics.averageRating": -1,
  "metrics.totalReviews": -1,
});
BusinessSchema.index({ "metrics.totalViews": -1 });
BusinessSchema.index({ lastActivityAt: -1 });

// Índice de texto multiidioma para búsqueda
BusinessSchema.index(
  {
    "businessName.original.text": "text",
    "description.original.text": "text",
    "shortDescription.original.text": "text",
    keywords: "text",
    tags: "text",
  },
  {
    name: "business_search_index",
    weights: {
      "businessName.original.text": 10,
      "shortDescription.original.text": 8,
      "description.original.text": 5,
      keywords: 3,
      tags: 2,
    },
  }
);

// ================================
// VIRTUALS
// ================================

// Virtual para verificar si está abierto ahora
BusinessSchema.virtual("isOpenNow").get(function () {
  if (!this.operatingHours || this.operatingHours.length === 0) {
    return false;
  }

  const now = new Date();
  const dayOfWeek = now.getDay();
  const currentTime = now.toTimeString().slice(0, 5);

  const todayHours = this.operatingHours.find((h) => h.dayOfWeek === dayOfWeek);

  if (!todayHours || todayHours.isClosed) {
    return false;
  }

  if (todayHours.is24Hours) {
    return true;
  }

  return (
    currentTime >= todayHours.openTime && currentTime <= todayHours.closeTime
  );
});

// Virtual para verificar si está verificado completamente
BusinessSchema.virtual("isFullyVerified").get(function () {
  return (
    this.verificationStatus === "verified" &&
    this.verificationDocuments &&
    this.verificationDocuments.length > 0
  );
});

// Virtual para calcular completitud del perfil
BusinessSchema.virtual("profileCompleteness").get(function () {
  let score = 0;

  // Información básica (40 puntos)
  if (this.businessName?.original?.text) score += 15;
  if (this.description?.original?.text) score += 15;
  if (this.contactInfo?.primaryPhone) score += 10;

  // Ubicación y horarios (30 puntos)
  if (this.address) score += 15;
  if (this.operatingHours && this.operatingHours.length > 0) score += 15;

  // Categorización (15 puntos)
  if (this.primaryCategory) score += 10;
  if (this.categories && this.categories.length > 0) score += 5;

  // Multimedia y verificación (15 puntos)
  if (this.logo) score += 8;
  if (this.verificationStatus === "verified") score += 7;

  return Math.min(score, 100);
});

// ================================
// MÉTODOS DE INSTANCIA
// ================================

// Método para verificar si está abierto en un momento específico
BusinessSchema.methods.isOpenAt = function (date) {
  const dayOfWeek = date.getDay();
  const time = date.toTimeString().slice(0, 5);

  const dayHours = this.operatingHours.find((h) => h.dayOfWeek === dayOfWeek);

  if (!dayHours || dayHours.isClosed) {
    return false;
  }

  if (dayHours.is24Hours) {
    return true;
  }

  return time >= dayHours.openTime && time <= dayHours.closeTime;
};

// Método para agregar manager
BusinessSchema.methods.addManager = function (
  userId,
  role = "manager",
  permissions = [],
  addedBy = null
) {
  const existingManager = this.managers.find((m) => m.userId.equals(userId));
  if (existingManager) {
    throw new Error("El usuario ya es manager de esta empresa");
  }

  this.managers.push({
    userId,
    role,
    permissions,
    addedAt: new Date(),
    addedBy,
  });

  return this;
};

// Método para remover manager
BusinessSchema.methods.removeManager = function (userId) {
  this.managers = this.managers.filter((m) => !m.userId.equals(userId));
  return this;
};

// Método para verificar si un usuario puede gestionar la empresa
BusinessSchema.methods.canUserManage = function (userId) {
  // El propietario siempre puede gestionar
  if (this.ownerId.equals(userId)) {
    return true;
  }

  // Verificar si es manager
  const manager = this.managers.find((m) => m.userId.equals(userId));
  return manager && ["manager", "editor"].includes(manager.role);
};

// Método para generar slug único
BusinessSchema.methods.generateUniqueSlug = async function (baseName = null) {
  const name = baseName || this.businessName?.original?.text || "business";

  const baseSlug = name
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .substring(0, 100);

  let slug = baseSlug;
  let counter = 1;

  while (
    await this.constructor.findOne({
      slug,
      _id: { $ne: this._id },
    })
  ) {
    slug = `${baseSlug}-${counter}`;
    counter++;
  }

  this.slug = slug;
  return slug;
};

// Método para actualizar métricas
BusinessSchema.methods.updateMetrics = async function (
  metricType,
  increment = 1
) {
  const validMetrics = [
    "totalViews",
    "totalContacts",
    "phoneClicks",
    "websiteClicks",
  ];

  if (!validMetrics.includes(metricType)) {
    throw new Error(`Tipo de métrica inválido: ${metricType}`);
  }

  if (!this.metrics) {
    this.metrics = {};
  }

  this.metrics[metricType] = (this.metrics[metricType] || 0) + increment;
  this.lastActivityAt = new Date();

  return this.save();
};

// ================================
// MÉTODOS ESTÁTICOS
// ================================

// Buscar empresas por proximidad
BusinessSchema.statics.findNearby = function (
  longitude,
  latitude,
  maxDistance = 5000,
  options = {}
) {
  const {
    limit = 20,
    categories = null,
    businessStatus = "active",
    isPublic = true,
    minRating = 0,
  } = options;

  let query = this.find({
    coordinates: {
      $near: {
        $geometry: {
          type: "Point",
          coordinates: [longitude, latitude],
        },
        $maxDistance: maxDistance,
      },
    },
    businessStatus,
    isPublic,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  });

  if (categories) {
    const categoryArray = Array.isArray(categories) ? categories : [categories];
    query = query.where({ categories: { $in: categoryArray } });
  }

  if (minRating > 0) {
    query = query.where({ "metrics.averageRating": { $gte: minRating } });
  }

  return query
    .populate("primaryCategory", "categoryName categorySlug")
    .populate("address", "formattedAddress city state")
    .limit(limit)
    .lean();
};

// Buscar empresas con texto
BusinessSchema.statics.searchBusinesses = function (searchText, options = {}) {
  const {
    limit = 20,
    categories = null,
    location = null,
    radius = 10000,
    businessStatus = "active",
    isPublic = true,
  } = options;

  let query = this.find(
    {
      $text: { $search: searchText },
      businessStatus,
      isPublic,
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    },
    {
      score: { $meta: "textScore" },
    }
  );

  if (location && location.longitude && location.latitude) {
    query = query.where({
      coordinates: {
        $near: {
          $geometry: {
            type: "Point",
            coordinates: [location.longitude, location.latitude],
          },
          $maxDistance: radius,
        },
      },
    });
  }

  if (categories) {
    const categoryArray = Array.isArray(categories) ? categories : [categories];
    query = query.where({ categories: { $in: categoryArray } });
  }

  return query
    .sort({ score: { $meta: "textScore" }, "metrics.averageRating": -1 })
    .populate("primaryCategory", "categoryName categorySlug")
    .populate("address", "formattedAddress city state")
    .limit(limit);
};

// Obtener empresas populares
BusinessSchema.statics.getPopularBusinesses = function (options = {}) {
  const { limit = 10, categoryId = null } = options;

  let query = this.find({
    businessStatus: "active",
    isPublic: true,
    "metrics.totalViews": { $gte: 100 },
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  });

  if (categoryId) {
    query = query.where({ categories: categoryId });
  }

  return query
    .sort({
      "metrics.totalViews": -1,
      "metrics.averageRating": -1,
    })
    .populate("primaryCategory", "categoryName categorySlug")
    .populate("address", "formattedAddress city state")
    .limit(limit);
};

// Obtener empresas destacadas
BusinessSchema.statics.getFeaturedBusinesses = function (limit = 5) {
  return this.find({
    isFeatured: true,
    businessStatus: "active",
    isPublic: true,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  })
    .sort({ "metrics.averageRating": -1, "metrics.totalViews": -1 })
    .populate("primaryCategory", "categoryName categorySlug")
    .populate("address", "formattedAddress city state")
    .limit(limit);
};

// Obtener empresas por propietario
BusinessSchema.statics.getBusinessesByOwner = function (ownerId, options = {}) {
  const { includeInactive = false, page = 1, limit = 10 } = options;

  let query = this.find({
    ownerId,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  });

  if (!includeInactive) {
    query = query.where({ businessStatus: "active" });
  }

  return query
    .sort({ lastActivityAt: -1 })
    .populate("primaryCategory", "categoryName categorySlug")
    .populate("address", "formattedAddress city state")
    .skip((page - 1) * limit)
    .limit(limit);
};

// Obtener estadísticas de empresas
BusinessSchema.statics.getBusinessStats = async function () {
  const stats = await this.aggregate([
    {
      $match: {
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      },
    },
    {
      $group: {
        _id: null,
        totalBusinesses: { $sum: 1 },
        activeBusinesses: {
          $sum: { $cond: [{ $eq: ["$businessStatus", "active"] }, 1, 0] },
        },
        verifiedBusinesses: {
          $sum: { $cond: [{ $eq: ["$verificationStatus", "verified"] }, 1, 0] },
        },
        featuredBusinesses: {
          $sum: { $cond: [{ $eq: ["$isFeatured", true] }, 1, 0] },
        },
        totalViews: { $sum: "$metrics.totalViews" },
        avgRating: { $avg: "$metrics.averageRating" },
      },
    },
  ]);

  return (
    stats[0] || {
      totalBusinesses: 0,
      activeBusinesses: 0,
      verifiedBusinesses: 0,
      featuredBusinesses: 0,
      totalViews: 0,
      avgRating: 0,
    }
  );
};

// ================================
// MIDDLEWARES
// ================================

// Pre-save middleware
BusinessSchema.pre("save", async function (next) {
  try {
    // Generar slug si no existe
    if (!this.slug && this.businessName?.original?.text) {
      await this.generateUniqueSlug();
    }

    // Sincronizar coordenadas con dirección
    if (this.isModified("address") && this.address) {
      try {
        const Address = mongoose.model("Address");
        const address = await Address.findById(this.address);
        if (address && address.coordinates) {
          this.coordinates = {
            type: "Point",
            coordinates: address.coordinates.coordinates,
          };
        }
      } catch (error) {
        console.warn(
          "No se pudieron sincronizar las coordenadas:",
          error.message
        );
      }
    }

    // Validar que la categoría principal esté en la lista de categorías
    if (this.primaryCategory && this.categories) {
      if (!this.categories.includes(this.primaryCategory)) {
        this.categories.push(this.primaryCategory);
      }
    }

    // Actualizar lastActivityAt en modificaciones importantes
    const importantFields = [
      "businessName",
      "description",
      "contactInfo",
      "operatingHours",
      "logo",
    ];

    if (importantFields.some((field) => this.isModified(field))) {
      this.lastActivityAt = new Date();
    }

    next();
  } catch (error) {
    next(error);
  }
});

// Post-save middleware
BusinessSchema.post("save", async function (doc, next) {
  try {
    if (doc.isNew) {
      console.log(
        `🏢 Empresa creada: ${
          doc.businessName?.original?.text || "Sin nombre"
        } (ID: ${doc._id})`
      );

      // Actualizar estadísticas de categorías
      if (doc.categories && doc.categories.length > 0) {
        const BusinessCategory = mongoose.model("BusinessCategory");

        for (const categoryId of doc.categories) {
          try {
            const category = await BusinessCategory.findById(categoryId);
            if (category) {
              await category.updateStats();
            }
          } catch (error) {
            console.warn(
              `Error actualizando estadísticas de categoría ${categoryId}:`,
              error.message
            );
          }
        }
      }
    }

    next();
  } catch (error) {
    console.error("Error en post-save de Business:", error);
    next();
  }
});

// ================================
// EXPORTAR MODELO
// ================================

export const Business = mongoose.model("Business", BusinessSchema);
export default Business;
