// =============================================================================
// src/modules/business/models/business_category.scheme.js - VERSIÓN OPTIMIZADA
// Segundo esquema + mejores funcionalidades del primero
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
  MultiLanguageValidators,
  SUPPORTED_LANGUAGES,
} from "../../core/models/multi_language_pattern.scheme.js";

/**
 * Schema para metadatos específicos de categoría (mejorado)
 */
const CategoryMetadataSchema = new mongoose.Schema(
  {
    color: {
      type: String,
      validate: {
        validator: function (v) {
          return !v || /^#[0-9A-F]{6}$/i.test(v);
        },
        message: "El color debe ser un código hexadecimal válido (#RRGGBB)",
      },
      default: "#6B7280",
    },
    icon: {
      type: String,
      trim: true,
      maxlength: [50, "El icono no puede exceder 50 caracteres"],
      default: "building",
    },
    iconLibrary: {
      type: String,
      enum: ["fontawesome", "material", "custom", "emoji"],
      default: "fontawesome",
    },
    imageUrl: {
      type: String,
      validate: CommonValidators.url,
    },
    bannerUrl: {
      type: String,
      validate: CommonValidators.url,
    },
    // NUEVO: Del primer esquema - información de popularidad
    popularityScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
      index: true,
    },
    isPromoted: {
      type: Boolean,
      default: false,
      index: true,
    },
    promotionWeight: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
  },
  { _id: false }
);

/**
 * Schema para configuración SEO de categoría (del segundo esquema)
 */
const CategorySEOSchema = new mongoose.Schema(
  {
    metaTitle: createMultiLanguageField(false),
    metaDescription: createMultiLanguageField(false),
    keywords: [
      {
        type: String,
        trim: true,
        lowercase: true,
        maxlength: 50,
      },
    ],
    canonicalUrl: {
      type: String,
      validate: CommonValidators.url,
    },
    ogImage: {
      type: String,
      validate: CommonValidators.url,
    },
    // NUEVO: SEO adicional
    focusKeyword: {
      type: String,
      trim: true,
      maxlength: 100,
    },
    seoScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },
  },
  { _id: false }
);

/**
 * Schema para códigos de industria (selectivo del primer esquema)
 */
const IndustryCodesSchema = new mongoose.Schema(
  {
    // Código personalizado del sistema
    customCode: {
      type: String,
      uppercase: true,
      maxlength: 20,
      index: true,
    },

    // NAICS (North American Industry Classification System)
    naicsCode: {
      type: String,
      trim: true,
      maxlength: [10, "El código NAICS no puede exceder 10 caracteres"],
      validate: {
        validator: function (v) {
          return !v || /^\d{2,6}$/.test(v);
        },
        message: "El código NAICS debe contener solo números (2-6 dígitos)",
      },
      index: true,
    },

    // Código de Google Business Categories (útil para integración)
    googleBusinessCategory: {
      type: String,
      maxlength: 100,
    },
  },
  { _id: false }
);

/**
 * Schema para palabras clave y búsqueda (simplificado del primer esquema)
 */
const SearchKeywordsSchema = new mongoose.Schema(
  {
    // Términos de búsqueda principales
    primaryKeywords: [
      {
        type: String,
        trim: true,
        lowercase: true,
        maxlength: 50,
      },
    ],

    // Sinónimos y términos alternativos
    aliases: createMultiLanguageField(false),

    // Etiquetas para clasificación interna
    tags: [
      {
        type: String,
        trim: true,
        lowercase: true,
        maxlength: 30,
      },
    ],

    // Palabras clave para SEO
    seoKeywords: [
      {
        type: String,
        trim: true,
        lowercase: true,
        maxlength: 50,
      },
    ],
  },
  { _id: false }
);

/**
 * Schema principal de BusinessCategory (optimizado)
 */
const BusinessCategorySchema = new mongoose.Schema({
  // Información multiidioma (del segundo esquema)
  categoryName: createMultiLanguageField(true, {
    textIndex: true,
    validate: [
      MultiLanguageValidators.hasOriginalText,
      MultiLanguageValidators.minLength(2),
      MultiLanguageValidators.maxLength(100),
    ],
  }),

  description: createMultiLanguageField(false, {
    textIndex: true,
    validate: [
      MultiLanguageValidators.minLength(10),
      MultiLanguageValidators.maxLength(500),
    ],
  }),

  shortDescription: createMultiLanguageField(false, {
    validate: [
      MultiLanguageValidators.minLength(5),
      MultiLanguageValidators.maxLength(150),
    ],
  }),

  // Estructura jerárquica (del segundo esquema)
  parentCategory: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "BusinessCategory",
    default: null,
    index: true,
    validate: {
      validator: function (v) {
        return !v || !this._id || !v.equals(this._id);
      },
      message: "Una categoría no puede ser su propia categoría padre",
    },
  },

  // NUEVO: Del primer esquema - Array de categorías hijas para navegación rápida
  childCategories: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "BusinessCategory",
    },
  ],

  categoryLevel: {
    type: Number,
    default: 0,
    min: [0, "El nivel de categoría no puede ser negativo"],
    max: [5, "El nivel máximo de categoría es 5"],
    index: true,
  },

  categoryPath: {
    type: String,
    index: true,
    maxlength: [200, "La ruta de categoría no puede exceder 200 caracteres"],
  },

  // Identificadores únicos
  categorySlug: {
    type: String,
    required: [true, "El slug de categoría es requerido"],
    unique: true,
    lowercase: true,
    trim: true,
    maxlength: [100, "El slug no puede exceder 100 caracteres"],
    match: [
      /^[a-z0-9-]+$/,
      "El slug solo puede contener letras minúsculas, números y guiones",
    ],
    index: true,
  },

  // NUEVO: Del primer esquema - Código de categoría para APIs
  categoryCode: {
    type: String,
    uppercase: true,
    trim: true,
    maxlength: 50,
    match: /^[A-Z0-9_]+$/,
    index: true,
    sparse: true, // Permite que sea opcional pero único
  },

  // Códigos de industria (simplificado del primer esquema)
  industryCodes: {
    type: IndustryCodesSchema,
  },

  // Palabras clave de búsqueda (del primer esquema optimizado)
  searchKeywords: {
    type: SearchKeywordsSchema,
  },

  // Estado y configuración (del segundo esquema)
  isActive: {
    type: Boolean,
    default: true,
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

  sortOrder: {
    type: Number,
    default: 0,
    index: true,
  },

  requiresApproval: {
    type: Boolean,
    default: false,
    index: true,
  },

  // NUEVO: Del primer esquema - Control de moderación
  autoApprove: {
    type: Boolean,
    default: true,
  },

  // Metadatos y presentación (mejorado)
  metadata: CategoryMetadataSchema,

  // SEO y marketing (del segundo esquema - CRÍTICO)
  seo: CategorySEOSchema,

  // Estadísticas y métricas (del segundo esquema expandido)
  stats: {
    businessCount: {
      type: Number,
      default: 0,
      min: [0, "El conteo de empresas no puede ser negativo"],
      index: true,
    },
    activeBusinessCount: {
      type: Number,
      default: 0,
      min: [0, "El conteo de empresas activas no puede ser negativo"],
    },
    totalViews: {
      type: Number,
      default: 0,
      min: [0, "El total de vistas no puede ser negativo"],
    },
    monthlyViews: {
      type: Number,
      default: 0,
      min: [0, "Las vistas mensuales no pueden ser negativas"],
    },
    averageRating: {
      type: Number,
      default: 0,
      min: [0, "La calificación promedio no puede ser negativa"],
      max: [5, "La calificación promedio no puede exceder 5"],
    },
    lastBusinessAdded: {
      type: Date,
    },
    // NUEVO: Del primer esquema
    lastStatsUpdate: {
      type: Date,
      default: Date.now,
    },
  },

  // Configuración específica de categoría (del segundo esquema)
  categoryConfig: {
    allowSubcategories: {
      type: Boolean,
      default: true,
    },
    maxSubcategories: {
      type: Number,
      default: 20,
      min: [0, "El máximo de subcategorías no puede ser negativo"],
    },
    allowMultipleSelection: {
      type: Boolean,
      default: false,
    },
    requiresVerification: {
      type: Boolean,
      default: false,
    },
    // NUEVO: Del primer esquema - Campos customizables por categoría
    customFields: [
      {
        fieldName: {
          type: String,
          required: true,
          trim: true,
          maxlength: 50,
        },
        fieldType: {
          type: String,
          enum: ["text", "number", "boolean", "select", "multiselect"],
          required: true,
        },
        isRequired: {
          type: Boolean,
          default: false,
        },
        options: [String], // Para campos select/multiselect
      },
    ],
    // NUEVO: Del primer esquema - Validación básica
    minimumPhotos: {
      type: Number,
      min: 0,
      max: 20,
      default: 1,
    },
    requiresDocuments: {
      type: Boolean,
      default: false,
    },
  },

  // Restricciones geográficas (del segundo esquema)
  geographicRestrictions: {
    allowedCountries: [
      {
        type: String,
        uppercase: true,
        length: [2, "El código de país debe tener 2 caracteres"],
      },
    ],
    restrictedCountries: [
      {
        type: String,
        uppercase: true,
        length: [2, "El código de país debe tener 2 caracteres"],
      },
    ],
    isGlobalCategory: {
      type: Boolean,
      default: true,
    },
  },

  // Relaciones entre categorías
  relatedCategories: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "BusinessCategory",
    },
  ],

  // Display y prioridad (del primer esquema)
  displayPriority: {
    type: Number,
    min: 1,
    max: 100,
    default: 50,
    index: true,
  },

  // Campos base de auditoría
  ...BaseSchemaFields,
});

// Configurar el esquema con funcionalidades base
setupBaseSchema(BusinessCategorySchema, {
  addTimestamps: false,
});

// ================================
// ÍNDICES ESPECÍFICOS OPTIMIZADOS
// ================================

// Índices únicos
BusinessCategorySchema.index({ categorySlug: 1 }, { unique: true });
BusinessCategorySchema.index(
  { categoryCode: 1 },
  { unique: true, sparse: true }
);

// Índices jerárquicos
BusinessCategorySchema.index({
  parentCategory: 1,
  sortOrder: 1,
  displayPriority: -1,
});
BusinessCategorySchema.index({ categoryLevel: 1, isActive: 1 });
BusinessCategorySchema.index({ categoryPath: 1 });

// Índices de estado y filtrado
BusinessCategorySchema.index({
  isActive: 1,
  isPublic: 1,
  isFeatured: 1,
});

// Índices para búsqueda y clasificación
BusinessCategorySchema.index({ "industryCodes.naicsCode": 1 });
BusinessCategorySchema.index({ "industryCodes.customCode": 1 });
BusinessCategorySchema.index({ "searchKeywords.primaryKeywords": 1 });

// Índices para estadísticas y popularidad
BusinessCategorySchema.index({
  "stats.businessCount": -1,
  "metadata.popularityScore": -1,
});
BusinessCategorySchema.index({
  "stats.averageRating": -1,
  isActive: 1,
});

// Índices geográficos para restricciones
BusinessCategorySchema.index({ "geographicRestrictions.allowedCountries": 1 });
BusinessCategorySchema.index({
  "geographicRestrictions.restrictedCountries": 1,
});

// Índice de texto multiidioma para búsqueda optimizada
BusinessCategorySchema.index(
  {
    "categoryName.original.text": "text",
    "description.original.text": "text",
    "shortDescription.original.text": "text",
    "searchKeywords.primaryKeywords": "text",
    "searchKeywords.tags": "text",
  },
  {
    name: "category_search_index",
    weights: {
      "categoryName.original.text": 10,
      "searchKeywords.primaryKeywords": 8,
      "description.original.text": 5,
      "shortDescription.original.text": 3,
      "searchKeywords.tags": 2,
    },
  }
);

// ================================
// MIDDLEWARE OPTIMIZADO
// ================================

// Pre-save middleware
BusinessCategorySchema.pre("save", async function (next) {
  try {
    // Generar slug si no existe
    if (!this.categorySlug && this.categoryName?.original?.text) {
      await this.generateUniqueSlug(this.categoryName.original.text);
    }

    // Generar categoryPath automáticamente (del primer esquema)
    if (this.isNew || this.isModified("parentCategory")) {
      this.categoryPath = await this.generateCategoryPath();
    }

    // Actualizar nivel de categoría automáticamente
    if (
      this.parentCategory &&
      (this.isNew || this.isModified("parentCategory"))
    ) {
      const parent = await this.constructor.findById(this.parentCategory);
      if (parent) {
        this.categoryLevel = parent.categoryLevel + 1;

        // Actualizar childCategories del padre (del primer esquema)
        if (this.isNew) {
          await this.constructor.findByIdAndUpdate(this.parentCategory, {
            $addToSet: { childCategories: this._id },
          });
        }
      }
    } else if (!this.parentCategory) {
      this.categoryLevel = 0;
    }

    // Validar profundidad máxima
    if (this.categoryLevel > 5) {
      return next(
        new Error("La profundidad máxima de categorías es 5 niveles")
      );
    }

    // Generar categoryCode si no existe
    if (!this.categoryCode && this.categorySlug) {
      this.categoryCode = this.categorySlug.toUpperCase().replace(/-/g, "_");
    }

    // Actualizar timestamp de estadísticas
    this.stats.lastStatsUpdate = new Date();

    next();
  } catch (error) {
    next(error);
  }
});

// Post-save middleware
BusinessCategorySchema.post("save", async function (doc) {
  if (doc.isNew) {
    console.log(
      `✅ Categoría creada: ${doc.categorySlug} (Nivel: ${doc.categoryLevel})`
    );
  }
});

// ================================
// MÉTODOS DE INSTANCIA (combinados y optimizados)
// ================================

/**
 * Generar path de categoría automáticamente (del primer esquema)
 */
BusinessCategorySchema.methods.generateCategoryPath = async function () {
  const path = [];
  let currentCategory = this;

  // Construir path hacia arriba hasta la raíz
  while (currentCategory) {
    path.unshift(currentCategory.categorySlug || currentCategory.categoryCode);

    if (currentCategory.parentCategory) {
      currentCategory = await this.constructor.findById(
        currentCategory.parentCategory
      );
    } else {
      break;
    }
  }

  return path.join("/");
};

/**
 * Obtener jerarquía completa (breadcrumb) - del segundo esquema
 */
BusinessCategorySchema.methods.getHierarchy = async function () {
  const hierarchy = [this];
  let current = this;

  while (current.parentCategory) {
    current = await this.constructor.findById(current.parentCategory);
    if (current) {
      hierarchy.unshift(current);
    } else {
      break;
    }
  }

  return hierarchy;
};

/**
 * Obtener subcategorías - del segundo esquema mejorado
 */
BusinessCategorySchema.methods.getSubcategories = function (options = {}) {
  const { includeInactive = false, limit = 50 } = options;

  let query = this.constructor.find({
    parentCategory: this._id,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  });

  if (!includeInactive) {
    query = query.where({ isActive: true });
  }

  return query
    .sort({
      sortOrder: 1,
      displayPriority: -1,
      "categoryName.original.text": 1,
    })
    .limit(limit);
};

/**
 * Actualizar estadísticas - del segundo esquema mejorado
 */
BusinessCategorySchema.methods.updateStats = async function () {
  const Business = mongoose.model("Business");

  // Contar empresas totales y activas
  const [totalCount, activeCount] = await Promise.all([
    Business.countDocuments({
      categories: this._id,
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    }),
    Business.countDocuments({
      categories: this._id,
      businessStatus: "active",
      isPublic: true,
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    }),
  ]);

  // Calcular calificación promedio y popularidad
  const ratingStats = await Business.aggregate([
    {
      $match: {
        categories: this._id,
        businessStatus: "active",
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      },
    },
    {
      $group: {
        _id: null,
        averageRating: { $avg: "$metrics.averageRating" },
        totalViews: { $sum: "$metrics.totalViews" },
        lastBusinessAdded: { $max: "$createdAt" },
      },
    },
  ]);

  const stats = ratingStats[0] || {};

  // Actualizar estadísticas
  this.stats = {
    ...this.stats,
    businessCount: totalCount,
    activeBusinessCount: activeCount,
    averageRating: Math.round((stats.averageRating || 0) * 10) / 10,
    totalViews: stats.totalViews || this.stats.totalViews || 0,
    lastBusinessAdded: stats.lastBusinessAdded || this.stats.lastBusinessAdded,
    lastStatsUpdate: new Date(),
  };

  // Calcular score de popularidad (del primer esquema)
  this.metadata.popularityScore = this.calculatePopularityScore(
    totalCount,
    stats.averageRating,
    stats.totalViews
  );

  return this.save();
};

/**
 * Calcular score de popularidad (del primer esquema optimizado)
 */
BusinessCategorySchema.methods.calculatePopularityScore = function (
  businessCount = 0,
  avgRating = 0,
  totalViews = 0
) {
  const businessWeight = Math.min(businessCount / 10, 10); // Máximo 10 puntos
  const ratingWeight = (avgRating || 0) * 2; // Máximo 10 puntos
  const viewWeight = Math.min((totalViews || 0) / 1000, 10); // Máximo 10 puntos

  return Math.round((businessWeight + ratingWeight + viewWeight) / 3);
};

/**
 * Generar slug único - del segundo esquema
 */
BusinessCategorySchema.methods.generateUniqueSlug = async function (baseName) {
  const baseSlug = baseName
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");

  let slug = baseSlug;
  let counter = 1;

  while (
    await this.constructor.findOne({
      categorySlug: slug,
      _id: { $ne: this._id },
    })
  ) {
    slug = `${baseSlug}-${counter}`;
    counter++;
  }

  this.categorySlug = slug;
  return slug;
};

/**
 * Verificar disponibilidad en país (del primer esquema)
 */
BusinessCategorySchema.methods.isAvailableInCountry = function (countryCode) {
  // Si hay países permitidos definidos, verificar que esté en la lista
  if (this.geographicRestrictions.allowedCountries?.length > 0) {
    return this.geographicRestrictions.allowedCountries.includes(countryCode);
  }

  // Si hay países restringidos, verificar que NO esté en la lista
  if (this.geographicRestrictions.restrictedCountries?.length > 0) {
    return !this.geographicRestrictions.restrictedCountries.includes(
      countryCode
    );
  }

  return true;
};

/**
 * Obtener nombre en idioma específico - del primer esquema
 */
BusinessCategorySchema.methods.getName = function (language = "es") {
  if (this.categoryName?.getText) {
    return this.categoryName.getText(language);
  }
  return this.categoryName?.original?.text || this.categorySlug;
};

/**
 * Obtener descripción en idioma específico - del primer esquema
 */
BusinessCategorySchema.methods.getDescription = function (language = "es") {
  if (this.description?.getText) {
    return this.description.getText(language);
  }
  return this.description?.original?.text || "";
};

// ================================
// MÉTODOS ESTÁTICOS OPTIMIZADOS
// ================================

/**
 * Obtener categorías raíz - del segundo esquema
 */
BusinessCategorySchema.statics.getRootCategories = function (options = {}) {
  const { includeInactive = false, limit = 50, country = null } = options;

  let query = this.find({
    $or: [{ parentCategory: null }, { parentCategory: { $exists: false } }],
    $and: [{ $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }] }],
  });

  if (!includeInactive) {
    query = query.where({ isActive: true, isPublic: true });
  }

  // Aplicar restricciones geográficas si se especifica país
  if (country) {
    query = query.where({
      $and: [
        {
          $or: [
            { "geographicRestrictions.restrictedCountries": { $ne: country } },
            {
              "geographicRestrictions.restrictedCountries": { $exists: false },
            },
            { "geographicRestrictions.restrictedCountries": { $size: 0 } },
          ],
        },
        {
          $or: [
            { "geographicRestrictions.allowedCountries": country },
            { "geographicRestrictions.allowedCountries": { $exists: false } },
            { "geographicRestrictions.allowedCountries": { $size: 0 } },
          ],
        },
      ],
    });
  }

  return query
    .sort({
      displayPriority: -1,
      sortOrder: 1,
      "categoryName.original.text": 1,
    })
    .limit(limit);
};

/**
 * Buscar categorías por texto - del segundo esquema mejorado
 */
BusinessCategorySchema.statics.searchCategories = function (
  searchText,
  options = {}
) {
  const {
    limit = 20,
    includeInactive = false,
    parentCategory = null,
    country = null,
  } = options;

  let query = this.find(
    {
      $text: { $search: searchText },
      $and: [
        { $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }] },
      ],
    },
    {
      score: { $meta: "textScore" },
    }
  );

  if (!includeInactive) {
    query = query.where({ isActive: true, isPublic: true });
  }

  if (parentCategory) {
    query = query.where({ parentCategory });
  }

  if (country) {
    query = query.where({
      $and: [
        {
          $or: [
            { "geographicRestrictions.restrictedCountries": { $ne: country } },
            {
              "geographicRestrictions.restrictedCountries": { $exists: false },
            },
          ],
        },
      ],
    });
  }

  return query
    .sort({
      score: { $meta: "textScore" },
      "metadata.popularityScore": -1,
      "stats.businessCount": -1,
    })
    .limit(limit);
};

/**
 * Obtener categorías destacadas - del segundo esquema
 */
BusinessCategorySchema.statics.getFeaturedCategories = function (limit = 5) {
  return this.find({
    isFeatured: true,
    isActive: true,
    isPublic: true,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  })
    .sort({
      displayPriority: -1,
      sortOrder: 1,
      "metadata.popularityScore": -1,
    })
    .limit(limit);
};

/**
 * Crear categorías predeterminadas del sistema - mejorado
 */
BusinessCategorySchema.statics.createDefaultCategories = async function () {
  const defaultCategories = [
    {
      categoryName: createMultiLanguageContent("Restaurantes y Comida", "es"),
      description: createMultiLanguageContent(
        "Restaurantes, cafeterías, bares y servicios de comida",
        "es"
      ),
      shortDescription: createMultiLanguageContent(
        "Lugares para comer y beber",
        "es"
      ),
      categorySlug: "restaurantes-comida",
      categoryCode: "FOOD_DRINK",
      industryCodes: {
        customCode: "REST",
        naicsCode: "722",
        googleBusinessCategory: "Restaurant",
      },
      searchKeywords: {
        primaryKeywords: ["restaurant", "comida", "café", "bar"],
        tags: ["food", "beverage", "dining"],
        seoKeywords: ["restaurante", "comida", "gastronomía"],
      },
      metadata: {
        color: "#FF6B6B",
        icon: "utensils",
        iconLibrary: "fontawesome",
        popularityScore: 85,
      },
      seo: {
        focusKeyword: "restaurantes",
        seoScore: 80,
      },
      isFeatured: true,
      sortOrder: 1,
      displayPriority: 90,
    },
    {
      categoryName: createMultiLanguageContent("Tiendas y Retail", "es"),
      description: createMultiLanguageContent(
        "Tiendas, supermercados, centros comerciales y retail",
        "es"
      ),
      shortDescription: createMultiLanguageContent("Compras y retail", "es"),
      categorySlug: "tiendas-retail",
      categoryCode: "RETAIL",
      industryCodes: {
        customCode: "RETAIL",
        naicsCode: "44",
        googleBusinessCategory: "Store",
      },
      searchKeywords: {
        primaryKeywords: ["tienda", "shopping", "retail", "compras"],
        tags: ["shopping", "store", "retail"],
        seoKeywords: ["tienda", "compras", "shopping"],
      },
      metadata: {
        color: "#4ECDC4",
        icon: "shopping-bag",
        iconLibrary: "fontawesome",
        popularityScore: 80,
      },
      seo: {
        focusKeyword: "tiendas",
        seoScore: 75,
      },
      isFeatured: true,
      sortOrder: 2,
      displayPriority: 85,
    },
    {
      categoryName: createMultiLanguageContent("Salud y Bienestar", "es"),
      description: createMultiLanguageContent(
        "Hospitales, clínicas, farmacias y servicios de salud",
        "es"
      ),
      shortDescription: createMultiLanguageContent(
        "Servicios médicos y de salud",
        "es"
      ),
      categorySlug: "salud-bienestar",
      categoryCode: "HEALTH",
      industryCodes: {
        customCode: "HEALTH",
        naicsCode: "62",
        googleBusinessCategory: "Medical",
      },
      searchKeywords: {
        primaryKeywords: ["hospital", "clínica", "médico", "salud"],
        tags: ["health", "medical", "healthcare"],
        seoKeywords: ["salud", "médico", "hospital"],
      },
      metadata: {
        color: "#96CEB4",
        icon: "heart",
        iconLibrary: "fontawesome",
        popularityScore: 75,
      },
      seo: {
        focusKeyword: "salud",
        seoScore: 85,
      },
      categoryConfig: {
        requiresVerification: true,
        requiresDocuments: true,
        minimumPhotos: 2,
      },
      isFeatured: true,
      sortOrder: 3,
      displayPriority: 80,
    },
    {
      categoryName: createMultiLanguageContent("Servicios Profesionales", "es"),
      description: createMultiLanguageContent(
        "Abogados, contadores, consultores y servicios profesionales",
        "es"
      ),
      shortDescription: createMultiLanguageContent(
        "Servicios profesionales",
        "es"
      ),
      categorySlug: "servicios-profesionales",
      categoryCode: "PROFESSIONAL",
      industryCodes: {
        customCode: "PROF",
        naicsCode: "54",
        googleBusinessCategory: "Professional Service",
      },
      searchKeywords: {
        primaryKeywords: ["abogado", "contador", "consultor", "profesional"],
        tags: ["professional", "service", "consulting"],
        seoKeywords: ["servicios profesionales", "consultoría"],
      },
      metadata: {
        color: "#45B7D1",
        icon: "briefcase",
        iconLibrary: "fontawesome",
        popularityScore: 70,
      },
      seo: {
        focusKeyword: "servicios profesionales",
        seoScore: 75,
      },
      isFeatured: true,
      sortOrder: 4,
      displayPriority: 75,
    },
  ];

  const createdCategories = [];

  for (const categoryData of defaultCategories) {
    try {
      const existingCategory = await this.findOne({
        categorySlug: categoryData.categorySlug,
      });

      if (!existingCategory) {
        const category = new this(categoryData);
        await category.save();
        createdCategories.push(category);
        console.log(
          `✅ Categoría predeterminada creada: ${categoryData.categorySlug}`
        );
      }
    } catch (error) {
      console.error(
        `❌ Error creando categoría ${categoryData.categorySlug}:`,
        error.message
      );
    }
  }

  return createdCategories;
};

/**
 * Actualizar estadísticas de todas las categorías (del primer esquema)
 */
BusinessCategorySchema.statics.updateAllCategoryStats = async function () {
  const categories = await this.find({ isActive: true });

  for (const category of categories) {
    await category.updateStats();
  }

  console.log(
    `✅ Estadísticas actualizadas para ${categories.length} categorías`
  );
};

// ================================
// VIRTUALES OPTIMIZADOS
// ================================

/**
 * Virtual para verificar si es categoría raíz
 */
BusinessCategorySchema.virtual("isRootCategory").get(function () {
  return !this.parentCategory && this.categoryLevel === 0;
});

/**
 * Virtual para verificar si puede tener subcategorías
 */
BusinessCategorySchema.virtual("canHaveSubcategories").get(function () {
  return this.categoryConfig?.allowSubcategories && this.categoryLevel < 5;
});

/**
 * Virtual para verificar popularidad
 */
BusinessCategorySchema.virtual("isPopular").get(function () {
  return this.stats.businessCount > 10 && this.stats.averageRating > 4.0;
});

/**
 * Virtual para obtener path como array
 */
BusinessCategorySchema.virtual("pathArray").get(function () {
  return this.categoryPath ? this.categoryPath.split("/") : [this.categorySlug];
});

/**
 * Virtual para verificar si tiene subcategorías
 */
BusinessCategorySchema.virtual("hasChildren").get(function () {
  return this.childCategories?.length > 0;
});

// ================================
// CONFIGURACIÓN ADICIONAL
// ================================

// Configurar opciones de transformación para JSON
BusinessCategorySchema.set("toJSON", {
  virtuals: true,
  transform: function (doc, ret) {
    delete ret.__v;

    // Agregar información calculada
    ret.isRootCategory = doc.isRootCategory;
    ret.canHaveSubcategories = doc.canHaveSubcategories;
    ret.isPopular = doc.isPopular;
    ret.pathArray = doc.pathArray;
    ret.hasChildren = doc.hasChildren;

    return ret;
  },
});

// ================================
// EXPORTAR MODELO
// ================================

export const BusinessCategory = mongoose.model(
  "BusinessCategory",
  BusinessCategorySchema
);
export default BusinessCategory;
