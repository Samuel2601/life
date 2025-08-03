// =============================================================================
// src/modules/business/models/business_category.scheme.js
// =============================================================================
import mongoose from "mongoose";
import {
  BaseSchemeFields,
  setupBaseSchema,
  CommonValidators,
} from "../../core/models/base.scheme.js";
import {
  createMultiLanguageField,
  createMultiLanguageContent,
  SUPPORTED_LANGUAGES,
} from "../../core/models/multi_language_pattern.scheme.js";

/**
 * Schema para metadatos específicos de categoría
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
    imageUrl: {
      type: String,
      validate: CommonValidators.url,
    },
    bannerUrl: {
      type: String,
      validate: CommonValidators.url,
    },
  },
  { _id: false }
);

/**
 * Schema para configuración SEO de categoría
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
  },
  { _id: false }
);

/**
 * Schema principal de Categoría de Empresa
 */
const BusinessCategorySchema = new mongoose.Schema({
  // Información multiidioma
  categoryName: createMultiLanguageField(true, { textIndex: true }),
  description: createMultiLanguageField(false, { textIndex: true }),
  shortDescription: createMultiLanguageField(false),

  // Estructura jerárquica
  parentCategory: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "BusinessCategory",
    default: null,
    index: true,
    validate: {
      validator: function (v) {
        // No puede ser su propia categoría padre
        return !v || !this._id || !v.equals(this._id);
      },
      message: "Una categoría no puede ser su propia categoría padre",
    },
  },

  categoryLevel: {
    type: Number,
    default: 0,
    min: [0, "El nivel de categoría no puede ser negativo"],
    max: [5, "El nivel máximo de categoría es 5"],
    index: true,
  },

  categoryPath: {
    type: String,
    index: true, // Para búsqueda jerárquica rápida
    maxlength: [200, "La ruta de categoría no puede exceder 200 caracteres"],
  },

  // Identificadores y clasificación
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

  industryCode: {
    type: String,
    trim: true,
    maxlength: [20, "El código de industria no puede exceder 20 caracteres"],
    uppercase: true,
    index: true,
  },

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
  },

  // Estado y configuración
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

  // Metadatos y presentación
  metadata: CategoryMetadataSchema,

  // SEO y marketing
  seo: CategorySEOSchema,

  // Estadísticas y métricas
  stats: {
    businessCount: {
      type: Number,
      default: 0,
      min: [0, "El conteo de empresas no puede ser negativo"],
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
  },

  // Configuración específica de categoría
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
  },

  // Campos de búsqueda y etiquetas
  searchTags: [
    {
      type: String,
      trim: true,
      lowercase: true,
      maxlength: [30, "Las etiquetas no pueden exceder 30 caracteres"],
    },
  ],

  relatedCategories: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "BusinessCategory",
    },
  ],

  // Restricciones geográficas
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

  // Campos base (auditoría, soft delete, etc.)
  ...BaseSchemeFields,
});

// Configurar el esquema con funcionalidades base
setupBaseSchema(BusinessCategorySchema, {
  addBaseFields: false, // Ya los agregamos manualmente arriba
});

// ================================
// ÍNDICES ESPECÍFICOS
// ================================

// Índices únicos
BusinessCategorySchema.index({ categorySlug: 1 }, { unique: true });

// Índices jerárquicos
BusinessCategorySchema.index({ parentCategory: 1, sortOrder: 1 });
BusinessCategorySchema.index({ categoryLevel: 1, isActive: 1 });
BusinessCategorySchema.index({ categoryPath: 1 });

// Índices de estado y filtrado
BusinessCategorySchema.index({ isActive: 1, isPublic: 1 });
BusinessCategorySchema.index({ isFeatured: 1, isActive: 1 });
BusinessCategorySchema.index({ requiresApproval: 1, isActive: 1 });

// Índices para búsqueda y clasificación
BusinessCategorySchema.index({ industryCode: 1 });
BusinessCategorySchema.index({ naicsCode: 1 });
BusinessCategorySchema.index({ "metadata.category": 1 });

// Índices para estadísticas
BusinessCategorySchema.index({ "stats.businessCount": -1 });
BusinessCategorySchema.index({ "stats.totalViews": -1 });
BusinessCategorySchema.index({ "stats.averageRating": -1 });

// Índice de texto multiidioma para búsqueda
BusinessCategorySchema.index(
  {
    "categoryName.original.text": "text",
    "description.original.text": "text",
    "shortDescription.original.text": "text",
    searchTags: "text",
  },
  {
    name: "category_search_index",
    weights: {
      "categoryName.original.text": 10,
      "description.original.text": 5,
      "shortDescription.original.text": 3,
      searchTags: 2,
    },
  }
);

// ================================
// VIRTUALS
// ================================

// Virtual para verificar si es categoría raíz
BusinessCategorySchema.virtual("isRootCategory").get(function () {
  return !this.parentCategory && this.categoryLevel === 0;
});

// Virtual para verificar si puede tener subcategorías
BusinessCategorySchema.virtual("canHaveSubcategories").get(function () {
  return this.categoryConfig?.allowSubcategories && this.categoryLevel < 5;
});

// Virtual para obtener el porcentaje de ocupación
BusinessCategorySchema.virtual("occupancyPercentage").get(function () {
  if (!this.categoryConfig?.maxSubcategories) return 0;
  return Math.round(
    (this.stats.businessCount / this.categoryConfig.maxSubcategories) * 100
  );
});

// Virtual para verificar popularidad
BusinessCategorySchema.virtual("isPopular").get(function () {
  return this.stats.businessCount > 10 && this.stats.averageRating > 4.0;
});

// ================================
// MÉTODOS DE INSTANCIA
// ================================

// Método para obtener subcategorías
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
    .sort({ sortOrder: 1, "categoryName.original.text": 1 })
    .limit(limit);
};

// Método para obtener la jerarquía completa (breadcrumb)
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

// Método para verificar si es ancestro de otra categoría
BusinessCategorySchema.methods.isAncestorOf = async function (categoryId) {
  const category = await this.constructor.findById(categoryId);
  if (!category) return false;

  const hierarchy = await category.getHierarchy();
  return hierarchy.some((cat) => cat._id.equals(this._id));
};

// Método para actualizar estadísticas
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

  // Calcular calificación promedio
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
    lastBusinessAdded: stats.lastBusinessAdded || this.stats.lastBusinessAdded,
  };

  return this.save();
};

// Método para generar slug único
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

// Método para agregar campo personalizado
BusinessCategorySchema.methods.addCustomField = function (
  fieldName,
  fieldType,
  options = {}
) {
  if (!this.categoryConfig) {
    this.categoryConfig = { customFields: [] };
  }

  if (!this.categoryConfig.customFields) {
    this.categoryConfig.customFields = [];
  }

  // Verificar si el campo ya existe
  const existingField = this.categoryConfig.customFields.find(
    (f) => f.fieldName === fieldName
  );
  if (existingField) {
    throw new Error(`El campo personalizado '${fieldName}' ya existe`);
  }

  this.categoryConfig.customFields.push({
    fieldName,
    fieldType,
    isRequired: options.isRequired || false,
    options: options.selectOptions || [],
  });

  return this;
};

// ================================
// MÉTODOS ESTÁTICOS
// ================================

// Obtener categorías raíz
BusinessCategorySchema.statics.getRootCategories = function (options = {}) {
  const { includeInactive = false, limit = 50 } = options;

  let query = this.find({
    $or: [{ parentCategory: null }, { parentCategory: { $exists: false } }],
    $and: [{ $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }] }],
  });

  if (!includeInactive) {
    query = query.where({ isActive: true, isPublic: true });
  }

  return query
    .sort({ sortOrder: 1, "categoryName.original.text": 1 })
    .limit(limit);
};

// Obtener árbol de categorías completo
BusinessCategorySchema.statics.getCategoryTree = async function (options = {}) {
  const { maxDepth = 5, includeInactive = false } = options;

  const buildTree = async (parentId = null, depth = 0) => {
    if (depth >= maxDepth) return [];

    let query = this.find({
      parentCategory: parentId,
      $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
    });

    if (!includeInactive) {
      query = query.where({ isActive: true, isPublic: true });
    }

    const categories = await query
      .sort({ sortOrder: 1, "categoryName.original.text": 1 })
      .lean();

    for (const category of categories) {
      category.subcategories = await buildTree(category._id, depth + 1);
    }

    return categories;
  };

  return await buildTree();
};

// Buscar categorías por texto
BusinessCategorySchema.statics.searchCategories = function (
  searchText,
  options = {}
) {
  const {
    limit = 20,
    includeInactive = false,
    language = "es",
    parentCategory = null,
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

  return query
    .sort({ score: { $meta: "textScore" }, "stats.businessCount": -1 })
    .limit(limit);
};

// Obtener categorías populares
BusinessCategorySchema.statics.getPopularCategories = function (limit = 10) {
  return this.find({
    isActive: true,
    isPublic: true,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  })
    .sort({
      "stats.businessCount": -1,
      "stats.averageRating": -1,
      "stats.totalViews": -1,
    })
    .limit(limit);
};

// Obtener categorías destacadas
BusinessCategorySchema.statics.getFeaturedCategories = function (limit = 5) {
  return this.find({
    isFeatured: true,
    isActive: true,
    isPublic: true,
    $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
  })
    .sort({ sortOrder: 1, "stats.businessCount": -1 })
    .limit(limit);
};

// Crear categorías predeterminadas del sistema
BusinessCategorySchema.statics.createDefaultCategories = async function () {
  const defaultCategories = [
    {
      categoryName: createMultiLanguageContent("Restaurantes y Comida", "es"),
      description: createMultiLanguageContent(
        "Restaurantes, cafeterías, bares y servicios de comida",
        "es"
      ),
      categorySlug: "restaurantes-comida",
      industryCode: "REST",
      naicsCode: "722",
      metadata: { color: "#FF6B6B", icon: "utensils" },
      isFeatured: true,
      sortOrder: 1,
    },
    {
      categoryName: createMultiLanguageContent("Tiendas y Retail", "es"),
      description: createMultiLanguageContent(
        "Tiendas, supermercados, centros comerciales y retail",
        "es"
      ),
      categorySlug: "tiendas-retail",
      industryCode: "RETAIL",
      naicsCode: "44",
      metadata: { color: "#4ECDC4", icon: "shopping-bag" },
      isFeatured: true,
      sortOrder: 2,
    },
    {
      categoryName: createMultiLanguageContent("Servicios Profesionales", "es"),
      description: createMultiLanguageContent(
        "Abogados, contadores, consultores y servicios profesionales",
        "es"
      ),
      categorySlug: "servicios-profesionales",
      industryCode: "PROF",
      naicsCode: "54",
      metadata: { color: "#45B7D1", icon: "briefcase" },
      isFeatured: true,
      sortOrder: 3,
    },
    {
      categoryName: createMultiLanguageContent("Salud y Bienestar", "es"),
      description: createMultiLanguageContent(
        "Hospitales, clínicas, farmacias y servicios de salud",
        "es"
      ),
      categorySlug: "salud-bienestar",
      industryCode: "HEALTH",
      naicsCode: "62",
      metadata: { color: "#96CEB4", icon: "heart" },
      isFeatured: true,
      sortOrder: 4,
    },
    {
      categoryName: createMultiLanguageContent("Entretenimiento", "es"),
      description: createMultiLanguageContent(
        "Cines, teatros, centros de entretenimiento y recreación",
        "es"
      ),
      categorySlug: "entretenimiento",
      industryCode: "ENT",
      naicsCode: "71",
      metadata: { color: "#FECA57", icon: "film" },
      isFeatured: true,
      sortOrder: 5,
    },
    {
      categoryName: createMultiLanguageContent("Educación", "es"),
      description: createMultiLanguageContent(
        "Escuelas, universidades, institutos y centros educativos",
        "es"
      ),
      categorySlug: "educacion",
      industryCode: "EDU",
      naicsCode: "61",
      metadata: { color: "#FF9FF3", icon: "graduation-cap" },
      sortOrder: 6,
    },
    {
      categoryName: createMultiLanguageContent("Automotriz", "es"),
      description: createMultiLanguageContent(
        "Concesionarios, talleres, gasolineras y servicios automotrices",
        "es"
      ),
      categorySlug: "automotriz",
      industryCode: "AUTO",
      naicsCode: "441",
      metadata: { color: "#54A0FF", icon: "car" },
      sortOrder: 7,
    },
    {
      categoryName: createMultiLanguageContent("Tecnología", "es"),
      description: createMultiLanguageContent(
        "Desarrollo de software, soporte técnico y servicios de IT",
        "es"
      ),
      categorySlug: "tecnologia",
      industryCode: "TECH",
      naicsCode: "541",
      metadata: { color: "#5F27CD", icon: "laptop" },
      sortOrder: 8,
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

// Obtener estadísticas generales de categorías
BusinessCategorySchema.statics.getCategoryStats = async function () {
  const stats = await this.aggregate([
    {
      $match: {
        $or: [{ isDeleted: false }, { isDeleted: { $exists: false } }],
      },
    },
    {
      $group: {
        _id: null,
        totalCategories: { $sum: 1 },
        activeCategories: {
          $sum: { $cond: [{ $eq: ["$isActive", true] }, 1, 0] },
        },
        featuredCategories: {
          $sum: { $cond: [{ $eq: ["$isFeatured", true] }, 1, 0] },
        },
        rootCategories: {
          $sum: { $cond: [{ $eq: ["$categoryLevel", 0] }, 1, 0] },
        },
        totalBusinesses: { $sum: "$stats.businessCount" },
        avgBusinessesPerCategory: { $avg: "$stats.businessCount" },
      },
    },
  ]);

  return (
    stats[0] || {
      totalCategories: 0,
      activeCategories: 0,
      featuredCategories: 0,
      rootCategories: 0,
      totalBusinesses: 0,
      avgBusinessesPerCategory: 0,
    }
  );
};

// ================================
// MIDDLEWARES
// ================================

// Pre-save middleware para generar categoryPath y validaciones
BusinessCategorySchema.pre("save", async function (next) {
  try {
    // Generar slug si no existe
    if (!this.categorySlug && this.categoryName?.original?.text) {
      await this.generateUniqueSlug(this.categoryName.original.text);
    }

    // Actualizar nivel y ruta de categoría
    if (this.parentCategory) {
      const parent = await this.constructor.findById(this.parentCategory);
      if (parent) {
        this.categoryLevel = parent.categoryLevel + 1;
        this.categoryPath = parent.categoryPath
          ? `${parent.categoryPath}/${this.categorySlug}`
          : this.categorySlug;
      }
    } else {
      this.categoryLevel = 0;
      this.categoryPath = this.categorySlug;
    }

    // Normalizar código de industria
    if (this.industryCode) {
      this.industryCode = this.industryCode.toUpperCase().trim();
    }

    next();
  } catch (error) {
    next(error);
  }
});

// Post-save middleware para logging
BusinessCategorySchema.post("save", function (doc, next) {
  if (doc.isNew) {
    console.log(
      `📁 Categoría de empresa creada: ${doc.categorySlug} (Nivel: ${doc.categoryLevel})`
    );
  }
  next();
});

// ================================
// EXPORTAR MODELO
// ================================

export const BusinessCategory = mongoose.model(
  "BusinessCategory",
  BusinessCategorySchema
);
export default BusinessCategory;
