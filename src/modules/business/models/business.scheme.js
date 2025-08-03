// =============================================================================
// src/models/business/Business.js
// =============================================================================
import mongoose from "mongoose";
import {
  BaseSchemeFields,
  addTimestampMiddleware,
  addCommonIndexes,
} from "../base/BaseSchema.js";
import { createMultiLanguageField } from "../base/MultiLanguagePattern.js";

// Schema para horarios de operación
const BusinessHoursSchema = new mongoose.Schema(
  {
    dayOfWeek: {
      type: Number,
      required: true,
      min: 0,
      max: 6, // 0 = Domingo, 6 = Sábado
    },
    openTime: {
      type: String,
      required: true,
      validate: {
        validator: function (v) {
          return /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(v);
        },
        message: "Formato de hora inválido (HH:MM)",
      },
    },
    closeTime: {
      type: String,
      required: true,
      validate: {
        validator: function (v) {
          return /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(v);
        },
        message: "Formato de hora inválido (HH:MM)",
      },
    },
    isClosed: {
      type: Boolean,
      default: false,
    },
  },
  { _id: false }
);

// Schema para información de contacto
const ContactInfoSchema = new mongoose.Schema(
  {
    primaryPhone: {
      type: String,
      trim: true,
      maxlength: 20,
    },
    secondaryPhone: {
      type: String,
      trim: true,
      maxlength: 20,
    },
    whatsapp: {
      type: String,
      trim: true,
      maxlength: 20,
    },
    email: {
      type: String,
      lowercase: true,
      trim: true,
      validate: {
        validator: function (v) {
          return !v || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
        },
        message: "Email inválido",
      },
    },
    website: {
      type: String,
      validate: {
        validator: function (v) {
          return !v || /^https?:\/\/.+/.test(v);
        },
        message: "Website debe ser una URL válida",
      },
    },
    socialMedia: {
      facebook: String,
      instagram: String,
      twitter: String,
      linkedin: String,
      tiktok: String,
    },
  },
  { _id: false }
);

const BusinessSchema = new mongoose.Schema({
  // Información principal multiidioma
  businessName: createMultiLanguageField(true),
  description: createMultiLanguageField(true),
  shortDescription: createMultiLanguageField(false),

  // Servicios y especialidades (multiidioma)
  services: [createMultiLanguageField(false)],
  specializations: [createMultiLanguageField(false)],

  // Propiedad y gestión
  ownerId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true,
  },
  managers: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
  ],

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
    required: true,
  },
  tags: [String],

  // Ubicación
  address: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Address",
    required: true,
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
    enum: ["pending", "verified", "rejected", "suspended"],
    default: "pending",
    index: true,
  },
  verificationDocuments: [
    {
      documentType: {
        type: String,
        enum: ["business_license", "tax_id", "identity_card", "other"],
      },
      documentUrl: String,
      uploadedAt: Date,
      verifiedAt: Date,
      verifiedBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
      },
    },
  ],

  // Estado del negocio
  businessStatus: {
    type: String,
    enum: ["active", "inactive", "temporarily_closed", "permanently_closed"],
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
  metrics: {
    totalViews: {
      type: Number,
      default: 0,
      min: 0,
    },
    totalContacts: {
      type: Number,
      default: 0,
      min: 0,
    },
    averageRating: {
      type: Number,
      default: 0,
      min: 0,
      max: 5,
    },
    totalReviews: {
      type: Number,
      default: 0,
      min: 0,
    },
  },

  // Multimedia
  logo: String,
  coverImage: String,
  gallery: [String],

  // SEO y búsqueda
  slug: {
    type: String,
    unique: true,
    lowercase: true,
    trim: true,
  },
  metaDescription: createMultiLanguageField(false),
  keywords: [String],

  // Fechas importantes
  establishedDate: Date,
  lastActivityAt: {
    type: Date,
    default: Date.now,
    index: true,
  },

  ...BaseSchemeFields,
});

// Índices específicos para rendimiento
BusinessSchema.index({ slug: 1 }, { unique: true });
BusinessSchema.index({ ownerId: 1, businessStatus: 1 });
BusinessSchema.index({ categories: 1, businessStatus: 1, isPublic: 1 });
BusinessSchema.index({ verificationStatus: 1, businessStatus: 1 });
BusinessSchema.index({ isFeatured: 1, businessStatus: 1, isPublic: 1 });
BusinessSchema.index({
  "metrics.averageRating": -1,
  "metrics.totalReviews": -1,
});
BusinessSchema.index({ lastActivityAt: -1 });

// Índice de texto multiidioma para búsqueda
BusinessSchema.index({
  "businessName.original.text": "text",
  "description.original.text": "text",
  "shortDescription.original.text": "text",
  keywords: "text",
  tags: "text",
});

// Índice geográfico para búsqueda por proximidad
BusinessSchema.index({ address: 1, businessStatus: 1, isPublic: 1 });

addTimestampMiddleware(BusinessSchema);
addCommonIndexes(BusinessSchema);

// Pre-save para generar slug
BusinessSchema.pre("save", async function (next) {
  if (this.isNew || this.isModified("businessName")) {
    const baseName = this.businessName.original.text
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "-")
      .replace(/-+/g, "-")
      .replace(/^-|-$/g, "");

    let slug = baseName;
    let counter = 1;

    while (await this.constructor.findOne({ slug, _id: { $ne: this._id } })) {
      slug = `${baseName}-${counter}`;
      counter++;
    }

    this.slug = slug;
  }
  next();
});

// Método para verificar si está abierto
BusinessSchema.methods.isOpenNow = function () {
  const now = new Date();
  const dayOfWeek = now.getDay();
  const currentTime = now.toTimeString().slice(0, 5);

  const todayHours = this.operatingHours.find((h) => h.dayOfWeek === dayOfWeek);

  if (!todayHours || todayHours.isClosed) {
    return false;
  }

  return (
    currentTime >= todayHours.openTime && currentTime <= todayHours.closeTime
  );
};

export const Business = mongoose.model("Business", BusinessSchema);
