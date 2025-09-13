// =============================================================================
// src/models/system/FileUpload.js
// =============================================================================
import mongoose from "mongoose";
import {
  BaseSchemaFields,
  addTimestampMiddleware,
  addCommonIndexes,
} from "../base/BaseSchema.js";

// Schema para metadatos específicos de imagen
const ImageMetadataSchema = new mongoose.Schema(
  {
    width: Number,
    height: Number,
    format: String,
    hasAlpha: Boolean,
    colorSpace: String,
    orientation: Number,
  },
  { _id: false }
);

// Schema para metadatos específicos de documento
const DocumentMetadataSchema = new mongoose.Schema(
  {
    pageCount: Number,
    wordCount: Number,
    author: String,
    title: String,
    subject: String,
    createdDate: Date,
  },
  { _id: false }
);

const FileUploadSchema = new mongoose.Schema({
  // Información básica del archivo
  originalFileName: {
    type: String,
    required: true,
    maxlength: 255,
  },
  fileName: {
    type: String,
    required: true,
    unique: true,
    maxlength: 255,
  },
  fileExtension: {
    type: String,
    required: true,
    lowercase: true,
    maxlength: 10,
  },
  mimeType: {
    type: String,
    required: true,
    maxlength: 100,
  },

  // Tamaño y almacenamiento
  fileSize: {
    type: Number,
    required: true,
    min: 0,
  },
  fileSizeHuman: String, // "1.2 MB"

  // Rutas y URLs
  filePath: {
    type: String,
    required: true,
  },
  url: {
    type: String,
    required: true,
  },
  thumbnailUrl: String,
  cdnUrl: String,

  // Categorización
  fileType: {
    type: String,
    required: true,
    enum: ["image", "document", "video", "audio", "archive", "other"],
    index: true,
  },
  category: {
    type: String,
    enum: ["avatar", "logo", "gallery", "document", "verification", "temp"],
    index: true,
  },

  // Propietario y relaciones
  uploadedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    index: true,
  },
  businessId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Business",
    index: true,
  },
  isPublic: {
    type: Boolean,
    default: false,
    index: true,
  },

  // Procesamiento y estado
  processingStatus: {
    type: String,
    enum: ["pending", "processing", "completed", "failed"],
    default: "pending",
    index: true,
  },
  processingError: String,
  isOptimized: {
    type: Boolean,
    default: false,
  },
  compressionRatio: Number,

  // Seguridad
  virusScanned: {
    type: Boolean,
    default: false,
  },
  virusScanResult: {
    type: String,
    enum: ["clean", "infected", "suspicious", "unknown"],
    default: "unknown",
  },
  checksum: {
    type: String,
    required: true,
    index: true,
  },
  checksumAlgorithm: {
    type: String,
    default: "sha256",
  },

  // Metadatos específicos por tipo
  imageMetadata: ImageMetadataSchema,
  documentMetadata: DocumentMetadataSchema,

  // Metadatos generales
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },

  // Expiración y limpieza
  expiresAt: {
    type: Date,
    index: 1, // TTL index
  },
  isTemporary: {
    type: Boolean,
    default: false,
    index: true,
  },

  // Análisis y uso
  downloadCount: {
    type: Number,
    default: 0,
    min: 0,
  },
  lastAccessedAt: {
    type: Date,
    default: Date.now,
  },

  ...BaseSchemaFields,
});

// Índices específicos
FileUploadSchema.index({ fileName: 1 }, { unique: true });
FileUploadSchema.index({ uploadedBy: 1, createdAt: -1 });
FileUploadSchema.index({ businessId: 1, category: 1 });
FileUploadSchema.index({ fileType: 1, isPublic: 1 });
FileUploadSchema.index({ processingStatus: 1, createdAt: -1 });
FileUploadSchema.index({ checksum: 1 });

// TTL index para archivos temporales
FileUploadSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

addTimestampMiddleware(FileUploadSchema);
addCommonIndexes(FileUploadSchema);

// Pre-save para establecer expiración de archivos temporales
FileUploadSchema.pre("save", function (next) {
  if (this.isNew && this.isTemporary && !this.expiresAt) {
    // Archivos temporales expiran en 24 horas
    this.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  }
  next();
});

// Método para generar URL firmada (para archivos privados)
FileUploadSchema.methods.getSignedUrl = function (expirationMinutes = 60) {
  // Implementar lógica de URL firmada según el proveedor de almacenamiento
  // Esta es una implementación conceptual
  const crypto = require("crypto");
  const expires = Math.floor(Date.now() / 1000) + expirationMinutes * 60;
  const signature = crypto
    .createHmac("sha256", process.env.FILE_SIGNING_SECRET)
    .update(`${this.fileName}:${expires}`)
    .digest("hex");

  return `${this.url}?expires=${expires}&signature=${signature}`;
};

export const FileUpload = mongoose.model("FileUpload", FileUploadSchema);
