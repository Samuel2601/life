// =============================================================================
// src/models/utils/schemaHelpers.js
// =============================================================================

// Helper para validación de coordenadas
export const validateCoordinates = (coords) => {
  return (
    coords.length === 2 &&
    coords[0] >= -180 &&
    coords[0] <= 180 && // Longitude
    coords[1] >= -90 &&
    coords[1] <= 90
  ); // Latitude
};

// Helper para generar slug único
export const generateUniqueSlug = async (Model, baseText, currentId = null) => {
  const baseName = baseText
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");

  let slug = baseName;
  let counter = 1;

  const query = currentId ? { slug, _id: { $ne: currentId } } : { slug };

  while (await Model.findOne(query)) {
    slug = `${baseName}-${counter}`;
    counter++;
    query.slug = slug;
  }

  return slug;
};

// Helper para crear hash de archivos
export const createFileHash = (buffer, algorithm = "sha256") => {
  const crypto = require("crypto");
  return crypto.createHash(algorithm).update(buffer).digest("hex");
};

// Helper para formatear tamaño de archivo
export const formatFileSize = (bytes) => {
  if (bytes === 0) return "0 Bytes";

  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
};

// Helper para validar tipos de archivo permitidos
export const isAllowedFileType = (mimeType, allowedTypes = []) => {
  if (allowedTypes.length === 0) return true;
  return allowedTypes.includes(mimeType);
};

// Helper para extraer extensión de archivo
export const getFileExtension = (filename) => {
  return filename.split(".").pop().toLowerCase();
};
