// =============================================================================
// src/models/business/Address.js
// =============================================================================
import mongoose from "mongoose";
import {
  BaseSchemeFields,
  addTimestampMiddleware,
  addCommonIndexes,
} from "../base/BaseSchema.js";

const AddressSchema = new mongoose.Schema({
  // Dirección estructurada
  streetAddress: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200,
  },
  streetNumber: {
    type: String,
    trim: true,
    maxlength: 20,
  },
  apartment: {
    type: String,
    trim: true,
    maxlength: 50,
  },
  neighborhood: {
    type: String,
    trim: true,
    maxlength: 100,
  },
  city: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100,
    index: true,
  },
  state: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100,
    index: true,
  },
  country: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100,
    index: true,
    default: "Perú",
  },
  postalCode: {
    type: String,
    trim: true,
    maxlength: 20,
    index: true,
  },

  // Coordenadas geográficas (crítico para geolocalización)
  coordinates: {
    type: {
      type: String,
      enum: ["Point"],
      default: "Point",
    },
    coordinates: {
      type: [Number], // [longitude, latitude]
      required: true,
      validate: {
        validator: function (coords) {
          return (
            coords.length === 2 &&
            coords[0] >= -180 &&
            coords[0] <= 180 && // Longitude
            coords[1] >= -90 &&
            coords[1] <= 90
          ); // Latitude
        },
        message: "Coordenadas inválidas",
      },
    },
  },

  // Dirección formateada
  formattedAddress: {
    type: String,
    required: true,
    maxlength: 500,
  },

  // Información adicional
  addressType: {
    type: String,
    enum: ["business", "residential", "office", "warehouse", "store"],
    default: "business",
  },

  // Validación y calidad
  isValidated: {
    type: Boolean,
    default: false,
  },
  validationSource: {
    type: String,
    enum: ["google_maps", "manual", "user_input", "gps"],
  },
  validatedAt: Date,

  // Metadatos geográficos
  timezone: {
    type: String,
    default: "America/Lima",
  },
  plusCode: String, // Google Plus Code

  // Referencias
  businessId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Business",
    index: true,
  },

  ...BaseSchemeFields,
});

// Índice geográfico principal (CRÍTICO)
AddressSchema.index({ coordinates: "2dsphere" });

// Índices específicos para búsqueda
AddressSchema.index({ city: 1, state: 1, country: 1 });
AddressSchema.index({ postalCode: 1, country: 1 });
AddressSchema.index({ businessId: 1 });
AddressSchema.index({ addressType: 1, isValidated: 1 });

// Índice de texto para búsqueda
AddressSchema.index({
  formattedAddress: "text",
  city: "text",
  neighborhood: "text",
});

addTimestampMiddleware(AddressSchema);
addCommonIndexes(AddressSchema);

// Virtual para latitud y longitud separadas
AddressSchema.virtual("latitude").get(function () {
  return this.coordinates.coordinates[1];
});

AddressSchema.virtual("longitude").get(function () {
  return this.coordinates.coordinates[0];
});

// Método para calcular distancia a otro punto
AddressSchema.methods.distanceTo = function (otherCoordinates) {
  const [lon1, lat1] = this.coordinates.coordinates;
  const [lon2, lat2] = otherCoordinates;

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

export const Address = mongoose.model("Address", AddressSchema);
