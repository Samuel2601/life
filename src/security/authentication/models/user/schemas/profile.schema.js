// =============================================================================
// src/modules/authentication/models/user/schemas/profile.schema.js
// =============================================================================
import mongoose from "mongoose";
import { CommonValidators } from "../../../../core/models/base.scheme.js";

/**
 * Schema de perfil de usuario
 */
export const UserProfileSchema = new mongoose.Schema(
  {
    firstName: {
      type: String,
      required: [true, "El nombre es requerido"],
      trim: true,
      maxlength: [50, "El nombre no puede exceder 50 caracteres"],
      minlength: [2, "El nombre debe tener al menos 2 caracteres"],
    },
    lastName: {
      type: String,
      required: [true, "El apellido es requerido"],
      trim: true,
      maxlength: [50, "El apellido no puede exceder 50 caracteres"],
      minlength: [2, "El apellido debe tener al menos 2 caracteres"],
    },
    avatar: {
      type: String,
      validate: CommonValidators.url,
      default: null,
    },
    dateOfBirth: {
      type: Date,
      validate: {
        validator: function (v) {
          return !v || v <= new Date();
        },
        message: "La fecha de nacimiento no puede ser futura",
      },
    },
    phone: {
      type: String,
      trim: true,
      maxlength: [20, "El teléfono no puede exceder 20 caracteres"],
      validate: CommonValidators.phone,
    },
    bio: {
      type: String,
      maxlength: [500, "La biografía no puede exceder 500 caracteres"],
      trim: true,
    },
    website: {
      type: String,
      validate: CommonValidators.url,
    },
  },
  { _id: false }
);
