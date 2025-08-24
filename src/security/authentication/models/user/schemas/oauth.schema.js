// =============================================================================
// src/modules/authentication/models/user/schemas/oauth.schema.js
// =============================================================================
import mongoose from "mongoose";
import { CommonValidators } from "../../../../core/models/base.scheme.js";

/**
 * Schema para proveedores OAuth
 */
export const OAuthProviderSchema = new mongoose.Schema(
  {
    providerId: {
      type: String,
      required: true,
      index: true,
    },
    email: {
      type: String,
      required: true,
      validate: CommonValidators.email,
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    connectedAt: {
      type: Date,
      default: Date.now,
    },
    lastUsed: {
      type: Date,
      default: Date.now,
    },
  },
  { _id: false }
);
