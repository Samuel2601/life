import mongoose from "mongoose";

const PermissionSchema = new mongoose.Schema(
  {
    resource: {
      type: String,
      required: [true, "El recurso es requerido"],
      enum: [
        "users",
        "businesses",
        "reviews",
        "categories",
        "addresses",
        "roles",
        "permissions",
        "system",
        "reports",
        "audit",
        "translations",
        "media",
        "notifications",
        "analytics",
        "all",
      ],
      index: true,
    },
    actions: [
      {
        type: String,
        required: [true, "La acción es requerida"],
        enum: [
          "create",
          "read",
          "update",
          "delete",
          "manage",
          "approve",
          "reject",
          "publish",
          "unpublish",
          "export",
          "import",
          "restore",
          "archive",
          "moderate",
          "verify",
          "all",
        ],
      },
    ],
    scope: {
      type: String,
      enum: ["none", "own", "company", "global"],
      default: "own",
      index: true,
    },
    conditions: {
      type: mongoose.Schema.Types.Mixed,
      default: {},
    },
    geographicRestrictions: {
      allowedCountries: [String],
      allowedRegions: [String],
      restrictToLocation: {
        type: Boolean,
        default: false,
      },
    },
    timeRestrictions: {
      businessHoursOnly: {
        type: Boolean,
        default: false,
      },
      timezone: {
        type: String,
        default: "America/Lima",
      },
    },
  },
  { _id: false }
);

export default PermissionSchema;
