import mongoose from "mongoose";

const MetadataSchema = new mongoose.Schema({
  color: {
    type: String,
    validate: {
      validator: function (v) {
        return !v || /^#[0-9A-F]{6}$/i.test(v);
      },
      message: "El color debe ser un código hexadecimal válido",
    },
  },
  icon: {
    type: String,
    maxlength: 50,
  },
  category: {
    type: String,
    enum: ["admin", "business", "customer", "moderator", "support", "system"],
    default: "customer",
    index: true,
  },
  priority: {
    type: Number,
    default: 0,
    min: 0,
    max: 10,
  },
  badgeText: String,
  sortOrder: {
    type: Number,
    default: 0,
  },
});

export default MetadataSchema;
