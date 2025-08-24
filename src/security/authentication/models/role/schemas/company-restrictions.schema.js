import mongoose from "mongoose";

const CompanyRestrictionsSchema = new mongoose.Schema({
  canManageAllCompanies: {
    type: Boolean,
    default: false,
  },
  restrictedToOwnCompany: {
    type: Boolean,
    default: true,
  },
  allowedCompanies: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Business",
    },
  ],
  maxCompaniesManaged: {
    type: Number,
    default: 1,
    min: [0, "El máximo de empresas no puede ser negativo"],
  },
  allowedBusinessCategories: [String],
  excludedBusinessCategories: [String],
});

export default CompanyRestrictionsSchema;
