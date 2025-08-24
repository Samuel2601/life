import mongoose from "mongoose";

const GeographicRestrictionsSchema = new mongoose.Schema({
  allowedCountries: [
    {
      type: String,
      uppercase: true,
      length: 2,
    },
  ],
  allowedRegions: [String],
  restrictToGeolocation: {
    type: Boolean,
    default: false,
  },
});

export default GeographicRestrictionsSchema;
