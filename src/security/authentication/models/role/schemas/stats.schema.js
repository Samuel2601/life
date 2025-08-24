import mongoose from "mongoose";

const StatsSchema = new mongoose.Schema({
  userCount: {
    type: Number,
    default: 0,
    min: 0,
  },
  lastAssigned: {
    type: Date,
  },
  totalAssignments: {
    type: Number,
    default: 0,
    min: 0,
  },
  avgSessionDuration: {
    type: Number,
    default: 0,
  },
  lastUsed: {
    type: Date,
  },
});

export default StatsSchema;
