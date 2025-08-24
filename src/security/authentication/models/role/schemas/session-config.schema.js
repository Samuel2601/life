import mongoose from "mongoose";

const SessionConfigSchema = new mongoose.Schema({
  maxConcurrentSessions: {
    type: Number,
    default: 3,
    min: 1,
    max: 10,
  },
  sessionTimeoutMinutes: {
    type: Number,
    default: 480,
    min: 15,
    max: 43200,
  },
  requireTwoFactor: {
    type: Boolean,
    default: false,
  },
  allowRememberMe: {
    type: Boolean,
    default: true,
  },
});

export default SessionConfigSchema;
