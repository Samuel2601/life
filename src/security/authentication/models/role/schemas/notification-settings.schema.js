import mongoose from "mongoose";

const NotificationSettingsSchema = new mongoose.Schema({
  enableSystemNotifications: {
    type: Boolean,
    default: true,
  },
  enableBusinessNotifications: {
    type: Boolean,
    default: true,
  },
  notificationChannels: [
    {
      type: String,
      enum: ["email", "sms", "push", "in_app"],
    },
  ],
  dailyDigest: {
    type: Boolean,
    default: false,
  },
});

export default NotificationSettingsSchema;
