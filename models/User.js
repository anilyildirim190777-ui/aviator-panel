const mongoose = require("mongoose");

const notificationSchema = new mongoose.Schema(
  {
    title: String,
    message: String,
    createdAt: { type: Date, default: Date.now },
    read: { type: Boolean, default: false }
  },
  { _id: false }
);

const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,

  isApproved: { type: Boolean, default: false },
  isPremium: { type: Boolean, default: false },
  premiumEndDate: Date,

  isAdmin: { type: Boolean, default: false },

  isBanned: { type: Boolean, default: false },
  banReason: { type: String, default: "" },

  notifications: { type: [notificationSchema], default: [] }
});

module.exports = mongoose.model("User", userSchema);