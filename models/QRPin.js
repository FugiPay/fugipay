const mongoose = require('mongoose');

const qrPinSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    ref: 'User', // Reference to User model
    index: true, // Explicit index for queries by username
  },
  qrId: {
    type: String,
    required: true,
    unique: true, // Ensures QR codes are unique
    index: true, // Explicit for clarity
  },
  pin: {
    type: String,
    required: true,
    match: /^\d{4}$/, // Enforces 4-digit numeric PIN
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 900, // Expires after 15 minutes (900 seconds)
  },
});

// Compound index (optional if qrId uniqueness is sufficient)
qrPinSchema.index({ username: 1, qrId: 1 });

module.exports = mongoose.model('QRPin', qrPinSchema);