const mongoose = require('mongoose');

const qrPinSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    ref: 'User' // Reference to User model
  },
  qrId: { 
    type: String, 
    required: true, 
    unique: true // Ensures QR codes are unique
  },
  pin: { 
    type: String, 
    required: true, 
    match: /^\d{4}$/ // Enforces 4-digit PIN
  },
  createdAt: { 
    type: Date, 
    default: Date.now,
    expires: 900 // TTL index: expires after 15 minutes (900 seconds)
  }
});

// Index for efficient querying
qrPinSchema.index({ username: 1, qrId: 1 });

module.exports = mongoose.model('QRPin', qrPinSchema);