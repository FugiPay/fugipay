const mongoose = require('mongoose');

const qrPinSchema = new mongoose.Schema({
  type: {
    type: String,
    required: true,
    enum: ['user', 'business'],
  },
  username: {
    type: String,
    required: function() { return this.type === 'user'; },
    ref: 'User',
  },
  businessId: {
    type: String,
    required: function() { return this.type === 'business'; },
    ref: 'Business',
  },
  qrId: {
    type: String,
    required: true,
    unique: true,
  },
  pin: {
    type: String,
    required: true,
    minlength: 4,
    maxlength: 4,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  persistent: {
    type: Boolean,
    default: function() { return this.type === 'business'; }, // Business QR pins are persistent
  },
});

// Define indexes
qrPinSchema.index({ username: 1 });
qrPinSchema.index({ businessId: 1 });
qrPinSchema.index({ qrId: 1 }, { unique: true });
qrPinSchema.index({ createdAt: 1 }, { name: 'createdAt_1', expireAfterSeconds: 900, background: true });

// Pre-save hook to ensure persistent business QR pins aren't affected by TTL
qrPinSchema.pre('save', function(next) {
  if (this.type === 'business') {
    this.persistent = true;
  }
  next();
});

module.exports = mongoose.model('QRPin', qrPinSchema);