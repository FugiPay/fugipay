const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

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
    index: true,
  },
  businessId: {
    type: String,
    required: function() { return this.type === 'business'; },
    ref: 'Business',
    index: true,
  },
  qrId: {
    type: String,
    required: true,
    unique: true,
  },
  pin: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
    index: true,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
  persistent: {
    type: Boolean,
    default: function() { return this.type === 'business'; },
  },
  isActive: {
    type: Boolean,
    default: true,
    index: true,
  }, // New: Tracks active status for soft deletion
  archivedAt: {
    type: Date,
  }, // New: Timestamp of archival
  archivedReason: {
    type: String,
  }, // New: Reason for archival (e.g., 'user-archived', 'business-archived')
}, {
  timestamps: false, // Disable automatic timestamps to manage updatedAt manually
});

// Define indexes
qrPinSchema.index({ username: 1 }, { sparse: true });
qrPinSchema.index({ businessId: 1 }, { sparse: true });
qrPinSchema.index({ qrId: 1 }, { unique: true });
qrPinSchema.index({ isActive: 1 });
qrPinSchema.index({ createdAt: 1 }); // Removed expireAfterSeconds

// Pre-save hook to hash PIN, ensure persistent business QR pins, and update timestamps
qrPinSchema.pre('save', async function(next) {
  if (this.isModified('pin') && !this.pin.startsWith('$2')) {
    if (!/^\d{4}$/.test(this.pin)) {
      return next(new Error('PIN must be a 4-digit number'));
    }
    this.pin = await bcrypt.hash(this.pin, 10);
  }
  if (this.type === 'business') {
    this.persistent = true;
  }
  this.updatedAt = new Date(); // Update timestamp on save
  next();
});

// Method to compare PIN
qrPinSchema.methods.comparePin = async function(candidatePin) {
  return await bcrypt.compare(candidatePin, this.pin);
};

// Virtual to check if QR pin is effectively usable
qrPinSchema.virtual('isEffectivelyUsable').get(function() {
  return this.isActive && !this.archivedAt;
});

module.exports = mongoose.model('QRPin', qrPinSchema);