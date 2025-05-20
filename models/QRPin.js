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
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  persistent: {
    type: Boolean,
    default: function() { return this.type === 'business'; },
  },
});

// Define indexes
qrPinSchema.index({ username: 1 });
qrPinSchema.index({ businessId: 1 });
qrPinSchema.index({ qrId: 1 }, { unique: true });
qrPinSchema.index({ createdAt: 1 }, { name: 'createdAt_1', expireAfterSeconds: 900, background: true });

// Pre-save hook to hash PIN and ensure persistent business QR pins
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
  next();
});

// Method to compare PIN
qrPinSchema.methods.comparePin = async function(candidatePin) {
  return await bcrypt.compare(candidatePin, this.pin);
};

module.exports = mongoose.model('QRPin', qrPinSchema);