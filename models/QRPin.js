const mongoose = require('mongoose');

const qrPinSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    ref: 'User',
    index: true,
  },
  qrId: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  temp_pin: {  // Renamed from pin
    type: String,
    required: true,
    match: /^\d{4}$/,
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 900,
  },
});

qrPinSchema.index({ username: 1, qrId: 1 });

module.exports = mongoose.model('QRPin', qrPinSchema);