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
    index: true,
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
    expires: function() { return this.type === 'user' ? 15 * 60 : null; }, // 15 minutes for users, persistent for businesses
  },
});

module.exports = mongoose.model('QRPin', qrPinSchema);