const mongoose = require('mongoose');

const businessSchema = new mongoose.Schema({
  businessId: {
    type: String,
    required: true,
    unique: true,
    match: /^\d{10}$/,
  },
  pin: {
    type: String,
    required: true,
  },
  username: {
    type: String,
    required: true,
    unique: true,
    match: /^[a-zA-Z0-9]{3,}$/,
  },
  balance: {
    type: mongoose.Types.Decimal128,
    required: true,
    default: 0,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  },
}, { timestamps: true });

module.exports = mongoose.model('Business', businessSchema);