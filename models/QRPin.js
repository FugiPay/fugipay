// models/QRPin.js
const mongoose = require('mongoose');

const qrPinSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true, 
    ref: 'User', // Reference to User model
    index: true 
  },
  qrId: { 
    type: String, 
    required: true, 
    unique: true, 
    index: true 
  },
  pin: { 
    type: String, 
    required: true, 
    minlength: 4, 
    maxlength: 4 
  },
  createdAt: { 
    type: Date, 
    default: Date.now, 
    expires: 15 * 60 // Auto-delete after 15 minutes
  },
});

module.exports = mongoose.model('QRPin', qrPinSchema);