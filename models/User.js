const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  phoneNumber: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  idImageUrl: { type: String },
  role: { type: String, default: 'user' },
  balance: { type: Number, default: 0 },
  transactions: [
    {
      type: { type: String },
      amount: { type: Number },
      toFrom: { type: String },
      date: { type: Date, default: Date.now },
    },
  ],
  kycStatus: { type: String, default: 'pending' },
  isActive: { type: Boolean, default: false },
  resetToken: { type: String }, // New field for password reset token
  resetTokenExpiry: { type: Number }, // New field for token expiry
});

module.exports = mongoose.model('User', userSchema);