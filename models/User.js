const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  phoneNumber: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  idImageUrl: { type: String },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  balance: { type: Number, default: 0 },
  transactions: [{
    type: { type: String, required: true },
    amount: { type: Number, required: true },
    toFrom: { type: String, required: true },
    date: { type: Date, default: Date.now },
  }],
  kycStatus: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
  isActive: { type: Boolean, default: false }, // New field
});

module.exports = mongoose.model('User', userSchema);