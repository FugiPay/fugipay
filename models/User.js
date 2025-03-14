const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  phoneNumber: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  idImageUrl: { type: String },
  role: { type: String, default: 'user' },
  balance: { type: Number, default: 0 }, // Renamed from mainBalance, used as wallet balance
  transactions: [
    {
      type: { type: String }, // 'sent', 'received', 'credited', 'deposited', 'withdrawn', 'fee-collected', 'pending-pin'
      amount: { type: Number },
      toFrom: { type: String },
      date: { type: Date, default: Date.now },
      fee: { type: Number }, // Added for user-facing fees (sent, received, deposited, withdrawn)
      originalAmount: { type: Number }, // Added for fee-collected (admin)
      sendingFee: { type: Number },     // Added for fee-collected (admin)
      receivingFee: { type: Number },   // Added for fee-collected (admin)
    },
  ],
  kycStatus: { type: String, default: 'pending' },
  isActive: { type: Boolean, default: false },
  resetToken: { type: String },
  resetTokenExpiry: { type: Number },
});

module.exports = mongoose.model('User', userSchema);