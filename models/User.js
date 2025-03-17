const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, index: true },
  name: { type: String, required: true },
  phoneNumber: {
    type: String,
    required: true,
    unique: true,
    index: true,
    match: /^\+260(9[5678]|7[34679])\d{7}$/,
  },
  email: { type: String, required: true, unique: true, index: true },
  password: { type: String, required: true, minlength: 6 },
  idImageUrl: { type: String },
  role: { type: String, default: 'user', enum: ['user', 'admin'] },
  balance: { type: Number, default: 0 },
  transactions: [
    {
      type: {
        type: String,
        enum: ['sent', 'received', 'credited', 'deposited', 'withdrawn', 'fee-collected', 'pending-pin'],
      },
      amount: { type: Number },
      toFrom: { type: String },
      date: { type: Date, default: Date.now, index: true },
      fee: { type: Number },
      originalAmount: { type: Number },
      sendingFee: { type: Number },
      receivingFee: { type: Number },
    },
  ],
  kycStatus: { type: String, default: 'pending', enum: ['pending', 'verified', 'rejected'] },
  isActive: { type: Boolean, default: false },
  resetToken: { type: String },
  resetTokenExpiry: { type: Date },
  pushToken: { type: String, default: null },
  pendingDeposits: [
    {
      amount: { type: Number, required: true },
      transactionId: { type: String, required: true },
      date: { type: Date, default: Date.now },
      status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    },
  ],
  pendingWithdrawals: [
    {
      amount: { type: Number, required: true },
      date: { type: Date, default: Date.now },
      status: { type: String, enum: ['pending', 'completed', 'rejected'], default: 'pending' },
    },
  ],
});

module.exports = mongoose.model('User', userSchema);