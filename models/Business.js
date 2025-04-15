const mongoose = require('mongoose');
const crypto = require('crypto');

const transactionSchema = new mongoose.Schema({
  _id: { type: String, default: () => crypto.randomBytes(16).toString('hex') },
  type: {
    type: String,
    required: true,
    enum: ['received', 'deposited', 'withdrawn', 'refunded', 'settled'],
  },
  amount: { type: Number, required: true },
  toFrom: { type: String, required: true },
  fee: { type: Number, default: 0 },
  reason: { type: String },
  date: { type: Date, default: Date.now, index: true },
});

const pendingDepositSchema = new mongoose.Schema({
  amount: { type: Number, required: true },
  transactionId: { type: String, required: true },
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
});

const pendingWithdrawalSchema = new mongoose.Schema({
  amount: { type: Number, required: true },
  fee: { type: Number, default: 0 },
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'completed', 'rejected'], default: 'pending' },
});

const businessSchema = new mongoose.Schema({
  businessId: { type: String, required: true, unique: true, index: true },
  name: { type: String, required: true },
  ownerUsername: { type: String, required: true, unique: true },
  pin: { type: String, required: true },
  phoneNumber: {
    type: String,
    required: true,
    unique: true,
    match: [/^\+2609[567]\d{7}$/, 'Phone number must be a valid Zambian mobile number (e.g., +260961234567)'],
  },
  email: {
    type: String,
    unique: true,
    sparse: true,
    match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Invalid email address'],
  },
  resetToken: { type: String },
  resetTokenExpiry: { type: Date },
  balance: { type: Number, default: 0 },
  qrCode: { type: String },
  bankDetails: {
    bankName: { type: String },
    accountNumber: { type: String },
    accountType: { type: String, enum: ['bank', 'mobile_money'] },
  },
  role: { type: String, enum: ['business', 'admin'], default: 'business' },
  approvalStatus: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  transactions: [transactionSchema],
  pendingDeposits: [pendingDepositSchema],
  pendingWithdrawals: [pendingWithdrawalSchema],
  pushToken: { type: String, default: null },
  isActive: { type: Boolean, default: false },
}, { timestamps: true });

businessSchema.index({ businessId: 1 });
businessSchema.index({ ownerUsername: 1 });
businessSchema.index({ phoneNumber: 1 });
businessSchema.index({ email: 1 });

module.exports = mongoose.model('Business', businessSchema);