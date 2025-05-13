const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// Transaction Schema (embedded in Business)
const transactionSchema = new mongoose.Schema({
  _id: { type: String, default: () => crypto.randomBytes(16).toString('hex') },
  type: {
    type: String,
    required: true,
    enum: ['received', 'deposited', 'withdrawn', 'refunded', 'settled'],
  },
  amount: { type: mongoose.Schema.Types.Decimal128, required: true },
  toFrom: { type: String, required: true },
  fee: { type: mongoose.Schema.Types.Decimal128, default: 0 },
  date: { type: Date, default: Date.now, index: true },
});

// Pending Deposit Schema (embedded in Business)
const pendingDepositSchema = new mongoose.Schema({
  amount: { type: mongoose.Schema.Types.Decimal128, required: true },
  transactionId: { type: String, required: true },
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
});

// Pending Withdrawal Schema (embedded in Business)
const pendingWithdrawalSchema = new mongoose.Schema({
  amount: { type: mongoose.Schema.Types.Decimal128, required: true },
  fee: { type: mongoose.Schema.Types.Decimal128, default: 0 },
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  destination: {
    type: { type: String, enum: ['bank', 'mobile_money'] },
    bankName: { type: String },
    accountNumber: { type: String },
  },
});

// Business Schema
const businessSchema = new mongoose.Schema({
  businessId: {
    type: String,
    required: true,
    unique: true,
    match: [/^\d{10}$/, 'Business ID must be a 10-digit TPIN'],
  },
  name: { type: String, required: true },
  ownerUsername: {
    type: String,
    required: true,
    unique: true,
    match: [/^[a-zA-Z0-9]{3,}$/, 'Username must be at least 3 alphanumeric characters'],
  },
  phoneNumber: {
    type: String,
    required: true,
    unique: true,
    match: [/^\+260(9[5678]|7[34679])\d{7}$/, 'Phone number must be a valid Zambian mobile number'],
  },
  email: {
    type: String,
    unique: true,
    sparse: true,
    match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Invalid email address'],
  },
  hashedPin: { type: String, required: true },
  balance: { type: mongoose.Schema.Types.Decimal128, default: 0 },
  bankDetails: {
    bankName: String,
    accountNumber: String,
    accountType: { type: String, enum: ['bank', 'mobile_money'] },
  },
  tpinCertificate: { type: String },
  pacraCertificate: { type: String },
  kycStatus: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
  isActive: { type: Boolean, default: false },
  transactions: [transactionSchema],
  pendingDeposits: [pendingDepositSchema],
  pendingWithdrawals: [pendingWithdrawalSchema],
  pushToken: { type: String },
}, { timestamps: true });

// Hash PIN before saving
businessSchema.pre('save', async function (next) {
  if (this.isModified('hashedPin') && this.hashedPin && !this.hashedPin.startsWith('$2')) {
    if (!/^\d{4}$/.test(this.hashedPin)) {
      return next(new Error('PIN must be a 4-digit number'));
    }
    this.hashedPin = await bcrypt.hash(this.hashedPin, 10);
  }
  next();
});

// Business Transaction Schema (for QR payments)
const businessTransactionSchema = new mongoose.Schema({
  transactionId: { type: String, unique: true, required: true },
  businessId: { type: String, required: true, index: true },
  amount: { type: Number, required: true },
  status: { type: String, enum: ['pending', 'completed', 'expired'], default: 'pending' },
  qrCodeId: { type: String, unique: true },
  qrCodeUrl: { type: String },
  description: { type: String },
  fromUsername: { type: String },
  expiresAt: { type: Date },
  createdAt: { type: Date, default: Date.now, index: true },
});

// Export models
module.exports = {
  Business: mongoose.model('Business', businessSchema),
  BusinessTransaction: mongoose.model('BusinessTransaction', businessTransactionSchema),
};