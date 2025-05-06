const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const transactionSchema = new mongoose.Schema({
  _id: { type: String, default: () => crypto.randomBytes(16).toString('hex') },
  type: {
    type: String,
    required: true,
    enum: [
      'received', 'deposited', 'withdrawn', 'refunded', 'settled', 'fee-collected',
      'zmc-received', 'zmc-sent',
    ],
  },
  amount: { type: mongoose.Schema.Types.Decimal128, required: true },
  toFrom: { type: String, required: true },
  fee: { type: mongoose.Schema.Types.Decimal128, default: 0 },
  originalAmount: { type: mongoose.Schema.Types.Decimal128 },
  sendingFee: { type: mongoose.Schema.Types.Decimal128 },
  receivingFee: { type: mongoose.Schema.Types.Decimal128 },
  reason: { type: String },
  trustRating: { type: Number, min: 1, max: 5 },
  date: { type: Date, default: Date.now, index: true },
});

const pendingDepositSchema = new mongoose.Schema({
  amount: { type: mongoose.Schema.Types.Decimal128, required: true },
  transactionId: { type: String, required: true },
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  rejectionReason: { type: String },
});

const pendingWithdrawalSchema = new mongoose.Schema({
  amount: { type: mongoose.Schema.Types.Decimal128, required: true },
  fee: { type: mongoose.Schema.Types.Decimal128, default: 0 },
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  rejectionReason: { type: String },
  destination: {
    type: { type: String, enum: ['bank', 'mobile_money', 'zambia_coin'] },
    accountDetails: { type: String },
  },
});

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
    match: [/^\+260(9[5678]|7[34679])\d{7}$/, 'Phone number must be a valid Zambian mobile number (e.g., +260951234567)'],
  },
  email: {
    type: String,
    unique: true,
    sparse: true,
    match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Invalid email address'],
  },
  pin: {
    type: String,
    required: true,
    match: [/^\d{4}$/, 'PIN must be a 4-digit number'],
  },
  resetToken: { type: String }, // Re-added for /forgot-pin, /reset-pin
  resetTokenExpiry: { type: Date }, // Re-added for /forgot-pin, /reset-pin
  balance: { type: mongoose.Schema.Types.Decimal128, default: 0 },
  zambiaCoinBalance: { type: mongoose.Schema.Types.Decimal128, default: 0 },
  qrCode: { type: String },
  bankDetails: {
    bankName: String,
    accountNumber: String,
    accountType: { type: String, enum: ['bank', 'mobile_money', 'zambia_coin'] },
  },
  tpinCertificate: { type: String, required: true }, // File path for ZRA TPIN Certificate
  pacraCertificate: { type: String, required: true }, // File path for PACRA Certificate
  kycStatus: { type: String, enum: ['pending', 'verified', 'rejected'], default: 'pending' },
  role: { type: String, enum: ['business', 'admin'], default: 'business' },
  trustScore: { type: Number, default: 0, min: 0, max: 100 },
  ratingCount: { type: Number, default: 0 },
  transactions: [transactionSchema],
  pendingDeposits: [pendingDepositSchema],
  pendingWithdrawals: [pendingWithdrawalSchema],
  pushToken: { type: String, default: null },
  isActive: { type: Boolean, default: false },
}, { timestamps: true });

// Hash PIN before saving
businessSchema.pre('save', async function (next) {
  if (this.isModified('pin')) {
    this.pin = await bcrypt.hash(this.pin, 10);
  }
  next();
});

module.exports = mongoose.model('Business', businessSchema);