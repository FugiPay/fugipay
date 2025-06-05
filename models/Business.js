const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// Audit Log Schema (embedded)
const auditLogSchema = new mongoose.Schema({
  action: {
    type: String,
    required: true,
    enum: [
      'create', 'update', 'delete', 'kyc_update', 'balance_change', 'login',
      'pin_reset', 'view_dashboard', 'update_notifications', 'withdrawal_request',
      'transaction_received', 'qr_generate'
    ],
  },
  performedBy: { type: String, required: true },
  timestamp: { type: Date, default: Date.now, index: true },
  details: { type: mongoose.Schema.Types.Mixed },
});

// Transaction Schema (embedded in Business)
const transactionSchema = new mongoose.Schema({
  _id: { type: String, default: () => crypto.randomBytes(16).toString('hex') },
  type: {
    type: String,
    required: true,
    enum: [
      'received', 'deposited', 'withdrawn', 'refunded', 'settled', 'fee-collected',
      'zmc-received', 'zmc-sent', 'currency-converted', 'pending-pin',
    ],
  },
  amount: { type: mongoose.Schema.Types.Decimal128, required: true },
  currency: { type: String, enum: ['ZMW', 'ZMC', 'USD'], default: 'ZMW' },
  toFrom: { type: String, required: true },
  fee: { type: mongoose.Schema.Types.Decimal128, default: 0 },
  originalAmount: { type: mongoose.Schema.Types.Decimal128 },
  originalCurrency: { type: String, enum: ['ZMW', 'ZMC', 'USD'] },
  exchangeRate: { type: Number },
  reason: { type: String, maxlength: 200 },
  trustRating: { type: Number, min: 1, max: 5 },
  date: { type: Date, default: Date.now, index: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'completed' },
  qrId: { type: String },
  isRead: { type: Boolean, default: true }, // Added for notification badge
});

// Pending Deposit Schema (embedded in Business)
const pendingDepositSchema = new mongoose.Schema({
  amount: { type: mongoose.Schema.Types.Decimal128, required: true },
  currency: { type: String, enum: ['ZMW', 'ZMC', 'USD'], default: 'ZMW' },
  transactionId: { type: String, required: true },
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  rejectionReason: { type: String, maxlength: 200 },
  sourceOfFunds: { type: String, enum: ['bank_transfer', 'mobile_money', 'cash', 'other'], required: true },
});

// Pending Withdrawal Schema (embedded in Business)
const pendingWithdrawalSchema = new mongoose.Schema({
  amount: { type: mongoose.Schema.Types.Decimal128, required: true },
  currency: { type: String, enum: ['ZMW', 'ZMC', 'USD'], default: 'ZMW' },
  fee: { type: mongoose.Schema.Types.Decimal128, default: 0 },
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  rejectionReason: { type: String, maxlength: 200 },
  destination: {
    type: { type: String, enum: ['bank', 'mobile_money', 'zambia_coin'], required: true },
    bankName: { type: String },
    accountNumber: { type: String },
    swiftCode: { type: String },
  },
});

// Business Schema
const businessSchema = new mongoose.Schema({
  businessId: {
    type: String,
    required: true,
    unique: true,
    match: [/^\d{10}$/, 'Business ID must be a 10-digit TPIN'],
    index: true,
  },
  name: { type: String, required: true, trim: true, maxlength: 100 },
  ownerUsername: {
    type: String,
    required: true,
    unique: true,
    match: [/^[a-zA-Z0-9]{3,}$/, 'Username must be at least 3 alphanumeric characters'],
    index: true,
  },
  phoneNumber: {
    type: String,
    required: true,
    unique: true,
    match: [/^\+260(9[5678]|7[34679])\d{7}$/, 'Phone number must be a valid Zambian mobile number'],
    index: true,
  },
  email: {
    type: String,
    unique: true,
    sparse: true,
    match: [/^[^\s@]+@[^\s@]+\.[^\s@]+$/, 'Invalid email address'],
    lowercase: true,
    trim: true,
  },
  hashedPin: { type: String, required: true },
  resetToken: { type: String },
  resetTokenExpiry: { type: Date },
  balances: {
    ZMW: { type: mongoose.Schema.Types.Decimal128, default: 0 },
    ZMC: { type: mongoose.Schema.Types.Decimal128, default: 0 },
    USD: { type: mongoose.Schema.Types.Decimal128, default: 0 },
  },
  qrCode: { type: String },
  bankDetails: {
    bankName: { type: String },
    accountNumber: { type: String },
    accountType: { type: String, enum: ['bank', 'mobile_money', 'zambia_coin'] },
    swiftCode: { type: String },
  },
  tpinCertificate: { type: String },
  pacraCertificate: { type: String },
  kycStatus: { type: String, enum: ['pending', 'verified', 'rejected', 'flagged'], default: 'pending' },
  kycDetails: {
    incorporationDate: { type: Date },
    registeredAddress: { type: String },
    taxId: { type: String },
    sourceOfFunds: { type: String, enum: ['business_revenue', 'investment', 'loan', 'other'] },
    sanctionsScreening: {
      status: { type: String, enum: ['clear', 'flagged', 'blocked'], default: 'clear' },
      lastChecked: { type: Date },
    },
  },
  accountTier: {
    type: String,
    enum: ['basic', 'pro', 'enterprise'],
    default: 'basic',
  },
  transactionLimits: {
    daily: { type: Number, default: 100000 },
    monthly: { type: Number, default: 1000000 },
    maxPerTransaction: { type: Number, default: 50000 },
  },
  role: { type: String, enum: ['business', 'admin'], default: 'business' },
  trustScore: { type: Number, default: 0, min: 0, max: 100 },
  ratingCount: { type: Number, default: 0 },
  transactions: [transactionSchema],
  pendingDeposits: [pendingDepositSchema],
  pendingWithdrawals: [pendingWithdrawalSchema],
  auditLogs: [auditLogSchema],
  pushToken: { type: String, default: null },
  pushNotificationsEnabled: { type: Boolean, default: true },
  isActive: { type: Boolean, default: false },
  lastLogin: { type: Date },
}, { timestamps: true });

// Indexes for performance
businessSchema.index({ 'transactions.date': -1 });
businessSchema.index({ 'auditLogs.timestamp': -1 });
businessSchema.index({ kycStatus: 1 });

// Middleware: Hash PIN
businessSchema.pre('save', async function (next) {
  if (this.isModified('hashedPin') && this.hashedPin && !this.hashedPin.startsWith('$2')) {
    if (!/^\d{4}$/.test(this.hashedPin)) {
      return next(new Error('PIN must be a 4-digit number'));
    }
    this.hashedPin = await bcrypt.hash(this.hashedPin, 10);
    this.auditLogs.push({
      action: 'pin_reset',
      performedBy: this.ownerUsername || 'system',
      details: { message: 'PIN updated' },
    });
  }
  next();
});

// Middleware: Log balance changes
businessSchema.pre('save', function (next) {
  if (this.isModified('balances')) {
    this.auditLogs.push({
      action: 'balance_change',
      performedBy: 'system',
      details: {
        oldBalances: this._previousBalances || {},
        newBalances: {
          ZMW: this.balances.ZMW?.toString(),
          ZMC: this.balances.ZMC?.toString(),
          USD: this.balances.USD?.toString(),
        },
      },
    });
    this._previousBalances = { ...this.balances };
  }
  next();
});

// Middleware: Validate transaction limits
businessSchema.pre('save', async function (next) {
  if (this.isModified('transactions')) {
    const newTransaction = this.transactions[this.transactions.length - 1];
    if (newTransaction && ['received', 'deposited', 'withdrawn'].includes(newTransaction.type)) {
      const amount = parseFloat(newTransaction.amount.toString());
      if (amount > this.transactionLimits.maxPerTransaction) {
        return next(new Error(`Transaction amount exceeds max limit of ${this.transactionLimits.maxPerTransaction} ZMW`));
      }
      const startOfDay = new Date();
      startOfDay.setHours(0, 0, 0, 0);
      const dailyTotal = this.transactions
        .filter(t => t.date >= startOfDay && ['received', 'deposited', 'withdrawn'].includes(t.type))
        .reduce((sum, t) => sum + parseFloat(t.amount.toString()), 0);
      if (dailyTotal + amount > this.transactionLimits.daily) {
        return next(new Error(`Transaction exceeds daily limit of ${this.transactionLimits.daily} ZMW`));
      }
    }
  }
  next();
});

// Business Transaction Schema (for QR payments)
const businessTransactionSchema = new mongoose.Schema({
  transactionId: { type: String, unique: true, required: true },
  businessId: { type: String, required: true, index: true },
  amount: { type: mongoose.Schema.Types.Decimal128, required: true },
  currency: { type: String, enum: ['ZMW', 'ZMC', 'USD'], default: 'ZMW' },
  status: { type: String, enum: ['pending', 'completed', 'expired', 'refunded'], default: 'pending' },
  qrCodeId: { type: String, unique: true },
  qrCodeUrl: { type: String },
  description: { type: String, maxlength: 200 },
  fromUsername: { type: String },
  expiresAt: { type: Date },
  createdAt: { type: Date, default: Date.now, index: true },
  refundedAmount: { type: mongoose.Schema.Types.Decimal128, default: 0 },
});

// Export models
module.exports = {
  Business: mongoose.model('Business', businessSchema),
  BusinessTransaction: mongoose.model('BusinessTransaction', businessTransactionSchema),
};