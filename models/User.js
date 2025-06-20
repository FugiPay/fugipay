const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  _id: { type: String }, // Custom transaction ID
  type: {
    type: String,
    required: true,
    enum: [
      'sent', 'received', 'credited', 'deposited', 'withdrawn', 'fee-collected', 'pending-pin',
      'zmc-sent', 'zmc-received',
    ],
  },
  amount: { type: Number, required: true },
  toFrom: { type: String, required: true },
  date: { type: Date, default: Date.now, index: true },
  fee: { type: Number, default: 0 },
  originalAmount: { type: Number },
  sendingFee: { type: Number },
  receivingFee: { type: Number },
  trustRating: { type: Number, min: 1, max: 5 },
});

const pendingDepositSchema = new mongoose.Schema({
  amount: { type: Number, required: true },
  transactionId: { type: String, required: true },
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
});

const pendingWithdrawalSchema = new mongoose.Schema({
  amount: { type: Number, required: true },
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'completed', 'rejected'], default: 'pending' },
});

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
  pin: { type: String, required: true, minlength: 4, maxlength: 4 },
  idImageUrl: { type: String },
  role: { type: String, default: 'user', enum: ['user', 'admin'] },
  balance: { type: Number, default: 0 },
  zambiaCoinBalance: { type: Number, default: 0 },
  trustScore: { type: Number, default: 0, min: 0, max: 100 },
  ratingCount: { type: Number, default: 0 },
  transactions: [transactionSchema],
  kycStatus: { type: String, default: 'pending', enum: ['pending', 'verified', 'rejected'] },
  isActive: { type: Boolean, default: false },
  isArchived: { type: Boolean, default: false, index: true }, // New: Marks account as archived
  archivedAt: { type: Date }, // New: Timestamp of archival
  archivedReason: { type: String }, // New: Reason for archival (e.g., 'user-requested', 'compliance')
  resetToken: { type: String },
  resetTokenExpiry: { type: Date },
  pushToken: { type: String, default: null },
  pendingDeposits: [pendingDepositSchema],
  pendingWithdrawals: [pendingWithdrawalSchema],
  lastLogin: { type: Date, default: null },
  lastViewedTimestamp: { type: Number, default: 0 },
  twoFactorSecret: { type: String }, // 2FA secret for TOTP
  twoFactorEnabled: { type: Boolean, default: false }, // 2FA status
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
});

// Virtual to check if account is effectively active (not archived and isActive)
userSchema.virtual('isEffectivelyActive').get(function () {
  return this.isActive && !this.isArchived;
});

// Index for efficient querying of active/archived users
userSchema.index({ isActive: 1, isArchived: 1 });

// Ensure unique constraints are enforced
userSchema.index({ username: 1 }, { unique: true });
userSchema.index({ phoneNumber: 1 }, { unique: true });
userSchema.index({ email: 1 }, { unique: true });

module.exports = mongoose.model('User', userSchema);