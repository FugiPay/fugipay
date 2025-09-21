
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');

const transactionSchema = new mongoose.Schema({
  _id: { type: String },
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
  fraudScore: { type: Number, min: -1, max: 1, default: null },
  analyticsEventId: { type: mongoose.Schema.Types.ObjectId, ref: 'Analytics', default: null },
});

const pendingDepositSchema = new mongoose.Schema({
  amount: { type: Number, required: true },
  transactionId: { type: String, required: true, default: uuidv4 },
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  fraudScore: { type: Number, min: -1, max: 1, default: null },
  analyticsEventId: { type: mongoose.Schema.Types.ObjectId, ref: 'Analytics', default: null },
  fraudAnalyticsEventId: { type: String, default: null },
});

const pendingWithdrawalSchema = new mongoose.Schema({
  amount: { type: Number, required: true },
  transactionId: { type: String, required: true, default: uuidv4 },
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'completed', 'rejected'], default: 'pending' },
  analyticsEventId: { type: mongoose.Schema.Types.ObjectId, ref: 'Analytics', default: null },
  fraudAnalyticsEventId: { type: String, default: null },
});

const kycAnalysisSchema = new mongoose.Schema({
  textCount: { type: Number, default: 0 },
  faceCount: { type: Number, default: 0 },
  isValid: { type: Boolean, default: false },
  analyzedAt: { type: Date, default: Date.now },
  error: { type: String },
  analyticsEventId: { type: mongoose.Schema.Types.ObjectId, ref: 'Analytics', default: null },
});

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  phoneNumber: {
    type: String,
    required: true,
    unique: true,
    match: /^\+260(9[5678]|7[34679])\d{7}$/,
  },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true, minlength: 6 },
  pin: { type: String, required: true },
  idImageUrl: { type: String, required: true },
  role: { type: String, default: 'user', enum: ['user', 'admin'] },
  balance: { type: Number, default: 0 },
  zambiaCoinBalance: { type: Number, default: 0 },
  trustScore: { type: Number, default: 0, min: 0, max: 100, index: true },
  ratingCount: { type: Number, default: 0 },
  transactions: [transactionSchema],
  kycStatus: { type: String, default: 'pending', enum: ['pending', 'verified', 'rejected'] },
  kycAnalysis: { type: kycAnalysisSchema, default: () => ({}) },
  isActive: { type: Boolean, default: false },
  isFlagged: { type: Boolean, default: false, index: true },
  isArchived: { type: Boolean, default: false, index: true },
  archivedAt: { type: Date },
  archivedReason: { type: String },
  resetToken: { type: String },
  resetTokenExpiry: { type: Date },
  pushToken: { type: String, default: null },
  pendingDeposits: [pendingDepositSchema],
  pendingWithdrawals: [pendingWithdrawalSchema],
  lastLogin: { type: Date, default: null },
  lastLoginAttempts: { type: Number, default: 0 },
  lastViewedTimestamp: { type: Number, default: 0 },
  twoFactorSecret: { type: String },
  twoFactorEnabled: { type: Boolean, default: false },
  depositAttempts: { type: Number, default: 0 },
  lastWithdrawAttempts: { type: Number, default: 0 },
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
  autoIndex: false, // Disable auto-indexing to rely on explicit indexes
});

userSchema.virtual('isEffectivelyActive').get(function () {
  return this.isActive && !this.isArchived;
});

// Define indexes explicitly
userSchema.index({ isActive: 1, isArchived: 1 });
userSchema.index({ username: 1 }, { unique: true });
userSchema.index({ phoneNumber: 1 }, { unique: true });
userSchema.index({ email: 1 }, { unique: true, sparse: true });
userSchema.index({ 'pendingDeposits.transactionId': 1 }, { unique: true, sparse: true });
userSchema.index({ 'pendingWithdrawals.transactionId': 1 }, { unique: true, sparse: true });
userSchema.index({ 'transactions.analyticsEventId': 1 });
userSchema.index({ 'pendingDeposits.analyticsEventId': 1 });
userSchema.index({ 'pendingWithdrawals.analyticsEventId': 1 });
userSchema.index({ 'kycAnalysis.analyticsEventId': 1 });

module.exports = mongoose.model('User', userSchema);
