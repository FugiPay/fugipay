const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  type: { type: String, required: true }, // e.g., "deposited", "withdrawn", "zmc-received"
  amount: { type: Number, required: true },
  toFrom: { type: String, required: true }, // e.g., "admin", "manual-mobile-money"
  fee: { type: Number, default: 0 },
  date: { type: Date, default: Date.now },
  trustRating: { type: Number }, // Optional, for zmc-sent
});

const pendingDepositSchema = new mongoose.Schema({
  amount: { type: Number, required: true },
  transactionId: { type: String, required: true },
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'approved'], default: 'pending' },
});

const pendingWithdrawalSchema = new mongoose.Schema({
  amount: { type: Number, required: true },
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'completed'], default: 'pending' },
});

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  phoneNumber: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  balance: { type: Number, default: 0 },
  zambiaCoinBalance: { type: Number, default: 0 },
  kycStatus: { type: String, enum: ['pending', 'verified'], default: 'pending' },
  isFirstLogin: { type: Boolean, default: true },
  email: { type: String, trim: true },
  name: { type: String, trim: true },
  transactions: [transactionSchema],
  pendingDeposits: [pendingDepositSchema],
  pendingWithdrawals: [pendingWithdrawalSchema],
  lastLogin: { type: Date },
  pin: { type: String },
  trustScore: { type: Number, default: 0 },
  ratingCount: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
}, { timestamps: true });

// Ensure unique indexes
userSchema.index({ username: 1 }, { unique: true });
userSchema.index({ phoneNumber: 1 }, { unique: true });

module.exports = mongoose.models.User || mongoose.model('User', userSchema);