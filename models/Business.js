const mongoose = require('mongoose');
const crypto = require('crypto');

const transactionSchema = new mongoose.Schema({
  _id: { type: String, default: () => crypto.randomBytes(16).toString('hex') }, // 32-char hex string
  type: {
    type: String,
    required: true,
    enum: ['received', 'deposited', 'withdrawn'],
  },
  amount: { type: Number, required: true },
  toFrom: { type: String, required: true },
  fee: { type: Number, default: 0 },
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
  businessId: { type: String, required: true, unique: true, index: true }, // TPIN
  name: { type: String, required: true },
  ownerUsername: { type: String, required: true },
  pin: { type: String, required: true, minlength: 4, maxlength: 4 }, // Align with User
  balance: { type: Number, default: 0 },
  qrCode: { type: String },
  role: { type: String, enum: ['business', 'admin'], default: 'business' },
  approvalStatus: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  transactions: [transactionSchema],
  pendingDeposits: [pendingDepositSchema],
  pendingWithdrawals: [pendingWithdrawalSchema],
  pushToken: { type: String, default: null }, // Added default for consistency
  isActive: { type: Boolean, default: false },
}, { timestamps: true });

module.exports = mongoose.model('Business', businessSchema);