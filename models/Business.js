const mongoose = require('mongoose');
const crypto = require('crypto');

const businessSchema = new mongoose.Schema({
  businessId: { type: String, required: true, unique: true }, // TPIN
  name: { type: String, required: true },
  ownerUsername: { type: String, required: true },
  pin: { type: String, required: true },
  balance: { type: Number, default: 0 },
  qrCode: { type: String },
  role: { type: String, enum: ['business', 'admin'], default: 'business' },
  approvalStatus: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' }, // New field
  transactions: [
    {
      _id: { type: String, default: () => crypto.randomBytes(16).toString('hex') },
      type: { type: String, enum: ['received', 'deposited', 'withdrawn'] },
      amount: { type: Number },
      toFrom: { type: String },
      fee: { type: Number, default: 0 },
      date: { type: Date, default: Date.now },
    },
  ],
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
      fee: { type: Number, default: 0 },
      date: { type: Date, default: Date.now },
      status: { type: String, enum: ['pending', 'completed', 'rejected'], default: 'pending' },
    },
  ],
  pushToken: { type: String },
  isActive: { type: Boolean, default: false }, // Default to false until approved
});

module.exports = mongoose.model('Business', businessSchema);