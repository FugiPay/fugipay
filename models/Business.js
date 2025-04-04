const mongoose = require('mongoose');

const businessSchema = new mongoose.Schema({
  businessId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  owner: { type: String, required: true }, // Username of owner from User model
  pin: { type: String, required: true }, // Hashed PIN for authentication
  balance: { type: Number, default: 0 }, // ZMW balance
  qrCode: { type: String }, // Permanent QR code
  transactions: [
    {
      _id: { type: String, default: () => require('crypto').randomBytes(16).toString('hex') },
      type: { type: String, enum: ['received', 'deposited', 'withdrawn', 'fee-collected'] },
      amount: { type: Number },
      toFrom: { type: String },
      fee: { type: Number, default: 0 }, // Fee for sending/receiving
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
      fee: { type: Number, default: 0 }, // Added fee field
      date: { type: Date, default: Date.now },
      status: { type: String, enum: ['pending', 'completed', 'rejected'], default: 'pending' },
    },
  ],
  pushToken: { type: String }, // For notifications
  isActive: { type: Boolean, default: true }, // Business account status
});

module.exports = mongoose.model('Business', businessSchema);