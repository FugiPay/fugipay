const mongoose = require('mongoose');

const businessTransactionSchema = new mongoose.Schema({
  transactionId: { type: String, unique: true, required: true },
  businessId: { type: String, required: true, index: true },
  amount: { type: Number },
  status: { type: String, enum: ['pending', 'completed', 'expired'], default: 'pending' },
  qrCodeId: { type: String, unique: true },
  qrCodeUrl: { type: String },
  description: { type: String },
  fromUsername: { type: String },
  expiresAt: { type: Date },
  createdAt: { type: Date, default: Date.now, index: true },
  refundedAmount: { type: Number, default: 0 },
});

module.exports = mongoose.model('BusinessTransaction', businessTransactionSchema);