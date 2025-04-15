const mongoose = require('mongoose');

const businessLedgerTransactionSchema = new mongoose.Schema({
  type: {
    type: String,
    required: true,
    enum: ['fee-collected', 'settlement-fee'],
  },
  amount: { type: Number, required: true, min: 0 },
  businessId: { type: String, required: true },
  userId: { type: String },
  transactionId: { type: String, required: true },
  date: { type: Date, default: Date.now, index: true },
});

const businessAdminLedgerSchema = new mongoose.Schema({
  totalBalance: { type: Number, default: 0, min: 0 },
  lastUpdated: { type: Date, default: Date.now, index: true },
  transactions: [businessLedgerTransactionSchema],
}, { timestamps: true });

businessAdminLedgerSchema.pre('save', async function (next) {
  const count = await this.constructor.countDocuments();
  if (count > 0 && this.isNew) {
    throw new Error('Only one BusinessAdminLedger document is allowed');
  }
  next();
});

module.exports = mongoose.model('BusinessAdminLedger', businessAdminLedgerSchema);