const mongoose = require('mongoose');

const adminLedgerTransactionSchema = new mongoose.Schema({
  type: {
    type: String,
    required: true,
    enum: ['fee-collected'], // Expandable (e.g., 'admin-withdrawal')
    default: 'fee-collected',
  },
  amount: {
    type: Number,
    required: true,
    min: 0, // Fee amount (sendingFee + receivingFee)
  },
  sender: {
    type: String,
    required: true, // Sender username
  },
  receiver: {
    type: String,
    required: true, // Receiver username
  },
  userTransactionIds: {
    type: [String],
    required: true, // References sender/receiver transaction _id
  },
  date: {
    type: Date,
    default: Date.now,
    index: true, // For sorting/querying
  },
});

const adminLedgerSchema = new mongoose.Schema({
  totalBalance: {
    type: Number,
    default: 0,
    min: 0,
  },
  lastUpdated: {
    type: Date,
    default: Date.now,
    index: true,
  },
  transactions: [adminLedgerTransactionSchema], // New transaction history
}, {
  timestamps: true,
});

// Singleton enforcement
adminLedgerSchema.pre('save', async function (next) {
  const count = await this.constructor.countDocuments();
  if (count > 0 && this.isNew) {
    throw new Error('Only one AdminLedger document is allowed');
  }
  next();
});

module.exports = mongoose.model('AdminLedger', adminLedgerSchema);