const mongoose = require('mongoose');
const User = require('./User');

const adminLedgerTransactionSchema = new mongoose.Schema({
  type: {
    type: String,
    required: true,
    enum: [
      'fee-collected', // Fees from transactions (e.g., /api/withdraw, /deposit/manual)
      'deposit_fee', // Fees from deposits (/deposit/manual)
      'withdrawal_fee', // Fees from withdrawals (/withdraw/request, /api/withdraw)
      'admin_adjustment', // Manual admin balance adjustments
      'admin_withdrawal', // Admin-initiated withdrawals
    ],
    default: 'fee-collected',
  },
  amount: {
    type: Number,
    required: true,
    min: 0, // Fee or adjustment amount
  },
  sender: {
    type: String,
    required: true, // Sender username (or 'System' for admin actions)
  },
  receiver: {
    type: String,
    required: true, // Receiver username (or 'System' for admin actions)
  },
  userTransactionIds: {
    type: [String],
    required: function () {
      return ['fee-collected', 'deposit_fee', 'withdrawal_fee'].includes(this.type);
    }, // Required for user-related fees
    validate: {
      validator: async function (ids) {
        if (!['fee-collected', 'deposit_fee', 'withdrawal_fee'].includes(this.type)) {
          return true; // Not required for admin_adjustment, admin_withdrawal
        }
        if (ids.length === 0) return false;
        const user = await User.findOne({
          $or: [
            { 'transactions._id': { $in: ids } },
            { 'pendingWithdrawals._id': { $in: ids } },
            { 'pendingDeposits.transactionId': { $in: ids } },
          ],
        });
        return !!user;
      },
      message: 'Invalid userTransactionIds: must reference User.transactions, pendingWithdrawals, or pendingDeposits',
    },
  },
  fraudScore: {
    type: Number,
    min: -1,
    max: 1,
    default: null, // AI: Anomaly score from fraud_detection.py
  },
  analyticsEventId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Analytics',
    default: null, // Link to Analytics event
  },
  ip: {
    type: String,
    default: null, // Device metadata for AML
  },
  userAgent: {
    type: String,
    default: null, // Device metadata for AML
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
    validate: {
      validator: async function (value) {
        const ledger = await this.constructor.findById(this._id);
        if (!ledger) return true; // Skip validation for new documents
        const total = ledger.transactions.reduce((sum, tx) => {
          return ['fee-collected', 'deposit_fee', 'withdrawal_fee'].includes(tx.type)
            ? sum + tx.amount
            : ['admin_withdrawal'].includes(tx.type)
            ? sum - tx.amount
            : sum;
        }, 0);
        return value === total;
      },
      message: 'totalBalance must equal the net sum of transaction amounts',
    },
  },
  lastUpdated: {
    type: Date,
    default: Date.now,
    index: true,
  },
  transactions: [adminLedgerTransactionSchema],
}, {
  timestamps: true,
});

// Singleton enforcement
adminLedgerSchema.pre('save', async function (next) {
  if (this.isNew) {
    const count = await this.constructor.countDocuments();
    if (count > 0) {
      throw new Error('Only one AdminLedger document is allowed');
    }
  }
  next();
});

// Update lastUpdated on transaction push
adminLedgerSchema.pre('save', function (next) {
  if (this.isModified('transactions')) {
    this.lastUpdated = new Date();
  }
  next();
});

// Indexes for efficient querying
adminLedgerSchema.index({ 'transactions.userTransactionIds': 1 });
adminLedgerSchema.index({ 'transactions.analyticsEventId': 1 });
adminLedgerSchema.index({ 'transactions.date': -1 });

module.exports = mongoose.model('AdminLedger', adminLedgerSchema);