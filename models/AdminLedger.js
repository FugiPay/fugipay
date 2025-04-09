const mongoose = require('mongoose');

const adminLedgerSchema = new mongoose.Schema({
  totalBalance: {
    type: Number,
    default: 0,
    min: 0, // Prevent negative balances (optional, adjust if negatives are valid)
  },
  lastUpdated: {
    type: Date,
    default: Date.now,
    index: true, // Index for sorting/querying by date
  },
}, {
  timestamps: true, // Adds createdAt/updatedAt for consistency with User, Business
});

// Optional: Ensure singleton behavior with a pre-save hook
adminLedgerSchema.pre('save', async function (next) {
  const count = await this.constructor.countDocuments();
  if (count > 0 && this.isNew) {
    throw new Error('Only one AdminLedger document is allowed');
  }
  next();
});

module.exports = mongoose.model('AdminLedger', adminLedgerSchema);