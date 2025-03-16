const adminLedgerSchema = new mongoose.Schema({
    totalBalance: { type: Number, default: 0 },
    lastUpdated: { type: Date, default: Date.now },
  });
  const AdminLedger = mongoose.model('AdminLedger', adminLedgerSchema);