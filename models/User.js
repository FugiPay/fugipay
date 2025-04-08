const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  type: { type: String, required: true },
  amount: { type: Number, required: true },
  toFrom: { type: String, required: true },
  fee: { type: Number, default: 0 },
  date: { type: Date, default: Date.now },
});

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true },
  phoneNumber: { type: String, required: true, unique: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  balance: { type: Number, default: 0 },
  kycStatus: { type: String, enum: ['pending', 'verified'], default: 'pending' },
  transactions: [transactionSchema],
}, { timestamps: true });

userSchema.index({ username: 1 }, { unique: true });
userSchema.index({ phoneNumber: 1 }, { unique: true });

module.exports = mongoose.models.User || mongoose.model('User', userSchema);