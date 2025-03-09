const mongoose = require('mongoose');
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  name: { type: String, required: true }, // Full name for KYC
  phoneNumber: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  idImageUrl: { type: String }, // S3 URL for ID image
  role: { type: String, default: 'user' },
  balance: { type: Number, default: 0 },
  transactions: [{
    type: { type: String, required: true },
    amount: { type: Number, required: true },
    toFrom: { type: String, required: true },
    date: { type: Date, default: Date.now },
  }],
  kycStatus: { type: String, default: 'pending' }, // 'pending', 'verified', 'rejected'
});
module.exports = mongoose.model('User', userSchema);