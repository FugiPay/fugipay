const mongoose = require('mongoose');

const testBusinessSchema = new mongoose.Schema({
  businessId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  pin: { type: String, required: true },
  balance: { type: Number, default: 0 },
  approvalStatus: { type: String, default: 'pending' },
  isActive: { type: Boolean, default: false },
});

module.exports = mongoose.model('TestBusiness', testBusinessSchema);