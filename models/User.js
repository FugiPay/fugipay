const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phoneNumber: { type: String, required: true, unique: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
  balance: { type: Number, default: 0 },
  transactions: [{
    type: { type: String, enum: ['sent', 'received', 'credited', 'pending-pin'] }, // Added 'pending-pin'
    amount: Number,
    toFrom: String,
    date: { type: Date, default: Date.now }
  }]
});

module.exports = mongoose.model('User', userSchema);