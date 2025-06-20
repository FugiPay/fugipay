const mongoose = require('mongoose');
const crypto = require('crypto');

const transactionSchema = new mongoose.Schema({
  _id: { type: String }, // Custom transaction ID
  type: {
    type: String,
    required: true,
    enum: [
      'sent', 'received', 'credited', 'deposited', 'withdrawn', 'fee-collected', 'pending-pin',
      'zmc-sent', 'zmc-received',
    ],
  },
  amount: { type: Number, required: true },
  toFrom: { type: String, required: true },
  date: { type: Date, default: Date.now, index: true },
  fee: { type: Number, default: 0 },
  originalAmount: { type: Number },
  sendingFee: { type: Number },
  receivingFee: { type: Number },
  trustRating: { type: Number, min: 1, max: 5 },
  mobileMoneyProvider: { type: String, enum: ['MTN', 'Airtel', null], default: null }, // New: Indicates source of transaction
});

const pendingDepositSchema = new mongoose.Schema({
  amount: { type: Number, required: true },
  transactionId: { type: String, required: true },
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
});

const pendingWithdrawalSchema = new mongoose.Schema({
  amount: { type: Number, required: true },
  fee: { type: Number, required: true },
  destinationOfFunds: {
    type: String,
    required: true,
    enum: ['MTN Mobile Money', 'Airtel Mobile Money', 'Bank Transfer'],
  },
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ['pending', 'completed', 'rejected'], default: 'pending' },
});

const mobileMoneyAccountSchema = new mongoose.Schema({
  provider: { type: String, required: true, enum: ['MTN', 'Airtel'] },
  phoneNumber: {
    type: String,
    required: true,
    match: /^\+260(9[5678]|7[34679])\d{7}$/,
  },
  accessToken: { type: String, required: true }, // Encrypted
  refreshToken: { type: String, required: true }, // Encrypted
  tokenExpiry: { type: Date, required: true },
  lastSynced: { type: Date }, // Tracks last transaction sync
});

// Encryption middleware for mobile money tokens
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex'); // Must be 32 bytes
const IV_LENGTH = 16; // AES-256-CBC IV length

function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let encrypted = cipher.update(text);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
  const textParts = text.split(':');
  const iv = Buffer.from(textParts.shift(), 'hex');
  const encryptedText = Buffer.from(textParts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let decrypted = decipher.update(encryptedText);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted.toString();
}

mobileMoneyAccountSchema.pre('save', function(next) {
  if (this.isModified('accessToken')) {
    this.accessToken = encrypt(this.accessToken);
  }
  if (this.isModified('refreshToken')) {
    this.refreshToken = encrypt(this.refreshToken);
  }
  next();
});

mobileMoneyAccountSchema.methods.getAccessToken = function() {
  return decrypt(this.accessToken);
};

mobileMoneyAccountSchema.methods.getRefreshToken = function() {
  return decrypt(this.refreshToken);
};

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, index: true },
  name: { type: String, required: true },
  phoneNumber: {
    type: String,
    required: true,
    unique: true,
    index: true,
    match: /^\+260(9[5678]|7[34679])\d{7}$/,
  },
  email: { type: String, required: true, unique: true, index: true },
  password: { type: String, required: true, minlength: 6 },
  hashedPin: { type: String, required: true }, // Renamed from pin, removed length constraints
  idImageUrl: { type: String },
  role: { type: String, default: 'user', enum: ['user', 'admin'] },
  balance: { type: Number, default: 0 },
  zambiaCoinBalance: { type: Number, default: 0 },
  trustScore: { type: Number, default: 0, min: 0, max: 100 },
  ratingCount: { type: Number, default: 0 },
  transactions: [transactionSchema],
  kycStatus: { type: String, default: 'pending', enum: ['pending', 'verified', 'rejected'] },
  isActive: { type: Boolean, default: false },
  isArchived: { type: Boolean, default: false, index: true },
  archivedAt: { type: Date },
  archivedReason: { type: String },
  resetToken: { type: String },
  resetTokenExpiry: { type: Date },
  pushToken: { type: String, default: null },
  pendingDeposits: [pendingDepositSchema],
  pendingWithdrawals: [pendingWithdrawalSchema],
  lastLogin: { type: Date, default: null },
  lastViewedTimestamp: { type: Number, default: 0 },
  twoFactorSecret: { type: String },
  twoFactorEnabled: { type: Boolean, default: false },
  mobileMoneyAccounts: [mobileMoneyAccountSchema], // New: Stores MTN/Airtel account details
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true },
});

// Virtual to check if account is effectively active
userSchema.virtual('isEffectivelyActive').get(function () {
  return this.isActive && !this.isArchived;
});

// Index for efficient querying
userSchema.index({ isActive: 1, isArchived: 1 });
userSchema.index({ username: 1 }, { unique: true });
userSchema.index({ phoneNumber: 1 }, { unique: true });
userSchema.index({ email: 1 }, { unique: true });

module.exports = mongoose.model('User', userSchema);