const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const qrPinSchema = new mongoose.Schema({
  type: {
    type: String,
    required: true,
    enum: ['user', 'business'],
  },
  username: {
    type: String,
    required: function () {
      return this.type === 'user';
    },
    ref: 'User',
  },
  businessId: {
    type: String,
    required: function () {
      return this.type === 'business';
    },
    ref: 'Business',
  },
  qrId: {
    type: String,
    required: true,
    unique: true,
  },
  pin: {
    type: String,
    required: function () {
      return this.type === 'user';
    },
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
  persistent: {
    type: Boolean,
    default: function () {
      return this.type === 'business';
    },
  },
  isActive: {
    type: Boolean,
    default: true,
  },
  archivedAt: {
    type: Date,
  },
  archivedReason: {
    type: String,
  },
}, {
  timestamps: false,
});

// Pre-save hook
qrPinSchema.pre('save', async function (next) {
  if (this.isModified('pin') && this.pin && !this.pin.startsWith('$2')) {
    if (!/^\d{4}$/.test(this.pin)) {
      return next(new Error('PIN must be a 4-digit number'));
    }
    this.pin = await bcrypt.hash(this.pin, 10);
  }
  if (this.type === 'business') {
    this.persistent = true;
  }
  this.updatedAt = new Date();
  next();
});

// Compare PIN method
qrPinSchema.methods.comparePin = async function (candidatePin) {
  if (!this.pin) return true;
  return await bcrypt.compare(candidatePin, this.pin);
};

// Virtual for usability
qrPinSchema.virtual('isEffectivelyUsable').get(function () {
  return this.isActive && !this.archivedAt;
});

// Define indexes in a controlled manner
async function ensureQRPinIndexes() {
  try {
    console.log('[QRPin] Ensuring indexes for QRPin collection');
    // Check if qrpins collection exists
    const collections = await mongoose.connection.db.listCollections().toArray();
    const qrPinCollectionExists = collections.some(col => col.name === 'qrpins');

    if (!qrPinCollectionExists) {
      console.log('[QRPin] qrpins collection does not exist, creating it');
      await mongoose.connection.db.createCollection('qrpins');
    }

    // Check for existing indexes and drop conflicting ones
    const existingIndexes = await mongoose.connection.db.collection('qrpins').indexes();
    const usernameIndex = existingIndexes.find(index => index.key.username === 1);
    const businessIdIndex = existingIndexes.find(index => index.key.businessId === 1);

    if (usernameIndex && (usernameIndex.name !== 'username_1' || !usernameIndex.sparse)) {
      console.log(`[QRPin] Dropping conflicting username index: ${usernameIndex.name}`);
      await mongoose.connection.db.collection('qrpins').dropIndex(usernameIndex.name, { maxTimeMS: 30000 });
    }
    if (businessIdIndex && (businessIdIndex.name !== 'businessId_1' || !businessIdIndex.sparse)) {
      console.log(`[QRPin] Dropping conflicting businessId index: ${businessIdIndex.name}`);
      await mongoose.connection.db.collection('qrpins').dropIndex(businessIdIndex.name, { maxTimeMS: 30000 });
    }

    // Create indexes
    await mongoose.connection.db.collection('qrpins').createIndexes([
      { key: { username: 1 }, name: 'username_1', sparse: true },
      { key: { businessId: 1 }, name: 'businessId_1', sparse: true },
      { key: { qrId: 1 }, name: 'qrId_1', unique: true },
      { key: { isActive: 1 }, name: 'isActive_1' },
      { key: { createdAt: 1 }, name: 'createdAt_1' },
    ], { maxTimeMS: 30000 });
    console.log('[QRPin] Successfully ensured indexes');
  } catch (error) {
    console.error('[QRPin] Error ensuring indexes:', {
      message: error.message,
      code: error.code,
      codeName: error.codeName,
    });
    if (error.code === 85 || error.code === 86 || error.code === 26) {
      console.log('[QRPin] Ignoring index conflict or namespace error (code 85, 86, or 26)');
    } else {
      throw error;
    }
  }
}

// Run index creation after connection is established
mongoose.connection.once('open', () => {
  console.log('[MongoDB] Connected, ensuring QRPin indexes');
  ensureQRPinIndexes();
});

module.exports = mongoose.model('QRPin', qrPinSchema);