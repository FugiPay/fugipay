const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const User = require('./models/User');

async function migrateHashedPin() {
  try {
    await mongoose.connect('mongodb+srv://KHAH-YAH:01H0EwNnhMYW8zpO@cluster0.1ap41.mongodb.net/Zangena?retryWrites=true&w=majority', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('[Migration] Connected to MongoDB');

    const users = await User.find({ $or: [{ hashedPin: { $exists: false } }, { hashedPin: null }] });
    console.log(`[Migration] Found ${users.length} users without hashedPin`);

    for (const user of users) {
      const tempPin = crypto.randomBytes(4).toString('hex'); // Temporary 4-character PIN
      user.hashedPin = await bcrypt.hash(tempPin, 10);
      await user.save();
      console.log(`[Migration] Updated user: ${user.username} (${user.phoneNumber})`);
    }

    console.log('[Migration] Migration completed');
    await mongoose.disconnect();
  } catch (error) {
    console.error('[Migration] Error:', {
      message: error.message,
      stack: error.stack,
    });
    process.exit(1);
  }
}

migrateHashedPin();