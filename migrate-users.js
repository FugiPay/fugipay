const mongoose = require('mongoose');
const User = require('./models/User'); // Adjust path to your User model
require('dotenv').config();

// MongoDB connection string from .env
const MONGODB_URI = process.env.MONGODB_URI || process.env.MONGO_URI;

async function connectToDatabase() {
  try {
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Connected to MongoDB');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
}

async function migrateUsers() {
  try {
    // Step 1: Find all users without a pin
    const users = await User.find({ pin: { $exists: false } });
    console.log(`Found ${users.length} users without a PIN to migrate`);

    if (users.length === 0) {
      console.log('No users need migration. All users already have a PIN.');
      return;
    }

    // Step 2: Update each user with a default PIN
    const defaultPin = '1234'; // Default PIN
    for (const user of users) {
      user.pin = defaultPin;
      try {
        await user.save();
        console.log(`Added PIN to user: ${user.username} (PIN: ${user.pin})`);
      } catch (saveError) {
        console.error(`Failed to save user ${user.username}:`, saveError.message);
      }
    }

    // Step 3: Verify counts
    const updatedUsers = await User.find({ pin: defaultPin });
    console.log(`Migration complete. Processed ${users.length} users, set PIN to "${defaultPin}" for ${updatedUsers.length}.`);
  } catch (error) {
    console.error('Migration error:', error);
  } finally {
    await mongoose.connection.close();
    console.log('Database connection closed');
    process.exit(0);
  }
}

async function runMigration() {
  await connectToDatabase();
  await migrateUsers();
}

runMigration();