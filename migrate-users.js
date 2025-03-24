const mongoose = require('mongoose');
const User = require('./models/User'); // Adjust path to your User model
require('dotenv').config();

// MongoDB connection string from .env
const MONGODB_URI = process.env.MONGO_URI;

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
    // Step 1: Find all users
    const users = await User.find({});
    console.log(`Found ${users.length} users to migrate`);

    // Step 2: Update each user individually
    for (const user of users) {
      let updated = false;

      // Reset balance to 0 if it’s not already 0
      if (user.balance !== 0) {
        user.balance = 0;
        updated = true;
      }

      // Save the user if any changes were made
      if (updated) {
        try {
          await user.save();
          console.log(`Migrated user: ${user.username} (balance: ${user.balance})`);
        } catch (saveError) {
          console.error(`Failed to save user ${user.username}:`, saveError.message);
        }
      } else {
        console.log(`No changes needed for user: ${user.username}`);
      }
    }

    // Step 3: Verify counts
    const totalUpdated = users.filter(user => user.isModified()).length;
    console.log(`Migration complete. Processed ${users.length} users, updated ${totalUpdated}.`);
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