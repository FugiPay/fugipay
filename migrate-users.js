const mongoose = require('mongoose');
const User = require('./models/User'); // Adjust path to your User model
require('dotenv').config();

// MongoDB connection string
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
    // Step 1: Find users missing any of the required fields (isActive, name, email)
    const usersToMigrate = await User.find({
      $or: [
        { isActive: { $exists: false } },
        { name: { $exists: false } },
        { email: { $exists: false } },
      ],
    });
    console.log(`Found ${usersToMigrate.length} users to migrate`);

    // Step 2: Update each user individually
    for (const user of usersToMigrate) {
      let updated = false;

      // Add isActive if missing
      if (user.isActive === undefined) {
        user.isActive = false;
        updated = true;
      }

      // Add name if missing (use username as fallback)
      if (!user.name) {
        user.name = user.username;
        updated = true;
      }

      // Add email if missing (derive from username)
      if (!user.email) {
        user.email = `${user.username.toLowerCase()}@zangena.com`; // Adjust domain as needed
        updated = true;
      }

      // Save the user if any changes were made
      if (updated) {
        try {
          await user.save();
          console.log(`Migrated user: ${user.username} (name: ${user.name}, email: ${user.email}, isActive: ${user.isActive})`);
        } catch (saveError) {
          console.error(`Failed to save user ${user.username}:`, saveError.message);
        }
      } else {
        console.log(`No changes needed for user: ${user.username}`);
      }
    }

    // Step 3: Verify counts
    const totalUpdated = usersToMigrate.filter(user => user.isModified()).length;
    console.log(`Migration complete. Processed ${usersToMigrate.length} users, updated ${totalUpdated}.`);
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