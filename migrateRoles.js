const mongoose = require('mongoose');
const User = require('./models/User'); // Adjust path to your User model
const Business = require('./models/Business'); // Adjust path to your Business model
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
    // Step 1: Find all users without a role or with an invalid role
    const users = await User.find({
      $or: [
        { role: { $exists: false } },
        { role: { $nin: ['user', 'admin'] } }, // Exclude valid roles
      ],
    });
    console.log(`Found ${users.length} users without a valid role to migrate`);

    if (users.length === 0) {
      console.log('No users need role migration. All users already have valid roles.');
    } else {
      // Step 2: Update each user with a default role of 'user', preserving 'admin'
      for (const user of users) {
        const newRole = user.role === 'admin' ? 'admin' : 'user'; // Preserve existing admin roles
        user.role = newRole;
        try {
          await user.save();
          console.log(`Set role for user: ${user.username} (Role: ${user.role})`);
        } catch (saveError) {
          console.error(`Failed to save user ${user.username}:`, saveError.message);
        }
      }

      // Step 3: Verify counts
      const updatedUsers = await User.find({ role: 'user' });
      const adminUsers = await User.find({ role: 'admin' });
      console.log(
        `User migration complete. Processed ${users.length} users, set role to 'user' for ${updatedUsers.length}, preserved 'admin' for ${adminUsers.length}.`
      );
    }
  } catch (error) {
    console.error('User migration error:', error);
  }
}

async function migrateBusinesses() {
  try {
    // Step 1: Find all businesses without a role or with an invalid role
    const businesses = await Business.find({
      $or: [
        { role: { $exists: false } },
        { role: { $nin: ['business', 'admin'] } }, // Exclude valid roles
      ],
    });
    console.log(`Found ${businesses.length} businesses without a valid role to migrate`);

    if (businesses.length === 0) {
      console.log('No businesses need role migration. All businesses already have valid roles.');
    } else {
      // Step 2: Update each business with a default role of 'business', preserving 'admin'
      for (const business of businesses) {
        const newRole = business.role === 'admin' ? 'admin' : 'business'; // Preserve existing admin roles
        business.role = newRole;
        try {
          await business.save();
          console.log(`Set role for business: ${business.businessId} (Role: ${business.role})`);
        } catch (saveError) {
          console.error(`Failed to save business ${business.businessId}:`, saveError.message);
        }
      }

      // Step 3: Verify counts
      const updatedBusinesses = await Business.find({ role: 'business' });
      const adminBusinesses = await Business.find({ role: 'admin' });
      console.log(
        `Business migration complete. Processed ${businesses.length} businesses, set role to 'business' for ${updatedBusinesses.length}, preserved 'admin' for ${adminBusinesses.length}.`
      );
    }
  } catch (error) {
    console.error('Business migration error:', error);
  }
}

async function runMigration() {
  await connectToDatabase();
  await migrateUsers();
  await migrateBusinesses();
  await mongoose.connection.close();
  console.log('Database connection closed');
  process.exit(0);
}

runMigration();