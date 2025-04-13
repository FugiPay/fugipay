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
    // 1. Check for duplicate usernames
    const duplicateUsers = await User.aggregate([
      { $group: { _id: "$username", count: { $sum: 1 }, docs: { $push: "$$ROOT" } } },
      { $match: { count: { $gt: 1 } } },
    ]);
    if (duplicateUsers.length > 0) {
      for (const dup of duplicateUsers) {
        const docs = dup.docs.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
        const keep = docs[0];
        const removeIds = docs.slice(1).map(d => d._id);
        await User.deleteMany({ _id: { $in: removeIds } });
        console.log(`Removed ${removeIds.length} duplicates for username: ${dup._id}`);
      }
    } else {
      console.log('No duplicate usernames found');
    }

    // 2. Migrate roles
    const usersWithInvalidRoles = await User.find({
      $or: [{ role: { $exists: false } }, { role: { $nin: ['user', 'admin'] } }],
    });
    for (const user of usersWithInvalidRoles) {
      user.role = user.role === 'admin' ? 'admin' : 'user';
      await user.save();
      console.log(`Set role for user: ${user.username} (Role: ${user.role})`);
    }
    console.log(`Processed ${usersWithInvalidRoles.length} users for role migration`);

    // 3. Add lastViewedTimestamp
    const result = await User.updateMany(
      { lastViewedTimestamp: { $exists: false } },
      { $set: { lastViewedTimestamp: 0 } }
    );
    console.log(`Added lastViewedTimestamp to ${result.modifiedCount} users`);

  } catch (error) {
    console.error('Migration error:', error.message);
    process.exit(1);
  }
}

async function runMigration() {
  await connectToDatabase();
  await migrateUsers();
}

runMigration();