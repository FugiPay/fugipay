const mongoose = require('mongoose');
const User = require('./models/User'); // Adjust path to your User model
require('dotenv').config();

// MongoDB connection string (replace with your actual URI)
const MONGODB_URI = process.env.MONGO_URI

// Connect to MongoDB
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

// Migration function
async function migrateUsers() {
  try {
    // Update all users where isActive is undefined to set it to false
    const result = await User.updateMany(
      { isActive: { $exists: false } }, // Targets documents missing the isActive field
      { $set: { isActive: false } }    // Sets isActive to false
    );
    console.log(`Migration complete. Updated ${result.modifiedCount} users.`);
  } catch (error) {
    console.error('Migration error:', error);
  } finally {
    await mongoose.connection.close();
    console.log('Database connection closed');
    process.exit(0);
  }
}

// Run the migration
async function runMigration() {
  await connectToDatabase();
  await migrateUsers();
}

runMigration();