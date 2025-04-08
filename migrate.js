const mongoose = require('mongoose');
const User = require('./models/User');

const connectDB = async () => {
  const mongoUri = process.env.MONGODB_URI;
  if (!mongoUri) throw new Error('MONGODB_URI not set');
  await mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true });
  console.log('Connected to MongoDB');
};

async function migrateUsers() {
  try {
    // Check for duplicate usernames
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
    }

    // Migrate roles
    const users = await User.find({ $or: [{ role: { $exists: false } }, { role: { $nin: ['user', 'admin'] } }] });
    for (const user of users) {
      user.role = user.role === 'admin' ? 'admin' : 'user';
      await user.save();
      console.log(`Set role for user: ${user.username} (Role: ${user.role})`);
    }
    console.log(`Processed ${users.length} users`);
  } catch (error) {
    console.error('Migration error:', error);
    process.exit(1);
  }
}

connectDB()
  .then(migrateUsers)
  .then(() => mongoose.connection.close())
  .then(() => console.log('Done'))
  .catch(() => process.exit(1));