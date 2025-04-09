const mongoose = require('mongoose');
const User = require('./models/User');

async function fixTransactions() {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Connected to MongoDB');

    const users = await User.find({ 'transactions._id': { $exists: true } });
    console.log(`Found ${users.length} users with transactions`);

    for (const user of users) {
      const validTransactions = user.transactions.filter(tx => {
        if (!tx._id) {
          console.log(`Removing transaction for ${user.username} with undefined _id`);
          return false;
        }
        if (typeof tx._id === 'string' && /^[0-9a-fA-F]{24}$/.test(tx._id)) {
          return true; // Keep valid ObjectId strings
        }
        console.log(`Removing invalid _id in transaction for ${user.username}: ${tx._id}`);
        return false;
      });

      if (validTransactions.length !== user.transactions.length) {
        user.transactions = validTransactions;
        await user.save();
        console.log(`Cleaned transactions for ${user.username}. Kept ${validTransactions.length} of ${user.transactions.length} entries.`);
      } else {
        console.log(`No changes needed for ${user.username}`);
      }
    }

    console.log('Transaction cleanup complete');
  } catch (error) {
    console.error('Error:', error.message);
  } finally {
    await mongoose.connection.close();
    console.log('Connection closed');
  }
}

fixTransactions().then(() => process.exit(0)).catch(err => {
  console.error('Script failed:', err);
  process.exit(1);
});