const mongoose = require('mongoose');
const User = require('./models/User');

async function fixTransactions() {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Connected to MongoDB');

    // Find users with invalid transaction _ids
    const users = await User.find({ 'transactions._id': { $type: 'string' } });
    console.log(`Found ${users.length} users with string _ids in transactions`);

    for (const user of users) {
      const validTransactions = user.transactions.filter(tx => {
        try {
          mongoose.Types.ObjectId(tx._id); // Test if _id is a valid ObjectId
          return true;
        } catch (e) {
          console.log(`Invalid _id in transaction for ${user.username}: ${tx._id}`);
          return false;
        }
      });

      if (validTransactions.length !== user.transactions.length) {
        user.transactions = validTransactions;
        await user.save();
        console.log(`Cleaned transactions for ${user.username}. Kept ${validTransactions.length} valid entries.`);
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