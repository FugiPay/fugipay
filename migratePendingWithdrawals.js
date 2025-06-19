const mongoose = require('mongoose');

// Connect to MongoDB (replace with your connection string)
mongoose.connect('mongodb+srv://KHAH-YAH:01H0EwNnhMYW8zpO@cluster0.1ap41.mongodb.net/Zangena?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const userSchema = new mongoose.Schema({
  pendingWithdrawals: [{
    amount: { type: Number, required: true },
    fee: { type: Number },
    destinationOfFunds: { type: String },
    date: { type: Date, default: Date.now },
    status: { type: String, enum: ['pending', 'completed', 'rejected'], default: 'pending' },
  }],
  // Other fields omitted for brevity
}, { strict: false });

const User = mongoose.model('User', userSchema);

async function migratePendingWithdrawals() {
  try {
    console.log('Starting migration...');
    const users = await User.find({ pendingWithdrawals: { $exists: true, $ne: [] } });

    for (const user of users) {
      let needsUpdate = false;
      for (const withdrawal of user.pendingWithdrawals) {
        if (withdrawal.fee === undefined) {
          withdrawal.fee = Math.max(withdrawal.amount * 0.01, 2); // Default to 1% fee, min 2
          needsUpdate = true;
        }
        if (withdrawal.destinationOfFunds === undefined) {
          // Infer destination based on phoneNumber (if available)
          const phonePrefix = user.phoneNumber?.slice(4, 6);
          withdrawal.destinationOfFunds = ['96', '76'].includes(phonePrefix)
            ? 'MTN Mobile Money'
            : ['97', '77'].includes(phonePrefix)
              ? 'Airtel Mobile Money'
              : 'Unknown';
          needsUpdate = true;
        }
      }
      if (needsUpdate) {
        await user.save({ validateBeforeSave: false }); // Bypass validation to fix existing data
        console.log(`Updated user ${user.username || user.phoneNumber}`);
      }
    }
    console.log('Migration completed successfully.');
  } catch (error) {
    console.error('Migration error:', error.message, error.stack);
  } finally {
    mongoose.connection.close();
  }
}

migratePendingWithdrawals();