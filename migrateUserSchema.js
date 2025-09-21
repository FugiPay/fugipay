const mongoose = require('mongoose');
const User = require('./models/User');

async function migrateUserSchema() {
  try {
    await mongoose.connect('mongodb+srv://KHAH-YAH:01H0EwNnhMYW8zpO@cluster0.1ap41.mongodb.net/Zangena?retryWrites=true&w=majority', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('[Migration] Connected to MongoDB');

    // Add lastLoginAttempts to all users
    const updateLoginAttempts = await User.updateMany(
      { lastLoginAttempts: { $exists: false } },
      { $set: { lastLoginAttempts: 0 } }
    );
    console.log('[Migration] Added lastLoginAttempts:', updateLoginAttempts);

    // Add lastWithdrawAttempts to all users
    const updateWithdrawAttempts = await User.updateMany(
      { lastWithdrawAttempts: { $exists: false } },
      { $set: { lastWithdrawAttempts: 0 } }
    );
    console.log('[Migration] Added lastWithdrawAttempts:', updateWithdrawAttempts);

    // Add analyticsEventId to kycAnalysis
    const updateKycAnalysis = await User.updateMany(
      { 'kycAnalysis.analyticsEventId': { $exists: false } },
      { $set: { 'kycAnalysis.analyticsEventId': null } }
    );
    console.log('[Migration] Added kycAnalysis.analyticsEventId:', updateKycAnalysis);

    // Ensure idImageUrl is set
    const updateIdImageUrl = await User.updateMany(
      { idImageUrl: { $exists: false } },
      { $set: { idImageUrl: '' } }
    );
    console.log('[Migration] Set idImageUrl for existing users:', updateIdImageUrl);

    console.log('[Migration] Completed successfully');
    process.exit(0);
  } catch (error) {
    console.error('[Migration] Error:', error.message);
    process.exit(1);
  }
}

migrateUserSchema();