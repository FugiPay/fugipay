const mongoose = require('mongoose');
const User = require('./models/User');

async function dropDuplicateIndexes() {
  try {
    await mongoose.connect(
      process.env.MONGODB_URI || 
      'mongodb+srv://KHAH-YAH:01H0EwNnhMYW8zpO@cluster0.1ap41.mongodb.net/Zangena?retryWrites=true&w=majority',
      { useNewUrlParser: true, useUnifiedTopology: true }
    );
    console.log('[DropIndexes] Connected to MongoDB');

    // List all indexes on the users collection
    const indexes = await User.collection.getIndexes();
    console.log('[DropIndexes] Current indexes:', JSON.stringify(indexes, null, 2));

    // Define expected indexes from User.js schema
    const expectedIndexes = [
      { name: 'username_1', key: { username: 1 }, options: { unique: true } },
      { name: 'phoneNumber_1', key: { phoneNumber: 1 }, options: { unique: true } },
      { name: 'email_1', key: { email: 1 }, options: { unique: true } },
      { name: 'isActive_1_isArchived_1', key: { isActive: 1, isArchived: 1 }, options: {} },
      { name: 'trustScore_1', key: { trustScore: 1 }, options: {} },
      { name: 'isFlagged_1', key: { isFlagged: 1 }, options: {} },
      { name: 'isArchived_1', key: { isArchived: 1 }, options: {} },
      { name: 'pendingDeposits.transactionId_1', key: { 'pendingDeposits.transactionId': 1 }, options: { unique: true, sparse: true } },
      { name: 'pendingWithdrawals.transactionId_1', key: { 'pendingWithdrawals.transactionId': 1 }, options: { unique: true, sparse: true } },
      { name: 'transactions.analyticsEventId_1', key: { 'transactions.analyticsEventId': 1 }, options: {} },
      { name: 'pendingDeposits.analyticsEventId_1', key: { 'pendingDeposits.analyticsEventId': 1 }, options: {} },
      { name: 'pendingWithdrawals.analyticsEventId_1', key: { 'pendingWithdrawals.analyticsEventId': 1 }, options: {} },
      { name: 'kycAnalysis.analyticsEventId_1', key: { 'kycAnalysis.analyticsEventId': 1 }, options: {} },
      { name: 'transactions.date_1', key: { 'transactions.date': 1 }, options: {} },
      { name: 'createdAt_1', key: { createdAt: 1 }, options: { background: true } }, // Explicitly define without expireAfterSeconds
    ];

    // Drop conflicting or unexpected indexes
    for (const [indexName, indexSpec] of Object.entries(indexes)) {
      if (indexName === '_id_') continue; // Skip default _id index

      const expectedIndex = expectedIndexes.find(
        idx => idx.name === indexName || JSON.stringify(idx.key) === JSON.stringify(indexSpec[0])
      );

      if (!expectedIndex || indexName === 'createdAt_1') {
        // Drop unexpected indexes or createdAt_1 with expireAfterSeconds
        console.log(`[DropIndexes] Dropping index: ${indexName}`);
        await User.collection.dropIndex(indexName);
      } else {
        // Check for option conflicts
        const currentOptions = {
          unique: indexSpec.unique || false,
          sparse: indexSpec.sparse || false,
          expireAfterSeconds: indexSpec.expireAfterSeconds || undefined,
          background: indexSpec.background || false,
        };
        const expectedOptions = expectedIndex.options;

        if (JSON.stringify(currentOptions) !== JSON.stringify(expectedOptions)) {
          console.log(`[DropIndexes] Dropping conflicting index: ${indexName}`);
          await User.collection.dropIndex(indexName);
        }
      }
    }

    // Clean up null transactionIds in pendingDeposits and pendingWithdrawals
    console.log('[DropIndexes] Cleaning up null transactionIds in pendingDeposits');
    await User.updateMany(
      { 'pendingDeposits.transactionId': null },
      { $pull: { pendingDeposits: { transactionId: null } } }
    );

    console.log('[DropIndexes] Cleaning up null transactionIds in pendingWithdrawals');
    await User.updateMany(
      { 'pendingWithdrawals.transactionId': null },
      { $pull: { pendingWithdrawals: { transactionId: null } } }
    );

    // Re-create schema indexes
    console.log('[DropIndexes] Re-creating schema indexes');
    await User.createIndexes();

    // Verify indexes
    const newIndexes = await User.collection.getIndexes();
    console.log('[DropIndexes] Updated indexes:', JSON.stringify(newIndexes, null, 2));

    console.log('[DropIndexes] Index cleanup completed');
    await mongoose.connection.close();
    process.exit(0);
  } catch (error) {
    console.error('[DropIndexes] Error:', {
      message: error.message,
      stack: error.stack,
    });
    await mongoose.connection.close();
    process.exit(1);
  }
}

dropDuplicateIndexes();