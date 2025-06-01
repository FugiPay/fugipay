require('dotenv').config();
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Business = require('./models/Business').Business; // Access the Business model

async function migratePins() {
  try {
    console.log('Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGO_URI || 'mongodb+srv://KHAH-YAH:01H0EwNnhMYW8zpO@cluster0.1ap41.mongodb.net/Zangena?retryWrites=true&w=majority');
    console.log('Connected to MongoDB');

    console.log('Business model:', Business);
    if (!Business || typeof Business.find !== 'function') {
      throw new Error('Business is not a valid Mongoose model');
    }

    const businesses = await Business.find({ hashedPin: { $exists: true } });
    console.log(`Found ${businesses.length} businesses with hashedPin`);

    let migratedCount = 0;
    for (const business of businesses) {
      if (business.hashedPin && business.hashedPin.length === 4 && /^\d{4}$/.test(business.hashedPin)) {
        console.log(`Migrating PIN for business: ${business.businessId}`);
        const hashedPin = await bcrypt.hash(business.hashedPin, 10);
        // Use updateOne to avoid triggering pre('save') middleware
        await Business.updateOne(
          { _id: business._id },
          {
            $set: { hashedPin },
            $push: {
              auditLogs: {
                action: 'pin_reset',
                performedBy: 'system',
                details: { message: 'PIN hashed during migration' },
                timestamp: new Date(),
              },
            },
          }
        );
        console.log(`Migrated PIN for business: ${business.businessId}`);
        migratedCount++;
      }
    }
    console.log(`Migration complete. Migrated ${migratedCount} PINs.`);
  } catch (error) {
    console.error('Migration error:', error.message);
    console.error('Error stack:', error.stack);
  } finally {
    console.log('Disconnecting from MongoDB...');
    await mongoose.disconnect();
    console.log('Disconnected');
  }
}

migratePins();