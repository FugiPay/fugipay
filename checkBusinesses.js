const mongoose = require('mongoose');
const Business = require('./models/Business'); // Adjust path to your Business model

async function checkBusinesses() {
  try {
  await mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
    if (!mongoUri) {
      throw new Error('MONGODB_URI environment variable not set. Run: heroku config:get MONGODB_URI --app zangena');
    }
    await mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true });
    console.log('Connected to MongoDB');

    // Find businesses with hashed pins (non-4-digit)
    const businesses = await Business.find({ pin: { $not: /^\d{4}$/ } });
    console.log(`Found ${businesses.length} businesses with hashed PINs`);

    if (businesses.length === 0) {
      console.log('No businesses need PIN migration');
      return;
    }

    // Update documents: move pin to hashedPin, set pin to '0000'
    const updateResult = await Business.updateMany(
      { pin: { $not: /^\d{4}$/ } },
      { $set: { hashedPin: '$pin', pin: '0000' } }
    );
    console.log(`Update result: matched=${updateResult.matchedCount}, modified=${updateResult.modifiedCount}`);

    // Verify updates
    const updatedBusinesses = await Business.find({ pin: '0000' });
    console.log(`Verified: ${updatedBusinesses.length} businesses with PIN '0000'`);
    updatedBusinesses.forEach((business) => {
      console.log(`Business: ${business.businessId}, PIN: ${business.pin}, Hashed PIN: ${business.hashedPin ? 'set' : 'not set'}`);
    });

    console.log('PIN migration complete');
  } catch (error) {
    console.error('Error fixing PINs:', error.message);
  } finally {
    await mongoose.connection.close();
    console.log('Disconnected from MongoDB');
  }
}

checkBusinesses().catch(console.error);