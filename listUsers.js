const mongoose = require('mongoose');
const User = require('./models/User');

async function listUsers() {
  try {
    // Connect using Heroku's MONGODB_URI
    const mongoUri = process.env.MONGODB_URI;
    if (!mongoUri) throw new Error('MONGODB_URI not set');
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Connected to MongoDB');

    // List all users
    const users = await User.find({}, { username: 1, phoneNumber: 1, _id: 0 });
    if (users.length === 0) {
      console.log('No users found in the database');
    } else {
      console.log(`Found ${users.length} users:`);
      users.forEach(user => {
        console.log(`Username: ${user.username}, Phone: ${user.phoneNumber}`);
      });
    }
  } catch (error) {
    console.error('Error:', error.message);
  } finally {
    await mongoose.connection.close();
    console.log('Connection closed');
  }
}

listUsers().then(() => process.exit(0)).catch(err => {
  console.error('Script failed:', err);
  process.exit(1);
});