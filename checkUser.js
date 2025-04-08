const mongoose = require('mongoose');

// Define the User schema (match your actual schema in models/User.js)
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  phoneNumber: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' },
  balance: { type: Number, default: 0 },
  kycStatus: { type: String, default: 'pending' },
  isFirstLogin: { type: Boolean, default: true },
  transactions: [{
    type: { type: String },
    amount: { type: Number },
    toFrom: { type: String },
    fee: { type: Number },
    date: { type: Date, default: Date.now },
  }],
  airtelBalance: { type: Number, default: 0 },
  mtnBalance: { type: Number, default: 0 },
  moneyunifyBalance: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  email: { type: String },
  name: { type: String },
  pendingDeposits: [{
    amount: { type: Number },
    transactionId: { type: String },
    date: { type: Date },
    status: { type: String },
  }],
  pendingWithdrawals: [{
    amount: { type: Number },
    date: { type: Date },
    status: { type: String },
  }],
  lastLogin: { type: Date },
  pin: { type: String },
  trustScore: { type: Number },
  zambiaCoinBalance: { type: Number },
  ratingCount: { type: Number },
}, { timestamps: true });

// Create the User model
const User = mongoose.models.User || mongoose.model('User', userSchema);

// Main function to check the database
async function checkUser() {
  try {
    // Connect to MongoDB using the environment variable
    const mongoUri = process.env.MONGO_URI; // Changed to MONGO_URI to match Heroku convention
    if (!mongoUri) {
      throw new Error('MONGO_URI environment variable not set');
    }

    console.log('Connecting to MongoDB...');
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Connected to MongoDB');

    // Check connection state
    console.log('MongoDB connection state:', mongoose.connection.readyState); // 1 = connected

    // Count users with username "Anthony"
    const count = await User.countDocuments({ username: 'Anthony' });
    console.log(`Total users with username "Anthony": ${count}`);

    // Query all users with username "Anthony"
    const users = await User.find({ username: 'Anthony' }, { password: 0, __v: 0 });
    if (users.length === 0) {
      console.log('User "Anthony" not found in the database');
    } else {
      console.log(`Found ${users.length} user(s) with username "Anthony":`);
      users.forEach((user, index) => {
        console.log(`User ${index + 1}:`, user);
      });

      // If duplicates exist, keep the most recent by lastLogin and delete others
      if (users.length > 1) {
        const keep = users.sort((a, b) => (b.lastLogin || 0) - (a.lastLogin || 0))[0]; // Keep latest login
        const removeIds = users.filter(u => u._id.toString() !== keep._id.toString()).map(u => u._id);
        await User.deleteMany({ _id: { $in: removeIds } });
        console.log(`Deleted ${removeIds.length} duplicate users. Kept user with _id: ${keep._id}`);
      }
    }

    // Query by phoneNumber as a fallback
    const userByPhone = await User.findOne({ phoneNumber: '+260972721581' }, { password: 0, __v: 0 });
    if (!userByPhone) {
      console.log('User with phoneNumber "+260972721581" not found in the database');
    } else {
      console.log('Found user by phoneNumber:', userByPhone);
    }
  } catch (error) {
    console.error('Error checking user:', {
      message: error.message,
      stack: error.stack,
    });
  } finally {
    // Close the connection
    await mongoose.connection.close();
    console.log('MongoDB connection closed');
  }
}

// Run the check
checkUser().then(() => process.exit(0)).catch((err) => {
  console.error('Script failed:', err);
  process.exit(1);
});