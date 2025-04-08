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
}, { timestamps: true });

// Create the User model
const User = mongoose.models.User || mongoose.model('User', userSchema);

// Main function to check the database
async function checkUser() {
  try {
    // Connect to MongoDB using the environment variable
    const mongoUri = process.env.MONGO_URI;
    if (!mongoUri) {
      throw new Error('MONGODB_URI environment variable not set');
    }

    console.log('Connecting to MongoDB...');
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Connected to MongoDB');

    // Check connection state
    console.log('MongoDB connection state:', mongoose.connection.readyState); // 1 = connected

    // Query for user "Anthony"
    const user = await User.findOne({ username: 'Anthony' }, { password: 0, __v: 0 });
    if (!user) {
      console.log('User "Anthony" not found in the database');
    } else {
      console.log('Found user:', user);
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