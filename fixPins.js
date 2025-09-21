const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('./models/User');

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(async () => {
  console.log('[MongoDB] Connected for pin fix');
  const users = await User.find({ pin: { $regex: '^[0-9]{4}$' } });
  for (const user of users) {
    user.pin = await bcrypt.hash(user.pin, 10);
    await user.save({ validateBeforeSave: false });
    console.log(`Hashed pin for user: ${user.username}`);
  }
  console.log('Pin fix completed');
  mongoose.disconnect();
}).catch(err => console.error('[MongoDB] Error:', err));