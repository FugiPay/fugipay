const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('./models/User');

mongoose.connect('mongodb+srv://KHAH-YAH:01H0EwNnhMYW8zpO@cluster0.1ap41.mongodb.net/Zangena?retryWrites=true&w=majority', {
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