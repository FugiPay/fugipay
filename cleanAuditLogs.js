require('dotenv').config();
const mongoose = require('mongoose');
const Business = require('./models/Business').Business;

async function cleanAuditLogs() {
  try {
    console.log('Connecting to MongoDB...');
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://KHAH-YAH:01H0EwNnhMYW8zpO@cluster0.1ap41.mongodb.net/Zangena?retryWrites=true&w=majority');
    console.log('Connected to MongoDB');

    const result = await Business.updateMany(
      { 'auditLogs.action': 'view_dashboard' },
      { $pull: { auditLogs: { action: 'view_dashboard' } } }
    );
    console.log(`Removed ${result.modifiedCount} businesses' view_dashboard audit logs`);

    console.log('Cleaning complete');
  } catch (error) {
    console.error('Cleaning error:', error.message);
    console.error('Error stack:', error.stack);
  } finally {
    console.log('Disconnecting from MongoDB...');
    await mongoose.disconnect();
    console.log('Disconnected');
  }
}

cleanAuditLogs();