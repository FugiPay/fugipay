// migration.js
const mongoose = require('mongoose');
const { Business } = require('./models/Business');

async function migrateAuditLogs() {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('[Migration] Connected to MongoDB');

    const result = await Business.updateMany(
      { "auditLogs.action": "dashboard_view" },
      { $set: { "auditLogs.$[elem].action": "view_dashboard" } },
      { arrayFilters: [{ "elem.action": "dashboard_view" }] }
    );

    console.log('[Migration] Updated audit logs:', result);
  } catch (error) {
    console.error('[Migration] Error:', error.message);
  } finally {
    await mongoose.disconnect();
    console.log('[Migration] Disconnected from MongoDB');
  }
}

migrateAuditLogs();