const mongoose = require('mongoose');
const AdminLedger = require('./models/AdminLedger');

async function checkAdminLedger() {
  await mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
  console.log('Connected to MongoDB');
  const ledgers = await AdminLedger.find({});
  console.log(`Found ${ledgers.length} AdminLedger entries:`);
  ledgers.forEach(l => {
    console.log(`Total Balance: ${l.totalBalance}, Last Updated: ${l.lastUpdated}`);
  });
  await mongoose.connection.close();
}

checkAdminLedger().catch(console.error);