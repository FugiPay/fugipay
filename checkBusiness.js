// checkBusiness.js
const mongoose = require('mongoose');
const Business = require('./models/Business');

async function checkBusinesses() {
  await mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
  console.log('Connected to MongoDB');
  const businesses = await Business.find({});
  console.log(`Found ${businesses.length} businesses:`);
  businesses.forEach(b => {
    console.log(`Business: ${b.businessId}, Transactions: ${b.transactions.length}`);
    b.transactions.forEach(t => console.log(`  _id: ${t._id}, Type: ${t.type}`));
  });
  await mongoose.connection.close();
}

checkBusinesses().catch(console.error);