const mongoose = require('mongoose');
const QRPin = require('./models/QRPin');

async function checkQRPins() {
  await mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
  console.log('Connected to MongoDB');
  const qrPins = await QRPin.find({});
  console.log(`Found ${qrPins.length} QRPin entries:`);
  qrPins.forEach(q => {
    console.log(`Username: ${q.username}, QR ID: ${q.qrId}, PIN: ${q.pin}, Created: ${q.createdAt}`);
  });
  await mongoose.connection.close();
}

checkQRPins().catch(console.error);