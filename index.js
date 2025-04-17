const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());

// CORS Configuration
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:19006', // Expo dev
  'https://nzubo.net',
  'https://nzubo-admin.web.app',
  'https://kayah.net',
  'https://khah-334000.web.app',
  'https://api.ipify.org',
];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin) || origin.endsWith('.exp.direct')) {
      callback(null, true);
    } else {
      console.log(`Blocked origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
};
app.use(cors(corsOptions));

// Health Check
app.get('/health', async (req, res) => {
  try {
    await mongoose.connection.db.admin().ping();
    res.status(200).json({ status: 'ok', database: 'connected' });
  } catch (err) {
    console.error(`Health check failed: ${err.message} (code: ${err.code || 'unknown'})`);
    res.status(500).json({ status: 'error', database: 'unavailable', error: `Database ping failed: ${err.message}` });
  }
});

// Wake Endpoint
app.get('/wake', (req, res) => {
  console.log('[WAKE] Server pinged');
  res.send('Awake');
});

// Routes
app.use('/api', require('./routes/api'));

// MongoDB Connection
const mongoUri = process.env.MONGODB_URI;
if (!mongoUri) {
  console.error('MONGODB_URI is not defined');
  process.exit(1);
}
mongoose.connect(mongoUri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}) 
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// Start Server
const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Log Startup
console.log('Server starting...');