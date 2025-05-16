const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const compression = require('compression');
require('dotenv').config();

// Import route files
const userRoutes = require('./routes/userRoutes');
const businessRoutes = require('./routes/businessRoutes');
const adminRoutes = require('./routes/adminRoutes');

const app = express();
app.use(compression()); // Enable response compression
app.use(express.json());

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err.message, err.stack);
  res.status(err.status || 500).json({ error: err.message || 'Server error' });
});

// CORS Configuration
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:3002',
  'http://localhost:19006',
  'https://nzubo.net',
  'https://nzubo-admin.web.app',
  'https://kayah.net',
  'https://khah-334000.web.app',
  'https://api.ipify.org',
  'https://zangena-e33a7e55637a.herokuapp.com',
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
app.get('/health', (req, res) => {
  res.send('OK');
});

// Wake Endpoint
app.get('/wake', (req, res) => {
  console.log('[WAKE] Server pinged');
  res.send('Awake');
});

// Routes
app.use('/api/users', userRoutes); // User-related endpoints
app.use('/api/business', businessRoutes); // Business-related endpoints
app.use('/api/admin', adminRoutes); // Admin-related endpoints

// MongoDB Connection
const mongoUri = process.env.MONGODB_URI;
if (!mongoUri) {
  console.error('MONGODB_URI is not defined');
  process.exit(1);
}
mongoose.connect(mongoUri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  maxPoolSize: 10, // Connection pool size
  minPoolSize: 2,
  serverSelectionTimeoutMS: 5000,
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