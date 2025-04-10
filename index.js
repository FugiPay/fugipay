const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Middleware
app.use(express.json({ limit: '10mb' })); // Increase payload limit for file uploads
app.use(express.urlencoded({ extended: true }));

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
      console.warn(`CORS blocked request from origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
  optionsSuccessStatus: 204, // Better handling for preflight requests
};
app.use(cors(corsOptions));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per IP
  message: { error: 'Too many requests, please try again later.' },
});
app.use(limiter);

// Health Check Endpoint
app.get('/health', async (req, res) => {
  try {
    await mongoose.connection.db.admin().ping(); // Check MongoDB connection
    res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
  } catch (error) {
    console.error('Health check failed:', error.message);
    res.status(503).json({ status: 'DOWN', error: 'Database unavailable' });
  }
});

// Routes
app.use('/api', require('./routes/api'));
// Uncomment and use when businessRoutes is implemented
// app.use('/api/business', require('./routes/business'));

// Global Error Handler
app.use((err, req, res, next) => {
  console.error(`Unhandled error: ${err.stack}`);
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

// MongoDB Connection
const mongoUri = process.env.MONGODB_URI;
if (!mongoUri) {
  console.error('MONGODB_URI is not defined in environment variables');
  process.exit(1);
}

const connectToMongoDB = async () => {
  try {
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000, // Timeout for initial connection
      heartbeatFrequencyMS: 10000, // Keep connection alive
    });
    console.log('MongoDB connected successfully');
  } catch (err) {
    console.error('MongoDB connection failed:', err.message);
    process.exit(1);
  }
};

// Graceful Shutdown
const server = app.listen(process.env.PORT || 3002, async () => {
  await connectToMongoDB(); // Connect to MongoDB before listening
  console.log(`Server running on port ${process.env.PORT || 3002}`);
});

// Handle Shutdown Signals
const shutdown = async () => {
  console.log('Shutting down server...');
  server.close(() => {
    mongoose.connection.close(false, () => {
      console.log('MongoDB connection closed');
      process.exit(0);
    });
  });
};

process.on('SIGINT', shutdown); // Ctrl+C
process.on('SIGTERM', shutdown); // Termination signal

// Log Startup
console.log('Server starting...');