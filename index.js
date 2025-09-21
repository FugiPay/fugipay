const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const compression = require('compression');
const morgan = require('morgan');
require('dotenv').config();

const app = express(); // Initialize app first

// Logging
app.use(morgan('dev'));

// Enable response compression
app.use(compression());

// Apply JSON parser only for non-multipart routes
app.use((req, res, next) => {
  if (req.headers['content-type']?.startsWith('multipart/form-data')) {
    return next();
  }
  express.json()(req, res, next);
});

// CORS Configuration
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:3002',
  'http://localhost:5173',
  'http://localhost:19006',
  'https://nzubo.net',
  'https://nzubo-admin.web.app',
  'https://kayah.net',
  'https://khah-334000.web.app',
  'https://api.ipify.org',
  'https://zangena-e33a7e55637a.herokuapp.com',
  'https://fugipay-4727b9eec37a.herokuapp.com',
  'https://fugipay.onrender.com',
];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin) || origin.endsWith('.exp.direct')) {
      callback(null, true);
    } else {
      console.log(`[CORS] Blocked origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
};
app.use(cors(corsOptions));

// Import route files
const userRoutes = require('./routes/userRoutes');
const businessRoutes = require('./routes/businessRoutes');
const adminRoutes = require('./routes/adminRoutes');

// Routes
app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

app.get('/wake', (req, res) => {
  console.log('[WAKE] Server pinged');
  res.status(200).send('Awake');
});

app.use('/api/users', userRoutes); // User-related endpoints
app.use('/api/business', businessRoutes); // Business-related endpoints
app.use('/api/admin', adminRoutes); // Admin-related endpoints

// Global error handler (consolidated)
app.use((err, req, res, next) => {
  console.error('[Global Error]', {
    message: err.message,
    stack: err.stack,
    endpoint: req.originalUrl,
    method: req.method,
    headers: req.headers,
    body: req.body,
    file: req.file ? { originalname: req.file.originalname, mimetype: req.file.mimetype, size: req.file.size } : null,
  });
  res.status(err.status || 500).json({ error: err.message || 'Server error', details: err.message });
});

// MongoDB Connection
const mongoUri = process.env.MONGODB_URI;
if (!mongoUri) {
  console.error('[MongoDB] MONGODB_URI is not defined');
  process.exit(1);
}

mongoose.connect(mongoUri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  maxPoolSize: 10,
  minPoolSize: 2,
  serverSelectionTimeoutMS: 5000,
})
  .then(() => console.log('[MongoDB] Connected successfully'))
  .catch(err => {
    console.error('[MongoDB] Connection error:', err.message, err.stack);
    process.exit(1);
  });

// Start Server
const PORT = process.env.PORT || 3002;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[Server] Running on port ${PORT}`);
});
/* app.listen(PORT, () => {
  console.log(`[Server] Running on port ${PORT}`);
}); */

// Log Startup
console.log('[Server] Starting...');