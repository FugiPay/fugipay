const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());

// Define allowed origins for CORS
const allowedOrigins = [
  'http://localhost:3000',
  'https://nzubo.net',
  'https://nzubo-admin.web.app',
  'https://kayah.net',
  'https://khah-334000.web.app',
];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
};

app.use(cors(corsOptions));

// Health check endpoint
app.get('/health', (req, res) => {
  res.send('OK');
});

// Routes
app.use('/api', require('./routes/api'));

// MongoDB connection
const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/zangena';
mongoose.connect(mongoUri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1); // Exit if MongoDB fails to connect
  });

// Start Server
const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Log startup
console.log('Server starting...');