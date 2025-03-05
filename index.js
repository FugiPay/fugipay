const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error(err));

// Routes
app.use('/api', require('./routes/api'));

// Define allowed origins for CORS
const allowedOrigins = [
  'http://localhost:3000',   // Local development
  'https://nzubo.net',        // Production
  'https://nzubo-admin.web.app', // Admin Production
  'https://kayah.net',        // Production
  'https://khah-334000.web.app'
];

// Configure CORS options
const corsOptions = {
  origin: (origin, callback) => {
    // Allow requests with no origin (like mobile apps or curl requests) or from allowed origins
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],    // Specify allowed HTTP methods
  credentials: true            // Allow credentials (cookies, authorization headers)
};

// Apply CORS middleware with the configured options
app.use(cors(corsOptions));
// app.use(cors({ origin: 'https://khah-334000.web.app' }));

const PORT = process.env.PORT || 3002;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));