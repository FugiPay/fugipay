const express = require('express');
const connectDB = require('./db');
const apiRoutes = require('./routes/api');

const app = express();

// Middleware
app.use(express.json());

// Connect to MongoDB
connectDB();

// Routes
app.use('/api', apiRoutes);

// Basic route for testing
app.get('/api/ip', (req, res) => {
  res.json({ ip: req.ip });
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.stack);
  res.status(500).json({ error: 'Something went wrong' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});