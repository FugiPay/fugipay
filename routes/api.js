const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const User = require('../models/User'); // Adjust path
const authenticateToken = require('../middleware/authenticateToken');

router.get('/user/:username', authenticateToken, async (req, res) => {
  const start = Date.now();
  console.log(`[GET] /api/user/${req.params.username} - Starting fetch for ${req.params.username}`);
  
  try {
    // Check MongoDB connection
    if (mongoose.connection.readyState !== 1) {
      console.error(`[GET] /api/user/${req.params.username} - MongoDB not connected: ${mongoose.connection.readyState}`);
      return res.status(503).json({ error: 'Database unavailable' });
    }

    const user = await User.findOne({ username: req.params.username }, { password: 0, __v: 0 });
    if (!user) {
      console.log(`[GET] /api/user/${req.params.username} - User not found`);
      return res.status(404).json({ error: 'User not found' });
    }

    console.log(`[GET] /api/user/${req.params.username} - User query: ${Date.now() - start}ms`);
    res.json(user);
  } catch (error) {
    console.error(`[GET] /api/user/${req.params.username} - Error:`, {
      message: error.message,
      stack: error.stack,
    });
    res.status(500).json({ error: 'Server error fetching user', details: error.message });
  }
});

module.exports = router;