const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const Business = require('../models/Business');
require('dotenv').config();

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    req.user = user;
    next();
  } catch (error) {
    console.error('[Auth] Error:', error.message);
    res.status(403).json({ error: 'Invalid or expired token' });
  }
};

router.post('/register', async (req, res) => {
  try {
    const { businessId, pin, username, email } = req.body;
    if (!businessId || !pin || !username || !email) {
      return res.status(400).json({ error: 'All fields required' });
    }
    if (!/^\d{10}$/.test(businessId)) {
      return res.status(400).json({ error: 'Business ID must be a 10-digit TPIN' });
    }
    if (!/^\d{4}$/.test(pin)) {
      return res.status(400).json({ error: 'PIN must be a 4-digit number' });
    }
    if (!/^[a-zA-Z0-9]{3,}$/.test(username)) {
      return res.status(400).json({ error: 'Username must be 3+ alphanumeric characters' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email address' });
    }
    const existing = await Business.findOne({ $or: [{ businessId }, { username }, { email }] });
    if (existing) {
      return res.status(409).json({ error: 'Business ID, username, or email already taken' });
    }
    const hashedPin = await bcrypt.hash(pin, 10);
    const business = new Business({
      businessId,
      pin: hashedPin,
      username,
      balance: 0,
      email,
    });
    await business.save();
    res.status(201).json({ message: 'Business registered', businessId });
  } catch (error) {
    console.error('[Register] Error:', error.message);
    res.status(500).json({ error: 'Registration failed' });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { businessId, pin } = req.body;
    if (!businessId || !pin) {
      return res.status(400).json({ error: 'Business ID and PIN required' });
    }
    const business = await Business.findOne({ businessId }).lean();
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    if (!(await bcrypt.compare(pin, business.pin))) {
      return res.status(401).json({ error: 'Invalid PIN' });
    }
    const token = jwt.sign({ businessId: business.businessId }, process.env.JWT_SECRET, { expiresIn: '12h' });
    const businessData = {
      username: business.username,
      balance: parseFloat(business.balance.toString()),
      email: business.email,
    };
    res.json({ message: 'Login successful', token, businessId, businessData });
  } catch (error) {
    console.error('[Login] Error:', error.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

router.get('/:businessId', authenticateToken, async (req, res) => {
  try {
    if (req.user.businessId !== req.params.businessId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const business = await Business.findOne({ businessId: req.params.businessId }).lean();
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    res.json({
      businessId: business.businessId,
      username: business.username,
      balance: parseFloat(business.balance.toString()),
      email: business.email,
    });
  } catch (error) {
    console.error('[BusinessFetch] Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch business' });
  }
});

module.exports = router;