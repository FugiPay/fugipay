const express = require('express');
const router = express.Router();
const User = require('../models/User');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const secretKey = process.env.LOGIN_KEY || '1243$'; // Matches your setup

const QRPin = require('./models/QRPin'); // Adjust path to your QRPin model
const authenticateToken = require('./middleware/authenticateToken'); // Adjust path

// Check QR PIN status
router.get('/check-qr-pin/:qrId', authenticateToken, async (req, res) => {
  const { qrId } = req.params;
  try {
    const qrPin = await QRPin.findOne({ qrId });
    if (!qrPin) {
      return res.status(200).json({ used: true, expired: false }); // QR code used or never existed
    }
    const now = Date.now();
    const expired = now > qrPin.createdAt.getTime() + 15 * 60 * 1000; // 15 minutes
    res.status(200).json({ used: false, expired });
  } catch (error) {
    console.error('QR Check Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Middleware to verify token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  console.log('Auth Header:', authHeader); // Debug
  if (!token) {
    console.log('No token provided');
    return res.status(401).json({ error: 'Access denied: No token provided' });
  }

  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      console.log('Token Verification Error:', err.message);
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Middleware to check if user is admin
const isAdmin = async (req, res, next) => {
  const username = req.query.adminUsername || req.body.adminUsername;
  if (!username) return res.status(400).json({ error: 'Admin username required' });
  try {
    const user = await User.findOne({ username });
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    req.adminUsername = username;
    next();
  } catch (error) {
    console.error('Admin Check Error:', error);
    return res.status(500).json({ error: 'Server error during admin check' });
  }
};

// QR code PIN storage schema
const qrPinSchema = new mongoose.Schema({
  username: { type: String, required: true },
  pin: { type: String, required: true },
  qrId: { type: String, required: true, unique: true },
  createdAt: { type: Date, default: Date.now, expires: 15 * 60 } // TTL: 15 minutes
});
const QRPin = mongoose.model('QRPin', qrPinSchema);

// Store QR code PIN
router.post('/store-qr-pin', async (req, res) => {
  const { username, pin } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!pin || pin.length !== 4 || !/^\d{4}$/.test(pin)) {
      return res.status(400).json({ error: 'PIN must be a 4-digit number' });
    }
    const qrId = new mongoose.Types.ObjectId().toString(); // Fixed with 'new'
    const qrPin = new QRPin({ username, pin, qrId });
    await qrPin.save();
    res.json({ qrId, message: 'PIN stored successfully' });
  } catch (error) {
    console.error('Store QR Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Payment with QR PIN validation
router.post('/payment-with-qr-pin', async (req, res) => {
  const { fromUsername, toUsername, amount, qrId, pin } = req.body;
  try {
    const sender = await User.findOne({ username: fromUsername });
    const receiver = await User.findOne({ username: toUsername });
    if (!sender || !receiver) return res.status(404).json({ error: 'User not found' });
    if (sender.role === 'admin') return res.status(403).json({ error: 'Admins cannot send payments' });
    if (sender.balance < amount) return res.status(400).json({ error: 'Insufficient funds' });

    const qrPin = await QRPin.findOne({ qrId, username: toUsername });
    if (!qrPin) return res.status(400).json({ error: 'QR code invalid or expired' });
    if (qrPin.pin !== pin) return res.status(400).json({ error: 'Invalid PIN' });

    sender.balance -= amount;
    receiver.balance += amount;

    sender.transactions.push({ type: 'sent', amount, toFrom: toUsername });
    receiver.transactions.push({ type: 'received', amount, toFrom: fromUsername });

    await sender.save();
    await receiver.save();
    await QRPin.deleteOne({ qrId });

    res.json({ message: 'Payment successful' });
  } catch (error) {
    console.error('Payment Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Register a user
router.post('/register', async (req, res) => {
  const { username, password, phoneNumber, role } = req.body;
  try {
    const user = new User({ username, password, phoneNumber, role: role || 'user' });
    await user.save();
    res.status(201).json({ message: 'User registered', username: user.username });
  } catch (error) {
    console.error('Register Error:', error);
    res.status(400).json({ error: error.message });
  }
});

// Login a user
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user || user.password !== password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ username: user.username, role: user.role }, secretKey, { expiresIn: '1h' });
    res.json({ message: 'Login successful', username: user.username, role: user.role, token });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get user balance and transactions (protected)
router.get('/user/:username', authenticateToken, async (req, res) => {
  const { username } = req.params;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      balance: user.balance,
      transactions: user.transactions,
      phoneNumber: user.phoneNumber,
      role: user.role,
      username: user.username,
    });
  } catch (error) {
    console.error('User Fetch Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Admin: Give credit to a user
router.post('/credit', isAdmin, async (req, res) => {
  const { toUsername, amount } = req.body;
  const adminUsername = req.adminUsername;
  try {
    const user = await User.findOne({ username: toUsername });
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.balance += amount;
    user.transactions.push({ type: 'credited', amount, toFrom: adminUsername });
    await user.save();
    res.json({ message: `Credited $${amount} to ${toUsername}` });
  } catch (error) {
    console.error('Credit Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Admin: Get all users
router.get('/users', isAdmin, async (req, res) => {
  try {
    const users = await User.find({}, 'username phoneNumber role balance');
    res.json(users);
  } catch (error) {
    console.error('Users Fetch Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Admin: Get all transactions for a user
router.get('/transactions/:username', isAdmin, async (req, res) => {
  const { username } = req.params;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user.transactions);
  } catch (error) {
    console.error('Transactions Fetch Error:', error);
    res.status(500).json({ error: error.message });
  }
});

router.post('/payment-with-search', authenticateToken, async (req, res) => {
  const { searchQuery, amount, pin } = req.body;
  const sender = await User.findOne({ username: req.user.username });
  const receiver = await User.findOne({ $or: [{ username: searchQuery }, { phoneNumber: searchQuery }] });
  if (!receiver) return res.status(404).json({ error: 'Recipient not found' });
  // Add PIN verification logic if needed
  if (sender.mainBalance < amount) return res.status(400).json({ error: 'Insufficient balance' });
  sender.mainBalance -= amount;
  receiver.mainBalance += amount;
  sender.transactions.push({ type: 'sent', amount, toFrom: receiver.username, date: new Date() });
  receiver.transactions.push({ type: 'received', amount, toFrom: sender.username, date: new Date() });
  await sender.save();
  await receiver.save();
  res.json({ message: 'Payment successful' });
});

module.exports = router;