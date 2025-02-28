const express = require('express');
const router = express.Router();
const User = require('../models/User');

// Generate a timed PIN for receiving a payment
router.post('/generate-pin', async (req, res) => {
  const { username } = req.body;
  const pin = Math.floor(1000 + Math.random() * 9000).toString(); // 4-digit PIN
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes expiry
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.transactions.push({ type: 'pending-pin', amount: 0, toFrom: `PIN:${pin}`, date: new Date(expiresAt) });
    await user.save();
    res.json({ pin, expiresAt });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Make a payment with PIN verification
router.post('/payment-with-pin', async (req, res) => {
  const { fromUsername, toUsername, amount, pin } = req.body;
  try {
    const sender = await User.findOne({ username: fromUsername });
    const receiver = await User.findOne({ username: toUsername });
    if (!sender || !receiver) return res.status(404).json({ error: 'User not found' });

    const pendingPin = receiver.transactions.find(tx => tx.toFrom === `PIN:${pin}` && tx.type === 'pending-pin');
    if (!pendingPin || new Date(pendingPin.date) < new Date()) {
      return res.status(400).json({ error: 'Invalid or expired PIN' });
    }

    if (sender.balance < amount) return res.status(400).json({ error: 'Insufficient funds' });

    sender.balance -= amount;
    receiver.balance += amount;

    sender.transactions.push({ type: 'sent', amount, toFrom: toUsername });
    receiver.transactions = receiver.transactions.filter(tx => tx !== pendingPin); // Remove pending PIN
    receiver.transactions.push({ type: 'received', amount, toFrom: fromUsername });

    await sender.save();
    await receiver.save();
    res.json({ message: 'Payment successful' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Middleware to check if user is admin (use query param for GET, body for POST)
const isAdmin = async (req, res, next) => {
  const username = req.query.adminUsername || req.body.adminUsername; // Check query first, then body
  if (!username) return res.status(400).json({ error: 'Admin username required' });
  const user = await User.findOne({ username });
  if (!user || user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  req.adminUsername = username; // Pass it along
  next();
};

// Register a user
router.post('/register', async (req, res) => {
  const { username, password, phoneNumber, role } = req.body;
  try {
    const user = new User({ username, password, phoneNumber, role: role || 'user' });
    await user.save();
    res.status(201).json({ message: 'User registered', username: user.username });
  } catch (error) {
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
    res.json({ message: 'Login successful', username: user.username, role: user.role });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get user balance and transactions
router.get('/user/:username', async (req, res) => {
  const { username } = req.params;
  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ balance: user.balance, transactions: user.transactions, phoneNumber: user.phoneNumber, role: user.role });
});

// Make a payment (users only)
router.post('/payment', async (req, res) => {
  const { fromUsername, toUsername, amount } = req.body;
  try {
    const sender = await User.findOne({ username: fromUsername });
    const receiver = await User.findOne({ username: toUsername });
    if (!sender || !receiver) return res.status(404).json({ error: 'User not found' });
    if (sender.role === 'admin') return res.status(403).json({ error: 'Admins cannot send payments' });
    if (sender.balance < amount) return res.status(400).json({ error: 'Insufficient funds' });

    sender.balance -= amount;
    receiver.balance += amount;

    sender.transactions.push({ type: 'sent', amount, toFrom: toUsername });
    receiver.transactions.push({ type: 'received', amount, toFrom: fromUsername });

    await sender.save();
    await receiver.save();
    res.json({ message: 'Payment successful' });
  } catch (error) {
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
    res.status(500).json({ error: error.message });
  }
});

// Admin: Get all users
router.get('/users', isAdmin, async (req, res) => {
  const users = await User.find({}, 'username phoneNumber role balance');
  res.json(users);
});

// Admin: Get all transactions for a user
router.get('/transactions/:username', isAdmin, async (req, res) => {
  const { username } = req.params;
  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user.transactions);
});

module.exports = router;