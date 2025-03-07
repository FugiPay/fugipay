const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const User = require('./models/User'); // Adjust path
const QRPin = require('./models/QRPin'); // Adjust path
const authenticateToken = require('./middleware/authenticateToken'); // Adjust path

// GET /api/user/:username
router.get('/user/:username', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (req.user.username !== user.username && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    res.json(user);
  } catch (error) {
    console.error('User Fetch Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/store-qr-pin
router.post('/store-qr-pin', authenticateToken, async (req, res) => {
  const { username, pin } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (req.user.username !== username) return res.status(403).json({ error: 'Unauthorized' });

    const qrId = require('crypto').randomBytes(16).toString('hex');
    const qrPin = new QRPin({ username, qrId, pin });
    await qrPin.save();

    // Add pending-pin transaction
    user.transactions.push({ type: 'pending-pin', amount: 0, toFrom: 'Self', date: new Date() });
    await user.save();

    res.json({ qrId });
  } catch (error) {
    console.error('QR Pin Store Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/payment-with-qr-pin
router.post('/payment-with-qr-pin', authenticateToken, async (req, res) => {
  const { fromUsername, toUsername, amount, qrId, pin } = req.body;

  try {
    const sender = await User.findOne({ username: fromUsername });
    if (!sender) return res.status(404).json({ error: 'Sender not found' });
    if (sender.role === 'admin') return res.status(403).json({ error: 'Admins cannot send payments' });

    const receiver = await User.findOne({ username: toUsername });
    if (!receiver) return res.status(404).json({ error: 'Recipient not found' });

    const qrPin = await QRPin.findOne({ qrId, pin });
    if (!qrPin || qrPin.username !== toUsername) {
      return res.status(400).json({ error: 'Invalid QR code or PIN' });
    }

    if (sender.balance < amount) return res.status(400).json({ error: 'Insufficient balance' });

    sender.balance -= amount;
    receiver.balance += amount;
    sender.transactions.push({ type: 'sent', amount, toFrom: toUsername, date: new Date() });
    receiver.transactions.push({ type: 'received', amount, toFrom: fromUsername, date: new Date() });

    await QRPin.deleteOne({ qrId });
    await sender.save();
    await receiver.save();

    res.json({ message: 'Payment successful' });
  } catch (error) {
    console.error('QR Payment Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST /api/payment-with-search
router.post('/payment-with-search', authenticateToken, async (req, res) => {
  const { fromUsername, searchQuery, amount, pin } = req.body;

  try {
    const sender = await User.findOne({ username: fromUsername });
    if (!sender) return res.status(404).json({ error: 'Sender not found' });
    if (sender.role === 'admin') return res.status(403).json({ error: 'Admins cannot send payments' });

    const receiver = await User.findOne({ $or: [{ username: searchQuery }, { phoneNumber: searchQuery }] });
    if (!receiver) return res.status(404).json({ error: 'Recipient not found' });

    const qrPin = await QRPin.findOne({ username: receiver.username, pin });
    if (!qrPin) return res.status(400).json({ error: 'Invalid PIN or no active QR code' });

    if (sender.balance < amount) return res.status(400).json({ error: 'Insufficient balance' });

    sender.balance -= amount;
    receiver.balance += amount;
    sender.transactions.push({ type: 'sent', amount, toFrom: receiver.username, date: new Date() });
    receiver.transactions.push({ type: 'received', amount, toFrom: fromUsername, date: new Date() });

    await QRPin.deleteOne({ _id: qrPin._id });
    await sender.save();
    await receiver.save();

    res.json({ message: 'Payment successful' });
  } catch (error) {
    console.error('Search Payment Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// PUT /api/user/update
router.put('/user/update', authenticateToken, async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (username) user.username = username;
    if (password) user.password = await bcrypt.hash(password, 10);
    await user.save();

    res.json({ message: 'User updated' });
  } catch (error) {
    console.error('User Update Error:', error);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;