const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const QRPin = require('../models/QRPin');
const authenticateToken = require('../middleware/authenticateToken');

// Secret key for JWT (use environment variable in production)
const JWT_SECRET = process.env.JWT_SECRET || 'Zangena123$@2025';

// POST /api/register (to match your signup.tsx)
router.post('/register', async (req, res) => {
  const { username, password, phoneNumber, role } = req.body;

  if (!username || !password || !phoneNumber) {
    return res.status(400).json({ error: 'Username, password, and phone number are required' });
  }

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { phoneNumber }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Username or phone number already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username,
      password: hashedPassword,
      phoneNumber,
      role: role || 'user', // Default to 'user' if not provided
    });
    await user.save();

    const token = jwt.sign(
      { username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(201).json({
      token,
      username: user.username,
      role: user.role,
    });
  } catch (error) {
    console.error('Register Error:', error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});
router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    let isMatch;
    // Check if password is hashed (starts with $2a$ or similar)
    if (user.password.startsWith('$2')) {
      isMatch = await bcrypt.compare(password, user.password);
    } else {
      // Plaintext fallback for old users
      isMatch = password === user.password;
    }
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token, username: user.username, role: user.role });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});
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
    res.status(500).json({ error: 'Server error fetching user' });
  }
});

// POST /api/store-qr-pin
router.post('/store-qr-pin', authenticateToken, async (req, res) => {
  const { username, pin } = req.body;

  if (!username || !pin) {
    return res.status(400).json({ error: 'Username and PIN are required' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (req.user.username !== username) return res.status(403).json({ error: 'Unauthorized' });

    const qrId = require('crypto').randomBytes(16).toString('hex');
    const qrPin = new QRPin({ username, qrId, pin });
    await qrPin.save();

    user.transactions.push({ type: 'pending-pin', amount: 0, toFrom: 'Self', date: new Date() });
    await user.save();

    res.json({ qrId });
  } catch (error) {
    console.error('QR Pin Store Error:', error);
    res.status(500).json({ error: 'Server error storing QR pin' });
  }
});

// POST /api/payment-with-qr-pin
router.post('/payment-with-qr-pin', authenticateToken, async (req, res) => {
  const { fromUsername, toUsername, amount, qrId, pin } = req.body;

  if (!fromUsername || !toUsername || !amount || !qrId || !pin) {
    return res.status(400).json({ error: 'All fields are required' });
  }

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

    const paymentAmount = parseFloat(amount);
    if (isNaN(paymentAmount) || paymentAmount <= 0) {
      return res.status(400).json({ error: 'Amount must be a positive number' });
    }

    if (sender.balance < paymentAmount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    sender.balance -= paymentAmount;
    receiver.balance += paymentAmount;
    sender.transactions.push({ type: 'sent', amount: paymentAmount, toFrom: toUsername, date: new Date() });
    receiver.transactions.push({ type: 'received', amount: paymentAmount, toFrom: fromUsername, date: new Date() });

    await QRPin.deleteOne({ qrId });
    await sender.save();
    await receiver.save();

    res.json({ message: 'Payment successful' });
  } catch (error) {
    console.error('QR Payment Error:', error);
    res.status(500).json({ error: 'Server error during payment' });
  }
});

// POST /api/payment-with-search
router.post('/payment-with-search', authenticateToken, async (req, res) => {
  const { fromUsername, searchQuery, amount, pin } = req.body;

  if (!fromUsername || !searchQuery || !amount || !pin) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const sender = await User.findOne({ username: fromUsername });
    if (!sender) return res.status(404).json({ error: 'Sender not found' });
    if (sender.role === 'admin') return res.status(403).json({ error: 'Admins cannot send payments' });

    const receiver = await User.findOne({ $or: [{ username: searchQuery }, { phoneNumber: searchQuery }] });
    if (!receiver) return res.status(404).json({ error: 'Recipient not found' });

    const qrPin = await QRPin.findOne({ username: receiver.username, pin });
    if (!qrPin) return res.status(400).json({ error: 'Invalid PIN or no active QR code' });

    const paymentAmount = parseFloat(amount);
    if (isNaN(paymentAmount) || paymentAmount <= 0) {
      return res.status(400).json({ error: 'Amount must be a positive number' });
    }

    if (sender.balance < paymentAmount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    sender.balance -= paymentAmount;
    receiver.balance += paymentAmount;
    sender.transactions.push({ type: 'sent', amount: paymentAmount, toFrom: receiver.username, date: new Date() });
    receiver.transactions.push({ type: 'received', amount: paymentAmount, toFrom: fromUsername, date: new Date() });

    await QRPin.deleteOne({ _id: qrPin._id });
    await sender.save();
    await receiver.save();

    res.json({ message: 'Payment successful' });
  } catch (error) {
    console.error('Search Payment Error:', error);
    res.status(500).json({ error: 'Server error during payment' });
  }
});

// PUT /api/user/update
router.put('/user/update', authenticateToken, async (req, res) => {
  const { username, password } = req.body;

  if (!username && !password) {
    return res.status(400).json({ error: 'Username or password required to update' });
  }

  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (username) user.username = username;
    if (password) user.password = await bcrypt.hash(password, 10);
    await user.save();

    res.json({ message: 'User updated' });
  } catch (error) {
    console.error('User Update Error:', error);
    res.status(500).json({ error: 'Server error updating user' });
  }
});

// GET /api/users (Fetch all users with pagination and search, admin only)
router.get('/users', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized: Admins only' });
    }
    const { page = 1, limit = 10, search = '' } = req.query;
    const pageNum = parseInt(page, 10);
    const limitNum = parseInt(limit, 10);
    const skip = (pageNum - 1) * limitNum;

    const query = search
      ? {
          $or: [
            { username: { $regex: search, $options: 'i' } },
            { phoneNumber: { $regex: search, $options: 'i' } },
          ],
        }
      : {};

    const total = await User.countDocuments(query);
    const users = await User.find(query, { password: 0 })
      .skip(skip)
      .limit(limitNum);

    res.json({
      users,
      total,
      page: pageNum,
      limit: limitNum,
      totalPages: Math.ceil(total / limitNum),
    });
  } catch (error) {
    console.error('Fetch All Users Error:', error);
    res.status(500).json({ error: 'Server error fetching users' });
  }
});

// POST /api/credit (Admin credits a user)
router.post('/credit', authenticateToken, async (req, res) => {
  const { adminUsername, toUsername, amount } = req.body;
  if (req.user.role !== 'admin' || req.user.username !== adminUsername) {
    return res.status(403).json({ error: 'Unauthorized: Admins only' });
  }
  try {
    const user = await User.findOne({ username: toUsername });
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.balance += amount;
    user.transactions.push({ type: 'credited', amount, toFrom: adminUsername, date: new Date() });
    await user.save();
    res.json({ message: 'Credit successful' });
  } catch (error) {
    console.error('Credit Error:', error);
    res.status(500).json({ error: 'Server error during credit' });
  }
});

// POST /api/payment-with-pin (Admin payment with PIN)
router.post('/payment-with-pin', authenticateToken, async (req, res) => {
  const { fromUsername, toUsername, amount, pin } = req.body;
  if (req.user.username !== fromUsername || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const sender = await User.findOne({ username: fromUsername });
    const receiver = await User.findOne({ username: toUsername });
    if (!sender || !receiver) return res.status(404).json({ error: 'User not found' });
    const qrPin = await QRPin.findOne({ username: toUsername, pin });
    if (!qrPin) return res.status(400).json({ error: 'Invalid PIN' });
    if (sender.balance < amount) return res.status(400).json({ error: 'Insufficient balance' });
    sender.balance -= amount;
    receiver.balance += amount;
    sender.transactions.push({ type: 'sent', amount, toFrom: toUsername, date: new Date() });
    receiver.transactions.push({ type: 'received', amount, toFrom: fromUsername, date: new Date() });
    await QRPin.deleteOne({ _id: qrPin._id });
    await sender.save();
    await receiver.save();
    res.json({ message: 'Payment successful' });
  } catch (error) {
    console.error('Payment with PIN Error:', error);
    res.status(500).json({ error: 'Server error during payment' });
  }
});

// GET /api/transactions/:username (Fetch user transactions, admin only)
router.get('/transactions/:username', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized: Admins only' });
  }
  try {
    const user = await User.findOne({ username: req.params.username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user.transactions);
  } catch (error) {
    console.error('Transactions Fetch Error:', error);
    res.status(500).json({ error: 'Server error fetching transactions' });
  }
});

module.exports = router;