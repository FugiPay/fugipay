const express = require('express');
const router = express.Router();
const User = require('../models/User');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const axios = require('axios');
require('dotenv').config();

const secretKey = process.env.LOGIN_KEY || '1243$';
const MONEYUNIFY_CONFIG = {
  muid: process.env.MONEYUNIFY_MUID || 'YOUR_MONEYUNIFY_MUID', // From moneyunify.com
  baseUrl: 'https://api.moneyunify.com/v1', // Adjust if MoneyUnify provides a different URL
};

// Middleware to verify token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  console.log('Auth Header:', authHeader);
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
  createdAt: { type: Date, default: Date.now, expires: 15 * 60 },
});
const QRPin = mongoose.model('QRPin', qrPinSchema);

// Store QR code PIN
router.post('/store-qr-pin', authenticateToken, async (req, res) => {
  const { username, pin } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!pin || pin.length !== 4 || !/^\d{4}$/.test(pin)) {
      return res.status(400).json({ error: 'PIN must be a 4-digit number' });
    }
    const qrId = new mongoose.Types.ObjectId().toString();
    const qrPin = new QRPin({ username, pin, qrId });
    await qrPin.save();
    res.json({ qrId, message: 'PIN stored successfully' });
  } catch (error) {
    console.error('Store QR Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Payment with QR PIN validation
router.post('/payment-with-qr-pin', authenticateToken, async (req, res) => {
  const { fromUsername, toUsername, amount, qrId, pin } = req.body;
  try {
    const sender = await User.findOne({ username: fromUsername });
    const receiver = await User.findOne({ username: toUsername });
    if (!sender || !receiver) return res.status(404).json({ error: 'User not found' });
    if (sender.role === 'admin') return res.status(403).json({ error: 'Admins cannot send payments' });
    if (sender.balance < amount) return res.status(400).json({ error: 'Insufficient internal funds' });

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

// Send Money via MoneyUnify
router.post('/moneyunify/send', authenticateToken, async (req, res) => {
  const { username, recipientPhone, amount, network } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.role === 'admin') return res.status(403).json({ error: 'Admins cannot send payments' });
    if (!recipientPhone || !amount || amount <= 0) {
      return res.status(400).json({ error: 'Invalid recipient phone or amount' });
    }
    if ((user.moneyunifyBalance || 0) < amount) {
      return res.status(400).json({ 
        error: 'Insufficient MoneyUnify balance in app. Top up from your mobile money account if needed.' 
      });
    }
    if (!['MTN', 'AIRTEL', 'ZAMTEL'].includes(network)) {
      return res.status(400).json({ error: 'Invalid network. Use MTN, AIRTEL, or ZAMTEL' });
    }

    const response = await axios.post(
      `${MONEYUNIFY_CONFIG.baseUrl}/disburse`,
      {
        muid: MONEYUNIFY_CONFIG.muid,
        phone: `260${recipientPhone.replace(/^0/, '')}`, // Zambia format: 260XXXXXXXXX
        amount,
        network,
      },
      { headers: { 'Content-Type': 'application/json' } }
    );

    if (!response.data.success) {
      throw new Error(response.data.error || 'MoneyUnify disbursement failed');
    }

    user.moneyunifyBalance -= amount;
    user.transactions.push({ type: 'sent_moneyunify', amount, toFrom: recipientPhone });
    await user.save();

    res.json({ 
      message: 'Money sent via MoneyUnify (deducted from app balance; real funds moved from your mobile money account)', 
      transactionId: response.data.transactionId 
    });
  } catch (error) {
    console.error('MoneyUnify Send Error:', error.response?.data || error.message);
    res.status(500).json({ error: error.response?.data?.error || 'Failed to send money via MoneyUnify' });
  }
});

// Receive Money via MoneyUnify (Top-up app balance from real mobile money)
router.post('/moneyunify/receive', authenticateToken, async (req, res) => {
  const { username, payerPhone, amount, network } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!payerPhone || !amount || amount <= 0) {
      return res.status(400).json({ error: 'Invalid payer phone or amount' });
    }
    if (!['MTN', 'AIRTEL', 'ZAMTEL'].includes(network)) {
      return res.status(400).json({ error: 'Invalid network. Use MTN, AIRTEL, or ZAMTEL' });
    }

    const response = await axios.post(
      `${MONEYUNIFY_CONFIG.baseUrl}/collect`,
      {
        muid: MONEYUNIFY_CONFIG.muid,
        phone: `260${payerPhone.replace(/^0/, '')}`,
        amount,
        network,
      },
      { headers: { 'Content-Type': 'application/json' } }
    );

    if (!response.data.success) {
      throw new Error(response.data.error || 'MoneyUnify collection failed');
    }

    user.moneyunifyBalance = (user.moneyunifyBalance || 0) + amount;
    user.transactions.push({ type: 'received_moneyunify', amount, toFrom: payerPhone });
    await user.save();

    res.json({ 
      message: 'Money received via MoneyUnify (added to app balance; real funds moved from payer’s mobile money account)', 
      transactionId: response.data.transactionId 
    });
  } catch (error) {
    console.error('MoneyUnify Receive Error:', error.response?.data || error.message);
    res.status(500).json({ error: error.response?.data?.error || 'Failed to receive money via MoneyUnify' });
  }
});

// Register a user
router.post('/register', async (req, res) => {
  const { username, password, phoneNumber, role } = req.body;
  try {
    const user = new User({ 
      username, 
      password, 
      phoneNumber, 
      role: role || 'user', 
      airtelBalance: 0, 
      moneyunifyBalance: 0,
      mtnBalance: 0
    });
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
    const mainBalance = user.balance + (user.airtelBalance || 0) + (user.moneyunifyBalance || 0) + (user.mtnBalance || 0);
    res.json({
      mainBalance,
      subBalances: { 
        airtel: user.airtelBalance || 0, 
        moneyunify: user.moneyunifyBalance || 0,
        mtn: user.mtnBalance || 0
      },
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

// Admin: Give credit to a user (manual sync option)
router.post('/credit', isAdmin, async (req, res) => {
  const { toUsername, amount, targetBalance } = req.body;
  const adminUsername = req.adminUsername;
  try {
    const user = await User.findOne({ username: toUsername });
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (targetBalance === 'moneyunify') {
      user.moneyunifyBalance += amount;
    } else if (targetBalance === 'airtel') {
      user.airtelBalance += amount;
    } else if (targetBalance === 'mtn') {
      user.mtnBalance += amount;
    } else {
      user.balance += amount; // Default to internal balance
    }
    user.transactions.push({ type: 'credited', amount, toFrom: adminUsername });
    await user.save();
    res.json({ message: `Credited $${amount} to ${toUsername} (${targetBalance || 'internal'} balance)` });
  } catch (error) {
    console.error('Credit Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Admin: Get all users
router.get('/users', isAdmin, async (req, res) => {
  try {
    const users = await User.find({}, 'username phoneNumber role balance airtelBalance moneyunifyBalance mtnBalance');
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

// Get QR PIN for validation
router.get('/qr-pins/:qrId', authenticateToken, async (req, res) => {
  try {
    const qrPin = await QRPin.findOne({ qrId: req.params.qrId });
    if (!qrPin) return res.status(404).json({ error: 'QR code not found or expired' });
    res.json({ pin: qrPin.pin });
  } catch (error) {
    console.error('QR PIN Fetch Error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Fetch real MoneyUnify balance
router.get('/moneyunify/balance', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user || !user.phoneNumber) {
      return res.status(400).json({ error: 'Phone number not registered' });
    }

    const phone = user.phoneNumber;
    let network;
    if (phone.startsWith('097') || phone.startsWith('077')) network = 'AIRTEL';
    else if (phone.startsWith('096') || phone.startsWith('076')) network = 'MTN';
    else if (phone.startsWith('095') || phone.startsWith('075')) network = 'ZAMTEL';
    else return res.status(400).json({ error: 'Unknown network prefix' });

    // Mock or real MoneyUnify balance request
    const response = await axios.get('https://api.moneyunify.com/v1/balance', {
      params: { phone, network },
      headers: { Authorization: `Bearer ${process.env.MONEYUNIFY_MUID}` },
    });

    const realBalance = response.data.balance || 0;
    user.moneyunifyBalance = realBalance;
    await user.save();

    res.json({ balance: realBalance, network });
  } catch (error) {
    console.error('Balance Fetch Error:', error);
    res.status(500).json({ error: 'Failed to fetch balance' });
  }
});

module.exports = router;