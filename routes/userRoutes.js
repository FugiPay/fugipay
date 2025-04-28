const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const AWS = require('aws-sdk');
const fs = require('fs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const User = require('../models/User');
const QRPin = require('../models/QRPin');
const AdminLedger = require('../models/AdminLedger');
const authenticateToken = require('../middleware/authenticateToken');
const axios = require('axios');

// Configure multer for temporary local storage
const upload = multer({ dest: 'uploads/' });

// Configure AWS S3
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION || 'us-east-1',
});
const S3_BUCKET = process.env.S3_BUCKET || 'zangena';

// Secret key for JWT
const JWT_SECRET = process.env.JWT_SECRET || 'Zangena123$@2025';

// Configure Nodemailer with Gmail
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Middleware to check admin role
const requireAdmin = async (req, res, next) => {
  try {
    const user = await User.findOne({ phoneNumber: req.user.phoneNumber });
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  } catch (error) {
    console.error('[ADMIN] Error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
};

// POST /api/register
router.post('/register', upload.single('idImage'), async (req, res) => {
  const { username, name, phoneNumber, email, password, pin } = req.body;
  const idImage = req.file;

  if (!username || !name || !phoneNumber || !email || !password || !idImage || !pin) {
    return res.status(400).json({ error: 'All fields, ID image, and PIN are required' });
  }

  if (!username.match(/^[a-zA-Z0-9_]{3,20}$/)) {
    return res.status(400).json({ error: 'Username must be 3-20 characters, alphanumeric with underscores only' });
  }

  if (!phoneNumber.match(/^\+260(9[5678]|7[34679])\d{7}$/)) {
    return res.status(400).json({ error: 'Invalid Zambian phone number (e.g., +260971234567)' });
  }

  if (!email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }

  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'PIN must be a 4-digit number' });
  }

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }, { phoneNumber }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Username, email, or phone number already exists' });
    }

    const fileStream = fs.createReadStream(idImage.path);
    const s3Key = `id-images/${username}-${Date.now()}-${idImage.originalname}`;
    const params = { Bucket: S3_BUCKET, Key: s3Key, Body: fileStream, ContentType: idImage.mimetype, ACL: 'private' };
    const s3Response = await s3.upload(params).promise();
    fs.unlinkSync(idImage.path);

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username: username.trim(),
      name: name.trim(),
      phoneNumber,
      email,
      password: hashedPassword,
      pin,
      idImageUrl: s3Response.Location,
      role: 'user',
      balance: 0,
      zambiaCoinBalance: 0,
      trustScore: 0,
      ratingCount: 0,
      transactions: [],
      kycStatus: 'pending',
      isActive: false,
    });
    await user.save();

    const token = jwt.sign({ phoneNumber: user.phoneNumber, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: '24h' });

    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(admin.pushToken, 'New User Registration', `User ${username} needs KYC approval.`, { userId: user._id });
    }

    res.status(201).json({ token, username: user.username, role: user.role, kycStatus: user.kycStatus });
  } catch (error) {
    console.error('[REGISTER] Error:', error.message);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// POST /api/login
router.post('/login', async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) {
    return res.status(400).json({ error: 'Username or phone number and password are required' });
  }

  try {
    const user = await User.findOne({ $or: [{ username: identifier }, { phoneNumber: identifier }] });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ phoneNumber: user.phoneNumber, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
    const isFirstLogin = !user.lastLogin;
    user.lastLogin = new Date();
    await user.save();

    res.status(200).json({
      token,
      username: user.username,
      phoneNumber: user.phoneNumber,
      role: user.role || 'user',
      kycStatus: user.kycStatus || 'pending',
      isFirstLogin,
    });
  } catch (error) {
    console.error('[LOGIN] Error:', error.message);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// POST /api/forgot-password
router.post('/forgot-password', async (req, res) => {
  const { identifier } = req.body;
  if (!identifier) {
    return res.status(400).json({ error: 'Username or phone number is required' });
  }

  try {
    const user = await User.findOne({ $or: [{ username: identifier }, { phoneNumber: identifier }] });
    if (!user) {
      return res.status(404).json({ error: 'No account found with that identifier' });
    }
    if (!user.email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
      return res.status(500).json({ error: 'Invalid user email configuration' });
    }

    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000;

    user.resetToken = resetToken;
    user.resetTokenExpiry = resetTokenExpiry;
    await user.save();

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: 'Zangena Password Reset',
      text: `Your password reset token is: ${resetToken}. It expires in 1 hour.\n\nEnter it in the Zangena app to reset your password.`,
      html: `<h2>Zangena Password Reset</h2><p>Your password reset token is: <strong>${resetToken}</strong></p><p>It expires in 1 hour. Enter it in the Zangena app to reset your password.</p>`,
    };

    await transporter.sendMail(mailOptions);
    res.json({ message: 'Reset instructions have been sent to your email.' });
  } catch (error) {
    console.error('[FORGOT-PASSWORD] Error:', error.message);
    res.status(500).json({ error: 'Server error during password reset request' });
  }
});

// POST /api/reset-password
router.post('/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) {
    return res.status(400).json({ error: 'Token and new password are required' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  try {
    const user = await User.findOne({ resetToken: token, resetTokenExpiry: { $gt: Date.now() } });
    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;
    await user.save();

    res.json({ message: 'Password reset successful' });
  } catch (error) {
    console.error('[RESET-PASSWORD] Error:', error.message);
    res.status(500).json({ error: 'Server error during password reset' });
  }
});

// GET /api/user/:username
router.get('/user/:username', authenticateToken(), async (req, res) => {
  try {
    const user = await User.findOne(
      { username: req.params.username },
      { username: 1, name: 1, phoneNumber: 1, email: 1, balance: 1, zambiaCoinBalance: 1, trustScore: 1, transactions: { $slice: -10 }, kycStatus: 1, isActive: 1 }
    ).lean();
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (req.user.username !== req.params.username && !['admin', 'business'].includes(req.user.role)) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    res.json({
      username: user.username,
      name: user.name,
      phoneNumber: user.phoneNumber,
      email: user.email,
      balance: user.balance,
      zambiaCoinBalance: user.zambiaCoinBalance,
      trustScore: user.trustScore,
      transactions: user.transactions,
      kycStatus: user.kycStatus,
      isActive: user.isActive,
    });
  } catch (error) {
    console.error('[USER-FETCH] Error:', error.message);
    res.status(500).json({ error: 'Server error fetching user' });
  }
});

// GET /api/user/phone/:phoneNumber
router.get('/user/phone/:phoneNumber', authenticateToken(), async (req, res) => {
  try {
    const user = await User.findOne({ phoneNumber: req.params.phoneNumber });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.phoneNumber !== req.user.phoneNumber) return res.status(403).json({ error: 'Unauthorized' });
    res.json({
      phoneNumber: user.phoneNumber,
      username: user.username,
      email: user.email,
      name: user.name,
      balance: user.balance || 0,
      transactions: user.transactions || [],
      kycStatus: user.kycStatus,
      role: user.role,
      lastViewedTimestamp: user.lastViewedTimestamp || 0,
    });
  } catch (error) {
    console.error('[USER-PHONE] Error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/user/update
router.put('/user/update', authenticateToken(), async (req, res) => {
  const { username, email, password, pin } = req.body;

  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    if (username && username !== user.username) {
      const existingUsername = await User.findOne({ username });
      if (existingUsername) return res.status(400).json({ error: 'Username already taken' });
      user.username = username;
    }
    if (email && email !== user.email) {
      const existingEmail = await User.findOne({ email });
      if (existingEmail) return res.status(400).json({ error: 'Email already in use' });
      if (!email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) return res.status(400).json({ error: 'Invalid email format' });
      user.email = email;
    }
    if (password) {
      if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
      user.password = await bcrypt.hash(password, 10);
    }
    if (pin) {
      if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be a 4-digit number' });
      user.pin = pin;
    }
    await user.save();
    res.json({ message: 'User updated' });
  } catch (error) {
    console.error('[USER-UPDATE] Error:', error.message);
    res.status(500).json({ error: 'Server error updating user' });
  }
});

// DELETE /api/user/delete
router.delete('/user/delete', authenticateToken(), async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: 'User not found' });

    await QRPin.deleteMany({ username: user.username });
    await User.deleteOne({ username: req.user.username });
    res.json({ message: 'Account deleted successfully' });
  } catch (error) {
    console.error('[USER-DELETE] Error:', error.message);
    res.status(500).json({ error: 'Server error deleting account' });
  }
});

// PUT /api/user/update-notification
router.put('/user/update-notification', authenticateToken(), async (req, res) => {
  const { phoneNumber, lastViewedTimestamp } = req.body;
  if (!phoneNumber || typeof lastViewedTimestamp !== 'number') {
    return res.status(400).json({ error: 'Invalid phoneNumber or timestamp' });
  }
  if (phoneNumber !== req.user.phoneNumber) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  try {
    const user = await User.findOneAndUpdate(
      { phoneNumber },
      { lastViewedTimestamp },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'Notification timestamp updated' });
  } catch (error) {
    console.error('[USER-NOTIFICATION] Error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/save-push-token
router.post('/save-push-token', authenticateToken(), async (req, res) => {
  const { pushToken } = req.body;
  if (!pushToken) return res.status(400).json({ error: 'Push token is required' });
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.pushToken = pushToken;
    await user.save();
    res.status(200).json({ message: 'Push token saved for user' });
  } catch (error) {
    console.error('[SAVE-PUSH-TOKEN] Error:', error.message);
    res.status(500).json({ error: 'Failed to save push token' });
  }
});

// POST /api/deposit/manual
router.post('/deposit/manual', authenticateToken(), async (req, res) => {
  const { amount, transactionId } = req.body;
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user || !user.isActive) {
      return res.status(403).json({ error: 'User not found or inactive' });
    }
    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    if (!transactionId || user.pendingDeposits.some(d => d.transactionId === transactionId)) {
      return res.status(400).json({ error: 'Transaction ID required or already used' });
    }
    user.pendingDeposits = user.pendingDeposits || [];
    user.pendingDeposits.push({ amount, transactionId, date: new Date(), status: 'pending' });
    await user.save();

    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(admin.pushToken, 'New Deposit Request', `Deposit of ${amount} ZMW from ${user.username} needs approval.`, { userId: user._id, transactionId });
    }

    res.json({ message: 'Deposit submitted for verification' });
  } catch (error) {
    console.error('[DEPOSIT-MANUAL] Error:', error.message);
    res.status(500).json({ error: 'Failed to submit deposit' });
  }
});

// POST /api/withdraw/request
router.post('/withdraw/request', authenticateToken(), async (req, res) => {
  const { amount } = req.body;
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user || !user.isActive) {
      return res.status(403).json({ error: 'User not found or inactive' });
    }
    if (!amount || amount <= 0 || amount > user.balance) {
      return res.status(400).json({ error: 'Invalid amount or insufficient balance' });
    }
    user.pendingWithdrawals = user.pendingWithdrawals || [];
    user.pendingWithdrawals.push({ amount, date: new Date(), status: 'pending' });
    await user.save();

    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(admin.pushToken, 'New Withdrawal Request', `Withdrawal of ${amount} ZMW from ${user.username} needs approval.`, { userId: user._id, withdrawalIndex: user.pendingWithdrawals.length - 1 });
    }

    res.json({ message: 'Withdrawal requested. Awaiting approval.' });
  } catch (error) {
    console.error('[WITHDRAW-REQUEST] Error:', error.message);
    res.status(500).json({ error: 'Failed to request withdrawal' });
  }
});

// GET /api/user/transactions
router.get('/user/transactions', authenticateToken(), async (req, res) => {
  const { limit = 50, skip = 0 } = req.query;
  try {
    const parsedLimit = Math.min(parseInt(limit, 10), 100);
    const parsedSkip = Math.max(parseInt(skip, 10), 0);

    const user = await User.findOne({ username: req.user.username }).lean();
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const transactions = (user.transactions || []).slice(parsedSkip, parsedSkip + parsedLimit);
    const totalTransactions = user.transactions.length;

    res.json({
      transactions,
      pagination: {
        total: totalTransactions,
        limit: parsedLimit,
        skip: parsedSkip,
        hasMore: parsedSkip + parsedLimit < totalTransactions,
      },
    });
  } catch (error) {
    console.error('[USER-TRANSACTIONS] Error:', error.message);
    res.status(500).json({ error: 'Server error fetching transactions' });
  }
});

// POST /api/logout
router.post('/logout', authenticateToken(), async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (user) {
      user.pushToken = null;
      await user.save();
    }
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('[LOGOUT] Error:', error.message);
    res.status(500).json({ error: 'Server error during logout' });
  }
});

// POST /api/store-qr-pin
router.post('/store-qr-pin', authenticateToken(), async (req, res) => {
  const { username, pin } = req.body;
  if (!username || !pin) {
    return res.status(400).json({ error: 'Username and PIN are required' });
  }

  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.isActive) return res.status(403).json({ error: 'User is inactive' });
    if (username !== user.username) return res.status(403).json({ error: 'Unauthorized' });

    const qrId = crypto.randomBytes(16).toString('hex');
    const qrPin = new QRPin({ username, qrId, pin });
    await qrPin.save();

    user.transactions.push({ 
      type: 'pending-pin', 
      amount: 0, 
      toFrom: 'Self', 
      date: new Date() 
    });
    await user.save();

    res.json({ qrId });
  } catch (error) {
    console.error('[QR-PIN-STORE] Error:', error.message);
    res.status(500).json({ error: 'Server error storing QR pin' });
  }
});

// POST /api/transfer
router.post('/transfer', authenticateToken(), async (req, res) => {
  const { sender, receiver, amount, pin } = req.body;
  if (!sender || !receiver || !amount || !pin) {
    return res.status(400).json({ error: 'Sender, receiver, amount, and PIN are required' });
  }

  try {
    const senderUser = await User.findOne({ username: sender });
    if (!senderUser || senderUser.username !== req.user.username) {
      return res.status(403).json({ error: 'Unauthorized sender' });
    }
    if (!senderUser.isActive) return res.status(403).json({ error: 'Sender account is inactive' });
    if (senderUser.pin !== pin) return res.status(400).json({ error: 'Invalid PIN' });
    if (senderUser.zambiaCoinBalance < amount) return res.status(400).json({ error: 'Insufficient ZMC balance' });

    const receiverUser = await User.findOne({ username: receiver });
    if (!receiverUser) return res.status(400).json({ error: 'Receiver not found' });
    if (!receiverUser.isActive) return res.status(403).json({ error: 'Receiver account is inactive' });

    const paymentAmount = parseFloat(amount);
    if (isNaN(paymentAmount) || paymentAmount <= 0) {
      return res.status(400).json({ error: 'Amount must be a positive number' });
    }

    senderUser.zambiaCoinBalance -= paymentAmount;
    receiverUser.zambiaCoinBalance += paymentAmount;
    const txId = crypto.randomBytes(16).toString('hex');
    senderUser.transactions.push({ _id: txId, type: 'zmc-sent', amount: paymentAmount, toFrom: receiver, date: new Date() });
    receiverUser.transactions.push({ _id: crypto.randomBytes(16).toString('hex'), type: 'zmc-received', amount: paymentAmount, toFrom: sender, date: new Date() });

    await Promise.all([senderUser.save(), receiverUser.save()]);
    res.json({ message: 'ZMC transfer successful', transactionId: txId });
  } catch (error) {
    console.error('[TRANSFER] Error:', error.message);
    res.status(500).json({ error: 'Transfer failed' });
  }
});

// POST /api/rate
router.post('/rate', authenticateToken(), async (req, res) => {
  const { transactionId, rating, raterUsername } = req.body;
  if (!transactionId || !rating || !raterUsername) {
    return res.status(400).json({ error: 'Transaction ID, rating, and rater username are required' });
  }
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
    return res.status(400).json({ error: 'Rating must be an integer between 1 and 5' });
  }

  try {
    if (raterUsername !== req.user.username) {
      return res.status(403).json({ error: 'Unauthorized rater' });
    }

    const senderUser = await User.findOne({ username: raterUsername });
    if (!senderUser) return res.status(404).json({ error: 'Rater not found' });

    const transaction = senderUser.transactions.find(tx => tx._id === transactionId && tx.type === 'zmc-sent');
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found or not sent by this user' });
    }

    const receiverUser = await User.findOne({ username: transaction.toFrom });
    if (!receiverUser) return res.status(404).json({ error: 'Receiver not found' });

    transaction.trustRating = rating;

    const newRatingCount = (receiverUser.ratingCount || 0) + 1;
    const currentAverage = receiverUser.trustScore ? (receiverUser.trustScore / 100) * 5 : 0;
    const newAverage = ((currentAverage * (newRatingCount - 1)) + rating) / newRatingCount;
    const newTrustScore = Math.round((newAverage / 5) * 100);

    receiverUser.trustScore = newTrustScore;
    receiverUser.ratingCount = newRatingCount;

    await Promise.all([senderUser.save(), receiverUser.save()]);
    res.json({ message: 'Rating submitted successfully', trustScore: newTrustScore, ratingCount: newRatingCount });
  } catch (error) {
    console.error('[RATE] Error:', error.message);
    res.status(500).json({ error: 'Failed to submit rating' });
  }
});

// POST /api/generate-qr
router.post('/generate-qr', authenticateToken(), async (req, res) => {
  const { pin } = req.body;
  if (!pin || pin.length !== 4 || !/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'A valid 4-digit PIN is required' });
  }

  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.isActive) return res.status(403).json({ error: 'Account is inactive' });
    if (user.pin !== pin) return res.status(400).json({ error: 'Invalid PIN' });

    res.json({ message: 'PIN validated successfully' });
  } catch (error) {
    console.error('[GENERATE-QR] Error:', error.message);
    res.status(500).json({ error: 'Failed to validate PIN' });
  }
});

// Admin Routes
router.put('/user/update-kyc', authenticateToken(['admin']), async (req, res) => {
  const { username, kycStatus } = req.body;
  if (!username || !kycStatus || !['pending', 'verified', 'rejected'].includes(kycStatus)) {
    return res.status(400).json({ error: 'Valid username and kycStatus are required' });
  }
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.kycStatus = kycStatus;
    if (kycStatus === 'verified') user.isActive = true;
    else if (kycStatus === 'rejected') user.isActive = false;
    await user.save();
    res.json({ message: 'KYC status updated' });
  } catch (error) {
    console.error('[UPDATE-KYC] Error:', error.message);
    res.status(500).json({ error: 'Server error updating KYC status' });
  }
});

router.put('/user/toggle-active', authenticateToken(['admin']), async (req, res) => {
  const { username, isActive } = req.body;
  if (!username || typeof isActive !== 'boolean') {
    return res.status(400).json({ error: 'Valid username and isActive status are required' });
  }
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.isActive = isActive;
    await user.save();
    res.json({ message: `User ${isActive ? 'activated' : 'deactivated'}` });
  } catch (error) {
    console.error('[TOGGLE-ACTIVE] Error:', error.message);
    res.status(500).json({ error: 'Server error toggling user status' });
  }
});

router.post('/admin/verify-deposit', authenticateToken(['admin']), async (req, res) => {
  const { userId, transactionId, approved } = req.body;
  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const deposit = user.pendingDeposits.find(d => d.transactionId === transactionId);
    if (!deposit || deposit.status !== 'pending') {
      return res.status(400).json({ error: 'Invalid or already processed deposit' });
    }
    if (approved) {
      const amount = deposit.amount;
      let creditedAmount = amount;
      const isFirstDeposit = !user.transactions.some(tx => tx.type === 'deposited');
      if (isFirstDeposit) {
        const bonus = Math.min(amount * 0.05, 10);
        creditedAmount += bonus;
      }
      user.balance += creditedAmount;
      user.transactions.push({
        _id: crypto.randomBytes(16).toString('hex'), type: 'deposited', amount: creditedAmount,
        toFrom: 'manual-mobile-money', fee: 0, date: new Date(),
      });
      deposit.status = 'approved';

      const adminLedger = await AdminLedger.findOne();
      if (adminLedger) {
        adminLedger.totalBalance += creditedAmount;
        adminLedger.lastUpdated = new Date();
        await adminLedger.save();
      }
    } else {
      deposit.status = 'rejected';
    }
    await user.save();
    res.json({ message: `Deposit ${approved ? 'approved' : 'rejected'}` });
  } catch (error) {
    console.error('[VERIFY-DEPOSIT] Error:', error.message);
    res.status(500).json({ error: 'Failed to verify deposit' });
  }
});

router.post('/admin/verify-withdrawal', authenticateToken(['admin']), async (req, res) => {
  const { userId, withdrawalIndex, approved } = req.body;
  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const withdrawal = user.pendingWithdrawals[withdrawalIndex];
    if (!withdrawal || withdrawal.status !== 'pending') {
      return res.status(400).json({ error: 'Invalid or already processed withdrawal' });
    }
    if (approved) {
      const withdrawFee = Math.max(withdrawal.amount * 0.01, 2);
      const totalDeduction = withdrawal.amount + withdrawFee;
      if (user.balance < totalDeduction) {
        return res.status(400).json({ error: 'Insufficient balance' });
      }
      user.balance -= totalDeduction;
      user.transactions.push({
        _id: crypto.randomBytes(16).toString('hex'), type: 'withdrawn', amount: withdrawal.amount,
        toFrom: 'manual-mobile-money', fee: withdrawFee, date: new Date(),
      });
      withdrawal.status = 'completed';
    } else {
      withdrawal.status = 'rejected';
    }
    await user.save();
    res.json({ message: `Withdrawal ${approved ? 'completed' : 'rejected'}` });
  } catch (error) {
    console.error('[VERIFY-WITHDRAWAL] Error:', error.message);
    res.status(500).json({ error: 'Failed to verify withdrawal' });
  }
});

router.get('/admin/users/pending', authenticateToken(['admin']), async (req, res) => {
  const { page = 1, limit = 10 } = req.query;
  try {
    const users = await User.find({ kycStatus: 'pending' })
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .select('username name phoneNumber email idImageUrl createdAt');
    const total = await User.countDocuments({ kycStatus: 'pending' });
    res.json({ users, total });
  } catch (error) {
    console.error('[PENDING-USERS] Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch pending users' });
  }
});

router.post('/admin/user/suspend', authenticateToken(['admin']), async (req, res) => {
  const { username, reason } = req.body;
  if (!username || !reason) {
    return res.status(400).json({ error: 'Username and reason are required' });
  }
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.isActive = false;
    user.suspensionReason = reason;
    user.suspensionDate = new Date();
    await user.save();
    await AdminLedger.findOneAndUpdate(
      {},
      {
        $push: {
          transactions: {
            type: 'user-suspension',
            userId: username,
            reason,
            date: new Date(),
          },
        },
      },
      { upsert: true }
    );
    if (user.pushToken) {
      await sendPushNotification(
        user.pushToken,
        'Account Suspended',
        `Your account has been suspended: ${reason}`,
        { username }
      );
    }
    res.json({ message: 'User suspended successfully' });
  } catch (error) {
    console.error('[USER-SUSPEND] Error:', error.message);
    res.status(500).json({ error: 'Failed to suspend user' });
  }
});

router.post('/credit', authenticateToken(['admin']), async (req, res) => {
  const { adminUsername, toUsername, amount } = req.body;
  try {
    const admin = await User.findOne({ username: req.user.username });
    if (!admin || admin.username !== adminUsername) return res.status(403).json({ error: 'Unauthorized admin' });
    const user = await User.findOne({ username: toUsername });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.isActive) return res.status(403).json({ error: 'User is inactive' });
    const paymentAmount = parseFloat(amount);
    if (isNaN(paymentAmount) || paymentAmount <= 0) {
      return res.status(400).json({ error: 'Amount must be a positive number' });
    }
    user.balance += paymentAmount;
    user.transactions.push({ _id: crypto.randomBytes(16).toString('hex'), type: 'credited', amount: paymentAmount, toFrom: adminUsername });
    await user.save();
    res.json({ message: 'Credit successful' });
  } catch (error) {
    console.error('[CREDIT] Error:', error.message);
    res.status(500).json({ error: 'Server error during credit' });
  }
});

router.post('/credit-zmc', authenticateToken(['admin']), async (req, res) => {
  const { toUsername, amount } = req.body;
  try {
    const user = await User.findOne({ username: toUsername });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.isActive) return res.status(403).json({ error: 'User is inactive' });
    const creditAmount = parseFloat(amount);
    if (isNaN(creditAmount) || creditAmount <= 0) return res.status(400).json({ error: 'Invalid amount' });
    user.zambiaCoinBalance += creditAmount;
    user.transactions.push({ _id: crypto.randomBytes(16).toString('hex'), type: 'zmc-received', amount: creditAmount, toFrom: 'admin', date: new Date() });
    await user.save();
    res.json({ message: 'ZMC credited successfully' });
  } catch (error) {
    console.error('[CREDIT-ZMC] Error:', error.message);
    res.status(500).json({ error: 'Failed to credit ZMC' });
  }
});

router.post('/airdrop', authenticateToken(['admin']), async (req, res) => {
  const { amount } = req.body;
  if (!amount || amount <= 0) {
    return res.status(400).json({ error: 'Valid amount required' });
  }

  try {
    const users = await User.find({ kycStatus: 'verified' });
    await Promise.all(users.map(user => {
      user.zambiaCoinBalance += amount;
      user.transactions.push({ _id: crypto.randomBytes(16).toString('hex'), type: 'zmc-received', amount, toFrom: 'admin-airdrop', date: new Date() });
      return user.save();
    }));
    res.json({ message: `Airdropped ${amount} ZMC to all verified users` });
  } catch (error) {
    console.error('[AIRDROP] Error:', error.message);
    res.status(500).json({ error: 'Airdrop failed' });
  }
});

module.exports = router;