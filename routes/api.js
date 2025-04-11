const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const AWS = require('aws-sdk');
const fs = require('fs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const Flutterwave = require('flutterwave-node-v3');
const mongoose = require('mongoose');
const User = require('../models/User');
const Business = require('../models/Business'); // Added Business model
const QRPin = require('../models/QRPin');
const AdminLedger = require('../models/AdminLedger'); // Added for balance tracking
const authenticateToken = require('../middleware/authenticateToken');
const axios = require('axios');

/* let axios;
try {
  axios = require('axios');
} catch (e) {
  console.error('Axios not installed. Please run `npm install axios`');
} */

// Configure multer for temporary local storage
const upload = multer({ dest: 'uploads/' });

// Configure AWS S3
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION || 'us-east-1',
});
const S3_BUCKET = process.env.S3_BUCKET || 'zangena';

// Configure Flutterwave
const flw = new Flutterwave(process.env.FLUTTERWAVE_PUBLIC_KEY, process.env.FLUTTERWAVE_SECRET_KEY);

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

// Charge Sheet Functions for Zangena ZMW
const getSendingFee = (amount) => {
  if (amount <= 50) return 1.00;
  if (amount <= 100) return 2.00;
  if (amount <= 500) return 3.50;
  if (amount <= 1000) return 5.00;
  if (amount <= 5000) return 10.00;
  if (amount <= 10000) return 15.00;
  return 0; // Explicitly 0 for > 10,000
};

const getReceivingFee = (amount) => {
  if (amount <= 50) return 0.50;
  if (amount <= 100) return 1.00;
  if (amount <= 500) return 1.50;
  if (amount <= 1000) return 2.00;
  if (amount <= 5000) return 3.00;
  if (amount <= 10000) return 5.00;
  return 0; // Explicitly 0 for > 10,000
};

// Function to send push notifications
async function sendPushNotification(pushToken, title, body, data = {}) {
  if (!axios) {
    console.error('Axios not available, cannot send push notification');
    return;
  }
  const message = {
    to: pushToken,
    sound: 'default',
    title,
    body,
    data: { type: 'pendingApproval', ...data },
  };
  try {
    await axios.post('https://exp.host/--/api/v2/push/send', message, {
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      timeout: 5000,
    });
    console.log(`Push notification sent to ${pushToken}: ${title} - ${body}`);
  } catch (error) {
    console.error('Error sending push notification:', error.message);
  }
}

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
    });
  } catch (error) {
    console.error('[USER] Error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/register
router.post('/register', upload.single('idImage'), async (req, res) => {
  const { username, name, phoneNumber, email, password, pin } = req.body;
  const idImage = req.file;

  console.time('Register Total');
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
    console.time('Check Existing User');
    const existingUser = await User.findOne({ $or: [{ username }, { email }, { phoneNumber }] }).lean();
    console.timeEnd('Check Existing User');
    if (existingUser) {
      return res.status(400).json({ error: 'Username, email, or phone number already exists' });
    }

    console.time('S3 Upload');
    const fileStream = fs.createReadStream(idImage.path);
    const s3Key = `id-images/${username}-${Date.now()}-${idImage.originalname}`;
    const params = { Bucket: S3_BUCKET, Key: s3Key, Body: fileStream, ContentType: idImage.mimetype, ACL: 'private' };
    const s3Response = await s3.upload(params).promise();
    const idImageUrl = s3Response.Location;
    fs.unlinkSync(idImage.path);
    console.timeEnd('S3 Upload');

    console.time('User Creation');
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      username: username.trim(),
      name: name.trim(),
      phoneNumber,
      email,
      password: hashedPassword,
      pin,
      idImageUrl,
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
    console.timeEnd('User Creation');

    const token = jwt.sign({ phoneNumber: user.phoneNumber, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: '24h' });

    console.time('Push Notification');
    if (axios) {
      const admin = await User.findOne({ role: 'admin' });
      if (admin && admin.pushToken) {
        await sendPushNotification(admin.pushToken, 'New User Registration', `User ${username} needs KYC approval.`, { userId: user._id });
      }
    }
    console.timeEnd('Push Notification');

    console.timeEnd('Register Total');
    res.status(201).json({ token, username: user.username, role: user.role, kycStatus: user.kycStatus });
  } catch (error) {
    console.error('Register Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error during registration', details: error.message });
  }
});

// POST /api/business/register
router.post('/business/register', authenticateToken(['user']), upload.single('qrCode'), async (req, res) => {
  const { businessId, name, pin } = req.body;
  const qrCodeImage = req.file;
  if (!businessId || !name || !pin || !qrCodeImage) {
    return res.status(400).json({ error: 'Business ID (TPIN), name, PIN, and QR code image are required' });
  }
  if (!/^\d{10}$/.test(businessId)) {
    return res.status(400).json({ error: 'Business ID must be a 10-digit TPIN' });
  }
  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'PIN must be a 4-digit number' });
  }
  try {
    const existingBusiness = await Business.findOne({ $or: [{ businessId }, { ownerUsername: req.user.username }] }).lean();
    if (existingBusiness) return res.status(400).json({ error: 'Business ID (TPIN) or owner username already registered' });
    const owner = await User.findOne({ username: req.user.username });
    if (!owner) return res.status(404).json({ error: 'Owner user not found' });
    const fileStream = fs.createReadStream(qrCodeImage.path);
    const s3Key = `qr-codes/${Date.now()}-${qrCodeImage.originalname}`;
    const params = { Bucket: S3_BUCKET, Key: s3Key, Body: fileStream, ContentType: qrCodeImage.mimetype, ACL: 'private' };
    const s3Response = await s3.upload(params).promise();
    const qrCodeUrl = s3Response.Location;
    fs.unlinkSync(qrCodeImage.path);
    const business = new Business({
      businessId, name, ownerUsername: req.user.username, pin, balance: 0, qrCode: qrCodeUrl,
      role: 'business', approvalStatus: 'pending', transactions: [], isActive: false,
    });
    await business.save();
    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(admin.pushToken, 'New Business Registration', `Business ${name} (${businessId}) needs approval`, { businessId });
    }
    res.status(201).json({ message: 'Business registered, awaiting approval', businessId });
  } catch (error) {
    console.error('Business Register Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error during business registration', details: error.message });
  }
});

// POST /api/save-push-token
router.post('/save-push-token', authenticateToken(), async (req, res) => {
  const { pushToken } = req.body;
  if (!pushToken) return res.status(400).json({ error: 'Push token is required' });
  try {
    const user = await User.findOne({ username: req.user.username });
    if (user) {
      user.pushToken = pushToken;
      await user.save();
      return res.status(200).json({ message: 'Push token saved for user' });
    }
    const business = await Business.findOne({ businessId: req.user.businessId });
    if (business) {
      business.pushToken = pushToken;
      await business.save();
      return res.status(200).json({ message: 'Push token saved for business' });
    }
    res.status(404).json({ error: 'User or business not found' });
  } catch (error) {
    console.error('Save Push Token Error:', error.message);
    res.status(500).json({ error: 'Failed to save push token' });
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
      phoneNumber: user.phoneNumber, // Added
      role: user.role || 'user',
      kycStatus: user.kycStatus || 'pending',
      isFirstLogin,
    });
  } catch (error) {
    console.error('Login Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error during login', details: error.message });
  }
});

// POST /api/business/login
router.post('/business/login', async (req, res) => {
  const { businessId, pin } = req.body;
  if (!businessId || !pin) return res.status(400).json({ error: 'Business ID and PIN are required' });
  if (!/^\d{10}$/.test(businessId)) return res.status(400).json({ error: 'Business ID must be a 10-digit TPIN' });
  if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be a 4-digit number' });
  try {
    const business = await Business.findOne({ businessId });
    if (!business || business.pin !== pin) return res.status(400).json({ error: 'Invalid credentials' });
    if (!business.isActive) return res.status(403).json({ error: 'Business not approved or inactive' });
    const token = jwt.sign({ businessId, role: business.role, ownerUsername: business.ownerUsername }, JWT_SECRET, { expiresIn: '30d' });
    res.status(200).json({ token, businessId, role: business.role, approvalStatus: business.approvalStatus });
  } catch (error) {
    console.error('Business Login Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error during business login', details: error.message });
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
    console.error('Forgot Password Error:', error.message);
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
    console.error('Reset Password Error:', error.message);
    res.status(500).json({ error: 'Server error during password reset' });
  }
});

// GET /api/user/:username
router.get('/user/:username', authenticateToken(), async (req, res) => {
  const start = Date.now();
  console.log(`[${req.method}] ${req.path} - Starting fetch for ${req.params.username}`);
  const timeout = setTimeout(() => {
    console.error(`[${req.method}] ${req.path} - Request timed out after 25s`);
    res.status(503).json({ error: 'Request timed out', duration: `${Date.now() - start}ms` });
  }, 25000);

  try {
    console.time(`[${req.method}] ${req.path} - MongoDB ping`);
    await mongoose.connection.db.admin().ping();
    console.timeEnd(`[${req.method}] ${req.path} - MongoDB ping`);

    console.time(`[${req.method}] ${req.path} - User query`);
    const user = await User.findOne(
      { username: req.params.username },
      { username: 1, name: 1, phoneNumber: 1, email: 1, balance: 1, zambiaCoinBalance: 1, trustScore: 1, transactions: { $slice: -10 }, kycStatus: 1, isActive: 1 }
    ).lean().exec();
    console.timeEnd(`[${req.method}] ${req.path} - User query`);

    if (!user) {
      console.log(`[${req.method}] ${req.path} - User not found`);
      clearTimeout(timeout);
      return res.status(404).json({ error: 'User not found' });
    }

    if (req.user.username !== req.params.username && !['admin', 'business'].includes(req.user.role)) {
      console.log(`[${req.method}] ${req.path} - Unauthorized access by ${req.user.username}`);
      clearTimeout(timeout);
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const responseData = {
      username: user.username, name: user.name, phoneNumber: user.phoneNumber, email: user.email,
      balance: user.balance, zambiaCoinBalance: user.zambiaCoinBalance, trustScore: user.trustScore,
      transactions: user.transactions, kycStatus: user.kycStatus, isActive: user.isActive,
    };

    console.log(`[${req.method}] ${req.path} - Total time: ${Date.now() - start}ms`);
    clearTimeout(timeout);
    res.json(responseData);
  } catch (error) {
    console.error(`[${req.method}] ${req.path} - User Fetch Error:`, error.message, error.stack);
    clearTimeout(timeout);
    res.status(500).json({ error: 'Server error fetching user', details: error.message, duration: `${Date.now() - start}ms` });
  }
});

// GET /api/business/:businessId
router.get('/business/:businessId', authenticateToken(['business', 'admin']), async (req, res) => {
  try {
    const business = await Business.findOne({ businessId: req.params.businessId }).lean();
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    if (req.user.role === 'business' && req.user.businessId !== business.businessId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    res.json({
      businessId: business.businessId, name: business.name, ownerUsername: business.ownerUsername,
      balance: business.balance, qrCode: business.qrCode, approvalStatus: business.approvalStatus,
      transactions: business.transactions.slice(-10), isActive: business.isActive,
    });
  } catch (error) {
    console.error('Business Fetch Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error fetching business', details: error.message });
  }
});

// POST /api/store-qr-pin
router.post('/store-qr-pin', authenticateToken(), async (req, res) => {
  const { username, pin } = req.body;

  if (!username || !pin) {
    return res.status(400).json({ error: 'Username and PIN are required' });
  }

  try {
    const user = await User.findOne({ phoneNumber: req.user.phoneNumber });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.isActive) return res.status(403).json({ error: 'User is inactive' });
    if (username !== user.username) return res.status(403).json({ error: 'Unauthorized' });

    const qrId = crypto.randomBytes(16).toString('hex');
    const qrPin = new QRPin({ username, qrId, pin });
    await qrPin.save();

    user.transactions.push({ type: 'pending-pin', amount: 0, toFrom: 'Self' });
    await user.save();

    res.json({ qrId });
  } catch (error) {
    console.error('QR Pin Store Error:', error);
    res.status(500).json({ error: 'Server error storing QR pin' });
  }
});

// POST /api/deposit/manual
router.post('/deposit/manual', authenticateToken(), async (req, res) => {
  const { amount, transactionId } = req.body;
  console.log('Manual Deposit Request:', { amount, transactionId });

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
    console.error('Manual Deposit Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to submit deposit' });
  }
});

// POST /api/business/deposit/manual
router.post('/business/deposit/manual', authenticateToken(['business']), async (req, res) => {
  const { amount, transactionId } = req.body;

  try {
    const business = await Business.findOne({ businessId: req.user.businessId });
    if (!business || !business.isActive) {
      return res.status(403).json({ error: 'Business not found or inactive' });
    }
    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    if (!transactionId || business.pendingDeposits.some(d => d.transactionId === transactionId)) {
      return res.status(400).json({ error: 'Transaction ID required or already used' });
    }
    business.pendingDeposits = business.pendingDeposits || [];
    business.pendingDeposits.push({ amount, transactionId, date: new Date(), status: 'pending' });
    await business.save();

    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(admin.pushToken, 'New Business Deposit', `Deposit of ${amount} ZMW from ${business.name} (${business.businessId}) needs approval.`, { businessId: business.businessId, transactionId });
    }

    res.json({ message: 'Business deposit submitted for verification' });
  } catch (error) {
    console.error('Business Deposit Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to submit business deposit' });
  }
});

// POST /api/admin/verify-withdrawal
router.post('/admin/verify-withdrawal', authenticateToken(['admin']), async (req, res) => {
  const { userId, withdrawalIndex, approved } = req.body;
  console.log('Verify Withdrawal Request:', { userId, withdrawalIndex, approved });

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
    console.error('Verify Withdrawal Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to verify withdrawal' });
  }
});

// POST /api/admin/verify-deposit
router.post('/admin/verify-deposit', authenticateToken(['admin']), async (req, res) => {
  const { userId, transactionId, approved } = req.body;
  console.log('Verify Deposit Request:', { userId, transactionId, approved });

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
    console.error('Verify Deposit Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to verify deposit' });
  }
});

// POST /api/admin/verify-business-deposit
router.post('/admin/verify-business-deposit', authenticateToken(['admin']), async (req, res) => {
  const { businessId, transactionId, approved } = req.body;

  try {
    const business = await Business.findOne({ businessId });
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    const deposit = business.pendingDeposits.find(d => d.transactionId === transactionId);
    if (!deposit || deposit.status !== 'pending') {
      return res.status(400).json({ error: 'Invalid or already processed deposit' });
    }
    if (approved) {
      business.balance += deposit.amount;
      business.transactions.push({
        _id: crypto.randomBytes(16).toString('hex'), type: 'deposited', amount: deposit.amount,
        toFrom: 'manual-mobile-money', fee: 0, date: new Date(),
      });
      deposit.status = 'approved';

      const adminLedger = await AdminLedger.findOne();
      if (adminLedger) {
        adminLedger.totalBalance += deposit.amount;
        adminLedger.lastUpdated = new Date();
        await adminLedger.save();
      }
    } else {
      deposit.status = 'rejected';
    }
    await business.save();
    res.json({ message: `Business deposit ${approved ? 'approved' : 'rejected'}` });
  } catch (error) {
    console.error('Verify Business Deposit Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to verify business deposit' });
  }
});

// GET /api/test-flutterwave
router.get('/test-flutterwave', async (req, res) => {
  try {
    const testData = { tx_ref: 'test', amount: 10, currency: 'ZMW', email: 'test@example.com', phone_number: '+260972721581', network: 'AIRTEL' };
    const result = await flw.MobileMoney.zambia(testData);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/withdraw/request
router.post('/withdraw/request', authenticateToken(), async (req, res) => {
  const { amount } = req.body;
  console.log('Withdraw Request:', { amount });

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
    console.error('Withdraw Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to request withdrawal' });
  }
});

// POST /api/business/withdraw/request
router.post('/business/withdraw/request', authenticateToken(['business']), async (req, res) => {
  const { amount } = req.body;
  try {
    const business = await Business.findOne({ businessId: req.user.businessId });
    if (!business || !business.isActive) return res.status(403).json({ error: 'Business not found or inactive' });
    const withdrawalAmount = parseFloat(amount);
    if (!withdrawalAmount || withdrawalAmount <= 0) return res.status(400).json({ error: 'Invalid amount' });
    const withdrawalFee = Math.max(withdrawalAmount * 0.01, 2);
    const totalDeduction = withdrawalAmount + withdrawalFee;
    if (business.balance < totalDeduction) return res.status(400).json({ error: 'Insufficient balance to cover amount and fee' });
    business.pendingWithdrawals = business.pendingWithdrawals || [];
    business.pendingWithdrawals.push({ amount: withdrawalAmount, fee: withdrawalFee, date: new Date(), status: 'pending' });
    await business.save();
    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(admin.pushToken, 'New Business Withdrawal', `Withdrawal of ${withdrawalAmount} ZMW from ${business.name} (${business.businessId}) needs approval`, { businessId: business.businessId, withdrawalIndex: business.pendingWithdrawals.length - 1 });
    }
    if (business.pushToken) {
      await sendPushNotification(business.pushToken, 'Withdrawal Requested', `Your request for ${withdrawalAmount.toFixed(2)} ZMW (Fee: ${withdrawalFee.toFixed(2)} ZMW) is pending approval`, { businessId: business.businessId, withdrawalIndex: business.pendingWithdrawals.length - 1 });
    }
    res.json({ message: 'Business withdrawal requested. Awaiting approval', withdrawalFee });
  } catch (error) {
    console.error('Business Withdraw Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to request business withdrawal' });
  }
});

// POST /api/withdraw
router.post('/api/withdraw', authenticateToken(), async (req, res) => {
  const { amount } = req.body;
  console.log('Withdraw Request Received:', { amount });

  try {
    const user = await User.findOne({ phoneNumber: req.user.phoneNumber });
    if (!user || !user.isActive) {
      console.log('User check failed:', { phoneNumber: req.user.phoneNumber });
      return res.status(403).json({ error: 'User not found or inactive' });
    }

    if (!amount || amount <= 0) {
      console.log('Invalid amount:', amount);
      return res.status(400).json({ error: 'Invalid amount' });
    }

    let phoneNumber = req.user.phoneNumber;
    console.log('Raw Phone Number:', phoneNumber);
    if (!phoneNumber.startsWith('+260')) {
      if (phoneNumber.startsWith('0')) phoneNumber = '+26' + phoneNumber;
      else if (phoneNumber.startsWith('260')) phoneNumber = '+' + phoneNumber;
    }
    console.log('Normalized Phone Number:', phoneNumber);

    const mtnPrefixes = ['96', '76'];
    const airtelPrefixes = ['97', '77'];
    const prefix = phoneNumber.slice(4, 6);
    console.log('Extracted Prefix:', prefix);

    let paymentMethod;
    if (mtnPrefixes.includes(prefix)) {
      paymentMethod = 'mobile-money-mtn';
      console.log('Payment Method Set: mobile-money-mtn');
    } else if (airtelPrefixes.includes(prefix)) {
      paymentMethod = 'mobile-money-airtel';
      console.log('Payment Method Set: mobile-money-airtel');
    } else {
      console.log('Phone number not supported');
      return res.status(400).json({ error: 'Phone number not supported for withdrawals' });
    }

    const withdrawFee = Math.max(amount * 0.01, 2);
    const totalDeduction = amount + withdrawFee;

    if (user.balance < totalDeduction) {
      console.log('Insufficient balance:', { balance: user.balance, totalDeduction });
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const paymentData = {
      reference: `zangena-withdraw-${Date.now()}`,
      amount,
      currency: 'ZMW',
      account_bank: 'mobilemoneyzambia',
      account_number: phoneNumber,
      narration: 'Zangena Withdrawal',
    };
    console.log('Payment Data:', paymentData);

    const transferResponse = await flw.Transfer.initiate(paymentData);
    console.log('Flutterwave Raw Response:', transferResponse);

    if (transferResponse.status !== 'success') {
      console.log('Flutterwave failed:', transferResponse);
      throw new Error(`Withdrawal failed: ${transferResponse.message}`);
    }

    user.balance -= totalDeduction;
    user.transactions = user.transactions || [];
    user.transactions.push({
      _id: crypto.randomBytes(16).toString('hex'),
      type: 'withdrawn',
      amount,
      toFrom: `${phoneNumber} (${paymentMethod})`,
      fee: withdrawFee,
      date: new Date(),
    });

    await user.save();
    console.log('User updated:', { balance: user.balance });
    res.json({ message: `Withdrew ${amount.toFixed(2)} ZMW (fee: ${withdrawFee.toFixed(2)} ZMW)`, balance: user.balance });
  } catch (error) {
    console.error('Withdraw Error:', error.message, error.stack);
    res.status(500).json({ error: error.message || 'Withdrawal failed' });
  }
});

// GET /api/ip
router.get('/ip', async (req, res) => {
  try {
    const response = await axios.get('https://api.ipify.org?format=json', { timeout: 5000 });
    console.log('Outbound IP:', response.data.ip);
    res.json({ ip: response.data.ip });
  } catch (error) {
    console.error('IP Fetch Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch IP' });
  }
});

// POST /api/payment-with-qr-pin
router.post('/payment-with-qr-pin', authenticateToken(), async (req, res) => {
  const { fromUsername, toUsername, amount, qrId, pin } = req.body;

  if (!fromUsername || !toUsername || !amount || !qrId || !pin) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const sender = await User.findOne({ username: req.user.username });
    if (!sender || !sender.isActive) return res.status(403).json({ error: 'Sender not found or inactive' });
    if (sender.username !== fromUsername) return res.status(403).json({ error: 'Unauthorized sender' });
    if (sender.role === 'admin') return res.status(403).json({ error: 'Admins cannot send payments' });

    const receiver = await User.findOne({ username: toUsername });
    if (!receiver || !receiver.isActive) return res.status(403).json({ error: 'Recipient not found or inactive' });

    const qrPin = await QRPin.findOne({ qrId, pin });
    if (!qrPin || qrPin.username !== toUsername) {
      return res.status(400).json({ error: 'Invalid QR code or PIN' });
    }

    const paymentAmount = parseFloat(amount);
    if (isNaN(paymentAmount) || paymentAmount <= 0 || paymentAmount > 10000) {
      return res.status(400).json({ error: 'Amount must be a positive number up to 10,000 ZMW' });
    }

    const sendingFee = getSendingFee(paymentAmount);
    const receivingFee = getReceivingFee(paymentAmount);
    const totalSenderDeduction = paymentAmount + sendingFee;

    if (sender.balance < totalSenderDeduction) {
      return res.status(400).json({ error: 'Insufficient balance to cover amount and sending fee' });
    }

    const admin = await User.findOne({ username: 'admin', role: 'admin' });
    if (!admin) return res.status(500).json({ error: 'Admin account not found' });

    sender.balance -= totalSenderDeduction;
    receiver.balance += paymentAmount - receivingFee;
    admin.balance += sendingFee + receivingFee;

    const txId = crypto.randomBytes(16).toString('hex');
    sender.transactions.push({ _id: txId, type: 'sent', amount: paymentAmount, toFrom: toUsername, fee: sendingFee });
    receiver.transactions.push({ _id: crypto.randomBytes(16).toString('hex'), type: 'received', amount: paymentAmount, toFrom: fromUsername, fee: receivingFee });
    admin.transactions.push({
      _id: crypto.randomBytes(16).toString('hex'), type: 'fee-collected', amount: sendingFee + receivingFee,
      toFrom: `${fromUsername} -> ${toUsername}`, originalAmount: paymentAmount, sendingFee, receivingFee,
    });

    const adminLedger = await AdminLedger.findOne();
    if (adminLedger) {
      adminLedger.totalBalance += sendingFee + receivingFee;
      adminLedger.lastUpdated = new Date();
      await adminLedger.save();
    }

    await QRPin.deleteOne({ qrId });
    await Promise.all([sender.save(), receiver.save(), admin.save()]);

    res.json({ message: 'Payment successful', sendingFee, receivingFee, amountReceived: paymentAmount - receivingFee });
  } catch (error) {
    console.error('QR Payment Error:', error.message);
    res.status(500).json({ error: 'Server error during payment' });
  }
});

// POST /api/business/payment-to-business
router.post('/business/payment-to-business', authenticateToken(), async (req, res) => {
  const { fromUsername, businessId, amount } = req.body;

  if (!fromUsername || !businessId || !amount) {
    return res.status(400).json({ error: 'From username, business ID, and amount are required' });
  }

  try {
    const sender = await User.findOne({ username: req.user.username });
    if (!sender || !sender.isActive) return res.status(403).json({ error: 'Sender not found or inactive' });
    if (sender.username !== fromUsername) return res.status(403).json({ error: 'Unauthorized sender' });

    const business = await Business.findOne({ businessId });
    if (!business || !business.isActive) return res.status(403).json({ error: 'Business not found or inactive' });

    const paymentAmount = parseFloat(amount);
    if (isNaN(paymentAmount) || paymentAmount <= 0 || paymentAmount > 10000) {
      return res.status(400).json({ error: 'Amount must be a positive number up to 10,000 ZMW' });
    }

    const sendingFee = getSendingFee(paymentAmount);
    const totalSenderDeduction = paymentAmount + sendingFee;

    if (sender.balance < totalSenderDeduction) {
      return res.status(400).json({ error: 'Insufficient balance to cover amount and fee' });
    }

    const admin = await User.findOne({ role: 'admin' });
    if (!admin) return res.status(500).json({ error: 'Admin account not found' });

    sender.balance -= totalSenderDeduction;
    business.balance += paymentAmount;
    admin.balance += sendingFee;

    const txId = crypto.randomBytes(16).toString('hex');
    sender.transactions.push({ _id: txId, type: 'sent', amount: paymentAmount, toFrom: businessId, fee: sendingFee });
    business.transactions.push({ _id: crypto.randomBytes(16).toString('hex'), type: 'received', amount: paymentAmount, toFrom: fromUsername });
    admin.transactions.push({
      _id: crypto.randomBytes(16).toString('hex'), type: 'fee-collected', amount: sendingFee,
      toFrom: `${fromUsername} -> ${businessId}`, originalAmount: paymentAmount, sendingFee,
    });

    const adminLedger = await AdminLedger.findOne();
    if (adminLedger) {
      adminLedger.totalBalance += sendingFee;
      adminLedger.lastUpdated = new Date();
      await adminLedger.save();
    }

    await Promise.all([sender.save(), business.save(), admin.save()]);
    res.json({ message: 'Payment to business successful', sendingFee, amountReceived: paymentAmount });
  } catch (error) {
    console.error('Business Payment Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error during business payment' });
  }
});

// POST /api/payment-with-search
router.post('/payment-with-search', authenticateToken(), async (req, res) => {
  const { fromUsername, searchQuery, amount, pin } = req.body;

  if (!fromUsername || !searchQuery || !amount || !pin) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const sender = await User.findOne({ username: req.user.username });
    if (!sender || !sender.isActive) return res.status(403).json({ error: 'Sender not found or inactive' });
    if (sender.username !== fromUsername) return res.status(403).json({ error: 'Unauthorized sender' });
    if (sender.role === 'admin') return res.status(403).json({ error: 'Admins cannot send payments' });

    const receiver = await User.findOne({ $or: [{ username: searchQuery }, { phoneNumber: searchQuery }] });
    if (!receiver || !receiver.isActive) return res.status(403).json({ error: 'Recipient not found or inactive' });

    const qrPin = await QRPin.findOne({ username: receiver.username, pin });
    if (!qrPin) return res.status(400).json({ error: 'Invalid PIN or no active QR code' });

    const paymentAmount = parseFloat(amount);
    if (isNaN(paymentAmount) || paymentAmount <= 0 || paymentAmount > 10000) {
      return res.status(400).json({ error: 'Amount must be a positive number up to 10,000 ZMW' });
    }

    const sendingFee = getSendingFee(paymentAmount);
    const receivingFee = getReceivingFee(paymentAmount);
    const totalSenderDeduction = paymentAmount + sendingFee;

    if (sender.balance < totalSenderDeduction) {
      return res.status(400).json({ error: 'Insufficient balance to cover amount and sending fee' });
    }

    const admin = await User.findOne({ username: 'admin', role: 'admin' });
    if (!admin) return res.status(500).json({ error: 'Admin account not found' });

    sender.balance -= totalSenderDeduction;
    receiver.balance += paymentAmount - receivingFee;
    admin.balance += sendingFee + receivingFee;

    const txId = crypto.randomBytes(16).toString('hex');
    sender.transactions.push({ _id: txId, type: 'sent', amount: paymentAmount, toFrom: receiver.username, fee: sendingFee });
    receiver.transactions.push({ _id: crypto.randomBytes(16).toString('hex'), type: 'received', amount: paymentAmount, toFrom: fromUsername, fee: receivingFee });
    admin.transactions.push({
      _id: crypto.randomBytes(16).toString('hex'), type: 'fee-collected', amount: sendingFee + receivingFee,
      toFrom: `${fromUsername} -> ${receiver.username}`, originalAmount: paymentAmount, sendingFee, receivingFee,
    });

    const adminLedger = await AdminLedger.findOne();
    if (adminLedger) {
      adminLedger.totalBalance += sendingFee + receivingFee;
      adminLedger.lastUpdated = new Date();
      await adminLedger.save();
    }

    await QRPin.deleteOne({ _id: qrPin._id });
    await Promise.all([sender.save(), receiver.save(), admin.save()]);

    res.json({ message: 'Payment successful', sendingFee, receivingFee, amountReceived: paymentAmount - receivingFee });
  } catch (error) {
    console.error('Search Payment Error:', error.message);
    res.status(500).json({ error: 'Server error during payment' });
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
    console.error('User Update Error:', error.message);
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
    console.error('Delete Account Error:', error.message);
    res.status(500).json({ error: 'Server error deleting account' });
  }
});

// PUT /api/user/update-kyc
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
    console.error('KYC Update Error:', error.message);
    res.status(500).json({ error: 'Server error updating KYC status' });
  }
});

// PUT /api/business/update
router.put('/business/update', authenticateToken(['business']), async (req, res) => {
  const { name, ownerUsername } = req.body;
  if (!name && !ownerUsername) return res.status(400).json({ error: 'At least one field (name or ownerUsername) is required' });
  try {
    const business = await Business.findOne({ businessId: req.user.businessId });
    if (!business) return res.status(404).json({ error: 'Business not found' });
    if (name) business.name = name;
    if (ownerUsername && ownerUsername !== business.ownerUsername) {
      const existingBusiness = await Business.findOne({ ownerUsername });
      if (existingBusiness) return res.status(409).json({ error: 'Owner Username already taken' });
      business.ownerUsername = ownerUsername;
    }
    await business.save();
    res.json({ message: 'Business profile updated', business: { businessId: business.businessId, name: business.name, ownerUsername: business.ownerUsername } });
  } catch (error) {
    console.error('Business Update Error:', error.message);
    res.status(500).json({ error: 'Failed to update business profile' });
  }
});

// PUT /api/business/update-approval
router.put('/business/update-approval', authenticateToken(['admin']), async (req, res) => {
  const { businessId, approvalStatus } = req.body;
  if (!businessId || !approvalStatus || !['pending', 'approved', 'rejected'].includes(approvalStatus)) {
    return res.status(400).json({ error: 'Valid businessId and approvalStatus are required' });
  }
  try {
    const business = await Business.findOne({ businessId });
    if (!business) return res.status(404).json({ error: 'Business not found' });
    business.approvalStatus = approvalStatus;
    if (approvalStatus === 'approved') business.isActive = true;
    else if (approvalStatus === 'rejected') business.isActive = false;
    await business.save();
    res.json({ message: 'Business approval status updated' });
  } catch (error) {
    console.error('Business Approval Update Error:', error.message);
    res.status(500).json({ error: 'Server error updating business approval' });
  }
});

// PUT /api/user/toggle-active
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
    console.error('Toggle Active Error:', error.message);
    res.status(500).json({ error: 'Server error toggling user status' });
  }
});

// PUT /api/business/toggle-active
router.put('/business/toggle-active', authenticateToken(['admin']), async (req, res) => {
  const { businessId, isActive } = req.body;
  if (!businessId || typeof isActive !== 'boolean') return res.status(400).json({ error: 'Valid businessId and isActive status are required' });
  try {
    const business = await Business.findOne({ businessId });
    if (!business) return res.status(404).json({ error: 'Business not found' });
    if (business.approvalStatus !== 'approved') return res.status(400).json({ error: 'Business must be approved before toggling active status' });
    business.isActive = isActive;
    await business.save();
    res.json({ message: `Business ${isActive ? 'activated' : 'deactivated'}` });
  } catch (error) {
    console.error('Toggle Business Active Error:', error.message);
    res.status(500).json({ error: 'Server error toggling business status' });
  }
});

// PUT /api/business/set-role
router.put('/business/set-role', authenticateToken(['admin']), async (req, res) => {
  const { businessId, role } = req.body;
  if (!businessId || !['business', 'admin'].includes(role)) return res.status(400).json({ error: 'Valid businessId and role (business or admin) are required' });
  try {
    const business = await Business.findOne({ businessId });
    if (!business) return res.status(404).json({ error: 'Business not found' });
    business.role = role;
    await business.save();
    res.json({ message: `Business ${businessId} role set to ${role}` });
  } catch (error) {
    console.error('Set Business Role Error:', error.message);
    res.status(500).json({ error: 'Failed to set business role' });
  }
});

// POST /api/business/regenerate-qr
router.post('/business/regenerate-qr', authenticateToken(['business']), upload.single('qrCode'), async (req, res) => {
  const qrCodeImage = req.file;
  if (!qrCodeImage) return res.status(400).json({ error: 'New QR code image is required' });
  try {
    const business = await Business.findOne({ businessId: req.user.businessId });
    if (!business || !business.isActive) return res.status(403).json({ error: 'Business not found or inactive' });
    const fileStream = fs.createReadStream(qrCodeImage.path);
    const s3Key = `qr-codes/${Date.now()}-${qrCodeImage.originalname}`;
    const params = { Bucket: S3_BUCKET, Key: s3Key, Body: fileStream, ContentType: qrCodeImage.mimetype, ACL: 'private' };
    const s3Response = await s3.upload(params).promise();
    business.qrCode = s3Response.Location;
    fs.unlinkSync(qrCodeImage.path);
    await business.save();
    res.json({ qrCode: business.qrCode });
  } catch (error) {
    console.error('QR Regeneration Error:', error.message);
    res.status(500).json({ error: 'Failed to regenerate QR code' });
  }
});

// POST /api/admin/verify-business-withdrawal
router.post('/admin/verify-business-withdrawal', authenticateToken(['admin']), async (req, res) => {
  const { businessId, withdrawalIndex, approved } = req.body;
  try {
    const business = await Business.findOne({ businessId });
    if (!business) return res.status(404).json({ error: 'Business not found' });
    const withdrawal = business.pendingWithdrawals[withdrawalIndex];
    if (!withdrawal || withdrawal.status !== 'pending') return res.status(400).json({ error: 'Invalid or already processed withdrawal' });
    const admin = await User.findOne({ role: 'admin' });
    if (!admin) return res.status(500).json({ error: 'Admin account not found' });
    if (approved) {
      const totalDeduction = withdrawal.amount + withdrawal.fee;
      if (business.balance < totalDeduction) return res.status(400).json({ error: 'Insufficient balance' });
      business.balance -= totalDeduction;
      admin.balance += withdrawal.fee;
      business.transactions.push({
        _id: crypto.randomBytes(16).toString('hex'), type: 'withdrawn', amount: withdrawal.amount,
        toFrom: 'manual-mobile-money', fee: withdrawal.fee, date: new Date(),
      });
      admin.transactions.push({
        _id: crypto.randomBytes(16).toString('hex'), type: 'fee-collected', amount: withdrawal.fee,
        toFrom: `Withdrawal from ${business.businessId}`, date: new Date(),
      });
      withdrawal.status = 'completed';
    } else {
      withdrawal.status = 'rejected';
    }
    await Promise.all([business.save(), admin.save()]);
    if (business.pushToken) {
      await sendPushNotification(business.pushToken, `Withdrawal ${approved ? 'Approved' : 'Rejected'}`, 
        approved ? `Your withdrawal of ${withdrawal.amount.toFixed(2)} ZMW has been approved` : `Your withdrawal of ${withdrawal.amount.toFixed(2)} ZMW was rejected`, 
        { businessId, withdrawalIndex });
    }
    res.json({ message: `Business withdrawal ${approved ? 'completed' : 'rejected'}` });
  } catch (error) {
    console.error('Verify Business Withdrawal Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to verify business withdrawal' });
  }
});

// GET /api/users
router.get('/users', authenticateToken(['admin']), async (req, res) => {
  const { page = 1, limit = 10, search = '' } = req.query;
  const skip = (page - 1) * limit;
  const query = search ? {
    $or: [
      { username: { $regex: search, $options: 'i' } },
      { phoneNumber: { $regex: search, $options: 'i' } },
      { email: { $regex: search, $options: 'i' } },
      { name: { $regex: search, $options: 'i' } },
    ],
  } : {};
  try {
    const users = await User.find(query).skip(skip).limit(parseInt(limit));
    const total = await User.countDocuments(query);
    res.json({ users, total });
  } catch (error) {
    console.error('Users Fetch Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// GET /api/businesses
router.get('/businesses', authenticateToken(['admin']), async (req, res) => {
  const { page = 1, limit = 10, search = '' } = req.query;
  const skip = (page - 1) * limit;
  const query = search ? {
    $or: [
      { businessId: { $regex: search, $options: 'i' } },
      { name: { $regex: search, $options: 'i' } },
      { ownerUsername: { $regex: search, $options: 'i' } },
    ],
  } : {};
  try {
    const businesses = await Business.find(query).skip(skip).limit(parseInt(limit));
    const total = await Business.countDocuments(query);
    res.json({ businesses, total });
  } catch (error) {
    console.error('Businesses Fetch Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch businesses' });
  }
});

// POST /api/credit
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
    console.error('Credit Error:', error.message);
    res.status(500).json({ error: 'Server error during credit' });
  }
});

// POST /api/payment-with-pin
router.post('/payment-with-pin', authenticateToken(['admin']), async (req, res) => {
  const { fromUsername, toUsername, amount, pin } = req.body;
  try {
    const sender = await User.findOne({ username: req.user.username });
    if (!sender || !sender.isActive) return res.status(403).json({ error: 'Sender not found or inactive' });
    if (sender.username !== fromUsername) return res.status(403).json({ error: 'Unauthorized sender' });
    const receiver = await User.findOne({ username: toUsername });
    if (!receiver || !receiver.isActive) return res.status(403).json({ error: 'Recipient not found or inactive' });
    const qrPin = await QRPin.findOne({ username: toUsername, pin });
    if (!qrPin) return res.status(400).json({ error: 'Invalid PIN' });
    const paymentAmount = parseFloat(amount);
    if (isNaN(paymentAmount) || paymentAmount <= 0) {
      return res.status(400).json({ error: 'Amount must be a positive number' });
    }
    if (sender.balance < paymentAmount) return res.status(400).json({ error: 'Insufficient balance' });
    sender.balance -= paymentAmount;
    receiver.balance += paymentAmount;
    sender.transactions.push({ _id: crypto.randomBytes(16).toString('hex'), type: 'sent', amount: paymentAmount, toFrom: toUsername });
    receiver.transactions.push({ _id: crypto.randomBytes(16).toString('hex'), type: 'received', amount: paymentAmount, toFrom: fromUsername });
    await QRPin.deleteOne({ _id: qrPin._id });
    await Promise.all([sender.save(), receiver.save()]);
    res.json({ message: 'Payment successful' });
  } catch (error) {
    console.error('Payment with PIN Error:', error.message);
    res.status(500).json({ error: 'Server error during payment' });
  }
});

// GET /api/transactions/:username
router.get('/transactions/:username', authenticateToken(['admin']), async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user.transactions);
  } catch (error) {
    console.error('Transactions Fetch Error:', error.message);
    res.status(500).json({ error: 'Server error fetching transactions' });
  }
});

// GET /api/admin/stats
router.get('/admin/stats', authenticateToken(['admin']), async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalUserBalance = await User.aggregate([{ $group: { _id: null, total: { $sum: { $ifNull: ['$balance', 0] } } } }]).then(r => r[0]?.total || 0);
    const recentUserTxCount = await User.aggregate([
      { $unwind: { path: '$transactions', preserveNullAndEmptyArrays: true } },
      { $match: { 'transactions.date': { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } } },
      { $count: 'recentTxCount' },
    ]).then(r => r[0]?.recentTxCount || 0);
    const pendingUserDepositsCount = await User.aggregate([
      { $unwind: { path: '$pendingDeposits', preserveNullAndEmptyArrays: true } },
      { $match: { 'pendingDeposits.status': 'pending' } },
      { $count: 'pendingDepositsCount' },
    ]).then(r => r[0]?.pendingDepositsCount || 0);
    const pendingUserWithdrawalsCount = await User.aggregate([
      { $unwind: { path: '$pendingWithdrawals', preserveNullAndEmptyArrays: true } },
      { $match: { 'pendingWithdrawals.status': 'pending' } },
      { $count: 'pendingWithdrawalsCount' },
    ]).then(r => r[0]?.pendingWithdrawalsCount || 0);

    const totalBusinesses = await Business.countDocuments();
    const totalBusinessBalance = await Business.aggregate([{ $group: { _id: null, total: { $sum: { $ifNull: ['$balance', 0] } } } }]).then(r => r[0]?.total || 0);
    const recentBusinessTxCount = await Business.aggregate([
      { $unwind: { path: '$transactions', preserveNullAndEmptyArrays: true } },
      { $match: { 'transactions.date': { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } } },
      { $count: 'recentTxCount' },
    ]).then(r => r[0]?.recentTxCount || 0);
    const pendingBusinessDepositsCount = await Business.aggregate([
      { $unwind: { path: '$pendingDeposits', preserveNullAndEmptyArrays: true } },
      { $match: { 'pendingDeposits.status': 'pending' } },
      { $count: 'pendingDepositsCount' },
    ]).then(r => r[0]?.pendingDepositsCount || 0);
    const pendingBusinessWithdrawalsCount = await Business.aggregate([
      { $unwind: { path: '$pendingWithdrawals', preserveNullAndEmptyArrays: true } },
      { $match: { 'pendingWithdrawals.status': 'pending' } },
      { $count: 'pendingWithdrawalsCount' },
    ]).then(r => r[0]?.pendingWithdrawalsCount || 0);

    const totalBalance = totalUserBalance + totalBusinessBalance;
    const recentTxCount = recentUserTxCount + recentBusinessTxCount;

    res.json({
      totalUsers, totalUserBalance, pendingUserDepositsCount, pendingUserWithdrawalsCount,
      totalBusinesses, totalBusinessBalance, pendingBusinessDepositsCount, pendingBusinessWithdrawalsCount,
      totalBalance, recentTxCount,
    });
  } catch (error) {
    console.error('Stats Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to fetch stats', details: error.message });
  }
});

// GET /api/admin/pending
router.get('/admin/pending', authenticateToken(['admin']), async (req, res) => {
  try {
    const pendingUsers = await User.countDocuments({ kycStatus: 'pending' });
    const pendingBusinesses = await Business.countDocuments({ approvalStatus: 'pending' });
    const pendingUserDeposits = await User.aggregate([
      { $unwind: '$pendingDeposits' },
      { $match: { 'pendingDeposits.status': 'pending' } },
      { $count: 'count' },
    ]).then(r => r[0]?.count || 0);
    const pendingUserWithdrawals = await User.aggregate([
      { $unwind: '$pendingWithdrawals' },
      { $match: { 'pendingWithdrawals.status': 'pending' } },
      { $count: 'count' },
    ]).then(r => r[0]?.count || 0);
    const pendingBusinessDeposits = await Business.aggregate([
      { $unwind: '$pendingDeposits' },
      { $match: { 'pendingDeposits.status': 'pending' } },
      { $count: 'count' },
    ]).then(r => r[0]?.count || 0);
    res.json({ users: pendingUsers, businesses: pendingBusinesses, userDeposits: pendingUserDeposits, userWithdrawals: pendingUserWithdrawals, businessDeposits: pendingBusinessDeposits });
  } catch (error) {
    console.error('Pending Stats Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch pending stats' });
  }
});

// GET /api/admin/pending-deposits
router.get('/admin/pending-deposits', authenticateToken(['admin']), async (req, res) => {
  try {
    const userDeposits = await User.find({ 'pendingDeposits.status': 'pending' })
      .flatMap(user => user.pendingDeposits
        .filter(d => d.status === 'pending')
        .map(d => ({ userId: user._id, user: { username: user.username }, ...d.toObject() })));
    const businessDeposits = await Business.find({ 'pendingDeposits.status': 'pending' })
      .flatMap(business => business.pendingDeposits
        .filter(d => d.status === 'pending')
        .map(d => ({ businessId: business.businessId, business: { name: business.name }, ...d.toObject() })));
    res.json({ userDeposits, businessDeposits });
  } catch (error) {
    console.error('Pending Deposits Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch pending deposits' });
  }
});

// GET /api/admin/pending-withdrawals
router.get('/api/admin/pending-withdrawals', authenticateToken(['admin']), async (req, res) => {
  try {
    const userWithdrawals = await User.find({ 'pendingWithdrawals.status': 'pending' })
      .flatMap((user, uIndex) => user.pendingWithdrawals
        .map((w, wIndex) => ({ userId: user._id, user: { username: user.username }, ...w.toObject(), index: wIndex }))
        .filter(w => w.status === 'pending'));
    const businessWithdrawals = await Business.find({ 'pendingWithdrawals.status': 'pending' })
      .flatMap((business, bIndex) => business.pendingWithdrawals
        .map((w, wIndex) => ({ businessId: business.businessId, business: { name: business.name }, ...w.toObject(), index: wIndex }))
        .filter(w => w.status === 'pending'));
    res.json({ userWithdrawals, businessWithdrawals });
  } catch (error) {
    console.error('Pending Withdrawals Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch pending withdrawals' });
  }
});

// GET /api/user
router.get('/user', authenticateToken(), async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username })
      .select('username name phoneNumber email kycStatus zambiaCoinBalance trustScore transactions');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      username: user.username, name: user.name, phoneNumber: user.phoneNumber, email: user.email,
      kycStatus: user.kycStatus, zambiaCoinBalance: user.zambiaCoinBalance, trustScore: user.trustScore,
      transactions: user.transactions,
    });
  } catch (error) {
    console.error('ZambiaCoin User Fetch Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch user data' });
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
    console.error('ZMC Transfer Error:', error.message);
    res.status(500).json({ error: 'Transfer failed' });
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
    console.error('QR Generation Error:', error.message);
    res.status(500).json({ error: 'Failed to validate PIN' });
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
    console.error('Rating Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to submit rating', details: error.message });
  }
});

// POST /api/airdrop
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
    console.error('ZMC Airdrop Error:', error.message);
    res.status(500).json({ error: 'Airdrop failed' });
  }
});

// POST /api/credit-zmc
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
    console.error('Credit ZMC Error:', error.message);
    res.status(500).json({ error: 'Failed to credit ZMC' });
  }
});

module.exports = router;