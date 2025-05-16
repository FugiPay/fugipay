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

// Ensure indexes
User.createIndexes({ username: 1, phoneNumber: 1 });
QRPin.createIndexes({ qrId: 1 });

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

// Function to send push notifications
async function sendPushNotification(pushToken, title, body, data = {}) {
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

// Get all users
router.get('/', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '' } = req.query;
    const skip = (Number(page) - 1) * Number(limit);
    const query = search
      ? {
          $or: [
            { username: { $regex: search, $options: 'i' } },
            { phoneNumber: { $regex: search, $options: 'i' } },
            { email: { $regex: search, $options: 'i' } },
          ],
        }
      : {};
    const [users, total] = await Promise.all([
      User.find(query)
        .select('username phoneNumber balance kycStatus trustScore pendingDeposits pendingWithdrawals transactions')
        .skip(skip)
        .limit(Number(limit))
        .lean(),
      User.countDocuments(query),
    ]);
    res.json({ users, total, page: Number(page), limit: Number(limit) });
  } catch (error) {
    console.error('Fetch Users Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Update KYC status
router.post('/update-kyc', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { id, kycStatus } = req.body;
  if (!id || !['pending', 'verified', 'rejected'].includes(kycStatus)) {
    return res.status(400).json({ error: 'Invalid user ID or KYC status' });
  }
  try {
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    user.kycStatus = kycStatus;
    await user.save();
    res.json({ message: 'KYC status updated' });
  } catch (error) {
    console.error('Update KYC Error:', error.message);
    res.status(500).json({ error: 'Failed to update KYC status' });
  }
});

// Register
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
    const existingUser = await User.findOne({ $or: [{ username }, { email }, { phoneNumber }] }).lean();
    if (existingUser) {
      return res.status(400).json({ error: 'Username, email, or phone number already exists' });
    }
    const fileStream = fs.createReadStream(idImage.path);
    const s3Key = `id-images/${username}-${Date.now()}-${idImage.originalname}`;
    const params = { Bucket: S3_BUCKET, Key: s3Key, Body: fileStream, ContentType: idImage.mimetype, ACL: 'private' };
    const s3Response = await s3.upload(params).promise();
    const idImageUrl = s3Response.Location;
    fs.unlinkSync(idImage.path);
    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedPin = await bcrypt.hash(pin, 10);
    const user = new User({
      username: username.trim(),
      name: name.trim(),
      phoneNumber,
      email,
      password: hashedPassword,
      pin: hashedPin,
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
    const token = jwt.sign({ phoneNumber: user.phoneNumber, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(admin.pushToken, 'New User Registration', `User ${username} needs KYC approval.`, { userId: user._id });
    }
    res.status(201).json({ token, username: user.username, role: user.role, kycStatus: user.kycStatus });
  } catch (error) {
    console.error('Register Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error during registration', details: error.message });
  }
});

// Login
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
    console.error('Login Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error during login', details: error.message });
  }
});

// Forgot Password
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

// Reset Password
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

// Get User by Username
router.get('/user/:username', authenticateToken(), async (req, res) => {
  const start = Date.now();
  console.log(`[${req.method}] ${req.path} - Starting fetch for ${req.params.username}`);
  const timeout = setTimeout(() => {
    console.error(`[${req.method}] ${req.path} - Request timed out after 25s`);
    res.status(503).json({ error: 'Request timed out', duration: `${Date.now() - start}ms` });
  }, 25000);
  try {
    await mongoose.connection.db.admin().ping();
    const user = await User.findOne(
      { username: req.params.username },
      { username: 1, name: 1, phoneNumber: 1, email: 1, balance: 1, zambiaCoinBalance: 1, trustScore: 1, transactions: { $slice: -10 }, kycStatus: 1, isActive: 1, pendingDeposits: 1, pendingWithdrawals: 1 }
    ).lean().exec();
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
      pendingDeposits: user.pendingDeposits, pendingWithdrawals: user.pendingWithdrawals
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

// Get User by Phone Number
router.get('/phone/:phoneNumber', authenticateToken(), async (req, res, next) => {
  try {
    const { phoneNumber } = req.params;
    const { limit = 10, skip = 0 } = req.query;
    if (req.user.phoneNumber !== phoneNumber && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const user = await User.findOne({ phoneNumber })
      .select('phoneNumber username email name balance zambiaCoinBalance trustScore kycStatus role lastViewedTimestamp pendingDeposits pendingWithdrawals transactions')
      .slice('transactions', [Number(skip), Number(limit)])
      .lean()
      .exec();
    if (!user) return res.status(404).json({ error: 'User not found' });
    // Convert Decimal128 fields
    const convertedUser = {
      ...user,
      balance: user.balance?.$numberDecimal ? parseSensei.parseFloat(user.balance.$numberDecimal) : user.balance || 0,
      zambiaCoinBalance: user.zambiaCoinBalance?.$numberDecimal ? parseFloat(user.zambiaCoinBalance.$numberDecimal) : user.zambiaCoinBalance || 0,
      trustScore: user.trustScore?.$numberDecimal ? parseFloat(user.trustScore.$numberDecimal) : user.trustScore || 0,
      transactions: user.transactions?.map(tx => ({
        ...tx,
        amount: tx.amount?.$numberDecimal ? parseFloat(tx.amount.$numberDecimal) : tx.amount || 0,
        fee: tx.fee?.$numberDecimal ? parseFloat(tx.fee.$numberDecimal) : tx.fee || 0,
      })) || [],
      pendingDeposits: user.pendingDeposits?.map(dep => ({
        ...dep,
        amount: dep.amount?.$numberDecimal ? parseFloat(dep.amount.$numberDecimal) : dep.amount || 0,
      })) || [],
      pendingWithdrawals: user.pendingWithdrawals?.map(wd => ({
        ...wd,
        amount: wd.amount?.$numberDecimal ? parseFloat(wd.amount.$numberDecimal) : wd.amount || 0,
      })) || [],
    };
    res.json({
      phoneNumber: convertedUser.phoneNumber,
      username: convertedUser.username,
      email: convertedUser.email || '',
      name: convertedUser.name || '',
      balance: convertedUser.balance,
      zambiaCoinBalance: convertedUser.zambiaCoinBalance,
      trustScore: convertedUser.trustScore,
      transactions: convertedUser.transactions,
      kycStatus: convertedUser.kycStatus || 'rejected',
      role: convertedUser.role || 'user',
      lastViewedTimestamp: convertedUser.lastViewedTimestamp || 0,
      pendingDeposits: convertedUser.pendingDeposits,
      pendingWithdrawals: convertedUser.pendingWithdrawals,
    });
  } catch (error) {
    console.error('[USER] Error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get User by Phone Number (Alternative)
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
      pendingDeposits: user.pendingDeposits,
      pendingWithdrawals: user.pendingWithdrawals
    });
  } catch (error) {
    console.error('[USER] Error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update Notification Timestamp
router.put('/user/update-notification', authenticateToken(), async (req, res) => {
  try {
    const { phoneNumber, lastViewedTimestamp } = req.body;
    if (!phoneNumber || typeof lastViewedTimestamp !== 'number') {
      return res.status(400).json({ error: 'Invalid phoneNumber or timestamp' });
    }
    if (phoneNumber !== req.user.phoneNumber) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const user = await User.findOneAndUpdate(
      { phoneNumber },
      { lastViewedTimestamp },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'Notification timestamp updated' });
  } catch (error) {
    console.error('[USER] Update Notification Error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Store QR PIN
router.post('/store-qr-pin', authenticateToken(), async (req, res) => {
  const { username, pin } = req.body;
  if (!username || !pin) {
    return res.status(400).json({ error: 'Username and PIN are required' });
  }
  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'PIN must be a 4-digit number' });
  }
  try {
    const qrId = crypto.randomBytes(16).toString('hex');
    const session = await mongoose.startSession();
    session.startTransaction({ writeConcern: { w: 'majority' } });
    try {
      const user = await User.findOneAndUpdate(
        { username: req.user.username, isActive: true },
        {
          $push: {
            transactions: {
              type: 'pending-pin',
              amount: 0,
              toFrom: 'Self',
              date: new Date(),
              qrId,
            },
          },
        },
        { new: true, session }
      );
      if (!user) {
        await session.abortTransaction();
        session.endSession();
        console.error('QR Pin Store: User not found or inactive', { username: req.user.username });
        return res.status(404).json({ error: 'User not found or inactive' });
      }
      if (username !== user.username) {
        await session.abortTransaction();
        session.endSession();
        console.error('QR Pin Store: Unauthorized', { requested: username, actual: user.username });
        return res.status(403).json({ error: 'Unauthorized' });
      }
      await new QRPin({ username, qrId, pin }).save({ session });
      await session.commitTransaction();
      session.endSession();
      console.log('QR Pin Store: Success', { username, qrId });
      res.json({ qrId });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      throw error;
    }
  } catch (error) {
    console.error('QR Pin Store Error:', {
      message: error.message,
      stack: error.stack,
      username,
      pinLength: pin?.length,
    });
    res.status(500).json({ error: 'Server error storing QR pin' });
  }
});

// Pay QR
router.post('/pay-qr', authenticateToken(), async (req, res) => {
  const { qrId, amount, pin, senderUsername } = req.body;
  if (!qrId || !amount || !pin || !senderUsername) {
    return res.status(400).json({ error: 'QR ID, amount, PIN, and sender username required' });
  }
  if (amount <= 0 || amount > 10000) {
    return res.status(400).json({ error: 'Amount must be between 0 and 10,000 ZMW' });
  }
  const session = await mongoose.startSession();
  session.startTransaction({ writeConcern: { w: 'majority' } });
  try {
    const sender = await User.findOne({ username: senderUsername, isActive: true }).session(session);
    if (!sender || sender.username !== req.user.username) {
      await session.abortTransaction();
      session.endSession();
      return res.status(403).json({ error: 'Unauthorized sender' });
    }
    const qrPin = await QRPin.findOne({ qrId }).session(session);
    if (!qrPin || qrPin.pin !== pin) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ error: 'Invalid QR code or PIN' });
    }
    const receiver = await User.findOne({ username: qrPin.username, isActive: true }).session(session);
    if (!receiver) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ error: 'Receiver not found or inactive' });
    }
    const sendingFee = amount <= 50 ? 0.50 : 
                      amount <= 100 ? 1.00 : 
                      amount <= 500 ? 2.00 :
                      amount <= 1000 ? 2.50 : 
                      amount <= 5000 ? 3.50 : 5.00;
    const receivingFee = amount <= 50 ? 0.50 : 
                        amount <= 100 ? 1.00 : 
                        amount <= 500 ? 1.50 :
                        amount <= 1000 ? 2.00 : 
                        amount <= 5000 ? 3.00 : 5.00;
    if (sender.balance < amount + sendingFee) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    const sentTxId = new mongoose.Types.ObjectId().toString();
    const receivedTxId = new mongoose.Types.ObjectId().toString();
    const transactionDate = new Date();

    // Batch User updates
    await User.bulkWrite([
      {
        updateOne: {
          filter: { _id: sender._id },
          update: {
            $inc: { balance: -(amount + sendingFee) },
            $push: {
              transactions: {
                _id: sentTxId,
                type: 'sent',
                amount,
                toFrom: receiver.username,
                fee: sendingFee,
                date: transactionDate,
                qrId,
              },
            },
          },
        },
      },
      {
        updateOne: {
          filter: { _id: receiver._id },
          update: {
            $inc: { balance: amount - receivingFee },
            $push: {
              transactions: {
                _id: receivedTxId,
                type: 'received',
                amount,
                toFrom: sender.username,
                fee: receivingFee,
                date: transactionDate,
                qrId,
              },
            },
          },
        },
      },
    ], { session });

    // Delete QRPin and update AdminLedger
    const updates = Promise.all([
      QRPin.deleteOne({ qrId }, { session }),
      AdminLedger.updateOne(
        {},
        {
          $inc: { totalBalance: sendingFee + receivingFee },
          $set: { lastUpdated: new Date() },
          $push: {
            transactions: {
              type: 'fee-collected',
              amount: sendingFee + receivingFee,
              sender: sender.username,
              receiver: receiver.username,
              userTransactionIds: [sentTxId, receivedTxId],
              date: transactionDate,
              qrId,
            },
          },
        },
        { upsert: true, session }
      ),
    ]);

    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('Transaction update timeout')), 15000);
    });
    await Promise.race([updates, timeoutPromise]);

    await session.commitTransaction();
    session.endSession();
    console.log('[PAY-QR] Transaction:', {
      amount,
      sendingFee,
      receivingFee,
      sender: sender.username,
      receiver: receiver.username,
      qrId,
      transactionDate,
    });
    res.json({ sendingFee, receivingFee, amount });
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    console.error('[PAY-QR] Error:', {
      message: error.message,
      stack: error.stack,
      qrId,
      senderUsername,
      amount,
    });
    res.status(500).json({ error: error.message === 'Transaction update timeout' ? 'Transaction timed out' : 'Server error processing payment' });
  }
});

// Manual Deposit
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

// Withdraw Request
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

// Withdraw (Direct)
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

// Save Push Token
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
    console.error('Save Push Token Error:', error.message);
    res.status(500).json({ error: 'Failed to save push token' });
  }
});

// Update Profile
router.put('/user/update', authenticateToken(['user']), async (req, res) => {
  try {
    const { email, password, pin } = req.body;
    const updates = {};

    if (email) {
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        console.log('[USER] Invalid email format:', email);
        return res.status(400).json({ error: 'Invalid email format' });
      }
      const existingUser = await User.findOne({ email });
      if (existingUser && existingUser.phoneNumber !== req.user.phoneNumber) {
        console.log('[USER] Email already exists:', email);
        return res.status(409).json({ error: 'Email already exists' });
      }
      updates.email = email;
    }

    if (password) {
      if (password.length < 6) {
        console.log('[USER] Password too short:', password.length);
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
      }
      updates.password = await bcrypt.hash(password, 10);
    }

    if (pin) {
      if (pin.length !== 4 || !/^\d{4}$/.test(pin)) {
        console.log('[USER] Invalid PIN:', pin);
        return res.status(400).json({ error: 'PIN must be exactly 4 digits' });
      }
      updates.pin = pin;
    }

    if (!Object.keys(updates).length) {
      console.log('[USER] No fields to update');
      return res.status(400).json({ error: 'No fields to update' });
    }

    console.log('[USER] Updating user:', { phoneNumber: req.user.phoneNumber, updates });
    const user = await User.findOneAndUpdate(
      { phoneNumber: req.user.phoneNumber },
      { $set: updates },
      { new: true, runValidators: true }
    ).select('-password -pin');

    if (!user) {
      console.error('[USER] User not found:', req.user.phoneNumber);
      return res.status(404).json({ error: 'User not found' });
    }

    const token = jwt.sign(
      { _id: user._id, phoneNumber: user.phoneNumber, role: user.role || 'user' },
      process.env.JWT_SECRET || 'Zangena123$@2025',
      { expiresIn: '1h' }
    );

    console.log('[USER] Profile updated:', { phoneNumber: user.phoneNumber, updatedFields: Object.keys(updates) });
    res.json({ message: 'Profile updated', user, token });
  } catch (error) {
    console.error('[USER] Update Error:', {
      message: error.message,
      code: error.code,
      name: error.name,
      stack: error.stack,
    });
    if (error.code === 11000) {
      return res.status(409).json({ error: 'Email already exists' });
    }
    if (error.name === 'ValidationError') {
      return res.status(400).json({ error: 'Invalid input' });
    }
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete User
router.delete('/user/delete', authenticateToken(['user']), async (req, res) => {
  try {
    const user = await User.findOneAndDelete({ phoneNumber: req.user.phoneNumber });
    if (!user) {
      console.error('[USER] User not found:', req.user.phoneNumber);
      return res.status(404).json({ error: 'User not found' });
    }
    await QRPin.deleteMany({ phoneNumber: user.phoneNumber });
    console.log('[USER] Account deleted:', req.user.phoneNumber);
    res.json({ message: 'Account deleted' });
  } catch (error) {
    console.error('[USER] Delete Error:', {
      message: error.message,
      stack: error.stack,
    });
    res.status(500).json({ error: 'Server error deleting account' });
  }
});

// Refresh Token
router.post('/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    console.log('[USER] Refresh token missing');
    return res.status(400).json({ error: 'Refresh token is required', code: 'MISSING_REFRESH_TOKEN' });
  }
  try {
    const user = await User.findOne({ refreshToken });
    if (!user) {
      console.log('[USER] Invalid refresh token');
      return res.status(403).json({ error: 'Invalid refresh token', code: 'INVALID_REFRESH_TOKEN' });
    }
    try {
      jwt.verify(refreshToken, process.env.JWT_SECRET || 'Zangena123$@2025');
    } catch (error) {
      console.log('[USER] Invalid or expired refresh token');
      return res.status(403).json({ error: 'Invalid or expired refresh token', code: 'INVALID_REFRESH_TOKEN' });
    }
    const accessToken = jwt.sign(
      { phoneNumber: user.phoneNumber, role: user.role || 'user' },
      process.env.JWT_SECRET || 'Zangena123$@2025',
      { expiresIn: '1h' }
    );
    const newRefreshToken = jwt.sign(
      { phoneNumber: user.phoneNumber, role: user.role || 'user' },
      process.env.JWT_SECRET || 'Zangena123$@2025',
      { expiresIn: '7d' }
    );
    await User.updateOne({ _id: user._id }, { $set: { refreshToken: newRefreshToken } });
    console.log('[USER] Refresh Token Success:', { phoneNumber: user.phoneNumber });
    res.json({
      accessToken,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    console.error('[USER] Refresh Token Error:', {
      message: error.message,
      stack: error.stack,
      refreshToken: refreshToken ? 'provided' : 'missing',
    });
    res.status(500).json({ error: 'Server error refreshing token', code: 'SERVER_ERROR' });
  }
});

// Update Timestamp
router.patch('/update-timestamp', authenticateToken(), async (req, res, next) => {
  try {
    const { phoneNumber, lastViewedTimestamp } = req.body;
    if (!phoneNumber || !lastViewedTimestamp) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    if (req.user.phoneNumber !== phoneNumber) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const user = await User.findOneAndUpdate(
      { phoneNumber },
      { lastViewedTimestamp },
      { new: true, lean: true }
    );
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({
      user: {
        ...user,
        balance: user.balance?.$numberDecimal ? parseFloat(user.balance.$numberDecimal) : user.balance || 0,
        zambiaCoinBalance: user.zambiaCoinBalance?.$numberDecimal ? parseFloat(user.zambiaCoinBalance.$numberDecimal) : user.zambiaCoinBalance || 0,
        trustScore: user.trustScore?.$numberDecimal ? parseFloat(user.trustScore.$numberDecimal) : user.trustScore || 0,
        transactions: user.transactions?.map(tx => ({
          ...tx,
          amount: tx.amount?.$numberDecimal ? parseFloat(tx.amount.$numberDecimal) : tx.amount || 0,
          fee: tx.fee?.$numberDecimal ? parseFloat(tx.fee.$numberDecimal) : tx.fee || 0,
        })) || [],
        pendingDeposits: user.pendingDeposits?.map(dep => ({
          ...dep,
          amount: dep.amount?.$numberDecimal ? parseFloat(dep.amount.$numberDecimal) : dep.amount || 0,
        })) || [],
        pendingWithdrawals: user.pendingWithdrawals?.map(wd => ({
          ...wd,
          amount: wd.amount?.$numberDecimal ? parseFloat(wd.amount.$numberDecimal) : wd.amount || 0,
        })) || [],
      },
    });
  } catch (error) {
    console.error('[USER] Error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

router.put('/toggle-active', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: 'Username required' });
  }
  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    user.isActive = !user.isActive;
    await user.save();
    res.json({ message: `User ${username} is now ${user.isActive ? 'active' : 'inactive'}` });
  } catch (error) {
    console.error('Toggle Active Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to toggle user status' });
  }
});

router.get('/transactions/:username', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { username } = req.params;
  const { startDate, endDate, limit = 50, skip = 0 } = req.query;
  try {
    const query = { username };
    const transactionQuery = {};
    if (startDate || endDate) {
      transactionQuery.date = {};
      if (startDate) transactionQuery.date.$gte = new Date(startDate);
      if (endDate) transactionQuery.date.$lte = new Date(endDate);
    }
    const user = await User.findOne(query).lean();
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const transactions = user.transactions
      .filter(tx => {
        if (startDate && new Date(tx.date) < new Date(startDate)) return false;
        if (endDate && new Date(tx.date) > new Date(endDate)) return false;
        return true;
      })
      .slice(Number(skip), Number(skip) + Number(limit))
      .map(tx => ({
        _id: tx._id,
        type: tx.type,
        amount: tx.amount,
        toFrom: tx.toFrom,
        fee: tx.fee,
        date: tx.date,
      }));
    res.json({ transactions, total: user.transactions.length });
  } catch (error) {
    console.error('Fetch Transactions Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

module.exports = router;