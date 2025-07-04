const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const fs = require('fs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const axios = require('axios');
const User = require('../models/User');
const QRPin = require('../models/QRPin');
const Business = require('../models/Business');
const AdminLedger = require('../models/AdminLedger');
const authenticateToken = require('../middleware/authenticateToken');
const { generalRateLimiter, strictRateLimiter, validate, registerValidation, loginValidation, payQrValidation, updateProfileValidation } = require('../middleware/securityMiddleware');

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'Zangena123$@2025';
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const S3_BUCKET = process.env.S3_BUCKET || 'zangena';
const EMAIL_USER = process.env.EMAIL_USER || 'your_email@example.com';
const EMAIL_PASS = process.env.EMAIL_PASS || 'your_email_password';

// Configure AWS S3
const s3 = new S3Client({
  region: AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

// Configure Multer with memory storage
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error('Only images (JPEG, PNG, GIF) or PDFs are allowed'));
    }
    cb(null, true);
  },
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
});

// Multer error handling middleware
const handleMulterError = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    console.error('[Multer] Error:', {
      message: err.message,
      code: err.code,
      endpoint: req.originalUrl,
    });
    return res.status(400).json({ error: 'File upload error', details: err.message });
  }
  if (err.message === 'Only images (JPEG, PNG, GIF) or PDFs are allowed') {
    console.error('[Multer] Invalid file type:', err.message);
    return res.status(400).json({ error: 'Invalid file type', details: err.message });
  }
  next(err);
};

// Configure Nodemailer with Gmail
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS,
  },
});

// Ensure indexes with error handling
const ensureIndexes = async () => {
  try {
    await User.createIndexes({ username: 1, phoneNumber: 1 });
    await QRPin.createIndexes({ qrId: 1 });
    console.log('[Indexes] Successfully ensured indexes for User and QRPin');
  } catch (error) {
    console.error('[Indexes] Error creating indexes:', {
      message: error.message,
      code: error.code,
      codeName: error.codeName,
    });
    if (error.code !== 85) throw error;
  }
};
ensureIndexes();

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
    console.log(`[Push] Sent to ${pushToken}: ${title} - ${body}`);
  } catch (error) {
    console.error('[Push] Error:', error.message);
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
    console.error('[Admin] Error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
};

// Setup 2FA
router.post('/setup-2fa', authenticateToken(), strictRateLimiter, async (req, res) => {
  const { phoneNumber } = req.body;
  try {
    const user = await User.findOne({ phoneNumber, username: req.user.username });
    if (!user || !user.isActive) {
      return res.status(403).json({ error: 'User not found or inactive' });
    }
    if (user.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA already enabled' });
    }
    const secret = speakeasy.generateSecret({
      length: 20,
      name: `Zangena:${user.username}`,
      issuer: 'Zangena',
    });
    user.twoFactorSecret = secret.base32;
    await user.save();
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
    res.json({ qrCodeUrl, secret: secret.base32 });
  } catch (error) {
    console.error('[Setup2FA] Error:', error.message);
    res.status(500).json({ error: 'Failed to setup 2FA' });
  }
});

// Verify 2FA
router.post('/verify-2fa', authenticateToken(), strictRateLimiter, async (req, res) => {
  const { phoneNumber, totpCode } = req.body;
  if (!totpCode || !/^\d{6}$/.test(totpCode)) {
    return res.status(400).json({ error: 'Valid 6-digit TOTP code required' });
  }
  try {
    const user = await User.findOne({ phoneNumber, username: req.user.username });
    if (!user || !user.isActive) {
      return res.status(403).json({ error: 'User not found or inactive' });
    }
    if (!user.twoFactorSecret) {
      return res.status(400).json({ error: '2FA not setup' });
    }
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: totpCode,
    });
    if (!verified) {
      return res.status(400).json({ error: 'Invalid TOTP code' });
    }
    user.twoFactorEnabled = true;
    await user.save();
    res.json({ user: { ...user.toObject(), twoFactorEnabled: true } });
  } catch (error) {
    console.error('[Verify2FA] Error:', error.message);
    res.status(500).json({ error: 'Failed to verify 2FA' });
  }
});

// Disable 2FA
router.post('/disable-2fa', authenticateToken(), async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    user.twoFactorSecret = undefined;
    user.twoFactorEnabled = false;
    await user.save();
    res.json({ message: '2FA disabled successfully' });
  } catch (error) {
    console.error('[Disable2FA] Error:', error.message);
    res.status(500).json({ error: 'Failed to disable 2FA' });
  }
});

// Get all users
router.get('/', authenticateToken(['admin']), requireAdmin, generalRateLimiter, async (req, res) => {
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
    console.error('[GetUsers] Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Update KYC status
router.post('/update-kyc', authenticateToken(['admin']), requireAdmin, generalRateLimiter, async (req, res) => {
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
    console.error('[UpdateKYC] Error:', error.message);
    res.status(500).json({ error: 'Failed to update KYC status' });
  }
});

// Register User
router.post('/register', strictRateLimiter, upload.single('idImage'), handleMulterError, validate(registerValidation), async (req, res, next) => {
  console.log('[Register] Request Body:', req.body);
  console.log('[Register] File:', req.file ? { originalname: req.file.originalname, mimetype: req.file.mimetype, size: req.file.size } : null);

  const { username, name, phoneNumber, email, password, pin } = req.body;
  const idImage = req.file;

  if (!idImage) {
    console.error('[Register] No ID image provided');
    return res.status(400).json({ error: 'ID image or PDF is required' });
  }

  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }, { phoneNumber }] }).lean();
    if (existingUser) {
      console.error('[Register] Duplicate user:', { username, email, phoneNumber });
      return res.status(409).json({ error: 'Username, email, or phone number already exists' });
    }

    const s3Key = `id-images/${username}-${Date.now()}-${idImage.originalname}`;
    const params = {
      Bucket: S3_BUCKET,
      Key: s3Key,
      Body: idImage.buffer,
      ContentType: idImage.mimetype,
      ACL: 'private',
    };
    await s3.send(new PutObjectCommand(params));

    const hashedPassword = await bcrypt.hash(password, 10);
    const hashedPin = await bcrypt.hash(pin, 10);

    const user = new User({
      username: username.trim(),
      name: name.trim(),
      phoneNumber,
      email,
      password: hashedPassword,
      pin: hashedPin,
      idImageUrl: `https://${S3_BUCKET}.s3.${AWS_REGION}.amazonaws.com/${s3Key}`,
      role: 'user',
      balance: 0,
      zambiaCoinBalance: 0,
      trustScore: 0,
      ratingCount: 0,
      transactions: [],
      kycStatus: 'pending',
      isActive: false,
      isArchived: false,
    });

    await user.save();

    const token = jwt.sign({ phoneNumber: user.phoneNumber, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: '24h' });

    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(admin.pushToken, 'New User Registration', `User ${username} needs KYC approval.`, { userId: user._id });
    }

    console.log('[Register] Success:', { username, phoneNumber });
    res.status(201).json({ token, username: user.username, role: user.role, kycStatus: user.kycStatus });
  } catch (error) {
    console.error('[Register] Error:', {
      message: error.message,
      stack: error.stack,
      body: req.body,
      file: req.file ? { originalname: req.file.originalname, mimetype: req.file.mimetype, size: req.file.size } : null,
    });
    next(error);
  }
});

// Login
router.post('/login', strictRateLimiter, validate(loginValidation), async (req, res) => {
  const { identifier, password, totpCode } = req.body;
  try {
    const user = await User.findOne({ $or: [{ username: identifier }, { phoneNumber: identifier }] });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    if (user.twoFactorEnabled) {
      if (!totpCode) {
        return res.status(400).json({ error: 'TOTP code required for 2FA' });
      }
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: totpCode,
      });
      if (!verified) {
        return res.status(400).json({ error: 'Invalid TOTP code' });
      }
    }
    const token = jwt.sign({ phoneNumber: user.phoneNumber, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
    const isFirstLogin = !user.lastLogin;
    user.lastLogin = new Date();
    await user.save();
    res.status(200).json({
      token,
      username: user.username,
      name: user.name,
      phoneNumber: user.phoneNumber,
      role: user.role || 'user',
      kycStatus: user.kycStatus || 'pending',
      isFirstLogin,
      isActive: user.isActive,
      twoFactorEnabled: user.twoFactorEnabled,
    });
  } catch (error) {
    console.error('[Login] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error during login', details: error.message });
  }
});

// Forgot Password
router.post('/forgot-password', strictRateLimiter, async (req, res) => {
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
      from: EMAIL_USER,
      to: user.email,
      subject: 'Zangena Password Reset',
      text: `Your password reset token is: ${resetToken}. It expires in 1 hour.\n\nEnter it in the Zangena app to reset your password.`,
      html: `<h2>Zangena Password Reset</h2><p>Your password reset token is: <strong>${resetToken}</strong></p><p>It expires in 1 hour. Enter it in the Zangena app to reset your password.</p>`,
    };
    await transporter.sendMail(mailOptions);
    res.json({ message: 'Reset instructions have been sent to your email.' });
  } catch (error) {
    console.error('[ForgotPassword] Error:', error.message);
    res.status(500).json({ error: 'Server error during password reset request' });
  }
});

// Reset Password
router.post('/reset-password', strictRateLimiter, async (req, res) => {
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
    console.error('[ResetPassword] Error:', error.message);
    res.status(500).json({ error: 'Server error during password reset' });
  }
});

// Get User by Username
router.get('/user/:username', authenticateToken(), generalRateLimiter, async (req, res) => {
  const start = Date.now();
  console.log(`[GET /user/${req.params.username}] Starting fetch`);
  const timeout = setTimeout(() => {
    console.error(`[GET /user/${req.params.username}] Request timed out after 25s`);
    res.status(503).json({ error: 'Request timed out', duration: `${Date.now() - start}ms` });
  }, 25000);
  try {
    await mongoose.connection.db.admin().ping();
    const user = await User.findOne({ username: req.params.username });
    if (!user) {
      console.log(`[GET /user/${req.params.username}] User not found`);
      clearTimeout(timeout);
      return res.status(404).json({ error: 'User not found' });
    }
    const qrPin = await QRPin.findOne({ username: req.params.username, type: 'user' });
    if (req.user.username !== req.params.username && !['admin', 'business'].includes(req.user.role)) {
      console.log(`[GET /user/${req.params.username}] Unauthorized access by ${req.user.username}`);
      clearTimeout(timeout);
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const responseData = {
      username: user.username,
      name: user.name,
      phoneNumber: user.phoneNumber,
      email: user.email,
      balance: user.balance,
      zambiaCoinBalance: user.zambiaCoinBalance,
      trustScore: user.trustScore,
      transactions: user.transactions.slice(-10),
      kycStatus: user.kycStatus,
      isActive: user.isActive,
      pendingDeposits: user.pendingDeposits,
      pendingWithdrawals: user.pendingWithdrawals,
      qrId: qrPin ? qrPin.qrId : null,
      twoFactorEnabled: user.twoFactorEnabled,
    };
    console.log(`[GET /user/${req.params.username}] Total time: ${Date.now() - start}ms`);
    clearTimeout(timeout);
    res.json(responseData);
  } catch (error) {
    console.error(`[GET /user/${req.params.username}] Error:`, error.message, error.stack);
    clearTimeout(timeout);
    res.status(500).json({ error: 'Server error fetching user', details: error.message, duration: `${Date.now() - start}ms` });
  }
});

// Get User by Phone Number
router.get('/phone/:phoneNumber', authenticateToken(), generalRateLimiter, async (req, res) => {
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
    const qrPin = await QRPin.findOne({ username: user.username, type: 'user' });
    const convertedUser = {
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
      qrId: qrPin ? qrPin.qrId : null,
      twoFactorEnabled: convertedUser.twoFactorEnabled,
    });
  } catch (error) {
    console.error('[GetUserByPhone] Error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update User by Phone Number to include twoFactorEnabled
router.get('/user/phone/:phoneNumber', authenticateToken(), async (req, res) => {
  const { phoneNumber } = req.params;
  const { limit = 10, skip = 0 } = req.query;
  try {
    const user = await User.findOne({ phoneNumber, username: req.user.username });
    if (!user || !user.isActive) {
      console.log('[GetUserByPhone] User check failed:', { found: !!user, isActive: user?.isActive });
      return res.status(403).json({ error: 'User not found or inactive' });
    }
    const transactions = user.transactions
      .slice(parseInt(skip), parseInt(skip) + parseInt(limit))
      .map(tx => ({
        _id: tx._id,
        type: tx.type,
        toFrom: tx.toFrom,
        amount: tx.amount,
        fee: tx.fee,
        date: tx.date,
      }));
    res.json({
      username: user.username,
      phoneNumber: user.phoneNumber,
      balance: user.balance,
      transactions,
      kycStatus: user.kycStatus,
      email: user.email,
      name: user.name || '', // Include name, default to empty string
      twoFactorEnabled: user.twoFactorEnabled || false,
      isArchived: user.isArchived,
      lastViewedTimestamp: user.lastViewedTimestamp,
    });
  } catch (error) {
    console.error('[GetUserByPhone] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

// Update Notification Timestamp
router.put('/user/update-notification', authenticateToken(), generalRateLimiter, async (req, res) => {
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
    console.error('[UpdateNotification] Error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Store QR PIN
router.post('/store-qr-pin', authenticateToken(), strictRateLimiter, async (req, res) => {
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
        console.error('[StoreQRPin] User not found or inactive', { username: req.user.username });
        return res.status(404).json({ error: 'User not found or inactive' });
      }
      if (username !== user.username) {
        await session.abortTransaction();
        session.endSession();
        console.error('[StoreQRPin] Unauthorized', { requested: username, actual: user.username });
        return res.status(403).json({ error: 'Unauthorized' });
      }
      await QRPin.deleteOne({ username, type: 'user' }, { session });
      await new QRPin({
        type: 'user',
        username,
        qrId,
        pin: await bcrypt.hash(pin, 10),
        createdAt: new Date(),
        persistent: false,
      }).save({ session });
      await session.commitTransaction();
      session.endSession();
      console.log('[StoreQRPin] Success', { username, qrId });
      res.json({ qrId });
    } catch (error) {
      await session.abortTransaction();
      session.endSession();
      throw error;
    }
  } catch (error) {
    console.error('[StoreQRPin] Error:', {
      message: error.message,
      stack: error.stack,
      username,
      pinLength: pin?.length,
    });
    res.status(500).json({ error: 'Server error storing QR PIN' });
  }
});

// Pay QR
router.post('/pay-qr', authenticateToken(), strictRateLimiter, validate(payQrValidation), async (req, res) => {
  const { qrId, amount, pin, senderUsername } = req.body;
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
    if (!qrPin) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ error: 'Invalid QR code' });
    }
    if (qrPin.type === 'user' && !await qrPin.comparePin(pin)) {
      await session.abortTransaction();
      session.endSession();
      return res.status(401).json({ error: 'Invalid PIN' });
    }
    if (!qrPin.persistent && qrPin.createdAt < new Date(Date.now() - 15 * 60 * 1000)) {
      await QRPin.deleteOne({ qrId }, { session });
      await session.commitTransaction();
      session.endSession();
      return res.status(400).json({ error: 'QR code expired' });
    }
    let receiver, receiverIdentifier;
    if (qrPin.type === 'user') {
      receiver = await User.findOne({ username: qrPin.username, isActive: true }).session(session);
      receiverIdentifier = receiver?.username;
    } else if (qrPin.type === 'business') {
      receiver = await Business.findOne({ businessId: qrPin.businessId, isActive: true }).session(session);
      receiverIdentifier = receiver?.businessId;
    }
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
                toFrom: receiverIdentifier,
                fee: sendingFee,
                date: transactionDate,
                qrId,
              },
            },
          },
        },
      },
    ], { session });

    if (qrPin.type === 'user') {
      await User.bulkWrite([
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
    } else if (qrPin.type === 'business') {
      await Business.bulkWrite([
        {
          updateOne: {
            filter: { _id: receiver._id },
            update: {
              $inc: { 'balances.ZMW': amount - receivingFee },
              $push: {
                transactions: {
                  _id: receivedTxId,
                  type: 'received',
                  amount,
                  currency: 'ZMW',
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
    }

    const updates = [
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
              receiver: receiverIdentifier,
              userTransactionIds: [sentTxId, receivedTxId],
              date: transactionDate,
              qrId,
            },
          },
        },
        { upsert: true, session }
      ),
    ];

    if (!qrPin.persistent) {
      updates.push(QRPin.deleteOne({ qrId }, { session }));
    }

    await Promise.all(updates);
    await session.commitTransaction();
    session.endSession();
    res.json({ message: 'Payment successful', sendingFee, receivingFee, amount });
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    console.error('[PayQR] Error:', error.message);
    res.status(500).json({ error: 'Server error processing payment' });
  }
});

// Updated Manual Deposit
router.post('/deposit/manual', authenticateToken(), strictRateLimiter, async (req, res) => {
  const { amount, transactionId, totpCode } = req.body;
  console.log('[DepositManual] Request:', { amount, transactionId });
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user || !user.isActive) {
      return res.status(403).json({ error: 'User not found or inactive' });
    }
    if (!user.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA required for deposits' });
    }
    if (!totpCode || !/^\d{6}$/.test(totpCode)) {
      return res.status(400).json({ error: 'Valid 6-digit TOTP code required' });
    }
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: totpCode,
    });
    if (!verified) {
      return res.status(400).json({ error: 'Invalid TOTP code' });
    }
    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    if (amount > 10000) {
      return res.status(400).json({ error: 'Deposit amount cannot exceed 10,000 ZMW' });
    }
    if (!transactionId || typeof transactionId !== 'string' || transactionId.trim() === '') {
      return res.status(400).json({ error: 'Transaction ID required' });
    }
    // Check for duplicate transactionId across all users
    const existingDeposit = await User.findOne({ 'pendingDeposits.transactionId': transactionId });
    if (existingDeposit) {
      return res.status(400).json({ error: 'Transaction ID already used' });
    }
    user.pendingDeposits = user.pendingDeposits || [];
    user.pendingDeposits.push({ amount, transactionId, date: new Date(), status: 'pending' });
    // Flag account if excessive deposits (5+ in 24 hours)
    const recentDeposits = user.pendingDeposits.filter(
      d => d.date > new Date(Date.now() - 24 * 60 * 60 * 1000)
    );
    if (recentDeposits.length >= 5) {
      user.isFlagged = true;
    }
    await user.save();
    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(
        admin.pushToken,
        'New Deposit Request',
        `Deposit of ${amount} ZMW from ${user.username} needs approval.`,
        { userId: user._id, transactionId }
      );
    }
    res.json({ message: 'Deposit submitted for verification' });
  } catch (error) {
    console.error('[DepositManual] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to submit deposit' });
  }
});

// Withdraw Request
router.post('/withdraw/request', authenticateToken(), generalRateLimiter, async (req, res) => {
  const { amount } = req.body;
  console.log('[WithdrawRequest] Request:', { amount });
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
    console.error('[WithdrawRequest] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to request withdrawal' });
  }
});

// Withdraw (Direct)
router.post('/api/withdraw', authenticateToken(), generalRateLimiter, async (req, res) => {
  const { amount } = req.body;
  console.log('[WithdrawDirect] Request:', { amount });
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user || !user.isActive) {
      return res.status(403).json({ error: 'User not found or inactive' });
    }
    if (!amount || amount <= 0 || amount > user.balance) {
      return res.status(400).json({ error: 'Invalid amount or insufficient balance' });
    }
    const fee = amount <= 50 ? 0.50 :
                amount <= 100 ? 1.00 :
                amount <= 500 ? 1.50 :
                amount <= 1000 ? 2.00 :
                amount <= 5000 ? 3.00 : 5.00;
    const totalDeduction = amount + fee;
    if (user.balance < totalDeduction) {
      return res.status(400).json({ error: 'Insufficient balance including fee' });
    }
    user.balance -= totalDeduction;
    user.transactions.push({
      type: 'withdrawal',
      amount,
      fee,
      toFrom: 'System',
      date: new Date(),
    });
    await user.save();
    await AdminLedger.updateOne(
      {},
      {
        $inc: { totalBalance: fee },
        $set: { lastUpdated: new Date() },
        $push: {
          transactions: {
            type: 'fee-collected',
            amount: fee,
            sender: user.username,
            receiver: 'System',
            date: new Date(),
          },
        },
      },
      { upsert: true }
    );
    res.json({ message: 'Withdrawal successful', amount, fee });
  } catch (error) {
    console.error('[WithdrawDirect] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to process withdrawal' });
  }
});

// Save Push Token
router.post('/save-push-token', authenticateToken(), generalRateLimiter, async (req, res) => {
  const { pushToken } = req.body;
  if (!pushToken) return res.status(400).json({ error: 'Push token is required' });
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.pushToken = pushToken;
    await user.save();
    res.status(200).json({ message: 'Push token saved for user' });
  } catch (error) {
    console.error('[SavePushToken] Error:', error.message);
    res.status(500).json({ error: 'Failed to save push token' });
  }
});

// Update Profile
router.put('/user/update', authenticateToken(['user']), generalRateLimiter, validate(updateProfileValidation), async (req, res) => {
  try {
    const { email, password, pin, phoneNumber } = req.body;
    if (phoneNumber !== req.user.phoneNumber) {
      console.error('[UpdateProfile] Unauthorized phoneNumber:', { requested: phoneNumber, user: req.user.phoneNumber });
      return res.status(403).json({ error: 'Unauthorized phone number' });
    }

    const updates = {};
    if (email) {
      updates.email = email;
    }
    if (password) {
      updates.password = await bcrypt.hash(password, 10);
    }
    if (pin) {
      if (!/^\d{4}$/.test(pin)) {
        console.error('[UpdateProfile] Invalid PIN format:', { pin });
        return res.status(400).json({ error: 'PIN must be a 4-digit number' });
      }
      updates.pin = await bcrypt.hash(pin, 10);
    }

    if (!Object.keys(updates).length) {
      console.log('[UpdateProfile] No fields to update');
      return res.status(400).json({ error: 'No fields to update' });
    }

    console.log('[UpdateProfile] Updating user:', { phoneNumber: req.user.phoneNumber, updates });
    const user = await User.findOneAndUpdate(
      { phoneNumber: req.user.phoneNumber },
      { $set: updates },
      { new: true, runValidators: true }
    ).select('username phoneNumber email balance transactions kycStatus role lastViewedTimestamp pendingDeposits pendingWithdrawals twoFactorEnabled');

    if (!user) {
      console.error('[UpdateProfile] User not found:', req.user.phoneNumber);
      return res.status(404).json({ error: 'User not found' });
    }

    const token = jwt.sign(
      { phoneNumber: user.phoneNumber, role: user.role, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log('[UpdateProfile] Profile updated:', { phoneNumber: user.phoneNumber, updatedFields: Object.keys(updates) });
    res.json({
      message: 'Profile updated',
      status: 'updated',
      user: {
        username: user.username,
        phoneNumber: user.phoneNumber,
        email: user.email || '',
        balance: user.balance || 0,
        transactions: user.transactions || [],
        kycStatus: user.kycStatus || 'pending',
        role: user.role || 'user',
        lastViewedTimestamp: user.lastViewedTimestamp || 0,
        pendingDeposits: user.pendingDeposits || [],
        pendingWithdrawals: user.pendingWithdrawals || [],
        twoFactorEnabled: user.twoFactorEnabled || false,
      },
      token,
    });
  } catch (error) {
    console.error('[UpdateProfile] Error:', {
      message: error.message,
      code: error.code,
      name: error.name,
      stack: error.stack,
    });
    if (error.code === 11000) {
      return res.status(409).json({ error: 'Email already exists' });
    }
    if (error.name === 'ValidationError') {
      return res.status(400).json({ error: 'Invalid input', details: error.message });
    }
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Delete User
router.delete('/user/delete', authenticateToken(['user']), generalRateLimiter, async (req, res) => {
  const session = await mongoose.startSession();
  session.startTransaction({ writeConcern: { w: 'majority' } });
  try {
    const user = await User.findOne({ phoneNumber: req.user.phoneNumber }).session(session);
    if (!user) {
      await session.abortTransaction();
      session.endSession();
      console.error('[DeleteUser] User not found:', req.user.phoneNumber);
      return res.status(404).json({ error: 'User not found' });
    }
    if (user.isArchived) {
      await session.abortTransaction();
      session.endSession();
      console.error('[DeleteUser] User already archived:', req.user.phoneNumber);
      return res.status(400).json({ error: 'Account already archived' });
    }

    user.isActive = false;
    user.isArchived = true;
    user.archivedAt = new Date();
    user.archivedReason = 'user-requested';
    user.pushToken = null;
    user.resetToken = null;
    user.resetTokenExpiry = null;
    user.twoFactorSecret = null;
    user.twoFactorEnabled = false;
    await user.save({ session });

    await QRPin.updateMany(
      { username: user.username },
      {
        $set: {
          isActive: false,
          archivedAt: new Date(),
          archivedReason: 'user-archived',
          updatedAt: new Date(),
        },
      },
      { session }
    );

    await session.commitTransaction();
    session.endSession();
    console.log('[DeleteUser] Account archived:', req.user.phoneNumber);
    res.json({ message: 'Account archived successfully' });
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    console.error('[DeleteUser] Error:', {
      message: error.message,
      stack: error.stack,
    });
    res.status(500).json({ error: 'Server error archiving account' });
  }
});

// Refresh Token
router.post('/refresh-token', strictRateLimiter, async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) {
    console.log('[RefreshToken] Refresh token missing');
    return res.status(400).json({ error: 'Refresh token is required', code: 'MISSING_REFRESH_TOKEN' });
  }
  try {
    const user = await User.findOne({ refreshToken });
    if (!user) {
      console.log('[RefreshToken] Invalid refresh token');
      return res.status(403).json({ error: 'Invalid refresh token', code: 'INVALID_REFRESH_TOKEN' });
    }
    try {
      jwt.verify(refreshToken, JWT_SECRET);
    } catch (error) {
      console.log('[RefreshToken] Invalid or expired refresh token');
      return res.status(403).json({ error: 'Invalid or expired refresh token', code: 'INVALID_REFRESH_TOKEN' });
    }
    const accessToken = jwt.sign(
      { phoneNumber: user.phoneNumber, role: user.role, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    const newRefreshToken = jwt.sign(
      { phoneNumber: user.phoneNumber, role: user.role, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    await User.updateOne({ _id: user._id }, { $set: { refreshToken: newRefreshToken } });
    console.log('[RefreshToken] Success:', { phoneNumber: user.phoneNumber });
    res.json({
      accessToken,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    console.error('[RefreshToken] Error:', {
      message: error.message,
      stack: error.stack,
      refreshToken: refreshToken ? 'provided' : 'missing',
    });
    res.status(500).json({ error: 'Server error refreshing token', code: 'SERVER_ERROR' });
  }
});

// Update Timestamp
router.patch('/update-timestamp', authenticateToken(), generalRateLimiter, async (req, res) => {
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
    console.error('[UpdateTimestamp] Error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Toggle Active Status
router.put('/toggle-active', authenticateToken(['admin']), requireAdmin, generalRateLimiter, async (req, res) => {
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
    console.error('[ToggleActive] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to toggle user status' });
  }
});

// Get Transactions
router.get('/transactions/:username', authenticateToken(['admin']), requireAdmin, generalRateLimiter, async (req, res) => {
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
    console.error('[GetTransactions] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// Reset PIN
router.post('/reset-pin', strictRateLimiter, async (req, res) => {
  const { identifier } = req.body;
  try {
    const user = await User.findOne({ $or: [{ username: identifier }, { phoneNumber: identifier }] });
    if (!user) return res.status(404).json({ error: 'User not found' });
    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetToken = resetToken;
    user.resetTokenExpiry = Date.now() + 3600000;
    await user.save();
    const mailOptions = {
      from: EMAIL_USER,
      to: user.email,
      subject: 'Zangena PIN Reset',
      text: `Your PIN reset token is: ${resetToken}. It expires in 1 hour.\n\nEnter it in the Zangena app to reset your PIN.`,
      html: `<h2>Zangena PIN Reset</h2><p>Your PIN reset token is: <strong>${resetToken}</strong></p><p>It expires in 1 hour. Enter it in the Zangena app to reset your PIN.</p>`,
    };
    await transporter.sendMail(mailOptions);
    res.json({ message: 'PIN reset instructions sent' });
  } catch (error) {
    console.error('[ResetPin] Error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify TOTP Code
router.post('/verify-totp', authenticateToken(), strictRateLimiter, async (req, res) => {
  const { totpCode } = req.body;
  if (!totpCode || !/^\d{6}$/.test(totpCode)) {
    return res.status(400).json({ error: 'Valid 6-digit TOTP code required' });
  }
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
      return res.status(400).json({ error: '2FA not enabled' });
    }
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: totpCode,
    });
    if (!verified) {
      return res.status(400).json({ error: 'Invalid TOTP code' });
    }
    res.json({ message: 'TOTP verified' });
  } catch (error) {
    console.error('[VerifyTOTP] Error:', error.message);
    res.status(500).json({ error: 'Server error verifying TOTP' });
  }
});

// Validate Token
router.get('/validate-token', authenticateToken(), strictRateLimiter, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user || !user.isActive) {
      return res.status(403).json({ error: 'User not found or inactive' });
    }
    res.json({ message: 'Token valid' });
  } catch (error) {
    console.error('[ValidateToken] Error:', error.message);
    res.status(500).json({ error: 'Server error validating token' });
  }
});

module.exports = router;