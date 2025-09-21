const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { RekognitionClient, DetectTextCommand, DetectFacesCommand } = require('@aws-sdk/client-rekognition');
const fs = require('fs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const axios = require('axios');
const twilio = require('twilio');
// const { sendPushNotification } = require('../utils/notifications');
const { v4: uuidv4 } = require('uuid');
const User = require('../models/User');
const QRPin = require('../models/QRPin');
const Business = require('../models/Business');
const AdminLedger = require('../models/AdminLedger');
const authenticateToken = require('../middleware/authenticateToken');
const { generalRateLimiter, strictRateLimiter, validate, registerValidation, loginValidation, payQrValidation, updateProfileValidation } = require('../middleware/securityMiddleware');
const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const Analytics = require('../models/Analytics');

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'Zangena123$@2025';
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const S3_BUCKET = process.env.S3_BUCKET || 'zangena';
const EMAIL_USER = process.env.EMAIL_USER || 'your_email@example.com';
const EMAIL_PASS = process.env.EMAIL_PASS || 'your_email_password';

const MAX_WITHDRAW_AMOUNT = 10000; // BoZ-compliant max withdrawal per transaction
const MTN_PREFIXES = ['96', '76'];
const AIRTEL_PREFIXES = ['97', '77'];

const TWILIO_SID = process.env.TWILIO_ACCOUNT_SID;
const TWILIO_AUTH_TOKEN = process.env.TWILIO_AUTH_TOKEN;
const TWILIO_PHONE_NUMBER = process.env.TWILIO_PHONE_NUMBER;

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

// Configure AWS Rekognition
const rekognition = new RekognitionClient({
  region: AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

// Configure Nodemailer with Gmail
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASS,
  },
});

// Configure Twilio
const twilioClient = twilio(TWILIO_SID, TWILIO_AUTH_TOKEN);

// Ensure indexes for QRPin only
const ensureIndexes = async () => {
  const maxRetries = 3;
  let attempt = 1;

  while (attempt <= maxRetries) {
    try {
      console.log(`[Indexes] Attempt ${attempt} to ensure indexes for QRPin`);
      await QRPin.createIndexes([
        { key: { qrId: 1 }, unique: true },
      ], { maxTimeMS: 30000 });
      console.log('[Indexes] Successfully ensured indexes for QRPin');
      return;
    } catch (error) {
      console.error('[Indexes] Error creating indexes for QRPin:', {
        message: error.message,
        code: error.code,
        codeName: error.codeName,
        attempt,
      });
      if (error.message.includes('buffering timed out') && attempt < maxRetries) {
        console.log(`[Indexes] Retrying in 5s...`);
        await new Promise(resolve => setTimeout(resolve, 5000));
        attempt++;
      } else if (error.code === 85 || error.code === 86) {
        console.log('[Indexes] Ignoring index conflict error (code 85 or 86) for QRPin');
        return;
      } else {
        throw error;
      }
    }
  }
  console.error('[Indexes] Failed to create indexes for QRPin after', maxRetries, 'attempts');
};

ensureIndexes();

// Debug route to inspect indexes
router.get('/debug/indexes', authenticateToken(['admin']), async (req, res) => {
  try {
    const users = await mongoose.connection.db.collection('users').indexes();
    const qrpins = await mongoose.connection.db.collection('qrpins').indexes();
    const analytics = await mongoose.connection.db.collection('analytics').indexes();
    const businesses = await mongoose.connection.db.collection('businesses').indexes();
    res.json({ users, qrpins, analytics, businesses });
  } catch (error) {
    console.error('[Debug] Error fetching indexes:', error.message);
    res.status(500).json({ error: 'Failed to fetch indexes' });
  }
});


// Analytics Schema
/* const analyticsSchema = new mongoose.Schema({
  event: { type: String, required: true, enum: ['deposit_submitted', 'deposit_failed', 'input_error', 'focus_event'] },
  username: { type: String, required: true, index: true },
  phoneNumber: { type: String, required: true, index: true },
  timestamp: { type: Date, required: true, default: Date.now },
  data: {
    amount: { type: Number, default: 0 },
    transactionId: { type: String },
    error: { type: String },
    focusCount: { type: Number, default: 0 },
    errorCount: { type: Number, default: 0 },
    depositAttempts: { type: Number, default: 0 },
  },
  createdAt: { type: Date, default: Date.now, expires: '90d' }, // Auto-expire after 90 days
}); */

// const Analytics = mongoose.model('Analytics', analyticsSchema);

// Ensure indexes
const ensureAnalyticsIndexes = async () => {
  try {
    await Analytics.createIndexes({ username: 1, phoneNumber: 1, timestamp: 1 });
    console.log('[Analytics] Successfully ensured indexes');
  } catch (error) {
    console.error('[Analytics] Error creating indexes:', error.message);
  }
};
ensureAnalyticsIndexes();

async function calculateTrustScore(username) {
  try {
    const user = await User.findOne({ username });
    const analytics = await Analytics.find({ username });
    
    // Base score
    let trustScore = 50; // Neutral starting point (0-100 scale)
    
    // KYC status
    if (user.kycStatus === 'verified') trustScore += 20;
    else if (user.kycStatus === 'rejected') trustScore -= 20;
    
    // Transaction frequency (last 30 days)
    const recentTransactions = user.transactions.filter(
      t => t.date > new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
    );
    trustScore += Math.min(recentTransactions.length * 2, 20); // +2 per transaction, max 20
    
    // Analytics: Error rate
    const errorCount = analytics.reduce((sum, a) => sum + (a.data.errorCount || 0), 0);
    trustScore -= Math.min(errorCount * 5, 20); // -5 per error, max -20
    
    // Analytics: Deposit attempts
    const depositAttempts = analytics.reduce((sum, a) => sum + (a.data.depositAttempts || 0), 0);
    trustScore -= depositAttempts > 10 ? 10 : 0; // Penalty for excessive attempts
    
    // Ensure score is between 0 and 100
    trustScore = Math.max(0, Math.min(100, trustScore));
    
    await User.updateOne({ username }, { trustScore });
    console.log('[TrustScore] Updated:', { username, trustScore });
    return trustScore;
  } catch (error) {
    console.error('[TrustScore] Error:', error.message);
    return null;
  }
}


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
  console.log('[Setup2FA] Request:', { phoneNumber, username: req.user.username });
  try {
    const user = await User.findOne({ phoneNumber, username: req.user.username });
    if (!user || !user.isActive) {
      console.log('[Setup2FA] User check failed:', { found: !!user, isActive: user?.isActive });
      return res.status(403).json({ error: 'User not found or inactive' });
    }
    if (user.twoFactorEnabled) {
      console.log('[Setup2FA] 2FA already enabled for user:', user.username);
      return res.status(400).json({ error: '2FA already enabled' });
    }
    const secret = speakeasy.generateSecret({
      length: 20,
      name: `Zangena:${user.username}`,
      issuer: 'Zangena',
    });
    console.log('[Setup2FA] Generated secret:', secret.base32);
    user.twoFactorSecret = secret.base32;
    await user.save();
    console.log('[Setup2FA] User updated with secret:', user.twoFactorSecret);
    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
    console.log('[Setup2FA] QR code generated');
    res.json({ qrCodeUrl, secret: secret.base32 }); // Return secret.base32
  } catch (error) {
    console.error('[Setup2FA] Error:', error.message, error.stack);
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

// Updated Register User
router.post('/register', strictRateLimiter, upload.single('idImage'), handleMulterError, validate(registerValidation), async (req, res, next) => {
  console.log('[Register] Request Body:', req.body);
  console.log('[Register] File:', req.file ? { originalname: req.file.originalname, mimetype: req.file.mimetype, size: req.file.size } : null);

  const { username, name, phoneNumber, email, password, pin } = req.body;
  const idImage = req.file;

  if (!idImage) {
    console.error('[Register] No ID image provided');
    const analytics = await new Analytics({
      event: 'signup_failed',
      username: username || 'unknown',
      data: { error: 'ID image or PDF is required' },
      timestamp: new Date(),
    }).save();
    return res.status(400).json({ error: 'ID image or PDF is required', analyticsEventId: analytics._id });
  }

  try {
    // Check for duplicate user
    const existingUser = await User.findOne({ $or: [{ username }, { email: email.toLowerCase() }, { phoneNumber }] }).lean();
    if (existingUser) {
      console.error('[Register] Duplicate user:', { username, email, phoneNumber });
      const analytics = await new Analytics({
        event: 'signup_failed',
        username,
        data: { error: 'Duplicate user', username, email, phoneNumber },
        timestamp: new Date(),
      }).save();
      return res.status(409).json({ error: 'Username, email, or phone number already exists', analyticsEventId: analytics._id });
    }

    // AI: Check for suspicious input patterns
    if (username.match(/(.)\1{3,}/) || email.match(/(.)\1{3,}@/)) {
      const analytics = await new Analytics({
        event: 'signup_failed',
        username,
        data: { error: 'Suspicious input patterns', username, email },
        timestamp: new Date(),
      }).save();
      return res.status(403).json({ error: 'Suspicious input detected', isFlagged: true, analyticsEventId: analytics._id });
    }

    // AI: Fraud detection via microservice
    let fraudScore = 1;
    try {
      const fraudResult = await axios.post('http://localhost:5000/predict', {
        username,
        email,
        phoneNumber,
        timestamp: Date.now(),
      });
      fraudScore = fraudResult.data.is_anomaly ? -1 : 1;
    } catch (fraudError) {
      console.error('[Register] Fraud Detection Error:', fraudError.message);
      fraudScore = 0; // Neutral score if fraud detection fails
    }

    if (fraudScore < -0.5) {
      const analytics = await new Analytics({
        event: 'signup_failed',
        username,
        data: { error: 'High-risk signup detected', fraudScore, username, email, phoneNumber },
        timestamp: new Date(),
      }).save();
      return res.status(403).json({ error: 'High-risk signup detected', isFlagged: true, fraudScore, analyticsEventId: analytics._id });
    }

    // KYC: Analyze ID image with AWS Rekognition
    let kycAnalysis = { textCount: 0, faceCount: 0, isValid: false, analyzedAt: new Date() };
    try {
      const detectTextCommand = new DetectTextCommand({ Image: { Bytes: idImage.buffer } });
      const detectFacesCommand = new DetectFacesCommand({ Image: { Bytes: idImage.buffer } });
      const [textResponse, facesResponse] = await Promise.all([
        rekognition.send(detectTextCommand),
        rekognition.send(detectFacesCommand),
      ]);
      kycAnalysis.textCount = textResponse.TextDetections?.length || 0;
      kycAnalysis.faceCount = facesResponse.FaceDetails?.length || 0;
      kycAnalysis.isValid = kycAnalysis.textCount > 0 && kycAnalysis.faceCount > 0;
    } catch (rekogError) {
      console.error('[Rekognition] Error:', rekogError.message);
      kycAnalysis.error = rekogError.message;
    }

    // Log KYC analysis to analytics
    const kycAnalytics = await new Analytics({
      event: 'kyc_image_analysis',
      username,
      phoneNumber,
      data: kycAnalysis,
      timestamp: new Date(),
    }).save();

    // Upload ID to S3
    const s3Key = `id-images/${username}-${Date.now()}-${idImage.originalname}`;
    const params = {
      Bucket: S3_BUCKET,
      Key: s3Key,
      Body: idImage.buffer,
      ContentType: idImage.mimetype,
      ACL: 'private',
    };
    await s3.send(new PutObjectCommand(params));
    const idImageUrl = `https://${S3_BUCKET}.s3.${process.env.AWS_REGION}.amazonaws.com/${s3Key}`;

    // Calculate initial trust score
    const trustScore = kycAnalysis.faceCount > 0 ? 10 : 0 + (fraudScore > 0 ? 5 : 0);

    // Create user
    const user = new User({
      username: username.trim(),
      name: name.trim(),
      phoneNumber,
      email: email.toLowerCase(),
      password: await bcrypt.hash(password, 10),
      pin: await bcrypt.hash(pin, 10),
      idImageUrl,
      role: 'user',
      balance: 0,
      zambiaCoinBalance: 0,
      trustScore,
      ratingCount: 0,
      transactions: [],
      kycStatus: kycAnalysis.isValid ? 'pending' : 'pending', // Always pending for manual review
      kycAnalysis: { ...kycAnalysis, analyticsEventId: kycAnalytics._id },
      isActive: false,
      isArchived: false,
      isFlagged: fraudScore < -0.5,
    });
    await user.save();

    // Log signup request to analytics
    const signupAnalytics = await new Analytics({
      event: 'signup_request',
      username,
      data: { kycAnalysis, idImageUrl, fraudScore },
      timestamp: new Date(),
    }).save();

    // Generate JWT
    const token = jwt.sign({ phoneNumber: user.phoneNumber, role: user.role, username: user.username }, JWT_SECRET, { expiresIn: '24h' });

    // Notify admin
    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(
        admin.pushToken,
        'New User Registration',
        `User ${username} needs KYC approval.`,
        { userId: user._id }
      );
    }

    console.log('[Register] Success:', { username, phoneNumber, kycStatus: user.kycStatus, trustScore });
    res.status(201).json({ token, username: user.username, role: user.role, kycStatus: user.kycStatus, kycAnalysis });
  } catch (error) {
    console.error('[Register] Error:', {
      message: error.message,
      stack: error.stack,
      body: req.body,
      file: req.file ? { originalname: req.file.originalname, mimetype: req.file.mimetype, size: req.file.size } : null,
    });
    const analytics = await new Analytics({
      event: 'signup_failed',
      username: username || 'unknown',
      data: { error: error.message, kycAnalysis: kycAnalysis || null },
      timestamp: new Date(),
    }).save();
    res.status(500).json({ error: 'Server error during registration', analyticsEventId: analytics._id });
  }
});

// Login endpoint
router.post('/login', strictRateLimiter, validate(loginValidation), async (req, res) => {
  const { identifier, password, smsCode } = req.body;
  console.log('[Login] Request:', { identifier });

  try {
    const user = await User.findOne({
      $or: [{ username: identifier }, { phoneNumber: identifier }],
    });

    if (!user) {
      console.log('[Login] User not found:', identifier);
      await Analytics.create({
        event: 'login_failed',
        username: identifier,
        data: { reason: 'User not found' },
        timestamp: new Date(),
      });
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      console.log('[Login] Invalid password for:', user.username);
      await Analytics.create({
        event: 'login_failed',
        username: user.username,
        data: { reason: 'Invalid password' },
        timestamp: new Date(),
      });
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    if (!user.isEffectivelyActive) {
      console.log('[Login] Inactive or archived user:', user.username);
      await Analytics.create({
        event: 'login_failed',
        username: user.username,
        data: { reason: 'Account inactive or archived' },
        timestamp: new Date(),
      });
      return res.status(403).json({ error: 'Account is inactive or archived' });
    }

    if (user.twoFactorEnabled && !smsCode) {
      const smsCode = Math.floor(100000 + Math.random() * 900000).toString();
      user.twoFactorSecret = smsCode;
      user.twoFactorExpiry = new Date(Date.now() + 10 * 60 * 1000);
      await user.save();

      try {
        await twilioClient.messages.create({
          body: `Your FugiPay 2FA code is ${smsCode}. It expires in 10 minutes.`,
          from: TWILIO_PHONE_NUMBER,
          to: user.phoneNumber,
        });
        console.log('[Login] SMS sent to:', user.phoneNumber);
      } catch (error) {
        console.error('[Login] SMS send error:', error.message);
        await Analytics.create({
          event: 'login_failed',
          username: user.username,
          data: { reason: 'SMS send failed' },
          timestamp: new Date(),
        });
        return res.status(500).json({ error: 'Failed to send 2FA code' });
      }

      console.log('[Login] SMS 2FA required for:', user.username);
      return res.status(401).json({ error: 'SMS 2FA code required', twoFactorEnabled: true });
    }

    if (user.twoFactorEnabled && smsCode) {
      if (!/^\d{6}$/.test(smsCode)) {
        console.log('[Login] Invalid SMS code format for:', user.username);
        await Analytics.create({
          event: 'login_failed',
          username: user.username,
          data: { reason: 'Invalid SMS code format' },
          timestamp: new Date(),
        });
        return res.status(400).json({ error: 'Invalid 2FA code' });
      }
      if (user.twoFactorSecret !== smsCode || user.twoFactorExpiry < new Date()) {
        console.log('[Login] Invalid or expired SMS code for:', user.username);
        await Analytics.create({
          event: 'login_failed',
          username: user.username,
          data: { reason: 'Invalid or expired SMS code' },
          timestamp: new Date(),
        });
        return res.status(400).json({ error: 'Invalid or expired 2FA code' });
      }
    }

    user.lastLogin = new Date();
    user.lastLoginAttempts = (user.lastLoginAttempts || 0) + 1;
    user.twoFactorSecret = undefined;
    user.twoFactorExpiry = undefined;
    await user.save();

    const token = jwt.sign(
      { username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    const analyticsEvent = await Analytics.create({
      event: 'login_success',
      username: user.username,
      data: { role: user.role, kycStatus: user.kycStatus },
      timestamp: new Date(),
    });

    await AdminLedger.create({
      action: 'login',
      username: user.username,
      details: { analyticsEventId: analyticsEvent._id },
      timestamp: new Date(),
    });

    res.json({
      phoneNumber: user.phoneNumber,
      token,
      username: user.username,
      name: user.name,
      role: user.role,
      kycStatus: user.kycStatus,
      isFirstLogin: !user.lastLoginAttempts || user.lastLoginAttempts === 1,
      isActive: user.isActive,
      twoFactorEnabled: user.twoFactorEnabled,
    });
  } catch (error) {
    console.error('[Login] Error:', error.message, error.stack);
    await Analytics.create({
      event: 'login_failed',
      username: identifier,
      data: { reason: error.message },
      timestamp: new Date(),
    });
    res.status(500).json({ error: 'Server error' });
  }
});

// Enable SMS 2FA
router.post('/enable-sms-2fa', authenticateToken(), strictRateLimiter, async (req, res) => {
  const { phoneNumber } = req.body;
  console.log('[EnableSMS2FA] Request:', { phoneNumber, username: req.user.username });
  try {
    const user = await User.findOne({ phoneNumber, username: req.user.username });
    if (!user || !user.isActive) {
      console.log('[EnableSMS2FA] User check failed:', { found: !!user, isActive: user?.isActive });
      return res.status(403).json({ error: 'User not found or inactive' });
    }
    if (user.twoFactorEnabled) {
      console.log('[EnableSMS2FA] 2FA already enabled for user:', user.username);
      return res.status(400).json({ error: '2FA already enabled' });
    }
    user.twoFactorEnabled = true;
    await user.save();
    console.log('[EnableSMS2FA] 2FA enabled for:', user.username);
    res.json({ message: 'SMS 2FA enabled successfully' });
  } catch (error) {
    console.error('[EnableSMS2FA] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to enable SMS 2FA' });
  }
});

// Verify SMS 2FA
router.post('/verify-sms-2fa', strictRateLimiter, async (req, res) => {
  const { identifier, smsCode } = req.body;
  console.log('[VerifySMS2FA] Request:', { identifier });
  try {
    const user = await User.findOne({
      $or: [{ username: identifier }, { phoneNumber: identifier }],
    });
    if (!user || !user.isActive) {
      console.log('[VerifySMS2FA] User not found or inactive:', identifier);
      return res.status(403).json({ error: 'User not found or inactive' });
    }
    if (!user.twoFactorEnabled) {
      console.log('[VerifySMS2FA] 2FA not enabled for:', user.username);
      return res.status(400).json({ error: '2FA not enabled' });
    }
    if (!smsCode || !/^\d{6}$/.test(smsCode)) {
      console.log('[VerifySMS2FA] Invalid SMS code format for:', user.username);
      return res.status(400).json({ error: 'Valid 6-digit SMS code required' });
    }
    if (user.twoFactorSecret !== smsCode || user.twoFactorExpiry < new Date()) {
      console.log('[VerifySMS2FA] Invalid or expired SMS code for:', user.username);
      return res.status(400).json({ error: 'Invalid or expired SMS code' });
    }
    user.twoFactorSecret = undefined;
    user.twoFactorExpiry = undefined;
    await user.save();
    console.log('[VerifySMS2FA] SMS 2FA verified for:', user.username);
    res.json({ message: 'SMS 2FA verified successfully' });
  } catch (error) {
    console.error('[VerifySMS2FA] Error:', error.message);
    res.status(500).json({ error: 'Failed to verify SMS 2FA' });
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
    user.twoFactorExpiry = undefined;
    await user.save();
    res.json({ message: '2FA disabled successfully' });
  } catch (error) {
    console.error('[Disable2FA] Error:', error.message);
    res.status(500).json({ error: 'Failed to disable 2FA' });
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
router.post('/deposit/manual', authenticateToken(), generalRateLimiter, async (req, res) => {
  const { amount, transactionId } = req.body;
  const { username } = req.user;
  console.log('[DepositManual] Request:', { username, amount, transactionId });

  try {
    // Validate amount
    const depositAmount = parseFloat(amount);
    if (isNaN(depositAmount) || depositAmount <= 0) {
      const analytics = await new Analytics({
        event: 'deposit_failed',
        identifier: username,
        data: { error: 'Invalid amount', amount },
        timestamp: new Date(),
      }).save();
      return res.status(400).json({ error: 'Invalid amount', analyticsEventId: analytics._id });
    }
    if (depositAmount > MAX_DEPOSIT_AMOUNT) {
      const analytics = await new Analytics({
        event: 'deposit_failed',
        identifier: username,
        data: { error: `Amount cannot exceed K${MAX_DEPOSIT_AMOUNT}`, amount },
        timestamp: new Date(),
      }).save();
      return res.status(400).json({ error: `Amount cannot exceed K${MAX_DEPOSIT_AMOUNT}`, analyticsEventId: analytics._id });
    }

    // Validate transactionId
    if (!transactionId || typeof transactionId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(transactionId)) {
      const analytics = await new Analytics({
        event: 'deposit_failed',
        identifier: username,
        data: { error: 'Invalid transaction ID format (must be UUID)', transactionId },
        timestamp: new Date(),
      }).save();
      return res.status(400).json({ error: 'Invalid transaction ID format (must be UUID)', analyticsEventId: analytics._id });
    }

    // Fetch user
    const user = await User.findOne({ username });
    if (!user) {
      const analytics = await new Analytics({
        event: 'deposit_failed',
        identifier: username,
        data: { error: 'User not found' },
        timestamp: new Date(),
      }).save();
      return res.status(404).json({ error: 'User not found', analyticsEventId: analytics._id });
    }

    // Validate user status
    if (!user.isActive || user.isArchived) {
      const analytics = await new Analytics({
        event: 'deposit_failed',
        identifier: username,
        data: { error: 'User is not active or archived' },
        timestamp: new Date(),
      }).save();
      return res.status(403).json({ error: 'User is not active or archived', analyticsEventId: analytics._id });
    }

    if (user.kycStatus !== 'verified') {
      const analytics = await new Analytics({
        event: 'deposit_failed',
        identifier: username,
        data: { error: 'KYC verification required' },
        timestamp: new Date(),
      }).save();
      return res.status(403).json({ error: 'KYC verification required', analyticsEventId: analytics._id });
    }

    if (user.isFlagged) {
      const analytics = await new Analytics({
        event: 'deposit_failed',
        identifier: username,
        data: { error: 'Account flagged', fraudScore: -1, isFlagged: true },
        timestamp: new Date(),
      }).save();
      return res.status(403).json({ error: 'Account flagged', fraudScore: -1, isFlagged: true, analyticsEventId: analytics._id });
    }

    // Validate phone number (MTN/Airtel)
    let phoneNumber = user.phoneNumber;
    if (!phoneNumber.startsWith('+260')) {
      if (phoneNumber.startsWith('260')) phoneNumber = '+' + phoneNumber;
      else if (phoneNumber.startsWith('0')) phoneNumber = '+260' + phoneNumber.slice(1);
      else {
        const analytics = await new Analytics({
          event: 'deposit_failed',
          identifier: username,
          data: { error: 'Invalid phone number format' },
          timestamp: new Date(),
        }).save();
        return res.status(400).json({ error: 'Invalid phone number format', analyticsEventId: analytics._id });
      }
    }
    const prefix = phoneNumber.slice(4, 6);
    if (!MTN_PREFIXES.includes(prefix) && !AIRTEL_PREFIXES.includes(prefix)) {
      const analytics = await new Analytics({
        event: 'deposit_failed',
        identifier: username,
        data: { error: 'Deposits only supported for MTN or Airtel numbers' },
        timestamp: new Date(),
      }).save();
      return res.status(400).json({ error: 'Deposits only supported for MTN or Airtel numbers', analyticsEventId: analytics._id });
    }

    // Check for duplicate transactionId
    if (user.pendingDeposits.some(deposit => deposit.transactionId === transactionId)) {
      const analytics = await new Analytics({
        event: 'deposit_failed',
        identifier: username,
        data: { error: 'Duplicate transaction ID', transactionId },
        timestamp: new Date(),
      }).save();
      return res.status(400).json({ error: 'Duplicate transaction ID', analyticsEventId: analytics._id });
    }

    // Calculate fee (1% with min K2, consistent with withdraw.tsx)
    const fee = Math.max(depositAmount * 0.01, 2);

    // AI: Fraud detection
    let fraudScore = 1;
    let fraudAnalyticsEventId = null;
    try {
      const fraudResult = await axios.post('http://localhost:5000/predict', {
        username,
        amount: depositAmount,
        transactionId,
        userId: user._id,
        timestamp: Date.now(),
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });
      const { is_anomaly, analyticsEventId, error } = fraudResult.data;
      if (error) {
        console.error('[DepositManual] Fraud Detection Error:', error);
        const analytics = await new Analytics({
          event: 'deposit_failed',
          identifier: username,
          phoneNumber: user.phoneNumber,
          data: { error: `Fraud detection error: ${error}`, transactionId },
          timestamp: new Date(),
        }).save();
        return res.status(500).json({ error: 'Fraud detection failed', analyticsEventId: analytics._id });
      }
      fraudScore = is_anomaly ? -1 : 1;
      fraudAnalyticsEventId = analyticsEventId;
    } catch (fraudError) {
      console.error('[DepositManual] Fraud Detection Error:', fraudError.message);
      fraudScore = 0; // Neutral score if fraud detection fails
      const analytics = await new Analytics({
        event: 'deposit_failed',
        identifier: username,
        phoneNumber: user.phoneNumber,
        data: { error: `Fraud detection error: ${fraudError.message}`, transactionId },
        timestamp: new Date(),
      }).save();
      return res.status(500).json({ error: 'Fraud detection failed', analyticsEventId: analytics._id });
    }

    if (fraudScore < -0.5) {
      await User.updateOne({ username }, { $set: { isFlagged: true } });
      const analytics = await new Analytics({
        event: 'deposit_failed',
        identifier: username,
        phoneNumber: user.phoneNumber,
        data: {
          error: 'High-risk deposit detected',
          amount: depositAmount,
          transactionId,
          fraudScore,
          isFlagged: true,
          fraudAnalyticsEventId
        },
        timestamp: new Date(),
      }).save();
      return res.status(403).json({
        error: 'High-risk deposit detected',
        fraudScore,
        isFlagged: true,
        analyticsEventId: analytics._id,
        fraudAnalyticsEventId
      });
    }

    // Increment deposit attempts
    user.depositAttempts = (user.depositAttempts || 0) + 1;
    if (user.depositAttempts >= 5) {
      user.isFlagged = true;
    }

    const analyticsEntry = await new Analytics({
      event: 'deposit_request',
      identifier: username,
      phoneNumber: user.phoneNumber,
      data: {
        amount: depositAmount,
        fee,
        transactionId,
        fraudScore,
        fraudAnalyticsEventId,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      },
      timestamp: new Date(),
    }).save();

    user.pendingDeposits.push({
      amount: depositAmount,
      transactionId,
      fraudScore,
      analyticsEventId: analyticsEntry._id,
      fraudAnalyticsEventId,
      status: 'pending',
    });
    await user.save();

    // Update AdminLedger with deposit fee
    await AdminLedger.updateOne(
      {},
      {
        $inc: { totalBalance: fee },
        $set: { lastUpdated: new Date() },
        $push: {
          transactions: {
            type: 'deposit_fee',
            amount: fee,
            sender: username,
            receiver: 'System',
            userTransactionIds: [transactionId],
            fraudScore,
            analyticsEventId: analyticsEntry._id,
            fraudAnalyticsEventId,
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            date: new Date(),
          },
        },
      },
      { upsert: true }
    );

    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      const notificationResult = await sendPushNotification(
        admin.pushToken,
        'New Deposit Request',
        `User ${username} submitted a deposit of K${depositAmount.toFixed(2)} (fee: K${fee.toFixed(2)}).`,
        {
          type: 'deposit_request',
          userId: user._id,
          depositId: transactionId,
          analyticsEventId: analyticsEntry._id,
          fraudAnalyticsEventId,
          ip: req.ip,
          userAgent: req.headers['user-agent'],
        },
        username
      );
      if (notificationResult.error) {
        console.error('[DepositManual] Notification Error:', notificationResult.error);
        const analytics = await new Analytics({
          event: 'deposit_notification_failed',
          identifier: username,
          phoneNumber: user.phoneNumber,
          data: {
            error: notificationResult.error,
            transactionId,
            analyticsEventId: analyticsEntry._id,
            fraudAnalyticsEventId
          },
          timestamp: new Date(),
        }).save();
      }
    }

    console.log('[DepositManual] Success:', { username, amount: depositAmount, transactionId, fraudScore, analyticsEventId: analyticsEntry._id, fraudAnalyticsEventId });
    res.status(200).json({
      message: 'Deposit submitted for verification',
      transactionId,
      fraudScore,
      analyticsEventId: analyticsEntry._id,
      fraudAnalyticsEventId
    });
  } catch (error) {
    console.error('[DepositManual] Error:', {
      message: error.message,
      stack: error.stack,
      username,
      amount,
      transactionId,
    });
    let status = 500;
    let errorMessage = 'Failed to process deposit';
    if (error.message.includes('Rate limit')) {
      status = 429;
      errorMessage = 'Too many requests. Please try again later.';
    }
    const analytics = await new Analytics({
      event: 'deposit_failed',
      identifier: username || 'unknown',
      phoneNumber: user?.phoneNumber,
      data: {
        error: error.message,
        amount,
        transactionId,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      },
      timestamp: new Date(),
    }).save();
    res.status(status).json({ error: errorMessage, analyticsEventId: analytics._id });
  }
});

// Withdraw Request
router.post('/withdraw/request', authenticateToken(), generalRateLimiter, async (req, res) => {
  const { amount } = req.body;
  const { username } = req.user;
  console.log('[WithdrawRequest] Request:', { username, amount });

  try {
    // Validate amount
    const withdrawAmount = parseFloat(amount);
    if (isNaN(withdrawAmount) || withdrawAmount <= 0) {
      const analytics = await new Analytics({
        event: 'withdraw_failed',
        identifier: username,
        data: { error: 'Invalid amount', amount },
        timestamp: new Date(),
      }).save();
      return res.status(400).json({ error: 'Invalid amount', analyticsEventId: analytics._id });
    }
    if (withdrawAmount > MAX_WITHDRAW_AMOUNT) {
      const analytics = await new Analytics({
        event: 'withdraw_failed',
        identifier: username,
        data: { error: `Amount cannot exceed K${MAX_WITHDRAW_AMOUNT}`, amount },
        timestamp: new Date(),
      }).save();
      return res.status(400).json({ error: `Amount cannot exceed K${MAX_WITHDRAW_AMOUNT}`, analyticsEventId: analytics._id });
    }

    // Fetch user
    const user = await User.findOne({ username });
    if (!user) {
      const analytics = await new Analytics({
        event: 'withdraw_failed',
        identifier: username,
        data: { error: 'User not found' },
        timestamp: new Date(),
      }).save();
      return res.status(404).json({ error: 'User not found', analyticsEventId: analytics._id });
    }

    // Validate user status
    if (!user.isActive || user.isArchived) {
      const analytics = await new Analytics({
        event: 'withdraw_failed',
        identifier: username,
        data: { error: user.isActive ? 'Account is inactive' : 'Account is archived' },
        timestamp: new Date(),
      }).save();
      return res.status(403).json({
        error: user.isActive ? 'Account is inactive' : 'Account is archived',
        analyticsEventId: analytics._id,
      });
    }

    if (user.kycStatus !== 'verified') {
      const analytics = await new Analytics({
        event: 'withdraw_failed',
        identifier: username,
        data: { error: 'KYC verification required' },
        timestamp: new Date(),
      }).save();
      return res.status(403).json({ error: 'KYC verification required', analyticsEventId: analytics._id });
    }

    if (user.isFlagged) {
      const analytics = await new Analytics({
        event: 'withdraw_failed',
        identifier: username,
        data: { error: 'Account flagged', fraudScore: -1, isFlagged: true },
        timestamp: new Date(),
      }).save();
      return res.status(403).json({
        error: 'Account flagged for suspicious activity. Contact support.',
        fraudScore: -1,
        isFlagged: true,
        analyticsEventId: analytics._id,
      });
    }

    // Validate phone number (MTN/Airtel)
    let phoneNumber = user.phoneNumber;
    if (!phoneNumber.startsWith('+260')) {
      if (phoneNumber.startsWith('260')) phoneNumber = '+' + phoneNumber;
      else if (phoneNumber.startsWith('0')) phoneNumber = '+260' + phoneNumber.slice(1);
      else {
        const analytics = await new Analytics({
          event: 'withdraw_failed',
          identifier: username,
          data: { error: 'Invalid phone number format' },
          timestamp: new Date(),
        }).save();
        return res.status(400).json({ error: 'Invalid phone number format', analyticsEventId: analytics._id });
      }
    }
    const prefix = phoneNumber.slice(4, 6);
    if (!MTN_PREFIXES.includes(prefix) && !AIRTEL_PREFIXES.includes(prefix)) {
      const analytics = await new Analytics({
        event: 'withdraw_failed',
        identifier: username,
        data: { error: 'Withdrawals only supported for MTN or Airtel numbers' },
        timestamp: new Date(),
      }).save();
      return res.status(400).json({ error: 'Withdrawals only supported for MTN or Airtel numbers', analyticsEventId: analytics._id });
    }

    // Calculate fee
    const fee = Math.max(withdrawAmount * 0.01, 2);
    const totalDeduction = withdrawAmount + fee;
    if (user.balance < totalDeduction) {
      const analytics = await new Analytics({
        event: 'withdraw_failed',
        identifier: username,
        data: { error: 'Insufficient balance including fee', amount: withdrawAmount, fee, balance: user.balance },
        timestamp: new Date(),
      }).save();
      return res.status(400).json({
        error: 'Insufficient balance including fee',
        analyticsEventId: analytics._id,
      });
    }

    // Generate transactionId
    const transactionId = uuidv4();
    if (user.pendingWithdrawals.some(withdrawal => withdrawal.transactionId === transactionId)) {
      const analytics = await new Analytics({
        event: 'withdraw_failed',
        identifier: username,
        data: { error: 'Duplicate transaction ID', transactionId },
        timestamp: new Date(),
      }).save();
      return res.status(400).json({ error: 'Duplicate transaction ID', analyticsEventId: analytics._id });
    }

    // AI: Fraud detection
    let fraudScore = 1;
    let fraudAnalyticsEventId = null;
    try {
      const fraudResult = await axios.post('http://localhost:5000/predict', {
        username,
        amount: withdrawAmount,
        transactionId,
        userId: user._id,
        timestamp: Date.now(),
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });
      const { is_anomaly, analyticsEventId, error } = fraudResult.data;
      if (error) {
        console.error('[WithdrawRequest] Fraud Detection Error:', error);
        const analytics = await new Analytics({
          event: 'withdraw_failed',
          identifier: username,
          phoneNumber: user.phoneNumber,
          data: { error: `Fraud detection error: ${error}`, transactionId },
          timestamp: new Date(),
        }).save();
        return res.status(500).json({ error: 'Fraud detection failed', analyticsEventId: analytics._id });
      }
      fraudScore = is_anomaly ? -1 : 1;
      fraudAnalyticsEventId = analyticsEventId;
    } catch (fraudError) {
      console.error('[WithdrawRequest] Fraud Detection Error:', fraudError.message);
      fraudScore = 0; // Neutral score if fraud detection fails
      const analytics = await new Analytics({
        event: 'withdraw_failed',
        identifier: username,
        phoneNumber: user.phoneNumber,
        data: { error: `Fraud detection error: ${fraudError.message}`, transactionId },
        timestamp: new Date(),
      }).save();
      return res.status(500).json({ error: 'Fraud detection failed', analyticsEventId: analytics._id });
    }

    if (fraudScore < -0.5) {
      await User.updateOne({ username }, { $set: { isFlagged: true } });
      const analytics = await new Analytics({
        event: 'withdraw_failed',
        identifier: username,
        phoneNumber: user.phoneNumber,
        data: {
          error: 'High-risk withdrawal detected',
          amount: withdrawAmount,
          transactionId,
          fraudScore,
          isFlagged: true,
          fraudAnalyticsEventId
        },
        timestamp: new Date(),
      }).save();
      return res.status(403).json({
        error: 'High-risk withdrawal detected',
        fraudScore,
        isFlagged: true,
        analyticsEventId: analytics._id,
        fraudAnalyticsEventId
      });
    }

    // Increment withdrawal attempts
    user.lastWithdrawAttempts = (user.lastWithdrawAttempts || 0) + 1;
    if (user.lastWithdrawAttempts >= 5) {
      user.isFlagged = true;
    }

    // Create analytics entry
    const analytics = await new Analytics({
      event: 'withdraw_request',
      identifier: username,
      phoneNumber: user.phoneNumber,
      data: {
        amount: withdrawAmount,
        fee,
        transactionId,
        fraudScore,
        fraudAnalyticsEventId,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      },
      timestamp: new Date(),
    }).save();

    // Add to pendingWithdrawals
    user.pendingWithdrawals = user.pendingWithdrawals || [];
    user.pendingWithdrawals.push({
      amount: withdrawAmount,
      transactionId,
      date: new Date(),
      status: 'pending',
      analyticsEventId: analytics._id,
      fraudAnalyticsEventId
    });
    await user.save();

    // Update AdminLedger with withdrawal fee
    await AdminLedger.updateOne(
      {},
      {
        $inc: { totalBalance: fee },
        $set: { lastUpdated: new Date() },
        $push: {
          transactions: {
            type: 'withdrawal_fee',
            amount: fee,
            sender: username,
            receiver: 'System',
            userTransactionIds: [transactionId],
            fraudScore,
            analyticsEventId: analytics._id,
            fraudAnalyticsEventId,
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            date: new Date(),
          },
        },
      },
      { upsert: true }
    );

    // Notify admin
    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      const notificationResult = await sendPushNotification(
        admin.pushToken,
        'New Withdrawal Request',
        `User ${username} submitted a withdrawal of K${withdrawAmount.toFixed(2)} (fee: K${fee.toFixed(2)}).`,
        {
          type: 'withdrawal_request',
          userId: user._id,
          withdrawalIndex: user.pendingWithdrawals.length - 1,
          transactionId,
          analyticsEventId: analytics._id,
          fraudAnalyticsEventId,
          ip: req.ip,
          userAgent: req.headers['user-agent'],
        },
        username
      );
      if (notificationResult.error) {
        console.error('[WithdrawRequest] Notification Error:', notificationResult.error);
        const analytics = await new Analytics({
          event: 'withdraw_notification_failed',
          identifier: username,
          phoneNumber: user.phoneNumber,
          data: {
            error: notificationResult.error,
            transactionId,
            analyticsEventId: analytics._id,
            fraudAnalyticsEventId
          },
          timestamp: new Date(),
        }).save();
      }
    }

    console.log('[WithdrawRequest] Success:', { username, amount: withdrawAmount, transactionId, fraudScore, analyticsEventId: analytics._id, fraudAnalyticsEventId });
    res.status(200).json({
      message: 'Withdrawal requested. Awaiting approval.',
      transactionId,
      fraudScore,
      analyticsEventId: analytics._id,
      fraudAnalyticsEventId
    });
  } catch (error) {
    console.error('[WithdrawRequest] Error:', {
      message: error.message,
      stack: error.stack,
      username,
      amount,
    });
    let status = 500;
    let errorMessage = 'Failed to request withdrawal';
    if (error.message.includes('Rate limit')) {
      status = 429;
      errorMessage = 'Too many requests. Please try again later.';
    }
    const analytics = await new Analytics({
      event: 'withdraw_failed',
      identifier: username || 'unknown',
      phoneNumber: user?.phoneNumber,
      data: {
        error: error.message,
        amount,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      },
      timestamp: new Date(),
    }).save();
    res.status(status).json({ error: errorMessage, analyticsEventId: analytics._id });
  }
});

// Withdraw (Direct)
router.post('/api/withdraw', authenticateToken(), generalRateLimiter, async (req, res) => {
  const { amount } = req.body;
  console.log('[WithdrawDirect] Request:', { amount, username: req.user.username });

  try {
    const withdrawAmount = parseFloat(amount);
    if (isNaN(withdrawAmount) || withdrawAmount <= 0) {
      const analytics = await new Analytics({
        event: 'withdraw_failed',
        identifier: req.user.username,
        data: { error: 'Invalid amount', amount },
        timestamp: new Date(),
      }).save();
      return res.status(400).json({ error: 'Invalid amount', analyticsEventId: analytics._id });
    }

    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      const analytics = await new Analytics({
        event: 'withdraw_failed',
        identifier: req.user.username,
        data: { error: 'User not found' },
        timestamp: new Date(),
      }).save();
      return res.status(404).json({ error: 'User not found', analyticsEventId: analytics._id });
    }

    if (!user.isActive || user.kycStatus !== 'verified') {
      const analytics = await new Analytics({
        event: 'withdraw_failed',
        identifier: req.user.username,
        data: { error: user.isActive ? 'KYC verification required' : 'Account is inactive' },
        timestamp: new Date(),
      }).save();
      return res.status(403).json({
        error: user.isActive ? 'KYC verification required' : 'Account is inactive',
        analyticsEventId: analytics._id,
      });
    }

    const fee = withdrawAmount <= 50 ? 0.50 :
                withdrawAmount <= 100 ? 1.00 :
                withdrawAmount <= 500 ? 1.50 :
                withdrawAmount <= 1000 ? 2.00 :
                withdrawAmount <= 5000 ? 3.00 : 5.00;
    const totalDeduction = withdrawAmount + fee;
    if (user.balance < totalDeduction) {
      const analytics = await new Analytics({
        event: 'withdraw_failed',
        identifier: req.user.username,
        data: { error: 'Insufficient balance including fee', amount, fee, balance: user.balance },
        timestamp: new Date(),
      }).save();
      return res.status(400).json({
        error: 'Insufficient balance including fee',
        analyticsEventId: analytics._id,
      });
    }

    // AI: Fraud detection via microservice
    let fraudScore = 1;
    try {
      const fraudResult = await axios.post('http://localhost:5000/predict', {
        username: req.user.username,
        amount: withdrawAmount,
        timestamp: Date.now(),
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });
      fraudScore = fraudResult.data.is_anomaly ? -1 : 1;
    } catch (fraudError) {
      console.error('[WithdrawDirect] Fraud Detection Error:', fraudError.message);
      fraudScore = 0; // Neutral score if fraud detection fails
    }

    if (user.isFlagged || fraudScore < -0.5) {
      const analytics = await new Analytics({
        event: 'withdraw_failed',
        identifier: req.user.username,
        data: { error: 'Account flagged for suspicious activity', amount, fraudScore, isFlagged: user.isFlagged },
        timestamp: new Date(),
      }).save();
      return res.status(403).json({
        error: 'Account flagged for suspicious activity. Contact support.',
        isFlagged: true,
        fraudScore,
        analyticsEventId: analytics._id,
      });
    }

    // Increment withdrawal attempts
    user.lastWithdrawAttempts = (user.lastWithdrawAttempts || 0) + 1;
    if (user.lastWithdrawAttempts >= 5) {
      user.isFlagged = true;
    }

    const transactionId = uuidv4();
    user.balance -= totalDeduction;
    user.transactions.push({
      _id: transactionId,
      type: 'withdrawn',
      amount: withdrawAmount,
      fee,
      toFrom: 'System',
      date: new Date(),
      analyticsEventId: null, // Will be updated below
    });

    const analytics = await new Analytics({
      event: 'withdraw_success',
      identifier: req.user.username,
      phoneNumber: user.phoneNumber,
      data: {
        amount: withdrawAmount,
        fee,
        transactionId,
        fraudScore,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      },
      timestamp: new Date(),
    }).save();

    // Update transaction with analyticsEventId
    user.transactions[user.transactions.length - 1].analyticsEventId = analytics._id;
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
            analyticsEventId: analytics._id,
          },
        },
      },
      { upsert: true }
    );

    console.log('[WithdrawDirect] Success:', { username: req.user.username, amount, transactionId });
    res.json({
      message: 'Withdrawal successful',
      amount: withdrawAmount,
      fee,
      transactionId,
      analyticsEventId: analytics._id,
    });
  } catch (error) {
    console.error('[WithdrawDirect] Error:', {
      message: error.message,
      stack: error.stack,
      body: req.body,
    });
    const analytics = await new Analytics({
      event: 'withdraw_failed',
      identifier: req.user.username || 'unknown',
      data: { error: error.message, amount },
      timestamp: new Date(),
    }).save();
    res.status(500).json({ error: 'Failed to process withdrawal', analyticsEventId: analytics._id });
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

// Analytics Endpoint
router.post('/analytics', authenticateToken(), generalRateLimiter, async (req, res) => {
  const { event, username, amount, transactionId, error, focusCount, errorCount, depositAttempts } = req.body;

  // Validate request
  if (!event || !username || !['deposit_submitted', 'deposit_failed', 'input_error', 'focus_event'].includes(event)) {
    console.error('[Analytics] Invalid request:', { event, username });
    return res.status(400).json({ error: 'Invalid event or username' });
  }
  if (username !== req.user.username) {
    console.error('[Analytics] Unauthorized:', { requested: username, actual: req.user.username });
    return res.status(403).json({ error: 'Unauthorized' });
  }

  try {
    const analyticsEntry = new Analytics({
      event,
      username,
      phoneNumber: req.user.phoneNumber,
      timestamp: new Date(),
      data: {
        amount: parseFloat(amount) || 0,
        transactionId: transactionId || '',
        error: error || '',
        focusCount: parseInt(focusCount) || 0,
        errorCount: parseInt(errorCount) || 0,
        depositAttempts: parseInt(depositAttempts) || 0,
      },
    });

    await analyticsEntry.save();
    console.log('[Analytics] Event saved:', { event, username, phoneNumber: req.user.phoneNumber });
    res.status(201).json({ message: 'Analytics event recorded' });
  } catch (error) {
    console.error('[Analytics] Error:', {
      message: error.message,
      stack: error.stack,
      body: req.body,
    });
    res.status(500).json({ error: 'Failed to record analytics event' });
  }
});

router.post('/update-trust-score', authenticateToken(['admin']), requireAdmin, generalRateLimiter, async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: 'Username required' });
  }
  try {
    const trustScore = await calculateTrustScore(username);
    if (trustScore === null) {
      return res.status(500).json({ error: 'Failed to calculate trust score' });
    }
    res.json({ message: 'Trust score updated', trustScore });
  } catch (error) {
    console.error('[UpdateTrustScore] Error:', error.message);
    res.status(500).json({ error: 'Server error updating trust score' });
  }
});

module.exports = router;