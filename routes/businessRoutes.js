const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const multerS3 = require('multer-s3');
const AWS = require('aws-sdk');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { Expo } = require('expo-server-sdk');
const { Business, BusinessTransaction } = require('../models/businessSchema');
const authenticateToken = require('../middleware/authenticateToken');
const path = require('path');

// Configure AWS S3
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION || 'us-east-1',
});

const S3_BUCKET = process.env.S3_BUCKET || 'zangena';

// Configure multer-s3 for file uploads
const uploadS3 = multer({
  storage: multerS3({
    s3,
    bucket: S3_BUCKET,
    acl: 'private',
    key: (req, file, cb) => {
      const ext = path.extname(file.originalname);
      cb(null, `kyc/${file.fieldname}-${Date.now()}${ext}`);
    },
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (['application/pdf', 'image/png', 'image/jpeg'].includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only PDF, PNG, or JPEG allowed'), false);
    }
  },
});

// Configure Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Initialize Expo SDK
const expo = new Expo();

// Secret key for JWT
const JWT_SECRET = process.env.JWT_SECRET;

// Helper: Convert Decimal128 to number
const convertDecimal128 = (obj) => {
  if (obj === null || obj === undefined) return null;
  if (obj.constructor.name === 'Decimal128') {
    const strValue = obj.toString();
    return isNaN(strValue) ? 0 : parseFloat(strValue);
  }
  if (Array.isArray(obj)) {
    return obj.map(item => convertDecimal128(item));
  }
  if (typeof obj === 'object') {
    const newObj = {};
    for (const key in obj) {
      newObj[key] = convertDecimal128(obj[key]);
    }
    return newObj;
  }
  return obj;
};

// Helper: Send email
async function sendEmail(to, subject, html) {
  if (!to || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) {
    console.error('[SendEmail] Invalid email:', to);
    return;
  }
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER || 'no-reply@zangena.com',
      to,
      subject,
      html,
    });
    console.log(`[SendEmail] Sent to ${to}: ${subject}`);
  } catch (error) {
    console.error(`[SendEmail] Error sending to ${to}: ${error.message}`);
  }
}

// Helper: Send push notification
async function sendPushNotification(pushToken, title, body, data = {}) {
  if (!pushToken || !Expo.isExpoPushToken(pushToken)) {
    console.error('[PushNotification] Invalid push token:', pushToken);
    return;
  }
  const message = {
    to: pushToken,
    sound: 'default',
    title,
    body,
    data,
  };
  try {
    await expo.sendPushNotificationsAsync([message]);
    console.log(`[PushNotification] Sent to ${pushToken}: ${title} - ${body}`);
  } catch (error) {
    console.error(`[PushNotification] Error sending to ${pushToken}: ${error.message}`);
  }
}

// Email templates
const emailTemplates = {
  signup: (business) => `
    <h2>Business Registration Submitted</h2>
    <p>Dear ${business.name},</p>
    <p>Your registration is pending approval:</p>
    <ul>
      <li><strong>Business ID:</strong> ${business.businessId}</li>
      <li><strong>Name:</strong> ${business.name}</li>
    </ul>
    <p>You'll be notified once approved.</p>
    <p>Zangena Team</p>
  `,
  deposit: (business, deposit) => `
    <h2>Deposit Submitted</h2>
    <p>Dear ${business.name},</p>
    <p>Your deposit request:</p>
    <ul>
      <li><strong>Amount:</strong> ZMW ${deposit.amount.toFixed(2)}</li>
      <li><strong>Transaction ID:</strong> ${deposit.transactionId}</li>
    </ul>
    <p>Awaiting verification.</p>
    <p>Zangena Team</p>
  `,
  withdrawal: (business, withdrawal) => `
    <h2>Withdrawal Requested</h2>
    <p>Dear ${business.name},</p>
    <p>Your withdrawal request:</p>
    <ul>
      <li><strong>Amount:</strong> ZMW ${withdrawal.amount.toFixed(2)}</li>
      <li><strong>Fee:</strong> ZMW ${withdrawal.fee.toFixed(2)}</li>
    </ul>
    <p>Awaiting approval.</p>
    <p>Zangena Team</p>
  `,
  transaction: (business, transaction) => `
    <h2>Payment Received</h2>
    <p>Dear ${business.name},</p>
    <p>New transaction:</p>
    <ul>
      <li><strong>Amount:</strong> ZMW ${transaction.amount.toFixed(2)}</li>
      <li><strong>From:</strong> ${transaction.fromUsername || 'Unknown'}</li>
      <li><strong>Transaction ID:</strong> ${transaction.transactionId}</li>
    </ul>
    <p>Zangena Team</p>
  `,
};

// Register Business
router.post('/register', uploadS3.fields([
  { name: 'tpinCertificate', maxCount: 1 },
  { name: 'pacraCertificate', maxCount: 1 },
]), async (req, res) => {
  const { businessId, name, ownerUsername, hashedPin, phoneNumber, email, bankDetails } = req.body;
  const tpinCertificate = req.files?.tpinCertificate?.[0];
  const pacraCertificate = req.files?.pacraCertificate?.[0];

  try {
    if (!businessId || !name || !ownerUsername || !hashedPin || !phoneNumber || !tpinCertificate || !pacraCertificate) {
      return res.status(400).json({ error: 'All required fields and documents needed' });
    }
    if (!/^\d{10}$/.test(businessId)) {
      return res.status(400).json({ error: 'Business ID must be 10 digits' });
    }
    if (!/^[a-zA-Z0-9]{3,}$/.test(ownerUsername)) {
      return res.status(400).json({ error: 'Username must be 3+ alphanumeric characters' });
    }
    if (!/^\d{4}$/.test(hashedPin)) {
      return res.status(400).json({ error: 'PIN must be 4 digits' });
    }
    if (!/^\+260(9[5678]|7[34679])\d{7}$/.test(phoneNumber)) {
      return res.status(400).json({ error: 'Invalid Zambian phone number' });
    }
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email' });
    }
    let parsedBankDetails;
    if (bankDetails) {
      try {
        parsedBankDetails = typeof bankDetails === 'string' ? JSON.parse(bankDetails) : bankDetails;
        if (!['bank', 'mobile_money'].includes(parsedBankDetails.accountType)) {
          return res.status(400).json({ error: 'Account type must be bank or mobile_money' });
        }
        if (!parsedBankDetails.bankName || !parsedBankDetails.accountNumber) {
          return res.status(400).json({ error: 'Bank name and account number required' });
        }
      } catch (error) {
        return res.status(400).json({ error: 'Invalid bank details' });
      }
    }
    const existing = await Business.findOne({
      $or: [{ businessId }, { ownerUsername }, { phoneNumber }, email ? { email } : {}].filter(Boolean),
    });
    if (existing) {
      return res.status(409).json({ error: 'Business ID, username, phone, or email already taken' });
    }
    const business = new Business({
      businessId,
      name,
      ownerUsername,
      hashedPin, // Will be hashed by schema middleware
      phoneNumber,
      email,
      bankDetails: parsedBankDetails,
      tpinCertificate: tpinCertificate?.key,
      pacraCertificate: pacraCertificate?.key,
      kycStatus: 'pending',
      isActive: false,
      balance: mongoose.Types.Decimal128.fromString('0'),
      transactions: [],
      pendingDeposits: [],
      pendingWithdrawals: [],
    });
    await business.save();
    if (business.email) {
      await sendEmail(business.email, 'Registration Submitted', emailTemplates.signup(business));
    }
    res.status(201).json({ message: 'Business registered, awaiting approval', businessId });
  } catch (error) {
    console.error('[Register] Error:', error.message);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { businessId, pin } = req.body;
  try {
    if (!businessId || !pin) {
      return res.status(400).json({ error: 'Business ID and PIN required' });
    }
    if (!/^\d{10}$/.test(businessId) || !/^\d{4}$/.test(pin)) {
      return res.status(400).json({ error: 'Invalid Business ID or PIN' });
    }
    const business = await Business.findOne({ businessId }).lean();
    if (!business || !business.isActive) {
      return res.status(403).json({ error: 'Business not found or inactive' });
    }
    const isPinValid = await bcrypt.compare(pin, business.hashedPin);
    if (!isPinValid) {
      return res.status(401).json({ error: 'Invalid PIN' });
    }
    const token = jwt.sign({ businessId, role: 'business' }, JWT_SECRET, { expiresIn: '30d' });
    res.json({
      token,
      business: {
        businessId,
        name: business.name,
        balance: convertDecimal128(business.balance),
        isActive: business.isActive,
      },
    });
  } catch (error) {
    console.error('[Login] Error:', error.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Fetch Business Details
router.get('/:businessId', authenticateToken(['business']), async (req, res) => {
  try {
    const business = await Business.findOne({ businessId: req.params.businessId }).lean();
    if (!business || req.user.businessId !== business.businessId) {
      return res.status(403).json({ error: 'Unauthorized or business not found' });
    }
    res.json(convertDecimal128({
      businessId: business.businessId,
      name: business.name,
      balance: business.balance,
      isActive: business.isActive,
    }));
  } catch (error) {
    console.error('[BusinessFetch] Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch business' });
  }
});

// Generate QR Code
router.post('/qr/generate', authenticateToken(['business']), async (req, res) => {
  const { amount, description } = req.body;
  try {
    if (!description || !amount || amount <= 0) {
      return res.status(400).json({ error: 'Amount and description required' });
    }
    const business = await Business.findOne({ businessId: req.user.businessId });
    if (!business || !business.isActive) {
      return res.status(403).json({ error: 'Business not found or inactive' });
    }
    const transactionId = `tx_${crypto.randomBytes(8).toString('hex')}`;
    const transaction = new BusinessTransaction({
      transactionId,
      businessId: business.businessId,
      amount,
      status: 'pending',
      description,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000),
    });
    await transaction.save();
    res.json({ transactionId, expiresAt: transaction.expiresAt });
  } catch (error) {
    console.error('[QRGenerate] Error:', error.message);
    res.status(500).json({ error: 'Failed to generate QR code' });
  }
});

// Process QR Payment
router.post('/qr/pay', authenticateToken(['business']), async (req, res) => {
  const { transactionId, amount } = req.body;
  try {
    if (!transactionId || !amount || amount <= 0) {
      return res.status(400).json({ error: 'Transaction ID and valid amount required' });
    }
    const transaction = await BusinessTransaction.findOne({ transactionId, status: 'pending' });
    if (!transaction || transaction.expiresAt < new Date()) {
      return res.status(400).json({ error: 'Invalid or expired transaction' });
    }
    const business = await Business.findOne({ businessId: transaction.businessId });
    if (!business || !business.isActive) {
      return res.status(403).json({ error: 'Business not found or inactive' });
    }
    business.balance = mongoose.Types.Decimal128.fromString((convertDecimal128(business.balance) + amount).toString());
    business.transactions.push({
      _id: crypto.randomBytes(16).toString('hex'),
      type: 'received',
      amount: mongoose.Types.Decimal128.fromString(amount.toString()),
      toFrom: 'Customer',
      date: new Date(),
    });
    transaction.status = 'completed';
    transaction.amount = amount;
    await Promise.all([business.save(), transaction.save()]);
    if (business.email) {
      await sendEmail(business.email, 'Payment Received', emailTemplates.transaction(business, {
        transactionId,
        amount,
        fromUsername: 'Customer',
      }));
    }
    if (business.pushToken) {
      await sendPushNotification(business.pushToken, 'Payment Received', `Received ${amount.toFixed(2)} ZMW`, { transactionId });
    }
    res.json({ message: 'Payment successful', transactionId, amount });
  } catch (error) {
    console.error('[QRPay] Error:', error.message);
    res.status(400).json({ error: error.message });
  }
});

// Dashboard Metrics
router.get('/dashboard', authenticateToken(['business']), async (req, res) => {
  try {
    const business = await Business.findOne({ businessId: req.user.businessId }).lean();
    if (!business || !business.isActive) {
      return res.status(403).json({ error: 'Business not found or inactive' });
    }
    const metrics = await BusinessTransaction.aggregate([
      { $match: { businessId: business.businessId, status: 'completed' } },
      {
        $group: {
          _id: null,
          totalRevenue: { $sum: '$amount' },
          transactionCount: { $sum: 1 },
        },
      },
    ]);
    const recentTransactions = await BusinessTransaction.find({
      businessId: business.businessId,
      status: 'completed',
    })
      .select('transactionId amount description createdAt')
      .sort({ createdAt: -1 })
      .limit(5)
      .lean();
    res.json(convertDecimal128({
      totalRevenue: metrics[0]?.totalRevenue || 0,
      transactionCount: metrics[0]?.transactionCount || 0,
      recentTransactions,
    }));
  } catch (error) {
    console.error('[Dashboard] Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// Manual Deposit
router.post('/deposit/manual', authenticateToken(['business']), async (req, res) => {
  const { amount, transactionId } = req.body;
  try {
    const business = await Business.findOne({ businessId: req.user.businessId });
    if (!business || !business.isActive) {
      return res.status(403).json({ error: 'Business not found or inactive' });
    }
    if (!amount || amount <= 0 || !transactionId) {
      return res.status(400).json({ error: 'Valid amount and transaction ID required' });
    }
    if (business.pendingDeposits.some(d => d.transactionId === transactionId)) {
      return res.status(400).json({ error: 'Transaction ID already used' });
    }
    const deposit = {
      amount: mongoose.Types.Decimal128.fromString(amount.toString()),
      transactionId,
      date: new Date(),
      status: 'pending',
    };
    business.pendingDeposits.push(deposit);
    await business.save();
    if (business.email) {
      await sendEmail(business.email, 'Deposit Submitted', emailTemplates.deposit(business, convertDecimal128(deposit)));
    }
    if (business.pushToken) {
      await sendPushNotification(business.pushToken, 'Deposit Submitted', `Deposit of ${amount.toFixed(2)} ZMW submitted`, { transactionId });
    }
    res.json({ message: 'Deposit submitted for verification' });
  } catch (error) {
    console.error('[Deposit] Error:', error.message);
    res.status(500).json({ error: 'Failed to submit deposit' });
  }
});

// Withdrawal Request
router.post('/withdraw/request', authenticateToken(['business']), async (req, res) => {
  const { amount, destination } = req.body;
  try {
    const business = await Business.findOne({ businessId: req.user.businessId });
    if (!business || !business.isActive) {
      return res.status(403).json({ error: 'Business not found or inactive' });
    }
    const withdrawalAmount = parseFloat(amount);
    if (!withdrawalAmount || withdrawalAmount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    if (!destination || !['bank', 'mobile_money'].includes(destination.type) || !destination.bankName || !destination.accountNumber) {
      return res.status(400).json({ error: 'Valid destination required' });
    }
    const withdrawalFee = Math.max(withdrawalAmount * 0.01, 2);
    const totalDeduction = withdrawalAmount + withdrawalFee;
    if (convertDecimal128(business.balance) < totalDeduction) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    const withdrawal = {
      amount: mongoose.Types.Decimal128.fromString(withdrawalAmount.toString()),
      fee: mongoose.Types.Decimal128.fromString(withdrawalFee.toString()),
      date: new Date(),
      status: 'pending',
      destination,
    };
    business.pendingWithdrawals.push(withdrawal);
    await business.save();
    if (business.email) {
      await sendEmail(business.email, 'Withdrawal Requested', emailTemplates.withdrawal(business, convertDecimal128(withdrawal)));
    }
    if (business.pushToken) {
      await sendPushNotification(business.pushToken, 'Withdrawal Requested', `Requested ${withdrawalAmount.toFixed(2)} ZMW`, { businessId: business.businessId });
    }
    res.json({ message: 'Withdrawal requested, awaiting approval', withdrawalFee });
  } catch (error) {
    console.error('[Withdraw] Error:', error.message);
    res.status(500).json({ error: 'Failed to request withdrawal' });
  }
});

// Register Push Token
router.post('/register-push-token', authenticateToken(['business']), async (req, res) => {
  const { pushToken } = req.body;
  try {
    if (!pushToken) {
      return res.status(400).json({ error: 'Push token required' });
    }
    const business = await Business.findOne({ businessId: req.user.businessId });
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    business.pushToken = pushToken;
    await business.save();
    res.json({ message: 'Push token registered' });
  } catch (error) {
    console.error('[PushToken] Error:', error.message);
    res.status(500).json({ error: 'Failed to register push token' });
  }
});

module.exports = router;