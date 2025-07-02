const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const crypto = require('crypto');
const multer = require('multer');
const { S3Client } = require('@aws-sdk/client-s3');
const multerS3 = require('multer-s3');
const nodemailer = require('nodemailer');
const { Expo } = require('expo-server-sdk');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { Business, BusinessTransaction } = require('../models/Business');
const User = require('../models/User');
const QRPin = require('../models/QRPin');
const AdminLedger = require('../models/AdminLedger');
const rateLimit = require('express-rate-limit');

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const S3_BUCKET = process.env.S3_BUCKET || 'zangena-files';
const EMAIL_USER = process.env.EMAIL_USER || 'your_email@example.com';
const EMAIL_PASS = process.env.EMAIL_PASS || 'your_email_password';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;

// S3 setup
const s3Client = new S3Client({ region: AWS_REGION });
const upload = multer({
  storage: multerS3({
    s3: s3Client,
    bucket: S3_BUCKET,
    key: (req, file, cb) => cb(null, `certificates/${Date.now()}_${file.originalname}`),
  }),
});

// Email and push notification setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: EMAIL_USER, pass: EMAIL_PASS },
});
const expo = new Expo();

// Rate limiters
const forgotPinLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many PIN reset requests, try again after 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.warn('[ForgotPin] Rate limit exceeded for IP:', req.ip);
    res.status(429).json({ error: 'Too many PIN reset requests, try again after 15 minutes' });
  },
});

const updateEmailLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many email update requests, try again after 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    console.warn('[UpdateEmail] Rate limit exceeded for IP:', req.ip);
    res.status(429).json({ error: 'Too many email update requests, try again after 15 minutes' });
  },
});

const twoFactorLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { error: 'Too many 2FA attempts, try again later' },
  keyGenerator: (req) => req.body.businessId || req.ip,
});

// Utility Functions
const sendNotification = async (business, subject, text, pushTitle, pushBody, pushData) => {
  if (business.email && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(business.email)) {
    await transporter.sendMail({ from: EMAIL_USER, to: business.email, subject, text }).catch(err => 
      console.error(`[Email] Error: ${err.message}`));
  }
  if (business.pushToken && Expo.isExpoPushToken(business.pushToken)) {
    await expo.sendPushNotificationsAsync([{
      to: business.pushToken,
      sound: 'default',
      title: pushTitle,
      body: pushBody,
      data: pushData,
    }]).catch(err => console.error(`[Push] Error: ${err.message}`));
  }
};

const logAudit = async (business, action, performedBy, details) => {
  business.auditLogs.push({ action, performedBy, details, timestamp: new Date() });
  await business.save();
};

const convertDecimal128 = (value) => (value ? parseFloat(value.toString()) : 0);

// Transaction function to process payment logic
const transaction = async (data, session) => {
  const { qrId, amount, senderUsername, businessId } = data;
  const paymentAmount = parseFloat(amount);
  if (isNaN(paymentAmount) || paymentAmount <= 0 || paymentAmount > 10000) {
    throw new Error('Amount must be between 0 and 10,000 ZMW');
  }

  const user = await User.findOne({ username: senderUsername, isActive: true }).session(session);
  if (!user) throw new Error('User not found or inactive');

  const qrPin = await QRPin.findOne({ qrId, type: 'business', isActive: true }).session(session);
  if (!qrPin || !qrPin.isEffectivelyUsable || (businessId && qrPin.businessId !== businessId)) {
    throw new Error('Invalid, inactive, or mismatched QR code');
  }

  const business = await Business.findOne({ businessId: qrPin.businessId, isActive: true }).session(session);
  if (!business) throw new Error('Business not found or inactive');

  const sendingFee = paymentAmount <= 50 ? 0.50 : paymentAmount <= 100 ? 1.00 : paymentAmount <= 500 ? 2.00 :
                     paymentAmount <= 1000 ? 2.50 : paymentAmount <= 5000 ? 3.50 : 5.00;
  const receivingFee = paymentAmount <= 50 ? 0.50 : paymentAmount <= 100 ? 1.00 : paymentAmount <= 500 ? 1.50 :
                       paymentAmount <= 1000 ? 2.00 : paymentAmount <= 5000 ? 3.00 : 5.00;
  if (user.balance < paymentAmount + sendingFee) {
    throw new Error('Insufficient balance');
  }

  const sentTxId = new mongoose.Types.ObjectId().toString();
  const receivedTxId = new mongoose.Types.ObjectId().toString();
  const transactionDate = new Date();

  await User.bulkWrite([{
    updateOne: {
      filter: { _id: user._id },
      update: {
        $inc: { balance: -(paymentAmount + sendingFee) },
        $push: { transactions: { _id: sentTxId, type: 'sent', amount: paymentAmount, toFrom: business.businessId, fee: sendingFee, date: transactionDate, qrId } },
      },
    },
  }], { session });

  await Business.bulkWrite([{
    updateOne: {
      filter: { _id: business._id },
      update: {
        $inc: { 'balances.ZMW': paymentAmount - receivingFee },
        $push: {
          transactions: { _id: receivedTxId, type: 'received', amount: paymentAmount, currency: 'ZMW', toFrom: user.username, fee: receivingFee, date: transactionDate, qrId, isRead: false },
          auditLogs: { action: 'transaction_received', performedBy: user.username, details: { amount: paymentAmount, fee: receivingFee, qrId }, timestamp: new Date() },
        },
      },
    },
  }], { session });

  await AdminLedger.updateOne({}, {
    $inc: { totalBalance: sendingFee + receivingFee },
    $set: { lastUpdated: new Date() },
    $push: { transactions: { type: 'fee-collected', amount: sendingFee + receivingFee, sender: user.username, receiver: business.businessId, userTransactionIds: [sentTxId, receivedTxId], date: transactionDate, qrId } },
  }, { upsert: true, session });

  await sendNotification(business, 'New Transaction Received', `Received ${paymentAmount} ZMW from ${user.username}.`, 
    'New Transaction', `Received ${paymentAmount} ZMW from ${user.username}.`, { businessId: business.businessId, transactionId: receivedTxId });

  return { message: 'Payment successful', sendingFee, receivingFee, amount: paymentAmount };
};

// Middleware
const authenticateToken = (roles = ['business', 'admin']) => (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    if (!roles.includes(user.role)) return res.status(403).json({ error: 'Unauthorized role' });
    req.user = user;
    next();
  });
};

const require2FA = async (req, res, next) => {
  const business = await Business.findOne({ businessId: req.user.businessId }).select('twoFactorEnabled twoFactorSecret ownerUsername');
  if (business.twoFactorEnabled && !req.body.totpCode) {
    return res.status(400).json({ error: '2FA code required', twoFactorRequired: true });
  }
  if (business.twoFactorEnabled) {
    const isValid = speakeasy.totp.verify({
      secret: business.twoFactorSecret,
      encoding: 'base32',
      token: req.body.totpCode,
    });
    if (!isValid) {
      await logAudit(business, '2fa_verify', business.ownerUsername, { success: false, message: 'Invalid 2FA code' });
      return res.status(401).json({ error: 'Invalid 2FA code' });
    }
    await logAudit(business, '2fa_verify', business.ownerUsername, { success: true, message: '2FA verified' });
  }
  next();
};

const validateBusinessId = (req, res, next) => {
  const { businessId } = req.params;
  if (!businessId) return res.status(400).json({ error: 'Business ID is required' });
  if (req.user.role !== 'admin' && req.user.businessId !== businessId) {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  next();
};

// Register Business
router.post('/register', upload.fields([
  { name: 'tpinCertificate', maxCount: 1 },
  { name: 'pacraCertificate', maxCount: 1 },
]), async (req, res) => {
  const { businessId, name, ownerUsername, pin, phoneNumber, email } = req.body;
  const { tpinCertificate, pacraCertificate } = req.files || {};
  if (!/^\d{10}$/.test(businessId) || !/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'Business ID must be a 10-digit TPIN and PIN must be a 4-digit number' });
  }
  const existing = await Business.findOne({ $or: [{ businessId }, { ownerUsername }, { phoneNumber }, { email }] });
  if (existing) return res.status(400).json({ error: 'Business ID, username, phone, or email already exists' });
  
  const business = new Business({
    businessId,
    name,
    ownerUsername,
    phoneNumber,
    email,
    hashedPin: await bcrypt.hash(pin, 10),
    tpinCertificate: tpinCertificate?.[0].location,
    pacraCertificate: pacraCertificate?.[0].location,
    kycStatus: 'pending',
    isActive: false,
  });
  await business.save();
  await sendNotification(business, 'Welcome to Zangena', `Welcome ${name}! Your account is pending KYC verification.`, 
    'Welcome to Zangena', 'Your account is pending KYC verification.', { businessId });
  res.status(201).json({ message: 'Business registered. Awaiting KYC verification' });
});

// Enable 2FA
router.post('/enable-2fa', authenticateToken(['business']), async (req, res) => {
  const business = await Business.findOne({ businessId: req.user.businessId });
  if (!business || !business.isActive) return res.status(404).json({ error: 'Business not found or inactive' });
  if (business.twoFactorEnabled) return res.status(400).json({ error: '2FA already enabled' });
  
  const secret = speakeasy.generateSecret({ name: `Zangena Business (${business.name})`, issuer: 'Zangena' });
  business.twoFactorSecret = secret.base32;
  business.twoFactorEnabled = true;
  await logAudit(business, '2fa_enable', business.ownerUsername, { message: '2FA enabled' });
  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
  await sendNotification(business, '2FA Enabled', `2FA enabled for ${business.name}. Scan the QR code in your authenticator app.`, 
    '2FA Enabled', 'Set up your authenticator app.', { businessId: business.businessId, qrCodeUrl });
  res.json({ qrCodeUrl, secret: secret.base32 });
});

// Disable 2FA
router.post('/disable-2fa', authenticateToken(['business']), require2FA, async (req, res) => {
  const business = await Business.findOne({ businessId: req.user.businessId });
  if (!business || !business.isActive) return res.status(404).json({ error: 'Business not found or inactive' });
  if (!business.twoFactorEnabled) return res.status(400).json({ error: '2FA is not enabled' });
  
  business.twoFactorSecret = null;
  business.twoFactorEnabled = false;
  await logAudit(business, '2fa_disable', business.ownerUsername, { message: '2FA disabled' });
  await sendNotification(business, '2FA Disabled', `2FA disabled for ${business.name}.`, 
    '2FA Disabled', '2FA has been disabled.', { businessId: business.businessId });
  res.json({ message: '2FA disabled successfully' });
});

// Verify 2FA
router.post('/verify-2fa', twoFactorLimiter, authenticateToken(['business']), async (req, res) => {
  const { totpCode } = req.body;
  if (!totpCode) return res.status(400).json({ error: '2FA code required' });
  
  const business = await Business.findOne({ businessId: req.user.businessId }).select('twoFactorSecret twoFactorEnabled ownerUsername');
  if (!business || !business.isActive) return res.status(404).json({ error: 'Business not found or inactive' });
  if (!business.twoFactorEnabled || !business.twoFactorSecret) return res.status(400).json({ error: '2FA not enabled' });
  
  const isValid = speakeasy.totp.verify({ secret: business.twoFactorSecret, encoding: 'base32', token: totpCode });
  if (!isValid) {
    await logAudit(business, '2fa_verify', business.ownerUsername, { success: false, message: 'Invalid 2FA code' });
    return res.status(401).json({ error: 'Invalid 2FA code' });
  }
  await logAudit(business, '2fa_verify', business.ownerUsername, { success: true, message: '2FA verified' });
  res.json({ message: '2FA verified successfully' });
});

// Login
router.post('/login', async (req, res) => {
  const { businessId, phoneNumber, pin, totpCode } = req.body;
  if (!pin || (!businessId && !phoneNumber)) return res.status(400).json({ error: 'Business ID or phone number and PIN required' });
  
  const business = await Business.findOne(businessId ? { businessId } : { phoneNumber }).select('+hashedPin +twoFactorSecret +twoFactorEnabled');
  if (!business || !business.isActive) return res.status(404).json({ error: 'Business not found or inactive' });
  
  const isPinValid = await bcrypt.compare(pin, business.hashedPin);
  if (!isPinValid) {
    await logAudit(business, 'login', business.ownerUsername, { success: false, message: 'Invalid PIN' });
    return res.status(401).json({ error: 'Invalid PIN' });
  }
  
  if (business.twoFactorEnabled && !totpCode) {
    return res.status(200).json({ twoFactorRequired: true, businessId: business.businessId });
  }
  if (business.twoFactorEnabled) {
    const isValid = speakeasy.totp.verify({ secret: business.twoFactorSecret, encoding: 'base32', token: totpCode });
    if (!isValid) {
      await logAudit(business, '2fa_verify', business.ownerUsername, { success: false, message: 'Invalid 2FA code' });
      return res.status(401).json({ error: 'Invalid 2FA code' });
    }
    await logAudit(business, '2fa_verify', business.ownerUsername, { success: true, message: '2FA verified' });
  }
  
  const token = jwt.sign({ businessId: business.businessId, role: 'business' }, JWT_SECRET, { expiresIn: '1d' });
  await Business.updateOne({ _id: business._id }, { 
    $set: { lastLogin: new Date() },
    $push: { auditLogs: { action: 'login', performedBy: business.ownerUsername, details: { success: true, ip: req.ip } } }
  });
  await sendNotification(business, 'Login Successful', `Welcome back, ${business.name}!`, 
    'Login Successful', `Welcome back, ${business.name}!`, { businessId: business.businessId });
  
  res.json({
    token,
    business: {
      businessId: business.businessId,
      name: business.name,
      ownerUsername: business.ownerUsername,
      balances: {
        ZMW: convertDecimal128(business.balances.ZMW),
        ZMC: convertDecimal128(business.balances.ZMC),
        USD: convertDecimal128(business.balances.USD),
      },
      isActive: business.isActive,
      kycStatus: business.kycStatus,
      accountTier: business.accountTier,
      twoFactorEnabled: business.twoFactorEnabled,
    },
  });
});

// Dashboard
router.get('/dashboard', authenticateToken(['business']), async (req, res) => {
  const { page = 1, currency = 'all', dateRange = '30d' } = req.query;
  const limit = 10;
  const skip = (page - 1) * limit;
  const dateFilter = {
    '30d': new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
    '7d': new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
    '1d': new Date(Date.now() - 24 * 60 * 60 * 1000),
  };
  
  const business = await Business.findOne({ businessId: req.user.businessId }).lean();
  if (!business || !business.isActive) return res.status(404).json({ error: 'Business not found or inactive' });
  
  const query = {
    businessId: req.user.businessId,
    status: 'completed',
    createdAt: { $gte: dateFilter[dateRange] || dateFilter['30d'] },
  };
  if (currency !== 'all') query.currency = currency;
  
  const transactions = await BusinessTransaction.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit).lean();
  const totalRevenue = transactions.reduce((sum, t) => sum + convertDecimal128(t.amount), 0);
  const transactionCount = await BusinessTransaction.countDocuments(query);
  
  await logAudit(business, 'view_dashboard', business.ownerUsername, { message: 'Dashboard accessed' });
  res.json({
    totalRevenue,
    transactionCount,
    recentTransactions: transactions.map(t => ({
      transactionId: t.transactionId,
      amount: convertDecimal128(t.amount),
      currency: t.currency,
      fromUsername: t.fromUsername || 'Unknown',
      createdAt: t.createdAt,
    })),
  });
});

// Debug Dashboard
router.get('/debug-dashboard', authenticateToken(['business', 'admin']), async (req, res) => {
  const business = await Business.findOne({ businessId: req.user.businessId }).lean();
  res.json({
    user: req.user,
    business: business ? {
      businessId: business.businessId,
      name: business.name,
      isActive: business.isActive,
      kycStatus: business.kycStatus,
      twoFactorEnabled: business.twoFactorEnabled,
    } : null,
  });
});

// Manual Deposit
router.post('/deposit/manual', authenticateToken(['business']), async (req, res) => {
  const { amount, sourceOfFunds } = req.body;
  const business = await Business.findOne({ businessId: req.user.businessId });
  if (!business || !business.isActive) return res.status(403).json({ error: 'Business not found or inactive' });
  
  const depositAmount = parseFloat(amount);
  if (!depositAmount || depositAmount <= 0) return res.status(400).json({ error: 'Invalid amount' });
  if (depositAmount > business.transactionLimits.maxPerTransaction) {
    return res.status(400).json({ error: `Deposit exceeds max transaction limit of ${business.transactionLimits.maxPerTransaction} ZMW` });
  }
  if (!['bank_transfer', 'mobile_money', 'cash', 'other'].includes(sourceOfFunds)) {
    return res.status(400).json({ error: 'Invalid source of funds' });
  }
  
  const transactionId = crypto.randomBytes(16).toString('hex');
  business.pendingDeposits.push({ amount: depositAmount, currency: 'ZMW', transactionId, sourceOfFunds });
  await logAudit(business, 'deposit_request', business.ownerUsername, { amount: depositAmount, sourceOfFunds });
  await sendNotification(business, 'Deposit Request Submitted', `Deposit of ${depositAmount} ZMW is pending approval.`, 
    'Deposit Requested', `Your deposit of ${depositAmount} ZMW is pending.`, { businessId: business.businessId });
  res.json({ message: 'Deposit request submitted', transactionId });
});

// Withdrawal Request
router.post('/withdraw/request', authenticateToken(['business']), require2FA, async (req, res) => {
  const { amount, destination, currency } = req.body;
  const business = await Business.findOne({ businessId: req.user.businessId });
  if (!business || !business.isActive) return res.status(403).json({ error: 'Business not found or inactive' });
  
  const amountNum = parseFloat(amount);
  if (!amountNum || amountNum <= 0) return res.status(400).json({ error: 'Invalid amount' });
  if (amountNum > business.transactionLimits.maxPerTransaction) {
    return res.status(400).json({ error: `Withdrawal exceeds max transaction limit of ${business.transactionLimits.maxPerTransaction} ZMW` });
  }
  if (!destination || !['bank', 'mobile_money'].includes(destination.type)) {
    return res.status(400).json({ error: 'Valid destination type required (bank or mobile_money)' });
  }
  
  const withdrawalFee = Math.max(amountNum * 0.01, 2);
  const totalDeduction = amountNum + withdrawalFee;
  if (convertDecimal128(business.balances.ZMW) < totalDeduction) {
    return res.status(400).json({ error: 'Insufficient balance to cover amount and fee' });
  }
  
  const transactionId = crypto.randomBytes(16).toString('hex');
  const withdrawal = {
    amount: amountNum,
    fee: withdrawalFee,
    currency: 'ZMW',
    date: new Date(),
    destination: {
      type: destination.type,
      bankName: destination.bankName || '',
      accountNumber: destination.accountNumber || '',
      swiftCode: destination.swiftCode || '',
    },
  };
  const transaction = {
    _id: transactionId,
    type: 'withdrawn',
    amount: amountNum,
    currency: 'ZMW',
    toFrom: destination.type === 'bank' ? destination.bankName : destination.accountNumber,
    fee: withdrawalFee,
    date: new Date(),
    status: 'pending',
    isRead: false,
  };
  
  business.pendingWithdrawals.push(withdrawal);
  business.transactions.push(transaction);
  await logAudit(business, 'withdrawal_request', business.ownerUsername, { amount: amountNum, fee: withdrawalFee, destination, transactionId });
  await sendNotification(business, 'Withdrawal Request Submitted', 
    `Your withdrawal of ${amountNum} ZMW (Fee: ${withdrawalFee} ZMW) to ${destination.type} is pending approval. Transaction ID: ${transactionId}`, 
    'Withdrawal Requested', `Your request for ${amountNum} ZMW to ${destination.type} is pending.`, 
    { businessId: business.businessId, transactionId });
  await sendNotification({ email: ADMIN_EMAIL }, `Withdrawal Request - ${business.businessId}`, 
    `Business: ${business.name}\nAmount: ${amountNum} ZMW\nFee: ${withdrawalFee} ZMW\nDestination: ${destination.type}`, null, null, null);
  res.json({ message: 'Withdrawal requested. Awaiting approval', withdrawalFee, transactionId });
});

// Verify KYC
router.post('/verify-kyc', authenticateToken(['admin']), async (req, res) => {
  const { businessId, approved, rejectionReason } = req.body;
  const business = await Business.findOne({ businessId });
  if (!business) return res.status(404).json({ error: 'Business not found' });
  
  business.kycStatus = approved ? 'verified' : 'rejected';
  if (!approved && rejectionReason) business.kycDetails.rejectionReason = rejectionReason;
  if (approved) {
    business.isActive = true;
    business.kycDetails.sanctionsScreening = { status: 'clear', lastChecked: new Date() };
  }
  await logAudit(business, 'kyc_update', req.user.businessId, { approved, rejectionReason });
  await sendNotification(business, approved ? 'KYC Approved' : 'KYC Rejected', 
    approved ? `Your KYC for ${business.name} has been approved!` : `KYC rejected: ${rejectionReason}`, 
    approved ? 'KYC Approved' : 'KYC Rejected', approved ? 'Your account is now active!' : `KYC rejected: ${rejectionReason}`, 
    { businessId });
  res.json({ message: `KYC ${approved ? 'approved' : 'rejected'}` });
});

// Generate QR Code
router.post('/qr/generate', authenticateToken(['business']), async (req, res) => {
  const { pin, amount, description } = req.body;
  if (!pin || !/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'Valid 4-digit PIN required' });
  
  const business = await Business.findOne({ businessId: req.user.businessId }).select('+hashedPin');
  if (!business || !business.isActive) return res.status(403).json({ error: 'Business not found or inactive' });
  
  const isPinValid = await bcrypt.compare(pin, business.hashedPin);
  if (!isPinValid) {
    await logAudit(business, 'qr_generate', business.ownerUsername, { success: false, message: 'Invalid PIN', amount, description });
    return res.status(401).json({ error: 'Invalid PIN' });
  }
  
  const qrId = crypto.randomBytes(16).toString('hex');
  const qrData = JSON.stringify({ type: 'business_payment', businessId: business.businessId, qrId, amount, description });
  const qrCodeUrl = await QRCode.toDataURL(qrData);
  
  const qrPin = new QRPin({ qrId, type: 'business', businessId: business.businessId, isActive: true });
  await qrPin.save();
  
  business.transactions.push({
    _id: crypto.randomBytes(16).toString('hex'),
    type: 'pending-pin',
    amount: amount ? parseFloat(amount) : 0,
    currency: 'ZMW',
    toFrom: 'Self',
    date: new Date(),
    status: 'completed',
    qrId,
    description: description || 'QR code generated',
  });
  await logAudit(business, 'qr_generate', business.ownerUsername, { success: true, qrId, amount, description });
  await sendNotification(business, 'QR Code Generated', `New QR code generated for ${business.name}.`, 
    'QR Code Generated', `New QR code for ${business.name}.`, { businessId: business.businessId });
  
  res.json({ qrId, qrCodeUrl, amount, description });
});

// Pay QR (User-to-user and user-to-business)
router.post('/pay-qr', authenticateToken(['user', 'business', 'admin']), async (req, res) => {
  const { qrId, amount, pin, senderUsername } = req.body;
  if (!qrId || !amount || !senderUsername || (!pin && req.body.recipientType !== 'business')) {
    return res.status(400).json({ error: 'QR ID, amount, sender username, and PIN (for user payments) required' });
  }
  if (pin && !/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be a 4-digit number' });
  
  const paymentAmount = parseFloat(amount);
  if (isNaN(paymentAmount) || paymentAmount <= 0 || paymentAmount > 10000) {
    return res.status(400).json({ error: 'Amount must be between 0 and 10,000 ZMW' });
  }
  
  const session = await mongoose.startSession();
  session.startTransaction({ writeConcern: { w: 'majority' } });
  try {
    const sender = await User.findOne({ username: senderUsername, isActive: true }).session(session);
    if (!sender || sender.username !== req.user.username) {
      await session.abortTransaction();
      session.endSession();
      return res.status(sender ? 403 : 404).json({ error: sender ? 'Unauthorized sender' : 'Sender not found or inactive' });
    }
    
    const qrPin = await QRPin.findOne({ qrId }).session(session);
    if (!qrPin || (!qrPin.persistent && qrPin.createdAt < new Date(Date.now() - 15 * 60 * 1000))) {
      if (qrPin && !qrPin.persistent) await QRPin.deleteOne({ qrId }, { session });
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ error: qrPin ? 'QR code expired' : 'Invalid QR code' });
    }
    
    if (qrPin.type === 'user' && !await qrPin.comparePin(pin)) {
      await session.abortTransaction();
      session.endSession();
      return res.status(401).json({ error: 'Invalid PIN' });
    }
    
    let receiver, receiverIdentifier;
    if (qrPin.type === 'user') {
      receiver = await User.findOne({ username: qrPin.username, isActive: true }).session(session);
      receiverIdentifier = receiver?.username;
    } else {
      receiver = await Business.findOne({ businessId: qrPin.businessId, isActive: true }).session(session);
      receiverIdentifier = receiver?.businessId;
    }
    if (!receiver) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ error: `Receiver not found or inactive (type: ${qrPin.type})` });
    }
    
    const sendingFee = paymentAmount <= 50 ? 0.50 : paymentAmount <= 100 ? 1.00 : paymentAmount <= 500 ? 2.00 :
                       paymentAmount <= 1000 ? 2.50 : paymentAmount <= 5000 ? 3.50 : 5.00;
    const receivingFee = paymentAmount <= 50 ? 0.50 : paymentAmount <= 100 ? 1.00 : paymentAmount <= 500 ? 1.50 :
                         paymentAmount <= 1000 ? 2.00 : paymentAmount <= 5000 ? 3.00 : 5.00;
    if (sender.balance < paymentAmount + sendingFee) {
      await session.abortTransaction();
      session.endSession();
      return res.status(403).json({ error: 'Insufficient balance' });
    }
    
    const sentTxId = new mongoose.Types.ObjectId().toString();
    const receivedTxId = new mongoose.Types.ObjectId().toString();
    const transactionDate = new Date();
    
    await User.bulkWrite([{
      updateOne: {
        filter: { _id: sender._id },
        update: {
          $inc: { balance: -(paymentAmount + sendingFee) },
          $push: { transactions: { _id: sentTxId, type: 'sent', amount: paymentAmount, toFrom: receiverIdentifier, fee: sendingFee, date: transactionDate, qrId } },
        },
      },
    }], { session });
    
    if (qrPin.type === 'user') {
      await User.bulkWrite([{
        updateOne: {
          filter: { _id: receiver._id },
          update: {
            $inc: { balance: paymentAmount - receivingFee },
            $push: { transactions: { _id: receivedTxId, type: 'received', amount: paymentAmount, toFrom: sender.username, fee: receivingFee, date: transactionDate, qrId } },
          },
        },
      }], { session });
    } else {
      await Business.bulkWrite([{
        updateOne: {
          filter: { _id: receiver._id },
          update: {
            $inc: { 'balances.ZMW': paymentAmount - receivingFee },
            $push: {
              transactions: { _id: receivedTxId, type: 'received', amount: paymentAmount, currency: 'ZMW', toFrom: sender.username, fee: receivingFee, date: transactionDate, qrId, isRead: false },
              auditLogs: { action: 'transaction_received', performedBy: sender.username, details: { amount: paymentAmount, fee: receivingFee, qrId }, timestamp: new Date() },
            },
          },
        },
      }], { session });
      await sendNotification(receiver, 'New Transaction Received', `Received ${paymentAmount} ZMW from ${sender.username}.`, 
        'New Transaction', `Received ${paymentAmount} ZMW from ${sender.username}.`, { businessId: receiver.businessId, transactionId: receivedTxId });
    }
    
    await AdminLedger.updateOne({}, {
      $inc: { totalBalance: sendingFee + receivingFee },
      $set: { lastUpdated: new Date() },
      $push: { transactions: { type: 'fee-collected', amount: sendingFee + receivingFee, sender: sender.username, receiver: receiverIdentifier, userTransactionIds: [sentTxId, receivedTxId], date: transactionDate, qrId } },
    }, { upsert: true, session });
    
    if (!qrPin.persistent) await QRPin.deleteOne({ qrId }, { session });
    await session.commitTransaction();
    session.endSession();
    res.json({ message: 'Payment successful', sendingFee, receivingFee, amount: paymentAmount });
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    res.status(error.message.includes('not found') || error.message.includes('expired') ? 400 : 
              error.message.includes('Invalid PIN') || error.message.includes('Unauthorized') ? 401 : 
              error.message.includes('Insufficient balance') ? 403 : 500)
      .json({ error: 'Payment failed', details: error.message });
  }
});

// Pay QR (User-to-business)
router.post('/qr/pay', authenticateToken(['user']), async (req, res) => {
  console.log('[QRPay] Request body:', req.body); // Temporary logging for debugging
  const { qrId, amount, senderUsername, businessId } = req.body;
  if (!qrId || !amount || !senderUsername) return res.status(400).json({ error: 'QR ID, amount, and sender username required' });
  
  const session = await mongoose.startSession();
  session.startTransaction({ writeConcern: { w: 'majority' } });
  try {
    const result = await transaction({ qrId, amount, senderUsername, businessId }, session);
    await session.commitTransaction();
    session.endSession();
    res.json(result);
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    res.status(error.message.includes('not found') || error.message.includes('expired') ? 400 : 
              error.message.includes('Unauthorized') ? 403 : 500)
      .json({ error: 'Payment failed', details: error.message });
  }
});

// Get Unread Notifications Count
router.get('/:businessId/notifications/unread', validateBusinessId, authenticateToken(['business']), async (req, res) => {
  const business = await Business.findOne({ businessId: req.params.businessId });
  if (!business || !business.isActive) return res.status(404).json({ error: 'Business not found or inactive' });
  const unreadCount = business.transactions.filter(t => !t.isRead).length;
  res.json({ unreadCount });
});

// Mark Notifications as Read
router.post('/:businessId/notifications/mark-read', validateBusinessId, authenticateToken(['business']), async (req, res) => {
  const business = await Business.findOne({ businessId: req.params.businessId });
  if (!business || !business.isActive) return res.status(404).json({ error: 'Business not found or inactive' });
  
  await Business.updateOne({ businessId: req.params.businessId }, { $set: { 'transactions.$[].isRead': true } });
  await logAudit(business, 'update', business.ownerUsername, { message: 'All transactions marked as read' });
  await sendNotification(business, 'Notifications Marked as Read', `All notifications for ${business.name} marked as read.`, 
    'Notifications Marked as Read', 'All transactions marked as read.', { businessId: business.businessId });
  res.json({ message: 'All notifications marked as read' });
});

// Currency Conversion
router.post('/currency/convert', authenticateToken(['business']), async (req, res) => {
  const { fromCurrency, toCurrency, amount } = req.body;
  const business = await Business.findOne({ businessId: req.user.businessId });
  if (!business || !business.isActive) return res.status(403).json({ error: 'Business not found or inactive' });
  
  if (!['ZMW', 'ZMC', 'USD'].includes(fromCurrency) || !['ZMW', 'ZMC', 'USD'].includes(toCurrency)) {
    return res.status(400).json({ error: 'Invalid currency' });
  }
  const conversionAmount = parseFloat(amount);
  if (!conversionAmount || conversionAmount <= 0) return res.status(400).json({ error: 'Invalid amount' });
  
  const exchangeRates = {
    'ZMW-USD': 0.038, 'USD-ZMW': 26.32, 'ZMW-ZMC': 1, 'ZMC-ZMW': 1, 'USD-ZMC': 26.32, 'ZMC-USD': 0.038,
  };
  const rateKey = `${fromCurrency}-${toCurrency}`;
  if (!exchangeRates[rateKey]) return res.status(400).json({ error: 'Currency conversion not supported' });
  
  const convertedAmount = conversionAmount * exchangeRates[rateKey];
  if (convertDecimal128(business.balances[fromCurrency]) < conversionAmount) {
    return res.status(400).json({ error: `Insufficient ${fromCurrency} balance` });
  }
  
  business.balances[fromCurrency] = convertDecimal128(business.balances[fromCurrency]) - conversionAmount;
  business.balances[toCurrency] = convertDecimal128(business.balances[toCurrency]) + convertedAmount;
  business.transactions.push({
    type: 'currency-converted',
    amount: convertedAmount,
    currency: toCurrency,
    originalAmount: conversionAmount,
    originalCurrency: fromCurrency,
    exchangeRate: exchangeRates[rateKey],
    toFrom: 'system',
    date: new Date(),
  });
  await logAudit(business, 'currency_conversion', business.ownerUsername, { fromCurrency, toCurrency, amount: conversionAmount, convertedAmount });
  await sendNotification(business, 'Currency Converted', `Converted ${conversionAmount} ${fromCurrency} to ${convertedAmount} ${toCurrency}.`, 
    'Currency Converted', `Converted ${conversionAmount} ${fromCurrency} to ${convertedAmount} ${toCurrency}.`, { businessId: business.businessId });
  res.json({ message: 'Currency converted', convertedAmount, currency: toCurrency });
});

// Get Audit Logs
router.get('/audit-logs', authenticateToken(['business', 'admin']), async (req, res) => {
  const business = await Business.findOne({ businessId: req.user.businessId }, { auditLogs: 1 }).lean();
  if (!business) return res.status(404).json({ error: 'Business not found' });
  res.json({ auditLogs: business.auditLogs });
});

// Update Account Tier
router.post('/update-tier', authenticateToken(['admin']), async (req, res) => {
  const { businessId, tier } = req.body;
  if (!['basic', 'pro', 'enterprise'].includes(tier)) return res.status(400).json({ error: 'Invalid account tier' });
  
  const business = await Business.findOne({ businessId });
  if (!business) return res.status(404).json({ error: 'Business not found' });
  
  const oldTier = business.accountTier;
  business.accountTier = tier;
  business.transactionLimits = {
    daily: tier === 'enterprise' ? 1000000 : tier === 'pro' ? 500000 : 100000,
    monthly: tier === 'enterprise' ? 10000000 : tier === 'pro' ? 5000000 : 1000000,
    maxPerTransaction: tier === 'enterprise' ? 500000 : tier === 'pro' ? 250000 : 50000,
  };
  await logAudit(business, 'tier_update', req.user.businessId, { oldTier, newTier: tier });
  await sendNotification(business, 'Account Tier Updated', `Your account tier is now ${tier}.`, 
    'Account Tier Updated', `Your account is now ${tier}.`, { businessId });
  res.json({ message: `Account tier updated to ${tier}` });
});

// Get Business Details
router.get('/:businessId', validateBusinessId, authenticateToken(['business', 'admin']), async (req, res) => {
  const business = await Business.findOne({ businessId: req.params.businessId }, 
    { businessId: 1, name: 1, ownerUsername: 1, balances: 1, transactions: 1, isActive: 1, kycStatus: 1, twoFactorEnabled: 1 });
  if (!business) return res.status(404).json({ error: 'Business not found' });
  
  res.json({
    businessId: business.businessId,
    name: business.name,
    ownerUsername: business.ownerUsername,
    balances: {
      ZMW: convertDecimal128(business.balances.ZMW),
      ZMC: convertDecimal128(business.balances.ZMC),
      USD: convertDecimal128(business.balances.USD),
    },
    transactions: business.transactions.map(t => ({
      _id: t._id,
      type: t.type,
      amount: convertDecimal128(t.amount),
      currency: t.currency,
      toFrom: t.toFrom,
      date: t.date,
      status: t.status,
      reason: t.reason || '',
      qrId: t.qrId || '',
      isRead: t.isRead !== undefined ? t.isRead : true,
    })),
    isActive: business.isActive,
    kycStatus: business.kycStatus || 'pending',
    twoFactorEnabled: business.twoFactorEnabled,
  });
});

// Update Push Notifications
router.patch('/:businessId/notifications', authenticateToken(['business']), async (req, res) => {
  const { pushToken, enabled } = req.body;
  const business = await Business.findOne({ businessId: req.params.businessId });
  if (!business || !business.isActive) return res.status(404).json({ error: 'Business not found or inactive' });
  
  business.pushToken = enabled ? pushToken : null;
  business.pushNotificationsEnabled = enabled;
  await logAudit(business, 'update_notifications', business.ownerUsername, { pushToken: enabled ? 'set' : 'cleared', enabled });
  res.json({ message: 'Notification settings updated' });
});

// Forgot PIN
router.post('/forgot-pin', forgotPinLimiter, authenticateToken(['business']), async (req, res) => {
  const { businessId } = req.body;
  if (businessId !== req.user.businessId) return res.status(403).json({ error: 'Unauthorized' });
  
  const business = await Business.findOne({ businessId });
  if (!business || !business.isActive || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(business.email)) {
    return res.status(404).json({ error: 'Business not found, inactive, or no valid email' });
  }
  
  const resetToken = crypto.randomBytes(32).toString('hex');
  const resetTokenExpires = new Date(Date.now() + 15 * 60 * 1000);
  business.resetPinToken = resetToken;
  business.resetPinExpires = resetTokenExpires;
  await logAudit(business, 'pin_reset_request', business.ownerUsername, { success: true, message: 'PIN reset token generated' });
  await sendNotification(business, 'PIN Reset Request', `Use token: ${resetToken}\nExpires: ${resetTokenExpires.toLocaleString()}.`, 
    'PIN Reset Request', 'Check your email for PIN reset instructions.', { businessId });
  res.json({ message: 'PIN reset token sent to your email' });
});

// Reset PIN
router.post('/reset-pin', authenticateToken(['business']), async (req, res) => {
  const { businessId, resetToken, newPin } = req.body;
  if (businessId !== req.user.businessId || !/^\d{4}$/.test(newPin)) {
    return res.status(400).json({ error: 'Invalid business ID or PIN format' });
  }
  
  const business = await Business.findOne({ businessId, resetPinToken: resetToken, resetPinExpires: { $gt: new Date() } }).select('+hashedPin');
  if (!business || !business.isActive) return res.status(400).json({ error: 'Invalid or expired reset token' });
  
  business.hashedPin = await bcrypt.hash(newPin, 10);
  business.resetPinToken = null;
  business.resetPinExpires = null;
  await logAudit(business, 'pin_reset', business.ownerUsername, { success: true, message: 'PIN reset successfully' });
  await sendNotification(business, 'PIN Reset Successful', `Your PIN for ${business.name} has been reset.`, 
    'PIN Reset Successful', 'Your PIN has been reset.', { businessId });
  res.json({ message: 'PIN reset successful' });
});

// Update Email
router.post('/update-email', updateEmailLimiter, authenticateToken(['business']), async (req, res) => {
  const { businessId, newEmail } = req.body;
  if (businessId !== req.user.businessId || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(newEmail)) {
    return res.status(400).json({ error: 'Invalid business ID or email format' });
  }
  
  const business = await Business.findOne({ businessId });
  if (!business || !business.isActive) return res.status(404).json({ error: 'Business not found or inactive' });
  
  const existing = await Business.findOne({ email: newEmail.toLowerCase() });
  if (existing && existing.businessId !== businessId) return res.status(409).json({ error: 'Email already in use' });
  
  const oldEmail = business.email;
  business.email = newEmail.toLowerCase();
  await logAudit(business, 'update', business.ownerUsername, { success: true, message: 'Email updated', oldEmail, newEmail });
  await sendNotification(business, 'Email Address Updated', `Email updated to ${newEmail}.`, 
    'Email Updated', `Your email has been updated to ${newEmail}.`, { businessId });
  if (oldEmail && oldEmail !== newEmail) {
    await sendNotification({ email: oldEmail }, 'Email Address Changed', 
      `Email for ${business.name} changed to ${newEmail}. Contact support if unauthorized.`, null, null, null);
  }
  res.json({ message: 'Email updated successfully' });
});

// Get Latest QR Code
router.get('/qr/latest/:businessId', validateBusinessId, authenticateToken(['business']), async (req, res) => {
  const qrPin = await QRPin.findOne({ businessId: req.params.businessId, type: 'business', isActive: true, archivedAt: null })
    .sort({ createdAt: -1 }).lean();
  if (!qrPin) return res.status(200).json({});
  
  const qrData = JSON.stringify({ type: 'business_payment', businessId: qrPin.businessId, qrId: qrPin.qrId });
  const qrCodeUrl = await QRCode.toDataURL(qrData);
  res.json({ qrId: qrPin.qrId, qrCodeUrl });
});

// Delete Account
router.delete('/delete-account', authenticateToken(['business']), require2FA, async (req, res) => {
  const business = await Business.findOne({ businessId: req.user.businessId });
  if (!business || !business.isActive) return res.status(404).json({ error: 'Business not found or already inactive' });
  if (Object.values(business.balances).some(b => convertDecimal128(b) > 0) || business.pendingDeposits.length > 0 || business.pendingWithdrawals.length > 0) {
    return res.status(400).json({ error: 'Cannot delete account with non-zero balances or pending transactions' });
  }
  
  business.isActive = false;
  await logAudit(business, 'delete-account', business.ownerUsername, { message: 'Account deactivated' });
  await sendNotification(business, 'Account Deactivated', `Your account ${business.name} has been deactivated.`, 
    'Account Deactivated', 'Your account has been deactivated.', { businessId: business.businessId });
  res.json({ message: 'Account deactivated successfully' });
});

// Version Endpoint for Debugging
router.get('/version', (req, res) => {
  res.json({ version: '1.0.0', commit: process.env.HEROKU_SLUG_COMMIT || 'unknown' });
});


module.exports = router;