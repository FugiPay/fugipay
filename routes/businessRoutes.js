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
const QRPin = require('../models/QRPin');
const QRCode = require('qrcode');
const { Business, BusinessTransaction } = require('../models/Business');
const User = require('../models/User'); // Added User model
const AdminLedger = require('../models/AdminLedger'); // Added AdminLedger model

// Environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret';
const AWS_REGION = process.env.AWS_REGION || 'us-east-1';
const S3_BUCKET = process.env.S3_BUCKET || 'zangena-files';
const EMAIL_USER = process.env.EMAIL_USER || 'your_email@example.com';
const EMAIL_PASS = process.env.EMAIL_PASS || 'your_email_password';

// S3 setup
const s3Client = new S3Client({ region: AWS_REGION });
const upload = multer({
  storage: multerS3({
    s3: s3Client,
    bucket: S3_BUCKET,
    key: (req, file, cb) => {
      cb(null, `certificates/${Date.now()}_${file.originalname}`);
    },
  }),
});

// Email setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: EMAIL_USER, pass: EMAIL_PASS },
});

// Push notification setup
const expo = new Expo();

// Middleware: Authenticate JWT
const authenticateToken = (roles = ['business', 'admin']) => (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    if (!roles.includes(user.role)) return res.status(403).json({ error: 'Unauthorized role' });
    req.user = user;
    next();
  });
};

// Ensure indexes with error handling
const ensureIndexes = async () => {
  try {
    await Business.createIndexes({ businessId: 1, email: 1 });
    await QRPin.createIndexes({ qrId: 1, businessId: 1 });
    await User.createIndexes({ username: 1 }); // Added index for User
    console.log('[Indexes] Successfully ensured indexes for Business, QRPin, and User');
  } catch (error) {
    console.error('[Indexes] Error creating indexes:', {
      message: error.message,
      code: error.code,
      codeName: error.codeName,
    });
    if (error.code !== 85) throw error; // Ignore IndexOptionsConflict
  }
};
ensureIndexes();

// Convert Decimal128 to float
const convertDecimal128 = (value) => (value ? parseFloat(value.toString()) : 0);

// Email templates
const emailTemplates = {
  welcome: (business) => `Welcome ${business.name}! Your account is pending KYC verification.`,
  withdrawal: (business, withdrawal) => `Withdrawal of ${withdrawal.amount} ZMW requested. Fee: ${withdrawal.fee} ZMW.`,
  kycApproved: (business) => `Your KYC for ${business.name} has been approved!`,
};

// Send email
const sendEmail = async (to, subject, text) => {
  try {
    await transporter.sendMail({ from: EMAIL_USER, to, subject, text });
    console.log(`[Email] Sent to ${to}: ${subject}`);
  } catch (error) {
    console.error(`[Email] Error: ${error.message}`);
  }
};

// Send push notification
const sendPushNotification = async (pushToken, title, body, data) => {
  if (!Expo.isExpoPushToken(pushToken)) return;
  try {
    await expo.sendPushNotificationsAsync([{
      to: pushToken,
      sound: 'default',
      title,
      body,
      data,
    }]);
    console.log(`[Push] Sent to ${pushToken}: ${title}`);
  } catch (error) {
    console.error(`[Push] Error: ${error.message}`);
  }
};

// Register Business
router.post('/register', upload.fields([
  { name: 'tpinCertificate', maxCount: 1 },
  { name: 'pacraCertificate', maxCount: 1 },
]), async (req, res) => {
  const { businessId, name, ownerUsername, pin, phoneNumber, email } = req.body;
  const { tpinCertificate, pacraCertificate } = req.files || {};
  try {
    if (!/^\d{10}$/.test(businessId)) {
      return res.status(400).json({ error: 'Business ID must be a 10-digit TPIN' });
    }
    if (!/^\d{4}$/.test(pin)) {
      return res.status(400).json({ error: 'PIN must be a 4-digit number' });
    }
    const existing = await Business.findOne({
      $or: [{ businessId }, { ownerUsername }, { phoneNumber }, { email }],
    });
    if (existing) {
      return res.status(400).json({ error: 'Business ID, username, phone, or email already exists' });
    }
    const business = new Business({
      businessId,
      name,
      ownerUsername,
      phoneNumber,
      email,
      hashedPin: pin,
      tpinCertificate: tpinCertificate ? tpinCertificate[0].location : null,
      pacraCertificate: pacraCertificate ? pacraCertificate[0].location : null,
      kycStatus: 'pending',
      isActive: false,
      auditLogs: [{ action: 'create', performedBy: ownerUsername, details: { message: 'Business registered' } }],
    });
    await business.save();
    if (business.email) {
      await sendEmail(business.email, 'Welcome to Zangena', emailTemplates.welcome(business));
    }
    res.status(201).json({ message: 'Business registered. Awaiting KYC verification' });
  } catch (error) {
    console.error('[Register] Error:', error.message);
    res.status(500).json({ error: 'Failed to register business', details: error.message });
  }
});

// Login
router.post('/login', async (req, res) => {
  const { businessId, phoneNumber, pin } = req.body;
  try {
    console.log('[Login] Attempting login with:', { businessId, phoneNumber });
    if (!pin || (!businessId && !phoneNumber)) {
      return res.status(400).json({ error: 'Business ID or phone number and PIN are required' });
    }
    const query = businessId ? { businessId } : { phoneNumber };
    const business = await Business.findOne(query);
    if (!business) {
      console.log('[Login] Business not found for:', { businessId, phoneNumber });
      return res.status(404).json({ error: 'Business not found' });
    }
    console.log('[Login] Business found:', business.businessId, 'isActive:', business.isActive, 'kycStatus:', business.kycStatus);
    if (!business.isActive) {
      return res.status(403).json({ error: 'Business account is not active' });
    }
    if (!business.hashedPin) {
      console.error('[Login] Missing hashedPin for business:', business.businessId);
      return res.status(500).json({ error: 'Invalid business account configuration' });
    }
    const isPinValid = await bcrypt.compare(pin, business.hashedPin);
    if (!isPinValid) {
      business.auditLogs.push({
        action: 'login',
        performedBy: business.ownerUsername,
        details: { success: false, message: 'Invalid PIN' },
      });
      await business.save();
      return res.status(401).json({ error: 'Invalid PIN' });
    }
    const token = jwt.sign(
      { businessId: business.businessId, role: 'business' }, // Explicitly set role
      JWT_SECRET,
      { expiresIn: '1d' }
    );
    business.lastLogin = new Date();
    business.auditLogs.push({
      action: 'login',
      performedBy: business.ownerUsername,
      details: { success: true, ip: req.ip, loginMethod: businessId ? 'businessId' : 'phoneNumber' },
    });
    await business.save();
    if (business.pushToken) {
      await sendPushNotification(business.pushToken, 'Login Successful', `Welcome back, ${business.name}!`, { businessId: business.businessId });
    }
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
      },
    });
  } catch (error) {
    console.error('[Login] Error:', {
      message: error.message,
      stack: error.stack,
      businessId,
      phoneNumber,
    });
    res.status(500).json({ error: 'Failed to login', details: error.message });
  }
});

// Dashboard
router.get('/dashboard', authenticateToken(['business']), async (req, res) => {
  try {
    const business = await Business.findOne({ businessId: req.user.businessId }).lean();
    if (!business || !business.isActive) {
      return res.status(404).json({ error: 'Business not found or inactive' });
    }
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const transactions = await BusinessTransaction.find({
      businessId: req.user.businessId,
      createdAt: { $gte: thirtyDaysAgo },
      status: 'completed',
    })
      .sort({ createdAt: -1 })
      .limit(5)
      .lean();
    const totalRevenue = transactions.reduce((sum, t) => sum + convertDecimal128(t.amount), 0);
    const transactionCount = transactions.length;
    await Business.findOneAndUpdate(
      { businessId: req.user.businessId },
      {
        $push: {
          auditLogs: {
            action: 'dashboard_view',
            performedBy: business.ownerUsername,
            details: { message: 'Dashboard accessed' },
          },
        },
      }
    );
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
  } catch (error) {
    console.error('[Dashboard] Error:', error.message);
    res.status(500).json({ error: 'Failed to load dashboard', details: error.message });
  }
});

// Debug Dashboard
router.get('/debug-dashboard', authenticateToken(['business', 'admin']), async (req, res) => {
  try {
    const business = await Business.findOne({ businessId: req.user.businessId }).lean();
    res.json({
      user: req.user,
      business: business ? {
        businessId: business.businessId,
        name: business.name,
        isActive: business.isActive,
        kycStatus: business.kycStatus,
      } : null,
    });
  } catch (error) {
    console.error('[DebugDashboard] Error:', error.message);
    res.status(500).json({ error: 'Failed to debug dashboard', details: error.message });
  }
});

// Manual Deposit
router.post('/deposit/manual', authenticateToken(['business']), async (req, res) => {
  const { amount, sourceOfFunds } = req.body;
  try {
    const business = await Business.findOne({ businessId: req.user.businessId });
    if (!business || !business.isActive) {
      return res.status(403).json({ error: 'Business not found or inactive' });
    }
    const depositAmount = parseFloat(amount);
    if (!depositAmount || depositAmount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    if (depositAmount > business.transactionLimits.maxPerTransaction) {
      return res.status(400).json({ error: `Deposit exceeds max transaction limit of ${business.transactionLimits.maxPerTransaction} ZMW` });
    }
    if (!['bank_transfer', 'mobile_money', 'cash', 'other'].includes(sourceOfFunds)) {
      return res.status(400).json({ error: 'Invalid source of funds' });
    }
    const transactionId = crypto.randomBytes(16).toString('hex');
    business.pendingDeposits.push({
      amount: mongoose.Types.Decimal128.fromString(depositAmount.toString()),
      currency: 'ZMW',
      transactionId,
      sourceOfFunds,
    });
    business.auditLogs.push({
      action: 'deposit_request',
      performedBy: business.ownerUsername,
      details: { amount: depositAmount, sourceOfFunds },
    });
    await business.save();
    if (business.email) {
      await sendEmail(business.email, 'Deposit Request Submitted', `Deposit of ${depositAmount} ZMW is pending approval.`);
    }
    if (business.pushToken) {
      await sendPushNotification(business.pushToken, 'Deposit Requested', `Your deposit of ${depositAmount} ZMW is pending.`, { businessId: business.businessId });
    }
    res.json({ message: 'Deposit request submitted', transactionId });
  } catch (error) {
    console.error('[DepositManual] Error:', error.message);
    res.status(500).json({ error: 'Failed to request deposit', details: error.message });
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
    if (withdrawalAmount > business.transactionLimits.maxPerTransaction) {
      return res.status(400).json({ error: `Withdrawal exceeds max transaction limit of ${business.transactionLimits.maxPerTransaction} ZMW` });
    }
    if (!destination || !['bank', 'mobile_money', 'zambia_coin'].includes(destination.type)) {
      return res.status(400).json({ error: 'Valid destination required' });
    }
    const withdrawalFee = Math.max(withdrawalAmount * 0.01, 2);
    const totalDeduction = withdrawalAmount + withdrawalFee;
    if (convertDecimal128(business.balances.ZMW) < totalDeduction) {
      return res.status(400).json({ error: 'Insufficient balance to cover amount and fee' });
    }
    const withdrawal = {
      amount: mongoose.Types.Decimal128.fromString(withdrawalAmount.toString()),
      fee: mongoose.Types.Decimal128.fromString(withdrawalFee.toString()),
      currency: 'ZMW',
      date: new Date(),
      destination,
    };
    business.pendingWithdrawals.push(withdrawal);
    business.auditLogs.push({
      action: 'withdrawal_request',
      performedBy: business.ownerUsername,
      details: { amount: withdrawalAmount, fee: withdrawalFee, destination },
    });
    await business.save();
    if (business.email) {
      await sendEmail(business.email, 'Withdrawal Request Submitted', emailTemplates.withdrawal(business, withdrawal));
    }
    if (business.pushToken) {
      await sendPushNotification(business.pushToken, 'Withdrawal Requested', `Your request for ${withdrawalAmount} ZMW is pending.`, { businessId: business.businessId });
    }
    res.json({ message: 'Withdrawal requested. Awaiting approval', withdrawalFee });
  } catch (error) {
    console.error('[WithdrawRequest] Error:', error.message);
    res.status(500).json({ error: 'Failed to request withdrawal', details: error.message });
  }
});

// Verify KYC
router.post('/verify-kyc', authenticateToken(['admin']), async (req, res) => {
  const { businessId, approved, rejectionReason } = req.body;
  try {
    const business = await Business.findOne({ businessId });
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    business.kycStatus = approved ? 'verified' : 'rejected';
    if (!approved && rejectionReason) {
      business.kycDetails.rejectionReason = rejectionReason;
    }
    if (approved) {
      business.isActive = true;
      business.kycDetails.sanctionsScreening = { status: 'clear', lastChecked: new Date() };
    }
    business.auditLogs.push({
      action: 'kyc_update',
      performedBy: req.user.businessId,
      details: { approved, rejectionReason },
    });
    await business.save();
    if (business.email) {
      const subject = approved ? 'KYC Approved' : 'KYC Rejected';
      const text = approved ? emailTemplates.kycApproved(business) : `KYC rejected: ${rejectionReason}`;
      await sendEmail(business.email, subject, text);
    }
    if (business.pushToken) {
      await sendPushNotification(business.pushToken, approved ? 'KYC Approved' : 'KYC Rejected', approved ? 'Your account is now active!' : `KYC rejected: ${rejectionReason}`, { businessId });
    }
    res.json({ message: `KYC ${approved ? 'approved' : 'rejected'}` });
  } catch (error) {
    console.error('[VerifyKYC] Error:', error.message);
    res.status(500).json({ error: 'Failed to verify KYC', details: error.message });
  }
});

// Generate QR Code
router.post('/qr/generate', authenticateToken(['business']), async (req, res) => {
  const { amount, description } = req.body;
  try {
    const business = await Business.findOne({ businessId: req.user.businessId });
    if (!business || !business.isActive) {
      return res.status(403).json({ error: 'Business not found or inactive' });
    }
    const qrPin = await QRPin.findOne({ businessId: req.user.businessId, type: 'business' });
    if (!qrPin) {
      return res.status(400).json({ error: 'No QR PIN set for this business. Please set one first.' });
    }
    const qrData = JSON.stringify({
      type: 'business_payment',
      businessId: business.businessId,
      qrId: qrPin.qrId,
      amount: amount ? parseFloat(amount) : undefined,
      description,
    });
    const qrCodeUrl = await QRCode.toDataURL(qrData);
    res.json({ qrId: qrPin.qrId, qrCodeUrl, amount, description });
  } catch (error) {
    console.error('[QRGenerate] Error:', error.message);
    res.status(500).json({ error: 'Failed to generate QR code' });
  }
});

// Pay QR (Handles both user-to-user and user-to-business payments)
router.post('/pay-qr', authenticateToken(['user', 'business', 'admin']), async (req, res) => {
  const { qrId, amount, pin, senderUsername } = req.body;
  if (!qrId || !amount || !senderUsername || (!pin && req.body.recipientType !== 'business')) {
    return res.status(400).json({ error: 'QR ID, amount, sender username, and PIN (for user payments) are required' });
  }
  if (pin && !/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'PIN must be a 4-digit number' });
  }
  const paymentAmount = parseFloat(amount);
  if (isNaN(paymentAmount) || paymentAmount <= 0 || paymentAmount > 10000) {
    return res.status(400).json({ error: 'Amount must be between 0 and 10,000 ZMW' });
  }
  const session = await mongoose.startSession();
  session.startTransaction({ writeConcern: { w: 'majority' } });
  try {
    const sender = await User.findOne({ username: senderUsername, isActive: true }).session(session);
    if (!sender) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ error: 'Sender not found or inactive' });
    }
    if (sender.username !== req.user.username) {
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
      return res.status(404).json({ error: `Receiver not found or inactive (type: ${qrPin.type})` });
    }
    const sendingFee = paymentAmount <= 50 ? 0.50 :
                      paymentAmount <= 100 ? 1.00 :
                      paymentAmount <= 500 ? 2.00 :
                      paymentAmount <= 1000 ? 2.50 :
                      paymentAmount <= 5000 ? 3.50 : 5.00;
    const receivingFee = paymentAmount <= 50 ? 0.50 :
                        paymentAmount <= 100 ? 1.00 :
                        paymentAmount <= 500 ? 1.50 :
                        paymentAmount <= 1000 ? 2.00 :
                        paymentAmount <= 5000 ? 3.00 : 5.00;
    if (sender.balance < paymentAmount + sendingFee) {
      await session.abortTransaction();
      session.endSession();
      return res.status(403).json({ error: 'Insufficient balance' });
    }
    const sentTxId = new mongoose.Types.ObjectId().toString();
    const receivedTxId = new mongoose.Types.ObjectId().toString();
    const transactionDate = new Date();

    await User.bulkWrite([
      {
        updateOne: {
          filter: { _id: sender._id },
          update: {
            $inc: { balance: -(paymentAmount + sendingFee) },
            $push: {
              transactions: {
                _id: sentTxId,
                type: 'sent',
                amount: paymentAmount,
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
              $inc: { balance: paymentAmount - receivingFee },
              $push: {
                transactions: {
                  _id: receivedTxId,
                  type: 'received',
                  amount: paymentAmount,
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
              $inc: { 'balances.ZMW': paymentAmount - receivingFee },
              $push: {
                transactions: {
                  _id: receivedTxId,
                  type: 'received',
                  amount: paymentAmount,
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

    await AdminLedger.updateOne(
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
    );

    if (!qrPin.persistent) {
      await QRPin.deleteOne({ qrId }, { session });
    }

    await session.commitTransaction();
    session.endSession();
    res.json({ message: 'Payment successful', sendingFee, receivingFee, amount: paymentAmount });
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    console.error('[PayQR] Error:', {
      message: error.message,
      stack: error.stack,
      qrId,
      senderUsername,
      amount,
      recipientType: qrPin?.type || 'unknown',
      userRole: req.user?.role,
    });
    const status = error.message === 'Sender not found or inactive' ||
                   error.message === 'Invalid QR code' ||
                   error.message === 'Receiver not found or inactive' ||
                   error.message === 'QR code expired' ? 400 :
                   error.message === 'Invalid PIN' || error.message === 'Unauthorized sender' ? 401 :
                   error.message === 'Insufficient balance' ? 403 : 500;
    res.status(status).json({
      error: status === 500 ? 'Server error processing payment' : error.message,
      details: error.message,
    });
  }
});

// Pay via QR Code (User-to-business payments)
router.post('/qr/pay', authenticateToken(['user']), async (req, res) => {
  const { qrId, amount, senderUsername, businessId } = req.body;
  if (!qrId || !amount || !senderUsername) {
    return res.status(400).json({ error: 'QR ID, amount, and sender username are required' });
  }
  const paymentAmount = parseFloat(amount);
  if (isNaN(paymentAmount) || paymentAmount <= 0 || paymentAmount > 10000) {
    return res.status(400).json({ error: 'Amount must be between 0 and 10,000 ZMW' });
  }
  const session = await mongoose.startSession();
  session.startTransaction({ writeConcern: { w: 'majority' } });
  let user;
  try {
    user = await User.findOne({ username: senderUsername, isActive: true }).session(session);
    if (!user) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ error: 'User not found or inactive' });
    }
    if (user.username !== req.user.username) {
      await session.abortTransaction();
      session.endSession();
      return res.status(403).json({ error: 'Unauthorized sender' });
    }
    const qrPin = await QRPin.findOne({ qrId, type: 'business' }).session(session);
    if (!qrPin) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ error: 'Invalid or expired QR code' });
    }
    if (businessId && qrPin.businessId !== businessId) {
      await session.abortTransaction();
      session.endSession();
      return res.status(400).json({ error: 'QR code does not match provided business ID' });
    }
    const business = await Business.findOne({ businessId: qrPin.businessId, isActive: true }).session(session);
    if (!business) {
      await session.abortTransaction();
      session.endSession();
      return res.status(404).json({ error: 'Business not found or inactive' });
    }
    const sendingFee = paymentAmount <= 50 ? 0.50 :
                      paymentAmount <= 100 ? 1.00 :
                      paymentAmount <= 500 ? 2.00 :
                      paymentAmount <= 1000 ? 2.50 :
                      paymentAmount <= 5000 ? 3.50 : 5.00;
    const receivingFee = paymentAmount <= 50 ? 0.50 :
                        paymentAmount <= 100 ? 1.00 :
                        paymentAmount <= 500 ? 1.50 :
                        paymentAmount <= 1000 ? 2.00 :
                        paymentAmount <= 5000 ? 3.00 : 5.00;
    if (user.balance < paymentAmount + sendingFee) {
      await session.abortTransaction();
      session.endSession();
      return res.status(403).json({ error: 'Insufficient balance' });
    }
    const sentTxId = new mongoose.Types.ObjectId().toString();
    const receivedTxId = new mongoose.Types.ObjectId().toString();
    const transactionDate = new Date();

    await User.bulkWrite([
      {
        updateOne: {
          filter: { _id: user._id },
          update: {
            $inc: { balance: -(paymentAmount + sendingFee) },
            $push: {
              transactions: {
                _id: sentTxId,
                type: 'sent',
                amount: paymentAmount,
                toFrom: business.businessId,
                fee: sendingFee,
                date: transactionDate,
                qrId,
              },
            },
          },
        },
      },
    ], { session });

    await Business.bulkWrite([
      {
        updateOne: {
          filter: { _id: business._id },
          update: {
            $inc: { 'balances.ZMW': paymentAmount - receivingFee },
            $push: {
              transactions: {
                _id: receivedTxId,
                type: 'received',
                amount: paymentAmount,
                currency: 'ZMW',
                toFrom: user.username,
                fee: receivingFee,
                date: transactionDate,
                qrId,
              },
            },
          },
        },
      },
    ], { session });

    await AdminLedger.updateOne(
      {},
      {
        $inc: { totalBalance: sendingFee + receivingFee },
        $set: { lastUpdated: new Date() },
        $push: {
          transactions: {
            type: 'fee-collected',
            amount: sendingFee + receivingFee,
            sender: user.username,
            receiver: business.businessId,
            userTransactionIds: [sentTxId, receivedTxId],
            date: transactionDate,
            qrId,
          },
        },
      },
      { upsert: true, session }
    );

    await session.commitTransaction();
    session.endSession();
    res.json({
      message: 'Payment successful',
      sendingFee,
      receivingFee,
      amount: paymentAmount,
    });
  } catch (error) {
    await session.abortTransaction();
    session.endSession();
    console.error('[QRPay] Error:', {
      message: error.message,
      stack: error.stack,
      qrId,
      senderUsername,
      amount: paymentAmount,
      businessId,
      userDefined: !!user,
      userRole: req.user?.role,
      jwtUsername: req.user?.username,
    });
    const status = error.message === 'User not found or inactive' ||
                   error.message === 'Invalid or expired QR code' ||
                   error.message === 'Business not found or inactive' ||
                   error.message === 'QR code does not match provided business ID' ? 400 :
                   error.message === 'Insufficient balance' || error.message === 'Unauthorized sender' ? 403 : 500;
    res.status(status).json({
      error: status === 500 ? 'Server error processing payment' : error.message,
      details: error.message,
    });
  }
});

// Currency Conversion
router.post('/currency/convert', authenticateToken(['business']), async (req, res) => {
  const { fromCurrency, toCurrency, amount } = req.body;
  try {
    const business = await Business.findOne({ businessId: req.user.businessId });
    if (!business || !business.isActive) {
      return res.status(403).json({ error: 'Business not found or inactive' });
    }
    if (!['ZMW', 'ZMC', 'USD'].includes(fromCurrency) || !['ZMW', 'ZMC', 'USD'].includes(toCurrency)) {
      return res.status(400).json({ error: 'Invalid currency' });
    }
    const conversionAmount = parseFloat(amount);
    if (!conversionAmount || conversionAmount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    const exchangeRates = {
      'ZMW-USD': 0.038,
      'USD-ZMW': 26.32,
      'ZMW-ZMC': 1,
      'ZMC-ZMW': 1,
      'USD-ZMC': 26.32,
      'ZMC-USD': 0.038,
    };
    const rateKey = `${fromCurrency}-${toCurrency}`;
    if (!exchangeRates[rateKey]) {
      return res.status(400).json({ error: 'Currency conversion not supported' });
    }
    const convertedAmount = conversionAmount * exchangeRates[rateKey];
    if (convertDecimal128(business.balances[fromCurrency]) < conversionAmount) {
      return res.status(400).json({ error: `Insufficient ${fromCurrency} balance` });
    }
    business.balances[fromCurrency] = mongoose.Types.Decimal128.fromString(
      (convertDecimal128(business.balances[fromCurrency]) - conversionAmount).toString()
    );
    business.balances[toCurrency] = mongoose.Types.Decimal128.fromString(
      (convertDecimal128(business.balances[toCurrency]) + convertedAmount).toString()
    );
    business.transactions.push({
      type: 'currency-converted',
      amount: mongoose.Types.Decimal128.fromString(convertedAmount.toString()),
      currency: toCurrency,
      originalAmount: mongoose.Types.Decimal128.fromString(conversionAmount.toString()),
      originalCurrency: fromCurrency,
      exchangeRate: exchangeRates[rateKey],
      toFrom: 'system',
      date: new Date(),
    });
    business.auditLogs.push({
      action: 'currency_conversion',
      performedBy: business.ownerUsername,
      details: { fromCurrency, toCurrency, amount: conversionAmount, convertedAmount },
    });
    await business.save();
    if (business.pushToken) {
      await sendPushNotification(business.pushToken, 'Currency Converted', `Converted ${conversionAmount} ${fromCurrency} to ${convertedAmount} ${toCurrency}`, { businessId: business.businessId });
    }
    res.json({ message: 'Currency converted', convertedAmount, currency: toCurrency });
  } catch (error) {
    console.error('[CurrencyConvert] Error:', error.message);
    res.status(500).json({ error: 'Failed to convert currency', details: error.message });
  }
});

// Get Audit Logs
router.get('/audit-logs', authenticateToken(['business', 'admin']), async (req, res) => {
  try {
    const business = await Business.findOne({ businessId: req.user.businessId }, { auditLogs: 1 }).lean();
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    res.json({ auditLogs: business.auditLogs });
  } catch (error) {
    console.error('[AuditLogs] Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch audit logs', details: error.message });
  }
});

// Update Account Tier
router.post('/update-tier', authenticateToken(['admin']), async (req, res) => {
  const { businessId, tier } = req.body;
  try {
    if (!['basic', 'pro', 'enterprise'].includes(tier)) {
      return res.status(400).json({ error: 'Invalid account tier' });
    }
    const business = await Business.findOne({ businessId });
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    const oldTier = business.accountTier;
    business.accountTier = tier;
    business.transactionLimits = {
      daily: tier === 'enterprise' ? 1000000 : tier === 'pro' ? 500000 : 100000,
      monthly: tier === 'enterprise' ? 10000000 : tier === 'pro' ? 5000000 : 1000000,
      maxPerTransaction: tier === 'enterprise' ? 500000 : tier === 'pro' ? 250000 : 50000,
    };
    business.auditLogs.push({
      action: 'tier_update',
      performedBy: req.user.businessId,
      details: { oldTier, newTier: tier },
    });
    await business.save();
    if (business.email) {
      await sendEmail(business.email, 'Account Tier Updated', `Your account tier is now ${tier}.`);
    }
    if (business.pushToken) {
      await sendPushNotification(business.pushToken, 'Account Tier Updated', `Your account is now ${tier}.`, { businessId });
    }
    res.json({ message: `Account tier updated to ${tier}` });
  } catch (error) {
    console.error('[UpdateTier] Error:', error.message);
    res.status(500).json({ error: 'Failed to update account tier', details: error.message });
  }
});

// Get Business Details
router.get('/:businessId', async (req, res) => {
  const { businessId } = req.params;
  try {
    console.log('[GetBusiness] Fetching business:', businessId);
    const business = await Business.findOne({ businessId });
    if (!business) {
      console.log('[GetBusiness] Business not found:', businessId);
      return res.status(404).json({ error: 'Business not found' });
    }
    res.json({
      businessId: business.businessId,
      name: business.name,
      ownerUsername: business.ownerUsername,
      qrId: business.qrCode,
      isActive: business.isActive,
      kycStatus: business.kycStatus,
      accountTier: business.accountTier,
    });
  } catch (error) {
    console.error('[GetBusiness] Error:', {
      message: error.message,
      stack: error.stack,
      businessId,
    });
    res.status(500).json({ error: 'Failed to fetch business', details: error.message });
  }
});

// Forgot PIN
router.post('/forgot-pin', async (req, res) => {
  const { businessId, email } = req.body;
  try {
    const business = await Business.findOne({ businessId, email });
    if (!business) {
      return res.status(404).json({ error: 'Business or email not found' });
    }
    const resetToken = crypto.randomBytes(32).toString('hex');
    business.resetToken = resetToken;
    business.resetTokenExpiry = new Date(Date.now() + 60 * 60 * 1000);
    business.auditLogs.push({
      action: 'pin_reset_request',
      performedBy: business.ownerUsername,
      details: { email },
    });
    await business.save();
    const resetLink = `https://your-app.com/reset-pin?token=${resetToken}&businessId=${businessId}`;
    await sendEmail(business.email, 'Reset Your PIN', `Click to reset: ${resetLink}`);
    res.json({ message: 'PIN reset link sent to email' });
  } catch (error) {
    console.error('[ForgotPin] Error:', error.message);
    res.status(500).json({ error: 'Failed to request PIN reset', details: error.message });
  }
});

// Reset PIN
router.post('/reset-pin', async (req, res) => {
  const { businessId, resetToken, newPin } = req.body;
  try {
    if (!/^\d{4}$/.test(newPin)) {
      return res.status(400).json({ error: 'PIN must be a 4-digit number' });
    }
    const business = await Business.findOne({
      businessId,
      resetToken,
      resetTokenExpiry: { $gt: new Date() },
    });
    if (!business) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    business.hashedPin = newPin;
    business.resetToken = null;
    business.resetTokenExpiry = null;
    business.auditLogs.push({
      action: 'pin_reset',
      performedBy: business.ownerUsername,
      details: { message: 'PIN reset successful' },
    });
    await business.save();
    if (business.email) {
      await sendEmail(business.email, 'PIN Reset Successful', 'Your PIN has been updated.');
    }
    res.json({ message: 'PIN reset successful' });
  } catch (error) {
    console.error('[ResetPin] Error:', error.message);
    res.status(500).json({ error: 'Failed to reset PIN', details: error.message });
  }
});

// Store QR PIN
router.post('/store-qr-pin', authenticateToken(['business']), async (req, res) => {
  const { businessId, pin } = req.body;
  if (!businessId || !pin) {
    return res.status(400).json({ error: 'Business ID and PIN are required' });
  }
  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'PIN must be a 4-digit number' });
  }
  try {
    let qrId;
    try {
      qrId = crypto.randomBytes(16).toString('hex');
      console.log('[StoreQRPin] Generated qrId with crypto:', qrId);
    } catch (cryptoError) {
      console.warn('[StoreQRPin] Crypto failed, using uuid fallback:', cryptoError.message);
      const { v4: uuidv4 } = require('uuid');
      qrId = uuidv4().replace(/-/g, '');
    }

    const hashedPin = await bcrypt.hash(pin, 10);
    const session = await mongoose.startSession();
    session.startTransaction({ writeConcern: { w: 'majority' } });
    try {
      const business = await Business.findOne({ businessId, isActive: true }).session(session);
      if (!business) {
        await session.abortTransaction();
        session.endSession();
        return res.status(404).json({ error: 'Business not found or inactive' });
      }
      if (businessId !== req.user.businessId) {
        await session.abortTransaction();
        session.endSession();
        return res.status(403).json({ error: 'Unauthorized' });
      }
      await QRPin.deleteOne({ businessId, type: 'business' }, { session });
      await new QRPin({
        type: 'business',
        businessId,
        qrId,
        pin: hashedPin,
        createdAt: new Date(),
        persistent: true,
      }).save({ session });
      await Business.updateOne(
        { businessId },
        {
          $push: {
            transactions: {
              _id: new mongoose.Types.ObjectId().toString(),
              type: 'pending-pin',
              amount: mongoose.Types.Decimal128.fromString('0'),
              currency: 'ZMW',
              toFrom: 'Self',
              date: new Date(),
              status: 'completed',
              qrId,
            },
          },
        },
        { session }
      );
      await session.commitTransaction();
      session.endSession();
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
      businessId,
      pinLength: pin?.length,
    });
    res.status(500).json({ error: 'Server error storing QR PIN' });
  }
});

module.exports = router;