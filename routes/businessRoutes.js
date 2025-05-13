const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const multerS3 = require('multer-s3');
const AWS = require('aws-sdk');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const Flutterwave = require('flutterwave-node-v3');
const mongoose = require('mongoose');
const { Expo } = require('expo-server-sdk');
const { Business, BusinessTransaction } = require('../models/Business');
const BusinessAdminLedger = require('../models/BusinessAdminLedger');
const User = require('../models/User');
const QRCode = require('qrcode');
const authenticateToken = require('../middleware/authenticateToken');
const path = require('path');

// Configure AWS S3
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION || 'us-east-1',
});

const S3_BUCKET = process.env.S3_BUCKET || 'zangena';

// Configure multer for in-memory storage
const uploadMemory = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    console.log('[FileFilter] Checking file:', file.originalname, file.mimetype);
    const filetypes = /pdf|png|jpeg/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(file.originalname.split('.').pop().toLowerCase());
    if (mimetype && extname) {
      return cb(null, true);
    }
    console.error('[FileFilter] Invalid file type:', file.mimetype);
    cb(new Error('Invalid file type. Only PDF, PNG, or JPEG allowed'));
  },
});

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

// Configure Flutterwave
const flw = new Flutterwave(process.env.FLUTTERWAVE_PUBLIC_KEY, process.env.FLUTTERWAVE_SECRET_KEY);

// Secret key for JWT
const JWT_SECRET = process.env.JWT_SECRET;

// Configure Nodemailer with Gmail
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Initialize Expo SDK
const expo = new Expo();

// Helper function to send email notifications
async function sendEmail(to, subject, html) {
  if (!to || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) {
    console.error('[SendEmail] Invalid email address:', to);
    return;
  }
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER || 'no-reply@zangena.com',
      to,
      subject,
      html,
    });
    console.log(`[SendEmail] Sent email to ${to}: ${subject}`);
  } catch (error) {
    console.error(`[SendEmail] Error sending email to ${to}: ${error.message}`);
  }
}

// Helper function to send push notifications
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
    data: { type: 'businessActivity', ...data },
  };
  try {
    await expo.sendPushNotificationsAsync([message]);
    console.log(`[PushNotification] Sent to ${pushToken}: ${title} - ${body}`);
  } catch (error) {
    console.error(`[PushNotification] Error sending to ${pushToken}: ${error.message}`);
  }
}

// Email notification templates
const emailTemplates = {
  transaction: (business, transaction) => `
    <h2>New Transaction Received</h2>
    <p>Dear ${business.name},</p>
    <p>A new transaction has been recorded on your Zangena account:</p>
    <ul>
      <li><strong>Amount:</strong> ZMW ${transaction.amount.toFixed(2)}</li>
      <li><strong>From:</strong> ${transaction.fromUsername || 'Unknown'}</li>
      <li><strong>Description:</strong> ${transaction.description || 'N/A'}</li>
      <li><strong>Date:</strong> ${new Date(transaction.createdAt).toLocaleString()}</li>
      <li><strong>Transaction ID:</strong> ${transaction.transactionId}</li>
    </ul>
    <p>View more details in your Zangena Business app.</p>
    <p>Best regards,<br>Zangena Team</p>
  `,
  deposit: (business, deposit) => `
    <h2>Manual Deposit Submitted</h2>
    <p>Dear ${business.name},</p>
    <p>Your manual deposit request has been submitted:</p>
    <ul>
      <li><strong>Amount:</strong> ZMW ${deposit.amount.toFixed(2)}</li>
      <li><strong>Transaction ID:</strong> ${deposit.transactionId}</li>
      <li><strong>Date:</strong> ${new Date(deposit.date).toLocaleString()}</li>
      <li><strong>Status:</strong> ${deposit.status}</li>
    </ul>
    <p>Awaiting admin verification. You'll be notified once approved.</p>
    <p>Best regards,<br>Zangena Team</p>
  `,
  withdrawal: (business, withdrawal) => `
    <h2>Withdrawal Request Submitted</h2>
    <p>Dear ${business.name},</p>
    <p>Your withdrawal request has been submitted:</p>
    <ul>
      <li><strong>Amount:</strong> ZMW ${withdrawal.amount.toFixed(2)}</li>
      <li><strong>Fee:</strong> ZMW ${withdrawal.fee.toFixed(2)}</li>
      <li><strong>Date:</strong> ${new Date(withdrawal.date).toLocaleString()}</li>
      <li><strong>Status:</strong> ${withdrawal.status}</li>
    </ul>
    <p>Awaiting admin approval. You'll be notified once processed.</p>
    <p>Best regards,<br>Zangena Team</p>
  `,
  refund: (business, refund) => `
    <h2>Refund Processed</h2>
    <p>Dear ${business.name},</p>
    <p>A refund has been processed from your account:</p>
    <ul>
      <li><strong>Amount:</strong> ZMW ${refund.amount.toFixed(2)}</li>
      <li><strong>Fee:</strong> ZMW ${refund.fee.toFixed(2)}</li>
      <li><strong>To:</strong> ${refund.toFrom}</li>
      <li><strong>Reason:</strong> ${refund.reason}</li>
      <li><strong>Date:</strong> ${new Date(refund.date).toLocaleString()}</li>
      <li><strong>Refund ID:</strong> ${refund._id}</li>
    </ul>
    <p>View more details in your Zangena Business app.</p>
    <p>Best regards,<br>Zangena Team</p>
  `,
  signup: (business) => `
    <h2>Business Registration Submitted</h2>
    <p>Dear ${business.name},</p>
    <p>Your business registration has been submitted for approval:</p>
    <ul>
      <li><strong>Business ID:</strong> ${business.businessId}</li>
      <li><strong>Name:</strong> ${business.name}</li>
      <li><strong>Status:</strong> ${business.kycStatus}</li>
      <li><strong>Date:</strong> ${new Date().toLocaleString()}</li>
    </ul>
    <p>You'll be notified once your account is approved.</p>
    <p>Best regards,<br>Zangena Team</p>
  `,
  forgotPin: (business, resetToken) => `
    <h2>Zangena PIN Reset</h2>
    <p>Dear ${business.name},</p>
    <p>You requested a PIN reset for your Zangena account:</p>
    <ul>
      <li><strong>Reset Token:</strong> ${resetToken}</li>
      <li><strong>Expires:</strong> ${new Date(Date.now() + 3600000).toLocaleString()}</li>
    </ul>
    <p>Enter this token in the Zangena Business app to reset your PIN.</p>
    <p>If you didn't request this, please contact support.</p>
    <p>Best regards,<br>Zangena Team</p>
  `,
};

// Function to calculate sending fee
function getSendingFee(amount) {
  return amount <= 50 ? 0.50 :
         amount <= 100 ? 1.00 :
         amount <= 500 ? 2.00 :
         amount <= 1000 ? 2.50 :
         amount <= 5000 ? 3.50 : 5.00;
}

// Function to initiate settlement
async function initiateSettlement(business, amount, transactionId) {
  const settlementFee = amount * 0.015;
  const netAmount = amount - settlementFee;
  const settlementId = `settle_${crypto.randomBytes(8).toString('hex')}`;
  const paymentData = {
    reference: settlementId,
    amount: netAmount,
    currency: 'ZMW',
    narration: `Zangena Payment to ${business.name}`,
    meta: { feeCharged: settlementFee },
  };
  if (business.bankDetails?.accountType === 'bank') {
    paymentData.account_bank = 'ZANACO_CODE';
    paymentData.account_number = business.bankDetails.accountNumber;
  } else {
    paymentData.phone_number = business.bankDetails?.accountNumber?.startsWith('+260') 
      ? business.bankDetails.accountNumber 
      : `+260${business.bankDetails?.accountNumber}`;
    paymentData.network = business.bankDetails?.bankName?.toUpperCase();
  }
  const response = await flw.Transfer.initiate(paymentData);
  if (response.status !== 'success') {
    throw new Error('Settlement failed');
  }
  business.transactions.push({
    _id: crypto.randomBytes(16).toString('hex'),
    type: 'settled',
    amount: mongoose.Types.Decimal128.fromString(netAmount.toString()),
    fee: mongoose.Types.Decimal128.fromString(settlementFee.toString()),
    toFrom: `${business.bankDetails?.bankName || 'N/A'} (${business.bankDetails?.accountNumber || 'N/A'})`,
    date: new Date(),
  });
  const ledger = await BusinessAdminLedger.findOne();
  if (!ledger) {
    throw new Error('BusinessAdminLedger not initialized');
  }
  ledger.transactions.push({
    type: 'settlement-fee',
    amount: settlementFee,
    businessId: business.businessId,
    transactionId,
    date: new Date(),
  });
  ledger.totalBalance += settlementFee;
  ledger.lastUpdated = new Date();
  await Promise.all([business.save(), ledger.save()]);
  return { settlementId, netAmount, settlementFee };
}

// Admin Middleware
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

// Helper function to convert Decimal128 fields to numbers
const convertDecimal128 = (obj) => {
  if (obj === null || obj === undefined) return null; // Return null for null/undefined
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

// Verify KYC for a business
router.post('/verify-kyc', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { businessId, approved, rejectionReason } = req.body;
  try {
    if (!businessId || typeof approved !== 'boolean') {
      return res.status(400).json({ error: 'businessId and approved status required' });
    }
    const business = await Business.findOne({ businessId });
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    if (business.kycStatus !== 'pending') {
      return res.status(400).json({ error: 'KYC already processed' });
    }
    business.kycStatus = approved ? 'verified' : 'rejected';
    business.isActive = approved;
    if (!approved) {
      business.rejectionReason = rejectionReason || 'KYC documents invalid';
    }
    await business.save();
    if (business.email) {
      await sendEmail(business.email, `KYC ${approved ? 'Approved' : 'Rejected'}`, `
        <h2>KYC Status Update</h2>
        <p>Dear ${business.name},</p>
        <p>Your KYC verification has been ${approved ? 'approved' : 'rejected'}.</p>
        ${!approved ? `<p><strong>Reason:</strong> ${rejectionReason || 'Invalid documents'}</p>` : ''}
        <p>${approved ? 'You can now use your Zangena account fully.' : 'Please contact support for assistance.'}</p>
        <p>Best regards,<br>Zangena Team</p>
      `);
    }
    res.json({ message: `KYC ${approved ? 'approved' : 'rejected'}` });
  } catch (error) {
    console.error('[VerifyKYC] Error:', error.message);
    res.status(500).json({ error: 'Failed to verify KYC', details: error.message });
  }
});

// Consolidated Registration Route
router.post('/register', uploadS3.fields([
  { name: 'tpinCertificate', maxCount: 1 },
  { name: 'pacraCertificate', maxCount: 1 },
]), async (req, res) => {
  const { businessId, name, ownerUsername, pin, phoneNumber, email, bankDetails } = req.body;
  const tpinCertificate = req.files?.tpinCertificate?.[0];
  const pacraCertificate = req.files?.pacraCertificate?.[0];

  try {
    // Input Validation
    if (!businessId || !name || !ownerUsername || !pin || !phoneNumber || !tpinCertificate || !pacraCertificate) {
      return res.status(400).json({ error: 'Business ID, name, username, PIN, phone number, TPIN certificate, and PACRA certificate required' });
    }
    if (!/^\d{10}$/.test(businessId)) {
      return res.status(400).json({ error: 'Business ID must be a 10-digit TPIN' });
    }
    if (!/^[a-zA-Z0-9]{3,}$/.test(ownerUsername)) {
      return res.status(400).json({ error: 'Username must be at least 3 alphanumeric characters' });
    }
    if (!/^\d{4}$/.test(pin)) {
      return res.status(400).json({ error: 'PIN must be a 4-digit number' });
    }
    if (!/^\+260(9[5678]|7[34679])\d{7}$/.test(phoneNumber)) {
      return res.status(400).json({ error: 'Invalid Zambian phone number' });
    }
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email address' });
    }
    let parsedBankDetails;
    if (bankDetails) {
      try {
        parsedBankDetails = typeof bankDetails === 'string' ? JSON.parse(bankDetails) : bankDetails;
        if (!['bank', 'mobile_money', 'zambia_coin'].includes(parsedBankDetails.accountType)) {
          return res.status(400).json({ error: 'Account type must be bank, mobile_money, or zambia_coin' });
        }
        if (parsedBankDetails.accountNumber) {
          if (parsedBankDetails.accountType === 'bank' && !/^\d{10,12}$/.test(parsedBankDetails.accountNumber)) {
            return res.status(400).json({ error: 'Bank account must be 10-12 digits' });
          }
          if (parsedBankDetails.accountType === 'mobile_money' && !/^\+260(9[5678]|7[34679])\d{7}$/.test(parsedBankDetails.accountNumber)) {
            return res.status(400).json({ error: 'Invalid mobile money number' });
          }
          if (!parsedBankDetails.bankName?.trim()) {
            return res.status(400).json({ error: 'Bank or mobile name required' });
          }
        }
      } catch (error) {
        return res.status(400).json({ error: 'Invalid bankDetails format' });
      }
    }

    // Check for duplicates
    const existingBusiness = await Business.findOne({
      $or: [{ businessId }, { ownerUsername }, { phoneNumber }, email ? { email } : {}].filter(Boolean),
    });
    if (existingBusiness) {
      return res.status(409).json({ error: 'TPIN, username, phone, or email already taken' });
    }

    // Generate QR code data
    const qrCodeData = JSON.stringify({ type: 'business_payment', businessId, businessName: name });

    // Hash PIN
    const hashedPin = await bcrypt.hash(pin, 10);

    // Create business
    const business = new Business({
      businessId,
      name,
      ownerUsername,
      hashedPin,
      phoneNumber,
      email,
      bankDetails: parsedBankDetails && (parsedBankDetails.bankName || parsedBankDetails.accountNumber) ? {
        bankName: parsedBankDetails.bankName?.trim(),
        accountNumber: parsedBankDetails.accountNumber,
        accountType: parsedBankDetails.accountType,
      } : null,
      tpinCertificate: tpinCertificate?.location,
      pacraCertificate: pacraCertificate?.location,
      qrCode: qrCodeData,
      balance: mongoose.Types.Decimal128.fromString('0'),
      zambiaCoinBalance: mongoose.Types.Decimal128.fromString('0'),
      transactions: [],
      pendingDeposits: [],
      pendingWithdrawals: [],
      kycStatus: 'pending',
      role: 'business',
      isActive: false,
    });

    await business.save();

    // Notifications
    if (business.email) {
      await sendEmail(business.email, 'Business Registration Submitted', emailTemplates.signup(business));
    }
    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(
        admin.pushToken,
        'New Business Registration',
        `Business ${name} (${businessId}) needs approval`,
        { businessId }
      );
    }

    res.status(201).json({
      message: 'Business registered, awaiting approval',
      business: { businessId, name, kycStatus: 'pending' },
    });
  } catch (error) {
    console.error('[BusinessRegister] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error during business registration', details: error.message });
  }
});

// Consolidated Login Route
// Login
router.post('/login', async (req, res) => {
  const { businessId, pin } = req.body;
  try {
    console.log('[Login] Attempting login for businessId:', businessId);
    if (!businessId || !pin) {
      console.error('[Login] Missing businessId or pin');
      return res.status(400).json({ error: 'Business ID and PIN are required' });
    }
    if (!/^\d{10}$/.test(businessId)) {
      console.error('[Login] Invalid businessId format:', businessId);
      return res.status(400).json({ error: 'Business ID must be a 10-digit TPIN' });
    }
    if (!/^\d{4}$/.test(pin)) {
      console.error('[Login] Invalid PIN format');
      return res.status(400).json({ error: 'PIN must be a 4-digit number' });
    }

    const business = await Business.findOne({ businessId }).lean();
    if (!business) {
      console.error('[Login] Business not found:', businessId);
      return res.status(404).json({ error: 'Business not found' });
    }
    if (!business.isActive) {
      console.error('[Login] Business inactive:', businessId);
      return res.status(403).json({ error: 'Business is inactive' });
    }

    // Compare PIN (assuming PIN is hashed in the database)
    const isPinValid = await bcrypt.compare(pin, business.pin);
    if (!isPinValid) {
      console.error('[Login] Invalid PIN for businessId:', businessId);
      return res.status(401).json({ error: 'Invalid PIN' });
    }

    const token = jwt.sign(
      { businessId: business.businessId, role: business.role || 'business', ownerUsername: business.ownerUsername },
      JWT_SECRET,
      { expiresIn: '30d' }
    );
    console.log('[Login] Token generated for businessId:', businessId);
    res.json({
      token,
      business: {
        businessId: business.businessId,
        name: business.name,
        ownerUsername: business.ownerUsername,
        kycStatus: business.kycStatus,
        isActive: business.isActive,
        balance: convertDecimal128(business.balance),
      },
    });
  } catch (error) {
    console.error('[Login] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to sign in', details: error.message });
  }
});

// Forgot PIN
router.post('/forgot-pin', async (req, res) => {
  const { phoneNumber, businessId } = req.body;
  try {
    if (!phoneNumber && !businessId) {
      return res.status(400).json({ error: 'Phone number or Business ID required' });
    }
    if (phoneNumber && !/^\+260(9[5678]|7[34679])\d{7}$/.test(phoneNumber)) {
      return res.status(400).json({ error: 'Invalid phone number' });
    }
    if (businessId && !/^\d{10}$/.test(businessId)) {
      return res.status(400).json({ error: 'Business ID must be a 10-digit TPIN' });
    }
    const business = await Business.findOne({
      $or: [
        phoneNumber ? { phoneNumber } : {},
        businessId ? { businessId } : {},
      ].filter(Boolean),
    });
    if (!business) {
      return res.status(404).json({ error: 'No account found with that identifier' });
    }
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000;
    business.resetToken = resetToken;
    business.resetTokenExpiry = resetTokenExpiry;
    await business.save();
    if (business.email) {
      await sendEmail(business.email, 'Zangena PIN Reset', emailTemplates.forgotPin(business, resetToken));
    }
    if (business.pushToken) {
      await sendPushNotification(business.pushToken, 'PIN Reset Requested', 'A PIN reset token has been sent to your email.');
    }
    res.json({ message: 'Reset instructions sent to your email, if provided.' });
  } catch (error) {
    console.error('[ForgotPin] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error during PIN reset request', details: error.message });
  }
});

// Reset PIN
router.post('/reset-pin', async (req, res) => {
  const { resetToken, newPin, phoneNumber, businessId } = req.body;
  try {
    if (!resetToken || !newPin || (!phoneNumber && !businessId)) {
      return res.status(400).json({ error: 'Reset token, new PIN, and phone number or Business ID required' });
    }
    if (!/^\d{4}$/.test(newPin)) {
      return res.status(400).json({ error: 'New PIN must be a 4-digit number' });
    }
    const business = await Business.findOne({
      $or: [
        phoneNumber ? { phoneNumber } : {},
        businessId ? { businessId } : {},
      ].filter(Boolean),
    });
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    if (!business.resetToken || business.resetToken !== resetToken || business.resetTokenExpiry < Date.now()) {
      return res.status(401).json({ error: 'Invalid or expired reset token' });
    }
    business.hashedPin = await bcrypt.hash(newPin, 10);
    business.resetToken = null;
    business.resetTokenExpiry = null;
    await business.save();
    if (business.email) {
      await sendEmail(business.email, 'PIN Reset Successful', `
        <h2>PIN Reset Successful</h2>
        <p>Dear ${business.name},</p>
        <p>Your Zangena account PIN has been successfully reset.</p>
        <p>If you didn't perform this action, please contact support immediately.</p>
        <p>Best regards,<br>Zangena Team</p>
      `);
    }
    if (business.pushToken) {
      await sendPushNotification(business.pushToken, 'PIN Reset Successful', 'Your account PIN has been successfully reset.');
    }
    res.json({ message: 'PIN reset successfully' });
  } catch (error) {
    console.error('[ResetPin] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error during PIN reset', details: error.message });
  }
});

// Fetch Business Details
router.get('/:businessId', authenticateToken(['business', 'admin']), async (req, res) => {
  try {
    console.log('[BusinessFetch] Fetching business:', req.params.businessId, 'User:', req.user);
    const business = await Business.findOne({ businessId: req.params.businessId }).lean();
    if (!business) {
      console.error('[BusinessFetch] Business not found:', req.params.businessId);
      return res.status(404).json({ error: 'Business not found' });
    }
    if (req.user.role === 'business' && req.user.businessId !== business.businessId) {
      console.error('[BusinessFetch] Unauthorized access:', req.user.businessId, '!=', business.businessId);
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const response = convertDecimal128({
      businessId: business.businessId,
      name: business.name,
      ownerUsername: business.ownerUsername,
      balance: business.balance,
      zambiaCoinBalance: business.zambiaCoinBalance,
      qrCode: business.qrCode,
      kycStatus: business.kycStatus,
      transactions: business.transactions.slice(-10),
      isActive: business.isActive,
      email: business.email,
      phoneNumber: business.phoneNumber,
      bankDetails: business.bankDetails,
    });
    res.json(response);
  } catch (error) {
    console.error('[BusinessFetch] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error fetching business', details: error.message });
  }
});

// Generate QR Code
router.post('/qr/generate', authenticateToken(['business']), async (req, res) => {
  const { amount, description, transactionType } = req.body;
  try {
    if (!description || !['in-store', 'online'].includes(transactionType)) {
      return res.status(400).json({ error: 'Description and valid transactionType (in-store or online) required' });
    }
    if (transactionType === 'online' && (!amount || amount <= 0)) {
      return res.status(400).json({ error: 'Amount required for online transactions' });
    }
    const business = await Business.findOne({ businessId: req.user.businessId });
    if (!business || !business.isActive) {
      return res.status(403).json({ error: 'Business not found or inactive' });
    }
    const transactionId = `tx_${crypto.randomBytes(8).toString('hex')}`;
    const qrCodeId = `qr_${crypto.randomBytes(8).toString('hex')}`;
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);
    const qrData = { businessId: business.businessId, transactionId, amount: amount || null, expiresAt };
    const qrCodeBuffer = await QRCode.toBuffer(JSON.stringify(qrData));
    const s3Key = `qr-codes/dynamic/${qrCodeId}.png`;
    await s3.upload({
      Bucket: S3_BUCKET,
      Key: s3Key,
      Body: qrCodeBuffer,
      ContentType: 'image/png',
      ACL: 'public-read',
    }).promise();
    const qrCodeUrl = `https://${S3_BUCKET}.s3.amazonaws.com/${s3Key}`;
    const transaction = new BusinessTransaction({
      transactionId,
      businessId: business.businessId,
      amount,
      status: 'pending',
      qrCodeId,
      qrCodeUrl,
      description,
      expiresAt,
    });
    await transaction.save();
    res.status(201).json({ qrCodeId, qrCodeUrl, transactionId, expiresAt: expiresAt.toISOString() });
  } catch (error) {
    console.error('[QRGenerate] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to generate QR code', details: error.message });
  }
});

// Process QR Payment
router.post('/qr/pay', authenticateToken(['user']), async (req, res) => {
  const { qrCodeId, amount, pin } = req.body;
  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    if (!qrCodeId || !pin || (amount && amount <= 0)) {
      throw new Error('QR code ID, PIN, and valid amount (if provided) required');
    }
    const user = await User.findOne({ username: req.user.username }).session(session);
    if (!user || !user.isActive) {
      throw new Error('User not found or inactive');
    }
    const isPinValid = await bcrypt.compare(pin, user.hashedPin);
    if (!isPinValid) {
      throw new Error('Invalid PIN');
    }
    const transaction = await BusinessTransaction.findOne({ qrCodeId, status: 'pending' }).session(session);
    if (!transaction || transaction.expiresAt < new Date()) {
      throw new Error('Invalid or expired QR code');
    }
    const business = await Business.findOne({ businessId: transaction.businessId }).session(session);
    if (!business || !business.isActive) {
      throw new Error('Business not found or inactive');
    }
    const paymentAmount = transaction.amount || amount;
    if (!paymentAmount || paymentAmount > 10000) {
      throw new Error('Invalid amount or exceeds 10,000 ZMW');
    }
    const sendingFee = getSendingFee(paymentAmount);
    const totalDeduction = paymentAmount + sendingFee;
    if (convertDecimal128(user.balance) < totalDeduction) {
      throw new Error('Insufficient balance');
    }
    user.balance = mongoose.Types.Decimal128.fromString((convertDecimal128(user.balance) - totalDeduction).toString());
    business.balance = mongoose.Types.Decimal128.fromString((convertDecimal128(business.balance) + paymentAmount).toString());
    const ledger = await BusinessAdminLedger.findOne().session(session);
    if (!ledger) {
      throw new Error('BusinessAdminLedger not initialized');
    }
    ledger.totalBalance += sendingFee;
    ledger.lastUpdated = new Date();
    const txId = crypto.randomBytes(16).toString('hex');
    user.transactions.push({
      _id: txId,
      type: 'sent',
      amount: mongoose.Types.Decimal128.fromString(paymentAmount.toString()),
      toFrom: business.businessId,
      fee: mongoose.Types.Decimal128.fromString(sendingFee.toString()),
      date: new Date(),
    });
    const businessTransaction = {
      _id: crypto.randomBytes(16).toString('hex'),
      type: 'received',
      amount: mongoose.Types.Decimal128.fromString(paymentAmount.toString()),
      toFrom: user.username,
      date: new Date(),
    };
    business.transactions.push(businessTransaction);
    ledger.transactions.push({
      type: 'fee-collected',
      amount: sendingFee,
      businessId: business.businessId,
      userId: user.username,
      transactionId: txId,
      date: new Date(),
    });
    transaction.status = 'completed';
    transaction.fromUsername = user.username;
    let settlementResult;
    try {
      settlementResult = await initiateSettlement(business, paymentAmount, txId);
    } catch (settleError) {
      console.error('[QRPay] Settlement failed but transaction recorded:', settleError.message);
    }
    await Promise.all([user.save({ session }), business.save({ session }), ledger.save({ session }), transaction.save({ session })]);
    await session.commitTransaction();
    if (business.email) {
      await sendEmail(business.email, 'Payment Received', emailTemplates.transaction(business, {
        ...businessTransaction,
        transactionId: txId,
        amount: paymentAmount,
        fromUsername: user.username,
        description: transaction.description,
        createdAt: new Date(),
      }));
    }
    if (business.pushToken) {
      await sendPushNotification(business.pushToken, 'Payment Received', `Received ${paymentAmount.toFixed(2)} ZMW from ${user.username}`, { transactionId: txId });
    }
    res.json({
      message: 'Payment successful',
      transactionId: txId,
      amount: paymentAmount,
      sendingFee,
      settlementId: settlementResult?.settlementId,
      settlementAmount: settlementResult?.netAmount,
      settlementFee: settlementResult?.settlementFee,
    });
  } catch (error) {
    await session.abortTransaction();
    console.error('[QRPay] Error:', error.message, error.stack);
    res.status(error.message.includes('not found') ? 404 : 400).json({ error: error.message });
  } finally {
    session.endSession();
  }
});

// Dashboard Metrics
router.get('/dashboard', authenticateToken(['business']), async (req, res) => {
  const { startDate, endDate } = req.query;
  try {
    console.log('[Dashboard] Fetching for businessId:', req.user?.businessId, 'User:', req.user);
    if (!req.user?.businessId) {
      console.error('[Dashboard] No businessId in req.user');
      return res.status(401).json({ error: 'Authentication error: Missing businessId' });
    }
    console.log('[Dashboard] Querying Business collection for businessId:', req.user.businessId);
    const business = await Business.findOne({ businessId: req.user.businessId }).lean();
    if (!business) {
      console.error('[Dashboard] Business not found:', req.user.businessId);
      console.log('[Dashboard] Business query result:', business);
      return res.status(404).json({ error: 'Business not found' });
    }
    console.log('[Dashboard] Business found:', business.businessId, 'Active:', business.isActive);
    if (!business.isActive) {
      console.error('[Dashboard] Business inactive:', req.user.businessId);
      return res.status(403).json({ error: 'Business is inactive' });
    }
    const match = { businessId: business.businessId, status: 'completed' };
    if (startDate || endDate) {
      match.createdAt = {};
      if (startDate) match.createdAt.$gte = new Date(startDate);
      if (endDate) match.createdAt.$lte = new Date(endDate);
    }
    console.log('[Dashboard] Aggregating transactions with match:', match);
    const metrics = await BusinessTransaction.aggregate([
      { $match: match },
      {
        $group: {
          _id: null,
          totalRevenue: { $sum: '$amount' },
          transactionCount: { $sum: 1 },
          amounts: { $push: '$amount' },
        },
      },
      {
        $project: {
          totalRevenue: 1,
          transactionCount: 1,
          averageTransaction: { $cond: [{ $eq: ['$transactionCount', 0] }, 0, { $divide: ['$totalRevenue', '$transactionCount'] }] },
        },
      },
    ]);
    const recentTransactions = await BusinessTransaction.find(match)
      .select('transactionId amount fromUsername description createdAt')
      .sort({ createdAt: -1 })
      .limit(10)
      .lean();
    const settlements = (business.transactions || []).filter(t => t.type === 'settled').slice(0, 10);
    const response = convertDecimal128({
      totalRevenue: metrics[0]?.totalRevenue || 0,
      transactionCount: metrics[0]?.transactionCount || 0,
      averageTransaction: metrics[0]?.averageTransaction || 0,
      settlements,
      recentTransactions,
    });
    console.log('[Dashboard] Response:', response);
    res.json(response);
  } catch (error) {
    console.error('[Dashboard] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to fetch dashboard data', details: error.message });
  }
});

// Process Refund
router.post('/refund', authenticateToken(['business']), async (req, res) => {
  const { transactionId, amount, reason } = req.body;
  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    if (!transactionId || !amount || amount <= 0 || !reason) {
      throw new Error('Transaction ID, valid amount, and reason required');
    }
    const transaction = await BusinessTransaction.findOne({ transactionId, status: 'completed' }).session(session);
    if (!transaction || transaction.businessId !== req.user.businessId) {
      throw new Error('Invalid or unauthorized transaction');
    }
    const business = await Business.findOne({ businessId: req.user.businessId }).session(session);
    if (!business || !business.isActive) {
      throw new Error('Business not found or inactive');
    }
    const refundAmount = parseFloat(amount);
    if (convertDecimal128(business.balance) < refundAmount) {
      throw new Error('Insufficient business balance');
    }
    const user = await User.findOne({ username: transaction.fromUsername }).session(session);
    if (!user || !user.isActive) {
      throw new Error('User not found or inactive');
    }
    const refundFee = refundAmount * 0.01;
    const netRefund = refundAmount - refundFee;
    business.balance = mongoose.Types.Decimal128.fromString((convertDecimal128(business.balance) - refundAmount).toString());
    user.balance = mongoose.Types.Decimal128.fromString((convertDecimal128(user.balance) + netRefund).toString());
    const ledger = await BusinessAdminLedger.findOne().session(session);
    if (!ledger) {
      throw new Error('BusinessAdminLedger not initialized');
    }
    ledger.totalBalance += refundFee;
    ledger.lastUpdated = new Date();
    const refundId = `rf_${crypto.randomBytes(8).toString('hex')}`;
    const refundTransaction = {
      _id: refundId,
      type: 'refunded',
      amount: mongoose.Types.Decimal128.fromString(refundAmount.toString()),
      toFrom: user.username,
      fee: mongoose.Types.Decimal128.fromString(refundFee.toString()),
      reason,
      date: new Date(),
    };
    business.transactions.push(refundTransaction);
    user.transactions.push({
      _id: crypto.randomBytes(16).toString('hex'),
      type: 'received',
      amount: mongoose.Types.Decimal128.fromString(netRefund.toString()),
      toFrom: business.businessId,
      fee: mongoose.Types.Decimal128.fromString(refundFee.toString()),
      reason,
      date: new Date(),
    });
    ledger.transactions.push({
      type: 'fee-collected',
      amount: refundFee,
      businessId: business.businessId,
      userId: user.username,
      transactionId: refundId,
      date: new Date(),
    });
    transaction.refundedAmount = mongoose.Types.Decimal128.fromString(((transaction.refundedAmount ? convertDecimal128(transaction.refundedAmount) : 0) + refundAmount).toString());
    await Promise.all([business.save({ session }), user.save({ session }), ledger.save({ session }), transaction.save({ session })]);
    await session.commitTransaction();
    if (business.email) {
      await sendEmail(business.email, 'Refund Processed', emailTemplates.refund(business, refundTransaction));
    }
    if (user.pushToken) {
      await sendPushNotification(user.pushToken, 'Refund Received', `Received ${netRefund.toFixed(2)} ZMW refund from ${business.name}`, { refundId });
    }
    if (business.pushToken) {
      await sendPushNotification(business.pushToken, 'Refund Processed', `Refunded ${netRefund.toFixed(2)} ZMW to ${user.username}`, { refundId });
    }
    res.json({ refundId, message: 'Refund processed', refundAmount: netRefund, refundFee });
  } catch (error) {
    await session.abortTransaction();
    console.error('[Refund] Error:', error.message, error.stack);
    res.status(error.message.includes('not found') ? 404 : 400).json({ error: error.message });
  } finally {
    session.endSession();
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
    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    if (!transactionId || business.pendingDeposits.some(d => d.transactionId === transactionId)) {
      return res.status(400).json({ error: 'Transaction ID required or already used' });
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
      await sendEmail(business.email, 'Manual Deposit Submitted', emailTemplates.deposit(business, convertDecimal128(deposit)));
    }
    if (business.pushToken) {
      await sendPushNotification(business.pushToken, 'Deposit Submitted', `Manual deposit of ${amount.toFixed(2)} ZMW submitted for verification`, { transactionId });
    }
    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(admin.pushToken, 'New Business Deposit', `Deposit of ${amount} ZMW from ${business.name} (${business.businessId}) needs approval`, { businessId: business.businessId, transactionId });
    }
    res.json({ message: 'Business deposit submitted for verification' });
  } catch (error) {
    console.error('[BusinessDeposit] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to submit business deposit', details: error.message });
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
    if (!destination || !['bank', 'mobile_money', 'zambia_coin'].includes(destination.type)) {
      return res.status(400).json({ error: 'Valid destination required' });
    }
    const withdrawalFee = Math.max(withdrawalAmount * 0.01, 2);
    const totalDeduction = withdrawalAmount + withdrawalFee;
    if (convertDecimal128(business.balance) < totalDeduction) {
      return res.status(400).json({ error: 'Insufficient balance to cover amount and fee' });
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
      await sendEmail(business.email, 'Withdrawal Request Submitted', emailTemplates.withdrawal(business, convertDecimal128(withdrawal)));
    }
    if (business.pushToken) {
      await sendPushNotification(business.pushToken, 'Withdrawal Requested', `Your request for ${withdrawalAmount.toFixed(2)} ZMW (Fee: ${withdrawalFee.toFixed(2)} ZMW) is pending approval`, { businessId: business.businessId });
    }
    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(admin.pushToken, 'New Business Withdrawal', `Withdrawal of ${withdrawalAmount} ZMW from ${business.name} (${business.businessId}) needs approval`, { businessId: business.businessId });
    }
    res.json({ message: 'Business withdrawal requested. Awaiting approval', withdrawalFee });
  } catch (error) {
    console.error('[BusinessWithdraw] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to request business withdrawal', details: error.message });
  }
});

// Register Push Token
router.post('/register-push-token', authenticateToken(['business']), async (req, res) => {
  const { pushToken } = req.body;
  try {
    if (!pushToken) {
      return res.status(400).json({ error: 'Push token is required' });
    }
    const business = await Business.findOne({ businessId: req.user.businessId });
    if (!business) {
      console.error('[RegisterPushToken] Business not found:', req.user.businessId);
      return res.status(404).json({ error: 'Business not found' });
    }
    business.pushToken = pushToken;
    await business.save();
    console.log('[RegisterPushToken] Push token saved for business:', business.businessId);
    res.status(200).json({ message: 'Push token registered for business' });
  } catch (error) {
    console.error('[RegisterPushToken] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to register push token', details: error.message });
  }
});

// Get Businesses (Admin)
router.get('/', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '' } = req.query;
    const pageNum = parseInt(page, 10);
    const limitNum = parseInt(limit, 10);

    const query = search
      ? {
          $or: [
            { businessId: { $regex: search, $options: 'i' } },
            { name: { $regex: search, $options: 'i' } },
          ],
        }
      : {};

    const businesses = await Business.find(query)
      .select('businessId name isActive balance zambiaCoinBalance')
      .skip((pageNum - 1) * limitNum)
      .limit(limitNum)
      .lean();

    const total = await Business.countDocuments(query);

    res.status(200).json({
      businesses: businesses.map(b => convertDecimal128({
        businessId: b.businessId,
        name: b.name || '',
        isActive: b.isActive,
        balance: b.balance,
        zambiaCoinBalance: b.zambiaCoinBalance,
      })),
      total,
      page: pageNum,
      totalPages: Math.ceil(total / limitNum) || 1,
    });
  } catch (error) {
    console.error('[FetchBusinesses] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to fetch businesses', details: error.message });
  }
});

// Get Business by ID (Admin)
router.get('/:id', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  try {
    const business = await Business.findOne({ businessId: req.params.id }).lean();
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    res.json(convertDecimal128(business));
  } catch (error) {
    console.error('[FetchBusiness] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to fetch business', details: error.message });
  }
});

// Update KYC Status (Admin)
router.post('/update-kyc', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { businessId, kycStatus } = req.body;
  try {
    if (!businessId || !['pending', 'verified', 'rejected'].includes(kycStatus)) {
      return res.status(400).json({ error: 'Invalid businessId or kycStatus' });
    }
    const business = await Business.findOneAndUpdate(
      { businessId },
      { kycStatus, updatedAt: new Date() },
      { new: true }
    );
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    res.json({ message: `KYC status updated to ${kycStatus}`, business: convertDecimal128(business) });
  } catch (error) {
    console.error('[UpdateKYC] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Toggle Active Status (Admin)
router.put('/toggle-active', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { businessId } = req.body;
  try {
    if (!businessId) {
      return res.status(400).json({ error: 'Invalid businessId' });
    }
    const business = await Business.findOne({ businessId });
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    business.isActive = !business.isActive;
    await business.save();
    res.status(200).json({
      message: business.isActive ? 'Business activated' : 'Business deactivated',
      business: convertDecimal128({
        businessId: business.businessId,
        name: business.name || '',
        isActive: business.isActive,
        balance: business.balance,
        zambiaCoinBalance: business.zambiaCoinBalance,
      }),
    });
  } catch (error) {
    console.error('[ToggleActive] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

// Reset All PINs (Admin)
router.post('/admin/reset-all-pins', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  try {
    const businesses = await Business.find({});
    for (const business of businesses) {
      business.hashedPin = await bcrypt.hash('0000', 10);
      await business.save();
    }
    res.json({ message: 'All PINs reset to 0000' });
  } catch (error) {
    console.error('[ResetAllPins] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to reset PINs', details: error.message });
  }
});

module.exports = router;