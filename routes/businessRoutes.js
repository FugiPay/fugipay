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
const Business = require('../models/Business');
const BusinessTransaction = require('../models/BusinessTransaction');
const BusinessAdminLedger = require('../models/BusinessAdminLedger');
const User = require('../models/User');
const QRCode = require('qrcode');
const authenticateToken = require('../middleware/authenticateToken');
const axios = require('axios');
const path = require('path');

// Configure AWS S3
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION || 'us-east-1',
});

const S3_BUCKET = process.env.S3_BUCKET || 'zangena';

// Configure multer for in-memory storage (for /signup)
const memoryStorage = multer.memoryStorage();

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
  }
});

// Configure multer-s3 for file uploads (for /register)
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
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
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
const JWT_SECRET = process.env.JWT_SECRET || 'Zangena123$@2025';

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

// Helper function to send email notifications directly
async function sendEmail(to, subject, html) {
  if (!to || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to)) {
    console.error('[SendEmail] Invalid email address:', to);
    return;
  }
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER || 'no-reply@zangena.com',
      to,
      subject,
      html,
    };
    await transporter.sendMail(mailOptions);
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
  if (business.bankDetails.accountType === 'bank') {
    paymentData.account_bank = 'ZANACO_CODE';
    paymentData.account_number = business.bankDetails.accountNumber;
  } else {
    paymentData.phone_number = business.bankDetails.accountNumber.startsWith('+260') ? business.bankDetails.accountNumber : `+260${business.bankDetails.accountNumber}`;
    paymentData.network = business.bankDetails.bankName.toUpperCase();
  }
  const response = await flw.Transfer.initiate(paymentData);
  if (response.status !== 'success') {
    throw new Error('Settlement failed');
  }
  business.transactions.push({
    _id: crypto.randomBytes(16).toString('hex'),
    type: 'settled',
    amount: netAmount,
    fee: settlementFee,
    toFrom: `${business.bankDetails.bankName} (${business.bankDetails.accountNumber})`,
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

// Admin Stuff ........................................................

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

// Get all businesses (with optional kycStatus filter)
router.get('/', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  try {
    const { kycStatus } = req.query;
    const query = kycStatus ? { kycStatus } : {};
    const businesses = await Business.find(query).select(
      'businessId name ownerUsername email phoneNumber balance kycStatus tpinCertificate pacraCertificate pendingDeposits isActive'
    );
    res.json(businesses);
  } catch (error) {
    console.error('[BusinessFetch] Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch businesses' });
  }
});

// Verify KYC for a business
router.post('/verify-kyc', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { businessId, approved, rejectionReason } = req.body;
  try {
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
    res.json({ message: `KYC ${approved ? 'approved' : 'rejected'}` });
  } catch (error) {
    console.error('[VerifyKYC] Error:', error.message);
    res.status(500).json({ error: 'Failed to verify KYC' });
  }
});

// End Admin ..........................................................

router.post('/signup', async (req, res) => {
  console.log('[SignUp] Received request:', {
    body: { ...req.body, pin: '****' }
  });

  try {
    const {
      businessId, name, ownerUsername, pin, phoneNumber, email, bankDetails
    } = req.body;

    if (!businessId || !name || !ownerUsername || !pin || !phoneNumber || !email) {
      console.error('[SignUp] Missing fields');
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (!/^\d{10}$/.test(businessId)) {
      console.error('[SignUp] Invalid businessId:', businessId);
      return res.status(400).json({ error: 'Business ID must be a 10-digit TPIN' });
    }

    if (!/^[a-zA-Z0-9]{3,}$/.test(ownerUsername)) {
      console.error('[SignUp] Invalid ownerUsername:', ownerUsername);
      return res.status(400).json({ error: 'Username must be at least 3 alphanumeric characters' });
    }

    if (!/^\d{4}$/.test(pin)) {
      console.error('[SignUp] Invalid pin:', pin);
      return res.status(400).json({ error: 'PIN must be a 4-digit number' });
    }

    if (!/^\+260(9[5678]|7[34679])\d{7}$/.test(phoneNumber)) {
      console.error('[SignUp] Invalid phoneNumber:', phoneNumber);
      return res.status(400).json({ error: 'Invalid Zambian phone number' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      console.error('[SignUp] Invalid email:', email);
      return res.status(400).json({ error: 'Invalid email address' });
    }

    // Check for duplicates individually
    const existingByBusinessId = await Business.findOne({ businessId });
    if (existingByBusinessId) {
      console.error('[SignUp] Duplicate businessId:', businessId);
      return res.status(409).json({ error: 'Business ID already taken' });
    }

    const existingByUsername = await Business.findOne({ ownerUsername });
    if (existingByUsername) {
      console.error('[SignUp] Duplicate ownerUsername:', ownerUsername);
      return res.status(409).json({ error: 'Username already taken' });
    }

    const existingByPhone = await Business.findOne({ phoneNumber });
    if (existingByPhone) {
      console.error('[SignUp] Duplicate phoneNumber:', phoneNumber);
      return res.status(409).json({ error: 'Phone number already taken' });
    }

    const existingByEmail = await Business.findOne({ email });
    if (existingByEmail) {
      console.error('[SignUp] Duplicate email:', email);
      return res.status(409).json({ error: 'Email already taken' });
    }

    let parsedBankDetails = null;
    if (bankDetails) {
      try {
        parsedBankDetails = JSON.parse(bankDetails);
        console.log('[SignUp] Parsed bankDetails:', parsedBankDetails);
        // Validate bankDetails fields
        if (!parsedBankDetails.bankName || typeof parsedBankDetails.bankName !== 'string') {
          console.error('[SignUp] Invalid bankName:', parsedBankDetails.bankName);
          return res.status(400).json({ error: 'Bank or mobile money provider name is required' });
        }
        if (!parsedBankDetails.accountNumber || typeof parsedBankDetails.accountNumber !== 'string') {
          console.error('[SignUp] Invalid accountNumber:', parsedBankDetails.accountNumber);
          return res.status(400).json({ error: 'Account number is required' });
        }
        if (!parsedBankDetails.accountType || !['bank', 'mobile_money', 'zambia_coin'].includes(parsedBankDetails.accountType)) {
          console.error('[SignUp] Invalid accountType:', parsedBankDetails.accountType);
          return res.status(400).json({ error: 'Account type must be bank, mobile_money, or zambia_coin' });
        }
        // Validate accountNumber based on accountType
        if (parsedBankDetails.accountType === 'bank' && !/^\d{10,12}$/.test(parsedBankDetails.accountNumber)) {
          console.error('[SignUp] Invalid bank accountNumber:', parsedBankDetails.accountNumber);
          return res.status(400).json({ error: 'Bank account number must be 10-12 digits' });
        }
        if ((parsedBankDetails.accountType === 'mobile_money' || parsedBankDetails.accountType === 'zambia_coin') && 
            !/^\+260(9[5678]|7[34679])\d{7}$/.test(parsedBankDetails.accountNumber)) {
          console.error('[SignUp] Invalid mobile money/zambia_coin accountNumber:', parsedBankDetails.accountNumber);
          return res.status(400).json({ error: 'Mobile money or Zambia Coin number must be a valid Zambian number' });
        }
      } catch (error) {
        console.error('[SignUp] Invalid bankDetails format:', bankDetails, error.message);
        return res.status(400).json({ error: 'Invalid bank details format' });
      }
    }

    const business = new Business({
      businessId,
      name,
      ownerUsername,
      pin,
      phoneNumber,
      email,
      bankDetails: parsedBankDetails,
      tpinCertificate: null,
      pacraCertificate: null,
      kycStatus: 'pending',
      registrationDate: new Date()
    });

    console.log('[SignUp] Prepared business document:', {
      businessId,
      name,
      ownerUsername,
      pin: '****',
      phoneNumber,
      email,
      bankDetails: parsedBankDetails,
      tpinCertificate: business.tpinCertificate,
      pacraCertificate: business.pacraCertificate,
      kycStatus: business.kycStatus,
      registrationDate: business.registrationDate
    });

    await business.save();
    console.log('[SignUp] Business saved:', businessId);

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Business Registration Submitted',
      text: `Dear ${ownerUsername},\n\nYour business (${name}, TPIN: ${businessId}) has been submitted for review. You'll be notified once approved.\n\nZangena Team`
    };

    console.log('[SendEmail] Sending email to:', email);
    await transporter.sendMail(mailOptions);
    console.log('[SendEmail] Sent email to:', email);

    res.status(201).json({ message: 'Business registered successfully' });
  } catch (error) {
    console.error('[SignUp] Error:', {
      message: error.message,
      stack: error.stack,
      code: error.code,
      details: error.details
    });
    res.status(500).json({ error: 'Server error', details: error.message });
  }
});

router.post('/register', uploadS3.fields([
  { name: 'tpinCertificate', maxCount: 1 },
  { name: 'pacraCertificate', maxCount: 1 },
]), async (req, res) => {
  const { businessId, name, ownerUsername, pin, phoneNumber, email, bankDetails } = req.body;
  const tpinCertificate = req.files?.tpinCertificate?.[0];
  const pacraCertificate = req.files?.pacraCertificate?.[0];

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
  if (bankDetails) {
    try {
      const parsedBankDetails = typeof bankDetails === 'string' ? JSON.parse(bankDetails) : bankDetails;
      if (!['bank', 'mobile_money', 'zambia_coin'].includes(parsedBankDetails.accountType)) {
        return res.status(400).json({ error: 'Account type must be bank, mobile_money, or zambia_coin' });
      }
      if (parsedBankDetails.accountNumber) {
        if (parsedBankDetails.accountType === 'bank') {
          if (!/^\d{10,12}$/.test(parsedBankDetails.accountNumber)) {
            return res.status(400).json({ error: 'Bank account must be 10-12 digits' });
          }
        } else if (parsedBankDetails.accountType === 'mobile_money') {
          if (!/^\+260(9[5678]|7[34679])\d{7}$/.test(parsedBankDetails.accountNumber)) {
            return res.status(400).json({ error: 'Invalid mobile money number' });
          }
        }
        if (!parsedBankDetails.bankName?.trim()) {
          return res.status(400).json({ error: 'Bank or mobile name required' });
        }
      }
    } catch (error) {
      return res.status(400).json({ error: 'Invalid bankDetails format' });
    }
  }

  try {
    const existingBusiness = await Business.findOne({
      $or: [{ businessId }, { ownerUsername }, { phoneNumber }, email ? { email } : {}].filter(Boolean),
    });
    if (existingBusiness) {
      return res.status(409).json({ error: 'TPIN, username, phone, or email already taken' });
    }

    const hashedPin = await bcrypt.hash(pin, 10);
    const qrCodeData = JSON.stringify({ type: 'business_payment', businessId, businessName: name });
    const business = new Business({
      businessId,
      name,
      ownerUsername,
      pin: hashedPin,
      phoneNumber,
      email,
      bankDetails: bankDetails && (bankDetails.bankName || bankDetails.accountNumber) ? {
        bankName: bankDetails.bankName?.trim(),
        accountNumber: bankDetails.accountNumber,
        accountType: bankDetails.accountType,
      } : undefined,
      tpinCertificate: tpinCertificate.location,
      pacraCertificate: pacraCertificate.location,
      qrCode: qrCodeData,
      balance: 0,
      transactions: [],
      pendingDeposits: [],
      pendingWithdrawals: [],
      kycStatus: 'pending',
      role: 'business',
      isActive: false,
    });

    await business.save();

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
    console.error('[BusinessRegister] Error:', error.message);
    res.status(500).json({ error: 'Server error during business registration' });
  }
});

router.post('/login', async (req, res) => {
  const { businessId, pin } = req.body;
  if (!businessId || !pin) return res.status(400).json({ error: 'Business ID and PIN are required' });
  if (!/^\d{10}$/.test(businessId)) return res.status(400).json({ error: 'Business ID must be a 10-digit TPIN' });
  if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be a 4-digit number' });
  try {
    const business = await Business.findOne({ businessId });
    if (!business) return res.status(400).json({ error: 'Invalid credentials' });
    if (!business.isActive) return res.status(403).json({ error: 'Business not approved or inactive' });
    const isMatch = await bcrypt.compare(pin, business.pin);
    if (!isMatch) return res.status(400).json({ error: 'Invalid PIN' });
    const token = jwt.sign({ businessId, role: business.role, ownerUsername: business.ownerUsername }, JWT_SECRET, { expiresIn: '30d' });
    res.status(200).json({ token, businessId, role: business.role, kycStatus: business.kycStatus });
  } catch (error) {
    console.error('[BusinessLogin] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error during business login', details: error.message });
  }
});

router.post('/signin', async (req, res) => {
  const { businessId, pin } = req.body;
  if (!businessId || !pin) {
    return res.status(400).json({ error: 'Business ID and PIN are required' });
  }
  if (!/^\d{10}$/.test(businessId)) {
    return res.status(400).json({ error: 'Business ID must be a 10-digit TPIN' });
  }
  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'PIN must be a 4-digit number' });
  }
  try {
    const business = await Business.findOne({ businessId });
    if (!business) {
      return res.status(404).json({ error: 'Business not found, check your 10-digit TPIN and PIN' });
    }
    if (business.kycStatus !== 'verified') {
      return res.status(403).json({ error: 'Business KYC is not yet verified by admin' });
    }
    const isMatch = await bcrypt.compare(pin, business.pin);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid PIN' });
    }
    const token = jwt.sign({ id: business._id, role: business.role }, JWT_SECRET, { expiresIn: '30d' });
    res.json({
      token,
      business: { businessId: business.businessId, name: business.name, role: business.role, phoneNumber: business.phoneNumber },
    });
  } catch (error) {
    console.error('[BusinessSignin] Error:', error.message);
    res.status(500).json({ error: 'Server error during signin' });
  }
});

router.post('/forgot-pin', async (req, res) => {
  const { phoneNumber, businessId } = req.body;
  if (!phoneNumber && !businessId) {
    return res.status(400).json({ error: 'Phone number or Business ID required' });
  }
  if (phoneNumber && !/^\+260(9[5678]|7[34679])\d{7}$/.test(phoneNumber)) {
    return res.status(400).json({ error: 'Invalid phone number' });
  }
  if (businessId && !/^\d{10}$/.test(businessId)) {
    return res.status(400).json({ error: 'Business ID must be a 10-digit TPIN' });
  }
  try {
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
    res.json({ message: 'Reset instructions have been sent to your email, if provided.' });
  } catch (error) {
    console.error('[ForgotPin] Error:', error.message);
    res.status(500).json({ error: 'Server error during PIN reset request' });
  }
});

router.post('/reset-pin', async (req, res) => {
  const { resetToken, newPin, phoneNumber, businessId } = req.body;
  if (!resetToken || !newPin || (!phoneNumber && !businessId)) {
    return res.status(400).json({ error: 'Reset token, new PIN, and phone number or Business ID required' });
  }
  if (!/^\d{4}$/.test(newPin)) {
    return res.status(400).json({ error: 'New PIN must be a 4-digit number' });
  }
  try {
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
    business.pin = await bcrypt.hash(newPin, 10);
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
    console.error('[ResetPin] Error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

router.get('/:businessId', authenticateToken(['business', 'admin']), async (req, res) => {
  try {
    const business = await Business.findOne({ businessId: req.params.businessId }).lean();
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    if (req.user.role === 'business' && req.user.businessId !== business.businessId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const response = {
      businessId: business.businessId,
      name: business.name,
      ownerUsername: business.ownerUsername,
      balance: business.balance,
      qrCode: business.qrCode,
      kycStatus: business.kycStatus,
      transactions: business.transactions.slice(-10),
      isActive: business.isActive,
      email: business.email,
      phoneNumber: business.phoneNumber,
      bankDetails: business.bankDetails,
    };
    res.json(response);
  } catch (error) {
    console.error('[BusinessFetch] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error fetching business', details: error.message });
  }
});

router.post('/qr/generate', authenticateToken(['business']), async (req, res) => {
  const { amount, description, transactionType } = req.body;
  if (!description || !['in-store', 'online'].includes(transactionType)) {
    return res.status(400).json({ error: 'Description and valid transactionType required' });
  }
  if (transactionType === 'online' && (!amount || amount <= 0)) {
    return res.status(400).json({ error: 'Amount required for online transactions' });
  }
  try {
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
    console.error('[QRGenerate] Error:', error.message);
    res.status(500).json({ error: 'Failed to generate QR code' });
  }
});

router.post('/qr/pay', authenticateToken(['user']), async (req, res) => {
  const { qrCodeId, amount, pin } = req.body;
  if (!qrCodeId || !pin || (amount && amount <= 0)) {
    return res.status(400).json({ error: 'QR code ID, PIN, and valid amount (if provided) required' });
  }
  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    const user = await User.findOne({ username: req.user.username }).session(session);
    if (!user || !user.isActive) {
      throw new Error('User not found or inactive');
    }
    const isPinValid = await bcrypt.compare(pin, user.pin);
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
    if (user.balance < totalDeduction) {
      throw new Error('Insufficient balance');
    }
    user.balance -= totalDeduction;
    business.balance += paymentAmount;
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
      amount: paymentAmount,
      toFrom: business.businessId,
      fee: sendingFee,
      date: new Date(),
    });
    const businessTransaction = {
      _id: crypto.randomBytes(16).toString('hex'),
      type: 'received',
      amount: paymentAmount,
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
    const { settlementId, netAmount, settlementFee } = await initiateSettlement(business, paymentAmount, txId);
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
      settlementId,
      settlementAmount: netAmount,
      settlementFee,
    });
  } catch (error) {
    await session.abortTransaction();
    console.error('[QRPay] Error:', error.message);
    res.status(error.message.includes('not found') ? 404 : 400).json({ error: error.message });
  } finally {
    session.endSession();
  }
});

router.get('/dashboard', authenticateToken(['business']), async (req, res) => {
  const { startDate, endDate } = req.query;
  try {
    const business = await Business.findOne({ businessId: req.user.businessId });
    if (!business || !business.isActive) {
      return res.status(403).json({ error: 'Business not found or inactive' });
    }
    const match = { businessId: business.businessId, status: 'completed' };
    if (startDate || endDate) {
      match.createdAt = {};
      if (startDate) match.createdAt.$gte = new Date(startDate);
      if (endDate) match.createdAt.$lte = new Date(endDate);
    }
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
          averageTransaction: { $divide: ['$totalRevenue', '$transactionCount'] },
        },
      },
    ]);
    const recentTransactions = await BusinessTransaction.find(match)
      .select('transactionId amount fromUsername description createdAt')
      .sort({ createdAt: -1 })
      .limit(10)
      .lean();
    const settlements = await Business.findOne({ businessId: business.businessId })
      .select('transactions')
      .then(b => b.transactions.filter(t => t.type === 'settled').slice(0, 10));
    const response = {
      totalRevenue: metrics[0]?.totalRevenue || 0,
      transactionCount: metrics[0]?.transactionCount || 0,
      averageTransaction: metrics[0]?.averageTransaction || 0,
      settlements,
      recentTransactions,
    };
    res.json(response);
  } catch (error) {
    console.error('[Dashboard] Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

router.post('/refund', authenticateToken(['business']), async (req, res) => {
  const { transactionId, amount, reason } = req.body;
  if (!transactionId || !amount || amount <= 0 || !reason) {
    return res.status(400).json({ error: 'Transaction ID, valid amount, and reason required' });
  }
  const session = await mongoose.startSession();
  session.startTransaction();
  try {
    const transaction = await BusinessTransaction.findOne({ transactionId, status: 'completed' }).session(session);
    if (!transaction || transaction.businessId !== req.user.businessId) {
      throw new Error('Invalid or unauthorized transaction');
    }
    const business = await Business.findOne({ businessId: req.user.businessId }).session(session);
    if (!business || !business.isActive) {
      throw new Error('Business not found or inactive');
    }
    if (business.balance < amount) {
      throw new Error('Insufficient business balance');
    }
    const user = await User.findOne({ username: transaction.fromUsername }).session(session);
    if (!user || !user.isActive) {
      throw new Error('User not found or inactive');
    }
    const refundFee = amount * 0.01;
    const netRefund = amount - refundFee;
    business.balance -= amount;
    user.balance += netRefund;
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
      amount,
      toFrom: user.username,
      fee: refundFee,
      reason,
      date: new Date(),
    };
    business.transactions.push(refundTransaction);
    user.transactions.push({
      _id: crypto.randomBytes(16).toString('hex'),
      type: 'received',
      amount: netRefund,
      toFrom: business.businessId,
      fee: refundFee,
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
    transaction.refundedAmount = (transaction.refundedAmount || 0) + amount;
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
    console.error('[Refund] Error:', error.message);
    res.status(error.message.includes('not found') ? 404 : 400).json({ error: error.message });
  } finally {
    session.endSession();
  }
});

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
    business.pendingDeposits = business.pendingDeposits || [];
    const deposit = { amount, transactionId, date: new Date(), status: 'pending' };
    business.pendingDeposits.push(deposit);
    await business.save();
    if (business.email) {
      await sendEmail(business.email, 'Manual Deposit Submitted', emailTemplates.deposit(business, deposit));
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
    res.status(500).json({ error: 'Failed to submit business deposit' });
  }
});

router.post('/withdraw/request', authenticateToken(['business']), async (req, res) => {
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
    const withdrawal = { amount: withdrawalAmount, fee: withdrawalFee, date: new Date(), status: 'pending' };
    business.pendingWithdrawals.push(withdrawal);
    await business.save();
    if (business.email) {
      await sendEmail(business.email, 'Withdrawal Request Submitted', emailTemplates.withdrawal(business, withdrawal));
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
    res.status(500).json({ error: 'Failed to request business withdrawal' });
  }
});

router.post('/register-push-token', authenticateToken(['business']), async (req, res) => {
  const { pushToken } = req.body;
  if (!pushToken) return res.status(400).json({ error: 'Push token is required' });
  try {
    const business = await Business.findOne({ businessId: req.user.businessId });
    if (!business) return res.status(404).json({ error: 'Business not found' });
    business.pushToken = pushToken;
    await business.save();
    res.status(200).json({ message: 'Push token registered for business' });
  } catch (error) {
    console.error('[RegisterPushToken] Error:', error.message);
    res.status(500).json({ error: 'Failed to register push token' });
  }
});

module.exports = router;