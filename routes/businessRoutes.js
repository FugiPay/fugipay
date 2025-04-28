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
const Business = require('../models/Business');
const BusinessTransaction = require('../models/BusinessTransaction');
const BusinessAdminLedger = require('../models/BusinessAdminLedger');
const User = require('../models/User');
const QRCode = require('qrcode');
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

router.post('/register', authenticateToken(['user']), upload.single('qrCode'), async (req, res) => {
  const { businessId, name, pin, bankDetails } = req.body;
  const qrCodeImage = req.file;
  if (!businessId || !name || !pin || !qrCodeImage || !bankDetails?.bankName || !bankDetails?.accountNumber || !['bank', 'mobile_money'].includes(bankDetails?.accountType)) {
    return res.status(400).json({ error: 'Business ID, name, PIN, QR code, and valid bank details required' });
  }
  if (!/^\d{10}$/.test(businessId)) {
    return res.status(400).json({ error: 'Business ID must be a 10-digit TPIN' });
  }
  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'PIN must be a 4-digit number' });
  }
  try {
    const existingBusiness = await Business.findOne({ $or: [{ businessId }, { ownerUsername: req.user.username }] });
    if (existingBusiness) return res.status(400).json({ error: 'Business ID or owner username already registered' });
    const owner = await User.findOne({ username: req.user.username });
    if (!owner) return res.status(404).json({ error: 'Owner user not found' });
    const fileStream = fs.createReadStream(qrCodeImage.path);
    const s3Key = `qr-codes/${Date.now()}-${qrCodeImage.originalname}`;
    const params = { Bucket: S3_BUCKET, Key: s3Key, Body: fileStream, ContentType: qrCodeImage.mimetype, ACL: 'private' };
    const s3Response = await s3.upload(params).promise();
    const qrCodeUrl = s3Response.Location;
    fs.unlinkSync(qrCodeImage.path);
    const hashedPin = await bcrypt.hash(pin, 10);
    const business = new Business({
      businessId,
      name,
      ownerUsername: req.user.username,
      pin: hashedPin,
      balance: 0,
      qrCode: qrCodeUrl,
      bankDetails,
      role: 'business',
      approvalStatus: 'pending',
      transactions: [],
      isActive: false,
    });
    await business.save();
    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(admin.pushToken, 'New Business Registration', `Business ${name} (${businessId}) needs approval`, { businessId });
    }
    res.status(201).json({ message: 'Business registered, awaiting approval', businessId });
  } catch (error) {
    console.error('Business Register Error:', error.message);
    res.status(500).json({ error: 'Server error during business registration' });
  }
});

router.post('/signup', async (req, res) => {
  const { businessId, name, ownerUsername, pin, phoneNumber, email, bankDetails } = req.body;
  if (!businessId || !name || !ownerUsername || !pin || !phoneNumber) {
    return res.status(400).json({ error: 'Business ID, Name, Username, PIN, and Phone required' });
  }
  if (!/^\d{10}$/.test(businessId)) {
    return res.status(400).json({ error: 'Business ID must be 10 digits' });
  }
  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'PIN must be 4 digits' });
  }
  if (!/^[a-zA-Z0-9]+$/.test(ownerUsername)) {
    return res.status(400).json({ error: 'Username must be alphanumeric' });
  }
  if (!/^\+260(9[567]|7[567])\d{7}$/.test(phoneNumber)) {
    return res.status(400).json({ error: 'Invalid Zambian phone number' });
  }
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email address' });
  }
  if (bankDetails) {
    if (!['bank', 'mobile_money'].includes(bankDetails.accountType)) {
      return res.status(400).json({ error: 'Account type must be bank or mobile_money' });
    }
    if (bankDetails.accountNumber) {
      if (bankDetails.accountType === 'bank') {
        if (!/^\d{10,12}$/.test(bankDetails.accountNumber)) {
          return res.status(400).json({ error: 'Bank account must be 10-12 digits' });
        }
      } else {
        if (!/^\+260(9[567]|7[567])\d{7}$/.test(bankDetails.accountNumber)) {
          return res.status(400).json({ error: 'Invalid mobile money number' });
        }
      }
      if (!bankDetails.bankName?.trim()) {
        return res.status(400).json({ error: 'Bank or Mobile Name required' });
      }
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
      balance: 0,
      transactions: [],
      pendingDeposits: [],
      pendingWithdrawals: [],
      qrCode: JSON.stringify({ type: 'business_payment', businessId, businessName: name }),
      role: 'business',
      approvalStatus: 'pending',
      isActive: false,
    });
    await business.save();
    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(
        admin.pushToken,
        'New Business Signup',
        `Business ${businessId} (${name}) awaits approval`,
        { businessId }
      );
    }
    res.status(201).json({
      message: 'Business registered, awaiting approval',
      business: { businessId: business.businessId, name: business.name, approvalStatus: business.approvalStatus },
    });
  } catch (error) {
    console.error(`Business Signup Error [businessId: ${businessId}]:`, error.message, error.stack);
    res.status(500).json({ error: 'Internal server error. Contact support.' });
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
    res.status(200).json({ token, businessId, role: business.role, approvalStatus: business.approvalStatus });
  } catch (error) {
    console.error('Business Login Error:', error.message, error.stack);
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
    if (business.approvalStatus !== 'approved') {
      return res.status(403).json({ error: 'Business is not yet approved by admin' });
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
    console.error('Business Signin Error:', error);
    res.status(500).json({ error: 'Server error during signin' });
  }
});

router.post('/forgot-pin', async (req, res) => {
  const { phoneNumber, businessId } = req.body;
  if (!phoneNumber && !businessId) {
    return res.status(400).json({ error: 'Phone number or Business ID required' });
  }
  if (phoneNumber && !/^\+260(9[567]|7[567])\d{7}$/.test(phoneNumber)) {
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
    if (!business.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(business.email)) {
      return res.status(500).json({ error: 'Invalid email configuration' });
    }
    const resetToken = crypto.randomBytes(20).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000;
    business.resetToken = resetToken;
    business.resetTokenExpiry = resetTokenExpiry;
    await business.save();
    const mailOptions = {
      from: process.env.EMAIL_USER || 'no-reply@zangena.com',
      to: business.email,
      subject: 'Zangena PIN Reset',
      text: `Your PIN reset token is: ${resetToken}. It expires in 1 hour.\n\nEnter it in the Zangena Business app to reset your PIN.`,
      html: `<h2>Zangena PIN Reset</h2><p>Your PIN reset token is: <strong>${resetToken}</strong></p><p>It expires in 1 hour. Enter it in the Zangena Business app to reset your PIN.</p>`,
    };
    await transporter.sendMail(mailOptions);
    res.json({ message: 'Reset instructions have been sent to your email.' });
  } catch (error) {
    console.error('Forgot PIN Error:', error);
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
    res.json({ message: 'PIN reset successfully' });
  } catch (error) {
    console.error('Reset PIN Error:', error);
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
      businessId: business.businessId, name: business.name, ownerUsername: business.ownerUsername,
      balance: business.balance, qrCode: business.qrCode, approvalStatus: business.approvalStatus,
      transactions: business.transactions.slice(-10), isActive: business.isActive,
    };
    res.json(response);
  } catch (error) {
    console.error('Business Fetch Error:', error.message, error.stack);
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
    console.error('QR Generate Error:', error.message);
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
    business.transactions.push({
      _id: crypto.randomBytes(16).toString('hex'),
      type: 'received',
      amount: paymentAmount,
      toFrom: user.username,
      date: new Date(),
    });
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
    console.error('QR Pay Error:', error.message);
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
    console.error('Dashboard Error:', error.message);
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
    business.transactions.push({
      _id: crypto.randomBytes(16).toString('hex'),
      type: 'refunded',
      amount,
      toFrom: user.username,
      fee: refundFee,
      reason,
      date: new Date(),
    });
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
    if (user.pushToken) {
      await sendPushNotification(user.pushToken, 'Refund Received', `Received ${netRefund.toFixed(2)} ZMW refund from ${business.name}`, { refundId });
    }
    res.json({ refundId, message: 'Refund processed', refundAmount: netRefund, refundFee });
  } catch (error) {
    await session.abortTransaction();
    console.error('Refund Error:', error.message);
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

router.post('/save-push-token', authenticateToken(['business']), async (req, res) => {
  const { pushToken } = req.body;
  if (!pushToken) return res.status(400).json({ error: 'Push token is required' });
  try {
    const business = await Business.findOne({ businessId: req.user.businessId });
    if (!business) return res.status(404).json({ error: 'Business not found' });
    business.pushToken = pushToken;
    await business.save();
    res.status(200).json({ message: 'Push token saved for business' });
  } catch (error) {
    console.error('Save Push Token Error:', error.message);
    res.status(500).json({ error: 'Failed to save push token' });
  }
});

module.exports = router;