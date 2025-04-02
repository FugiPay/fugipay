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
const User = require('../models/User');
const QRPin = require('../models/QRPin');
const authenticateToken = require('../middleware/authenticateToken');
let axios;
try {
  axios = require('axios');
} catch (e) {
  console.error('Axios not installed. Please run `npm install axios`');
}

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
  return 0; // Explicitly 0 for > 10,000, validation catches this
};

const getReceivingFee = (amount) => {
  if (amount <= 50) return 0.50;
  if (amount <= 100) return 1.00;
  if (amount <= 500) return 1.50;
  if (amount <= 1000) return 2.00;
  if (amount <= 5000) return 3.00;
  if (amount <= 10000) return 5.00;
  return 0; // Explicitly 0 for > 10,000, validation catches this
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
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
    });
    console.log(`Push notification sent to ${pushToken}: ${title} - ${body}`);
  } catch (error) {
    console.error('Error sending push notification:', error.message);
  }
}

// POST /api/register (Updated for ZambiaCoin: Added pin)
router.post('/register', upload.single('idImage'), async (req, res) => {
  const { name, phoneNumber, email, password, pin } = req.body;
  const idImage = req.file;

  console.time('Register Total');
  if (!name || !phoneNumber || !email || !password || !idImage || !pin) {
    return res.status(400).json({ error: 'All fields, ID image, and PIN are required' });
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
    const existingUser = await User.findOne({ $or: [{ email }, { phoneNumber }] });
    console.timeEnd('Check Existing User');
    if (existingUser) {
      return res.status(400).json({ error: 'Email or phone number already exists' });
    }

    console.time('S3 Upload');
    const fileStream = fs.createReadStream(idImage.path);
    const s3Key = `id-images/${Date.now()}-${idImage.originalname}`;
    const params = {
      Bucket: S3_BUCKET,
      Key: s3Key,
      Body: fileStream,
      ContentType: idImage.mimetype,
      ACL: 'private',
    };
    const s3Response = await s3.upload(params).promise();
    const idImageUrl = s3Response.Location;
    fs.unlinkSync(idImage.path);
    console.timeEnd('S3 Upload');

    console.time('User Creation');
    const hashedPassword = await bcrypt.hash(password, 10);
    const username = email.split('@')[0];
    const user = new User({
      username,
      name,
      phoneNumber,
      email,
      password: hashedPassword,
      pin, // Added for ZambiaCoin (plain text for transfer verification)
      idImageUrl,
      role: 'user',
      balance: 0, // Zangena ZMW
      zambiaCoinBalance: 0, // ZambiaCoin ZMC
      trustScore: 0, // ZambiaCoin
      transactions: [],
      kycStatus: 'pending',
      isActive: false,
    });
    await user.save();
    console.timeEnd('User Creation');

    const token = jwt.sign({ phoneNumber: user.phoneNumber, role: user.role }, JWT_SECRET, { expiresIn: '24h' });

    console.time('Push Notification');
    if (axios) {
      const admin = await User.findOne({ role: 'admin' });
      if (admin && admin.pushToken) {
        await sendPushNotification(
          admin.pushToken,
          'New User Registration',
          `User ${username} needs KYC approval.`,
          { userId: user._id }
        );
      }
    }
    console.timeEnd('Push Notification');

    console.timeEnd('Register Total');
    res.status(201).json({
      token,
      username: user.username,
      role: user.role,
      kycStatus: user.kycStatus,
    });
  } catch (error) {
    console.error('Register Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error during registration', details: error.message });
  }
});

// POST /api/save-push-token (Unchanged)
router.post('/save-push-token', authenticateToken, async (req, res) => {
  const { pushToken } = req.body;

  if (!pushToken) {
    return res.status(400).json({ error: 'Push token is required' });
  }

  try {
    const user = await User.findOne({ phoneNumber: req.user.phoneNumber });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.pushToken = pushToken;
    await user.save();
    res.status(200).json({ message: 'Push token saved' });
  } catch (error) {
    console.error('Save Push Token Error:', error);
    res.status(500).json({ error: 'Failed to save push token' });
  }
});

// POST /api/login (Unchanged, ZambiaCoin uses same auth)
router.post('/login', async (req, res) => {
  const { identifier, password } = req.body;

  if (!identifier || !password) {
    return res.status(400).json({ error: 'Username or phone number and password are required' });
  }

  if (!process.env.JWT_SECRET) {
    console.error('JWT_SECRET is not defined');
    return res.status(500).json({ error: 'Server configuration error' });
  }

  try {
    const user = await User.findOne({
      $or: [{ username: identifier }, { phoneNumber: identifier }],
    });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    let isMatch;
    if (user.password.startsWith('$2')) {
      isMatch = await bcrypt.compare(password, user.password);
    } else {
      isMatch = password === user.password; // Plaintext fallback
    }
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { phoneNumber: user.phoneNumber, role: user.role, username: user.username }, // Added username for ZambiaCoin
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const isFirstLogin = !user.lastLogin;
    user.lastLogin = new Date();
    await user.save();

    res.status(200).json({
      token,
      username: user.username,
      role: user.role,
      kycStatus: user.kycStatus,
      isFirstLogin,
    });
  } catch (error) {
    console.error('Login Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error during login', details: error.message });
  }
});

// POST /api/forgot-password (Unchanged)
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
      html: `
        <h2>Zangena Password Reset</h2>
        <p>Your password reset token is: <strong>${resetToken}</strong></p>
        <p>It expires in 1 hour. Enter it in the Zangena app to reset your password.</p>
      `,
    };

    try {
      await transporter.sendMail(mailOptions);
    } catch (emailError) {
      console.error('Email Error:', {
        message: emailError.message,
        code: emailError.code,
        response: emailError.response,
      });
      return res.status(500).json({
        error: 'Failed to send email',
        emailError: { message: emailError.message, code: emailError.code },
      });
    }

    res.json({ message: 'Reset instructions have been sent to your email.' });
  } catch (error) {
    console.error('Forgot Password Error:', error);
    res.status(500).json({ error: 'Server error during password reset request' });
  }
});

// POST /api/reset-password (Unchanged)
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
    console.error('Reset Password Error:', error);
    res.status(500).json({ error: 'Server error during password reset' });
  }
});

// GET /api/user/:username (Updated for ZambiaCoin)
router.get('/user/:username', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (req.user.phoneNumber !== user.phoneNumber && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    res.json({
      username: user.username,
      name: user.name,
      phoneNumber: user.phoneNumber,
      email: user.email,
      balance: user.balance,
      zambiaCoinBalance: user.zambiaCoinBalance, // Added for ZambiaCoin
      trustScore: user.trustScore, // Added for ZambiaCoin
      transactions: user.transactions,
      kycStatus: user.kycStatus,
      isActive: user.isActive,
    });
  } catch (error) {
    console.error('User Fetch Error:', error);
    res.status(500).json({ error: 'Server error fetching user' });
  }
});

// POST /api/store-qr-pin (Unchanged)
router.post('/store-qr-pin', authenticateToken, async (req, res) => {
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

// POST /api/deposit/manual (Unchanged)
router.post('/deposit/manual', authenticateToken, async (req, res) => {
  const { amount, transactionId } = req.body;
  console.log('Manual Deposit Request:', { amount, transactionId });

  try {
    const user = await User.findOne({ phoneNumber: req.user.phoneNumber });
    if (!user || !user.isActive) {
      return res.status(403).json({ error: 'User not found or inactive' });
    }
    if (!amount || amount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    if (!transactionId) {
      return res.status(400).json({ error: 'Transaction ID required' });
    }
    user.pendingDeposits = user.pendingDeposits || [];
    user.pendingDeposits.push({
      amount,
      transactionId,
      date: new Date(),
      status: 'pending',
    });
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
    console.error('Manual Deposit Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to submit deposit' });
  }
});

// POST /api/admin/verify-withdrawal (Unchanged)
router.post('/admin/verify-withdrawal', authenticateToken, async (req, res) => {
  const { userId, withdrawalIndex, approved } = req.body;
  console.log('Verify Withdrawal Request:', { userId, withdrawalIndex, approved });
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
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
      user.transactions = user.transactions || [];
      user.transactions.push({
        type: 'withdrawn',
        amount: withdrawal.amount,
        toFrom: 'manual-mobile-money',
        fee: withdrawFee,
        date: new Date(),
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

// POST /api/admin/verify-deposit (Unchanged)
router.post('/admin/verify-deposit', authenticateToken, async (req, res) => {
  const { userId, transactionId, approved } = req.body;
  console.log('Verify Deposit Request:', { userId, transactionId, approved });
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const deposit = user.pendingDeposits.find((d) => d.transactionId === transactionId);
    if (!deposit || deposit.status !== 'pending') {
      return res.status(400).json({ error: 'Invalid or already processed deposit' });
    }
    if (approved) {
      const amount = deposit.amount;
      let creditedAmount = amount;
      const isFirstDeposit = !user.transactions || user.transactions.every((tx) => tx.type !== 'deposited');
      if (isFirstDeposit) {
        const bonus = Math.min(amount * 0.05, 10);
        creditedAmount += bonus;
      }
      user.balance += creditedAmount;
      user.transactions = user.transactions || [];
      user.transactions.push({
        type: 'deposited',
        amount: creditedAmount,
        toFrom: 'manual-mobile-money',
        fee: 0,
        date: new Date(),
      });
      deposit.status = 'approved';
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

// GET /api/test-flutterwave (Unchanged)
router.get('/test-flutterwave', async (req, res) => {
  try {
    const testData = { tx_ref: 'test', amount: 10, currency: 'ZMW', email: 'test@example.com', phone_number: '+260972721581', network: 'AIRTEL' };
    const result = await flw.MobileMoney.zambia(testData);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// POST /api/withdraw/request (Unchanged)
router.post('/withdraw/request', authenticateToken, async (req, res) => {
  const { amount } = req.body;
  console.log('Withdraw Request:', { amount });

  try {
    const user = await User.findOne({ phoneNumber: req.user.phoneNumber });
    if (!user || !user.isActive) {
      return res.status(403).json({ error: 'User not found or inactive' });
    }
    if (!amount || amount <= 0 || amount > user.balance) {
      return res.status(400).json({ error: 'Invalid amount or insufficient balance' });
    }
    user.pendingWithdrawals = user.pendingWithdrawals || [];
    user.pendingWithdrawals.push({
      amount,
      date: new Date(),
      status: 'pending',
    });
    await user.save();

    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(
        admin.pushToken,
        'New Withdrawal Request',
        `Withdrawal of ${amount} ZMW from ${user.username} needs approval.`,
        { userId: user._id, withdrawalIndex: user.pendingWithdrawals.length - 1 }
      );
    }

    res.json({ message: 'Withdrawal requested. Awaiting approval.' });
  } catch (error) {
    console.error('Withdraw Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to request withdrawal' });
  }
});

// POST /api/withdraw (Unchanged)
router.post('/withdraw', authenticateToken, async (req, res) => {
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

// GET /api/ip (Unchanged)
router.get('/ip', async (req, res) => {
  try {
    const response = await axios.get('https://api.ipify.org?format=json');
    console.log('Outbound IP:', response.data.ip);
    res.json({ ip: response.data.ip });
  } catch (error) {
    console.error('IP Fetch Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch IP' });
  }
});

// POST /api/payment-with-qr-pin (Unchanged)
router.post('/payment-with-qr-pin', authenticateToken, async (req, res) => {
  const { fromUsername, toUsername, amount, qrId, pin } = req.body;

  if (!fromUsername || !toUsername || !amount || !qrId || !pin) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const sender = await User.findOne({ phoneNumber: req.user.phoneNumber });
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
    if (isNaN(paymentAmount) || paymentAmount <= 0) {
      return res.status(400).json({ error: 'Amount must be a positive number' });
    }
    if (paymentAmount > 10000) {
      return res.status(400).json({ error: 'You cannot send more than 10,000 ZMW in a single transaction' });
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

    sender.transactions.push({
      type: 'sent',
      amount: paymentAmount,
      toFrom: toUsername,
      fee: sendingFee,
    });
    receiver.transactions.push({
      type: 'received',
      amount: paymentAmount,
      toFrom: fromUsername,
      fee: receivingFee,
    });
    admin.transactions.push({
      type: 'fee-collected',
      amount: sendingFee + receivingFee,
      toFrom: `${fromUsername} -> ${toUsername}`,
      originalAmount: paymentAmount,
      sendingFee,
      receivingFee,
    });

    await QRPin.deleteOne({ qrId });
    await Promise.all([sender.save(), receiver.save(), admin.save()]);

    res.json({
      message: 'Payment successful',
      sendingFee,
      receivingFee,
      amountReceived: paymentAmount - receivingFee,
    });
  } catch (error) {
    console.error('QR Payment Error:', error);
    res.status(500).json({ error: 'Server error during payment' });
  }
});

// POST /api/payment-with-search (Unchanged)
router.post('/payment-with-search', authenticateToken, async (req, res) => {
  const { fromUsername, searchQuery, amount, pin } = req.body;

  if (!fromUsername || !searchQuery || !amount || !pin) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const sender = await User.findOne({ phoneNumber: req.user.phoneNumber });
    if (!sender || !sender.isActive) return res.status(403).json({ error: 'Sender not found or inactive' });
    if (sender.username !== fromUsername) return res.status(403).json({ error: 'Unauthorized sender' });
    if (sender.role === 'admin') return res.status(403).json({ error: 'Admins cannot send payments' });

    const receiver = await User.findOne({ $or: [{ username: searchQuery }, { phoneNumber: searchQuery }] });
    if (!receiver || !receiver.isActive) return res.status(403).json({ error: 'Recipient not found or inactive' });

    const qrPin = await QRPin.findOne({ username: receiver.username, pin });
    if (!qrPin) return res.status(400).json({ error: 'Invalid PIN or no active QR code' });

    const paymentAmount = parseFloat(amount);
    if (isNaN(paymentAmount) || paymentAmount <= 0) {
      return res.status(400).json({ error: 'Amount must be a positive number' });
    }
    if (paymentAmount > 10000) {
      return res.status(400).json({ error: 'You cannot send more than 10,000 ZMW in a single transaction' });
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

    sender.transactions.push({
      type: 'sent',
      amount: paymentAmount,
      toFrom: receiver.username,
      fee: sendingFee,
    });
    receiver.transactions.push({
      type: 'received',
      amount: paymentAmount,
      toFrom: fromUsername,
      fee: receivingFee,
    });
    admin.transactions.push({
      type: 'fee-collected',
      amount: sendingFee + receivingFee,
      toFrom: `${fromUsername} -> ${receiver.username}`,
      originalAmount: paymentAmount,
      sendingFee,
      receivingFee,
    });

    await QRPin.deleteOne({ _id: qrPin._id });
    await Promise.all([sender.save(), receiver.save(), admin.save()]);

    res.json({
      message: 'Payment successful',
      sendingFee,
      receivingFee,
      amountReceived: paymentAmount - receivingFee,
    });
  } catch (error) {
    console.error('Search Payment Error:', error);
    res.status(500).json({ error: 'Server error during payment' });
  }
});

// PUT /api/user/update (Updated for ZambiaCoin: Added PIN update option)
router.put('/user/update', authenticateToken, async (req, res) => {
  const { username, email, password, pin } = req.body;

  try {
    const user = await User.findOne({ phoneNumber: req.user.phoneNumber });
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
      user.pin = pin; // Update PIN for ZambiaCoin
    }
    await user.save();
    res.json({ message: 'User updated' });
  } catch (error) {
    console.error('User Update Error:', error);
    res.status(500).json({ error: 'Server error updating user' });
  }
});

// DELETE /api/user/delete (Unchanged)
router.delete('/user/delete', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ phoneNumber: req.user.phoneNumber });
    if (!user) return res.status(404).json({ error: 'User not found' });

    await QRPin.deleteMany({ username: user.username });
    await User.deleteOne({ phoneNumber: req.user.phoneNumber });
    res.json({ message: 'Account deleted successfully' });
  } catch (error) {
    console.error('Delete Account Error:', error);
    res.status(500).json({ error: 'Server error deleting account' });
  }
});

// PUT /api/user/update-kyc (Unchanged)
router.put('/user/update-kyc', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized: Admins only' });
  }
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
    console.error('KYC Update Error:', error);
    res.status(500).json({ error: 'Server error updating KYC status' });
  }
});

// PUT /api/user/toggle-active (Unchanged)
router.put('/user/toggle-active', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized: Admins only' });
  }
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
    console.error('Toggle Active Error:', error);
    res.status(500).json({ error: 'Server error toggling user status' });
  }
});

// GET /api/users (Unchanged)
router.get('/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
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
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// POST /api/credit (Unchanged)
router.post('/credit', authenticateToken, async (req, res) => {
  const { adminUsername, toUsername, amount } = req.body;
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized: Admins only' });
  }
  try {
    const admin = await User.findOne({ phoneNumber: req.user.phoneNumber });
    if (!admin || admin.username !== adminUsername) return res.status(403).json({ error: 'Unauthorized admin' });
    const user = await User.findOne({ username: toUsername });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.isActive) return res.status(403).json({ error: 'User is inactive' });
    const paymentAmount = parseFloat(amount);
    if (isNaN(paymentAmount) || paymentAmount <= 0) {
      return res.status(400).json({ error: 'Amount must be a positive number' });
    }
    user.balance += paymentAmount;
    user.transactions.push({ type: 'credited', amount: paymentAmount, toFrom: adminUsername });
    await user.save();
    res.json({ message: 'Credit successful' });
  } catch (error) {
    console.error('Credit Error:', error);
    res.status(500).json({ error: 'Server error during credit' });
  }
});

// POST /api/payment-with-pin (Unchanged)
router.post('/payment-with-pin', authenticateToken, async (req, res) => {
  const { fromUsername, toUsername, amount, pin } = req.body;
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized: Admins only' });
  }
  try {
    const sender = await User.findOne({ phoneNumber: req.user.phoneNumber });
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
    sender.transactions.push({ type: 'sent', amount: paymentAmount, toFrom: toUsername });
    receiver.transactions.push({ type: 'received', amount: paymentAmount, toFrom: fromUsername });
    await QRPin.deleteOne({ _id: qrPin._id });
    await sender.save();
    await receiver.save();
    res.json({ message: 'Payment successful' });
  } catch (error) {
    console.error('Payment with PIN Error:', error);
    res.status(500).json({ error: 'Server error during payment' });
  }
});

// GET /api/transactions/:username (Unchanged)
router.get('/transactions/:username', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Unauthorized: Admins only' });
  }
  try {
    const user = await User.findOne({ username: req.params.username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user.transactions);
  } catch (error) {
    console.error('Transactions Fetch Error:', error);
    res.status(500).json({ error: 'Server error fetching transactions' });
  }
});

// GET /api/admin/stats (Unchanged)
router.get('/admin/stats', async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalBalance = await User.aggregate([
      { $group: { _id: null, total: { $sum: '$balance' } } },
    ]).then(result => result[0]?.total || 0);
    const recentTxCount = await User.aggregate([
      { $unwind: '$transactions' },
      { $match: { 'transactions.date': { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } } },
      { $count: 'recentTxCount' },
    ]).then(result => result[0]?.recentTxCount || 0);

    res.json({ totalUsers, totalBalance, recentTxCount });
  } catch (error) {
    console.error('Stats Error:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// GET /api/admin/pending (Unchanged)
router.get('/admin/pending', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const pendingUsers = await User.countDocuments({ kycStatus: 'pending' });
    const pendingDeposits = await User.aggregate([
      { $unwind: '$pendingDeposits' },
      { $match: { 'pendingDeposits.status': 'pending' } },
      { $count: 'count' },
    ]).then(r => r[0]?.count || 0);
    const pendingWithdrawals = await User.aggregate([
      { $unwind: '$pendingWithdrawals' },
      { $match: { 'pendingWithdrawals.status': 'pending' } },
      { $count: 'count' },
    ]).then(r => r[0]?.count || 0);
    res.json({ users: pendingUsers, deposits: pendingDeposits, withdrawals: pendingWithdrawals });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch pending stats' });
  }
});

// GET /api/admin/pending-deposits (Unchanged)
router.get('/api/admin/pending-deposits', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const users = await User.find({ 'pendingDeposits.status': 'pending' });
    const deposits = users.flatMap(user => user.pendingDeposits
      .filter(d => d.status === 'pending')
      .map(d => ({ userId: user._id, user: { username: user.username }, ...d.toObject() })));
    res.json(deposits);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch pending deposits' });
  }
});

// GET /api/admin/pending-withdrawals (Unchanged)
router.get('/api/admin/pending-withdrawals', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  try {
    const users = await User.find({ 'pendingWithdrawals.status': 'pending' });
    const withdrawals = users.flatMap((user, uIndex) => user.pendingWithdrawals
      .map((w, wIndex) => ({ userId: user._id, user: { username: user.username }, ...w.toObject(), index: wIndex }))
      .filter(w => w.status === 'pending'));
    res.json(withdrawals);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch pending withdrawals' });
  }
});

// --------------------------- ZambiaCoin Endpoints ---------------------------

// GET /api/user (ZambiaCoin-specific: Extended for profile/dashboard)
router.get('/user', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username }).select(
      'username name phoneNumber email kycStatus zambiaCoinBalance trustScore transactions'
    );
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      username: user.username,
      name: user.name,
      phoneNumber: user.phoneNumber,
      email: user.email,
      kycStatus: user.kycStatus,
      zambiaCoinBalance: user.zambiaCoinBalance,
      trustScore: user.trustScore,
      transactions: user.transactions,
    });
  } catch (error) {
    console.error('ZambiaCoin User Fetch Error:', error);
    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

// POST /api/transfer (ZambiaCoin: ZMC transfer)
// POST /api/transfer
router.post('/transfer', authenticateToken, async (req, res) => {
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
    senderUser.transactions.push({ type: 'zmc-sent', amount: paymentAmount, toFrom: receiver, date: new Date(), _id: txId });
    receiverUser.transactions.push({ type: 'zmc-received', amount: paymentAmount, toFrom: sender, date: new Date() });

    await Promise.all([senderUser.save(), receiverUser.save()]);
    res.json({ message: 'ZMC transfer successful', transactionId: txId });
  } catch (error) {
    console.error('ZMC Transfer Error:', error);
    res.status(500).json({ error: 'Transfer failed' });
  }
});

// POST /api/generate-qr (new endpoint)
router.post('/generate-qr', authenticateToken, async (req, res) => {
  const { pin } = req.body;
  if (!pin || pin.length !== 4 || !/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'A valid 4-digit PIN is required' });
  }

  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.isActive) return res.status(403).json({ error: 'Account is inactive' });
    if (user.pin !== pin) return res.status(400).json({ error: 'Invalid PIN' });

    // PIN is valid; frontend will generate the QR payload
    res.json({ message: 'PIN validated successfully' });
  } catch (error) {
    console.error('QR Generation Error:', error);
    res.status(500).json({ error: 'Failed to validate PIN' });
  }
});

// POST /api/rate (ZambiaCoin: Rate a transaction)
router.post('/rate', authenticateToken, async (req, res) => {
  const { transactionId, rating, raterUsername } = req.body;

  if (!transactionId || !rating || !raterUsername) {
    return res.status(400).json({ error: 'Transaction ID, rating, and rater username are required' });
  }
  if (!Number.isInteger(rating) || rating < 1 || rating > 5) {
    return res.status(400).json({ error: 'Rating must be an integer between 1 and 5' });
  }

  try {
    // Ensure the rater is authenticated
    if (raterUsername !== req.user.username) {
      return res.status(403).json({ error: 'Unauthorized rater' });
    }

    // Find the sender (rater) and verify the transaction
    const senderUser = await User.findOne({ username: raterUsername });
    if (!senderUser) return res.status(404).json({ error: 'Rater not found' });

    const transaction = senderUser.transactions.find(tx => tx._id === transactionId && tx.type === 'zmc-sent');
    if (!transaction) {
      return res.status(404).json({ error: 'Transaction not found or not sent by this user' });
    }

    // Find the receiver to update their trust score
    const receiverUser = await User.findOne({ username: transaction.toFrom });
    if (!receiverUser) return res.status(404).json({ error: 'Receiver not found' });

    // Update the transaction with the rating (optional)
    transaction.trustRating = rating;

    // Calculate new trust score on a 0-100 scale
    const newRatingCount = (receiverUser.ratingCount || 0) + 1;
    const currentAverage = receiverUser.trustScore ? (receiverUser.trustScore / 100) * 5 : 0; // Convert back to 1-5 scale
    const newAverage = ((currentAverage * (newRatingCount - 1)) + rating) / newRatingCount;
    const newTrustScore = (newAverage / 5) * 100; // Scale to 0-100

    receiverUser.trustScore = newTrustScore;
    receiverUser.ratingCount = newRatingCount;

    // Save both users
    await Promise.all([senderUser.save(), receiverUser.save()]);

    res.json({ message: 'Rating submitted successfully', trustScore: newTrustScore });
  } catch (error) {
    console.error('Rating Error:', error);
    res.status(500).json({ error: 'Failed to submit rating' });
  }
});

// POST /api/airdrop (ZambiaCoin: Admin-only airdrop)
router.post('/airdrop', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { amount } = req.body;
  if (!amount || amount <= 0) {
    return res.status(400).json({ error: 'Valid amount required' });
  }

  try {
    const users = await User.find({ kycStatus: 'verified' });
    await Promise.all(
      users.map(user => {
        user.zambiaCoinBalance += amount;
        user.transactions.push({ type: 'zmc-received', amount, toFrom: 'admin-airdrop', date: new Date() });
        return user.save();
      })
    );
    res.json({ message: `Airdropped ${amount} ZMC to all verified users` });
  } catch (error) {
    console.error('ZMC Airdrop Error:', error);
    res.status(500).json({ error: 'Airdrop failed' });
  }
});

router.post('/credit-zmc', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const { toUsername, amount } = req.body;
  const user = await User.findOne({ username: toUsername });
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!user.isActive) return res.status(403).json({ error: 'User is inactive' });
  const creditAmount = parseFloat(amount);
  if (isNaN(creditAmount) || creditAmount <= 0) return res.status(400).json({ error: 'Invalid amount' });
  user.zambiaCoinBalance += creditAmount;
  user.transactions.push({ type: 'zmc-received', amount: creditAmount, toFrom: 'admin', date: new Date() });
  await user.save();
  res.json({ message: 'ZMC credited successfully' });
});

module.exports = router;