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
let axios; // Define axios conditionally
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

// Charge Sheet Functions
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

// POST /api/register
router.post('/register', upload.single('idImage'), async (req, res) => {
  const { name, phoneNumber, email, password } = req.body;
  const idImage = req.file;

  if (!name || !phoneNumber || !email || !password || !idImage) {
    return res.status(400).json({ error: 'Name, phone number, email, password, and ID image are required' });
  }

  if (!phoneNumber.match(/^\+260(9[5678]|7[34679])\d{7}$/)) {
    return res.status(400).json({ error: 'Invalid Zambian phone number (e.g., +260 971 234 567)' });
  }

  try {
    const existingUser = await User.findOne({ $or: [{ email }, { phoneNumber }] });
    if (existingUser) {
      return res.status(400).json({ error: 'Email or phone number already exists' });
    }

    const fileContent = fs.readFileSync(idImage.path);
    const s3Key = `id-images/${Date.now()}-${idImage.originalname}`;
    const params = {
      Bucket: S3_BUCKET,
      Key: s3Key,
      Body: fileContent,
      ContentType: idImage.mimetype,
      ACL: 'private',
    };
    const s3Response = await s3.upload(params).promise();
    const idImageUrl = s3Response.Location;

    fs.unlinkSync(idImage.path);

    const idData = { name, idNumber: 'pending_verification', dob: 'pending_verification' };
    const isSanctioned = false; // Placeholder for sanctions check
    if (isSanctioned) {
      return res.status(403).json({ error: 'User is on sanctions list' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const username = email.split('@')[0];
    const user = new User({
      username,
      name,
      phoneNumber,
      email,
      password: hashedPassword,
      idImageUrl,
      role: 'user',
      balance: 0,
      transactions: [],
      kycStatus: 'pending',
      isActive: false,
    });
    await user.save();

    const token = jwt.sign(
      { phoneNumber: user.phoneNumber, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      token,
      username: user.username,
      role: user.role,
    });
  } catch (error) {
    console.error('Register Error:', error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// POST /api/login
router.post('/login', async (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier || !password) {
    return res.status(400).json({ error: 'Username or phone number and password are required' });
  }
  if (!JWT_SECRET) {
    console.error('JWT_SECRET is not defined');
    return res.status(500).json({ error: 'Server configuration error' });
  }
  try {
    const user = await User.findOne({ $or: [{ username: identifier }, { phoneNumber: identifier }] });
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
      { phoneNumber: user.phoneNumber, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.json({ token, username: user.username, role: user.role });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// POST /api/forgot-password
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
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour expiry

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

// POST /api/reset-password
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

// GET /api/user/:username
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
      transactions: user.transactions,
      kycStatus: user.kycStatus,
      isActive: user.isActive,
    });
  } catch (error) {
    console.error('User Fetch Error:', error);
    res.status(500).json({ error: 'Server error fetching user' });
  }
});

// POST /api/store-qr-pin
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

// POST /api/deposit
router.post('/deposit', authenticateToken, async (req, res) => {
  const { amount } = req.body; // No paymentMethod needed
  const user = await User.findOne({ phoneNumber: req.user.phoneNumber });

  if (!user || !user.isActive) return res.status(403).json({ error: 'User not found or inactive' });
  if (!amount || amount <= 0) return res.status(400).json({ error: 'Invalid amount' });

  // Normalize and detect payment method
  let phoneNumber = req.user.phoneNumber;
  if (!phoneNumber.startsWith('+260')) {
    if (phoneNumber.startsWith('0')) phoneNumber = '+26' + phoneNumber;
    else if (phoneNumber.startsWith('260')) phoneNumber = '+' + phoneNumber;
  }
  const mtnPrefixes = ['96', '76'];
  const airtelPrefixes = ['97', '77'];
  const prefix = phoneNumber.slice(4, 6);
  let paymentMethod;
  if (mtnPrefixes.includes(prefix)) {
    paymentMethod = 'mobile-money-mtn';
  } else if (airtelPrefixes.includes(prefix)) {
    paymentMethod = 'mobile-money-airtel';
  } else {
    return res.status(400).json({ error: 'Phone number not supported for deposits' });
  }

  const gatewayFeePercentage = 0.015; // 1.5%
  const gatewayFlatFee = 0.5; // 0.5 ZMW
  const depositFee = amount * gatewayFeePercentage + gatewayFlatFee;
  const totalCharge = amount + depositFee;

  const paymentData = {
    tx_ref: `zangena-deposit-${Date.now()}`,
    amount: totalCharge,
    currency: 'ZMW',
    email: user.email || 'user@example.com', // Fallback if email isn’t set
    phone_number: phoneNumber,
    redirect_url: 'https://zangena.onrender.com/deposit-success',
    payment_options: 'mobilemoneyzambia',
  };

  try {
    const response = await flw.Charge.mobilemoney(paymentData);
    console.log('Flutterwave Deposit Response:', response);
    if (response.status !== 'success') throw new Error('Payment failed');

    let creditedAmount = amount;
    const isFirstDeposit = user.transactions.every((tx) => tx.type !== 'deposited');
    if (isFirstDeposit) {
      const bonus = Math.min(amount * 0.05, 10); // 5% bonus, max 10 ZMW
      creditedAmount += bonus;
    }

    user.balance += creditedAmount;
    user.transactions = user.transactions || [];
    user.transactions.push({
      type: 'deposited',
      amount: creditedAmount,
      toFrom: paymentMethod,
      fee: depositFee,
      date: new Date(),
    });

    await user.save();
    res.json({
      message: `Deposited ${creditedAmount.toFixed(2)} ZMW${isFirstDeposit ? ' (incl. bonus)' : ''}`,
      balance: user.balance,
    });
  } catch (error) {
    console.error('Deposit Error:', error);
    res.status(500).json({ error: error.message || 'Deposit failed' });
  }
});

// POST /api/withdraw
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
      account_bank: 'mobilemoneyzambia', // Verify this later
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

// Temporary endpoint to fetch outbound IP
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


// POST /api/payment-with-qr-pin
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

// POST /api/payment-with-search
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

// PUT /api/user/update
router.put('/user/update', authenticateToken, async (req, res) => {
  const { username, email, password } = req.body;

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
    await user.save();
    res.json({ message: 'User updated' });
  } catch (error) {
    console.error('User Update Error:', error);
    res.status(500).json({ error: 'Server error updating user' });
  }
});

// DELETE /api/user/delete
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

// PUT /api/user/update-kyc (Admin only)
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

// PUT /api/user/toggle-active (Admin only)
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

// GET /api/users (Admin only)
router.get('/users', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized: Admins only' });
    }
    const { page = 1, limit = 10, search = '' } = req.query;
    const pageNum = parseInt(page, 10);
    const limitNum = parseInt(limit, 10);
    const skip = (pageNum - 1) * limitNum;

    const query = search
      ? {
          $or: [
            { username: { $regex: search, $options: 'i' } },
            { phoneNumber: { $regex: search, $options: 'i' } },
          ],
        }
      : {};

    const total = await User.countDocuments(query);
    const users = await User.find(query, { password: 0, idImageUrl: 0 })
      .skip(skip)
      .limit(limitNum);

    res.json({
      users,
      total,
      page: pageNum,
      limit: limitNum,
      totalPages: Math.ceil(total / limitNum),
    });
  } catch (error) {
    console.error('Fetch All Users Error:', error);
    res.status(500).json({ error: 'Server error fetching users' });
  }
});

// POST /api/credit (Admin only)
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

// POST /api/payment-with-pin (Admin only)
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

// GET /api/transactions/:username (Admin only)
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

// Admin stats route
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

module.exports = router;