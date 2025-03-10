const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const AWS = require('aws-sdk');
const fs = require('fs');
const User = require('../models/User');
const QRPin = require('../models/QRPin');
const authenticateToken = require('../middleware/authenticateToken');

// Configure multer for temporary local storage
const upload = multer({ dest: 'uploads/' });

// Configure AWS S3
const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION || 'us-east-1', // Default region
});
const S3_BUCKET = process.env.S3_BUCKET || 'zangena';

// Secret key for JWT (use environment variable in production)
const JWT_SECRET = process.env.JWT_SECRET || 'Zangena123$@2025';

// POST /api/register - Updated for KYC and S3
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

    // Upload ID image to S3
    const fileContent = fs.readFileSync(idImage.path);
    const s3Key = `id-images/${Date.now()}-${idImage.originalname}`;
    const params = {
      Bucket: S3_BUCKET,
      Key: s3Key,
      Body: fileContent,
      ContentType: idImage.mimetype,
      ACL: 'private', // Restrict access
    };
    const s3Response = await s3.upload(params).promise();
    const idImageUrl = s3Response.Location;

    // Delete local file
    fs.unlinkSync(idImage.path);

    // Placeholder for KYC verification (e.g., Smile ID/uqudo later)
    const idData = { name, idNumber: 'pending_verification', dob: 'pending_verification' };
    const isSanctioned = false; // Replace with real sanctions check later
    if (isSanctioned) {
      return res.status(403).json({ error: 'User is on sanctions list' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const username = email.split('@')[0]; // Derive username from email
    const user = new User({
      username,
      name,
      phoneNumber,
      email,
      password: hashedPassword,
      idImageUrl,
      role: 'user', // Default role
      balance: 0,
      transactions: [],
      kycStatus: 'pending', // Track KYC status
      isActive: false, // Default to inactive until KYC is verified
    });
    await user.save();

    const token = jwt.sign(
      { phoneNumber: user.phoneNumber, role: user.role }, // Use phoneNumber in token
      JWT_SECRET,
      { expiresIn: '24h' } // Extended to 24 hours
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
      { phoneNumber: user.phoneNumber, role: user.role }, // Use phoneNumber in token
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    res.json({ token, username: user.username, role: user.role });
  } catch (error) {
    console.error('Login Error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// GET /api/user/:username
router.get('/user/:username', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (req.user.phoneNumber !== user.phoneNumber && req.user.role !== 'admin') { // Use phoneNumber for auth check
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
    const user = await User.findOne({ phoneNumber: req.user.phoneNumber }); // Use phoneNumber for lookup
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.isActive) return res.status(403).json({ error: 'User is inactive' });
    if (username !== user.username) return res.status(403).json({ error: 'Unauthorized' });

    const qrId = require('crypto').randomBytes(16).toString('hex');
    const qrPin = new QRPin({ username, qrId, pin });
    await qrPin.save();

    user.transactions.push({ type: 'pending-pin', amount: 0, toFrom: 'Self', date: new Date() });
    await user.save();

    res.json({ qrId });
  } catch (error) {
    console.error('QR Pin Store Error:', error);
    res.status(500).json({ error: 'Server error storing QR pin' });
  }
});

// POST /api/payment-with-qr-pin
router.post('/payment-with-qr-pin', authenticateToken, async (req, res) => {
  const { fromUsername, toUsername, amount, qrId, pin } = req.body;

  if (!fromUsername || !toUsername || !amount || !qrId || !pin) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const sender = await User.findOne({ phoneNumber: req.user.phoneNumber }); // Use phoneNumber for sender
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

    if (sender.balance < paymentAmount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    sender.balance -= paymentAmount;
    receiver.balance += paymentAmount;
    sender.transactions.push({ type: 'sent', amount: paymentAmount, toFrom: toUsername, date: new Date() });
    receiver.transactions.push({ type: 'received', amount: paymentAmount, toFrom: fromUsername, date: new Date() });

    await QRPin.deleteOne({ qrId });
    await sender.save();
    await receiver.save();

    res.json({ message: 'Payment successful' });
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
    const sender = await User.findOne({ phoneNumber: req.user.phoneNumber }); // Use phoneNumber for sender
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

    if (sender.balance < paymentAmount) {
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    sender.balance -= paymentAmount;
    receiver.balance += paymentAmount;
    sender.transactions.push({ type: 'sent', amount: paymentAmount, toFrom: receiver.username, date: new Date() });
    receiver.transactions.push({ type: 'received', amount: paymentAmount, toFrom: fromUsername, date: new Date() });

    await QRPin.deleteOne({ _id: qrPin._id });
    await sender.save();
    await receiver.save();

    res.json({ message: 'Payment successful' });
  } catch (error) {
    console.error('Search Payment Error:', error);
    res.status(500).json({ error: 'Server error during payment' });
  }
});

// PUT /api/user/update
router.put('/user/update', authenticateToken, async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const user = await User.findOne({ phoneNumber: req.user.phoneNumber }); // Use phoneNumber for lookup
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
    const user = await User.findOne({ phoneNumber: req.user.phoneNumber }); // Use phoneNumber for lookup
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
    console.error('KYC Update Error:', {
      message: error.message,
      stack: error.stack,
      username,
      kycStatus,
    });
    res.status(500).json({ error: 'Server error updating KYC status', details: error.message });
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
    console.error('Toggle Active Error:', {
      message: error.message,
      stack: error.stack,
      username,
      isActive,
    });
    res.status(500).json({ error: 'Server error toggling user status', details: error.message });
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
    const users = await User.find(query, { password: 0, idImageUrl: 0 }) // Exclude sensitive fields
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
    const admin = await User.findOne({ phoneNumber: req.user.phoneNumber }); // Verify admin
    if (!admin || admin.username !== adminUsername) return res.status(403).json({ error: 'Unauthorized admin' });
    const user = await User.findOne({ username: toUsername });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (!user.isActive) return res.status(403).json({ error: 'User is inactive' });
    const paymentAmount = parseFloat(amount);
    if (isNaN(paymentAmount) || paymentAmount <= 0) {
      return res.status(400).json({ error: 'Amount must be a positive number' });
    }
    user.balance += paymentAmount;
    user.transactions.push({ type: 'credited', amount: paymentAmount, toFrom: adminUsername, date: new Date() });
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
    const sender = await User.findOne({ phoneNumber: req.user.phoneNumber }); // Use phoneNumber for sender
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
    sender.transactions.push({ type: 'sent', amount: paymentAmount, toFrom: toUsername, date: new Date() });
    receiver.transactions.push({ type: 'received', amount: paymentAmount, toFrom: fromUsername, date: new Date() });
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

module.exports = router;