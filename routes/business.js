const express = require('express');
const router = express.Router();
const Business = require('../models/Business');
const User = require('../models/User');
const { authenticateToken } = require('../middleware/auth');
const { sendPushNotification } = require('../utils/notifications');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET || 'Zangena123$@2025';

// Business Signup
router.post('/signup', async (req, res) => {
  const { businessId, name, ownerUsername, pin } = req.body;
  try {
    if (!businessId || !name || !ownerUsername || !pin) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (!/^\d{4}$/.test(pin)) {
      return res.status(400).json({ error: 'PIN must be a 4-digit number' });
    }

    const existingBusiness = await Business.findOne({ businessId });
    if (existingBusiness) {
      return res.status(400).json({ error: 'Business ID already exists' });
    }
    const owner = await User.findOne({ username: ownerUsername });
    if (!owner) {
      return res.status(400).json({ error: 'Owner username not found' });
    }

    const hashedPin = await bcrypt.hash(pin, 10);
    const qrCode = JSON.stringify({ type: 'business_payment', businessId, businessName: name });
    const business = new Business({
      businessId,
      name,
      owner: ownerUsername,
      pin: hashedPin,
      balance: 0,
      qrCode,
      transactions: [],
      pendingDeposits: [],
      pendingWithdrawals: [],
    });
    await business.save();

    const token = jwt.sign({ businessId, type: 'business' }, JWT_SECRET, { expiresIn: '24h' });
    res.status(201).json({ token, business: { businessId, name } });
  } catch (error) {
    console.error('Business Sign-Up Error:', error.message);
    res.status(500).json({ error: 'Server error during sign-up' });
  }
});

// Business Signin
router.post('/signin', async (req, res) => {
  const { businessId, pin } = req.body;
  try {
    if (!businessId || !pin) {
      return res.status(400).json({ error: 'Business ID and PIN are required' });
    }

    const business = await Business.findOne({ businessId });
    if (!business) {
      return res.status(400).json({ error: 'Invalid Business ID or PIN' });
    }

    const isMatch = await bcrypt.compare(pin, business.pin);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid Business ID or PIN' });
    }

    const token = jwt.sign({ businessId, type: 'business' }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, business: { businessId, name: business.name } });
  } catch (error) {
    console.error('Business Sign-In Error:', error.message);
    res.status(500).json({ error: 'Server error during sign-in' });
  }
});

// Fetch Business Details
router.get('/:businessId', authenticateToken, async (req, res) => {
  try {
    const business = await Business.findOne({ businessId: req.params.businessId });
    if (!business) return res.status(404).json({ error: 'Business not found' });
    if (req.user.businessId !== business.businessId && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    res.json({
      businessId: business.businessId,
      name: business.name,
      balance: business.balance,
      qrCode: business.qrCode,
      transactions: business.transactions,
      pendingWithdrawals: business.pendingWithdrawals, // Added for BusinessHome
    });
  } catch (error) {
    console.error('Business Fetch Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Regenerate QR Code
router.post('/regenerate-qr', authenticateToken, async (req, res) => {
  const { businessId } = req.body;
  try {
    const business = await Business.findOne({ businessId });
    if (!business || business.businessId !== req.user.businessId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    const qrCode = JSON.stringify({ type: 'business_payment', businessId, businessName: business.name });
    business.qrCode = qrCode;
    await business.save();
    res.json({ qrCode });
  } catch (error) {
    console.error('QR Regeneration Error:', error);
    res.status(500).json({ error: 'Failed to generate QR' });
  }
});

// User-to-Business Transfer
router.post('/transfer/business', authenticateToken, async (req, res) => {
  const { sender, businessId, amount, pin } = req.body;

  if (!sender || !businessId || !amount || !pin) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    const user = await User.findOne({ username: sender });
    const business = await Business.findOne({ businessId });
    if (!user || !business) return res.status(404).json({ error: 'User or business not found' });
    if (user.phoneNumber !== req.user.phoneNumber) return res.status(403).json({ error: 'Unauthorized sender' });
    if (user.pin !== pin) return res.status(401).json({ error: 'Invalid PIN' });

    const paymentAmount = parseFloat(amount);
    if (isNaN(paymentAmount) || paymentAmount <= 0) {
      return res.status(400).json({ error: 'Amount must be a positive number' });
    }

    const sendingFee = require('../routes/index').getSendingFee(paymentAmount);
    const receivingFee = require('../routes/index').getReceivingFee(paymentAmount);
    const totalSenderDeduction = paymentAmount + sendingFee;

    if (user.balance < totalSenderDeduction) {
      return res.status(400).json({ error: 'Insufficient balance to cover amount and fee' });
    }

    const admin = await User.findOne({ role: 'admin' });
    if (!admin) return res.status(500).json({ error: 'Admin account not found' });

    user.balance -= totalSenderDeduction;
    business.balance += paymentAmount - receivingFee;
    admin.balance += sendingFee + receivingFee;

    const transactionId = crypto.randomBytes(16).toString('hex');
    user.transactions.push({
      _id: transactionId,
      type: 'sent',
      amount: paymentAmount,
      toFrom: businessId,
      fee: sendingFee,
      date: new Date(),
    });
    business.transactions.push({
      _id: transactionId,
      type: 'received',
      amount: paymentAmount - receivingFee,
      toFrom: sender,
      fee: receivingFee,
      date: new Date(),
    });
    admin.transactions.push({
      _id: transactionId,
      type: 'fee-collected',
      amount: sendingFee + receivingFee,
      toFrom: `${sender} -> ${businessId}`,
      originalAmount: paymentAmount,
      sendingFee,
      receivingFee,
      date: new Date(),
    });

    await Promise.all([user.save(), business.save(), admin.save()]);
    if (business.pushToken) {
      await sendPushNotification(
        business.pushToken,
        'Payment Received',
        `Received ${(paymentAmount - receivingFee).toFixed(2)} ZMW from ${sender}`,
        { transactionId }
      );
    }
    res.json({
      message: 'Payment successful',
      transactionId,
      sendingFee,
      receivingFee,
      amountReceived: paymentAmount - receivingFee,
      totalDeduction: totalSenderDeduction,
    });
  } catch (error) {
    console.error('Business Transfer Error:', error);
    res.status(500).json({ error: 'Transfer failed', details: error.message });
  }
});

// Business Deposit (Unchanged from your code)
router.post('/deposit', authenticateToken, async (req, res) => {
  const { businessId, amount, transactionId } = req.body;

  if (!businessId || !amount || !transactionId) {
    return res.status(400).json({ error: 'Business ID, amount, and transaction ID are required' });
  }

  try {
    const business = await Business.findOne({ businessId });
    if (!business || business.businessId !== req.user.businessId) {
      return res.status(403).json({ error: 'Unauthorized or business not found' });
    }
    const paymentAmount = parseFloat(amount);
    if (isNaN(paymentAmount) || paymentAmount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    business.pendingDeposits.push({ amount: paymentAmount, transactionId, date: new Date() });
    await business.save();

    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(
        admin.pushToken,
        'New Business Deposit Request',
        `Deposit of ${paymentAmount.toFixed(2)} ZMW from ${businessId} needs approval`,
        { businessId, transactionId }
      );
    }

    res.json({ message: 'Deposit request submitted' });
  } catch (error) {
    console.error('Business Deposit Error:', error);
    res.status(500).json({ error: 'Deposit request failed' });
  }
});

// Business Withdrawal
router.post('/withdrawal', authenticateToken, async (req, res) => {
  const { businessId, amount } = req.body;

  if (!businessId || !amount) {
    return res.status(400).json({ error: 'Business ID and amount are required' });
  }

  try {
    const business = await Business.findOne({ businessId });
    if (!business || business.businessId !== req.user.businessId) {
      return res.status(403).json({ error: 'Unauthorized or business not found' });
    }
    const withdrawalAmount = parseFloat(amount);
    if (isNaN(withdrawalAmount) || withdrawalAmount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }

    const withdrawalFee = Math.max(withdrawalAmount * 0.01, 2);
    const totalDeduction = withdrawalAmount + withdrawalFee;

    if (business.balance < totalDeduction) {
      return res.status(400).json({ error: 'Insufficient balance to cover amount and fee' });
    }

    business.pendingWithdrawals.push({
      amount: withdrawalAmount,
      fee: withdrawalFee,
      date: new Date(),
      status: 'pending', // Explicitly set status
    });
    await business.save();

    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(
        admin.pushToken,
        'New Business Withdrawal Request',
        `Withdrawal of ${withdrawalAmount.toFixed(2)} ZMW (Fee: ${withdrawalFee.toFixed(2)} ZMW) from ${businessId} needs approval`,
        { businessId, withdrawalIndex: business.pendingWithdrawals.length - 1 }
      );
    }
    if (business.pushToken) {
      await sendPushNotification(
        business.pushToken,
        'Withdrawal Requested',
        `Your request for ${withdrawalAmount.toFixed(2)} ZMW (Fee: ${withdrawalFee.toFixed(2)} ZMW) is pending approval`,
        { businessId, withdrawalIndex: business.pendingWithdrawals.length - 1 }
      );
    }

    res.json({ 
      message: 'Withdrawal request submitted', 
      withdrawalFee 
    });
  } catch (error) {
    console.error('Business Withdrawal Error:', error);
    res.status(500).json({ error: 'Withdrawal request failed' });
  }
});

// Admin Verify Business Withdrawal
router.post('/admin/verify-business-withdrawal', authenticateToken, async (req, res) => {
  const { businessId, withdrawalIndex, approved } = req.body;
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const business = await Business.findOne({ businessId });
    if (!business) return res.status(404).json({ error: 'Business not found' });

    const withdrawal = business.pendingWithdrawals[withdrawalIndex];
    if (!withdrawal || withdrawal.status !== 'pending') {
      return res.status(400).json({ error: 'Invalid or already processed withdrawal' });
    }

    const admin = await User.findOne({ role: 'admin' });
    if (!admin) return res.status(500).json({ error: 'Admin account not found' });

    if (approved) {
      const totalDeduction = withdrawal.amount + withdrawal.fee;
      if (business.balance < totalDeduction) {
        return res.status(400).json({ error: 'Insufficient balance' });
      }

      business.balance -= totalDeduction;
      admin.balance += withdrawal.fee;
      business.transactions.push({
        _id: crypto.randomBytes(16).toString('hex'),
        type: 'withdrawn',
        amount: withdrawal.amount,
        toFrom: 'manual-mobile-money',
        fee: withdrawal.fee,
        date: new Date(),
      });
      admin.transactions.push({
        _id: crypto.randomBytes(16).toString('hex'),
        type: 'fee-collected',
        amount: withdrawal.fee,
        toFrom: `Withdrawal from ${businessId}`,
        date: new Date(),
      });
      withdrawal.status = 'completed';
    } else {
      withdrawal.status = 'rejected';
    }
    await Promise.all([business.save(), admin.save()]);

    if (business.pushToken) {
      await sendPushNotification(
        business.pushToken,
        `Withdrawal ${approved ? 'Approved' : 'Rejected'}`,
        approved
          ? `Your withdrawal of ${withdrawal.amount.toFixed(2)} ZMW has been approved`
          : `Your withdrawal of ${withdrawal.amount.toFixed(2)} ZMW was rejected`,
        { businessId, withdrawalIndex }
      );
    }

    res.json({ message: `Withdrawal ${approved ? 'completed' : 'rejected'}` });
  } catch (error) {
    console.error('Verify Business Withdrawal Error:', error);
    res.status(500).json({ error: 'Failed to verify withdrawal' });
  }
});

// Fetch All Businesses (for Admin)
router.get('/all', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  try {
    const businesses = await Business.find();
    res.json(businesses);
  } catch (error) {
    console.error('Fetch All Businesses Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Save Push Token
router.post('/save-push-token', authenticateToken, async (req, res) => {
  const { businessId, pushToken } = req.body;
  if (!businessId || !pushToken) return res.status(400).json({ error: 'Business ID and push token required' });
  try {
    const business = await Business.findOne({ businessId });
    if (!business || business.businessId !== req.user.businessId) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    business.pushToken = pushToken;
    await business.save();
    res.json({ message: 'Push token saved' });
  } catch (error) {
    console.error('Save Push Token Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;