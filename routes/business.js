const express = require('express');
const router = express.Router();
const Business = require('../models/Business');
const User = require('../models/User');
const authenticateToken = require('../middleware/authenticateToken');
const { sendPushNotification } = require('../utils/notifications');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const JWT_SECRET = process.env.JWT_SECRET || 'Zangena123$@2025';

console.log('Loading business.js routes...');

// Business Signup
/* router.post('/signup', async (req, res) => {
  const { businessId, name, ownerUsername, pin } = req.body;
  if (!businessId || !name || !ownerUsername || !pin) {
    return res.status(400).json({ error: 'All fields are required' });
  }
  if (!/^\d{10}$/.test(businessId)) {
    return res.status(400).json({ error: 'Business ID must be a 10-digit TPIN' });
  }
  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'PIN must be a 4-digit number' });
  }
  try {
    const existingBusiness = await Business.findOne({ $or: [{ businessId }, { ownerUsername }] });
    if (existingBusiness) {
      return res.status(409).json({ error: 'Business ID (TPIN) or Owner Username already registered' });
    }
    const hashedPin = await bcrypt.hash(pin, 10);
    const business = new Business({
      businessId,
      name,
      ownerUsername,
      pin: hashedPin,
      balance: 0,
      transactions: [],
      pendingDeposits: [],
      pendingWithdrawals: [],
      qrCode: JSON.stringify({ type: 'business_payment', businessId, businessName: name }),
      role: 'business',
      approvalStatus: 'pending', // Start as pending
      isActive: false, // Inactive until approved
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
    res.json({
      message: 'Business registered, awaiting admin approval',
      business: { businessId: business.businessId, name: business.name, approvalStatus: business.approvalStatus },
    });
  } catch (error) {
    console.error('Business Signup Error:', error);
    res.status(500).json({ error: 'Server error during signup' });
  }
}); */

// Business Signin
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
      return res.status(404).json({ error: 'Business not found, check your 10 digit ID (TPIN) & PIN' });
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
      business: { businessId: business.businessId, name: business.name, role: business.role },
    });
  } catch (error) {
    console.error('Business Signin Error:', error);
    res.status(500).json({ error: 'Server error during signin' });
  }
});

// Fetch Business Details
console.log('Defining GET /:businessId');
router.get('/:businessId', authenticateToken, async (req, res) => {
  try {
    const business = await Business.findOne({ businessId: req.params.businessId });
    if (!business) return res.status(404).json({ error: 'Business not found' });
    if (req.user.role !== 'admin' && req.user.id !== business._id.toString()) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    res.json({
      businessId: business.businessId,
      name: business.name,
      ownerUsername: business.ownerUsername,
      balance: business.balance,
      qrCode: business.qrCode,
      role: business.role,
      approvalStatus: business.approvalStatus,
      transactions: business.transactions,
      pendingWithdrawals: business.pendingWithdrawals,
      pendingDeposits: business.pendingDeposits,
      isActive: business.isActive,
    });
  } catch (error) {
    console.error('Business Fetch Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update Business Profile
router.put('/:businessId', authenticateToken, async (req, res) => {
  const { name, ownerUsername } = req.body;
  if (!name && !ownerUsername) {
    return res.status(400).json({ error: 'At least one field (name or ownerUsername) is required' });
  }
  try {
    const business = await Business.findOne({ businessId: req.params.businessId });
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    if (business._id.toString() !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    if (name) business.name = name;
    if (ownerUsername) {
      const existingBusiness = await Business.findOne({ ownerUsername });
      if (existingBusiness && existingBusiness.businessId !== business.businessId) {
        return res.status(409).json({ error: 'Owner Username already taken' });
      }
      business.ownerUsername = ownerUsername;
    }
    await business.save();
    res.json({
      message: 'Profile updated successfully',
      business: {
        businessId: business.businessId,
        name: business.name,
        ownerUsername: business.ownerUsername,
        role: business.role,
        approvalStatus: business.approvalStatus,
      },
    });
  } catch (error) {
    console.error('Business Profile Update Error:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Regenerate QR Code
router.post('/regenerate-qr', authenticateToken, async (req, res) => {
  const { businessId } = req.body;
  if (!businessId) return res.status(400).json({ error: 'Business ID is required' });
  try {
    const business = await Business.findOne({ businessId });
    if (!business || business._id.toString() !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    if (business.approvalStatus !== 'approved') {
      return res.status(403).json({ error: 'Business must be approved to regenerate QR code' });
    }
    const qrCode = JSON.stringify({ type: 'business_payment', businessId, businessName: business.name });
    business.qrCode = qrCode;
    await business.save();
    res.json({ qrCode });
  } catch (error) {
    console.error('QR Regeneration Error:', error);
    res.status(500).json({ error: 'Failed to regenerate QR code' });
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
    if (user._id.toString() !== req.user.id) return res.status(403).json({ error: 'Unauthorized sender' });
    if (business.approvalStatus !== 'approved' || !business.isActive) {
      return res.status(403).json({ error: 'Business is not approved or active' });
    }
    const isPinMatch = await bcrypt.compare(pin, user.pin);
    if (!isPinMatch) return res.status(401).json({ error: 'Invalid PIN' });
    const paymentAmount = parseFloat(amount);
    if (isNaN(paymentAmount) || paymentAmount <= 0) {
      return res.status(400).json({ error: 'Amount must be a positive number' });
    }
    const sendingFee = Math.max(paymentAmount * 0.01, 2);
    const receivingFee = Math.max(paymentAmount * 0.01, 2);
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
    user.transactions.push({ _id: transactionId, type: 'sent', amount: paymentAmount, toFrom: businessId, fee: sendingFee, date: new Date() });
    business.transactions.push({ _id: transactionId, type: 'received', amount: paymentAmount - receivingFee, toFrom: sender, fee: receivingFee, date: new Date() });
    admin.transactions.push({ _id: transactionId, type: 'fee-collected', amount: sendingFee + receivingFee, toFrom: `${sender} -> ${businessId}`, originalAmount: paymentAmount, sendingFee, receivingFee, date: new Date() });
    await Promise.all([user.save(), business.save(), admin.save()]);
    if (business.pushToken) {
      await sendPushNotification(business.pushToken, 'Payment Received', `Received ${(paymentAmount - receivingFee).toFixed(2)} ZMW from ${sender}`, { transactionId });
    }
    res.json({ message: 'Payment successful', transactionId, sendingFee, receivingFee, amountReceived: paymentAmount - receivingFee, totalDeduction: totalSenderDeduction });
  } catch (error) {
    console.error('Business Transfer Error:', error);
    res.status(500).json({ error: 'Transfer failed', details: error.message });
  }
});

// Business Deposit
router.post('/deposit', authenticateToken, async (req, res) => {
  const { businessId, amount, transactionId } = req.body;
  if (!businessId || !amount || !transactionId) {
    return res.status(400).json({ error: 'Business ID, amount, and transaction ID are required' });
  }
  try {
    const business = await Business.findOne({ businessId });
    if (!business || business._id.toString() !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized or business not found' });
    }
    if (business.approvalStatus !== 'approved' || !business.isActive) {
      return res.status(403).json({ error: 'Business must be approved and active to deposit' });
    }
    const paymentAmount = parseFloat(amount);
    if (isNaN(paymentAmount) || paymentAmount <= 0) {
      return res.status(400).json({ error: 'Invalid amount' });
    }
    business.pendingDeposits.push({ amount: paymentAmount, transactionId, date: new Date(), status: 'pending' });
    await business.save();
    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(admin.pushToken, 'New Business Deposit Request', `Deposit of ${paymentAmount.toFixed(2)} ZMW from ${businessId} needs approval`, { businessId, transactionId });
    }
    res.json({ message: 'Deposit request submitted' });
  } catch (error) {
    console.error('Business Deposit Error:', error);
    res.status(500).json({ error: 'Deposit request failed' });
  }
});

// Admin Verify Business Deposit
router.post('/verify-deposit', authenticateToken, async (req, res) => {
  const { businessId, transactionId, approved } = req.body;
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  if (!businessId || !transactionId || approved === undefined) {
    return res.status(400).json({ error: 'Business ID, transaction ID, and approval status required' });
  }
  try {
    const business = await Business.findOne({ businessId });
    if (!business) return res.status(404).json({ error: 'Business not found' });
    const deposit = business.pendingDeposits.find((d) => d.transactionId === transactionId);
    if (!deposit || deposit.status !== 'pending') {
      return res.status(400).json({ error: 'Deposit not found or already processed' });
    }
    if (approved) {
      business.balance += deposit.amount;
      business.transactions.push({
        _id: crypto.randomBytes(16).toString('hex'),
        type: 'deposited',
        amount: deposit.amount,
        toFrom: 'manual-mobile-money',
        date: new Date(),
      });
      deposit.status = 'approved';
    } else {
      deposit.status = 'rejected';
    }
    await business.save();
    if (business.pushToken) {
      await sendPushNotification(
        business.pushToken,
        `Deposit ${approved ? 'Approved' : 'Rejected'}`,
        approved
          ? `Your deposit of ${deposit.amount.toFixed(2)} ZMW has been approved`
          : `Your deposit of ${deposit.amount.toFixed(2)} ZMW was rejected`,
        { businessId: business.businessId, transactionId }
      );
    }
    res.json({ message: `Deposit ${approved ? 'approved' : 'rejected'}` });
  } catch (error) {
    console.error('Verify Business Deposit Error:', error);
    res.status(500).json({ error: 'Failed to verify deposit' });
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
    if (!business || business._id.toString() !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized or business not found' });
    }
    if (business.approvalStatus !== 'approved' || !business.isActive) {
      return res.status(403).json({ error: 'Business must be approved and active to withdraw' });
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
    business.pendingWithdrawals.push({ amount: withdrawalAmount, fee: withdrawalFee, date: new Date(), status: 'pending' });
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
    res.json({ message: 'Withdrawal request submitted', withdrawalFee });
  } catch (error) {
    console.error('Business Withdrawal Error:', error);
    res.status(500).json({ error: 'Withdrawal request failed' });
  }
});

// Admin Verify Business Withdrawal
router.post('/verify-withdrawal', authenticateToken, async (req, res) => {
  const { businessId, withdrawalIndex, approved } = req.body;
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  if (!businessId || withdrawalIndex === undefined || approved === undefined) {
    return res.status(400).json({ error: 'Business ID, withdrawal index, and approval status are required' });
  }
  try {
    const business = await Business.findOne({ businessId });
    if (!business) return res.status(404).json({ error: 'Business not found' });
    if (withdrawalIndex >= business.pendingWithdrawals.length) {
      return res.status(404).json({ error: 'Withdrawal not found' });
    }
    const withdrawal = business.pendingWithdrawals[withdrawalIndex];
    if (withdrawal.status !== 'pending') {
      return res.status(400).json({ error: 'Withdrawal already processed' });
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
        toFrom: `Withdrawal from ${business.businessId}`,
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
        { businessId: business.businessId, withdrawalIndex }
      );
    }
    res.json({ message: `Withdrawal ${approved ? 'completed' : 'rejected'}` });
  } catch (error) {
    console.error('Verify Business Withdrawal Error:', error);
    res.status(500).json({ error: 'Failed to verify withdrawal' });
  }
});

// Fetch All Businesses
console.log('Defining GET /businesses');
router.get('/businesses', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  try {
    const { page = 1, limit = 10, search = '' } = req.query;
    const query = search ? { name: { $regex: search, $options: 'i' } } : {};
    const businesses = await Business.find(query)
      .skip((page - 1) * limit)
      .limit(parseInt(limit));
    const total = await Business.countDocuments(query);
    res.json({ businesses, total });
  } catch (error) {
    console.error('Fetch Businesses Error:', error);
    res.status(500).json({ error: 'Failed to fetch businesses' });
  }
});

// Save Push Token
router.post('/save-push-token', authenticateToken, async (req, res) => {
  const { businessId, pushToken } = req.body;
  if (!businessId || !pushToken) return res.status(400).json({ error: 'Business ID and push token required' });
  try {
    const business = await Business.findOne({ businessId });
    if (!business || business._id.toString() !== req.user.id) {
      return res.status(403).json({ error: 'Unauthorized' });
    }
    if (business.approvalStatus !== 'approved') {
      return res.status(403).json({ error: 'Business must be approved to save push token' });
    }
    business.pushToken = pushToken;
    await business.save();
    res.json({ message: 'Push token saved' });
  } catch (error) {
    console.error('Save Push Token Error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Set Business Role (Admin Only)
router.put('/set-role', authenticateToken, async (req, res) => {
  const { businessId, role } = req.body;
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  if (!businessId || !['business', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Business ID and valid role (business or admin) required' });
  }
  try {
    const business = await Business.findOne({ businessId });
    if (!business) return res.status(404).json({ error: 'Business not found' });
    business.role = role;
    await business.save();
    res.json({ message: `Business ${businessId} role set to ${role}` });
  } catch (error) {
    console.error('Set Business Role Error:', error);
    res.status(500).json({ error: 'Failed to set business role' });
  }
});

// Toggle Business Active Status (Admin Only)
router.put('/toggle-active', authenticateToken, async (req, res) => {
  const { businessId, isActive } = req.body;
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  if (!businessId || isActive === undefined) {
    return res.status(400).json({ error: 'Business ID and active status required' });
  }
  try {
    const business = await Business.findOne({ businessId });
    if (!business) return res.status(404).json({ error: 'Business not found' });
    if (business.approvalStatus !== 'approved') {
      return res.status(400).json({ error: 'Business must be approved before toggling active status' });
    }
    business.isActive = isActive;
    await business.save();
    res.json({ message: `Business ${businessId} is now ${isActive ? 'active' : 'inactive'}` });
  } catch (error) {
    console.error('Toggle Business Active Error:', error);
    res.status(500).json({ error: 'Failed to toggle business status' });
  }
});

// Approve/Reject Business (Admin Only)
router.put('/approve', authenticateToken, async (req, res) => {
  const { businessId, approvalStatus } = req.body;
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  if (!businessId || !['approved', 'rejected'].includes(approvalStatus)) {
    return res.status(400).json({ error: 'Business ID and valid approval status (approved or rejected) required' });
  }
  try {
    const business = await Business.findOne({ businessId });
    if (!business) return res.status(404).json({ error: 'Business not found' });
    if (business.approvalStatus !== 'pending') {
      return res.status(400).json({ error: 'Business approval status already processed' });
    }
    business.approvalStatus = approvalStatus;
    if (approvalStatus === 'approved') {
      business.isActive = true; // Activate on approval
    }
    await business.save();
    if (business.pushToken) {
      await sendPushNotification(
        business.pushToken,
        `Business ${approvalStatus === 'approved' ? 'Approved' : 'Rejected'}`,
        approvalStatus === 'approved'
          ? 'Your business has been approved and is now active'
          : 'Your business registration was rejected',
        { businessId }
      );
    }
    res.json({ message: `Business ${businessId} ${approvalStatus}` });
  } catch (error) {
    console.error('Approve Business Error:', error);
    res.status(500).json({ error: 'Failed to process business approval' });
  }
});

module.exports = router;
console.log('Business.js routes fully loaded');