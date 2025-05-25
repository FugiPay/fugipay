const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const crypto = require('crypto');
const User = require('../models/User');
const { Business } = require('../models/Business'); // Fix: Destructure Business
const AdminLedger = require('../models/AdminLedger');
const authenticateToken = require('../middleware/authenticateToken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { Expo } = require('expo-server-sdk');

// Environment variables
const EMAIL_USER = process.env.EMAIL_USER || 'your_email@example.com';
const EMAIL_PASS = process.env.EMAIL_PASS || 'your_email_password';

// Email setup
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: EMAIL_USER, pass: EMAIL_PASS },
});

// Push notification setup
const expo = new Expo();

// Middleware to check admin role
const requireAdmin = async (req, res, next) => {
  try {
    const user = await User.findOne({ phoneNumber: req.user.phoneNumber });
    if (!user || user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    if (!user.isActive || user.kycStatus !== 'verified') {
      return res.status(403).json({ error: 'Admin account inactive or not verified' });
    }
    next();
  } catch (error) {
    console.error('[ADMIN] RequireAdmin Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error' });
  }
};

// Send email
const sendEmail = async (to, subject, html) => {
  try {
    await transporter.sendMail({ from: EMAIL_USER, to, subject, html });
    console.log(`[Email] Sent to ${to}: ${subject}`);
  } catch (error) {
    console.error(`[Email] Error: ${error.message}`);
  }
};

// Send push notification
const sendPushNotification = async (pushToken, title, body, data = {}) => {
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

// Get all users with pagination and search
router.get('/users', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '' } = req.query;
    const skip = (Number(page) - 1) * Number(limit);
    const query = search
      ? {
          $or: [
            { username: { $regex: search, $options: 'i' } },
            { phoneNumber: { $regex: search, $options: 'i' } },
            { email: { $regex: search, $options: 'i' } },
          ],
        }
      : {};
    const [users, total] = await Promise.all([
      User.find(query)
        .select('username phoneNumber balance kycStatus trustScore isActive pendingDeposits pendingWithdrawals transactions')
        .skip(skip)
        .limit(Number(limit))
        .lean(),
      User.countDocuments(query),
    ]);
    res.json({ users, total, page: Number(page), limit: Number(limit) });
  } catch (error) {
    console.error('[GetUsers] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Update user KYC status
router.post('/update-kyc', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { id, kycStatus } = req.body;
  if (!id || !['pending', 'verified', 'rejected'].includes(kycStatus)) {
    return res.status(400).json({ error: 'Invalid user ID or KYC status' });
  }
  try {
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    user.kycStatus = kycStatus;
    user.isActive = kycStatus === 'verified';
    await user.save();
    if (user.email) {
      await sendEmail(
        user.email,
        `KYC ${kycStatus === 'verified' ? 'Approved' : 'Rejected'}`,
        `<h2>KYC ${kycStatus === 'verified' ? 'Approved' : 'Rejected'}</h2>
         <p>Your KYC verification has been ${kycStatus === 'verified' ? 'approved' : 'rejected'}.</p>
         <p>Best regards,<br>Zangena Team</p>`
      );
    }
    if (user.pushToken) {
      await sendPushNotification(
        user.pushToken,
        `KYC ${kycStatus === 'verified' ? 'Approved' : 'Rejected'}`,
        `Your KYC verification was ${kycStatus === 'verified' ? 'approved' : 'rejected'}.`
      );
    }
    res.json({ message: 'KYC status updated' });
  } catch (error) {
    console.error('[UpdateKYC] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to update KYC status' });
  }
});

// Toggle user active status
router.put('/toggle-active', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { username } = req.body;
  if (!username) {
    return res.status(400).json({ error: 'Username required' });
  }
  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    user.isActive = !user.isActive;
    await user.save();
    if (user.email) {
      await sendEmail(
        user.email,
        `Account ${user.isActive ? 'Activated' : 'Deactivated'}`,
        `<h2>Account ${user.isActive ? 'Activated' : 'Deactivated'}</h2>
         <p>Your account has been ${user.isActive ? 'activated' : 'deactivated'}.</p>
         <p>Best regards,<br>Zangena Team</p>`
      );
    }
    if (user.pushToken) {
      await sendPushNotification(
        user.pushToken,
        `Account ${user.isActive ? 'Activated' : 'Deactivated'}`,
        `Your account was ${user.isActive ? 'activated' : 'deactivated'}.`
      );
    }
    res.json({ message: `User ${username} is now ${user.isActive ? 'active' : 'inactive'}` });
  } catch (error) {
    console.error('[ToggleActive] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to toggle user status' });
  }
});

// Get user transactions
router.get('/transactions/:username', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { username } = req.params;
  const { startDate, endDate, limit = 50, skip = 0 } = req.query;
  try {
    const query = { username };
    const transactionQuery = {};
    if (startDate || endDate) {
      transactionQuery.date = {};
      if (startDate) transactionQuery.date.$gte = new Date(startDate);
      if (endDate) transactionQuery.date.$lte = new Date(endDate);
    }
    const user = await User.findOne(query).lean();
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const transactions = user.transactions
      .filter(tx => {
        if (startDate && new Date(tx.date) < new Date(startDate)) return false;
        if (endDate && new Date(tx.date) > new Date(endDate)) return false;
        return true;
      })
      .slice(Number(skip), Number(skip) + Number(limit))
      .map(tx => ({
        _id: tx._id,
        type: tx.type,
        amount: tx.amount,
        toFrom: tx.toFrom,
        fee: tx.fee,
        date: tx.date,
      }));
    res.json({ transactions, total: user.transactions.length });
  } catch (error) {
    console.error('[GetTransactions] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to fetch transactions' });
  }
});

// Get all businesses with pagination and filters
router.get('/businesses', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, kycStatus, isActive } = req.query;
    const query = {};
    if (kycStatus) query.kycStatus = kycStatus;
    if (isActive !== undefined) query.isActive = isActive === 'true';
    
    const businesses = await Business.find(query)
      .select('businessId name kycStatus isActive accountTier createdAt')
      .limit(Number(limit))
      .skip((Number(page) - 1) * Number(limit))
      .lean();
    
    const total = await Business.countDocuments(query);
    
    res.json({
      businesses,
      total,
      page: Number(page),
      pages: Math.ceil(total / Number(limit)),
    });
  } catch (error) {
    console.error('[ADMIN] Fetch Businesses Error:', error.message, error.stack);
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
    if (approved) {
      business.isActive = true;
      business.kycDetails = { sanctionsScreening: { status: 'clear', lastChecked: new Date() } };
    } else if (rejectionReason) {
      business.kycDetails = { rejectionReason };
    }
    business.auditLogs.push({
      action: 'kyc_update',
      performedBy: req.user.username,
      details: { approved, rejectionReason },
    });
    await business.save();
    if (business.email) {
      await sendEmail(
        business.email,
        `KYC ${approved ? 'Approved' : 'Rejected'}`,
        `<h2>KYC ${approved ? 'Approved' : 'Rejected'}</h2>
         <p>Your KYC verification has been ${approved ? 'approved' : 'rejected'}${rejectionReason ? ': ' + rejectionReason : '.'}</p>
         <p>Best regards,<br>Zangena Team</p>`
      );
    }
    if (business.pushToken) {
      await sendPushNotification(
        business.pushToken,
        `KYC ${approved ? 'Approved' : 'Rejected'}`,
        `Your KYC verification was ${approved ? 'approved' : 'rejected'}${rejectionReason ? ': ' + rejectionReason : '.'}`
      );
    }
    res.json({ message: `KYC ${approved ? 'approved' : 'rejected'}` });
  } catch (error) {
    console.error('[ADMIN] Verify KYC Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to verify KYC' });
  }
});

// Set business active status
router.post('/set-business-active', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { businessId, isActive } = req.body;
  try {
    const business = await Business.findOne({ businessId });
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    business.isActive = isActive;
    business.auditLogs.push({
      action: 'set_active',
      performedBy: req.user.username,
      details: { isActive },
    });
    await business.save();
    if (business.email) {
      await sendEmail(
        business.email,
        `Business Account ${isActive ? 'Activated' : 'Deactivated'}`,
        `<h2>Business Account ${isActive ? 'Activated' : 'Deactivated'}</h2>
         <p>Your business account has been ${isActive ? 'activated' : 'deactivated'}.</p>
         <p>Best regards,<br>Zangena Team</p>`
      );
    }
    if (business.pushToken) {
      await sendPushNotification(
        business.pushToken,
        `Business Account ${isActive ? 'Activated' : 'Deactivated'}`,
        `Your business account was ${isActive ? 'activated' : 'deactivated'}.`
      );
    }
    res.json({ message: `Business ${isActive ? 'activated' : 'deactivated'}` });
  } catch (error) {
    console.error('[ADMIN] Set Business Active Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to set business active status' });
  }
});

// Update business account tier
router.post('/update-tier', authenticateToken(['admin']), requireAdmin, async (req, res) => {
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
      performedBy: req.user.username,
      details: { oldTier, newTier: tier },
    });
    await business.save();
    if (business.email) {
      await sendEmail(
        business.email,
        'Account Tier Updated',
        `<h2>Account Tier Updated</h2>
         <p>Your account tier is now ${tier}.</p>
         <p>Best regards,<br>Zangena Team</p>`
      );
    }
    if (business.pushToken) {
      await sendPushNotification(
        business.pushToken,
        'Account Tier Updated',
        `Your account is now ${tier}.`,
        { businessId }
      );
    }
    res.json({ message: `Account tier updated to ${tier}` });
  } catch (error) {
    console.error('[UpdateTier] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to update account tier' });
  }
});

// Get business audit logs
router.get('/audit-logs/:businessId', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  try {
    const business = await Business.findOne({ businessId: req.params.businessId }, { auditLogs: 1 }).lean();
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    res.json({ auditLogs: business.auditLogs });
  } catch (error) {
    console.error('[AuditLogs] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

// Verify user withdrawal
router.post('/verify-withdrawal', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { userId, withdrawalIndex, approved } = req.body;
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
      user.transactions.push({
        _id: crypto.randomBytes(16).toString('hex'),
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
    if (user.email) {
      await sendEmail(
        user.email,
        `Withdrawal ${approved ? 'Approved' : 'Rejected'}`,
        `<h2>Withdrawal ${approved ? 'Approved' : 'Rejected'}</h2>
         <p>Your withdrawal request for ${withdrawal.amount.toFixed(2)} ZMW has been ${approved ? 'approved' : 'rejected'}.</p>
         <p>Best regards,<br>Zangena Team</p>`
      );
    }
    if (user.pushToken) {
      await sendPushNotification(
        user.pushToken,
        `Withdrawal ${approved ? 'Approved' : 'Rejected'}`,
        `Your withdrawal of ${withdrawal.amount.toFixed(2)} ZMW was ${approved ? 'approved' : 'rejected'}.`
      );
    }
    res.json({ message: `Withdrawal ${approved ? 'completed' : 'rejected'}` });
  } catch (error) {
    console.error('[VerifyWithdrawal] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to verify withdrawal' });
  }
});

// Verify user deposit
router.post('/verify-deposit', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { userId, transactionId, approved } = req.body;
  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    const deposit = user.pendingDeposits.find(d => d.transactionId === transactionId);
    if (!deposit || deposit.status !== 'pending') {
      return res.status(400).json({ error: 'Invalid or already processed deposit' });
    }
    if (approved) {
      let creditedAmount = deposit.amount;
      const isFirstDeposit = !user.transactions.some(tx => tx.type === 'deposited');
      if (isFirstDeposit) {
        const bonus = Math.min(deposit.amount * 0.05, 10);
        creditedAmount += bonus;
      }
      user.balance += creditedAmount;
      user.transactions.push({
        _id: crypto.randomBytes(16).toString('hex'),
        type: 'deposited',
        amount: creditedAmount,
        toFrom: 'manual-mobile-money',
        fee: 0,
        date: new Date(),
      });
      deposit.status = 'approved';
      const adminLedger = await AdminLedger.findOne();
      if (adminLedger) {
        adminLedger.totalBalance += creditedAmount;
        adminLedger.lastUpdated = new Date();
        await adminLedger.save();
      }
    } else {
      deposit.status = 'rejected';
    }
    await user.save();
    if (user.email) {
      await sendEmail(
        user.email,
        `Deposit ${approved ? 'Approved' : 'Rejected'}`,
        `<h2>Deposit ${approved ? 'Approved' : 'Rejected'}</h2>
         <p>Your deposit request for ${deposit.amount.toFixed(2)} ZMW has been ${approved ? 'approved' : 'rejected'}.</p>
         <p>Best regards,<br>Zangena Team</p>`
      );
    }
    if (user.pushToken) {
      await sendPushNotification(
        user.pushToken,
        `Deposit ${approved ? 'Approved' : 'Rejected'}`,
        `Your deposit of ${deposit.amount.toFixed(2)} ZMW was ${approved ? 'approved' : 'rejected'}.`
      );
    }
    res.json({ message: `Deposit ${approved ? 'approved' : 'rejected'}` });
  } catch (error) {
    console.error('[VerifyDeposit] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to verify deposit' });
  }
});

// Verify business deposit
router.post('/verify-business-deposit', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { businessId, transactionId, approved } = req.body;
  try {
    const business = await Business.findOne({ businessId });
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    const deposit = business.pendingDeposits.find(d => d.transactionId === transactionId);
    if (!deposit || deposit.status !== 'pending') {
      return res.status(400).json({ error: 'Invalid or already processed deposit' });
    }
    if (approved) {
      business.balances.ZMW = Number(business.balances.ZMW || 0) + Number(deposit.amount);
      business.transactions.push({
        _id: crypto.randomBytes(16).toString('hex'),
        type: 'deposited',
        amount: deposit.amount,
        toFrom: 'manual-mobile-money',
        fee: 0,
        date: new Date(),
      });
      deposit.status = 'approved';
      const adminLedger = await AdminLedger.findOne();
      if (adminLedger) {
        adminLedger.totalBalance += Number(deposit.amount);
        adminLedger.lastUpdated = new Date();
        await adminLedger.save();
      }
    } else {
      deposit.status = 'rejected';
    }
    business.auditLogs.push({
      action: 'deposit_verification',
      performedBy: req.user.username,
      details: { transactionId, approved },
    });
    await business.save();
    if (business.email) {
      await sendEmail(
        business.email,
        `Deposit ${approved ? 'Approved' : 'Rejected'}`,
        `<h2>Deposit ${approved ? 'Approved' : 'Rejected'}</h2>
         <p>Your deposit request for ${Number(deposit.amount).toFixed(2)} ZMW has been ${approved ? 'approved' : 'rejected'}.</p>
         <p>Best regards,<br>Zangena Team</p>`
      );
    }
    if (business.pushToken) {
      await sendPushNotification(
        business.pushToken,
        `Deposit ${approved ? 'Approved' : 'Rejected'}`,
        `Your deposit of ${Number(deposit.amount).toFixed(2)} ZMW was ${approved ? 'approved' : 'rejected'}.`
      );
    }
    res.json({ message: `Business deposit ${approved ? 'approved' : 'rejected'}` });
  } catch (error) {
    console.error('[VerifyBusinessDeposit] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to verify business deposit' });
  }
});

// Verify business withdrawal
router.post('/verify-business-withdrawal', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { businessId, withdrawalIndex, approved } = req.body;
  try {
    const business = await Business.findOne({ businessId });
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    const withdrawal = business.pendingWithdrawals[withdrawalIndex];
    if (!withdrawal || withdrawal.status !== 'pending') {
      return res.status(400).json({ error: 'Invalid or already processed withdrawal' });
    }
    if (approved) {
      const withdrawFee = Number(withdrawal.fee) || Math.max(Number(withdrawal.amount) * 0.01, 2);
      const totalDeduction = Number(withdrawal.amount) + withdrawFee;
      if (Number(business.balances.ZMW) < totalDeduction) {
        return res.status(400).json({ error: 'Insufficient balance' });
      }
      business.balances.ZMW = Number(business.balances.ZMW) - totalDeduction;
      business.transactions.push({
        _id: crypto.randomBytes(16).toString('hex'),
        type: 'withdrawn',
        amount: withdrawal.amount,
        toFrom: withdrawal.destination?.accountDetails || 'manual-mobile-money',
        fee: withdrawFee,
        date: new Date(),
      });
      withdrawal.status = 'approved';
      const adminLedger = await AdminLedger.findOne();
      if (adminLedger) {
        adminLedger.totalBalance += withdrawFee;
        adminLedger.lastUpdated = new Date();
        await adminLedger.save();
      }
    } else {
      withdrawal.status = 'rejected';
    }
    business.auditLogs.push({
      action: 'withdrawal_verification',
      performedBy: req.user.username,
      details: { withdrawalIndex, approved },
    });
    await business.save();
    if (business.email) {
      await sendEmail(
        business.email,
        `Withdrawal ${approved ? 'Approved' : 'Rejected'}`,
        `<h2>Withdrawal ${approved ? 'Approved' : 'Rejected'}</h2>
         <p>Your withdrawal request for ${Number(withdrawal.amount).toFixed(2)} ZMW has been ${approved ? 'approved' : 'rejected'}.</p>
         <p>Best regards,<br>Zangena Team</p>`
      );
    }
    if (business.pushToken) {
      await sendPushNotification(
        business.pushToken,
        `Withdrawal ${approved ? 'Approved' : 'Rejected'}`,
        `Your withdrawal of ${Number(withdrawal.amount).toFixed(2)} ZMW was ${approved ? 'approved' : 'rejected'}.`
      );
    }
    res.json({ message: `Business withdrawal ${approved ? 'approved' : 'rejected'}` });
  } catch (error) {
    console.error('[VerifyBusinessWithdrawal] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to verify business withdrawal' });
  }
});

// Get admin ledger
router.get('/ledger', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  try {
    const { startDate, endDate, limit = 50, skip = 0 } = req.query;
    const query = {};
    if (startDate || endDate) {
      query['transactions.date'] = {};
      if (startDate) query['transactions.date'].$gte = new Date(startDate);
      if (endDate) query['transactions.date'].$lte = new Date(endDate);
    }
    const ledger = await AdminLedger.findOne(query)
      .select('totalBalance lastUpdated transactions')
      .lean();
    if (!ledger) {
      return res.status(404).json({ error: 'Ledger not found' });
    }
    ledger.transactions = ledger.transactions
      .slice(Number(skip), Number(skip) + Number(limit))
      .map(tx => ({
        type: tx.type,
        amount: tx.amount,
        sender: tx.sender,
        receiver: tx.receiver,
        userTransactionIds: tx.userTransactionIds,
        date: tx.date,
      }));
    res.json(ledger);
  } catch (error) {
    console.error('[LedgerFetch] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to fetch ledger' });
  }
});

// Get system stats
router.get('/stats', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  try {
    const [users, businesses, ledger] = await Promise.all([
      User.find().lean(),
      Business.find().lean(),
      AdminLedger.findOne().lean(),
    ]);

    // Safely handle numerical calculations
    const stats = {
      totalUsers: users.length,
      totalUserBalance: users.reduce((sum, u) => {
        const balance = Number(u.balance || 0);
        return sum + (isNaN(balance) ? 0 : balance);
      }, 0),
      pendingUserDepositsCount: users
        .flatMap(u => u.pendingDeposits || [])
        .filter(d => d.status === 'pending').length,
      pendingUserWithdrawalsCount: users
        .flatMap(u => u.pendingWithdrawals || [])
        .filter(w => w.status === 'pending').length,
      totalBusinesses: businesses.length,
      totalBusinessBalance: businesses.reduce((sum, b) => {
        const balance = Number(b.balances?.ZMW || 0);
        return sum + (isNaN(balance) ? 0 : balance);
      }, 0),
      pendingBusinessDepositsCount: businesses
        .flatMap(b => b.pendingDeposits || [])
        .filter(d => d.status === 'pending').length,
      pendingBusinessWithdrawalsCount: businesses
        .flatMap(b => b.pendingWithdrawals || [])
        .filter(w => w.status === 'pending').length,
      totalBalance: Number(ledger?.totalBalance || 0),
      recentTxCount: users
        .flatMap(u => u.transactions || [])
        .concat(businesses.flatMap(b => b.transactions || []))
        .filter(tx => {
          try {
            return new Date(tx.date) > new Date(Date.now() - 24 * 60 * 60 * 1000);
          } catch (e) {
            console.warn('[Stats] Invalid transaction date:', tx);
            return false;
          }
        }).length,
    };

    res.json(stats);
  } catch (error) {
    console.error('[Stats] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to fetch stats', details: error.message });
  }
});

// Credit user balance
router.post('/credit', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { adminUsername, toUsername, amount } = req.body;
  if (!toUsername || !amount || amount <= 0) {
    return res.status(400).json({ error: 'Invalid username or amount' });
  }
  try {
    const user = await User.findOne({ username: toUsername });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    user.balance = Number(user.balance || 0) + Number(amount);
    user.transactions.push({
      _id: crypto.randomBytes(16).toString('hex'),
      type: 'credited',
      amount,
      toFrom: adminUsername,
      date: new Date(),
    });
    await user.save();
    if (user.pushToken) {
      await sendPushNotification(
        user.pushToken,
        'Balance Credited',
        `Your account was credited ${Number(amount).toFixed(2)} ZMW by admin.`
      );
    }
    if (user.email) {
      await sendEmail(
        user.email,
        'Balance Credited',
        `<h2>Balance Credited</h2>
         <p>Your account was credited ${Number(amount).toFixed(2)} ZMW by admin.</p>
         <p>Best regards,<br>Zangena Team</p>`
      );
    }
    res.json({ message: `Credited ${Number(amount).toFixed(2)} ZMW to ${toUsername}` });
  } catch (error) {
    console.error('[Credit] Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to credit user' });
  }
});

router.get('/check', authenticateToken(['admin']), requireAdmin, (req, res) => {
  res.json({ message: 'Token valid', user: req.user });
});

module.exports = router;