const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const crypto = require('crypto');
const User = require('../models/User');
const Business = require('../models/Business');
const AdminLedger = require('../models/AdminLedger');
const authenticateToken = require('../middleware/authenticateToken');

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
  const { businessId, approved } = req.body;
  console.log('[ADMIN] Verify KYC Request:', { businessId, approved });
  try {
    const business = await Business.findOne({ businessId });
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    if (business.kycStatus !== 'pending') {
      return res.status(400).json({ error: 'KYC already processed' });
    }
    business.kycStatus = approved ? 'verified' : 'rejected';
    await business.save();
    
    if (business.email) {
      await sendEmail(
        business.email,
        `KYC ${approved ? 'Approved' : 'Rejected'}`,
        `<h2>KYC ${approved ? 'Approved' : 'Rejected'}</h2>
         <p>Your KYC verification has been ${approved ? 'approved' : 'rejected'}.</p>
         <p>Best regards,<br>Zangena Team</p>`
      );
    }
    if (business.pushToken) {
      await sendPushNotification(
        business.pushToken,
        `KYC ${approved ? 'Approved' : 'Rejected'}`,
        `Your KYC verification was ${approved ? 'approved' : 'rejected'}.`
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
  console.log('[ADMIN] Set Business Active Request:', { businessId, isActive });
  try {
    const business = await Business.findOne({ businessId });
    if (!business) {
      return res.status(404).json({ error: 'Business not found' });
    }
    business.isActive = isActive;
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

// Existing routes (unchanged)
router.post('/verify-withdrawal', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { userId, withdrawalIndex, approved } = req.body;
  console.log('Verify Withdrawal Request:', { userId, withdrawalIndex, approved });
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
    res.json({ message: `Withdrawal ${approved ? 'completed' : 'rejected'}` });
  } catch (error) {
    console.error('Verify Withdrawal Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to verify withdrawal' });
  }
});

router.post('/verify-deposit', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { userId, transactionId, approved } = req.body;
  console.log('Verify Deposit Request:', { userId, transactionId, approved });
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
      const amount = deposit.amount;
      let creditedAmount = amount;
      const isFirstDeposit = !user.transactions.some(tx => tx.type === 'deposited');
      if (isFirstDeposit) {
        const bonus = Math.min(amount * 0.05, 10);
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
    res.json({ message: `Deposit ${approved ? 'approved' : 'rejected'}` });
  } catch (error) {
    console.error('Verify Deposit Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to verify deposit' });
  }
});

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
      business.balance += deposit.amount;
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
        adminLedger.totalBalance += deposit.amount;
        adminLedger.lastUpdated = new Date();
        adminLedger.save();
      }
    } else {
      deposit.status = 'rejected';
    }
    await business.save();
    res.json({ message: `Business deposit ${approved ? 'approved' : 'rejected'}` });
  } catch (error) {
    console.error('Verify Business Deposit Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to verify business deposit' });
  }
});

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
    console.error('Ledger Fetch Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to fetch ledger' });
  }
});

router.get('/stats', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  try {
    const [users, businesses, ledger] = await Promise.all([
      User.find().lean(),
      Business.find().lean(),
      AdminLedger.findOne().lean(),
    ]);
    const stats = {
      totalUsers: users.length,
      totalUserBalance: users.reduce((sum, u) => sum + u.balance, 0),
      pendingUserDepositsCount: users.flatMap(u => u.pendingDeposits).filter(d => d.status === 'pending').length,
      pendingUserWithdrawalsCount: users.flatMap(u => u.pendingWithdrawals).filter(w => w.status === 'pending').length,
      totalBusinesses: businesses.length,
      totalBusinessBalance: businesses.reduce((sum, b) => sum + Number(b.balance), 0),
      pendingBusinessDepositsCount: businesses.flatMap(b => b.pendingDeposits).filter(d => d.status === 'pending').length,
      pendingBusinessWithdrawalsCount: businesses.flatMap(b => b.pendingWithdrawals).filter(w => w.status === 'pending').length,
      totalBalance: ledger?.totalBalance || 0,
      recentTxCount: users
        .flatMap(u => u.transactions)
        .concat(businesses.flatMap(b => b.transactions))
        .filter(tx => new Date(tx.date) > new Date(Date.now() - 24 * 60 * 60 * 1000)).length,
    };
    res.json(stats);
  } catch (error) {
    console.error('Stats Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

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
    user.balance += amount;
    user.transactions.push({
      _id: crypto.randomBytes(16).toString('hex'),
      type: 'credited',
      amount,
      toFrom: adminUsername,
      date: new Date(),
    });
    await user.save();
    if (user.pushToken) {
      await sendPushNotification(user.pushToken, 'Balance Credited', `Your account was credited ${amount.toFixed(2)} ZMW by admin.`);
    }
    res.json({ message: `Credited ${amount} ZMW to ${toUsername}` });
  } catch (error) {
    console.error('Credit Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to credit user' });
  }
});

router.post('/verify-business-withdrawal', authenticateToken(['admin']), requireAdmin, async (req, res) => {
  const { businessId, withdrawalIndex, approved } = req.body;
  console.log('Verify Business Withdrawal Request:', { businessId, withdrawalIndex, approved });
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
      if (Number(business.balance) < totalDeduction) {
        return res.status(400).json({ error: 'Insufficient balance' });
      }
      business.balance = Number(business.balance) - totalDeduction;
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
    await business.save();
    if (business.email) {
      await sendEmail(
        business.email,
        `Withdrawal ${approved ? 'Approved' : 'Rejected'}`,
        `<h2>Withdrawal ${approved ? 'Approved' : 'Rejected'}</h2>
         <p>Your withdrawal request for ${withdrawal.amount.toFixed(2)} ZMW has been ${approved ? 'approved' : 'rejected'}.</p>
         <p>Best regards,<br>Zangena Team</p>`
      );
    }
    if (business.pushToken) {
      await sendPushNotification(
        business.pushToken,
        `Withdrawal ${approved ? 'Approved' : 'Rejected'}`,
        `Your withdrawal of ${withdrawal.amount.toFixed(2)} ZMW was ${approved ? 'approved' : 'rejected'}.`
      );
    }
    res.json({ message: `Business withdrawal ${approved ? 'approved' : 'rejected'}` });
  } catch (error) {
    console.error('Verify Business Withdrawal Error:', error.message, error.stack);
    res.status(500).json({ error: 'Failed to verify business withdrawal' });
  }
});

module.exports = router;