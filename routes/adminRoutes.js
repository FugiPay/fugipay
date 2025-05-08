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

module.exports = router;