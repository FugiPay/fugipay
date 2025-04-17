const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const TestBusiness = require('../models/TestBusiness');

router.post('/test/register', async (req, res) => {
  const { businessId, name, pin } = req.body;

  // Validate fields
  if (!businessId || !name || !pin) {
    return res.status(400).json({ error: 'Business ID, name, and PIN required' });
  }
  if (!/^\d{10}$/.test(businessId)) {
    return res.status(400).json({ error: 'Business ID must be a 10-digit TPIN' });
  }
  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'PIN must be a 4-digit number' });
  }

  try {
    // Check existing business
    const existingBusiness = await TestBusiness.findOne({ businessId });
    if (existingBusiness) {
      return res.status(409).json({ error: 'TPIN already taken' });
    }

    // Hash PIN
    const hashedPin = await bcrypt.hash(pin, 10);

    // Create business
    const business = new TestBusiness({
      businessId,
      name,
      pin: hashedPin,
      balance: 0,
      approvalStatus: 'pending',
      isActive: false,
    });

    // Save business
    await business.save();

    res.status(201).json({
      message: 'Business registered, awaiting approval',
      business: { businessId, name, approvalStatus: 'pending' },
    });
  } catch (error) {
    console.error(`Test Register Error [businessId: ${businessId || 'unknown'}]:`, error.message);
    const errorMessage = error.message.includes('Mongo')
      ? 'Database issue. Try again later.'
      : 'Server error. Contact support@zangena.com';
    res.status(500).json({ error: errorMessage });
  }
});

router.post('/test/signin', async (req, res) => {
  const { businessId, pin } = req.body;

  // Validate fields
  if (!businessId || !pin) {
    return res.status(400).json({ error: 'Business ID and PIN required' });
  }

  try {
    const business = await TestBusiness.findOne({ businessId });
    if (!business) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (business.approvalStatus !== 'approved' || !business.isActive) {
      return res.status(403).json({ error: 'Business account not approved or inactive' });
    }

    const isMatch = await bcrypt.compare(pin, business.pin);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    res.json({ message: 'Sign-in successful', businessId });
  } catch (error) {
    console.error(`Test Signin Error [businessId: ${businessId}]:`, error.message);
    const errorMessage = error.message.includes('Mongo')
      ? 'Database issue. Try again later.'
      : 'Server error. Contact support@zangena.com';
    res.status(500).json({ error: errorMessage });
  }
});

module.exports = router;