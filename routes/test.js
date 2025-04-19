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


// POST /api/business/register
/* router.post('/business/register', authenticateToken(['user']), upload.single('qrCode'), async (req, res) => {
  const { businessId, name, pin } = req.body;
  const qrCodeImage = req.file;
  if (!businessId || !name || !pin || !qrCodeImage) {
    return res.status(400).json({ error: 'Business ID (TPIN), name, PIN, and QR code image are required' });
  }
  if (!/^\d{10}$/.test(businessId)) {
    return res.status(400).json({ error: 'Business ID must be a 10-digit TPIN' });
  }
  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'PIN must be a 4-digit number' });
  }
  try {
    const existingBusiness = await Business.findOne({ $or: [{ businessId }, { ownerUsername: req.user.username }] }).lean();
    if (existingBusiness) return res.status(400).json({ error: 'Business ID (TPIN) or owner username already registered' });
    const owner = await User.findOne({ username: req.user.username });
    if (!owner) return res.status(404).json({ error: 'Owner user not found' });
    const fileStream = fs.createReadStream(qrCodeImage.path);
    const s3Key = `qr-codes/${Date.now()}-${qrCodeImage.originalname}`;
    const params = { Bucket: S3_BUCKET, Key: s3Key, Body: fileStream, ContentType: qrCodeImage.mimetype, ACL: 'private' };
    const s3Response = await s3.upload(params).promise();
    const qrCodeUrl = s3Response.Location;
    fs.unlinkSync(qrCodeImage.path);
    const business = new Business({
      businessId, name, ownerUsername: req.user.username, pin, balance: 0, qrCode: qrCodeUrl,
      role: 'business', approvalStatus: 'pending', transactions: [], isActive: false,
    });
    await business.save();
    const admin = await User.findOne({ role: 'admin' });
    if (admin && admin.pushToken) {
      await sendPushNotification(admin.pushToken, 'New Business Registration', `Business ${name} (${businessId}) needs approval`, { businessId });
    }
    res.status(201).json({ message: 'Business registered, awaiting approval', businessId });
  } catch (error) {
    console.error('Business Register Error:', error.message, error.stack);
    res.status(500).json({ error: 'Server error during business registration', details: error.message });
  }
}); */

/* router.post('/business/register', authenticateToken(['user']), upload.single('qrCode'), async (req, res) => {
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
    const business = new Business({
      businessId,
      name,
      ownerUsername: req.user.username,
      pin,
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
}); */

/* router.post('/business/register', async (req, res) => {
  const { businessId, name, pin } = req.body;

  // Validate required fields
  if (!businessId || !name || !pin) {
    return res.status(400).json({ error: 'Business ID, name, and PIN required' });
  }

  // Validate field formats
  if (!/^\d{10}$/.test(businessId)) {
    return res.status(400).json({ error: 'Business ID must be a 10-digit TPIN' });
  }
  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'PIN must be a 4-digit number' });
  }

  try {
    // Check existing business
    const existingBusiness = await Business.findOne({ businessId });
    if (existingBusiness) {
      return res.status(409).json({ error: 'TPIN already taken' });
    }

    // Hash PIN
    const hashedPin = await bcrypt.hash(pin, 10);

    // Create business
    const business = new Business({
      businessId,
      name,
      pin: hashedPin,
      balance: 0,
      transactions: [],
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
    console.error(`Business Register Error [businessId: ${businessId || 'unknown'}]:`, error.message, error.stack);
    const errorMessage = error.message.includes('Mongo')
      ? error.message.includes('refused') ? 'Database connection refused. Try again later.'
        : error.message.includes('authentication') ? 'Database authentication failed. Contact support.'
        : error.message.includes('MongoServerSelectionError') ? 'Database server unavailable. Try again later.'
        : error.message.includes('E11000') ? 'Duplicate entry detected. Contact support.'
        : 'Database unavailable. Try again later.'
      : 'Internal server error. Contact support@zangena.com';
    res.status(500).json({ error: errorMessage });
  }
}); */


/* 
router.post('/business/signup', async (req, res) => {
  const startTime = Date.now();
  const { businessId, name, ownerUsername, phoneNumber, email, pin } = req.body;

  // Validate required fields
  if (!businessId || !name || !ownerUsername || !phoneNumber || !pin) {
    return res.status(400).json({ error: 'Business ID, name, username, phone number, and PIN required' });
  }

  // Validate field formats
  if (!/^\d{10}$/.test(businessId)) {
    return res.status(400).json({ error: 'Business ID must be a 10-digit TPIN' });
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
  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ error: 'PIN must be a 4-digit number' });
  }

  try {
    // Check existing business
    console.log(`[SIGNUP] Checking existing business`);
    const businessCheckStart = Date.now();
    const existingBusiness = await withRetry(() =>
      Business.findOne({
        $or: [{ businessId }, { ownerUsername }, { phoneNumber }, email ? { email } : {}],
      }).catch(err => {
        throw new Error(`Business query failed: ${err.message} (code: ${err.code || 'unknown'})`);
      })
    );
    console.log(`[SIGNUP] Business check took ${Date.now() - businessCheckStart}ms`);
    if (existingBusiness) {
      return res.status(409).json({ error: 'TPIN, username, phone, or email already taken' });
    }

    // Hash PIN
    console.log(`[SIGNUP] Hashing PIN`);
    const hashStart = Date.now();
    let hashedPin;
    try {
      hashedPin = await bcrypt.hash(pin, 10);
    } catch (err) {
      throw new Error(`PIN hashing failed: ${err.message}`);
    }
    console.log(`[SIGNUP] PIN hashing took ${Date.now() - hashStart}ms`);

    // Create business
    const business = new Business({
      businessId,
      name,
      ownerUsername,
      pin: hashedPin,
      phoneNumber,
      email: email || undefined,
      balance: 0,
      transactions: [],
      pendingDeposits: [],
      pendingWithdrawals: [],
      qrCode: JSON.stringify({ type: 'business_payment', businessId, businessName: name }),
      role: 'business',
      approvalStatus: 'pending',
      isActive: false,
    });

    // Save business
    console.log(`[SIGNUP] Saving business`);
    const saveStart = Date.now();
    await withRetry(() =>
      business.save().catch(err => {
        throw new Error(`Business save failed: ${err.message} (code: ${err.code || 'unknown'})`);
      })
    );
    console.log(`[SIGNUP] Business save took ${Date.now() - saveStart}ms`);

    console.log(`[SIGNUP] Completed in ${Date.now() - startTime}ms`);
    res.status(201).json({
      message: 'Business registered, awaiting approval',
      business: { businessId, name, approvalStatus: 'pending' },
    });
  } catch (error) {
    console.error(`Business Signup Error [businessId: ${businessId || 'unknown'}]:`, error.message, error.stack);
    const errorMessage = error.message.includes('query failed') || error.message.includes('save failed')
      ? error.message.includes('refused') ? 'Database connection refused. Try again later.'
        : error.message.includes('authentication') ? 'Database authentication failed. Contact support.'
        : error.message.includes('MongoServerSelectionError') ? 'Database server unavailable. Try again later.'
        : error.message.includes('E11000') ? 'Duplicate entry detected. Contact support.'
        : 'Database unavailable. Try again later.'
      : error.message.includes('PIN hashing')
      ? 'PIN processing failed. Try again.'
      : 'Internal server error. Contact support@zangena.com';
    res.status(500).json({ error: errorMessage });
  }
});

router.post('/business/signin', async (req, res) => {
  const { businessId, pin } = req.body;
  if (!businessId || !pin) {
    return res.status(400).json({ error: 'Business ID and PIN required' });
  }

  try {
    const business = await withRetry(() =>
      Business.findOne({ businessId }).catch(err => {
        throw new Error(`Business query failed: ${err.message} (code: ${err.code || 'unknown'})`);
      })
    );
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

    const token = jwt.sign(
      { username: business.ownerUsername, role: 'business' },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    res.json({ token, message: 'Sign-in successful' });
  } catch (error) {
    console.error(`Business Signin Error [businessId: ${businessId}]:`, error.message, error.stack);
    const errorMessage = error.message.includes('query failed')
      ? error.message.includes('refused') ? 'Database connection refused. Try again later.'
        : error.message.includes('authentication') ? 'Database authentication failed. Contact support.'
        : error.message.includes('MongoServerSelectionError') ? 'Database server unavailable. Try again later.'
        : 'Database unavailable. Try again later.'
      : 'Internal server error. Contact support@zangena.com';
    res.status(500).json({ error: errorMessage });
  }
}); */

// Business Signin
/* router.post('/business/signin', async (req, res) => {
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
}); */

module.exports = router;