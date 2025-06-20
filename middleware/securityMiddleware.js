const rateLimit = require('express-rate-limit');
const { body, validationResult, query } = require('express-validator');

// General rate limiter (100 requests per 15 minutes per IP)
const generalRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Strict rate limiter for sensitive endpoints (20 requests per 15 minutes per IP)
const strictRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Validation middleware
const validate = (validations) => {
  return async (req, res, next) => {
    await Promise.all(validations.map(validation => validation.run(req)));
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      console.error('[Validation] Errors:', {
        endpoint: req.originalUrl,
        method: req.method,
        errors: errors.array(),
        body: req.body,
      });
      return res.status(400).json({ error: 'Invalid input', details: errors.array() });
    }
    next();
  };
};

// Input validation rules
const registerValidation = [
  body('username')
    .trim()
    .isAlphanumeric('en-US', { ignore: '_' })
    .isLength({ min: 3, max: 20 })
    .withMessage('Username must be 3-20 characters, alphanumeric with underscores'),
  body('email')
    .trim()
    .isEmail()
    .normalizeEmail()
    .withMessage('Invalid email format'),
  body('phoneNumber')
    .trim()
    .matches(/^\+260(9[5678]|7[34679])\d{7}$/)
    .withMessage('Invalid Zambian phone number'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters'),
  body('pin')
    .matches(/^\d{4}$/)
    .withMessage('PIN must be a 4-digit number'),
  body('name')
    .trim()
    .isString()
    .isLength({ min: 1 })
    .withMessage('Name is required'),
];

const loginValidation = [
  body('identifier')
    .trim()
    .isString()
    .isLength({ min: 1 })
    .withMessage('Username or phone number is required'),
  body('password')
    .isString()
    .isLength({ min: 1 })
    .withMessage('Password is required'),
  body('totpCode')
    .optional()
    .isNumeric()
    .isLength({ min: 6, max: 6 })
    .withMessage('TOTP code must be 6 digits'),
];

const payQrValidation = [
  body('qrId')
    .trim()
    .isString()
    .isLength({ min: 1 })
    .withMessage('QR ID is required'),
  body('amount')
    .isFloat({ min: 0.01, max: 10000 })
    .withMessage('Amount must be between 0.01 and 10,000 ZMW'),
  body('senderUsername')
    .trim()
    .isAlphanumeric('en-US', { ignore: '_' })
    .isLength({ min: 3, max: 20 })
    .withMessage('Invalid sender username'),
  body('pin')
    .optional()
    .matches(/^\d{4}$/)
    .withMessage('PIN must be a 4-digit number'),
];

const updateProfileValidation = [
  body('email')
    .optional()
    .trim()
    .isEmail()
    .normalizeEmail()
    .withMessage('Invalid email format'),
  body('password')
    .optional()
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters'),
  body('pin')
    .optional()
    .matches(/^\d{4}$/)
    .withMessage('PIN must be a 4-digit number'),
];

const mobileMoneyLinkValidation = [
  body('code')
    .trim()
    .isAlphanumeric()
    .isLength({ min: 1 })
    .withMessage('Authorization code is required and must be alphanumeric'),
  body('phoneNumber')
    .trim()
    .matches(/^\+260(9[5678]|7[34679])\d{7}$/)
    .withMessage('Invalid Zambian phone number'),
];

const mobileMoneyWithdrawValidation = [
  body('phoneNumber')
    .trim()
    .matches(/^\+260(9[5678]|7[34679])\d{7}$/)
    .withMessage('Invalid Zambian phone number'),
  body('amount')
    .isFloat({ min: 0.01, max: 10000 })
    .withMessage('Amount must be between 0.01 and 10,000 ZMW'),
];

module.exports = {
  generalRateLimiter,
  strictRateLimiter,
  validate,
  registerValidation,
  loginValidation,
  payQrValidation,
  updateProfileValidation,
  mobileMoneyLinkValidation,
  mobileMoneyWithdrawValidation,
};