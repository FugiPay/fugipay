const mongoose = require('mongoose');

const analyticsSchema = new mongoose.Schema({
  event: {
    type: String,
    required: true,
    enum: [
      // Signup events (from signup.tsx and /register)
      'signup_request',
      'signup_success',
      'signup_failed',
      'signup_input_error',
      'signup_document_upload',
      'signup_document_failed',
      'signup_document_removed',
      'signup_focus_event',
      'kyc_image_analysis',
      // Signin events (from signin.tsx and /login)
      'signin_success',
      'signin_failed',
      'signin_input_error',
      'signin_2fa_required',
      'signin_2fa_setup_required',
      'signin_focus_event',
      'biometric_check_failed',
      'biometric_auth_failed',
      'biometric_setup_success',
      'biometric_setup_failed',
      'signin_storage_failed',
      // Deposit events (from deposit.tsx and /deposit/manual)
      'deposit_submitted',
      'deposit_failed',
      'deposit_input_error',
      'deposit_focus_event',
    ],
    index: true,
  },
  username: { type: String, required: false, index: true }, // Not required for anonymous events
  phoneNumber: { type: String, required: false, index: true }, // Not required for anonymous events
  identifier: { type: String, required: false }, // For signin events (username or phoneNumber)
  timestamp: { type: Date, required: true, default: Date.now, index: true },
  data: {
    amount: { type: Number, default: 0 }, // For deposit events
    transactionId: { type: String }, // For deposit or transaction events
    error: { type: String }, // Error message
    field: { type: String }, // For focus events
    focusCount: { type: Number, default: 0 }, // Input focus count
    errorCount: { type: Number, default: 0 }, // Input error count
    signupAttempts: { type: Number, default: 0 }, // Signup attempts
    signinAttempts: { type: Number, default: 0 }, // Signin attempts
    depositAttempts: { type: Number, default: 0 }, // Deposit attempts
    fraudScore: { type: Number, min: -1, max: 1 }, // AI: Anomaly score
    isFlagged: { type: Boolean, default: false }, // Fraud flag
    kycAnalysis: { // KYC analysis results
      textCount: { type: Number, default: 0 },
      faceCount: { type: Number, default: 0 },
      isValid: { type: Boolean, default: false },
      analyzedAt: { type: Date },
      error: { type: String },
    },
    idImageUrl: { type: String }, // For signup KYC events
    role: { type: String, enum: ['user', 'admin'] }, // For successful signin/signup
    kycStatus: { type: String, enum: ['pending', 'verified', 'rejected'] }, // For KYC-related events
    ip: { type: String }, // Device metadata for fraud detection
    userAgent: { type: String }, // Device metadata for fraud detection
  },
  createdAt: { type: Date, default: Date.now, expires: '90d' }, // Auto-expire after 90 days
}, {
  timestamps: true,
});

// Define indexes explicitly
analyticsSchema.index({ event: 1, timestamp: -1 });
analyticsSchema.index({ username: 1, timestamp: -1 });
analyticsSchema.index({ phoneNumber: 1, timestamp: -1 });
analyticsSchema.index({ identifier: 1, timestamp: -1 });
analyticsSchema.index({ createdAt: 1 }, { expireAfterSeconds: 90 * 24 * 60 * 60 }); // 90 days TTL

module.exports = mongoose.model('Analytics', analyticsSchema);