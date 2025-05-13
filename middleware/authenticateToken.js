/* const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'Zangena123$@2025';

module.exports = (roles = []) => (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });

    req.user = user;

    if (roles.length && !roles.includes(user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  });
}; */
/* 
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'Zangena123$@2025'; // Fallback for development

// Log warning if JWT_SECRET is missing (avoid crashing in production)
if (!process.env.JWT_SECRET) {
  console.warn('[AUTH] JWT_SECRET is not set. Using default fallback (unsafe for production).');
}

module.exports = (roles = []) => (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.error('[AUTH] No token provided');
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) {
      console.error('[AUTH] Token verification failed:', err.message);
      return res.status(403).json({
        error: err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token',
      });
    }

    // Attach payload to req.user for consistency across user, business, and admin routes
    req.user = payload;

    // Validate role if roles are specified
    if (roles.length && !roles.includes(payload.role)) {
      console.error('[AUTH] Role denied:', payload.role, 'Expected:', roles);
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  });
}; */

const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'Zangena123$@2025'; // Fallback for development

// Log warning if JWT_SECRET is missing
if (!process.env.JWT_SECRET) {
  console.warn('[AUTH] JWT_SECRET is not set. Using default fallback (unsafe for production).');
}

module.exports = (roles = []) => (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.error('[AUTH] No token provided');
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) {
      console.error('[AUTH] Token verification failed:', err.message);
      return res.status(403).json({
        error: err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token',
      });
    }

    console.log('[AUTH] Decoded payload:', payload); // Log payload for debugging

    // Validate payload for business routes
    if (roles.includes('business') && (!payload.businessId || !/^\d{10}$/.test(payload.businessId))) {
      console.error('[AUTH] Invalid businessId in token:', payload.businessId);
      return res.status(403).json({ error: 'Invalid business ID in token' });
    }

    // Attach payload to req.user
    req.user = payload;

    // Validate role
    if (roles.length && !roles.includes(payload.role)) {
      console.error('[AUTH] Role denied:', payload.role, 'Expected:', roles);
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  });
};