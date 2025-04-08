const jwt = require('jsonwebtoken');
require('dotenv').config();

// Use the same fallback as api.js for consistency; ideally, this should be centralized
const JWT_SECRET = process.env.JWT_SECRET || 'Zangena123$@2025';

function authenticateToken(allowedRoles = []) {
  return (req, res, next) => {
    const start = Date.now(); // Track execution time
    const authHeader = req.headers['authorization'];

    // Log incoming request details
    console.log(`[${req.method}] ${req.path} - AuthenticateToken Start - Auth Header:`, authHeader || 'None');

    // Check for token presence
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      console.log(`[${req.method}] ${req.path} - No valid Bearer token provided`);
      return res.status(401).json({ error: 'Access denied. No valid token provided.' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      console.log(`[${req.method}] ${req.path} - Token missing after Bearer`);
      return res.status(401).json({ error: 'Access denied. Token missing.' });
    }

    // Ensure JWT_SECRET is available
    if (!JWT_SECRET) {
      console.error(`[${req.method}] ${req.path} - JWT_SECRET not configured`);
      return res.status(500).json({ error: 'Server configuration error: JWT_SECRET missing' });
    }

    try {
      // Verify token
      console.time(`[${req.method}] ${req.path} - JWT Verify`);
      const decoded = jwt.verify(token, JWT_SECRET);
      console.timeEnd(`[${req.method}] ${req.path} - JWT Verify`);
      console.log(`[${req.method}] ${req.path} - Token Decoded:`, {
        phoneNumber: decoded.phoneNumber,
        role: decoded.role,
        username: decoded.username,
      });

      // Role-based access control
      if (allowedRoles.length && !allowedRoles.includes(decoded.role)) {
        console.log(`[${req.method}] ${req.path} - Role not allowed: ${decoded.role} (Allowed: ${allowedRoles})`);
        return res.status(403).json({ error: `Unauthorized role: ${decoded.role}` });
      }

      // Attach decoded user to request
      req.user = decoded;

      // Log completion time
      console.log(`[${req.method}] ${req.path} - AuthenticateToken Completed in ${Date.now() - start}ms`);
      next();
    } catch (error) {
      console.error(`[${req.method}] ${req.path} - Token Verification Error:`, {
        name: error.name,
        message: error.message,
        stack: error.stack,
      });

      // Handle specific JWT errors
      if (error.name === 'TokenExpiredError') {
        return res.status(403).json({ error: 'Token expired', expiredAt: error.expiredAt });
      } else if (error.name === 'JsonWebTokenError') {
        return res.status(403).json({ error: 'Invalid token', details: error.message });
      } else {
        return res.status(403).json({ error: 'Token verification failed', details: error.message });
      }
    }
  };
}

module.exports = authenticateToken;