const jwt = require('jsonwebtoken');
require('dotenv').config(); // Load .env variables

const JWT_SECRET = process.env.JWT_SECRET;

function authenticateToken(allowedRoles = []) {
  return (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    // Log request details for debugging
    console.log(`[${req.method}] ${req.path} - Auth Header:`, authHeader);

    if (!token) {
      console.log('No token provided');
      return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    if (!JWT_SECRET) {
      console.error('JWT_SECRET is not defined in environment variables');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    try {
      // Verify token with JWT_SECRET from .env
      const decoded = jwt.verify(token, JWT_SECRET);
      console.log('Token Decoded:', decoded);

      // Check if role is required and matches
      if (allowedRoles.length && !allowedRoles.includes(decoded.role)) {
        console.log(`Unauthorized role: ${decoded.role}. Required: ${allowedRoles}`);
        return res.status(403).json({ error: 'Unauthorized role.' });
      }

      req.user = decoded;
      next();
    } catch (error) {
      console.error('Token Verification Error:', {
        name: error.name,
        message: error.message,
        tokenSnippet: token.substring(0, 10) + '...',
      });
      if (error.name === 'TokenExpiredError') {
        return res.status(403).json({ error: 'Token has expired.' });
      } else if (error.name === 'JsonWebTokenError') {
        return res.status(403).json({ error: 'Invalid token.' });
      }
      return res.status(403).json({ error: 'Token verification failed.' });
    }
  };
}

module.exports = authenticateToken;