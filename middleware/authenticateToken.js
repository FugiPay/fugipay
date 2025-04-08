const jwt = require('jsonwebtoken');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;

function authenticateToken(allowedRoles = []) {
  return (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    console.log(`[${req.method}] ${req.path} - Auth Header:`, authHeader);

    if (!token) return res.status(401).json({ error: 'Access denied. No token provided.' });
    if (!JWT_SECRET) return res.status(500).json({ error: 'Server configuration error' });

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      console.log('Token Decoded:', decoded);
      if (allowedRoles.length && !allowedRoles.includes(decoded.role)) {
        return res.status(403).json({ error: 'Unauthorized role.' });
      }
      req.user = decoded;
      next();
    } catch (error) {
      console.error('Token Error:', error.name, error.message);
      return res.status(403).json({ error: error.name === 'TokenExpiredError' ? 'Token expired.' : 'Invalid token.' });
    }
  };
}

module.exports = authenticateToken;