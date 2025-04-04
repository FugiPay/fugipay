const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'Zangena123$@2025';

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token Verification Error:', error);
    return res.status(403).json({ error: 'Invalid or expired token.' });
  }
}

module.exports = authenticateToken;