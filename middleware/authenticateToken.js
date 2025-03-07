const jwt = require('jsonwebtoken');

// Replace with your own secret key (store in environment variables in production)
const JWT_SECRET = process.env.JWT_SECRET || 'Zangena123$@2025';

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Expected format: "Bearer <token>"

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // Attach decoded user data (e.g., { username, role })
    next();
  } catch (error) {
    console.error('Token Verification Error:', error);
    return res.status(403).json({ error: 'Invalid or expired token.' });
  }
}

module.exports = authenticateToken;