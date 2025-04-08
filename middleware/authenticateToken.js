const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'Zangena123$@2025';

function authenticateToken(allowedRoles = []) {
  return (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      console.log('No token provided in request:', req.path);
      return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
      console.log('Verifying token with JWT_SECRET:', JWT_SECRET);
      const decoded = jwt.verify(token, JWT_SECRET);
      console.log('Decoded Token:', decoded);

      if (allowedRoles.length && !allowedRoles.includes(decoded.role)) {
        console.log(`Role ${decoded.role} not in allowed roles: ${allowedRoles}`);
        return res.status(403).json({ error: 'Unauthorized role.' });
      }

      req.user = decoded;
      next();
    } catch (error) {
      console.error('Token Verification Error:', {
        name: error.name,
        message: error.message,
        token: token.substring(0, 10) + '...', // Partial token for debugging
      });
      return res.status(403).json({ error: 'Invalid or expired token.' });
    }
  };
}

module.exports = authenticateToken;