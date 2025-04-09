const jwt = require('jsonwebtoken');

// JWT_SECRET should match what's set in Heroku config vars
const JWT_SECRET = process.env.JWT_SECRET || 'Zangena123$@2025$$';

function authenticateToken(allowedRoles = []) {
  return (req, res, next) => {
    const start = Date.now();
    const authHeader = req.headers['authorization'];
    const logPrefix = `[${req.method}] ${req.path}`;

    console.log(`${logPrefix} - AuthenticateToken Start - Auth Header:`, authHeader || 'None');

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      console.log(`${logPrefix} - No valid Bearer token provided`);
      return res.status(401).json({ error: 'Access denied. No valid token provided.' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      console.log(`${logPrefix} - Token missing after Bearer`);
      return res.status(401).json({ error: 'Access denied. Token missing.' });
    }

    if (!JWT_SECRET) {
      console.error(`${logPrefix} - JWT_SECRET not configured`);
      return res.status(500).json({ error: 'Server configuration error: JWT_SECRET missing' });
    }

    try {
      console.time(`${logPrefix} - JWT Verify`);
      const decoded = jwt.verify(token, JWT_SECRET);
      console.timeEnd(`${logPrefix} - JWT Verify`);
      console.log(`${logPrefix} - Token Decoded:`, {
        phoneNumber: decoded.phoneNumber,
        role: decoded.role,
        username: decoded.username,
      });

      // Role check: if allowedRoles is empty, all roles are allowed
      if (allowedRoles.length && !allowedRoles.includes(decoded.role)) {
        console.log(`${logPrefix} - Role not allowed: ${decoded.role} (Allowed: ${allowedRoles})`);
        return res.status(403).json({ error: `Unauthorized role: ${decoded.role}` });
      }

      req.user = decoded;
      console.log(`${logPrefix} - AuthenticateToken Completed in ${Date.now() - start}ms`);
      next();
    } catch (error) {
      console.error(`${logPrefix} - Token Verification Error:`, {
        name: error.name,
        message: error.message,
      });

      if (error.name === 'TokenExpiredError') {
        return res.status(403).json({ error: 'Token expired', expiredAt: error.expiredAt });
      }
      if (error.name === 'JsonWebTokenError') {
        return res.status(403).json({ error: 'Invalid token', details: error.message });
      }
      return res.status(403).json({ error: 'Token verification failed', details: error.message });
    }
  };
}

module.exports = authenticateToken;