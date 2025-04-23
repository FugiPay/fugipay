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

const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) throw new Error('JWT_SECRET is required');

module.exports = (roles = []) => (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.error('[AUTH] No token provided');
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('[AUTH] Token error:', err.message);
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    req.user = user;

    if (roles.length && !roles.includes(user.role)) {
      console.error('[AUTH] Role denied:', user.role, roles);
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  });

  jwt.verify(token, JWT_SECRET, (err, business) => {
    if (err) {
      console.error('[AUTH] Token error:', err.message);
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    req.business = business;

    if (roles.length && !roles.includes(business.role)) {
      console.error('[AUTH] Role denied:', business.role, roles);
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    next();
  });
};