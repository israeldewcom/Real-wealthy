const jwt = require('jsonwebtoken');
const User = require('../models/User');

// Protect routes
exports.protect = async (req, res, next) => {
  try {
    let token;

    // Get token from header or cookie
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.token) {
      token = req.cookies.token;
    }

    // Check if token exists
    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Not authorized to access this route'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Get user from token
    const user = await User.findById(decoded.id).select('-password');

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found'
      });
    }

    // Check if user is active
    if (!user.is_active) {
      return res.status(403).json({
        success: false,
        message: 'Account is deactivated. Please contact support.'
      });
    }

    // Check if user needs to verify email
    if (!user.is_email_verified) {
      return res.status(403).json({
        success: false,
        message: 'Please verify your email address'
      });
    }

    // Set user in request
    req.user = user;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token'
      });
    }

    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token expired'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Authentication error'
    });
  }
};

// Grant access to specific roles
exports.authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: `User role ${req.user.role} is not authorized to access this route`
      });
    }
    next();
  };
};

// Check KYC status
exports.requireKYC = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (user.kyc_status !== 'verified') {
      return res.status(403).json({
        success: false,
        message: 'KYC verification required to access this feature'
      });
    }
    
    next();
  } catch (error) {
    console.error('KYC middleware error:', error);
    res.status(500).json({
      success: false,
      message: 'KYC verification error'
    });
  }
};

// Check minimum balance
exports.checkBalance = (requiredAmount) => {
  return async (req, res, next) => {
    try {
      const user = await User.findById(req.user.id);
      
      if (user.balance < requiredAmount) {
        return res.status(400).json({
          success: false,
          message: `Insufficient balance. Required: ${requiredAmount}, Available: ${user.balance}`
        });
      }
      
      next();
    } catch (error) {
      console.error('Balance check error:', error);
      res.status(500).json({
        success: false,
        message: 'Balance verification error'
      });
    }
  };
};

// IP whitelist for admin routes
exports.ipWhitelist = (allowedIPs) => {
  return (req, res, next) => {
    const clientIP = req.ip || req.connection.remoteAddress;
    
    if (!allowedIPs.includes(clientIP)) {
      return res.status(403).json({
        success: false,
        message: 'Access denied from this IP address'
      });
    }
    
    next();
  };
};

// Rate limiting per user
exports.userRateLimit = (maxRequests, windowMs) => {
  const requests = new Map();
  
  return (req, res, next) => {
    const userId = req.user ? req.user.id : req.ip;
    const now = Date.now();
    
    if (!requests.has(userId)) {
      requests.set(userId, []);
    }
    
    const userRequests = requests.get(userId);
    
    // Remove old requests
    const windowStart = now - windowMs;
    const validRequests = userRequests.filter(time => time > windowStart);
    
    if (validRequests.length >= maxRequests) {
      return res.status(429).json({
        success: false,
        message: 'Too many requests. Please try again later.'
      });
    }
    
    validRequests.push(now);
    requests.set(userId, validRequests);
    
    // Cleanup old entries (optional, to prevent memory leak)
    setTimeout(() => {
      const currentTime = Date.now();
      for (const [key, times] of requests.entries()) {
        const valid = times.filter(time => time > currentTime - windowMs);
        if (valid.length === 0) {
          requests.delete(key);
        } else {
          requests.set(key, valid);
        }
      }
    }, windowMs);
    
    next();
  };
};
