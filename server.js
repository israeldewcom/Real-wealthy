require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Create directories if they don't exist
const uploadsDir = path.join(__dirname, 'uploads');
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });

// Custom logger
const logger = {
  info: (message) => console.log(`📘 INFO: ${message}`),
  error: (message) => console.error(`❌ ERROR: ${message}`),
  warn: (message) => console.warn(`⚠️ WARN: ${message}`),
  success: (message) => console.log(`✅ SUCCESS: ${message}`),
  debug: (message) => {
    if (process.env.NODE_ENV === 'development') {
      console.log(`🐛 DEBUG: ${message}`);
    }
  }
};

// Import middleware
const { protect, admin, requireKYC } = require('./src/middleware/auth');

const app = express();
const PORT = process.env.PORT || 10000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/raw-wealthy';

// Enhanced MongoDB connection with retry logic
const connectWithRetry = () => {
  mongoose.connect(MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
  })
  .then(() => {
    logger.success('MongoDB connected successfully');
  })
  .catch((err) => {
    logger.error(`MongoDB connection error: ${err.message}`);
    logger.warn('Retrying connection in 5 seconds...');
    setTimeout(connectWithRetry, 5000);
  });
};

// Connect to MongoDB
connectWithRetry();

// Request logger middleware
const requestLogger = (req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info(`${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`);
  });
  next();
};

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", "https://cdn.jsdelivr.net"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https://images.unsplash.com", "https://randomuser.me"],
      connectSrc: ["'self'", process.env.FRONTEND_URL || "http://localhost:3000"]
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:8080',
      'https://rawwealthy.com',
      'https://www.rawwealthy.com',
      'https://raw-wealthy.vercel.app'
    ];
    
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1 || process.env.NODE_ENV === 'development') {
      callback(null, true);
    } else {
      logger.warn(`CORS blocked for origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
  exposedHeaders: ['Content-Length', 'Content-Type', 'Authorization'],
  maxAge: 86400 // 24 hours
};

app.use(cors(corsOptions));

// Handle preflight requests
app.options('*', cors(corsOptions));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again after 15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  keyGenerator: (req) => {
    return req.headers['x-forwarded-for'] || req.ip || req.connection.remoteAddress;
  }
});

const authLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 login attempts per hour
  message: {
    success: false,
    message: 'Too many login attempts, please try again after an hour'
  }
});

// Apply rate limiting
app.use('/api/', apiLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api/auth/forgot-password', authLimiter);

// Body parsing middleware
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));
app.use(express.urlencoded({ 
  extended: true, 
  limit: '10mb',
  parameterLimit: 100
}));

// Compression
app.use(compression({
  level: 6,
  threshold: 100 * 1024 // Compress responses larger than 100KB
}));

// Logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
  app.use(requestLogger);
} else {
  app.use(morgan('combined', {
    skip: (req, res) => req.originalUrl === '/api/health'
  }));
}

// Static files
app.use('/uploads', express.static(uploadsDir, {
  maxAge: '1d',
  setHeaders: (res, path) => {
    if (path.endsWith('.png') || path.endsWith('.jpg') || path.endsWith('.jpeg')) {
      res.setHeader('Cache-Control', 'public, max-age=86400');
    }
  }
}));

// Debug endpoint for testing
app.get('/api/debug/routes', (req, res) => {
  const routes = [];
  const collectRoutes = (stack, prefix = '') => {
    stack.forEach((middleware) => {
      if (middleware.route) {
        const route = middleware.route;
        routes.push({
          path: prefix + route.path,
          methods: Object.keys(route.methods).filter(method => route.methods[method])
        });
      } else if (middleware.name === 'router' || middleware.name === 'bound dispatch') {
        let routerPath = '';
        if (middleware.handle && middleware.handle.stack) {
          routerPath = middleware.regexp ? middleware.regexp.source.replace('^\\/', '').replace('\\/?(?=\\/|$)', '') : '';
          collectRoutes(middleware.handle.stack, prefix + routerPath);
        }
      }
    });
  };
  
  collectRoutes(app._router.stack);
  res.json({ 
    success: true, 
    count: routes.length,
    routes: routes.sort((a, b) => a.path.localeCompare(b.path))
  });
});

// Database connection status endpoint
app.get('/api/database/status', (req, res) => {
  const status = mongoose.connection.readyState;
  const statusText = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting'
  }[status] || 'unknown';
  
  res.json({
    success: true,
    data: {
      status: statusText,
      readyState: status,
      dbName: mongoose.connection.name,
      host: mongoose.connection.host,
      port: mongoose.connection.port,
      models: mongoose.modelNames()
    }
  });
});

// Health check endpoint with detailed diagnostics
app.get('/api/health', (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    environment: process.env.NODE_ENV || 'development',
    nodeVersion: process.version,
    platform: process.platform,
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    databaseState: mongoose.connection.readyState,
    totalRequests: req.app.locals.requestCount || 0
  };
  
  res.status(200).json({
    success: true,
    message: 'Raw Wealthy Backend is running',
    data: health
  });
});

// Request counter middleware
app.use((req, res, next) => {
  if (!req.app.locals.requestCount) {
    req.app.locals.requestCount = 0;
  }
  req.app.locals.requestCount++;
  next();
});

// Import models
const models = [
  'User', 'InvestmentPlan', 'Investment', 'Transaction', 
  'Deposit', 'Withdrawal', 'KYC', 'SupportTicket', 
  'Referral', 'Notification', 'Wallet', 'AdminLog'
];

models.forEach(modelName => {
  try {
    require(`./src/models/${modelName}`);
    logger.debug(`Model loaded: ${modelName}`);
  } catch (error) {
    logger.error(`Failed to load model ${modelName}: ${error.message}`);
  }
});

// Import controllers
const authController = require('./src/controllers/authController');
const userController = require('./src/controllers/userController');
const investmentController = require('./src/controllers/investmentController');
const transactionController = require('./src/controllers/transactionController');
const depositController = require('./src/controllers/depositController');
const withdrawalController = require('./src/controllers/withdrawalController');
const kycController = require('./src/controllers/kycController');
const supportController = require('./src/controllers/supportController');
const referralController = require('./src/controllers/referralController');
const adminController = require('./src/controllers/adminController');
const walletController = require('./src/controllers/walletController');
const notificationController = require('./src/controllers/notificationController');

// ==================== AUTH ROUTES ====================
app.post('/api/auth/register', authController.register);
app.post('/api/auth/login', authController.login);
app.get('/api/auth/me', protect, authController.getMe);
app.post('/api/auth/forgot-password', authController.forgotPassword);
app.post('/api/auth/reset-password/:token', authController.resetPassword);
app.post('/api/auth/change-password', protect, authController.changePassword);
app.post('/api/auth/logout', protect, authController.logout);
app.post('/api/auth/two-factor/enable', protect, authController.enable2FA);
app.post('/api/auth/two-factor/verify', protect, authController.verify2FA);
app.post('/api/auth/two-factor/disable', protect, authController.disable2FA);
app.get('/api/auth/verify-email/:token', authController.verifyEmail);
app.post('/api/auth/verify-phone', protect, authController.verifyPhone);
app.post('/api/auth/resend-verification', authController.resendVerification);
app.post('/api/auth/refresh-token', authController.refreshToken);

// ==================== USER ROUTES ====================
app.get('/api/profile', protect, userController.getProfile);
app.put('/api/profile', protect, userController.updateProfile);
app.put('/api/profile/bank', protect, userController.updateBankDetails);
app.put('/api/profile/preferences', protect, userController.updatePreferences);
app.get('/api/dashboard', protect, userController.getDashboardData); // CRITICAL: Frontend expects this
app.get('/api/dashboard/stats', protect, userController.getDashboardStats);

// ==================== INVESTMENT ROUTES ====================
app.get('/api/plans', investmentController.getInvestmentPlans);
app.get('/api/plans/:id', investmentController.getInvestmentPlan);
app.get('/api/investments', protect, investmentController.getUserInvestments);
app.post('/api/investments', protect, investmentController.createInvestment);
app.get('/api/investments/:id', protect, investmentController.getInvestment);
app.post('/api/investments/:id/renew', protect, investmentController.renewInvestment);
app.post('/api/investments/:id/early-withdrawal', protect, investmentController.requestEarlyWithdrawal);
app.get('/api/investments/stats', protect, investmentController.getInvestmentStats);
app.get('/api/investments/active', protect, investmentController.getActiveInvestments); // Frontend uses this

// ==================== TRANSACTION ROUTES ====================
app.get('/api/transactions', protect, transactionController.getUserTransactions);
app.get('/api/transactions/:id', protect, transactionController.getTransaction);
app.get('/api/transactions/recent', protect, transactionController.getRecentTransactions); // Frontend uses this

// ==================== DEPOSIT ROUTES ====================
app.get('/api/deposits', protect, depositController.getUserDeposits);
app.post('/api/deposits', protect, depositController.createDeposit);
app.post('/api/deposits/:id/cancel', protect, depositController.cancelDeposit);

// ==================== WITHDRAWAL ROUTES ====================
app.get('/api/withdrawals', protect, withdrawalController.getUserWithdrawals);
app.post('/api/withdrawals', protect, withdrawalController.createWithdrawal);
app.post('/api/withdrawals/:id/cancel', protect, withdrawalController.cancelWithdrawal);

// ==================== KYC ROUTES ====================
app.get('/api/kyc/status', protect, kycController.getKYCStatus);
app.get('/api/kyc', protect, kycController.getKYC);
app.post('/api/kyc', protect, kycController.submitKYC);
app.get('/api/kyc/:id', protect, kycController.getKYCDetails);
app.put('/api/kyc/:id', protect, admin, kycController.updateKYC);

// ==================== SUPPORT ROUTES ====================
app.get('/api/support/tickets', protect, supportController.getUserTickets);
app.post('/api/support', protect, supportController.createTicket);
app.get('/api/support/tickets/:id', protect, supportController.getTicket);
app.post('/api/support/tickets/:id/reply', protect, supportController.addReply);
app.get('/api/support/faq', supportController.getFAQ);

// ==================== REFERRAL ROUTES ====================
app.get('/api/referrals/stats', protect, referralController.getReferralStats);
app.get('/api/referrals/list', protect, referralController.getReferralList);
app.get('/api/referrals/earnings', protect, referralController.getReferralEarnings);

// ==================== ADMIN ROUTES ====================
app.get('/api/admin/dashboard', protect, admin, adminController.getDashboardStats);
app.get('/api/admin/users', protect, admin, adminController.getUsers);
app.get('/api/admin/users/:id', protect, admin, adminController.getUser);
app.put('/api/admin/users/:id', protect, admin, adminController.updateUser);
app.post('/api/admin/users/:id/adjust-balance', protect, admin, adminController.adjustUserBalance);
app.post('/api/admin/users/:id/status', protect, admin, adminController.toggleUserStatus);
app.get('/api/admin/pending-investments', protect, admin, adminController.getPendingInvestments);
app.post('/api/admin/investments/:id/approve', protect, admin, adminController.approveInvestment);
app.post('/api/admin/investments/:id/reject', protect, admin, adminController.rejectInvestment);
app.get('/api/admin/pending-deposits', protect, admin, adminController.getPendingDeposits);
app.post('/api/admin/deposits/:id/approve', protect, admin, adminController.approveDeposit);
app.post('/api/admin/deposits/:id/reject', protect, admin, adminController.rejectDeposit);
app.get('/api/admin/pending-withdrawals', protect, admin, adminController.getPendingWithdrawals);
app.post('/api/admin/withdrawals/:id/approve', protect, admin, adminController.approveWithdrawal);
app.post('/api/admin/withdrawals/:id/reject', protect, admin, adminController.rejectWithdrawal);
app.get('/api/admin/pending-kyc', protect, admin, adminController.getPendingKYC);
app.post('/api/admin/kyc/:id/approve', protect, admin, adminController.approveKYC);
app.post('/api/admin/kyc/:id/reject', protect, admin, adminController.rejectKYC);
app.post('/api/admin/notifications/send', protect, admin, adminController.sendNotification);
app.get('/api/admin/logs', protect, admin, adminController.getAdminLogs);
app.get('/api/admin/analytics', protect, admin, adminController.getAnalytics);

// ==================== WALLET ROUTES ====================
app.get('/api/wallet', protect, walletController.getWallet);
app.post('/api/wallet/transfer', protect, walletController.transferFunds);
app.get('/api/wallet/transactions', protect, walletController.getWalletTransactions);

// ==================== NOTIFICATION ROUTES ====================
app.get('/api/notifications', protect, notificationController.getNotifications);
app.post('/api/notifications/:id/read', protect, notificationController.markAsRead);
app.delete('/api/notifications/:id', protect, notificationController.deleteNotification);
app.get('/api/notifications/unread-count', protect, notificationController.getUnreadCount);

// ==================== FILE UPLOAD ROUTE ====================
const multer = require('multer');
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const folder = req.body.folder || 'general';
    const uploadPath = path.join(uploadsDir, folder);
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    const name = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9]/g, '-');
    cb(null, name + '-' + uniqueSuffix + ext);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|pdf|doc|docx/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error('Error: File type not supported. Only images (JPEG, PNG) and documents (PDF, DOC) are allowed.'));
  }
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB
  }
});

app.post('/api/upload', protect, upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        success: false,
        message: 'No file uploaded or file type not supported'
      });
    }

    const folder = req.body.folder || 'general';
    const fileUrl = `/uploads/${folder}/${req.file.filename}`;

    logger.info(`File uploaded: ${req.file.originalname} -> ${fileUrl}`);

    res.json({
      success: true,
      message: 'File uploaded successfully',
      data: {
        fileUrl: fileUrl,
        filename: req.file.filename,
        originalname: req.file.originalname,
        size: req.file.size,
        mimetype: req.file.mimetype,
        path: req.file.path
      }
    });
  } catch (error) {
    logger.error(`File upload error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Failed to upload file',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Multiple file upload
app.post('/api/upload/multiple', protect, upload.array('files', 5), (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No files uploaded'
      });
    }

    const folder = req.body.folder || 'general';
    const files = req.files.map(file => ({
      fileUrl: `/uploads/${folder}/${file.filename}`,
      filename: file.filename,
      originalname: file.originalname,
      size: file.size,
      mimetype: file.mimetype
    }));

    logger.info(`${files.length} files uploaded to ${folder}`);

    res.json({
      success: true,
      message: 'Files uploaded successfully',
      data: { files }
    });
  } catch (error) {
    logger.error(`Multiple file upload error: ${error.message}`);
    res.status(500).json({
      success: false,
      message: 'Failed to upload files'
    });
  }
});

// ==================== PUBLIC ROUTES ====================
app.get('/api/public/plans', investmentController.getPublicPlans);
app.get('/api/public/stats', (req, res) => {
  res.json({
    success: true,
    data: {
      total_invested: 2500000000,
      active_investors: 15240,
      user_rating: 4.9,
      total_returns: 350000000,
      platform_earnings: 75000000
    }
  });
});

// ==================== ANALYTICS ROUTE ====================
app.post('/api/analytics/track', (req, res) => {
  try {
    const { event, userId, sessionId, properties } = req.body;
    
    // Log analytics event (in production, send to analytics service)
    logger.debug(`Analytics event: ${event} from user ${userId}`);
    
    res.json({
      success: true,
      message: 'Event tracked'
    });
  } catch (error) {
    res.json({
      success: true,
      message: 'Event tracking failed but request continues'
    });
  }
});

// ==================== BACKUP ROUTES (for frontend compatibility) ====================
// These routes ensure frontend never gets 404 errors
app.get('/api/investments?*', protect, investmentController.getUserInvestments);
app.get('/api/transactions?*', protect, transactionController.getUserTransactions);
app.get('/api/deposits?*', protect, depositController.getUserDeposits);
app.get('/api/withdrawals?*', protect, withdrawalController.getUserWithdrawals);
app.get('/api/support?*', protect, supportController.getUserTickets);

// ==================== SYSTEM INFO ====================
app.get('/api/system/info', protect, admin, (req, res) => {
  res.json({
    success: true,
    data: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      memory: process.memoryUsage(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV,
      database: {
        connected: mongoose.connection.readyState === 1,
        host: mongoose.connection.host,
        name: mongoose.connection.name,
        collections: mongoose.connection.collections ? Object.keys(mongoose.connection.collections) : []
      },
      server: {
        port: PORT,
        uploadsDir: uploadsDir,
        requestCount: req.app.locals.requestCount || 0
      }
    }
  });
});

// ==================== 404 HANDLER ====================
app.use('/api/*', (req, res) => {
  logger.warn(`Route not found: ${req.method} ${req.originalUrl}`);
  
  // Provide helpful error message
  res.status(404).json({
    success: false,
    message: `API route ${req.originalUrl} not found`,
    suggestions: [
      'Check the URL for typos',
      'Ensure you have the correct HTTP method',
      'Verify your authentication token',
      'See /api/debug/routes for available endpoints'
    ],
    requestedUrl: req.originalUrl,
    method: req.method,
    timestamp: new Date().toISOString()
  });
});

// ==================== ERROR HANDLING MIDDLEWARE ====================
app.use((err, req, res, next) => {
  logger.error(`Error: ${err.message}`);
  logger.error(`Stack: ${err.stack}`);
  
  // Log error to file
  const errorLog = {
    timestamp: new Date().toISOString(),
    method: req.method,
    url: req.originalUrl,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    userId: req.user ? req.user.id : 'anonymous',
    error: {
      message: err.message,
      stack: err.stack,
      name: err.name
    }
  };
  
  // Save to error log file
  const errorLogPath = path.join(logsDir, 'errors.json');
  fs.readFile(errorLogPath, 'utf8', (readErr, data) => {
    const errors = data ? JSON.parse(data) : [];
    errors.push(errorLog);
    fs.writeFile(errorLogPath, JSON.stringify(errors, null, 2), (writeErr) => {
      if (writeErr) logger.error(`Failed to write error log: ${writeErr.message}`);
    });
  });
  
  // Multer errors
  if (err instanceof multer.MulterError) {
    return res.status(400).json({
      success: false,
      message: `File upload error: ${err.message}`
    });
  }
  
  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      message: 'Invalid authentication token'
    });
  }
  
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      success: false,
      message: 'Authentication token expired'
    });
  }
  
  // MongoDB errors
  if (err.name === 'MongoError' || err.name === 'MongoServerError') {
    let message = 'Database error occurred';
    
    if (err.code === 11000) {
      const field = Object.keys(err.keyPattern)[0];
      message = `${field} already exists`;
    }
    
    return res.status(400).json({
      success: false,
      message
    });
  }
  
  // Validation errors
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(e => e.message);
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: messages
    });
  }
  
  // Default error
  const statusCode = err.status || err.statusCode || 500;
  res.status(statusCode).json({
    success: false,
    message: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { 
      stack: err.stack,
      fullError: err.toString() 
    })
  });
});

// ==================== START SERVER ====================
const server = app.listen(PORT, '0.0.0.0', () => {
  const address = server.address();
  const host = address.address === '::' ? 'localhost' : address.address;
  
  console.log('='.repeat(60));
  console.log('🚀 RAW WEALTHY INVESTMENT PLATFORM BACKEND');
  console.log('='.repeat(60));
  console.log(`📡 Server running on: http://${host}:${PORT}`);
  console.log(`🏷️  Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🗄️  Database: ${mongoose.connection.readyState === 1 ? '✅ Connected' : '❌ Disconnected'}`);
  console.log(`📁 Uploads directory: ${uploadsDir}`);
  console.log(`📊 Logs directory: ${logsDir}`);
  console.log('='.repeat(60));
  console.log('🔗 Essential Endpoints:');
  console.log(`   ✅ Health Check: http://${host}:${PORT}/api/health`);
  console.log(`   ✅ Debug Routes: http://${host}:${PORT}/api/debug/routes`);
  console.log(`   ✅ Database Status: http://${host}:${PORT}/api/database/status`);
  console.log(`   ✅ System Info: http://${host}:${PORT}/api/system/info (admin only)`);
  console.log('='.repeat(60));
  console.log('📋 Available API Categories:');
  console.log('   🔐 Authentication (11 routes)');
  console.log('   👤 User Management (6 routes)');
  console.log('   📈 Investments (9 routes)');
  console.log('   💰 Transactions (6 routes)');
  console.log('   🏦 Deposits/Withdrawals (8 routes)');
  console.log('   📝 KYC Verification (5 routes)');
  console.log('   🆘 Support System (5 routes)');
  console.log('   👥 Referral System (3 routes)');
  console.log('   👑 Admin Dashboard (20+ routes)');
  console.log('   💼 Wallet Management (3 routes)');
  console.log('   🔔 Notifications (4 routes)');
  console.log('   📤 File Upload (2 routes)');
  console.log('='.repeat(60));
  console.log('⚠️  Important: Ensure frontend CORS origin is properly configured');
  console.log('   Allowed origins:', corsOptions.origin);
  console.log('='.repeat(60));
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.info('SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    logger.info('HTTP server closed');
    mongoose.connection.close(false, () => {
      logger.info('MongoDB connection closed');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  logger.info('SIGINT received. Shutting down gracefully...');
  server.close(() => {
    logger.info('HTTP server closed');
    mongoose.connection.close(false, () => {
      logger.info('MongoDB connection closed');
      process.exit(0);
    });
  });
});

// Unhandled promise rejection handler
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Uncaught exception handler
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

// Export for testing
module.exports = app;
