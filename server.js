const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const dotenv = require('dotenv');
const http = require('http');
const socketIo = require('socket.io');
const cron = require('node-cron');
const path = require('path');

// Load environment variables
dotenv.config();

// Import routes - CORRECTED PATHS (server.js is outside src folder)
const authRoutes = require('./src/routes/authRoutes');
const userRoutes = require('./src/routes/userRoutes');
const investmentRoutes = require('./src/routes/investmentRoutes');
const transactionRoutes = require('./src/routes/transactionRoutes');
const depositRoutes = require('./src/routes/depositRoutes');
const withdrawalRoutes = require('./src/routes/withdrawalRoutes');
const kycRoutes = require('./src/routes/kycRoutes');
const supportRoutes = require('./src/routes/supportRoutes');
const referralRoutes = require('./src/routes/referralRoutes');
const adminRoutes = require('./src/routes/adminRoutes');
const walletRoutes = require('./src/routes/walletRoutes');
const notificationRoutes = require('./src/routes/notificationRoutes');

// Import middleware
const errorHandler = require('./src/middleware/errorHandler');
const { notFound } = require('./src/middleware/errorHandler');

// Import database connection
const connectDB = require('./src/config/database');

// Import jobs
const { startCronJobs } = require('./src/jobs/cronJobs');

// Import socket server
const setupSocketServer = require('./src/sockets/socketServer');

// Initialize Express app
const app = express();
const server = http.createServer(app);

// Initialize Socket.io
const io = socketIo(server, {
  cors: {
    origin: process.env.FRONTEND_URL || '*',
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Setup Socket Server
setupSocketServer(io);

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:", "http:", "blob:"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"]
    }
  }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: process.env.NODE_ENV === 'production' ? 100 : 1000, // Limit per IP
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true
});

app.use('/api/', limiter);

// CORS configuration
const corsOptions = {
  origin: process.env.FRONTEND_URL || '*',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
};

app.use(cors(corsOptions));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Data sanitization against NoSQL injection
app.use(mongoSanitize());

// Compression
app.use(compression());

// Logging
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined'));
}

// Static files - UPDATED PATH for Render
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Health check endpoint for Render
app.get('/api/health', (req, res) => {
  res.status(200).json({
    status: 'success',
    message: 'Raw Wealthy Backend is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV,
    version: process.env.npm_package_version || '1.0.0',
    nodeVersion: process.version
  });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/investments', investmentRoutes);
app.use('/api/transactions', transactionRoutes);
app.use('/api/deposits', depositRoutes);
app.use('/api/withdrawals', withdrawalRoutes);
app.use('/api/kyc', kycRoutes);
app.use('/api/support', supportRoutes);
app.use('/api/referrals', referralRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/wallets', walletRoutes);
app.use('/api/notifications', notificationRoutes);

// File upload endpoint - CORRECTED PATH
const fileUploadMiddleware = require('./src/middleware/fileUpload');
app.post('/api/upload', fileUploadMiddleware.upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({
      success: false,
      message: 'No file uploaded'
    });
  }
  
  res.json({
    success: true,
    message: 'File uploaded successfully',
    data: {
      fileUrl: `/uploads/${req.file.filename}`,
      filename: req.file.filename,
      originalname: req.file.originalname,
      size: req.file.size,
      mimetype: req.file.mimetype
    }
  });
});

// 404 handler
app.use(notFound);

// Error handling middleware
app.use(errorHandler);

// Database connection with enhanced error handling
connectDB()
  .then(() => {
    console.log('✅ MongoDB connected successfully');
    
    // Start cron jobs after DB connection
    try {
      startCronJobs();
      console.log('✅ Cron jobs initialized');
    } catch (cronError) {
      console.warn('⚠️ Cron jobs initialization failed:', cronError.message);
    }
    
    const PORT = process.env.PORT || 10000;
    
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📁 Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🌐 Frontend URL: ${process.env.FRONTEND_URL || 'Not set'}`);
      console.log(`🔗 Health check: http://0.0.0.0:${PORT}/api/health`);
    });
  })
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err);
    
    // Even if DB fails, start server for health checks
    const PORT = process.env.PORT || 10000;
    server.listen(PORT, '0.0.0.0', () => {
      console.log(`⚠️ Server started without DB on port ${PORT}`);
      console.log(`❌ DB Connection failed: ${err.message}`);
    });
  });

// Graceful shutdown handlers
process.on('SIGTERM', () => {
  console.log('👋 SIGTERM received. Shutting down gracefully...');
  
  // Close server first
  server.close(() => {
    console.log('💤 HTTP server closed');
    
    // Close MongoDB connection
    mongoose.connection.close(false, () => {
      console.log('💤 MongoDB connection closed');
      process.exit(0);
    });
  });
  
  // Force exit after 10 seconds
  setTimeout(() => {
    console.error('⏰ Force shutdown after timeout');
    process.exit(1);
  }, 10000);
});

process.on('SIGINT', () => {
  console.log('👋 SIGINT received. Shutting down gracefully...');
  server.close(() => {
    console.log('💤 Process terminated!');
    process.exit(0);
  });
});

// Global error handlers
process.on('unhandledRejection', (err) => {
  console.error('🔥 Unhandled Rejection:', err);
});

process.on('uncaughtException', (err) => {
  console.error('💥 Uncaught Exception:', err);
  server.close(() => {
    process.exit(1);
  });
});

// Export for testing
module.exports = { app, server };
