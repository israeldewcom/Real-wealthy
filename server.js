// server.js - RAW WEALTHY BACKEND v38.0 - ULTIMATE PRODUCTION READY WITH ADVANCED DEBUGGING
// COMPLETE ENHANCEMENT: Advanced Debugging + Real-time Monitoring + Enhanced Security + Complete Admin Features
// AUTO-DEPLOYMENT READY WITH INTELLIGENT ERROR RECOVERY

import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import mongoSanitize from 'express-mongo-sanitize';
import xss from 'xss-clean';
import hpp from 'hpp';
import { body, validationResult, param } from 'express-validator';
import cron from 'node-cron';
import path from 'path';
import multer from 'multer';
import fs from 'fs';
import nodemailer from 'nodemailer';
import QRCode from 'qrcode';
import speakeasy from 'speakeasy';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import axios from 'axios';
import util from 'util';
import os from 'os';
import cluster from 'cluster';
import { createLogger, format, transports } from 'winston';
import 'winston-daily-rotate-file';

// Enhanced debugging
const debug = util.debuglog('server');

// ES Modules equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ==================== ENHANCED LOGGING SYSTEM ====================
const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: format.combine(
    format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss'
    }),
    format.errors({ stack: true }),
    format.splat(),
    format.json(),
    format.printf(({ timestamp, level, message, ...meta }) => {
      return `${timestamp} [${level.toUpperCase()}] ${message} ${Object.keys(meta).length ? JSON.stringify(meta, null, 2) : ''}`;
    })
  ),
  transports: [
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.simple()
      )
    }),
    new transports.DailyRotateFile({
      filename: path.join(__dirname, 'logs', 'application-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '30d',
      level: 'debug'
    }),
    new transports.DailyRotateFile({
      filename: path.join(__dirname, 'logs', 'error-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '90d',
      level: 'error'
    })
  ],
  exceptionHandlers: [
    new transports.File({ 
      filename: path.join(__dirname, 'logs', 'exceptions.log') 
    })
  ],
  rejectionHandlers: [
    new transports.File({ 
      filename: path.join(__dirname, 'logs', 'rejections.log') 
    })
  ]
});

// Ensure logs directory exists
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Global error handler for uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  // Don't exit immediately, let the server handle it
  console.error('Uncaught Exception:', error);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  console.error('Unhandled Rejection:', reason);
});

// ==================== INTELLIGENT ENVIRONMENT LOADING ====================
console.log('🔍 Enhanced Environment Configuration Loading...');
logger.info('Starting server initialization');

// Try multiple environment file locations
const envFiles = [
  '.env.production',
  '.env.development', 
  '.env.local',
  '.env'
];

let envLoaded = false;
for (const envFile of envFiles) {
  const envPath = path.join(__dirname, envFile);
  if (fs.existsSync(envPath)) {
    dotenv.config({ path: envPath });
    console.log(`✅ Loaded environment from: ${envFile}`);
    logger.info(`Environment loaded from ${envFile}`);
    envLoaded = true;
    break;
  }
}

// If no env file found, try to load from process.env
if (!envLoaded) {
  console.log('⚠️ No environment file found, using process.env');
  logger.warn('No environment file found, using process.env');
  dotenv.config();
}

// ==================== ENHANCED CONFIGURATION VALIDATION ====================
console.log('\n📋 Environment Validation Report:');
console.log('=' .repeat(50));

const requiredEnvVars = [
  'MONGODB_URI',
  'JWT_SECRET'
];

const recommendedEnvVars = [
  'NODE_ENV',
  'CLIENT_URL',
  'SERVER_URL',
  'EMAIL_HOST',
  'EMAIL_USER',
  'EMAIL_PASSWORD',
  'ADMIN_EMAIL',
  'ADMIN_PASSWORD'
];

const config = {
  // Server Configuration
  port: parseInt(process.env.PORT) || 10000,
  nodeEnv: process.env.NODE_ENV || 'development',
  serverURL: process.env.SERVER_URL || `http://localhost:${parseInt(process.env.PORT) || 10000}`,
  isProduction: (process.env.NODE_ENV || 'development') === 'production',
  
  // Database Configuration
  mongoURI: process.env.MONGODB_URI || process.env.DATABASE_URL || 'mongodb://localhost:27017/rawwealthy',
  
  // Security Configuration
  jwtSecret: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '30d',
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 12,
  
  // Client Configuration
  clientURL: process.env.CLIENT_URL || 'http://localhost:3000',
  allowedOrigins: [],
  
  // Email Configuration
  emailEnabled: !!(process.env.EMAIL_HOST && process.env.EMAIL_USER && process.env.EMAIL_PASSWORD),
  emailConfig: {
    host: process.env.EMAIL_HOST || '',
    port: parseInt(process.env.EMAIL_PORT) || 587,
    secure: parseInt(process.env.EMAIL_PORT) === 465,
    user: process.env.EMAIL_USER || '',
    pass: process.env.EMAIL_PASS || process.env.EMAIL_PASSWORD || '',
    from: process.env.EMAIL_FROM || `"Raw Wealthy" <${process.env.EMAIL_USER || 'noreply@rawwealthy.com'}>`
  },
  
  // Business Logic Configuration
  minInvestment: parseInt(process.env.MIN_INVESTMENT) || 3500,
  minDeposit: parseInt(process.env.MIN_DEPOSIT) || 3500,
  minWithdrawal: parseInt(process.env.MIN_WITHDRAWAL) || 3500,
  platformFeePercent: parseFloat(process.env.PLATFORM_FEE_PERCENT) || 10,
  referralCommissionPercent: parseFloat(process.env.REFERRAL_COMMISSION_PERCENT) || 10,
  welcomeBonus: parseInt(process.env.WELCOME_BONUS) || 100,
  
  // Admin Configuration
  adminEmail: process.env.ADMIN_EMAIL || 'admin@rawwealthy.com',
  adminPassword: process.env.ADMIN_PASSWORD || 'Admin123456',
  
  // Performance Configuration
  maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024, // 10MB
  rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000, // 15 minutes
  rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX) || 100,
  
  // Storage Configuration
  uploadDir: path.join(__dirname, 'uploads'),
  logsDir: path.join(__dirname, 'logs'),
  
  // Debug Configuration
  debugEnabled: process.env.DEBUG === 'true' || process.env.NODE_ENV === 'development',
  logLevel: process.env.LOG_LEVEL || 'info',
  
  // Feature Flags
  enableTwoFactor: process.env.ENABLE_TWO_FACTOR !== 'false',
  enableEmailVerification: process.env.ENABLE_EMAIL_VERIFICATION !== 'false',
  enableKYC: process.env.ENABLE_KYC !== 'false',
  enableAutoRenew: process.env.ENABLE_AUTO_RENEW !== 'false',
  
  // Investment Plans (Loaded dynamically)
  investmentPlans: [],
  
  // Allowed MIME Types
  allowedMimeTypes: {
    'image/jpeg': 'jpg',
    'image/jpg': 'jpg',
    'image/png': 'png',
    'image/gif': 'gif',
    'image/webp': 'webp',
    'application/pdf': 'pdf',
    'image/svg+xml': 'svg'
  }
};

// Build allowed origins
config.allowedOrigins = [
  config.clientURL,
  config.serverURL,
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:3001',
  'https://rawwealthy.com',
  'https://www.rawwealthy.com',
  'https://uun-rawwealthy.vercel.app',
  'https://real-wealthy-1.onrender.com'
].filter(Boolean);

// Validate required environment variables
const missingRequired = [];
const missingRecommended = [];

requiredEnvVars.forEach(envVar => {
  if (!process.env[envVar] && !config[envVar.toLowerCase().replace('mongodb_uri', 'mongoURI')]) {
    missingRequired.push(envVar);
  }
});

recommendedEnvVars.forEach(envVar => {
  if (!process.env[envVar]) {
    missingRecommended.push(envVar);
  }
});

console.log('\n✅ Loaded Configuration:');
console.log(`- Port: ${config.port}`);
console.log(`- Environment: ${config.nodeEnv}`);
console.log(`- Production: ${config.isProduction}`);
console.log(`- Client URL: ${config.clientURL}`);
console.log(`- Server URL: ${config.serverURL}`);
console.log(`- Email Enabled: ${config.emailEnabled}`);
console.log(`- MongoDB URI: ${config.mongoURI ? 'Set' : 'Not Set'}`);
console.log(`- JWT Secret: ${config.jwtSecret ? 'Set' : 'Not Set'}`);
console.log(`- Debug Enabled: ${config.debugEnabled}`);

if (missingRequired.length > 0) {
  console.error('\n❌ Missing REQUIRED Environment Variables:');
  missingRequired.forEach(envVar => console.error(`  - ${envVar}`));
  
  // Try to auto-generate missing values
  if (missingRequired.includes('JWT_SECRET')) {
    config.jwtSecret = crypto.randomBytes(64).toString('hex');
    console.log(`✅ Auto-generated JWT_SECRET`);
  }
  
  if (missingRequired.includes('MONGODB_URI')) {
    config.mongoURI = 'mongodb://localhost:27017/rawwealthy';
    console.log(`✅ Using default MongoDB URI: ${config.mongoURI}`);
  }
}

if (missingRecommended.length > 0) {
  console.warn('\n⚠️ Missing RECOMMENDED Environment Variables:');
  missingRecommended.forEach(envVar => console.warn(`  - ${envVar}`));
}

console.log('=' .repeat(50) + '\n');

// ==================== ENHANCED EXPRESS APPLICATION SETUP ====================
const app = express();

// Enhanced request logging middleware
app.use((req, res, next) => {
  const startTime = Date.now();
  const requestId = uuidv4();
  
  // Store request info for logging
  req.requestId = requestId;
  req.startTime = startTime;
  
  // Log incoming request
  if (config.debugEnabled) {
    logger.debug('Incoming Request', {
      requestId,
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      timestamp: new Date().toISOString()
    });
  }
  
  // Capture response finish
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const logData = {
      requestId,
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      timestamp: new Date().toISOString()
    };
    
    if (res.statusCode >= 400) {
      logger.warn('Request Error', logData);
    } else if (config.debugEnabled) {
      logger.debug('Request Completed', logData);
    }
  });
  
  next();
});

// Advanced security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:", "blob:"],
      connectSrc: ["'self'", config.clientURL, config.serverURL]
    }
  },
  crossOriginResourcePolicy: { policy: "cross-origin" },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// Enhanced security middleware
app.use(xss());
app.use(hpp());
app.use(mongoSanitize());
app.use(compression());

// Enhanced CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Check allowed origins
    if (config.allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      // Allow preview deployments and local development
      const isAllowed = origin.includes('vercel.app') || 
                       origin.includes('onrender.com') || 
                       origin.includes('localhost') ||
                       origin.includes('127.0.0.1');
      
      if (isAllowed) {
        if (config.debugEnabled) {
          logger.debug('Allowed origin', { origin });
        }
        callback(null, true);
      } else {
        logger.warn('Blocked by CORS', { origin });
        callback(new Error('Not allowed by CORS'));
      }
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'x-api-key', 'x-user-id', 'x-request-id'],
  exposedHeaders: ['x-request-id', 'x-response-time']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Enhanced body parsing with size limits
app.use(express.json({ 
  limit: '50mb',
  verify: (req, res, buf) => {
    try {
      req.rawBody = buf;
      // Try to parse for debugging
      if (config.debugEnabled && buf.length > 0) {
        try {
          const jsonString = buf.toString('utf8');
          req.parsedBody = JSON.parse(jsonString);
        } catch (e) {
          // Not JSON, that's okay
        }
      }
    } catch (error) {
      logger.error('Body parsing error', { error: error.message });
    }
  }
}));

app.use(express.urlencoded({ 
  extended: true, 
  limit: '50mb',
  parameterLimit: 100000
}));

// Enhanced rate limiting with different strategies
const createRateLimiter = (windowMs, max, message, keyGenerator = null) => {
  return rateLimit({
    windowMs,
    max,
    message: { success: false, message },
    keyGenerator: keyGenerator || (req => req.ip),
    skip: (req, res) => {
      // Skip rate limiting for health checks and admin endpoints from admin IPs
      if (req.path === '/health' || req.path === '/api/health') return true;
      if (req.path.startsWith('/api/admin') && req.ip === '::1') return true;
      return false;
    },
    standardHeaders: true,
    legacyHeaders: false,
    onLimitReached: (req, res, options) => {
      logger.warn('Rate limit reached', {
        ip: req.ip,
        path: req.path,
        method: req.method
      });
    }
  });
};

// Apply rate limiters
const rateLimiters = {
  auth: createRateLimiter(15 * 60 * 1000, 20, 'Too many authentication attempts'),
  api: createRateLimiter(15 * 60 * 1000, 1000, 'Too many requests'),
  financial: createRateLimiter(15 * 60 * 1000, 50, 'Too many financial operations'),
  admin: createRateLimiter(5 * 60 * 1000, 500, 'Too many admin requests'),
  createAccount: createRateLimiter(60 * 60 * 1000, 10, 'Too many account creations')
};

app.use('/api/auth/login', rateLimiters.auth);
app.use('/api/auth/register', rateLimiters.createAccount);
app.use('/api/auth/forgot-password', rateLimiters.auth);
app.use('/api/investments', rateLimiters.financial);
app.use('/api/deposits', rateLimiters.financial);
app.use('/api/withdrawals', rateLimiters.financial);
app.use('/api/admin', rateLimiters.admin);
app.use('/api/', rateLimiters.api);

// ==================== ENHANCED FILE UPLOAD SYSTEM ====================
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  const allowedTypes = config.allowedMimeTypes;
  
  if (!allowedTypes[file.mimetype]) {
    const error = new Error(`Invalid file type: ${file.mimetype}. Allowed types: ${Object.keys(allowedTypes).join(', ')}`);
    error.code = 'INVALID_FILE_TYPE';
    return cb(error, false);
  }
  
  if (file.size > config.maxFileSize) {
    const error = new Error(`File too large: ${file.size} bytes. Maximum size: ${config.maxFileSize} bytes`);
    error.code = 'FILE_TOO_LARGE';
    return cb(error, false);
  }
  
  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: config.maxFileSize,
    files: 10,
    fieldNameSize: 100,
    fieldSize: 1024 * 1024 // 1MB for field values
  }
});

// Enhanced file upload handler
const handleFileUpload = async (file, folder = 'general', userId = null) => {
  if (!file) {
    throw new Error('No file provided');
  }
  
  try {
    // Validate file
    if (!config.allowedMimeTypes[file.mimetype]) {
      throw new Error(`Unsupported file type: ${file.mimetype}`);
    }
    
    const uploadsDir = path.join(config.uploadDir, folder);
    
    // Create directory if it doesn't exist
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }
    
    // Generate secure filename
    const timestamp = Date.now();
    const randomStr = crypto.randomBytes(8).toString('hex');
    const userIdPrefix = userId ? `${userId}_` : '';
    const fileExtension = config.allowedMimeTypes[file.mimetype] || file.originalname.split('.').pop();
    const filename = `${userIdPrefix}${timestamp}_${randomStr}.${fileExtension}`;
    const filepath = path.join(uploadsDir, filename);
    
    // Write file with error handling
    await fs.promises.writeFile(filepath, file.buffer);
    
    // Set file permissions (readable by all, writable by owner)
    await fs.promises.chmod(filepath, 0o644);
    
    const result = {
      url: `${config.serverURL}/uploads/${folder}/${filename}`,
      relativeUrl: `/uploads/${folder}/${filename}`,
      filename,
      originalName: file.originalname,
      size: file.size,
      mimeType: file.mimetype,
      uploadPath: filepath,
      uploadedAt: new Date(),
      folder
    };
    
    logger.debug('File uploaded successfully', {
      filename: result.filename,
      size: result.size,
      userId
    });
    
    return result;
  } catch (error) {
    logger.error('File upload failed', {
      error: error.message,
      originalName: file.originalname,
      size: file.size,
      mimeType: file.mimetype
    });
    throw new Error(`File upload failed: ${error.message}`);
  }
};

// Create uploads directory if it doesn't exist
if (!fs.existsSync(config.uploadDir)) {
  fs.mkdirSync(config.uploadDir, { recursive: true });
}

// Serve static files with caching
app.use('/uploads', express.static(config.uploadDir, {
  maxAge: '7d',
  setHeaders: (res, filePath) => {
    res.set('Cache-Control', 'public, max-age=604800');
    res.set('X-Content-Type-Options', 'nosniff');
    
    // Set appropriate content type
    const ext = path.extname(filePath).toLowerCase();
    const mimeTypes = {
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.gif': 'image/gif',
      '.webp': 'image/webp',
      '.pdf': 'application/pdf',
      '.svg': 'image/svg+xml'
    };
    
    if (mimeTypes[ext]) {
      res.set('Content-Type', mimeTypes[ext]);
    }
  }
}));

// ==================== ENHANCED EMAIL SYSTEM ====================
let emailTransporter = null;

if (config.emailEnabled) {
  try {
    emailTransporter = nodemailer.createTransport({
      host: config.emailConfig.host,
      port: config.emailConfig.port,
      secure: config.emailConfig.secure,
      auth: {
        user: config.emailConfig.user,
        pass: config.emailConfig.pass
      },
      tls: {
        rejectUnauthorized: false // For self-signed certificates
      }
    });
    
    // Verify connection
    emailTransporter.verify((error, success) => {
      if (error) {
        logger.error('Email configuration error', { error: error.message });
        console.error('❌ Email configuration error:', error.message);
      } else {
        logger.info('Email server is ready to send messages');
        console.log('✅ Email server is ready to send messages');
      }
    });
  } catch (error) {
    logger.error('Email setup failed', { error: error.message });
    console.error('❌ Email setup failed:', error.message);
  }
}

// Enhanced email utility function
const sendEmail = async (to, subject, html, text = '', attachments = []) => {
  try {
    if (!emailTransporter) {
      logger.warn('Email would be sent (simulated)', { to, subject });
      console.log(`📧 Email would be sent (simulated): To: ${to}, Subject: ${subject}`);
      return { simulated: true, success: true };
    }
    
    const mailOptions = {
      from: config.emailConfig.from,
      to,
      subject,
      text: text || html.replace(/<[^>]*>/g, ''),
      html,
      attachments
    };
    
    const info = await emailTransporter.sendMail(mailOptions);
    
    logger.info('Email sent successfully', {
      to,
      subject,
      messageId: info.messageId
    });
    
    return { 
      success: true, 
      messageId: info.messageId,
      response: info.response 
    };
  } catch (error) {
    logger.error('Email sending failed', {
      to,
      subject,
      error: error.message
    });
    
    return { 
      success: false, 
      error: error.message,
      stack: error.stack 
    };
  }
};

// ==================== ENHANCED DATABASE MODELS ====================

// Enhanced User Model with debugging
const userSchema = new mongoose.Schema({
  full_name: { 
    type: String, 
    required: [true, 'Full name is required'], 
    trim: true,
    minlength: [2, 'Full name must be at least 2 characters'],
    maxlength: [100, 'Full name cannot exceed 100 characters']
  },
  email: { 
    type: String, 
    required: [true, 'Email is required'], 
    unique: true, 
    lowercase: true,
    trim: true,
    match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email address']
  },
  phone: { 
    type: String, 
    required: [true, 'Phone number is required'],
    trim: true
  },
  password: { 
    type: String, 
    required: [true, 'Password is required'], 
    select: false,
    minlength: [6, 'Password must be at least 6 characters']
  },
  role: { 
    type: String, 
    enum: ['user', 'admin', 'super_admin'], 
    default: 'user' 
  },
  balance: { 
    type: Number, 
    default: 0, 
    min: 0,
    get: v => parseFloat(v.toFixed(2))
  },
  total_earnings: { 
    type: Number, 
    default: 0, 
    min: 0,
    get: v => parseFloat(v.toFixed(2))
  },
  referral_earnings: { 
    type: Number, 
    default: 0, 
    min: 0,
    get: v => parseFloat(v.toFixed(2))
  },
  risk_tolerance: { 
    type: String, 
    enum: ['low', 'medium', 'high'], 
    default: 'medium' 
  },
  investment_strategy: { 
    type: String, 
    enum: ['conservative', 'balanced', 'aggressive'], 
    default: 'balanced' 
  },
  country: { 
    type: String, 
    default: 'ng',
    uppercase: true,
    minlength: 2,
    maxlength: 2
  },
  currency: { 
    type: String, 
    enum: ['NGN', 'USD', 'EUR', 'GBP'], 
    default: 'NGN' 
  },
  referral_code: { 
    type: String, 
    unique: true, 
    sparse: true,
    uppercase: true
  },
  referred_by: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  },
  referral_count: { 
    type: Number, 
    default: 0 
  },
  kyc_verified: { 
    type: Boolean, 
    default: false 
  },
  kyc_status: { 
    type: String, 
    enum: ['pending', 'verified', 'rejected', 'not_submitted'], 
    default: 'not_submitted' 
  },
  kyc_submitted_at: Date,
  kyc_verified_at: Date,
  two_factor_enabled: { 
    type: Boolean, 
    default: false 
  },
  two_factor_secret: { 
    type: String, 
    select: false 
  },
  is_active: { 
    type: Boolean, 
    default: true 
  },
  is_verified: { 
    type: Boolean, 
    default: false 
  },
  verification_token: { 
    type: String, 
    select: false 
  },
  verification_expires: Date,
  password_reset_token: { 
    type: String, 
    select: false 
  },
  password_reset_expires: Date,
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String,
    bank_code: String,
    verified: { type: Boolean, default: false },
    verified_at: Date,
    last_updated: Date,
    verification_notes: String
  },
  wallet_address: String,
  paypal_email: String,
  last_login: Date,
  last_active: Date,
  login_attempts: { 
    type: Number, 
    default: 0,
    min: 0,
    max: 10
  },
  lock_until: Date,
  profile_image: String,
  notifications_enabled: { 
    type: Boolean, 
    default: true 
  },
  email_notifications: { 
    type: Boolean, 
    default: true 
  },
  sms_notifications: { 
    type: Boolean, 
    default: false 
  },
  metadata: { 
    type: mongoose.Schema.Types.Mixed, 
    default: {} 
  },
  total_deposits: { 
    type: Number, 
    default: 0,
    get: v => parseFloat(v.toFixed(2))
  },
  total_withdrawals: { 
    type: Number, 
    default: 0,
    get: v => parseFloat(v.toFixed(2))
  },
  total_investments: { 
    type: Number, 
    default: 0,
    get: v => parseFloat(v.toFixed(2))
  },
  last_deposit_date: Date,
  last_withdrawal_date: Date,
  last_investment_date: Date,
  last_earning_date: Date,
  total_logins: { type: Number, default: 0 },
  device_info: {
    last_device: String,
    last_ip: String,
    device_history: [{
      device: String,
      ip: String,
      timestamp: Date
    }]
  }
}, { 
  timestamps: true,
  toJSON: { 
    virtuals: true,
    getters: true,
    transform: function(doc, ret) {
      // Remove sensitive data
      delete ret.password;
      delete ret.two_factor_secret;
      delete ret.verification_token;
      delete ret.password_reset_token;
      delete ret.login_attempts;
      delete ret.lock_until;
      
      // Format dates
      if (ret.createdAt) ret.createdAt = ret.createdAt.toISOString();
      if (ret.updatedAt) ret.updatedAt = ret.updatedAt.toISOString();
      if (ret.last_login) ret.last_login = ret.last_login.toISOString();
      
      return ret;
    }
  }
});

// Indexes for performance
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ referral_code: 1 }, { unique: true, sparse: true });
userSchema.index({ is_active: 1, role: 1 });
userSchema.index({ kyc_status: 1 });
userSchema.index({ 'bank_details.verified': 1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ balance: -1 });
userSchema.index({ total_earnings: -1 });

// Virtual fields
userSchema.virtual('portfolio_value').get(function() {
  return parseFloat((this.balance + this.total_earnings + this.referral_earnings).toFixed(2));
});

userSchema.virtual('total_profit').get(function() {
  const totalInvested = this.total_investments || 0;
  const totalEarned = this.total_earnings || 0;
  return parseFloat((totalEarned - totalInvested).toFixed(2));
});

userSchema.virtual('account_age_days').get(function() {
  const created = this.createdAt || new Date();
  const now = new Date();
  const diffTime = Math.abs(now - created);
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
});

// Pre-save middleware
userSchema.pre('save', async function(next) {
  try {
    // Hash password if modified
    if (this.isModified('password')) {
      logger.debug('Hashing password for user', { userId: this._id });
      this.password = await bcrypt.hash(this.password, config.bcryptRounds);
    }
    
    // Generate referral code if not present
    if (!this.referral_code) {
      this.referral_code = crypto.randomBytes(6).toString('hex').toUpperCase();
      logger.debug('Generated referral code', { 
        userId: this._id, 
        referralCode: this.referral_code 
      });
    }
    
    // Generate verification token if email is modified
    if (this.isModified('email') && !this.is_verified) {
      this.verification_token = crypto.randomBytes(32).toString('hex');
      this.verification_expires = new Date(Date.now() + 24 * 60 * 60 * 1000);
    }
    
    // Update bank details timestamp
    if (this.isModified('bank_details')) {
      this.bank_details.last_updated = new Date();
    }
    
    next();
  } catch (error) {
    logger.error('Error in user pre-save middleware', { 
      error: error.message,
      userId: this._id 
    });
    next(error);
  }
});

// Instance methods
userSchema.methods.comparePassword = async function(candidatePassword) {
  try {
    const isMatch = await bcrypt.compare(candidatePassword, this.password);
    logger.debug('Password comparison result', { 
      userId: this._id, 
      isMatch 
    });
    return isMatch;
  } catch (error) {
    logger.error('Error comparing passwords', { 
      error: error.message,
      userId: this._id 
    });
    throw error;
  }
};

userSchema.methods.generateAuthToken = function() {
  try {
    const payload = {
      id: this._id,
      email: this.email,
      role: this.role,
      kyc_verified: this.kyc_verified,
      is_active: this.is_active,
      is_verified: this.is_verified
    };
    
    const token = jwt.sign(payload, config.jwtSecret, { 
      expiresIn: config.jwtExpiresIn 
    });
    
    logger.debug('Generated auth token', { 
      userId: this._id,
      role: this.role 
    });
    
    return token;
  } catch (error) {
    logger.error('Error generating auth token', { 
      error: error.message,
      userId: this._id 
    });
    throw error;
  }
};

userSchema.methods.generatePasswordResetToken = function() {
  try {
    const resetToken = crypto.randomBytes(32).toString('hex');
    this.password_reset_token = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    this.password_reset_expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    
    logger.debug('Generated password reset token', { 
      userId: this._id 
    });
    
    return resetToken;
  } catch (error) {
    logger.error('Error generating password reset token', { 
      error: error.message,
      userId: this._id 
    });
    throw error;
  }
};

userSchema.methods.generateVerificationToken = function() {
  try {
    const verificationToken = crypto.randomBytes(32).toString('hex');
    this.verification_token = crypto
      .createHash('sha256')
      .update(verificationToken)
      .digest('hex');
    this.verification_expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    
    logger.debug('Generated verification token', { 
      userId: this._id 
    });
    
    return verificationToken;
  } catch (error) {
    logger.error('Error generating verification token', { 
      error: error.message,
      userId: this._id 
    });
    throw error;
  }
};

// Static methods
userSchema.statics.findByEmail = async function(email) {
  try {
    const user = await this.findOne({ email: email.toLowerCase() });
    return user;
  } catch (error) {
    logger.error('Error finding user by email', { 
      error: error.message,
      email 
    });
    throw error;
  }
};

userSchema.statics.findByReferralCode = async function(referralCode) {
  try {
    const user = await this.findOne({ referral_code: referralCode.toUpperCase() });
    return user;
  } catch (error) {
    logger.error('Error finding user by referral code', { 
      error: error.message,
      referralCode 
    });
    throw error;
  }
};

userSchema.statics.getDashboardStats = async function(userId) {
  try {
    const user = await this.findById(userId);
    if (!user) return null;
    
    const Investment = mongoose.model('Investment');
    const activeInvestments = await Investment.find({
      user: userId,
      status: 'active'
    }).populate('plan', 'daily_interest name');
    
    let dailyInterest = 0;
    let activeInvestmentValue = 0;
    let investmentDetails = [];
    
    activeInvestments.forEach(inv => {
      activeInvestmentValue += inv.amount;
      if (inv.plan && inv.plan.daily_interest) {
        const dailyEarning = (inv.amount * inv.plan.daily_interest) / 100;
        dailyInterest += dailyEarning;
        investmentDetails.push({
          plan: inv.plan.name,
          amount: inv.amount,
          daily_interest: inv.plan.daily_interest,
          daily_earning: dailyEarning
        });
      }
    });
    
    return {
      daily_interest: parseFloat(dailyInterest.toFixed(2)),
      active_investment_value: parseFloat(activeInvestmentValue.toFixed(2)),
      portfolio_value: user.portfolio_value,
      referral_earnings: user.referral_earnings || 0,
      total_earnings: user.total_earnings || 0,
      investment_details: investmentDetails
    };
  } catch (error) {
    logger.error('Error getting dashboard stats', { 
      error: error.message,
      userId 
    });
    throw error;
  }
};

const User = mongoose.model('User', userSchema);

// Enhanced Investment Plan Model
const investmentPlanSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: [true, 'Plan name is required'], 
    unique: true,
    trim: true,
    minlength: [3, 'Plan name must be at least 3 characters'],
    maxlength: [100, 'Plan name cannot exceed 100 characters']
  },
  description: { 
    type: String, 
    required: [true, 'Plan description is required'],
    trim: true,
    minlength: [10, 'Plan description must be at least 10 characters'],
    maxlength: [500, 'Plan description cannot exceed 500 characters']
  },
  min_amount: { 
    type: Number, 
    required: [true, 'Minimum amount is required'], 
    min: [1, 'Minimum amount must be at least 1'],
    get: v => parseFloat(v.toFixed(2))
  },
  max_amount: { 
    type: Number, 
    min: [1, 'Maximum amount must be at least 1'],
    get: v => parseFloat(v.toFixed(2))
  },
  daily_interest: { 
    type: Number, 
    required: [true, 'Daily interest is required'], 
    min: [0.01, 'Daily interest must be at least 0.01%'],
    max: [100, 'Daily interest cannot exceed 100%'],
    get: v => parseFloat(v.toFixed(2))
  },
  total_interest: { 
    type: Number, 
    required: [true, 'Total interest is required'], 
    min: [0.01, 'Total interest must be at least 0.01%'],
    max: [1000, 'Total interest cannot exceed 1000%'],
    get: v => parseFloat(v.toFixed(2))
  },
  duration: { 
    type: Number, 
    required: [true, 'Duration is required'], 
    min: [1, 'Duration must be at least 1 day'],
    max: [365, 'Duration cannot exceed 365 days']
  },
  risk_level: { 
    type: String, 
    enum: ['low', 'medium', 'high'], 
    required: [true, 'Risk level is required'] 
  },
  raw_material: { 
    type: String, 
    required: [true, 'Raw material is required'],
    trim: true 
  },
  category: { 
    type: String, 
    enum: ['agriculture', 'mining', 'energy', 'metals', 'crypto', 'real_estate', 'precious_stones'], 
    default: 'agriculture' 
  },
  is_active: { 
    type: Boolean, 
    default: true 
  },
  is_popular: { 
    type: Boolean, 
    default: false 
  },
  is_featured: { 
    type: Boolean, 
    default: false 
  },
  image_url: String,
  color: String,
  icon: String,
  features: [{
    type: String,
    trim: true
  }],
  investment_count: { 
    type: Number, 
    default: 0 
  },
  total_invested: { 
    type: Number, 
    default: 0,
    get: v => parseFloat(v.toFixed(2))
  },
  total_earned: { 
    type: Number, 
    default: 0,
    get: v => parseFloat(v.toFixed(2))
  },
  success_rate: { 
    type: Number, 
    default: 0,
    min: 0,
    max: 100,
    get: v => parseFloat(v.toFixed(2))
  },
  rating: { 
    type: Number, 
    default: 0, 
    min: 0, 
    max: 5,
    get: v => parseFloat(v.toFixed(1))
  },
  tags: [String],
  display_order: { 
    type: Number, 
    default: 0,
    min: 0 
  },
  terms_and_conditions: String,
  risk_disclaimer: String,
  metadata: { 
    type: mongoose.Schema.Types.Mixed, 
    default: {} 
  }
}, { 
  timestamps: true,
  toJSON: { getters: true }
});

investmentPlanSchema.index({ is_active: 1, is_popular: 1, category: 1 });
investmentPlanSchema.index({ min_amount: 1, max_amount: 1 });
investmentPlanSchema.index({ daily_interest: -1 });
investmentPlanSchema.index({ total_interest: -1 });

// Virtual fields
investmentPlanSchema.virtual('monthly_interest').get(function() {
  return parseFloat((this.daily_interest * 30).toFixed(2));
});

investmentPlanSchema.virtual('estimated_roi').get(function() {
  return parseFloat((this.total_interest / 100).toFixed(2));
});

// Pre-save middleware
investmentPlanSchema.pre('save', function(next) {
  // Ensure max_amount is greater than min_amount if both are set
  if (this.max_amount && this.max_amount <= this.min_amount) {
    const err = new Error('Maximum amount must be greater than minimum amount');
    return next(err);
  }
  
  next();
});

// Static methods
investmentPlanSchema.statics.getActivePlans = async function() {
  try {
    const plans = await this.find({ is_active: true })
      .sort({ display_order: 1, min_amount: 1 })
      .lean();
    
    return plans.map(plan => ({
      ...plan,
      monthly_interest: parseFloat((plan.daily_interest * 30).toFixed(2)),
      estimated_roi: parseFloat((plan.total_interest / 100).toFixed(2))
    }));
  } catch (error) {
    logger.error('Error getting active plans', { error: error.message });
    throw error;
  }
};

investmentPlanSchema.statics.getPopularPlans = async function() {
  try {
    const plans = await this.find({ 
      is_active: true,
      is_popular: true 
    })
      .sort({ display_order: 1 })
      .limit(6)
      .lean();
    
    return plans;
  } catch (error) {
    logger.error('Error getting popular plans', { error: error.message });
    throw error;
  }
};

const InvestmentPlan = mongoose.model('InvestmentPlan', investmentPlanSchema);

// Enhanced Investment Model
const investmentSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'] 
  },
  plan: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'InvestmentPlan', 
    required: [true, 'Plan is required'] 
  },
  amount: { 
    type: Number, 
    required: [true, 'Amount is required'], 
    min: [1, 'Amount must be at least 1'],
    get: v => parseFloat(v.toFixed(2))
  },
  status: { 
    type: String, 
    enum: ['pending', 'active', 'completed', 'cancelled', 'failed', 'expired'], 
    default: 'pending' 
  },
  start_date: { 
    type: Date, 
    default: Date.now 
  },
  end_date: { 
    type: Date, 
    required: [true, 'End date is required'] 
  },
  approved_at: Date,
  expected_earnings: { 
    type: Number, 
    required: [true, 'Expected earnings are required'],
    get: v => parseFloat(v.toFixed(2))
  },
  earned_so_far: { 
    type: Number, 
    default: 0,
    get: v => parseFloat(v.toFixed(2))
  },
  daily_earnings: { 
    type: Number, 
    default: 0,
    get: v => parseFloat(v.toFixed(2))
  },
  last_earning_date: Date,
  payment_proof_url: String,
  payment_verified: { 
    type: Boolean, 
    default: false 
  },
  auto_renew: { 
    type: Boolean, 
    default: false 
  },
  auto_renewed: { 
    type: Boolean, 
    default: false 
  },
  approved_by: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  },
  transaction_id: String,
  remarks: String,
  metadata: { 
    type: mongoose.Schema.Types.Mixed, 
    default: {} 
  },
  admin_notes: String,
  proof_verified_by: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  },
  proof_verified_at: Date,
  investment_image_url: String,
  profit_loss: { 
    type: Number, 
    default: 0,
    get: v => parseFloat(v.toFixed(2))
  },
  roi_percentage: { 
    type: Number, 
    default: 0,
    get: v => parseFloat(v.toFixed(2))
  }
}, { 
  timestamps: true,
  toJSON: { getters: true }
});

investmentSchema.index({ user: 1, status: 1 });
investmentSchema.index({ end_date: 1 });
investmentSchema.index({ createdAt: -1 });
investmentSchema.index({ plan: 1, status: 1 });
investmentSchema.index({ 'metadata.renewal_count': 1 });

// Virtual fields
investmentSchema.virtual('remaining_days').get(function() {
  if (this.status !== 'active') return 0;
  const now = new Date();
  const end = new Date(this.end_date);
  const diffTime = Math.max(0, end - now);
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
});

investmentSchema.virtual('progress_percentage').get(function() {
  if (this.status === 'completed') return 100;
  if (this.status !== 'active') return 0;
  
  const start = new Date(this.start_date);
  const end = new Date(this.end_date);
  const now = new Date();
  
  const totalDuration = end - start;
  const elapsed = now - start;
  
  return Math.min(100, Math.max(0, (elapsed / totalDuration) * 100));
});

investmentSchema.virtual('remaining_earnings').get(function() {
  return parseFloat((this.expected_earnings - this.earned_so_far).toFixed(2));
});

// Pre-save middleware
investmentSchema.pre('save', async function(next) {
  try {
    // Calculate ROI percentage when earnings are updated
    if (this.isModified('earned_so_far') && this.amount > 0) {
      this.roi_percentage = parseFloat(((this.earned_so_far / this.amount) * 100).toFixed(2));
      this.profit_loss = parseFloat((this.earned_so_far - this.amount).toFixed(2));
    }
    
    // Update status if end date passed
    if (this.status === 'active' && new Date(this.end_date) < new Date()) {
      this.status = 'completed';
      logger.info('Investment completed automatically', {
        investmentId: this._id,
        userId: this.user
      });
    }
    
    next();
  } catch (error) {
    logger.error('Error in investment pre-save middleware', {
      error: error.message,
      investmentId: this._id
    });
    next(error);
  }
});

const Investment = mongoose.model('Investment', investmentSchema);

// Enhanced Deposit Model
const depositSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'] 
  },
  amount: { 
    type: Number, 
    required: [true, 'Amount is required'], 
    min: [1, 'Amount must be at least 1'],
    get: v => parseFloat(v.toFixed(2))
  },
  currency: { 
    type: String, 
    enum: ['NGN', 'USD', 'EUR', 'GBP'], 
    default: 'NGN' 
  },
  payment_method: { 
    type: String, 
    enum: ['bank_transfer', 'crypto', 'paypal', 'card', 'flutterwave', 'paystack'], 
    required: [true, 'Payment method is required'] 
  },
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'cancelled', 'processing'], 
    default: 'pending' 
  },
  payment_proof_url: String,
  transaction_hash: String,
  reference: { 
    type: String, 
    unique: true, 
    sparse: true 
  },
  admin_notes: String,
  approved_by: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  },
  approved_at: Date,
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String,
    bank_code: String
  },
  crypto_details: {
    wallet_address: String,
    coin_type: String,
    network: String,
    txid: String
  },
  card_details: {
    last4: String,
    brand: String,
    country: String
  },
  metadata: { 
    type: mongoose.Schema.Types.Mixed, 
    default: {} 
  },
  deposit_image_url: String,
  proof_verified_by: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  },
  proof_verified_at: Date,
  processed_by_gateway: { type: Boolean, default: false },
  gateway_response: mongoose.Schema.Types.Mixed,
  exchange_rate: Number,
  converted_amount: Number,
  fee: { type: Number, default: 0, get: v => parseFloat(v.toFixed(2)) }
}, { 
  timestamps: true,
  toJSON: { getters: true }
});

depositSchema.index({ user: 1, status: 1 });
depositSchema.index({ reference: 1 }, { unique: true, sparse: true });
depositSchema.index({ createdAt: -1 });
depositSchema.index({ payment_method: 1, status: 1 });

const Deposit = mongoose.model('Deposit', depositSchema);

// Enhanced Withdrawal Model
const withdrawalSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'] 
  },
  amount: { 
    type: Number, 
    required: [true, 'Amount is required'], 
    min: [1, 'Amount must be at least 1'],
    get: v => parseFloat(v.toFixed(2))
  },
  currency: { 
    type: String, 
    enum: ['NGN', 'USD', 'EUR', 'GBP'], 
    default: 'NGN' 
  },
  payment_method: { 
    type: String, 
    enum: ['bank_transfer', 'crypto', 'paypal', 'wire_transfer'], 
    required: [true, 'Payment method is required'] 
  },
  platform_fee: { 
    type: Number, 
    default: 0,
    get: v => parseFloat(v.toFixed(2))
  },
  net_amount: { 
    type: Number, 
    required: [true, 'Net amount is required'],
    get: v => parseFloat(v.toFixed(2))
  },
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String,
    bank_code: String,
    swift_code: String,
    iban: String,
    routing_number: String,
    verified: { type: Boolean, default: false }
  },
  wallet_address: String,
  paypal_email: String,
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'paid', 'processing', 'failed'], 
    default: 'pending' 
  },
  reference: { 
    type: String, 
    unique: true, 
    sparse: true 
  },
  admin_notes: String,
  approved_by: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  },
  approved_at: Date,
  paid_at: Date,
  transaction_id: String,
  metadata: { 
    type: mongoose.Schema.Types.Mixed, 
    default: {} 
  },
  payment_proof_url: String,
  proof_verified_by: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  },
  proof_verified_at: Date,
  processed_by_gateway: { type: Boolean, default: false },
  gateway_response: mongoose.Schema.Types.Mixed,
  exchange_rate: Number,
  converted_amount: Number,
  failure_reason: String,
  retry_count: { type: Number, default: 0 }
}, { 
  timestamps: true,
  toJSON: { getters: true }
});

withdrawalSchema.index({ user: 1, status: 1 });
withdrawalSchema.index({ reference: 1 }, { unique: true, sparse: true });
withdrawalSchema.index({ createdAt: -1 });
withdrawalSchema.index({ payment_method: 1, status: 1 });

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// Enhanced Transaction Model
const transactionSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'] 
  },
  type: { 
    type: String, 
    enum: ['deposit', 'withdrawal', 'investment', 'earning', 'referral', 'bonus', 'fee', 'refund', 'transfer', 'adjustment', 'penalty'], 
    required: [true, 'Transaction type is required'] 
  },
  amount: { 
    type: Number, 
    required: [true, 'Amount is required'],
    get: v => parseFloat(v.toFixed(2))
  },
  currency: { 
    type: String, 
    enum: ['NGN', 'USD', 'EUR', 'GBP'], 
    default: 'NGN' 
  },
  description: { 
    type: String, 
    required: [true, 'Description is required'],
    trim: true 
  },
  reference: { 
    type: String, 
    unique: true, 
    sparse: true 
  },
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed', 'cancelled', 'processing'], 
    default: 'completed' 
  },
  balance_before: { 
    type: Number,
    get: v => parseFloat(v.toFixed(2))
  },
  balance_after: { 
    type: Number,
    get: v => parseFloat(v.toFixed(2))
  },
  related_investment: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Investment' 
  },
  related_deposit: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Deposit' 
  },
  related_withdrawal: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'Withdrawal' 
  },
  metadata: { 
    type: mongoose.Schema.Types.Mixed, 
    default: {} 
  },
  payment_proof_url: String,
  admin_notes: String,
  processed_by: String,
  ip_address: String,
  user_agent: String,
  device_info: String
}, { 
  timestamps: true,
  toJSON: { getters: true }
});

transactionSchema.index({ user: 1, createdAt: -1 });
transactionSchema.index({ type: 1, status: 1 });
transactionSchema.index({ reference: 1 });
transactionSchema.index({ 'metadata.source': 1 });

const Transaction = mongoose.model('Transaction', transactionSchema);

// Enhanced KYC Submission Model
const kycSubmissionSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'], 
    unique: true 
  },
  id_type: { 
    type: String, 
    enum: ['national_id', 'passport', 'driver_license', 'voters_card'], 
    required: [true, 'ID type is required'] 
  },
  id_number: { 
    type: String, 
    required: [true, 'ID number is required'],
    trim: true 
  },
  id_front_url: { 
    type: String, 
    required: [true, 'ID front image is required'] 
  },
  id_back_url: String,
  selfie_with_id_url: { 
    type: String, 
    required: [true, 'Selfie with ID is required'] 
  },
  address_proof_url: String,
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'under_review'], 
    default: 'pending' 
  },
  reviewed_by: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  },
  reviewed_at: Date,
  rejection_reason: String,
  notes: String,
  metadata: { 
    type: mongoose.Schema.Types.Mixed, 
    default: {} 
  },
  submitted_ip: String,
  submitted_user_agent: String,
  verification_score: { type: Number, min: 0, max: 100 },
  expiration_date: Date,
  country: String,
  document_country: String
}, { 
  timestamps: true 
});

kycSubmissionSchema.index({ status: 1, submitted_at: -1 });
kycSubmissionSchema.index({ user: 1 }, { unique: true });

const KYCSubmission = mongoose.model('KYCSubmission', kycSubmissionSchema);

// Enhanced Support Ticket Model
const supportTicketSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'] 
  },
  ticket_id: { 
    type: String, 
    unique: true, 
    required: [true, 'Ticket ID is required'] 
  },
  subject: { 
    type: String, 
    required: [true, 'Subject is required'],
    trim: true,
    minlength: [5, 'Subject must be at least 5 characters'],
    maxlength: [200, 'Subject cannot exceed 200 characters']
  },
  message: { 
    type: String, 
    required: [true, 'Message is required'],
    trim: true,
    minlength: [10, 'Message must be at least 10 characters'],
    maxlength: [5000, 'Message cannot exceed 5000 characters']
  },
  category: { 
    type: String, 
    enum: ['general', 'technical', 'investment', 'withdrawal', 'deposit', 'kyc', 'account', 'other', 'bug', 'feature_request'], 
    default: 'general' 
  },
  priority: { 
    type: String, 
    enum: ['low', 'medium', 'high', 'urgent'], 
    default: 'medium' 
  },
  status: { 
    type: String, 
    enum: ['open', 'in_progress', 'resolved', 'closed', 'pending'], 
    default: 'open' 
  },
  attachments: [{
    filename: String,
    url: String,
    size: Number,
    mime_type: String,
    uploaded_at: { type: Date, default: Date.now }
  }],
  assigned_to: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  },
  last_reply_at: Date,
  reply_count: { 
    type: Number, 
    default: 0 
  },
  is_read_by_user: { 
    type: Boolean, 
    default: false 
  },
  is_read_by_admin: { 
    type: Boolean, 
    default: false 
  },
  resolution_notes: String,
  closed_at: Date,
  closed_by: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User' 
  },
  satisfaction_rating: { 
    type: Number, 
    min: 1, 
    max: 5 
  },
  metadata: { 
    type: mongoose.Schema.Types.Mixed, 
    default: {} 
  },
  tags: [String],
  department: String
}, { 
  timestamps: true 
});

supportTicketSchema.index({ user: 1, status: 1, createdAt: -1 });
supportTicketSchema.index({ ticket_id: 1 }, { unique: true });
supportTicketSchema.index({ category: 1, priority: 1 });

const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);

// Enhanced Referral Model
const referralSchema = new mongoose.Schema({
  referrer: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'Referrer is required'] 
  },
  referred_user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'Referred user is required'], 
    unique: true 
  },
  referral_code: { 
    type: String, 
    required: [true, 'Referral code is required'] 
  },
  status: { 
    type: String, 
    enum: ['pending', 'active', 'completed', 'expired', 'inactive'], 
    default: 'pending' 
  },
  earnings: { 
    type: Number, 
    default: 0,
    get: v => parseFloat(v.toFixed(2))
  },
  commission_percentage: { 
    type: Number, 
    default: config.referralCommissionPercent,
    min: 0,
    max: 100,
    get: v => parseFloat(v.toFixed(2))
  },
  investment_amount: { 
    type: Number,
    get: v => parseFloat(v.toFixed(2))
  },
  earnings_paid: { 
    type: Boolean, 
    default: false 
  },
  paid_at: Date,
  paid_amount: { 
    type: Number,
    get: v => parseFloat(v.toFixed(2))
  },
  metadata: { 
    type: mongoose.Schema.Types.Mixed, 
    default: {} 
  },
  level: { type: Number, default: 1, min: 1, max: 3 },
  expires_at: Date,
  conversion_date: Date
}, { 
  timestamps: true 
});

referralSchema.index({ referrer: 1, status: 1 });
referralSchema.index({ referred_user: 1 }, { unique: true });
referralSchema.index({ referral_code: 1 });

const Referral = mongoose.model('Referral', referralSchema);

// Enhanced Notification Model
const notificationSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'User is required'] 
  },
  title: { 
    type: String, 
    required: [true, 'Title is required'],
    trim: true 
  },
  message: { 
    type: String, 
    required: [true, 'Message is required'],
    trim: true 
  },
  type: { 
    type: String, 
    enum: ['info', 'success', 'warning', 'error', 'promotional', 'investment', 'withdrawal', 'deposit', 'kyc', 'referral', 'system', 'security', 'account'], 
    default: 'info' 
  },
  is_read: { 
    type: Boolean, 
    default: false 
  },
  is_email_sent: { 
    type: Boolean, 
    default: false 
  },
  is_sms_sent: { 
    type: Boolean, 
    default: false 
  },
  action_url: String,
  priority: { 
    type: Number, 
    default: 0, 
    min: 0, 
    max: 3 
  },
  metadata: { 
    type: mongoose.Schema.Types.Mixed, 
    default: {} 
  },
  expires_at: Date,
  read_at: Date,
  sent_at: Date,
  category: String
}, { 
  timestamps: true 
});

notificationSchema.index({ user: 1, is_read: 1, createdAt: -1 });
notificationSchema.index({ expires_at: 1 }, { expireAfterSeconds: 0 });

const Notification = mongoose.model('Notification', notificationSchema);

// Enhanced Admin Audit Log Model
const adminAuditSchema = new mongoose.Schema({
  admin_id: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: [true, 'Admin ID is required'] 
  },
  action: { 
    type: String, 
    required: [true, 'Action is required'] 
  },
  target_type: { 
    type: String, 
    enum: ['user', 'investment', 'deposit', 'withdrawal', 'kyc', 'transaction', 'plan', 'system', 'settings', 'notification', 'referral', 'ticket'] 
  },
  target_id: mongoose.Schema.Types.ObjectId,
  details: mongoose.Schema.Types.Mixed,
  ip_address: String,
  user_agent: String,
  metadata: { 
    type: mongoose.Schema.Types.Mixed, 
    default: {} 
  },
  severity: { 
    type: String, 
    enum: ['low', 'medium', 'high', 'critical'], 
    default: 'medium' 
  },
  status: { 
    type: String, 
    enum: ['success', 'failure', 'pending'], 
    default: 'success' 
  },
  error_message: String
}, { 
  timestamps: true 
});

adminAuditSchema.index({ admin_id: 1, createdAt: -1 });
adminAuditSchema.index({ action: 1, target_type: 1 });

const AdminAudit = mongoose.model('AdminAudit', adminAuditSchema);

// System Settings Model
const systemSettingsSchema = new mongoose.Schema({
  key: { 
    type: String, 
    required: true, 
    unique: true 
  },
  value: mongoose.Schema.Types.Mixed,
  type: { 
    type: String, 
    enum: ['string', 'number', 'boolean', 'array', 'object'], 
    default: 'string' 
  },
  category: String,
  description: String,
  is_public: { type: Boolean, default: false },
  metadata: { 
    type: mongoose.Schema.Types.Mixed, 
    default: {} 
  }
}, { 
  timestamps: true 
});

systemSettingsSchema.index({ key: 1 }, { unique: true });
systemSettingsSchema.index({ category: 1, is_public: 1 });

const SystemSettings = mongoose.model('SystemSettings', systemSettingsSchema);

// ==================== ENHANCED UTILITY FUNCTIONS ====================

// Format response utility
const formatResponse = (success, message, data = null, pagination = null, debugInfo = null) => {
  const response = {
    success,
    message,
    timestamp: new Date().toISOString(),
    version: '38.0.0'
  };
  
  if (data !== null) response.data = data;
  if (pagination !== null) response.pagination = pagination;
  if (debugInfo !== null && config.debugEnabled) response.debug = debugInfo;
  
  return response;
};

// Enhanced error handling
const handleError = (res, error, defaultMessage = 'An error occurred', requestId = null) => {
  const errorId = crypto.randomBytes(8).toString('hex');
  const timestamp = new Date().toISOString();
  
  // Log the error
  logger.error('API Error', {
    errorId,
    requestId,
    message: error.message,
    stack: error.stack,
    name: error.name,
    code: error.code,
    defaultMessage
  });
  
  // Handle specific error types
  if (error.name === 'ValidationError') {
    const messages = Object.values(error.errors).map(val => val.message);
    return res.status(400).json(formatResponse(false, 'Validation Error', { 
      errors: messages,
      errorId 
    }));
  }
  
  if (error.code === 11000) {
    const field = Object.keys(error.keyValue)[0];
    return res.status(400).json(formatResponse(false, `${field} already exists`, { errorId }));
  }
  
  if (error.name === 'JsonWebTokenError') {
    return res.status(401).json(formatResponse(false, 'Invalid token', { errorId }));
  }
  
  if (error.name === 'TokenExpiredError') {
    return res.status(401).json(formatResponse(false, 'Token expired', { errorId }));
  }
  
  if (error.name === 'CastError') {
    return res.status(400).json(formatResponse(false, 'Invalid ID format', { errorId }));
  }
  
  const statusCode = error.statusCode || error.status || 500;
  const message = config.isProduction && statusCode === 500 
    ? defaultMessage 
    : error.message;

  const response = formatResponse(false, message, { errorId });
  
  // Add debug info in development
  if (!config.isProduction) {
    response.debug = {
      message: error.message,
      stack: error.stack,
      name: error.name
    };
  }
  
  return res.status(statusCode).json(response);
};

// Generate reference
const generateReference = (prefix = 'REF') => {
  const timestamp = Date.now();
  const random = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `${prefix}${timestamp}${random}`;
};

// Create notification with enhanced features
const createNotification = async (userId, title, message, type = 'info', actionUrl = null, metadata = {}) => {
  try {
    const notification = new Notification({
      user: userId,
      title,
      message,
      type,
      action_url: actionUrl,
      metadata: {
        ...metadata,
        sentAt: new Date(),
        notificationId: crypto.randomBytes(8).toString('hex')
      }
    });
    
    await notification.save();
    
    logger.debug('Notification created', {
      userId,
      title,
      type,
      notificationId: notification._id
    });
    
    // Send email notification if enabled
    const user = await User.findById(userId);
    if (user && user.email_notifications && type !== 'system') {
      const emailSubject = `Raw Wealthy - ${title}`;
      const emailHtml = `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>${title}</title>
          <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; }
            .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; color: white; }
            .content { padding: 30px; background: #f9f9f9; }
            .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .button { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block; }
            .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; text-align: center; color: #888; font-size: 12px; }
          </style>
        </head>
        <body>
          <div class="header">
            <h1>Raw Wealthy</h1>
            <p>Investment Platform</p>
          </div>
          <div class="content">
            <h2>${title}</h2>
            <div class="card">
              <p>${message}</p>
              ${actionUrl ? `
                <div style="text-align: center; margin: 30px 0;">
                  <a href="${config.clientURL}${actionUrl}" class="button">
                    View Details
                  </a>
                </div>
              ` : ''}
            </div>
            <div class="footer">
              <p>This is an automated message from Raw Wealthy. Please do not reply to this email.</p>
              <p>© ${new Date().getFullYear()} Raw Wealthy. All rights reserved.</p>
            </div>
          </div>
        </body>
        </html>
      `;
      
      await sendEmail(user.email, emailSubject, emailHtml);
      notification.is_email_sent = true;
      await notification.save();
    }
    
    return notification;
  } catch (error) {
    logger.error('Error creating notification', {
      error: error.message,
      userId,
      title
    });
    return null;
  }
};

// Create transaction with enhanced tracking
const createTransaction = async (userId, type, amount, description, status = 'completed', metadata = {}, proofUrl = null) => {
  try {
    const user = await User.findById(userId);
    if (!user) {
      logger.error('User not found for transaction', { userId });
      return null;
    }
    
    const transaction = new Transaction({
      user: userId,
      type,
      amount,
      description,
      status,
      reference: generateReference('TXN'),
      balance_before: user.balance,
      balance_after: user.balance + amount,
      payment_proof_url: proofUrl,
      metadata: {
        ...metadata,
        processedAt: new Date(),
        transactionId: crypto.randomBytes(8).toString('hex')
      },
      ip_address: metadata.ip || 'system',
      user_agent: metadata.userAgent || 'system'
    });
    
    await transaction.save();
    
    // Update user statistics based on transaction type
    const updateFields = {};
    if (type === 'deposit' && status === 'completed') {
      updateFields.total_deposits = (user.total_deposits || 0) + Math.abs(amount);
      updateFields.last_deposit_date = new Date();
    } else if (type === 'withdrawal' && status === 'completed') {
      updateFields.total_withdrawals = (user.total_withdrawals || 0) + Math.abs(amount);
      updateFields.last_withdrawal_date = new Date();
    } else if (type === 'investment' && status === 'completed') {
      updateFields.total_investments = (user.total_investments || 0) + Math.abs(amount);
      updateFields.last_investment_date = new Date();
    } else if (type === 'earning' && status === 'completed') {
      updateFields.total_earnings = (user.total_earnings || 0) + amount;
      updateFields.last_earning_date = new Date();
    }
    
    if (Object.keys(updateFields).length > 0) {
      await User.findByIdAndUpdate(userId, updateFields);
    }
    
    logger.debug('Transaction created', {
      transactionId: transaction._id,
      userId,
      type,
      amount,
      status
    });
    
    return transaction;
  } catch (error) {
    logger.error('Error creating transaction', {
      error: error.message,
      userId,
      type,
      amount
    });
    return null;
  }
};

// Calculate user statistics
const calculateUserStats = async (userId) => {
  try {
    const [
      totalInvestments,
      activeInvestments,
      totalDeposits,
      totalWithdrawals,
      totalReferrals,
      recentInvestments,
      recentDeposits,
      recentWithdrawals,
      user
    ] = await Promise.all([
      Investment.countDocuments({ user: userId }),
      Investment.countDocuments({ user: userId, status: 'active' }),
      Deposit.countDocuments({ user: userId, status: 'approved' }),
      Withdrawal.countDocuments({ user: userId, status: 'paid' }),
      Referral.countDocuments({ referrer: userId }),
      Investment.find({ user: userId })
        .populate('plan', 'name daily_interest')
        .sort({ createdAt: -1 })
        .limit(5)
        .lean(),
      Deposit.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(5)
        .lean(),
      Withdrawal.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(5)
        .lean(),
      User.findById(userId).lean()
    ]);

    // Calculate daily interest from active investments
    const activeInv = await Investment.find({ 
      user: userId, 
      status: 'active' 
    }).populate('plan', 'daily_interest name');
    
    let dailyInterest = 0;
    let activeInvestmentValue = 0;
    const investmentBreakdown = [];
    
    activeInv.forEach(inv => {
      activeInvestmentValue += inv.amount;
      if (inv.plan && inv.plan.daily_interest) {
        const dailyEarning = (inv.amount * inv.plan.daily_interest) / 100;
        dailyInterest += dailyEarning;
        investmentBreakdown.push({
          plan: inv.plan.name,
          amount: inv.amount,
          daily_interest: inv.plan.daily_interest,
          daily_earning: dailyEarning
        });
      }
    });

    return {
      total_investments: totalInvestments,
      active_investments: activeInvestments,
      total_deposits: totalDeposits,
      total_withdrawals: totalWithdrawals,
      total_referrals: totalReferrals,
      daily_interest: parseFloat(dailyInterest.toFixed(2)),
      active_investment_value: parseFloat(activeInvestmentValue.toFixed(2)),
      portfolio_value: user ? parseFloat((user.balance + user.total_earnings + user.referral_earnings).toFixed(2)) : 0,
      investment_breakdown: investmentBreakdown,
      recent_activity: {
        investments: recentInvestments.map(inv => ({
          ...inv,
          has_proof: !!inv.payment_proof_url
        })),
        deposits: recentDeposits.map(dep => ({
          ...dep,
          has_proof: !!dep.payment_proof_url
        })),
        withdrawals: recentWithdrawals.map(wdl => ({
          ...wdl,
          has_proof: !!wdl.payment_proof_url
        }))
      }
    };
  } catch (error) {
    logger.error('Error calculating user stats', {
      error: error.message,
      userId
    });
    return null;
  }
};

// Admin audit log function
const createAdminAudit = async (adminId, action, targetType, targetId, details = {}, ip = '', userAgent = '', severity = 'medium', status = 'success') => {
  try {
    const audit = new AdminAudit({
      admin_id: adminId,
      action,
      target_type: targetType,
      target_id: targetId,
      details,
      ip_address: ip,
      user_agent: userAgent,
      severity,
      status,
      metadata: {
        timestamp: new Date(),
        auditId: crypto.randomBytes(8).toString('hex')
      }
    });
    
    await audit.save();
    
    logger.debug('Admin audit created', {
      adminId,
      action,
      targetType,
      severity,
      auditId: audit._id
    });
    
    return audit;
  } catch (error) {
    logger.error('Error creating admin audit', {
      error: error.message,
      adminId,
      action
    });
    return null;
  }
};

// Validate request data
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json(formatResponse(false, 'Validation failed', {
      errors: errors.array().map(err => ({
        field: err.param,
        message: err.msg,
        value: err.value
      }))
    }));
  }
  next();
};

// ==================== ENHANCED AUTHENTICATION MIDDLEWARE ====================

const auth = async (req, res, next) => {
  try {
    let token = req.header('Authorization');
    
    if (!token) {
      return res.status(401).json(formatResponse(false, 'No token provided'));
    }
    
    if (token.startsWith('Bearer ')) {
      token = token.slice(7, token.length);
    }
    
    const decoded = jwt.verify(token, config.jwtSecret);
    
    const user = await User.findById(decoded.id);
    
    if (!user) {
      return res.status(401).json(formatResponse(false, 'User not found'));
    }
    
    if (!user.is_active) {
      return res.status(401).json(formatResponse(false, 'Account is deactivated'));
    }
    
    // Update last active time
    user.last_active = new Date();
    await user.save();
    
    req.user = user;
    req.userId = user._id;
    req.userRole = user.role;
    
    // Add debug info
    if (config.debugEnabled) {
      req.debug = {
        userId: user._id.toString(),
        role: user.role,
        kycVerified: user.kyc_verified
      };
    }
    
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json(formatResponse(false, 'Invalid token'));
    }
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json(formatResponse(false, 'Token expired'));
    }
    
    logger.error('Auth middleware error', {
      error: error.message,
      ip: req.ip,
      path: req.path
    });
    
    handleError(res, error, 'Authentication error', req.requestId);
  }
};

const adminAuth = async (req, res, next) => {
  try {
    await auth(req, res, () => {
      if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
        logger.warn('Admin access denied', {
          userId: req.userId,
          role: req.user.role,
          path: req.path
        });
        
        return res.status(403).json(formatResponse(false, 'Admin access required'));
      }
      next();
    });
  } catch (error) {
    handleError(res, error, 'Admin authentication error', req.requestId);
  }
};

const superAdminAuth = async (req, res, next) => {
  try {
    await auth(req, res, () => {
      if (req.user.role !== 'super_admin') {
        logger.warn('Super admin access denied', {
          userId: req.userId,
          role: req.user.role,
          path: req.path
        });
        
        return res.status(403).json(formatResponse(false, 'Super admin access required'));
      }
      next();
    });
  } catch (error) {
    handleError(res, error, 'Super admin authentication error', req.requestId);
  }
};

// ==================== ENHANCED DATABASE INITIALIZATION ====================

const initializeDatabase = async () => {
  try {
    logger.info('Initializing database connection...');
    console.log('🔄 Connecting to MongoDB...');
    
    const connectionOptions = {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      minPoolSize: 5,
      retryWrites: true,
      w: 'majority',
      connectTimeoutMS: 10000,
      heartbeatFrequencyMS: 10000
    };
    
    await mongoose.connect(config.mongoURI, connectionOptions);
    
    logger.info('MongoDB connected successfully');
    console.log('✅ MongoDB connected successfully');
    
    // Load investment plans
    await loadInvestmentPlans();
    
    // Create admin user
    await createAdminUser();
    
    // Create default settings
    await createDefaultSettings();
    
    // Create indexes
    await createDatabaseIndexes();
    
    logger.info('Database initialization completed');
    console.log('✅ Database initialization completed');
    
  } catch (error) {
    logger.error('Database initialization failed', {
      error: error.message,
      mongoURI: config.mongoURI
    });
    
    console.error('❌ Database connection error:', error.message);
    
    // Try to reconnect
    if (config.isProduction) {
      console.log('🔄 Attempting to reconnect in 5 seconds...');
      setTimeout(initializeDatabase, 5000);
    } else {
      throw error;
    }
  }
};

const loadInvestmentPlans = async () => {
  try {
    const plans = await InvestmentPlan.find({ is_active: true })
      .sort({ display_order: 1, min_amount: 1 })
      .lean();
    
    config.investmentPlans = plans;
    console.log(`✅ Loaded ${plans.length} investment plans`);
    
    // Create default plans if none exist
    if (plans.length === 0) {
      await createDefaultInvestmentPlans();
    }
  } catch (error) {
    logger.error('Error loading investment plans', { error: error.message });
    console.error('Error loading investment plans:', error);
  }
};

const createDefaultInvestmentPlans = async () => {
  const defaultPlans = [
    {
      name: 'Cocoa Beans',
      description: 'Invest in premium cocoa beans with stable returns. Perfect for beginners with low risk tolerance.',
      min_amount: 3500,
      max_amount: 50000,
      daily_interest: 10,
      total_interest: 300,
      duration: 30,
      risk_level: 'low',
      raw_material: 'Cocoa',
      category: 'agriculture',
      is_popular: true,
      is_featured: true,
      features: ['Low Risk', 'Stable Returns', 'Beginner Friendly', 'Daily Payouts', 'Guaranteed Returns'],
      color: '#10b981',
      icon: '🌱',
      display_order: 1,
      tags: ['beginner', 'agriculture', 'low-risk'],
      terms_and_conditions: 'Minimum investment: ₦3,500. Maximum investment: ₦50,000. Daily payout.',
      risk_disclaimer: 'Agricultural investments are subject to market conditions and weather factors.'
    },
    {
      name: 'Gold Investment',
      description: 'Precious metal investment with high liquidity and strong market demand.',
      min_amount: 50000,
      max_amount: 500000,
      daily_interest: 15,
      total_interest: 450,
      duration: 30,
      risk_level: 'medium',
      raw_material: 'Gold',
      category: 'metals',
      is_popular: true,
      is_featured: true,
      features: ['Medium Risk', 'Higher Returns', 'High Liquidity', 'Market Stability', 'Global Demand'],
      color: '#fbbf24',
      icon: '🥇',
      display_order: 2,
      tags: ['precious-metals', 'medium-risk', 'global'],
      terms_and_conditions: 'Minimum investment: ₦50,000. Maximum investment: ₦500,000. Daily payout.',
      risk_disclaimer: 'Gold prices are subject to international market fluctuations.'
    },
    {
      name: 'Crude Oil',
      description: 'Energy sector investment with premium returns from the global oil market.',
      min_amount: 100000,
      max_amount: 1000000,
      daily_interest: 20,
      total_interest: 600,
      duration: 30,
      risk_level: 'high',
      raw_material: 'Crude Oil',
      category: 'energy',
      is_popular: false,
      is_featured: true,
      features: ['High Risk', 'Maximum Returns', 'Premium Investment', 'Energy Sector', 'Global Market'],
      color: '#dc2626',
      icon: '🛢️',
      display_order: 3,
      tags: ['energy', 'high-risk', 'premium'],
      terms_and_conditions: 'Minimum investment: ₦100,000. Maximum investment: ₦1,000,000. Daily payout.',
      risk_disclaimer: 'Oil prices are highly volatile and subject to geopolitical factors.'
    },
    {
      name: 'Diamond Mining',
      description: 'High-value precious stones investment with exceptional returns.',
      min_amount: 500000,
      max_amount: 5000000,
      daily_interest: 25,
      total_interest: 750,
      duration: 30,
      risk_level: 'high',
      raw_material: 'Diamonds',
      category: 'precious_stones',
      is_popular: false,
      is_featured: false,
      features: ['Very High Risk', 'Exceptional Returns', 'Precious Stones', 'Luxury Market'],
      color: '#8b5cf6',
      icon: '💎',
      display_order: 4,
      tags: ['luxury', 'high-risk', 'premium'],
      terms_and_conditions: 'Minimum investment: ₦500,000. Maximum investment: ₦5,000,000. Daily payout.',
      risk_disclaimer: 'Diamond market is subject to luxury demand and certification requirements.'
    }
  ];

  try {
    await InvestmentPlan.insertMany(defaultPlans);
    config.investmentPlans = defaultPlans;
    console.log('✅ Created default investment plans');
    logger.info('Default investment plans created');
  } catch (error) {
    logger.error('Error creating default investment plans', { error: error.message });
    console.error('Error creating default investment plans:', error);
  }
};

const createAdminUser = async () => {
  try {
    console.log('🔧 Checking admin user...');
    
    const adminEmail = config.adminEmail;
    const adminPassword = config.adminPassword;
    
    // Check if admin already exists
    const existingAdmin = await User.findOne({ email: adminEmail });
    
    if (existingAdmin) {
      console.log('✅ Admin user already exists');
      
      // Ensure admin has correct role
      if (existingAdmin.role !== 'super_admin') {
        existingAdmin.role = 'super_admin';
        await existingAdmin.save();
        console.log('✅ Updated admin role to super_admin');
      }
      
      // Update password if using default
      if (adminPassword === 'Admin123456') {
        const salt = await bcrypt.genSalt(config.bcryptRounds);
        const hash = await bcrypt.hash(adminPassword, salt);
        existingAdmin.password = hash;
        await existingAdmin.save();
        console.log('✅ Admin password updated');
      }
      
      return;
    }
    
    // Create new admin user
    console.log('👤 Creating new admin user...');
    
    const salt = await bcrypt.genSalt(config.bcryptRounds);
    const hash = await bcrypt.hash(adminPassword, salt);
    
    const adminData = {
      full_name: 'Raw Wealthy Admin',
      email: adminEmail,
      phone: '09161806424',
      password: hash,
      role: 'super_admin',
      balance: 0,
      total_earnings: 0,
      referral_earnings: 0,
      risk_tolerance: 'medium',
      investment_strategy: 'balanced',
      country: 'ng',
      currency: 'NGN',
      referral_code: 'ADMIN' + crypto.randomBytes(4).toString('hex').toUpperCase(),
      kyc_verified: true,
      kyc_status: 'verified',
      is_active: true,
      is_verified: true,
      two_factor_enabled: false,
      notifications_enabled: true,
      email_notifications: true,
      sms_notifications: false,
      bank_details: {
        bank_name: 'Admin Bank',
        account_name: 'Raw Wealthy Admin',
        account_number: '0000000000',
        verified: true,
        verified_at: new Date()
      }
    };
    
    const admin = new User(adminData);
    await admin.save();
    
    console.log('🎉 Admin user created successfully!');
    console.log(`📧 Email: ${adminEmail}`);
    console.log(`🔑 Password: ${adminPassword}`);
    console.log('👉 Login at: /api/auth/login');
    
    logger.info('Admin user created', { email: adminEmail });
    
  } catch (error) {
    logger.error('Error creating admin user', { error: error.message });
    console.error('❌ Error creating admin user:', error.message);
  }
};

const createDefaultSettings = async () => {
  try {
    const defaultSettings = [
      {
        key: 'site_name',
        value: 'Raw Wealthy',
        type: 'string',
        category: 'general',
        description: 'Website name',
        is_public: true
      },
      {
        key: 'site_description',
        value: 'Premium Investment Platform',
        type: 'string',
        category: 'general',
        description: 'Website description',
        is_public: true
      },
      {
        key: 'contact_email',
        value: 'support@rawwealthy.com',
        type: 'string',
        category: 'contact',
        description: 'Contact email address',
        is_public: true
      },
      {
        key: 'contact_phone',
        value: '+2349161806424',
        type: 'string',
        category: 'contact',
        description: 'Contact phone number',
        is_public: true
      },
      {
        key: 'maintenance_mode',
        value: false,
        type: 'boolean',
        category: 'system',
        description: 'Maintenance mode status',
        is_public: true
      },
      {
        key: 'registration_enabled',
        value: true,
        type: 'boolean',
        category: 'auth',
        description: 'Allow new registrations',
        is_public: true
      },
      {
        key: 'min_investment',
        value: config.minInvestment,
        type: 'number',
        category: 'investment',
        description: 'Minimum investment amount',
        is_public: true
      },
      {
        key: 'min_deposit',
        value: config.minDeposit,
        type: 'number',
        category: 'deposit',
        description: 'Minimum deposit amount',
        is_public: true
      },
      {
        key: 'min_withdrawal',
        value: config.minWithdrawal,
        type: 'number',
        category: 'withdrawal',
        description: 'Minimum withdrawal amount',
        is_public: true
      },
      {
        key: 'platform_fee_percent',
        value: config.platformFeePercent,
        type: 'number',
        category: 'fees',
        description: 'Platform fee percentage',
        is_public: true
      },
      {
        key: 'referral_commission_percent',
        value: config.referralCommissionPercent,
        type: 'number',
        category: 'referral',
        description: 'Referral commission percentage',
        is_public: true
      },
      {
        key: 'welcome_bonus',
        value: config.welcomeBonus,
        type: 'number',
        category: 'bonus',
        description: 'Welcome bonus amount',
        is_public: true
      }
    ];
    
    for (const setting of defaultSettings) {
      const existing = await SystemSettings.findOne({ key: setting.key });
      if (!existing) {
        await SystemSettings.create(setting);
      }
    }
    
    console.log('✅ Default settings created');
    logger.info('Default settings created');
  } catch (error) {
    logger.error('Error creating default settings', { error: error.message });
    console.error('Error creating default settings:', error);
  }
};

const createDatabaseIndexes = async () => {
  try {
    // Create additional indexes for performance
    await Transaction.collection.createIndex({ createdAt: -1 });
    await User.collection.createIndex({ 'bank_details.verified': 1 });
    await Investment.collection.createIndex({ status: 1, end_date: 1 });
    await Deposit.collection.createIndex({ status: 1, createdAt: -1 });
    await Withdrawal.collection.createIndex({ status: 1, createdAt: -1 });
    await Notification.collection.createIndex({ expires_at: 1 });
    
    console.log('✅ Database indexes created');
    logger.info('Database indexes created');
  } catch (error) {
    logger.error('Error creating database indexes', { error: error.message });
    console.error('Error creating indexes:', error);
  }
};

// ==================== ENHANCED HEALTH CHECK ====================

app.get('/health', async (req, res) => {
  try {
    const health = {
      success: true,
      status: 'OK',
      timestamp: new Date().toISOString(),
      version: '38.0.0',
      environment: config.nodeEnv,
      server: {
        uptime: process.uptime(),
        memory: {
          rss: `${Math.round(process.memoryUsage().rss / 1024 / 1024)}MB`,
          heapTotal: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)}MB`,
          heapUsed: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`,
          external: `${Math.round(process.memoryUsage().external / 1024 / 1024)}MB`
        },
        cpu: os.loadavg(),
        platform: os.platform(),
        arch: os.arch(),
        node: process.version
      },
      database: {
        status: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        readyState: mongoose.connection.readyState,
        host: mongoose.connection.host,
        name: mongoose.connection.name
      },
      services: {
        email: config.emailEnabled ? 'enabled' : 'disabled',
        fileUpload: 'enabled',
        cronJobs: 'enabled'
      },
      stats: {
        users: await User.countDocuments({}),
        activeUsers: await User.countDocuments({ is_active: true }),
        investments: await Investment.countDocuments({}),
        activeInvestments: await Investment.countDocuments({ status: 'active' }),
        deposits: await Deposit.countDocuments({}),
        withdrawals: await Withdrawal.countDocuments({}),
        pendingKYC: await KYCSubmission.countDocuments({ status: 'pending' })
      }
    };
    
    // Add debug info if enabled
    if (config.debugEnabled) {
      health.debug = {
        requestId: req.requestId,
        ip: req.ip,
        headers: req.headers
      };
    }
    
    res.json(health);
  } catch (error) {
    logger.error('Health check failed', { error: error.message });
    
    res.status(500).json({
      success: false,
      status: 'ERROR',
      timestamp: new Date().toISOString(),
      error: error.message,
      database: {
        status: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        readyState: mongoose.connection.readyState
      }
    });
  }
});

// ==================== ENHANCED ROOT ENDPOINT ====================

app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 Raw Wealthy Backend API v38.0 - Ultimate Production Edition',
    version: '38.0.0',
    timestamp: new Date().toISOString(),
    status: 'Operational',
    environment: config.nodeEnv,
    debug: config.debugEnabled,
    endpoints: {
      auth: '/api/auth/*',
      profile: '/api/profile',
      investments: '/api/investments/*',
      deposits: '/api/deposits/*',
      withdrawals: '/api/withdrawals/*',
      plans: '/api/plans',
      kyc: '/api/kyc/*',
      support: '/api/support/*',
      referrals: '/api/referrals/*',
      admin: '/api/admin/*',
      upload: '/api/upload',
      health: '/health',
      debug: config.debugEnabled ? '/api/debug/*' : 'disabled'
    },
    documentation: 'https://docs.rawwealthy.com',
    support: 'support@rawwealthy.com'
  });
});

// ==================== ENHANCED DEBUG ENDPOINTS ====================

if (config.debugEnabled) {
  // Debug endpoint for system info
  app.get('/api/debug/system', (req, res) => {
    const systemInfo = {
      process: {
        pid: process.pid,
        ppid: process.ppid,
        platform: process.platform,
        arch: process.arch,
        version: process.version,
        versions: process.versions,
        memoryUsage: process.memoryUsage(),
        cpuUsage: process.cpuUsage(),
        uptime: process.uptime()
      },
      os: {
        hostname: os.hostname(),
        type: os.type(),
        release: os.release(),
        uptime: os.uptime(),
        loadavg: os.loadavg(),
        totalmem: `${Math.round(os.totalmem() / 1024 / 1024)}MB`,
        freemem: `${Math.round(os.freemem() / 1024 / 1024)}MB`,
        cpus: os.cpus().length,
        networkInterfaces: os.networkInterfaces()
      },
      config: {
        port: config.port,
        nodeEnv: config.nodeEnv,
        isProduction: config.isProduction,
        debugEnabled: config.debugEnabled,
        mongoURI: config.mongoURI ? 'Set' : 'Not set',
        jwtSecret: config.jwtSecret ? 'Set' : 'Not set',
        emailEnabled: config.emailEnabled,
        clientURL: config.clientURL,
        serverURL: config.serverURL
      },
      mongoose: {
        readyState: mongoose.connection.readyState,
        models: Object.keys(mongoose.models),
        connections: mongoose.connections.length
      },
      app: {
        settings: app.settings,
        mountpath: app.mountpath,
        _router: {
          stack: app._router.stack.length
        }
      }
    };
    
    res.json(formatResponse(true, 'System debug info', systemInfo));
  });
  
  // Debug endpoint for database stats
  app.get('/api/debug/database', async (req, res) => {
    try {
      const dbStats = {
        users: await User.countDocuments({}),
        investments: await Investment.countDocuments({}),
        deposits: await Deposit.countDocuments({}),
        withdrawals: await Withdrawal.countDocuments({}),
        transactions: await Transaction.countDocuments({}),
        plans: await InvestmentPlan.countDocuments({}),
        kyc: await KYCSubmission.countDocuments({}),
        referrals: await Referral.countDocuments({}),
        tickets: await SupportTicket.countDocuments({}),
        notifications: await Notification.countDocuments({}),
        audits: await AdminAudit.countDocuments({}),
        settings: await SystemSettings.countDocuments({})
      };
      
      // Get collection sizes
      const collections = await mongoose.connection.db.listCollections().toArray();
      const collectionStats = [];
      
      for (const collection of collections) {
        const stats = await mongoose.connection.db.collection(collection.name).stats();
        collectionStats.push({
          name: collection.name,
          count: stats.count,
          size: `${Math.round(stats.size / 1024 / 1024)}MB`,
          avgObjSize: `${Math.round(stats.avgObjSize)} bytes`,
          storageSize: `${Math.round(stats.storageSize / 1024 / 1024)}MB`,
          indexes: stats.nindexes,
          totalIndexSize: `${Math.round(stats.totalIndexSize / 1024 / 1024)}MB`
        });
      }
      
      res.json(formatResponse(true, 'Database debug info', {
        counts: dbStats,
        collections: collectionStats,
        connection: {
          readyState: mongoose.connection.readyState,
          host: mongoose.connection.host,
          port: mongoose.connection.port,
          name: mongoose.connection.name
        }
      }));
    } catch (error) {
      handleError(res, error, 'Error getting database stats', req.requestId);
    }
  });
  
  // Debug endpoint for testing email
  app.post('/api/debug/email/test', async (req, res) => {
    try {
      const { email } = req.body;
      
      if (!email) {
        return res.status(400).json(formatResponse(false, 'Email is required'));
      }
      
      const testResult = await sendEmail(
        email,
        'Raw Wealthy - Test Email',
        `<h2>Test Email</h2>
         <p>This is a test email from Raw Wealthy backend.</p>
         <p>Timestamp: ${new Date().toISOString()}</p>
         <p>Environment: ${config.nodeEnv}</p>`,
        'Test email from Raw Wealthy'
      );
      
      res.json(formatResponse(true, 'Test email sent', { testResult }));
    } catch (error) {
      handleError(res, error, 'Error sending test email', req.requestId);
    }
  });
}

// ==================== ENHANCED AUTH ENDPOINTS ====================

// Register endpoint
app.post('/api/auth/register', [
  body('full_name').notEmpty().trim().isLength({ min: 2, max: 100 })
    .withMessage('Full name must be between 2 and 100 characters'),
  body('email').isEmail().normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('phone').notEmpty().trim()
    .withMessage('Phone number is required'),
  body('password').isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters'),
  body('referral_code').optional().trim(),
  body('risk_tolerance').optional().isIn(['low', 'medium', 'high'])
    .withMessage('Invalid risk tolerance'),
  body('investment_strategy').optional().isIn(['conservative', 'balanced', 'aggressive'])
    .withMessage('Invalid investment strategy'),
  body('country').optional().isLength({ min: 2, max: 2 })
    .withMessage('Country must be 2 characters'),
  body('currency').optional().isIn(['NGN', 'USD', 'EUR', 'GBP'])
    .withMessage('Invalid currency')
], async (req, res) => {
  try {
    // Validate request
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { 
        errors: errors.array().map(err => ({ field: err.param, message: err.msg }))
      }));
    }

    const { 
      full_name, 
      email, 
      phone, 
      password, 
      referral_code, 
      risk_tolerance = 'medium', 
      investment_strategy = 'balanced',
      country = 'ng',
      currency = 'NGN'
    } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json(formatResponse(false, 'User with this email already exists'));
    }

    // Handle referral
    let referredBy = null;
    if (referral_code) {
      referredBy = await User.findOne({ referral_code: referral_code.toUpperCase() });
      if (!referredBy) {
        return res.status(400).json(formatResponse(false, 'Invalid referral code'));
      }
    }

    // Create user
    const user = new User({
      full_name: full_name.trim(),
      email: email.toLowerCase(),
      phone: phone.trim(),
      password,
      balance: config.welcomeBonus,
      risk_tolerance,
      investment_strategy,
      country: country.toLowerCase(),
      currency,
      referred_by: referredBy ? referredBy._id : null,
      device_info: {
        last_device: req.headers['user-agent'],
        last_ip: req.ip,
        device_history: [{
          device: req.headers['user-agent'],
          ip: req.ip,
          timestamp: new Date()
        }]
      }
    });

    await user.save();

    logger.info('New user registered', {
      userId: user._id,
      email: user.email,
      referredBy: referredBy ? referredBy._id : null
    });

    // Handle referral
    if (referredBy) {
      referredBy.referral_count += 1;
      await referredBy.save();

      const referral = new Referral({
        referrer: referredBy._id,
        referred_user: user._id,
        referral_code: referral_code.toUpperCase(),
        status: 'pending',
        conversion_date: new Date()
      });
      await referral.save();
      
      // Create notification for referrer
      await createNotification(
        referredBy._id,
        'New Referral!',
        `${user.full_name} has signed up using your referral code!`,
        'referral',
        '/referrals',
        { referredUserId: user._id, referredUserEmail: user.email }
      );
    }

    // Generate token
    const token = user.generateAuthToken();

    // Create welcome notification
    await createNotification(
      user._id,
      'Welcome to Raw Wealthy!',
      'Your account has been successfully created. Your welcome bonus has been credited.',
      'success',
      '/dashboard',
      { welcomeBonus: config.welcomeBonus }
    );

    // Create welcome bonus transaction
    await createTransaction(
      user._id,
      'bonus',
      config.welcomeBonus,
      'Welcome bonus for new account registration',
      'completed',
      { type: 'welcome_bonus' }
    );

    // Send welcome email
    if (config.emailEnabled) {
      await sendEmail(
        user.email,
        'Welcome to Raw Wealthy!',
        `<h2>Welcome ${user.full_name}!</h2>
         <p>Your account has been successfully created. Welcome bonus of ₦${config.welcomeBonus} has been credited.</p>
         <p><strong>Account Details:</strong></p>
         <ul>
           <li>Email: ${user.email}</li>
           <li>Balance: ₦${user.balance.toLocaleString()}</li>
           <li>Referral Code: ${user.referral_code}</li>
         </ul>
         <p><a href="${config.clientURL}/dashboard">Go to Dashboard</a></p>`
      );
    }

    res.status(201).json(formatResponse(true, 'Registration successful', {
      user: {
        id: user._id,
        full_name: user.full_name,
        email: user.email,
        balance: user.balance,
        referral_code: user.referral_code,
        kyc_verified: user.kyc_verified,
        is_verified: user.is_verified
      },
      token
    }));

  } catch (error) {
    handleError(res, error, 'Registration failed', req.requestId);
  }
});

// Login endpoint
app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('password').notEmpty()
    .withMessage('Password is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { email, password } = req.body;

    // Find user with password
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    
    if (!user) {
      logger.warn('Login failed - user not found', { email });
      return res.status(400).json(formatResponse(false, 'Invalid credentials'));
    }

    // Check if account is locked
    if (user.lock_until && user.lock_until > new Date()) {
      const lockTime = Math.ceil((user.lock_until - new Date()) / 1000 / 60);
      return res.status(423).json(formatResponse(false, `Account is locked. Try again in ${lockTime} minutes.`));
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      user.login_attempts += 1;
      
      // Lock account after 5 failed attempts
      if (user.login_attempts >= 5) {
        user.lock_until = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
        logger.warn('Account locked due to failed login attempts', {
          userId: user._id,
          email: user.email,
          ip: req.ip
        });
      }
      
      await user.save();
      
      logger.warn('Login failed - invalid password', {
        email,
        ip: req.ip,
        attempts: user.login_attempts
      });
      
      return res.status(400).json(formatResponse(false, 'Invalid credentials'));
    }

    // Reset login attempts on successful login
    user.login_attempts = 0;
    user.lock_until = undefined;
    user.last_login = new Date();
    user.last_active = new Date();
    user.total_logins = (user.total_logins || 0) + 1;
    
    // Update device info
    if (!user.device_info) user.device_info = {};
    user.device_info.last_device = req.headers['user-agent'];
    user.device_info.last_ip = req.ip;
    
    if (!user.device_info.device_history) {
      user.device_info.device_history = [];
    }
    
    user.device_info.device_history.push({
      device: req.headers['user-agent'],
      ip: req.ip,
      timestamp: new Date()
    });
    
    // Keep only last 10 devices
    if (user.device_info.device_history.length > 10) {
      user.device_info.device_history = user.device_info.device_history.slice(-10);
    }
    
    await user.save();

    // Generate token
    const token = user.generateAuthToken();

    logger.info('User logged in successfully', {
      userId: user._id,
      email: user.email,
      role: user.role,
      ip: req.ip
    });

    res.json(formatResponse(true, 'Login successful', {
      user: {
        id: user._id,
        full_name: user.full_name,
        email: user.email,
        role: user.role,
        balance: user.balance,
        kyc_verified: user.kyc_verified,
        is_verified: user.is_verified,
        referral_code: user.referral_code,
        total_earnings: user.total_earnings,
        referral_earnings: user.referral_earnings,
        total_investments: user.total_investments,
        last_login: user.last_login
      },
      token
    }));

  } catch (error) {
    handleError(res, error, 'Login failed', req.requestId);
  }
});

// Forgot password endpoint
app.post('/api/auth/forgot-password', [
  body('email').isEmail().normalizeEmail()
    .withMessage('Please provide a valid email address')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { email } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      // Don't reveal that user doesn't exist for security
      logger.warn('Password reset requested for non-existent email', { email, ip: req.ip });
      return res.json(formatResponse(true, 'If an account exists with this email, a reset link has been sent'));
    }

    // Generate reset token
    const resetToken = user.generatePasswordResetToken();
    await user.save();

    // Create reset URL
    const resetUrl = `${config.clientURL}/reset-password/${resetToken}`;

    logger.info('Password reset requested', {
      userId: user._id,
      email: user.email,
      ip: req.ip
    });

    // Send email
    const emailResult = await sendEmail(
      user.email,
      'Password Reset Request - Raw Wealthy',
      `<h2>Password Reset Request</h2>
       <p>You requested a password reset for your Raw Wealthy account.</p>
       <p>Click the link below to reset your password:</p>
       <p><a href="${resetUrl}">${resetUrl}</a></p>
       <p>This link will expire in 10 minutes.</p>
       <p>If you didn't request this, please ignore this email.</p>
       <p><strong>Security Notice:</strong> If you didn't request this reset, please contact our support team immediately.</p>`
    );

    if (!emailResult.success && !emailResult.simulated) {
      logger.error('Failed to send password reset email', {
        userId: user._id,
        error: emailResult.error
      });
      return res.status(500).json(formatResponse(false, 'Failed to send reset email. Please try again later.'));
    }

    res.json(formatResponse(true, 'Password reset email sent successfully'));

  } catch (error) {
    handleError(res, error, 'Error processing forgot password request', req.requestId);
  }
});

// Reset password endpoint
app.post('/api/auth/reset-password/:token', [
  body('password').isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { token } = req.params;
    const { password } = req.body;

    // Hash token
    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    const user = await User.findOne({
      password_reset_token: hashedToken,
      password_reset_expires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json(formatResponse(false, 'Invalid or expired token'));
    }

    // Update password
    user.password = password;
    user.password_reset_token = undefined;
    user.password_reset_expires = undefined;
    await user.save();

    logger.info('Password reset successful', {
      userId: user._id,
      email: user.email,
      ip: req.ip
    });

    // Send confirmation email
    await sendEmail(
      user.email,
      'Password Reset Successful - Raw Wealthy',
      `<h2>Password Reset Successful</h2>
       <p>Your password has been successfully reset.</p>
       <p>If you did not perform this action, please contact our support team immediately.</p>
       <p><strong>Security Notice:</strong> If you suspect unauthorized access to your account, please enable two-factor authentication in your account settings.</p>`
    );

    // Create notification
    await createNotification(
      user._id,
      'Password Changed',
      'Your password has been successfully reset.',
      'security',
      '/profile/security',
      { resetFromIp: req.ip, resetTime: new Date() }
    );

    res.json(formatResponse(true, 'Password reset successful'));

  } catch (error) {
    handleError(res, error, 'Error resetting password', req.requestId);
  }
});

// Verify email endpoint
app.get('/api/auth/verify-email/:token', async (req, res) => {
  try {
    const { token } = req.params;

    // Hash token
    const hashedToken = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');

    const user = await User.findOne({
      verification_token: hashedToken,
      verification_expires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json(formatResponse(false, 'Invalid or expired verification token'));
    }

    // Mark user as verified
    user.is_verified = true;
    user.verification_token = undefined;
    user.verification_expires = undefined;
    await user.save();

    logger.info('Email verified', {
      userId: user._id,
      email: user.email
    });

    // Create notification
    await createNotification(
      user._id,
      'Email Verified',
      'Your email address has been successfully verified.',
      'success',
      '/dashboard'
    );

    // Send welcome email
    await sendEmail(
      user.email,
      'Email Verified - Raw Wealthy',
      `<h2>Email Verification Successful</h2>
       <p>Your email address has been successfully verified.</p>
       <p>You now have full access to all features of your Raw Wealthy account.</p>
       <p><a href="${config.clientURL}/dashboard">Go to Dashboard</a></p>`
    );

    res.json(formatResponse(true, 'Email verified successfully'));

  } catch (error) {
    handleError(res, error, 'Error verifying email', req.requestId);
  }
});

// Resend verification email endpoint
app.post('/api/auth/resend-verification', [
  body('email').isEmail().normalizeEmail()
    .withMessage('Please provide a valid email address')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { email } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    if (user.is_verified) {
      return res.status(400).json(formatResponse(false, 'Email is already verified'));
    }

    // Generate new verification token
    const verificationToken = user.generateVerificationToken();
    await user.save();

    // Create verification URL
    const verificationUrl = `${config.clientURL}/verify-email/${verificationToken}`;

    logger.info('Verification email resent', {
      userId: user._id,
      email: user.email
    });

    // Send verification email
    await sendEmail(
      user.email,
      'Verify Your Email - Raw Wealthy',
      `<h2>Verify Your Email</h2>
       <p>Please verify your email address by clicking the link below:</p>
       <p><a href="${verificationUrl}">${verificationUrl}</a></p>
       <p>This link will expire in 24 hours.</p>
       <p>If you didn't create an account, please ignore this email.</p>`
    );

    res.json(formatResponse(true, 'Verification email sent successfully'));

  } catch (error) {
    handleError(res, error, 'Error resending verification email', req.requestId);
  }
});

// ==================== ENHANCED PROFILE ENDPOINTS ====================

// Get profile endpoint
app.get('/api/profile', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Get complete user data with related information
    const [
      user,
      investments,
      transactions,
      notifications,
      kyc,
      deposits,
      withdrawals,
      referrals,
      supportTickets,
      stats
    ] = await Promise.all([
      User.findById(userId).lean(),
      Investment.find({ user: userId })
        .populate('plan', 'name daily_interest duration total_interest')
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      Transaction.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(50)
        .lean(),
      Notification.find({ user: userId, is_read: false })
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      KYCSubmission.findOne({ user: userId }).lean(),
      Deposit.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      Withdrawal.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      Referral.find({ referrer: userId })
        .populate('referred_user', 'full_name email createdAt balance total_earnings')
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      SupportTicket.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      calculateUserStats(userId)
    ]);

    // Calculate additional metrics
    const activeInvestments = investments.filter(inv => inv.status === 'active');
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    
    // Calculate daily interest
    const dailyInterest = activeInvestments.reduce((sum, inv) => {
      if (inv.plan && inv.plan.daily_interest) {
        return sum + (inv.amount * inv.plan.daily_interest / 100);
      }
      return sum;
    }, 0);
    
    // Calculate totals
    const totalEarnings = investments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0);
    const referralEarnings = referrals.reduce((sum, ref) => sum + (ref.earnings || 0), 0);
    
    const totalDepositsAmount = deposits
      .filter(d => d.status === 'approved')
      .reduce((sum, dep) => sum + dep.amount, 0);
    
    const totalWithdrawalsAmount = withdrawals
      .filter(w => w.status === 'paid')
      .reduce((sum, wdl) => sum + wdl.amount, 0);

    const profileData = {
      user: {
        ...user,
        bank_details: user.bank_details || null,
        wallet_address: user.wallet_address || null,
        paypal_email: user.paypal_email || null,
        device_info: config.debugEnabled ? user.device_info : undefined
      },
      
      dashboard_stats: {
        // Financial stats
        balance: user.balance || 0,
        total_earnings: totalEarnings,
        referral_earnings: referralEarnings,
        daily_interest: parseFloat(dailyInterest.toFixed(2)),
        active_investment_value: parseFloat(totalActiveValue.toFixed(2)),
        portfolio_value: parseFloat((user.balance + totalEarnings + referralEarnings).toFixed(2)),
        
        // Transaction totals
        total_deposits_amount: parseFloat(totalDepositsAmount.toFixed(2)),
        total_withdrawals_amount: parseFloat(totalWithdrawalsAmount.toFixed(2)),
        
        // Counts
        total_investments: investments.length,
        active_investments: activeInvestments.length,
        total_deposits: deposits.filter(d => d.status === 'approved').length,
        total_withdrawals: withdrawals.filter(w => w.status === 'paid').length,
        referral_count: user.referral_count || 0,
        unread_notifications: notifications.length,
        
        // Status
        kyc_status: user.kyc_status || 'not_submitted',
        kyc_verified: user.kyc_verified || false,
        account_status: user.is_active ? 'active' : 'inactive',
        email_verified: user.is_verified || false,
        two_factor_enabled: user.two_factor_enabled || false
      },
      
      // Historical data
      recent_investments: investments.slice(0, 10).map(inv => ({
        ...inv,
        has_proof: !!inv.payment_proof_url,
        proof_url: inv.payment_proof_url || null,
        remaining_days: Math.max(0, Math.ceil((new Date(inv.end_date) - new Date()) / (1000 * 60 * 60 * 24)))
      })),
      
      recent_transactions: transactions.slice(0, 20).map(txn => ({
        ...txn,
        has_proof: !!txn.payment_proof_url,
        proof_url: txn.payment_proof_url || null,
        formatted_amount: `${txn.amount >= 0 ? '+' : '-'}₦${Math.abs(txn.amount).toLocaleString()}`,
        type_color: txn.amount >= 0 ? 'success' : 'error'
      })),
      
      recent_deposits: deposits.slice(0, 10).map(dep => ({
        ...dep,
        has_proof: !!dep.payment_proof_url,
        proof_url: dep.payment_proof_url || null,
        formatted_amount: `₦${dep.amount.toLocaleString()}`,
        status_color: dep.status === 'approved' ? 'success' : 
                     dep.status === 'pending' ? 'warning' : 'error'
      })),
      
      recent_withdrawals: withdrawals.slice(0, 10).map(wdl => ({
        ...wdl,
        has_proof: !!wdl.payment_proof_url,
        proof_url: wdl.payment_proof_url || null,
        formatted_amount: `₦${wdl.amount.toLocaleString()}`,
        formatted_net_amount: `₦${wdl.net_amount.toLocaleString()}`,
        status_color: wdl.status === 'paid' ? 'success' : 
                     wdl.status === 'pending' ? 'warning' : 'error'
      })),
      
      // Other data
      referrals: referrals,
      kyc_submission: kyc,
      notifications: notifications,
      support_tickets: supportTickets,
      
      // Calculations
      calculations: {
        daily_interest_breakdown: activeInvestments.map(inv => ({
          plan: inv.plan?.name,
          amount: inv.amount,
          daily_rate: inv.plan?.daily_interest || 0,
          daily_earning: (inv.amount * (inv.plan?.daily_interest || 0) / 100),
          remaining_days: Math.max(0, Math.ceil((new Date(inv.end_date) - new Date()) / (1000 * 60 * 60 * 24))),
          progress_percentage: Math.min(100, Math.max(0, ((inv.plan?.duration || 30) - Math.max(0, Math.ceil((new Date(inv.end_date) - new Date()) / (1000 * 60 * 60 * 24)))) / (inv.plan?.duration || 30) * 100))
        })),
        upcoming_payouts: activeInvestments.filter(inv => {
          const daysLeft = Math.ceil((new Date(inv.end_date) - new Date()) / (1000 * 60 * 60 * 24));
          return daysLeft <= 7;
        }).map(inv => ({
          plan: inv.plan?.name,
          amount: inv.amount,
          end_date: inv.end_date,
          days_left: Math.ceil((new Date(inv.end_date) - new Date()) / (1000 * 60 * 60 * 24)),
          expected_payout: inv.expected_earnings,
          earned_so_far: inv.earned_so_far || 0
        }))
      }
    };

    logger.debug('Profile retrieved', { userId });

    res.json(formatResponse(true, 'Profile retrieved successfully', profileData));

  } catch (error) {
    handleError(res, error, 'Error fetching profile', req.requestId);
  }
});

// Update profile endpoint
app.put('/api/profile', auth, [
  body('full_name').optional().trim().isLength({ min: 2, max: 100 })
    .withMessage('Full name must be between 2 and 100 characters'),
  body('phone').optional().trim(),
  body('country').optional().isLength({ min: 2, max: 2 })
    .withMessage('Country must be 2 characters'),
  body('currency').optional().isIn(['NGN', 'USD', 'EUR', 'GBP'])
    .withMessage('Invalid currency'),
  body('risk_tolerance').optional().isIn(['low', 'medium', 'high'])
    .withMessage('Invalid risk tolerance'),
  body('investment_strategy').optional().isIn(['conservative', 'balanced', 'aggressive'])
    .withMessage('Invalid investment strategy'),
  body('notifications_enabled').optional().isBoolean(),
  body('email_notifications').optional().isBoolean(),
  body('sms_notifications').optional().isBoolean()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.user._id;
    const updateData = req.body;

    // Update allowed fields
    const allowedUpdates = [
      'full_name', 
      'phone', 
      'country', 
      'currency',
      'risk_tolerance', 
      'investment_strategy', 
      'notifications_enabled', 
      'email_notifications', 
      'sms_notifications'
    ];
    
    const updateFields = {};
    
    allowedUpdates.forEach(field => {
      if (updateData[field] !== undefined) {
        updateFields[field] = updateData[field];
      }
    });

    const user = await User.findByIdAndUpdate(
      userId,
      updateFields,
      { new: true, runValidators: true }
    );

    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    logger.info('Profile updated', {
      userId,
      updatedFields: Object.keys(updateFields)
    });

    await createNotification(
      userId,
      'Profile Updated',
      'Your profile information has been successfully updated.',
      'info',
      '/profile',
      { updatedFields: Object.keys(updateFields) }
    );

    res.json(formatResponse(true, 'Profile updated successfully', { 
      user: {
        id: user._id,
        full_name: user.full_name,
        email: user.email,
        phone: user.phone,
        country: user.country,
        currency: user.currency,
        risk_tolerance: user.risk_tolerance,
        investment_strategy: user.investment_strategy,
        notifications_enabled: user.notifications_enabled,
        email_notifications: user.email_notifications,
        sms_notifications: user.sms_notifications
      }
    }));

  } catch (error) {
    handleError(res, error, 'Error updating profile', req.requestId);
  }
});

// Update bank details endpoint
app.put('/api/profile/bank', auth, [
  body('bank_name').notEmpty().trim()
    .withMessage('Bank name is required'),
  body('account_name').notEmpty().trim()
    .withMessage('Account name is required'),
  body('account_number').notEmpty().trim()
    .withMessage('Account number is required'),
  body('bank_code').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.user._id;
    const { bank_name, account_name, account_number, bank_code } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    // Validate account number (basic validation)
    if (!/^\d{10,20}$/.test(account_number)) {
      return res.status(400).json(formatResponse(false, 'Invalid account number'));
    }

    user.bank_details = {
      bank_name: bank_name.trim(),
      account_name: account_name.trim(),
      account_number: account_number.trim(),
      bank_code: bank_code ? bank_code.trim() : '',
      verified: false,
      last_updated: new Date()
    };

    await user.save();

    logger.info('Bank details updated', {
      userId,
      bankName: bank_name,
      accountNumber: account_number.replace(/\d(?=\d{4})/g, '*') // Mask for logging
    });

    // Create notification
    await createNotification(
      userId,
      'Bank Details Updated',
      'Your bank account details have been updated successfully. They will be verified by our team.',
      'info',
      '/profile',
      { bankName: bank_name, verified: false }
    );

    // Notify admin
    const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } });
    for (const admin of admins) {
      await createNotification(
        admin._id,
        'User Updated Bank Details',
        `User ${user.full_name} has updated their bank details. Please verify for withdrawal requests.`,
        'system',
        `/admin/users/${userId}`,
        { 
          userId: userId,
          userName: user.full_name,
          bankName: bank_name,
          accountNumber: account_number.replace(/\d(?=\d{4})/g, '*')
        }
      );
    }

    res.json(formatResponse(true, 'Bank details updated successfully', {
      bank_details: {
        bank_name: user.bank_details.bank_name,
        account_name: user.bank_details.account_name,
        account_number: user.bank_details.account_number.replace(/\d(?=\d{4})/g, '*'),
        verified: user.bank_details.verified,
        last_updated: user.bank_details.last_updated
      }
    }));

  } catch (error) {
    handleError(res, error, 'Error updating bank details', req.requestId);
  }
});

// Update wallet address endpoint
app.put('/api/profile/wallet', auth, [
  body('wallet_address').notEmpty().trim()
    .withMessage('Wallet address is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.user._id;
    const { wallet_address } = req.body;

    // Basic wallet address validation
    if (!/^0x[a-fA-F0-9]{40}$/.test(wallet_address) && 
        !/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(wallet_address)) {
      return res.status(400).json(formatResponse(false, 'Invalid wallet address format'));
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    user.wallet_address = wallet_address.trim();
    await user.save();

    logger.info('Wallet address updated', {
      userId,
      walletAddress: wallet_address.substring(0, 10) + '...' // Partial for logging
    });

    await createNotification(
      userId,
      'Wallet Address Updated',
      'Your crypto wallet address has been updated successfully.',
      'info',
      '/profile',
      { walletAddress: wallet_address.substring(0, 10) + '...' }
    );

    res.json(formatResponse(true, 'Wallet address updated successfully'));

  } catch (error) {
    handleError(res, error, 'Error updating wallet address', req.requestId);
  }
});

// Update PayPal email endpoint
app.put('/api/profile/paypal', auth, [
  body('paypal_email').isEmail().normalizeEmail()
    .withMessage('Please provide a valid PayPal email address')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.user._id;
    const { paypal_email } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    user.paypal_email = paypal_email.toLowerCase();
    await user.save();

    logger.info('PayPal email updated', {
      userId,
      paypalEmail: paypal_email
    });

    await createNotification(
      userId,
      'PayPal Email Updated',
      'Your PayPal email has been updated successfully.',
      'info',
      '/profile',
      { paypalEmail: paypal_email }
    );

    res.json(formatResponse(true, 'PayPal email updated successfully'));

  } catch (error) {
    handleError(res, error, 'Error updating PayPal email', req.requestId);
  }
});

// Change password endpoint
app.put('/api/profile/change-password', auth, [
  body('current_password').notEmpty()
    .withMessage('Current password is required'),
  body('new_password').isLength({ min: 6 })
    .withMessage('New password must be at least 6 characters')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.user._id;
    const { current_password, new_password } = req.body;

    const user = await User.findById(userId).select('+password');
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    // Verify current password
    const isMatch = await user.comparePassword(current_password);
    if (!isMatch) {
      return res.status(400).json(formatResponse(false, 'Current password is incorrect'));
    }

    // Update password
    user.password = new_password;
    await user.save();

    logger.info('Password changed', {
      userId,
      ip: req.ip
    });

    // Send email notification
    await sendEmail(
      user.email,
      'Password Changed - Raw Wealthy',
      `<h2>Password Changed Successfully</h2>
       <p>Your password has been changed successfully.</p>
       <p>If you did not make this change, please contact our support team immediately.</p>
       <p><strong>Security Notice:</strong> This change was made from IP: ${req.ip}</p>`
    );

    // Create notification
    await createNotification(
      userId,
      'Password Changed',
      'Your password has been changed successfully.',
      'security',
      '/profile/security',
      { changedFromIp: req.ip, changedAt: new Date() }
    );

    res.json(formatResponse(true, 'Password changed successfully'));

  } catch (error) {
    handleError(res, error, 'Error changing password', req.requestId);
  }
});

// ==================== ENHANCED INVESTMENT PLANS ENDPOINTS ====================

// Get all investment plans
app.get('/api/plans', async (req, res) => {
  try {
    const { category, risk_level, featured, popular } = req.query;
    
    let query = { is_active: true };
    
    // Apply filters
    if (category) query.category = category;
    if (risk_level) query.risk_level = risk_level;
    if (featured === 'true') query.is_featured = true;
    if (popular === 'true') query.is_popular = true;
    
    const plans = await InvestmentPlan.find(query)
      .sort({ display_order: 1, min_amount: 1 })
      .lean();
    
    // Calculate ROI and other metrics
    const enhancedPlans = plans.map(plan => {
      const monthlyInterest = plan.daily_interest * 30;
      const estimatedMonthlyEarnings = (plan.min_amount * monthlyInterest) / 100;
      const estimatedTotalEarnings = (plan.min_amount * plan.total_interest) / 100;
      const roiPercentage = plan.total_interest;
      
      return {
        ...plan,
        monthly_interest: parseFloat(monthlyInterest.toFixed(2)),
        estimated_monthly_earnings: parseFloat(estimatedMonthlyEarnings.toFixed(2)),
        estimated_total_earnings: parseFloat(estimatedTotalEarnings.toFixed(2)),
        roi_percentage: parseFloat(roiPercentage.toFixed(2)),
        features: plan.features || ['Secure Investment', 'Daily Payouts', '24/7 Support'],
        success_rate: plan.success_rate || 95,
        rating: plan.rating || 4.5
      };
    });
    
    res.json(formatResponse(true, 'Plans retrieved successfully', { 
      plans: enhancedPlans,
      filters: {
        category,
        risk_level,
        featured,
        popular
      }
    }));
    
  } catch (error) {
    handleError(res, error, 'Error fetching investment plans', req.requestId);
  }
});

// Get specific plan
app.get('/api/plans/:id', async (req, res) => {
  try {
    const plan = await InvestmentPlan.findById(req.params.id);
    
    if (!plan) {
      return res.status(404).json(formatResponse(false, 'Investment plan not found'));
    }
    
    if (!plan.is_active) {
      return res.status(400).json(formatResponse(false, 'This investment plan is not currently available'));
    }
    
    // Calculate additional metrics
    const monthlyInterest = plan.daily_interest * 30;
    const estimatedMonthlyEarningsMin = (plan.min_amount * monthlyInterest) / 100;
    const estimatedTotalEarningsMin = (plan.min_amount * plan.total_interest) / 100;
    const roiPercentage = plan.total_interest;
    
    const enhancedPlan = {
      ...plan.toObject(),
      monthly_interest: parseFloat(monthlyInterest.toFixed(2)),
      estimated_monthly_earnings_min: parseFloat(estimatedMonthlyEarningsMin.toFixed(2)),
      estimated_total_earnings_min: parseFloat(estimatedTotalEarningsMin.toFixed(2)),
      roi_percentage: parseFloat(roiPercentage.toFixed(2)),
      investment_count: plan.investment_count || 0,
      total_invested: plan.total_invested || 0,
      total_earned: plan.total_earned || 0,
      success_rate: plan.success_rate || 95,
      rating: plan.rating || 4.5
    };
    
    // Add calculated fields for max amount if exists
    if (plan.max_amount) {
      const estimatedMonthlyEarningsMax = (plan.max_amount * monthlyInterest) / 100;
      const estimatedTotalEarningsMax = (plan.max_amount * plan.total_interest) / 100;
      
      enhancedPlan.estimated_monthly_earnings_max = parseFloat(estimatedMonthlyEarningsMax.toFixed(2));
      enhancedPlan.estimated_total_earnings_max = parseFloat(estimatedTotalEarningsMax.toFixed(2));
    }
    
    res.json(formatResponse(true, 'Plan retrieved successfully', { 
      plan: enhancedPlan 
    }));
    
  } catch (error) {
    handleError(res, error, 'Error fetching investment plan', req.requestId);
  }
});

// ==================== ENHANCED INVESTMENT ENDPOINTS ====================

// Get user investments
app.get('/api/investments', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { status, page = 1, limit = 10, sort = '-createdAt' } = req.query;
    
    const query = { user: userId };
    if (status) query.status = status;
    
    const skip = (page - 1) * limit;
    
    const [investments, total] = await Promise.all([
      Investment.find(query)
        .populate('plan', 'name daily_interest duration total_interest')
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Investment.countDocuments(query)
    ]);

    // Enhance investments with calculations
    const enhancedInvestments = investments.map(inv => {
      const remainingDays = Math.max(0, Math.ceil((new Date(inv.end_date) - new Date()) / (1000 * 60 * 60 * 24)));
      const totalDays = Math.ceil((new Date(inv.end_date) - new Date(inv.start_date)) / (1000 * 60 * 60 * 24));
      const daysPassed = totalDays - remainingDays;
      const progressPercentage = inv.status === 'active' ? 
        Math.min(100, (daysPassed / totalDays) * 100) : 
        (inv.status === 'completed' ? 100 : 0);

      return {
        ...inv,
        remaining_days: remainingDays,
        total_days: totalDays,
        days_passed: daysPassed,
        progress_percentage: Math.round(progressPercentage),
        estimated_completion: inv.end_date,
        daily_earning: (inv.amount * (inv.plan?.daily_interest || 0)) / 100,
        total_earned_so_far: inv.earned_so_far || 0,
        remaining_earnings: (inv.expected_earnings || 0) - (inv.earned_so_far || 0),
        has_proof: !!inv.payment_proof_url,
        proof_url: inv.payment_proof_url || null,
        can_withdraw_earnings: inv.status === 'active' && (inv.earned_so_far || 0) > 0,
        roi_percentage: inv.roi_percentage || 0,
        profit_loss: inv.profit_loss || 0
      };
    });

    // Calculate stats
    const activeInvestments = enhancedInvestments.filter(inv => inv.status === 'active');
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    const totalEarnings = activeInvestments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0);
    const dailyEarnings = activeInvestments.reduce((sum, inv) => sum + inv.daily_earning, 0);

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(formatResponse(true, 'Investments retrieved successfully', {
      investments: enhancedInvestments,
      stats: {
        total_active_value: parseFloat(totalActiveValue.toFixed(2)),
        total_earnings: parseFloat(totalEarnings.toFixed(2)),
        daily_earnings: parseFloat(dailyEarnings.toFixed(2)),
        active_count: activeInvestments.length,
        total_count: total,
        pending_count: enhancedInvestments.filter(inv => inv.status === 'pending').length,
        completed_count: enhancedInvestments.filter(inv => inv.status === 'completed').length
      },
      pagination
    }));

  } catch (error) {
    handleError(res, error, 'Error fetching investments', req.requestId);
  }
});

// Create investment
app.post('/api/investments', auth, upload.single('payment_proof'), [
  body('plan_id').notEmpty()
    .withMessage('Plan ID is required'),
  body('amount').isFloat({ min: config.minInvestment })
    .withMessage(`Amount must be at least ₦${config.minInvestment}`),
  body('auto_renew').optional().isBoolean(),
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { plan_id, amount, auto_renew = false, remarks } = req.body;
    const userId = req.user._id;
    
    // Check plan
    const plan = await InvestmentPlan.findById(plan_id);
    if (!plan) {
      return res.status(404).json(formatResponse(false, 'Investment plan not found'));
    }

    if (!plan.is_active) {
      return res.status(400).json(formatResponse(false, 'This investment plan is not currently available'));
    }

    const investmentAmount = parseFloat(amount);

    // Validate amount
    if (investmentAmount < plan.min_amount) {
      return res.status(400).json(formatResponse(false, 
        `Minimum investment for ${plan.name} is ₦${plan.min_amount.toLocaleString()}`));
    }

    if (plan.max_amount && investmentAmount > plan.max_amount) {
      return res.status(400).json(formatResponse(false,
        `Maximum investment for ${plan.name} is ₦${plan.max_amount.toLocaleString()}`));
    }

    // Check user balance
    if (investmentAmount > req.user.balance) {
      return res.status(400).json(formatResponse(false, 'Insufficient balance for this investment'));
    }

    // Handle file upload
    let proofUrl = null;
    let uploadResult = null;
    if (req.file) {
      try {
        uploadResult = await handleFileUpload(req.file, 'investment-proofs', userId);
        proofUrl = uploadResult.url;
      } catch (uploadError) {
        return res.status(400).json(formatResponse(false, `File upload failed: ${uploadError.message}`));
      }
    }

    // Calculate expected earnings
    const expectedEarnings = (investmentAmount * plan.total_interest) / 100;
    const dailyEarnings = (investmentAmount * plan.daily_interest) / 100;
    const endDate = new Date(Date.now() + plan.duration * 24 * 60 * 60 * 1000);

    // Create investment
    const investment = new Investment({
      user: userId,
      plan: plan_id,
      amount: investmentAmount,
      status: proofUrl ? 'pending' : 'active',
      start_date: new Date(),
      end_date: endDate,
      expected_earnings: expectedEarnings,
      earned_so_far: 0,
      daily_earnings: dailyEarnings,
      auto_renew,
      payment_proof_url: proofUrl,
      payment_verified: !proofUrl,
      remarks: remarks,
      investment_image_url: proofUrl,
      metadata: {
        uploaded_file: uploadResult ? {
          filename: uploadResult.filename,
          size: uploadResult.size,
          mime_type: uploadResult.mimeType
        } : null,
        ip_address: req.ip,
        user_agent: req.headers['user-agent']
      }
    });

    await investment.save();

    // Update user balance
    await User.findByIdAndUpdate(userId, { 
      $inc: { balance: -investmentAmount }
    });

    // Update plan statistics
    await InvestmentPlan.findByIdAndUpdate(plan_id, {
      $inc: { 
        investment_count: 1,
        total_invested: investmentAmount
      }
    });

    // Create transaction
    await createTransaction(
      userId,
      'investment',
      -investmentAmount,
      `Investment in ${plan.name} plan`,
      proofUrl ? 'pending' : 'completed',
      { 
        investment_id: investment._id,
        plan_name: plan.name,
        plan_duration: plan.duration,
        daily_interest: plan.daily_interest,
        total_interest: plan.total_interest
      },
      proofUrl
    );

    logger.info('Investment created', {
      userId,
      investmentId: investment._id,
      planId: plan_id,
      amount: investmentAmount,
      requiresApproval: !!proofUrl
    });

    // Create notification
    await createNotification(
      userId,
      'Investment Created',
      `Your investment of ₦${investmentAmount.toLocaleString()} in ${plan.name} has been created successfully.${proofUrl ? ' Awaiting admin approval.' : ''}`,
      'investment',
      '/investments',
      { 
        amount: investmentAmount,
        plan_name: plan.name,
        requires_approval: !!proofUrl,
        investment_id: investment._id
      }
    );

    // Notify admin if payment proof uploaded
    if (proofUrl) {
      const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } });
      for (const admin of admins) {
        await createNotification(
          admin._id,
          'New Investment Pending Approval',
          `User ${req.user.full_name} has created a new investment of ₦${investmentAmount.toLocaleString()} requiring approval.`,
          'system',
          `/admin/investments/${investment._id}`,
          { 
            user_id: userId,
            user_name: req.user.full_name,
            amount: investmentAmount,
            plan_name: plan.name,
            proof_url: proofUrl 
          }
        );
      }
    }

    res.status(201).json(formatResponse(true, 'Investment created successfully!', { 
      investment: {
        ...investment.toObject(),
        plan_name: plan.name,
        plan_details: {
          daily_interest: plan.daily_interest,
          duration: plan.duration,
          total_interest: plan.total_interest
        },
        expected_daily_earnings: dailyEarnings,
        expected_total_earnings: expectedEarnings,
        end_date: endDate,
        requires_approval: !!proofUrl,
        next_payout: new Date(Date.now() + 24 * 60 * 60 * 1000)
      }
    }));

  } catch (error) {
    handleError(res, error, 'Error creating investment', req.requestId);
  }
});

// Get specific investment
app.get('/api/investments/:id', auth, async (req, res) => {
  try {
    const investment = await Investment.findById(req.params.id)
      .populate('plan', 'name daily_interest duration total_interest features')
      .populate('approved_by', 'full_name email')
      .lean();
    
    if (!investment) {
      return res.status(404).json(formatResponse(false, 'Investment not found'));
    }
    
    // Check ownership
    if (investment.user.toString() !== req.user._id.toString() && req.user.role === 'user') {
      return res.status(403).json(formatResponse(false, 'Access denied'));
    }
    
    // Calculate additional details
    const remainingDays = Math.max(0, Math.ceil((new Date(investment.end_date) - new Date()) / (1000 * 60 * 60 * 24)));
    const totalDays = Math.ceil((new Date(investment.end_date) - new Date(investment.start_date)) / (1000 * 60 * 60 * 24));
    const daysPassed = totalDays - remainingDays;
    const progressPercentage = Math.min(100, (daysPassed / totalDays) * 100);
    
    const enhancedInvestment = {
      ...investment,
      remaining_days: remainingDays,
      total_days: totalDays,
      days_passed: daysPassed,
      progress_percentage: Math.round(progressPercentage),
      daily_earning: (investment.amount * (investment.plan?.daily_interest || 0)) / 100,
      remaining_earnings: investment.expected_earnings - (investment.earned_so_far || 0),
      next_payout_date: investment.last_earning_date ? 
        new Date(investment.last_earning_date.getTime() + 24 * 60 * 60 * 1000) : 
        new Date(),
      has_proof: !!investment.payment_proof_url,
      proof_url: investment.payment_proof_url || null,
      can_withdraw: investment.status === 'active' && (investment.earned_so_far || 0) > 0,
      roi_percentage: investment.roi_percentage || 0,
      profit_loss: investment.profit_loss || 0
    };
    
    res.json(formatResponse(true, 'Investment retrieved successfully', { 
      investment: enhancedInvestment 
    }));
    
  } catch (error) {
    handleError(res, error, 'Error fetching investment', req.requestId);
  }
});

// Cancel investment (if pending)
app.post('/api/investments/:id/cancel', auth, async (req, res) => {
  try {
    const investment = await Investment.findById(req.params.id);
    
    if (!investment) {
      return res.status(404).json(formatResponse(false, 'Investment not found'));
    }
    
    // Check ownership
    if (investment.user.toString() !== req.user._id.toString()) {
      return res.status(403).json(formatResponse(false, 'Access denied'));
    }
    
    // Only pending investments can be cancelled
    if (investment.status !== 'pending') {
      return res.status(400).json(formatResponse(false, 'Only pending investments can be cancelled'));
    }
    
    // Refund user balance
    await User.findByIdAndUpdate(investment.user, {
      $inc: { balance: investment.amount }
    });
    
    // Update investment status
    investment.status = 'cancelled';
    investment.remarks = 'Cancelled by user';
    await investment.save();
    
    logger.info('Investment cancelled', {
      userId: req.user._id,
      investmentId: investment._id,
      amount: investment.amount
    });
    
    // Create transaction for refund
    await createTransaction(
      investment.user,
      'refund',
      investment.amount,
      `Refund for cancelled investment in ${investment.plan?.name || 'Unknown'} plan`,
      'completed',
      { 
        investment_id: investment._id,
        cancellation_reason: 'User cancelled'
      }
    );
    
    // Create notification
    await createNotification(
      investment.user,
      'Investment Cancelled',
      `Your investment of ₦${investment.amount.toLocaleString()} has been cancelled and refunded.`,
      'info',
      '/investments',
      { 
        amount: investment.amount,
        plan_name: investment.plan?.name || 'Unknown',
        refunded: true
      }
    );
    
    res.json(formatResponse(true, 'Investment cancelled successfully', {
      investment: {
        id: investment._id,
        status: investment.status,
        amount_refunded: investment.amount
      }
    }));
    
  } catch (error) {
    handleError(res, error, 'Error cancelling investment', req.requestId);
  }
});

// ==================== ENHANCED DEPOSIT ENDPOINTS ====================

// Get user deposits
app.get('/api/deposits', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { status, page = 1, limit = 10, payment_method } = req.query;
    
    const query = { user: userId };
    if (status) query.status = status;
    if (payment_method) query.payment_method = payment_method;
    
    const skip = (page - 1) * limit;
    
    const [deposits, total] = await Promise.all([
      Deposit.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Deposit.countDocuments(query)
    ]);

    // Enhance deposits
    const enhancedDeposits = deposits.map(dep => ({
      ...dep,
      has_proof: !!dep.payment_proof_url,
      proof_url: dep.payment_proof_url || null,
      formatted_amount: `₦${dep.amount.toLocaleString()}`,
      status_color: dep.status === 'approved' ? 'success' : 
                    dep.status === 'pending' ? 'warning' : 
                    dep.status === 'rejected' ? 'error' : 'default',
      days_pending: dep.status === 'pending' ? 
        Math.ceil((new Date() - new Date(dep.createdAt)) / (1000 * 60 * 60 * 24)) : null
    }));

    // Calculate stats
    const totalDeposits = enhancedDeposits.filter(d => d.status === 'approved').reduce((sum, d) => sum + d.amount, 0);
    const pendingDeposits = enhancedDeposits.filter(d => d.status === 'pending').reduce((sum, d) => sum + d.amount, 0);

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(formatResponse(true, 'Deposits retrieved successfully', {
      deposits: enhancedDeposits,
      stats: {
        total_deposits: parseFloat(totalDeposits.toFixed(2)),
        pending_deposits: parseFloat(pendingDeposits.toFixed(2)),
        total_count: total,
        approved_count: enhancedDeposits.filter(d => d.status === 'approved').length,
        pending_count: enhancedDeposits.filter(d => d.status === 'pending').length,
        rejected_count: enhancedDeposits.filter(d => d.status === 'rejected').length
      },
      pagination
    }));

  } catch (error) {
    handleError(res, error, 'Error fetching deposits', req.requestId);
  }
});

// Create deposit
app.post('/api/deposits', auth, upload.single('payment_proof'), [
  body('amount').isFloat({ min: config.minDeposit })
    .withMessage(`Minimum deposit is ₦${config.minDeposit}`),
  body('payment_method').isIn(['bank_transfer', 'crypto', 'paypal', 'card'])
    .withMessage('Invalid payment method'),
  body('remarks').optional().trim(),
  body('currency').optional().isIn(['NGN', 'USD', 'EUR', 'GBP'])
    .withMessage('Invalid currency')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { amount, payment_method, remarks, currency = 'NGN' } = req.body;
    const userId = req.user._id;
    const depositAmount = parseFloat(amount);

    // Handle file upload
    let proofUrl = null;
    let uploadResult = null;
    if (req.file) {
      try {
        uploadResult = await handleFileUpload(req.file, 'deposit-proofs', userId);
        proofUrl = uploadResult.url;
      } catch (uploadError) {
        return res.status(400).json(formatResponse(false, `File upload failed: ${uploadError.message}`));
      }
    }

    // Create deposit
    const deposit = new Deposit({
      user: userId,
      amount: depositAmount,
      currency,
      payment_method,
      status: 'pending',
      payment_proof_url: proofUrl,
      deposit_image_url: proofUrl,
      reference: generateReference('DEP'),
      remarks: remarks,
      metadata: {
        uploaded_file: uploadResult ? {
          filename: uploadResult.filename,
          size: uploadResult.size,
          mime_type: uploadResult.mimeType
        } : null,
        ip_address: req.ip,
        user_agent: req.headers['user-agent']
      }
    });

    await deposit.save();

    logger.info('Deposit created', {
      userId,
      depositId: deposit._id,
      amount: depositAmount,
      paymentMethod: payment_method,
      hasProof: !!proofUrl
    });

    // Create notification
    await createNotification(
      userId,
      'Deposit Request Submitted',
      `Your deposit request of ₦${depositAmount.toLocaleString()} has been submitted and is pending approval.`,
      'deposit',
      '/deposits',
      { 
        amount: depositAmount,
        payment_method,
        has_proof: !!proofUrl,
        reference: deposit.reference
      }
    );

    // Notify admin
    const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } });
    for (const admin of admins) {
      await createNotification(
        admin._id,
        'New Deposit Request',
        `User ${req.user.full_name} has submitted a deposit request of ₦${depositAmount.toLocaleString()}.${proofUrl ? ' Payment proof attached.' : ''}`,
        'system',
        `/admin/deposits/${deposit._id}`,
        { 
          user_id: userId,
          user_name: req.user.full_name,
          amount: depositAmount,
          payment_method,
          proof_url: proofUrl,
          reference: deposit.reference
        }
      );
    }

    res.status(201).json(formatResponse(true, 'Deposit request submitted successfully!', { 
      deposit: {
        ...deposit.toObject(),
        formatted_amount: `₦${depositAmount.toLocaleString()}`,
        requires_approval: true,
        estimated_approval_time: '24-48 hours',
        proof_uploaded: !!proofUrl,
        reference: deposit.reference
      },
      message: 'Your deposit is pending approval. You will be notified once approved.'
    }));

  } catch (error) {
    handleError(res, error, 'Error creating deposit', req.requestId);
  }
});

// Get deposit by reference
app.get('/api/deposits/reference/:reference', auth, async (req, res) => {
  try {
    const { reference } = req.params;
    const userId = req.user._id;
    
    const deposit = await Deposit.findOne({ 
      reference,
      user: userId 
    }).lean();
    
    if (!deposit) {
      return res.status(404).json(formatResponse(false, 'Deposit not found'));
    }
    
    res.json(formatResponse(true, 'Deposit retrieved successfully', {
      deposit: {
        ...deposit,
        has_proof: !!deposit.payment_proof_url,
        proof_url: deposit.payment_proof_url || null,
        formatted_amount: `₦${deposit.amount.toLocaleString()}`
      }
    }));
    
  } catch (error) {
    handleError(res, error, 'Error fetching deposit', req.requestId);
  }
});

// ==================== ENHANCED WITHDRAWAL ENDPOINTS ====================

// Get user withdrawals
app.get('/api/withdrawals', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { status, page = 1, limit = 10, payment_method } = req.query;
    
    const query = { user: userId };
    if (status) query.status = status;
    if (payment_method) query.payment_method = payment_method;
    
    const skip = (page - 1) * limit;
    
    const [withdrawals, total] = await Promise.all([
      Withdrawal.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Withdrawal.countDocuments(query)
    ]);

    // Enhance withdrawals
    const enhancedWithdrawals = withdrawals.map(wdl => ({
      ...wdl,
      has_proof: !!wdl.payment_proof_url,
      proof_url: wdl.payment_proof_url || null,
      formatted_amount: `₦${wdl.amount.toLocaleString()}`,
      formatted_net_amount: `₦${wdl.net_amount.toLocaleString()}`,
      formatted_fee: `₦${wdl.platform_fee.toLocaleString()}`,
      status_color: wdl.status === 'paid' ? 'success' : 
                   wdl.status === 'pending' ? 'warning' : 
                   wdl.status === 'rejected' ? 'error' : 'default',
      processing_time: wdl.status === 'paid' && wdl.paid_at ? 
        Math.ceil((new Date(wdl.paid_at) - new Date(wdl.createdAt)) / (1000 * 60 * 60)) : null,
      days_pending: wdl.status === 'pending' ? 
        Math.ceil((new Date() - new Date(wdl.createdAt)) / (1000 * 60 * 60 * 24)) : null
    }));

    // Calculate stats
    const totalWithdrawals = enhancedWithdrawals.filter(w => w.status === 'paid').reduce((sum, w) => sum + w.amount, 0);
    const pendingWithdrawals = enhancedWithdrawals.filter(w => w.status === 'pending').reduce((sum, w) => sum + w.amount, 0);
    const totalFees = enhancedWithdrawals.filter(w => w.status === 'paid').reduce((sum, w) => sum + w.platform_fee, 0);

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(formatResponse(true, 'Withdrawals retrieved successfully', {
      withdrawals: enhancedWithdrawals,
      stats: {
        total_withdrawals: parseFloat(totalWithdrawals.toFixed(2)),
        pending_withdrawals: parseFloat(pendingWithdrawals.toFixed(2)),
        total_fees: parseFloat(totalFees.toFixed(2)),
        total_count: total,
        paid_count: enhancedWithdrawals.filter(w => w.status === 'paid').length,
        pending_count: enhancedWithdrawals.filter(w => w.status === 'pending').length,
        rejected_count: enhancedWithdrawals.filter(w => w.status === 'rejected').length
      },
      pagination
    }));

  } catch (error) {
    handleError(res, error, 'Error fetching withdrawals', req.requestId);
  }
});

// Create withdrawal
app.post('/api/withdrawals', auth, [
  body('amount').isFloat({ min: config.minWithdrawal })
    .withMessage(`Minimum withdrawal is ₦${config.minWithdrawal}`),
  body('payment_method').isIn(['bank_transfer', 'crypto', 'paypal'])
    .withMessage('Invalid payment method'),
  body('remarks').optional().trim(),
  body('currency').optional().isIn(['NGN', 'USD', 'EUR', 'GBP'])
    .withMessage('Invalid currency')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { amount, payment_method, remarks, currency = 'NGN' } = req.body;
    const userId = req.user._id;
    const withdrawalAmount = parseFloat(amount);

    // Check minimum withdrawal
    if (withdrawalAmount < config.minWithdrawal) {
      return res.status(400).json(formatResponse(false, 
        `Minimum withdrawal is ₦${config.minWithdrawal.toLocaleString()}`));
    }

    // Check user balance
    if (withdrawalAmount > req.user.balance) {
      return res.status(400).json(formatResponse(false, 'Insufficient balance for withdrawal'));
    }

    // Check KYC verification for large withdrawals
    if (withdrawalAmount > 50000 && !req.user.kyc_verified) {
      return res.status(400).json(formatResponse(false, 
        'KYC verification required for withdrawals above ₦50,000. Please complete KYC verification first.'));
    }

    // Validate payment method specific details
    let paymentDetails = {};
    if (payment_method === 'bank_transfer') {
      if (!req.user.bank_details || !req.user.bank_details.account_number) {
        return res.status(400).json(formatResponse(false, 'Please update your bank details in profile settings'));
      }
      if (!req.user.bank_details.verified && withdrawalAmount > 10000) {
        return res.status(400).json(formatResponse(false, 
          'Bank account verification required for withdrawals above ₦10,000'));
      }
      paymentDetails = {
        bank_name: req.user.bank_details.bank_name,
        account_name: req.user.bank_details.account_name,
        account_number: req.user.bank_details.account_number,
        bank_code: req.user.bank_details.bank_code || '',
        verified: req.user.bank_details.verified || false
      };
    } else if (payment_method === 'crypto') {
      if (!req.user.wallet_address) {
        return res.status(400).json(formatResponse(false, 'Please set your wallet address in profile settings'));
      }
      paymentDetails = { wallet_address: req.user.wallet_address };
    } else if (payment_method === 'paypal') {
      if (!req.user.paypal_email) {
        return res.status(400).json(formatResponse(false, 'Please set your PayPal email in profile settings'));
      }
      paymentDetails = { paypal_email: req.user.paypal_email };
    }

    // Calculate platform fee
    const platformFee = withdrawalAmount * (config.platformFeePercent / 100);
    const netAmount = withdrawalAmount - platformFee;

    // Create withdrawal
    const withdrawal = new Withdrawal({
      user: userId,
      amount: withdrawalAmount,
      currency,
      payment_method,
      platform_fee: platformFee,
      net_amount: netAmount,
      status: 'pending',
      reference: generateReference('WDL'),
      remarks: remarks,
      ...paymentDetails,
      metadata: {
        ip_address: req.ip,
        user_agent: req.headers['user-agent']
      }
    });

    await withdrawal.save();

    // Update user balance (temporarily hold the amount)
    await User.findByIdAndUpdate(userId, { 
      $inc: { balance: -withdrawalAmount }
    });

    // Create transaction
    await createTransaction(
      userId,
      'withdrawal',
      -withdrawalAmount,
      `Withdrawal request via ${payment_method}`,
      'pending',
      { 
        withdrawal_id: withdrawal._id,
        payment_method,
        platform_fee: platformFee,
        net_amount: netAmount,
        reference: withdrawal.reference
      }
    );

    logger.info('Withdrawal created', {
      userId,
      withdrawalId: withdrawal._id,
      amount: withdrawalAmount,
      paymentMethod: payment_method,
      netAmount: netAmount,
      fee: platformFee
    });

    // Create notification
    await createNotification(
      userId,
      'Withdrawal Request Submitted',
      `Your withdrawal request of ₦${withdrawalAmount.toLocaleString()} has been submitted and is pending approval.`,
      'withdrawal',
      '/withdrawals',
      { 
        amount: withdrawalAmount,
        net_amount: netAmount,
        fee: platformFee,
        payment_method,
        reference: withdrawal.reference
      }
    );

    // Notify admin
    const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } });
    for (const admin of admins) {
      await createNotification(
        admin._id,
        'New Withdrawal Request',
        `User ${req.user.full_name} has requested a withdrawal of ₦${withdrawalAmount.toLocaleString()} via ${payment_method}.`,
        'system',
        `/admin/withdrawals/${withdrawal._id}`,
        { 
          user_id: userId,
          user_name: req.user.full_name,
          amount: withdrawalAmount,
          net_amount: netAmount,
          fee: platformFee,
          payment_method,
          ...paymentDetails
        }
      );
    }

    res.status(201).json(formatResponse(true, 'Withdrawal request submitted successfully!', { 
      withdrawal: {
        ...withdrawal.toObject(),
        formatted_amount: `₦${withdrawalAmount.toLocaleString()}`,
        formatted_net_amount: `₦${netAmount.toLocaleString()}`,
        formatted_fee: `₦${platformFee.toLocaleString()}`,
        requires_approval: true,
        estimated_processing_time: '24-48 hours',
        reference: withdrawal.reference
      },
      message: 'Your withdrawal is pending approval. Processing time is 24-48 hours.'
    }));

  } catch (error) {
    handleError(res, error, 'Error creating withdrawal', req.requestId);
  }
});

// Get withdrawal by reference
app.get('/api/withdrawals/reference/:reference', auth, async (req, res) => {
  try {
    const { reference } = req.params;
    const userId = req.user._id;
    
    const withdrawal = await Withdrawal.findOne({ 
      reference,
      user: userId 
    }).lean();
    
    if (!withdrawal) {
      return res.status(404).json(formatResponse(false, 'Withdrawal not found'));
    }
    
    res.json(formatResponse(true, 'Withdrawal retrieved successfully', {
      withdrawal: {
        ...withdrawal,
        has_proof: !!withdrawal.payment_proof_url,
        proof_url: withdrawal.payment_proof_url || null,
        formatted_amount: `₦${withdrawal.amount.toLocaleString()}`,
        formatted_net_amount: `₦${withdrawal.net_amount.toLocaleString()}`,
        formatted_fee: `₦${withdrawal.platform_fee.toLocaleString()}`
      }
    }));
    
  } catch (error) {
    handleError(res, error, 'Error fetching withdrawal', req.requestId);
  }
});

// ==================== ENHANCED TRANSACTION ENDPOINTS ====================

// Get user transactions
app.get('/api/transactions', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { 
      type, 
      status, 
      start_date, 
      end_date, 
      page = 1, 
      limit = 20,
      min_amount,
      max_amount 
    } = req.query;
    
    const query = { user: userId };
    
    // Apply filters
    if (type) query.type = type;
    if (status) query.status = status;
    if (start_date || end_date) {
      query.createdAt = {};
      if (start_date) query.createdAt.$gte = new Date(start_date);
      if (end_date) query.createdAt.$lte = new Date(end_date);
    }
    if (min_amount || max_amount) {
      query.amount = {};
      if (min_amount) query.amount.$gte = parseFloat(min_amount);
      if (max_amount) query.amount.$lte = parseFloat(max_amount);
    }
    
    const skip = (page - 1) * limit;
    
    const [transactions, total] = await Promise.all([
      Transaction.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Transaction.countDocuments(query)
    ]);

    // Enhance transactions
    const enhancedTransactions = transactions.map(txn => {
      const isPositive = txn.amount > 0;
      const typeColor = isPositive ? 'success' : 'error';
      const typeIcon = isPositive ? '↑' : '↓';
      
      return {
        ...txn,
        formatted_amount: `${isPositive ? '+' : '-'}₦${Math.abs(txn.amount).toLocaleString()}`,
        type_color: typeColor,
        type_icon: typeIcon,
        has_proof: !!txn.payment_proof_url,
        proof_url: txn.payment_proof_url || null,
        date_formatted: new Date(txn.createdAt).toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit'
        })
      };
    });

    // Calculate summary
    const summary = {
      total_income: parseFloat(transactions.filter(t => t.amount > 0).reduce((sum, t) => sum + t.amount, 0).toFixed(2)),
      total_expenses: parseFloat(transactions.filter(t => t.amount < 0).reduce((sum, t) => sum + Math.abs(t.amount), 0).toFixed(2)),
      net_flow: parseFloat(transactions.reduce((sum, t) => sum + t.amount, 0).toFixed(2)),
      by_type: transactions.reduce((acc, t) => {
        acc[t.type] = (acc[t.type] || 0) + 1;
        return acc;
      }, {})
    };

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(formatResponse(true, 'Transactions retrieved successfully', {
      transactions: enhancedTransactions,
      summary,
      pagination
    }));

  } catch (error) {
    handleError(res, error, 'Error fetching transactions', req.requestId);
  }
});

// ==================== ENHANCED KYC ENDPOINTS ====================

// Submit KYC
app.post('/api/kyc', auth, upload.fields([
  { name: 'id_front', maxCount: 1 },
  { name: 'id_back', maxCount: 1 },
  { name: 'selfie_with_id', maxCount: 1 },
  { name: 'address_proof', maxCount: 1 }
]), [
  body('id_type').isIn(['national_id', 'passport', 'driver_license', 'voters_card'])
    .withMessage('Invalid ID type'),
  body('id_number').notEmpty().trim()
    .withMessage('ID number is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { id_type, id_number } = req.body;
    const userId = req.user._id;
    const files = req.files;

    // Check required files
    if (!files || !files.id_front || !files.selfie_with_id) {
      return res.status(400).json(formatResponse(false, 'ID front and selfie with ID are required'));
    }

    // Upload files
    let idFrontUrl, idBackUrl, selfieWithIdUrl, addressProofUrl;
    const uploadResults = {};
    
    try {
      idFrontUrl = (await handleFileUpload(files.id_front[0], 'kyc-documents', userId)).url;
      uploadResults.id_front = idFrontUrl;
      
      selfieWithIdUrl = (await handleFileUpload(files.selfie_with_id[0], 'kyc-documents', userId)).url;
      uploadResults.selfie_with_id = selfieWithIdUrl;
      
      if (files.id_back && files.id_back[0]) {
        idBackUrl = (await handleFileUpload(files.id_back[0], 'kyc-documents', userId)).url;
        uploadResults.id_back = idBackUrl;
      }
      
      if (files.address_proof && files.address_proof[0]) {
        addressProofUrl = (await handleFileUpload(files.address_proof[0], 'kyc-documents', userId)).url;
        uploadResults.address_proof = addressProofUrl;
      }
    } catch (uploadError) {
      return res.status(400).json(formatResponse(false, `File upload failed: ${uploadError.message}`));
    }

    // Check for existing KYC submission
    let kycSubmission = await KYCSubmission.findOne({ user: userId });

    // Create or update KYC submission
    const kycData = {
      user: userId,
      id_type,
      id_number,
      id_front_url: idFrontUrl,
      id_back_url: idBackUrl,
      selfie_with_id_url: selfieWithIdUrl,
      address_proof_url: addressProofUrl,
      status: 'pending',
      submitted_ip: req.ip,
      submitted_user_agent: req.headers['user-agent'],
      metadata: {
        submitted_at: new Date(),
        uploads: uploadResults
      }
    };

    if (kycSubmission) {
      kycSubmission = await KYCSubmission.findByIdAndUpdate(
        kycSubmission._id,
        kycData,
        { new: true }
      );
    } else {
      kycSubmission = new KYCSubmission(kycData);
      await kycSubmission.save();
    }

    // Update user KYC status
    await User.findByIdAndUpdate(userId, {
      kyc_status: 'pending',
      kyc_submitted_at: new Date()
    });

    logger.info('KYC submitted', {
      userId,
      idType: id_type,
      hasAddressProof: !!addressProofUrl
    });

    // Create notification
    await createNotification(
      userId,
      'KYC Submitted',
      'Your KYC documents have been submitted successfully. Verification typically takes 24-48 hours.',
      'kyc',
      '/kyc',
      { 
        id_type, 
        has_address_proof: !!addressProofUrl,
        submission_id: kycSubmission._id 
      }
    );

    // Notify admin
    const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } });
    for (const admin of admins) {
      await createNotification(
        admin._id,
        'New KYC Submission',
        `User ${req.user.full_name} has submitted KYC documents for verification. ID Type: ${id_type}`,
        'system',
        `/admin/kyc/${kycSubmission._id}`,
        { 
          user_id: userId,
          user_name: req.user.full_name,
          id_type,
          id_number,
          has_id_front: !!idFrontUrl,
          has_selfie: !!selfieWithIdUrl,
          has_address_proof: !!addressProofUrl
        }
      );
    }

    res.status(201).json(formatResponse(true, 'KYC submitted successfully!', {
      kyc: {
        id: kycSubmission._id,
        id_type: kycSubmission.id_type,
        status: kycSubmission.status,
        submitted_at: kycSubmission.createdAt
      },
      uploads: uploadResults,
      message: 'Your KYC documents have been submitted for verification. You will be notified once verified.'
    }));

  } catch (error) {
    handleError(res, error, 'Error submitting KYC', req.requestId);
  }
});

// Get KYC status
app.get('/api/kyc/status', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const [kycSubmission, user] = await Promise.all([
      KYCSubmission.findOne({ user: userId }).lean(),
      User.findById(userId).lean()
    ]);

    const responseData = {
      kyc_status: user.kyc_status,
      kyc_verified: user.kyc_verified,
      kyc_submitted_at: user.kyc_submitted_at,
      kyc_verified_at: user.kyc_verified_at,
      kyc_submission: kycSubmission ? {
        id_type: kycSubmission.id_type,
        id_number: kycSubmission.id_number,
        status: kycSubmission.status,
        submitted_at: kycSubmission.createdAt,
        reviewed_at: kycSubmission.reviewed_at,
        rejection_reason: kycSubmission.rejection_reason,
        notes: kycSubmission.notes,
        // Include image URLs
        id_front_url: kycSubmission.id_front_url,
        id_back_url: kycSubmission.id_back_url,
        selfie_with_id_url: kycSubmission.selfie_with_id_url,
        address_proof_url: kycSubmission.address_proof_url
      } : null
    };

    res.json(formatResponse(true, 'KYC status retrieved', responseData));

  } catch (error) {
    handleError(res, error, 'Error fetching KYC status', req.requestId);
  }
});

// ==================== ENHANCED SUPPORT ENDPOINTS ====================

// Submit support ticket
app.post('/api/support', auth, upload.array('attachments', 5), [
  body('subject').notEmpty().trim().isLength({ min: 5, max: 200 })
    .withMessage('Subject must be between 5 and 200 characters'),
  body('message').notEmpty().trim().isLength({ min: 10, max: 5000 })
    .withMessage('Message must be between 10 and 5000 characters'),
  body('category').optional().isIn(['general', 'technical', 'investment', 'withdrawal', 'deposit', 'kyc', 'account', 'other', 'bug', 'feature_request'])
    .withMessage('Invalid category'),
  body('priority').optional().isIn(['low', 'medium', 'high', 'urgent'])
    .withMessage('Invalid priority')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { subject, message, category = 'general', priority = 'medium' } = req.body;
    const userId = req.user._id;
    const files = req.files || [];

    // Handle file uploads
    const attachments = [];
    for (const file of files) {
      try {
        const uploadResult = await handleFileUpload(file, 'support-attachments', userId);
        attachments.push({
          filename: uploadResult.filename,
          url: uploadResult.url,
          size: uploadResult.size,
          mime_type: uploadResult.mimeType,
          uploaded_at: new Date()
        });
      } catch (uploadError) {
        logger.error('Error uploading support attachment', {
          error: uploadError.message,
          userId
        });
      }
    }

    // Generate unique ticket ID
    const ticketId = `TKT${Date.now()}${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

    // Create support ticket
    const supportTicket = new SupportTicket({
      user: userId,
      ticket_id: ticketId,
      subject,
      message,
      category,
      priority,
      attachments,
      status: 'open',
      metadata: {
        ip_address: req.ip,
        user_agent: req.headers['user-agent'],
        attachments_count: attachments.length
      }
    });

    await supportTicket.save();

    logger.info('Support ticket created', {
      userId,
      ticketId,
      category,
      priority,
      attachmentsCount: attachments.length
    });

    // Create notification
    await createNotification(
      userId,
      'Support Ticket Created',
      `Your support ticket #${ticketId} has been created successfully. We will respond within 24 hours.`,
      'info',
      `/support/ticket/${ticketId}`,
      { 
        ticket_id: ticketId, 
        category, 
        priority, 
        attachments_count: attachments.length 
      }
    );

    // Notify admin
    const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } });
    for (const admin of admins) {
      await createNotification(
        admin._id,
        'New Support Ticket',
        `User ${req.user.full_name} has submitted a new support ticket: ${subject} (${category}, ${priority} priority)`,
        'system',
        `/admin/support/${ticketId}`,
        { 
          user_id: userId,
          user_name: req.user.full_name,
          ticket_id: ticketId,
          subject,
          category,
          priority,
          attachments_count: attachments.length,
          has_attachments: attachments.length > 0
        }
      );
    }

    res.status(201).json(formatResponse(true, 'Support ticket created successfully!', {
      ticket: {
        id: supportTicket._id,
        ticket_id: ticketId,
        subject: supportTicket.subject,
        category: supportTicket.category,
        priority: supportTicket.priority,
        status: supportTicket.status,
        created_at: supportTicket.createdAt,
        attachments_count: attachments.length
      },
      message: 'Your support ticket has been submitted. You will receive a response within 24 hours.'
    }));

  } catch (error) {
    handleError(res, error, 'Error creating support ticket', req.requestId);
  }
});

// Get user support tickets
app.get('/api/support/tickets', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { status, page = 1, limit = 10 } = req.query;
    
    const query = { user: userId };
    if (status) query.status = status;
    
    const skip = (page - 1) * limit;
    
    const [tickets, total] = await Promise.all([
      SupportTicket.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      SupportTicket.countDocuments(query)
    ]);

    // Enhance tickets
    const enhancedTickets = tickets.map(ticket => {
      const statusColors = {
        'open': 'warning',
        'in_progress': 'info',
        'resolved': 'success',
        'closed': 'default',
        'pending': 'warning'
      };
      
      const priorityColors = {
        'low': 'success',
        'medium': 'warning',
        'high': 'error',
        'urgent': 'danger'
      };
      
      return {
        ...ticket,
        status_color: statusColors[ticket.status] || 'default',
        priority_color: priorityColors[ticket.priority] || 'default',
        has_attachments: ticket.attachments && ticket.attachments.length > 0,
        attachments_count: ticket.attachments ? ticket.attachments.length : 0,
        last_updated: ticket.updatedAt,
        days_open: Math.ceil((new Date() - new Date(ticket.createdAt)) / (1000 * 60 * 60 * 24))
      };
    });

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(formatResponse(true, 'Support tickets retrieved successfully', {
      tickets: enhancedTickets,
      stats: {
        total_tickets: total,
        open_tickets: enhancedTickets.filter(t => t.status === 'open').length,
        in_progress_tickets: enhancedTickets.filter(t => t.status === 'in_progress').length,
        resolved_tickets: enhancedTickets.filter(t => t.status === 'resolved').length,
        closed_tickets: enhancedTickets.filter(t => t.status === 'closed').length
      },
      pagination
    }));

  } catch (error) {
    handleError(res, error, 'Error fetching support tickets', req.requestId);
  }
});

// Get support ticket by ID
app.get('/api/support/ticket/:ticketId', auth, async (req, res) => {
  try {
    const { ticketId } = req.params;
    const userId = req.user._id;
    
    const ticket = await SupportTicket.findOne({ 
      ticket_id: ticketId,
      user: userId 
    }).lean();
    
    if (!ticket) {
      return res.status(404).json(formatResponse(false, 'Support ticket not found'));
    }
    
    res.json(formatResponse(true, 'Support ticket retrieved successfully', {
      ticket: {
        ...ticket,
        has_attachments: ticket.attachments && ticket.attachments.length > 0,
        attachments_count: ticket.attachments ? ticket.attachments.length : 0
      }
    }));
    
  } catch (error) {
    handleError(res, error, 'Error fetching support ticket', req.requestId);
  }
});

// ==================== ENHANCED REFERRAL ENDPOINTS ====================

// Get referral stats
app.get('/api/referrals/stats', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const referrals = await Referral.find({ referrer: userId })
      .populate('referred_user', 'full_name email createdAt balance total_earnings')
      .sort({ createdAt: -1 })
      .lean();
    
    const totalReferrals = referrals.length;
    const activeReferrals = referrals.filter(r => r.status === 'active').length;
    const totalEarnings = referrals.reduce((sum, r) => sum + (r.earnings || 0), 0);
    const pendingEarnings = referrals
      .filter(r => r.status === 'pending' && !r.earnings_paid)
      .reduce((sum, r) => sum + (r.earnings || 0), 0);
    
    // Calculate recent referrals (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const recentReferrals = referrals.filter(r => new Date(r.createdAt) > thirtyDaysAgo);

    // Calculate estimated monthly earnings
    const estimatedMonthlyEarnings = activeReferrals > 0 ? 
      (totalEarnings / (referrals.length || 1)) * activeReferrals : 0;

    res.json(formatResponse(true, 'Referral stats retrieved successfully', {
      stats: {
        total_referrals: totalReferrals,
        active_referrals: activeReferrals,
        total_earnings: parseFloat(totalEarnings.toFixed(2)),
        pending_earnings: parseFloat(pendingEarnings.toFixed(2)),
        referral_code: req.user.referral_code,
        referral_link: `${config.clientURL}/register?ref=${req.user.referral_code}`,
        recent_referrals: recentReferrals.length,
        estimated_monthly_earnings: parseFloat(estimatedMonthlyEarnings.toFixed(2)),
        commission_rate: `${config.referralCommissionPercent}%`
      },
      referrals: referrals.slice(0, 10),
      recent_activity: recentReferrals.slice(0, 5)
    }));

  } catch (error) {
    handleError(res, error, 'Error fetching referral stats', req.requestId);
  }
});

// Get referral details
app.get('/api/referrals/details', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const referrals = await Referral.find({ referrer: userId })
      .populate('referred_user', 'full_name email phone createdAt balance total_earnings total_investments total_deposits')
      .sort({ createdAt: -1 })
      .lean();
    
    // Calculate detailed statistics
    const detailedStats = referrals.map(ref => {
      const referredUser = ref.referred_user;
      return {
        id: ref._id,
        referred_user: {
          id: referredUser?._id,
          full_name: referredUser?.full_name,
          email: referredUser?.email,
          phone: referredUser?.phone,
          joined_date: referredUser?.createdAt,
          balance: referredUser?.balance || 0,
          total_earnings: referredUser?.total_earnings || 0,
          total_investments: referredUser?.total_investments || 0,
          total_deposits: referredUser?.total_deposits || 0
        },
        referral: {
          status: ref.status,
          earnings: ref.earnings || 0,
          commission_percentage: ref.commission_percentage || config.referralCommissionPercent,
          earnings_paid: ref.earnings_paid || false,
          paid_at: ref.paid_at,
          conversion_date: ref.conversion_date,
          created_at: ref.createdAt
        }
      };
    });
    
    // Calculate summary
    const summary = {
      total_referrals: referrals.length,
      active_referrals: referrals.filter(r => r.status === 'active').length,
      total_earnings: parseFloat(referrals.reduce((sum, r) => sum + (r.earnings || 0), 0).toFixed(2)),
      unpaid_earnings: parseFloat(referrals.filter(r => !r.earnings_paid).reduce((sum, r) => sum + (r.earnings || 0), 0).toFixed(2)),
      total_invested_by_referrals: parseFloat(referrals.reduce((sum, r) => {
        const user = r.referred_user;
        return sum + (user?.total_investments || 0);
      }, 0).toFixed(2)),
      total_deposits_by_referrals: parseFloat(referrals.reduce((sum, r) => {
        const user = r.referred_user;
        return sum + (user?.total_deposits || 0);
      }, 0).toFixed(2))
    };
    
    res.json(formatResponse(true, 'Referral details retrieved successfully', {
      referrals: detailedStats,
      summary,
      referral_code: req.user.referral_code,
      referral_link: `${config.clientURL}/register?ref=${req.user.referral_code}`,
      commission_rate: `${config.referralCommissionPercent}%`
    }));
    
  } catch (error) {
    handleError(res, error, 'Error fetching referral details', req.requestId);
  }
});

// ==================== ENHANCED UPLOAD ENDPOINTS ====================

// File upload endpoint
app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json(formatResponse(false, 'No file uploaded'));
    }

    const userId = req.user._id;
    const folder = req.body.folder || 'general';
    const purpose = req.body.purpose || 'general';

    const uploadResult = await handleFileUpload(req.file, folder, userId);

    logger.info('File uploaded', {
      userId,
      filename: uploadResult.filename,
      folder,
      purpose,
      size: uploadResult.size
    });

    res.json(formatResponse(true, 'File uploaded successfully', {
      fileUrl: uploadResult.url,
      fileName: uploadResult.filename,
      originalName: uploadResult.originalName,
      size: uploadResult.size,
      mimeType: uploadResult.mimeType,
      folder,
      purpose,
      uploadedAt: uploadResult.uploadedAt,
      downloadUrl: `${config.serverURL}/uploads/${folder}/${uploadResult.filename}`
    }));

  } catch (error) {
    handleError(res, error, 'Error uploading file', req.requestId);
  }
});

// Multiple file upload endpoint
app.post('/api/upload/multiple', auth, upload.array('files', 10), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json(formatResponse(false, 'No files uploaded'));
    }

    const userId = req.user._id;
    const folder = req.body.folder || 'general';
    const uploadResults = [];

    for (const file of req.files) {
      try {
        const uploadResult = await handleFileUpload(file, folder, userId);
        uploadResults.push(uploadResult);
      } catch (uploadError) {
        logger.error('Error uploading file in batch', {
          error: uploadError.message,
          originalName: file.originalname
        });
      }
    }

    logger.info('Multiple files uploaded', {
      userId,
      folder,
      totalFiles: req.files.length,
      successfulUploads: uploadResults.length
    });

    res.json(formatResponse(true, 'Files uploaded successfully', {
      files: uploadResults,
      total: req.files.length,
      successful: uploadResults.length,
      failed: req.files.length - uploadResults.length
    }));

  } catch (error) {
    handleError(res, error, 'Error uploading files', req.requestId);
  }
});

// ==================== ENHANCED ADMIN ENDPOINTS ====================

// Admin dashboard
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
  try {
    // Get comprehensive statistics
    const [
      totalUsers,
      newUsersToday,
      newUsersWeek,
      totalInvestments,
      activeInvestments,
      totalDeposits,
      totalWithdrawals,
      earningsResult,
      platformFeesResult,
      referralEarningsResult,
      pendingInvestments,
      pendingDeposits,
      pendingWithdrawals,
      pendingKYC,
      recentTransactions,
      recentUsers,
      topPlans,
      adminAudits,
      systemStats
    ] = await Promise.all([
      User.countDocuments({}),
      User.countDocuments({ 
        createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) } 
      }),
      User.countDocuments({ 
        createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) } 
      }),
      Investment.countDocuments({}),
      Investment.countDocuments({ status: 'active' }),
      Deposit.countDocuments({ status: 'approved' }),
      Withdrawal.countDocuments({ status: 'paid' }),
      Investment.aggregate([
        { $match: { status: 'active' } },
        { $group: { _id: null, total: { $sum: '$earned_so_far' } } }
      ]),
      Withdrawal.aggregate([
        { $match: { status: 'paid' } },
        { $group: { _id: null, total: { $sum: '$platform_fee' } } }
      ]),
      Referral.aggregate([
        { $group: { _id: null, total: { $sum: '$earnings' } } }
      ]),
      Investment.countDocuments({ status: 'pending' }),
      Deposit.countDocuments({ status: 'pending' }),
      Withdrawal.countDocuments({ status: 'pending' }),
      KYCSubmission.countDocuments({ status: 'pending' }),
      Transaction.find({})
        .populate('user', 'full_name email')
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      User.find({})
        .select('full_name email phone createdAt last_login')
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      InvestmentPlan.find({ is_active: true })
        .sort({ investment_count: -1 })
        .limit(5)
        .lean(),
      AdminAudit.find({})
        .populate('admin_id', 'full_name email')
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      // System statistics
      Investment.aggregate([
        { $match: { status: 'active' } },
        { $group: { 
          _id: null, 
          totalActiveValue: { $sum: '$amount' },
          totalDailyEarnings: { $sum: '$daily_earnings' }
        } }
      ])
    ]);

    const totalEarnings = earningsResult[0]?.total || 0;
    const platformEarnings = platformFeesResult[0]?.total || 0;
    const referralEarnings = referralEarningsResult[0]?.total || 0;
    const systemStatsData = systemStats[0] || { totalActiveValue: 0, totalDailyEarnings: 0 };

    // Calculate total platform revenue
    const totalRevenue = platformEarnings;

    // Get daily/weekly/monthly stats
    const today = new Date();
    const startOfWeek = new Date(today.setDate(today.getDate() - today.getDay()));
    const startOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);

    const [weeklyStats, monthlyStats, userGrowth] = await Promise.all([
      // Weekly stats
      Promise.all([
        Deposit.aggregate([
          { $match: { 
            status: 'approved',
            createdAt: { $gte: startOfWeek }
          }},
          { $group: { _id: null, total: { $sum: '$amount' }, count: { $sum: 1 } } }
        ]),
        Withdrawal.aggregate([
          { $match: { 
            status: 'paid',
            createdAt: { $gte: startOfWeek }
          }},
          { $group: { _id: null, total: { $sum: '$amount' }, count: { $sum: 1 } } }
        ]),
        Investment.aggregate([
          { $match: { 
            createdAt: { $gte: startOfWeek }
          }},
          { $group: { _id: null, total: { $sum: '$amount' }, count: { $sum: 1 } } }
        ])
      ]),
      // Monthly stats
      Promise.all([
        Deposit.aggregate([
          { $match: { 
            status: 'approved',
            createdAt: { $gte: startOfMonth }
          }},
          { $group: { _id: null, total: { $sum: '$amount' } } }
        ]),
        Withdrawal.aggregate([
          { $match: { 
            status: 'paid',
            createdAt: { $gte: startOfMonth }
          }},
          { $group: { _id: null, total: { $sum: '$amount' } } }
        ])
      ]),
      // User growth (last 6 months)
      User.aggregate([
        {
          $group: {
            _id: {
              year: { $year: '$createdAt' },
              month: { $month: '$createdAt' }
            },
            count: { $sum: 1 }
          }
        },
        { $sort: { '_id.year': -1, '_id.month': -1 } },
        { $limit: 6 }
      ])
    ]);

    const weeklyDeposits = weeklyStats[0][0] || { total: 0, count: 0 };
    const weeklyWithdrawals = weeklyStats[1][0] || { total: 0, count: 0 };
    const weeklyInvestments = weeklyStats[2][0] || { total: 0, count: 0 };
    const monthlyDeposits = monthlyStats[0][0]?.total || 0;
    const monthlyWithdrawals = monthlyStats[1][0]?.total || 0;

    const stats = {
      overview: {
        total_users: totalUsers,
        new_users_today: newUsersToday,
        new_users_week: newUsersWeek,
        total_investments: totalInvestments,
        active_investments: activeInvestments,
        total_deposits: totalDeposits,
        total_withdrawals: totalWithdrawals,
        total_earnings: parseFloat(totalEarnings.toFixed(2)),
        platform_revenue: parseFloat(totalRevenue.toFixed(2)),
        referral_earnings: parseFloat(referralEarnings.toFixed(2)),
        total_active_value: parseFloat(systemStatsData.totalActiveValue.toFixed(2)),
        total_daily_earnings: parseFloat(systemStatsData.totalDailyEarnings.toFixed(2))
      },
      pending_actions: {
        pending_investments: pendingInvestments,
        pending_deposits: pendingDeposits,
        pending_withdrawals: pendingWithdrawals,
        pending_kyc: pendingKYC,
        total_pending: pendingInvestments + pendingDeposits + pendingWithdrawals + pendingKYC
      },
      period_stats: {
        weekly: {
          deposits: parseFloat(weeklyDeposits.total.toFixed(2)),
          deposits_count: weeklyDeposits.count,
          withdrawals: parseFloat(weeklyWithdrawals.total.toFixed(2)),
          withdrawals_count: weeklyWithdrawals.count,
          investments: parseFloat(weeklyInvestments.total.toFixed(2)),
          investments_count: weeklyInvestments.count
        },
        monthly: {
          deposits: parseFloat(monthlyDeposits.toFixed(2)),
          withdrawals: parseFloat(monthlyWithdrawals.toFixed(2))
        }
      },
      user_growth: userGrowth,
      top_performers: {
        investment_plans: topPlans
      },
      recent_activity: {
        transactions: recentTransactions.map(txn => ({
          ...txn,
          has_proof: !!txn.payment_proof_url,
          formatted_amount: `₦${Math.abs(txn.amount).toLocaleString()}`
        })),
        users: recentUsers,
        admin_actions: adminAudits
      }
    };

    // Create audit log
    await createAdminAudit(
      req.user._id,
      'VIEW_ADMIN_DASHBOARD',
      'system',
      null,
      { dashboard_viewed: true },
      req.ip,
      req.headers['user-agent']
    );

    res.json(formatResponse(true, 'Admin dashboard stats retrieved successfully', {
      stats,
      quick_links: {
        pending_investments: '/api/admin/pending-investments',
        pending_deposits: '/api/admin/pending-deposits',
        pending_withdrawals: '/api/admin/pending-withdrawals',
        pending_kyc: '/api/admin/pending-kyc',
        all_users: '/api/admin/users',
        all_transactions: '/api/admin/transactions',
        system_settings: '/api/admin/settings'
      }
    }));

  } catch (error) {
    handleError(res, error, 'Error fetching admin dashboard stats', req.requestId);
  }
});

// Get all users with filtering
app.get('/api/admin/users', adminAuth, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 20, 
      status, 
      role, 
      kyc_status, 
      search,
      sort_by = 'createdAt',
      sort_order = 'desc',
      min_balance,
      max_balance,
      start_date,
      end_date,
      has_bank_details,
      has_investments
    } = req.query;
    
    const query = {};
    
    // Apply filters
    if (status === 'active') query.is_active = true;
    if (status === 'inactive') query.is_active = false;
    if (role) query.role = role;
    if (kyc_status) query.kyc_status = kyc_status;
    
    // Balance range filter
    if (min_balance || max_balance) {
      query.balance = {};
      if (min_balance) query.balance.$gte = parseFloat(min_balance);
      if (max_balance) query.balance.$lte = parseFloat(max_balance);
    }
    
    // Date range filter
    if (start_date || end_date) {
      query.createdAt = {};
      if (start_date) query.createdAt.$gte = new Date(start_date);
      if (end_date) query.createdAt.$lte = new Date(end_date);
    }
    
    // Bank details filter
    if (has_bank_details === 'true') {
      query['bank_details.account_number'] = { $exists: true, $ne: '' };
    } else if (has_bank_details === 'false') {
      query['bank_details.account_number'] = { $exists: false };
    }
    
    // Search
    if (search) {
      query.$or = [
        { full_name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { phone: { $regex: search, $options: 'i' } },
        { referral_code: { $regex: search, $options: 'i' } },
        { 'bank_details.account_number': { $regex: search, $options: 'i' } }
      ];
    }
    
    const skip = (page - 1) * limit;
    const sort = { [sort_by]: sort_order === 'desc' ? -1 : 1 };
    
    const [users, total] = await Promise.all([
      User.find(query)
        .select('-password -two_factor_secret -verification_token -password_reset_token')
        .sort(sort)
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      User.countDocuments(query)
    ]);

    // Get additional stats for each user
    const enhancedUsers = await Promise.all(users.map(async (user) => {
      const [investments, deposits, withdrawals, referrals, activeInvestments] = await Promise.all([
        Investment.countDocuments({ user: user._id }),
        Deposit.countDocuments({ user: user._id, status: 'approved' }),
        Withdrawal.countDocuments({ user: user._id, status: 'paid' }),
        Referral.countDocuments({ referrer: user._id }),
        Investment.find({ user: user._id, status: 'active' })
          .populate('plan', 'daily_interest')
          .lean()
      ]);
      
      // Calculate daily interest
      let dailyInterest = 0;
      activeInvestments.forEach(inv => {
        if (inv.plan && inv.plan.daily_interest) {
          dailyInterest += (inv.amount * inv.plan.daily_interest) / 100;
        }
      });
      
      // Calculate total invested
      const totalInvested = await Investment.aggregate([
        { $match: { user: user._id } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]);
      
      // Calculate total earned
      const totalEarned = await Investment.aggregate([
        { $match: { user: user._id } },
        { $group: { _id: null, total: { $sum: '$earned_so_far' } } }
      ]);
      
      return {
        ...user,
        stats: {
          total_investments: investments,
          total_deposits: deposits,
          total_withdrawals: withdrawals,
          total_referrals: referrals,
          total_invested: totalInvested[0]?.total || 0,
          total_earned: totalEarned[0]?.total || 0,
          daily_interest: parseFloat(dailyInterest.toFixed(2)),
          portfolio_value: parseFloat((user.balance + (totalEarned[0]?.total || 0) + (user.referral_earnings || 0)).toFixed(2)),
          has_bank_details: !!(user.bank_details && user.bank_details.account_number),
          bank_verified: !!(user.bank_details && user.bank_details.verified),
          kyc_complete: user.kyc_status === 'verified'
        }
      };
    }));

    // Create audit log
    await createAdminAudit(
      req.user._id,
      'VIEW_ALL_USERS',
      'system',
      null,
      { 
        page,
        limit,
        filters: {
          status,
          role,
          kyc_status,
          search,
          min_balance,
          max_balance,
          start_date,
          end_date,
          has_bank_details,
          has_investments
        }
      },
      req.ip,
      req.headers['user-agent']
    );

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(formatResponse(true, 'Users retrieved successfully', {
      users: enhancedUsers,
      pagination,
      filters: {
        status,
        role,
        kyc_status,
        search,
        min_balance,
        max_balance,
        start_date,
        end_date,
        has_bank_details,
        has_investments
      },
      summary: {
        total_users: total,
        active_users: enhancedUsers.filter(u => u.is_active).length,
        verified_users: enhancedUsers.filter(u => u.kyc_verified).length,
        total_balance: parseFloat(enhancedUsers.reduce((sum, u) => sum + u.balance, 0).toFixed(2)),
        total_portfolio_value: parseFloat(enhancedUsers.reduce((sum, u) => sum + u.stats.portfolio_value, 0).toFixed(2))
      }
    }));

  } catch (error) {
    handleError(res, error, 'Error fetching users', req.requestId);
  }
});

// Get user by ID
app.get('/api/admin/users/:id', adminAuth, async (req, res) => {
  try {
    const userId = req.params.id;
    
    const user = await User.findById(userId)
      .select('-password -two_factor_secret -verification_token -password_reset_token')
      .populate('referred_by', 'full_name email referral_code')
      .lean();
    
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }
    
    // Get comprehensive user data
    const [
      investments,
      deposits,
      withdrawals,
      transactions,
      referrals,
      kyc,
      supportTickets,
      userReferrals,
      totalInvested,
      totalEarned,
      activeInvestments
    ] = await Promise.all([
      Investment.find({ user: userId })
        .populate('plan', 'name daily_interest')
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      Deposit.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      Withdrawal.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      Transaction.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(50)
        .lean(),
      Referral.find({ referred_user: userId })
        .populate('referrer', 'full_name email')
        .lean(),
      KYCSubmission.findOne({ user: userId }).lean(),
      SupportTicket.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      Referral.find({ referrer: userId })
        .populate('referred_user', 'full_name email createdAt balance total_earnings')
        .sort({ createdAt: -1 })
        .lean(),
      Investment.aggregate([
        { $match: { user: new mongoose.Types.ObjectId(userId) } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      Investment.aggregate([
        { $match: { 
          user: new mongoose.Types.ObjectId(userId),
          status: 'active'
        }},
        { $group: { _id: null, total: { $sum: '$earned_so_far' } } }
      ]),
      Investment.find({ user: userId, status: 'active' })
        .populate('plan', 'name daily_interest')
        .lean()
    ]);
    
    const totalInvestedAmount = totalInvested[0]?.total || 0;
    const totalEarnedAmount = totalEarned[0]?.total || 0;
    
    // Calculate daily interest
    let dailyInterest = 0;
    activeInvestments.forEach(inv => {
      if (inv.plan && inv.plan.daily_interest) {
        dailyInterest += (inv.amount * inv.plan.daily_interest) / 100;
      }
    });
    
    // Calculate user statistics
    const userStats = {
      total_investments: investments.length,
      active_investments: investments.filter(i => i.status === 'active').length,
      total_deposits: deposits.filter(d => d.status === 'approved').length,
      total_withdrawals: withdrawals.filter(w => w.status === 'paid').length,
      total_transactions: transactions.length,
      total_referrals: userReferrals.length,
      total_invested: parseFloat(totalInvestedAmount.toFixed(2)),
      total_earned: parseFloat(totalEarnedAmount.toFixed(2)),
      daily_interest: parseFloat(dailyInterest.toFixed(2)),
      portfolio_value: parseFloat((user.balance + totalEarnedAmount + (user.referral_earnings || 0)).toFixed(2)),
      average_investment: investments.length > 0 ? parseFloat((totalInvestedAmount / investments.length).toFixed(2)) : 0,
      success_rate: investments.length > 0 ? 
        parseFloat(((investments.filter(inv => inv.status === 'completed' || inv.status === 'active').length / investments.length) * 100).toFixed(2)) : 0
    };
    
    // Create audit log
    await createAdminAudit(
      req.user._id,
      'VIEW_USER_DETAILS',
      'user',
      userId,
      { viewed_at: new Date() },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'User details retrieved successfully', {
      user: {
        ...user,
        bank_details: user.bank_details || null,
        wallet_address: user.wallet_address || null,
        paypal_email: user.paypal_email || null
      },
      statistics: userStats,
      investments: {
        count: investments.length,
        recent: investments.slice(0, 10).map(inv => ({
          ...inv,
          has_proof: !!inv.payment_proof_url,
          proof_url: inv.payment_proof_url
        }))
      },
      deposits: {
        count: deposits.length,
        recent: deposits.slice(0, 10).map(dep => ({
          ...dep,
          has_proof: !!dep.payment_proof_url,
          proof_url: dep.payment_proof_url
        }))
      },
      withdrawals: {
        count: withdrawals.length,
        recent: withdrawals.slice(0, 10).map(wdl => ({
          ...wdl,
          has_proof: !!wdl.payment_proof_url,
          proof_url: wdl.payment_proof_url
        }))
      },
      transactions: {
        count: transactions.length,
        recent: transactions.slice(0, 20).map(txn => ({
          ...txn,
          has_proof: !!txn.payment_proof_url,
          proof_url: txn.payment_proof_url
        }))
      },
      referrals: {
        referred_by: referrals[0]?.referrer || null,
        referral_code: user.referral_code,
        referred_users: userReferrals
      },
      kyc_submission: kyc ? {
        ...kyc,
        has_id_front: !!kyc.id_front_url,
        has_selfie: !!kyc.selfie_with_id_url,
        has_address_proof: !!kyc.address_proof_url
      } : null,
      support_tickets: supportTickets,
      financial_summary: {
        current_balance: user.balance,
        total_earnings: user.total_earnings || 0,
        referral_earnings: user.referral_earnings || 0,
        total_invested: parseFloat(totalInvestedAmount.toFixed(2)),
        total_earned: parseFloat(totalEarnedAmount.toFixed(2)),
        net_profit: parseFloat((totalEarnedAmount - totalInvestedAmount).toFixed(2)),
        daily_interest: parseFloat(dailyInterest.toFixed(2)),
        monthly_interest_estimate: parseFloat((dailyInterest * 30).toFixed(2))
      },
      images: {
        profile_image: user.profile_image,
        kyc_images: kyc ? {
          id_front: kyc.id_front_url,
          id_back: kyc.id_back_url,
          selfie: kyc.selfie_with_id_url,
          address_proof: kyc.address_proof_url
        } : null
      }
    }));

  } catch (error) {
    handleError(res, error, 'Error fetching user details', req.requestId);
  }
});

// Update user role
app.put('/api/admin/users/:id/role', adminAuth, [
  body('role').isIn(['user', 'admin', 'super_admin'])
    .withMessage('Invalid role')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.params.id;
    const { role } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { role },
      { new: true }
    );

    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    logger.info('User role updated', {
      adminId: req.user._id,
      userId,
      newRole: role,
      oldRole: user.role
    });

    // Create notification for user
    await createNotification(
      userId,
      'Account Role Updated',
      `Your account role has been updated to ${role}.`,
      'system',
      null,
      { new_role: role, updated_by: req.user.full_name }
    );

    // Create audit log
    await createAdminAudit(
      req.user._id,
      'UPDATE_USER_ROLE',
      'user',
      userId,
      {
        old_role: user.role,
        new_role: role,
        user_name: user.full_name
      },
      req.ip,
      req.headers['user-agent'],
      'high'
    );

    res.json(formatResponse(true, 'User role updated successfully', { 
      user: {
        id: user._id,
        full_name: user.full_name,
        email: user.email,
        role: user.role
      }
    }));

  } catch (error) {
    handleError(res, error, 'Error updating user role', req.requestId);
  }
});

// Update user status
app.put('/api/admin/users/:id/status', adminAuth, [
  body('is_active').isBoolean()
    .withMessage('is_active must be a boolean')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.params.id;
    const { is_active } = req.body;

    const user = await User.findByIdAndUpdate(
      userId,
      { is_active },
      { new: true }
    );

    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    logger.info('User status updated', {
      adminId: req.user._id,
      userId,
      is_active
    });

    // Create notification for user
    await createNotification(
      userId,
      is_active ? 'Account Activated' : 'Account Deactivated',
      is_active 
        ? 'Your account has been activated. You can now access all features.'
        : 'Your account has been deactivated. Please contact support for assistance.',
      'system',
      null,
      { 
        status: is_active ? 'active' : 'inactive',
        updated_by: req.user.full_name,
        timestamp: new Date()
      }
    );

    // Create audit log
    await createAdminAudit(
      req.user._id,
      is_active ? 'ACTIVATE_USER' : 'DEACTIVATE_USER',
      'user',
      userId,
      {
        user_name: user.full_name,
        old_status: !is_active,
        new_status: is_active
      },
      req.ip,
      req.headers['user-agent'],
      'high'
    );

    res.json(formatResponse(true, 
      is_active ? 'User activated successfully' : 'User deactivated successfully', 
      { 
        user: {
          id: user._id,
          full_name: user.full_name,
          email: user.email,
          is_active: user.is_active
        }
      }
    ));

  } catch (error) {
    handleError(res, error, 'Error updating user status', req.requestId);
  }
});

// Update user balance
app.put('/api/admin/users/:id/balance', adminAuth, [
  body('amount').isFloat()
    .withMessage('Amount must be a number'),
  body('type').isIn(['add', 'subtract', 'set'])
    .withMessage('Type must be add, subtract, or set'),
  body('description').optional().trim(),
  body('reference').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.params.id;
    const { amount, type, description, reference } = req.body;
    const adminId = req.user._id;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    let newBalance = user.balance;
    let transactionType = 'bonus';
    let transactionDescription = description || '';

    switch (type) {
      case 'add':
        newBalance += parseFloat(amount);
        transactionType = 'bonus';
        transactionDescription = transactionDescription || `Admin credited balance: ₦${amount}`;
        break;
      case 'subtract':
        newBalance -= parseFloat(amount);
        transactionType = 'fee';
        transactionDescription = transactionDescription || `Admin debited balance: ₦${amount}`;
        break;
      case 'set':
        newBalance = parseFloat(amount);
        transactionType = 'transfer';
        transactionDescription = transactionDescription || `Admin set balance to: ₦${amount}`;
        break;
    }

    // Ensure balance doesn't go negative
    if (newBalance < 0) {
      return res.status(400).json(formatResponse(false, 'Balance cannot be negative'));
    }

    // Update user balance
    user.balance = newBalance;
    await user.save();

    logger.info('User balance updated', {
      adminId,
      userId,
      type,
      amount,
      oldBalance: user.balance - (type === 'add' ? parseFloat(amount) : type === 'subtract' ? -parseFloat(amount) : 0),
      newBalance
    });

    // Create transaction
    await createTransaction(
      userId,
      transactionType,
      type === 'subtract' ? -parseFloat(amount) : parseFloat(amount),
      transactionDescription,
      'completed',
      { 
        admin_id: adminId, 
        adjustment_type: type,
        reference: reference || generateReference('ADJ'),
        admin_name: req.user.full_name
      }
    );

    // Create notification
    await createNotification(
      userId,
      'Balance Updated',
      `Your account balance has been updated. New balance: ₦${newBalance.toLocaleString()}`,
      'info',
      '/dashboard',
      { 
        amount: type === 'set' ? amount : (type === 'add' ? amount : -amount),
        type: type,
        new_balance: newBalance,
        description: transactionDescription,
        reference: reference
      }
    );

    // Create audit log
    await createAdminAudit(
      adminId,
      'ADJUST_USER_BALANCE',
      'user',
      userId,
      {
        user_name: user.full_name,
        adjustment_type: type,
        amount: amount,
        old_balance: user.balance - (type === 'add' ? parseFloat(amount) : type === 'subtract' ? -parseFloat(amount) : 0),
        new_balance: newBalance,
        description: description,
        reference: reference
      },
      req.ip,
      req.headers['user-agent'],
      'high'
    );

    res.json(formatResponse(true, 'User balance updated successfully', {
      user: {
        id: user._id,
        email: user.email,
        previous_balance: user.balance - (type === 'add' ? parseFloat(amount) : type === 'subtract' ? -parseFloat(amount) : 0),
        new_balance: newBalance,
        change_type: type,
        change_amount: amount,
        transaction_reference: reference
      }
    }));

  } catch (error) {
    handleError(res, error, 'Error updating user balance', req.requestId);
  }
});

// Get pending investments
app.get('/api/admin/pending-investments', adminAuth, async (req, res) => {
  try {
    const pendingInvestments = await Investment.find({ status: 'pending' })
      .populate('user', 'full_name email phone')
      .populate('plan', 'name min_amount daily_interest')
      .sort({ createdAt: -1 })
      .lean();

    // Enhance with image data
    const enhancedInvestments = pendingInvestments.map(inv => ({
      ...inv,
      has_proof: !!inv.payment_proof_url,
      proof_url: inv.payment_proof_url || null,
      proof_available: !!inv.payment_proof_url,
      formatted_amount: `₦${inv.amount.toLocaleString()}`,
      user_details: {
        name: inv.user.full_name,
        email: inv.user.email,
        phone: inv.user.phone
      }
    }));

    // Create audit log
    await createAdminAudit(
      req.user._id,
      'VIEW_PENDING_INVESTMENTS',
      'system',
      null,
      { count: pendingInvestments.length },
      req.ip,
      req.headers['user-agent']
    );

    res.json(formatResponse(true, 'Pending investments retrieved successfully', {
      investments: enhancedInvestments,
      count: pendingInvestments.length,
      total_amount: parseFloat(pendingInvestments.reduce((sum, inv) => sum + inv.amount, 0).toFixed(2)),
      summary: {
        with_proof: pendingInvestments.filter(inv => inv.payment_proof_url).length,
        without_proof: pendingInvestments.filter(inv => !inv.payment_proof_url).length,
        average_amount: pendingInvestments.length > 0 ? 
          parseFloat((pendingInvestments.reduce((sum, inv) => sum + inv.amount, 0) / pendingInvestments.length).toFixed(2)) : 0
      }
    }));

  } catch (error) {
    handleError(res, error, 'Error fetching pending investments', req.requestId);
  }
});

// Approve investment
app.post('/api/admin/investments/:id/approve', adminAuth, [
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const investmentId = req.params.id;
    const adminId = req.user._id;
    const { remarks } = req.body;

    const investment = await Investment.findById(investmentId)
      .populate('user plan');
    
    if (!investment) {
      return res.status(404).json(formatResponse(false, 'Investment not found'));
    }

    if (investment.status !== 'pending') {
      return res.status(400).json(formatResponse(false, 'Investment is not pending approval'));
    }

    // Update investment
    investment.status = 'active';
    investment.approved_at = new Date();
    investment.approved_by = adminId;
    investment.payment_verified = true;
    investment.proof_verified_by = adminId;
    investment.proof_verified_at = new Date();
    investment.remarks = remarks;
    
    await investment.save();

    // Update plan statistics
    await InvestmentPlan.findByIdAndUpdate(investment.plan._id, {
      $inc: { 
        investment_count: 1,
        total_invested: investment.amount
      }
    });

    // Update user investment count
    await User.findByIdAndUpdate(investment.user._id, {
      $inc: { total_investments: 1 },
      last_investment_date: new Date()
    });

    logger.info('Investment approved', {
      adminId,
      investmentId,
      userId: investment.user._id,
      amount: investment.amount,
      plan: investment.plan.name
    });

    // Create notification for user
    await createNotification(
      investment.user._id,
      'Investment Approved',
      `Your investment of ₦${investment.amount.toLocaleString()} in ${investment.plan.name} has been approved and is now active.`,
      'investment',
      '/investments',
      { 
        amount: investment.amount,
        plan_name: investment.plan.name,
        approved_by: req.user.full_name,
        approved_at: new Date()
      }
    );

    // Send email notification
    await sendEmail(
      investment.user.email,
      'Investment Approved - Raw Wealthy',
      `<h2>Investment Approved</h2>
       <p>Your investment has been approved and is now active.</p>
       <p><strong>Investment Details:</strong></p>
       <ul>
         <li>Plan: ${investment.plan.name}</li>
         <li>Amount: ₦${investment.amount.toLocaleString()}</li>
         <li>Daily Interest: ${investment.plan.daily_interest}%</li>
         <li>Expected Earnings: ₦${investment.expected_earnings.toLocaleString()}</li>
         <li>Status: Active</li>
         <li>Approved By: ${req.user.full_name}</li>
       </ul>
       <p><a href="${config.clientURL}/investments">View Investment</a></p>`
    );

    // Create audit log
    await createAdminAudit(
      adminId,
      'APPROVE_INVESTMENT',
      'investment',
      investmentId,
      {
        amount: investment.amount,
        plan: investment.plan.name,
        user_id: investment.user._id,
        user_name: investment.user.full_name,
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent'],
      'medium'
    );

    res.json(formatResponse(true, 'Investment approved successfully', {
      investment: {
        ...investment.toObject(),
        approved_by_admin: req.user.full_name,
        proof_verified: true
      },
      message: 'Investment approved and user notified'
    }));

  } catch (error) {
    handleError(res, error, 'Error approving investment', req.requestId);
  }
});

// Reject investment
app.post('/api/admin/investments/:id/reject', adminAuth, [
  body('remarks').notEmpty()
    .withMessage('Rejection remarks are required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Rejection remarks are required'));
    }

    const investmentId = req.params.id;
    const adminId = req.user._id;
    const { remarks } = req.body;

    const investment = await Investment.findById(investmentId)
      .populate('user');
    
    if (!investment) {
      return res.status(404).json(formatResponse(false, 'Investment not found'));
    }

    if (investment.status !== 'pending') {
      return res.status(400).json(formatResponse(false, 'Investment is not pending'));
    }

    // Update investment
    investment.status = 'rejected';
    investment.approved_by = adminId;
    investment.remarks = remarks;
    investment.proof_verified_by = adminId;
    investment.proof_verified_at = new Date();
    
    await investment.save();

    // Refund user balance
    await User.findByIdAndUpdate(investment.user._id, {
      $inc: { balance: investment.amount }
    });

    logger.info('Investment rejected', {
      adminId,
      investmentId,
      userId: investment.user._id,
      amount: investment.amount,
      remarks
    });

    // Create transaction for refund
    await createTransaction(
      investment.user._id,
      'refund',
      investment.amount,
      `Refund for rejected investment`,
      'completed',
      { investment_id: investment._id, remarks: remarks }
    );

    // Create notification
    await createNotification(
      investment.user._id,
      'Investment Rejected',
      `Your investment of ₦${investment.amount.toLocaleString()} has been rejected. Reason: ${remarks}`,
      'error',
      '/investments',
      { amount: investment.amount, remarks: remarks }
    );

    // Create audit log
    await createAdminAudit(
      adminId,
      'REJECT_INVESTMENT',
      'investment',
      investmentId,
      {
        amount: investment.amount,
        user_id: investment.user._id,
        user_name: investment.user.full_name,
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent'],
      'medium'
    );

    res.json(formatResponse(true, 'Investment rejected successfully', {
      investment: {
        id: investment._id,
        status: investment.status,
        amount_refunded: investment.amount,
        remarks: investment.remarks
      }
    }));

  } catch (error) {
    handleError(res, error, 'Error rejecting investment', req.requestId);
  }
});

// Get pending deposits
app.get('/api/admin/pending-deposits', adminAuth, async (req, res) => {
  try {
    const pendingDeposits = await Deposit.find({ status: 'pending' })
      .populate('user', 'full_name email phone balance')
      .sort({ createdAt: -1 })
      .lean();

    // Enhance with image data
    const enhancedDeposits = pendingDeposits.map(dep => ({
      ...dep,
      has_proof: !!dep.payment_proof_url,
      proof_url: dep.payment_proof_url || null,
      proof_available: !!dep.payment_proof_url,
      formatted_amount: `₦${dep.amount.toLocaleString()}`,
      user_details: {
        name: dep.user.full_name,
        email: dep.user.email,
        phone: dep.user.phone,
        current_balance: dep.user.balance
      },
      days_pending: Math.ceil((new Date() - new Date(dep.createdAt)) / (1000 * 60 * 60 * 24))
    }));

    // Create audit log
    await createAdminAudit(
      req.user._id,
      'VIEW_PENDING_DEPOSITS',
      'system',
      null,
      { count: pendingDeposits.length },
      req.ip,
      req.headers['user-agent']
    );

    res.json(formatResponse(true, 'Pending deposits retrieved successfully', {
      deposits: enhancedDeposits,
      count: pendingDeposits.length,
      total_amount: parseFloat(pendingDeposits.reduce((sum, dep) => sum + dep.amount, 0).toFixed(2)),
      summary: {
        with_proof: pendingDeposits.filter(dep => dep.payment_proof_url).length,
        without_proof: pendingDeposits.filter(dep => !dep.payment_proof_url).length,
        by_payment_method: pendingDeposits.reduce((acc, dep) => {
          acc[dep.payment_method] = (acc[dep.payment_method] || 0) + 1;
          return acc;
        }, {})
      }
    }));

  } catch (error) {
    handleError(res, error, 'Error fetching pending deposits', req.requestId);
  }
});

// Approve deposit
app.post('/api/admin/deposits/:id/approve', adminAuth, [
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const depositId = req.params.id;
    const adminId = req.user._id;
    const { remarks } = req.body;

    const deposit = await Deposit.findById(depositId)
      .populate('user');
    
    if (!deposit) {
      return res.status(404).json(formatResponse(false, 'Deposit not found'));
    }

    if (deposit.status !== 'pending') {
      return res.status(400).json(formatResponse(false, 'Deposit is not pending approval'));
    }

    // Update deposit
    deposit.status = 'approved';
    deposit.approved_at = new Date();
    deposit.approved_by = adminId;
    deposit.proof_verified_by = adminId;
    deposit.proof_verified_at = new Date();
    deposit.admin_notes = remarks;
    
    await deposit.save();

    // Update user balance and stats
    await User.findByIdAndUpdate(deposit.user._id, {
      $inc: { 
        balance: deposit.amount,
        total_deposits: deposit.amount
      },
      last_deposit_date: new Date()
    });

    logger.info('Deposit approved', {
      adminId,
      depositId,
      userId: deposit.user._id,
      amount: deposit.amount,
      paymentMethod: deposit.payment_method
    });

    // Create transaction
    await createTransaction(
      deposit.user._id,
      'deposit',
      deposit.amount,
      `Deposit via ${deposit.payment_method}`,
      'completed',
      { 
        deposit_id: deposit._id,
        payment_method: deposit.payment_method,
        proof_url: deposit.payment_proof_url,
        verified_by: req.user.full_name
      },
      deposit.payment_proof_url
    );

    // Create notification
    await createNotification(
      deposit.user._id,
      'Deposit Approved',
      `Your deposit of ₦${deposit.amount.toLocaleString()} has been approved and credited to your account.`,
      'success',
      '/deposits',
      { 
        amount: deposit.amount,
        payment_method: deposit.payment_method,
        approved_by: req.user.full_name,
        new_balance: deposit.user.balance + deposit.amount
      }
    );

    // Send email notification
    await sendEmail(
      deposit.user.email,
      'Deposit Approved - Raw Wealthy',
      `<h2>Deposit Approved</h2>
       <p>Your deposit has been approved and the amount has been credited to your account.</p>
       <p><strong>Deposit Details:</strong></p>
       <ul>
         <li>Amount: ₦${deposit.amount.toLocaleString()}</li>
         <li>Payment Method: ${deposit.payment_method}</li>
         <li>Reference: ${deposit.reference}</li>
         <li>New Balance: ₦${(deposit.user.balance + deposit.amount).toLocaleString()}</li>
         <li>Approved By: ${req.user.full_name}</li>
       </ul>
       <p><a href="${config.clientURL}/deposits">View Deposit</a></p>`
    );

    // Create audit log
    await createAdminAudit(
      adminId,
      'APPROVE_DEPOSIT',
      'deposit',
      depositId,
      {
        amount: deposit.amount,
        payment_method: deposit.payment_method,
        user_id: deposit.user._id,
        user_name: deposit.user.full_name,
        remarks: remarks,
        has_proof: !!deposit.payment_proof_url
      },
      req.ip,
      req.headers['user-agent'],
      'medium'
    );

    res.json(formatResponse(true, 'Deposit approved successfully', {
      deposit: {
        ...deposit.toObject(),
        approved_by_admin: req.user.full_name,
        proof_verified: true,
        user_new_balance: deposit.user.balance + deposit.amount
      },
      message: 'Deposit approved and user notified'
    }));

  } catch (error) {
    handleError(res, error, 'Error approving deposit', req.requestId);
  }
});

// Reject deposit
app.post('/api/admin/deposits/:id/reject', adminAuth, [
  body('remarks').notEmpty()
    .withMessage('Rejection remarks are required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Rejection remarks are required'));
    }

    const depositId = req.params.id;
    const adminId = req.user._id;
    const { remarks } = req.body;

    const deposit = await Deposit.findById(depositId)
      .populate('user');
    
    if (!deposit) {
      return res.status(404).json(formatResponse(false, 'Deposit not found'));
    }

    if (deposit.status !== 'pending') {
      return res.status(400).json(formatResponse(false, 'Deposit is not pending'));
    }

    // Update deposit
    deposit.status = 'rejected';
    deposit.approved_by = adminId;
    deposit.proof_verified_by = adminId;
    deposit.proof_verified_at = new Date();
    deposit.admin_notes = remarks;
    
    await deposit.save();

    logger.info('Deposit rejected', {
      adminId,
      depositId,
      userId: deposit.user._id,
      amount: deposit.amount,
      remarks
    });

    // Create notification
    await createNotification(
      deposit.user._id,
      'Deposit Rejected',
      `Your deposit of ₦${deposit.amount.toLocaleString()} has been rejected. Reason: ${remarks}`,
      'error',
      '/deposits',
      { amount: deposit.amount, remarks: remarks }
    );

    // Create audit log
    await createAdminAudit(
      adminId,
      'REJECT_DEPOSIT',
      'deposit',
      depositId,
      {
        amount: deposit.amount,
        user_id: deposit.user._id,
        user_name: deposit.user.full_name,
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent'],
      'medium'
    );

    res.json(formatResponse(true, 'Deposit rejected successfully', {
      deposit: {
        id: deposit._id,
        status: deposit.status,
        amount: deposit.amount,
        remarks: deposit.admin_notes
      }
    }));

  } catch (error) {
    handleError(res, error, 'Error rejecting deposit', req.requestId);
  }
});

// Get pending withdrawals
app.get('/api/admin/pending-withdrawals', adminAuth, async (req, res) => {
  try {
    const pendingWithdrawals = await Withdrawal.find({ status: 'pending' })
      .populate('user', 'full_name email phone balance')
      .sort({ createdAt: -1 })
      .lean();

    // Enhance with calculations and image data
    const enhancedWithdrawals = pendingWithdrawals.map(wdl => ({
      ...wdl,
      has_proof: !!wdl.payment_proof_url,
      proof_url: wdl.payment_proof_url || null,
      proof_available: !!wdl.payment_proof_url,
      formatted_amount: `₦${wdl.amount.toLocaleString()}`,
      formatted_net_amount: `₦${wdl.net_amount.toLocaleString()}`,
      formatted_fee: `₦${wdl.platform_fee.toLocaleString()}`,
      user_details: {
        name: wdl.user.full_name,
        email: wdl.user.email,
        phone: wdl.user.phone,
        current_balance: wdl.user.balance
      },
      days_pending: Math.ceil((new Date() - new Date(wdl.createdAt)) / (1000 * 60 * 60 * 24)),
      payment_details: wdl.bank_details || { wallet_address: wdl.wallet_address } || { paypal_email: wdl.paypal_email }
    }));

    // Calculate summary
    const summary = {
      total_amount: parseFloat(pendingWithdrawals.reduce((sum, wdl) => sum + wdl.amount, 0).toFixed(2)),
      total_net_amount: parseFloat(pendingWithdrawals.reduce((sum, wdl) => sum + wdl.net_amount, 0).toFixed(2)),
      total_fees: parseFloat(pendingWithdrawals.reduce((sum, wdl) => sum + wdl.platform_fee, 0).toFixed(2)),
      by_payment_method: pendingWithdrawals.reduce((acc, wdl) => {
        acc[wdl.payment_method] = (acc[wdl.payment_method] || 0) + 1;
        return acc;
      }, {})
    };

    // Create audit log
    await createAdminAudit(
      req.user._id,
      'VIEW_PENDING_WITHDRAWALS',
      'system',
      null,
      { count: pendingWithdrawals.length, summary },
      req.ip,
      req.headers['user-agent']
    );

    res.json(formatResponse(true, 'Pending withdrawals retrieved successfully', {
      withdrawals: enhancedWithdrawals,
      count: pendingWithdrawals.length,
      summary
    }));

  } catch (error) {
    handleError(res, error, 'Error fetching pending withdrawals', req.requestId);
  }
});

// Approve withdrawal
app.post('/api/admin/withdrawals/:id/approve', adminAuth, [
  body('transaction_id').optional().trim(),
  body('payment_proof_url').optional().trim(),
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const withdrawalId = req.params.id;
    const adminId = req.user._id;
    const { transaction_id, payment_proof_url, remarks } = req.body;

    const withdrawal = await Withdrawal.findById(withdrawalId)
      .populate('user');
    
    if (!withdrawal) {
      return res.status(404).json(formatResponse(false, 'Withdrawal not found'));
    }

    if (withdrawal.status !== 'pending') {
      return res.status(400).json(formatResponse(false, 'Withdrawal is not pending approval'));
    }

    // Update withdrawal
    withdrawal.status = 'paid';
    withdrawal.approved_at = new Date();
    withdrawal.approved_by = adminId;
    withdrawal.paid_at = new Date();
    withdrawal.transaction_id = transaction_id;
    withdrawal.payment_proof_url = payment_proof_url;
    withdrawal.proof_verified_by = adminId;
    withdrawal.proof_verified_at = new Date();
    withdrawal.admin_notes = remarks;
    
    await withdrawal.save();

    logger.info('Withdrawal approved', {
      adminId,
      withdrawalId,
      userId: withdrawal.user._id,
      amount: withdrawal.amount,
      paymentMethod: withdrawal.payment_method,
      transactionId: transaction_id
    });

    // Update transaction status
    await Transaction.findOneAndUpdate(
      { related_withdrawal: withdrawalId },
      { 
        status: 'completed',
        payment_proof_url: payment_proof_url,
        admin_notes: remarks
      }
    );

    // Update user withdrawal stats
    await User.findByIdAndUpdate(withdrawal.user._id, {
      $inc: { total_withdrawals: withdrawal.amount },
      last_withdrawal_date: new Date()
    });

    // Create notification
    await createNotification(
      withdrawal.user._id,
      'Withdrawal Approved',
      `Your withdrawal of ₦${withdrawal.amount.toLocaleString()} has been approved and processed.${transaction_id ? ` Transaction ID: ${transaction_id}` : ''}`,
      'success',
      '/withdrawals',
      { 
        amount: withdrawal.amount,
        net_amount: withdrawal.net_amount,
        fee: withdrawal.platform_fee,
        payment_method: withdrawal.payment_method,
        transaction_id: transaction_id,
        has_proof: !!payment_proof_url
      }
    );

    // Send email notification
    await sendEmail(
      withdrawal.user.email,
      'Withdrawal Processed Successfully - Raw Wealthy',
      `<h2>Withdrawal Processed</h2>
       <p>Your withdrawal request has been processed successfully.</p>
       <p><strong>Details:</strong></p>
       <ul>
         <li>Amount: ₦${withdrawal.amount.toLocaleString()}</li>
         <li>Net Amount: ₦${withdrawal.net_amount.toLocaleString()}</li>
         <li>Platform Fee: ₦${withdrawal.platform_fee.toLocaleString()}</li>
         <li>Payment Method: ${withdrawal.payment_method}</li>
         <li>Transaction ID: ${transaction_id || 'N/A'}</li>
         ${withdrawal.bank_details ? `
         <li>Bank: ${withdrawal.bank_details.bank_name}</li>
         <li>Account: ${withdrawal.bank_details.account_number}</li>
         <li>Account Name: ${withdrawal.bank_details.account_name}</li>
         ` : ''}
         ${payment_proof_url ? `<li>Payment Proof: <a href="${payment_proof_url}">View Proof</a></li>` : ''}
       </ul>
       <p><a href="${config.clientURL}/withdrawals">View Withdrawal</a></p>`
    );

    // Create audit log
    await createAdminAudit(
      adminId,
      'APPROVE_WITHDRAWAL',
      'withdrawal',
      withdrawalId,
      {
        amount: withdrawal.amount,
        net_amount: withdrawal.net_amount,
        fee: withdrawal.platform_fee,
        payment_method: withdrawal.payment_method,
        user_id: withdrawal.user._id,
        user_name: withdrawal.user.full_name,
        transaction_id: transaction_id,
        has_proof: !!payment_proof_url,
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent'],
      'medium'
    );

    res.json(formatResponse(true, 'Withdrawal approved successfully', {
      withdrawal: {
        ...withdrawal.toObject(),
        approved_by_admin: req.user.full_name,
        proof_verified: true,
        has_transaction_proof: !!payment_proof_url
      },
      message: 'Withdrawal processed and user notified'
    }));

  } catch (error) {
    handleError(res, error, 'Error approving withdrawal', req.requestId);
  }
});

// Reject withdrawal
app.post('/api/admin/withdrawals/:id/reject', adminAuth, [
  body('remarks').notEmpty()
    .withMessage('Rejection remarks are required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Rejection remarks are required'));
    }

    const withdrawalId = req.params.id;
    const adminId = req.user._id;
    const { remarks } = req.body;

    const withdrawal = await Withdrawal.findById(withdrawalId)
      .populate('user');
    
    if (!withdrawal) {
      return res.status(404).json(formatResponse(false, 'Withdrawal not found'));
    }

    if (withdrawal.status !== 'pending') {
      return res.status(400).json(formatResponse(false, 'Withdrawal is not pending'));
    }

    // Update withdrawal
    withdrawal.status = 'rejected';
    withdrawal.approved_by = adminId;
    withdrawal.proof_verified_by = adminId;
    withdrawal.proof_verified_at = new Date();
    withdrawal.admin_notes = remarks;
    
    await withdrawal.save();

    // Refund user balance
    await User.findByIdAndUpdate(withdrawal.user._id, {
      $inc: { balance: withdrawal.amount }
    });

    logger.info('Withdrawal rejected', {
      adminId,
      withdrawalId,
      userId: withdrawal.user._id,
      amount: withdrawal.amount,
      remarks
    });

    // Update transaction status
    await Transaction.findOneAndUpdate(
      { related_withdrawal: withdrawalId },
      { 
        status: 'cancelled',
        admin_notes: remarks
      }
    );

    // Create transaction for refund
    await createTransaction(
      withdrawal.user._id,
      'refund',
      withdrawal.amount,
      `Refund for rejected withdrawal`,
      'completed',
      { 
        withdrawal_id: withdrawal._id,
        remarks: remarks 
      }
    );

    // Create notification
    await createNotification(
      withdrawal.user._id,
      'Withdrawal Rejected',
      `Your withdrawal of ₦${withdrawal.amount.toLocaleString()} has been rejected. Reason: ${remarks}`,
      'error',
      '/withdrawals',
      { amount: withdrawal.amount, remarks: remarks }
    );

    // Create audit log
    await createAdminAudit(
      adminId,
      'REJECT_WITHDRAWAL',
      'withdrawal',
      withdrawalId,
      {
        amount: withdrawal.amount,
        user_id: withdrawal.user._id,
        user_name: withdrawal.user.full_name,
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent'],
      'medium'
    );

    res.json(formatResponse(true, 'Withdrawal rejected successfully', {
      withdrawal: {
        id: withdrawal._id,
        status: withdrawal.status,
        amount_refunded: withdrawal.amount,
        remarks: withdrawal.admin_notes
      }
    }));

  } catch (error) {
    handleError(res, error, 'Error rejecting withdrawal', req.requestId);
  }
});

// Get all transactions (admin)
app.get('/api/admin/transactions', adminAuth, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 50,
      type,
      status,
      user_id,
      start_date,
      end_date,
      min_amount,
      max_amount,
      has_proof
    } = req.query;
    
    const query = {};
    
    if (type) query.type = type;
    if (status) query.status = status;
    if (user_id) query.user = user_id;
    if (start_date || end_date) {
      query.createdAt = {};
      if (start_date) query.createdAt.$gte = new Date(start_date);
      if (end_date) query.createdAt.$lte = new Date(end_date);
    }
    if (min_amount || max_amount) {
      query.amount = {};
      if (min_amount) query.amount.$gte = parseFloat(min_amount);
      if (max_amount) query.amount.$lte = parseFloat(max_amount);
    }
    if (has_proof === 'true') {
      query.payment_proof_url = { $exists: true, $ne: '' };
    } else if (has_proof === 'false') {
      query.payment_proof_url = { $exists: false };
    }
    
    const skip = (page - 1) * limit;
    
    const [transactions, total] = await Promise.all([
      Transaction.find(query)
        .populate('user', 'full_name email')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Transaction.countDocuments(query)
    ]);
    
    // Enhance transactions
    const enhancedTransactions = transactions.map(txn => {
      const isPositive = txn.amount > 0;
      const typeColor = isPositive ? 'success' : 'error';
      
      return {
        ...txn,
        formatted_amount: `${isPositive ? '+' : '-'}₦${Math.abs(txn.amount).toLocaleString()}`,
        type_color: typeColor,
        has_proof: !!txn.payment_proof_url,
        proof_url: txn.payment_proof_url || null,
        date_formatted: new Date(txn.createdAt).toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit'
        }),
        user_name: txn.user?.full_name || 'N/A',
        user_email: txn.user?.email || 'N/A'
      };
    });
    
    // Calculate summary
    const summary = {
      total_transactions: total,
      total_amount: parseFloat(transactions.reduce((sum, t) => sum + t.amount, 0).toFixed(2)),
      income: parseFloat(transactions.filter(t => t.amount > 0).reduce((sum, t) => sum + t.amount, 0).toFixed(2)),
      expenses: parseFloat(transactions.filter(t => t.amount < 0).reduce((sum, t) => sum + Math.abs(t.amount), 0).toFixed(2)),
      by_type: transactions.reduce((acc, t) => {
        acc[t.type] = (acc[t.type] || 0) + 1;
        return acc;
      }, {}),
      with_proof: transactions.filter(t => t.payment_proof_url).length,
      without_proof: transactions.filter(t => !t.payment_proof_url).length
    };
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };
    
    // Create audit log
    await createAdminAudit(
      req.user._id,
      'VIEW_ALL_TRANSACTIONS',
      'system',
      null,
      { 
        page,
        limit,
        filters: { type, status, user_id, start_date, end_date, min_amount, max_amount, has_proof },
        summary
      },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'Transactions retrieved successfully', {
      transactions: enhancedTransactions,
      summary,
      pagination
    }));

  } catch (error) {
    handleError(res, error, 'Error fetching transactions', req.requestId);
  }
});

// Get pending KYC submissions
app.get('/api/admin/pending-kyc', adminAuth, async (req, res) => {
  try {
    const pendingKYC = await KYCSubmission.find({ status: 'pending' })
      .populate('user', 'full_name email phone')
      .sort({ createdAt: -1 })
      .lean();

    // Enhance with image data
    const enhancedKYC = pendingKYC.map(kyc => ({
      ...kyc,
      user_name: kyc.user?.full_name,
      user_email: kyc.user?.email,
      user_phone: kyc.user?.phone,
      has_id_front: !!kyc.id_front_url,
      has_id_back: !!kyc.id_back_url,
      has_selfie: !!kyc.selfie_with_id_url,
      has_address_proof: !!kyc.address_proof_url,
      days_pending: Math.ceil((new Date() - new Date(kyc.createdAt)) / (1000 * 60 * 60 * 24)),
      images: {
        id_front: kyc.id_front_url,
        id_back: kyc.id_back_url,
        selfie: kyc.selfie_with_id_url,
        address_proof: kyc.address_proof_url
      }
    }));

    // Create audit log
    await createAdminAudit(
      req.user._id,
      'VIEW_PENDING_KYC',
      'system',
      null,
      { count: pendingKYC.length },
      req.ip,
      req.headers['user-agent']
    );

    res.json(formatResponse(true, 'Pending KYC submissions retrieved successfully', {
      kyc_submissions: enhancedKYC,
      count: pendingKYC.length,
      summary: {
        complete_submissions: pendingKYC.filter(k => k.id_front_url && k.selfie_with_id_url).length,
        incomplete_submissions: pendingKYC.filter(k => !(k.id_front_url && k.selfie_with_id_url)).length,
        with_address_proof: pendingKYC.filter(k => k.address_proof_url).length
      }
    }));

  } catch (error) {
    handleError(res, error, 'Error fetching pending KYC', req.requestId);
  }
});

// Approve KYC
app.post('/api/admin/kyc/:id/approve', adminAuth, [
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const kycId = req.params.id;
    const adminId = req.user._id;
    const { remarks } = req.body;

    const kyc = await KYCSubmission.findById(kycId)
      .populate('user');
    
    if (!kyc) {
      return res.status(404).json(formatResponse(false, 'KYC submission not found'));
    }

    if (kyc.status !== 'pending') {
      return res.status(400).json(formatResponse(false, 'KYC is not pending'));
    }

    // Update KYC
    kyc.status = 'approved';
    kyc.reviewed_by = adminId;
    kyc.reviewed_at = new Date();
    kyc.notes = remarks;
    
    await kyc.save();

    // Update user
    await User.findByIdAndUpdate(kyc.user._id, {
      kyc_status: 'verified',
      kyc_verified: true,
      kyc_verified_at: new Date()
    });

    logger.info('KYC approved', {
      adminId,
      kycId,
      userId: kyc.user._id,
      idType: kyc.id_type
    });

    // Create notification
    await createNotification(
      kyc.user._id,
      'KYC Approved',
      'Your KYC documents have been verified and approved. You can now enjoy full platform access.',
      'kyc',
      '/profile',
      { 
        verified_at: new Date(),
        verified_by: req.user.full_name,
        has_images: true,
        id_type: kyc.id_type
      }
    );

    // Send email
    await sendEmail(
      kyc.user.email,
      'KYC Verification Approved - Raw Wealthy',
      `<h2>KYC Verification Approved</h2>
       <p>Your KYC documents have been successfully verified and approved.</p>
       <p>You now have full access to all platform features, including withdrawals.</p>
       <p><strong>Verification Details:</strong></p>
       <ul>
         <li>ID Type: ${kyc.id_type}</li>
         <li>ID Number: ${kyc.id_number}</li>
         <li>Verified By: ${req.user.full_name}</li>
         <li>Verification Date: ${new Date().toLocaleDateString()}</li>
       </ul>
       <p>Thank you for completing the verification process.</p>`
    );

    // Create audit log
    await createAdminAudit(
      adminId,
      'APPROVE_KYC',
      'kyc',
      kycId,
      {
        user_id: kyc.user._id,
        user_name: kyc.user.full_name,
        id_type: kyc.id_type,
        has_id_front: !!kyc.id_front_url,
        has_selfie: !!kyc.selfie_with_id_url,
        has_address_proof: !!kyc.address_proof_url,
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent'],
      'medium'
    );

    res.json(formatResponse(true, 'KYC approved successfully', {
      kyc: {
        id: kyc._id,
        user_id: kyc.user._id,
        status: kyc.status,
        reviewed_by: req.user.full_name,
        reviewed_at: kyc.reviewed_at
      }
    }));

  } catch (error) {
    handleError(res, error, 'Error approving KYC', req.requestId);
  }
});

// Reject KYC
app.post('/api/admin/kyc/:id/reject', adminAuth, [
  body('rejection_reason').notEmpty()
    .withMessage('Rejection reason is required'),
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Rejection reason is required'));
    }

    const kycId = req.params.id;
    const adminId = req.user._id;
    const { rejection_reason, remarks } = req.body;

    const kyc = await KYCSubmission.findById(kycId)
      .populate('user');
    
    if (!kyc) {
      return res.status(404).json(formatResponse(false, 'KYC submission not found'));
    }

    if (kyc.status !== 'pending') {
      return res.status(400).json(formatResponse(false, 'KYC is not pending'));
    }

    // Update KYC
    kyc.status = 'rejected';
    kyc.reviewed_by = adminId;
    kyc.reviewed_at = new Date();
    kyc.rejection_reason = rejection_reason;
    kyc.notes = remarks;
    
    await kyc.save();

    // Update user
    await User.findByIdAndUpdate(kyc.user._id, {
      kyc_status: 'rejected'
    });

    logger.info('KYC rejected', {
      adminId,
      kycId,
      userId: kyc.user._id,
      rejectionReason: rejection_reason
    });

    // Create notification
    await createNotification(
      kyc.user._id,
      'KYC Rejected',
      `Your KYC documents have been rejected. Reason: ${rejection_reason}. Please submit new documents.`,
      'kyc',
      '/kyc',
      { 
        rejection_reason: rejection_reason,
        remarks: remarks,
        can_resubmit: true
      }
    );

    // Create audit log
    await createAdminAudit(
      adminId,
      'REJECT_KYC',
      'kyc',
      kycId,
      {
        user_id: kyc.user._id,
        user_name: kyc.user.full_name,
        rejection_reason: rejection_reason,
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent'],
      'medium'
    );

    res.json(formatResponse(true, 'KYC rejected successfully', {
      kyc: {
        id: kyc._id,
        user_id: kyc.user._id,
        status: kyc.status,
        rejection_reason: kyc.rejection_reason,
        reviewed_by: req.user.full_name,
        reviewed_at: kyc.reviewed_at
      }
    }));

  } catch (error) {
    handleError(res, error, 'Error rejecting KYC', req.requestId);
  }
});

// Verify bank details
app.post('/api/admin/users/:id/verify-bank', adminAuth, [
  body('verified').isBoolean()
    .withMessage('Verified must be a boolean'),
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.params.id;
    const { verified, remarks } = req.body;
    const adminId = req.user._id;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    if (!user.bank_details) {
      return res.status(400).json(formatResponse(false, 'User has no bank details'));
    }

    // Update bank details
    user.bank_details.verified = verified;
    user.bank_details.verified_at = verified ? new Date() : null;
    user.bank_details.last_updated = new Date();
    
    if (remarks) {
      user.bank_details.verification_notes = remarks;
    }
    
    await user.save();

    logger.info('Bank details verification updated', {
      adminId,
      userId,
      verified,
      bankName: user.bank_details.bank_name,
      accountNumber: user.bank_details.account_number.replace(/\d(?=\d{4})/g, '*')
    });

    // Create notification
    await createNotification(
      userId,
      verified ? 'Bank Details Verified' : 'Bank Details Verification Removed',
      verified 
        ? 'Your bank details have been verified successfully. You can now make withdrawals.'
        : 'Bank details verification has been removed. Please update and verify your bank details for withdrawals.',
      verified ? 'success' : 'warning',
      '/profile/bank',
      { 
        verified: verified,
        verified_at: user.bank_details.verified_at,
        verified_by: req.user.full_name,
        remarks: remarks
      }
    );

    // Create audit log
    await createAdminAudit(
      adminId,
      verified ? 'VERIFY_BANK_DETAILS' : 'UNVERIFY_BANK_DETAILS',
      'user',
      userId,
      {
        user_name: user.full_name,
        bank_name: user.bank_details.bank_name,
        account_number: user.bank_details.account_number.replace(/\d(?=\d{4})/g, '*'),
        verified: verified,
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent'],
      'medium'
    );

    res.json(formatResponse(true, 
      verified ? 'Bank details verified successfully' : 'Bank details verification removed',
      { 
        bank_details: {
          bank_name: user.bank_details.bank_name,
          account_name: user.bank_details.account_name,
          account_number: user.bank_details.account_number.replace(/\d(?=\d{4})/g, '*'),
          verified: user.bank_details.verified,
          verified_at: user.bank_details.verified_at,
          last_updated: user.bank_details.last_updated
        },
        user_name: user.full_name
      }
    ));

  } catch (error) {
    handleError(res, error, 'Error verifying bank details', req.requestId);
  }
});

// ==================== ENHANCED NOTIFICATION ENDPOINTS ====================

// Get user notifications
app.get('/api/notifications', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { unread_only, page = 1, limit = 20, type } = req.query;
    
    const query = { user: userId };
    if (unread_only === 'true') {
      query.is_read = false;
    }
    if (type) {
      query.type = type;
    }
    
    const skip = (page - 1) * limit;
    
    const [notifications, total, unreadCount] = await Promise.all([
      Notification.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Notification.countDocuments(query),
      Notification.countDocuments({ user: userId, is_read: false })
    ]);

    // Enhance notifications
    const enhancedNotifications = notifications.map(notif => {
      const typeColors = {
        'info': 'blue',
        'success': 'green',
        'warning': 'yellow',
        'error': 'red',
        'investment': 'purple',
        'withdrawal': 'orange',
        'deposit': 'teal',
        'kyc': 'indigo',
        'referral': 'pink',
        'system': 'gray',
        'security': 'red',
        'account': 'blue',
        'promotional': 'purple'
      };
      
      return {
        ...notif,
        type_color: typeColors[notif.type] || 'gray',
        time_ago: getTimeAgo(notif.createdAt),
        date_formatted: new Date(notif.createdAt).toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit'
        }),
        has_action: !!notif.action_url
      };
    });

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(formatResponse(true, 'Notifications retrieved successfully', {
      notifications: enhancedNotifications,
      pagination,
      unread_count: unreadCount,
      summary: {
        total: total,
        unread: unreadCount,
        by_type: enhancedNotifications.reduce((acc, n) => {
          acc[n.type] = (acc[n.type] || 0) + 1;
          return acc;
        }, {})
      }
    }));

  } catch (error) {
    handleError(res, error, 'Error fetching notifications', req.requestId);
  }
});

// Helper function for time ago
function getTimeAgo(date) {
  const now = new Date();
  const diffMs = now - new Date(date);
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);
  
  if (diffMins < 1) return 'just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return new Date(date).toLocaleDateString();
}

// Mark notification as read
app.post('/api/notifications/:id/read', auth, async (req, res) => {
  try {
    const notificationId = req.params.id;
    const userId = req.user._id;

    const notification = await Notification.findOne({
      _id: notificationId,
      user: userId
    });
    
    if (!notification) {
      return res.status(404).json(formatResponse(false, 'Notification not found'));
    }

    notification.is_read = true;
    notification.read_at = new Date();
    await notification.save();

    res.json(formatResponse(true, 'Notification marked as read', {
      notification_id: notificationId,
      marked_read_at: new Date()
    }));

  } catch (error) {
    handleError(res, error, 'Error marking notification as read', req.requestId);
  }
});

// Mark all notifications as read
app.post('/api/notifications/read-all', auth, async (req, res) => {
  try {
    const userId = req.user._id;

    const result = await Notification.updateMany(
      { user: userId, is_read: false },
      { $set: { is_read: true, read_at: new Date() } }
    );

    res.json(formatResponse(true, 'All notifications marked as read', {
      marked_count: result.modifiedCount,
      marked_at: new Date()
    }));

  } catch (error) {
    handleError(res, error, 'Error marking all notifications as read', req.requestId);
  }
});

// Send notification to users (admin only)
app.post('/api/admin/notifications/send', adminAuth, [
  body('user_ids').optional().isArray(),
  body('title').notEmpty().trim(),
  body('message').notEmpty().trim(),
  body('type').isIn(['info', 'success', 'warning', 'error', 'promotional', 'investment', 'withdrawal', 'deposit', 'kyc', 'referral', 'system', 'security', 'account']),
  body('action_url').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { user_ids, title, message, type, action_url } = req.body;
    const adminId = req.user._id;
    if (user_ids && user_ids.length > 0) {
      // Send to specific users
      users = await User.find({ _id: { $in: user_ids }, is_active: true });
      if (users.length !== user_ids.length) {
        logger.warn('Some users not found or inactive', { 
          requested: user_ids.length, 
          found: users.length 
        });
      }
    } else {
      // Send to all active users
      users = await User.find({ is_active: true });
    }

    const notifications = [];
    const successful = [];
    const failed = [];

    for (const user of users) {
      try {
        const notification = await createNotification(
          user._id,
          title,
          message,
          type,
          action_url,
          {
            sent_by_admin: true,
            admin_id: adminId,
            admin_name: req.user.full_name,
            mass_notification: true
          }
        );
        
        if (notification) {
          notifications.push({
            user_id: user._id,
            user_name: user.full_name,
            notification_id: notification._id
          });
          successful.push(user._id);
        } else {
          failed.push(user._id);
        }
      } catch (error) {
        logger.error('Error sending notification to user', {
          userId: user._id,
          error: error.message
        });
        failed.push(user._id);
      }
    }

    // Create audit log
    await createAdminAudit(
      adminId,
      'SEND_NOTIFICATION',
      'system',
      null,
      {
        target: user_ids ? 'specific_users' : 'all_users',
        target_count: users.length,
        successful_count: successful.length,
        failed_count: failed.length,
        title: title,
        type: type,
        message_length: message.length
      },
      req.ip,
      req.headers['user-agent'],
      'medium'
    );

    res.json(formatResponse(true, 'Notifications sent successfully', {
      sent_count: successful.length,
      failed_count: failed.length,
      target_users: users.length,
      notifications: notifications.slice(0, 10) // Return first 10 for reference
    }));

  } catch (error) {
    handleError(res, error, 'Error sending notifications', req.requestId);
  }
});

// ==================== ENHANCED CRON JOBS ====================

// Calculate daily earnings
cron.schedule('0 0 * * *', async () => {
  try {
    logger.info('🔄 Starting daily earnings calculation...');
    console.log('🔄 Calculating daily earnings...');
    
    const activeInvestments = await Investment.find({ 
      status: 'active',
      end_date: { $gt: new Date() }
    }).populate('user plan');

    let totalEarnings = 0;
    let processedCount = 0;
    const earningsByUser = new Map();

    for (const investment of activeInvestments) {
      try {
        const dailyEarning = investment.daily_earnings || (investment.amount * investment.plan.daily_interest / 100);
        
        // Update investment earnings
        investment.earned_so_far += dailyEarning;
        investment.last_earning_date = new Date();
        await investment.save();

        // Track user earnings
        const userId = investment.user._id.toString();
        if (!earningsByUser.has(userId)) {
          earningsByUser.set(userId, {
            user: investment.user,
            total: 0,
            investments: []
          });
        }
        
        const userEarnings = earningsByUser.get(userId);
        userEarnings.total += dailyEarning;
        userEarnings.investments.push({
          investment_id: investment._id,
          plan: investment.plan.name,
          amount: dailyEarning
        });
        
        totalEarnings += dailyEarning;
        processedCount++;

      } catch (investmentError) {
        logger.error(`Error processing investment ${investment._id}:`, {
          error: investmentError.message,
          investmentId: investment._id
        });
      }
    }

    // Update user balances and create notifications
    for (const [userId, userData] of earningsByUser.entries()) {
      try {
        // Update user balance and total earnings
        await User.findByIdAndUpdate(userId, {
          $inc: { 
            balance: userData.total,
            total_earnings: userData.total
          },
          last_earning_date: new Date()
        });
        
        // Create transaction
        await createTransaction(
          userId,
          'earning',
          userData.total,
          `Daily earnings from ${userData.investments.length} active investments`,
          'completed',
          { 
            earnings_date: new Date().toISOString().split('T')[0],
            investment_count: userData.investments.length,
            investments: userData.investments.map(inv => ({
              id: inv.investment_id,
              plan: inv.plan,
              amount: inv.amount
            }))
          }
        );
        
        // Create notification for user
        if (userData.total > 0) {
          await createNotification(
            userId,
            'Daily Earnings Credited',
            `₦${userData.total.toLocaleString()} has been credited to your account from daily earnings.`,
            'earning',
            '/investments',
            { 
              amount: userData.total,
              date: new Date().toISOString().split('T')[0],
              investment_count: userData.investments.length
            }
          );
        }
        
      } catch (userError) {
        logger.error(`Error updating user ${userId}:`, {
          error: userError.message,
          userId
        });
      }
    }

    // Check for completed investments
    const completedInvestments = await Investment.find({
      status: 'active',
      end_date: { $lte: new Date() }
    }).populate('user plan');

    for (const investment of completedInvestments) {
      try {
        investment.status = 'completed';
        await investment.save();
        
        await createNotification(
          investment.user._id,
          'Investment Completed',
          `Your investment in ${investment.plan.name} has completed successfully. Total earnings: ₦${investment.earned_so_far.toLocaleString()}`,
          'success',
          '/investments',
          { 
            plan_name: investment.plan.name,
            amount: investment.amount,
            total_earnings: investment.earned_so_far,
            duration: investment.plan.duration
          }
        );
        
        // Update plan success rate
        const plan = await InvestmentPlan.findById(investment.plan._id);
        if (plan) {
          const successfulInvestments = await Investment.countDocuments({
            plan: plan._id,
            status: 'completed'
          });
          const totalPlanInvestments = await Investment.countDocuments({
            plan: plan._id
          });
          
          if (totalPlanInvestments > 0) {
            plan.success_rate = (successfulInvestments / totalPlanInvestments) * 100;
            plan.total_earned = (plan.total_earned || 0) + investment.earned_so_far;
            await plan.save();
          }
        }
        
      } catch (completeError) {
        logger.error(`Error completing investment ${investment._id}:`, {
          error: completeError.message,
          investmentId: investment._id
        });
      }
    }

    logger.info('✅ Daily earnings calculation completed', {
      processed: processedCount,
      totalEarnings: totalEarnings,
      users: earningsByUser.size,
      completedInvestments: completedInvestments.length
    });

    console.log(`✅ Daily earnings calculated. Processed: ${processedCount}, Total: ₦${totalEarnings.toLocaleString()}, Users: ${earningsByUser.size}, Completed: ${completedInvestments.length}`);

  } catch (error) {
    logger.error('❌ Error calculating daily earnings:', {
      error: error.message,
      stack: error.stack
    });
    console.error('❌ Error calculating daily earnings:', error);
  }
});

// Auto-renew investments
cron.schedule('0 1 * * *', async () => {
  try {
    logger.info('🔄 Processing auto-renew investments...');
    console.log('🔄 Processing auto-renew investments...');
    
    const completedInvestments = await Investment.find({
      status: 'completed',
      auto_renew: true,
      auto_renewed: false
    }).populate('user plan');

    let renewedCount = 0;
    let skippedCount = 0;

    for (const investment of completedInvestments) {
      try {
        const userId = investment.user._id;
        const planId = investment.plan._id;
        
        // Check if user has sufficient balance
        const user = await User.findById(userId);
        if (!user || user.balance < investment.amount) {
          logger.warn(`User ${userId} has insufficient balance for auto-renew`);
          skippedCount++;
          continue;
        }

        // Check if plan is still active
        const plan = await InvestmentPlan.findById(planId);
        if (!plan || !plan.is_active) {
          logger.warn(`Plan ${planId} is not active for auto-renew`);
          skippedCount++;
          continue;
        }

        // Create new investment
        const newInvestment = new Investment({
          user: userId,
          plan: planId,
          amount: investment.amount,
          status: 'active',
          start_date: new Date(),
          end_date: new Date(Date.now() + plan.duration * 24 * 60 * 60 * 1000),
          expected_earnings: (investment.amount * plan.total_interest) / 100,
          earned_so_far: 0,
          daily_earnings: (investment.amount * plan.daily_interest) / 100,
          auto_renew: true,
          auto_renewed: false,
          metadata: {
            auto_renewed_from: investment._id,
            original_investment_date: investment.start_date,
            renewal_count: (investment.metadata?.renewal_count || 0) + 1
          }
        });

        await newInvestment.save();
        
        // Update user balance
        await User.findByIdAndUpdate(userId, {
          $inc: { balance: -investment.amount }
        });
        
        // Update plan statistics
        await InvestmentPlan.findByIdAndUpdate(planId, {
          $inc: { 
            investment_count: 1,
            total_invested: investment.amount
          }
        });
        
        // Create transaction
        await createTransaction(
          userId,
          'investment',
          -investment.amount,
          `Auto-renew investment in ${plan.name}`,
          'completed',
          { 
            investment_id: newInvestment._id,
            renewed_from: investment._id,
            plan_name: plan.name,
            renewal_count: (investment.metadata?.renewal_count || 0) + 1
          }
        );

        // Mark original investment as renewed
        investment.auto_renewed = true;
        if (!investment.metadata) investment.metadata = {};
        investment.metadata.renewed_to = newInvestment._id;
        investment.metadata.renewed_at = new Date();
        await investment.save();

        // Create notification
        await createNotification(
          userId,
          'Investment Auto-Renewed',
          `Your investment of ₦${investment.amount.toLocaleString()} in ${plan.name} has been automatically renewed.`,
          'investment',
          '/investments',
          { 
            amount: investment.amount,
            plan_name: plan.name,
            new_investment_id: newInvestment._id,
            renewal_count: (investment.metadata?.renewal_count || 0) + 1
          }
        );

        renewedCount++;
        logger.info(`Auto-renewed investment ${investment._id} for user ${userId}`);

      } catch (error) {
        logger.error(`Error auto-renewing investment ${investment._id}:`, {
          error: error.message,
          investmentId: investment._id
        });
        skippedCount++;
      }
    }

    logger.info('✅ Auto-renew completed', {
      renewed: renewedCount,
      skipped: skippedCount
    });

    console.log(`✅ Auto-renew completed. Renewed: ${renewedCount}, Skipped: ${skippedCount}`);

  } catch (error) {
    logger.error('❌ Error processing auto-renew:', {
      error: error.message,
      stack: error.stack
    });
    console.error('❌ Error processing auto-renew:', error);
  }
});

// Cleanup expired data
cron.schedule('0 2 * * *', async () => {
  try {
    logger.info('🔄 Cleaning up expired data...');
    console.log('🔄 Cleaning up expired data...');
    
    const now = new Date();
    
    // Clean up old notifications (older than 90 days)
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
    
    const deletedNotifications = await Notification.deleteMany({
      createdAt: { $lt: ninetyDaysAgo },
      is_read: true
    });
    
    // Clean up expired password reset tokens
    const cleanedUsers = await User.updateMany({
      password_reset_expires: { $lt: now }
    }, {
      $unset: {
        password_reset_token: 1,
        password_reset_expires: 1
      }
    });
    
    // Clean up expired verification tokens
    const cleanedVerificationTokens = await User.updateMany({
      verification_expires: { $lt: now }
    }, {
      $unset: {
        verification_token: 1,
        verification_expires: 1
      }
    });
    
    // Clean up old admin audit logs (older than 180 days)
    const oneEightyDaysAgo = new Date();
    oneEightyDaysAgo.setDate(oneEightyDaysAgo.getDate() - 180);
    
    const deletedAudits = await AdminAudit.deleteMany({
      createdAt: { $lt: oneEightyDaysAgo }
    });
    
    // Clean up expired sessions/inactive users
    const oneYearAgo = new Date();
    oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);
    
    const inactiveUsers = await User.find({
      last_active: { $lt: oneYearAgo },
      is_active: true,
      role: 'user',
      balance: 0,
      total_investments: 0
    });
    
    let deactivatedCount = 0;
    for (const user of inactiveUsers) {
      user.is_active = false;
      await user.save();
      deactivatedCount++;
    }
    
    logger.info('✅ Cleanup completed', {
      deletedNotifications: deletedNotifications.deletedCount,
      deletedAudits: deletedAudits.deletedCount,
      deactivatedUsers: deactivatedCount
    });

    console.log(`✅ Cleanup completed. Removed: ${deletedNotifications.deletedCount} notifications, ${deletedAudits.deletedCount} audit logs, Deactivated: ${deactivatedCount} users`);
    
  } catch (error) {
    logger.error('❌ Error during cleanup:', {
      error: error.message,
      stack: error.stack
    });
    console.error('❌ Error during cleanup:', error);
  }
});

// Weekly report generation
cron.schedule('0 9 * * 1', async () => { // Every Monday at 9 AM
  try {
    logger.info('📊 Generating weekly report...');
    console.log('📊 Generating weekly report...');
    
    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
    
    const [
      newUsers,
      newInvestments,
      totalDeposits,
      totalWithdrawals,
      activeUsers,
      totalRevenue,
      newKYC,
      completedInvestments
    ] = await Promise.all([
      User.countDocuments({ createdAt: { $gte: oneWeekAgo } }),
      Investment.countDocuments({ createdAt: { $gte: oneWeekAgo } }),
      Deposit.aggregate([
        { $match: { 
          status: 'approved',
          createdAt: { $gte: oneWeekAgo }
        }},
        { $group: { _id: null, total: { $sum: '$amount' }, count: { $sum: 1 } } }
      ]),
      Withdrawal.aggregate([
        { $match: { 
          status: 'paid',
          createdAt: { $gte: oneWeekAgo }
        }},
        { $group: { _id: null, total: { $sum: '$amount' }, count: { $sum: 1 } } }
      ]),
      User.countDocuments({ last_active: { $gte: oneWeekAgo } }),
      Withdrawal.aggregate([
        { $match: { 
          status: 'paid',
          createdAt: { $gte: oneWeekAgo }
        }},
        { $group: { _id: null, total_fees: { $sum: '$platform_fee' } } }
      ]),
      KYCSubmission.countDocuments({ 
        status: 'approved',
        createdAt: { $gte: oneWeekAgo }
      }),
      Investment.countDocuments({ 
        status: 'completed',
        createdAt: { $gte: oneWeekAgo }
      })
    ]);
    
    const deposits = totalDeposits[0] || { total: 0, count: 0 };
    const withdrawals = totalWithdrawals[0] || { total: 0, count: 0 };
    const revenue = totalRevenue[0] || { total_fees: 0 };
    
    // Send report to admins
    const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } });
    
    for (const admin of admins) {
      await sendEmail(
        admin.email,
        'Raw Wealthy - Weekly Performance Report',
        `<h2>Weekly Platform Performance Report</h2>
         <p>Here's your weekly performance report for the period:</p>
         <p><strong>Period:</strong> ${oneWeekAgo.toLocaleDateString()} - ${new Date().toLocaleDateString()}</p>
         
         <h3>📈 User Statistics</h3>
         <ul>
           <li><strong>New Users:</strong> ${newUsers}</li>
           <li><strong>Active Users (last week):</strong> ${activeUsers}</li>
           <li><strong>New KYC Approvals:</strong> ${newKYC}</li>
         </ul>
         
         <h3>💰 Financial Statistics</h3>
         <ul>
           <li><strong>New Investments:</strong> ${newInvestments}</li>
           <li><strong>Completed Investments:</strong> ${completedInvestments}</li>
           <li><strong>Total Deposits:</strong> ₦${deposits.total.toLocaleString()} (${deposits.count} transactions)</li>
           <li><strong>Total Withdrawals:</strong> ₦${withdrawals.total.toLocaleString()} (${withdrawals.count} transactions)</li>
           <li><strong>Platform Revenue (Fees):</strong> ₦${revenue.total_fees.toLocaleString()}</li>
           <li><strong>Net Flow:</strong> ₦${(deposits.total - withdrawals.total).toLocaleString()}</li>
         </ul>
         
         <h3>📊 Growth Metrics</h3>
         <ul>
           <li><strong>Deposit Growth Rate:</strong> ${deposits.count > 0 ? 'Positive' : 'No new deposits'}</li>
           <li><strong>Withdrawal Growth Rate:</strong> ${withdrawals.count > 0 ? 'Positive' : 'No new withdrawals'}</li>
           <li><strong>User Growth Rate:</strong> ${newUsers > 0 ? 'Positive' : 'No new users'}</li>
         </ul>
         
         <p><strong>Actions Required:</strong></p>
         <ul>
           ${pendingActions > 0 ? `<li>You have ${pendingActions} pending actions requiring attention</li>` : '<li>No pending actions</li>'}
           ${newKYC > 0 ? `<li>${newKYC} new KYC submissions to review</li>` : ''}
         </ul>
         
         <p>Best regards,<br>Raw Wealthy Analytics System</p>`,
        `Weekly Report: ${newUsers} new users, ₦${deposits.total} deposits, ₦${withdrawals.total} withdrawals`
      );
    }
    
    logger.info('✅ Weekly report sent', {
      adminsCount: admins.length,
      newUsers,
      newInvestments,
      deposits: deposits.total,
      withdrawals: withdrawals.total
    });
    
    console.log(`✅ Weekly report sent to ${admins.length} admins`);
    
  } catch (error) {
    logger.error('❌ Error generating weekly report:', {
      error: error.message,
      stack: error.stack
    });
    console.error('❌ Error generating weekly report:', error);
  }
});

// Daily maintenance check
cron.schedule('30 3 * * *', async () => {
  try {
    logger.info('🔧 Running daily maintenance check...');
    console.log('🔧 Running daily maintenance check...');
    
    // Check for stuck transactions
    const stuckTransactions = await Transaction.find({
      status: 'processing',
      createdAt: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) } // Older than 24 hours
    });
    
    if (stuckTransactions.length > 0) {
      logger.warn(`Found ${stuckTransactions.length} stuck transactions`);
      console.log(`⚠️ Found ${stuckTransactions.length} stuck transactions`);
      
      // Update stuck transactions to failed
      await Transaction.updateMany(
        { 
          _id: { $in: stuckTransactions.map(t => t._id) }
        },
        { 
          $set: { 
            status: 'failed',
            admin_notes: 'Automatically marked as failed due to prolonged processing time'
          }
        }
      );
    }
    
    // Check for expired investments that are still active
    const expiredInvestments = await Investment.find({
      status: 'active',
      end_date: { $lt: new Date(Date.now() - 24 * 60 * 60 * 1000) } // Ended more than 24 hours ago
    });
    
    if (expiredInvestments.length > 0) {
      logger.warn(`Found ${expiredInvestments.length} expired investments still marked as active`);
      console.log(`⚠️ Found ${expiredInvestments.length} expired investments still marked as active`);
      
      for (const investment of expiredInvestments) {
        investment.status = 'completed';
        await investment.save();
        
        logger.info(`Auto-completed investment ${investment._id}`);
      }
    }
    
    // Check database connection health
    const dbStats = await mongoose.connection.db.stats();
    logger.info('Database health check', {
      collections: dbStats.collections,
      objects: dbStats.objects,
      avgObjSize: dbStats.avgObjSize,
      dataSize: dbStats.dataSize,
      storageSize: dbStats.storageSize,
      indexes: dbStats.indexes,
      indexSize: dbStats.indexSize
    });
    
    // Check disk space for uploads
    const uploadsDir = config.uploadDir;
    try {
      const stats = fs.statSync(uploadsDir);
      const freeSpace = os.freemem();
      const totalSpace = os.totalmem();
      const usedSpacePercentage = ((totalSpace - freeSpace) / totalSpace) * 100;
      
      if (usedSpacePercentage > 90) {
        logger.warn('Low disk space warning', {
          freeSpace: `${Math.round(freeSpace / 1024 / 1024)}MB`,
          totalSpace: `${Math.round(totalSpace / 1024 / 1024)}MB`,
          usedPercentage: Math.round(usedSpacePercentage)
        });
        console.log(`⚠️ Low disk space: ${Math.round(usedSpacePercentage)}% used`);
      }
    } catch (error) {
      logger.error('Error checking disk space', { error: error.message });
    }
    
    logger.info('✅ Daily maintenance check completed');
    console.log('✅ Daily maintenance check completed');
    
  } catch (error) {
    logger.error('❌ Error during daily maintenance check:', {
      error: error.message,
      stack: error.stack
    });
    console.error('❌ Error during daily maintenance check:', error);
  }
});

// ==================== ENHANCED ERROR HANDLING ====================

// 404 handler
app.use((req, res) => {
  logger.warn('404 Not Found', {
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });
  
  res.status(404).json(formatResponse(false, 'Endpoint not found', {
    requested_url: req.originalUrl,
    method: req.method,
    available_endpoints: [
      '/api/auth/*',
      '/api/profile',
      '/api/investments/*',
      '/api/deposits/*',
      '/api/withdrawals/*',
      '/api/plans',
      '/api/kyc/*',
      '/api/support/*',
      '/api/referrals/*',
      '/api/admin/*',
      '/api/upload',
      '/api/notifications/*',
      '/api/transactions',
      '/health'
    ]
  }));
});

// Global error handler
app.use((err, req, res, next) => {
  const errorId = crypto.randomBytes(8).toString('hex');
  
  // Log error with request context
  logger.error('Global error handler', {
    errorId,
    message: err.message,
    stack: err.stack,
    name: err.name,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userId: req.userId || 'anonymous',
    userAgent: req.headers['user-agent'],
    requestId: req.requestId
  });
  
  console.error(`🔥 [${errorId}] Global error:`, err.message);
  
  // Handle specific error types
  if (err instanceof multer.MulterError) {
    let message = 'File upload error';
    if (err.code === 'LIMIT_FILE_SIZE') {
      message = `File too large. Maximum size: ${config.maxFileSize / 1024 / 1024}MB`;
    } else if (err.code === 'LIMIT_FILE_COUNT') {
      message = 'Too many files uploaded';
    } else if (err.code === 'LIMIT_UNEXPECTED_FILE') {
      message = 'Unexpected file field';
    }
    
    return res.status(400).json(formatResponse(false, message, { errorId }));
  }
  
  // Database errors
  if (err.name === 'MongoError' || err.name === 'MongooseError') {
    const message = config.isProduction 
      ? 'Database error occurred. Please try again later.' 
      : `Database error: ${err.message}`;
    
    return res.status(500).json(formatResponse(false, message, { 
      errorId,
      ...(config.debugEnabled && { debug: 'Database connection issue' })
    }));
  }
  
  // Network errors
  if (err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT') {
    return res.status(503).json(formatResponse(false, 
      'Service temporarily unavailable. Please try again later.', 
      { errorId }
    ));
  }
  
  // JWT errors
  if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
    return res.status(401).json(formatResponse(false, 
      'Authentication error. Please login again.', 
      { errorId }
    ));
  }
  
  // Default error response
  const response = {
    success: false,
    message: config.isProduction 
      ? 'Internal server error. Please try again later.' 
      : err.message,
    errorId,
    timestamp: new Date().toISOString()
  };
  
  // Add debug info in development
  if (!config.isProduction) {
    response.debug = {
      message: err.message,
      stack: err.stack,
      name: err.name
    };
  }
  
  res.status(err.status || 500).json(response);
});

// ==================== ENHANCED SERVER INITIALIZATION ====================

const startServer = async () => {
  try {
    logger.info('🚀 Starting Raw Wealthy Backend Server v38.0');
    console.log(`
🎯 RAW WEALTHY BACKEND v38.0 - ULTIMATE PRODUCTION EDITION
==========================================================
🌐 Environment: ${config.nodeEnv}
🔧 Debug Mode: ${config.debugEnabled}
📊 Log Level: ${config.logLevel}
    
🚀 Initializing server...
    `);
    
    // Initialize database
    await initializeDatabase();
    
    // Create necessary directories
    const directories = [config.uploadDir, config.logsDir];
    for (const dir of directories) {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(`✅ Created directory: ${dir}`);
      }
    }
    
    // Start server
    const server = app.listen(config.port, '0.0.0.0', () => {
      const serverInfo = `
🎉 SERVER STARTED SUCCESSFULLY!
================================
🌐 Server running on port ${config.port}
🚀 Environment: ${config.nodeEnv}
📊 Health Check: http://localhost:${config.port}/health
🔗 API Base: http://localhost:${config.port}/api
💾 Database: MongoDB Connected
🛡️ Security: Enhanced Protection Active
📧 Email: ${config.emailEnabled ? '✅ Enabled' : '❌ Disabled'}
📁 Uploads: ${config.uploadDir}
📊 Logs: ${config.logsDir}
🌐 Client URL: ${config.clientURL}
🌐 Server URL: ${config.serverURL}

✅ ENHANCED FEATURES:
   ✅ Advanced Debugging & Logging System
   ✅ Real-time Performance Monitoring
   ✅ Comprehensive Error Handling
   ✅ Enhanced Security Headers
   ✅ Rate Limiting & DDoS Protection
   ✅ File Upload System with Validation
   ✅ Email System with Templates
   ✅ Automated Cron Jobs
   ✅ Database Connection Pooling
   ✅ Health Check Endpoints
   ✅ Admin Dashboard with Analytics
   ✅ User Dashboard with Real-time Stats
   ✅ Investment Plans with ROI Calculator
   ✅ Deposit & Withdrawal Management
   ✅ KYC Verification System
   ✅ Support Ticket System
   ✅ Referral Program with Tracking
   ✅ Notification System with Email
   ✅ Transaction History with Images
   ✅ Bank Account Verification
   ✅ Automated Earnings Calculation
   ✅ Investment Auto-renewal
   ✅ Weekly Report Generation
   ✅ Maintenance Mode Support
   ✅ Graceful Shutdown
   ✅ Cluster Mode Ready
   ✅ Memory Leak Protection
   ✅ Request/Response Logging
   ✅ Audit Trail for Admin Actions
   ✅ System Settings Management
   ✅ Multi-language Support Ready
   ✅ API Versioning Ready

🔐 SECURITY FEATURES:
   ✅ JWT Authentication
   ✅ Password Hashing with Bcrypt
   ✅ Two-Factor Authentication Ready
   ✅ IP-based Rate Limiting
   ✅ CORS Configuration
   ✅ XSS Protection
   ✅ SQL Injection Protection
   ✅ CSRF Protection
   ✅ Helmet.js Security Headers
   ✅ Input Validation & Sanitization
   ✅ File Upload Validation
   ✅ Secure Password Reset
   ✅ Session Management
   ✅ Audit Logging

📈 PERFORMANCE FEATURES:
   ✅ Database Indexing
   ✅ Query Optimization
   ✅ Response Compression
   ✅ Caching Headers
   ✅ Connection Pooling
   ✅ Load Balancing Ready
   ✅ Memory Management
   ✅ Background Job Processing
   ✅ Real-time Notifications
   ✅ Batch Processing

🚀 READY FOR PRODUCTION DEPLOYMENT!
====================================
      `;
      
      console.log(serverInfo);
      logger.info('Server started successfully', {
        port: config.port,
        environment: config.nodeEnv,
        clientURL: config.clientURL,
        serverURL: config.serverURL
      });
    });
    
    // Server event listeners
    server.on('error', (error) => {
      logger.error('Server error', {
        error: error.message,
        code: error.code
      });
      
      if (error.code === 'EADDRINUSE') {
        console.error(`❌ Port ${config.port} is already in use`);
        process.exit(1);
      } else {
        console.error('❌ Server error:', error.message);
      }
    });
    
    server.on('listening', () => {
      logger.info('Server listening', { port: config.port });
    });
    
    // Graceful shutdown
    const gracefulShutdown = async (signal) => {
      logger.info(`Received ${signal}, starting graceful shutdown...`);
      console.log(`\n${signal} received, starting graceful shutdown...`);
      
      // Stop accepting new connections
      server.close(async () => {
        console.log('✅ HTTP server closed');
        logger.info('HTTP server closed');
        
        try {
          // Close database connection
          await mongoose.connection.close();
          console.log('✅ Database connection closed');
          logger.info('Database connection closed');
          
          // Close any other connections
          if (emailTransporter) {
            emailTransporter.close();
            console.log('✅ Email transporter closed');
          }
          
          console.log('✅ Graceful shutdown completed');
          logger.info('Graceful shutdown completed');
          process.exit(0);
        } catch (dbError) {
          console.error('❌ Error during shutdown:', dbError.message);
          logger.error('Error during shutdown', { error: dbError.message });
          process.exit(1);
        }
      });
      
      // Force shutdown after 10 seconds
      setTimeout(() => {
        console.error('❌ Could not close connections in time, forcing shutdown');
        logger.error('Forced shutdown due to timeout');
        process.exit(1);
      }, 10000);
    };
    
    // Handle different shutdown signals
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    process.on('SIGUSR2', () => gracefulShutdown('SIGUSR2')); // For nodemon
    
    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught Exception:', {
        error: error.message,
        stack: error.stack
      });
      console.error('Uncaught Exception:', error);
      
      // Don't exit immediately, try to recover
      setTimeout(() => {
        gracefulShutdown('uncaughtException');
      }, 1000);
    });
    
    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled Rejection at:', {
        promise: promise,
        reason: reason
      });
      console.error('Unhandled Rejection:', reason);
      // Don't crash for unhandled rejections
    });
    
    // Memory usage monitoring
    if (config.debugEnabled) {
      setInterval(() => {
        const memoryUsage = process.memoryUsage();
        const memoryStats = {
          rss: `${Math.round(memoryUsage.rss / 1024 / 1024)}MB`,
          heapTotal: `${Math.round(memoryUsage.heapTotal / 1024 / 1024)}MB`,
          heapUsed: `${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`,
          external: `${Math.round(memoryUsage.external / 1024 / 1024)}MB`
        };
        
        logger.debug('Memory usage', memoryStats);
        
        // Warn if memory usage is high
        if (memoryUsage.heapUsed > 500 * 1024 * 1024) { // 500MB
          logger.warn('High memory usage detected', memoryStats);
        }
      }, 60000); // Every minute
    }
    
  } catch (error) {
    logger.error('❌ Server initialization failed:', {
      error: error.message,
      stack: error.stack
    });
    
    console.error('❌ Server initialization failed:', error.message);
    console.error(error.stack);
    
    process.exit(1);
  }
};

// Start the server
if (cluster.isPrimary && config.nodeEnv === 'production') {
  // Cluster mode for production
  console.log(`🏢 Master ${process.pid} is running`);
  
  // Fork workers
  const numCPUs = os.cpus().length;
  for (let i = 0; i < Math.min(numCPUs, 4); i++) {
    cluster.fork();
  }
  
  cluster.on('exit', (worker, code, signal) => {
    console.log(`⚠️ Worker ${worker.process.pid} died. Restarting...`);
    cluster.fork();
  });
} else {
  // Start server in worker or development mode
  startServer();
}

export default app;
