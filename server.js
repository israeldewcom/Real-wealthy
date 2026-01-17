// server.js - RAW WEALTHY BACKEND v38.0 - ENHANCED DEBUGGING + ADVANCED MONITORING + PRODUCTION READY
// COMPLETE ENHANCEMENT: Advanced Debugging System + Real-time Monitoring + Performance Optimization + Enhanced Security
// FULLY INTEGRATED DEBUGGING WITH AUTOMATIC PROBLEM DETECTION AND FIXING

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
import os from 'os';

// ES Modules equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ==================== ENHANCED DEBUGGING SYSTEM ====================
const debug = {
  enabled: true,
  level: process.env.DEBUG_LEVEL || 'detailed',
  logs: [],
  
  log: function(level, message, data = null) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level,
      message,
      data,
      pid: process.pid,
      memory: process.memoryUsage().rss / 1024 / 1024 // MB
    };
    
    this.logs.push(logEntry);
    
    // Keep only last 1000 logs to prevent memory leak
    if (this.logs.length > 1000) {
      this.logs = this.logs.slice(-500);
    }
    
    // Color-coded console output
    const colors = {
      info: '\x1b[36m',  // Cyan
      warn: '\x1b[33m',  // Yellow
      error: '\x1b[31m', // Red
      success: '\x1b[32m', // Green
      debug: '\x1b[35m', // Magenta
      reset: '\x1b[0m'
    };
    
    const color = colors[level] || colors.info;
    console.log(`${color}[${timestamp}] [${level.toUpperCase()}] ${message}${colors.reset}`);
    
    if (data && this.level === 'detailed') {
      console.log(`${color}Data:`, data, `${colors.reset}`);
    }
  },
  
  info: function(message, data) {
    this.log('info', message, data);
  },
  
  warn: function(message, data) {
    this.log('warn', message, data);
  },
  
  error: function(message, data) {
    this.log('error', message, data);
  },
  
  success: function(message, data) {
    this.log('success', message, data);
  },
  
  debug: function(message, data) {
    if (this.level === 'detailed') {
      this.log('debug', message, data);
    }
  },
  
  // Performance monitoring
  performance: {
    timers: new Map(),
    start: function(name) {
      this.timers.set(name, {
        start: Date.now(),
        memory: process.memoryUsage()
      });
    },
    end: function(name) {
      const timer = this.timers.get(name);
      if (timer) {
        const duration = Date.now() - timer.start;
        const memoryDiff = process.memoryUsage().rss - timer.memory.rss;
        debug.info(`Performance: ${name}`, {
          duration: `${duration}ms`,
          memoryChange: `${(memoryDiff / 1024 / 1024).toFixed(2)}MB`,
          timestamp: new Date().toISOString()
        });
        this.timers.delete(name);
        return duration;
      }
      return 0;
    }
  },
  
  // System health monitoring
  health: {
    checks: [],
    lastCheck: null,
    
    checkSystem: function() {
      debug.performance.start('system_health_check');
      
      const health = {
        timestamp: new Date().toISOString(),
        system: {
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          cpu: os.loadavg(),
          platform: os.platform(),
          arch: os.arch(),
          freemem: os.freemem(),
          totalmem: os.totalmem()
        },
        process: {
          pid: process.pid,
          version: process.version,
          versions: process.versions,
          env: process.env.NODE_ENV
        },
        database: {
          state: mongoose.connection.readyState,
          host: mongoose.connection.host,
          name: mongoose.connection.name
        }
      };
      
      this.checks.push(health);
      if (this.checks.length > 100) this.checks.shift();
      
      this.lastCheck = health;
      debug.performance.end('system_health_check');
      
      return health;
    }
  },
  
  // Automatic problem detection and fixing
  autoFix: {
    database: {
      async checkConnection() {
        try {
          await mongoose.connection.db.admin().ping();
          debug.success('Database connection check passed');
          return true;
        } catch (error) {
          debug.error('Database connection check failed', error.message);
          
          // Attempt auto-fix
          try {
            debug.warn('Attempting database auto-reconnect...');
            await mongoose.disconnect();
            await mongoose.connect(config.mongoURI, {
              serverSelectionTimeoutMS: 5000,
              socketTimeoutMS: 45000,
            });
            debug.success('Database auto-reconnect successful');
            return true;
          } catch (reconnectError) {
            debug.error('Database auto-reconnect failed', reconnectError.message);
            return false;
          }
        }
      }
    }
  }
};

// Enhanced environment configuration with debugging
debug.performance.start('environment_config');
dotenv.config({ 
  path: path.join(__dirname, '.env.production'),
  debug: process.env.DEBUG === 'true'
});

// ==================== ENVIRONMENT VALIDATION ====================
const requiredEnvVars = [
  'MONGODB_URI',
  'JWT_SECRET',
  'NODE_ENV',
  'CLIENT_URL'
];

debug.info('🔍 Environment Configuration Check:');

const missingEnvVars = requiredEnvVars.filter(envVar => {
  if (!process.env[envVar]) {
    debug.error(`❌ Missing: ${envVar}`);
    return true;
  }
  debug.success(`✅ ${envVar}: ${envVar === 'JWT_SECRET' ? '***' : process.env[envVar]}`);
  return false;
});

if (missingEnvVars.length > 0) {
  debug.error('🚨 CRITICAL: Missing required environment variables');
  debug.warn('🔄 Attempting to load from alternative sources...');
  
  // Try to load from alternative sources
  if (process.env.DATABASE_URL) {
    process.env.MONGODB_URI = process.env.DATABASE_URL;
    debug.success('✅ Loaded MONGODB_URI from DATABASE_URL');
  }
  
  if (!process.env.JWT_SECRET) {
    process.env.JWT_SECRET = crypto.randomBytes(64).toString('hex');
    debug.success('✅ Generated JWT_SECRET automatically');
  }
  
  if (!process.env.CLIENT_URL) {
    process.env.CLIENT_URL = 'https://us-raw-wealthy.vercel.app';
    debug.success('✅ Set default CLIENT_URL');
  }
}

// Add SERVER_URL for absolute image paths
if (!process.env.SERVER_URL) {
  process.env.SERVER_URL = process.env.CLIENT_URL || `http://localhost:${process.env.PORT || 10000}`;
  debug.success(`✅ Set SERVER_URL: ${process.env.SERVER_URL}`);
}

// ==================== DYNAMIC CONFIGURATION WITH DEBUGGING ====================
const config = {
  // Server
  port: process.env.PORT || 10000,
  nodeEnv: process.env.NODE_ENV || 'production',
  serverURL: process.env.SERVER_URL,
  
  // Database
  mongoURI: process.env.MONGODB_URI || process.env.DATABASE_URL,
  
  // Security
  jwtSecret: process.env.JWT_SECRET,
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '30d',
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 12,
  
  // Client
  clientURL: process.env.CLIENT_URL,
  allowedOrigins: [],
  
  // Email
  emailEnabled: process.env.EMAIL_HOST && process.env.EMAIL_USER && process.env.EMAIL_PASSWORD,
  emailConfig: {
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT) || 587,
    secure: parseInt(process.env.EMAIL_PORT) === 465,
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
    from: process.env.EMAIL_FROM || `"Raw Wealthy" <${process.env.EMAIL_USER}>`
  },
  
  // Business Logic
  minInvestment: parseInt(process.env.MIN_INVESTMENT) || 3500,
  minDeposit: parseInt(process.env.MIN_DEPOSIT) || 3500,
  minWithdrawal: parseInt(process.env.MIN_WITHDRAWAL) || 3500,
  platformFeePercent: parseFloat(process.env.PLATFORM_FEE_PERCENT) || 10,
  referralCommissionPercent: parseFloat(process.env.REFERRAL_COMMISSION_PERCENT) || 10,
  welcomeBonus: parseInt(process.env.WELCOME_BONUS) || 100,
  
  // Investment Plans
  investmentPlans: [],
  
  // Storage
  uploadDir: path.join(__dirname, 'uploads'),
  maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024,
  allowedMimeTypes: {
    'image/jpeg': 'jpg',
    'image/jpg': 'jpg',
    'image/png': 'png',
    'image/gif': 'gif',
    'image/webp': 'webp',
    'application/pdf': 'pdf',
    'image/svg+xml': 'svg'
  },
  
  // Debugging
  debugMode: process.env.DEBUG === 'true',
  debugLevel: process.env.DEBUG_LEVEL || 'info',
  
  // Performance
  requestTimeout: parseInt(process.env.REQUEST_TIMEOUT) || 30000,
  maxRequestBodySize: process.env.MAX_REQUEST_BODY_SIZE || '50mb'
};

// Build allowed origins dynamically
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

debug.info('⚙️ Dynamic Configuration Loaded:', {
  port: config.port,
  environment: config.nodeEnv,
  clientURL: config.clientURL,
  serverURL: config.serverURL,
  emailEnabled: config.emailEnabled,
  allowedOrigins: config.allowedOrigins.length,
  debugMode: config.debugMode
});

debug.performance.end('environment_config');

// ==================== ENHANCED EXPRESS SETUP WITH DEBUGGING ====================
const app = express();

// Enhanced Security Headers
debug.performance.start('security_setup');
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:", "https:", "http:", config.serverURL, config.clientURL],
      connectSrc: ["'self'", "ws:", "wss:", config.clientURL, config.serverURL]
    }
  }
}));

// Security middleware
app.use(xss());
app.use(hpp());
app.use(mongoSanitize());
app.use(compression());

// Enhanced logging with request tracking
const requestTracker = (req, res, next) => {
  req.requestId = crypto.randomBytes(8).toString('hex');
  req.startTime = Date.now();
  
  debug.debug(`Request started: ${req.method} ${req.originalUrl}`, {
    requestId: req.requestId,
    ip: req.ip,
    userAgent: req.headers['user-agent']
  });
  
  // Log response when finished
  res.on('finish', () => {
    const duration = Date.now() - req.startTime;
    debug.debug(`Request completed: ${req.method} ${req.originalUrl}`, {
      requestId: req.requestId,
      status: res.statusCode,
      duration: `${duration}ms`,
      memory: `${(process.memoryUsage().rss / 1024 / 1024).toFixed(2)}MB`
    });
  });
  
  next();
};

app.use(requestTracker);

// Enhanced morgan logging
if (config.nodeEnv === 'production') {
  app.use(morgan('combined'));
} else {
  app.use(morgan(':method :url :status :response-time ms - :res[content-length]'));
}

debug.performance.end('security_setup');

// ==================== ENHANCED CORS CONFIGURATION ====================
debug.performance.start('cors_setup');
const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    
    if (config.allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      const isPreviewDeployment = origin.includes('vercel.app') || origin.includes('onrender.com');
      if (isPreviewDeployment) {
        debug.info(`🌐 Allowed preview deployment: ${origin}`);
        callback(null, true);
      } else {
        debug.warn(`🚫 Blocked by CORS: ${origin}`);
        callback(new Error('Not allowed by CORS'));
      }
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'x-api-key', 'x-user-id', 'X-Request-ID']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
debug.performance.end('cors_setup');

// ==================== ENHANCED BODY PARSING ====================
app.use(express.json({ 
  limit: config.maxRequestBodySize,
  verify: (req, res, buf) => {
    req.rawBody = buf;
    req.bodySize = buf.length;
  }
}));

app.use(express.urlencoded({ 
  extended: true, 
  limit: config.maxRequestBodySize,
  parameterLimit: 100000
}));

// ==================== ENHANCED RATE LIMITING WITH DEBUGGING ====================
debug.performance.start('rate_limiting_setup');

const createRateLimiter = (windowMs, max, message, name) => rateLimit({
  windowMs,
  max,
  message: { success: false, message },
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip + req.headers['user-agent'];
  },
  handler: (req, res) => {
    debug.warn(`Rate limit exceeded: ${name}`, {
      ip: req.ip,
      endpoint: req.originalUrl,
      userAgent: req.headers['user-agent']
    });
    res.status(429).json({ success: false, message });
  }
});

const rateLimiters = {
  createAccount: createRateLimiter(60 * 60 * 1000, 10, 'Too many accounts created from this IP, please try again after an hour', 'account_creation'),
  auth: createRateLimiter(15 * 60 * 1000, 20, 'Too many authentication attempts from this IP, please try again after 15 minutes', 'authentication'),
  api: createRateLimiter(15 * 60 * 1000, 1000, 'Too many requests from this IP, please try again later', 'api_requests'),
  financial: createRateLimiter(15 * 60 * 1000, 50, 'Too many financial operations from this IP, please try again later', 'financial_operations'),
  passwordReset: createRateLimiter(15 * 60 * 1000, 5, 'Too many password reset attempts, please try again later', 'password_reset'),
  admin: createRateLimiter(15 * 60 * 1000, 500, 'Too many admin requests from this IP', 'admin_requests')
};

// Apply rate limiting
app.use('/api/auth/register', rateLimiters.createAccount);
app.use('/api/auth/login', rateLimiters.auth);
app.use('/api/auth/forgot-password', rateLimiters.passwordReset);
app.use('/api/auth/reset-password', rateLimiters.passwordReset);
app.use('/api/investments', rateLimiters.financial);
app.use('/api/deposits', rateLimiters.financial);
app.use('/api/withdrawals', rateLimiters.financial);
app.use('/api/admin', rateLimiters.admin);
app.use('/api/', rateLimiters.api);

debug.performance.end('rate_limiting_setup');

// ==================== ENHANCED FILE UPLOAD WITH DEBUGGING ====================
debug.performance.start('file_upload_setup');

const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  if (!config.allowedMimeTypes[file.mimetype]) {
    debug.warn(`Invalid file type attempted: ${file.mimetype}`, {
      originalname: file.originalname,
      size: file.size
    });
    return cb(new Error(`Invalid file type: ${file.mimetype}`), false);
  }
  
  if (file.size > config.maxFileSize) {
    debug.warn(`File size exceeded: ${file.size} bytes`, {
      originalname: file.originalname,
      limit: config.maxFileSize
    });
    return cb(new Error(`File size exceeds ${config.maxFileSize / 1024 / 1024}MB limit`), false);
  }
  
  debug.debug(`File accepted: ${file.originalname}`, {
    mimetype: file.mimetype,
    size: file.size
  });
  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: { 
    fileSize: config.maxFileSize,
    files: 10
  }
});

// Enhanced file upload handler
const handleFileUpload = async (file, folder = 'general', userId = null) => {
  debug.performance.start('file_upload');
  
  if (!file) {
    debug.warn('No file provided for upload');
    return null;
  }
  
  try {
    if (!config.allowedMimeTypes[file.mimetype]) {
      throw new Error('Invalid file type');
    }
    
    const uploadsDir = path.join(config.uploadDir, folder);
    
    // Create directory if it doesn't exist
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
      debug.debug(`Created upload directory: ${uploadsDir}`);
    }
    
    // Generate secure filename
    const timestamp = Date.now();
    const randomStr = crypto.randomBytes(8).toString('hex');
    const userIdPrefix = userId ? `${userId}_` : '';
    const fileExtension = config.allowedMimeTypes[file.mimetype] || file.originalname.split('.').pop();
    const filename = `${userIdPrefix}${timestamp}_${randomStr}.${fileExtension}`;
    const filepath = path.join(uploadsDir, filename);
    
    // Write file
    await fs.promises.writeFile(filepath, file.buffer);
    
    debug.success(`File uploaded successfully: ${filename}`, {
      originalName: file.originalname,
      size: file.size,
      folder,
      userId
    });
    
    const result = {
      url: `${config.serverURL}/uploads/${folder}/${filename}`,
      relativeUrl: `/uploads/${folder}/${filename}`,
      filename,
      originalName: file.originalname,
      size: file.size,
      mimeType: file.mimetype,
      uploadPath: filepath,
      uploadedAt: new Date()
    };
    
    debug.performance.end('file_upload');
    return result;
    
  } catch (error) {
    debug.error('File upload error:', error);
    debug.performance.end('file_upload');
    throw new Error(`File upload failed: ${error.message}`);
  }
};

// Serve static files with caching
if (!fs.existsSync(config.uploadDir)) {
  fs.mkdirSync(config.uploadDir, { recursive: true });
  debug.info(`Created uploads directory: ${config.uploadDir}`);
}

app.use('/uploads', express.static(config.uploadDir, {
  maxAge: '7d',
  setHeaders: (res, path) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Cache-Control', 'public, max-age=604800');
    res.set('Access-Control-Allow-Origin', '*');
  }
}));

debug.performance.end('file_upload_setup');

// ==================== ENHANCED EMAIL CONFIGURATION ====================
debug.performance.start('email_setup');

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
      }
    });
    
    // Verify connection
    emailTransporter.verify((error, success) => {
      if (error) {
        debug.error('Email configuration error:', error.message);
      } else {
        debug.success('✅ Email server is ready to send messages');
      }
    });
  } catch (error) {
    debug.error('Email setup failed:', error.message);
  }
}

// Enhanced email utility function
const sendEmail = async (to, subject, html, text = '') => {
  debug.performance.start('send_email');
  
  try {
    if (!emailTransporter) {
      debug.warn(`Email would be sent (simulated): To: ${to}, Subject: ${subject}`);
      debug.performance.end('send_email');
      return { simulated: true, success: true };
    }
    
    const mailOptions = {
      from: config.emailConfig.from,
      to,
      subject,
      text: text || html.replace(/<[^>]*>/g, ''),
      html
    };
    
    const info = await emailTransporter.sendMail(mailOptions);
    debug.success(`Email sent to ${to}`, {
      messageId: info.messageId,
      subject
    });
    
    debug.performance.end('send_email');
    return { success: true, messageId: info.messageId };
    
  } catch (error) {
    debug.error('Email sending error:', error.message);
    debug.performance.end('send_email');
    return { success: false, error: error.message };
  }
};

debug.performance.end('email_setup');

// ==================== DATABASE MODELS - ENHANCED WITH DEBUGGING ====================
debug.performance.start('database_models_setup');

// Enhanced User Model
const userSchema = new mongoose.Schema({
  full_name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  phone: { type: String, required: true },
  password: { type: String, required: true, select: false },
  role: { type: String, enum: ['user', 'admin', 'super_admin'], default: 'user' },
  balance: { type: Number, default: 0, min: 0 },
  total_earnings: { type: Number, default: 0, min: 0 },
  referral_earnings: { type: Number, default: 0, min: 0 },
  risk_tolerance: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  investment_strategy: { type: String, enum: ['conservative', 'balanced', 'aggressive'], default: 'balanced' },
  country: { type: String, default: 'ng' },
  currency: { type: String, enum: ['NGN', 'USD', 'EUR', 'GBP'], default: 'NGN' },
  referral_code: { type: String, unique: true, sparse: true },
  referred_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  referral_count: { type: Number, default: 0 },
  kyc_verified: { type: Boolean, default: false },
  kyc_status: { type: String, enum: ['pending', 'verified', 'rejected', 'not_submitted'], default: 'not_submitted' },
  kyc_submitted_at: Date,
  kyc_verified_at: Date,
  two_factor_enabled: { type: Boolean, default: false },
  two_factor_secret: { type: String, select: false },
  is_active: { type: Boolean, default: true },
  is_verified: { type: Boolean, default: false },
  verification_token: String,
  verification_expires: Date,
  password_reset_token: String,
  password_reset_expires: Date,
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String,
    bank_code: String,
    verified: { type: Boolean, default: false },
    verified_at: Date,
    last_updated: Date
  },
  wallet_address: String,
  paypal_email: String,
  last_login: Date,
  last_active: Date,
  login_attempts: { type: Number, default: 0 },
  lock_until: Date,
  profile_image: String,
  notifications_enabled: { type: Boolean, default: true },
  email_notifications: { type: Boolean, default: true },
  sms_notifications: { type: Boolean, default: false },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  total_deposits: { type: Number, default: 0 },
  total_withdrawals: { type: Number, default: 0 },
  total_investments: { type: Number, default: 0 },
  last_deposit_date: Date,
  last_withdrawal_date: Date,
  last_investment_date: Date
}, { 
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.two_factor_secret;
      delete ret.verification_token;
      delete ret.password_reset_token;
      delete ret.login_attempts;
      delete ret.lock_until;
      return ret;
    }
  }
});

// Indexes
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ referral_code: 1 }, { unique: true, sparse: true });
userSchema.index({ is_active: 1, role: 1, kyc_status: 1 });
userSchema.index({ 'bank_details.last_updated': -1 });
userSchema.index({ createdAt: -1 });

// Virtuals
userSchema.virtual('portfolio_value').get(function() {
  return this.balance + this.total_earnings + this.referral_earnings;
});

// Pre-save hooks with debugging
userSchema.pre('save', async function(next) {
  debug.debug(`User pre-save hook triggered for: ${this.email}`);
  
  if (this.isModified('password')) {
    debug.debug('Hashing password');
    this.password = await bcrypt.hash(this.password, config.bcryptRounds);
  }
  
  if (!this.referral_code) {
    this.referral_code = crypto.randomBytes(6).toString('hex').toUpperCase();
    debug.debug(`Generated referral code: ${this.referral_code}`);
  }
  
  if (this.isModified('email') && !this.is_verified) {
    this.verification_token = crypto.randomBytes(32).toString('hex');
    this.verification_expires = new Date(Date.now() + 24 * 60 * 60 * 1000);
    debug.debug('Generated verification token');
  }
  
  if (this.isModified('bank_details')) {
    this.bank_details.last_updated = new Date();
    debug.debug('Updated bank details timestamp');
  }
  
  next();
});

// Methods
userSchema.methods.comparePassword = async function(candidatePassword) {
  debug.debug(`Comparing password for user: ${this.email}`);
  const result = await bcrypt.compare(candidatePassword, this.password);
  debug.debug(`Password comparison result: ${result}`);
  return result;
};

userSchema.methods.generateAuthToken = function() {
  debug.debug(`Generating auth token for user: ${this.email}`);
  return jwt.sign(
    { 
      id: this._id,
      email: this.email,
      role: this.role,
      kyc_verified: this.kyc_verified
    },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn }
  );
};

userSchema.methods.generatePasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.password_reset_token = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');
  this.password_reset_expires = new Date(Date.now() + 10 * 60 * 1000);
  debug.debug(`Generated password reset token for user: ${this.email}`);
  return resetToken;
};

const User = mongoose.model('User', userSchema);

// Investment Plan Model
const investmentPlanSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  description: { type: String, required: true },
  min_amount: { type: Number, required: true, min: config.minInvestment },
  max_amount: { type: Number, min: config.minInvestment },
  daily_interest: { type: Number, required: true, min: 0.1, max: 100 },
  total_interest: { type: Number, required: true, min: 1, max: 1000 },
  duration: { type: Number, required: true, min: 1 },
  risk_level: { type: String, enum: ['low', 'medium', 'high'], required: true },
  raw_material: { type: String, required: true },
  category: { type: String, enum: ['agriculture', 'mining', 'energy', 'metals', 'crypto', 'real_estate', 'precious_stones'], default: 'agriculture' },
  is_active: { type: Boolean, default: true },
  is_popular: { type: Boolean, default: false },
  image_url: String,
  color: String,
  icon: String,
  features: [String],
  investment_count: { type: Number, default: 0 },
  total_invested: { type: Number, default: 0 },
  total_earned: { type: Number, default: 0 },
  rating: { type: Number, default: 0, min: 0, max: 5 },
  tags: [String],
  display_order: { type: Number, default: 0 },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { 
  timestamps: true 
});

investmentPlanSchema.index({ is_active: 1, is_popular: 1, category: 1 });
investmentPlanSchema.index({ min_amount: 1 });

const InvestmentPlan = mongoose.model('InvestmentPlan', investmentPlanSchema);

// Investment Model
const investmentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  plan: { type: mongoose.Schema.Types.ObjectId, ref: 'InvestmentPlan', required: true },
  amount: { type: Number, required: true, min: config.minInvestment },
  status: { type: String, enum: ['pending', 'active', 'completed', 'cancelled', 'failed'], default: 'pending' },
  start_date: { type: Date, default: Date.now },
  end_date: { type: Date, required: true },
  approved_at: Date,
  expected_earnings: { type: Number, required: true },
  earned_so_far: { type: Number, default: 0 },
  daily_earnings: { type: Number, default: 0 },
  last_earning_date: Date,
  payment_proof_url: String,
  payment_verified: { type: Boolean, default: false },
  auto_renew: { type: Boolean, default: false },
  auto_renewed: { type: Boolean, default: false },
  approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  transaction_id: String,
  remarks: String,
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  admin_notes: String,
  proof_verified_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  proof_verified_at: Date,
  investment_image_url: String
}, { 
  timestamps: true 
});

investmentSchema.index({ user: 1, status: 1 });
investmentSchema.index({ end_date: 1 });
investmentSchema.index({ createdAt: -1 });

const Investment = mongoose.model('Investment', investmentSchema);

// Deposit Model
const depositSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true, min: config.minDeposit },
  payment_method: { type: String, enum: ['bank_transfer', 'crypto', 'paypal', 'card', 'flutterwave', 'paystack'], required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'cancelled'], default: 'pending' },
  payment_proof_url: String,
  transaction_hash: String,
  reference: { type: String, unique: true, sparse: true },
  admin_notes: String,
  approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approved_at: Date,
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String
  },
  crypto_details: {
    wallet_address: String,
    coin_type: String
  },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  deposit_image_url: String,
  proof_verified_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  proof_verified_at: Date
}, { 
  timestamps: true 
});

depositSchema.index({ user: 1, status: 1 });
depositSchema.index({ reference: 1 }, { unique: true, sparse: true });
depositSchema.index({ createdAt: -1 });

const Deposit = mongoose.model('Deposit', depositSchema);

// Withdrawal Model
const withdrawalSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true, min: config.minWithdrawal },
  payment_method: { type: String, enum: ['bank_transfer', 'crypto', 'paypal'], required: true },
  platform_fee: { type: Number, default: 0 },
  net_amount: { type: Number, required: true },
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String,
    bank_code: String,
    verified: { type: Boolean, default: false }
  },
  wallet_address: String,
  paypal_email: String,
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'paid', 'processing'], default: 'pending' },
  reference: { type: String, unique: true, sparse: true },
  admin_notes: String,
  approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approved_at: Date,
  paid_at: Date,
  transaction_id: String,
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  payment_proof_url: String,
  proof_verified_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  proof_verified_at: Date
}, { 
  timestamps: true 
});

withdrawalSchema.index({ user: 1, status: 1 });
withdrawalSchema.index({ reference: 1 }, { unique: true, sparse: true });
withdrawalSchema.index({ createdAt: -1 });

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// Transaction Model
const transactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'investment', 'earning', 'referral', 'bonus', 'fee', 'refund', 'transfer'], required: true },
  amount: { type: Number, required: true },
  description: { type: String, required: true },
  reference: { type: String, unique: true, sparse: true },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'completed' },
  balance_before: Number,
  balance_after: Number,
  related_investment: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment' },
  related_deposit: { type: mongoose.Schema.Types.ObjectId, ref: 'Deposit' },
  related_withdrawal: { type: mongoose.Schema.Types.ObjectId, ref: 'Withdrawal' },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  payment_proof_url: String,
  admin_notes: String
}, { 
  timestamps: true 
});

transactionSchema.index({ user: 1, createdAt: -1 });
transactionSchema.index({ type: 1, status: 1 });
transactionSchema.index({ reference: 1 });

const Transaction = mongoose.model('Transaction', transactionSchema);

// KYC Submission Model
const kycSubmissionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  id_type: { type: String, enum: ['national_id', 'passport', 'driver_license', 'voters_card'], required: true },
  id_number: { type: String, required: true },
  id_front_url: { type: String, required: true },
  id_back_url: String,
  selfie_with_id_url: { type: String, required: true },
  address_proof_url: String,
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'under_review'], default: 'pending' },
  reviewed_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reviewed_at: Date,
  rejection_reason: String,
  notes: String,
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { 
  timestamps: true 
});

kycSubmissionSchema.index({ status: 1, submitted_at: -1 });

const KYCSubmission = mongoose.model('KYCSubmission', kycSubmissionSchema);

// Support Ticket Model
const supportTicketSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  ticket_id: { type: String, unique: true, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  category: { type: String, enum: ['general', 'technical', 'investment', 'withdrawal', 'deposit', 'kyc', 'account', 'other'], default: 'general' },
  priority: { type: String, enum: ['low', 'medium', 'high', 'urgent'], default: 'medium' },
  status: { type: String, enum: ['open', 'in_progress', 'resolved', 'closed'], default: 'open' },
  attachments: [{
    filename: String,
    url: String,
    size: Number,
    mime_type: String
  }],
  assigned_to: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  last_reply_at: Date,
  reply_count: { type: Number, default: 0 },
  is_read_by_user: { type: Boolean, default: false },
  is_read_by_admin: { type: Boolean, default: false },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { 
  timestamps: true 
});

supportTicketSchema.index({ user: 1, status: 1, createdAt: -1 });

const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);

// Referral Model
const referralSchema = new mongoose.Schema({
  referrer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  referred_user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  referral_code: { type: String, required: true },
  status: { type: String, enum: ['pending', 'active', 'completed', 'expired'], default: 'pending' },
  earnings: { type: Number, default: 0 },
  commission_percentage: { type: Number, default: config.referralCommissionPercent },
  investment_amount: Number,
  earnings_paid: { type: Boolean, default: false },
  paid_at: Date,
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { 
  timestamps: true 
});

referralSchema.index({ referrer: 1, status: 1 });

const Referral = mongoose.model('Referral', referralSchema);

// Notification Model
const notificationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, enum: ['info', 'success', 'warning', 'error', 'promotional', 'investment', 'withdrawal', 'deposit', 'kyc', 'referral', 'system'], default: 'info' },
  is_read: { type: Boolean, default: false },
  is_email_sent: { type: Boolean, default: false },
  action_url: String,
  priority: { type: Number, default: 0, min: 0, max: 3 },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { 
  timestamps: true 
});

notificationSchema.index({ user: 1, is_read: 1, createdAt: -1 });

const Notification = mongoose.model('Notification', notificationSchema);

// Admin Audit Log Model
const adminAuditSchema = new mongoose.Schema({
  admin_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  target_type: { type: String, enum: ['user', 'investment', 'deposit', 'withdrawal', 'kyc', 'transaction', 'plan', 'system'] },
  target_id: mongoose.Schema.Types.ObjectId,
  details: mongoose.Schema.Types.Mixed,
  ip_address: String,
  user_agent: String,
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { 
  timestamps: true 
});

adminAuditSchema.index({ admin_id: 1, createdAt: -1 });

const AdminAudit = mongoose.model('AdminAudit', adminAuditSchema);

// Performance Metrics Model
const performanceMetricsSchema = new mongoose.Schema({
  endpoint: String,
  method: String,
  duration: Number,
  memory_usage: Number,
  status_code: Number,
  user_agent: String,
  ip_address: String,
  timestamp: { type: Date, default: Date.now }
});

performanceMetricsSchema.index({ endpoint: 1, timestamp: -1 });
const PerformanceMetrics = mongoose.model('PerformanceMetrics', performanceMetricsSchema);

debug.performance.end('database_models_setup');

// ==================== ENHANCED UTILITY FUNCTIONS ====================

const formatResponse = (success, message, data = null, pagination = null) => {
  const response = { 
    success, 
    message, 
    timestamp: new Date().toISOString() 
  };
  
  if (data !== null) response.data = data;
  if (pagination !== null) response.pagination = pagination;
  
  return response;
};

const handleError = (res, error, defaultMessage = 'An error occurred', requestId = null) => {
  debug.error(`Error: ${error.message}`, {
    requestId,
    errorName: error.name,
    errorCode: error.code,
    stack: config.debugMode ? error.stack : undefined
  });
  
  if (error.name === 'ValidationError') {
    const messages = Object.values(error.errors).map(val => val.message);
    return res.status(400).json(formatResponse(false, 'Validation Error', { 
      errors: messages,
      requestId: config.debugMode ? requestId : undefined
    }));
  }
  
  if (error.code === 11000) {
    const field = Object.keys(error.keyValue)[0];
    return res.status(400).json(formatResponse(false, `${field} already exists`, {
      requestId: config.debugMode ? requestId : undefined
    }));
  }
  
  if (error.name === 'JsonWebTokenError') {
    return res.status(401).json(formatResponse(false, 'Invalid token'));
  }
  
  if (error.name === 'TokenExpiredError') {
    return res.status(401).json(formatResponse(false, 'Token expired'));
  }
  
  const statusCode = error.statusCode || error.status || 500;
  const message = config.nodeEnv === 'production' && statusCode === 500 
    ? defaultMessage 
    : error.message;

  const response = formatResponse(false, message, {
    requestId: config.debugMode ? requestId : undefined,
    errorId: crypto.randomBytes(8).toString('hex')
  });

  return res.status(statusCode).json(response);
};

const generateReference = (prefix = 'REF') => {
  const timestamp = Date.now();
  const random = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `${prefix}${timestamp}${random}`;
};

// Enhanced createNotification
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
        sentAt: new Date()
      }
    });
    
    await notification.save();
    
    debug.success(`Notification created for user ${userId}`, {
      title,
      type
    });
    
    // Send email notification
    const user = await User.findById(userId);
    if (user && user.email_notifications && type !== 'system') {
      const emailResult = await sendEmail(
        user.email,
        `Raw Wealthy - ${title}`,
        message
      );
      
      if (emailResult.success) {
        notification.is_email_sent = true;
        await notification.save();
        debug.success(`Email notification sent to ${user.email}`);
      }
    }
    
    return notification;
  } catch (error) {
    debug.error('Error creating notification:', error);
    return null;
  }
};

// Enhanced createTransaction
const createTransaction = async (userId, type, amount, description, status = 'completed', metadata = {}, proofUrl = null) => {
  try {
    const user = await User.findById(userId);
    if (!user) {
      debug.warn(`User ${userId} not found for transaction creation`);
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
        processedAt: new Date()
      }
    });
    
    await transaction.save();
    
    debug.success(`Transaction created for user ${userId}`, {
      type,
      amount,
      reference: transaction.reference
    });
    
    return transaction;
  } catch (error) {
    debug.error('Error creating transaction:', error);
    return null;
  }
};

// Enhanced createAdminAudit
const createAdminAudit = async (adminId, action, targetType, targetId, details = {}, ip = '', userAgent = '') => {
  try {
    const audit = new AdminAudit({
      admin_id: adminId,
      action,
      target_type: targetType,
      target_id: targetId,
      details,
      ip_address: ip,
      user_agent: userAgent,
      metadata: {
        timestamp: new Date()
      }
    });
    
    await audit.save();
    
    debug.info(`Admin audit created for action: ${action}`, {
      adminId,
      targetType,
      targetId
    });
    
    return audit;
  } catch (error) {
    debug.error('Error creating admin audit:', error);
    return null;
  }
};

// Performance monitoring middleware
const performanceMonitor = async (req, res, next) => {
  const start = Date.now();
  const startMemory = process.memoryUsage().rss;
  
  // Capture response finish
  res.on('finish', async () => {
    const duration = Date.now() - start;
    const memoryUsage = process.memoryUsage().rss - startMemory;
    
    // Log performance metrics
    debug.debug(`Performance: ${req.method} ${req.originalUrl}`, {
      duration: `${duration}ms`,
      memoryChange: `${(memoryUsage / 1024 / 1024).toFixed(2)}MB`,
      status: res.statusCode
    });
    
    // Store in database (optional)
    if (config.debugMode) {
      try {
        await PerformanceMetrics.create({
          endpoint: req.originalUrl,
          method: req.method,
          duration,
          memory_usage: memoryUsage,
          status_code: res.statusCode,
          user_agent: req.headers['user-agent'],
          ip_address: req.ip,
          timestamp: new Date()
        });
      } catch (error) {
        debug.error('Error saving performance metrics:', error);
      }
    }
  });
  
  next();
};

app.use(performanceMonitor);

// ==================== ENHANCED AUTH MIDDLEWARE ====================

const auth = async (req, res, next) => {
  try {
    let token = req.header('Authorization');
    
    if (!token) {
      debug.warn('No token provided for authentication');
      return res.status(401).json(formatResponse(false, 'No token, authorization denied'));
    }
    
    if (token.startsWith('Bearer ')) {
      token = token.slice(7, token.length);
    }
    
    const decoded = jwt.verify(token, config.jwtSecret);
    
    const user = await User.findById(decoded.id);
    
    if (!user) {
      debug.warn(`User not found for token: ${decoded.id}`);
      return res.status(401).json(formatResponse(false, 'Token is not valid'));
    }
    
    if (!user.is_active) {
      debug.warn(`Inactive user attempted access: ${user.email}`);
      return res.status(401).json(formatResponse(false, 'Account is deactivated. Please contact support.'));
    }
    
    req.user = user;
    req.userId = user._id;
    
    debug.debug(`User authenticated: ${user.email}`, {
      role: user.role,
      userId: user._id
    });
    
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      debug.warn('Invalid JWT token provided');
      return res.status(401).json(formatResponse(false, 'Invalid token'));
    } else if (error.name === 'TokenExpiredError') {
      debug.warn('Expired JWT token provided');
      return res.status(401).json(formatResponse(false, 'Token expired'));
    }
    
    debug.error('Auth middleware error:', error);
    res.status(500).json(formatResponse(false, 'Server error during authentication'));
  }
};

const adminAuth = async (req, res, next) => {
  try {
    await auth(req, res, () => {
      if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
        debug.warn(`Non-admin user attempted admin access: ${req.user.email}`);
        return res.status(403).json(formatResponse(false, 'Access denied. Admin privileges required.'));
      }
      debug.debug(`Admin access granted: ${req.user.email}`);
      next();
    });
  } catch (error) {
    handleError(res, error, 'Admin authentication error', req.requestId);
  }
};

// ==================== ENHANCED DATABASE INITIALIZATION ====================

const initializeDatabase = async () => {
  try {
    debug.info('🔄 Initializing database...');
    
    // Connect to MongoDB
    debug.performance.start('database_connection');
    await mongoose.connect(config.mongoURI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
    });
    debug.performance.end('database_connection');
    
    debug.success('✅ MongoDB connected successfully', {
      host: mongoose.connection.host,
      name: mongoose.connection.name
    });
    
    // Load investment plans
    await loadInvestmentPlans();
    
    // Create admin user if it doesn't exist
    await createAdminUser();
    
    // Create indexes
    await createDatabaseIndexes();
    
    // Run initial health check
    debug.health.checkSystem();
    
    debug.success('✅ Database initialization completed');
  } catch (error) {
    debug.error('❌ Database initialization error:', error.message);
    debug.error('Error stack:', error.stack);
    
    // Attempt auto-fix
    const fixed = await debug.autoFix.database.checkConnection();
    if (!fixed) {
      throw error;
    }
  }
};

const loadInvestmentPlans = async () => {
  try {
    const plans = await InvestmentPlan.find({ is_active: true })
      .sort({ display_order: 1 })
      .lean();
    
    config.investmentPlans = plans;
    debug.success(`✅ Loaded ${plans.length} investment plans`);
    
    if (plans.length === 0) {
      await createDefaultInvestmentPlans();
    }
  } catch (error) {
    debug.error('Error loading investment plans:', error);
  }
};

const createDefaultInvestmentPlans = async () => {
  const defaultPlans = [
    {
      name: 'Cocoa Beans',
      description: 'Invest in premium cocoa beans with stable returns.',
      min_amount: 3500,
      max_amount: 50000,
      daily_interest: 10,
      total_interest: 300,
      duration: 30,
      risk_level: 'low',
      raw_material: 'Cocoa',
      category: 'agriculture',
      is_popular: true,
      features: ['Low Risk', 'Stable Returns', 'Beginner Friendly'],
      color: '#10b981',
      icon: '🌱',
      display_order: 1
    },
    {
      name: 'Gold',
      description: 'Precious metal investment with high liquidity.',
      min_amount: 50000,
      max_amount: 500000,
      daily_interest: 15,
      total_interest: 450,
      duration: 30,
      risk_level: 'medium',
      raw_material: 'Gold',
      category: 'metals',
      is_popular: true,
      features: ['Medium Risk', 'Higher Returns', 'High Liquidity'],
      color: '#fbbf24',
      icon: '🥇',
      display_order: 2
    },
    {
      name: 'Crude Oil',
      description: 'Energy sector investment with premium returns.',
      min_amount: 100000,
      max_amount: 1000000,
      daily_interest: 20,
      total_interest: 600,
      duration: 30,
      risk_level: 'high',
      raw_material: 'Crude Oil',
      category: 'energy',
      features: ['High Risk', 'Maximum Returns', 'Premium Investment'],
      color: '#dc2626',
      icon: '🛢️',
      display_order: 3
    }
  ];

  try {
    await InvestmentPlan.insertMany(defaultPlans);
    config.investmentPlans = defaultPlans;
    debug.success('✅ Created default investment plans');
  } catch (error) {
    debug.error('Error creating default investment plans:', error);
  }
};

const createAdminUser = async () => {
  try {
    debug.info('🚀 Creating/Verifying Admin User...');
    
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@rawwealthy.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123456';
    
    debug.debug('Admin credentials:', {
      email: adminEmail,
      password: '***' // Don't log actual password
    });
    
    // Check if admin exists
    const existingAdmin = await User.findOne({ email: adminEmail });
    if (existingAdmin) {
      debug.success('✅ Admin already exists');
      
      // Update password if it's the default
      if (adminPassword === 'Admin123456') {
        const salt = await bcrypt.genSalt(12);
        const hash = await bcrypt.hash(adminPassword, salt);
        existingAdmin.password = hash;
        await existingAdmin.save();
        debug.success('✅ Admin password updated');
      }
      
      return;
    }
    
    // Create new admin
    const salt = await bcrypt.genSalt(12);
    const hash = await bcrypt.hash(adminPassword, salt);
    
    const adminData = {
      _id: new mongoose.Types.ObjectId(),
      full_name: 'Raw Wealthy Admin',
      email: adminEmail,
      phone: '09161806424',
      password: hash,
      role: 'super_admin',
      balance: 1000000,
      referral_code: 'ADMIN' + crypto.randomBytes(4).toString('hex').toUpperCase(),
      kyc_verified: true,
      kyc_status: 'verified',
      is_active: true,
      is_verified: true,
      two_factor_enabled: false,
      notifications_enabled: true,
      email_notifications: true,
      sms_notifications: false,
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    await mongoose.connection.collection('users').insertOne(adminData);
    
    // Verify creation
    const verifyUser = await mongoose.connection.collection('users').findOne({ email: adminEmail });
    const match = await bcrypt.compare(adminPassword, verifyUser.password);
    
    if (match) {
      debug.success('🎉 ADMIN CREATED SUCCESSFULLY!');
      debug.info(`📧 Email: ${adminEmail}`);
      debug.info(`🔑 Password: ${adminPassword}`);
      debug.info('👉 Login at: /api/auth/login');
    } else {
      debug.error('❌ PASSWORD MISMATCH DETECTED!');
    }
    
  } catch (error) {
    debug.error('❌ Admin creation error:', error.message);
    debug.error('Stack:', error.stack);
  }
};

const createDatabaseIndexes = async () => {
  try {
    await Transaction.collection.createIndex({ createdAt: -1 });
    await User.collection.createIndex({ 'bank_details.verified': 1 });
    await Investment.collection.createIndex({ status: 1, end_date: 1 });
    debug.success('✅ Database indexes created');
  } catch (error) {
    debug.error('Error creating indexes:', error);
  }
};

// ==================== ENHANCED DEBUGGING ENDPOINTS ====================

// Enhanced health check with detailed debugging
app.get('/health', async (req, res) => {
  debug.performance.start('health_check');
  
  try {
    const health = debug.health.checkSystem();
    
    // Additional checks
    const [users, investments, deposits, withdrawals] = await Promise.all([
      User.countDocuments({}),
      Investment.countDocuments({}),
      Deposit.countDocuments({}),
      Withdrawal.countDocuments({})
    ]);
    
    const response = {
      success: true,
      status: 'OK',
      timestamp: new Date().toISOString(),
      version: '38.0.0',
      environment: config.nodeEnv,
      database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
      uptime: process.uptime(),
      memory: {
        rss: `${Math.round(process.memoryUsage().rss / 1024 / 1024)}MB`,
        heapTotal: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)}MB`,
        heapUsed: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`
      },
      stats: {
        users,
        investments,
        deposits,
        withdrawals
      },
      system: health.system,
      debug: {
        enabled: debug.enabled,
        level: debug.level,
        recentLogs: debug.logs.slice(-10)
      },
      performance: {
        metrics: await PerformanceMetrics.countDocuments(),
        averageResponseTime: await PerformanceMetrics.aggregate([
          { $group: { _id: null, avg: { $avg: '$duration' } } }
        ])
      }
    };
    
    debug.performance.end('health_check');
    res.json(response);
    
  } catch (error) {
    debug.error('Health check failed:', error);
    debug.performance.end('health_check');
    res.status(500).json({
      success: false,
      status: 'ERROR',
      error: error.message
    });
  }
});

// Debug endpoint to view logs (admin only)
app.get('/api/debug/logs', adminAuth, async (req, res) => {
  try {
    const { limit = 100, level, search } = req.query;
    
    let logs = debug.logs;
    
    if (level) {
      logs = logs.filter(log => log.level === level);
    }
    
    if (search) {
      logs = logs.filter(log => 
        log.message.toLowerCase().includes(search.toLowerCase()) ||
        JSON.stringify(log.data).toLowerCase().includes(search.toLowerCase())
      );
    }
    
    logs = logs.slice(-parseInt(limit));
    
    res.json(formatResponse(true, 'Debug logs retrieved', {
      logs,
      total: debug.logs.length,
      filtered: logs.length,
      memory: `${(process.memoryUsage().rss / 1024 / 1024).toFixed(2)}MB`
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching debug logs', req.requestId);
  }
});

// System metrics endpoint
app.get('/api/debug/metrics', adminAuth, async (req, res) => {
  try {
    const { timeframe = '1h' } = req.query;
    let timeAgo = new Date();
    
    switch (timeframe) {
      case '1h':
        timeAgo.setHours(timeAgo.getHours() - 1);
        break;
      case '24h':
        timeAgo.setHours(timeAgo.getHours() - 24);
        break;
      case '7d':
        timeAgo.setDate(timeAgo.getDate() - 7);
        break;
    }
    
    const metrics = await PerformanceMetrics.find({
      timestamp: { $gte: timeAgo }
    }).sort({ timestamp: -1 }).limit(100).lean();
    
    // Calculate averages
    const averages = await PerformanceMetrics.aggregate([
      {
        $match: { timestamp: { $gte: timeAgo } }
      },
      {
        $group: {
          _id: '$endpoint',
          avgDuration: { $avg: '$duration' },
          avgMemory: { $avg: '$memory_usage' },
          count: { $sum: 1 }
        }
      }
    ]);
    
    res.json(formatResponse(true, 'Performance metrics retrieved', {
      metrics,
      averages,
      system: debug.health.lastCheck,
      timeframe
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching metrics', req.requestId);
  }
});

// Database diagnostics endpoint
app.get('/api/debug/database', adminAuth, async (req, res) => {
  try {
    const db = mongoose.connection.db;
    const stats = await db.stats();
    
    const collections = await db.listCollections().toArray();
    const collectionStats = [];
    
    for (const collection of collections.slice(0, 10)) {
      try {
        const coll = db.collection(collection.name);
        const collStats = await coll.stats();
        collectionStats.push({
          name: collection.name,
          count: collStats.count,
          size: collStats.size,
          avgObjSize: collStats.avgObjSize,
          storageSize: collStats.storageSize
        });
      } catch (error) {
        debug.warn(`Could not get stats for collection ${collection.name}:`, error.message);
      }
    }
    
    res.json(formatResponse(true, 'Database diagnostics', {
      connection: {
        state: mongoose.connection.readyState,
        host: mongoose.connection.host,
        name: mongoose.connection.name
      },
      stats: {
        db: stats.db,
        collections: stats.collections,
        objects: stats.objects,
        avgObjSize: stats.avgObjSize,
        dataSize: stats.dataSize,
        storageSize: stats.storageSize,
        indexSize: stats.indexSize
      },
      collections: collectionStats,
      indexes: await mongoose.connection.db.collection('system.indexes').find({}).toArray()
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching database diagnostics', req.requestId);
  }
});

// Force garbage collection (development only)
app.post('/api/debug/gc', adminAuth, (req, res) => {
  if (global.gc && config.nodeEnv !== 'production') {
    global.gc();
    debug.info('Garbage collection forced');
    res.json(formatResponse(true, 'Garbage collection completed', {
      memoryBefore: process.memoryUsage(),
      memoryAfter: process.memoryUsage()
    }));
  } else {
    res.status(400).json(formatResponse(false, 'Garbage collection not available'));
  }
});

// Test email endpoint
app.post('/api/debug/test-email', adminAuth, [
  body('email').isEmail(),
  body('subject').optional(),
  body('message').optional()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }
    
    const { email, subject = 'Test Email', message = 'This is a test email from Raw Wealthy debugging system.' } = req.body;
    
    const result = await sendEmail(
      email,
      subject,
      `<h2>Test Email</h2><p>${message}</p>`
    );
    
    res.json(formatResponse(true, 'Test email sent', {
      success: result.success,
      simulated: result.simulated,
      messageId: result.messageId,
      to: email
    }));
  } catch (error) {
    handleError(res, error, 'Error sending test email', req.requestId);
  }
});

// ==================== ENHANCED AUTH ENDPOINTS ====================

// Register
app.post('/api/auth/register', [
  body('full_name').notEmpty().trim().isLength({ min: 2, max: 100 }),
  body('email').isEmail().normalizeEmail(),
  body('phone').notEmpty().trim(),
  body('password').isLength({ min: 6 }),
  body('referral_code').optional().trim(),
  body('risk_tolerance').optional().isIn(['low', 'medium', 'high']),
  body('investment_strategy').optional().isIn(['conservative', 'balanced', 'aggressive'])
], async (req, res) => {
  debug.performance.start('user_registration');
  
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      debug.warn('Registration validation failed', errors.array());
      return res.status(400).json(formatResponse(false, 'Validation failed', { 
        errors: errors.array().map(err => ({ field: err.param, message: err.msg }))
      }));
    }

    const { full_name, email, phone, password, referral_code, risk_tolerance = 'medium', investment_strategy = 'balanced' } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      debug.warn(`User registration failed - email already exists: ${email}`);
      return res.status(400).json(formatResponse(false, 'User already exists with this email'));
    }

    // Handle referral
    let referredBy = null;
    if (referral_code) {
      referredBy = await User.findOne({ referral_code: referral_code.toUpperCase() });
      if (!referredBy) {
        debug.warn(`Invalid referral code used: ${referral_code}`);
        return res.status(400).json(formatResponse(false, 'Invalid referral code'));
      }
      debug.info(`Referral code used: ${referral_code} by ${referredBy.email}`);
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
      referred_by: referredBy ? referredBy._id : null
    });

    await user.save();
    debug.success(`New user registered: ${user.email}`, { userId: user._id });

    // Handle referral
    if (referredBy) {
      referredBy.referral_count += 1;
      await referredBy.save();

      const referral = new Referral({
        referrer: referredBy._id,
        referred_user: user._id,
        referral_code: referral_code.toUpperCase(),
        status: 'pending'
      });
      await referral.save();
      
      debug.info(`Referral created for ${referredBy.email}`, { referralId: referral._id });
      
      await createNotification(
        referredBy._id,
        'New Referral!',
        `${user.full_name} has signed up using your referral code!`,
        'referral',
        '/referrals'
      );
    }

    // Generate token
    const token = user.generateAuthToken();

    // Create welcome notification
    await createNotification(
      user._id,
      'Welcome to Raw Wealthy!',
      'Your account has been successfully created. Start your investment journey today.',
      'success',
      '/dashboard'
    );

    // Create welcome bonus transaction
    await createTransaction(
      user._id,
      'bonus',
      config.welcomeBonus,
      'Welcome bonus for new account',
      'completed'
    );

    // Send welcome email
    await sendEmail(
      user.email,
      'Welcome to Raw Wealthy!',
      `<h2>Welcome ${user.full_name}!</h2>
       <p>Your account has been successfully created. Your welcome bonus of ₦${config.welcomeBonus} has been credited to your account.</p>
       <p>Start investing today and grow your wealth with us!</p>
       <p><strong>Account Details:</strong></p>
       <ul>
         <li>Email: ${user.email}</li>
         <li>Balance: ₦${user.balance.toLocaleString()}</li>
         <li>Referral Code: ${user.referral_code}</li>
       </ul>
       <p><a href="${config.clientURL}/dashboard">Go to Dashboard</a></p>`
    );

    debug.performance.end('user_registration');
    
    res.status(201).json(formatResponse(true, 'User registered successfully', {
      user: user.toObject(),
      token
    }));

  } catch (error) {
    debug.performance.end('user_registration');
    handleError(res, error, 'Registration failed', req.requestId);
  }
});

// Login
app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  debug.performance.start('user_login');
  
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { email, password } = req.body;

    // Find user with password
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    
    if (!user) {
      debug.warn(`Login failed - user not found: ${email}`);
      return res.status(400).json(formatResponse(false, 'Invalid credentials'));
    }

    // Check if account is locked
    if (user.lock_until && user.lock_until > new Date()) {
      const lockTime = Math.ceil((user.lock_until - new Date()) / 1000 / 60);
      debug.warn(`Login failed - account locked: ${email}`, { lockTime });
      return res.status(423).json(formatResponse(false, `Account is locked. Try again in ${lockTime} minutes.`));
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      user.login_attempts += 1;
      if (user.login_attempts >= 5) {
        user.lock_until = new Date(Date.now() + 15 * 60 * 1000);
        debug.warn(`Account locked due to failed attempts: ${email}`);
      }
      await user.save();
      debug.warn(`Login failed - incorrect password: ${email}`);
      return res.status(400).json(formatResponse(false, 'Invalid credentials'));
    }

    // Reset login attempts
    user.login_attempts = 0;
    user.lock_until = undefined;
    user.last_login = new Date();
    user.last_active = new Date();
    await user.save();

    // Generate token
    const token = user.generateAuthToken();

    debug.success(`User logged in: ${user.email}`);
    debug.performance.end('user_login');
    
    res.json(formatResponse(true, 'Login successful', {
      user: user.toObject(),
      token
    }));

  } catch (error) {
    debug.performance.end('user_login');
    handleError(res, error, 'Login failed', req.requestId);
  }
});

// Forgot Password
app.post('/api/auth/forgot-password', [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  debug.performance.start('forgot_password');
  
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { email } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      debug.warn(`Forgot password - user not found: ${email}`);
      return res.status(404).json(formatResponse(false, 'No user found with this email'));
    }

    // Generate reset token
    const resetToken = user.generatePasswordResetToken();
    await user.save();

    // Create reset URL
    const resetUrl = `${config.clientURL}/reset-password/${resetToken}`;

    // Send email
    const emailResult = await sendEmail(
      user.email,
      'Password Reset Request',
      `<h2>Password Reset Request</h2>
       <p>You requested a password reset for your Raw Wealthy account.</p>
       <p>Click the link below to reset your password:</p>
       <p><a href="${resetUrl}">${resetUrl}</a></p>
       <p>This link will expire in 10 minutes.</p>
       <p>If you didn't request this, please ignore this email.</p>`
    );

    if (!emailResult.success) {
      debug.error('Failed to send password reset email', { email: user.email });
      return res.status(500).json(formatResponse(false, 'Failed to send reset email'));
    }

    debug.success(`Password reset email sent to: ${user.email}`);
    debug.performance.end('forgot_password');
    
    res.json(formatResponse(true, 'Password reset email sent successfully'));
  } catch (error) {
    debug.performance.end('forgot_password');
    handleError(res, error, 'Error processing forgot password request', req.requestId);
  }
});

// ==================== ENHANCED PROFILE ENDPOINTS ====================

// Get profile with debugging
app.get('/api/profile', auth, async (req, res) => {
  debug.performance.start('get_profile');
  
  try {
    const userId = req.user._id;
    
    const [user, investments, transactions, notifications] = await Promise.all([
      User.findById(userId).lean(),
      Investment.find({ user: userId })
        .populate('plan', 'name daily_interest duration total_interest')
        .sort({ createdAt: -1 })
        .lean(),
      Transaction.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(50)
        .lean(),
      Notification.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean()
    ]);

    debug.debug(`Profile retrieved for user: ${user.email}`);
    debug.performance.end('get_profile');
    
    res.json(formatResponse(true, 'Profile retrieved successfully', {
      user,
      investments,
      transactions,
      notifications
    }));
  } catch (error) {
    debug.performance.end('get_profile');
    handleError(res, error, 'Error fetching profile', req.requestId);
  }
});

// ==================== ENHANCED INVESTMENT ENDPOINTS ====================

// Get user investments
app.get('/api/investments', auth, async (req, res) => {
  debug.performance.start('get_investments');
  
  try {
    const userId = req.user._id;
    const { status, page = 1, limit = 10 } = req.query;
    
    const query = { user: userId };
    if (status) query.status = status;
    
    const skip = (page - 1) * limit;
    
    const [investments, total] = await Promise.all([
      Investment.find(query)
        .populate('plan', 'name daily_interest duration total_interest')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Investment.countDocuments(query)
    ]);

    debug.debug(`Investments retrieved for user: ${userId}`, { count: investments.length });
    debug.performance.end('get_investments');
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(formatResponse(true, 'Investments retrieved successfully', {
      investments,
      pagination
    }));
  } catch (error) {
    debug.performance.end('get_investments');
    handleError(res, error, 'Error fetching investments', req.requestId);
  }
});

// ==================== ENHANCED DEPOSIT ENDPOINTS ====================

// Get user deposits
app.get('/api/deposits', auth, async (req, res) => {
  debug.performance.start('get_deposits');
  
  try {
    const userId = req.user._id;
    const { status, page = 1, limit = 10 } = req.query;
    
    const query = { user: userId };
    if (status) query.status = status;
    
    const skip = (page - 1) * limit;
    
    const [deposits, total] = await Promise.all([
      Deposit.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Deposit.countDocuments(query)
    ]);

    debug.debug(`Deposits retrieved for user: ${userId}`, { count: deposits.length });
    debug.performance.end('get_deposits');
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(formatResponse(true, 'Deposits retrieved successfully', {
      deposits,
      pagination
    }));
  } catch (error) {
    debug.performance.end('get_deposits');
    handleError(res, error, 'Error fetching deposits', req.requestId);
  }
});

// ==================== ENHANCED WITHDRAWAL ENDPOINTS ====================

// Get user withdrawals
app.get('/api/withdrawals', auth, async (req, res) => {
  debug.performance.start('get_withdrawals');
  
  try {
    const userId = req.user._id;
    const { status, page = 1, limit = 10 } = req.query;
    
    const query = { user: userId };
    if (status) query.status = status;
    
    const skip = (page - 1) * limit;
    
    const [withdrawals, total] = await Promise.all([
      Withdrawal.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Withdrawal.countDocuments(query)
    ]);

    debug.debug(`Withdrawals retrieved for user: ${userId}`, { count: withdrawals.length });
    debug.performance.end('get_withdrawals');
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(formatResponse(true, 'Withdrawals retrieved successfully', {
      withdrawals,
      pagination
    }));
  } catch (error) {
    debug.performance.end('get_withdrawals');
    handleError(res, error, 'Error fetching withdrawals', req.requestId);
  }
});

// ==================== ENHANCED ADMIN ENDPOINTS ====================

// Admin dashboard with debugging
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
  debug.performance.start('admin_dashboard');
  
  try {
    const [
      totalUsers,
      newUsersToday,
      totalInvestments,
      activeInvestments,
      totalDeposits,
      totalWithdrawals,
      pendingInvestments,
      pendingDeposits,
      pendingWithdrawals,
      pendingKYC
    ] = await Promise.all([
      User.countDocuments({}),
      User.countDocuments({ 
        createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) } 
      }),
      Investment.countDocuments({}),
      Investment.countDocuments({ status: 'active' }),
      Deposit.countDocuments({ status: 'approved' }),
      Withdrawal.countDocuments({ status: 'paid' }),
      Investment.countDocuments({ status: 'pending' }),
      Deposit.countDocuments({ status: 'pending' }),
      Withdrawal.countDocuments({ status: 'pending' }),
      KYCSubmission.countDocuments({ status: 'pending' })
    ]);

    const stats = {
      overview: {
        total_users: totalUsers,
        new_users_today: newUsersToday,
        total_investments: totalInvestments,
        active_investments: activeInvestments,
        total_deposits: totalDeposits,
        total_withdrawals: totalWithdrawals
      },
      pending_actions: {
        pending_investments: pendingInvestments,
        pending_deposits: pendingDeposits,
        pending_withdrawals: pendingWithdrawals,
        pending_kyc: pendingKYC
      }
    };

    debug.debug(`Admin dashboard accessed by: ${req.user.email}`);
    debug.performance.end('admin_dashboard');
    
    res.json(formatResponse(true, 'Admin dashboard stats retrieved successfully', {
      stats,
      quick_links: {
        pending_investments: '/api/admin/pending-investments',
        pending_deposits: '/api/admin/pending-deposits',
        pending_withdrawals: '/api/admin/pending-withdrawals',
        pending_kyc: '/api/admin/pending-kyc'
      }
    }));
  } catch (error) {
    debug.performance.end('admin_dashboard');
    handleError(res, error, 'Error fetching admin dashboard stats', req.requestId);
  }
});

// Get all users with debugging
app.get('/api/admin/users', adminAuth, async (req, res) => {
  debug.performance.start('admin_get_users');
  
  try {
    const { page = 1, limit = 20, search } = req.query;
    
    const query = {};
    if (search) {
      query.$or = [
        { full_name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { phone: { $regex: search, $options: 'i' } }
      ];
    }
    
    const skip = (page - 1) * limit;
    
    const [users, total] = await Promise.all([
      User.find(query)
        .select('-password -two_factor_secret -verification_token -password_reset_token')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      User.countDocuments(query)
    ]);

    debug.debug(`Admin users list accessed by: ${req.user.email}`, { count: users.length });
    debug.performance.end('admin_get_users');
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(formatResponse(true, 'Users retrieved successfully', {
      users,
      pagination
    }));
  } catch (error) {
    debug.performance.end('admin_get_users');
    handleError(res, error, 'Error fetching users', req.requestId);
  }
});

// ==================== ENHANCED CRON JOBS WITH DEBUGGING ====================

// Calculate daily earnings
cron.schedule('0 0 * * *', async () => {
  debug.performance.start('daily_earnings_cron');
  debug.info('🔄 Calculating daily earnings...');
  
  try {
    const activeInvestments = await Investment.find({ 
      status: 'active',
      end_date: { $gt: new Date() }
    }).populate('user plan');

    let totalEarnings = 0;
    let processedCount = 0;

    for (const investment of activeInvestments) {
      try {
        const dailyEarning = investment.daily_earnings || (investment.amount * investment.plan.daily_interest / 100);
        
        // Update investment earnings
        investment.earned_so_far += dailyEarning;
        investment.last_earning_date = new Date();
        await investment.save();

        // Update user balance
        await User.findByIdAndUpdate(investment.user._id, {
          $inc: { 
            balance: dailyEarning,
            total_earnings: dailyEarning
          }
        });
        
        // Create transaction
        await createTransaction(
          investment.user._id,
          'earning',
          dailyEarning,
          `Daily earnings from ${investment.plan.name} investment`,
          'completed',
          { investment_id: investment._id }
        );
        
        totalEarnings += dailyEarning;
        processedCount++;

      } catch (investmentError) {
        debug.error(`Error processing investment ${investment._id}:`, investmentError);
      }
    }

    debug.success(`Daily earnings calculated. Processed: ${processedCount}, Total: ₦${totalEarnings.toLocaleString()}`);
    debug.performance.end('daily_earnings_cron');
  } catch (error) {
    debug.error('❌ Error calculating daily earnings:', error);
    debug.performance.end('daily_earnings_cron');
  }
});

// Auto-renew investments
cron.schedule('0 1 * * *', async () => {
  debug.performance.start('auto_renew_cron');
  debug.info('🔄 Processing auto-renew investments...');
  
  try {
    const completedInvestments = await Investment.find({
      status: 'completed',
      auto_renew: true,
      auto_renewed: false
    }).populate('user plan');

    let renewedCount = 0;

    for (const investment of completedInvestments) {
      try {
        const userId = investment.user._id;
        const planId = investment.plan._id;
        
        // Check user balance
        const user = await User.findById(userId);
        if (!user || user.balance < investment.amount) {
          debug.warn(`User ${userId} has insufficient balance for auto-renew`);
          continue;
        }

        // Create new investment
        const newInvestment = new Investment({
          user: userId,
          plan: planId,
          amount: investment.amount,
          status: 'active',
          start_date: new Date(),
          end_date: new Date(Date.now() + investment.plan.duration * 24 * 60 * 60 * 1000),
          expected_earnings: (investment.amount * investment.plan.total_interest) / 100,
          earned_so_far: 0,
          daily_earnings: (investment.amount * investment.plan.daily_interest) / 100,
          auto_renew: true,
          auto_renewed: false
        });

        await newInvestment.save();
        
        // Update user balance
        await User.findByIdAndUpdate(userId, {
          $inc: { balance: -investment.amount }
        });
        
        // Mark original investment as renewed
        investment.auto_renewed = true;
        await investment.save();

        debug.info(`Auto-renewed investment ${investment._id} for user ${userId}`);
        renewedCount++;

      } catch (error) {
        debug.error(`Error auto-renewing investment ${investment._id}:`, error);
      }
    }

    debug.success(`Auto-renew completed. Renewed: ${renewedCount}`);
    debug.performance.end('auto_renew_cron');
  } catch (error) {
    debug.error('❌ Error processing auto-renew:', error);
    debug.performance.end('auto_renew_cron');
  }
});

// System health check cron
cron.schedule('*/30 * * * *', async () => {
  debug.performance.start('system_health_cron');
  debug.info('🔄 Running system health check...');
  
  try {
    const health = debug.health.checkSystem();
    
    // Check database connection
    const dbHealthy = await debug.autoFix.database.checkConnection();
    
    if (!dbHealthy) {
      debug.error('❌ Database health check failed');
      // Attempt to send alert
      if (config.emailEnabled) {
        await sendEmail(
          process.env.ADMIN_EMAIL || config.emailConfig.user,
          '🚨 Database Connection Alert',
          `Database connection failed at ${new Date().toISOString()}. Please check your MongoDB connection.`
        );
      }
    }
    
    debug.success('✅ System health check completed', {
      database: dbHealthy ? 'healthy' : 'unhealthy',
      memory: `${(health.system.memory.rss / 1024 / 1024).toFixed(2)}MB`,
      uptime: `${Math.floor(health.system.uptime / 60)} minutes`
    });
    
    debug.performance.end('system_health_cron');
  } catch (error) {
    debug.error('❌ System health check error:', error);
    debug.performance.end('system_health_cron');
  }
});

// Cleanup old logs and metrics
cron.schedule('0 3 * * *', async () => {
  debug.performance.start('cleanup_cron');
  debug.info('🔄 Cleaning up old data...');
  
  try {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    // Cleanup old performance metrics
    const deletedMetrics = await PerformanceMetrics.deleteMany({
      timestamp: { $lt: thirtyDaysAgo }
    });
    
    // Cleanup old notifications
    const deletedNotifications = await Notification.deleteMany({
      createdAt: { $lt: thirtyDaysAgo },
      is_read: true
    });
    
    // Cleanup debug logs (in-memory)
    const oldLogCount = debug.logs.length;
    debug.logs = debug.logs.filter(log => new Date(log.timestamp) > thirtyDaysAgo);
    
    debug.success('✅ Cleanup completed', {
      deletedMetrics: deletedMetrics.deletedCount,
      deletedNotifications: deletedNotifications.deletedCount,
      cleanedLogs: oldLogCount - debug.logs.length
    });
    
    debug.performance.end('cleanup_cron');
  } catch (error) {
    debug.error('❌ Cleanup error:', error);
    debug.performance.end('cleanup_cron');
  }
});

// ==================== ENHANCED ERROR HANDLING ====================

// 404 handler
app.use((req, res) => {
  debug.warn(`404 - Endpoint not found: ${req.method} ${req.originalUrl}`);
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
      '/api/admin/*',
      '/api/debug/*',
      '/health'
    ]
  }));
});

// Global error handler with enhanced debugging
app.use((err, req, res, next) => {
  debug.performance.start('global_error_handler');
  
  const errorLog = {
    timestamp: new Date().toISOString(),
    requestId: req.requestId,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    user_agent: req.headers['user-agent'],
    error: {
      message: err.message,
      stack: config.debugMode ? err.stack : undefined,
      name: err.name,
      code: err.code
    },
    user: req.user ? { id: req.user._id, email: req.user.email } : null
  };
  
  debug.error('Global error occurred:', errorLog);
  
  // Save error to database for analysis
  if (config.debugMode) {
    // Could save to an errors collection here
  }
  
  if (err instanceof multer.MulterError) {
    debug.performance.end('global_error_handler');
    return res.status(400).json(formatResponse(false, `File upload error: ${err.message}`, {
      requestId: config.debugMode ? req.requestId : undefined
    }));
  }
  
  if (err.name === 'MongoError' || err.name === 'MongooseError') {
    debug.performance.end('global_error_handler');
    return res.status(500).json(formatResponse(false, 'Database error occurred. Please try again later.', {
      requestId: config.debugMode ? req.requestId : undefined
    }));
  }
  
  if (err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT') {
    debug.performance.end('global_error_handler');
    return res.status(503).json(formatResponse(false, 'Service temporarily unavailable. Please try again later.', {
      requestId: config.debugMode ? req.requestId : undefined
    }));
  }
  
  debug.performance.end('global_error_handler');
  res.status(500).json(formatResponse(false, 'Internal server error', {
    requestId: config.debugMode ? req.requestId : undefined,
    errorId: crypto.randomBytes(8).toString('hex'),
    timestamp: new Date().toISOString()
  }));
});

// ==================== ENHANCED SERVER INITIALIZATION ====================

const startServer = async () => {
  try {
    debug.info(`
🚀 RAW WEALTHY BACKEND v38.0 - ENHANCED DEBUGGING EDITION
=========================================================
🌐 Server starting on port ${config.port}
🚀 Environment: ${config.nodeEnv}
🔧 Debug Mode: ${config.debugMode ? 'ENABLED' : 'DISABLED'}
📊 Health Check: /health
🔗 API Base: /api
🛡️ Enhanced Security: ENABLED
📧 Email Service: ${config.emailEnabled ? 'ENABLED' : 'DISABLED'}
📁 Upload Directory: ${config.uploadDir}
🌐 Server URL: ${config.serverURL}

✅ ENHANCED DEBUGGING FEATURES:
   ✅ Advanced Logging System with Levels
   ✅ Request/Response Tracking
   ✅ Performance Monitoring
   ✅ Automatic Problem Detection
   ✅ Database Connection Auto-Fix
   ✅ Real-time System Health Checks
   ✅ Memory Usage Tracking
   ✅ Error Analysis & Reporting
   ✅ Debug Endpoints for Admins
   ✅ Performance Metrics Collection
   ✅ Automatic Cleanup Jobs
   ✅ Email Alert System
   ✅ Comprehensive Dashboard

🚀 SYSTEM READY FOR PRODUCTION WITH ENHANCED DEBUGGING!
🔐 SECURITY ENHANCED WITH REAL-TIME MONITORING
📈 PERFORMANCE OPTIMIZED WITH METRICS COLLECTION
🐛 DEBUGGING INTEGRATED FOR PRODUCTION SUPPORT
    `);

    // Initialize database
    await initializeDatabase();
    
    // Start server
    const server = app.listen(config.port, '0.0.0.0', () => {
      debug.success(`Server running on port ${config.port}`);
      
      // Initial system health check
      setTimeout(() => {
        debug.health.checkSystem();
      }, 5000);
    });

    // Graceful shutdown with debugging
    const gracefulShutdown = async (signal) => {
      debug.warn(`${signal} received, shutting down gracefully...`);
      
      // Close server
      server.close(async () => {
        debug.info('HTTP server closed');
        
        // Close database connection
        try {
          await mongoose.connection.close();
          debug.success('Database connection closed');
        } catch (dbError) {
          debug.error('Error closing database:', dbError);
        }
        
        // Log final system state
        debug.info('Final system state:', {
          memory: `${(process.memoryUsage().rss / 1024 / 1024).toFixed(2)}MB`,
          uptime: `${Math.floor(process.uptime())} seconds`,
          totalLogs: debug.logs.length
        });
        
        debug.success('Process terminated gracefully');
        process.exit(0);
      });
      
      // Force shutdown after 10 seconds
      setTimeout(() => {
        debug.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
      }, 10000);
    };

    // Handle shutdown signals
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    process.on('SIGUSR2', () => gracefulShutdown('SIGUSR2'));

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      debug.error('Uncaught Exception:', error);
      gracefulShutdown('uncaughtException');
    });

    process.on('unhandledRejection', (reason, promise) => {
      debug.error('Unhandled Rejection at:', promise, 'reason:', reason);
    });

  } catch (error) {
    debug.error('❌ Server initialization failed:', error);
    debug.error('Error stack:', error.stack);
    
    // Attempt auto-recovery
    debug.warn('Attempting auto-recovery...');
    setTimeout(() => {
      process.exit(1);
    }, 5000);
  }
};

// Start the enhanced server
startServer();

export default app;
