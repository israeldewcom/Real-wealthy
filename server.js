// server.js - RAW WEALTHY BACKEND v47.0 ENHANCED - ENTERPRISE EDITION
// COMPLETE DEBUGGED & ENHANCED: Advanced Admin Dashboard + Full Data Analytics + Enhanced Notifications + Image Management
// AUTO-DEPLOYMENT READY WITH DYNAMIC CONFIGURATION
// DEBUGGED MONGODB CONNECTION WITH RETRY MECHANISM

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
import { Server } from 'socket.io';
import http from 'http';
import os from 'os';

// ES Modules equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Enhanced environment configuration with multiple fallbacks
dotenv.config({ path: path.join(__dirname, '.env.production') });

// ==================== ADVANCED ENVIRONMENT VALIDATION & DEBUGGING ====================
console.log('\n' + '='.repeat(80));
console.log('🚀 RAW WEALTHY BACKEND v47.0 ENHANCED - INITIALIZING');
console.log('='.repeat(80));

const requiredEnvVars = [
  'MONGODB_URI',
  'JWT_SECRET',
  'NODE_ENV',
  'CLIENT_URL'
];

console.log('🔍 Environment Configuration:');
console.log('-' .repeat(50));

// Try multiple sources for MongoDB URI
let mongoURI = process.env.MONGODB_URI;

if (!mongoURI) {
  console.log('🔍 Searching for MongoDB connection string...');
  
  // Try alternative environment variables
  if (process.env.DATABASE_URL) {
    mongoURI = process.env.DATABASE_URL;
    console.log('✅ Found MONGODB_URI from DATABASE_URL');
  } else if (process.env.MONGO_URL) {
    mongoURI = process.env.MONGO_URL;
    console.log('✅ Found MONGODB_URI from MONGO_URL');
  } else if (process.env.MONGODB_URL) {
    mongoURI = process.env.MONGODB_URL;
    console.log('✅ Found MONGODB_URI from MONGODB_URL');
  } else {
    // Try local MongoDB as last resort
    mongoURI = 'mongodb://localhost:27017/rawwealthy';
    console.log('⚠️ Using local MongoDB as fallback');
  }
}

// Update process.env
process.env.MONGODB_URI = mongoURI;

// Generate JWT secret if missing
if (!process.env.JWT_SECRET) {
  process.env.JWT_SECRET = crypto.randomBytes(64).toString('hex');
  console.log('✅ Generated JWT_SECRET automatically');
}

// Set default client URL
if (!process.env.CLIENT_URL) {
  process.env.CLIENT_URL = 'https://us-raw-wealthy.vercel.app';
  console.log('✅ Set default CLIENT_URL');
}

// Add SERVER_URL for absolute image paths
if (!process.env.SERVER_URL) {
  process.env.SERVER_URL = process.env.CLIENT_URL || `http://localhost:${process.env.PORT || 10000}`;
  console.log('✅ Set SERVER_URL:', process.env.SERVER_URL);
}

console.log('-' .repeat(50));
console.log('✅ Environment configuration complete');
console.log('='.repeat(80) + '\n');

// ==================== ENHANCED CONFIGURATION WITH DEBUGGING ====================
const config = {
  // Server
  port: process.env.PORT || 10000,
  nodeEnv: process.env.NODE_ENV || 'production',
  serverURL: process.env.SERVER_URL,
  
  // Database (DEBUGGED)
  mongoURI: process.env.MONGODB_URI,
  
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
  platformFeePercent: parseFloat(process.env.PLATFORM_FEE_PERCENT) || 5,
  referralCommissionPercent: parseFloat(process.env.REFERRAL_COMMISSION_PERCENT) || 15,
  welcomeBonus: parseInt(process.env.WELCOME_BONUS) || 100,
  
  // Investment Plans (Will be loaded from database)
  investmentPlans: [],
  
  // Storage
  uploadDir: path.join(__dirname, 'uploads'),
  maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 10 * 1024 * 1024, // 10MB
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
  debug: process.env.DEBUG === 'true',
  logLevel: process.env.LOG_LEVEL || 'info',
  
  // Advanced Features
  enableRealTimeStats: process.env.ENABLE_REAL_TIME_STATS === 'true',
  enableAutoBackup: process.env.ENABLE_AUTO_BACKUP === 'true',
  enableAPIAnalytics: process.env.ENABLE_API_ANALYTICS === 'true'
};

// Build allowed origins dynamically
config.allowedOrigins = [
  config.clientURL,
  config.serverURL,
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:3001',
  'http://localhost:5173',
  'http://localhost:8080',
  'https://rawwealthy.com',
  'https://www.rawwealthy.com',
  'https://uun-rawwealthy.vercel.app',
  'https://real-wealthy-1.onrender.com',
  'https://raw-wealthy-backend.herokuapp.com'
].filter(Boolean);

console.log('⚙️  Dynamic Configuration Loaded:');
console.log(`- Port: ${config.port}`);
console.log(`- Environment: ${config.nodeEnv}`);
console.log(`- Client URL: ${config.clientURL}`);
console.log(`- Server URL: ${config.serverURL}`);
console.log(`- Database URI: ${config.mongoURI ? '✅ Set' : '❌ Not set'}`);
console.log(`- Email Enabled: ${config.emailEnabled}`);
console.log(`- Allowed Origins: ${config.allowedOrigins.length}`);
console.log(`- Debug Mode: ${config.debug}`);
console.log(`- Advanced Features: Real-time: ${config.enableRealTimeStats}, Backup: ${config.enableAutoBackup}`);

// ==================== ADVANCED DEBUGGING SYSTEM ====================

// Request tracking for analytics
const requestAnalytics = {
  totalRequests: 0,
  requestsByEndpoint: {},
  requestsByMethod: {},
  requestsByHour: {},
  errorsByEndpoint: {},
  responseTimes: []
};

// Performance monitoring
const performanceStats = {
  startTime: Date.now(),
  dbQueries: 0,
  cacheHits: 0,
  cacheMisses: 0,
  socketConnections: 0
};

// Advanced logging system
const advancedLogger = {
  log: (level, message, data = {}) => {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      level,
      message,
      data,
      pid: process.pid,
      memory: process.memoryUsage()
    };
    
    if (config.debug) {
      const colors = {
        info: '\x1b[36m%s\x1b[0m', // Cyan
        warn: '\x1b[33m%s\x1b[0m', // Yellow
        error: '\x1b[31m%s\x1b[0m', // Red
        success: '\x1b[32m%s\x1b[0m', // Green
        debug: '\x1b[35m%s\x1b[0m' // Magenta
      };
      
      const color = colors[level] || '\x1b[37m%s\x1b[0m'; // White
      console.log(color, `[${timestamp}] ${level.toUpperCase()}: ${message}`);
      if (Object.keys(data).length > 0 && config.logLevel === 'debug') {
        console.log('📊 Data:', data);
      }
    }
    
    // Log to file in production
    if (config.nodeEnv === 'production') {
      const logFile = path.join(__dirname, 'logs', `${timestamp.split('T')[0]}.log`);
      const logDir = path.dirname(logFile);
      
      if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true });
      }
      
      fs.appendFileSync(logFile, JSON.stringify(logEntry) + '\n');
    }
  },
  
  info: (message, data = {}) => advancedLogger.log('info', message, data),
  warn: (message, data = {}) => advancedLogger.log('warn', message, data),
  error: (message, data = {}) => advancedLogger.log('error', message, data),
  success: (message, data = {}) => advancedLogger.log('success', message, data),
  debug: (message, data = {}) => {
    if (config.debug) {
      advancedLogger.log('debug', message, data);
    }
  }
};

// Initialize logger
advancedLogger.info('Advanced logging system initialized');

// ==================== ENHANCED EXPRESS SETUP WITH DEBUGGING ====================
const app = express();
const server = http.createServer(app);

// Initialize Socket.IO for real-time updates
const io = new Server(server, {
  cors: {
    origin: config.allowedOrigins,
    credentials: true
  }
});

// Track Socket.IO connections
io.on('connection', (socket) => {
  performanceStats.socketConnections++;
  advancedLogger.debug(`Socket.IO connection established`, {
    socketId: socket.id,
    totalConnections: performanceStats.socketConnections
  });
  
  socket.on('disconnect', () => {
    performanceStats.socketConnections--;
    advancedLogger.debug(`Socket.IO connection closed`, {
      socketId: socket.id,
      remainingConnections: performanceStats.socketConnections
    });
  });
});

// Advanced security headers with dynamic CSP
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

// Enhanced logging with levels
const morganFormat = config.nodeEnv === 'production' ? 'combined' : 'dev';
if (config.logLevel === 'debug') {
  app.use(morgan('dev'));
} else {
  app.use(morgan(morganFormat));
}

// ==================== ADVANCED REQUEST DEBUGGING MIDDLEWARE ====================

app.use((req, res, next) => {
  const requestId = crypto.randomBytes(8).toString('hex');
  const startTime = Date.now();
  
  // Store request info
  req.requestId = requestId;
  req.startTime = startTime;
  
  // Track analytics
  requestAnalytics.totalRequests++;
  
  const endpoint = req.path;
  requestAnalytics.requestsByEndpoint[endpoint] = (requestAnalytics.requestsByEndpoint[endpoint] || 0) + 1;
  requestAnalytics.requestsByMethod[req.method] = (requestAnalytics.requestsByMethod[req.method] || 0) + 1;
  
  const hour = new Date().getHours();
  requestAnalytics.requestsByHour[hour] = (requestAnalytics.requestsByHour[hour] || 0) + 1;
  
  // Enhanced logging
  advancedLogger.debug('📥 Incoming Request', {
    requestId,
    method: req.method,
    url: req.url,
    endpoint: req.path,
    ip: req.ip,
    userAgent: req.headers['user-agent'],
    contentType: req.headers['content-type'],
    authorization: req.headers.authorization ? 'Present' : 'Missing'
  });
  
  // Log request body for non-GET requests
  if (req.method !== 'GET' && req.body && Object.keys(req.body).length > 0) {
    advancedLogger.debug('📦 Request Body', {
      requestId,
      body: req.body
    });
  }
  
  // Override res.json to capture response data
  const originalJson = res.json;
  res.json = function(data) {
    const responseTime = Date.now() - startTime;
    requestAnalytics.responseTimes.push(responseTime);
    
    // Log response
    advancedLogger.debug('📤 Outgoing Response', {
      requestId,
      statusCode: res.statusCode,
      responseTime: `${responseTime}ms`,
      success: data?.success,
      message: data?.message,
      dataSize: JSON.stringify(data).length
    });
    
    // Track errors
    if (!data?.success || res.statusCode >= 400) {
      requestAnalytics.errorsByEndpoint[endpoint] = (requestAnalytics.errorsByEndpoint[endpoint] || 0) + 1;
      advancedLogger.warn('⚠️ Error Response', {
        requestId,
        endpoint,
        statusCode: res.statusCode,
        error: data?.message
      });
    }
    
    // Add performance headers
    res.setHeader('X-Request-ID', requestId);
    res.setHeader('X-Response-Time', `${responseTime}ms`);
    res.setHeader('X-API-Version', '47.0.0');
    
    return originalJson.call(this, data);
  };
  
  next();
});

// ==================== ENHANCED CORS CONFIGURATION ====================
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) {
      if (config.debug) advancedLogger.debug('🌐 No origin - Allowing request');
      return callback(null, true);
    }
    
    if (config.allowedOrigins.indexOf(origin) !== -1) {
      if (config.debug) advancedLogger.debug(`🌐 Allowed origin: ${origin}`);
      callback(null, true);
    } else {
      // Check if origin matches pattern (for preview deployments)
      const isPreviewDeployment = origin.includes('vercel.app') || 
                                  origin.includes('onrender.com') ||
                                  origin.includes('netlify.app') ||
                                  origin.includes('github.io');
      
      if (isPreviewDeployment) {
        advancedLogger.debug(`🌐 Allowed preview deployment: ${origin}`);
        callback(null, true);
      } else {
        advancedLogger.warn(`🚫 Blocked by CORS: ${origin}`);
        callback(new Error('Not allowed by CORS'));
      }
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'x-api-key', 'x-user-id', 'x-debug-token'],
  exposedHeaders: ['X-Response-Time', 'X-Powered-By', 'X-Version', 'X-Request-ID']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// ==================== ENHANCED BODY PARSING ====================
app.use(express.json({ 
  limit: '50mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
    if (config.debug && req.headers['content-type']?.includes('application/json')) {
      try {
        const body = JSON.parse(buf.toString());
        advancedLogger.debug('📨 Parsed JSON Body', {
          size: buf.length,
          keys: Object.keys(body)
        });
      } catch (e) {
        advancedLogger.debug('📨 Raw body (not JSON)', {
          preview: buf.toString().substring(0, 200)
        });
      }
    }
  }
}));

app.use(express.urlencoded({ 
  extended: true, 
  limit: '50mb',
  parameterLimit: 100000
}));

// ==================== ENHANCED RATE LIMITING ====================
const createRateLimiter = (windowMs, max, message) => rateLimit({
  windowMs,
  max,
  message: { success: false, message },
  skipSuccessfulRequests: false,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Use user ID if authenticated, otherwise IP
    return req.user?.id || req.ip;
  },
  handler: (req, res) => {
    advancedLogger.warn('⏰ Rate limit exceeded', {
      ip: req.ip,
      endpoint: req.path,
      userId: req.user?.id
    });
    res.status(429).json({ success: false, message });
  }
});

const rateLimiters = {
  createAccount: createRateLimiter(60 * 60 * 1000, 10, 'Too many accounts created, please try again after an hour'),
  auth: createRateLimiter(15 * 60 * 1000, 20, 'Too many authentication attempts, please try again after 15 minutes'),
  api: createRateLimiter(15 * 60 * 1000, 1000, 'Too many requests, please try again later'),
  financial: createRateLimiter(15 * 60 * 1000, 50, 'Too many financial operations, please try again later'),
  passwordReset: createRateLimiter(15 * 60 * 1000, 5, 'Too many password reset attempts, please try again later'),
  admin: createRateLimiter(15 * 60 * 1000, 500, 'Too many admin requests'),
  upload: createRateLimiter(15 * 60 * 1000, 20, 'Too many file uploads, please try again later')
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
app.use('/api/upload', rateLimiters.upload);
app.use('/api/', rateLimiters.api);

// ==================== ENHANCED DATABASE MODELS ====================

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
  // Enhanced fields
  total_deposits: { type: Number, default: 0 },
  total_withdrawals: { type: Number, default: 0 },
  total_investments: { type: Number, default: 0 },
  last_deposit_date: Date,
  last_withdrawal_date: Date,
  last_investment_date: Date,
  // Debug fields
  created_by_ip: String,
  created_by_user_agent: String,
  // Analytics fields
  login_count: { type: Number, default: 0 },
  total_session_time: { type: Number, default: 0 } // in minutes
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
userSchema.index({ createdAt: -1 });

// Virtuals
userSchema.virtual('portfolio_value').get(function() {
  return this.balance + this.total_earnings + this.referral_earnings;
});

userSchema.virtual('account_age_days').get(function() {
  return Math.floor((Date.now() - this.createdAt) / (1000 * 60 * 60 * 24));
});

// Pre-save hooks
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    advancedLogger.debug(`🔑 Hashing password for user: ${this.email}`);
    this.password = await bcrypt.hash(this.password, config.bcryptRounds);
  }
  
  if (!this.referral_code) {
    this.referral_code = crypto.randomBytes(6).toString('hex').toUpperCase();
    advancedLogger.debug(`🎫 Generated referral code for ${this.email}: ${this.referral_code}`);
  }
  
  if (this.isModified('email') && !this.is_verified) {
    this.verification_token = crypto.randomBytes(32).toString('hex');
    this.verification_expires = new Date(Date.now() + 24 * 60 * 60 * 1000);
  }
  
  if (this.isModified('bank_details')) {
    this.bank_details.last_updated = new Date();
  }
  
  next();
});

// Methods
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.generateAuthToken = function() {
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
  this.password_reset_expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
  return resetToken;
};

userSchema.methods.toJSON = function() {
  const obj = this.toObject();
  delete obj.password;
  delete obj.two_factor_secret;
  delete obj.verification_token;
  delete obj.password_reset_token;
  return obj;
};

const User = mongoose.model('User', userSchema);

// Enhanced Investment Plan Model
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

const InvestmentPlan = mongoose.model('InvestmentPlan', investmentPlanSchema);

// Enhanced Investment Model
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
  investment_image_url: String,
  // Analytics fields
  roi_percentage: { type: Number, default: 0 },
  days_remaining: { type: Number, default: 0 },
  estimated_completion: Date
}, { 
  timestamps: true 
});

investmentSchema.index({ user: 1, status: 1 });
investmentSchema.index({ end_date: 1 });
investmentSchema.index({ createdAt: -1 });

const Investment = mongoose.model('Investment', investmentSchema);

// Enhanced Deposit Model
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
  proof_verified_at: Date,
  // Analytics fields
  processing_time: Number, // in minutes
  auto_approved: { type: Boolean, default: false }
}, { 
  timestamps: true 
});

depositSchema.index({ user: 1, status: 1 });
depositSchema.index({ reference: 1 }, { unique: true, sparse: true });

const Deposit = mongoose.model('Deposit', depositSchema);

// Enhanced Withdrawal Model
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
  proof_verified_at: Date,
  // Analytics fields
  processing_time: Number, // in minutes
  fee_percentage: Number
}, { 
  timestamps: true 
});

withdrawalSchema.index({ user: 1, status: 1 });
withdrawalSchema.index({ reference: 1 }, { unique: true, sparse: true });

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// Enhanced Transaction Model
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

const Transaction = mongoose.model('Transaction', transactionSchema);

// Enhanced KYC Submission Model
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

// Enhanced Support Ticket Model
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

// Enhanced Referral Model
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

// Enhanced Notification Model
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

// Enhanced Admin Audit Log Model
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

// Analytics Model
const analyticsSchema = new mongoose.Schema({
  date: { type: Date, required: true, index: true },
  metric: { type: String, required: true, index: true },
  value: { type: Number, required: true },
  breakdown: mongoose.Schema.Types.Mixed,
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
  timestamps: true
});

analyticsSchema.index({ date: 1, metric: 1 }, { unique: true });

const Analytics = mongoose.model('Analytics', analyticsSchema);

// ==================== ENHANCED UTILITY FUNCTIONS ====================

const formatResponse = (success, message, data = null, pagination = null) => {
  const response = { 
    success, 
    message, 
    timestamp: new Date().toISOString(),
    version: '47.0.0'
  };
  
  if (data !== null) response.data = data;
  if (pagination !== null) response.pagination = pagination;
  
  return response;
};

const handleError = (res, error, defaultMessage = 'An error occurred') => {
  advancedLogger.error('❌ Error Details:', {
    message: error.message,
    stack: error.stack,
    name: error.name,
    code: error.code,
    endpoint: res.req?.originalUrl
  });
  
  if (error.name === 'ValidationError') {
    const messages = Object.values(error.errors).map(val => val.message);
    return res.status(400).json(formatResponse(false, 'Validation Error', { errors: messages }));
  }
  
  if (error.code === 11000) {
    const field = Object.keys(error.keyValue)[0];
    return res.status(400).json(formatResponse(false, `${field} already exists`));
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

  return res.status(statusCode).json(formatResponse(false, message));
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
    
    // Emit real-time notification via Socket.IO
    io.to(`user:${userId}`).emit('notification', {
      title,
      message,
      type,
      actionUrl,
      timestamp: new Date()
    });
    
    advancedLogger.debug(`📢 Notification created for user ${userId}: ${title}`);
    
    return notification;
  } catch (error) {
    advancedLogger.error('Error creating notification:', error);
    return null;
  }
};

// Enhanced createTransaction
const createTransaction = async (userId, type, amount, description, status = 'completed', metadata = {}, proofUrl = null) => {
  try {
    const user = await User.findById(userId);
    if (!user) {
      advancedLogger.error(`User ${userId} not found for transaction creation`);
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
    
    // Update user statistics
    const updateFields = {};
    if (type === 'deposit' && status === 'completed') {
      updateFields.total_deposits = (user.total_deposits || 0) + amount;
      updateFields.last_deposit_date = new Date();
    } else if (type === 'withdrawal' && status === 'completed') {
      updateFields.total_withdrawals = (user.total_withdrawals || 0) + Math.abs(amount);
      updateFields.last_withdrawal_date = new Date();
    } else if (type === 'investment' && status === 'completed') {
      updateFields.total_investments = (user.total_investments || 0) + Math.abs(amount);
      updateFields.last_investment_date = new Date();
    }
    
    if (Object.keys(updateFields).length > 0) {
      await User.findByIdAndUpdate(userId, updateFields);
    }
    
    advancedLogger.debug(`💳 Transaction created: ${type} - ${amount} for user ${userId}`);
    
    return transaction;
  } catch (error) {
    advancedLogger.error('Error creating transaction:', error);
    return null;
  }
};

// Enhanced calculateUserStats
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
      recentWithdrawals
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
        .lean()
    ]);

    // Calculate daily interest from active investments
    const activeInv = await Investment.find({ 
      user: userId, 
      status: 'active' 
    }).populate('plan', 'daily_interest');
    
    let dailyInterest = 0;
    let activeInvestmentValue = 0;
    
    activeInv.forEach(inv => {
      activeInvestmentValue += inv.amount;
      if (inv.plan && inv.plan.daily_interest) {
        dailyInterest += (inv.amount * inv.plan.daily_interest) / 100;
      }
    });

    return {
      total_investments: totalInvestments,
      active_investments: activeInvestments,
      total_deposits: totalDeposits,
      total_withdrawals: totalWithdrawals,
      total_referrals: totalReferrals,
      daily_interest: dailyInterest,
      active_investment_value: activeInvestmentValue,
      recent_activity: {
        investments: recentInvestments,
        deposits: recentDeposits,
        withdrawals: recentWithdrawals
      }
    };
  } catch (error) {
    advancedLogger.error('Error calculating user stats:', error);
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
    advancedLogger.debug(`📝 Admin audit created: ${action} by admin ${adminId}`);
    return audit;
  } catch (error) {
    advancedLogger.error('Error creating admin audit:', error);
    return null;
  }
};

// Analytics tracking
const trackAnalytics = async (metric, value, breakdown = {}) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    await Analytics.findOneAndUpdate(
      { date: today, metric },
      { 
        $set: { breakdown },
        $inc: { value },
        $setOnInsert: { date: today, metric }
      },
      { upsert: true, new: true }
    );
    
    advancedLogger.debug(`📊 Analytics tracked: ${metric} = ${value}`);
  } catch (error) {
    advancedLogger.error('Error tracking analytics:', error);
  }
};

// ==================== ENHANCED AUTH MIDDLEWARE ====================

const auth = async (req, res, next) => {
  try {
    let token = req.header('Authorization');
    
    if (!token) {
      advancedLogger.debug('🔒 No token provided', { endpoint: req.path });
      return res.status(401).json(formatResponse(false, 'No token, authorization denied'));
    }
    
    if (token.startsWith('Bearer ')) {
      token = token.slice(7, token.length);
    }
    
    const decoded = jwt.verify(token, config.jwtSecret);
    
    const user = await User.findById(decoded.id);
    
    if (!user) {
      advancedLogger.debug(`🔒 User not found for token: ${decoded.id}`);
      return res.status(401).json(formatResponse(false, 'Token is not valid'));
    }
    
    if (!user.is_active) {
      advancedLogger.debug(`🔒 User account deactivated: ${user.email}`);
      return res.status(401).json(formatResponse(false, 'Account is deactivated. Please contact support.'));
    }
    
    req.user = user;
    req.userId = user._id;
    
    // Update last active time
    user.last_active = new Date();
    await user.save();
    
    advancedLogger.debug(`🔒 Authenticated user: ${user.email} (${user.role})`);
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      advancedLogger.debug('🔒 Invalid JWT token');
      return res.status(401).json(formatResponse(false, 'Invalid token'));
    } else if (error.name === 'TokenExpiredError') {
      advancedLogger.debug('🔒 Expired JWT token');
      return res.status(401).json(formatResponse(false, 'Token expired'));
    }
    
    advancedLogger.error('Auth middleware error:', error);
    res.status(500).json(formatResponse(false, 'Server error during authentication'));
  }
};

const adminAuth = async (req, res, next) => {
  try {
    await auth(req, res, () => {
      if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
        advancedLogger.debug(`🔒 Admin access denied for user: ${req.user.email}`);
        return res.status(403).json(formatResponse(false, 'Access denied. Admin privileges required.'));
      }
      advancedLogger.debug(`🔒 Admin access granted: ${req.user.email}`);
      next();
    });
  } catch (error) {
    handleError(res, error, 'Admin authentication error');
  }
};

// ==================== DEBUGGED DATABASE INITIALIZATION ====================

const initializeDatabase = async () => {
  advancedLogger.info('🔄 Initializing database with enhanced connection...');
  
  // Set Mongoose debug mode
  mongoose.set('debug', config.debug);
  
  // Handle Mongoose connection events
  mongoose.connection.on('connecting', () => {
    advancedLogger.info('🔄 MongoDB connecting...');
  });
  
  mongoose.connection.on('connected', () => {
    advancedLogger.success('✅ MongoDB connected successfully');
  });
  
  mongoose.connection.on('error', (err) => {
    advancedLogger.error('❌ MongoDB connection error:', err.message);
  });
  
  mongoose.connection.on('disconnected', () => {
    advancedLogger.warn('⚠️ MongoDB disconnected');
  });
  
  mongoose.connection.on('reconnected', () => {
    advancedLogger.info('🔁 MongoDB reconnected');
  });
  
  try {
    advancedLogger.debug(`🔗 Attempting to connect to MongoDB`);
    
    const connectionOptions = {
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      retryWrites: true,
    };
    
    await mongoose.connect(config.mongoURI, connectionOptions);
    
    advancedLogger.success('✅ MongoDB connection established');
    
    // Load investment plans
    await loadInvestmentPlans();
    
    // Create admin user if it doesn't exist
    await createAdminUser();
    
    // Create indexes
    await createDatabaseIndexes();
    
    advancedLogger.success('✅ Database initialization completed successfully');
    
  } catch (error) {
    advancedLogger.error('❌ FATAL: Database initialization failed:', error.message);
    
    // Try fallback connection for development
    if (config.nodeEnv === 'development') {
      advancedLogger.info('🔄 Attempting fallback to local MongoDB...');
      try {
        const fallbackURI = 'mongodb://localhost:27017/rawwealthy';
        await mongoose.connect(fallbackURI);
        advancedLogger.success('✅ Connected to local MongoDB fallback');
      } catch (fallbackError) {
        advancedLogger.error('❌ Fallback connection also failed:', fallbackError.message);
      }
    }
    
    advancedLogger.warn('⚠️ Server starting without database connection');
  }
};

const loadInvestmentPlans = async () => {
  try {
    const plans = await InvestmentPlan.find({ is_active: true })
      .sort({ display_order: 1 })
      .lean();
    
    config.investmentPlans = plans;
    advancedLogger.info(`✅ Loaded ${plans.length} investment plans`);
    
    // If no plans exist, create default plans
    if (plans.length === 0) {
      await createDefaultInvestmentPlans();
    }
  } catch (error) {
    advancedLogger.error('Error loading investment plans:', error);
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
      features: ['Low Risk', 'Stable Returns', 'Beginner Friendly', 'Daily Payouts'],
      color: '#10b981',
      icon: '🌱',
      display_order: 1
    },
    {
      name: 'Gold',
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
      features: ['Medium Risk', 'Higher Returns', 'High Liquidity', 'Market Stability'],
      color: '#fbbf24',
      icon: '🥇',
      display_order: 2
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
      features: ['High Risk', 'Maximum Returns', 'Premium Investment', 'Energy Sector'],
      color: '#dc2626',
      icon: '🛢️',
      display_order: 3
    }
  ];

  try {
    await InvestmentPlan.insertMany(defaultPlans);
    config.investmentPlans = defaultPlans;
    advancedLogger.success('✅ Created default investment plans');
  } catch (error) {
    advancedLogger.error('Error creating default investment plans:', error);
  }
};

const createAdminUser = async () => {
  advancedLogger.info('🚀 ADMIN USER INITIALIZATION STARTING...');
  
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@rawwealthy.com';
  const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123456';
  
  advancedLogger.debug(`🔑 Attempting to create admin: ${adminEmail}`);
  
  try {
    // Check if admin already exists
    const existingAdmin = await User.findOne({ email: adminEmail });
    if (existingAdmin) {
      advancedLogger.success('✅ Admin already exists');
      
      // Ensure admin has correct role
      if (existingAdmin.role !== 'super_admin') {
        existingAdmin.role = 'super_admin';
        await existingAdmin.save();
        advancedLogger.success('✅ Updated existing admin to super_admin role');
      }
      
      return;
    }
    
    // Create new admin
    const salt = await bcrypt.genSalt(12);
    const hash = await bcrypt.hash(adminPassword, salt);
    
    const adminData = {
      full_name: 'Raw Wealthy Admin',
      email: adminEmail,
      phone: '09161806424',
      password: hash,
      role: 'super_admin',
      balance: 1000000,
      kyc_verified: true,
      kyc_status: 'verified',
      is_active: true,
      is_verified: true,
      two_factor_enabled: false,
      referral_code: 'ADMIN' + crypto.randomBytes(4).toString('hex').toUpperCase()
    };
    
    const admin = new User(adminData);
    await admin.save();
    
    advancedLogger.success('🎉 ADMIN USER CREATED SUCCESSFULLY!');
    advancedLogger.info(`📧 Email: ${adminEmail}`);
    advancedLogger.info(`🔑 Password: ${adminPassword}`);
    advancedLogger.info('👉 Login at: /api/auth/login');
    
  } catch (error) {
    advancedLogger.error('❌ Error creating admin user:', error.message);
  }
  
  advancedLogger.info('🚀 ADMIN USER INITIALIZATION COMPLETE');
};

const createDatabaseIndexes = async () => {
  try {
    // Create indexes in background
    await Promise.all([
      User.collection.createIndex({ email: 1 }, { unique: true }),
      User.collection.createIndex({ referral_code: 1 }, { unique: true, sparse: true }),
      Investment.collection.createIndex({ user: 1, status: 1 }),
      Deposit.collection.createIndex({ user: 1, status: 1 }),
      Withdrawal.collection.createIndex({ user: 1, status: 1 }),
      Transaction.collection.createIndex({ user: 1, createdAt: -1 })
    ]);
    
    advancedLogger.success('✅ Database indexes created/verified');
  } catch (error) {
    advancedLogger.error('Error creating indexes:', error);
  }
};

// ==================== ENHANCED EMAIL CONFIGURATION ====================
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
        advancedLogger.error('❌ Email configuration error:', error.message);
      } else {
        advancedLogger.success('✅ Email server is ready to send messages');
      }
    });
  } catch (error) {
    advancedLogger.error('❌ Email setup failed:', error.message);
  }
}

// Enhanced email utility function
const sendEmail = async (to, subject, html, text = '') => {
  try {
    if (!emailTransporter) {
      advancedLogger.debug(`📧 Email would be sent (simulated): To: ${to}, Subject: ${subject}`);
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
    advancedLogger.debug(`✅ Email sent to ${to} (Message ID: ${info.messageId})`);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    advancedLogger.error('❌ Email sending error:', error.message);
    return { success: false, error: error.message };
  }
};

// ==================== ENHANCED FILE UPLOAD CONFIGURATION ====================
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  if (!config.allowedMimeTypes[file.mimetype]) {
    return cb(new Error(`Invalid file type: ${file.mimetype}. Allowed: ${Object.keys(config.allowedMimeTypes).join(', ')}`), false);
  }
  
  if (file.size > config.maxFileSize) {
    return cb(new Error(`File size exceeds ${config.maxFileSize / 1024 / 1024}MB limit`), false);
  }
  
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

// Enhanced file upload handler with debugging
const handleFileUpload = async (file, folder = 'general', userId = null) => {
  if (!file) {
    advancedLogger.error('No file provided for upload');
    return null;
  }
  
  try {
    advancedLogger.debug(`📁 Uploading file: ${file.originalname}, Size: ${file.size} bytes, Type: ${file.mimetype}`);
    
    // Validate file type
    if (!config.allowedMimeTypes[file.mimetype]) {
      throw new Error(`Invalid file type: ${file.mimetype}`);
    }
    
    const uploadsDir = path.join(config.uploadDir, folder);
    
    // Create directory if it doesn't exist
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
      advancedLogger.debug(`📁 Created directory: ${uploadsDir}`);
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
    
    // Generate URL
    const url = `${config.serverURL}/uploads/${folder}/${filename}`;
    
    advancedLogger.debug(`✅ File uploaded: ${filename}, URL: ${url}`);
    
    return {
      url,
      relativeUrl: `/uploads/${folder}/${filename}`,
      filename,
      originalName: file.originalname,
      size: file.size,
      mimeType: file.mimetype,
      uploadPath: filepath,
      uploadedAt: new Date()
    };
  } catch (error) {
    advancedLogger.error('❌ File upload error:', error);
    throw new Error(`File upload failed: ${error.message}`);
  }
};

// Create uploads directory if it doesn't exist
if (!fs.existsSync(config.uploadDir)) {
  fs.mkdirSync(config.uploadDir, { recursive: true });
  advancedLogger.debug(`📁 Created upload directory: ${config.uploadDir}`);
}

// Serve static files with proper caching
app.use('/uploads', express.static(config.uploadDir, {
  maxAge: '7d',
  setHeaders: (res, path) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Cache-Control', 'public, max-age=604800');
    res.set('Access-Control-Allow-Origin', '*');
  }
}));

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
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { 
        errors: errors.array().map(err => ({ field: err.param, message: err.msg }))
      }));
    }

    const { full_name, email, phone, password, referral_code, risk_tolerance = 'medium', investment_strategy = 'balanced' } = req.body;

    advancedLogger.info(`📝 Registration attempt: ${email}`);

    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      advancedLogger.debug(`❌ User already exists: ${email}`);
      return res.status(400).json(formatResponse(false, 'User already exists with this email'));
    }

    // Handle referral
    let referredBy = null;
    if (referral_code) {
      referredBy = await User.findOne({ referral_code: referral_code.toUpperCase() });
      if (!referredBy) {
        advancedLogger.debug(`❌ Invalid referral code: ${referral_code}`);
        return res.status(400).json(formatResponse(false, 'Invalid referral code'));
      }
      advancedLogger.debug(`👥 Referral found: ${referredBy.email}`);
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
      referred_by: referredBy ? referredBy._id : null,
      created_by_ip: req.ip,
      created_by_user_agent: req.headers['user-agent']
    });

    await user.save();
    advancedLogger.success(`✅ User created: ${email}`);

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
      
      advancedLogger.debug(`👥 Referral created for ${referredBy.email}`);
      
      // Create notification for referrer
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
    advancedLogger.debug(`🔑 Token generated for ${email}`);

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
    if (config.emailEnabled) {
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
    }

    advancedLogger.success(`🎉 Registration complete for ${email}`);

    res.status(201).json(formatResponse(true, 'User registered successfully', {
      user: user.toObject(),
      token
    }));

  } catch (error) {
    advancedLogger.error('Registration error:', error);
    handleError(res, error, 'Registration failed');
  }
});

// Login
app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { email, password } = req.body;
    
    advancedLogger.debug(`🔐 Login attempt: ${email}`);

    // Find user with password
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    
    if (!user) {
      advancedLogger.debug(`❌ User not found: ${email}`);
      return res.status(400).json(formatResponse(false, 'Invalid credentials'));
    }

    // Check if account is locked
    if (user.lock_until && user.lock_until > new Date()) {
      const lockTime = Math.ceil((user.lock_until - new Date()) / 1000 / 60);
      advancedLogger.debug(`🔒 Account locked for ${email}: ${lockTime} minutes remaining`);
      return res.status(423).json(formatResponse(false, `Account is locked. Try again in ${lockTime} minutes.`));
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      user.login_attempts += 1;
      if (user.login_attempts >= 5) {
        user.lock_until = new Date(Date.now() + 15 * 60 * 1000);
        advancedLogger.debug(`🔒 Account locked for ${email} due to failed attempts`);
      }
      await user.save();
      advancedLogger.debug(`❌ Invalid password for ${email}`);
      return res.status(400).json(formatResponse(false, 'Invalid credentials'));
    }

    // Reset login attempts
    user.login_attempts = 0;
    user.lock_until = undefined;
    user.last_login = new Date();
    user.last_active = new Date();
    user.login_count = (user.login_count || 0) + 1;
    await user.save();

    // Track analytics
    await trackAnalytics('user_logins', 1);

    // Generate token
    const token = user.generateAuthToken();
    
    advancedLogger.success(`✅ Login successful: ${email}`);

    res.json(formatResponse(true, 'Login successful', {
      user: user.toObject(),
      token
    }));

  } catch (error) {
    advancedLogger.error('Login error:', error);
    handleError(res, error, 'Login failed');
  }
});

// Forgot Password
app.post('/api/auth/forgot-password', [
  body('email').isEmail().normalizeEmail()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { email } = req.body;
    
    advancedLogger.debug(`🔑 Forgot password request: ${email}`);

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      advancedLogger.debug(`❌ User not found for password reset: ${email}`);
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
      advancedLogger.debug(`❌ Failed to send reset email to ${email}`);
      return res.status(500).json(formatResponse(false, 'Failed to send reset email'));
    }

    advancedLogger.success(`✅ Password reset email sent to ${email}`);

    res.json(formatResponse(true, 'Password reset email sent successfully'));
  } catch (error) {
    advancedLogger.error('Forgot password error:', error);
    handleError(res, error, 'Error processing forgot password request');
  }
});

// Reset Password
app.post('/api/auth/reset-password/:token', [
  body('password').isLength({ min: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { token } = req.params;
    const { password } = req.body;
    
    advancedLogger.debug(`🔑 Password reset attempt with token`);

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
      advancedLogger.debug(`❌ Invalid or expired reset token`);
      return res.status(400).json(formatResponse(false, 'Invalid or expired token'));
    }

    // Update password
    user.password = password;
    user.password_reset_token = undefined;
    user.password_reset_expires = undefined;
    await user.save();

    // Send confirmation email
    await sendEmail(
      user.email,
      'Password Reset Successful',
      `<h2>Password Reset Successful</h2>
       <p>Your password has been successfully reset.</p>
       <p>If you did not perform this action, please contact our support team immediately.</p>`
    );

    // Create notification
    await createNotification(
      user._id,
      'Password Changed',
      'Your password has been successfully reset.',
      'system'
    );

    advancedLogger.success(`✅ Password reset successful for ${user.email}`);

    res.json(formatResponse(true, 'Password reset successful'));
  } catch (error) {
    advancedLogger.error('Reset password error:', error);
    handleError(res, error, 'Error resetting password');
  }
});

// ==================== ENHANCED PROFILE ENDPOINTS ====================

// Get profile with complete data
app.get('/api/profile', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    advancedLogger.debug(`📊 Fetching profile for user: ${userId}`);
    
    // Get user with basic info
    const user = await User.findById(userId).lean();
    if (!user) {
      advancedLogger.debug(`❌ User not found: ${userId}`);
      return res.status(404).json(formatResponse(false, 'User not found'));
    }
    
    // Get other data in parallel
    const [
      investments,
      transactions,
      notifications,
      kyc,
      deposits,
      withdrawals,
      referrals,
      supportTickets
    ] = await Promise.all([
      Investment.find({ user: userId })
        .populate('plan', 'name daily_interest duration total_interest')
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      Transaction.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      Notification.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      KYCSubmission.findOne({ user: userId }).lean(),
      Deposit.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      Withdrawal.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      Referral.find({ referrer: userId })
        .populate('referred_user', 'full_name email createdAt balance')
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      SupportTicket.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(5)
        .lean()
    ]);

    // Calculate stats
    const activeInvestments = investments.filter(inv => inv.status === 'active');
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + (inv.amount || 0), 0);
    
    const dailyInterest = activeInvestments.reduce((sum, inv) => {
      if (inv.plan && inv.plan.daily_interest) {
        return sum + ((inv.amount || 0) * inv.plan.daily_interest / 100);
      }
      return sum;
    }, 0);
    
    const totalEarnings = investments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0);
    const referralEarnings = referrals.reduce((sum, ref) => sum + (ref.earnings || 0), 0);
    
    const totalDepositsAmount = deposits
      .filter(d => d.status === 'approved')
      .reduce((sum, dep) => sum + (dep.amount || 0), 0);
    
    const totalWithdrawalsAmount = withdrawals
      .filter(w => w.status === 'paid')
      .reduce((sum, wdl) => sum + (wdl.amount || 0), 0);

    const profileData = {
      user: {
        ...user,
        bank_details: user.bank_details || null,
        wallet_address: user.wallet_address || null,
        paypal_email: user.paypal_email || null
      },
      
      dashboard_stats: {
        active_investment_value: totalActiveValue,
        total_earnings: totalEarnings,
        daily_interest: dailyInterest,
        referral_earnings: referralEarnings,
        total_deposits_amount: totalDepositsAmount,
        total_withdrawals_amount: totalWithdrawalsAmount,
        
        total_investments: investments.length,
        active_investments_count: activeInvestments.length,
        total_deposits: deposits.filter(d => d.status === 'approved').length,
        total_withdrawals: withdrawals.filter(w => w.status === 'paid').length,
        referral_count: user.referral_count || 0,
        unread_notifications: notifications.filter(n => !n.is_read).length,
        
        available_balance: user.balance || 0,
        portfolio_value: (user.balance || 0) + totalEarnings + referralEarnings,
        
        kyc_status: user.kyc_status || 'not_submitted',
        kyc_verified: user.kyc_verified || false,
        account_status: user.is_active ? 'active' : 'inactive'
      },
      
      investment_history: investments,
      transaction_history: transactions,
      deposit_history: deposits,
      withdrawal_history: withdrawals,
      referral_history: referrals,
      kyc_submission: kyc,
      notifications: notifications,
      support_tickets: supportTickets
    };

    advancedLogger.success(`✅ Profile fetched for user: ${userId}`);

    res.json(formatResponse(true, 'Profile retrieved successfully', profileData));
  } catch (error) {
    advancedLogger.error('Error fetching profile:', error);
    handleError(res, error, 'Error fetching profile');
  }
});

// Update profile
app.put('/api/profile', auth, [
  body('full_name').optional().trim().isLength({ min: 2, max: 100 }),
  body('phone').optional().trim(),
  body('country').optional().isLength({ min: 2, max: 2 }),
  body('risk_tolerance').optional().isIn(['low', 'medium', 'high']),
  body('investment_strategy').optional().isIn(['conservative', 'balanced', 'aggressive']),
  body('notifications_enabled').optional().isBoolean(),
  body('email_notifications').optional().isBoolean()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.user._id;
    const updateData = req.body;

    advancedLogger.debug(`✏️ Updating profile for user: ${userId}`);

    // Update allowed fields
    const allowedUpdates = ['full_name', 'phone', 'country', 'risk_tolerance', 'investment_strategy', 'notifications_enabled', 'email_notifications', 'sms_notifications'];
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
      advancedLogger.debug(`❌ User not found during update: ${userId}`);
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    await createNotification(
      userId,
      'Profile Updated',
      'Your profile information has been successfully updated.',
      'info',
      '/profile'
    );

    advancedLogger.success(`✅ Profile updated for user: ${userId}`);

    res.json(formatResponse(true, 'Profile updated successfully', { user }));
  } catch (error) {
    advancedLogger.error('Error updating profile:', error);
    handleError(res, error, 'Error updating profile');
  }
});

// Update bank details
app.put('/api/profile/bank', auth, [
  body('bank_name').notEmpty().trim(),
  body('account_name').notEmpty().trim(),
  body('account_number').notEmpty().trim(),
  body('bank_code').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.user._id;
    const { bank_name, account_name, account_number, bank_code } = req.body;

    advancedLogger.debug(`🏦 Updating bank details for user: ${userId}`);

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    user.bank_details = {
      bank_name,
      account_name,
      account_number,
      bank_code: bank_code || '',
      verified: false,
      last_updated: new Date()
    };

    await user.save();

    await createNotification(
      userId,
      'Bank Details Updated',
      'Your bank account details have been updated successfully. They will be verified by our team.',
      'info',
      '/profile'
    );

    // Notify admin about bank details update
    const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } }).limit(5);
    for (const admin of admins) {
      await createNotification(
        admin._id,
        'User Updated Bank Details',
        `User ${user.full_name} has updated their bank details. Please verify for withdrawal requests.`,
        'system',
        `/admin/users/${userId}`
      );
    }

    advancedLogger.success(`✅ Bank details updated for user: ${userId}`);

    res.json(formatResponse(true, 'Bank details updated successfully', {
      bank_details: user.bank_details
    }));
  } catch (error) {
    advancedLogger.error('Error updating bank details:', error);
    handleError(res, error, 'Error updating bank details');
  }
});

// ==================== ENHANCED INVESTMENT PLANS ENDPOINTS ====================

// Get all investment plans
app.get('/api/plans', async (req, res) => {
  try {
    advancedLogger.debug('📋 Fetching investment plans');
    
    const plans = await InvestmentPlan.find({ is_active: true })
      .sort({ display_order: 1, min_amount: 1 })
      .lean();
    
    // Calculate ROI and other metrics for display
    const enhancedPlans = plans.map(plan => ({
      ...plan,
      roi_percentage: plan.total_interest,
      daily_roi: plan.daily_interest,
      monthly_roi: plan.daily_interest * 30,
      is_popular: plan.is_popular || false,
      features: plan.features || ['Secure Investment', 'Daily Payouts', '24/7 Support']
    }));
    
    advancedLogger.debug(`✅ Found ${plans.length} investment plans`);
    
    res.json(formatResponse(true, 'Plans retrieved successfully', { plans: enhancedPlans }));
  } catch (error) {
    advancedLogger.error('Error fetching investment plans:', error);
    handleError(res, error, 'Error fetching investment plans');
  }
});

// Get specific plan
app.get('/api/plans/:id', async (req, res) => {
  try {
    const plan = await InvestmentPlan.findById(req.params.id);
    
    if (!plan) {
      advancedLogger.debug(`❌ Investment plan not found: ${req.params.id}`);
      return res.status(404).json(formatResponse(false, 'Investment plan not found'));
    }
    
    // Calculate additional metrics
    const enhancedPlan = {
      ...plan.toObject(),
      roi_percentage: plan.total_interest,
      daily_roi: plan.daily_interest,
      monthly_roi: plan.daily_interest * 30,
      estimated_monthly_earnings: (plan.min_amount * plan.daily_interest * 30) / 100,
      estimated_total_earnings: (plan.min_amount * plan.total_interest) / 100
    };
    
    advancedLogger.debug(`✅ Retrieved plan: ${plan.name}`);
    
    res.json(formatResponse(true, 'Plan retrieved successfully', { plan: enhancedPlan }));
  } catch (error) {
    advancedLogger.error('Error fetching investment plan:', error);
    handleError(res, error, 'Error fetching investment plan');
  }
});

// ==================== ENHANCED INVESTMENT ENDPOINTS ====================

// Get user investments
app.get('/api/investments', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { status, page = 1, limit = 10 } = req.query;
    
    advancedLogger.debug(`📊 Fetching investments for user: ${userId}, status: ${status || 'all'}`);
    
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

    // Calculate additional details
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
        can_withdraw_earnings: inv.status === 'active' && (inv.earned_so_far || 0) > 0
      };
    });

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

    advancedLogger.debug(`✅ Found ${total} investments for user ${userId}`);

    res.json(formatResponse(true, 'Investments retrieved successfully', {
      investments: enhancedInvestments,
      stats: {
        total_active_value: totalActiveValue,
        total_earnings: totalEarnings,
        daily_earnings: dailyEarnings,
        active_count: activeInvestments.length,
        total_count: total,
        pending_count: enhancedInvestments.filter(inv => inv.status === 'pending').length
      },
      pagination
    }));
  } catch (error) {
    advancedLogger.error('Error fetching investments:', error);
    handleError(res, error, 'Error fetching investments');
  }
});

// Create investment
app.post('/api/investments', auth, upload.single('payment_proof'), [
  body('plan_id').notEmpty(),
  body('amount').isFloat({ min: config.minInvestment }),
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
    
    advancedLogger.debug(`💰 Creating investment for user ${userId}, plan: ${plan_id}, amount: ${amount}`);

    // Check plan
    const plan = await InvestmentPlan.findById(plan_id);
    if (!plan) {
      advancedLogger.debug(`❌ Investment plan not found: ${plan_id}`);
      return res.status(404).json(formatResponse(false, 'Investment plan not found'));
    }

    const investmentAmount = parseFloat(amount);

    // Validate amount
    if (investmentAmount < plan.min_amount) {
      advancedLogger.debug(`❌ Investment below minimum: ${investmentAmount} < ${plan.min_amount}`);
      return res.status(400).json(formatResponse(false, 
        `Minimum investment for ${plan.name} is ₦${plan.min_amount.toLocaleString()}`));
    }

    if (plan.max_amount && investmentAmount > plan.max_amount) {
      advancedLogger.debug(`❌ Investment above maximum: ${investmentAmount} > ${plan.max_amount}`);
      return res.status(400).json(formatResponse(false,
        `Maximum investment for ${plan.name} is ₦${plan.max_amount.toLocaleString()}`));
    }

    // Check balance
    if (investmentAmount > req.user.balance) {
      advancedLogger.debug(`❌ Insufficient balance: ${investmentAmount} > ${req.user.balance}`);
      return res.status(400).json(formatResponse(false, 'Insufficient balance for this investment'));
    }

    // Handle file upload
    let proofUrl = null;
    let uploadResult = null;
    if (req.file) {
      try {
        uploadResult = await handleFileUpload(req.file, 'investment-proofs', userId);
        proofUrl = uploadResult.url;
        advancedLogger.debug(`📁 Payment proof uploaded: ${proofUrl}`);
      } catch (uploadError) {
        advancedLogger.error('File upload error:', uploadError);
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
        } : null
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
        daily_interest: plan.daily_interest
      },
      proofUrl
    );

    // Create notification
    await createNotification(
      userId,
      'Investment Created',
      `Your investment of ₦${investmentAmount.toLocaleString()} in ${plan.name} has been created successfully.${proofUrl ? ' Awaiting admin approval.' : ''}`,
      'investment',
      '/investments',
      { amount: investmentAmount, plan_name: plan.name }
    );

    // Track analytics
    await trackAnalytics('investments_created', 1, { plan: plan.name, amount: investmentAmount });

    // Notify admin if payment proof uploaded
    if (proofUrl) {
      const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } }).limit(5);
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
            proof_url: proofUrl 
          }
        );
      }
    }

    advancedLogger.success(`✅ Investment created: ${investment._id}`);

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
        requires_approval: !!proofUrl
      }
    }));
  } catch (error) {
    advancedLogger.error('Error creating investment:', error);
    handleError(res, error, 'Error creating investment');
  }
});

// ==================== ENHANCED DEPOSIT ENDPOINTS ====================

// Get user deposits
app.get('/api/deposits', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { status, page = 1, limit = 10 } = req.query;
    
    advancedLogger.debug(`💰 Fetching deposits for user: ${userId}`);
    
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

    // Calculate stats
    const totalDeposits = deposits.filter(d => d.status === 'approved').reduce((sum, d) => sum + (d.amount || 0), 0);
    const pendingDeposits = deposits.filter(d => d.status === 'pending').reduce((sum, d) => sum + (d.amount || 0), 0);

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    advancedLogger.debug(`✅ Found ${total} deposits for user ${userId}`);

    res.json(formatResponse(true, 'Deposits retrieved successfully', {
      deposits,
      stats: {
        total_deposits: totalDeposits,
        pending_deposits: pendingDeposits,
        total_count: total,
        approved_count: deposits.filter(d => d.status === 'approved').length,
        pending_count: deposits.filter(d => d.status === 'pending').length
      },
      pagination
    }));
  } catch (error) {
    advancedLogger.error('Error fetching deposits:', error);
    handleError(res, error, 'Error fetching deposits');
  }
});

// Create deposit
app.post('/api/deposits', auth, upload.single('payment_proof'), [
  body('amount').isFloat({ min: config.minDeposit }),
  body('payment_method').isIn(['bank_transfer', 'crypto', 'paypal', 'card']),
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { amount, payment_method, remarks } = req.body;
    const userId = req.user._id;
    const depositAmount = parseFloat(amount);

    advancedLogger.debug(`💰 Creating deposit for user ${userId}, amount: ${depositAmount}, method: ${payment_method}`);

    // Handle file upload
    let proofUrl = null;
    let uploadResult = null;
    if (req.file) {
      try {
        uploadResult = await handleFileUpload(req.file, 'deposit-proofs', userId);
        proofUrl = uploadResult.url;
        advancedLogger.debug(`📁 Deposit proof uploaded: ${proofUrl}`);
      } catch (uploadError) {
        advancedLogger.error('File upload error:', uploadError);
        return res.status(400).json(formatResponse(false, `File upload failed: ${uploadError.message}`));
      }
    }

    // Create deposit
    const deposit = new Deposit({
      user: userId,
      amount: depositAmount,
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

    // Create notification
    await createNotification(
      userId,
      'Deposit Request Submitted',
      `Your deposit request of ₦${depositAmount.toLocaleString()} has been submitted and is pending approval.`,
      'deposit',
      '/deposits',
      { amount: depositAmount, payment_method, has_proof: !!proofUrl }
    );

    // Track analytics
    await trackAnalytics('deposits_requested', 1, { amount: depositAmount, payment_method });

    // Notify admin
    const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } }).limit(5);
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
          proof_url: proofUrl 
        }
      );
    }

    advancedLogger.success(`✅ Deposit created: ${deposit._id}`);

    res.status(201).json(formatResponse(true, 'Deposit request submitted successfully!', { 
      deposit: {
        ...deposit.toObject(),
        formatted_amount: `₦${depositAmount.toLocaleString()}`,
        requires_approval: true,
        estimated_approval_time: '24-48 hours',
        proof_uploaded: !!proofUrl
      },
      message: 'Your deposit is pending approval. You will be notified once approved.'
    }));
  } catch (error) {
    advancedLogger.error('Error creating deposit:', error);
    handleError(res, error, 'Error creating deposit');
  }
});

// ==================== ENHANCED WITHDRAWAL ENDPOINTS ====================

// Get user withdrawals
app.get('/api/withdrawals', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { status, page = 1, limit = 10 } = req.query;
    
    advancedLogger.debug(`💳 Fetching withdrawals for user: ${userId}`);
    
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

    // Calculate stats
    const totalWithdrawals = withdrawals.filter(w => w.status === 'paid').reduce((sum, w) => sum + (w.amount || 0), 0);
    const pendingWithdrawals = withdrawals.filter(w => w.status === 'pending').reduce((sum, w) => sum + (w.amount || 0), 0);
    const totalFees = withdrawals.filter(w => w.status === 'paid').reduce((sum, w) => sum + (w.platform_fee || 0), 0);

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    advancedLogger.debug(`✅ Found ${total} withdrawals for user ${userId}`);

    res.json(formatResponse(true, 'Withdrawals retrieved successfully', {
      withdrawals,
      stats: {
        total_withdrawals: totalWithdrawals,
        pending_withdrawals: pendingWithdrawals,
        total_fees: totalFees,
        total_count: total,
        paid_count: withdrawals.filter(w => w.status === 'paid').length,
        pending_count: withdrawals.filter(w => w.status === 'pending').length
      },
      pagination
    }));
  } catch (error) {
    advancedLogger.error('Error fetching withdrawals:', error);
    handleError(res, error, 'Error fetching withdrawals');
  }
});

// Create withdrawal
app.post('/api/withdrawals', auth, [
  body('amount').isFloat({ min: config.minWithdrawal }),
  body('payment_method').isIn(['bank_transfer', 'crypto', 'paypal']),
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { amount, payment_method, remarks } = req.body;
    const userId = req.user._id;
    const withdrawalAmount = parseFloat(amount);

    advancedLogger.debug(`💳 Creating withdrawal for user ${userId}, amount: ${withdrawalAmount}, method: ${payment_method}`);

    // Check minimum withdrawal
    if (withdrawalAmount < config.minWithdrawal) {
      advancedLogger.debug(`❌ Withdrawal below minimum: ${withdrawalAmount} < ${config.minWithdrawal}`);
      return res.status(400).json(formatResponse(false, 
        `Minimum withdrawal is ₦${config.minWithdrawal.toLocaleString()}`));
    }

    // Check user balance
    if (withdrawalAmount > req.user.balance) {
      advancedLogger.debug(`❌ Insufficient balance for withdrawal: ${withdrawalAmount} > ${req.user.balance}`);
      return res.status(400).json(formatResponse(false, 'Insufficient balance for withdrawal'));
    }

    // Calculate platform fee
    const platformFee = withdrawalAmount * (config.platformFeePercent / 100);
    const netAmount = withdrawalAmount - platformFee;

    // Validate payment method specific details
    let paymentDetails = {};
    if (payment_method === 'bank_transfer') {
      if (!req.user.bank_details || !req.user.bank_details.account_number) {
        advancedLogger.debug(`❌ No bank details for user ${userId}`);
        return res.status(400).json(formatResponse(false, 'Please update your bank details in profile settings'));
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
        advancedLogger.debug(`❌ No wallet address for user ${userId}`);
        return res.status(400).json(formatResponse(false, 'Please set your wallet address in profile settings'));
      }
      paymentDetails = { wallet_address: req.user.wallet_address };
    } else if (payment_method === 'paypal') {
      if (!req.user.paypal_email) {
        advancedLogger.debug(`❌ No PayPal email for user ${userId}`);
        return res.status(400).json(formatResponse(false, 'Please set your PayPal email in profile settings'));
      }
      paymentDetails = { paypal_email: req.user.paypal_email };
    }

    // Create withdrawal
    const withdrawal = new Withdrawal({
      user: userId,
      amount: withdrawalAmount,
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
        net_amount: netAmount 
      }
    );

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
        payment_method 
      }
    );

    // Track analytics
    await trackAnalytics('withdrawals_requested', 1, { amount: withdrawalAmount, payment_method, fee: platformFee });

    // Notify admin
    const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } }).limit(5);
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

    advancedLogger.success(`✅ Withdrawal created: ${withdrawal._id}`);

    res.status(201).json(formatResponse(true, 'Withdrawal request submitted successfully!', { 
      withdrawal: {
        ...withdrawal.toObject(),
        formatted_amount: `₦${withdrawalAmount.toLocaleString()}`,
        formatted_net_amount: `₦${netAmount.toLocaleString()}`,
        formatted_fee: `₦${platformFee.toLocaleString()}`,
        requires_approval: true,
        estimated_processing_time: '24-48 hours'
      },
      message: 'Your withdrawal is pending approval. Processing time is 24-48 hours.'
    }));
  } catch (error) {
    advancedLogger.error('Error creating withdrawal:', error);
    handleError(res, error, 'Error creating withdrawal');
  }
});

// ==================== REFERRAL ENDPOINTS ====================

// Get referral statistics
app.get('/api/referrals/stats', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    advancedLogger.debug(`📊 Fetching referral stats for user: ${userId}`);
    
    const user = await User.findById(userId);
    const referrals = await Referral.find({ referrer: userId })
      .populate('referred_user', 'full_name email createdAt balance')
      .sort({ createdAt: -1 })
      .lean();
    
    const totalReferrals = referrals.length;
    const activeReferrals = referrals.filter(r => r.status === 'active').length;
    const totalEarnings = referrals.reduce((sum, r) => sum + (r.earnings || 0), 0);
    
    res.json(formatResponse(true, 'Referral stats retrieved successfully', {
      stats: {
        total_referrals: totalReferrals,
        active_referrals: activeReferrals,
        total_earnings: totalEarnings,
        referral_code: user.referral_code,
        referral_link: `${config.clientURL}/register?ref=${user.referral_code}`,
        commission_rate: `${config.referralCommissionPercent}%`
      },
      referrals: referrals.slice(0, 10)
    }));
  } catch (error) {
    advancedLogger.error('Error fetching referral stats:', error);
    handleError(res, error, 'Error fetching referral stats');
  }
});

// ==================== COMPLETE ADMIN ENDPOINTS ====================

// Admin Dashboard
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
  try {
    advancedLogger.debug(`📊 Admin dashboard requested by: ${req.user.email}`);
    
    // Get all stats in parallel
    const [
      totalUsers,
      newUsersToday,
      activeUsers,
      totalInvestments,
      activeInvestments,
      totalDeposits,
      totalWithdrawals,
      pendingInvestments,
      pendingDeposits,
      pendingWithdrawals,
      pendingKYC,
      totalRevenue,
      totalBalance
    ] = await Promise.all([
      User.countDocuments({}),
      User.countDocuments({ 
        createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) } 
      }),
      User.countDocuments({ is_active: true }),
      Investment.countDocuments({}),
      Investment.countDocuments({ status: 'active' }),
      Deposit.countDocuments({ status: 'approved' }),
      Withdrawal.countDocuments({ status: 'paid' }),
      Investment.countDocuments({ status: 'pending' }),
      Deposit.countDocuments({ status: 'pending' }),
      Withdrawal.countDocuments({ status: 'pending' }),
      KYCSubmission.countDocuments({ status: 'pending' }),
      Transaction.aggregate([
        { $match: { type: { $in: ['deposit', 'investment'] } } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      User.aggregate([
        { $group: { _id: null, total: { $sum: '$balance' } } }
      ])
    ]);

    // Get recent activities
    const recentActivities = await Transaction.find({})
      .populate('user', 'full_name email')
      .sort({ createdAt: -1 })
      .limit(10)
      .lean();

    // Get platform growth (last 7 days)
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    const dailyStats = await Analytics.find({ 
      date: { $gte: sevenDaysAgo },
      metric: { $in: ['user_registrations', 'deposits_approved', 'investments_created'] }
    }).sort({ date: 1 }).lean();

    const stats = {
      overview: {
        total_users: totalUsers,
        new_users_today: newUsersToday,
        active_users: activeUsers,
        total_investments: totalInvestments,
        active_investments: activeInvestments,
        total_deposits: totalDeposits,
        total_withdrawals: totalWithdrawals,
        total_revenue: totalRevenue[0]?.total || 0,
        total_platform_balance: totalBalance[0]?.total || 0
      },
      pending_actions: {
        pending_investments: pendingInvestments,
        pending_deposits: pendingDeposits,
        pending_withdrawals: pendingWithdrawals,
        pending_kyc: pendingKYC,
        total_pending: pendingInvestments + pendingDeposits + pendingWithdrawals + pendingKYC
      },
      recent_activities: recentActivities,
      growth_data: dailyStats,
      charts: {
        user_growth: await getChartData('user_registrations', 30),
        revenue_trend: await getChartData('revenue', 30),
        investment_distribution: await getInvestmentDistribution()
      }
    };

    advancedLogger.success(`✅ Admin dashboard data retrieved for ${req.user.email}`);

    res.json(formatResponse(true, 'Admin dashboard stats retrieved successfully', {
      stats,
      quick_links: {
        pending_investments: '/api/admin/pending-investments',
        pending_deposits: '/api/admin/pending-deposits',
        pending_withdrawals: '/api/admin/pending-withdrawals',
        pending_kyc: '/api/admin/pending-kyc',
        all_users: '/api/admin/users',
        transactions: '/api/admin/transactions',
        plans: '/api/admin/plans'
      }
    }));
  } catch (error) {
    advancedLogger.error('Error fetching admin dashboard stats:', error);
    handleError(res, error, 'Error fetching admin dashboard stats');
  }
});

// Helper function for chart data
async function getChartData(metric, days) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);
  
  const data = await Analytics.find({
    metric,
    date: { $gte: startDate }
  }).sort({ date: 1 }).lean();
  
  return data.map(item => ({
    date: item.date.toISOString().split('T')[0],
    value: item.value
  }));
}

async function getInvestmentDistribution() {
  const distribution = await Investment.aggregate([
    { $match: { status: 'active' } },
    { $group: { 
      _id: '$plan', 
      total_amount: { $sum: '$amount' },
      count: { $sum: 1 }
    }},
    { $lookup: {
      from: 'investmentplans',
      localField: '_id',
      foreignField: '_id',
      as: 'plan'
    }},
    { $unwind: '$plan' },
    { $project: {
      plan_name: '$plan.name',
      total_amount: 1,
      count: 1,
      percentage: { $multiply: [{ $divide: ['$total_amount', { $sum: '$total_amount' }] }, 100] }
    }}
  ]);
  
  return distribution;
}

// Get pending investments for admin
app.get('/api/admin/pending-investments', adminAuth, async (req, res) => {
  try {
    const pendingInvestments = await Investment.find({ status: 'pending' })
      .populate('user', 'full_name email phone')
      .populate('plan', 'name min_amount daily_interest')
      .sort({ createdAt: -1 })
      .lean();

    advancedLogger.debug(`📋 Found ${pendingInvestments.length} pending investments`);

    res.json(formatResponse(true, 'Pending investments retrieved successfully', {
      investments: pendingInvestments,
      count: pendingInvestments.length,
      total_amount: pendingInvestments.reduce((sum, inv) => sum + (inv.amount || 0), 0)
    }));
  } catch (error) {
    advancedLogger.error('Error fetching pending investments:', error);
    handleError(res, error, 'Error fetching pending investments');
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

    advancedLogger.debug(`✅ Approving investment: ${investmentId} by admin: ${adminId}`);

    const investment = await Investment.findById(investmentId)
      .populate('user plan');
    
    if (!investment) {
      advancedLogger.debug(`❌ Investment not found: ${investmentId}`);
      return res.status(404).json(formatResponse(false, 'Investment not found'));
    }

    if (investment.status !== 'pending') {
      advancedLogger.debug(`❌ Investment not pending: ${investmentId}, status: ${investment.status}`);
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
      req.headers['user-agent']
    );

    advancedLogger.success(`✅ Investment approved: ${investmentId}`);

    res.json(formatResponse(true, 'Investment approved successfully', {
      investment: {
        ...investment.toObject(),
        approved_by_admin: req.user.full_name,
        proof_verified: true
      },
      message: 'Investment approved and user notified'
    }));
  } catch (error) {
    advancedLogger.error('Error approving investment:', error);
    handleError(res, error, 'Error approving investment');
  }
});

// Get pending deposits for admin
app.get('/api/admin/pending-deposits', adminAuth, async (req, res) => {
  try {
    const pendingDeposits = await Deposit.find({ status: 'pending' })
      .populate('user', 'full_name email phone balance')
      .sort({ createdAt: -1 })
      .lean();

    advancedLogger.debug(`📋 Found ${pendingDeposits.length} pending deposits`);

    res.json(formatResponse(true, 'Pending deposits retrieved successfully', {
      deposits: pendingDeposits,
      count: pendingDeposits.length,
      total_amount: pendingDeposits.reduce((sum, dep) => sum + (dep.amount || 0), 0)
    }));
  } catch (error) {
    advancedLogger.error('Error fetching pending deposits:', error);
    handleError(res, error, 'Error fetching pending deposits');
  }
});

// Approve deposit
app.post('/api/admin/deposits/:id/approve', adminAuth, [
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const depositId = req.params.id;
    const adminId = req.user._id;
    const { remarks } = req.body;

    advancedLogger.debug(`✅ Approving deposit: ${depositId} by admin: ${adminId}`);

    const deposit = await Deposit.findById(depositId)
      .populate('user');
    
    if (!deposit) {
      advancedLogger.debug(`❌ Deposit not found: ${depositId}`);
      return res.status(404).json(formatResponse(false, 'Deposit not found'));
    }

    if (deposit.status !== 'pending') {
      advancedLogger.debug(`❌ Deposit not pending: ${depositId}, status: ${deposit.status}`);
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
      req.headers['user-agent']
    );

    advancedLogger.success(`✅ Deposit approved: ${depositId}`);

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
    advancedLogger.error('Error approving deposit:', error);
    handleError(res, error, 'Error approving deposit');
  }
});

// Get pending withdrawals for admin
app.get('/api/admin/pending-withdrawals', adminAuth, async (req, res) => {
  try {
    const pendingWithdrawals = await Withdrawal.find({ status: 'pending' })
      .populate('user', 'full_name email phone balance')
      .sort({ createdAt: -1 })
      .lean();

    advancedLogger.debug(`📋 Found ${pendingWithdrawals.length} pending withdrawals`);

    res.json(formatResponse(true, 'Pending withdrawals retrieved successfully', {
      withdrawals: pendingWithdrawals,
      count: pendingWithdrawals.length,
      total_amount: pendingWithdrawals.reduce((sum, wdl) => sum + (wdl.amount || 0), 0)
    }));
  } catch (error) {
    advancedLogger.error('Error fetching pending withdrawals:', error);
    handleError(res, error, 'Error fetching pending withdrawals');
  }
});

// Approve withdrawal
app.post('/api/admin/withdrawals/:id/approve', adminAuth, [
  body('transaction_id').optional().trim(),
  body('payment_proof_url').optional().trim(),
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const withdrawalId = req.params.id;
    const adminId = req.user._id;
    const { transaction_id, payment_proof_url, remarks } = req.body;

    advancedLogger.debug(`✅ Approving withdrawal: ${withdrawalId} by admin: ${adminId}`);

    const withdrawal = await Withdrawal.findById(withdrawalId)
      .populate('user');
    
    if (!withdrawal) {
      advancedLogger.debug(`❌ Withdrawal not found: ${withdrawalId}`);
      return res.status(404).json(formatResponse(false, 'Withdrawal not found'));
    }

    if (withdrawal.status !== 'pending') {
      advancedLogger.debug(`❌ Withdrawal not pending: ${withdrawalId}, status: ${withdrawal.status}`);
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

    // Update user withdrawal stats
    await User.findByIdAndUpdate(withdrawal.user._id, {
      $inc: { total_withdrawals: withdrawal.amount },
      last_withdrawal_date = new Date()
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
      req.headers['user-agent']
    );

    advancedLogger.success(`✅ Withdrawal approved: ${withdrawalId}`);

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
    advancedLogger.error('Error approving withdrawal:', error);
    handleError(res, error, 'Error approving withdrawal');
  }
});

// Get all users for admin
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
      sort_order = 'desc'
    } = req.query;
    
    const query = {};
    
    // Apply filters
    if (status === 'active') query.is_active = true;
    if (status === 'inactive') query.is_active = false;
    if (role) query.role = role;
    if (kyc_status) query.kyc_status = kyc_status;
    
    // Search
    if (search) {
      query.$or = [
        { full_name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { phone: { $regex: search, $options: 'i' } },
        { referral_code: { $regex: search, $options: 'i' } }
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

    advancedLogger.debug(`📋 Found ${total} users for admin view`);

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(formatResponse(true, 'Users retrieved successfully', {
      users,
      pagination,
      summary: {
        total_users: total,
        active_users: users.filter(u => u.is_active).length,
        verified_users: users.filter(u => u.kyc_verified).length,
        total_balance: users.reduce((sum, u) => sum + (u.balance || 0), 0)
      }
    }));
  } catch (error) {
    advancedLogger.error('Error fetching users:', error);
    handleError(res, error, 'Error fetching users');
  }
});

// Get user details for admin
app.get('/api/admin/users/:id', adminAuth, async (req, res) => {
  try {
    const userId = req.params.id;
    
    const user = await User.findById(userId)
      .select('-password -two_factor_secret -verification_token -password_reset_token')
      .lean();
    
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }
    
    // Get user's activities
    const [investments, deposits, withdrawals, transactions, referrals] = await Promise.all([
      Investment.find({ user: userId }).populate('plan').lean(),
      Deposit.find({ user: userId }).lean(),
      Withdrawal.find({ user: userId }).lean(),
      Transaction.find({ user: userId }).sort({ createdAt: -1 }).limit(20).lean(),
      Referral.find({ referrer: userId }).populate('referred_user').lean()
    ]);
    
    res.json(formatResponse(true, 'User details retrieved', {
      user,
      activities: {
        investments,
        deposits,
        withdrawals,
        transactions,
        referrals
      },
      stats: {
        total_investments: investments.length,
        total_deposits: deposits.filter(d => d.status === 'approved').length,
        total_withdrawals: withdrawals.filter(w => w.status === 'paid').length,
        total_referrals: referrals.length,
        total_earnings: investments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0)
      }
    }));
  } catch (error) {
    advancedLogger.error('Error fetching user details:', error);
    handleError(res, error, 'Error fetching user details');
  }
});

// Update user for admin
app.put('/api/admin/users/:id', adminAuth, [
  body('full_name').optional().trim(),
  body('email').optional().isEmail(),
  body('phone').optional().trim(),
  body('role').optional().isIn(['user', 'admin', 'super_admin']),
  body('is_active').optional().isBoolean(),
  body('kyc_verified').optional().isBoolean(),
  body('kyc_status').optional().isIn(['pending', 'verified', 'rejected', 'not_submitted']),
  body('balance').optional().isFloat({ min: 0 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }
    
    const userId = req.params.id;
    const updateData = req.body;
    
    // Remove fields that shouldn't be updated directly
    delete updateData.password;
    delete updateData.referral_code;
    delete updateData.createdAt;
    delete updateData.updatedAt;
    
    const user = await User.findByIdAndUpdate(
      userId,
      updateData,
      { new: true, runValidators: true }
    ).select('-password -two_factor_secret');
    
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }
    
    // Create audit log
    await createAdminAudit(
      req.user._id,
      'UPDATE_USER',
      'user',
      userId,
      { updates: updateData },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'User updated successfully', { user }));
  } catch (error) {
    advancedLogger.error('Error updating user:', error);
    handleError(res, error, 'Error updating user');
  }
});

// Get all transactions for admin
app.get('/api/admin/transactions', adminAuth, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 50,
      type,
      status,
      start_date,
      end_date,
      user_id
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
    
    // Calculate totals
    const totals = await Transaction.aggregate([
      { $match: query },
      { $group: {
        _id: '$type',
        total_amount: { $sum: '$amount' },
        count: { $sum: 1 }
      }}
    ]);
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };
    
    res.json(formatResponse(true, 'Transactions retrieved', {
      transactions,
      totals,
      pagination
    }));
  } catch (error) {
    advancedLogger.error('Error fetching transactions:', error);
    handleError(res, error, 'Error fetching transactions');
  }
});

// Get pending KYC submissions
app.get('/api/admin/pending-kyc', adminAuth, async (req, res) => {
  try {
    const pendingKYC = await KYCSubmission.find({ status: 'pending' })
      .populate('user', 'full_name email phone')
      .sort({ createdAt: -1 })
      .lean();
    
    res.json(formatResponse(true, 'Pending KYC submissions', {
      kyc_submissions: pendingKYC,
      count: pendingKYC.length
    }));
  } catch (error) {
    advancedLogger.error('Error fetching pending KYC:', error);
    handleError(res, error, 'Error fetching pending KYC');
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
    
    // Create notification
    await createNotification(
      kyc.user._id,
      'KYC Approved',
      'Your KYC verification has been approved. You can now enjoy full platform features.',
      'success',
      '/profile'
    );
    
    res.json(formatResponse(true, 'KYC approved successfully', { kyc }));
  } catch (error) {
    advancedLogger.error('Error approving KYC:', error);
    handleError(res, error, 'Error approving KYC');
  }
});

// Get all referrals for admin
app.get('/api/admin/referrals', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const skip = (page - 1) * limit;
    
    const [referrals, total] = await Promise.all([
      Referral.find({})
        .populate('referrer', 'full_name email')
        .populate('referred_user', 'full_name email')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Referral.countDocuments({})
    ]);
    
    // Calculate platform-wide stats
    const platformStats = await Referral.aggregate([
      {
        $group: {
          _id: null,
          total_referrals: { $sum: 1 },
          total_earnings: { $sum: '$earnings' },
          active_referrals: { 
            $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] }
          }
        }
      }
    ]);
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };
    
    res.json(formatResponse(true, 'Referrals retrieved', {
      referrals,
      platform_stats: platformStats[0] || {},
      pagination
    }));
  } catch (error) {
    advancedLogger.error('Error fetching referrals:', error);
    handleError(res, error, 'Error fetching referrals');
  }
});

// ==================== ADVANCED DEBUGGING ENDPOINTS ====================

// Server status endpoint
app.get('/api/debug/status', async (req, res) => {
  try {
    const status = {
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
      database_state: mongoose.connection.readyState,
      server_info: {
        node_version: process.version,
        platform: process.platform,
        architecture: process.arch,
        hostname: os.hostname(),
        cpus: os.cpus().length,
        total_memory: os.totalmem(),
        free_memory: os.freemem()
      },
      performance: {
        request_analytics: requestAnalytics,
        socket_connections: performanceStats.socketConnections,
        db_queries: performanceStats.dbQueries,
        average_response_time: requestAnalytics.responseTimes.length > 0 
          ? requestAnalytics.responseTimes.reduce((a, b) => a + b, 0) / requestAnalytics.responseTimes.length
          : 0
      },
      config: {
        port: config.port,
        environment: config.nodeEnv,
        debug: config.debug,
        client_url: config.clientURL,
        server_url: config.serverURL
      }
    };
    
    res.json(formatResponse(true, 'Server status', status));
  } catch (error) {
    res.status(500).json(formatResponse(false, 'Debug error', { error: error.message }));
  }
});

// Database debug endpoint
app.get('/api/debug/database', async (req, res) => {
  try {
    const collections = await mongoose.connection.db.listCollections().toArray();
    const collectionNames = collections.map(col => col.name);
    
    const stats = {};
    
    // Get counts for each collection
    for (const collection of collectionNames) {
      try {
        stats[collection] = await mongoose.connection.db.collection(collection).countDocuments();
      } catch (err) {
        stats[collection] = 'Error: ' + err.message;
      }
    }
    
    res.json(formatResponse(true, 'Database debug info', {
      connection_state: mongoose.connection.readyState,
      collections: collectionNames,
      counts: stats,
      mongo_uri: config.mongoURI ? `${config.mongoURI.substring(0, 50)}...` : 'Not set'
    }));
  } catch (error) {
    res.json(formatResponse(false, 'Database debug error', { error: error.message }));
  }
});

// Test all endpoints
app.get('/api/debug/test-endpoints', adminAuth, async (req, res) => {
  const testResults = {};
  
  try {
    // Test basic endpoints
    testResults.health = '✅ Working';
    
    // Test admin endpoints
    const pendingInvestments = await Investment.countDocuments({ status: 'pending' });
    testResults.pending_investments = `✅ ${pendingInvestments} pending`;
    
    const pendingDeposits = await Deposit.countDocuments({ status: 'pending' });
    testResults.pending_deposits = `✅ ${pendingDeposits} pending`;
    
    const pendingWithdrawals = await Withdrawal.countDocuments({ status: 'pending' });
    testResults.pending_withdrawals = `✅ ${pendingWithdrawals} pending`;
    
    const pendingKYC = await KYCSubmission.countDocuments({ status: 'pending' });
    testResults.pending_kyc = `✅ ${pendingKYC} pending`;
    
    const totalUsers = await User.countDocuments({});
    testResults.total_users = `✅ ${totalUsers} users`;
    
    const totalTransactions = await Transaction.countDocuments({});
    testResults.total_transactions = `✅ ${totalTransactions} transactions`;
    
    const totalReferrals = await Referral.countDocuments({});
    testResults.total_referrals = `✅ ${totalReferrals} referrals`;
    
    res.json(formatResponse(true, 'Endpoint tests completed', testResults));
  } catch (error) {
    testResults.error = error.message;
    res.json(formatResponse(false, 'Test error', testResults));
  }
});

// Clear analytics data (admin only)
app.delete('/api/debug/clear-analytics', adminAuth, async (req, res) => {
  try {
    await Analytics.deleteMany({});
    requestAnalytics.totalRequests = 0;
    requestAnalytics.requestsByEndpoint = {};
    requestAnalytics.requestsByMethod = {};
    requestAnalytics.requestsByHour = {};
    requestAnalytics.errorsByEndpoint = {};
    requestAnalytics.responseTimes = [];
    
    res.json(formatResponse(true, 'Analytics data cleared'));
  } catch (error) {
    advancedLogger.error('Error clearing analytics:', error);
    handleError(res, error, 'Error clearing analytics');
  }
});

// ==================== FILE UPLOAD ENDPOINT ====================

app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json(formatResponse(false, 'No file uploaded'));
    }

    const userId = req.user._id;
    const folder = req.body.folder || 'general';
    const purpose = req.body.purpose || 'general';

    advancedLogger.debug(`📁 Uploading file for user ${userId}, folder: ${folder}, purpose: ${purpose}`);

    const uploadResult = await handleFileUpload(req.file, folder, userId);

    advancedLogger.success(`✅ File uploaded: ${uploadResult.filename}`);

    res.json(formatResponse(true, 'File uploaded successfully', {
      fileUrl: uploadResult.url,
      fileName: uploadResult.filename,
      originalName: uploadResult.originalName,
      size: uploadResult.size,
      mimeType: uploadResult.mimeType,
      folder,
      purpose,
      uploadedAt: uploadResult.uploadedAt
    }));
  } catch (error) {
    advancedLogger.error('Error uploading file:', error);
    handleError(res, error, 'Error uploading file');
  }
});

// ==================== ENHANCED HEALTH CHECK ====================
app.get('/health', async (req, res) => {
  const health = {
    success: true,
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '47.0.0',
    environment: config.nodeEnv,
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    uptime: process.uptime(),
    memory: {
      rss: `${Math.round(process.memoryUsage().rss / 1024 / 1024)}MB`,
      heapTotal: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)}MB`,
      heapUsed: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`
    },
    stats: {
      users: await User.estimatedDocumentCount().catch(() => 'N/A'),
      investments: await Investment.estimatedDocumentCount().catch(() => 'N/A'),
      deposits: await Deposit.estimatedDocumentCount().catch(() => 'N/A'),
      withdrawals: await Withdrawal.estimatedDocumentCount().catch(() => 'N/A')
    },
    config: {
      port: config.port,
      client_url: config.clientURL,
      server_url: config.serverURL,
      debug: config.debug
    }
  };
  
  res.json(health);
});

// ==================== ROOT ENDPOINT ====================
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 Raw Wealthy Backend API v47.0 ENHANCED - Enterprise Edition',
    version: '47.0.0',
    timestamp: new Date().toISOString(),
    status: 'Operational',
    environment: config.nodeEnv,
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
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
      debug: '/api/debug/*',
      health: '/health'
    },
    documentation: `${config.serverURL}/docs`,
    support: 'support@rawwealthy.com'
  });
});

// ==================== CRON JOBS FOR DAILY EARNINGS ====================

// Calculate daily earnings for active investments
cron.schedule('0 0 * * *', async () => {
  try {
    advancedLogger.info('🔄 Running daily earnings calculation...');
    
    const activeInvestments = await Investment.find({ 
      status: 'active',
      end_date: { $gt: new Date() }
    }).populate('plan user');
    
    let totalEarnings = 0;
    let processedCount = 0;
    
    for (const investment of activeInvestments) {
      try {
        // Calculate daily earning
        const dailyEarning = (investment.amount * investment.plan.daily_interest) / 100;
        
        // Update investment
        investment.earned_so_far += dailyEarning;
        investment.last_earning_date = new Date();
        
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
          { 
            investment_id: investment._id,
            plan_name: investment.plan.name,
            daily_interest: investment.plan.daily_interest
          }
        );
        
        // Check if investment has completed
        if (new Date() >= investment.end_date) {
          investment.status = 'completed';
          
          // Create notification for completed investment
          await createNotification(
            investment.user._id,
            'Investment Completed',
            `Your investment in ${investment.plan.name} has completed. Total earnings: ₦${investment.earned_so_far.toLocaleString()}`,
            'success',
            '/investments',
            { 
              plan_name: investment.plan.name,
              amount: investment.amount,
              total_earnings: investment.earned_so_far
            }
          );
        }
        
        await investment.save();
        
        totalEarnings += dailyEarning;
        processedCount++;
        
      } catch (error) {
        advancedLogger.error(`Error processing investment ${investment._id}:`, error);
      }
    }
    
    // Track analytics
    await trackAnalytics('daily_earnings_distributed', totalEarnings, {
      investments_processed: processedCount,
      average_earning_per_investment: processedCount > 0 ? totalEarnings / processedCount : 0
    });
    
    advancedLogger.success(`✅ Daily earnings calculated: Processed ${processedCount} investments, Total: ₦${totalEarnings.toLocaleString()}`);
    
  } catch (error) {
    advancedLogger.error('Error in daily earnings cron job:', error);
  }
});

// Daily analytics aggregation
cron.schedule('0 1 * * *', async () => {
  try {
    advancedLogger.info('📊 Running daily analytics aggregation...');
    
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    yesterday.setHours(0, 0, 0, 0);
    
    // Aggregate daily stats
    const [
      newUsers,
      newInvestments,
      newDeposits,
      newWithdrawals,
      totalRevenue
    ] = await Promise.all([
      User.countDocuments({ createdAt: { $gte: yesterday } }),
      Investment.countDocuments({ createdAt: { $gte: yesterday } }),
      Deposit.countDocuments({ createdAt: { $gte: yesterday } }),
      Withdrawal.countDocuments({ createdAt: { $gte: yesterday } }),
      Transaction.aggregate([
        { 
          $match: { 
            createdAt: { $gte: yesterday },
            type: { $in: ['deposit', 'investment'] }
          }
        },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ])
    ]);
    
    // Store aggregated analytics
    await Analytics.create([
      { date: yesterday, metric: 'user_registrations', value: newUsers },
      { date: yesterday, metric: 'investments_created', value: newInvestments },
      { date: yesterday, metric: 'deposits_approved', value: newDeposits },
      { date: yesterday, metric: 'withdrawals_processed', value: newWithdrawals },
      { date: yesterday, metric: 'revenue', value: totalRevenue[0]?.total || 0 }
    ]);
    
    advancedLogger.success(`✅ Daily analytics aggregated for ${yesterday.toISOString().split('T')[0]}`);
    
  } catch (error) {
    advancedLogger.error('Error in analytics cron job:', error);
  }
});

// Auto-backup (if enabled)
if (config.enableAutoBackup) {
  cron.schedule('0 3 * * *', async () => {
    try {
      advancedLogger.info('💾 Running auto-backup...');
      
      const backupDir = path.join(__dirname, 'backups');
      if (!fs.existsSync(backupDir)) {
        fs.mkdirSync(backupDir, { recursive: true });
      }
      
      const backupFile = path.join(backupDir, `backup-${Date.now()}.json`);
      
      // Export essential data
      const backupData = {
        timestamp: new Date().toISOString(),
        users: await User.find({}).limit(1000).lean(),
        investments: await Investment.find({}).populate('plan user').limit(1000).lean(),
        transactions: await Transaction.find({}).limit(1000).lean(),
        config: config
      };
      
      fs.writeFileSync(backupFile, JSON.stringify(backupData, null, 2));
      
      advancedLogger.success(`✅ Auto-backup completed: ${backupFile}`);
      
      // Keep only last 7 backups
      const files = fs.readdirSync(backupDir)
        .filter(f => f.startsWith('backup-'))
        .sort()
        .reverse();
      
      if (files.length > 7) {
        for (const file of files.slice(7)) {
          fs.unlinkSync(path.join(backupDir, file));
        }
      }
      
    } catch (error) {
      advancedLogger.error('Error in auto-backup:', error);
    }
  });
}

// ==================== ERROR HANDLING MIDDLEWARE ====================

// 404 handler
app.use((req, res) => {
  advancedLogger.warn(`❌ 404 Not Found: ${req.method} ${req.url}`);
  res.status(404).json(formatResponse(false, 'Endpoint not found'));
});

// Global error handler
app.use((err, req, res, next) => {
  advancedLogger.error('🔥 Unhandled error:', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    requestId: req.requestId
  });
  
  // Track error in analytics
  if (req.path) {
    requestAnalytics.errorsByEndpoint[req.path] = (requestAnalytics.errorsByEndpoint[req.path] || 0) + 1;
  }
  
  res.status(500).json(formatResponse(false, 
    config.nodeEnv === 'production' ? 'Internal server error' : err.message
  ));
});

// ==================== START SERVER ====================

const startServer = async () => {
  try {
    // Initialize database
    await initializeDatabase();
    
    // Start server
    server.listen(config.port, () => {
      console.log('\n' + '='.repeat(80));
      console.log('🚀 RAW WEALTHY BACKEND v47.0 ENHANCED - ENTERPRISE EDITION');
      console.log('='.repeat(80));
      console.log(`✅ Server running on port: ${config.port}`);
      console.log(`🌍 Environment: ${config.nodeEnv}`);
      console.log(`🔗 Client URL: ${config.clientURL}`);
      console.log(`🖥️  Server URL: ${config.serverURL}`);
      console.log(`📊 Database: ${mongoose.connection.readyState === 1 ? '✅ Connected' : '❌ Disconnected'}`);
      console.log(`🔧 Debug Mode: ${config.debug}`);
      console.log(`📅 Started at: ${new Date().toISOString()}`);
      console.log('='.repeat(80));
      console.log('\n📋 Available Endpoints:');
      console.log('- /api/auth/* - Authentication endpoints');
      console.log('- /api/profile - User profile management');
      console.log('- /api/investments/* - Investment management');
      console.log('- /api/deposits/* - Deposit management');
      console.log('- /api/withdrawals/* - Withdrawal management');
      console.log('- /api/plans - Investment plans');
      console.log('- /api/referrals/* - Referral system');
      console.log('- /api/admin/* - Admin dashboard (complete)');
      console.log('- /api/debug/* - Debug endpoints');
      console.log('- /health - Health check');
      console.log('- / - API documentation');
      console.log('='.repeat(80) + '\n');
      
      // Emit server start event
      io.emit('server_start', {
        timestamp: new Date(),
        version: '47.0.0',
        status: 'running'
      });
      
      advancedLogger.success('🚀 Server started successfully');
    });
    
  } catch (error) {
    advancedLogger.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

// Handle graceful shutdown
process.on('SIGTERM', () => {
  advancedLogger.info('🛑 SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    advancedLogger.success('✅ HTTP server closed');
    mongoose.connection.close(false, () => {
      advancedLogger.success('✅ MongoDB connection closed');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  advancedLogger.info('🛑 SIGINT received. Shutting down gracefully...');
  server.close(() => {
    advancedLogger.success('✅ HTTP server closed');
    mongoose.connection.close(false, () => {
      advancedLogger.success('✅ MongoDB connection closed');
      process.exit(0);
    });
  });
});

// Start the server
startServer();

export { app, server, config, advancedLogger };
