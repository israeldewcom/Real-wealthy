// s- RAW WEALTHY BACKEND v47.1 - ENTERPRISE EDITION
// COMPLETE DEBUGGED & ENHANCED: Advanced Admin Dashboard + Full Data Analytics + Enhanced Notifications + Image Management
// AUTO-DEPLOYMENT READY WITH DYNAMIC CONFIGURATION
// DEBCTION WITH RETRY MECHANISM
// COMPLETE ADMIN PANEL WITH ALL MISSING ENDPOINTS
// ENHANCED DEBUGGING & MONITORING

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
import util from 'util';

// ES Modules equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Enhanced environment configuration with multiple fallbacks
dotenv.config({ path: path.join(__dirname, '.env.production') });

// ==================== ENHANCED ENVIRONMENT VALIDATION ====================
const requiredEnvVars = [
  'MONGODB_URI',
  'JWT_SECRET',
  'NODE_ENV',
  'CLIENT_URL'
];

console.log('🔍 Environment Configuration:');
console.log('============================');

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

console.log('============================\n');

// ==================== ADVANCED DEBUGGING CONFIGURATION ====================
const debugConfig = {
  enabled: process.env.DEBUG === 'true' || false,
  level: process.env.DEBUG_LEVEL || 'info',
  logToFile: process.env.LOG_TO_FILE === 'true' || false,
  logFile: path.join(__dirname, 'debug.log'),
  maxLogSize: parseInt(process.env.MAX_LOG_SIZE) || 10 * 1024 * 1024, // 10MB
};

// Enhanced logging function
const log = {
  info: (...args) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ℹ️ INFO:`, ...args);
    if (debugConfig.logToFile) logToFile('INFO', args);
  },
  
  warn: (...args) => {
    const timestamp = new Date().toISOString();
    console.warn(`[${timestamp}] ⚠️ WARN:`, ...args);
    if (debugConfig.logToFile) logToFile('WARN', args);
  },
  
  error: (...args) => {
    const timestamp = new Date().toISOString();
    console.error(`[${timestamp}] ❌ ERROR:`, ...args);
    if (debugConfig.logToFile) logToFile('ERROR', args);
  },
  
  debug: (...args) => {
    if (debugConfig.enabled) {
      const timestamp = new Date().toISOString();
      console.debug(`[${timestamp}] 🔍 DEBUG:`, ...args);
      if (debugConfig.logToFile) logToFile('DEBUG', args);
    }
  },
  
  success: (...args) => {
    const timestamp = new Date().toISOString();
    console.log(`[${timestamp}] ✅ SUCCESS:`, ...args);
    if (debugConfig.logToFile) logToFile('SUCCESS', args);
  },
  
  database: (...args) => {
    if (debugConfig.enabled && debugConfig.level === 'debug') {
      const timestamp = new Date().toISOString();
      console.log(`[${timestamp}] 🗄️ DATABASE:`, ...args);
    }
  }
};

// File logging function
function logToFile(level, args) {
  try {
    const timestamp = new Date().toISOString();
    const message = args.map(arg => 
      typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
    ).join(' ');
    
    const logEntry = `[${timestamp}] ${level}: ${message}\n`;
    
    // Check if log file exists and size
    if (fs.existsSync(debugConfig.logFile)) {
      const stats = fs.statSync(debugConfig.logFile);
      if (stats.size > debugConfig.maxLogSize) {
        // Rotate log file
        const rotatedFile = debugConfig.logFile + '.' + Date.now();
        fs.renameSync(debugConfig.logFile, rotatedFile);
      }
    }
    
    fs.appendFileSync(debugConfig.logFile, logEntry);
  } catch (error) {
    console.error('Failed to write to log file:', error);
  }
}

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
  debug: debugConfig.enabled,
  logLevel: debugConfig.level
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

log.info('⚙️ Dynamic Configuration Loaded:');
log.info(`- Port: ${config.port}`);
log.info(`- Environment: ${config.nodeEnv}`);
log.info(`- Client URL: ${config.clientURL}`);
log.info(`- Server URL: ${config.serverURL}`);
log.info(`- Database URI: ${config.mongoURI ? 'Set (masked)' : 'Not set'}`);
log.info(`- Email Enabled: ${config.emailEnabled}`);
log.info(`- Allowed Origins: ${config.allowedOrigins.length}`);
log.info(`- Upload Directory: ${config.uploadDir}`);
log.info(`- Debug Mode: ${config.debug}`);

// ==================== ENHANCED EXPRESS SETUP ====================
const app = express();
const server = http.createServer(app);

// Initialize Socket.IO for real-time updates
const io = new Server(server, {
  cors: {
    origin: config.allowedOrigins,
    credentials: true
  }
});

// Advanced request tracking
let requestCounts = {};
let activeConnections = new Set();
let requestLatencies = [];
let errorCounts = {};

// Reset stats every hour
setInterval(() => {
  requestCounts = {};
  requestLatencies = [];
  errorCounts = {};
}, 3600000);

// Security Headers with dynamic CSP
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
  
  // Add request ID and start time to request object
  req.requestId = requestId;
  req.startTime = startTime;
  
  // Track active connection
  activeConnections.add(requestId);
  
  // Track endpoint usage
  const endpoint = req.path;
  requestCounts[endpoint] = (requestCounts[endpoint] || 0) + 1;
  
  if (config.debug) {
    log.debug('\n' + '='.repeat(80));
    log.debug(`📡 REQUEST START [${requestId}]`);
    log.debug(`- Method: ${req.method}`);
    log.debug(`- URL: ${req.originalUrl}`);
    log.debug(`- IP: ${req.ip}`);
    log.debug(`- User-Agent: ${req.headers['user-agent']?.substring(0, 100)}`);
    
    if (req.method !== 'GET') {
      log.debug(`- Body (first 500 chars):`, 
        JSON.stringify(req.body, null, 2).substring(0, 500));
    }
    
    if (req.headers.authorization) {
      log.debug(`- Auth: Bearer token present`);
      try {
        const token = req.headers.authorization.replace('Bearer ', '');
        const decoded = jwt.decode(token);
        log.debug(`- Token payload:`, decoded);
      } catch (err) {
        log.debug(`- Token decode error: ${err.message}`);
      }
    }
  }
  
  // Store original send and json methods
  const originalSend = res.send;
  const originalJson = res.json;
  
  // Override send method
  res.send = function(body) {
    const endTime = Date.now();
    const latency = endTime - startTime;
    
    // Track latency
    requestLatencies.push(latency);
    if (requestLatencies.length > 1000) requestLatencies.shift();
    
    // Remove from active connections
    activeConnections.delete(requestId);
    
    if (config.debug) {
      log.debug(`📤 RESPONSE SENT [${requestId}]`);
      log.debug(`- Status: ${res.statusCode}`);
      log.debug(`- Latency: ${latency}ms`);
      log.debug(`- Response size: ${typeof body === 'string' ? body.length : JSON.stringify(body).length} bytes`);
      log.debug('='.repeat(80) + '\n');
    }
    
    return originalSend.call(this, body);
  };
  
  // Override json method
  res.json = function(body) {
    const endTime = Date.now();
    const latency = endTime - startTime;
    
    // Track latency
    requestLatencies.push(latency);
    if (requestLatencies.length > 1000) requestLatencies.shift();
    
    // Remove from active connections
    activeConnections.delete(requestId);
    
    if (config.debug) {
      log.debug(`📤 RESPONSE JSON [${requestId}]`);
      log.debug(`- Status: ${res.statusCode}`);
      log.debug(`- Latency: ${latency}ms`);
      log.debug(`- Success: ${body?.success || 'N/A'}`);
      log.debug(`- Message: ${body?.message?.substring(0, 100) || 'N/A'}`);
      log.debug('='.repeat(80) + '\n');
    }
    
    return originalJson.call(this, body);
  };
  
  next();
});

// Error tracking middleware
app.use((err, req, res, next) => {
  const endpoint = req.path;
  errorCounts[endpoint] = (errorCounts[endpoint] || 0) + 1;
  next(err);
});

// ==================== ENHANCED CORS CONFIGURATION ====================
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) {
      if (config.debug) log.debug('🌐 No origin - Allowing request');
      return callback(null, true);
    }
    
    if (config.allowedOrigins.indexOf(origin) !== -1) {
      if (config.debug) log.debug(`🌐 Allowed origin: ${origin}`);
      callback(null, true);
    } else {
      // Check if origin matches pattern (for preview deployments)
      const isPreviewDeployment = origin.includes('vercel.app') || 
                                  origin.includes('onrender.com') ||
                                  origin.includes('netlify.app') ||
                                  origin.includes('github.io');
      
      if (isPreviewDeployment) {
        log.info(`🌐 Allowed preview deployment: ${origin}`);
        callback(null, true);
      } else {
        log.warn(`🚫 Blocked by CORS: ${origin}`);
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
        const jsonData = JSON.parse(buf.toString());
        log.debug('📨 Incoming JSON size:', buf.length, 'bytes');
        if (Object.keys(jsonData).length > 0) {
          log.debug('📨 JSON keys:', Object.keys(jsonData));
        }
      } catch (e) {
        log.debug('📨 Raw body (not JSON):', buf.toString().substring(0, 200));
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
    log.warn(`🚫 Rate limit exceeded for ${req.ip} on ${req.path}`);
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
    log.error('No file provided for upload');
    return null;
  }
  
  try {
    log.info(`📁 Uploading file: ${file.originalname}, Size: ${file.size} bytes, Type: ${file.mimetype}`);
    
    // Validate file type
    if (!config.allowedMimeTypes[file.mimetype]) {
      throw new Error(`Invalid file type: ${file.mimetype}`);
    }
    
    const uploadsDir = path.join(config.uploadDir, folder);
    
    // Create directory if it doesn't exist
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
      log.info(`📁 Created directory: ${uploadsDir}`);
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
    
    log.info(`✅ File uploaded: ${filename}, URL: ${url}`);
    
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
    log.error('❌ File upload error:', error);
    throw new Error(`File upload failed: ${error.message}`);
  }
};

// Create uploads directory if it doesn't exist
if (!fs.existsSync(config.uploadDir)) {
  fs.mkdirSync(config.uploadDir, { recursive: true });
  log.info(`📁 Created upload directory: ${config.uploadDir}`);
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
  created_by_user_agent: String
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

// Pre-save hooks
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    log.debug(`🔑 Hashing password for user: ${this.email}`);
    this.password = await bcrypt.hash(this.password, config.bcryptRounds);
  }
  
  if (!this.referral_code) {
    this.referral_code = crypto.randomBytes(6).toString('hex').toUpperCase();
    log.debug(`🎫 Generated referral code for ${this.email}: ${this.referral_code}`);
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
  investment_image_url: String
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
  proof_verified_at: Date
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
  proof_verified_at: Date
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

// ==================== ENHANCED UTILITY FUNCTIONS ====================

const formatResponse = (success, message, data = null, pagination = null) => {
  const response = { 
    success, 
    message, 
    timestamp: new Date().toISOString(),
    version: '47.1.0',
    debug: config.debug ? {
      requestCounts: Object.keys(requestCounts).length,
      activeConnections: activeConnections.size,
      avgLatency: requestLatencies.length > 0 ? 
        Math.round(requestLatencies.reduce((a, b) => a + b, 0) / requestLatencies.length) : 0
    } : undefined
  };
  
  if (data !== null) response.data = data;
  if (pagination !== null) response.pagination = pagination;
  
  return response;
};

const handleError = (res, error, defaultMessage = 'An error occurred') => {
  const errorId = crypto.randomBytes(4).toString('hex');
  
  log.error('❌ Error Details:', {
    errorId,
    message: error.message,
    stack: error.stack,
    name: error.name,
    code: error.code
  });
  
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
  
  const statusCode = error.statusCode || error.status || 500;
  const message = config.nodeEnv === 'production' && statusCode === 500 
    ? defaultMessage 
    : error.message;

  return res.status(statusCode).json(formatResponse(false, message, { errorId }));
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
    
    log.debug(`📢 Notification created for user ${userId}: ${title}`);
    
    return notification;
  } catch (error) {
    log.error('Error creating notification:', error);
    return null;
  }
};

// Enhanced createTransaction
const createTransaction = async (userId, type, amount, description, status = 'completed', metadata = {}, proofUrl = null) => {
  try {
    const user = await User.findById(userId);
    if (!user) {
      log.error(`User ${userId} not found for transaction creation`);
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
    
    log.debug(`💳 Transaction created: ${type} - ${amount} for user ${userId}`);
    
    return transaction;
  } catch (error) {
    log.error('Error creating transaction:', error);
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
    log.error('Error calculating user stats:', error);
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
    log.debug(`📝 Admin audit created: ${action} by admin ${adminId}`);
    return audit;
  } catch (error) {
    log.error('Error creating admin audit:', error);
    return null;
  }
};

// ==================== ENHANCED AUTH MIDDLEWARE ====================

const auth = async (req, res, next) => {
  try {
    let token = req.header('Authorization');
    
    if (!token) {
      log.debug('🔒 No token provided');
      return res.status(401).json(formatResponse(false, 'No token, authorization denied'));
    }
    
    if (token.startsWith('Bearer ')) {
      token = token.slice(7, token.length);
    }
    
    const decoded = jwt.verify(token, config.jwtSecret);
    
    const user = await User.findById(decoded.id);
    
    if (!user) {
      log.debug(`🔒 User not found for token: ${decoded.id}`);
      return res.status(401).json(formatResponse(false, 'Token is not valid'));
    }
    
    if (!user.is_active) {
      log.debug(`🔒 User account deactivated: ${user.email}`);
      return res.status(401).json(formatResponse(false, 'Account is deactivated. Please contact support.'));
    }
    
    req.user = user;
    req.userId = user._id;
    
    // Update last active time
    user.last_active = new Date();
    await user.save();
    
    log.debug(`🔒 Authenticated user: ${user.email} (${user.role})`);
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      log.debug('🔒 Invalid JWT token');
      return res.status(401).json(formatResponse(false, 'Invalid token'));
    } else if (error.name === 'TokenExpiredError') {
      log.debug('🔒 Expired JWT token');
      return res.status(401).json(formatResponse(false, 'Token expired'));
    }
    
    log.error('Auth middleware error:', error);
    res.status(500).json(formatResponse(false, 'Server error during authentication'));
  }
};

const adminAuth = async (req, res, next) => {
  try {
    await auth(req, res, () => {
      if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
        log.debug(`🔒 Admin access denied for user: ${req.user.email}`);
        return res.status(403).json(formatResponse(false, 'Access denied. Admin privileges required.'));
      }
      log.debug(`🔒 Admin access granted: ${req.user.email}`);
      next();
    });
  } catch (error) {
    handleError(res, error, 'Admin authentication error');
  }
};

// ==================== DEBUGGED DATABASE INITIALIZATION ====================

const initializeDatabase = async () => {
  log.info('🔄 Initializing database with enhanced connection...');
  
  // Set Mongoose debug mode
  mongoose.set('debug', (collectionName, method, query, doc) => {
    if (config.debug) {
      log.database(`${collectionName}.${method}`, {
        query: JSON.stringify(query),
        doc: doc ? JSON.stringify(doc).substring(0, 200) : null
      });
    }
  });
  
  // Handle Mongoose connection events
  mongoose.connection.on('connecting', () => {
    log.info('🔄 MongoDB connecting...');
  });
  
  mongoose.connection.on('connected', () => {
    log.success('✅ MongoDB connected successfully');
  });
  
  mongoose.connection.on('error', (err) => {
    log.error('❌ MongoDB connection error:', err.message);
  });
  
  mongoose.connection.on('disconnected', () => {
    log.warn('⚠️ MongoDB disconnected');
  });
  
  mongoose.connection.on('reconnected', () => {
    log.info('🔁 MongoDB reconnected');
  });
  
  try {
    log.info(`🔗 Attempting to connect to: ${config.mongoURI ? 'MongoDB URI provided' : 'No URI found'}`);
    
    const connectionOptions = {
      serverSelectionTimeoutMS: 10000, // Increased timeout
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      retryWrites: true,
    };
    
    await mongoose.connect(config.mongoURI, connectionOptions);
    
    log.success('✅ MongoDB connection established');
    
    // Load investment plans
    await loadInvestmentPlans();
    
    // Create admin user if it doesn't exist
    await createAdminUser();
    
    // Create indexes
    await createDatabaseIndexes();
    
    log.success('✅ Database initialization completed successfully');
    
  } catch (error) {
    log.error('❌ FATAL: Database initialization failed:', error.message);
    log.error('Stack trace:', error.stack);
    
    // Try fallback connection for development
    if (config.nodeEnv === 'development') {
      log.info('🔄 Attempting fallback to local MongoDB...');
      try {
        const fallbackURI = 'mongodb://localhost:27017/rawwealthy';
        await mongoose.connect(fallbackURI);
        log.success('✅ Connected to local MongoDB fallback');
      } catch (fallbackError) {
        log.error('❌ Fallback connection also failed:', fallbackError.message);
      }
    }
    
    // Don't throw error - let server start without DB for debugging
    log.warn('⚠️ Server starting without database connection');
  }
};

const loadInvestmentPlans = async () => {
  try {
    const plans = await InvestmentPlan.find({ is_active: true })
      .sort({ display_order: 1 })
      .lean();
    
    config.investmentPlans = plans;
    log.info(`✅ Loaded ${plans.length} investment plans`);
    
    // If no plans exist, create default plans
    if (plans.length === 0) {
      await createDefaultInvestmentPlans();
    }
  } catch (error) {
    log.error('Error loading investment plans:', error);
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
    log.info('✅ Created default investment plans');
  } catch (error) {
    log.error('Error creating default investment plans:', error);
  }
};

const createAdminUser = async () => {
  log.info('🚀 ADMIN USER INITIALIZATION STARTING...');
  
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@rawwealthy.com';
  const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123456';
  
  log.info(`🔑 Attempting to create admin: ${adminEmail}`);
  
  try {
    // Check if admin already exists
    const existingAdmin = await User.findOne({ email: adminEmail });
    if (existingAdmin) {
      log.info('✅ Admin already exists');
      
      // Ensure admin has correct role
      if (existingAdmin.role !== 'super_admin') {
        existingAdmin.role = 'super_admin';
        await existingAdmin.save();
        log.info('✅ Updated existing admin to super_admin role');
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
    
    log.success('🎉 ADMIN USER CREATED SUCCESSFULLY!');
    log.info(`📧 Email: ${adminEmail}`);
    log.info(`🔑 Password: ${adminPassword}`);
    log.info('👉 Login at: /api/auth/login');
    
  } catch (error) {
    log.error('❌ Error creating admin user:', error.message);
    log.error(error.stack);
  }
  
  log.info('🚀 ADMIN USER INITIALIZATION COMPLETE');
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
    
    log.info('✅ Database indexes created/verified');
  } catch (error) {
    log.error('Error creating indexes:', error);
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
        log.error('❌ Email configuration error:', error.message);
      } else {
        log.success('✅ Email server is ready to send messages');
      }
    });
  } catch (error) {
    log.error('❌ Email setup failed:', error.message);
  }
}

// Enhanced email utility function
const sendEmail = async (to, subject, html, text = '') => {
  try {
    if (!emailTransporter) {
      log.info(`📧 Email would be sent (simulated): To: ${to}, Subject: ${subject}`);
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
    log.info(`✅ Email sent to ${to} (Message ID: ${info.messageId})`);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    log.error('❌ Email sending error:', error.message);
    return { success: false, error: error.message };
  }
};

// ==================== SOCKET.IO INTEGRATION ====================

// Socket.IO connection handling
io.on('connection', (socket) => {
  log.info(`🔌 New Socket.IO connection: ${socket.id}`);
  
  // Join user-specific room
  socket.on('join-user', (userId) => {
    socket.join(`user:${userId}`);
    log.debug(`👤 Socket ${socket.id} joined user room: ${userId}`);
  });
  
  // Join admin room
  socket.on('join-admin', () => {
    socket.join('admin-room');
    log.debug(`👨‍💼 Socket ${socket.id} joined admin room`);
  });
  
  socket.on('disconnect', () => {
    log.info(`🔌 Socket disconnected: ${socket.id}`);
  });
});

// ==================== ENHANCED HEALTH CHECK ====================
app.get('/health', async (req, res) => {
  const health = {
    success: true,
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '47.1.0',
    environment: config.nodeEnv,
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    database_state: mongoose.connection.readyState,
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
    performance: {
      activeConnections: activeConnections.size,
      requestCounts: Object.keys(requestCounts).length,
      avgLatency: requestLatencies.length > 0 ? 
        Math.round(requestLatencies.reduce((a, b) => a + b, 0) / requestLatencies.length) : 0,
      errorCounts: Object.keys(errorCounts).length
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

// ==================== COMPREHENSIVE DEBUG ENDPOINTS ====================
app.get('/debug/db', async (req, res) => {
  try {
    const collections = await mongoose.connection.db.listCollections().toArray();
    const collectionNames = collections.map(col => col.name);
    
    // Get collection stats
    const collectionStats = {};
    for (const col of collections.slice(0, 10)) {
      try {
        const stats = await mongoose.connection.db.collection(col.name).stats();
        collectionStats[col.name] = {
          count: stats.count,
          size: stats.size,
          storageSize: stats.storageSize,
          avgObjSize: stats.avgObjSize
        };
      } catch (err) {
        collectionStats[col.name] = { error: err.message };
      }
    }
    
    const stats = {
      connection_state: mongoose.connection.readyState,
      collections: collectionNames,
      collection_stats: collectionStats,
      mongo_uri: config.mongoURI ? `${config.mongoURI.substring(0, 50)}...` : 'Not set',
      indexes: await mongoose.connection.db.collection('users').indexes().catch(() => [])
    };
    
    res.json(formatResponse(true, 'Database debug info', stats));
  } catch (error) {
    res.json(formatResponse(false, 'Database debug error', { error: error.message }));
  }
});

app.get('/debug/users', auth, async (req, res) => {
  if (req.user.role !== 'super_admin') {
    return res.status(403).json(formatResponse(false, 'Access denied'));
  }
  
  const users = await User.find().select('-password').limit(10).lean();
  res.json(formatResponse(true, 'Users debug', { users }));
});

app.get('/debug/performance', async (req, res) => {
  const performance = {
    server: {
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      cpu: process.cpuUsage(),
      platform: process.platform,
      nodeVersion: process.version
    },
    requests: {
      activeConnections: activeConnections.size,
      requestCounts: requestCounts,
      errorCounts: errorCounts,
      latencies: {
        avg: requestLatencies.length > 0 ? 
          Math.round(requestLatencies.reduce((a, b) => a + b, 0) / requestLatencies.length) : 0,
        min: requestLatencies.length > 0 ? Math.min(...requestLatencies) : 0,
        max: requestLatencies.length > 0 ? Math.max(...requestLatencies) : 0,
        p95: requestLatencies.length > 0 ? 
          requestLatencies.sort((a, b) => a - b)[Math.floor(requestLatencies.length * 0.95)] : 0
      }
    },
    database: {
      state: mongoose.connection.readyState,
      host: mongoose.connection.host,
      name: mongoose.connection.name,
      models: Object.keys(mongoose.connection.models)
    }
  };
  
  res.json(formatResponse(true, 'Performance stats', performance));
});

app.get('/debug/endpoints', async (req, res) => {
  const endpoints = [];
  
  app._router.stack.forEach((middleware) => {
    if (middleware.route) {
      const route = middleware.route;
      endpoints.push({
        path: route.path,
        methods: Object.keys(route.methods),
        regexp: route.regexp.toString()
      });
    } else if (middleware.name === 'router') {
      // Handle router middleware
      middleware.handle.stack.forEach((handler) => {
        if (handler.route) {
          const route = handler.route;
          endpoints.push({
            path: route.path,
            methods: Object.keys(route.methods),
            regexp: route.regexp.toString()
          });
        }
      });
    }
  });
  
  res.json(formatResponse(true, 'Registered endpoints', {
    count: endpoints.length,
    endpoints: endpoints
  }));
});

// ==================== ROOT ENDPOINT ====================
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 Raw Wealthy Backend API v47.1 - Enterprise Edition',
    version: '47.1.0',
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
      forgot_password: '/api/auth/forgot-password',
      health: '/health',
      debug: '/debug/* (admin only)'
    }
  });
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
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { 
        errors: errors.array().map(err => ({ field: err.param, message: err.msg }))
      }));
    }

    const { full_name, email, phone, password, referral_code, risk_tolerance = 'medium', investment_strategy = 'balanced' } = req.body;

    log.info(`📝 Registration attempt: ${email}`);

    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      log.warn(`❌ User already exists: ${email}`);
      return res.status(400).json(formatResponse(false, 'User already exists with this email'));
    }

    // Handle referral
    let referredBy = null;
    if (referral_code) {
      referredBy = await User.findOne({ referral_code: referral_code.toUpperCase() });
      if (!referredBy) {
        log.warn(`❌ Invalid referral code: ${referral_code}`);
        return res.status(400).json(formatResponse(false, 'Invalid referral code'));
      }
      log.info(`👥 Referral found: ${referredBy.email}`);
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
    log.info(`✅ User created: ${email}`);

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
      
      log.info(`👥 Referral created for ${referredBy.email}`);
      
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
    log.info(`🔑 Token generated for ${email}`);

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

    log.success(`🎉 Registration complete for ${email}`);

    res.status(201).json(formatResponse(true, 'User registered successfully', {
      user: user.toObject(),
      token
    }));

  } catch (error) {
    log.error('Registration error:', error);
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
    
    log.info(`🔐 Login attempt: ${email}`);

    // Find user with password
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    
    if (!user) {
      log.warn(`❌ User not found: ${email}`);
      return res.status(400).json(formatResponse(false, 'Invalid credentials'));
    }

    // Check if account is locked
    if (user.lock_until && user.lock_until > new Date()) {
      const lockTime = Math.ceil((user.lock_until - new Date()) / 1000 / 60);
      log.warn(`🔒 Account locked for ${email}: ${lockTime} minutes remaining`);
      return res.status(423).json(formatResponse(false, `Account is locked. Try again in ${lockTime} minutes.`));
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      user.login_attempts += 1;
      if (user.login_attempts >= 5) {
        user.lock_until = new Date(Date.now() + 15 * 60 * 1000);
        log.warn(`🔒 Account locked for ${email} due to failed attempts`);
      }
      await user.save();
      log.warn(`❌ Invalid password for ${email}`);
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
    
    log.success(`✅ Login successful: ${email}`);

    res.json(formatResponse(true, 'Login successful', {
      user: user.toObject(),
      token
    }));

  } catch (error) {
    log.error('Login error:', error);
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
    
    log.info(`🔑 Forgot password request: ${email}`);

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      log.warn(`❌ User not found for password reset: ${email}`);
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
      log.error(`❌ Failed to send reset email to ${email}`);
      return res.status(500).json(formatResponse(false, 'Failed to send reset email'));
    }

    log.info(`✅ Password reset email sent to ${email}`);

    res.json(formatResponse(true, 'Password reset email sent successfully'));
  } catch (error) {
    log.error('Forgot password error:', error);
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
    
    log.info(`🔑 Password reset attempt with token`);

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
      log.warn(`❌ Invalid or expired reset token`);
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

    log.info(`✅ Password reset successful for ${user.email}`);

    res.json(formatResponse(true, 'Password reset successful'));
  } catch (error) {
    log.error('Reset password error:', error);
    handleError(res, error, 'Error resetting password');
  }
});

// ==================== ENHANCED PROFILE ENDPOINTS ====================

// Get profile with complete data
app.get('/api/profile', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    log.info(`📊 Fetching profile for user: ${userId}`);
    
    // Get user with basic info
    const user = await User.findById(userId).lean();
    if (!user) {
      log.warn(`❌ User not found: ${userId}`);
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

    log.info(`✅ Profile fetched for user: ${userId}`);

    res.json(formatResponse(true, 'Profile retrieved successfully', profileData));
  } catch (error) {
    log.error('Error fetching profile:', error);
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

    log.info(`✏️ Updating profile for user: ${userId}`);

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
      log.warn(`❌ User not found during update: ${userId}`);
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    await createNotification(
      userId,
      'Profile Updated',
      'Your profile information has been successfully updated.',
      'info',
      '/profile'
    );

    log.info(`✅ Profile updated for user: ${userId}`);

    res.json(formatResponse(true, 'Profile updated successfully', { user }));
  } catch (error) {
    log.error('Error updating profile:', error);
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

    log.info(`🏦 Updating bank details for user: ${userId}`);

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

    log.info(`✅ Bank details updated for user: ${userId}`);

    res.json(formatResponse(true, 'Bank details updated successfully', {
      bank_details: user.bank_details
    }));
  } catch (error) {
    log.error('Error updating bank details:', error);
    handleError(res, error, 'Error updating bank details');
  }
});

// ==================== ENHANCED INVESTMENT PLANS ENDPOINTS ====================

// Get all investment plans
app.get('/api/plans', async (req, res) => {
  try {
    log.info('📋 Fetching investment plans');
    
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
    
    log.info(`✅ Found ${plans.length} investment plans`);
    
    res.json(formatResponse(true, 'Plans retrieved successfully', { plans: enhancedPlans }));
  } catch (error) {
    log.error('Error fetching investment plans:', error);
    handleError(res, error, 'Error fetching investment plans');
  }
});

// Get specific plan
app.get('/api/plans/:id', async (req, res) => {
  try {
    const plan = await InvestmentPlan.findById(req.params.id);
    
    if (!plan) {
      log.warn(`❌ Investment plan not found: ${req.params.id}`);
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
    
    log.info(`✅ Retrieved plan: ${plan.name}`);
    
    res.json(formatResponse(true, 'Plan retrieved successfully', { plan: enhancedPlan }));
  } catch (error) {
    log.error('Error fetching investment plan:', error);
    handleError(res, error, 'Error fetching investment plan');
  }
});

// ==================== ENHANCED INVESTMENT ENDPOINTS ====================

// Get user investments
app.get('/api/investments', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { status, page = 1, limit = 10 } = req.query;
    
    log.info(`📊 Fetching investments for user: ${userId}, status: ${status || 'all'}`);
    
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

    log.info(`✅ Found ${total} investments for user ${userId}`);

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
    log.error('Error fetching investments:', error);
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
    
    log.info(`💰 Creating investment for user ${userId}, plan: ${plan_id}, amount: ${amount}`);

    // Check plan
    const plan = await InvestmentPlan.findById(plan_id);
    if (!plan) {
      log.warn(`❌ Investment plan not found: ${plan_id}`);
      return res.status(404).json(formatResponse(false, 'Investment plan not found'));
    }

    const investmentAmount = parseFloat(amount);

    // Validate amount
    if (investmentAmount < plan.min_amount) {
      log.warn(`❌ Investment below minimum: ${investmentAmount} < ${plan.min_amount}`);
      return res.status(400).json(formatResponse(false, 
        `Minimum investment for ${plan.name} is ₦${plan.min_amount.toLocaleString()}`));
    }

    if (plan.max_amount && investmentAmount > plan.max_amount) {
      log.warn(`❌ Investment above maximum: ${investmentAmount} > ${plan.max_amount}`);
      return res.status(400).json(formatResponse(false,
        `Maximum investment for ${plan.name} is ₦${plan.max_amount.toLocaleString()}`));
    }

    // Check balance
    if (investmentAmount > req.user.balance) {
      log.warn(`❌ Insufficient balance: ${investmentAmount} > ${req.user.balance}`);
      return res.status(400).json(formatResponse(false, 'Insufficient balance for this investment'));
    }

    // Handle file upload
    let proofUrl = null;
    let uploadResult = null;
    if (req.file) {
      try {
        uploadResult = await handleFileUpload(req.file, 'investment-proofs', userId);
        proofUrl = uploadResult.url;
        log.info(`📁 Payment proof uploaded: ${proofUrl}`);
      } catch (uploadError) {
        log.error('File upload error:', uploadError);
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

    log.info(`✅ Investment created: ${investment._id}`);

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
    log.error('Error creating investment:', error);
    handleError(res, error, 'Error creating investment');
  }
});

// ==================== ENHANCED DEPOSIT ENDPOINTS ====================

// Get user deposits
app.get('/api/deposits', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { status, page = 1, limit = 10 } = req.query;
    
    log.info(`💰 Fetching deposits for user: ${userId}`);
    
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

    log.info(`✅ Found ${total} deposits for user ${userId}`);

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
    log.error('Error fetching deposits:', error);
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

    log.info(`💰 Creating deposit for user ${userId}, amount: ${depositAmount}, method: ${payment_method}`);

    // Handle file upload
    let proofUrl = null;
    let uploadResult = null;
    if (req.file) {
      try {
        uploadResult = await handleFileUpload(req.file, 'deposit-proofs', userId);
        proofUrl = uploadResult.url;
        log.info(`📁 Deposit proof uploaded: ${proofUrl}`);
      } catch (uploadError) {
        log.error('File upload error:', uploadError);
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

    log.info(`✅ Deposit created: ${deposit._id}`);

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
    log.error('Error creating deposit:', error);
    handleError(res, error, 'Error creating deposit');
  }
});

// ==================== ENHANCED WITHDRAWAL ENDPOINTS ====================

// Get user withdrawals
app.get('/api/withdrawals', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { status, page = 1, limit = 10 } = req.query;
    
    log.info(`💳 Fetching withdrawals for user: ${userId}`);
    
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

    log.info(`✅ Found ${total} withdrawals for user ${userId}`);

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
    log.error('Error fetching withdrawals:', error);
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

    log.info(`💳 Creating withdrawal for user ${userId}, amount: ${withdrawalAmount}, method: ${payment_method}`);

    // Check minimum withdrawal
    if (withdrawalAmount < config.minWithdrawal) {
      log.warn(`❌ Withdrawal below minimum: ${withdrawalAmount} < ${config.minWithdrawal}`);
      return res.status(400).json(formatResponse(false, 
        `Minimum withdrawal is ₦${config.minWithdrawal.toLocaleString()}`));
    }

    // Check user balance
    if (withdrawalAmount > req.user.balance) {
      log.warn(`❌ Insufficient balance for withdrawal: ${withdrawalAmount} > ${req.user.balance}`);
      return res.status(400).json(formatResponse(false, 'Insufficient balance for withdrawal'));
    }

    // Calculate platform fee
    const platformFee = withdrawalAmount * (config.platformFeePercent / 100);
    const netAmount = withdrawalAmount - platformFee;

    // Validate payment method specific details
    let paymentDetails = {};
    if (payment_method === 'bank_transfer') {
      if (!req.user.bank_details || !req.user.bank_details.account_number) {
        log.warn(`❌ No bank details for user ${userId}`);
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
        log.warn(`❌ No wallet address for user ${userId}`);
        return res.status(400).json(formatResponse(false, 'Please set your wallet address in profile settings'));
      }
      paymentDetails = { wallet_address: req.user.wallet_address };
    } else if (payment_method === 'paypal') {
      if (!req.user.paypal_email) {
        log.warn(`❌ No PayPal email for user ${userId}`);
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

    log.info(`✅ Withdrawal created: ${withdrawal._id}`);

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
    log.error('Error creating withdrawal:', error);
    handleError(res, error, 'Error creating withdrawal');
  }
});

// ==================== REFERRAL ENDPOINTS (NEW) ====================

// Get referral statistics for authenticated user
app.get('/api/referrals/stats', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    log.info(`📊 Fetching referral stats for user: ${userId}`);
    
    // Get user's referral stats
    const user = await User.findById(userId);
    
    // Get referral data
    const referrals = await Referral.find({ referrer: userId })
      .populate('referred_user', 'full_name email createdAt balance')
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
    const recentReferrals = referrals.filter(r => 
      new Date(r.createdAt) > thirtyDaysAgo
    );

    res.json(formatResponse(true, 'Referral stats retrieved successfully', {
      stats: {
        total_referrals: totalReferrals,
        active_referrals: activeReferrals,
        total_earnings: totalEarnings,
        pending_earnings: pendingEarnings,
        referral_code: user.referral_code,
        referral_link: `${config.clientURL}/register?ref=${user.referral_code}`,
        recent_referrals: recentReferrals.length,
        commission_rate: `${config.referralCommissionPercent}%`,
        estimated_monthly_earnings: (totalEarnings / (referrals.length || 1)) * (activeReferrals || 1)
      },
      referrals: referrals.slice(0, 10),
      recent_activity: recentReferrals.slice(0, 5)
    }));
  } catch (error) {
    log.error('Error fetching referral stats:', error);
    handleError(res, error, 'Error fetching referral stats');
  }
});

// Get detailed referral list
app.get('/api/referrals/list', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { page = 1, limit = 20, status } = req.query;
    
    const query = { referrer: userId };
    if (status) query.status = status;
    
    const skip = (page - 1) * limit;
    
    const [referrals, total] = await Promise.all([
      Referral.find(query)
        .populate('referred_user', 'full_name email phone createdAt balance total_earnings')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Referral.countDocuments(query)
    ]);

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    // Calculate summary
    const summary = {
      total: total,
      active: referrals.filter(r => r.status === 'active').length,
      pending: referrals.filter(r => r.status === 'pending').length,
      completed: referrals.filter(r => r.status === 'completed').length,
      total_earnings: referrals.reduce((sum, r) => sum + (r.earnings || 0), 0),
      pending_earnings: referrals
        .filter(r => r.status === 'pending' && !r.earnings_paid)
        .reduce((sum, r) => sum + (r.earnings || 0), 0)
    };

    res.json(formatResponse(true, 'Referrals retrieved successfully', {
      referrals,
      summary,
      pagination
    }));
  } catch (error) {
    log.error('Error fetching referrals:', error);
    handleError(res, error, 'Error fetching referrals');
  }
});

// Get referral earnings history
app.get('/api/referrals/earnings', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { start_date, end_date, page = 1, limit = 20 } = req.query;
    
    const query = { 
      referrer: userId,
      earnings_paid: true
    };
    
    // Date filter
    if (start_date || end_date) {
      query.paid_at = {};
      if (start_date) query.paid_at.$gte = new Date(start_date);
      if (end_date) query.paid_at.$lte = new Date(end_date);
    }
    
    const skip = (page - 1) * limit;
    
    const [earnings, total] = await Promise.all([
      Referral.find(query)
        .populate('referred_user', 'full_name email')
        .sort({ paid_at: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Referral.countDocuments(query)
    ]);

    // Calculate totals
    const totalEarnings = earnings.reduce((sum, item) => sum + (item.earnings || 0), 0);
    
    // Group by month
    const monthlyEarnings = {};
    earnings.forEach(item => {
      if (item.paid_at) {
        const monthYear = new Date(item.paid_at).toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'short'
        });
        monthlyEarnings[monthYear] = (monthlyEarnings[monthYear] || 0) + (item.earnings || 0);
      }
    });

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(formatResponse(true, 'Referral earnings retrieved successfully', {
      earnings,
      totals: {
        total_earnings: totalEarnings,
        monthly_earnings: monthlyEarnings,
        average_per_referral: total > 0 ? totalEarnings / total : 0
      },
      pagination
    }));
  } catch (error) {
    log.error('Error fetching referral earnings:', error);
    handleError(res, error, 'Error fetching referral earnings');
  }
});

// ==================== COMPLETE ADMIN ENDPOINTS ====================

// Admin dashboard
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
  try {
    log.info(`📊 Admin dashboard requested by: ${req.user.email}`);
    
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
      pendingKYC,
      totalEarnings
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
      KYCSubmission.countDocuments({ status: 'pending' }),
      Investment.aggregate([
        { $group: { _id: null, total: { $sum: '$earned_so_far' } } }
      ])
    ]);

    // Get recent activities
    const recentActivities = await Transaction.find({})
      .populate('user', 'full_name')
      .sort({ createdAt: -1 })
      .limit(10)
      .lean();

    // Get top users by balance
    const topUsers = await User.find({})
      .sort({ balance: -1 })
      .limit(5)
      .select('full_name email balance total_earnings')
      .lean();

    const stats = {
      overview: {
        total_users: totalUsers,
        new_users_today: newUsersToday,
        total_investments: totalInvestments,
        active_investments: activeInvestments,
        total_deposits: totalDeposits,
        total_withdrawals: totalWithdrawals,
        total_earnings: totalEarnings[0]?.total || 0,
        total_balance: await User.aggregate([
          { $group: { _id: null, total: { $sum: '$balance' } } }
        ]).then(res => res[0]?.total || 0)
      },
      pending_actions: {
        pending_investments: pendingInvestments,
        pending_deposits: pendingDeposits,
        pending_withdrawals: pendingWithdrawals,
        pending_kyc: pendingKYC,
        total_pending: pendingInvestments + pendingDeposits + pendingWithdrawals + pendingKYC
      },
      recent_activities: recentActivities,
      top_users: topUsers
    };

    log.info(`✅ Admin dashboard data retrieved for ${req.user.email}`);

    res.json(formatResponse(true, 'Admin dashboard stats retrieved successfully', {
      stats,
      quick_links: {
        pending_investments: '/api/admin/pending-investments',
        pending_deposits: '/api/admin/pending-deposits',
        pending_withdrawals: '/api/admin/pending-withdrawals',
        pending_kyc: '/api/admin/pending-kyc',
        all_users: '/api/admin/users',
        transactions: '/api/admin/transactions',
        referrals: '/api/admin/referrals',
        audit_logs: '/api/admin/audit'
      }
    }));
  } catch (error) {
    log.error('Error fetching admin dashboard stats:', error);
    handleError(res, error, 'Error fetching admin dashboard stats');
  }
});

// Get pending investments for admin
app.get('/api/admin/pending-investments', adminAuth, async (req, res) => {
  try {
    const pendingInvestments = await Investment.find({ status: 'pending' })
      .populate('user', 'full_name email phone')
      .populate('plan', 'name min_amount daily_interest')
      .sort({ createdAt: -1 })
      .lean();

    log.info(`📋 Found ${pendingInvestments.length} pending investments`);

    res.json(formatResponse(true, 'Pending investments retrieved successfully', {
      investments: pendingInvestments,
      count: pendingInvestments.length,
      total_amount: pendingInvestments.reduce((sum, inv) => sum + (inv.amount || 0), 0)
    }));
  } catch (error) {
    log.error('Error fetching pending investments:', error);
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

    log.info(`✅ Approving investment: ${investmentId} by admin: ${adminId}`);

    const investment = await Investment.findById(investmentId)
      .populate('user plan');
    
    if (!investment) {
      log.warn(`❌ Investment not found: ${investmentId}`);
      return res.status(404).json(formatResponse(false, 'Investment not found'));
    }

    if (investment.status !== 'pending') {
      log.warn(`❌ Investment not pending: ${investmentId}, status: ${investment.status}`);
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

    log.info(`✅ Investment approved: ${investmentId}`);

    res.json(formatResponse(true, 'Investment approved successfully', {
      investment: {
        ...investment.toObject(),
        approved_by_admin: req.user.full_name,
        proof_verified: true
      },
      message: 'Investment approved and user notified'
    }));
  } catch (error) {
    log.error('Error approving investment:', error);
    handleError(res, error, 'Error approving investment');
  }
});

// Reject investment
app.post('/api/admin/investments/:id/reject', adminAuth, [
  body('remarks').notEmpty().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const investmentId = req.params.id;
    const adminId = req.user._id;
    const { remarks } = req.body;

    log.info(`❌ Rejecting investment: ${investmentId} by admin: ${adminId}`);

    const investment = await Investment.findById(investmentId)
      .populate('user plan');
    
    if (!investment) {
      log.warn(`❌ Investment not found: ${investmentId}`);
      return res.status(404).json(formatResponse(false, 'Investment not found'));
    }

    if (investment.status !== 'pending') {
      log.warn(`❌ Investment not pending: ${investmentId}, status: ${investment.status}`);
      return res.status(400).json(formatResponse(false, 'Investment is not pending approval'));
    }

    // Update investment
    investment.status = 'rejected';
    investment.approved_by = adminId;
    investment.remarks = remarks;
    
    await investment.save();

    // Refund user
    await User.findByIdAndUpdate(investment.user._id, {
      $inc: { balance: investment.amount }
    });

    // Create notification for user
    await createNotification(
      investment.user._id,
      'Investment Rejected',
      `Your investment of ₦${investment.amount.toLocaleString()} in ${investment.plan.name} has been rejected. Reason: ${remarks}`,
      'error',
      '/investments',
      { 
        amount: investment.amount,
        plan_name: investment.plan.name,
        rejected_by: req.user.full_name,
        rejection_reason: remarks
      }
    );

    // Create audit log
    await createAdminAudit(
      adminId,
      'REJECT_INVESTMENT',
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

    log.info(`✅ Investment rejected: ${investmentId}`);

    res.json(formatResponse(true, 'Investment rejected successfully', {
      investment: {
        ...investment.toObject(),
        rejected_by_admin: req.user.full_name
      },
      message: 'Investment rejected and user notified'
    }));
  } catch (error) {
    log.error('Error rejecting investment:', error);
    handleError(res, error, 'Error rejecting investment');
  }
});

// Get pending deposits for admin
app.get('/api/admin/pending-deposits', adminAuth, async (req, res) => {
  try {
    const pendingDeposits = await Deposit.find({ status: 'pending' })
      .populate('user', 'full_name email phone balance')
      .sort({ createdAt: -1 })
      .lean();

    log.info(`📋 Found ${pendingDeposits.length} pending deposits`);

    res.json(formatResponse(true, 'Pending deposits retrieved successfully', {
      deposits: pendingDeposits,
      count: pendingDeposits.length,
      total_amount: pendingDeposits.reduce((sum, dep) => sum + (dep.amount || 0), 0)
    }));
  } catch (error) {
    log.error('Error fetching pending deposits:', error);
    handleError(res, error, 'Error fetching pending deposits');
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

    log.info(`✅ Approving deposit: ${depositId} by admin: ${adminId}`);

    const deposit = await Deposit.findById(depositId)
      .populate('user');
    
    if (!deposit) {
      log.warn(`❌ Deposit not found: ${depositId}`);
      return res.status(404).json(formatResponse(false, 'Deposit not found'));
    }

    if (deposit.status !== 'pending') {
      log.warn(`❌ Deposit not pending: ${depositId}, status: ${deposit.status}`);
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

    log.info(`✅ Deposit approved: ${depositId}`);

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
    log.error('Error approving deposit:', error);
    handleError(res, error, 'Error approving deposit');
  }
});

// Reject deposit
app.post('/api/admin/deposits/:id/reject', adminAuth, [
  body('remarks').notEmpty().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const depositId = req.params.id;
    const adminId = req.user._id;
    const { remarks } = req.body;

    log.info(`❌ Rejecting deposit: ${depositId} by admin: ${adminId}`);

    const deposit = await Deposit.findById(depositId)
      .populate('user');
    
    if (!deposit) {
      log.warn(`❌ Deposit not found: ${depositId}`);
      return res.status(404).json(formatResponse(false, 'Deposit not found'));
    }

    if (deposit.status !== 'pending') {
      log.warn(`❌ Deposit not pending: ${depositId}, status: ${deposit.status}`);
      return res.status(400).json(formatResponse(false, 'Deposit is not pending approval'));
    }

    // Update deposit
    deposit.status = 'rejected';
    deposit.approved_by = adminId;
    deposit.admin_notes = remarks;
    
    await deposit.save();

    // Create notification
    await createNotification(
      deposit.user._id,
      'Deposit Rejected',
      `Your deposit of ₦${deposit.amount.toLocaleString()} has been rejected. Reason: ${remarks}`,
      'error',
      '/deposits',
      { 
        amount: deposit.amount,
        payment_method: deposit.payment_method,
        rejected_by: req.user.full_name,
        rejection_reason: remarks
      }
    );

    // Create audit log
    await createAdminAudit(
      adminId,
      'REJECT_DEPOSIT',
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

    log.info(`✅ Deposit rejected: ${depositId}`);

    res.json(formatResponse(true, 'Deposit rejected successfully', {
      deposit: {
        ...deposit.toObject(),
        rejected_by_admin: req.user.full_name
      },
      message: 'Deposit rejected and user notified'
    }));
  } catch (error) {
    log.error('Error rejecting deposit:', error);
    handleError(res, error, 'Error rejecting deposit');
  }
});

// Get pending withdrawals for admin
app.get('/api/admin/pending-withdrawals', adminAuth, async (req, res) => {
  try {
    const pendingWithdrawals = await Withdrawal.find({ status: 'pending' })
      .populate('user', 'full_name email phone balance')
      .sort({ createdAt: -1 })
      .lean();

    log.info(`📋 Found ${pendingWithdrawals.length} pending withdrawals`);

    res.json(formatResponse(true, 'Pending withdrawals retrieved successfully', {
      withdrawals: pendingWithdrawals,
      count: pendingWithdrawals.length,
      total_amount: pendingWithdrawals.reduce((sum, wdl) => sum + (wdl.amount || 0), 0)
    }));
  } catch (error) {
    log.error('Error fetching pending withdrawals:', error);
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
    const withdrawalId = req.params.id;
    const adminId = req.user._id;
    const { transaction_id, payment_proof_url, remarks } = req.body;

    log.info(`✅ Approving withdrawal: ${withdrawalId} by admin: ${adminId}`);

    const withdrawal = await Withdrawal.findById(withdrawalId)
      .populate('user');
    
    if (!withdrawal) {
      log.warn(`❌ Withdrawal not found: ${withdrawalId}`);
      return res.status(404).json(formatResponse(false, 'Withdrawal not found'));
    }

    if (withdrawal.status !== 'pending') {
      log.warn(`❌ Withdrawal not pending: ${withdrawalId}, status: ${withdrawal.status}`);
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

    log.info(`✅ Withdrawal approved: ${withdrawalId}`);

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
    log.error('Error approving withdrawal:', error);
    handleError(res, error, 'Error approving withdrawal');
  }
});

// Reject withdrawal
app.post('/api/admin/withdrawals/:id/reject', adminAuth, [
  body('remarks').notEmpty().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const withdrawalId = req.params.id;
    const adminId = req.user._id;
    const { remarks } = req.body;

    log.info(`❌ Rejecting withdrawal: ${withdrawalId} by admin: ${adminId}`);

    const withdrawal = await Withdrawal.findById(withdrawalId)
      .populate('user');
    
    if (!withdrawal) {
      log.warn(`❌ Withdrawal not found: ${withdrawalId}`);
      return res.status(404).json(formatResponse(false, 'Withdrawal not found'));
    }

    if (withdrawal.status !== 'pending') {
      log.warn(`❌ Withdrawal not pending: ${withdrawalId}, status: ${withdrawal.status}`);
      return res.status(400).json(formatResponse(false, 'Withdrawal is not pending approval'));
    }

    // Update withdrawal
    withdrawal.status = 'rejected';
    withdrawal.approved_by = adminId;
    withdrawal.admin_notes = remarks;
    
    await withdrawal.save();

    // Refund user (amount was deducted when withdrawal created)
    await User.findByIdAndUpdate(withdrawal.user._id, {
      $inc: { balance: withdrawal.amount }
    });

    // Create notification
    await createNotification(
      withdrawal.user._id,
      'Withdrawal Rejected',
      `Your withdrawal of ₦${withdrawal.amount.toLocaleString()} has been rejected. Reason: ${remarks}`,
      'error',
      '/withdrawals',
      { 
        amount: withdrawal.amount,
        payment_method: withdrawal.payment_method,
        rejected_by: req.user.full_name,
        rejection_reason: remarks
      }
    );

    // Create audit log
    await createAdminAudit(
      adminId,
      'REJECT_WITHDRAWAL',
      'withdrawal',
      withdrawalId,
      {
        amount: withdrawal.amount,
        payment_method: withdrawal.payment_method,
        user_id: withdrawal.user._id,
        user_name: withdrawal.user.full_name,
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent']
    );

    log.info(`✅ Withdrawal rejected: ${withdrawalId}`);

    res.json(formatResponse(true, 'Withdrawal rejected successfully', {
      withdrawal: {
        ...withdrawal.toObject(),
        rejected_by_admin: req.user.full_name
      },
      message: 'Withdrawal rejected and user notified'
    }));
  } catch (error) {
    log.error('Error rejecting withdrawal:', error);
    handleError(res, error, 'Error rejecting withdrawal');
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

    log.info(`📋 Found ${total} users for admin view`);

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
    log.error('Error fetching users:', error);
    handleError(res, error, 'Error fetching users');
  }
});

// Get user details for admin
app.get('/api/admin/users/:id', adminAuth, async (req, res) => {
  try {
    const userId = req.params.id;
    
    log.info(`👤 Fetching user details for admin: ${userId}`);
    
    const user = await User.findById(userId)
      .select('-password -two_factor_secret -verification_token -password_reset_token')
      .lean();
    
    if (!user) {
      log.warn(`❌ User not found: ${userId}`);
      return res.status(404).json(formatResponse(false, 'User not found'));
    }
    
    // Get user's related data
    const [
      investments,
      deposits,
      withdrawals,
      transactions,
      referrals
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
        .limit(20)
        .lean(),
      Referral.find({ referrer: userId })
        .populate('referred_user', 'full_name email')
        .sort({ createdAt: -1 })
        .limit(20)
        .lean()
    ]);
    
    // Calculate stats
    const totalInvested = investments.reduce((sum, inv) => sum + (inv.amount || 0), 0);
    const totalDeposited = deposits
      .filter(d => d.status === 'approved')
      .reduce((sum, dep) => sum + (dep.amount || 0), 0);
    const totalWithdrawn = withdrawals
      .filter(w => w.status === 'paid')
      .reduce((sum, wdl) => sum + (wdl.amount || 0), 0);
    const totalEarnings = investments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0);
    
    const userStats = {
      total_invested,
      total_deposited,
      total_withdrawn,
      total_earnings,
      active_investments: investments.filter(inv => inv.status === 'active').length,
      pending_deposits: deposits.filter(dep => dep.status === 'pending').length,
      pending_withdrawals: withdrawals.filter(wdl => wdl.status === 'pending').length,
      total_referrals: referrals.length,
      referral_earnings: referrals.reduce((sum, ref) => sum + (ref.earnings || 0), 0)
    };
    
    log.info(`✅ User details retrieved: ${userId}`);
    
    res.json(formatResponse(true, 'User details retrieved successfully', {
      user,
      stats: userStats,
      activities: {
        investments,
        deposits,
        withdrawals,
        transactions,
        referrals
      }
    }));
  } catch (error) {
    log.error('Error fetching user details:', error);
    handleError(res, error, 'Error fetching user details');
  }
});

// Update user for admin
app.put('/api/admin/users/:id', adminAuth, [
  body('full_name').optional().trim(),
  body('phone').optional().trim(),
  body('role').optional().isIn(['user', 'admin', 'super_admin']),
  body('is_active').optional().isBoolean(),
  body('kyc_status').optional().isIn(['pending', 'verified', 'rejected', 'not_submitted']),
  body('balance').optional().isFloat({ min: 0 }),
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.params.id;
    const adminId = req.user._id;
    const updateData = req.body;
    const { remarks } = req.body;

    log.info(`✏️ Admin updating user: ${userId}`);

    const user = await User.findById(userId);
    if (!user) {
      log.warn(`❌ User not found: ${userId}`);
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    // Store old values for audit
    const oldValues = {
      full_name: user.full_name,
      phone: user.phone,
      role: user.role,
      is_active: user.is_active,
      kyc_status: user.kyc_status,
      balance: user.balance
    };

    // Update allowed fields
    const allowedUpdates = ['full_name', 'phone', 'role', 'is_active', 'kyc_status', 'balance'];
    const updatedFields = {};
    
    allowedUpdates.forEach(field => {
      if (updateData[field] !== undefined) {
        updatedFields[field] = updateData[field];
        user[field] = updateData[field];
      }
    });

    // Handle KYC verification
    if (updateData.kyc_status === 'verified') {
      user.kyc_verified = true;
      user.kyc_verified_at = new Date();
    } else if (updateData.kyc_status === 'rejected') {
      user.kyc_verified = false;
    }

    await user.save();

    // Create audit log
    await createAdminAudit(
      adminId,
      'UPDATE_USER',
      'user',
      userId,
      {
        old_values: oldValues,
        new_values: updatedFields,
        remarks: remarks,
        changed_fields: Object.keys(updatedFields)
      },
      req.ip,
      req.headers['user-agent']
    );

    // Create notification for user if important changes
    if (Object.keys(updatedFields).length > 0) {
      await createNotification(
        userId,
        'Account Updated',
        'Your account information has been updated by an administrator.',
        'info',
        '/profile',
        { updated_fields: Object.keys(updatedFields), updated_by: req.user.full_name }
      );
    }

    log.info(`✅ User updated: ${userId}`);

    res.json(formatResponse(true, 'User updated successfully', {
      user: user.toObject(),
      updated_fields: Object.keys(updatedFields)
    }));
  } catch (error) {
    log.error('Error updating user:', error);
    handleError(res, error, 'Error updating user');
  }
});

// Get user dashboard for admin
app.get('/api/admin/users/:id/dashboard', adminAuth, async (req, res) => {
  try {
    const userId = req.params.id;
    
    log.info(`📊 Fetching user dashboard for admin: ${userId}`);
    
    const user = await User.findById(userId)
      .select('-password -two_factor_secret')
      .lean();
    
    if (!user) {
      log.warn(`❌ User not found: ${userId}`);
      return res.status(404).json(formatResponse(false, 'User not found'));
    }
    
    // Get comprehensive user data
    const [
      investments,
      deposits,
      withdrawals,
      transactions,
      referrals,
      notifications
    ] = await Promise.all([
      Investment.find({ user: userId })
        .populate('plan', 'name daily_interest duration')
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      Deposit.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      Withdrawal.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      Transaction.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      Referral.find({ referrer: userId })
        .populate('referred_user', 'full_name email')
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      Notification.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean()
    ]);
    
    // Calculate comprehensive stats
    const activeInvestments = investments.filter(inv => inv.status === 'active');
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + (inv.amount || 0), 0);
    const totalEarnings = investments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0);
    const referralEarnings = referrals.reduce((sum, ref) => sum + (ref.earnings || 0), 0);
    
    const totalDepositsAmount = deposits
      .filter(d => d.status === 'approved')
      .reduce((sum, dep) => sum + (dep.amount || 0), 0);
    
    const totalWithdrawalsAmount = withdrawals
      .filter(w => w.status === 'paid')
      .reduce((sum, wdl) => sum + (wdl.amount || 0), 0);
    
    const dailyInterest = activeInvestments.reduce((sum, inv) => {
      if (inv.plan && inv.plan.daily_interest) {
        return sum + ((inv.amount || 0) * inv.plan.daily_interest / 100);
      }
      return sum;
    }, 0);
    
    const dashboardData = {
      user: user,
      summary: {
        portfolio_value: (user.balance || 0) + totalEarnings + referralEarnings,
        available_balance: user.balance || 0,
        total_earnings: totalEarnings,
        referral_earnings: referralEarnings,
        daily_interest: dailyInterest,
        active_investment_value: totalActiveValue,
        total_deposits: totalDepositsAmount,
        total_withdrawals: totalWithdrawalsAmount,
        net_profit: totalEarnings + referralEarnings - totalWithdrawalsAmount
      },
      counts: {
        total_investments: investments.length,
        active_investments: activeInvestments.length,
        total_deposits: deposits.filter(d => d.status === 'approved').length,
        total_withdrawals: withdrawals.filter(w => w.status === 'paid').length,
        total_referrals: referrals.length,
        unread_notifications: notifications.filter(n => !n.is_read).length
      },
      recent_activities: {
        investments: investments.slice(0, 5),
        deposits: deposits.slice(0, 5),
        withdrawals: withdrawals.slice(0, 5),
        transactions: transactions.slice(0, 10),
        referrals: referrals.slice(0, 5),
        notifications: notifications.slice(0, 5)
      }
    };
    
    log.info(`✅ User dashboard retrieved: ${userId}`);
    
    res.json(formatResponse(true, 'User dashboard retrieved successfully', dashboardData));
  } catch (error) {
    log.error('Error fetching user dashboard:', error);
    handleError(res, error, 'Error fetching user dashboard');
  }
});

// Update user role
app.put('/api/admin/users/:id/role', adminAuth, [
  body('role').isIn(['user', 'admin', 'super_admin']),
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.params.id;
    const adminId = req.user._id;
    const { role, remarks } = req.body;

    log.info(`👑 Updating user role: ${userId} to ${role}`);

    const user = await User.findById(userId);
    if (!user) {
      log.warn(`❌ User not found: ${userId}`);
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    const oldRole = user.role;
    user.role = role;
    await user.save();

    // Create audit log
    await createAdminAudit(
      adminId,
      'UPDATE_USER_ROLE',
      'user',
      userId,
      {
        old_role: oldRole,
        new_role: role,
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent']
    );

    // Create notification for user
    await createNotification(
      userId,
      'Role Updated',
      `Your account role has been updated to ${role}.`,
      'info',
      '/profile',
      { old_role: oldRole, new_role: role, updated_by: req.user.full_name }
    );

    log.info(`✅ User role updated: ${userId} from ${oldRole} to ${role}`);

    res.json(formatResponse(true, 'User role updated successfully', {
      user: {
        id: user._id,
        email: user.email,
        old_role: oldRole,
        new_role: role
      }
    }));
  } catch (error) {
    log.error('Error updating user role:', error);
    handleError(res, error, 'Error updating user role');
  }
});

// Update user status
app.put('/api/admin/users/:id/status', adminAuth, [
  body('is_active').isBoolean(),
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.params.id;
    const adminId = req.user._id;
    const { is_active, remarks } = req.body;

    log.info(`🔄 Updating user status: ${userId} to ${is_active ? 'active' : 'inactive'}`);

    const user = await User.findById(userId);
    if (!user) {
      log.warn(`❌ User not found: ${userId}`);
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    const oldStatus = user.is_active;
    user.is_active = is_active;
    await user.save();

    // Create audit log
    await createAdminAudit(
      adminId,
      'UPDATE_USER_STATUS',
      'user',
      userId,
      {
        old_status: oldStatus,
        new_status: is_active,
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent']
    );

    // Create notification for user
    await createNotification(
      userId,
      is_active ? 'Account Activated' : 'Account Deactivated',
      is_active 
        ? 'Your account has been activated by an administrator.' 
        : 'Your account has been deactivated by an administrator.',
      is_active ? 'success' : 'error',
      '/profile',
      { 
        status: is_active ? 'active' : 'inactive',
        remarks: remarks,
        updated_by: req.user.full_name 
      }
    );

    log.info(`✅ User status updated: ${userId} from ${oldStatus} to ${is_active}`);

    res.json(formatResponse(true, 'User status updated successfully', {
      user: {
        id: user._id,
        email: user.email,
        old_status: oldStatus,
        new_status: is_active
      }
    }));
  } catch (error) {
    log.error('Error updating user status:', error);
    handleError(res, error, 'Error updating user status');
  }
});

// Update user balance
app.put('/api/admin/users/:id/balance', adminAuth, [
  body('amount').isFloat(),
  body('type').isIn(['add', 'subtract', 'set']),
  body('description').notEmpty().trim(),
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.params.id;
    const adminId = req.user._id;
    const { amount, type, description, remarks } = req.body;

    log.info(`💰 Admin updating balance for user: ${userId}, type: ${type}, amount: ${amount}`);

    const user = await User.findById(userId);
    if (!user) {
      log.warn(`❌ User not found: ${userId}`);
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    const oldBalance = user.balance;
    let newBalance = oldBalance;
    
    if (type === 'add') {
      newBalance += parseFloat(amount);
    } else if (type === 'subtract') {
      newBalance -= parseFloat(amount);
      if (newBalance < 0) {
        log.warn(`❌ Insufficient balance for subtraction: ${oldBalance} - ${amount}`);
        return res.status(400).json(formatResponse(false, 'Insufficient balance for this operation'));
      }
    } else if (type === 'set') {
      newBalance = parseFloat(amount);
    }

    user.balance = newBalance;
    await user.save();

    // Create transaction
    const transactionType = type === 'add' ? 'bonus' : type === 'subtract' ? 'adjustment' : 'balance_update';
    await createTransaction(
      userId,
      transactionType,
      type === 'subtract' ? -parseFloat(amount) : parseFloat(amount),
      description,
      'completed',
      { 
        admin_id: adminId,
        admin_name: req.user.full_name,
        operation_type: type,
        old_balance: oldBalance,
        new_balance: newBalance,
        remarks: remarks
      }
    );

    // Create audit log
    await createAdminAudit(
      adminId,
      'UPDATE_USER_BALANCE',
      'user',
      userId,
      {
        old_balance: oldBalance,
        new_balance: newBalance,
        amount: amount,
        operation_type: type,
        description: description,
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent']
    );

    // Create notification for user
    await createNotification(
      userId,
      'Balance Updated',
      `Your account balance has been updated. ${description}`,
      type === 'add' ? 'success' : 'info',
      '/transactions',
      { 
        old_balance: oldBalance,
        new_balance: newBalance,
        amount: amount,
        operation: type,
        description: description,
        updated_by: req.user.full_name
      }
    );

    log.info(`✅ User balance updated: ${userId} from ${oldBalance} to ${newBalance}`);

    res.json(formatResponse(true, 'User balance updated successfully', {
      user: {
        id: user._id,
        email: user.email,
        old_balance: oldBalance,
        new_balance: newBalance,
        change: type === 'set' ? newBalance - oldBalance : parseFloat(amount) * (type === 'add' ? 1 : -1)
      },
      transaction: {
        type: transactionType,
        amount: type === 'subtract' ? -parseFloat(amount) : parseFloat(amount),
        description: description
      }
    }));
  } catch (error) {
    log.error('Error updating user balance:', error);
    handleError(res, error, 'Error updating user balance');
  }
});

// Verify bank details
app.post('/api/admin/users/:id/verify-bank', adminAuth, [
  body('verified').isBoolean(),
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.params.id;
    const adminId = req.user._id;
    const { verified, remarks } = req.body;

    log.info(`🏦 Admin verifying bank for user: ${userId}, verified: ${verified}`);

    const user = await User.findById(userId);
    if (!user) {
      log.warn(`❌ User not found: ${userId}`);
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    if (!user.bank_details) {
      log.warn(`❌ User has no bank details: ${userId}`);
      return res.status(400).json(formatResponse(false, 'User has no bank details'));
    }

    const oldVerified = user.bank_details.verified || false;
    user.bank_details.verified = verified;
    user.bank_details.verified_at = verified ? new Date() : null;
    await user.save();

    // Create audit log
    await createAdminAudit(
      adminId,
      'VERIFY_BANK_DETAILS',
      'user',
      userId,
      {
        old_verified: oldVerified,
        new_verified: verified,
        bank_details: {
          bank_name: user.bank_details.bank_name,
          account_name: user.bank_details.account_name,
          account_number: user.bank_details.account_number
        },
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent']
    );

    // Create notification for user
    await createNotification(
      userId,
      verified ? 'Bank Details Verified' : 'Bank Verification Removed',
      verified 
        ? 'Your bank account details have been verified and approved.' 
        : 'Your bank account verification has been removed.',
      verified ? 'success' : 'warning',
      '/profile',
      { 
        verified: verified,
        remarks: remarks,
        verified_by: req.user.full_name,
        verified_at: user.bank_details.verified_at
      }
    );

    log.info(`✅ Bank verification updated: ${userId} from ${oldVerified} to ${verified}`);

    res.json(formatResponse(true, 'Bank verification updated successfully', {
      user: {
        id: user._id,
        email: user.email,
        bank_details: user.bank_details
      }
    }));
  } catch (error) {
    log.error('Error verifying bank details:', error);
    handleError(res, error, 'Error verifying bank details');
  }
});

// Delete user (soft delete)
app.delete('/api/admin/users/:id', adminAuth, [
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const userId = req.params.id;
    const adminId = req.user._id;
    const { remarks } = req.body;

    log.info(`🗑️ Admin deleting user: ${userId}`);

    const user = await User.findById(userId);
    if (!user) {
      log.warn(`❌ User not found: ${userId}`);
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    // Soft delete - mark as inactive instead of actually deleting
    const oldStatus = user.is_active;
    user.is_active = false;
    user.deleted_at = new Date();
    user.deleted_by = adminId;
    await user.save();

    // Create audit log
    await createAdminAudit(
      adminId,
      'DELETE_USER',
      'user',
      userId,
      {
        user_email: user.email,
        user_name: user.full_name,
        old_status: oldStatus,
        new_status: false,
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent']
    );

    // Create notification for user
    await createNotification(
      userId,
      'Account Deactivated',
      'Your account has been deactivated by an administrator.',
      'error',
      '/contact',
      { 
        deactivated_by: req.user.full_name,
        deactivated_at: new Date(),
        remarks: remarks
      }
    );

    log.info(`✅ User deactivated: ${userId}`);

    res.json(formatResponse(true, 'User deactivated successfully', {
      user: {
        id: user._id,
        email: user.email,
        deactivated_at: user.deleted_at,
        deactivated_by: req.user.full_name
      }
    }));
  } catch (error) {
    log.error('Error deleting user:', error);
    handleError(res, error, 'Error deleting user');
  }
});

// ==================== ADMIN TRANSACTIONS ENDPOINT ====================
app.get('/api/admin/transactions', adminAuth, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 50,
      user_id,
      type,
      status,
      start_date,
      end_date,
      search
    } = req.query;
    
    const query = {};
    
    if (user_id) query.user = user_id;
    if (type) query.type = type;
    if (status) query.status = status;
    if (start_date || end_date) {
      query.createdAt = {};
      if (start_date) query.createdAt.$gte = new Date(start_date);
      if (end_date) query.createdAt.$lte = new Date(end_date);
    }
    
    // Search by reference or description
    if (search) {
      query.$or = [
        { reference: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } }
      ];
    }
    
    const skip = (page - 1) * limit;
    
    const [transactions, total] = await Promise.all([
      Transaction.find(query)
        .populate('user', 'full_name email phone')
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
        count: { $sum: 1 },
        total_amount: { $sum: '$amount' }
      }}
    ]);

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    log.info(`📋 Found ${total} transactions for admin`);

    res.json(formatResponse(true, 'Transactions retrieved successfully', {
      transactions,
      totals,
      pagination
    }));
  } catch (error) {
    log.error('Error fetching transactions:', error);
    handleError(res, error, 'Error fetching transactions');
  }
});

// ==================== ADMIN KYC ENDPOINTS ====================

// Get pending KYC submissions
app.get('/api/admin/pending-kyc', adminAuth, async (req, res) => {
  try {
    const pendingKYC = await KYCSubmission.find({ status: 'pending' })
      .populate('user', 'full_name email phone')
      .sort({ createdAt: -1 })
      .lean();

    log.info(`📋 Found ${pendingKYC.length} pending KYC submissions`);

    res.json(formatResponse(true, 'Pending KYC submissions retrieved', {
      kyc_submissions: pendingKYC,
      count: pendingKYC.length
    }));
  } catch (error) {
    log.error('Error fetching pending KYC:', error);
    handleError(res, error, 'Error fetching pending KYC');
  }
});

// Approve KYC submission
app.post('/api/admin/kyc/:id/approve', adminAuth, [
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const kycId = req.params.id;
    const adminId = req.user._id;
    const { remarks } = req.body;

    log.info(`✅ Approving KYC: ${kycId} by admin: ${adminId}`);

    const kyc = await KYCSubmission.findById(kycId).populate('user');
    if (!kyc) {
      log.warn(`❌ KYC submission not found: ${kycId}`);
      return res.status(404).json(formatResponse(false, 'KYC submission not found'));
    }

    kyc.status = 'approved';
    kyc.reviewed_by = adminId;
    kyc.reviewed_at = new Date();
    kyc.notes = remarks;
    await kyc.save();

    // Update user KYC status
    await User.findByIdAndUpdate(kyc.user._id, {
      kyc_status: 'verified',
      kyc_verified: true,
      kyc_verified_at: new Date()
    });

    // Create notification for user
    await createNotification(
      kyc.user._id,
      'KYC Approved',
      'Your KYC submission has been approved. You can now enjoy full platform access.',
      'success',
      '/profile'
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
        id_number: kyc.id_number,
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent']
    );

    log.info(`✅ KYC approved: ${kycId}`);

    res.json(formatResponse(true, 'KYC approved successfully', { kyc }));
  } catch (error) {
    log.error('Error approving KYC:', error);
    handleError(res, error, 'Error approving KYC');
  }
});

// Reject KYC submission
app.post('/api/admin/kyc/:id/reject', adminAuth, [
  body('rejection_reason').notEmpty().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const kycId = req.params.id;
    const adminId = req.user._id;
    const { rejection_reason } = req.body;

    log.info(`❌ Rejecting KYC: ${kycId} by admin: ${adminId}`);

    const kyc = await KYCSubmission.findById(kycId).populate('user');
    if (!kyc) {
      log.warn(`❌ KYC submission not found: ${kycId}`);
      return res.status(404).json(formatResponse(false, 'KYC submission not found'));
    }

    kyc.status = 'rejected';
    kyc.reviewed_by = adminId;
    kyc.reviewed_at = new Date();
    kyc.rejection_reason = rejection_reason;
    await kyc.save();

    // Update user KYC status
    await User.findByIdAndUpdate(kyc.user._id, {
      kyc_status: 'rejected'
    });

    // Create notification for user
    await createNotification(
      kyc.user._id,
      'KYC Rejected',
      `Your KYC submission was rejected. Reason: ${rejection_reason}. Please resubmit with correct documents.`,
      'error',
      '/kyc'
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
        id_type: kyc.id_type,
        id_number: kyc.id_number,
        rejection_reason: rejection_reason
      },
      req.ip,
      req.headers['user-agent']
    );

    log.info(`✅ KYC rejected: ${kycId}`);

    res.json(formatResponse(true, 'KYC rejected successfully', { kyc }));
  } catch (error) {
    log.error('Error rejecting KYC:', error);
    handleError(res, error, 'Error rejecting KYC');
  }
});

// ==================== ADMIN REFERRALS ENDPOINT ====================
app.get('/api/admin/referrals', adminAuth, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 50,
      referrer_id,
      status,
      start_date,
      end_date
    } = req.query;
    
    const query = {};
    
    if (referrer_id) query.referrer = referrer_id;
    if (status) query.status = status;
    if (start_date || end_date) {
      query.createdAt = {};
      if (start_date) query.createdAt.$gte = new Date(start_date);
      if (end_date) query.createdAt.$lte = new Date(end_date);
    }
    
    const skip = (page - 1) * limit;
    
    const [referrals, total] = await Promise.all([
      Referral.find(query)
        .populate('referrer', 'full_name email phone')
        .populate('referred_user', 'full_name email phone')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Referral.countDocuments(query)
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
          },
          paid_earnings: { 
            $sum: { $cond: [{ $eq: ['$earnings_paid', true] }, '$earnings', 0] }
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

    log.info(`📋 Found ${total} referrals for admin`);

    res.json(formatResponse(true, 'All referrals retrieved successfully', {
      referrals,
      platform_stats: platformStats[0] || {},
      pagination
    }));
  } catch (error) {
    log.error('Error fetching all referrals:', error);
    handleError(res, error, 'Error fetching all referrals');
  }
});

// ==================== ADMIN AUDIT LOGS ENDPOINT ====================
app.get('/api/admin/audit', adminAuth, async (req, res) => {
  try {
    const { page = 1, limit = 50, admin_id, action, start_date, end_date } = req.query;
    
    const query = {};
    
    if (admin_id) query.admin_id = admin_id;
    if (action) query.action = { $regex: action, $options: 'i' };
    if (start_date || end_date) {
      query.createdAt = {};
      if (start_date) query.createdAt.$gte = new Date(start_date);
      if (end_date) query.createdAt.$lte = new Date(end_date);
    }
    
    const skip = (page - 1) * limit;
    
    const [logs, total] = await Promise.all([
      AdminAudit.find(query)
        .populate('admin_id', 'full_name email')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      AdminAudit.countDocuments(query)
    ]);

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    log.info(`📋 Found ${total} audit logs`);

    res.json(formatResponse(true, 'Audit logs retrieved successfully', {
      logs,
      pagination
    }));
  } catch (error) {
    log.error('Error fetching audit logs:', error);
    handleError(res, error, 'Error fetching audit logs');
  }
});

// ==================== ADMIN NOTIFICATIONS SEND ENDPOINT ====================
app.post('/api/admin/notifications/send', adminAuth, [
  body('title').notEmpty().trim(),
  body('message').notEmpty().trim(),
  body('type').optional().isIn(['info', 'success', 'warning', 'error', 'promotional']),
  body('user_ids').optional().isArray(),
  body('send_to_all').optional().isBoolean(),
  body('role').optional().isIn(['user', 'admin', 'super_admin'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const { title, message, type = 'info', user_ids, send_to_all, role } = req.body;

    let users = [];

    if (user_ids && user_ids.length > 0) {
      // Send to specific users
      users = await User.find({ _id: { $in: user_ids } });
    } else if (send_to_all) {
      // Send to all users
      users = await User.find({});
    } else if (role) {
      // Send to users with specific role
      users = await User.find({ role });
    } else {
      return res.status(400).json(formatResponse(false, 'Please specify recipients'));
    }

    // Create notifications for each user
    const notifications = users.map(user => ({
      user: user._id,
      title,
      message,
      type,
      is_email_sent: false
    }));

    await Notification.insertMany(notifications);

    // Optionally, send emails (if email is configured and user has email notifications enabled)
    if (config.emailEnabled) {
      for (const user of users) {
        if (user.email_notifications) {
          await sendEmail(
            user.email,
            title,
            `<h2>${title}</h2><p>${message}</p>`
          );
        }
      }
    }

    // Create audit log
    await createAdminAudit(
      req.user._id,
      'SEND_NOTIFICATIONS',
      'system',
      null,
      {
        title,
        message,
        type,
        recipient_count: users.length,
        recipient_type: user_ids ? 'specific_users' : send_to_all ? 'all_users' : 'role_based',
        role: role
      },
      req.ip,
      req.headers['user-agent']
    );

    log.info(`📢 Admin sent notifications to ${users.length} users`);

    res.json(formatResponse(true, 'Notifications sent successfully', {
      sent_count: users.length
    }));
  } catch (error) {
    log.error('Error sending notifications:', error);
    handleError(res, error, 'Error sending notifications');
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

    log.info(`📁 Uploading file for user ${userId}, folder: ${folder}, purpose: ${purpose}`);

    const uploadResult = await handleFileUpload(req.file, folder, userId);

    log.info(`✅ File uploaded: ${uploadResult.filename}`);

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
    log.error('Error uploading file:', error);
    handleError(res, error, 'Error uploading file');
  }
});

// ==================== CRON JOBS FOR DAILY EARNINGS ====================

// Calculate daily earnings for active investments
cron.schedule('0 0 * * *', async () => {
  try {
    log.info('🔄 Running daily earnings calculation...');
    
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
        log.error(`Error processing investment ${investment._id}:`, error);
      }
    }
    
    log.info(`✅ Daily earnings calculated: Processed ${processedCount} investments, Total: ₦${totalEarnings.toLocaleString()}`);
    
  } catch (error) {
    log.error('Error in daily earnings cron job:', error);
  }
});

// ==================== ERROR HANDLING MIDDLEWARE ====================

// 404 handler
app.use((req, res) => {
  log.warn(`❌ 404 Not Found: ${req.method} ${req.url}`);
  res.status(404).json(formatResponse(false, 'Endpoint not found', {
    requested_url: req.url,
    method: req.method,
    available_endpoints: [
      '/api/auth/*',
      '/api/profile',
      '/api/investments/*',
      '/api/deposits/*',
      '/api/withdrawals/*',
      '/api/plans',
      '/api/referrals/*',
      '/api/admin/*',
      '/api/upload',
      '/health',
      '/debug/*'
    ]
  }));
});

// Global error handler
app.use((err, req, res, next) => {
  const errorId = crypto.randomBytes(8).toString('hex');
  
  log.error('🔥 Unhandled error:', {
    errorId,
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    user: req.user?._id
  });
  
  res.status(500).json(formatResponse(false, 
    config.nodeEnv === 'production' ? 'Internal server error' : err.message,
    config.debug ? { errorId, stack: err.stack } : { errorId }
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
      console.log('🚀 RAW WEALTHY BACKEND v47.1 - ENTERPRISE EDITION');
      console.log('='.repeat(80));
      console.log(`✅ Server running on port: ${config.port}`);
      console.log(`🌍 Environment: ${config.nodeEnv}`);
      console.log(`🔗 Client URL: ${config.clientURL}`);
      console.log(`🖥️  Server URL: ${config.serverURL}`);
      console.log(`📊 Database: ${mongoose.connection.readyState === 1 ? '✅ Connected' : '❌ Disconnected'}`);
      console.log(`🔧 Debug Mode: ${config.debug}`);
      console.log(`📅 Started at: ${new Date().toISOString()}`);
      console.log('='.repeat(80));
      console.log('\n📋 AVAILABLE ENDPOINTS:');
      console.log('  • /health - Health check');
      console.log('  • /debug/* - Debug endpoints');
      console.log('  • /api/auth/* - Authentication');
      console.log('  • /api/profile - User profile');
      console.log('  • /api/investments/* - Investments');
      console.log('  • /api/deposits/* - Deposits');
      console.log('  • /api/withdrawals/* - Withdrawals');
      console.log('  • /api/plans - Investment plans');
      console.log('  • /api/referrals/* - Referrals');
      console.log('  • /api/admin/* - Admin panel');
      console.log('  • /api/upload - File upload');
      console.log('='.repeat(80) + '\n');
      
      // Emit server start event
      io.emit('server_start', {
        timestamp: new Date(),
        version: '47.1.0',
        status: 'running'
      });
    });
    
  } catch (error) {
    log.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

// Handle graceful shutdown
process.on('SIGTERM', () => {
  log.info('🛑 SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    log.info('✅ HTTP server closed');
    mongoose.connection.close(false, () => {
      log.info('✅ MongoDB connection closed');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  log.info('🛑 SIGINT received. Shutting down gracefully...');
  server.close(() => {
    log.info('✅ HTTP server closed');
    mongoose.connection.close(false, () => {
      log.info('✅ MongoDB connection closed');
      process.exit(0);
    });
  });
});

// Start the server
startServer();
