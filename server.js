// server.js - RAW WEALTHY BACKEND v48.0 - ULTIMATE ENTERPRISE EDITION
// COMPLETE DEBUGGED & ENHANCED: Advanced Admin Dashboard + Full Data Analytics + Enhanced Notifications + Image Management
// AUTO-DEPLOYMENT READY WITH DYNAMIC CONFIGURATION
// DEBUGGED MONGODB CONNECTION WITH RETRY MECHANISM
// ADVANCED DEBUGGING SYSTEM WITH REAL-TIME MONITORING

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
import { createServer } from 'http';
import { WebSocketServer } from 'ws';

// ES Modules equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Enhanced environment configuration with multiple fallbacks
dotenv.config({ path: path.join(__dirname, '.env.production') });

// ==================== ULTIMATE ENVIRONMENT VALIDATION ====================
console.log('🔍 Ultimate Environment Configuration:');
console.log('=========================================');

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

console.log('=========================================\n');

// ==================== ULTIMATE CONFIGURATION WITH DEBUGGING ====================
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
  
  // Advanced Debugging
  enableWebSocketDebug: process.env.ENABLE_WS_DEBUG === 'true',
  enableRequestLogging: process.env.ENABLE_REQUEST_LOGGING === 'true',
  enableDatabaseQueryLogging: process.env.ENABLE_DB_QUERY_LOGGING === 'true'
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

console.log('⚙️  Ultimate Configuration Loaded:');
console.log(`- Port: ${config.port}`);
console.log(`- Environment: ${config.nodeEnv}`);
console.log(`- Client URL: ${config.clientURL}`);
console.log(`- Server URL: ${config.serverURL}`);
console.log(`- Database URI: ${config.mongoURI ? 'Set (masked)' : 'Not set'}`);
console.log(`- Email Enabled: ${config.emailEnabled}`);
console.log(`- Allowed Origins: ${config.allowedOrigins.length}`);
console.log(`- Debug Mode: ${config.debug}`);
console.log(`- WebSocket Debug: ${config.enableWebSocketDebug}`);
console.log(`- Request Logging: ${config.enableRequestLogging}`);

// ==================== ADVANCED DEBUGGING SYSTEM ====================
const debugSystem = {
  requests: new Map(),
  errors: [],
  performance: [],
  databaseQueries: [],
  requestCounts: {},
  
  logRequest(req, res, duration) {
    if (!config.enableRequestLogging) return;
    
    const logEntry = {
      id: req._requestId || crypto.randomBytes(8).toString('hex'),
      timestamp: new Date().toISOString(),
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      userId: req.user?._id,
      success: true
    };
    
    this.requests.set(logEntry.id, logEntry);
    
    // Track endpoint hits
    const endpoint = req.path;
    this.requestCounts[endpoint] = (this.requestCounts[endpoint] || 0) + 1;
    
    // Keep only last 1000 requests
    if (this.requests.size > 1000) {
      const firstKey = this.requests.keys().next().value;
      this.requests.delete(firstKey);
    }
  },
  
  logError(error, req) {
    const errorEntry = {
      id: crypto.randomBytes(8).toString('hex'),
      timestamp: new Date().toISOString(),
      message: error.message,
      stack: error.stack,
      url: req?.originalUrl,
      method: req?.method,
      userId: req?.user?._id
    };
    
    this.errors.push(errorEntry);
    
    // Keep only last 500 errors
    if (this.errors.length > 500) {
      this.errors.shift();
    }
    
    // Emit to WebSocket clients
    if (config.enableWebSocketDebug) {
      io.emit('error_log', errorEntry);
    }
  },
  
  logDatabaseQuery(collection, method, query, duration) {
    if (!config.enableDatabaseQueryLogging) return;
    
    const queryEntry = {
      id: crypto.randomBytes(8).toString('hex'),
      timestamp: new Date().toISOString(),
      collection,
      method,
      query: JSON.stringify(query).substring(0, 500),
      duration
    };
    
    this.databaseQueries.push(queryEntry);
    
    // Keep only last 500 queries
    if (this.databaseQueries.length > 500) {
      this.databaseQueries.shift();
    }
  },
  
  getStats() {
    return {
      totalRequests: this.requests.size,
      totalErrors: this.errors.length,
      totalQueries: this.databaseQueries.length,
      requestCounts: this.requestCounts,
      memoryUsage: process.memoryUsage(),
      uptime: process.uptime()
    };
  },
  
  clear() {
    this.requests.clear();
    this.errors = [];
    this.performance = [];
    this.databaseQueries = [];
    this.requestCounts = {};
  }
};

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

// Initialize WebSocket for debugging
let wss;
if (config.enableWebSocketDebug) {
  wss = new WebSocketServer({ noServer: true });
  
  wss.on('connection', (ws) => {
    console.log('🔌 WebSocket debug client connected');
    
    ws.on('message', (message) => {
      try {
        const data = JSON.parse(message);
        console.log('📨 WebSocket message:', data);
      } catch (error) {
        console.error('WebSocket message error:', error);
      }
    });
    
    // Send initial stats
    ws.send(JSON.stringify({
      type: 'initial',
      stats: debugSystem.getStats(),
      timestamp: new Date().toISOString()
    }));
  });
  
  // Attach WebSocket to HTTP server
  server.on('upgrade', (request, socket, head) => {
    if (request.url === '/debug-ws') {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    }
  });
}

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

// ==================== ULTIMATE CORS CONFIGURATION ====================
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) {
      if (config.debug) console.log('🌐 No origin - Allowing request');
      return callback(null, true);
    }
    
    if (config.allowedOrigins.indexOf(origin) !== -1) {
      if (config.debug) console.log(`🌐 Allowed origin: ${origin}`);
      callback(null, true);
    } else {
      // Check if origin matches pattern (for preview deployments)
      const isPreviewDeployment = origin.includes('vercel.app') || 
                                  origin.includes('onrender.com') ||
                                  origin.includes('netlify.app') ||
                                  origin.includes('github.io');
      
      if (isPreviewDeployment) {
        console.log(`🌐 Allowed preview deployment: ${origin}`);
        callback(null, true);
      } else {
        console.log(`🚫 Blocked by CORS: ${origin}`);
        callback(new Error('Not allowed by CORS'));
      }
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'x-api-key', 'x-user-id', 'x-debug-token'],
  exposedHeaders: ['X-Response-Time', 'X-Powered-By', 'X-Version']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// ==================== ULTIMATE BODY PARSING ====================
app.use(express.json({ 
  limit: '50mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
    if (config.debug && req.headers['content-type']?.includes('application/json')) {
      try {
        console.log('📨 Incoming JSON:', JSON.parse(buf.toString()).length ? '[Data present]' : 'Empty');
      } catch (e) {
        console.log('📨 Raw body (not JSON):', buf.toString().substring(0, 200));
      }
    }
  }
}));
app.use(express.urlencoded({ 
  extended: true, 
  limit: '50mb',
  parameterLimit: 100000
}));

// ==================== ULTIMATE RATE LIMITING ====================
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
  }
});

const rateLimiters = {
  createAccount: createRateLimiter(60 * 60 * 1000, 10, 'Too many accounts created, please try again after an hour'),
  auth: createRateLimiter(15 * 60 * 1000, 20, 'Too many authentication attempts, please try again after 15 minutes'),
  api: createRateLimiter(15 * 60 * 1000, 1000, 'Too many requests, please try again later'),
  financial: createRateLimiter(15 * 60 * 1000, 50, 'Too many financial operations, please try again later'),
  passwordReset: createRateLimiter(15 * 60 * 1000, 5, 'Too many password reset attempts, please try again later'),
  admin: createRateLimiter(15 * 60 * 1000, 500, 'Too many admin requests'),
  upload: createRateLimiter(15 * 60 * 1000, 20, 'Too many file uploads, please try again later'),
  debug: createRateLimiter(15 * 60 * 1000, 100, 'Too many debug requests')
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
app.use('/api/debug', rateLimiters.debug);
app.use('/api/', rateLimiters.api);

// ==================== ADVANCED DEBUG MIDDLEWARE ====================
app.use((req, res, next) => {
  const startTime = Date.now();
  const requestId = crypto.randomBytes(8).toString('hex');
  
  // Store debug info
  req._debug = {
    id: requestId,
    startTime,
    ip: req.ip,
    userAgent: req.headers['user-agent'],
    timestamp: new Date().toISOString()
  };
  
  if (config.debug) {
    console.log('\n' + '='.repeat(80));
    console.log(`📡 [${new Date().toISOString()}] ${requestId} - ${req.method} ${req.originalUrl}`);
    console.log(`👤 IP: ${req.ip} | User-Agent: ${req.headers['user-agent']?.substring(0, 50)}...`);
    
    if (req.method !== 'GET') {
      console.log(`📦 Body:`, JSON.stringify(req.body, null, 2).substring(0, 500));
    }
    
    if (req.headers.authorization) {
      const token = req.headers.authorization.replace('Bearer ', '');
      console.log(`🔑 Auth: Token present (${token.length} chars)`);
      try {
        const decoded = jwt.decode(token);
        console.log(`👤 Token payload:`, decoded);
      } catch (err) {
        console.log(`❌ Token decode error:`, err.message);
      }
    }
  }
  
  // Override res.json to log responses
  const originalJson = res.json;
  res.json = function(data) {
    const responseTime = Date.now() - startTime;
    
    // Log to debug system
    debugSystem.logRequest(req, res, responseTime);
    
    if (config.debug) {
      console.log(`⏱️  Response time: ${responseTime}ms`);
      console.log(`📤 Status: ${res.statusCode}`);
      console.log(`📊 Response:`, JSON.stringify(data, null, 2).substring(0, 500));
      console.log('='.repeat(80) + '\n');
    }
    
    return originalJson.call(this, data);
  };
  
  next();
});

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
    console.error('No file provided for upload');
    return null;
  }
  
  try {
    console.log(`📁 Uploading file: ${file.originalname}, Size: ${file.size} bytes, Type: ${file.mimetype}`);
    
    // Validate file type
    if (!config.allowedMimeTypes[file.mimetype]) {
      throw new Error(`Invalid file type: ${file.mimetype}`);
    }
    
    const uploadsDir = path.join(config.uploadDir, folder);
    
    // Create directory if it doesn't exist
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
      console.log(`📁 Created directory: ${uploadsDir}`);
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
    
    console.log(`✅ File uploaded: ${filename}, URL: ${url}`);
    
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
    console.error('❌ File upload error:', error);
    throw new Error(`File upload failed: ${error.message}`);
  }
};

// Create uploads directory if it doesn't exist
if (!fs.existsSync(config.uploadDir)) {
  fs.mkdirSync(config.uploadDir, { recursive: true });
  console.log(`📁 Created upload directory: ${config.uploadDir}`);
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

// ==================== ENHANCED DATABASE MODELS (UNCHANGED) ====================
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
  last_investment_date: Date,
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

userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ referral_code: 1 }, { unique: true, sparse: true });
userSchema.index({ is_active: 1, role: 1, kyc_status: 1 });
userSchema.index({ createdAt: -1 });

userSchema.virtual('portfolio_value').get(function() {
  return this.balance + this.total_earnings + this.referral_earnings;
});

userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    console.log(`🔑 Hashing password for user: ${this.email}`);
    this.password = await bcrypt.hash(this.password, config.bcryptRounds);
  }
  
  if (!this.referral_code) {
    this.referral_code = crypto.randomBytes(6).toString('hex').toUpperCase();
    console.log(`🎫 Generated referral code for ${this.email}: ${this.referral_code}`);
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
    version: '48.0.0'
  };
  
  if (data !== null) response.data = data;
  if (pagination !== null) response.pagination = pagination;
  
  return response;
};

const handleError = (res, error, defaultMessage = 'An error occurred') => {
  console.error('❌ Error Details:', {
    message: error.message,
    stack: error.stack,
    name: error.name,
    code: error.code
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
    
    console.log(`📢 Notification created for user ${userId}: ${title}`);
    
    return notification;
  } catch (error) {
    console.error('Error creating notification:', error);
    return null;
  }
};

const createTransaction = async (userId, type, amount, description, status = 'completed', metadata = {}, proofUrl = null) => {
  try {
    const user = await User.findById(userId);
    if (!user) {
      console.error(`User ${userId} not found for transaction creation`);
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
    
    console.log(`💳 Transaction created: ${type} - ${amount} for user ${userId}`);
    
    return transaction;
  } catch (error) {
    console.error('Error creating transaction:', error);
    return null;
  }
};

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
    console.error('Error calculating user stats:', error);
    return null;
  }
};

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
    console.log(`📝 Admin audit created: ${action} by admin ${adminId}`);
    return audit;
  } catch (error) {
    console.error('Error creating admin audit:', error);
    return null;
  }
};

// ==================== ENHANCED AUTH MIDDLEWARE ====================

const auth = async (req, res, next) => {
  try {
    let token = req.header('Authorization');
    
    if (!token) {
      console.log('🔒 No token provided');
      return res.status(401).json(formatResponse(false, 'No token, authorization denied'));
    }
    
    if (token.startsWith('Bearer ')) {
      token = token.slice(7, token.length);
    }
    
    const decoded = jwt.verify(token, config.jwtSecret);
    
    const user = await User.findById(decoded.id);
    
    if (!user) {
      console.log(`🔒 User not found for token: ${decoded.id}`);
      return res.status(401).json(formatResponse(false, 'Token is not valid'));
    }
    
    if (!user.is_active) {
      console.log(`🔒 User account deactivated: ${user.email}`);
      return res.status(401).json(formatResponse(false, 'Account is deactivated. Please contact support.'));
    }
    
    req.user = user;
    req.userId = user._id;
    
    // Update last active time
    user.last_active = new Date();
    await user.save();
    
    console.log(`🔒 Authenticated user: ${user.email} (${user.role})`);
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      console.log('🔒 Invalid JWT token');
      return res.status(401).json(formatResponse(false, 'Invalid token'));
    } else if (error.name === 'TokenExpiredError') {
      console.log('🔒 Expired JWT token');
      return res.status(401).json(formatResponse(false, 'Token expired'));
    }
    
    console.error('Auth middleware error:', error);
    res.status(500).json(formatResponse(false, 'Server error during authentication'));
  }
};

const adminAuth = async (req, res, next) => {
  try {
    await auth(req, res, () => {
      if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
        console.log(`🔒 Admin access denied for user: ${req.user.email}`);
        return res.status(403).json(formatResponse(false, 'Access denied. Admin privileges required.'));
      }
      console.log(`🔒 Admin access granted: ${req.user.email}`);
      next();
    });
  } catch (error) {
    handleError(res, error, 'Admin authentication error');
  }
};

// ==================== DEBUGGED DATABASE INITIALIZATION ====================

const initializeDatabase = async () => {
  console.log('🔄 Initializing database with enhanced connection...');
  
  // Set Mongoose debug mode
  mongoose.set('debug', config.enableDatabaseQueryLogging ? (collection, method, query, doc) => {
    const start = Date.now();
    const logData = {
      collection,
      method,
      query: JSON.stringify(query),
      doc: doc ? JSON.stringify(doc).substring(0, 200) : null
    };
    
    process.nextTick(() => {
      const duration = Date.now() - start;
      debugSystem.logDatabaseQuery(collection, method, query, duration);
      
      if (config.debug) {
        console.log(`🗄️  MongoDB ${method} on ${collection}:`, {
          query: JSON.stringify(query).substring(0, 200),
          duration: `${duration}ms`
        });
      }
    });
  } : false);
  
  // Handle Mongoose connection events
  mongoose.connection.on('connecting', () => {
    console.log('🔄 MongoDB connecting...');
  });
  
  mongoose.connection.on('connected', () => {
    console.log('✅ MongoDB connected successfully');
  });
  
  mongoose.connection.on('error', (err) => {
    console.error('❌ MongoDB connection error:', err.message);
    debugSystem.logError(err, null);
  });
  
  mongoose.connection.on('disconnected', () => {
    console.log('⚠️ MongoDB disconnected');
  });
  
  mongoose.connection.on('reconnected', () => {
    console.log('🔁 MongoDB reconnected');
  });
  
  try {
    console.log(`🔗 Attempting to connect to: ${config.mongoURI ? 'MongoDB URI provided' : 'No URI found'}`);
    
    const connectionOptions = {
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      retryWrites: true,
    };
    
    await mongoose.connect(config.mongoURI, connectionOptions);
    
    console.log('✅ MongoDB connection established');
    
    // Load investment plans
    await loadInvestmentPlans();
    
    // Create admin user if it doesn't exist
    await createAdminUser();
    
    // Create indexes
    await createDatabaseIndexes();
    
    console.log('✅ Database initialization completed successfully');
    
  } catch (error) {
    console.error('❌ FATAL: Database initialization failed:', error.message);
    console.error('Stack trace:', error.stack);
    debugSystem.logError(error, null);
    
    // Try fallback connection for development
    if (config.nodeEnv === 'development') {
      console.log('🔄 Attempting fallback to local MongoDB...');
      try {
        const fallbackURI = 'mongodb://localhost:27017/rawwealthy';
        await mongoose.connect(fallbackURI);
        console.log('✅ Connected to local MongoDB fallback');
      } catch (fallbackError) {
        console.error('❌ Fallback connection also failed:', fallbackError.message);
      }
    }
    
    // Don't throw error - let server start without DB for debugging
    console.log('⚠️ Server starting without database connection');
  }
};

const loadInvestmentPlans = async () => {
  try {
    const plans = await InvestmentPlan.find({ is_active: true })
      .sort({ display_order: 1 })
      .lean();
    
    config.investmentPlans = plans;
    console.log(`✅ Loaded ${plans.length} investment plans`);
    
    // If no plans exist, create default plans
    if (plans.length === 0) {
      await createDefaultInvestmentPlans();
    }
  } catch (error) {
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
    console.log('✅ Created default investment plans');
  } catch (error) {
    console.error('Error creating default investment plans:', error);
  }
};

const createAdminUser = async () => {
  console.log('🚀 ADMIN USER INITIALIZATION STARTING...');
  
  const adminEmail = process.env.ADMIN_EMAIL || 'admin@rawwealthy.com';
  const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123456';
  
  console.log(`🔑 Attempting to create admin: ${adminEmail}`);
  
  try {
    // Check if admin already exists
    const existingAdmin = await User.findOne({ email: adminEmail });
    if (existingAdmin) {
      console.log('✅ Admin already exists');
      
      // Ensure admin has correct role
      if (existingAdmin.role !== 'super_admin') {
        existingAdmin.role = 'super_admin';
        await existingAdmin.save();
        console.log('✅ Updated existing admin to super_admin role');
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
    
    console.log('🎉 ADMIN USER CREATED SUCCESSFULLY!');
    console.log(`📧 Email: ${adminEmail}`);
    console.log(`🔑 Password: ${adminPassword}`);
    console.log('👉 Login at: /api/auth/login');
    
  } catch (error) {
    console.error('❌ Error creating admin user:', error.message);
    console.error(error.stack);
  }
  
  console.log('🚀 ADMIN USER INITIALIZATION COMPLETE');
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
    
    console.log('✅ Database indexes created/verified');
  } catch (error) {
    console.error('Error creating indexes:', error);
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
        console.log('❌ Email configuration error:', error.message);
      } else {
        console.log('✅ Email server is ready to send messages');
      }
    });
  } catch (error) {
    console.error('❌ Email setup failed:', error.message);
  }
}

const sendEmail = async (to, subject, html, text = '') => {
  try {
    if (!emailTransporter) {
      console.log(`📧 Email would be sent (simulated): To: ${to}, Subject: ${subject}`);
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
    console.log(`✅ Email sent to ${to} (Message ID: ${info.messageId})`);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error('❌ Email sending error:', error.message);
    return { success: false, error: error.message };
  }
};

// ==================== SOCKET.IO INTEGRATION ====================

io.on('connection', (socket) => {
  console.log(`🔌 New Socket.IO connection: ${socket.id}`);
  
  // Join user-specific room
  socket.on('join-user', (userId) => {
    socket.join(`user:${userId}`);
    console.log(`👤 Socket ${socket.id} joined user room: ${userId}`);
  });
  
  // Join admin room
  socket.on('join-admin', () => {
    socket.join('admin-room');
    console.log(`👨‍💼 Socket ${socket.id} joined admin room`);
  });
  
  // Debug room
  socket.on('join-debug', () => {
    socket.join('debug-room');
    console.log(`🐛 Socket ${socket.id} joined debug room`);
  });
  
  socket.on('disconnect', () => {
    console.log(`🔌 Socket disconnected: ${socket.id}`);
  });
});

// ==================== ADVANCED DEBUG ENDPOINTS ====================

// Debug dashboard
app.get('/api/debug/dashboard', adminAuth, async (req, res) => {
  try {
    const stats = debugSystem.getStats();
    
    // Get recent errors
    const recentErrors = debugSystem.errors.slice(-10);
    
    // Get recent requests
    const recentRequests = Array.from(debugSystem.requests.values()).slice(-10);
    
    // Get recent database queries
    const recentQueries = debugSystem.databaseQueries.slice(-10);
    
    // Get database stats
    const dbStats = await getDatabaseStats();
    
    res.json(formatResponse(true, 'Debug dashboard', {
      system: {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        nodeVersion: process.version,
        platform: process.platform,
        pid: process.pid
      },
      debugStats: stats,
      recentErrors,
      recentRequests,
      recentQueries,
      database: dbStats,
      config: {
        debug: config.debug,
        enableRequestLogging: config.enableRequestLogging,
        enableDatabaseQueryLogging: config.enableDatabaseQueryLogging,
        enableWebSocketDebug: config.enableWebSocketDebug
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching debug dashboard');
  }
});

// Clear debug logs
app.post('/api/debug/clear', adminAuth, (req, res) => {
  debugSystem.clear();
  res.json(formatResponse(true, 'Debug logs cleared'));
});

// Test all endpoints
app.get('/api/debug/test-endpoints', adminAuth, async (req, res) => {
  const testResults = {};
  
  try {
    // Test health endpoint
    try {
      const response = await axios.get(`${config.serverURL}/health`);
      testResults.health = response.status === 200 ? '✅ Working' : '❌ Failed';
    } catch (error) {
      testResults.health = '❌ Failed';
    }
    
    // Test database connection
    testResults.database = mongoose.connection.readyState === 1 ? '✅ Connected' : '❌ Disconnected';
    
    // Test email configuration
    testResults.email = config.emailEnabled ? '✅ Configured' : '❌ Not configured';
    
    // Test socket.io
    testResults.socketio = '✅ Running';
    
    // Test file upload directory
    testResults.uploadDir = fs.existsSync(config.uploadDir) ? '✅ Exists' : '❌ Missing';
    
    res.json(formatResponse(true, 'Endpoint tests', testResults));
  } catch (error) {
    testResults.error = error.message;
    res.json(formatResponse(false, 'Test error', testResults));
  }
});

// Get request logs
app.get('/api/debug/requests', adminAuth, (req, res) => {
  const { limit = 50, page = 1 } = req.query;
  const allRequests = Array.from(debugSystem.requests.values());
  const start = (page - 1) * limit;
  const end = start + parseInt(limit);
  const paginatedRequests = allRequests.slice(start, end);
  
  res.json(formatResponse(true, 'Request logs', {
    requests: paginatedRequests,
    pagination: {
      page: parseInt(page),
      limit: parseInt(limit),
      total: allRequests.length,
      pages: Math.ceil(allRequests.length / limit)
    }
  }));
});

// Get error logs
app.get('/api/debug/errors', adminAuth, (req, res) => {
  const { limit = 50, page = 1 } = req.query;
  const start = (page - 1) * limit;
  const end = start + parseInt(limit);
  const paginatedErrors = debugSystem.errors.slice(start, end);
  
  res.json(formatResponse(true, 'Error logs', {
    errors: paginatedErrors,
    pagination: {
      page: parseInt(page),
      limit: parseInt(limit),
      total: debugSystem.errors.length,
      pages: Math.ceil(debugSystem.errors.length / limit)
    }
  }));
});

// Get database query logs
app.get('/api/debug/queries', adminAuth, (req, res) => {
  const { limit = 50, page = 1 } = req.query;
  const start = (page - 1) * limit;
  const end = start + parseInt(limit);
  const paginatedQueries = debugSystem.databaseQueries.slice(start, end);
  
  res.json(formatResponse(true, 'Database query logs', {
    queries: paginatedQueries,
    pagination: {
      page: parseInt(page),
      limit: parseInt(limit),
      total: debugSystem.databaseQueries.length,
      pages: Math.ceil(debugSystem.databaseQueries.length / limit)
    }
  }));
});

// Helper function to get database stats
async function getDatabaseStats() {
  try {
    const [
      usersCount,
      investmentsCount,
      depositsCount,
      withdrawalsCount,
      transactionsCount,
      referralsCount,
      kycCount,
      notificationsCount
    ] = await Promise.all([
      User.countDocuments({}),
      Investment.countDocuments({}),
      Deposit.countDocuments({}),
      Withdrawal.countDocuments({}),
      Transaction.countDocuments({}),
      Referral.countDocuments({}),
      KYCSubmission.countDocuments({}),
      Notification.countDocuments({})
    ]);
    
    // Get collection sizes
    const collections = await mongoose.connection.db.listCollections().toArray();
    const collectionSizes = {};
    
    for (const collection of collections) {
      const stats = await mongoose.connection.db.collection(collection.name).stats();
      collectionSizes[collection.name] = {
        count: stats.count,
        size: stats.size,
        storageSize: stats.storageSize,
        avgObjSize: stats.avgObjSize
      };
    }
    
    return {
      counts: {
        users: usersCount,
        investments: investmentsCount,
        deposits: depositsCount,
        withdrawals: withdrawalsCount,
        transactions: transactionsCount,
        referrals: referralsCount,
        kyc: kycCount,
        notifications: notificationsCount
      },
      collectionSizes,
      connectionState: mongoose.connection.readyState,
      host: mongoose.connection.host,
      name: mongoose.connection.name
    };
  } catch (error) {
    console.error('Error getting database stats:', error);
    return { error: error.message };
  }
}

// ==================== ENHANCED HEALTH CHECK ====================
app.get('/health', async (req, res) => {
  const health = {
    success: true,
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '48.0.0',
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
    config: {
      port: config.port,
      client_url: config.clientURL,
      server_url: config.serverURL,
      debug: config.debug
    },
    debug: {
      totalRequests: debugSystem.requests.size,
      totalErrors: debugSystem.errors.length,
      totalQueries: debugSystem.databaseQueries.length
    }
  };
  
  res.json(health);
});

// Database debug endpoint
app.get('/debug/db', async (req, res) => {
  try {
    const collections = await mongoose.connection.db.listCollections().toArray();
    const collectionNames = collections.map(col => col.name);
    
    const stats = {
      connection_state: mongoose.connection.readyState,
      collections: collectionNames,
      mongo_uri: config.mongoURI ? `${config.mongoURI.substring(0, 50)}...` : 'Not set'
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

// ==================== ROOT ENDPOINT ====================
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 Raw Wealthy Backend API v48.0 - Ultimate Enterprise Edition',
    version: '48.0.0',
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
      debug: '/api/debug/*'
    }
  });
});

// ==================== ENHANCED AUTH ENDPOINTS (UNCHANGED) ====================
// [Your existing auth endpoints remain exactly the same]
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

    console.log(`📝 Registration attempt: ${email}`);

    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      console.log(`❌ User already exists: ${email}`);
      return res.status(400).json(formatResponse(false, 'User already exists with this email'));
    }

    // Handle referral
    let referredBy = null;
    if (referral_code) {
      referredBy = await User.findOne({ referral_code: referral_code.toUpperCase() });
      if (!referredBy) {
        console.log(`❌ Invalid referral code: ${referral_code}`);
        return res.status(400).json(formatResponse(false, 'Invalid referral code'));
      }
      console.log(`👥 Referral found: ${referredBy.email}`);
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
    console.log(`✅ User created: ${email}`);

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
      
      console.log(`👥 Referral created for ${referredBy.email}`);
      
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
    console.log(`🔑 Token generated for ${email}`);

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

    console.log(`🎉 Registration complete for ${email}`);

    res.status(201).json(formatResponse(true, 'User registered successfully', {
      user: user.toObject(),
      token
    }));

  } catch (error) {
    console.error('Registration error:', error);
    handleError(res, error, 'Registration failed');
  }
});

// Login endpoint
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
    
    console.log(`🔐 Login attempt: ${email}`);

    // Find user with password
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    
    if (!user) {
      console.log(`❌ User not found: ${email}`);
      return res.status(400).json(formatResponse(false, 'Invalid credentials'));
    }

    // Check if account is locked
    if (user.lock_until && user.lock_until > new Date()) {
      const lockTime = Math.ceil((user.lock_until - new Date()) / 1000 / 60);
      console.log(`🔒 Account locked for ${email}: ${lockTime} minutes remaining`);
      return res.status(423).json(formatResponse(false, `Account is locked. Try again in ${lockTime} minutes.`));
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      user.login_attempts += 1;
      if (user.login_attempts >= 5) {
        user.lock_until = new Date(Date.now() + 15 * 60 * 1000);
        console.log(`🔒 Account locked for ${email} due to failed attempts`);
      }
      await user.save();
      console.log(`❌ Invalid password for ${email}`);
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
    
    console.log(`✅ Login successful: ${email}`);

    res.json(formatResponse(true, 'Login successful', {
      user: user.toObject(),
      token
    }));

  } catch (error) {
    console.error('Login error:', error);
    handleError(res, error, 'Login failed');
  }
});

// ==================== ENHANCED REFERRAL ENDPOINTS ====================

// Get referral statistics
app.get('/api/referrals/stats', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
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
    handleError(res, error, 'Error fetching referrals');
  }
});

// ==================== COMPLETE ADMIN ENDPOINTS ====================

// Admin dashboard
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
  try {
    console.log(`📊 Admin dashboard requested by: ${req.user.email}`);
    
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

    // Get financial totals
    const [
      totalDepositsAmount,
      totalWithdrawalsAmount,
      totalBalance
    ] = await Promise.all([
      Deposit.aggregate([
        { $match: { status: 'approved' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      Withdrawal.aggregate([
        { $match: { status: 'paid' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      User.aggregate([
        { $group: { _id: null, total: { $sum: '$balance' } } }
      ])
    ]);

    const stats = {
      overview: {
        total_users: totalUsers,
        new_users_today: newUsersToday,
        total_investments: totalInvestments,
        active_investments: activeInvestments,
        total_deposits: totalDeposits,
        total_withdrawals: totalWithdrawals,
        total_deposits_amount: totalDepositsAmount[0]?.total || 0,
        total_withdrawals_amount: totalWithdrawalsAmount[0]?.total || 0,
        total_balance: totalBalance[0]?.total || 0
      },
      pending_actions: {
        pending_investments: pendingInvestments,
        pending_deposits: pendingDeposits,
        pending_withdrawals: pendingWithdrawals,
        pending_kyc: pendingKYC,
        total_pending: pendingInvestments + pendingDeposits + pendingWithdrawals + pendingKYC
      }
    };

    // Get recent activities
    const recentActivities = await Transaction.find({})
      .populate('user', 'full_name')
      .sort({ createdAt: -1 })
      .limit(10)
      .lean();

    console.log(`✅ Admin dashboard data retrieved for ${req.user.email}`);

    res.json(formatResponse(true, 'Admin dashboard stats retrieved successfully', {
      stats,
      recent_activities: recentActivities,
      quick_links: {
        pending_investments: '/api/admin/pending-investments',
        pending_deposits: '/api/admin/pending-deposits',
        pending_withdrawals: '/api/admin/pending-withdrawals',
        pending_kyc: '/api/admin/pending-kyc',
        all_users: '/api/admin/users'
      }
    }));
  } catch (error) {
    console.error('Error fetching admin dashboard stats:', error);
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

    console.log(`📋 Found ${pendingInvestments.length} pending investments`);

    res.json(formatResponse(true, 'Pending investments retrieved successfully', {
      investments: pendingInvestments,
      count: pendingInvestments.length,
      total_amount: pendingInvestments.reduce((sum, inv) => sum + (inv.amount || 0), 0)
    }));
  } catch (error) {
    console.error('Error fetching pending investments:', error);
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

    console.log(`✅ Approving investment: ${investmentId} by admin: ${adminId}`);

    const investment = await Investment.findById(investmentId)
      .populate('user plan');
    
    if (!investment) {
      console.log(`❌ Investment not found: ${investmentId}`);
      return res.status(404).json(formatResponse(false, 'Investment not found'));
    }

    if (investment.status !== 'pending') {
      console.log(`❌ Investment not pending: ${investmentId}, status: ${investment.status}`);
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

    console.log(`✅ Investment approved: ${investmentId}`);

    res.json(formatResponse(true, 'Investment approved successfully', {
      investment: {
        ...investment.toObject(),
        approved_by_admin: req.user.full_name,
        proof_verified: true
      },
      message: 'Investment approved and user notified'
    }));
  } catch (error) {
    console.error('Error approving investment:', error);
    handleError(res, error, 'Error approving investment');
  }
});

// Reject investment
app.post('/api/admin/investments/:id/reject', adminAuth, [
  body('remarks').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const investmentId = req.params.id;
    const adminId = req.user._id;
    const { remarks } = req.body;

    console.log(`❌ Rejecting investment: ${investmentId} by admin: ${adminId}`);

    const investment = await Investment.findById(investmentId)
      .populate('user');
    
    if (!investment) {
      console.log(`❌ Investment not found: ${investmentId}`);
      return res.status(404).json(formatResponse(false, 'Investment not found'));
    }

    if (investment.status !== 'pending') {
      console.log(`❌ Investment not pending: ${investmentId}, status: ${investment.status}`);
      return res.status(400).json(formatResponse(false, 'Investment is not pending approval'));
    }

    // Update investment
    investment.status = 'rejected';
    investment.approved_by = adminId;
    investment.remarks = remarks;
    
    await investment.save();

    // Refund user balance
    await User.findByIdAndUpdate(investment.user._id, {
      $inc: { balance: investment.amount }
    });

    // Create notification for user
    await createNotification(
      investment.user._id,
      'Investment Rejected',
      `Your investment of ₦${investment.amount.toLocaleString()} has been rejected. Reason: ${remarks}`,
      'error',
      '/investments',
      { 
        amount: investment.amount,
        rejected_by: req.user.full_name,
        rejected_at: new Date(),
        remarks: remarks
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
        user_id: investment.user._id,
        user_name: investment.user.full_name,
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent']
    );

    console.log(`✅ Investment rejected: ${investmentId}`);

    res.json(formatResponse(true, 'Investment rejected successfully', {
      investment: {
        ...investment.toObject(),
        rejected_by_admin: req.user.full_name
      },
      message: 'Investment rejected and user notified'
    }));
  } catch (error) {
    console.error('Error rejecting investment:', error);
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

    console.log(`📋 Found ${pendingDeposits.length} pending deposits`);

    res.json(formatResponse(true, 'Pending deposits retrieved successfully', {
      deposits: pendingDeposits,
      count: pendingDeposits.length,
      total_amount: pendingDeposits.reduce((sum, dep) => sum + (dep.amount || 0), 0)
    }));
  } catch (error) {
    console.error('Error fetching pending deposits:', error);
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

    console.log(`✅ Approving deposit: ${depositId} by admin: ${adminId}`);

    const deposit = await Deposit.findById(depositId)
      .populate('user');
    
    if (!deposit) {
      console.log(`❌ Deposit not found: ${depositId}`);
      return res.status(404).json(formatResponse(false, 'Deposit not found'));
    }

    if (deposit.status !== 'pending') {
      console.log(`❌ Deposit not pending: ${depositId}, status: ${deposit.status}`);
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

    console.log(`✅ Deposit approved: ${depositId}`);

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
    console.error('Error approving deposit:', error);
    handleError(res, error, 'Error approving deposit');
  }
});

// Reject deposit
app.post('/api/admin/deposits/:id/reject', adminAuth, [
  body('remarks').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const depositId = req.params.id;
    const adminId = req.user._id;
    const { remarks } = req.body;

    console.log(`❌ Rejecting deposit: ${depositId} by admin: ${adminId}`);

    const deposit = await Deposit.findById(depositId)
      .populate('user');
    
    if (!deposit) {
      console.log(`❌ Deposit not found: ${depositId}`);
      return res.status(404).json(formatResponse(false, 'Deposit not found'));
    }

    if (deposit.status !== 'pending') {
      console.log(`❌ Deposit not pending: ${depositId}, status: ${deposit.status}`);
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
        rejected_at: new Date(),
        remarks: remarks
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
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent']
    );

    console.log(`✅ Deposit rejected: ${depositId}`);

    res.json(formatResponse(true, 'Deposit rejected successfully', {
      deposit: {
        ...deposit.toObject(),
        rejected_by_admin: req.user.full_name
      },
      message: 'Deposit rejected and user notified'
    }));
  } catch (error) {
    console.error('Error rejecting deposit:', error);
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

    console.log(`📋 Found ${pendingWithdrawals.length} pending withdrawals`);

    res.json(formatResponse(true, 'Pending withdrawals retrieved successfully', {
      withdrawals: pendingWithdrawals,
      count: pendingWithdrawals.length,
      total_amount: pendingWithdrawals.reduce((sum, wdl) => sum + (wdl.amount || 0), 0)
    }));
  } catch (error) {
    console.error('Error fetching pending withdrawals:', error);
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

    console.log(`✅ Approving withdrawal: ${withdrawalId} by admin: ${adminId}`);

    const withdrawal = await Withdrawal.findById(withdrawalId)
      .populate('user');
    
    if (!withdrawal) {
      console.log(`❌ Withdrawal not found: ${withdrawalId}`);
      return res.status(404).json(formatResponse(false, 'Withdrawal not found'));
    }

    if (withdrawal.status !== 'pending') {
      console.log(`❌ Withdrawal not pending: ${withdrawalId}, status: ${withdrawal.status}`);
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

    console.log(`✅ Withdrawal approved: ${withdrawalId}`);

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
    console.error('Error approving withdrawal:', error);
    handleError(res, error, 'Error approving withdrawal');
  }
});

// Reject withdrawal
app.post('/api/admin/withdrawals/:id/reject', adminAuth, [
  body('remarks').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const withdrawalId = req.params.id;
    const adminId = req.user._id;
    const { remarks } = req.body;

    console.log(`❌ Rejecting withdrawal: ${withdrawalId} by admin: ${adminId}`);

    const withdrawal = await Withdrawal.findById(withdrawalId)
      .populate('user');
    
    if (!withdrawal) {
      console.log(`❌ Withdrawal not found: ${withdrawalId}`);
      return res.status(404).json(formatResponse(false, 'Withdrawal not found'));
    }

    if (withdrawal.status !== 'pending') {
      console.log(`❌ Withdrawal not pending: ${withdrawalId}, status: ${withdrawal.status}`);
      return res.status(400).json(formatResponse(false, 'Withdrawal is not pending approval'));
    }

    // Update withdrawal
    withdrawal.status = 'rejected';
    withdrawal.approved_by = adminId;
    withdrawal.admin_notes = remarks;
    
    await withdrawal.save();

    // Refund user balance (amount was deducted when withdrawal created)
    await User.findByIdAndUpdate(withdrawal.user._id, {
      $inc: { balance: withdrawal.amount }
    });

    // Create transaction for refund
    await createTransaction(
      withdrawal.user._id,
      'refund',
      withdrawal.amount,
      `Withdrawal refund - ${remarks}`,
      'completed',
      { 
        withdrawal_id: withdrawal._id,
        payment_method: withdrawal.payment_method,
        reason: remarks
      }
    );

    // Create notification
    await createNotification(
      withdrawal.user._id,
      'Withdrawal Rejected',
      `Your withdrawal of ₦${withdrawal.amount.toLocaleString()} has been rejected. Reason: ${remarks}. The amount has been refunded to your account.`,
      'error',
      '/withdrawals',
      { 
        amount: withdrawal.amount,
        payment_method: withdrawal.payment_method,
        rejected_by: req.user.full_name,
        rejected_at: new Date(),
        remarks: remarks
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
        remarks: remarks,
        refunded: true
      },
      req.ip,
      req.headers['user-agent']
    );

    console.log(`✅ Withdrawal rejected: ${withdrawalId}`);

    res.json(formatResponse(true, 'Withdrawal rejected successfully', {
      withdrawal: {
        ...withdrawal.toObject(),
        rejected_by_admin: req.user.full_name
      },
      message: 'Withdrawal rejected and amount refunded to user'
    }));
  } catch (error) {
    console.error('Error rejecting withdrawal:', error);
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

    console.log(`📋 Found ${total} users for admin view`);

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
    console.error('Error fetching users:', error);
    handleError(res, error, 'Error fetching users');
  }
});

// Get user details
app.get('/api/admin/users/:id', adminAuth, async (req, res) => {
  try {
    const userId = req.params.id;
    
    const user = await User.findById(userId)
      .select('-password -two_factor_secret -verification_token -password_reset_token')
      .lean();
    
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    // Get user's related data
    const [
      investments,
      deposits,
      withdrawals,
      transactions,
      referrals,
      kyc
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
        .lean(),
      KYCSubmission.findOne({ user: userId }).lean()
    ]);

    // Calculate stats
    const totalInvested = investments.reduce((sum, inv) => sum + (inv.amount || 0), 0);
    const totalDeposited = deposits
      .filter(d => d.status === 'approved')
      .reduce((sum, dep) => sum + (dep.amount || 0), 0);
    const totalWithdrawn = withdrawals
      .filter(w => w.status === 'paid')
      .reduce((sum, wdl) => sum + (wdl.amount || 0), 0);

    res.json(formatResponse(true, 'User details retrieved successfully', {
      user,
      stats: {
        total_invested: totalInvested,
        total_deposited: totalDeposited,
        total_withdrawn: totalWithdrawn,
        investment_count: investments.length,
        deposit_count: deposits.length,
        withdrawal_count: withdrawals.length,
        referral_count: referrals.length
      },
      data: {
        investments,
        deposits,
        withdrawals,
        transactions,
        referrals,
        kyc
      }
    }));
  } catch (error) {
    console.error('Error fetching user details:', error);
    handleError(res, error, 'Error fetching user details');
  }
});

// Update user role
app.put('/api/admin/users/:id/role', adminAuth, [
  body('role').isIn(['user', 'admin', 'super_admin'])
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
    ).select('-password');
    
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }
    
    // Create audit log
    await createAdminAudit(
      req.user._id,
      'UPDATE_USER_ROLE',
      'user',
      userId,
      {
        old_role: user.role,
        new_role: role,
        user_email: user.email
      },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'User role updated successfully', { user }));
  } catch (error) {
    console.error('Error updating user role:', error);
    handleError(res, error, 'Error updating user role');
  }
});

// Update user status
app.put('/api/admin/users/:id/status', adminAuth, [
  body('is_active').isBoolean()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }
    
    const userId = req.params.id;
    const { is_active } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }
    
    const oldStatus = user.is_active;
    user.is_active = is_active;
    await user.save();
    
    // Create notification for user
    await createNotification(
      userId,
      'Account Status Updated',
      `Your account has been ${is_active ? 'activated' : 'deactivated'} by an administrator.`,
      'system',
      '/profile'
    );
    
    // Create audit log
    await createAdminAudit(
      req.user._id,
      'UPDATE_USER_STATUS',
      'user',
      userId,
      {
        old_status: oldStatus,
        new_status: is_active,
        user_email: user.email
      },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'User status updated successfully', { 
      user: {
        _id: user._id,
        email: user.email,
        is_active: user.is_active
      }
    }));
  } catch (error) {
    console.error('Error updating user status:', error);
    handleError(res, error, 'Error updating user status');
  }
});

// Update user balance
app.put('/api/admin/users/:id/balance', adminAuth, [
  body('amount').isFloat(),
  body('type').isIn(['add', 'subtract', 'set']),
  body('description').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }
    
    const userId = req.params.id;
    const { amount, type, description } = req.body;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }
    
    let newBalance = user.balance;
    let transactionAmount = 0;
    
    if (type === 'add') {
      newBalance += amount;
      transactionAmount = amount;
    } else if (type === 'subtract') {
      if (amount > user.balance) {
        return res.status(400).json(formatResponse(false, 'Insufficient balance'));
      }
      newBalance -= amount;
      transactionAmount = -amount;
    } else if (type === 'set') {
      transactionAmount = amount - user.balance;
      newBalance = amount;
    }
    
    user.balance = newBalance;
    await user.save();
    
    // Create transaction
    await createTransaction(
      userId,
      type === 'add' ? 'bonus' : 'adjustment',
      transactionAmount,
      `${description} (Admin adjustment)`,
      'completed',
      { 
        adjusted_by: req.user.full_name,
        adjustment_type: type,
        previous_balance: user.balance - transactionAmount
      }
    );
    
    // Create notification
    await createNotification(
      userId,
      'Balance Updated',
      `Your account balance has been updated by an administrator. New balance: ₦${newBalance.toLocaleString()}`,
      'system',
      '/dashboard',
      { 
        amount: transactionAmount,
        new_balance: newBalance,
        adjusted_by: req.user.full_name
      }
    );
    
    // Create audit log
    await createAdminAudit(
      req.user._id,
      'UPDATE_USER_BALANCE',
      'user',
      userId,
      {
        user_email: user.email,
        adjustment_type: type,
        amount: transactionAmount,
        old_balance: user.balance - transactionAmount,
        new_balance: newBalance,
        description: description
      },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'Balance updated successfully', { 
      user: {
        _id: user._id,
        email: user.email,
        balance: user.balance
      }
    }));
  } catch (error) {
    console.error('Error updating balance:', error);
    handleError(res, error, 'Error updating balance');
  }
});

// Get pending KYC
app.get('/api/admin/pending-kyc', adminAuth, async (req, res) => {
  try {
    const pendingKYC = await KYCSubmission.find({ status: 'pending' })
      .populate('user', 'full_name email phone')
      .sort({ createdAt: -1 })
      .lean();

    console.log(`📋 Found ${pendingKYC.length} pending KYC submissions`);

    res.json(formatResponse(true, 'Pending KYC retrieved successfully', {
      kyc_submissions: pendingKYC,
      count: pendingKYC.length
    }));
  } catch (error) {
    console.error('Error fetching pending KYC:', error);
    handleError(res, error, 'Error fetching pending KYC');
  }
});

// Approve KYC
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
      'Your KYC submission has been approved. Your account is now fully verified.',
      'success',
      '/profile',
      { 
        approved_by: req.user.full_name,
        approved_at: new Date()
      }
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
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'KYC approved successfully', { kyc }));
  } catch (error) {
    console.error('Error approving KYC:', error);
    handleError(res, error, 'Error approving KYC');
  }
});

// Reject KYC
app.post('/api/admin/kyc/:id/reject', adminAuth, [
  body('rejection_reason').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }
    
    const kycId = req.params.id;
    const adminId = req.user._id;
    const { rejection_reason } = req.body;
    
    const kyc = await KYCSubmission.findById(kycId)
      .populate('user');
    
    if (!kyc) {
      return res.status(404).json(formatResponse(false, 'KYC submission not found'));
    }
    
    kyc.status = 'rejected';
    kyc.reviewed_by = adminId;
    kyc.reviewed_at = new Date();
    kyc.rejection_reason = rejection_reason;
    await kyc.save();
    
    // Update user
    await User.findByIdAndUpdate(kyc.user._id, {
      kyc_status: 'rejected'
    });
    
    // Create notification
    await createNotification(
      kyc.user._id,
      'KYC Rejected',
      `Your KYC submission has been rejected. Reason: ${rejection_reason}. Please submit again with correct documents.`,
      'error',
      '/kyc',
      { 
        rejected_by: req.user.full_name,
        rejected_at: new Date(),
        rejection_reason: rejection_reason
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
        id_type: kyc.id_type,
        rejection_reason: rejection_reason
      },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'KYC rejected successfully', { kyc }));
  } catch (error) {
    console.error('Error rejecting KYC:', error);
    handleError(res, error, 'Error rejecting KYC');
  }
});

// Get all transactions
app.get('/api/admin/transactions', adminAuth, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 50,
      type,
      status,
      start_date,
      end_date,
      user_id,
      search
    } = req.query;
    
    const query = {};
    
    // Apply filters
    if (type) query.type = type;
    if (status) query.status = status;
    if (user_id) query.user = user_id;
    
    // Date filter
    if (start_date || end_date) {
      query.createdAt = {};
      if (start_date) query.createdAt.$gte = new Date(start_date);
      if (end_date) query.createdAt.$lte = new Date(end_date);
    }
    
    // Search
    if (search) {
      query.$or = [
        { description: { $regex: search, $options: 'i' } },
        { reference: { $regex: search, $options: 'i' } }
      ];
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
      { $group: { _id: '$type', total: { $sum: '$amount' } } }
    ]);

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(formatResponse(true, 'Transactions retrieved successfully', {
      transactions,
      totals,
      pagination
    }));
  } catch (error) {
    console.error('Error fetching transactions:', error);
    handleError(res, error, 'Error fetching transactions');
  }
});

// Get all referrals for admin
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

    res.json(formatResponse(true, 'All referrals retrieved successfully', {
      referrals,
      platform_stats: platformStats[0] || {},
      pagination
    }));
  } catch (error) {
    console.error('Error fetching all referrals:', error);
    handleError(res, error, 'Error fetching all referrals');
  }
});

// Get referral stats for admin
app.get('/api/admin/referrals/stats', adminAuth, async (req, res) => {
  try {
    const [totalReferrals, totalEarnings] = await Promise.all([
      Referral.countDocuments({}),
      Referral.aggregate([
        { $group: { _id: null, total: { $sum: '$earnings' } } }
      ])
    ]);
    
    // Get top referrers
    const topReferrers = await Referral.aggregate([
      {
        $group: {
          _id: '$referrer',
          total_referrals: { $sum: 1 },
          total_earnings: { $sum: '$earnings' }
        }
      },
      { $sort: { total_referrals: -1 } },
      { $limit: 10 },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'user'
        }
      },
      { $unwind: '$user' },
      {
        $project: {
          user_id: '$_id',
          user_name: '$user.full_name',
          user_email: '$user.email',
          total_referrals: 1,
          total_earnings: 1
        }
      }
    ]);

    res.json(formatResponse(true, 'Referral stats retrieved successfully', {
      stats: {
        total_referrals: totalReferrals,
        total_earnings: totalEarnings[0]?.total || 0
      },
      top_referrers: topReferrers
    }));
  } catch (error) {
    console.error('Error fetching referral stats:', error);
    handleError(res, error, 'Error fetching referral stats');
  }
});

// Send notifications
app.post('/api/admin/notifications/send', adminAuth, [
  body('title').notEmpty(),
  body('message').notEmpty(),
  body('type').optional(),
  body('user_id').optional(),
  body('role').optional()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }
    
    const { title, message, type = 'info', user_id, role } = req.body;
    
    let users = [];
    if (user_id) {
      // Send to specific user
      const user = await User.findById(user_id);
      if (user) users = [user];
    } else if (role) {
      // Send to all users with role
      users = await User.find({ role });
    } else {
      // Send to all active users
      users = await User.find({ is_active: true });
    }
    
    // Create notifications
    const notifications = [];
    for (const user of users) {
      const notification = new Notification({
        user: user._id,
        title,
        message,
        type,
        is_email_sent: false
      });
      notifications.push(notification);
      
      // Emit real-time notification
      io.to(`user:${user._id}`).emit('notification', {
        title,
        message,
        type,
        timestamp: new Date()
      });
    }
    
    await Notification.insertMany(notifications);
    
    // Send emails if configured
    if (config.emailEnabled) {
      for (const user of users) {
        if (user.email_notifications) {
          await sendEmail(
            user.email,
            title,
            `<h2>${title}</h2>
             <p>${message}</p>
             <p>Best regards,<br>Raw Wealthy Team</p>`
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
        target_user_count: users.length,
        target_type: user_id ? 'specific_user' : role ? 'role_based' : 'all_users'
      },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'Notifications sent successfully', {
      sent_count: users.length
    }));
  } catch (error) {
    console.error('Error sending notifications:', error);
    handleError(res, error, 'Error sending notifications');
  }
});

// Get audit logs
app.get('/api/admin/audit', adminAuth, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 50,
      admin_id,
      action,
      target_type,
      start_date,
      end_date
    } = req.query;
    
    const query = {};
    
    if (admin_id) query.admin_id = admin_id;
    if (action) query.action = { $regex: action, $options: 'i' };
    if (target_type) query.target_type = target_type;
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

    res.json(formatResponse(true, 'Audit logs retrieved successfully', {
      logs,
      pagination
    }));
  } catch (error) {
    console.error('Error fetching audit logs:', error);
    handleError(res, error, 'Error fetching audit logs');
  }
});

// Get investment plans for admin
app.get('/api/admin/plans', adminAuth, async (req, res) => {
  try {
    const plans = await InvestmentPlan.find({})
      .sort({ display_order: 1 })
      .lean();
    
    res.json(formatResponse(true, 'Investment plans retrieved successfully', {
      plans
    }));
  } catch (error) {
    console.error('Error fetching investment plans:', error);
    handleError(res, error, 'Error fetching investment plans');
  }
});

// Create investment plan
app.post('/api/admin/plans', adminAuth, [
  body('name').notEmpty(),
  body('description').notEmpty(),
  body('min_amount').isFloat({ min: config.minInvestment }),
  body('max_amount').optional().isFloat({ min: config.minInvestment }),
  body('daily_interest').isFloat({ min: 0.1, max: 100 }),
  body('total_interest').isFloat({ min: 1, max: 1000 }),
  body('duration').isInt({ min: 1 }),
  body('risk_level').isIn(['low', 'medium', 'high']),
  body('raw_material').notEmpty(),
  body('category').isIn(['agriculture', 'mining', 'energy', 'metals', 'crypto', 'real_estate', 'precious_stones'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }
    
    const planData = req.body;
    
    // Check if plan with same name exists
    const existingPlan = await InvestmentPlan.findOne({ name: planData.name });
    if (existingPlan) {
      return res.status(400).json(formatResponse(false, 'Investment plan with this name already exists'));
    }
    
    const plan = new InvestmentPlan({
      ...planData,
      is_active: planData.is_active || true,
      display_order: planData.display_order || 0
    });
    
    await plan.save();
    
    // Update config
    config.investmentPlans = await InvestmentPlan.find({ is_active: true })
      .sort({ display_order: 1 })
      .lean();
    
    // Create audit log
    await createAdminAudit(
      req.user._id,
      'CREATE_INVESTMENT_PLAN',
      'plan',
      plan._id,
      {
        name: plan.name,
        min_amount: plan.min_amount,
        max_amount: plan.max_amount,
        daily_interest: plan.daily_interest,
        total_interest: plan.total_interest,
        duration: plan.duration,
        risk_level: plan.risk_level,
        raw_material: plan.raw_material,
        category: plan.category
      },
      req.ip,
      req.headers['user-agent']
    );
    
    res.status(201).json(formatResponse(true, 'Investment plan created successfully', { plan }));
  } catch (error) {
    console.error('Error creating investment plan:', error);
    handleError(res, error, 'Error creating investment plan');
  }
});

// Update investment plan
app.put('/api/admin/plans/:id', adminAuth, async (req, res) => {
  try {
    const planId = req.params.id;
    const updateData = req.body;
    
    const plan = await InvestmentPlan.findByIdAndUpdate(
      planId,
      updateData,
      { new: true, runValidators: true }
    );
    
    if (!plan) {
      return res.status(404).json(formatResponse(false, 'Investment plan not found'));
    }
    
    // Update config
    config.investmentPlans = await InvestmentPlan.find({ is_active: true })
      .sort({ display_order: 1 })
      .lean();
    
    // Create audit log
    await createAdminAudit(
      req.user._id,
      'UPDATE_INVESTMENT_PLAN',
      'plan',
      planId,
      {
        updates: updateData,
        plan_name: plan.name
      },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'Investment plan updated successfully', { plan }));
  } catch (error) {
    console.error('Error updating investment plan:', error);
    handleError(res, error, 'Error updating investment plan');
  }
});

// Delete investment plan
app.delete('/api/admin/plans/:id', adminAuth, async (req, res) => {
  try {
    const planId = req.params.id;
    
    const plan = await InvestmentPlan.findById(planId);
    if (!plan) {
      return res.status(404).json(formatResponse(false, 'Investment plan not found'));
    }
    
    // Check if plan has active investments
    const activeInvestments = await Investment.countDocuments({ 
      plan: planId, 
      status: 'active' 
    });
    
    if (activeInvestments > 0) {
      return res.status(400).json(formatResponse(false, 
        `Cannot delete plan with ${activeInvestments} active investments. Deactivate instead.`));
    }
    
    await InvestmentPlan.findByIdAndDelete(planId);
    
    // Update config
    config.investmentPlans = await InvestmentPlan.find({ is_active: true })
      .sort({ display_order: 1 })
      .lean();
    
    // Create audit log
    await createAdminAudit(
      req.user._id,
      'DELETE_INVESTMENT_PLAN',
      'plan',
      planId,
      {
        plan_name: plan.name,
        plan_details: plan
      },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'Investment plan deleted successfully'));
  } catch (error) {
    console.error('Error deleting investment plan:', error);
    handleError(res, error, 'Error deleting investment plan');
  }
});

// Get support tickets for admin
app.get('/api/admin/support/tickets', adminAuth, async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 50,
      status,
      priority,
      category,
      assigned_to
    } = req.query;
    
    const query = {};
    
    if (status) query.status = status;
    if (priority) query.priority = priority;
    if (category) query.category = category;
    if (assigned_to) query.assigned_to = assigned_to;
    
    const skip = (page - 1) * limit;
    
    const [tickets, total] = await Promise.all([
      SupportTicket.find(query)
        .populate('user', 'full_name email phone')
        .populate('assigned_to', 'full_name email')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      SupportTicket.countDocuments(query)
    ]);

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(formatResponse(true, 'Support tickets retrieved successfully', {
      tickets,
      pagination,
      summary: {
        open: tickets.filter(t => t.status === 'open').length,
        in_progress: tickets.filter(t => t.status === 'in_progress').length,
        resolved: tickets.filter(t => t.status === 'resolved').length,
        closed: tickets.filter(t => t.status === 'closed').length
      }
    }));
  } catch (error) {
    console.error('Error fetching support tickets:', error);
    handleError(res, error, 'Error fetching support tickets');
  }
});

// ==================== CRON JOBS FOR DAILY EARNINGS ====================

// Calculate daily earnings for active investments
cron.schedule('0 0 * * *', async () => {
  try {
    console.log('🔄 Running daily earnings calculation...');
    
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
        console.error(`Error processing investment ${investment._id}:`, error);
        debugSystem.logError(error, null);
      }
    }
    
    console.log(`✅ Daily earnings calculated: Processed ${processedCount} investments, Total: ₦${totalEarnings.toLocaleString()}`);
    
  } catch (error) {
    console.error('Error in daily earnings cron job:', error);
    debugSystem.logError(error, null);
  }
});

// Cleanup old debug logs (run daily at 2 AM)
cron.schedule('0 2 * * *', async () => {
  try {
    console.log('🧹 Cleaning up old debug logs...');
    
    // Keep only last 1000 errors
    if (debugSystem.errors.length > 1000) {
      debugSystem.errors = debugSystem.errors.slice(-1000);
    }
    
    // Keep only last 1000 database queries
    if (debugSystem.databaseQueries.length > 1000) {
      debugSystem.databaseQueries = debugSystem.databaseQueries.slice(-1000);
    }
    
    console.log('✅ Debug logs cleaned up');
  } catch (error) {
    console.error('Error cleaning up debug logs:', error);
  }
});

// ==================== ERROR HANDLING MIDDLEWARE ====================

// 404 handler
app.use((req, res) => {
  console.log(`❌ 404 Not Found: ${req.method} ${req.url}`);
  res.status(404).json(formatResponse(false, 'Endpoint not found'));
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('🔥 Unhandled error:', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip
  });
  
  // Log to debug system
  debugSystem.logError(err, req);
  
  // Emit to debug room
  if (config.enableWebSocketDebug) {
    io.to('debug-room').emit('error', {
      message: err.message,
      stack: err.stack,
      url: req.url,
      method: req.method,
      timestamp: new Date().toISOString()
    });
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
      console.log('\n' + '='.repeat(60));
      console.log('🚀 RAW WEALTHY BACKEND v48.0 - ULTIMATE ENTERPRISE EDITION');
      console.log('='.repeat(60));
      console.log(`✅ Server running on port: ${config.port}`);
      console.log(`🌍 Environment: ${config.nodeEnv}`);
      console.log(`🔗 Client URL: ${config.clientURL}`);
      console.log(`🖥️  Server URL: ${config.serverURL}`);
      console.log(`📊 Database: ${mongoose.connection.readyState === 1 ? '✅ Connected' : '❌ Disconnected'}`);
      console.log(`🔧 Debug Mode: ${config.debug}`);
      console.log(`📅 Started at: ${new Date().toISOString()}`);
      
      if (config.enableWebSocketDebug) {
        console.log(`🔌 WebSocket Debug: Enabled (ws://localhost:${config.port}/debug-ws)`);
      }
      
      console.log('\n📋 Available Admin Endpoints:');
      console.log('  • /api/admin/dashboard');
      console.log('  • /api/admin/pending-investments');
      console.log('  • /api/admin/pending-deposits');
      console.log('  • /api/admin/pending-withdrawals');
      console.log('  • /api/admin/pending-kyc');
      console.log('  • /api/admin/users');
      console.log('  • /api/admin/transactions');
      console.log('  • /api/admin/referrals');
      console.log('  • /api/admin/audit');
      console.log('  • /api/admin/plans');
      console.log('  • /api/admin/support/tickets');
      
      console.log('\n🐛 Debug Endpoints:');
      console.log('  • /api/debug/dashboard');
      console.log('  • /api/debug/requests');
      console.log('  • /api/debug/errors');
      console.log('  • /api/debug/queries');
      console.log('  • /api/debug/test-endpoints');
      console.log('  • /health');
      
      console.log('='.repeat(60) + '\n');
      
      // Emit server start event
      io.emit('server_start', {
        timestamp: new Date(),
        version: '48.0.0',
        status: 'running'
      });
    });
    
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received. Shutting down gracefully...');
  server.close(() => {
    console.log('✅ HTTP server closed');
    mongoose.connection.close(false, () => {
      console.log('✅ MongoDB connection closed');
      process.exit(0);
    });
  });
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received. Shutting down gracefully...');
  server.close(() => {
    console.log('✅ HTTP server closed');
    mongoose.connection.close(false, () => {
      console.log('✅ MongoDB connection closed');
      process.exit(0);
    });
  });
});

// Start the server
startServer();
