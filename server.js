// server.js - RAW WEALTHY BACKEND v38.0 - DEBUGGED & ENHANCED PRODUCTION READY
// COMPLETE DEBUGGING: Database Connection Fix + Advanced Error Handling + Real-time Debugging
//  WITH: Connection Pooling + Retry Logic + Health Monitoring + Performance Optimization

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
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

// ES Modules equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Enhanced environment configuration with fallbacks
dotenv.config({ 
  path: path.join(__dirname, '.env.production'),
  override: true 
});

// ==================== ENHANCED DEBUGGING SYSTEM ====================
class DebugSystem {
  static logs = [];
  static errors = [];
  static warnings = [];
  
  static log(module, message, data = null) {
    const timestamp = new Date().toISOString();
    const logEntry = { timestamp, module, level: 'INFO', message, data };
    this.logs.push(logEntry);
    
    if (process.env.NODE_ENV !== 'production' || process.env.DEBUG_MODE === 'true') {
      console.log(`📝 [${module}] ${message}`, data ? data : '');
    }
  }
  
  static error(module, message, error = null) {
    const timestamp = new Date().toISOString();
    const errorEntry = { 
      timestamp, 
      module, 
      level: 'ERROR', 
      message, 
      error: error ? {
        message: error.message,
        stack: error.stack,
        name: error.name,
        code: error.code
      } : null
    };
    this.errors.push(errorEntry);
    
    console.error(`🔥 [${module}] ERROR: ${message}`);
    if (error) {
      console.error(`   ↳ ${error.message}`);
      if (process.env.NODE_ENV !== 'production') {
        console.error(error.stack);
      }
    }
  }
  
  static warn(module, message, data = null) {
    const timestamp = new Date().toISOString();
    const warnEntry = { timestamp, module, level: 'WARN', message, data };
    this.warnings.push(warnEntry);
    
    console.warn(`⚠️ [${module}] WARNING: ${message}`, data ? data : '');
  }
  
  static getStats() {
    return {
      logs: this.logs.length,
      errors: this.errors.length,
      warnings: this.warnings.length,
      recentErrors: this.errors.slice(-5),
      recentLogs: this.logs.slice(-10)
    };
  }
}

// ==================== ENVIRONMENT VALIDATION WITH DEBUGGING ====================
const requiredEnvVars = [
  'MONGODB_URI',
  'JWT_SECRET',
  'NODE_ENV',
  'CLIENT_URL'
];

DebugSystem.log('ENV', 'Starting environment validation...');

const missingEnvVars = requiredEnvVars.filter(envVar => {
  if (!process.env[envVar]) {
    DebugSystem.error('ENV', `Missing required environment variable: ${envVar}`);
    return true;
  }
  DebugSystem.log('ENV', `${envVar}: ${envVar === 'JWT_SECRET' ? '***' : process.env[envVar]}`);
  return false;
});

if (missingEnvVars.length > 0) {
  DebugSystem.warn('ENV', `${missingEnvVars.length} required environment variables missing`);
  
  // Try to load from alternative sources
  DebugSystem.log('ENV', 'Attempting to load from alternative sources...');
  
  // Check for Render/Heroku style environment
  if (process.env.DATABASE_URL) {
    process.env.MONGODB_URI = process.env.DATABASE_URL;
    DebugSystem.log('ENV', 'Loaded MONGODB_URI from DATABASE_URL');
  }
  
  // Generate JWT secret if missing
  if (!process.env.JWT_SECRET) {
    process.env.JWT_SECRET = crypto.randomBytes(64).toString('hex');
    DebugSystem.log('ENV', 'Generated JWT_SECRET automatically');
  }
  
  // Set default client URL
  if (!process.env.CLIENT_URL) {
    process.env.CLIENT_URL = 'https://us-raw-wealthy.vercel.app';
    DebugSystem.log('ENV', 'Set default CLIENT_URL');
  }
}

// Add SERVER_URL for absolute image paths
if (!process.env.SERVER_URL) {
  process.env.SERVER_URL = process.env.CLIENT_URL || `http://localhost:${process.env.PORT || 10000}`;
  DebugSystem.log('ENV', `Set SERVER_URL: ${process.env.SERVER_URL}`);
}

// ==================== ENHANCED DYNAMIC CONFIGURATION ====================
const config = {
  // Server
  port: process.env.PORT || 10000,
  nodeEnv: process.env.NODE_ENV || 'production',
  serverURL: process.env.SERVER_URL,
  
  // Database - FIXED: Use proper MongoDB connection string
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
  debugMode: process.env.DEBUG_MODE === 'true',
  logLevel: process.env.LOG_LEVEL || 'info'
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

DebugSystem.log('CONFIG', 'Dynamic Configuration Loaded:', {
  port: config.port,
  environment: config.nodeEnv,
  clientURL: config.clientURL,
  serverURL: config.serverURL,
  emailEnabled: config.emailEnabled,
  allowedOrigins: config.allowedOrigins.length,
  uploadDir: config.uploadDir,
  debugMode: config.debugMode
});

// ==================== ENHANCED EXPRESS SETUP WITH DEBUGGING ====================
const app = express();

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

// Enhanced logging with debugging
const morganFormat = config.nodeEnv === 'production' ? 'combined' : 'dev';
app.use(morgan(morganFormat, {
  stream: {
    write: (message) => {
      DebugSystem.log('HTTP', message.trim());
    }
  }
}));

// ==================== ENHANCED CORS CONFIGURATION ====================
const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (config.allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      // Check if origin matches pattern (for preview deployments)
      const isPreviewDeployment = origin.includes('vercel.app') || origin.includes('onrender.com');
      if (isPreviewDeployment) {
        DebugSystem.log('CORS', `Allowed preview deployment: ${origin}`);
        callback(null, true);
      } else {
        DebugSystem.warn('CORS', `Blocked by CORS: ${origin}`);
        callback(new Error('Not allowed by CORS'));
      }
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'x-api-key', 'x-user-id']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// ==================== BODY PARSING WITH SIZE LIMITS ====================
app.use(express.json({ 
  limit: '50mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
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
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false
});

const rateLimiters = {
  createAccount: createRateLimiter(60 * 60 * 1000, 10, 'Too many accounts created from this IP, please try again after an hour'),
  auth: createRateLimiter(15 * 60 * 1000, 20, 'Too many authentication attempts from this IP, please try again after 15 minutes'),
  api: createRateLimiter(15 * 60 * 1000, 1000, 'Too many requests from this IP, please try again later'),
  financial: createRateLimiter(15 * 60 * 1000, 50, 'Too many financial operations from this IP, please try again later'),
  passwordReset: createRateLimiter(15 * 60 * 1000, 5, 'Too many password reset attempts, please try again later'),
  admin: createRateLimiter(15 * 60 * 1000, 500, 'Too many admin requests from this IP')
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

// ==================== FILE UPLOAD CONFIGURATION ====================
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  if (!config.allowedMimeTypes[file.mimetype]) {
    return cb(new Error(`Invalid file type: ${file.mimetype}`), false);
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

// Enhanced file upload handler
const handleFileUpload = async (file, folder = 'general', userId = null) => {
  if (!file) return null;
  
  try {
    // Validate file type
    if (!config.allowedMimeTypes[file.mimetype]) {
      throw new Error('Invalid file type');
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
    
    // Write file
    await fs.promises.writeFile(filepath, file.buffer);
    
    // Return absolute URL for browser access
    return {
      url: `${config.serverURL}/uploads/${folder}/${filename}`,
      relativeUrl: `/uploads/${folder}/${filename}`,
      filename,
      originalName: file.originalname,
      size: file.size,
      mimeType: file.mimetype,
      uploadPath: filepath,
      uploadedAt: new Date()
    };
  } catch (error) {
    DebugSystem.error('FILE_UPLOAD', 'File upload error:', error);
    throw new Error(`File upload failed: ${error.message}`);
  }
};

// Serve static files with proper caching
if (!fs.existsSync(config.uploadDir)) {
  fs.mkdirSync(config.uploadDir, { recursive: true });
}

app.use('/uploads', express.static(config.uploadDir, {
  maxAge: '7d',
  setHeaders: (res, path) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Cache-Control', 'public, max-age=604800');
    res.set('Access-Control-Allow-Origin', '*');
  }
}));

// ==================== EMAIL CONFIGURATION ====================
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
        DebugSystem.error('EMAIL', 'Email configuration error:', error);
      } else {
        DebugSystem.log('EMAIL', 'Email server is ready to send messages');
      }
    });
  } catch (error) {
    DebugSystem.error('EMAIL', 'Email setup failed:', error);
  }
}

// Enhanced email utility function
const sendEmail = async (to, subject, html, text = '') => {
  try {
    if (!emailTransporter) {
      DebugSystem.log('EMAIL', `Email would be sent (simulated): To: ${to}, Subject: ${subject}`);
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
    DebugSystem.log('EMAIL', `Email sent to ${to} (Message ID: ${info.messageId})`);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    DebugSystem.error('EMAIL', 'Email sending error:', error);
    return { success: false, error: error.message };
  }
};

// ==================== DATABASE MODELS (UNCHANGED) ====================

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

// Virtual for total portfolio value
userSchema.virtual('portfolio_value').get(function() {
  return this.balance + this.total_earnings + this.referral_earnings;
});

// Pre-save hooks
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, config.bcryptRounds);
  }
  
  if (!this.referral_code) {
    this.referral_code = crypto.randomBytes(6).toString('hex').toUpperCase();
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
  this.password_reset_expires = new Date(Date.now() + 10 * 60 * 1000);
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

// ==================== UTILITY FUNCTIONS ====================

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

const handleError = (res, error, defaultMessage = 'An error occurred') => {
  DebugSystem.error('ERROR_HANDLER', defaultMessage, error);
  
  if (error.name === 'ValidationError') {
    const messages = Object.values(error.errors).map(val => val.message);
    return res.status(400).json(formatResponse(false, 'Validation Error', { errors: messages }));
  }
  
  if (error.code === 11000) {
    const field = Object.keys(error.keyPattern)[0];
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

// Enhanced createNotification with null checks
const createNotification = async (userId, title, message, type = 'info', actionUrl = null, metadata = {}) => {
  try {
    if (!userId) {
      DebugSystem.warn('NOTIFICATION', 'Cannot create notification: userId is null');
      return null;
    }
    
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
    
    // Send email notification if enabled
    const user = await User.findById(userId);
    if (user && user.email_notifications && type !== 'system') {
      const emailSubject = `Raw Wealthy - ${title}`;
      const emailHtml = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; color: white;">
            <h1 style="margin: 0;">Raw Wealthy</h1>
            <p style="opacity: 0.9; margin: 10px 0 0;">Investment Platform</p>
          </div>
          <div style="padding: 30px; background: #f9f9f9;">
            <h2 style="color: #333; margin-bottom: 20px;">${title}</h2>
            <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
              <p style="color: #555; line-height: 1.6; margin-bottom: 20px;">${message}</p>
              ${actionUrl ? `
                <div style="text-align: center; margin: 30px 0;">
                  <a href="${config.clientURL}${actionUrl}" 
                     style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                            color: white; 
                            padding: 12px 30px; 
                            text-decoration: none; 
                            border-radius: 5px; 
                            font-weight: bold;
                            display: inline-block;">
                    View Details
                  </a>
                </div>
              ` : ''}
            </div>
            <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; text-align: center; color: #888; font-size: 12px;">
              <p>This is an automated message from Raw Wealthy. Please do not reply to this email.</p>
              <p>© ${new Date().getFullYear()} Raw Wealthy. All rights reserved.</p>
            </div>
          </div>
        </div>
      `;
      
      await sendEmail(user.email, emailSubject, emailHtml);
    }
    
    return notification;
  } catch (error) {
    DebugSystem.error('NOTIFICATION', 'Error creating notification:', error);
    return null;
  }
};

// Enhanced createTransaction with null checks
const createTransaction = async (userId, type, amount, description, status = 'completed', metadata = {}, proofUrl = null) => {
  try {
    if (!userId) {
      DebugSystem.warn('TRANSACTION', 'Cannot create transaction: userId is null');
      return null;
    }
    
    const user = await User.findById(userId);
    if (!user) {
      DebugSystem.warn('TRANSACTION', `User not found for transaction: ${userId}`);
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
    
    // Update user statistics based on transaction type
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
    
    return transaction;
  } catch (error) {
    DebugSystem.error('TRANSACTION', 'Error creating transaction:', error);
    return null;
  }
};

// Enhanced admin audit log function
const createAdminAudit = async (adminId, action, targetType, targetId, details = {}, ip = '', userAgent = '') => {
  try {
    if (!adminId) {
      DebugSystem.warn('AUDIT', 'Cannot create audit: adminId is null');
      return null;
    }
    
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
    return audit;
  } catch (error) {
    DebugSystem.error('AUDIT', 'Error creating admin audit:', error);
    return null;
  }
};

// ==================== ENHANCED AUTH MIDDLEWARE WITH NULL CHECKS ====================

const auth = async (req, res, next) => {
  try {
    let token = req.header('Authorization');
    
    if (!token) {
      DebugSystem.warn('AUTH', 'No token provided in request');
      return res.status(401).json(formatResponse(false, 'No token, authorization denied'));
    }
    
    if (token.startsWith('Bearer ')) {
      token = token.slice(7, token.length);
    }
    
    const decoded = jwt.verify(token, config.jwtSecret);
    
    const user = await User.findById(decoded.id);
    
    if (!user) {
      DebugSystem.warn('AUTH', `User not found for token: ${decoded.id}`);
      return res.status(401).json(formatResponse(false, 'Token is not valid - User not found'));
    }
    
    if (!user.is_active) {
      DebugSystem.warn('AUTH', `User account deactivated: ${user.email}`);
      return res.status(401).json(formatResponse(false, 'Account is deactivated. Please contact support.'));
    }
    
    // Update last active timestamp
    user.last_active = new Date();
    await user.save();
    
    req.user = user;
    req.userId = user._id;
    next();
  } catch (error) {
    DebugSystem.error('AUTH', 'Authentication middleware error:', error);
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json(formatResponse(false, 'Invalid token'));
    } else if (error.name === 'TokenExpiredError') {
      return res.status(401).json(formatResponse(false, 'Token expired'));
    }
    
    res.status(500).json(formatResponse(false, 'Server error during authentication'));
  }
};

const adminAuth = async (req, res, next) => {
  try {
    await auth(req, res, () => {
      if (!req.user) {
        return res.status(401).json(formatResponse(false, 'Authentication required'));
      }
      
      if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
        DebugSystem.warn('ADMIN_AUTH', `Non-admin user attempted admin access: ${req.user.email}`);
        return res.status(403).json(formatResponse(false, 'Access denied. Admin privileges required.'));
      }
      next();
    });
  } catch (error) {
    DebugSystem.error('ADMIN_AUTH', 'Admin authentication error:', error);
    handleError(res, error, 'Admin authentication error');
  }
};

// ==================== ENHANCED DATABASE INITIALIZATION WITH RETRY LOGIC ====================

const initializeDatabase = async () => {
  try {
    DebugSystem.log('DATABASE', 'Initializing database connection...');
    
    // Check if MongoDB URI is available
    if (!config.mongoURI) {
      throw new Error('MONGODB_URI is not defined in environment variables');
    }
    
    DebugSystem.log('DATABASE', `Connecting to MongoDB: ${config.mongoURI.substring(0, 50)}...`);
    
    // FIXED: Remove deprecated Mongoose options
    // The error was caused by using deprecated options in Mongoose 6+
    await mongoose.connect(config.mongoURI);
    
    DebugSystem.log('DATABASE', '✅ MongoDB connected successfully');
    
    // Set up connection event listeners
    mongoose.connection.on('connected', () => {
      DebugSystem.log('DATABASE', 'Mongoose connected to MongoDB');
    });
    
    mongoose.connection.on('error', (err) => {
      DebugSystem.error('DATABASE', 'Mongoose connection error:', err);
    });
    
    mongoose.connection.on('disconnected', () => {
      DebugSystem.warn('DATABASE', 'Mongoose disconnected from MongoDB');
    });
    
    // Load investment plans into config
    await loadInvestmentPlans();
    
    // Create admin user if it doesn't exist
    await createAdminUser();
    
    // Create indexes if they don't exist
    await createDatabaseIndexes();
    
    DebugSystem.log('DATABASE', '✅ Database initialization completed');
    return true;
  } catch (error) {
    DebugSystem.error('DATABASE', 'Database initialization error:', error);
    
    // Provide helpful error messages
    if (error.message.includes('invalid connection string')) {
      DebugSystem.error('DATABASE', 'Invalid MongoDB connection string. Check your MONGODB_URI environment variable.');
    } else if (error.message.includes('ENOTFOUND')) {
      DebugSystem.error('DATABASE', 'Could not resolve MongoDB host. Check your network connection and MongoDB hostname.');
    } else if (error.message.includes('ECONNREFUSED')) {
      DebugSystem.error('DATABASE', 'MongoDB connection refused. Make sure MongoDB is running and accessible.');
    } else if (error.message.includes('auth failed')) {
      DebugSystem.error('DATABASE', 'MongoDB authentication failed. Check your username and password.');
    }
    
    throw error;
  }
};

const loadInvestmentPlans = async () => {
  try {
    const plans = await InvestmentPlan.find({ is_active: true })
      .sort({ display_order: 1 })
      .lean();
    
    config.investmentPlans = plans;
    DebugSystem.log('DATABASE', `Loaded ${plans.length} investment plans`);
    
    // If no plans exist, create default plans
    if (plans.length === 0) {
      await createDefaultInvestmentPlans();
    }
  } catch (error) {
    DebugSystem.error('DATABASE', 'Error loading investment plans:', error);
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
    DebugSystem.log('DATABASE', 'Created default investment plans');
  } catch (error) {
    DebugSystem.error('DATABASE', 'Error creating default investment plans:', error);
  }
};

const createAdminUser = async () => {
  try {
    DebugSystem.log('DATABASE', 'Checking/Creating admin user...');
    
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@rawwealthy.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123456';
    
    // Check if admin already exists
    const existingAdmin = await User.findOne({ email: adminEmail });
    if (existingAdmin) {
      DebugSystem.log('DATABASE', 'Admin already exists');
      
      // Update admin role to super_admin if not already
      if (existingAdmin.role !== 'super_admin') {
        existingAdmin.role = 'super_admin';
        await existingAdmin.save();
        DebugSystem.log('DATABASE', 'Updated admin role to super_admin');
      }
      
      return;
    }
    
    // Create new admin user
    const adminData = {
      full_name: 'Raw Wealthy Admin',
      email: adminEmail,
      phone: '09161806424',
      password: adminPassword,
      role: 'super_admin',
      balance: 1000000,
      kyc_verified: true,
      kyc_status: 'verified',
      is_active: true,
      is_verified: true,
      two_factor_enabled: false,
      notifications_enabled: true,
      email_notifications: true,
      sms_notifications: false
    };
    
    const admin = new User(adminData);
    await admin.save();
    
    DebugSystem.log('DATABASE', '✅ Admin user created successfully');
    DebugSystem.log('DATABASE', `Admin Email: ${adminEmail}`);
    DebugSystem.log('DATABASE', `Admin Password: ${adminPassword}`);
    
  } catch (error) {
    DebugSystem.error('DATABASE', 'Error creating admin user:', error);
  }
};

const createDatabaseIndexes = async () => {
  try {
    // Create additional indexes for performance
    await Transaction.collection.createIndex({ createdAt: -1 });
    await User.collection.createIndex({ 'bank_details.verified': 1 });
    await Investment.collection.createIndex({ status: 1, end_date: 1 });
    DebugSystem.log('DATABASE', 'Database indexes created/verified');
  } catch (error) {
    DebugSystem.error('DATABASE', 'Error creating indexes:', error);
  }
};

// ==================== ENHANCED DEBUG ENDPOINTS ====================

// Debug endpoint to check system status
app.get('/api/debug/status', async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState;
    const dbStates = {
      0: 'disconnected',
      1: 'connected',
      2: 'connecting',
      3: 'disconnecting'
    };
    
    const status = {
      server: {
        uptime: process.uptime(),
        memory: {
          rss: `${Math.round(process.memoryUsage().rss / 1024 / 1024)}MB`,
          heapTotal: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)}MB`,
          heapUsed: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`
        },
        nodeVersion: process.version,
        platform: process.platform,
        pid: process.pid
      },
      database: {
        status: dbStates[dbStatus] || 'unknown',
        readyState: dbStatus,
        host: mongoose.connection.host || 'not connected',
        name: mongoose.connection.name || 'not connected',
        models: Object.keys(mongoose.connection.models)
      },
      config: {
        nodeEnv: config.nodeEnv,
        port: config.port,
        clientURL: config.clientURL,
        serverURL: config.serverURL,
        emailEnabled: config.emailEnabled,
        debugMode: config.debugMode
      },
      debug: DebugSystem.getStats()
    };
    
    res.json(formatResponse(true, 'Debug status retrieved', status));
  } catch (error) {
    DebugSystem.error('DEBUG', 'Error getting debug status:', error);
    handleError(res, error, 'Error getting debug status');
  }
});

// Debug endpoint to test database connection
app.get('/api/debug/test-db', async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState;
    
    if (dbStatus !== 1) {
      return res.status(500).json(formatResponse(false, 'Database not connected', {
        readyState: dbStatus,
        message: 'Mongoose connection state is not "connected"'
      }));
    }
    
    // Test query
    const userCount = await User.countDocuments({});
    const investmentCount = await Investment.countDocuments({});
    
    res.json(formatResponse(true, 'Database test successful', {
      connected: true,
      readyState: dbStatus,
      host: mongoose.connection.host,
      name: mongoose.connection.name,
      counts: {
        users: userCount,
        investments: investmentCount
      }
    }));
  } catch (error) {
    DebugSystem.error('DEBUG', 'Database test failed:', error);
    handleError(res, error, 'Database test failed');
  }
});

// ==================== HEALTH CHECK WITH DATABASE VERIFICATION ====================
app.get('/health', async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState;
    const isDbConnected = dbStatus === 1;
    
    const health = {
      success: true,
      status: isDbConnected ? 'HEALTHY' : 'DEGRADED',
      timestamp: new Date().toISOString(),
      version: '38.0.0',
      environment: config.nodeEnv,
      database: {
        connected: isDbConnected,
        status: dbStatus,
        host: mongoose.connection.host || 'not connected'
      },
      uptime: process.uptime(),
      memory: {
        rss: `${Math.round(process.memoryUsage().rss / 1024 / 1024)}MB`,
        heapTotal: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)}MB`,
        heapUsed: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`
      },
      stats: isDbConnected ? {
        users: await User.countDocuments({}),
        investments: await Investment.countDocuments({}),
        deposits: await Deposit.countDocuments({}),
        withdrawals: await Withdrawal.countDocuments({})
      } : null,
      warnings: !isDbConnected ? ['Database not connected'] : []
    };
    
    const statusCode = isDbConnected ? 200 : 503;
    res.status(statusCode).json(health);
  } catch (error) {
    DebugSystem.error('HEALTH', 'Health check error:', error);
    res.status(500).json({
      success: false,
      status: 'UNHEALTHY',
      timestamp: new Date().toISOString(),
      error: error.message,
      database: {
        connected: false,
        error: error.message
      }
    });
  }
});

// ==================== ROOT ENDPOINT ====================
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 Raw Wealthy Backend API v38.0 - Debugged & Enhanced Edition',
    version: '38.0.0',
    timestamp: new Date().toISOString(),
    status: 'Operational',
    environment: config.nodeEnv,
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    debug: config.debugMode ? 'enabled' : 'disabled',
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

// ==================== ENHANCED AUTH ENDPOINTS WITH NULL CHECKS ====================

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

    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json(formatResponse(false, 'User already exists with this email'));
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
      referred_by: referredBy ? referredBy._id : null
    });

    await user.save();

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

    res.status(201).json(formatResponse(true, 'User registered successfully', {
      user: user.toObject(),
      token
    }));

  } catch (error) {
    DebugSystem.error('AUTH_REGISTER', 'Registration failed:', error);
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

    // Find user with password
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    
    if (!user) {
      DebugSystem.warn('AUTH_LOGIN', `Login attempt for non-existent user: ${email}`);
      return res.status(400).json(formatResponse(false, 'Invalid credentials'));
    }

    // Check if account is locked
    if (user.lock_until && user.lock_until > new Date()) {
      const lockTime = Math.ceil((user.lock_until - new Date()) / 1000 / 60);
      DebugSystem.warn('AUTH_LOGIN', `Locked account login attempt: ${email}`);
      return res.status(423).json(formatResponse(false, `Account is locked. Try again in ${lockTime} minutes.`));
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      user.login_attempts += 1;
      if (user.login_attempts >= 5) {
        user.lock_until = new Date(Date.now() + 15 * 60 * 1000);
      }
      await user.save();
      DebugSystem.warn('AUTH_LOGIN', `Failed login attempt for: ${email}`);
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

    DebugSystem.log('AUTH_LOGIN', `Successful login: ${email}`);
    res.json(formatResponse(true, 'Login successful', {
      user: user.toObject(),
      token
    }));

  } catch (error) {
    DebugSystem.error('AUTH_LOGIN', 'Login failed:', error);
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

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) {
      // Don't reveal that user doesn't exist for security
      DebugSystem.log('AUTH_FORGOT', `Password reset request for non-existent email: ${email}`);
      return res.json(formatResponse(true, 'If your email exists, you will receive a reset link'));
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
      DebugSystem.error('AUTH_FORGOT', 'Failed to send reset email', emailResult.error);
      return res.status(500).json(formatResponse(false, 'Failed to send reset email'));
    }

    DebugSystem.log('AUTH_FORGOT', `Password reset email sent to: ${email}`);
    res.json(formatResponse(true, 'Password reset email sent successfully'));
  } catch (error) {
    DebugSystem.error('AUTH_FORGOT', 'Error processing forgot password request:', error);
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

    DebugSystem.log('AUTH_RESET', `Password reset successful for user: ${user.email}`);
    res.json(formatResponse(true, 'Password reset successful'));
  } catch (error) {
    DebugSystem.error('AUTH_RESET', 'Error resetting password:', error);
    handleError(res, error, 'Error resetting password');
  }
});

// ==================== ENHANCED PROFILE ENDPOINTS WITH NULL SAFETY ====================

// Get profile with complete data
app.get('/api/profile', auth, async (req, res) => {
  try {
    if (!req.user || !req.user._id) {
      DebugSystem.warn('PROFILE', 'User not found in request');
      return res.status(401).json(formatResponse(false, 'User authentication required'));
    }
    
    const userId = req.user._id;
    
    DebugSystem.log('PROFILE', `Fetching profile for user: ${userId}`);
    
    // Get COMPLETE user data with all related information
    const [user, investments, transactions, notifications, kyc, deposits, withdrawals, referrals, supportTickets] = await Promise.all([
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
        .populate('referred_user', 'full_name email createdAt balance')
        .sort({ createdAt: -1 })
        .lean(),
      SupportTicket.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(5)
        .lean()
    ]);

    if (!user) {
      DebugSystem.warn('PROFILE', `User not found in database: ${userId}`);
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    // Calculate COMPREHENSIVE stats
    const activeInvestments = investments.filter(inv => inv.status === 'active');
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    
    // Calculate daily interest from active investments
    const dailyInterest = activeInvestments.reduce((sum, inv) => {
      if (inv.plan && inv.plan.daily_interest) {
        return sum + (inv.amount * inv.plan.daily_interest / 100);
      }
      return sum;
    }, 0);
    
    // Calculate total earnings
    const totalEarnings = investments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0);
    
    // Calculate referral earnings
    const referralEarnings = referrals.reduce((sum, ref) => sum + (ref.earnings || 0), 0);
    
    // Calculate total deposits and withdrawals
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
        paypal_email: user.paypal_email || null
      },
      
      // Enhanced dashboard stats with all calculations
      dashboard_stats: {
        // Financial stats
        active_investment_value: totalActiveValue,
        total_earnings: totalEarnings,
        daily_interest: dailyInterest,
        referral_earnings: referralEarnings,
        total_deposits_amount: totalDepositsAmount,
        total_withdrawals_amount: totalWithdrawalsAmount,
        
        // Count stats
        total_investments: investments.length,
        active_investments_count: activeInvestments.length,
        total_deposits: deposits.filter(d => d.status === 'approved').length,
        total_withdrawals: withdrawals.filter(w => w.status === 'paid').length,
        referral_count: user.referral_count || 0,
        unread_notifications: notifications.filter(n => !n.is_read).length,
        
        // Balance stats
        available_balance: user.balance || 0,
        portfolio_value: (user.balance || 0) + totalEarnings + referralEarnings,
        
        // Status stats
        kyc_status: user.kyc_status || 'not_submitted',
        kyc_verified: user.kyc_verified || false,
        account_status: user.is_active ? 'active' : 'inactive'
      },
      
      // All historical data with images
      investment_history: investments.map(inv => ({
        ...inv,
        has_proof: !!inv.payment_proof_url,
        proof_url: inv.payment_proof_url || null
      })),
      
      transaction_history: transactions.map(txn => ({
        ...txn,
        has_proof: !!txn.payment_proof_url,
        proof_url: txn.payment_proof_url || null
      })),
      
      deposit_history: deposits.map(dep => ({
        ...dep,
        has_proof: !!dep.payment_proof_url,
        proof_url: dep.payment_proof_url || null
      })),
      
      withdrawal_history: withdrawals.map(wdl => ({
        ...wdl,
        has_proof: !!wdl.payment_proof_url,
        proof_url: wdl.payment_proof_url || null
      })),
      
      // Other data
      referral_history: referrals,
      kyc_submission: kyc,
      notifications: notifications,
      support_tickets: supportTickets,
      
      // Calculations for display
      calculations: {
        daily_interest_breakdown: activeInvestments.map(inv => ({
          plan: inv.plan?.name,
          amount: inv.amount,
          daily_rate: inv.plan?.daily_interest || 0,
          daily_earning: (inv.amount * (inv.plan?.daily_interest || 0) / 100),
          remaining_days: Math.max(0, Math.ceil((new Date(inv.end_date) - new Date()) / (1000 * 60 * 60 * 24)))
        })),
        upcoming_payouts: activeInvestments.filter(inv => {
          const daysLeft = Math.ceil((new Date(inv.end_date) - new Date()) / (1000 * 60 * 60 * 24));
          return daysLeft <= 7;
        }).map(inv => ({
          plan: inv.plan?.name,
          amount: inv.amount,
          end_date: inv.end_date,
          days_left: Math.ceil((new Date(inv.end_date) - new Date()) / (1000 * 60 * 60 * 24)),
          expected_payout: inv.expected_earnings
        }))
      }
    };

    DebugSystem.log('PROFILE', `Profile retrieved for user: ${user.email}`);
    res.json(formatResponse(true, 'Profile retrieved successfully', profileData));
  } catch (error) {
    DebugSystem.error('PROFILE', 'Error fetching profile:', error);
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
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    await createNotification(
      userId,
      'Profile Updated',
      'Your profile information has been successfully updated.',
      'info',
      '/profile'
    );

    DebugSystem.log('PROFILE', `Profile updated for user: ${user.email}`);
    res.json(formatResponse(true, 'Profile updated successfully', { user }));
  } catch (error) {
    DebugSystem.error('PROFILE', 'Error updating profile:', error);
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

    // Create notification for user
    await createNotification(
      userId,
      'Bank Details Updated',
      'Your bank account details have been updated successfully. They will be verified by our team.',
      'info',
      '/profile'
    );

    // Notify admin about bank details update
    const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } });
    for (const admin of admins) {
      await createNotification(
        admin._id,
        'User Updated Bank Details',
        `User ${user.full_name} has updated their bank details. Please verify for withdrawal requests.`,
        'system',
        `/admin/users/${userId}`
      );
    }

    DebugSystem.log('PROFILE', `Bank details updated for user: ${user.email}`);
    res.json(formatResponse(true, 'Bank details updated successfully', {
      bank_details: user.bank_details
    }));
  } catch (error) {
    DebugSystem.error('PROFILE', 'Error updating bank details:', error);
    handleError(res, error, 'Error updating bank details');
  }
});

// ==================== INVESTMENT PLANS ENDPOINTS ====================

// Get all investment plans
app.get('/api/plans', async (req, res) => {
  try {
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
    
    DebugSystem.log('PLANS', `Retrieved ${plans.length} investment plans`);
    res.json(formatResponse(true, 'Plans retrieved successfully', { plans: enhancedPlans }));
  } catch (error) {
    DebugSystem.error('PLANS', 'Error fetching investment plans:', error);
    handleError(res, error, 'Error fetching investment plans');
  }
});

// Get specific plan
app.get('/api/plans/:id', async (req, res) => {
  try {
    const plan = await InvestmentPlan.findById(req.params.id);
    
    if (!plan) {
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
    
    res.json(formatResponse(true, 'Plan retrieved successfully', { plan: enhancedPlan }));
  } catch (error) {
    DebugSystem.error('PLANS', 'Error fetching investment plan:', error);
    handleError(res, error, 'Error fetching investment plan');
  }
});

// ==================== INVESTMENT ENDPOINTS ====================

// Get user investments
app.get('/api/investments', auth, async (req, res) => {
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

    DebugSystem.log('INVESTMENTS', `Retrieved ${investments.length} investments for user: ${userId}`);
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
    DebugSystem.error('INVESTMENTS', 'Error fetching investments:', error);
    handleError(res, error, 'Error fetching investments');
  }
});

// Create investment with image upload
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
    
    // Check plan
    const plan = await InvestmentPlan.findById(plan_id);
    if (!plan) {
      return res.status(404).json(formatResponse(false, 'Investment plan not found'));
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

    // Check balance
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
            proof_url: proofUrl 
          }
        );
      }
    }

    DebugSystem.log('INVESTMENTS', `Investment created: ${investment._id} for user: ${userId}`);
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
    DebugSystem.error('INVESTMENTS', 'Error creating investment:', error);
    handleError(res, error, 'Error creating investment');
  }
});

// ==================== DEPOSIT ENDPOINTS ====================

// Get user deposits
app.get('/api/deposits', auth, async (req, res) => {
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

    // Enhance deposits
    const enhancedDeposits = deposits.map(dep => ({
      ...dep,
      has_proof: !!dep.payment_proof_url,
      proof_url: dep.payment_proof_url || null,
      formatted_amount: `₦${dep.amount.toLocaleString()}`,
      status_color: dep.status === 'approved' ? 'success' : 
                    dep.status === 'pending' ? 'warning' : 
                    dep.status === 'rejected' ? 'error' : 'default'
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

    DebugSystem.log('DEPOSITS', `Retrieved ${deposits.length} deposits for user: ${userId}`);
    res.json(formatResponse(true, 'Deposits retrieved successfully', {
      deposits: enhancedDeposits,
      stats: {
        total_deposits: totalDeposits,
        pending_deposits: pendingDeposits,
        total_count: total,
        approved_count: enhancedDeposits.filter(d => d.status === 'approved').length,
        pending_count: enhancedDeposits.filter(d => d.status === 'pending').length
      },
      pagination
    }));
  } catch (error) {
    DebugSystem.error('DEPOSITS', 'Error fetching deposits:', error);
    handleError(res, error, 'Error fetching deposits');
  }
});

// Create deposit with image upload
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

    // Notify admin with image details
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
          proof_url: proofUrl 
        }
      );
    }

    DebugSystem.log('DEPOSITS', `Deposit created: ${deposit._id} for user: ${userId}`);
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
    DebugSystem.error('DEPOSITS', 'Error creating deposit:', error);
    handleError(res, error, 'Error creating deposit');
  }
});

// ==================== WITHDRAWAL ENDPOINTS ====================

// Get user withdrawals
app.get('/api/withdrawals', auth, async (req, res) => {
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

    // Enhance withdrawals with calculations
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
        Math.ceil((new Date(wdl.paid_at) - new Date(wdl.createdAt)) / (1000 * 60 * 60)) : null
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

    DebugSystem.log('WITHDRAWALS', `Retrieved ${withdrawals.length} withdrawals for user: ${userId}`);
    res.json(formatResponse(true, 'Withdrawals retrieved successfully', {
      withdrawals: enhancedWithdrawals,
      stats: {
        total_withdrawals: totalWithdrawals,
        pending_withdrawals: pendingWithdrawals,
        total_fees: totalFees,
        total_count: total,
        paid_count: enhancedWithdrawals.filter(w => w.status === 'paid').length,
        pending_count: enhancedWithdrawals.filter(w => w.status === 'pending').length
      },
      pagination
    }));
  } catch (error) {
    DebugSystem.error('WITHDRAWALS', 'Error fetching withdrawals:', error);
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

    // Check minimum withdrawal
    if (withdrawalAmount < config.minWithdrawal) {
      return res.status(400).json(formatResponse(false, 
        `Minimum withdrawal is ₦${config.minWithdrawal.toLocaleString()}`));
    }

    // Check user balance
    if (withdrawalAmount > req.user.balance) {
      return res.status(400).json(formatResponse(false, 'Insufficient balance for withdrawal'));
    }

    // Calculate platform fee
    const platformFee = withdrawalAmount * (config.platformFeePercent / 100);
    const netAmount = withdrawalAmount - platformFee;

    // Validate payment method specific details
    let paymentDetails = {};
    if (payment_method === 'bank_transfer') {
      if (!req.user.bank_details || !req.user.bank_details.account_number) {
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
        return res.status(400).json(formatResponse(false, 'Please set your wallet address in profile settings'));
      }
      paymentDetails = { wallet_address: req.user.wallet_address };
    } else if (payment_method === 'paypal') {
      if (!req.user.paypal_email) {
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

    DebugSystem.log('WITHDRAWALS', `Withdrawal created: ${withdrawal._id} for user: ${userId}`);
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
    DebugSystem.error('WITHDRAWALS', 'Error creating withdrawal:', error);
    handleError(res, error, 'Error creating withdrawal');
  }
});

// ==================== ADMIN ENDPOINTS WITH NULL SAFETY ====================

// Advanced Admin Dashboard Stats
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
  try {
    if (!req.user) {
      DebugSystem.warn('ADMIN_DASHBOARD', 'Admin user not found in request');
      return res.status(401).json(formatResponse(false, 'Admin authentication required'));
    }

    DebugSystem.log('ADMIN_DASHBOARD', `Admin dashboard accessed by: ${req.user.email}`);
    
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
      pendingKYC
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
      KYCSubmission.countDocuments({ status: 'pending' })
    ]);

    const totalEarnings = earningsResult[0]?.total || 0;
    const platformEarnings = platformFeesResult[0]?.total || 0;
    const referralEarnings = referralEarningsResult[0]?.total || 0;

    const stats = {
      overview: {
        total_users: totalUsers,
        new_users_today: newUsersToday,
        new_users_week: newUsersWeek,
        total_investments: totalInvestments,
        active_investments: activeInvestments,
        total_deposits: totalDeposits,
        total_withdrawals: totalWithdrawals,
        total_earnings: totalEarnings,
        platform_revenue: platformEarnings,
        referral_earnings: referralEarnings
      },
      pending_actions: {
        pending_investments: pendingInvestments,
        pending_deposits: pendingDeposits,
        pending_withdrawals: pendingWithdrawals,
        pending_kyc: pendingKYC,
        total_pending: pendingInvestments + pendingDeposits + pendingWithdrawals + pendingKYC
      }
    };

    // Create audit log
    await createAdminAudit(
      req.user._id,
      'VIEW_ADMIN_DASHBOARD',
      'system',
      null,
      { dashboard_accessed: new Date() },
      req.ip,
      req.headers['user-agent']
    );

    res.json(formatResponse(true, 'Admin dashboard stats retrieved successfully', {
      stats,
      admin: {
        name: req.user.full_name,
        email: req.user.email,
        role: req.user.role
      },
      quick_links: {
        pending_investments: '/api/admin/pending-investments',
        pending_deposits: '/api/admin/pending-deposits',
        pending_withdrawals: '/api/admin/pending-withdrawals',
        pending_kyc: '/api/admin/pending-kyc',
        all_users: '/api/admin/users',
        all_transactions: '/api/admin/transactions'
      }
    }));
  } catch (error) {
    DebugSystem.error('ADMIN_DASHBOARD', 'Error fetching admin dashboard stats:', error);
    handleError(res, error, 'Error fetching admin dashboard stats');
  }
});

// Admin view user dashboard endpoint
app.get('/api/admin/users/:id/dashboard', adminAuth, async (req, res) => {
  try {
    const userId = req.params.id;
    
    DebugSystem.log('ADMIN_USER_DASHBOARD', `Viewing user dashboard for: ${userId}`);
    
    // Get comprehensive user data
    const [user, investments, transactions, deposits, withdrawals, kyc, referrals] = await Promise.all([
      User.findById(userId)
        .select('-password -two_factor_secret -verification_token -password_reset_token')
        .populate('referred_by', 'full_name email referral_code')
        .lean(),
      Investment.find({ user: userId })
        .populate('plan', 'name daily_interest duration total_interest')
        .sort({ createdAt: -1 })
        .lean(),
      Transaction.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(50)
        .lean(),
      Deposit.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      Withdrawal.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      KYCSubmission.findOne({ user: userId }).lean(),
      Referral.find({ referrer: userId })
        .populate('referred_user', 'full_name email createdAt balance')
        .sort({ createdAt: -1 })
        .lean()
    ]);
    
    if (!user) {
      DebugSystem.warn('ADMIN_USER_DASHBOARD', `User not found: ${userId}`);
      return res.status(404).json(formatResponse(false, 'User not found'));
    }
    
    // Calculate detailed stats
    const activeInvestments = investments.filter(inv => inv.status === 'active');
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    const totalEarned = investments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0);
    const totalDeposited = deposits
      .filter(d => d.status === 'approved')
      .reduce((sum, d) => sum + d.amount, 0);
    const totalWithdrawn = withdrawals
      .filter(w => w.status === 'paid')
      .reduce((sum, w) => sum + w.amount, 0);
    
    // Calculate daily interest
    const dailyInterest = activeInvestments.reduce((sum, inv) => {
      if (inv.plan && inv.plan.daily_interest) {
        return sum + (inv.amount * inv.plan.daily_interest / 100);
      }
      return sum;
    }, 0);
    
    // Calculate referral earnings
    const referralEarnings = referrals.reduce((sum, ref) => sum + (ref.earnings || 0), 0);
    
    // Create audit log for admin viewing
    await createAdminAudit(
      req.user._id,
      'VIEW_USER_DASHBOARD',
      'user',
      userId,
      { viewed_at: new Date(), user_name: user.full_name },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'User dashboard data retrieved', {
      user: {
        ...user,
        bank_details: user.bank_details || null,
        wallet_address: user.wallet_address || null,
        paypal_email: user.paypal_email || null
      },
      dashboard_stats: {
        // Financial Overview
        current_balance: user.balance || 0,
        total_earnings: user.total_earnings || 0,
        referral_earnings: user.referral_earnings || 0,
        daily_interest: dailyInterest,
        active_investment_value: totalActiveValue,
        portfolio_value: (user.balance || 0) + totalEarned + referralEarnings,
        
        // Transaction Totals
        total_deposits: totalDeposited,
        total_withdrawals: totalWithdrawn,
        total_invested: investments.reduce((sum, inv) => sum + inv.amount, 0),
        total_earned: totalEarned,
        
        // Counts
        total_investments: investments.length,
        active_investments: activeInvestments.length,
        total_deposit_count: deposits.length,
        total_withdrawal_count: withdrawals.length,
        referral_count: referrals.length,
        
        // Status
        kyc_status: user.kyc_status,
        kyc_verified: user.kyc_verified,
        account_status: user.is_active ? 'active' : 'inactive',
        last_login: user.last_login,
        member_since: user.createdAt
      },
      
      // Detailed Data
      investments: investments.slice(0, 10),
      transactions: transactions.slice(0, 20),
      deposits: deposits.slice(0, 10),
      withdrawals: withdrawals.slice(0, 10),
      kyc_submission: kyc,
      referrals: referrals.slice(0, 10)
    }));
    
  } catch (error) {
    DebugSystem.error('ADMIN_USER_DASHBOARD', 'Error fetching user dashboard:', error);
    handleError(res, error, 'Error fetching user dashboard');
  }
});

// Get all users with advanced filtering
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

    // Create audit log
    await createAdminAudit(
      req.user._id,
      'VIEW_ALL_USERS',
      'system',
      null,
      { 
        page,
        limit,
        filters: { status, role, kyc_status, search },
        user_count: users.length
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

    DebugSystem.log('ADMIN_USERS', `Retrieved ${users.length} users for admin: ${req.user.email}`);
    res.json(formatResponse(true, 'Users retrieved successfully', {
      users,
      pagination,
      filters: {
        status,
        role,
        kyc_status,
        search
      },
      summary: {
        total_users: total,
        active_users: users.filter(u => u.is_active).length,
        verified_users: users.filter(u => u.kyc_verified).length
      }
    }));
  } catch (error) {
    DebugSystem.error('ADMIN_USERS', 'Error fetching users:', error);
    handleError(res, error, 'Error fetching users');
  }
});

// Get detailed user information by ID
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
      userReferrals
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
        .lean()
    ]);
    
    // Calculate user statistics
    const userStats = {
      total_investments: investments.length,
      active_investments: investments.filter(i => i.status === 'active').length,
      total_deposits: deposits.filter(d => d.status === 'approved').length,
      total_withdrawals: withdrawals.filter(w => w.status === 'paid').length,
      total_transactions: transactions.length,
      total_referrals: userReferrals.length
    };
    
    // Create audit log
    await createAdminAudit(
      req.user._id,
      'VIEW_USER_DETAILS',
      'user',
      userId,
      { viewed_at: new Date(), user_name: user.full_name },
      req.ip,
      req.headers['user-agent']
    );
    
    DebugSystem.log('ADMIN_USER_DETAILS', `Retrieved details for user: ${user.email}`);
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
        recent: investments.slice(0, 10)
      },
      deposits: {
        count: deposits.length,
        recent: deposits.slice(0, 10)
      },
      withdrawals: {
        count: withdrawals.length,
        recent: withdrawals.slice(0, 10)
      },
      transactions: {
        count: transactions.length,
        recent: transactions.slice(0, 20)
      },
      referrals: {
        referred_by: referrals[0]?.referrer || null,
        referral_code: user.referral_code,
        referred_users: userReferrals
      },
      kyc_submission: kyc,
      support_tickets: supportTickets
    }));
  } catch (error) {
    DebugSystem.error('ADMIN_USER_DETAILS', 'Error fetching user details:', error);
    handleError(res, error, 'Error fetching user details');
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

    DebugSystem.log('ADMIN_PENDING_INVESTMENTS', `Retrieved ${pendingInvestments.length} pending investments`);
    res.json(formatResponse(true, 'Pending investments retrieved successfully', {
      investments: pendingInvestments,
      count: pendingInvestments.length,
      total_amount: pendingInvestments.reduce((sum, inv) => sum + inv.amount, 0)
    }));
  } catch (error) {
    DebugSystem.error('ADMIN_PENDING_INVESTMENTS', 'Error fetching pending investments:', error);
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

    // Send email notification
    if (config.emailEnabled) {
      await sendEmail(
        investment.user.email,
        'Investment Approved',
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
    }

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

    DebugSystem.log('ADMIN_APPROVE_INVESTMENT', `Investment ${investmentId} approved by admin: ${req.user.email}`);
    res.json(formatResponse(true, 'Investment approved successfully', {
      investment: {
        ...investment.toObject(),
        approved_by_admin: req.user.full_name
      },
      message: 'Investment approved and user notified'
    }));
  } catch (error) {
    DebugSystem.error('ADMIN_APPROVE_INVESTMENT', 'Error approving investment:', error);
    handleError(res, error, 'Error approving investment');
  }
});

// Get pending deposits
app.get('/api/admin/pending-deposits', adminAuth, async (req, res) => {
  try {
    const pendingDeposits = await Deposit.find({ status: 'pending' })
      .populate('user', 'full_name email phone balance')
      .sort({ createdAt: -1 })
      .lean();

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

    DebugSystem.log('ADMIN_PENDING_DEPOSITS', `Retrieved ${pendingDeposits.length} pending deposits`);
    res.json(formatResponse(true, 'Pending deposits retrieved successfully', {
      deposits: pendingDeposits,
      count: pendingDeposits.length,
      total_amount: pendingDeposits.reduce((sum, dep) => sum + dep.amount, 0)
    }));
  } catch (error) {
    DebugSystem.error('ADMIN_PENDING_DEPOSITS', 'Error fetching pending deposits:', error);
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

    // Send email notification
    if (config.emailEnabled) {
      await sendEmail(
        deposit.user.email,
        'Deposit Approved',
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
    }

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

    DebugSystem.log('ADMIN_APPROVE_DEPOSIT', `Deposit ${depositId} approved by admin: ${req.user.email}`);
    res.json(formatResponse(true, 'Deposit approved successfully', {
      deposit: {
        ...deposit.toObject(),
        approved_by_admin: req.user.full_name,
        user_new_balance: deposit.user.balance + deposit.amount
      },
      message: 'Deposit approved and user notified'
    }));
  } catch (error) {
    DebugSystem.error('ADMIN_APPROVE_DEPOSIT', 'Error approving deposit:', error);
    handleError(res, error, 'Error approving deposit');
  }
});

// Get pending withdrawals
app.get('/api/admin/pending-withdrawals', adminAuth, async (req, res) => {
  try {
    const pendingWithdrawals = await Withdrawal.find({ status: 'pending' })
      .populate('user', 'full_name email phone balance')
      .sort({ createdAt: -1 })
      .lean();

    // Calculate summary
    const summary = {
      total_amount: pendingWithdrawals.reduce((sum, wdl) => sum + wdl.amount, 0),
      total_net_amount: pendingWithdrawals.reduce((sum, wdl) => sum + wdl.net_amount, 0),
      total_fees: pendingWithdrawals.reduce((sum, wdl) => sum + wdl.platform_fee, 0),
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

    DebugSystem.log('ADMIN_PENDING_WITHDRAWALS', `Retrieved ${pendingWithdrawals.length} pending withdrawals`);
    res.json(formatResponse(true, 'Pending withdrawals retrieved successfully', {
      withdrawals: pendingWithdrawals,
      count: pendingWithdrawals.length,
      summary
    }));
  } catch (error) {
    DebugSystem.error('ADMIN_PENDING_WITHDRAWALS', 'Error fetching pending withdrawals:', error);
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
    withdrawal.admin_notes = remarks;
    
    await withdrawal.save();

    // Update transaction status
    await Transaction.findOneAndUpdate(
      { related_withdrawal: withdrawalId },
      { 
        status: 'completed',
        payment_proof_url: payment_proof_url,
        admin_notes: remarks
      }
    );

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
    if (config.emailEnabled) {
      await sendEmail(
        withdrawal.user.email,
        'Withdrawal Processed Successfully',
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
    }

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

    DebugSystem.log('ADMIN_APPROVE_WITHDRAWAL', `Withdrawal ${withdrawalId} approved by admin: ${req.user.email}`);
    res.json(formatResponse(true, 'Withdrawal approved successfully', {
      withdrawal: {
        ...withdrawal.toObject(),
        approved_by_admin: req.user.full_name,
        has_transaction_proof: !!payment_proof_url
      },
      message: 'Withdrawal processed and user notified'
    }));
  } catch (error) {
    DebugSystem.error('ADMIN_APPROVE_WITHDRAWAL', 'Error approving withdrawal:', error);
    handleError(res, error, 'Error approving withdrawal');
  }
});

// Get pending KYC submissions
app.get('/api/admin/pending-kyc', adminAuth, async (req, res) => {
  try {
    const pendingKYC = await KYCSubmission.find({ status: 'pending' })
      .populate('user', 'full_name email phone')
      .sort({ createdAt: -1 })
      .lean();

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

    DebugSystem.log('ADMIN_PENDING_KYC', `Retrieved ${pendingKYC.length} pending KYC submissions`);
    res.json(formatResponse(true, 'Pending KYC submissions retrieved successfully', {
      kyc_submissions: pendingKYC,
      count: pendingKYC.length
    }));
  } catch (error) {
    DebugSystem.error('ADMIN_PENDING_KYC', 'Error fetching pending KYC:', error);
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
        id_type: kyc.id_type
      }
    );

    // Send email
    if (config.emailEnabled) {
      await sendEmail(
        kyc.user.email,
        'KYC Verification Approved',
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
    }

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

    DebugSystem.log('ADMIN_APPROVE_KYC', `KYC ${kycId} approved by admin: ${req.user.email}`);
    res.json(formatResponse(true, 'KYC approved successfully', {
      kyc: {
        ...kyc.toObject(),
        reviewed_by_admin: req.user.full_name
      }
    }));
  } catch (error) {
    DebugSystem.error('ADMIN_APPROVE_KYC', 'Error approving KYC:', error);
    handleError(res, error, 'Error approving KYC');
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
    );

    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

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
      req.headers['user-agent']
    );

    DebugSystem.log('ADMIN_UPDATE_ROLE', `User ${userId} role updated to ${role} by admin: ${req.user.email}`);
    res.json(formatResponse(true, 'User role updated successfully', { user }));
  } catch (error) {
    DebugSystem.error('ADMIN_UPDATE_ROLE', 'Error updating user role:', error);
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

    const user = await User.findByIdAndUpdate(
      userId,
      { is_active },
      { new: true }
    );

    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

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
      req.headers['user-agent']
    );

    DebugSystem.log('ADMIN_UPDATE_STATUS', `User ${userId} status updated to ${is_active ? 'active' : 'inactive'} by admin: ${req.user.email}`);
    res.json(formatResponse(true, 
      is_active ? 'User activated successfully' : 'User deactivated successfully', 
      { user }
    ));
  } catch (error) {
    DebugSystem.error('ADMIN_UPDATE_STATUS', 'Error updating user status:', error);
    handleError(res, error, 'Error updating user status');
  }
});

// ==================== ENHANCED CRON JOBS ====================

// Calculate daily earnings
cron.schedule('0 0 * * *', async () => {
  try {
    DebugSystem.log('CRON', 'Starting daily earnings calculation...');
    
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
          `Daily earnings from ${investment.plan.name}`,
          'completed',
          { 
            investment_id: investment._id,
            plan_name: investment.plan.name,
            daily_rate: investment.plan.daily_interest
          }
        );
        
        totalEarnings += dailyEarning;
        processedCount++;

      } catch (investmentError) {
        DebugSystem.error('CRON', `Error processing investment ${investment._id}:`, investmentError);
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
        
      } catch (completeError) {
        DebugSystem.error('CRON', `Error completing investment ${investment._id}:`, completeError);
      }
    }

    DebugSystem.log('CRON', `Daily earnings calculated. Processed: ${processedCount}, Total: ₦${totalEarnings.toLocaleString()}`);
  } catch (error) {
    DebugSystem.error('CRON', 'Error calculating daily earnings:', error);
  }
});

// Auto-renew investments
cron.schedule('0 1 * * *', async () => {
  try {
    DebugSystem.log('CRON', 'Processing auto-renew investments...');
    
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
          DebugSystem.log('CRON', `User ${userId} has insufficient balance for auto-renew`);
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
          end_date: new Date(Date.now() + investment.plan.duration * 24 * 60 * 60 * 1000),
          expected_earnings: (investment.amount * investment.plan.total_interest) / 100,
          earned_so_far: 0,
          daily_earnings: (investment.amount * investment.plan.daily_interest) / 100,
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
        
        // Create transaction
        await createTransaction(
          userId,
          'investment',
          -investment.amount,
          `Auto-renew investment in ${investment.plan.name}`,
          'completed',
          { 
            investment_id: newInvestment._id,
            renewed_from: investment._id,
            plan_name: investment.plan.name,
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
          `Your investment of ₦${investment.amount.toLocaleString()} in ${investment.plan.name} has been automatically renewed.`,
          'investment',
          '/investments',
          { 
            amount: investment.amount,
            plan_name: investment.plan.name,
            new_investment_id: newInvestment._id,
            renewal_count: (investment.metadata?.renewal_count || 0) + 1
          }
        );

        renewedCount++;
        DebugSystem.log('CRON', `Auto-renewed investment ${investment._id} for user ${userId}`);

      } catch (error) {
        DebugSystem.error('CRON', `Error auto-renewing investment ${investment._id}:`, error);
        skippedCount++;
      }
    }

    DebugSystem.log('CRON', `Auto-renew completed. Renewed: ${renewedCount}, Skipped: ${skippedCount}`);
  } catch (error) {
    DebugSystem.error('CRON', 'Error processing auto-renew:', error);
  }
});

// Cleanup expired data
cron.schedule('0 2 * * *', async () => {
  try {
    DebugSystem.log('CRON', 'Cleaning up expired data...');
    
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
    
    // Clean up old admin audit logs (older than 180 days)
    const oneEightyDaysAgo = new Date();
    oneEightyDaysAgo.setDate(oneEightyDaysAgo.getDate() - 180);
    
    const deletedAudits = await AdminAudit.deleteMany({
      createdAt: { $lt: oneEightyDaysAgo }
    });
    
    DebugSystem.log('CRON', `Cleanup completed. Removed: ${deletedNotifications.deletedCount} notifications, ${deletedAudits.deletedCount} audit logs`);
  } catch (error) {
    DebugSystem.error('CRON', 'Error during cleanup:', error);
  }
});

// ==================== ENHANCED ERROR HANDLING ====================

// 404 handler
app.use((req, res) => {
  DebugSystem.warn('404', `Endpoint not found: ${req.method} ${req.originalUrl}`);
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
      '/api/debug/*',
      '/health'
    ]
  }));
});

// Global error handler
app.use((err, req, res, next) => {
  DebugSystem.error('GLOBAL_ERROR', 'Unhandled error:', err);
  
  // Log error for debugging
  const errorLog = {
    timestamp: new Date().toISOString(),
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    user_agent: req.headers['user-agent'],
    error: {
      message: err.message,
      stack: config.nodeEnv === 'development' ? err.stack : undefined,
      name: err.name
    }
  };
  
  if (err instanceof multer.MulterError) {
    return res.status(400).json(formatResponse(false, `File upload error: ${err.message}`));
  }
  
  // Database errors
  if (err.name === 'MongoError' || err.name === 'MongooseError') {
    return res.status(500).json(formatResponse(false, 'Database error occurred. Please try again later.'));
  }
  
  // Network errors
  if (err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT') {
    return res.status(503).json(formatResponse(false, 'Service temporarily unavailable. Please try again later.'));
  }
  
  res.status(500).json(formatResponse(false, 'Internal server error', {
    error_id: crypto.randomBytes(8).toString('hex'),
    timestamp: new Date().toISOString(),
    support_contact: 'support@rawwealthy.com'
  }));
});

// ==================== ENHANCED SERVER INITIALIZATION ====================

const startServer = async () => {
  try {
    DebugSystem.log('SERVER', '🚀 Starting Raw Wealthy Backend v38.0...');
    
    // Initialize database
    DebugSystem.log('SERVER', 'Initializing database connection...');
    await initializeDatabase();
    
    // Start server
    const server = app.listen(config.port, '0.0.0.0', () => {
      console.log(`
🎯 RAW WEALTHY BACKEND v38.0 - DEBUGGED & ENHANCED
=================================================
🌐 Server running on port ${config.port}
🚀 Environment: ${config.nodeEnv}
📊 Health Check: /health
🔗 API Base: /api
🔍 Debug Endpoints: /api/debug/*
💾 Database: ${mongoose.connection.readyState === 1 ? '✅ Connected' : '❌ Disconnected'}
🛡️ Security: Enhanced Protection
📧 Email: ${config.emailEnabled ? '✅ Enabled' : '❌ Disabled'}
🐛 Debug Mode: ${config.debugMode ? '✅ Enabled' : '❌ Disabled'}

✅ DEBUGGING FEATURES:
   ✅ Fixed Database Connection Issues
   ✅ Enhanced Error Handling with Null Checks
   ✅ Real-time Debug Logging System
   ✅ Database Connection Status Monitoring
   ✅ Detailed Error Messages with Stack Traces
   ✅ Automatic Admin User Creation
   ✅ Connection Retry Logic
   ✅ Comprehensive Health Checks
   ✅ Memory Usage Monitoring
   ✅ Request/Response Logging
   ✅ CORS Configuration Debugging
   ✅ Environment Variable Validation

✅ ENHANCED FEATURES:
   ✅ Advanced Admin Dashboard
   ✅ Complete User Dashboard with Daily Interest
   ✅ Transaction & Image Management
   ✅ Bank Details Verification System
   ✅ Investment Plan Earnings Tracking
   ✅ Automated Notifications with Email
   ✅ Forgot Password Functionality
   ✅ KYC Verification with Image Uploads
   ✅ Support Ticket Management
   ✅ Referral Tracking & Commission
   ✅ File Upload System with Absolute URLs
   ✅ Advanced Filtering & Search
   ✅ Real-time Dashboard Updates
   ✅ Automated Cron Jobs for Earnings
   ✅ Comprehensive Reporting
   ✅ Admin Audit Logging
   ✅ Weekly Report Generation
   ✅ Graceful Shutdown
   ✅ Rate Limiting & Security Headers
   ✅ Memory & Performance Optimization

🚀 FULLY DEBUGGED & PRODUCTION READY!
🔐 SECURITY ENHANCED WITH NULL SAFETY
📈 COMPLETE ANALYTICS & DEBUGGING
📱 RESPONSIVE ADMIN INTERFACE SUPPORT

📊 Debug Stats: http://localhost:${config.port}/api/debug/status
🔧 Database Test: http://localhost:${config.port}/api/debug/test-db
💚 Health Check: http://localhost:${config.port}/health
      `);
      
      DebugSystem.log('SERVER', `Server started successfully on port ${config.port}`);
    });

    // Graceful shutdown
    const gracefulShutdown = async (signal) => {
      DebugSystem.log('SERVER', `${signal} received, shutting down gracefully...`);
      
      // Close server
      server.close(async () => {
        DebugSystem.log('SERVER', 'HTTP server closed');
        
        // Close database connection
        try {
          await mongoose.connection.close();
          DebugSystem.log('SERVER', 'Database connection closed');
        } catch (dbError) {
          DebugSystem.error('SERVER', 'Error closing database:', dbError);
        }
        
        DebugSystem.log('SERVER', 'Process terminated gracefully');
        process.exit(0);
      });
      
      // Force shutdown after 10 seconds
      setTimeout(() => {
        DebugSystem.error('SERVER', 'Could not close connections in time, forcefully shutting down');
        process.exit(1);
      }, 10000);
    };

    // Handle different shutdown signals
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    process.on('SIGUSR2', () => gracefulShutdown('SIGUSR2')); // For nodemon

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      DebugSystem.error('SERVER', 'Uncaught Exception:', error);
      gracefulShutdown('uncaughtException');
    });

    process.on('unhandledRejection', (reason, promise) => {
      DebugSystem.error('SERVER', 'Unhandled Rejection at:', promise, 'reason:', reason);
    });

  } catch (error) {
    DebugSystem.error('SERVER', '❌ Server initialization failed:', error);
    
    // Provide helpful error messages
    console.error('\n❌ SERVER STARTUP FAILED!');
    console.error('================================');
    console.error('Error:', error.message);
    console.error('\nPossible Solutions:');
    console.error('1. Check MongoDB connection string in environment variables');
    console.error('2. Make sure MongoDB is running and accessible');
    console.error('3. Check network connectivity');
    console.error('4. Verify environment variables are set correctly');
    console.error('5. Check if port', config.port, 'is already in use');
    console.error('\nFor more details, check the logs above.');
    console.error('================================\n');
    
    process.exit(1);
  }
};

// Start the server
startServer();

export default app;
