
// server.js - RAW WEALTHY BACKEND v38.0 - ULTIMATE PRODUCTION EDITION
// COMPLETE ENHANCEMENT: Advanced Dashboard + Real-time Earnings + Enhanced Referrals + Full Analytics
// AUTO-DEPLOYMENT READY WITH DYNAMIC CONFIGURATION + PERFORMANCE OPTIMIZATION

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
import WebSocket from 'ws';
import redis from 'redis';
import { promisify } from 'util';

// ES Modules equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Enhanced environment configuration
dotenv.config({ path: path.join(__dirname, '.env.production') });

// ==================== ENVIRONMENT VALIDATION ====================
const requiredEnvVars = [
  'MONGODB_URI',
  'JWT_SECRET',
  'NODE_ENV',
  'CLIENT_URL'
];

console.log('🔍 Environment Configuration:');
console.log('============================');
const missingEnvVars = requiredEnvVars.filter(envVar => {
  if (!process.env[envVar]) {
    console.error(`❌ Missing: ${envVar}`);
    return true;
  }
  console.log(`✅ ${envVar}: ${envVar === 'JWT_SECRET' ? '***' : process.env[envVar]}`);
  return false;
});

if (missingEnvVars.length > 0) {
  console.error('\n🚨 CRITICAL: Missing required environment variables');
  console.error('💡 Please set these in your deployment environment');
  
  // Try to load from alternative sources
  console.log('🔄 Attempting to load from alternative sources...');
  
  if (process.env.DATABASE_URL) {
    process.env.MONGODB_URI = process.env.DATABASE_URL;
    console.log('✅ Loaded MONGODB_URI from DATABASE_URL');
  }
  
  if (!process.env.JWT_SECRET) {
    process.env.JWT_SECRET = crypto.randomBytes(64).toString('hex');
    console.log('✅ Generated JWT_SECRET automatically');
  }
  
  if (!process.env.CLIENT_URL) {
    process.env.CLIENT_URL = 'https://us-raw-wealthy.vercel.app';
    console.log('✅ Set default CLIENT_URL');
  }
}

if (!process.env.SERVER_URL) {
  process.env.SERVER_URL = process.env.CLIENT_URL || `http://localhost:${process.env.PORT || 10000}`;
  console.log('✅ Set SERVER_URL:', process.env.SERVER_URL);
}

console.log('============================\n');

// ==================== DYNAMIC CONFIGURATION ====================
const config = {
  port: process.env.PORT || 10000,
  nodeEnv: process.env.NODE_ENV || 'production',
  serverURL: process.env.SERVER_URL,
  mongoURI: process.env.MONGODB_URI || process.env.DATABASE_URL,
  jwtSecret: process.env.JWT_SECRET,
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '30d',
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 12,
  clientURL: process.env.CLIENT_URL,
  allowedOrigins: [],
  emailEnabled: process.env.EMAIL_HOST && process.env.EMAIL_USER && process.env.EMAIL_PASSWORD,
  emailConfig: {
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT) || 587,
    secure: parseInt(process.env.EMAIL_PORT) === 465,
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
    from: process.env.EMAIL_FROM || `"Raw Wealthy" <${process.env.EMAIL_USER}>`
  },
  minInvestment: parseInt(process.env.MIN_INVESTMENT) || 3500,
  minDeposit: parseInt(process.env.MIN_DEPOSIT) || 3500,
  minWithdrawal: parseInt(process.env.MIN_WITHDRAWAL) || 3500,
  platformFeePercent: parseFloat(process.env.PLATFORM_FEE_PERCENT) || 10,
  referralCommissionPercent: parseFloat(process.env.REFERRAL_COMMISSION_PERCENT) || 10,
  welcomeBonus: parseInt(process.env.WELCOME_BONUS) || 100,
  investmentPlans: [],
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
  redisUrl: process.env.REDIS_URL || 'redis://localhost:6379'
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

console.log('⚙️ Dynamic Configuration Loaded:');
console.log(`- Port: ${config.port}`);
console.log(`- Environment: ${config.nodeEnv}`);
console.log(`- Client URL: ${config.clientURL}`);
console.log(`- Server URL: ${config.serverURL}`);
console.log(`- Email Enabled: ${config.emailEnabled}`);
console.log(`- Allowed Origins: ${config.allowedOrigins.length}`);
console.log(`- Upload Directory: ${config.uploadDir}`);

// ==================== REDIS CACHE SETUP ====================
let redisClient;
if (config.redisUrl && config.redisUrl !== 'redis://localhost:6379') {
  redisClient = redis.createClient({ url: config.redisUrl });
  redisClient.on('error', (err) => console.log('❌ Redis Client Error:', err));
  await redisClient.connect();
  console.log('✅ Redis connected successfully');
} else {
  console.log('⚠️ Redis not configured, using memory cache');
  const memoryCache = new Map();
  redisClient = {
    get: async (key) => memoryCache.get(key),
    set: async (key, value, options) => {
      memoryCache.set(key, value);
      if (options && options.EX) {
        setTimeout(() => memoryCache.delete(key), options.EX * 1000);
      }
    },
    del: async (key) => memoryCache.delete(key),
    exists: async (key) => memoryCache.has(key),
    expire: async (key, seconds) => {
      setTimeout(() => memoryCache.delete(key), seconds * 1000);
      return 1;
    }
  };
}

// Cache utility functions
const cache = {
  get: async (key) => {
    try {
      const value = await redisClient.get(key);
      return value ? JSON.parse(value) : null;
    } catch (error) {
      console.error('Cache get error:', error);
      return null;
    }
  },
  set: async (key, value, ttl = 300) => {
    try {
      await redisClient.set(key, JSON.stringify(value), { EX: ttl });
      return true;
    } catch (error) {
      console.error('Cache set error:', error);
      return false;
    }
  },
  delete: async (key) => {
    try {
      await redisClient.del(key);
      return true;
    } catch (error) {
      console.error('Cache delete error:', error);
      return false;
    }
  },
  clearPattern: async (pattern) => {
    try {
      const keys = await redisClient.keys(`${pattern}*`);
      if (keys.length > 0) {
        await redisClient.del(keys);
      }
      return true;
    } catch (error) {
      console.error('Cache clear pattern error:', error);
      return false;
    }
  }
};

// ==================== ENHANCED EXPRESS SETUP ====================
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

app.use(xss());
app.use(hpp());
app.use(mongoSanitize());
app.use(compression());

if (config.nodeEnv === 'production') {
  app.use(morgan('combined'));
} else {
  app.use(morgan('dev'));
}

// ==================== DYNAMIC CORS CONFIGURATION ====================
const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (config.allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      const isPreviewDeployment = origin.includes('vercel.app') || origin.includes('onrender.com');
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
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'x-api-key', 'x-user-id']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// ==================== BODY PARSING ====================
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

// ==================== RATE LIMITING ====================
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

// ==================== ENHANCED FILE UPLOAD ====================
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
    if (!config.allowedMimeTypes[file.mimetype]) {
      throw new Error('Invalid file type');
    }
    
    const uploadsDir = path.join(config.uploadDir, folder);
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }
    
    const timestamp = Date.now();
    const randomStr = crypto.randomBytes(8).toString('hex');
    const userIdPrefix = userId ? `${userId}_` : '';
    const fileExtension = config.allowedMimeTypes[file.mimetype] || file.originalname.split('.').pop();
    const filename = `${userIdPrefix}${timestamp}_${randomStr}.${fileExtension}`;
    const filepath = path.join(uploadsDir, filename);
    
    await fs.promises.writeFile(filepath, file.buffer);
    
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
    console.error('File upload error:', error);
    throw new Error(`File upload failed: ${error.message}`);
  }
};

// Serve static files
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

// Enhanced email utility function
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

// ==================== ENHANCED DATABASE MODELS ====================

// User Model with Enhanced Fields
const userSchema = new mongoose.Schema({
  full_name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  phone: { type: String, required: true },
  password: { type: String, required: true, select: false },
  role: { type: String, enum: ['user', 'admin', 'super_admin'], default: 'user' },
  balance: { type: Number, default: 0, min: 0 },
  total_earnings: { type: Number, default: 0, min: 0 },
  referral_earnings: { type: Number, default: 0, min: 0 },
  daily_earnings: { type: Number, default: 0, min: 0 },
  total_daily_earnings: { type: Number, default: 0, min: 0 },
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
  earnings_history: [{
    date: Date,
    amount: Number,
    type: String,
    investment_id: mongoose.Schema.Types.ObjectId,
    description: String
  }],
  referral_history: [{
    date: Date,
    referred_user: mongoose.Schema.Types.ObjectId,
    commission: Number,
    status: String
  }]
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
  investment_image_url: String,
  earnings_history: [{
    date: Date,
    amount: Number,
    type: String,
    description: String
  }]
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

// Referral Model with Enhanced Tracking
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
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  commission_history: [{
    date: Date,
    amount: Number,
    from_investment: mongoose.Schema.Types.ObjectId,
    status: String
  }]
}, {
  timestamps: true
});

referralSchema.index({ referrer: 1, status: 1 });

const Referral = mongoose.model('Referral', referralSchema);

// Earnings Model for Detailed Tracking
const earningsSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  investment: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment' },
  date: { type: Date, required: true },
  amount: { type: Number, required: true },
  type: { type: String, enum: ['daily_interest', 'investment_completion', 'referral', 'bonus'], required: true },
  description: { type: String, required: true },
  status: { type: String, enum: ['pending', 'credited', 'failed'], default: 'credited' },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
  timestamps: true
});

earningsSchema.index({ user: 1, date: -1 });
earningsSchema.index({ investment: 1 });

const Earnings = mongoose.model('Earnings', earningsSchema);

// Notification Model
const notificationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, enum: ['info', 'success', 'warning', 'error', 'promotional', 'investment', 'withdrawal', 'deposit', 'kyc', 'referral', 'system', 'earning'], default: 'info' },
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
  target_type: { type: String, enum: ['user', 'investment', 'deposit', 'withdrawal', 'kyc', 'transaction', 'plan', 'system', 'referral', 'earning'] },
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

// Format response utility
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

// Error handler
const handleError = (res, error, defaultMessage = 'An error occurred') => {
  console.error('Error:', error);
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

// Generate reference
const generateReference = (prefix = 'REF') => {
  const timestamp = Date.now();
  const random = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `${prefix}${timestamp}${random}`;
};

// Calculate daily earnings with advanced logic
const calculateDailyEarnings = async (userId) => {
  try {
    const cacheKey = `daily_earnings_${userId}`;
    const cached = await cache.get(cacheKey);
    if (cached) return cached;
    
    const activeInvestments = await Investment.find({
      user: userId,
      status: 'active',
      end_date: { $gt: new Date() }
    }).populate('plan', 'daily_interest name');
    
    let totalDailyEarnings = 0;
    const breakdown = [];
    
    activeInvestments.forEach(inv => {
      const dailyEarning = (inv.amount * (inv.plan?.daily_interest || 0)) / 100;
      totalDailyEarnings += dailyEarning;
      
      breakdown.push({
        investment_id: inv._id,
        plan_name: inv.plan?.name,
        amount: inv.amount,
        daily_interest: inv.plan?.daily_interest,
        daily_earning: dailyEarning
      });
    });
    
    // Update user's daily earnings
    await User.findByIdAndUpdate(userId, {
      daily_earnings: totalDailyEarnings
    });
    
    const result = {
      total_daily_earnings: totalDailyEarnings,
      breakdown,
      active_investments: activeInvestments.length,
      timestamp: new Date()
    };
    
    await cache.set(cacheKey, result, 300); // Cache for 5 minutes
    return result;
  } catch (error) {
    console.error('Error calculating daily earnings:', error);
    return { total_daily_earnings: 0, breakdown: [], active_investments: 0 };
  }
};

// Calculate referral earnings
const calculateReferralEarnings = async (userId) => {
  try {
    const cacheKey = `referral_earnings_${userId}`;
    const cached = await cache.get(cacheKey);
    if (cached) return cached;
    
    const referrals = await Referral.find({ referrer: userId });
    const totalEarnings = referrals.reduce((sum, ref) => sum + (ref.earnings || 0), 0);
    const activeReferrals = referrals.filter(r => r.status === 'active').length;
    
    // Get referred users who have made investments
    const referredUserIds = referrals.map(r => r.referred_user);
    const investments = await Investment.find({
      user: { $in: referredUserIds },
      status: 'active'
    });
    
    const totalInvestedByReferrals = investments.reduce((sum, inv) => sum + inv.amount, 0);
    
    const result = {
      total_earnings: totalEarnings,
      total_referrals: referrals.length,
      active_referrals: activeReferrals,
      pending_earnings: referrals.filter(r => !r.earnings_paid).reduce((sum, r) => sum + (r.earnings || 0), 0),
      total_invested_by_referrals: totalInvestedByReferrals,
      estimated_monthly_commission: totalInvestedByReferrals * (config.referralCommissionPercent / 100) / 12
    };
    
    await cache.set(cacheKey, result, 300);
    return result;
  } catch (error) {
    console.error('Error calculating referral earnings:', error);
    return { total_earnings: 0, total_referrals: 0, active_referrals: 0 };
  }
};

// Create notification
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
    
    // Send email if enabled
    const user = await User.findById(userId);
    if (user && user.email_notifications && type !== 'system') {
      await sendEmail(
        user.email,
        `Raw Wealthy - ${title}`,
        `
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
        `
      );
    }
    return notification;
  } catch (error) {
    console.error('Error creating notification:', error);
    return null;
  }
};

// Create transaction
const createTransaction = async (userId, type, amount, description, status = 'completed', metadata = {}, proofUrl = null) => {
  try {
    const user = await User.findById(userId);
    if (!user) return null;
    
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
    
    // Clear user cache
    await cache.delete(`user_${userId}`);
    await cache.clearPattern(`dashboard_${userId}`);
    
    return transaction;
  } catch (error) {
    console.error('Error creating transaction:', error);
    return null;
  }
};

// Create earnings record
const createEarningsRecord = async (userId, amount, type, description, investmentId = null) => {
  try {
    const earnings = new Earnings({
      user: userId,
      investment: investmentId,
      date: new Date(),
      amount,
      type,
      description,
      status: 'credited'
    });
    await earnings.save();
    
    // Update user total earnings
    await User.findByIdAndUpdate(userId, {
      $inc: { total_earnings: amount },
      $push: {
        earnings_history: {
          date: new Date(),
          amount,
          type,
          investment_id: investmentId,
          description
        }
      }
    });
    
    return earnings;
  } catch (error) {
    console.error('Error creating earnings record:', error);
    return null;
  }
};

// Create referral commission
const createReferralCommission = async (referrerId, referredUserId, amount, investmentId = null) => {
  try {
    const referral = await Referral.findOne({
      referrer: referrerId,
      referred_user: referredUserId
    });
    
    if (!referral) return null;
    
    const commission = (amount * config.referralCommissionPercent) / 100;
    
    referral.earnings += commission;
    referral.status = 'active';
    referral.investment_amount = amount;
    
    referral.commission_history.push({
      date: new Date(),
      amount: commission,
      from_investment: investmentId,
      status: 'pending'
    });
    
    await referral.save();
    
    // Update referrer's earnings
    await User.findByIdAndUpdate(referrerId, {
      $inc: { referral_earnings: commission },
      $push: {
        referral_history: {
          date: new Date(),
          referred_user: referredUserId,
          commission,
          status: 'pending'
        }
      }
    });
    
    // Create earnings record for referrer
    await createEarningsRecord(
      referrerId,
      commission,
      'referral',
      `Referral commission from investment`,
      investmentId
    );
    
    // Create transaction for referrer
    await createTransaction(
      referrerId,
      'referral',
      commission,
      `Referral commission from ${referredUserId}`
    );
    
    // Notify referrer
    await createNotification(
      referrerId,
      'Referral Commission Earned',
      `You earned ₦${commission.toLocaleString()} referral commission from your referral's investment.`,
      'referral',
      '/referrals'
    );
    
    return commission;
  } catch (error) {
    console.error('Error creating referral commission:', error);
    return null;
  }
};

// Admin audit log
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
    return audit;
  } catch (error) {
    console.error('Error creating admin audit:', error);
    return null;
  }
};

// ==================== AUTH MIDDLEWARE ====================
const auth = async (req, res, next) => {
  try {
    let token = req.header('Authorization');
    if (!token) {
      return res.status(401).json(formatResponse(false, 'No token, authorization denied'));
    }
    if (token.startsWith('Bearer ')) {
      token = token.slice(7, token.length);
    }
    const decoded = jwt.verify(token, config.jwtSecret);
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json(formatResponse(false, 'Token is not valid'));
    }
    if (!user.is_active) {
      return res.status(401).json(formatResponse(false, 'Account is deactivated. Please contact support.'));
    }
    req.user = user;
    req.userId = user._id;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json(formatResponse(false, 'Invalid token'));
    } else if (error.name === 'TokenExpiredError') {
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
        return res.status(403).json(formatResponse(false, 'Access denied. Admin privileges required.'));
      }
      next();
    });
  } catch (error) {
    handleError(res, error, 'Admin authentication error');
  }
};

// ==================== DATABASE INITIALIZATION ====================
const initializeDatabase = async () => {
  try {
    console.log('🔄 Initializing database...');
    await mongoose.connect(config.mongoURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      retryWrites: true
    });
    console.log('✅ MongoDB connected successfully');
    await loadInvestmentPlans();
    await createAdminUser();
    await createDatabaseIndexes();
    console.log('✅ Database initialization completed');
  } catch (error) {
    console.error('❌ Database initialization error:', error.message);
    throw error;
  }
};

const loadInvestmentPlans = async () => {
  try {
    const plans = await InvestmentPlan.find({ is_active: true })
      .sort({ display_order: 1 })
      .lean();
    config.investmentPlans = plans;
    console.log(`✅ Loaded ${plans.length} investment plans`);
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
  try {
    console.log('🚀 NUCLEAR ADMIN FIX STARTING...');
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@rawwealthy.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123456';
    console.log(`🔑 Using: ${adminEmail} / ${adminPassword}`);
    
    const existingAdmin = await User.findOne({ email: adminEmail });
    if (existingAdmin) {
      console.log('✅ Admin already exists');
      if (adminPassword === 'Admin123456') {
        const salt = await bcrypt.genSalt(12);
        const hash = await bcrypt.hash(adminPassword, salt);
        existingAdmin.password = hash;
        await existingAdmin.save();
        console.log('✅ Admin password updated');
      }
      return;
    }
    
    const salt = await bcrypt.genSalt(12);
    const hash = await bcrypt.hash(adminPassword, salt);
    console.log('📝 Generated fresh hash');
    
    const adminData = {
      _id: new mongoose.Types.ObjectId(),
      full_name: 'Raw Wealthy Admin',
      email: adminEmail,
      phone: '09161806424',
      password: hash,
      role: 'super_admin',
      balance: 1000000,
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
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    await mongoose.connection.collection('users').insertOne(adminData);
    console.log('✅ Admin created in database');
    
    const verifyUser = await mongoose.connection.collection('users').findOne({ email: adminEmail });
    const match = await bcrypt.compare(adminPassword, verifyUser.password);
    console.log('🔑 Password match test:', match ? '✅ PASS' : '❌ FAIL');
    
    if (match) {
      console.log('🎉 ADMIN READY FOR LOGIN!');
      console.log(`📧 Email: ${adminEmail}`);
      console.log(`🔑 Password: ${adminPassword}`);
      console.log('👉 Login at: /api/auth/login');
    } else {
      console.error('❌ PASSWORD MISMATCH DETECTED!');
    }
    console.log('🚀 NUCLEAR ADMIN FIX COMPLETE');
  } catch (error) {
    console.error('❌ NUCLEAR FIX ERROR:', error.message);
    console.error(error.stack);
  }
};

const createDatabaseIndexes = async () => {
  try {
    await Transaction.collection.createIndex({ createdAt: -1 });
    await User.collection.createIndex({ 'bank_details.verified': 1 });
    await Investment.collection.createIndex({ status: 1, end_date: 1 });
    await Earnings.collection.createIndex({ user: 1, date: -1 });
    console.log('✅ Database indexes created');
  } catch (error) {
    console.error('Error creating indexes:', error);
  }
};

// ==================== HEALTH CHECK ====================
app.get('/health', async (req, res) => {
  const health = {
    success: true,
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '38.0.0',
    environment: config.nodeEnv,
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    redis: redisClient ? 'connected' : 'not configured',
    uptime: process.uptime(),
    memory: {
      rss: `${Math.round(process.memoryUsage().rss / 1024 / 1024)}MB`,
      heapTotal: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)}MB`,
      heapUsed: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`
    },
    stats: {
      users: await User.countDocuments({}),
      investments: await Investment.countDocuments({}),
      deposits: await Deposit.countDocuments({}),
      withdrawals: await Withdrawal.countDocuments({}),
      earnings: await Earnings.countDocuments({})
    }
  };
  res.json(health);
});

// ==================== ROOT ENDPOINT ====================
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 Raw Wealthy Backend API v38.0 - Ultimate Edition',
    version: '38.0.0',
    timestamp: new Date().toISOString(),
    status: 'Operational',
    environment: config.nodeEnv,
    endpoints: {
      auth: '/api/auth/*',
      profile: '/api/profile',
      earnings: '/api/earnings/*',
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
      health: '/health'
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
    
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json(formatResponse(false, 'User already exists with this email'));
    }
    
    let referredBy = null;
    if (referral_code) {
      referredBy = await User.findOne({ referral_code: referral_code.toUpperCase() });
      if (!referredBy) {
        return res.status(400).json(formatResponse(false, 'Invalid referral code'));
      }
    }
    
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
    
    const token = user.generateAuthToken();
    
    await createNotification(
      user._id,
      'Welcome to Raw Wealthy!',
      'Your account has been successfully created. Start your investment journey today.',
      'success',
      '/dashboard'
    );
    
    await createTransaction(
      user._id,
      'bonus',
      config.welcomeBonus,
      'Welcome bonus for new account',
      'completed'
    );
    
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
    
    res.status(201).json(formatResponse(true, 'User registered successfully', {
      user: user.toObject(),
      token
    }));
  } catch (error) {
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
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    
    if (!user) {
      return res.status(400).json(formatResponse(false, 'Invalid credentials'));
    }
    
    if (user.lock_until && user.lock_until > new Date()) {
      const lockTime = Math.ceil((user.lock_until - new Date()) / 1000 / 60);
      return res.status(423).json(formatResponse(false, `Account is locked. Try again in ${lockTime} minutes.`));
    }
    
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      user.login_attempts += 1;
      if (user.login_attempts >= 5) {
        user.lock_until = new Date(Date.now() + 15 * 60 * 1000);
      }
      await user.save();
      return res.status(400).json(formatResponse(false, 'Invalid credentials'));
    }
    
    user.login_attempts = 0;
    user.lock_until = undefined;
    user.last_login = new Date();
    user.last_active = new Date();
    await user.save();
    
    const token = user.generateAuthToken();
    
    res.json(formatResponse(true, 'Login successful', {
      user: user.toObject(),
      token
    }));
  } catch (error) {
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
      return res.status(404).json(formatResponse(false, 'No user found with this email'));
    }
    
    const resetToken = user.generatePasswordResetToken();
    await user.save();
    
    const resetUrl = `${config.clientURL}/reset-password/${resetToken}`;
    
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
      return res.status(500).json(formatResponse(false, 'Failed to send reset email'));
    }
    
    res.json(formatResponse(true, 'Password reset email sent successfully'));
  } catch (error) {
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
    
    user.password = password;
    user.password_reset_token = undefined;
    user.password_reset_expires = undefined;
    await user.save();
    
    await sendEmail(
      user.email,
      'Password Reset Successful',
      `<h2>Password Reset Successful</h2>
      <p>Your password has been successfully reset.</p>
      <p>If you did not perform this action, please contact our support team immediately.</p>`
    );
    
    await createNotification(
      user._id,
      'Password Changed',
      'Your password has been successfully reset.',
      'system'
    );
    
    res.json(formatResponse(true, 'Password reset successful'));
  } catch (error) {
    handleError(res, error, 'Error resetting password');
  }
});

// ==================== ENHANCED PROFILE ENDPOINTS ====================

// Get profile with complete data
app.get('/api/profile', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const cacheKey = `profile_${userId}`;
    const cached = await cache.get(cacheKey);
    
    if (cached && config.nodeEnv === 'production') {
      return res.json(formatResponse(true, 'Profile retrieved successfully (cached)', cached));
    }
    
    const [user, earnings, referralStats] = await Promise.all([
      User.findById(userId).lean(),
      calculateDailyEarnings(userId),
      calculateReferralEarnings(userId)
    ]);
    
    const profileData = {
      user: {
        ...user,
        bank_details: user.bank_details || null,
        wallet_address: user.wallet_address || null,
        paypal_email: user.paypal_email || null
      },
      earnings,
      referral_stats: referralStats,
      dashboard_stats: {
        active_investment_value: earnings.total_daily_earnings * 100, // Estimate
        total_earnings: user.total_earnings || 0,
        daily_interest: earnings.total_daily_earnings,
        referral_earnings: user.referral_earnings || 0,
        available_balance: user.balance || 0,
        portfolio_value: (user.balance || 0) + (user.total_earnings || 0) + (user.referral_earnings || 0),
        kyc_status: user.kyc_status || 'not_submitted',
        kyc_verified: user.kyc_verified || false
      }
    };
    
    await cache.set(cacheKey, profileData, 60); // Cache for 1 minute
    
    res.json(formatResponse(true, 'Profile retrieved successfully', profileData));
  } catch (error) {
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
    
    // Clear cache
    await cache.delete(`profile_${userId}`);
    
    res.json(formatResponse(true, 'Profile updated successfully', { user }));
  } catch (error) {
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
    
    await createNotification(
      userId,
      'Bank Details Updated',
      'Your bank account details have been updated successfully. They will be verified by our team.',
      'info',
      '/profile'
    );
    
    // Notify admin
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
    
    // Clear cache
    await cache.delete(`profile_${userId}`);
    
    res.json(formatResponse(true, 'Bank details updated successfully', {
      bank_details: user.bank_details
    }));
  } catch (error) {
    handleError(res, error, 'Error updating bank details');
  }
});

// ==================== EARNINGS ENDPOINTS ====================

// Get daily earnings
app.get('/api/earnings/daily', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const earnings = await calculateDailyEarnings(userId);
    
    res.json(formatResponse(true, 'Daily earnings calculated successfully', earnings));
  } catch (error) {
    handleError(res, error, 'Error calculating daily earnings');
  }
});

// Get earnings history
app.get('/api/earnings/history', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { page = 1, limit = 20, type, start_date, end_date } = req.query;
    
    const query = { user: userId };
    if (type) query.type = type;
    if (start_date || end_date) {
      query.date = {};
      if (start_date) query.date.$gte = new Date(start_date);
      if (end_date) query.date.$lte = new Date(end_date);
    }
    
    const skip = (page - 1) * limit;
    const [earnings, total] = await Promise.all([
      Earnings.find(query)
        .populate('investment', 'plan')
        .sort({ date: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Earnings.countDocuments(query)
    ]);
    
    // Calculate summary
    const summary = {
      total_earnings: earnings.reduce((sum, e) => sum + e.amount, 0),
      daily_earnings: earnings.filter(e => e.type === 'daily_interest').reduce((sum, e) => sum + e.amount, 0),
      referral_earnings: earnings.filter(e => e.type === 'referral').reduce((sum, e) => sum + e.amount, 0),
      by_type: earnings.reduce((acc, e) => {
        acc[e.type] = (acc[e.type] || 0) + 1;
        return acc;
      }, {})
    };
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };
    
    res.json(formatResponse(true, 'Earnings history retrieved successfully', {
      earnings,
      summary,
      pagination
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching earnings history');
  }
});

// Get earnings summary
app.get('/api/earnings/summary', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const cacheKey = `earnings_summary_${userId}`;
    const cached = await cache.get(cacheKey);
    
    if (cached) {
      return res.json(formatResponse(true, 'Earnings summary retrieved successfully (cached)', cached));
    }
    
    const [dailyEarnings, referralStats, recentEarnings] = await Promise.all([
      calculateDailyEarnings(userId),
      calculateReferralEarnings(userId),
      Earnings.find({ user: userId })
        .sort({ date: -1 })
        .limit(10)
        .lean()
    ]);
    
    const user = await User.findById(userId);
    
    // Calculate monthly earnings
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    
    const monthlyEarnings = await Earnings.aggregate([
      {
        $match: {
          user: new mongoose.Types.ObjectId(userId),
          date: { $gte: thirtyDaysAgo },
          type: { $in: ['daily_interest', 'investment_completion'] }
        }
      },
      {
        $group: {
          _id: null,
          total: { $sum: '$amount' }
        }
      }
    ]);
    
    const summary = {
      total_earnings: user.total_earnings || 0,
      referral_earnings: user.referral_earnings || 0,
      daily_earnings: dailyEarnings.total_daily_earnings,
      monthly_earnings: monthlyEarnings[0]?.total || 0,
      referral_stats: referralStats,
      estimated_monthly_income: dailyEarnings.total_daily_earnings * 30,
      recent_earnings: recentEarnings
    };
    
    await cache.set(cacheKey, summary, 300); // Cache for 5 minutes
    
    res.json(formatResponse(true, 'Earnings summary retrieved successfully', summary));
  } catch (error) {
    handleError(res, error, 'Error fetching earnings summary');
  }
});

// ==================== ENHANCED INVESTMENT PLANS ENDPOINTS ====================

// Get all investment plans
app.get('/api/plans', async (req, res) => {
  try {
    const cacheKey = 'investment_plans';
    const cached = await cache.get(cacheKey);
    
    if (cached) {
      return res.json(formatResponse(true, 'Plans retrieved successfully (cached)', { plans: cached }));
    }
    
    const plans = await InvestmentPlan.find({ is_active: true })
      .sort({ display_order: 1, min_amount: 1 })
      .lean();
    
    const enhancedPlans = plans.map(plan => ({
      ...plan,
      roi_percentage: plan.total_interest,
      daily_roi: plan.daily_interest,
      monthly_roi: plan.daily_interest * 30,
      is_popular: plan.is_popular || false,
      features: plan.features || ['Secure Investment', 'Daily Payouts', '24/7 Support']
    }));
    
    await cache.set(cacheKey, enhancedPlans, 600); // Cache for 10 minutes
    
    res.json(formatResponse(true, 'Plans retrieved successfully', { plans: enhancedPlans }));
  } catch (error) {
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
    handleError(res, error, 'Error fetching investment plan');
  }
});

// ==================== ENHANCED INVESTMENT ENDPOINTS ====================

// Get user investments
app.get('/api/investments', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { status, page = 1, limit = 10 } = req.query;
    
    const cacheKey = `investments_${userId}_${status}_${page}_${limit}`;
    const cached = await cache.get(cacheKey);
    
    if (cached) {
      return res.json(formatResponse(true, 'Investments retrieved successfully (cached)', cached));
    }
    
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
    
    const response = {
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
    };
    
    await cache.set(cacheKey, response, 60); // Cache for 1 minute
    
    res.json(formatResponse(true, 'Investments retrieved successfully', response));
  } catch (error) {
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
    
    const plan = await InvestmentPlan.findById(plan_id);
    if (!plan) {
      return res.status(404).json(formatResponse(false, 'Investment plan not found'));
    }
    
    const investmentAmount = parseFloat(amount);
    
    if (investmentAmount < plan.min_amount) {
      return res.status(400).json(formatResponse(false,
        `Minimum investment for ${plan.name} is ₦${plan.min_amount.toLocaleString()}`));
    }
    
    if (plan.max_amount && investmentAmount > plan.max_amount) {
      return res.status(400).json(formatResponse(false,
        `Maximum investment for ${plan.name} is ₦${plan.max_amount.toLocaleString()}`));
    }
    
    if (investmentAmount > req.user.balance) {
      return res.status(400).json(formatResponse(false, 'Insufficient balance for this investment'));
    }
    
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
    
    const expectedEarnings = (investmentAmount * plan.total_interest) / 100;
    const dailyEarnings = (investmentAmount * plan.daily_interest) / 100;
    const endDate = new Date(Date.now() + plan.duration * 24 * 60 * 60 * 1000);
    
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
    
    // Handle referral commission
    const user = await User.findById(userId);
    if (user.referred_by) {
      await createReferralCommission(
        user.referred_by,
        userId,
        investmentAmount,
        investment._id
      );
    }
    
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
    
    // Clear cache
    await cache.clearPattern(`investments_${userId}`);
    await cache.delete(`profile_${userId}`);
    await cache.delete(`earnings_summary_${userId}`);
    
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
    handleError(res, error, 'Error creating investment');
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
    
    if (investment.user.toString() !== req.user._id.toString() && req.user.role === 'user') {
      return res.status(403).json(formatResponse(false, 'Access denied'));
    }
    
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
      can_withdraw: investment.status === 'active' && (investment.earned_so_far || 0) > 0
    };
    
    res.json(formatResponse(true, 'Investment retrieved successfully', {
      investment: enhancedInvestment
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching investment');
  }
});

// ==================== ENHANCED DEPOSIT ENDPOINTS ====================

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
    
    const enhancedDeposits = deposits.map(dep => ({
      ...dep,
      has_proof: !!dep.payment_proof_url,
      proof_url: dep.payment_proof_url || null,
      formatted_amount: `₦${dep.amount.toLocaleString()}`,
      status_color: dep.status === 'approved' ? 'success' :
                    dep.status === 'pending' ? 'warning' :
                    dep.status === 'rejected' ? 'error' : 'default'
    }));
    
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
        total_deposits: totalDeposits,
        pending_deposits: pendingDeposits,
        total_count: total,
        approved_count: enhancedDeposits.filter(d => d.status === 'approved').length,
        pending_count: enhancedDeposits.filter(d => d.status === 'pending').length
      },
      pagination
    }));
  } catch (error) {
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
    
    await createNotification(
      userId,
      'Deposit Request Submitted',
      `Your deposit request of ₦${depositAmount.toLocaleString()} has been submitted and is pending approval.`,
      'deposit',
      '/deposits',
      { amount: depositAmount, payment_method, has_proof: !!proofUrl }
    );
    
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
    handleError(res, error, 'Error creating deposit');
  }
});

// ==================== ENHANCED WITHDRAWAL ENDPOINTS ====================

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
    
    if (withdrawalAmount < config.minWithdrawal) {
      return res.status(400).json(formatResponse(false,
        `Minimum withdrawal is ₦${config.minWithdrawal.toLocaleString()}`));
    }
    
    if (withdrawalAmount > req.user.balance) {
      return res.status(400).json(formatResponse(false, 'Insufficient balance for withdrawal'));
    }
    
    const platformFee = withdrawalAmount * (config.platformFeePercent / 100);
    const netAmount = withdrawalAmount - platformFee;
    
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
    
    await User.findByIdAndUpdate(userId, {
      $inc: { balance: -withdrawalAmount }
    });
    
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
        estimated_processing_time: '24-48 hours'
      },
      message: 'Your withdrawal is pending approval. Processing time is 24-48 hours.'
    }));
  } catch (error) {
    handleError(res, error, 'Error creating withdrawal');
  }
});

// ==================== ENHANCED REFERRAL ENDPOINTS ====================

// Get referral stats
app.get('/api/referrals/stats', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const referralStats = await calculateReferralEarnings(userId);
    
    const user = await User.findById(userId);
    
    const referrals = await Referral.find({ referrer: userId })
      .populate('referred_user', 'full_name email createdAt balance total_earnings')
      .sort({ createdAt: -1 })
      .limit(10)
      .lean();
    
    const response = {
      ...referralStats,
      referral_code: user.referral_code,
      referral_link: `${config.clientURL}/register?ref=${user.referral_code}`,
      recent_referrals: referrals
    };
    
    res.json(formatResponse(true, 'Referral stats retrieved successfully', response));
  } catch (error) {
    handleError(res, error, 'Error fetching referral stats');
  }
});

// Get referral details
app.get('/api/referrals/details', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { page = 1, limit = 20 } = req.query;
    
    const skip = (page - 1) * limit;
    const [referrals, total] = await Promise.all([
      Referral.find({ referrer: userId })
        .populate('referred_user', 'full_name email phone createdAt balance total_earnings total_investments last_investment_date')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Referral.countDocuments({ referrer: userId })
    ]);
    
    const enhancedReferrals = referrals.map(ref => ({
      ...ref,
      referred_user: ref.referred_user ? {
        ...ref.referred_user,
        total_invested: await Investment.aggregate([
          { $match: { user: ref.referred_user._id } },
          { $group: { _id: null, total: { $sum: '$amount' } } }
        ]).then(result => result[0]?.total || 0)
      } : null,
      potential_commission: ref.referred_user?.total_investments ? 
        (ref.referred_user.total_investments * config.referralCommissionPercent / 100) : 0
    }));
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };
    
    res.json(formatResponse(true, 'Referral details retrieved successfully', {
      referrals: enhancedReferrals,
      pagination
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching referral details');
  }
});

// ==================== ENHANCED TRANSACTION ENDPOINTS ====================

// Get user transactions
app.get('/api/transactions', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { type, status, start_date, end_date, page = 1, limit = 20 } = req.query;
    
    const query = { user: userId };
    if (type) query.type = type;
    if (status) query.status = status;
    if (start_date || end_date) {
      query.createdAt = {};
      if (start_date) query.createdAt.$gte = new Date(start_date);
      if (end_date) query.createdAt.$lte = new Date(end_date);
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
    
    const summary = {
      total_income: transactions.filter(t => t.amount > 0).reduce((sum, t) => sum + t.amount, 0),
      total_expenses: transactions.filter(t => t.amount < 0).reduce((sum, t) => sum + Math.abs(t.amount), 0),
      net_flow: transactions.reduce((sum, t) => sum + t.amount, 0),
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
    handleError(res, error, 'Error fetching transactions');
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
  body('id_type').isIn(['national_id', 'passport', 'driver_license', 'voters_card']),
  body('id_number').notEmpty().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }
    
    const { id_type, id_number } = req.body;
    const userId = req.user._id;
    const files = req.files;
    
    if (!files || !files.id_front || !files.selfie_with_id) {
      return res.status(400).json(formatResponse(false, 'ID front and selfie with ID are required'));
    }
    
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
    
    let kycSubmission = await KYCSubmission.findOne({ user: userId });
    
    const kycData = {
      user: userId,
      id_type,
      id_number,
      id_front_url: idFrontUrl,
      id_back_url: idBackUrl,
      selfie_with_id_url: selfieWithIdUrl,
      address_proof_url: addressProofUrl,
      status: 'pending',
      metadata: {
        submitted_at: new Date(),
        uploads: uploadResults,
        ip_address: req.ip
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
    
    await User.findByIdAndUpdate(userId, {
      kyc_status: 'pending',
      kyc_submitted_at: new Date()
    });
    
    await createNotification(
      userId,
      'KYC Submitted',
      'Your KYC documents have been submitted successfully. Verification typically takes 24-48 hours.',
      'kyc',
      '/kyc',
      { id_type, has_address_proof: !!addressProofUrl }
    );
    
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
      kyc: kycSubmission,
      uploads: uploadResults,
      message: 'Your KYC documents have been submitted for verification. You will be notified once verified.'
    }));
  } catch (error) {
    handleError(res, error, 'Error submitting KYC');
  }
});

// Get KYC status
app.get('/api/kyc/status', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const kycSubmission = await KYCSubmission.findOne({ user: userId });
    const user = await User.findById(userId);
    
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
        id_front_url: kycSubmission.id_front_url,
        id_back_url: kycSubmission.id_back_url,
        selfie_with_id_url: kycSubmission.selfie_with_id_url,
        address_proof_url: kycSubmission.address_proof_url
      } : null
    };
    
    res.json(formatResponse(true, 'KYC status retrieved', responseData));
  } catch (error) {
    handleError(res, error, 'Error fetching KYC status');
  }
});

// ==================== ENHANCED SUPPORT ENDPOINTS ====================

// Submit support ticket
app.post('/api/support', auth, upload.array('attachments', 5), [
  body('subject').notEmpty().trim().isLength({ min: 5, max: 200 }),
  body('message').notEmpty().trim().isLength({ min: 10, max: 5000 }),
  body('category').optional().isIn(['general', 'technical', 'investment', 'withdrawal', 'deposit', 'kyc', 'account', 'other']),
  body('priority').optional().isIn(['low', 'medium', 'high', 'urgent'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }
    
    const { subject, message, category = 'general', priority = 'medium' } = req.body;
    const userId = req.user._id;
    const files = req.files || [];
    
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
        console.error('Error uploading attachment:', uploadError);
      }
    }
    
    const ticketId = `TKT${Date.now()}${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    
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
    
    await createNotification(
      userId,
      'Support Ticket Created',
      `Your support ticket #${ticketId} has been created successfully. We will respond within 24 hours.`,
      'info',
      `/support/ticket/${ticketId}`,
      { ticket_id: ticketId, category, priority, attachments_count: attachments.length }
    );
    
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
        ...supportTicket.toObject(),
        ticket_id: ticketId,
        created_at: supportTicket.createdAt,
        attachments_count: attachments.length
      },
      message: 'Your support ticket has been submitted. You will receive a response within 24 hours.'
    }));
  } catch (error) {
    handleError(res, error, 'Error creating support ticket');
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
    
    const enhancedTickets = tickets.map(ticket => {
      const statusColors = {
        'open': 'warning',
        'in_progress': 'info',
        'resolved': 'success',
        'closed': 'default'
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
        resolved_tickets: enhancedTickets.filter(t => t.status === 'resolved').length
      },
      pagination
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching support tickets');
  }
});

// ==================== ENHANCED UPLOAD ENDPOINT ====================

// File upload
app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json(formatResponse(false, 'No file uploaded'));
    }
    
    const userId = req.user._id;
    const folder = req.body.folder || 'general';
    const purpose = req.body.purpose || 'general';
    
    const uploadResult = await handleFileUpload(req.file, folder, userId);
    
    await createTransaction(
      userId,
      'system',
      0,
      `File uploaded: ${uploadResult.originalName}`,
      'completed',
      {
        upload_type: 'file',
        folder,
        purpose,
        file_size: uploadResult.size,
        mime_type: uploadResult.mimeType
      }
    );
    
    res.json(formatResponse(true, 'File uploaded successfully', {
      fileUrl: uploadResult.url,
      fileName: uploadResult.filename,
      originalName: uploadResult.originalName,
      size: uploadResult.size,
      mimeType: uploadResult.mimeType,
      folder,
      purpose,
      uploadedAt: uploadResult.uploadedAt,
      downloadUrl: `${config.serverURL}/download/${uploadResult.filename}`
    }));
  } catch (error) {
    handleError(res, error, 'Error uploading file');
  }
});

// Multiple file upload
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
        console.error('Error uploading file:', uploadError);
      }
    }
    
    res.json(formatResponse(true, 'Files uploaded successfully', {
      files: uploadResults,
      total: uploadResults.length,
      successful: uploadResults.length,
      failed: req.files.length - uploadResults.length
    }));
  } catch (error) {
    handleError(res, error, 'Error uploading files');
  }
});

// ==================== ENHANCED ADMIN ENDPOINTS ====================

// Advanced Admin Dashboard
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
  try {
    const cacheKey = 'admin_dashboard';
    const cached = await cache.get(cacheKey);
    
    if (cached && config.nodeEnv === 'production') {
      return res.json(formatResponse(true, 'Admin dashboard stats retrieved successfully (cached)', cached));
    }
    
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
      recentUsers
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
        .lean()
    ]);
    
    const totalEarnings = earningsResult[0]?.total || 0;
    const platformEarnings = platformFeesResult[0]?.total || 0;
    const referralEarnings = referralEarningsResult[0]?.total || 0;
    const totalRevenue = platformEarnings;
    
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
        platform_revenue: totalRevenue,
        referral_earnings: referralEarnings
      },
      pending_actions: {
        pending_investments: pendingInvestments,
        pending_deposits: pendingDeposits,
        pending_withdrawals: pendingWithdrawals,
        pending_kyc: pendingKYC,
        total_pending: pendingInvestments + pendingDeposits + pendingWithdrawals + pendingKYC
      },
      recent_activity: {
        transactions: recentTransactions,
        users: recentUsers
      }
    };
    
    await cache.set(cacheKey, stats, 60); // Cache for 1 minute
    
    res.json(formatResponse(true, 'Admin dashboard stats retrieved successfully', {
      stats,
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
    handleError(res, error, 'Error fetching admin dashboard stats');
  }
});

// Get all users
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
      end_date
    } = req.query;
    
    const query = {};
    if (status === 'active') query.is_active = true;
    if (status === 'inactive') query.is_active = false;
    if (role) query.role = role;
    if (kyc_status) query.kyc_status = kyc_status;
    
    if (min_balance || max_balance) {
      query.balance = {};
      if (min_balance) query.balance.$gte = parseFloat(min_balance);
      if (max_balance) query.balance.$lte = parseFloat(max_balance);
    }
    
    if (start_date || end_date) {
      query.createdAt = {};
      if (start_date) query.createdAt.$gte = new Date(start_date);
      if (end_date) query.createdAt.$lte = new Date(end_date);
    }
    
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
    
    const enhancedUsers = await Promise.all(users.map(async (user) => {
      const [investments, deposits, withdrawals] = await Promise.all([
        Investment.countDocuments({ user: user._id }),
        Deposit.countDocuments({ user: user._id, status: 'approved' }),
        Withdrawal.countDocuments({ user: user._id, status: 'paid' })
      ]);
      
      return {
        ...user,
        stats: {
          total_investments: investments,
          total_deposits: deposits,
          total_withdrawals: withdrawals,
          total_referrals: user.referral_count || 0,
          portfolio_value: user.balance + (user.total_earnings || 0) + (user.referral_earnings || 0)
        }
      };
    }));
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };
    
    await createAdminAudit(
      req.user._id,
      'VIEW_ALL_USERS',
      'system',
      null,
      {
        page,
        limit,
        filters: { status, role, kyc_status, search, min_balance, max_balance, start_date, end_date }
      },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'Users retrieved successfully', {
      users: enhancedUsers,
      pagination,
      summary: {
        total_users: total,
        active_users: enhancedUsers.filter(u => u.is_active).length,
        verified_users: enhancedUsers.filter(u => u.kyc_verified).length,
        total_balance: enhancedUsers.reduce((sum, u) => sum + u.balance, 0)
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching users');
  }
});

// Get user details
app.get('/api/admin/users/:id', adminAuth, async (req, res) => {
  try {
    const userId = req.params.id;
    
    const [user, investments, deposits, withdrawals, transactions, kyc, referrals] = await Promise.all([
      User.findById(userId)
        .select('-password -two_factor_secret -verification_token -password_reset_token')
        .populate('referred_by', 'full_name email referral_code')
        .lean(),
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
      KYCSubmission.findOne({ user: userId }).lean(),
      Referral.find({ referrer: userId })
        .populate('referred_user', 'full_name email createdAt balance')
        .sort({ createdAt: -1 })
        .lean()
    ]);
    
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }
    
    const activeInvestments = investments.filter(inv => inv.status === 'active');
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    const totalEarned = investments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0);
    
    let dailyInterest = 0;
    activeInvestments.forEach(inv => {
      if (inv.plan && inv.plan.daily_interest) {
        dailyInterest += (inv.amount * inv.plan.daily_interest / 100);
      }
    });
    
    const referralEarnings = referrals.reduce((sum, ref) => sum + (ref.earnings || 0), 0);
    
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
      statistics: {
        total_investments: investments.length,
        active_investments: activeInvestments.length,
        total_deposits: deposits.filter(d => d.status === 'approved').length,
        total_withdrawals: withdrawals.filter(w => w.status === 'paid').length,
        total_transactions: transactions.length,
        total_referrals: referrals.length,
        total_invested: investments.reduce((sum, inv) => sum + inv.amount, 0),
        total_earned: totalEarned,
        daily_interest: dailyInterest,
        referral_earnings: referralEarnings,
        portfolio_value: user.balance + totalEarned + referralEarnings
      },
      investments: investments.slice(0, 10),
      deposits: deposits.slice(0, 10),
      withdrawals: withdrawals.slice(0, 10),
      transactions: transactions.slice(0, 20),
      referrals: referrals,
      kyc_submission: kyc
    }));
  } catch (error) {
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
      total_amount: pendingInvestments.reduce((sum, inv) => sum + inv.amount, 0)
    }));
  } catch (error) {
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
    
    investment.status = 'active';
    investment.approved_at = new Date();
    investment.approved_by = adminId;
    investment.payment_verified = true;
    investment.proof_verified_by = adminId;
    investment.proof_verified_at = new Date();
    investment.remarks = remarks;
    
    await investment.save();
    
    await InvestmentPlan.findByIdAndUpdate(investment.plan._id, {
      $inc: {
        investment_count: 1,
        total_invested: investment.amount
      }
    });
    
    await User.findByIdAndUpdate(investment.user._id, {
      $inc: { total_investments: 1 },
      last_investment_date: new Date()
    });
    
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
    
    // Clear cache
    await cache.clearPattern(`investments_${investment.user._id}`);
    await cache.delete(`profile_${investment.user._id}`);
    await cache.delete(`earnings_summary_${investment.user._id}`);
    
    res.json(formatResponse(true, 'Investment approved successfully', {
      investment: {
        ...investment.toObject(),
        approved_by_admin: req.user.full_name,
        proof_verified: true
      },
      message: 'Investment approved and user notified'
    }));
  } catch (error) {
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
    
    investment.status = 'rejected';
    investment.approved_by = adminId;
    investment.remarks = remarks;
    investment.proof_verified_by = adminId;
    investment.proof_verified_at = new Date();
    
    await investment.save();
    
    await User.findByIdAndUpdate(investment.user._id, {
      $inc: { balance: investment.amount }
    });
    
    await createTransaction(
      investment.user._id,
      'refund',
      investment.amount,
      `Refund for rejected investment`,
      'completed',
      { investment_id: investment._id, remarks: remarks }
    );
    
    await createNotification(
      investment.user._id,
      'Investment Rejected',
      `Your investment of ₦${investment.amount.toLocaleString()} has been rejected. Reason: ${remarks}`,
      'error',
      '/investments',
      { amount: investment.amount, remarks: remarks }
    );
    
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
    
    // Clear cache
    await cache.clearPattern(`investments_${investment.user._id}`);
    await cache.delete(`profile_${investment.user._id}`);
    
    res.json(formatResponse(true, 'Investment rejected successfully', {
      investment
    }));
  } catch (error) {
    handleError(res, error, 'Error rejecting investment');
  }
});

// Get pending deposits
app.get('/api/admin/pending-deposits', adminAuth, async (req, res) => {
  try {
    const pendingDeposits = await Deposit.find({ status: 'pending' })
      .populate('user', 'full_name email phone balance')
      .sort({ createdAt: -1 })
      .lean();
    
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
      total_amount: pendingDeposits.reduce((sum, dep) => sum + dep.amount, 0)
    }));
  } catch (error) {
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
    
    deposit.status = 'approved';
    deposit.approved_at = new Date();
    deposit.approved_by = adminId;
    deposit.proof_verified_by = adminId;
    deposit.proof_verified_at = new Date();
    deposit.admin_notes = remarks;
    
    await deposit.save();
    
    await User.findByIdAndUpdate(deposit.user._id, {
      $inc: {
        balance: deposit.amount,
        total_deposits: deposit.amount
      },
      last_deposit_date: new Date()
    });
    
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
    
    // Clear cache
    await cache.delete(`profile_${deposit.user._id}`);
    
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
    
    deposit.status = 'rejected';
    deposit.approved_by = adminId;
    deposit.proof_verified_by = adminId;
    deposit.proof_verified_at = new Date();
    deposit.admin_notes = remarks;
    
    await deposit.save();
    
    await createNotification(
      deposit.user._id,
      'Deposit Rejected',
      `Your deposit of ₦${deposit.amount.toLocaleString()} has been rejected. Reason: ${remarks}`,
      'error',
      '/deposits',
      { amount: deposit.amount, remarks: remarks }
    );
    
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
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'Deposit rejected successfully', {
      deposit
    }));
  } catch (error) {
    handleError(res, error, 'Error rejecting deposit');
  }
});

// Get pending withdrawals
app.get('/api/admin/pending-withdrawals', adminAuth, async (req, res) => {
  try {
    const pendingWithdrawals = await Withdrawal.find({ status: 'pending' })
      .populate('user', 'full_name email phone balance')
      .sort({ createdAt: -1 })
      .lean();
    
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
      days_pending: Math.ceil((new Date() - new Date(wdl.createdAt)) / (1000 * 60 * 60 * 24))
    }));
    
    const summary = {
      total_amount: pendingWithdrawals.reduce((sum, wdl) => sum + wdl.amount, 0),
      total_net_amount: pendingWithdrawals.reduce((sum, wdl) => sum + wdl.net_amount, 0),
      total_fees: pendingWithdrawals.reduce((sum, wdl) => sum + wdl.platform_fee, 0)
    };
    
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
    
    await Transaction.findOneAndUpdate(
      { related_withdrawal: withdrawalId },
      {
        status: 'completed',
        payment_proof_url: payment_proof_url,
        admin_notes: remarks
      }
    );
    
    await User.findByIdAndUpdate(withdrawal.user._id, {
      $inc: { total_withdrawals: withdrawal.amount },
      last_withdrawal_date: new Date()
    );
    
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
    
    // Clear cache
    await cache.delete(`profile_${withdrawal.user._id}`);
    
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
    
    withdrawal.status = 'rejected';
    withdrawal.approved_by = adminId;
    withdrawal.proof_verified_by = adminId;
    withdrawal.proof_verified_at = new Date();
    withdrawal.admin_notes = remarks;
    
    await withdrawal.save();
    
    await User.findByIdAndUpdate(withdrawal.user._id, {
      $inc: { balance: withdrawal.amount }
    });
    
    await Transaction.findOneAndUpdate(
      { related_withdrawal: withdrawalId },
      {
        status: 'cancelled',
        admin_notes: remarks
      }
    );
    
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
    
    await createNotification(
      withdrawal.user._id,
      'Withdrawal Rejected',
      `Your withdrawal of ₦${withdrawal.amount.toLocaleString()} has been rejected. Reason: ${remarks}`,
      'error',
      '/withdrawals',
      { amount: withdrawal.amount, remarks: remarks }
    );
    
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
      req.headers['user-agent']
    );
    
    // Clear cache
    await cache.delete(`profile_${withdrawal.user._id}`);
    
    res.json(formatResponse(true, 'Withdrawal rejected successfully', {
      withdrawal
    }));
  } catch (error) {
    handleError(res, error, 'Error rejecting withdrawal');
  }
});

// Get pending KYC
app.get('/api/admin/pending-kyc', adminAuth, async (req, res) => {
  try {
    const pendingKYC = await KYCSubmission.find({ status: 'pending' })
      .populate('user', 'full_name email phone')
      .sort({ createdAt: -1 })
      .lean();
    
    const enhancedKYC = pendingKYC.map(kyc => ({
      ...kyc,
      user_name: kyc.user?.full_name,
      user_email: kyc.user?.email,
      user_phone: kyc.user?.phone,
      has_id_front: !!kyc.id_front_url,
      has_id_back: !!kyc.id_back_url,
      has_selfie: !!kyc.selfie_with_id_url,
      has_address_proof: !!kyc.address_proof_url,
      days_pending: Math.ceil((new Date() - new Date(kyc.createdAt)) / (1000 * 60 * 60 * 24))
    }));
    
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
      count: pendingKYC.length
    }));
  } catch (error) {
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
    
    kyc.status = 'approved';
    kyc.reviewed_by = adminId;
    kyc.reviewed_at = new Date();
    kyc.notes = remarks;
    
    await kyc.save();
    
    await User.findByIdAndUpdate(kyc.user._id, {
      kyc_status: 'verified',
      kyc_verified: true,
      kyc_verified_at: new Date()
    });
    
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
      req.headers['user-agent']
    );
    
    // Clear cache
    await cache.delete(`profile_${kyc.user._id}`);
    
    res.json(formatResponse(true, 'KYC approved successfully', {
      kyc: {
        ...kyc.toObject(),
        reviewed_by_admin: req.user.full_name,
        user_verified: true
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error approving KYC');
  }
});

// Reject KYC
app.post('/api/admin/kyc/:id/reject', adminAuth, [
  body('rejection_reason').notEmpty(),
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
    
    kyc.status = 'rejected';
    kyc.reviewed_by = adminId;
    kyc.reviewed_at = new Date();
    kyc.rejection_reason = rejection_reason;
    kyc.notes = remarks;
    
    await kyc.save();
    
    await User.findByIdAndUpdate(kyc.user._id, {
      kyc_status: 'rejected'
    });
    
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
      req.headers['user-agent']
    );
    
    // Clear cache
    await cache.delete(`profile_${kyc.user._id}`);
    
    res.json(formatResponse(true, 'KYC rejected successfully', {
      kyc
    }));
  } catch (error) {
    handleError(res, error, 'Error rejecting KYC');
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
    
    await createNotification(
      userId,
      'Account Role Updated',
      `Your account role has been updated to ${role}.`,
      'system',
      null,
      { new_role: role, updated_by: req.user.full_name }
    );
    
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
    
    // Clear cache
    await cache.delete(`profile_${userId}`);
    
    res.json(formatResponse(true, 'User role updated successfully', { user }));
  } catch (error) {
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
    
    // Clear cache
    await cache.delete(`profile_${userId}`);
    
    res.json(formatResponse(true,
      is_active ? 'User activated successfully' : 'User deactivated successfully',
      { user }
    ));
  } catch (error) {
    handleError(res, error, 'Error updating user status');
  }
});

// Update user balance
app.put('/api/admin/users/:id/balance', adminAuth, [
  body('amount').isFloat(),
  body('type').isIn(['add', 'subtract', 'set']),
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
    
    user.balance = newBalance;
    await user.save();
    
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
      req.headers['user-agent']
    );
    
    // Clear cache
    await cache.delete(`profile_${userId}`);
    
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
    handleError(res, error, 'Error updating user balance');
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
        'earning': 'green'
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
        unread: unreadCount
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching notifications');
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
    await notification.save();
    
    res.json(formatResponse(true, 'Notification marked as read', {
      notification_id: notificationId,
      marked_read_at: new Date()
    }));
  } catch (error) {
    handleError(res, error, 'Error marking notification as read');
  }
});

// Mark all notifications as read
app.post('/api/notifications/read-all', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const result = await Notification.updateMany(
      { user: userId, is_read: false },
      { $set: { is_read: true } }
    );
    
    res.json(formatResponse(true, 'All notifications marked as read', {
      marked_count: result.modifiedCount,
      marked_at: new Date()
    }));
  } catch (error) {
    handleError(res, error, 'Error marking all notifications as read');
  }
});

// ==================== ENHANCED CRON JOBS ====================

// Calculate daily earnings
cron.schedule('0 0 * * *', async () => {
  try {
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
        
        investment.earned_so_far += dailyEarning;
        investment.last_earning_date = new Date();
        
        investment.earnings_history.push({
          date: new Date(),
          amount: dailyEarning,
          type: 'daily_interest',
          description: `Daily interest from ${investment.plan.name}`
        });
        
        await investment.save();
        
        if (!earningsByUser.has(investment.user._id.toString())) {
          earningsByUser.set(investment.user._id.toString(), {
            user: investment.user,
            total: 0,
            investments: []
          });
        }
        
        const userEarnings = earningsByUser.get(investment.user._id.toString());
        userEarnings.total += dailyEarning;
        userEarnings.investments.push({
          investment_id: investment._id,
          plan: investment.plan.name,
          amount: dailyEarning
        });
        
        totalEarnings += dailyEarning;
        processedCount++;
        
      } catch (investmentError) {
        console.error(`Error processing investment ${investment._id}:`, investmentError);
      }
    }
    
    for (const [userId, userData] of earningsByUser.entries()) {
      try {
        await User.findByIdAndUpdate(userId, {
          $inc: {
            balance: userData.total,
            total_earnings: userData.total,
            total_daily_earnings: userData.total
          }
        });
        
        await createEarningsRecord(
          userId,
          userData.total,
          'daily_interest',
          `Daily earnings from ${userData.investments.length} active investments`
        );
        
        await createTransaction(
          userId,
          'earning',
          userData.total,
          `Daily earnings from ${userData.investments.length} active investments`,
          'completed',
          {
            earnings_date: new Date().toISOString().split('T')[0],
            investment_count: userData.investments.length
          }
        );
        
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
        
        // Clear user cache
        await cache.delete(`profile_${userId}`);
        await cache.delete(`earnings_summary_${userId}`);
        await cache.delete(`daily_earnings_${userId}`);
        
      } catch (userError) {
        console.error(`Error updating user ${userId}:`, userError);
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
        
        // Clear cache
        await cache.clearPattern(`investments_${investment.user._id}`);
        
      } catch (completeError) {
        console.error(`Error completing investment ${investment._id}:`, completeError);
      }
    }
    
    console.log(`✅ Daily earnings calculated. Processed: ${processedCount}, Total: ₦${totalEarnings.toLocaleString()}, Users: ${earningsByUser.size}`);
    
  } catch (error) {
    console.error('❌ Error calculating daily earnings:', error);
  }
});

// Auto-renew investments
cron.schedule('0 1 * * *', async () => {
  try {
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
        
        const user = await User.findById(userId);
        if (!user || user.balance < investment.amount) {
          console.log(`User ${userId} has insufficient balance for auto-renew`);
          skippedCount++;
          continue;
        }
        
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
        
        await User.findByIdAndUpdate(userId, {
          $inc: { balance: -investment.amount }
        });
        
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
        
        investment.auto_renewed = true;
        if (!investment.metadata) investment.metadata = {};
        investment.metadata.renewed_to = newInvestment._id;
        investment.metadata.renewed_at = new Date();
        await investment.save();
        
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
        console.log(`Auto-renewed investment ${investment._id} for user ${userId}`);
        
        // Clear cache
        await cache.clearPattern(`investments_${userId}`);
        await cache.delete(`profile_${userId}`);
        await cache.delete(`earnings_summary_${userId}`);
        
      } catch (error) {
        console.error(`Error auto-renewing investment ${investment._id}:`, error);
        skippedCount++;
      }
    }
    
    console.log(`✅ Auto-renew completed. Renewed: ${renewedCount}, Skipped: ${skippedCount}`);
    
  } catch (error) {
    console.error('❌ Error processing auto-renew:', error);
  }
});

// Cleanup expired data
cron.schedule('0 2 * * *', async () => {
  try {
    console.log('🔄 Cleaning up expired data...');
    
    const now = new Date();
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
    
    const deletedNotifications = await Notification.deleteMany({
      createdAt: { $lt: ninetyDaysAgo },
      is_read: true
    });
    
    const cleanedUsers = await User.updateMany({
      password_reset_expires: { $lt: now }
    }, {
      $unset: {
        password_reset_token: 1,
        password_reset_expires: 1
      }
    });
    
    console.log(`✅ Cleanup completed. Removed: ${deletedNotifications.deletedCount} notifications`);
    
  } catch (error) {
    console.error('❌ Error during cleanup:', error);
  }
});

// Weekly report
cron.schedule('0 9 * * 1', async () => {
  try {
    console.log('📊 Generating weekly report...');
    
    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
    
    const [
      newUsers,
      newInvestments,
      totalDeposits,
      totalWithdrawals,
      activeUsers
    ] = await Promise.all([
      User.countDocuments({ createdAt: { $gte: oneWeekAgo } }),
      Investment.countDocuments({ createdAt: { $gte: oneWeekAgo } }),
      Deposit.aggregate([
        {
          $match: {
            status: 'approved',
            createdAt: { $gte: oneWeekAgo }
          }
        },
        {
          $group: {
            _id: null,
            total: { $sum: '$amount' },
            count: { $sum: 1 }
          }
        }
      ]),
      Withdrawal.aggregate([
        {
          $match: {
            status: 'paid',
            createdAt: { $gte: oneWeekAgo }
          }
        },
        {
          $group: {
            _id: null,
            total: { $sum: '$amount' },
            count: { $sum: 1 }
          }
        }
      ]),
      User.countDocuments({ last_login: { $gte: oneWeekAgo } })
    ]);
    
    const deposits = totalDeposits[0] || { total: 0, count: 0 };
    const withdrawals = totalWithdrawals[0] || { total: 0, count: 0 };
    
    const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } });
    for (const admin of admins) {
      await sendEmail(
        admin.email,
        'Raw Wealthy - Weekly Report',
        `<h2>Weekly Platform Report</h2>
        <p>Here's your weekly performance report:</p>
        <ul>
          <li><strong>New Users:</strong> ${newUsers}</li>
          <li><strong>Active Users (last week):</strong> ${activeUsers}</li>
          <li><strong>New Investments:</strong> ${newInvestments}</li>
          <li><strong>Total Deposits:</strong> ₦${deposits.total.toLocaleString()} (${deposits.count} transactions)</li>
          <li><strong>Total Withdrawals:</strong> ₦${withdrawals.total.toLocaleString()} (${withdrawals.count} transactions)</li>
          <li><strong>Net Flow:</strong> ₦${(deposits.total - withdrawals.total).toLocaleString()}</li>
        </ul>
        <p>Report Period: ${oneWeekAgo.toLocaleDateString()} - ${new Date().toLocaleDateString()}</p>`
      );
    }
    
    console.log(`✅ Weekly report sent to ${admins.length} admins`);
    
  } catch (error) {
    console.error('❌ Error generating weekly report:', error);
  }
});

// ==================== ENHANCED ERROR HANDLING ====================

// 404 handler
app.use((req, res) => {
  res.status(404).json(formatResponse(false, 'Endpoint not found', {
    requested_url: req.originalUrl,
    method: req.method,
    available_endpoints: [
      '/api/auth/*',
      '/api/profile',
      '/api/earnings/*',
      '/api/investments/*',
      '/api/deposits/*',
      '/api/withdrawals/*',
      '/api/plans',
      '/api/kyc/*',
      '/api/support/*',
      '/api/referrals/*',
      '/api/admin/*',
      '/api/upload',
      '/health'
    ]
  }));
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error:', err);
  
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
  
  console.error('Error details:', errorLog);
  
  if (err instanceof multer.MulterError) {
    return res.status(400).json(formatResponse(false, `File upload error: ${err.message}`));
  }
  
  if (err.name === 'MongoError' || err.name === 'MongooseError') {
    return res.status(500).json(formatResponse(false, 'Database error occurred. Please try again later.'));
  }
  
  if (err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT') {
    return res.status(503).json(formatResponse(false, 'Service temporarily unavailable. Please try again later.'));
  }
  
  res.status(500).json(formatResponse(false, 'Internal server error', {
    error_id: crypto.randomBytes(8).toString('hex'),
    timestamp: new Date().toISOString()
  }));
});

// ==================== SERVER INITIALIZATION ====================

const startServer = async () => {
  try {
    await initializeDatabase();
    
    const server = app.listen(config.port, '0.0.0.0', () => {
      console.log(`
🎯 RAW WEALTHY BACKEND v38.0 - ULTIMATE PRODUCTION EDITION
=========================================================

🌐 Server running on port ${config.port}
🚀 Environment: ${config.nodeEnv}
📊 Health Check: /health
🔗 API Base: /api
💾 Database: MongoDB Connected
🛡️ Security: Enhanced Protection
📧 Email: ${config.emailEnabled ? '✅ Enabled' : '❌ Disabled'}
📁 Uploads: ${config.uploadDir}
🌐 Server URL: ${config.serverURL}
⚡ Cache: ${redisClient ? '✅ Redis' : '⚠️ Memory'}

✅ ENHANCED FEATURES:
✅ Advanced Earnings Calculation System
✅ Real-time Daily Interest Calculation
✅ Enhanced Referral Commission Tracking
✅ Complete User Dashboard Analytics
✅ Investment Auto-Renewal System
✅ KYC Verification with Image Upload
✅ Support Ticket Management
✅ Admin Dashboard with Real-time Stats
✅ Redis Caching for Performance
✅ File Upload System with CDN Support
✅ Email Notifications System
✅ Automated Cron Jobs
✅ Weekly Report Generation
✅ Advanced Error Handling
✅ Rate Limiting & Security Headers
✅ Graceful Shutdown

🚀 FULLY INTEGRATED & PRODUCTION READY!
🔐 SECURITY ENHANCED WITH AUDIT LOGGING
📈 COMPLETE ANALYTICS & REPORTING
📱 RESPONSIVE ADMIN INTERFACE SUPPORT
💸 EARNINGS & REFERRAL SYSTEM ACTIVE
`);
    });
    
    const gracefulShutdown = async (signal) => {
      console.log(`\n${signal} received, shutting down gracefully...`);
      server.close(async () => {
        console.log('HTTP server closed');
        try {
          await mongoose.connection.close();
          console.log('Database connection closed');
        } catch (dbError) {
          console.error('Error closing database:', dbError);
        }
        console.log('Process terminated gracefully');
        process.exit(0);
      });
      
      setTimeout(() => {
        console.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
      }, 10000);
    };
    
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    process.on('SIGUSR2', () => gracefulShutdown('SIGUSR2'));
    
    process.on('uncaughtException', (error) => {
      console.error('Uncaught Exception:', error);
      gracefulShutdown('uncaughtException');
    });
    
    process.on('unhandledRejection', (reason, promise) => {
      console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    });
    
  } catch (error) {
    console.error('❌ Server initialization failed:', error);
    process.exit(1);
  }
};

startServer();

export default app;
