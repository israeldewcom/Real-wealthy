// server.js - RAW WEALTHY BACKEND v38.0 - ULTIMATE PRODUCTION EDITION - FIXED VERSION

// COMPLETE DEBUGGING FIXES WITH ADVANCED USER EARNINGS SYSTEM

// FULLY INTEGRATED WITH FRONTEND v37.0 - 100% COMPATIBLE

// ENHANCED ADMIN DASHBOARD WITH DETAILED USER VIEWS

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

// Enhanced environment configuration
dotenv.config({ path: path.join(__dirname, '.env.production') });

// ==================== ENVIRONMENT VALIDATION ====================

const requiredEnvVars = [
  'MONGODB_URI',
  'JWT_SECRET',
  'NODE_ENV'
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
  
  // Generate JWT secret if missing
  if (!process.env.JWT_SECRET) {
    process.env.JWT_SECRET = crypto.randomBytes(64).toString('hex');
    console.log('✅ Generated JWT_SECRET automatically');
  }
  
  // Set default MongoDB URI
  if (!process.env.MONGODB_URI) {
    process.env.MONGODB_URI = 'mongodb://localhost:27017/rawwealthy';
    console.log('✅ Set default MONGODB_URI');
  }
}

// Set default values
const PORT = process.env.PORT || 10000;
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:3000';
const SERVER_URL = process.env.SERVER_URL || `http://localhost:${PORT}`;

console.log('✅ PORT:', PORT);
console.log('✅ CLIENT_URL:', CLIENT_URL);
console.log('✅ SERVER_URL:', SERVER_URL);
console.log('============================\n');

// ==================== DYNAMIC CONFIGURATION ====================

const config = {
  // Server
  port: PORT,
  nodeEnv: process.env.NODE_ENV || 'production',
  serverURL: SERVER_URL,
  
  // Database
  mongoURI: process.env.MONGODB_URI,
  
  // Security
  jwtSecret: process.env.JWT_SECRET,
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '30d',
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 12,
  
  // Client
  clientURL: CLIENT_URL,
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
  }
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

// Security middleware
app.use(xss());
app.use(hpp());
app.use(mongoSanitize());
app.use(compression());

// Enhanced logging
if (config.nodeEnv === 'production') {
  app.use(morgan('combined'));
} else {
  app.use(morgan('dev'));
}

// ==================== DYNAMIC CORS CONFIGURATION ====================

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

// ==================== ENHANCED FILE UPLOAD CONFIGURATION ====================

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

// Enhanced file upload handler with absolute URL
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
    console.error('File upload error:', error);
    throw new Error(`File upload failed: ${error.message}`);
  }
};

// Create uploads directory if it doesn't exist
if (!fs.existsSync(config.uploadDir)) {
  fs.mkdirSync(config.uploadDir, { recursive: true });
  console.log('📁 Created uploads directory');
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

// ==================== DYNAMIC EMAIL CONFIGURATION ====================

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

// ==================== DATABASE MODELS - ENHANCED ====================

// Enhanced User Model with complete fields
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
  // Enhanced fields for dashboard
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
  },
  toObject: {
    virtuals: true
  }
});

// Indexes
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ referral_code: 1 }, { unique: true, sparse: true });
userSchema.index({ is_active: 1, role: 1, kyc_status: 1 });

// Virtual for total portfolio value
userSchema.virtual('portfolio_value').get(function() {
  return (this.balance || 0) + (this.total_earnings || 0) + (this.referral_earnings || 0);
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
  try {
    const isMatch = await bcrypt.compare(candidatePassword, this.password);
    return isMatch;
  } catch (error) {
    console.error('Password comparison error:', error);
    return false;
  }
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

// Investment Plan Model - Enhanced
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

// Investment Model - Enhanced with image tracking
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
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
  timestamps: true
});

investmentSchema.index({ user: 1, status: 1 });
investmentSchema.index({ end_date: 1 });

const Investment = mongoose.model('Investment', investmentSchema);

// Deposit Model - Enhanced
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
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
  timestamps: true
});

depositSchema.index({ user: 1, status: 1 });
depositSchema.index({ reference: 1 }, { unique: true, sparse: true });

const Deposit = mongoose.model('Deposit', depositSchema);

// Withdrawal Model - Enhanced
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
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
  timestamps: true
});

withdrawalSchema.index({ user: 1, status: 1 });
withdrawalSchema.index({ reference: 1 }, { unique: true, sparse: true });

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// Transaction Model - Enhanced for complete history
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
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, {
  timestamps: true
});

transactionSchema.index({ user: 1, createdAt: -1 });
transactionSchema.index({ type: 1, status: 1 });
transactionSchema.index({ reference: 1 });

const Transaction = mongoose.model('Transaction', transactionSchema);

// KYC Submission Model - Enhanced
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

// Support Ticket Model - Enhanced
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

// Referral Model - Enhanced
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

// Notification Model - Enhanced
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

// ==================== UTILITY FUNCTIONS - CRITICAL FIXES ====================

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
    console.error('Error creating notification:', error);
    return null;
  }
};

// ==================== CRITICAL FIX: ENHANCED createTransaction FUNCTION ====================

// FIXED VERSION - Updates all user fields correctly
const createTransaction = async (userId, type, amount, description, status = 'completed', metadata = {}, proofUrl = null) => {
  try {
    console.log(`📊 Creating transaction: ${type} for user ${userId}, amount: ${amount}`);
    
    // Get user with current values
    const user = await User.findById(userId);
    if (!user) {
      console.error(`❌ User ${userId} not found for transaction`);
      return null;
    }
    
    const balanceBefore = user.balance || 0;
    const totalEarningsBefore = user.total_earnings || 0;
    const referralEarningsBefore = user.referral_earnings || 0;
    const totalDepositsBefore = user.total_deposits || 0;
    const totalWithdrawalsBefore = user.total_withdrawals || 0;
    const totalInvestmentsBefore = user.total_investments || 0;
    
    let balanceAfter = balanceBefore;
    let totalEarningsAfter = totalEarningsBefore;
    let referralEarningsAfter = referralEarningsBefore;
    let totalDepositsAfter = totalDepositsBefore;
    let totalWithdrawalsAfter = totalWithdrawalsBefore;
    let totalInvestmentsAfter = totalInvestmentsBefore;
    
    let updateFields = {};
    
    // Calculate changes based on transaction type
    switch (type) {
      case 'earning':
        if (status === 'completed') {
          balanceAfter += amount;
          totalEarningsAfter += amount;
          updateFields = {
            $inc: {
              balance: amount,
              total_earnings: amount
            }
          };
          console.log(`💰 Added ${amount} to total_earnings`);
        }
        break;
        
      case 'referral':
        if (status === 'completed') {
          balanceAfter += amount;
          referralEarningsAfter += amount;
          updateFields = {
            $inc: {
              balance: amount,
              referral_earnings: amount
            }
          };
          console.log(`🎁 Added ${amount} to referral_earnings`);
        }
        break;
        
      case 'investment':
        if (status === 'completed') {
          balanceAfter -= Math.abs(amount);
          totalInvestmentsAfter += Math.abs(amount);
          updateFields = {
            $inc: {
              balance: -Math.abs(amount),
              total_investments: Math.abs(amount)
            },
            last_investment_date: new Date()
          };
          console.log(`📈 Added ${Math.abs(amount)} to total_investments`);
        }
        break;
        
      case 'deposit':
        if (status === 'completed') {
          balanceAfter += amount;
          totalDepositsAfter += amount;
          updateFields = {
            $inc: {
              balance: amount,
              total_deposits: amount
            },
            last_deposit_date: new Date()
          };
          console.log(`💵 Added ${amount} to total_deposits`);
        }
        break;
        
      case 'withdrawal':
        if (status === 'completed') {
          balanceAfter -= Math.abs(amount);
          totalWithdrawalsAfter += Math.abs(amount);
          updateFields = {
            $inc: {
              balance: -Math.abs(amount),
              total_withdrawals: Math.abs(amount)
            },
            last_withdrawal_date: new Date()
          };
          console.log(`💸 Added ${Math.abs(amount)} to total_withdrawals`);
        }
        break;
        
      case 'bonus':
        if (status === 'completed') {
          balanceAfter += amount;
          updateFields = {
            $inc: { balance: amount }
          };
          console.log(`🎉 Added ${amount} as bonus`);
        }
        break;
        
      default:
        console.log(`⚠️ Unknown transaction type: ${type}`);
    }
    
    // Apply updates to user if there are changes
    if (Object.keys(updateFields).length > 0) {
      console.log(`🔄 Updating user ${userId} with:`, updateFields);
      await User.findByIdAndUpdate(userId, updateFields, { new: true });
    }
    
    // Create transaction record
    const transaction = new Transaction({
      user: userId,
      type,
      amount,
      description,
      status,
      reference: generateReference('TXN'),
      balance_before: balanceBefore,
      balance_after: balanceAfter,
      metadata: {
        ...metadata,
        processedAt: new Date(),
        user_stats_before: {
          balance: balanceBefore,
          total_earnings: totalEarningsBefore,
          referral_earnings: referralEarningsBefore,
          total_deposits: totalDepositsBefore,
          total_withdrawals: totalWithdrawalsBefore,
          total_investments: totalInvestmentsBefore
        },
        user_stats_after: {
          balance: balanceAfter,
          total_earnings: totalEarningsAfter,
          referral_earnings: referralEarningsAfter,
          total_deposits: totalDepositsAfter,
          total_withdrawals: totalWithdrawalsAfter,
          total_investments: totalInvestmentsAfter
        }
      }
    });
    
    await transaction.save();
    console.log(`✅ Transaction created: ${transaction._id}, type: ${type}`);
    
    return transaction;
  } catch (error) {
    console.error('❌ Error in createTransaction:', error);
    return null;
  }
};

// ==================== NEW FUNCTION: PROCESS REFERRAL BONUS ====================

const processReferralBonus = async (userId, investmentAmount) => {
  try {
    console.log(`🎁 Processing referral bonus for user: ${userId}, amount: ${investmentAmount}`);
    
    const user = await User.findById(userId);
    if (!user || !user.referred_by) {
      console.log('⚠️ User has no referrer or user not found');
      return;
    }
    
    const referrer = await User.findById(user.referred_by);
    if (!referrer) {
      console.log('⚠️ Referrer not found');
      return;
    }
    
    const commissionPercent = config.referralCommissionPercent;
    const bonusAmount = (investmentAmount * commissionPercent) / 100;
    
    console.log(`🎁 Referral bonus: ${bonusAmount} for referrer: ${referrer.email}`);
    
    // Credit referrer's account
    await createTransaction(
      referrer._id,
      'referral',
      bonusAmount,
      `Referral bonus from ${user.full_name}'s investment`,
      'completed',
      {
        referred_user_id: userId,
        referred_user_name: user.full_name,
        investment_amount: investmentAmount,
        commission_rate: commissionPercent
      }
    );
    
    // Update referral record
    await Referral.findOneAndUpdate(
      { referrer: referrer._id, referred_user: userId },
      {
        $inc: { earnings: bonusAmount },
        status: 'active',
        investment_amount: investmentAmount,
        earnings_paid: true,
        paid_at: new Date()
      },
      { upsert: true, new: true }
    );
    
    // Create notification for referrer
    await createNotification(
      referrer._id,
      'Referral Bonus Earned!',
      `You earned ₦${bonusAmount.toLocaleString()} referral bonus from ${user.full_name}'s investment!`,
      'referral',
      '/referrals'
    );
    
    console.log(`✅ Referral bonus processed: ₦${bonusAmount}`);
  } catch (error) {
    console.error('❌ Error processing referral bonus:', error);
  }
};

// Admin audit log function
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
    
    // Connect to MongoDB
    await mongoose.connect(config.mongoURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      retryWrites: true
    });
    
    console.log('✅ MongoDB connected successfully');
    
    // Create admin user if it doesn't exist
    await createAdminUser();
    
    // Create default investment plans if they don't exist
    await createDefaultInvestmentPlans();
    
    console.log('✅ Database initialization completed');
  } catch (error) {
    console.error('❌ Database initialization error:', error.message);
    throw error;
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
    for (const planData of defaultPlans) {
      const existingPlan = await InvestmentPlan.findOne({ name: planData.name });
      if (!existingPlan) {
        await InvestmentPlan.create(planData);
      }
    }
    console.log('✅ Default investment plans created/verified');
  } catch (error) {
    console.error('Error creating default investment plans:', error);
  }
};

// ==================== ENHANCED ADMIN CREATION WITH DEBUGGING ====================

const createAdminUser = async () => {
  try {
    console.log('\n🚀 =========== ADMIN USER SETUP STARTING ===========');
    
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@rawwealthy.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123456';
    
    console.log(`📧 Admin Email: ${adminEmail}`);
    console.log(`🔑 Admin Password: ${adminPassword ? '***' : 'NOT SET'}`);
    
    // Check if admin already exists
    let existingAdmin = await User.findOne({ email: adminEmail });
    
    if (existingAdmin) {
      console.log('✅ Admin already exists in database');
      
      // Test password for debugging
      const testAdmin = await User.findOne({ email: adminEmail }).select('+password');
      if (testAdmin && testAdmin.password) {
        const testMatch = await testAdmin.comparePassword(adminPassword);
        if (!testMatch) {
          testAdmin.password = adminPassword;
          await testAdmin.save();
          console.log('✅ Admin password updated successfully');
        }
      }
      
      // Ensure admin has correct role
      if (existingAdmin.role !== 'super_admin') {
        existingAdmin.role = 'super_admin';
        await existingAdmin.save();
        console.log('✅ Admin role updated to super_admin');
      }
      
      console.log('✅ Admin setup completed (existing user)');
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
      email_notifications: true,
      total_earnings: 500000,
      referral_earnings: 200000,
      total_deposits: 2000000,
      total_withdrawals: 500000,
      total_investments: 1500000
    };
    
    const admin = new User(adminData);
    await admin.save();
    
    console.log('✅ Admin created successfully');
    console.log(`👤 Admin ID: ${admin._id}`);
    console.log(`💰 Admin Balance: ₦${admin.balance.toLocaleString()}`);
    console.log(`💰 Admin Total Earnings: ₦${admin.total_earnings.toLocaleString()}`);
    
    // Create welcome notification
    await createNotification(
      admin._id,
      'Welcome Admin!',
      'Your admin account has been successfully created. You can now access the admin dashboard.',
      'success',
      '/admin/dashboard'
    );
    
    console.log('\n🎉 =========== ADMIN SETUP COMPLETED ===========');
    console.log(`📧 Login Email: ${adminEmail}`);
    console.log(`🔑 Login Password: ${adminPassword}`);
    console.log(`👉 Login at: ${config.clientURL}/admin/login`);
    
  } catch (error) {
    console.error('\n❌ =========== ADMIN CREATION ERROR ===========');
    console.error('Error:', error.message);
    
    // Try alternative approach
    try {
      const adminEmail = process.env.ADMIN_EMAIL || 'admin@rawwealthy.com';
      const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123456';
      
      // Hash password manually
      const hashedPassword = await bcrypt.hash(adminPassword, config.bcryptRounds);
      
      await User.updateOne(
        { email: adminEmail },
        {
          $set: {
            full_name: 'Raw Wealthy Admin',
            password: hashedPassword,
            role: 'super_admin',
            is_active: true,
            is_verified: true,
            kyc_verified: true,
            total_earnings: 500000,
            referral_earnings: 200000,
            total_deposits: 2000000,
            total_withdrawals: 500000,
            total_investments: 1500000
          },
          $setOnInsert: {
            phone: '09161806424',
            balance: 1000000
          }
        },
        { upsert: true }
      );
      
      console.log('✅ Admin created/updated via alternative method');
    } catch (retryError) {
      console.error('❌ Alternative method also failed:', retryError.message);
    }
  }
};

// ==================== DEBUG ENDPOINTS FOR ADMIN ====================

// Admin debug endpoint (only in development)
if (config.nodeEnv !== 'production') {
  app.get('/api/debug/admin-status', async (req, res) => {
    try {
      const adminEmail = process.env.ADMIN_EMAIL || 'admin@rawwealthy.com';
      const admin = await User.findOne({ email: adminEmail }).select('+password');
      
      if (!admin) {
        return res.json({
          success: false,
          message: 'Admin not found in database',
          email: adminEmail,
          exists: false
        });
      }
      
      // Test password
      const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123456';
      const passwordMatch = await admin.comparePassword(adminPassword);
      
      res.json({
        success: true,
        message: 'Admin debug information',
        admin: {
          id: admin._id,
          email: admin.email,
          role: admin.role,
          is_active: admin.is_active,
          is_verified: admin.is_verified,
          kyc_verified: admin.kyc_verified,
          balance: admin.balance,
          total_earnings: admin.total_earnings,
          referral_earnings: admin.referral_earnings,
          portfolio_value: admin.portfolio_value,
          created_at: admin.createdAt,
          password_hash_exists: !!admin.password,
          password_hash_length: admin.password ? admin.password.length : 0,
          password_match_test: passwordMatch
        },
        environment: {
          node_env: config.nodeEnv,
          bcrypt_rounds: config.bcryptRounds,
          admin_email_set: !!process.env.ADMIN_EMAIL,
          admin_password_set: !!process.env.ADMIN_PASSWORD
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Debug error',
        error: error.message
      });
    }
  });
  
  // Force admin creation endpoint
  app.post('/api/debug/create-admin', async (req, res) => {
    try {
      const { email = 'admin@rawwealthy.com', password = 'Admin123456' } = req.body;
      
      console.log('🔄 Manual admin creation requested');
      console.log(`📧 Email: ${email}`);
      console.log(`🔑 Password: ${password}`);
      
      // Delete existing admin
      await User.deleteOne({ email: email });
      console.log('✅ Cleared existing admin');
      
      // Create new admin
      const admin = new User({
        full_name: 'Raw Wealthy Admin',
        email: email,
        phone: '09161806424',
        password: password,
        role: 'super_admin',
        balance: 1000000,
        total_earnings: 500000,
        referral_earnings: 200000,
        total_deposits: 2000000,
        total_withdrawals: 500000,
        total_investments: 1500000,
        kyc_verified: true,
        kyc_status: 'verified',
        is_active: true,
        is_verified: true
      });
      
      await admin.save();
      console.log('✅ Admin created manually');
      
      // Verify
      const savedAdmin = await User.findOne({ email: email }).select('+password');
      const passwordMatch = await savedAdmin.comparePassword(password);
      
      res.json({
        success: true,
        message: 'Admin created manually',
        admin: {
          id: savedAdmin._id,
          email: savedAdmin.email,
          role: savedAdmin.role,
          balance: savedAdmin.balance,
          total_earnings: savedAdmin.total_earnings,
          referral_earnings: savedAdmin.referral_earnings,
          portfolio_value: savedAdmin.portfolio_value,
          password_match: passwordMatch
        }
      });
    } catch (error) {
      console.error('Manual admin creation error:', error);
      res.status(500).json({
        success: false,
        message: 'Manual admin creation failed',
        error: error.message
      });
    }
  });
  
  // List all admins
  app.get('/api/debug/admins', async (req, res) => {
    try {
      const admins = await User.find({
        $or: [{ role: 'admin' }, { role: 'super_admin' }]
      }).select('-password');
      
      res.json({
        success: true,
        count: admins.length,
        admins: admins.map(admin => ({
          id: admin._id,
          email: admin.email,
          role: admin.role,
          balance: admin.balance,
          total_earnings: admin.total_earnings,
          referral_earnings: admin.referral_earnings,
          portfolio_value: admin.portfolio_value,
          is_active: admin.is_active,
          created_at: admin.createdAt
        }))
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Error fetching admins',
        error: error.message
      });
    }
  });
  
  // Debug profile endpoint
  app.get('/api/debug/profile-test', auth, async (req, res) => {
    try {
      const userId = req.user._id;
      
      // Get user with all fields
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json(formatResponse(false, 'User not found'));
      }
      
      // Manually calculate portfolio value
      const portfolioValue = (user.balance || 0) + (user.total_earnings || 0) + (user.referral_earnings || 0);
      
      res.json({
        success: true,
        message: 'Debug profile data',
        data: {
          user: {
            id: user._id,
            email: user.email,
            balance: user.balance || 0,
            total_earnings: user.total_earnings || 0,
            referral_earnings: user.referral_earnings || 0,
            total_deposits: user.total_deposits || 0,
            total_withdrawals: user.total_withdrawals || 0,
            total_investments: user.total_investments || 0,
            portfolio_value: portfolioValue
          },
          computed_stats: {
            balance: user.balance || 0,
            total_earnings: user.total_earnings || 0,
            referral_earnings: user.referral_earnings || 0,
            total_portfolio: portfolioValue
          }
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Debug error',
        error: error.message
      });
    }
  });
}

// ==================== HEALTH CHECK ====================

app.get('/health', async (req, res) => {
  const health = {
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
      users: await User.countDocuments({}),
      investments: await Investment.countDocuments({}),
      deposits: await Deposit.countDocuments({}),
      withdrawals: await Withdrawal.countDocuments({})
    }
  };
  
  res.json(health);
});

// ==================== ROOT ENDPOINT ====================

app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 Raw Wealthy Backend API v38.0 - Ultimate Edition - FIXED VERSION',
    version: '38.0.0',
    timestamp: new Date().toISOString(),
    status: 'Operational',
    environment: config.nodeEnv,
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
      health: '/health'
    },
    fixes_applied: {
      total_earnings_fix: true,
      referral_earnings_fix: true,
      createTransaction_fix: true,
      referral_bonus_system: true,
      dashboard_data_fix: true
    }
  });
});

// ==================== ENHANCED AUTH ENDPOINTS WITH DEBUGGING ====================

// Register
app.post('/api/auth/register', [
  body('full_name').notEmpty().trim().isLength({ min: 2, max: 100 }),
  body('email').isEmail().normalizeEmail(),
  body('phone').notEmpty().trim(),
  body('password').isLength({ min: 6 }),
  body('referral_code').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', {
        errors: errors.array().map(err => ({ field: err.param, message: err.msg }))
      }));
    }
    
    const { full_name, email, phone, password, referral_code } = req.body;
    
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
      referred_by: referredBy ? referredBy._id : null,
      total_earnings: 0,
      referral_earnings: 0,
      total_deposits: 0,
      total_withdrawals: 0,
      total_investments: 0
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
        status: 'active'
      });
      
      await referral.save();
      
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
    
    // Create welcome notification
    await createNotification(
      user._id,
      'Welcome to Raw Wealthy!',
      'Your account has been successfully created. Start your investment journey today.',
      'success',
      '/dashboard'
    );
    
    // Create welcome bonus transaction - THIS UPDATES USER FIELDS CORRECTLY
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
           <li>Total Earnings: ₦${user.total_earnings.toLocaleString()}</li>
           <li>Referral Earnings: ₦${user.referral_earnings.toLocaleString()}</li>
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
    handleError(res, error, 'Registration failed');
  }
});

// Login with enhanced debugging
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
      return res.status(400).json(formatResponse(false, 'Invalid credentials'));
    }
    
    // Check if account is active
    if (!user.is_active) {
      return res.status(401).json(formatResponse(false, 'Account is deactivated. Please contact support.'));
    }
    
    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json(formatResponse(false, 'Invalid credentials'));
    }
    
    // Update last login
    user.last_login = new Date();
    user.last_active = new Date();
    await user.save();
    
    // Generate token
    const token = user.generateAuthToken();
    
    res.json(formatResponse(true, 'Login successful', {
      user: user.toObject(),
      token
    }));
  } catch (error) {
    handleError(res, error, 'Login failed');
  }
});

// ==================== CRITICAL FIX: ENHANCED PROFILE ENDPOINT ====================

// Get current user profile - FIXED VERSION with proper field handling
app.get('/api/profile', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Get user WITHOUT lean() to preserve methods
    const user = await User.findById(userId)
      .select('-password -two_factor_secret -verification_token -password_reset_token');
    
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }
    
    // Ensure all fields have values (not undefined)
    const userData = user.toObject();
    
    // Manually ensure all financial fields exist
    userData.balance = user.balance || 0;
    userData.total_earnings = user.total_earnings || 0;
    userData.referral_earnings = user.referral_earnings || 0;
    userData.total_deposits = user.total_deposits || 0;
    userData.total_withdrawals = user.total_withdrawals || 0;
    userData.total_investments = user.total_investments || 0;
    
    // Manually calculate portfolio value
    const portfolioValue = userData.balance + userData.total_earnings + userData.referral_earnings;
    userData.portfolio_value = portfolioValue;
    
    // Get additional stats
    const [investments, deposits, withdrawals, referrals] = await Promise.all([
      Investment.countDocuments({ user: userId }),
      Deposit.countDocuments({ user: userId, status: 'approved' }),
      Withdrawal.countDocuments({ user: userId, status: 'paid' }),
      Referral.countDocuments({ referrer: userId })
    ]);
    
    const activeInvestments = await Investment.find({
      user: userId,
      status: 'active'
    }).populate('plan', 'name daily_interest');
    
    let dailyInterest = 0;
    let activeInvestmentValue = 0;
    
    activeInvestments.forEach(inv => {
      activeInvestmentValue += inv.amount || 0;
      if (inv.plan && inv.plan.daily_interest) {
        dailyInterest += (inv.amount * inv.plan.daily_interest) / 100;
      }
    });
    
    const profileData = {
      user: userData,
      stats: {
        total_investments: investments,
        active_investments: activeInvestments.length,
        total_deposits: deposits,
        total_withdrawals: withdrawals,
        referral_count: referrals,
        daily_interest: dailyInterest,
        active_investment_value: activeInvestmentValue,
        portfolio_value: portfolioValue
      }
    };
    
    // Debug log
    console.log(`📊 Profile data for ${user.email}:`, {
      balance: userData.balance,
      total_earnings: userData.total_earnings,
      referral_earnings: userData.referral_earnings,
      portfolio_value: portfolioValue,
      active_investment_value: activeInvestmentValue
    });
    
    res.json(formatResponse(true, 'Profile retrieved successfully', profileData));
  } catch (error) {
    console.error('Error fetching profile:', error);
    handleError(res, error, 'Error fetching profile');
  }
});

// Update user profile
app.put('/api/profile', auth, [
  body('full_name').optional().trim().isLength({ min: 2, max: 100 }),
  body('phone').optional().trim(),
  body('country').optional().trim(),
  body('risk_tolerance').optional().isIn(['low', 'medium', 'high']),
  body('investment_strategy').optional().isIn(['conservative', 'balanced', 'aggressive']),
  body('email_notifications').optional().isBoolean(),
  body('sms_notifications').optional().isBoolean()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }
    
    const updates = {};
    const allowedFields = ['full_name', 'phone', 'country', 'risk_tolerance', 'investment_strategy', 'email_notifications', 'sms_notifications'];
    
    allowedFields.forEach(field => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });
    
    const user = await User.findByIdAndUpdate(
      req.user._id,
      updates,
      { new: true }
    ).select('-password');
    
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }
    
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
    
    const { bank_name, account_name, account_number, bank_code } = req.body;
    
    const user = await User.findByIdAndUpdate(
      req.user._id,
      {
        bank_details: {
          bank_name,
          account_name,
          account_number,
          bank_code: bank_code || '',
          verified: false,
          last_updated: new Date()
        }
      },
      { new: true }
    ).select('-password');
    
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }
    
    // Create notification
    await createNotification(
      req.user._id,
      'Bank Details Updated',
      'Your bank details have been updated successfully.',
      'info',
      '/profile'
    );
    
    res.json(formatResponse(true, 'Bank details updated successfully', {
      user,
      bank_details: user.bank_details
    }));
  } catch (error) {
    handleError(res, error, 'Error updating bank details');
  }
});

// Forgot password
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
      return res.status(404).json(formatResponse(false, 'User not found'));
    }
    
    // Generate reset token
    const resetToken = user.generatePasswordResetToken();
    await user.save();
    
    // Send email with reset link
    const resetUrl = `${config.clientURL}/reset-password/${resetToken}`;
    
    if (config.emailEnabled) {
      await sendEmail(
        user.email,
        'Password Reset Request',
        `<h2>Password Reset Request</h2>
         <p>You requested a password reset. Click the link below to reset your password:</p>
         <p><a href="${resetUrl}">${resetUrl}</a></p>
         <p>This link will expire in 10 minutes.</p>
         <p>If you didn't request this, please ignore this email.</p>`
      );
    }
    
    res.json(formatResponse(true, 'Password reset email sent', {
      resetToken: config.emailEnabled ? 'Email sent' : resetToken
    }));
  } catch (error) {
    handleError(res, error, 'Error processing forgot password');
  }
});

// Reset password
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
    
    // Create notification
    await createNotification(
      user._id,
      'Password Updated',
      'Your password has been updated successfully.',
      'success',
      '/profile'
    );
    
    res.json(formatResponse(true, 'Password reset successful'));
  } catch (error) {
    handleError(res, error, 'Error resetting password');
  }
});

// ==================== INVESTMENT PLANS ENDPOINTS ====================

// Get all investment plans
app.get('/api/plans', async (req, res) => {
  try {
    const plans = await InvestmentPlan.find({ is_active: true })
      .sort({ display_order: 1, min_amount: 1 })
      .lean();
    
    res.json(formatResponse(true, 'Plans retrieved successfully', { plans }));
  } catch (error) {
    handleError(res, error, 'Error fetching investment plans');
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
    
    // Calculate stats
    const activeInvestments = investments.filter(inv => inv.status === 'active');
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    const totalEarnings = investments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0);
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };
    
    res.json(formatResponse(true, 'Investments retrieved successfully', {
      investments,
      stats: {
        total_active_value: totalActiveValue,
        total_earnings: totalEarnings,
        active_count: activeInvestments.length,
        total_count: total
      },
      pagination
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching investments');
  }
});

// Create investment - UPDATED WITH REFERRAL BONUS
app.post('/api/investments', auth, upload.single('payment_proof'), [
  body('plan_id').notEmpty(),
  body('amount').isFloat({ min: config.minInvestment }),
  body('auto_renew').optional().isBoolean()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }
    
    const { plan_id, amount, auto_renew = false } = req.body;
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
    if (req.file) {
      try {
        const uploadResult = await handleFileUpload(req.file, 'investment-proofs', userId);
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
      daily_earnings: dailyEarnings,
      auto_renew,
      payment_proof_url: proofUrl,
      payment_verified: !proofUrl
    });
    
    await investment.save();
    
    // Use createTransaction to update user fields correctly
    await createTransaction(
      userId,
      'investment',
      -investmentAmount,
      `Investment in ${plan.name} plan`,
      'completed',
      {
        investment_id: investment._id,
        plan_name: plan.name,
        plan_duration: plan.duration,
        daily_interest: plan.daily_interest
      }
    );
    
    // Update plan statistics
    await InvestmentPlan.findByIdAndUpdate(plan_id, {
      $inc: {
        investment_count: 1,
        total_invested: investmentAmount
      }
    });
    
    // 🔥 CRITICAL FIX: Process referral bonus if user has a referrer
    if (req.user.referred_by) {
      await processReferralBonus(userId, investmentAmount);
    }
    
    // Create notification
    await createNotification(
      userId,
      'Investment Created',
      `Your investment of ₦${investmentAmount.toLocaleString()} in ${plan.name} has been created successfully.${proofUrl ? ' Awaiting admin approval.' : ''}`,
      'investment',
      '/investments'
    );
    
    res.status(201).json(formatResponse(true, 'Investment created successfully!', {
      investment: {
        ...investment.toObject(),
        plan_name: plan.name,
        expected_daily_earnings: dailyEarnings,
        expected_total_earnings: expectedEarnings,
        end_date: endDate
      }
    }));
  } catch (error) {
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
    
    // Calculate stats
    const totalDeposits = deposits.filter(d => d.status === 'approved').reduce((sum, d) => sum + d.amount, 0);
    const pendingDeposits = deposits.filter(d => d.status === 'pending').reduce((sum, d) => sum + d.amount, 0);
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };
    
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
    handleError(res, error, 'Error fetching deposits');
  }
});

// Create deposit
app.post('/api/deposits', auth, upload.single('payment_proof'), [
  body('amount').isFloat({ min: config.minDeposit }),
  body('payment_method').isIn(['bank_transfer', 'crypto', 'paypal', 'card'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }
    
    const { amount, payment_method } = req.body;
    const userId = req.user._id;
    const depositAmount = parseFloat(amount);
    
    // Handle file upload
    let proofUrl = null;
    if (req.file) {
      try {
        const uploadResult = await handleFileUpload(req.file, 'deposit-proofs', userId);
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
      reference: generateReference('DEP')
    });
    
    await deposit.save();
    
    // Create notification
    await createNotification(
      userId,
      'Deposit Request Submitted',
      `Your deposit request of ₦${depositAmount.toLocaleString()} has been submitted and is pending approval.`,
      'deposit',
      '/deposits'
    );
    
    res.status(201).json(formatResponse(true, 'Deposit request submitted successfully!', {
      deposit: {
        ...deposit.toObject(),
        formatted_amount: `₦${depositAmount.toLocaleString()}`,
        requires_approval: true
      }
    }));
  } catch (error) {
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
    
    // Calculate stats
    const totalWithdrawals = withdrawals.filter(w => w.status === 'paid').reduce((sum, w) => sum + w.amount, 0);
    const pendingWithdrawals = withdrawals.filter(w => w.status === 'pending').reduce((sum, w) => sum + w.amount, 0);
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };
    
    res.json(formatResponse(true, 'Withdrawals retrieved successfully', {
      withdrawals,
      stats: {
        total_withdrawals: totalWithdrawals,
        pending_withdrawals: pendingWithdrawals,
        total_count: total,
        paid_count: withdrawals.filter(w => w.status === 'paid').length,
        pending_count: withdrawals.filter(w => w.status === 'pending').length
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
  body('payment_method').isIn(['bank_transfer', 'crypto', 'paypal'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }
    
    const { amount, payment_method } = req.body;
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
    if (payment_method === 'bank_transfer') {
      if (!req.user.bank_details || !req.user.bank_details.account_number) {
        return res.status(400).json(formatResponse(false, 'Please update your bank details in profile settings'));
      }
    } else if (payment_method === 'crypto') {
      if (!req.user.wallet_address) {
        return res.status(400).json(formatResponse(false, 'Please set your wallet address in profile settings'));
      }
    } else if (payment_method === 'paypal') {
      if (!req.user.paypal_email) {
        return res.status(400).json(formatResponse(false, 'Please set your PayPal email in profile settings'));
      }
    }
    
    // Create withdrawal
    const withdrawal = new Withdrawal({
      user: userId,
      amount: withdrawalAmount,
      payment_method,
      platform_fee: platformFee,
      net_amount: netAmount,
      status: 'pending',
      reference: generateReference('WDL')
    });
    
    await withdrawal.save();
    
    // Use createTransaction to update user balance correctly
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
      '/withdrawals'
    );
    
    res.status(201).json(formatResponse(true, 'Withdrawal request submitted successfully!', {
      withdrawal: {
        ...withdrawal.toObject(),
        formatted_amount: `₦${withdrawalAmount.toLocaleString()}`,
        formatted_net_amount: `₦${netAmount.toLocaleString()}`,
        formatted_fee: `₦${platformFee.toLocaleString()}`,
        requires_approval: true
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error creating withdrawal');
  }
});

// ==================== TRANSACTION ENDPOINTS ====================

// Get user transactions
app.get('/api/transactions', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { type, status, start_date, end_date, page = 1, limit = 20 } = req.query;
    
    const query = { user: userId };
    
    // Apply filters
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
    
    // Calculate summary
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
      transactions,
      summary,
      pagination
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching transactions');
  }
});

// ==================== KYC ENDPOINTS ====================

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
    
    // Check required files
    if (!files || !files.id_front || !files.selfie_with_id) {
      return res.status(400).json(formatResponse(false, 'ID front and selfie with ID are required'));
    }
    
    // Upload files
    let idFrontUrl, idBackUrl, selfieWithIdUrl, addressProofUrl;
    
    try {
      idFrontUrl = (await handleFileUpload(files.id_front[0], 'kyc-documents', userId)).url;
      selfieWithIdUrl = (await handleFileUpload(files.selfie_with_id[0], 'kyc-documents', userId)).url;
      
      if (files.id_back && files.id_back[0]) {
        idBackUrl = (await handleFileUpload(files.id_back[0], 'kyc-documents', userId)).url;
      }
      
      if (files.address_proof && files.address_proof[0]) {
        addressProofUrl = (await handleFileUpload(files.address_proof[0], 'kyc-documents', userId)).url;
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
      status: 'pending'
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
    
    // Create notification
    await createNotification(
      userId,
      'KYC Submitted',
      'Your KYC documents have been submitted successfully. Verification typically takes 24-48 hours.',
      'kyc',
      '/kyc'
    );
    
    res.status(201).json(formatResponse(true, 'KYC submitted successfully!', {
      kyc: kycSubmission
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

// ==================== SUPPORT ENDPOINTS ====================

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
    
    // Handle file uploads
    const attachments = [];
    
    for (const file of files) {
      try {
        const uploadResult = await handleFileUpload(file, 'support-attachments', userId);
        attachments.push({
          filename: uploadResult.filename,
          url: uploadResult.url,
          size: uploadResult.size,
          mime_type: uploadResult.mimeType
        });
      } catch (uploadError) {
        console.error('Error uploading attachment:', uploadError);
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
      status: 'open'
    });
    
    await supportTicket.save();
    
    // Create notification
    await createNotification(
      userId,
      'Support Ticket Created',
      `Your support ticket #${ticketId} has been created successfully. We will respond within 24 hours.`,
      'info',
      `/support/ticket/${ticketId}`
    );
    
    res.status(201).json(formatResponse(true, 'Support ticket created successfully!', {
      ticket: {
        ...supportTicket.toObject(),
        ticket_id: ticketId
      }
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
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };
    
    res.json(formatResponse(true, 'Support tickets retrieved successfully', {
      tickets,
      stats: {
        total_tickets: total,
        open_tickets: tickets.filter(t => t.status === 'open').length,
        resolved_tickets: tickets.filter(t => t.status === 'resolved').length
      },
      pagination
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching support tickets');
  }
});

// ==================== CRITICAL FIX: REFERRAL ENDPOINTS ====================

// Get referral stats - FIXED VERSION
app.get('/api/referrals/stats', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Get all referrals
    const referrals = await Referral.find({ referrer: userId })
      .populate('referred_user', 'full_name email createdAt balance')
      .sort({ createdAt: -1 })
      .lean();
    
    // Calculate stats
    const totalReferrals = referrals.length;
    const activeReferrals = referrals.filter(r => r.status === 'active').length;
    
    // Get user's current referral earnings from user document
    const user = await User.findById(userId);
    
    res.json(formatResponse(true, 'Referral stats retrieved successfully', {
      stats: {
        total_referrals: totalReferrals,
        active_referrals: activeReferrals,
        referral_earnings: user.referral_earnings || 0,
        referral_code: user.referral_code,
        referral_link: `${config.clientURL}/register?ref=${user.referral_code}`,
        commission_rate: `${config.referralCommissionPercent}%`
      },
      referrals: referrals.slice(0, 10)
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching referral stats');
  }
});

// ==================== NOTIFICATION ENDPOINTS ====================

// Get user notifications
app.get('/api/notifications', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { unread_only = false, page = 1, limit = 20 } = req.query;
    
    const query = { user: userId };
    if (unread_only === 'true') {
      query.is_read = false;
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
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };
    
    res.json(formatResponse(true, 'Notifications retrieved successfully', {
      notifications,
      unread_count: unreadCount,
      pagination
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching notifications');
  }
});

// Mark notification as read
app.post('/api/notifications/:id/read', auth, async (req, res) => {
  try {
    const notificationId = req.params.id;
    const userId = req.user._id;
    
    const notification = await Notification.findOneAndUpdate(
      { _id: notificationId, user: userId },
      { is_read: true },
      { new: true }
    );
    
    if (!notification) {
      return res.status(404).json(formatResponse(false, 'Notification not found'));
    }
    
    res.json(formatResponse(true, 'Notification marked as read', { notification }));
  } catch (error) {
    handleError(res, error, 'Error marking notification as read');
  }
});

// Mark all notifications as read
app.post('/api/notifications/read-all', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    await Notification.updateMany(
      { user: userId, is_read: false },
      { is_read: true }
    );
    
    res.json(formatResponse(true, 'All notifications marked as read'));
  } catch (error) {
    handleError(res, error, 'Error marking notifications as read');
  }
});

// ==================== UPLOAD ENDPOINT ====================

// File upload
app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json(formatResponse(false, 'No file uploaded'));
    }
    
    const userId = req.user._id;
    const folder = req.body.folder || 'general';
    
    const uploadResult = await handleFileUpload(req.file, folder, userId);
    
    res.json(formatResponse(true, 'File uploaded successfully', {
      fileUrl: uploadResult.url,
      fileName: uploadResult.filename,
      originalName: uploadResult.originalName,
      size: uploadResult.size,
      mimeType: uploadResult.mimeType,
      folder,
      uploadedAt: uploadResult.uploadedAt
    }));
  } catch (error) {
    handleError(res, error, 'Error uploading file');
  }
});

// ==================== ADMIN ENDPOINTS ====================

// Admin dashboard stats
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
      Investment.countDocuments({ status: 'pending' }),
      Deposit.countDocuments({ status: 'pending' }),
      Withdrawal.countDocuments({ status: 'pending' }),
      KYCSubmission.countDocuments({ status: 'pending' })
    ]);
    
    // Calculate total earnings
    const earningsResult = await Investment.aggregate([
      { $match: { status: 'active' } },
      { $group: { _id: null, total: { $sum: '$earned_so_far' } } }
    ]);
    
    const totalEarnings = earningsResult[0]?.total || 0;
    
    // Calculate total portfolio value
    const portfolioResult = await User.aggregate([
      {
        $group: {
          _id: null,
          total_balance: { $sum: '$balance' },
          total_earnings: { $sum: '$total_earnings' },
          total_referral_earnings: { $sum: '$referral_earnings' }
        }
      }
    ]);
    
    const totalPortfolio = portfolioResult[0] ?
      (portfolioResult[0].total_balance || 0) +
      (portfolioResult[0].total_earnings || 0) +
      (portfolioResult[0].total_referral_earnings || 0) : 0;
    
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
        total_portfolio_value: totalPortfolio
      },
      pending_actions: {
        pending_investments: pendingInvestments,
        pending_deposits: pendingDeposits,
        pending_withdrawals: pendingWithdrawals,
        pending_kyc: pendingKYC,
        total_pending: pendingInvestments + pendingDeposits + pendingWithdrawals + pendingKYC
      }
    };
    
    res.json(formatResponse(true, 'Admin dashboard stats retrieved successfully', {
      stats,
      quick_links: {
        pending_investments: '/api/admin/pending-investments',
        pending_deposits: '/api/admin/pending-deposits',
        pending_withdrawals: '/api/admin/pending-withdrawals',
        pending_kyc: '/api/admin/pending-kyc',
        all_users: '/api/admin/users',
        all_transactions: '/api/admin/transactions',
        view_user: '/api/admin/users/:id'
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
      search
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
    
    const [users, total] = await Promise.all([
      User.find(query)
        .select('-password -two_factor_secret -verification_token -password_reset_token')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      User.countDocuments(query)
    ]);
    
    // Enhance users with portfolio value
    const enhancedUsers = users.map(user => ({
      ...user,
      portfolio_value: (user.balance || 0) + (user.total_earnings || 0) + (user.referral_earnings || 0)
    }));
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };
    
    res.json(formatResponse(true, 'Users retrieved successfully', {
      users: enhancedUsers,
      pagination,
      summary: {
        total_users: total,
        active_users: enhancedUsers.filter(u => u.is_active).length,
        verified_users: enhancedUsers.filter(u => u.kyc_verified).length,
        total_balance: enhancedUsers.reduce((sum, u) => sum + (u.balance || 0), 0),
        total_earnings: enhancedUsers.reduce((sum, u) => sum + (u.total_earnings || 0), 0),
        total_referral_earnings: enhancedUsers.reduce((sum, u) => sum + (u.referral_earnings || 0), 0),
        total_portfolio_value: enhancedUsers.reduce((sum, u) => sum + (u.portfolio_value || 0), 0)
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching users');
  }
});

// ==================== ADVANCED ADMIN: VIEW SPECIFIC USER INFORMATION ====================

// Get detailed information about a specific user (ADMIN ONLY)
app.get('/api/admin/users/:id', adminAuth, async (req, res) => {
  try {
    const userId = req.params.id;
    
    // Get user with all fields except sensitive ones
    const user = await User.findById(userId)
      .select('-password -two_factor_secret -verification_token -password_reset_token');
    
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }
    
    // Convert to object and ensure all fields exist
    const userData = user.toObject();
    userData.portfolio_value = (userData.balance || 0) + (userData.total_earnings || 0) + (userData.referral_earnings || 0);
    
    // Get comprehensive user statistics
    const [
      investments,
      deposits,
      withdrawals,
      referrals,
      transactions,
      activeInvestments,
      pendingInvestments,
      pendingDeposits,
      pendingWithdrawals,
      kycSubmission,
      supportTickets
    ] = await Promise.all([
      // All investments
      Investment.find({ user: userId })
        .populate('plan', 'name daily_interest duration')
        .sort({ createdAt: -1 })
        .lean(),
      
      // All deposits
      Deposit.find({ user: userId })
        .sort({ createdAt: -1 })
        .lean(),
      
      // All withdrawals
      Withdrawal.find({ user: userId })
        .sort({ createdAt: -1 })
        .lean(),
      
      // Referrals made by this user
      Referral.find({ referrer: userId })
        .populate('referred_user', 'full_name email createdAt')
        .sort({ createdAt: -1 })
        .lean(),
      
      // Recent transactions
      Transaction.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(50)
        .lean(),
      
      // Active investments
      Investment.find({ user: userId, status: 'active' })
        .populate('plan', 'name daily_interest')
        .lean(),
      
      // Pending investments
      Investment.countDocuments({ user: userId, status: 'pending' }),
      
      // Pending deposits
      Deposit.countDocuments({ user: userId, status: 'pending' }),
      
      // Pending withdrawals
      Withdrawal.countDocuments({ user: userId, status: 'pending' }),
      
      // KYC submission
      KYCSubmission.findOne({ user: userId }),
      
      // Support tickets
      SupportTicket.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(20)
        .lean()
    ]);
    
    // Calculate detailed statistics
    const totalInvestmentAmount = investments.reduce((sum, inv) => sum + inv.amount, 0);
    const totalEarnings = investments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0);
    const totalDepositAmount = deposits.filter(d => d.status === 'approved').reduce((sum, d) => sum + d.amount, 0);
    const totalWithdrawalAmount = withdrawals.filter(w => w.status === 'paid').reduce((sum, w) => sum + w.amount, 0);
    const activeInvestmentValue = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    
    // Calculate daily earnings from active investments
    let dailyEarnings = 0;
    activeInvestments.forEach(inv => {
      if (inv.plan && inv.plan.daily_interest) {
        dailyEarnings += (inv.amount * inv.plan.daily_interest) / 100;
      }
    });
    
    // Get referral earnings
    const referralEarnings = referrals.reduce((sum, ref) => sum + (ref.earnings || 0), 0);
    
    // Prepare comprehensive user data
    const userDetails = {
      basic_info: {
        _id: userData._id,
        full_name: userData.full_name,
        email: userData.email,
        phone: userData.phone,
        role: userData.role,
        country: userData.country,
        currency: userData.currency,
        referral_code: userData.referral_code,
        referred_by: userData.referred_by,
        created_at: userData.createdAt,
        last_login: userData.last_login,
        last_active: userData.last_active
      },
      account_status: {
        is_active: userData.is_active,
        is_verified: userData.is_verified,
        kyc_status: userData.kyc_status,
        kyc_verified: userData.kyc_verified,
        kyc_submitted_at: userData.kyc_submitted_at,
        kyc_verified_at: userData.kyc_verified_at
      },
      financial_overview: {
        balance: userData.balance || 0,
        total_earnings: userData.total_earnings || 0,
        referral_earnings: userData.referral_earnings || 0,
        portfolio_value: userData.portfolio_value,
        total_deposits: userData.total_deposits || 0,
        total_withdrawals: userData.total_withdrawals || 0,
        total_investments: userData.total_investments || 0
      },
      statistics: {
        total_investments: investments.length,
        active_investments: activeInvestments.length,
        total_deposits: deposits.length,
        total_withdrawals: withdrawals.length,
        total_referrals: referrals.length,
        total_transactions: transactions.length,
        total_support_tickets: supportTickets.length,
        pending_investments: pendingInvestments,
        pending_deposits: pendingDeposits,
        pending_withdrawals: pendingWithdrawals
      },
      calculated_stats: {
        total_investment_amount: totalInvestmentAmount,
        total_earnings_amount: totalEarnings,
        total_deposit_amount: totalDepositAmount,
        total_withdrawal_amount: totalWithdrawalAmount,
        active_investment_value: activeInvestmentValue,
        daily_earnings: dailyEarnings,
        referral_earnings: referralEarnings,
        net_profit: totalEarnings + referralEarnings - totalInvestmentAmount
      },
      kyc_info: kycSubmission ? {
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
      } : null,
      bank_details: userData.bank_details || null,
      settings: {
        risk_tolerance: userData.risk_tolerance,
        investment_strategy: userData.investment_strategy,
        email_notifications: userData.email_notifications,
        sms_notifications: userData.sms_notifications,
        notifications_enabled: userData.notifications_enabled
      },
      recent_activity: {
        last_deposit_date: userData.last_deposit_date,
        last_withdrawal_date: userData.last_withdrawal_date,
        last_investment_date: userData.last_investment_date
      }
    };
    
    // Create admin audit log
    await createAdminAudit(
      req.user._id,
      'VIEW_USER_DETAILS',
      'user',
      userId,
      {
        user_name: userData.full_name,
        user_email: userData.email,
        viewed_at: new Date()
      },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'User details retrieved successfully', {
      user: userDetails,
      preview_data: {
        investments: investments.slice(0, 5),
        deposits: deposits.slice(0, 5),
        withdrawals: withdrawals.slice(0, 5),
        referrals: referrals.slice(0, 5),
        transactions: transactions.slice(0, 10),
        support_tickets: supportTickets.slice(0, 5)
      },
      export_links: {
        all_investments: `/api/admin/users/${userId}/investments`,
        all_deposits: `/api/admin/users/${userId}/deposits`,
        all_withdrawals: `/api/admin/users/${userId}/withdrawals`,
        all_transactions: `/api/admin/users/${userId}/transactions`
      }
    }));
  } catch (error) {
    console.error('Error fetching user details:', error);
    handleError(res, error, 'Error fetching user information');
  }
});

// Get user's investments (ADMIN)
app.get('/api/admin/users/:id/investments', adminAuth, async (req, res) => {
  try {
    const userId = req.params.id;
    const { status, page = 1, limit = 20 } = req.query;
    
    const query = { user: userId };
    if (status) query.status = status;
    
    const skip = (page - 1) * limit;
    
    const [investments, total] = await Promise.all([
      Investment.find(query)
        .populate('plan', 'name daily_interest duration')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Investment.countDocuments(query)
    ]);
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };
    
    // Calculate summary
    const summary = {
      total_amount: investments.reduce((sum, inv) => sum + inv.amount, 0),
      total_earnings: investments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0),
      active_investments: investments.filter(inv => inv.status === 'active').length,
      completed_investments: investments.filter(inv => inv.status === 'completed').length,
      pending_investments: investments.filter(inv => inv.status === 'pending').length
    };
    
    res.json(formatResponse(true, 'User investments retrieved successfully', {
      investments,
      summary,
      pagination
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching user investments');
  }
});

// Get user's deposits (ADMIN)
app.get('/api/admin/users/:id/deposits', adminAuth, async (req, res) => {
  try {
    const userId = req.params.id;
    const { status, page = 1, limit = 20 } = req.query;
    
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
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };
    
    // Calculate summary
    const summary = {
      total_amount: deposits.reduce((sum, dep) => sum + dep.amount, 0),
      approved_amount: deposits.filter(d => d.status === 'approved').reduce((sum, d) => sum + d.amount, 0),
      pending_amount: deposits.filter(d => d.status === 'pending').reduce((sum, d) => sum + d.amount, 0),
      approved_count: deposits.filter(d => d.status === 'approved').length,
      pending_count: deposits.filter(d => d.status === 'pending').length
    };
    
    res.json(formatResponse(true, 'User deposits retrieved successfully', {
      deposits,
      summary,
      pagination
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching user deposits');
  }
});

// Get user's withdrawals (ADMIN)
app.get('/api/admin/users/:id/withdrawals', adminAuth, async (req, res) => {
  try {
    const userId = req.params.id;
    const { status, page = 1, limit = 20 } = req.query;
    
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
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };
    
    // Calculate summary
    const summary = {
      total_amount: withdrawals.reduce((sum, w) => sum + w.amount, 0),
      paid_amount: withdrawals.filter(w => w.status === 'paid').reduce((sum, w) => sum + w.amount, 0),
      pending_amount: withdrawals.filter(w => w.status === 'pending').reduce((sum, w) => sum + w.amount, 0),
      total_fees: withdrawals.reduce((sum, w) => sum + (w.platform_fee || 0), 0),
      paid_count: withdrawals.filter(w => w.status === 'paid').length,
      pending_count: withdrawals.filter(w => w.status === 'pending').length
    };
    
    res.json(formatResponse(true, 'User withdrawals retrieved successfully', {
      withdrawals,
      summary,
      pagination
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching user withdrawals');
  }
});

// Get user's transactions (ADMIN)
app.get('/api/admin/users/:id/transactions', adminAuth, async (req, res) => {
  try {
    const userId = req.params.id;
    const { type, page = 1, limit = 50 } = req.query;
    
    const query = { user: userId };
    if (type) query.type = type;
    
    const skip = (page - 1) * limit;
    
    const [transactions, total] = await Promise.all([
      Transaction.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Transaction.countDocuments(query)
    ]);
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };
    
    // Calculate summary by type
    const summary = transactions.reduce((acc, txn) => {
      const type = txn.type;
      if (!acc[type]) {
        acc[type] = { count: 0, total: 0 };
      }
      acc[type].count += 1;
      acc[type].total += txn.amount;
      return acc;
    }, {});
    
    // Calculate net flow
    const netFlow = transactions.reduce((sum, txn) => sum + txn.amount, 0);
    
    res.json(formatResponse(true, 'User transactions retrieved successfully', {
      transactions,
      summary: {
        by_type: summary,
        net_flow: netFlow,
        total_transactions: total
      },
      pagination
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching user transactions');
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
    
    res.json(formatResponse(true, 'Pending investments retrieved successfully', {
      investments: pendingInvestments,
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
    
    // Update investment
    investment.status = 'active';
    investment.approved_at = new Date();
    investment.approved_by = adminId;
    investment.payment_verified = true;
    investment.remarks = remarks;
    
    await investment.save();
    
    // Create notification for user
    await createNotification(
      investment.user._id,
      'Investment Approved',
      `Your investment of ₦${investment.amount.toLocaleString()} in ${investment.plan.name} has been approved and is now active.`,
      'investment',
      '/investments'
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
        user_name: investment.user.full_name
      },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'Investment approved successfully', {
      investment: investment.toObject()
    }));
  } catch (error) {
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
    
    res.json(formatResponse(true, 'Pending deposits retrieved successfully', {
      deposits: pendingDeposits,
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
    
    // Update deposit
    deposit.status = 'approved';
    deposit.approved_at = new Date();
    deposit.approved_by = adminId;
    deposit.admin_notes = remarks;
    
    await deposit.save();
    
    // Use createTransaction to update user fields correctly
    await createTransaction(
      deposit.user._id,
      'deposit',
      deposit.amount,
      `Deposit via ${deposit.payment_method}`,
      'completed',
      {
        deposit_id: deposit._id,
        payment_method: deposit.payment_method
      }
    );
    
    // Create notification
    await createNotification(
      deposit.user._id,
      'Deposit Approved',
      `Your deposit of ₦${deposit.amount.toLocaleString()} has been approved and credited to your account.`,
      'success',
      '/deposits'
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
        user_name: deposit.user.full_name
      },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'Deposit approved successfully', {
      deposit: deposit.toObject()
    }));
  } catch (error) {
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
    
    res.json(formatResponse(true, 'Pending withdrawals retrieved successfully', {
      withdrawals: pendingWithdrawals,
      count: pendingWithdrawals.length,
      total_amount: pendingWithdrawals.reduce((sum, w) => sum + w.amount, 0)
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching pending withdrawals');
  }
});

// Approve withdrawal
app.post('/api/admin/withdrawals/:id/approve', adminAuth, [
  body('transaction_id').optional().trim(),
  body('remarks').optional().trim()
], async (req, res) => {
  try {
    const withdrawalId = req.params.id;
    const adminId = req.user._id;
    const { transaction_id, remarks } = req.body;
    
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
    withdrawal.admin_notes = remarks;
    
    await withdrawal.save();
    
    // Update user withdrawal stats via createTransaction
    await createTransaction(
      withdrawal.user._id,
      'withdrawal',
      -withdrawal.amount,
      `Withdrawal via ${withdrawal.payment_method}`,
      'completed',
      {
        withdrawal_id: withdrawal._id,
        payment_method: withdrawal.payment_method,
        platform_fee: withdrawal.platform_fee,
        net_amount: withdrawal.net_amount,
        transaction_id: transaction_id
      }
    );
    
    // Create notification
    await createNotification(
      withdrawal.user._id,
      'Withdrawal Approved',
      `Your withdrawal of ₦${withdrawal.amount.toLocaleString()} has been approved and processed.`,
      'success',
      '/withdrawals'
    );
    
    // Create audit log
    await createAdminAudit(
      adminId,
      'APPROVE_WITHDRAWAL',
      'withdrawal',
      withdrawalId,
      {
        amount: withdrawal.amount,
        payment_method: withdrawal.payment_method,
        user_id: withdrawal.user._id,
        user_name: withdrawal.user.full_name,
        transaction_id: transaction_id
      },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'Withdrawal approved successfully', {
      withdrawal: withdrawal.toObject()
    }));
  } catch (error) {
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
    
    res.json(formatResponse(true, 'Pending KYC submissions retrieved successfully', {
      kyc_submissions: pendingKYC,
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
        id_type: kyc.id_type
      },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'KYC approved successfully', {
      kyc: kyc.toObject()
    }));
  } catch (error) {
    handleError(res, error, 'Error approving KYC');
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
      user_id
    } = req.query;
    
    const query = {};
    if (type) query.type = type;
    if (status) query.status = status;
    if (user_id) query.user = user_id;
    
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
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };
    
    res.json(formatResponse(true, 'Transactions retrieved successfully', {
      transactions,
      pagination
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching transactions');
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
      'system'
    );
    
    // Create audit log
    await createAdminAudit(
      req.user._id,
      'UPDATE_USER_ROLE',
      'user',
      userId,
      {
        new_role: role,
        user_name: user.full_name
      },
      req.ip,
      req.headers['user-agent']
    );
    
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
    
    // Create notification for user
    await createNotification(
      userId,
      is_active ? 'Account Activated' : 'Account Deactivated',
      is_active
        ? 'Your account has been activated. You can now access all features.'
        : 'Your account has been deactivated. Please contact support for assistance.',
      'system'
    );
    
    // Create audit log
    await createAdminAudit(
      req.user._id,
      is_active ? 'ACTIVATE_USER' : 'DEACTIVATE_USER',
      'user',
      userId,
      {
        status: is_active ? 'active' : 'inactive',
        user_name: user.full_name
      },
      req.ip,
      req.headers['user-agent']
    );
    
    res.json(formatResponse(true, 'User status updated successfully', { user }));
  } catch (error) {
    handleError(res, error, 'Error updating user status');
  }
});

// ==================== CRITICAL FIX: DAILY INTEREST CRON JOB ====================

// Schedule daily interest calculation - FIXED VERSION
cron.schedule('0 0 * * *', async () => {
  try {
    console.log('🔄 Running daily interest calculation...');
    
    const activeInvestments = await Investment.find({
      status: 'active',
      end_date: { $gt: new Date() }
    }).populate('plan', 'daily_interest').populate('user');
    
    let totalInterestPaid = 0;
    let investmentsUpdated = 0;
    
    for (const investment of activeInvestments) {
      if (investment.plan && investment.plan.daily_interest) {
        const dailyEarning = (investment.amount * investment.plan.daily_interest) / 100;
        
        // Update investment
        investment.earned_so_far += dailyEarning;
        investment.last_earning_date = new Date();
        await investment.save();
        
        // Use createTransaction to update user fields correctly (total_earnings)
        await createTransaction(
          investment.user._id,
          'earning',
          dailyEarning,
          `Daily interest from ${investment.plan.name} investment`,
          'completed',
          {
            investment_id: investment._id,
            plan_name: investment.plan.name,
            daily_interest_rate: investment.plan.daily_interest
          }
        );
        
        totalInterestPaid += dailyEarning;
        investmentsUpdated++;
      }
    }
    
    console.log(`✅ Daily interest calculation completed: ${investmentsUpdated} investments updated, ₦${totalInterestPaid.toLocaleString()} paid`);
  } catch (error) {
    console.error('❌ Error in daily interest calculation:', error);
  }
});

// Schedule investment completion check
cron.schedule('0 1 * * *', async () => {
  try {
    console.log('🔄 Checking completed investments...');
    
    const completedInvestments = await Investment.find({
      status: 'active',
      end_date: { $lte: new Date() }
    }).populate('user plan');
    
    let investmentsCompleted = 0;
    
    for (const investment of completedInvestments) {
      // Mark investment as completed
      investment.status = 'completed';
      await investment.save();
      
      // Create notification
      await createNotification(
        investment.user._id,
        'Investment Completed',
        `Your investment in ${investment.plan.name} has completed. Total earnings: ₦${investment.earned_so_far.toLocaleString()}`,
        'investment',
        '/investments'
      );
      
      investmentsCompleted++;
    }
    
    console.log(`✅ Investment completion check: ${investmentsCompleted} investments marked as completed`);
  } catch (error) {
    console.error('❌ Error in investment completion check:', error);
  }
});

// ==================== ERROR HANDLING MIDDLEWARE ====================

// 404 handler
app.use((req, res) => {
  res.status(404).json(formatResponse(false, 'Endpoint not found'));
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('🚨 Unhandled error:', err);
  
  // Handle multer errors
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json(formatResponse(false, 'File too large. Maximum size is 10MB'));
    }
    if (err.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json(formatResponse(false, 'Too many files. Maximum is 10 files'));
    }
    return res.status(400).json(formatResponse(false, `File upload error: ${err.message}`));
  }
  
  // Handle validation errors
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(e => e.message);
    return res.status(400).json(formatResponse(false, 'Validation Error', { errors: messages }));
  }
  
  // Handle JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json(formatResponse(false, 'Invalid token'));
  }
  
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json(formatResponse(false, 'Token expired'));
  }
  
  // Default error
  const statusCode = err.statusCode || 500;
  const message = config.nodeEnv === 'production' && statusCode === 500
    ? 'Internal server error'
    : err.message;
  
  res.status(statusCode).json(formatResponse(false, message));
});

// ==================== START SERVER ====================

const startServer = async () => {
  try {
    // Initialize database
    await initializeDatabase();
    
    // Start server
    app.listen(config.port, () => {
      console.log('\n🚀 ============================================');
      console.log(`✅ Raw Wealthy Backend v38.0 - FIXED ULTIMATE EDITION`);
      console.log(`🌐 Environment: ${config.nodeEnv}`);
      console.log(`📍 Port: ${config.port}`);
      console.log(`🔗 Server URL: ${config.serverURL}`);
      console.log(`🔗 Client URL: ${config.clientURL}`);
      console.log(`📁 Uploads Directory: ${config.uploadDir}`);
      console.log(`📊 Database: ${config.mongoURI}`);
      console.log('============================================\n');
      
      console.log('🎯 CRITICAL FIXES APPLIED:');
      console.log('1. ✅ createTransaction function now correctly updates user.total_earnings and user.referral_earnings');
      console.log('2. ✅ Profile endpoint returns correct financial data (no more 0 or "NO")');
      console.log('3. ✅ Daily interest cron job creates "earning" transactions that update total_earnings');
      console.log('4. ✅ Portfolio value calculated correctly in all responses');
      console.log('5. ✅ Admin can view detailed user info at /api/admin/users/:id');
      console.log('6. ✅ All user fields (balance, total_earnings, etc.) are guaranteed to have values');
      console.log('7. ✅ Added processReferralBonus function for automatic referral commissions');
      console.log('8. ✅ Investment creation now triggers referral bonuses for referrers');
      console.log('============================================\n');
      
      console.log('📋 Available Endpoints:');
      console.log(' • POST /api/auth/register');
      console.log(' • POST /api/auth/login');
      console.log(' • GET /api/profile (FIXED DASHBOARD DATA)');
      console.log(' • PUT /api/profile');
      console.log(' • PUT /api/profile/bank');
      console.log(' • POST /api/auth/forgot-password');
      console.log(' • POST /api/auth/reset-password/:token');
      console.log(' • GET /api/plans');
      console.log(' • GET /api/investments');
      console.log(' • POST /api/investments (WITH REFERRAL BONUS)');
      console.log(' • GET /api/deposits');
      console.log(' • POST /api/deposits');
      console.log(' • GET /api/withdrawals');
      console.log(' • POST /api/withdrawals');
      console.log(' • GET /api/transactions');
      console.log(' • POST /api/kyc');
      console.log(' • GET /api/kyc/status');
      console.log(' • POST /api/support');
      console.log(' • GET /api/support/tickets');
      console.log(' • GET /api/referrals/stats');
      console.log(' • GET /api/notifications');
      console.log(' • POST /api/upload');
      console.log(' • GET /api/admin/dashboard');
      console.log(' • GET /api/admin/users');
      console.log(' • GET /api/admin/users/:id (VIEW USER DETAILS)');
      console.log(' • GET /api/admin/users/:id/investments');
      console.log(' • GET /api/admin/users/:id/deposits');
      console.log(' • GET /api/admin/users/:id/withdrawals');
      console.log(' • GET /api/admin/users/:id/transactions');
      console.log(' • GET /api/admin/pending-investments');
      console.log(' • POST /api/admin/investments/:id/approve');
      console.log(' • GET /api/admin/pending-deposits');
      console.log(' • POST /api/admin/deposits/:id/approve');
      console.log(' • GET /api/admin/pending-withdrawals');
      console.log(' • POST /api/admin/withdrawals/:id/approve');
      console.log(' • GET /api/admin/pending-kyc');
      console.log(' • POST /api/admin/kyc/:id/approve');
      console.log(' • GET /api/admin/transactions');
      console.log(' • PUT /api/admin/users/:id/role');
      console.log(' • PUT /api/admin/users/:id/status');
      
      // Debug endpoints in non-production
      if (config.nodeEnv !== 'production') {
        console.log(' • GET /api/debug/admin-status');
        console.log(' • POST /api/debug/create-admin');
        console.log(' • GET /api/debug/admins');
        console.log(' • GET /api/debug/profile-test');
      }
      
      console.log(' • GET /health');
      console.log('============================================\n');
      
      console.log('🚀 FRONTEND INTEGRATION READY');
      console.log('✅ All endpoints match frontend v37.0');
      console.log('✅ CORS configured for frontend origins');
      console.log('✅ File upload system ready');
      console.log('✅ Admin dashboard operational');
      console.log('✅ Automated daily interest calculation');
      console.log('✅ Production error handling');
      console.log('✅ Enhanced security headers');
      console.log('✅ ADVANCED USER EARNINGS SYSTEM ENABLED');
      console.log('✅ DASHBOARD DATA 100% FIXED');
      console.log('✅ ADMIN USER VIEW ENDPOINTS ADDED');
      console.log('✅ AUTOMATIC REFERRAL BONUS SYSTEM ENABLED');
      console.log('============================================\n');
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('👋 SIGTERM received. Shutting down gracefully...');
  mongoose.connection.close(() => {
    console.log('✅ MongoDB connection closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('👋 SIGINT received. Shutting down gracefully...');
  mongoose.connection.close(() => {
    console.log('✅ MongoDB connection closed');
    process.exit(0);
  });
});

// Start the server
startServer();
