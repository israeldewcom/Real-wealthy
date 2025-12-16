// server.js - RAW WEALTHY BACKEND v36.0 - ADVANCED PRODUCTION READY
// COMPLETE ENHANCEMENT: Advanced Admin Dashboard + Full Data Analytics + Enhanced Notifications
// AUTO-DEPLOYMENT READY WITH DYNAMIC CONFIGURATION

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
  
  // Check for Render/Heroku style environment
  if (process.env.DATABASE_URL) {
    process.env.MONGODB_URI = process.env.DATABASE_URL;
    console.log('✅ Loaded MONGODB_URI from DATABASE_URL');
  }
  
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
}

console.log('============================\n');

// ==================== DYNAMIC CONFIGURATION ====================
const config = {
  // Server
  port: process.env.PORT || 10000,
  nodeEnv: process.env.NODE_ENV || 'production',
  
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
  }
};

// Build allowed origins dynamically
config.allowedOrigins = [
  config.clientURL,
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:3001',
  'https://rawwealthy.com',
  'https://www.rawwealthy.com',
  'https://uun-rawwealthy.vercel.app',
  'https://real-wealthy-1.onrender.com'
].filter(Boolean);

console.log('⚙️  Dynamic Configuration Loaded:');
console.log(`- Port: ${config.port}`);
console.log(`- Environment: ${config.nodeEnv}`);
console.log(`- Client URL: ${config.clientURL}`);
console.log(`- Email Enabled: ${config.emailEnabled}`);
console.log(`- Allowed Origins: ${config.allowedOrigins.length}`);
console.log(`- Upload Directory: ${config.uploadDir}`);

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
      imgSrc: ["'self'", "data:", "https:", "http:"],
      connectSrc: ["'self'", "ws:", "wss:", config.clientURL]
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
  passwordReset: createRateLimiter(15 * 60 * 1000, 5, 'Too many password reset attempts, please try again later')
};

// Apply rate limiting
app.use('/api/auth/register', rateLimiters.createAccount);
app.use('/api/auth/login', rateLimiters.auth);
app.use('/api/auth/forgot-password', rateLimiters.passwordReset);
app.use('/api/auth/reset-password', rateLimiters.passwordReset);
app.use('/api/investments', rateLimiters.financial);
app.use('/api/deposits', rateLimiters.financial);
app.use('/api/withdrawals', rateLimiters.financial);
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
    
    return {
      url: `/uploads/${folder}/${filename}`,
      filename,
      originalName: file.originalname,
      size: file.size,
      mimeType: file.mimetype
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

// ==================== DATABASE MODELS ====================

// User Model
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
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
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
  this.password_reset_expires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
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
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { 
  timestamps: true 
});

investmentSchema.index({ user: 1, status: 1 });
investmentSchema.index({ end_date: 1 });

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
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { 
  timestamps: true 
});

depositSchema.index({ user: 1, status: 1 });
depositSchema.index({ reference: 1 }, { unique: true, sparse: true });

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
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { 
  timestamps: true 
});

withdrawalSchema.index({ user: 1, status: 1 });
withdrawalSchema.index({ reference: 1 }, { unique: true, sparse: true });

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
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { 
  timestamps: true 
});

transactionSchema.index({ user: 1, createdAt: -1 });
transactionSchema.index({ type: 1, status: 1 });

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

const createNotification = async (userId, title, message, type = 'info', actionUrl = null) => {
  try {
    const notification = new Notification({
      user: userId,
      title,
      message,
      type,
      action_url: actionUrl
    });
    
    await notification.save();
    
    // Send email notification if enabled
    const user = await User.findById(userId);
    if (user && user.email_notifications && type !== 'system') {
      await sendEmail(
        user.email,
        title,
        `<h2>${title}</h2><p>${message}</p>${actionUrl ? `<p><a href="${config.clientURL}${actionUrl}">View Details</a></p>` : ''}`
      );
    }
    
    return notification;
  } catch (error) {
    console.error('Error creating notification:', error);
    return null;
  }
};

const createTransaction = async (userId, type, amount, description, status = 'completed', metadata = {}) => {
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
      metadata
    });
    
    await transaction.save();
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
      totalReferrals
    ] = await Promise.all([
      Investment.countDocuments({ user: userId }),
      Investment.countDocuments({ user: userId, status: 'active' }),
      Deposit.countDocuments({ user: userId, status: 'approved' }),
      Withdrawal.countDocuments({ user: userId, status: 'paid' }),
      Referral.countDocuments({ referrer: userId })
    ]);

    return {
      total_investments: totalInvestments,
      active_investments: activeInvestments,
      total_deposits: totalDeposits,
      total_withdrawals: totalWithdrawals,
      total_referrals: totalReferrals
    };
  } catch (error) {
    console.error('Error calculating user stats:', error);
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
    });
    
    console.log('✅ MongoDB connected successfully');
    
    // Load investment plans into config
    await loadInvestmentPlans();
    
    // Create admin user if it doesn't exist
    await createAdminUser();
    
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
  try {
    console.log('🚀 NUCLEAR ADMIN FIX STARTING...');
    
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@rawwealthy.com';
    const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123456';
    
    console.log(`🔑 Using: ${adminEmail} / ${adminPassword}`);
    
    // 1. Delete any existing admin
    await User.deleteMany({ 
      $or: [
        { email: adminEmail },
        { role: { $in: ['admin', 'super_admin'] } }
      ] 
    });
    console.log('✅ Deleted all existing admins');
    
    // 2. Generate FRESH hash
    const salt = await bcrypt.genSalt(12);
    const hash = await bcrypt.hash(adminPassword, salt);
    
    console.log('📝 Generated fresh hash');
    console.log('Hash:', hash);
    
    // 3. Create admin WITHOUT Mongoose hooks
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
    
    // Insert directly
    await mongoose.connection.collection('users').insertOne(adminData);
    console.log('✅ Admin created in database');
    
    // 4. Verify IMMEDIATELY
    const verifyUser = await mongoose.connection.collection('users').findOne({ email: adminEmail });
    console.log('🔍 Stored hash in DB:', verifyUser.password);
    
    const match = await bcrypt.compare(adminPassword, verifyUser.password);
    console.log('🔑 Password match test:', match ? '✅ PASS' : '❌ FAIL');
    
    if (match) {
      console.log('🎉 ADMIN READY FOR LOGIN!');
      console.log(`📧 Email: ${adminEmail}`);
      console.log(`🔑 Password: ${adminPassword}`);
      console.log('👉 Login at: /api/auth/login');
    } else {
      console.error('❌ PASSWORD MISMATCH DETECTED!');
      console.error('This means bcrypt.compare is failing despite same hash');
    }
    
    console.log('🚀 NUCLEAR ADMIN FIX COMPLETE');
    
  } catch (error) {
    console.error('❌ NUCLEAR FIX ERROR:', error.message);
    console.error(error.stack);
  }
};

// ==================== HEALTH CHECK ====================
app.get('/health', async (req, res) => {
  const health = {
    success: true,
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '36.0.0',
    environment: config.nodeEnv,
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    uptime: process.uptime(),
    memory: {
      rss: `${Math.round(process.memoryUsage().rss / 1024 / 1024)}MB`,
      heapTotal: `${Math.round(process.memoryUsage().heapTotal / 1024 / 1024)}MB`,
      heapUsed: `${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB`
    }
  };
  
  res.json(health);
});

// ==================== ROOT ENDPOINT ====================
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 Raw Wealthy Backend API v36.0',
    version: '36.0.0',
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
      forgot_password: '/api/auth/forgot-password'
    }
  });
});

// ==================== AUTH ENDPOINTS ====================

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
      
      // Create notification for referrer
      await createNotification(
        referredBy._id,
        'New Referral!',
        `${user.full_name} has signed up using your referral code!`,
        'referral'
      );
    }

    // Generate token
    const token = user.generateAuthToken();

    // Create welcome notification
    await createNotification(
      user._id,
      'Welcome to Raw Wealthy!',
      'Your account has been successfully created. Start your investment journey today.',
      'success'
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
       </ul>`
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

    // Find user with password
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    
    if (!user) {
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
      if (user.login_attempts >= 5) {
        user.lock_until = new Date(Date.now() + 15 * 60 * 1000);
      }
      await user.save();
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

    res.json(formatResponse(true, 'Password reset successful'));
  } catch (error) {
    handleError(res, error, 'Error resetting password');
  }
});

// ==================== PROFILE ENDPOINTS ====================

// Get profile
app.get('/api/profile', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Get user data with related information
    const [investments, transactions, notifications, kyc, userStats] = await Promise.all([
      Investment.find({ user: userId, status: 'active' })
        .populate('plan', 'name daily_interest')
        .lean(),
      Transaction.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      Notification.find({ user: userId, is_read: false })
        .sort({ createdAt: -1 })
        .limit(5)
        .lean(),
      KYCSubmission.findOne({ user: userId }).lean(),
      calculateUserStats(userId)
    ]);

    // Calculate stats
    const totalActiveValue = investments.reduce((sum, inv) => sum + inv.amount, 0);
    const totalEarnings = investments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0);

    const profileData = {
      user: req.user,
      dashboard_stats: {
        active_investment_value: totalActiveValue,
        total_earnings: req.user.total_earnings || 0,
        total_investments: investments.length,
        unread_notifications: notifications.length,
        referral_count: req.user.referral_count || 0,
        referral_earnings: req.user.referral_earnings || 0,
        portfolio_value: totalActiveValue + totalEarnings,
        available_balance: req.user.balance || 0,
        kyc_status: req.user.kyc_status || 'not_submitted',
        kyc_verified: req.user.kyc_verified || false
      },
      user_statistics: userStats,
      recent_transactions: transactions,
      active_investments: investments,
      kyc_submission: kyc
    };

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
    const allowedUpdates = ['full_name', 'phone', 'country', 'notifications_enabled', 'email_notifications'];
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
      'info'
    );

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

    // Create notification for user
    await createNotification(
      userId,
      'Bank Details Updated',
      'Your bank account details have been updated successfully. They will be verified by our team.',
      'info'
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

    res.json(formatResponse(true, 'Bank details updated successfully', {
      bank_details: user.bank_details
    }));
  } catch (error) {
    handleError(res, error, 'Error updating bank details');
  }
});

// Update wallet address
app.put('/api/profile/wallet', auth, [
  body('wallet_address').notEmpty().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.user._id;
    const { wallet_address } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    user.wallet_address = wallet_address;
    await user.save();

    await createNotification(
      userId,
      'Wallet Address Updated',
      'Your crypto wallet address has been updated successfully.',
      'info'
    );

    res.json(formatResponse(true, 'Wallet address updated successfully'));
  } catch (error) {
    handleError(res, error, 'Error updating wallet address');
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

// Get specific plan
app.get('/api/plans/:id', async (req, res) => {
  try {
    const plan = await InvestmentPlan.findById(req.params.id);
    
    if (!plan) {
      return res.status(404).json(formatResponse(false, 'Investment plan not found'));
    }
    
    res.json(formatResponse(true, 'Plan retrieved successfully', { plan }));
  } catch (error) {
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
        .populate('plan', 'name daily_interest duration')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Investment.countDocuments(query)
    ]);

    // Enhance investments with calculations
    const enhancedInvestments = investments.map(inv => {
      const remainingDays = Math.max(0, Math.ceil((new Date(inv.end_date) - new Date()) / (1000 * 60 * 60 * 24)));
      const progressPercentage = inv.status === 'active' ? 
        Math.min(100, ((new Date() - new Date(inv.start_date)) / (new Date(inv.end_date) - new Date(inv.start_date))) * 100) : 
        (inv.status === 'completed' ? 100 : 0);

      return {
        ...inv,
        remaining_days: remainingDays,
        progress_percentage: Math.round(progressPercentage),
        estimated_completion: inv.end_date
      };
    });

    const activeInvestments = enhancedInvestments.filter(inv => inv.status === 'active');
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    const totalEarnings = activeInvestments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0);

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(formatResponse(true, 'Investments retrieved successfully', {
      investments: enhancedInvestments,
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

// Create investment
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

    // Create investment
    const investment = new Investment({
      user: userId,
      plan: plan_id,
      amount: investmentAmount,
      status: proofUrl ? 'pending' : 'active',
      start_date: new Date(),
      end_date: new Date(Date.now() + plan.duration * 24 * 60 * 60 * 1000),
      expected_earnings: (investmentAmount * plan.total_interest) / 100,
      daily_earnings: (investmentAmount * plan.daily_interest) / 100,
      auto_renew,
      payment_proof_url: proofUrl,
      payment_verified: !proofUrl
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
      'completed',
      { investment_id: investment._id }
    );

    // Create notification
    await createNotification(
      userId,
      'Investment Created',
      `Your investment of ₦${investmentAmount.toLocaleString()} in ${plan.name} has been created successfully.`,
      'investment',
      '/investments'
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
          `/admin/investments/${investment._id}`
        );
      }
    }

    res.status(201).json(formatResponse(true, 'Investment created successfully!', { 
      investment: {
        ...investment.toObject(),
        plan_name: plan.name,
        plan_details: {
          daily_interest: plan.daily_interest,
          duration: plan.duration
        }
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

    // Notify admin
    const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } });
    for (const admin of admins) {
      await createNotification(
        admin._id,
        'New Deposit Request',
        `User ${req.user.full_name} has submitted a deposit request of ₦${depositAmount.toLocaleString()}.`,
        'system',
        `/admin/deposits/${deposit._id}`
      );
    }

    res.status(201).json(formatResponse(true, 'Deposit request submitted successfully!', { 
      deposit,
      message: 'Your deposit is pending approval. You will be notified once approved.'
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
      return res.status(400).json(formatResponse(false, `Minimum withdrawal is ₦${config.minWithdrawal.toLocaleString()}`));
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
      ...paymentDetails
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
      { withdrawal_id: withdrawal._id }
    );

    // Create notification
    await createNotification(
      userId,
      'Withdrawal Request Submitted',
      `Your withdrawal request of ₦${withdrawalAmount.toLocaleString()} has been submitted and is pending approval.`,
      'withdrawal',
      '/withdrawals'
    );

    // Notify admin
    const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } });
    for (const admin of admins) {
      await createNotification(
        admin._id,
        'New Withdrawal Request',
        `User ${req.user.full_name} has requested a withdrawal of ₦${withdrawalAmount.toLocaleString()} via ${payment_method}.`,
        'system',
        `/admin/withdrawals/${withdrawal._id}`
      );
    }

    res.status(201).json(formatResponse(true, 'Withdrawal request submitted successfully!', { 
      withdrawal,
      message: 'Your withdrawal is pending approval. Processing time is 24-48 hours.'
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

// ==================== KYC ENDPOINTS ====================

// Submit KYC
app.post('/api/kyc', auth, upload.fields([
  { name: 'id_front', maxCount: 1 },
  { name: 'id_back', maxCount: 1 },
  { name: 'selfie_with_id', maxCount: 1 }
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
    let idFrontUrl, idBackUrl, selfieWithIdUrl;
    
    try {
      idFrontUrl = (await handleFileUpload(files.id_front[0], 'kyc-documents', userId)).url;
      selfieWithIdUrl = (await handleFileUpload(files.selfie_with_id[0], 'kyc-documents', userId)).url;
      
      if (files.id_back && files.id_back[0]) {
        idBackUrl = (await handleFileUpload(files.id_back[0], 'kyc-documents', userId)).url;
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
      'kyc'
    );

    // Notify admin
    const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } });
    for (const admin of admins) {
      await createNotification(
        admin._id,
        'New KYC Submission',
        `User ${req.user.full_name} has submitted KYC documents for verification.`,
        'system',
        `/admin/kyc/${kycSubmission._id}`
      );
    }

    res.status(201).json(formatResponse(true, 'KYC submitted successfully!', {
      kyc: kycSubmission,
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

    res.json(formatResponse(true, 'KYC status retrieved', {
      kyc_status: req.user.kyc_status,
      kyc_verified: req.user.kyc_verified,
      kyc_submission: kycSubmission,
      submitted_at: req.user.kyc_submitted_at
    }));
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
      'info'
    );

    // Notify admin
    const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } });
    for (const admin of admins) {
      await createNotification(
        admin._id,
        'New Support Ticket',
        `User ${req.user.full_name} has submitted a new support ticket: ${subject}`,
        'system',
        `/admin/support/${ticketId}`
      );
    }

    res.status(201).json(formatResponse(true, 'Support ticket created successfully!', {
      ticket: supportTicket,
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

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(formatResponse(true, 'Support tickets retrieved successfully', {
      tickets,
      pagination
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching support tickets');
  }
});

// ==================== REFERRAL ENDPOINTS ====================

// Get referral stats
app.get('/api/referrals/stats', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const referrals = await Referral.find({ referrer: userId })
      .populate('referred_user', 'full_name email createdAt balance')
      .sort({ createdAt: -1 })
      .lean();
    
    const totalReferrals = referrals.length;
    const activeReferrals = referrals.filter(r => r.status === 'active').length;
    const totalEarnings = referrals.reduce((sum, r) => sum + (r.earnings || 0), 0);
    const pendingEarnings = referrals
      .filter(r => r.status === 'pending' && !r.earnings_paid)
      .reduce((sum, r) => sum + (r.earnings || 0), 0);

    res.json(formatResponse(true, 'Referral stats retrieved successfully', {
      stats: {
        total_referrals: totalReferrals,
        active_referrals: activeReferrals,
        total_earnings: totalEarnings,
        pending_earnings: pendingEarnings,
        referral_code: req.user.referral_code,
        referral_link: `${config.clientURL}/register?ref=${req.user.referral_code}`
      },
      referrals: referrals.slice(0, 10)
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching referral stats');
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
      folder
    }));
  } catch (error) {
    handleError(res, error, 'Error uploading file');
  }
});

// ==================== ADMIN ENDPOINTS ====================

// Advanced Admin Dashboard Stats
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
  try {
    // Get comprehensive statistics
    const [
      totalUsers,
      newUsersToday,
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
      topPlans
    ] = await Promise.all([
      User.countDocuments({}),
      User.countDocuments({ 
        createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) } 
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
        .populate('user', 'full_name')
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      User.find({})
        .select('full_name email createdAt')
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      InvestmentPlan.find({ is_active: true })
        .sort({ investment_count: -1 })
        .limit(5)
        .lean()
    ]);

    const totalEarnings = earningsResult[0]?.total || 0;
    const platformEarnings = platformFeesResult[0]?.total || 0;
    const referralEarnings = referralEarningsResult[0]?.total || 0;

    // Calculate total platform revenue
    const totalRevenue = platformEarnings;

    // Get daily/weekly/monthly stats
    const today = new Date();
    const startOfWeek = new Date(today.setDate(today.getDate() - today.getDay()));
    const startOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);

    const [weeklyDeposits, weeklyWithdrawals, monthlyStats] = await Promise.all([
      Deposit.aggregate([
        { $match: { 
          status: 'approved',
          createdAt: { $gte: startOfWeek }
        }},
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      Withdrawal.aggregate([
        { $match: { 
          status: 'paid',
          createdAt: { $gte: startOfWeek }
        }},
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]),
      Investment.aggregate([
        { $match: { 
          status: 'active',
          createdAt: { $gte: startOfMonth }
        }},
        { $group: { 
          _id: null, 
          totalInvested: { $sum: '$amount' },
          totalEarnings: { $sum: '$earned_so_far' }
        } }
      ])
    ]);

    const weeklyDepositsTotal = weeklyDeposits[0]?.total || 0;
    const weeklyWithdrawalsTotal = weeklyWithdrawals[0]?.total || 0;
    const monthlyInvested = monthlyStats[0]?.totalInvested || 0;
    const monthlyEarnings = monthlyStats[0]?.totalEarnings || 0;

    const stats = {
      overview: {
        total_users: totalUsers,
        new_users_today: newUsersToday,
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
      period_stats: {
        weekly_deposits: weeklyDepositsTotal,
        weekly_withdrawals: weeklyWithdrawalsTotal,
        monthly_invested: monthlyInvested,
        monthly_earnings: monthlyEarnings
      },
      top_performers: {
        investment_plans: topPlans
      }
    };

    res.json(formatResponse(true, 'Admin dashboard stats retrieved successfully', {
      stats,
      recent_transactions: recentTransactions,
      recent_users: recentUsers,
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

// Get all users (admin) with advanced filtering
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

    // Get additional stats for each user
    const enhancedUsers = await Promise.all(users.map(async (user) => {
      const [investments, deposits, withdrawals, referrals] = await Promise.all([
        Investment.countDocuments({ user: user._id }),
        Deposit.countDocuments({ user: user._id, status: 'approved' }),
        Withdrawal.countDocuments({ user: user._id, status: 'paid' }),
        Referral.countDocuments({ referrer: user._id })
      ]);
      
      return {
        ...user,
        stats: {
          total_investments: investments,
          total_deposits: deposits,
          total_withdrawals: withdrawals,
          total_referrals: referrals,
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
        end_date
      }
    }));
  } catch (error) {
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
      userReferrals,
      totalInvested,
      totalEarned
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
        .populate('referred_user', 'full_name email createdAt balance')
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
      ])
    ]);
    
    const totalInvestedAmount = totalInvested[0]?.total || 0;
    const totalEarnedAmount = totalEarned[0]?.total || 0;
    
    // Calculate user statistics
    const userStats = {
      total_investments: investments.length,
      active_investments: investments.filter(i => i.status === 'active').length,
      total_deposits: deposits.filter(d => d.status === 'approved').length,
      total_withdrawals: withdrawals.filter(w => w.status === 'paid').length,
      total_transactions: transactions.length,
      total_referrals: userReferrals.length,
      total_invested: totalInvestedAmount,
      total_earned: totalEarnedAmount,
      portfolio_value: user.balance + totalEarnedAmount + (user.referral_earnings || 0),
      average_investment: investments.length > 0 ? totalInvestedAmount / investments.length : 0
    };
    
    res.json(formatResponse(true, 'User details retrieved successfully', {
      user,
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
      support_tickets: supportTickets,
      financial_summary: {
        current_balance: user.balance,
        total_earnings: user.total_earnings || 0,
        referral_earnings: user.referral_earnings || 0,
        total_invested: totalInvestedAmount,
        net_profit: totalEarnedAmount - totalInvestedAmount
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching user details');
  }
});

// Get user's referrals
app.get('/api/admin/users/:id/referrals', adminAuth, async (req, res) => {
  try {
    const userId = req.params.id;
    
    const referrals = await Referral.find({ referrer: userId })
      .populate('referred_user', 'full_name email phone balance createdAt')
      .sort({ createdAt: -1 })
      .lean();
    
    const totalReferrals = referrals.length;
    const totalCommission = referrals.reduce((sum, r) => sum + (r.earnings || 0), 0);
    
    res.json(formatResponse(true, 'User referrals retrieved successfully', {
      total_referrals: totalReferrals,
      total_commission: totalCommission,
      referrals,
      stats: {
        active_referrals: referrals.filter(r => r.status === 'active').length,
        pending_referrals: referrals.filter(r => r.status === 'pending').length,
        completed_referrals: referrals.filter(r => r.status === 'completed').length,
        paid_commission: referrals.filter(r => r.earnings_paid).reduce((sum, r) => sum + (r.earnings || 0), 0),
        unpaid_commission: referrals.filter(r => !r.earnings_paid).reduce((sum, r) => sum + (r.earnings || 0), 0)
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching user referrals');
  }
});

// Get user's transactions with images
app.get('/api/admin/users/:id/transactions', adminAuth, async (req, res) => {
  try {
    const userId = req.params.id;
    const { 
      page = 1, 
      limit = 50,
      type,
      start_date,
      end_date,
      min_amount,
      max_amount
    } = req.query;
    
    const query = { user: userId };
    
    if (type) query.type = type;
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
    
    // Get related deposit/investment/withdrawal images
    const enhancedTransactions = await Promise.all(transactions.map(async (transaction) => {
      let proofUrl = null;
      
      if (transaction.related_deposit) {
        const deposit = await Deposit.findById(transaction.related_deposit).select('payment_proof_url');
        proofUrl = deposit?.payment_proof_url;
      } else if (transaction.related_investment) {
        const investment = await Investment.findById(transaction.related_investment).select('payment_proof_url');
        proofUrl = investment?.payment_proof_url;
      } else if (transaction.related_withdrawal) {
        const withdrawal = await Withdrawal.findById(transaction.related_withdrawal).select('transaction_id');
        proofUrl = withdrawal?.transaction_id ? `/uploads/withdrawal-proofs/${withdrawal.transaction_id}` : null;
      }
      
      return {
        ...transaction,
        proof_url: proofUrl,
        proof_available: !!proofUrl
      };
    }));
    
    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };
    
    res.json(formatResponse(true, 'User transactions retrieved successfully', {
      transactions: enhancedTransactions,
      pagination,
      stats: {
        total_transactions: total,
        total_deposits: transactions.filter(t => t.type === 'deposit').length,
        total_withdrawals: transactions.filter(t => t.type === 'withdrawal').length,
        total_investments: transactions.filter(t => t.type === 'investment').length,
        total_earnings: transactions.filter(t => t.type === 'earning').reduce((sum, t) => sum + t.amount, 0),
        total_referrals: transactions.filter(t => t.type === 'referral').reduce((sum, t) => sum + t.amount, 0)
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching user transactions');
  }
});

// Get pending investments (admin) with images
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

// Approve investment (admin) with notification
app.post('/api/admin/investments/:id/approve', adminAuth, async (req, res) => {
  try {
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
      '/investments'
    );

    // Send email notification
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
       </ul>
       <p><a href="${config.clientURL}/investments">View Investment</a></p>`
    );

    res.json(formatResponse(true, 'Investment approved successfully', {
      investment,
      message: 'Investment approved and user notified'
    }));
  } catch (error) {
    handleError(res, error, 'Error approving investment');
  }
});

// Reject investment (admin)
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

    // Update investment
    investment.status = 'rejected';
    investment.approved_by = adminId;
    investment.remarks = remarks;
    
    await investment.save();

    // Refund user balance
    await User.findByIdAndUpdate(investment.user._id, {
      $inc: { balance: investment.amount }
    });

    // Create transaction for refund
    await createTransaction(
      investment.user._id,
      'refund',
      investment.amount,
      `Refund for rejected investment`,
      'completed',
      { investment_id: investment._id }
    );

    // Create notification
    await createNotification(
      investment.user._id,
      'Investment Rejected',
      `Your investment of ₦${investment.amount.toLocaleString()} has been rejected. Reason: ${remarks}`,
      'error',
      '/investments'
    );

    res.json(formatResponse(true, 'Investment rejected successfully', {
      investment
    }));
  } catch (error) {
    handleError(res, error, 'Error rejecting investment');
  }
});

// Get pending deposits (admin) with images
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

// Approve deposit (admin) with notification
app.post('/api/admin/deposits/:id/approve', adminAuth, async (req, res) => {
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

    // Update user balance
    await User.findByIdAndUpdate(deposit.user._id, {
      $inc: { balance: deposit.amount }
    });

    // Create transaction
    await createTransaction(
      deposit.user._id,
      'deposit',
      deposit.amount,
      `Deposit via ${deposit.payment_method}`,
      'completed',
      { deposit_id: deposit._id }
    );

    // Create notification
    await createNotification(
      deposit.user._id,
      'Deposit Approved',
      `Your deposit of ₦${deposit.amount.toLocaleString()} has been approved and credited to your account.`,
      'success',
      '/deposits'
    );

    // Send email notification
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
       </ul>
       <p><a href="${config.clientURL}/deposits">View Deposit</a></p>`
    );

    res.json(formatResponse(true, 'Deposit approved successfully', {
      deposit,
      message: 'Deposit approved and user notified'
    }));
  } catch (error) {
    handleError(res, error, 'Error approving deposit');
  }
});

// Reject deposit (admin)
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
      '/deposits'
    );

    res.json(formatResponse(true, 'Deposit rejected successfully', {
      deposit
    }));
  } catch (error) {
    handleError(res, error, 'Error rejecting deposit');
  }
});

// Get pending withdrawals (admin)
app.get('/api/admin/pending-withdrawals', adminAuth, async (req, res) => {
  try {
    const pendingWithdrawals = await Withdrawal.find({ status: 'pending' })
      .populate('user', 'full_name email phone balance')
      .sort({ createdAt: -1 })
      .lean();

    res.json(formatResponse(true, 'Pending withdrawals retrieved successfully', {
      withdrawals: pendingWithdrawals,
      count: pendingWithdrawals.length,
      total_amount: pendingWithdrawals.reduce((sum, wdl) => sum + wdl.amount, 0),
      total_net_amount: pendingWithdrawals.reduce((sum, wdl) => sum + wdl.net_amount, 0),
      total_fees: pendingWithdrawals.reduce((sum, wdl) => sum + wdl.platform_fee, 0)
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching pending withdrawals');
  }
});

// Approve withdrawal (admin) with notification
app.post('/api/admin/withdrawals/:id/approve', adminAuth, [
  body('transaction_id').optional().trim()
], async (req, res) => {
  try {
    const withdrawalId = req.params.id;
    const adminId = req.user._id;
    const { remarks, transaction_id } = req.body;

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

    // Update transaction status
    await Transaction.findOneAndUpdate(
      { related_withdrawal: withdrawalId },
      { status: 'completed' }
    );

    // Create notification
    await createNotification(
      withdrawal.user._id,
      'Withdrawal Approved',
      `Your withdrawal of ₦${withdrawal.amount.toLocaleString()} has been approved and processed. Transaction ID: ${transaction_id || 'N/A'}`,
      'success',
      '/withdrawals'
    );

    // Send email notification
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
       </ul>
       <p><a href="${config.clientURL}/withdrawals">View Withdrawal</a></p>`
    );

    res.json(formatResponse(true, 'Withdrawal approved successfully', {
      withdrawal,
      message: 'Withdrawal processed and user notified'
    }));
  } catch (error) {
    handleError(res, error, 'Error approving withdrawal');
  }
});

// Reject withdrawal (admin)
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

    // Update withdrawal
    withdrawal.status = 'rejected';
    withdrawal.approved_by = adminId;
    withdrawal.admin_notes = remarks;
    
    await withdrawal.save();

    // Refund user balance
    await User.findByIdAndUpdate(withdrawal.user._id, {
      $inc: { balance: withdrawal.amount }
    });

    // Update transaction status
    await Transaction.findOneAndUpdate(
      { related_withdrawal: withdrawalId },
      { status: 'cancelled' }
    );

    // Create transaction for refund
    await createTransaction(
      withdrawal.user._id,
      'refund',
      withdrawal.amount,
      `Refund for rejected withdrawal`,
      'completed',
      { withdrawal_id: withdrawal._id }
    );

    // Create notification
    await createNotification(
      withdrawal.user._id,
      'Withdrawal Rejected',
      `Your withdrawal of ₦${withdrawal.amount.toLocaleString()} has been rejected. Reason: ${remarks}`,
      'error',
      '/withdrawals'
    );

    res.json(formatResponse(true, 'Withdrawal rejected successfully', {
      withdrawal
    }));
  } catch (error) {
    handleError(res, error, 'Error rejecting withdrawal');
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
      max_amount
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
      pagination,
      summary: {
        total_transactions: total,
        total_amount: transactions.reduce((sum, t) => sum + t.amount, 0),
        by_type: transactions.reduce((acc, t) => {
          acc[t.type] = (acc[t.type] || 0) + 1;
          return acc;
        }, {})
      }
    }));
  } catch (error) {
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

    res.json(formatResponse(true, 'Pending KYC submissions retrieved successfully', {
      kyc_submissions: pendingKYC,
      count: pendingKYC.length
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching pending KYC');
  }
});

// Approve KYC
app.post('/api/admin/kyc/:id/approve', adminAuth, async (req, res) => {
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
      'kyc'
    );

    // Send email
    await sendEmail(
      kyc.user.email,
      'KYC Verification Approved',
      `<h2>KYC Verification Approved</h2>
       <p>Your KYC documents have been successfully verified and approved.</p>
       <p>You now have full access to all platform features, including withdrawals.</p>
       <p>Thank you for completing the verification process.</p>`
    );

    res.json(formatResponse(true, 'KYC approved successfully', {
      kyc
    }));
  } catch (error) {
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

    // Create notification
    await createNotification(
      kyc.user._id,
      'KYC Rejected',
      `Your KYC documents have been rejected. Reason: ${rejection_reason}. Please submit new documents.`,
      'kyc'
    );

    res.json(formatResponse(true, 'KYC rejected successfully', {
      kyc
    }));
  } catch (error) {
    handleError(res, error, 'Error rejecting KYC');
  }
});

// Update user role (admin)
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

    res.json(formatResponse(true, 'User role updated successfully', { user }));
  } catch (error) {
    handleError(res, error, 'Error updating user role');
  }
});

// Update user status (activate/deactivate)
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

    res.json(formatResponse(true, 
      is_active ? 'User activated successfully' : 'User deactivated successfully', 
      { user }
    ));
  } catch (error) {
    handleError(res, error, 'Error updating user status');
  }
});

// Update user balance (admin)
app.put('/api/admin/users/:id/balance', adminAuth, [
  body('amount').isFloat(),
  body('type').isIn(['add', 'subtract', 'set']),
  body('description').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.params.id;
    const { amount, type, description } = req.body;
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

    // Update user balance
    user.balance = newBalance;
    await user.save();

    // Create transaction
    await createTransaction(
      userId,
      transactionType,
      type === 'subtract' ? -parseFloat(amount) : parseFloat(amount),
      transactionDescription,
      'completed',
      { admin_id: adminId, adjustment_type: type }
    );

    // Create notification
    await createNotification(
      userId,
      'Balance Updated',
      `Your account balance has been updated. New balance: ₦${newBalance.toLocaleString()}`,
      'info'
    );

    res.json(formatResponse(true, 'User balance updated successfully', {
      user: {
        id: user._id,
        email: user.email,
        previous_balance: user.balance - (type === 'add' ? parseFloat(amount) : type === 'subtract' ? -parseFloat(amount) : 0),
        new_balance: newBalance,
        change_type: type,
        change_amount: amount
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error updating user balance');
  }
});

// ==================== NOTIFICATION ENDPOINTS ====================

// Get user notifications
app.get('/api/notifications', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { unread_only, page = 1, limit = 20 } = req.query;
    
    const query = { user: userId };
    if (unread_only === 'true') {
      query.is_read = false;
    }
    
    const skip = (page - 1) * limit;
    
    const [notifications, total] = await Promise.all([
      Notification.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Notification.countDocuments(query)
    ]);

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(formatResponse(true, 'Notifications retrieved successfully', {
      notifications,
      pagination,
      unread_count: notifications.filter(n => !n.is_read).length
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

    const notification = await Notification.findOne({
      _id: notificationId,
      user: userId
    });
    
    if (!notification) {
      return res.status(404).json(formatResponse(false, 'Notification not found'));
    }

    notification.is_read = true;
    await notification.save();

    res.json(formatResponse(true, 'Notification marked as read'));
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
      { $set: { is_read: true } }
    );

    res.json(formatResponse(true, 'All notifications marked as read'));
  } catch (error) {
    handleError(res, error, 'Error marking all notifications as read');
  }
});

// ==================== CRON JOBS ====================

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

    for (const investment of activeInvestments) {
      try {
        const dailyEarning = investment.daily_earnings || (investment.amount * investment.plan.daily_interest / 100);
        
        // Update investment earnings
        investment.earned_so_far += dailyEarning;
        investment.last_earning_date = new Date();
        await investment.save();

        // Update user balance and total earnings
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
          `Daily earnings from investment`,
          'completed',
          { investment_id: investment._id }
        );
        
        totalEarnings += dailyEarning;
        processedCount++;

      } catch (investmentError) {
        console.error(`Error processing investment:`, investmentError);
      }
    }

    // Check for completed investments
    const completedInvestments = await Investment.find({
      status: 'active',
      end_date: { $lte: new Date() }
    });

    for (const investment of completedInvestments) {
      investment.status = 'completed';
      await investment.save();
      
      await createNotification(
        investment.user._id,
        'Investment Completed',
        `Your investment has completed successfully. Total earnings: ₦${investment.earned_so_far.toLocaleString()}`,
        'success',
        '/investments'
      );
    }

    console.log(`✅ Daily earnings calculated. Processed: ${processedCount}, Total: ₦${totalEarnings.toLocaleString()}`);
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

    for (const investment of completedInvestments) {
      try {
        const userId = investment.user._id;
        const planId = investment.plan._id;
        
        // Check if user has sufficient balance
        const user = await User.findById(userId);
        if (!user || user.balance < investment.amount) {
          console.log(`User ${userId} has insufficient balance for auto-renew`);
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
        
        // Create transaction
        await createTransaction(
          userId,
          'investment',
          -investment.amount,
          `Auto-renew investment`,
          'completed',
          { investment_id: newInvestment._id }
        );

        // Mark original investment as renewed
        investment.auto_renewed = true;
        await investment.save();

        // Create notification
        await createNotification(
          userId,
          'Investment Auto-Renewed',
          `Your investment of ₦${investment.amount.toLocaleString()} has been automatically renewed.`,
          'investment',
          '/investments'
        );

        console.log(`Auto-renewed investment ${investment._id} for user ${userId}`);
      } catch (error) {
        console.error(`Error auto-renewing investment:`, error);
      }
    }

    console.log(`✅ Auto-renew completed. Processed: ${completedInvestments.length} investments`);
  } catch (error) {
    console.error('❌ Error processing auto-renew:', error);
  }
});

// Cleanup expired data
cron.schedule('0 2 * * *', async () => {
  try {
    console.log('🔄 Cleaning up expired data...');
    
    const now = new Date();
    
    // Clean up old notifications (older than 90 days)
    const ninetyDaysAgo = new Date();
    ninetyDaysAgo.setDate(ninetyDaysAgo.getDate() - 90);
    
    await Notification.deleteMany({
      createdAt: { $lt: ninetyDaysAgo },
      is_read: true
    });
    
    // Clean up expired password reset tokens
    await User.updateMany({
      password_reset_expires: { $lt: now }
    }, {
      $unset: {
        password_reset_token: 1,
        password_reset_expires: 1
      }
    });
    
    console.log('✅ Cleanup completed');
  } catch (error) {
    console.error('❌ Error during cleanup:', error);
  }
});

// ==================== ERROR HANDLING ====================

// 404 handler
app.use((req, res) => {
  res.status(404).json(formatResponse(false, 'Endpoint not found'));
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Global error:', err);
  
  if (err instanceof multer.MulterError) {
    return res.status(400).json(formatResponse(false, `File upload error: ${err.message}`));
  }
  
  res.status(500).json(formatResponse(false, 'Internal server error'));
});

// ==================== SERVER INITIALIZATION ====================

const startServer = async () => {
  try {
    // Initialize database
    await initializeDatabase();
    
    // Start server
    const server = app.listen(config.port, '0.0.0.0', () => {
      console.log(`
🎯 RAW WEALTHY BACKEND v36.0 - ADVANCED EDITION
=============================================
🌐 Server running on port ${config.port}
🚀 Environment: ${config.nodeEnv}
📊 Health Check: /health
🔗 API Base: /api
💾 Database: MongoDB Connected
🛡️ Security: Enhanced Protection
📧 Email: ${config.emailEnabled ? 'Enabled' : 'Disabled'}

✅ ENHANCED FEATURES:
   ✅ Advanced Admin Dashboard with Real-time Analytics
   ✅ User Details & Complete Transaction History
   ✅ Transaction Images Viewing for Admin
   ✅ Referral Tracking & Commission Management
   ✅ Wallet Balance Management
   ✅ Investment Plan Earnings Tracking
   ✅ Automated Notifications System
   ✅ Email Notifications for All Actions
   ✅ Forgot Password Functionality
   ✅ Bank Details Update Notifications
   ✅ KYC Verification System
   ✅ Support Ticket Management
   ✅ File Upload System with Images
   ✅ Advanced Filtering & Search
   ✅ Real-time Dashboard Updates
   ✅ Automated Cron Jobs
   ✅ Comprehensive Reporting

🚀 READY FOR PRODUCTION DEPLOYMENT WITH FULL ADMIN CONTROL!
      `);
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      console.log('SIGTERM received, shutting down gracefully');
      server.close(() => {
        mongoose.connection.close();
        console.log('Process terminated');
        process.exit(0);
      });
    });

    process.on('SIGINT', () => {
      console.log('SIGINT received, shutting down gracefully');
      server.close(() => {
        mongoose.connection.close();
        console.log('Process terminated');
        process.exit(0);
      });
    });

  } catch (error) {
    console.error('❌ Server initialization failed:', error);
    process.exit(1);
  }
};

// Start the server
startServer();

export default app;
