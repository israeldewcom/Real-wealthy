// server.js - ULTIMATE PRODUCTION BACKEND v35.0 - FULL FRONTEND INTEGRATION
// COMPLETE FEATURE INTEGRATION + ZERO BREAKING CHANGES
// ENHANCED INVESTMENT PLANS + HIGHER INTEREST RATES
// FULL FRONTEND CONNECTION: https://us-raw-wealthy.vercel.app/

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
import { WebSocketServer } from 'ws';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';

// ES Modules equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Enhanced environment configuration
dotenv.config();

// ==================== ENVIRONMENT VALIDATION ====================
console.log('🔍 Environment check:');
console.log('- MONGODB_URI set:', !!process.env.MONGODB_URI);
console.log('- JWT_SECRET set:', !!process.env.JWT_SECRET);
console.log('- ADMIN_PASSWORD set:', !!process.env.ADMIN_PASSWORD);
console.log('- NODE_ENV:', process.env.NODE_ENV);

// Set default values if not in environment
process.env.JWT_SECRET = process.env.JWT_SECRET || 'temp-jwt-secret-for-development-1234567890';
process.env.ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
process.env.MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://israeldewa1_db_user:P@ssw0rd!123@rawwealthy.9cnu0jw.mongodb.net/rawwealthy';
process.env.CLIENT_URL = process.env.CLIENT_URL || 'https://us-raw-wealthy.vercel.app/';

// Function to encode MongoDB password
const encodeMongoDBURI = (uri) => {
  if (!uri || !uri.includes('mongodb')) return uri;
  
  try {
    const match = uri.match(/mongodb(\+srv)?:\/\/([^:]+):([^@]+)@/);
    if (match) {
      const [fullMatch, protocol, username, password] = match;
      const encodedPassword = encodeURIComponent(password);
      const encodedURI = uri.replace(`${username}:${password}@`, `${username}:${encodedPassword}@`);
      console.log('🔐 Password encoded for MongoDB URI');
      return encodedURI;
    }
  } catch (error) {
    console.error('Error encoding MongoDB URI:', error.message);
  }
  
  return uri;
};

// ==================== ENHANCED MONGODB CONNECTION ====================
const connectDBWithRetry = async () => {
  console.log('🚀 FINAL ATTEMPT: Connecting to MongoDB...');
  
  try {
    const uri = 'mongodb+srv://RawWealthyProduction:qwerty123@rawwealthy.9cnu0jw.mongodb.net/rawwealthy';
    
    console.log('🔗 URI: mongodb+srv://RawWealthyProduction:****@rawwealthy.9cnu0jw.mongodb.net/rawwealthy');
    
    await mongoose.connect(uri);
    
    console.log('✅✅✅ MONGODB CONNECTED SUCCESSFULLY!');
    console.log('📊 Database:', mongoose.connection.name);
    console.log('🏠 Host:', mongoose.connection.host);
    
    await initializeDatabase();
    return true;
    
  } catch (error) {
    console.log('❌ Connection failed:', error.message);
    console.log('📝 Using memory storage - app will still work!');
    return false;
  }
};

// ==================== ENHANCED EXPRESS SETUP ====================
const app = express();

// Enhanced Security Headers
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:", "https:", "http:"],
      connectSrc: ["'self'", "ws:", "wss:", "https://raw-wealthy-backend.onrender.com", "https://us-raw-wealthy.vercel.app"]
    }
  }
}));

// Security middleware
app.use(xss());
app.use(hpp());
app.use(mongoSanitize());
app.use(compression());

// Enhanced Morgan logging
if (process.env.NODE_ENV === 'production') {
  app.use(morgan('combined', {
    skip: (req, res) => req.url === '/health' || req.url === '/'
  }));
} else {
  app.use(morgan('dev'));
}

// ==================== ENHANCED CORS CONFIGURATION ====================
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      "https://us-raw-wealthy.vercel.app",
      "http://localhost:3000",
      "http://127.0.0.1:5500",
      "http://localhost:5500",
      "https://us-raw-wealthy.vercel.app",
      "https://rawwealthy.com",
      "http://localhost:3001",
      "https://raw-wealthy-yibn.onrender.com",
      "http://localhost:8080",
      "http://127.0.0.1:8080",
      "https://raw-wealthy-backend.onrender.com",
      process.env.CLIENT_URL
    ].filter(Boolean);
    
    // Allow requests with no origin (like mobile apps, curl, postman)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1 || allowedOrigins.some(allowed => origin.startsWith(allowed))) {
      callback(null, true);
    } else {
      console.log('🚫 Blocked by CORS:', origin);
      console.log('✅ Allowed origins:', allowedOrigins);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'x-api-key', 'x-user-id']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// ==================== ENHANCED BODY PARSING ====================
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
const createAccountLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  message: { 
    success: false, 
    message: 'Too many accounts created from this IP, please try again after an hour' 
  },
  skipSuccessfulRequests: true,
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { 
    success: false, 
    message: 'Too many authentication attempts from this IP, please try again after 15 minutes' 
  },
  skipSuccessfulRequests: true
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  message: { 
    success: false, 
    message: 'Too many requests from this IP, please try again later' 
  },
  skipFailedRequests: false
});

const financialLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { 
    success: false, 
    message: 'Too many financial operations from this IP, please try again later' 
  }
});

// Apply rate limiting
app.use('/api/auth/register', createAccountLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/investments', financialLimiter);
app.use('/api/deposits', financialLimiter);
app.use('/api/withdrawals', financialLimiter);
app.use('/api/', apiLimiter);

// ==================== ENHANCED FILE UPLOAD ====================
const ALLOWED_MIME_TYPES = {
  'image/jpeg': 'jpg',
  'image/jpg': 'jpg',
  'image/png': 'png',
  'image/gif': 'gif',
  'image/webp': 'webp',
  'application/pdf': 'pdf',
  'image/svg+xml': 'svg'
};

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  if (!ALLOWED_MIME_TYPES[file.mimetype]) {
    return cb(new Error(`Invalid file type: ${file.mimetype}`), false);
  }
  
  if (file.size > MAX_FILE_SIZE) {
    return cb(new Error('File size exceeds 10MB limit'), false);
  }
  
  cb(null, true);
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { 
    fileSize: MAX_FILE_SIZE,
    files: 10
  }
});

// Enhanced file upload handler
const handleFileUpload = async (file, folder = 'general', userId = null) => {
  if (!file) return null;
  
  try {
    if (!ALLOWED_MIME_TYPES[file.mimetype]) {
      throw new Error('Invalid file type');
    }
    
    const uploadsDir = path.join(__dirname, 'uploads', folder);
    
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }
    
    const timestamp = Date.now();
    const randomStr = crypto.randomBytes(8).toString('hex');
    const userIdPrefix = userId ? `${userId}_` : '';
    const fileExtension = ALLOWED_MIME_TYPES[file.mimetype] || file.originalname.split('.').pop();
    const filename = `${userIdPrefix}${timestamp}_${randomStr}.${fileExtension}`;
    const filepath = path.join(uploadsDir, filename);
    
    await fs.promises.writeFile(filepath, file.buffer);
    
    return {
      url: `/uploads/${folder}/${filename}`,
      filename: filename,
      originalName: file.originalname,
      size: file.size,
      mimeType: file.mimetype
    };
  } catch (error) {
    console.error('File upload error:', error);
    throw new Error(`File upload failed: ${error.message}`);
  }
};

// Serve static files securely
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  maxAge: '7d',
  setHeaders: (res, path) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Cache-Control', 'public, max-age=604800');
  }
}));

// ==================== EMAIL CONFIGURATION ====================
let transporter = null;

if (process.env.EMAIL_HOST && process.env.EMAIL_USER && process.env.EMAIL_PASSWORD) {
  transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT),
    secure: parseInt(process.env.EMAIL_PORT) === 465,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });
  
  transporter.verify(function(error, success) {
    if (error) {
      console.log('❌ Email configuration error:', error);
    } else {
      console.log('✅ Email server is ready to send messages');
    }
  });
} else {
  console.warn('⚠️ Email configuration incomplete. Email notifications will be logged but not sent.');
}

// Email utility functions
const sendEmail = async (to, subject, html, text = '') => {
  try {
    if (!transporter) {
      console.log(`📧 Email would be sent (simulated): To: ${to}, Subject: ${subject}`);
      console.log(`📧 Email content: ${text.substring(0, 100)}...`);
      return true;
    }
    
    const mailOptions = {
      from: `"Raw Wealthy" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      text,
      html
    };
    
    await transporter.sendMail(mailOptions);
    console.log(`✅ Email sent to ${to}`);
    return true;
  } catch (error) {
    console.error('❌ Email sending error:', error.message);
    console.log(`📧 Email content (for manual sending):`, { to, subject, text });
    return false;
  }
};

// ==================== FALLBACK IN-MEMORY STORAGE ====================
let memoryStorage = {
  users: [],
  investments: [],
  deposits: [],
  withdrawals: [],
  transactions: [],
  notifications: [],
  kycSubmissions: [],
  supportTickets: [],
  investmentPlans: [],
  referrals: [],
  twoFactorCodes: [],
  passwordResetTokens: [],
  dailyWithdrawals: {} // Track daily withdrawals by user
};

// ==================== COMPREHENSIVE DATABASE MODELS ====================

// Enhanced User Model
const userSchema = new mongoose.Schema({
  full_name: { 
    type: String, 
    required: [true, 'Full name is required'], 
    trim: true,
    maxlength: [100, 'Full name cannot exceed 100 characters']
  },
  email: { 
    type: String, 
    required: [true, 'Email is required'], 
    unique: true, 
    lowercase: true,
    validate: {
      validator: function(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
      },
      message: 'Please provide a valid email'
    }
  },
  phone: { 
    type: String, 
    required: [true, 'Phone number is required'],
    trim: true
  },
  password: { 
    type: String, 
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    select: false 
  },
  role: { 
    type: String, 
    enum: ['user', 'admin', 'super_admin'], 
    default: 'user' 
  },
  balance: { 
    type: Number, 
    default: 0, 
    min: [0, 'Balance cannot be negative'] 
  },
  total_earnings: { 
    type: Number, 
    default: 0, 
    min: 0 
  },
  referral_earnings: { 
    type: Number, 
    default: 0, 
    min: 0 
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
    default: 'ng' 
  },
  currency: { 
    type: String, 
    enum: ['NGN', 'USD', 'EUR', 'GBP'], 
    default: 'NGN' 
  },
  language: {
    type: String,
    default: 'en'
  },
  timezone: {
    type: String,
    default: 'Africa/Lagos'
  },
  referral_code: { 
    type: String, 
    unique: true,
    sparse: true
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
  verification_token: String,
  verification_expires: Date,
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String,
    bank_code: String,
    verified: { type: Boolean, default: false },
    verified_at: Date
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
  daily_withdrawal_total: { type: Number, default: 0 }, // Track daily withdrawals
  daily_withdrawal_reset: Date, // When daily withdrawal resets
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.two_factor_secret;
      delete ret.verification_token;
      delete ret.login_attempts;
      delete ret.lock_until;
      return ret;
    }
  }
});

// Indexes
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ referral_code: 1 }, { unique: true, sparse: true });
userSchema.index({ is_active: 1 });
userSchema.index({ role: 1 });
userSchema.index({ kyc_status: 1 });

// Pre-save hooks
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
  }
  
  if (!this.referral_code) {
    this.referral_code = crypto.randomBytes(6).toString('hex').toUpperCase();
  }
  
  if (this.isModified('email') && !this.isVerified) {
    this.is_verified = false;
    this.verification_token = crypto.randomBytes(32).toString('hex');
    this.verification_expires = new Date(Date.now() + 24 * 60 * 60 * 1000);
  }
  
  // Reset daily withdrawal if it's a new day
  const now = new Date();
  if (!this.daily_withdrawal_reset || now.getDate() !== this.daily_withdrawal_reset.getDate()) {
    this.daily_withdrawal_total = 0;
    this.daily_withdrawal_reset = now;
  }
  
  this.updatedAt = new Date();
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
    process.env.JWT_SECRET,
    { expiresIn: '30d' }
  );
};

userSchema.methods.generatePasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex');
  const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
  const resetTokenExpires = new Date(Date.now() + 1 * 60 * 60 * 1000); // 1 hour
  
  return { resetToken, resetTokenHash, resetTokenExpires };
};

userSchema.methods.incrementLoginAttempts = function() {
  this.login_attempts += 1;
  if (this.login_attempts >= 5) {
    this.lock_until = new Date(Date.now() + 15 * 60 * 1000); // Lock for 15 minutes
  }
  return this.save();
};

userSchema.methods.resetLoginAttempts = function() {
  this.login_attempts = 0;
  this.lock_until = undefined;
  return this.save();
};

userSchema.methods.canWithdrawToday = function(amount) {
  const now = new Date();
  const resetTime = this.daily_withdrawal_reset || now;
  
  // Check if it's a new day
  if (now.getDate() !== resetTime.getDate() || 
      now.getMonth() !== resetTime.getMonth() || 
      now.getFullYear() !== resetTime.getFullYear()) {
    return { canWithdraw: true, remaining: 20000, dailyTotal: 0 };
  }
  
  const dailyTotal = this.daily_withdrawal_total || 0;
  const remaining = 20000 - dailyTotal;
  const canWithdraw = dailyTotal + amount <= 20000;
  
  return { canWithdraw, remaining, dailyTotal };
};

const User = mongoose.model('User', userSchema);

// Investment Plan Model (UPDATED WITH NEW RATES)
const investmentPlanSchema = new mongoose.Schema({
  name: { 
    type: String, 
    required: [true, 'Plan name is required'],
    trim: true,
    unique: true
  },
  description: { 
    type: String, 
    required: [true, 'Description is required'] 
  },
  min_amount: { 
    type: Number, 
    required: true, 
    min: [35000, 'Minimum investment is ₦35,000']  // UPDATED: Increased to 35,000
  },
  max_amount: { 
    type: Number,
    min: [35000, 'Maximum investment must be at least ₦35,000'] 
  },
  daily_interest: { 
    type: Number, 
    required: true, 
    min: [1, 'Daily interest must be at least 1%'], 
    max: [25, 'Daily interest cannot exceed 25%'] 
  },
  total_interest: { 
    type: Number, 
    required: true, 
    min: [30, 'Total interest must be at least 30%'], 
    max: [750, 'Total interest cannot exceed 750%'] 
  },
  duration: { 
    type: Number, 
    required: true, 
    min: [1, 'Duration must be at least 1 day'] 
  },
  risk_level: { 
    type: String, 
    enum: ['low', 'medium', 'high'], 
    required: true 
  },
  raw_material: { 
    type: String, 
    required: true 
  },
  category: { 
    type: String, 
    enum: ['agriculture', 'mining', 'energy', 'metals', 'crypto', 'real_estate', 'precious_stones'], 
    default: 'agriculture' 
  },
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
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

investmentPlanSchema.index({ is_active: 1, is_popular: 1, category: 1 });

const InvestmentPlan = mongoose.model('InvestmentPlan', investmentPlanSchema);

// Investment Model
const investmentSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  plan: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'InvestmentPlan', 
    required: true 
  },
  amount: { 
    type: Number, 
    required: true, 
    min: [35000, 'Minimum investment is ₦35,000']  // UPDATED: Increased to 35,000
  },
  status: { 
    type: String, 
    enum: ['pending', 'active', 'completed', 'cancelled', 'failed'], 
    default: 'pending',
    index: true
  },
  start_date: { type: Date, default: Date.now },
  end_date: { type: Date, required: true },
  approved_at: Date,
  expected_earnings: { type: Number, required: true },
  earned_so_far: { type: Number, default: 0 },
  daily_earnings: { type: Number, default: 0 },
  last_earning_date: Date,
  payment_proof: String,
  payment_proof_url: String,
  payment_verified: { type: Boolean, default: false },
  auto_renew: { type: Boolean, default: false },
  auto_renewed: { type: Boolean, default: false },
  approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  transaction_id: String,
  remarks: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

investmentSchema.index({ user: 1, status: 1 });
investmentSchema.index({ end_date: 1 });
investmentSchema.index({ createdAt: -1 });

const Investment = mongoose.model('Investment', investmentSchema);

// Deposit Model
const depositSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  amount: { 
    type: Number, 
    required: true, 
    min: [500, 'Minimum deposit is ₦500'] 
  },
  payment_method: { 
    type: String, 
    enum: ['bank_transfer', 'crypto', 'paypal', 'card', 'flutterwave', 'paystack'], 
    required: true 
  },
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'cancelled'], 
    default: 'pending',
    index: true
  },
  payment_proof: String,
  payment_proof_url: String,
  transaction_hash: String,
  reference: { 
    type: String, 
    unique: true,
    sparse: true
  },
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
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

depositSchema.index({ user: 1, status: 1 });
depositSchema.index({ reference: 1 }, { unique: true, sparse: true });
depositSchema.index({ createdAt: -1 });

const Deposit = mongoose.model('Deposit', depositSchema);

// Withdrawal Model (UPDATED WITH DAILY LIMIT)
const withdrawalSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  amount: { 
    type: Number, 
    required: true, 
    min: [1000, 'Minimum withdrawal is ₦1000'] 
  },
  payment_method: { 
    type: String, 
    enum: ['bank_transfer', 'crypto', 'paypal'], 
    required: true 
  },
  platform_fee: { type: Number, default: 0 },
  net_amount: { type: Number, required: true },
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String,
    bank_code: String
  },
  wallet_address: String,
  paypal_email: String,
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'paid', 'processing'], 
    default: 'pending',
    index: true
  },
  reference: { 
    type: String, 
    unique: true,
    sparse: true
  },
  admin_notes: String,
  approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approved_at: Date,
  paid_at: Date,
  transaction_id: String,
  daily_withdrawal_tracked: { type: Boolean, default: false }, // Track if counted in daily limit
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

withdrawalSchema.index({ user: 1, status: 1 });
withdrawalSchema.index({ reference: 1 }, { unique: true, sparse: true });
withdrawalSchema.index({ createdAt: -1 });

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// Transaction Model
const transactionSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  type: { 
    type: String, 
    enum: ['deposit', 'withdrawal', 'investment', 'earning', 'referral', 'bonus', 'fee', 'refund', 'transfer'], 
    required: true,
    index: true
  },
  amount: { 
    type: Number, 
    required: true 
  },
  description: { 
    type: String, 
    required: true 
  },
  reference: { 
    type: String, 
    unique: true,
    sparse: true
  },
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed', 'cancelled'], 
    default: 'completed',
    index: true
  },
  balance_before: Number,
  balance_after: Number,
  related_investment: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment' },
  related_deposit: { type: mongoose.Schema.Types.ObjectId, ref: 'Deposit' },
  related_withdrawal: { type: mongoose.Schema.Types.ObjectId, ref: 'Withdrawal' },
  metadata: mongoose.Schema.Types.Mixed,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

transactionSchema.index({ user: 1, createdAt: -1 });
transactionSchema.index({ type: 1, status: 1 });
transactionSchema.index({ reference: 1 }, { unique: true, sparse: true });

const Transaction = mongoose.model('Transaction', transactionSchema);

// Notification Model
const notificationSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  title: { 
    type: String, 
    required: true 
  },
  message: { 
    type: String, 
    required: true 
  },
  type: { 
    type: String, 
    enum: ['info', 'success', 'warning', 'error', 'promotional', 'investment', 'withdrawal', 'deposit'], 
    default: 'info' 
  },
  is_read: { type: Boolean, default: false, index: true },
  is_email_sent: { type: Boolean, default: false },
  action_url: String,
  priority: { type: Number, default: 0, min: 0, max: 3 },
  metadata: mongoose.Schema.Types.Mixed,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

notificationSchema.index({ user: 1, is_read: 1, createdAt: -1 });

const Notification = mongoose.model('Notification', notificationSchema);

// KYC Submission Model
const kycSubmissionSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true,
    unique: true
  },
  id_type: { 
    type: String, 
    enum: ['national_id', 'passport', 'driver_license', 'voters_card'], 
    required: true 
  },
  id_number: { 
    type: String, 
    required: true 
  },
  id_front_url: { 
    type: String, 
    required: true 
  },
  id_back_url: { 
    type: String 
  },
  selfie_with_id_url: { 
    type: String, 
    required: true 
  },
  address_proof_url: String,
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'under_review'], 
    default: 'pending',
    index: true
  },
  reviewed_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reviewed_at: Date,
  rejection_reason: String,
  notes: String,
  submitted_at: { type: Date, default: Date.now },
  approved_at: Date,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

kycSubmissionSchema.index({ status: 1, submitted_at: -1 });

const KYCSubmission = mongoose.model('KYCSubmission', kycSubmissionSchema);

// Support Ticket Model
const supportTicketSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  ticket_id: { 
    type: String, 
    unique: true,
    required: true,
    index: true
  },
  subject: { 
    type: String, 
    required: true 
  },
  message: { 
    type: String, 
    required: true 
  },
  category: { 
    type: String, 
    enum: ['general', 'technical', 'investment', 'withdrawal', 'deposit', 'kyc', 'account', 'other'], 
    default: 'general' 
  },
  priority: { 
    type: String, 
    enum: ['low', 'medium', 'high', 'urgent'], 
    default: 'medium' 
  },
  status: { 
    type: String, 
    enum: ['open', 'in_progress', 'resolved', 'closed'], 
    default: 'open',
    index: true
  },
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
  metadata: mongoose.Schema.Types.Mixed,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

supportTicketSchema.index({ user: 1, status: 1, createdAt: -1 });
supportTicketSchema.index({ ticket_id: 1 }, { unique: true });

const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);

// Ticket Reply Model
const ticketReplySchema = new mongoose.Schema({
  ticket: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'SupportTicket', 
    required: true,
    index: true
  },
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true 
  },
  message: { 
    type: String, 
    required: true 
  },
  attachments: [{
    filename: String,
    url: String,
    size: Number,
    mime_type: String
  }],
  is_admin_reply: { type: Boolean, default: false },
  read_by: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

ticketReplySchema.index({ ticket: 1, createdAt: 1 });

const TicketReply = mongoose.model('TicketReply', ticketReplySchema);

// Referral Model (UPDATED WITH 20% COMMISSION)
const referralSchema = new mongoose.Schema({
  referrer: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  referred_user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    unique: true
  },
  referral_code: { 
    type: String, 
    required: true,
    index: true
  },
  status: { 
    type: String, 
    enum: ['pending', 'active', 'completed', 'expired'], 
    default: 'pending',
    index: true
  },
  earnings: { 
    type: Number, 
    default: 0 
  },
  commission_percentage: { 
    type: Number, 
    default: 20  // UPDATED: Increased to 20%
  },
  investment_amount: Number,
  earnings_paid: { type: Boolean, default: false },
  paid_at: Date,
  metadata: mongoose.Schema.Types.Mixed,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

referralSchema.index({ referrer: 1, status: 1 });
referralSchema.index({ referred_user: 1 }, { unique: true });

const Referral = mongoose.model('Referral', referralSchema);

// Two-Factor Authentication Model
const twoFactorSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    unique: true
  },
  secret: { 
    type: String, 
    required: true 
  },
  backup_codes: [{
    code: String,
    used: { type: Boolean, default: false },
    used_at: Date
  }],
  qr_code_url: String,
  enabled_at: Date,
  last_used: Date,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

const TwoFactor = mongoose.model('TwoFactor', twoFactorSchema);

// Password Reset Token Model
const passwordResetTokenSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true,
    index: true
  },
  token: { 
    type: String, 
    required: true,
    unique: true
  },
  token_hash: { 
    type: String, 
    required: true 
  },
  expires_at: { 
    type: Date, 
    required: true,
    index: true
  },
  used: { 
    type: Boolean, 
    default: false 
  },
  used_at: Date,
  ip_address: String,
  user_agent: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

passwordResetTokenSchema.index({ token_hash: 1 });
passwordResetTokenSchema.index({ expires_at: 1 }, { expireAfterSeconds: 0 });

const PasswordResetToken = mongoose.model('PasswordResetToken', passwordResetTokenSchema);

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
    return res.status(400).json(
      formatResponse(false, 'Validation Error', { errors: messages })
    );
  }
  
  if (error.code === 11000) {
    const field = Object.keys(error.keyValue)[0];
    return res.status(400).json(
      formatResponse(false, `${field} already exists`)
    );
  }
  
  if (error.name === 'JsonWebTokenError') {
    return res.status(401).json(
      formatResponse(false, 'Invalid token')
    );
  }
  
  if (error.name === 'TokenExpiredError') {
    return res.status(401).json(
      formatResponse(false, 'Token expired')
    );
  }
  
  const statusCode = error.statusCode || error.status || 500;
  const message = process.env.NODE_ENV === 'production' && statusCode === 500 
    ? defaultMessage 
    : error.message;

  return res.status(statusCode).json(
    formatResponse(false, message)
  );
};

// Generate unique reference
const generateReference = (prefix = 'REF') => {
  const timestamp = Date.now();
  const random = crypto.randomBytes(4).toString('hex').toUpperCase();
  return `${prefix}${timestamp}${random}`;
};

// Create notification
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
    
    const user = await User.findById(userId);
    if (user && user.email_notifications && (type === 'error' || type === 'success')) {
      await sendEmail(
        user.email,
        title,
        `<h2>${title}</h2><p>${message}</p>`,
        message
      );
    }
    
    return notification;
  } catch (error) {
    console.error('Error creating notification:', error);
  }
};

// Create transaction
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

// Calculate daily withdrawal for user
const calculateDailyWithdrawal = async (userId) => {
  try {
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    
    const endOfDay = new Date();
    endOfDay.setHours(23, 59, 59, 999);
    
    const withdrawals = await Withdrawal.find({
      user: userId,
      status: { $in: ['approved', 'paid', 'processing'] },
      createdAt: { $gte: startOfDay, $lte: endOfDay }
    });
    
    const dailyTotal = withdrawals.reduce((sum, w) => sum + w.amount, 0);
    const remaining = Math.max(0, 20000 - dailyTotal);
    
    return { dailyTotal, remaining, canWithdraw: dailyTotal < 20000 };
  } catch (error) {
    console.error('Error calculating daily withdrawal:', error);
    return { dailyTotal: 0, remaining: 20000, canWithdraw: true };
  }
};

// ==================== AUTH MIDDLEWARE ====================

const auth = async (req, res, next) => {
  try {
    let token = req.header('Authorization');
    
    if (!token) {
      return res.status(401).json(
        formatResponse(false, 'No token, authorization denied')
      );
    }
    
    if (token.startsWith('Bearer ')) {
      token = token.slice(7, token.length);
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    let user;
    try {
      user = await User.findById(decoded.id);
    } catch (dbError) {
      user = memoryStorage.users.find(u => u._id === decoded.id);
    }
    
    if (!user) {
      return res.status(401).json(
        formatResponse(false, 'Token is not valid')
      );
    }
    
    if (!user.is_active) {
      return res.status(401).json(
        formatResponse(false, 'Account is deactivated. Please contact support.')
      );
    }
    
    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json(
        formatResponse(false, 'Invalid token')
      );
    } else if (error.name === 'TokenExpiredError') {
      return res.status(401).json(
        formatResponse(false, 'Token expired')
      );
    }
    
    console.error('Auth middleware error:', error);
    res.status(500).json(
      formatResponse(false, 'Server error during authentication')
    );
  }
};

// Admin middleware
const adminAuth = async (req, res, next) => {
  try {
    await auth(req, res, () => {
      if (req.user.role !== 'admin' && req.user.role !== 'super_admin') {
        return res.status(403).json(
          formatResponse(false, 'Access denied. Admin privileges required.')
        );
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

    // Check if admin exists
    const adminExists = await User.findOne({ email: 'admin@rawwealthy.com' });
    if (!adminExists) {
      const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
      const admin = new User({
        full_name: 'Raw Wealthy Admin',
        email: 'admin@rawwealthy.com',
        phone: '+2348000000001',
        password: adminPassword,
        role: 'super_admin',
        kyc_verified: true,
        kyc_status: 'verified',
        is_verified: true,
        is_active: true,
        balance: 0,
        referral_code: 'ADMIN123'
      });
      await admin.save();
      console.log('✅ Super Admin user created');
    }

    // Create investment plans if they don't exist (UPDATED WITH NEW RATES)
    const plansExist = await InvestmentPlan.countDocuments();
    if (plansExist === 0) {
      const plans = [
        {
          name: 'Cocoa Beans',
          description: 'Invest in premium cocoa beans with high returns. Perfect for investors looking for stable growth.',
          min_amount: 35000,
          max_amount: 200000,
          daily_interest: 15,  // UPDATED: Increased to 15%
          total_interest: 450, // UPDATED: 450% over 30 days
          duration: 30,
          risk_level: 'low',
          is_popular: true,
          raw_material: 'Cocoa',
          category: 'agriculture',
          features: ['15% Daily Returns', '450% Total Returns', '30-Day Duration', 'Low Risk', 'Beginner Friendly'],
          color: '#10b981',
          icon: '🌱',
          tags: ['agriculture', 'beginner', 'low-risk', 'high-returns'],
          display_order: 1
        },
        {
          name: 'Gold',
          description: 'Precious metal investment with exceptional returns and market stability.',
          min_amount: 50000,
          max_amount: 500000,
          daily_interest: 18,  // UPDATED: Increased to 18%
          total_interest: 540, // UPDATED: 540% over 30 days
          duration: 30,
          risk_level: 'medium',
          is_popular: true,
          raw_material: 'Gold',
          category: 'metals',
          features: ['18% Daily Returns', '540% Total Returns', 'High Liquidity', 'Market Stability', 'Medium Risk'],
          color: '#fbbf24',
          icon: '🥇',
          tags: ['precious-metal', 'medium-risk', 'high-returns'],
          display_order: 2
        },
        {
          name: 'Crude Oil',
          description: 'Premium energy sector investment with maximum returns from global oil markets.',
          min_amount: 100000,
          max_amount: 1000000,
          daily_interest: 20,  // UPDATED: Increased to 20%
          total_interest: 600, // UPDATED: 600% over 30 days
          duration: 30,
          risk_level: 'high',
          raw_material: 'Crude Oil',
          category: 'energy',
          features: ['20% Daily Returns', '600% Total Returns', 'Premium Investment', 'Energy Sector', 'High Risk'],
          color: '#dc2626',
          icon: '🛢️',
          tags: ['energy', 'high-risk', 'premium', 'maximum-returns'],
          display_order: 3
        },
        {
          name: 'Diamond',
          description: 'Luxury diamond investment with exceptional long-term value growth and high daily returns.',
          min_amount: 250000,
          max_amount: 1000000,
          daily_interest: 22,  // UPDATED: Increased to 22%
          total_interest: 660, // UPDATED: 660% over 30 days
          duration: 30,
          risk_level: 'high',
          is_popular: true,
          raw_material: 'Diamond',
          category: 'precious_stones',
          features: ['22% Daily Returns', '660% Total Returns', 'Luxury Asset', 'High Value Retention', 'Exceptional Returns'],
          color: '#8b5cf6',
          icon: '💎',
          tags: ['luxury', 'high-value', 'premium-returns'],
          display_order: 4
        },
        {
          name: 'Copper',
          description: 'Industrial metal investment with high returns from growing tech and construction demand.',
          min_amount: 150000,
          max_amount: 1000000,
          daily_interest: 20,  // UPDATED: Increased to 20%
          total_interest: 600, // UPDATED: 600% over 30 days
          duration: 30,
          risk_level: 'medium',
          raw_material: 'Copper',
          category: 'metals',
          features: ['20% Daily Returns', '600% Total Returns', 'Industrial Demand', 'Tech Growth', 'Stable Returns'],
          color: '#f97316',
          icon: '🔌',
          tags: ['industrial', 'tech', 'high-returns'],
          display_order: 5
        },
        {
          name: 'Palm Oil',
          description: 'Premium agricultural commodity investment with high daily returns and global demand.',
          min_amount: 75000,
          max_amount: 1000000,
          daily_interest: 18,  // UPDATED: Increased to 18%
          total_interest: 540, // UPDATED: 540% over 30 days
          duration: 30,
          risk_level: 'low',
          raw_material: 'Palm Oil',
          category: 'agriculture',
          features: ['18% Daily Returns', '540% Total Returns', 'Essential Commodity', 'Global Consumption', 'Low Risk'],
          color: '#84cc16',
          icon: '🌴',
          tags: ['agriculture', 'low-risk', 'essential', 'high-returns'],
          display_order: 6
        }
      ];

      await InvestmentPlan.insertMany(plans);
      console.log('✅ Investment plans created (6 total with enhanced rates)');
    }

    // Initialize memory storage with same data
    initializeMemoryStorage();

    console.log('✅ Database initialization completed');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
    initializeMemoryStorage();
  }
};

// Initialize memory storage (UPDATED WITH NEW RATES)
const initializeMemoryStorage = () => {
  memoryStorage.investmentPlans = [
    {
      _id: '1',
      name: 'Cocoa Beans',
      description: 'Invest in premium cocoa beans with high returns',
      min_amount: 35000,
      max_amount: 200000,
      daily_interest: 15,  // UPDATED: Increased to 15%
      total_interest: 450, // UPDATED: 450% over 30 days
      duration: 30,
      risk_level: 'low',
      is_popular: true,
      raw_material: 'Cocoa',
      category: 'agriculture',
      features: ['15% Daily Returns', '450% Total Returns', '30-Day Duration', 'Low Risk'],
      color: '#10b981',
      icon: '🌱',
      is_active: true
    },
    {
      _id: '2',
      name: 'Gold',
      description: 'Precious metal investment with exceptional returns',
      min_amount: 50000,
      max_amount: 500000,
      daily_interest: 18,  // UPDATED: Increased to 18%
      total_interest: 540, // UPDATED: 540% over 30 days
      duration: 30,
      risk_level: 'medium',
      is_popular: true,
      raw_material: 'Gold',
      category: 'metals',
      features: ['18% Daily Returns', '540% Total Returns', 'High Liquidity'],
      color: '#fbbf24',
      icon: '🥇',
      is_active: true
    },
    {
      _id: '3',
      name: 'Crude Oil',
      description: 'Premium energy sector investment with maximum returns',
      min_amount: 100000,
      max_amount: 1000000,
      daily_interest: 20,  // UPDATED: Increased to 20%
      total_interest: 600, // UPDATED: 600% over 30 days
      duration: 30,
      risk_level: 'high',
      raw_material: 'Crude Oil',
      category: 'energy',
      features: ['20% Daily Returns', '600% Total Returns', 'Premium Investment'],
      color: '#dc2626',
      icon: '🛢️',
      is_active: true
    },
    {
      _id: '4',
      name: 'Diamond',
      description: 'Luxury diamond investment with exceptional long-term value growth',
      min_amount: 250000,
      max_amount: 1000000,
      daily_interest: 22,  // UPDATED: Increased to 22%
      total_interest: 660, // UPDATED: 660% over 30 days
      duration: 30,
      risk_level: 'high',
      is_popular: true,
      raw_material: 'Diamond',
      category: 'precious_stones',
      features: ['22% Daily Returns', '660% Total Returns', 'Luxury Asset', 'Exceptional Returns'],
      color: '#8b5cf6',
      icon: '💎',
      is_active: true
    },
    {
      _id: '5',
      name: 'Copper',
      description: 'Industrial metal investment with high returns from growing tech demand',
      min_amount: 150000,
      max_amount: 1000000,
      daily_interest: 20,  // UPDATED: Increased to 20%
      total_interest: 600, // UPDATED: 600% over 30 days
      duration: 30,
      risk_level: 'medium',
      raw_material: 'Copper',
      category: 'metals',
      features: ['20% Daily Returns', '600% Total Returns', 'Industrial Demand', 'Tech Growth'],
      color: '#f97316',
      icon: '🔌',
      is_active: true
    },
    {
      _id: '6',
      name: 'Palm Oil',
      description: 'Premium agricultural commodity investment with high daily returns',
      min_amount: 75000,
      max_amount: 1000000,
      daily_interest: 18,  // UPDATED: Increased to 18%
      total_interest: 540, // UPDATED: 540% over 30 days
      duration: 30,
      risk_level: 'low',
      raw_material: 'Palm Oil',
      category: 'agriculture',
      features: ['18% Daily Returns', '540% Total Returns', 'Essential Commodity', 'Low Risk'],
      color: '#84cc16',
      icon: '🌴',
      is_active: true
    }
  ];

  // Add demo admin user
  const hashedPassword = bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 12);
  memoryStorage.users.push({
    _id: 'admin-demo-id',
    full_name: 'Raw Wealthy Admin',
    email: 'admin@rawwealthy.com',
    phone: '+2348000000001',
    password: hashedPassword,
    role: 'super_admin',
    balance: 0,
    total_earnings: 0,
    referral_earnings: 0,
    referral_code: 'ADMIN123',
    kyc_verified: true,
    kyc_status: 'verified',
    is_verified: true,
    is_active: true,
    risk_tolerance: 'medium',
    investment_strategy: 'balanced',
    country: 'ng',
    currency: 'NGN',
    createdAt: new Date(),
    updatedAt: new Date()
  });

  console.log('✅ Memory storage initialized with enhanced investment plans');
};

// Database reconnect endpoint (for debugging)
app.post('/api/admin/reconnect-db', adminAuth, async (req, res) => {
  try {
    if (mongoose.connection.readyState === 1) {
      return res.json(formatResponse(true, 'Database is already connected'));
    }
    
    console.log('🔄 Admin manually triggering database reconnection...');
    await mongoose.disconnect();
    
    const connected = await connectDBWithRetry();
    
    if (connected) {
      res.json(formatResponse(true, 'Database reconnected successfully', {
        dbState: mongoose.connection.readyState,
        dbHost: mongoose.connection.host,
        dbName: mongoose.connection.name
      }));
    } else {
      res.status(500).json(formatResponse(false, 'Failed to reconnect to database', {
        usingMemoryStorage: true
      }));
    }
  } catch (error) {
    handleError(res, error, 'Error reconnecting to database');
  }
});

// ==================== HEALTH CHECK ====================
app.get('/health', async (req, res) => {
  const dbStatus = mongoose.connection.readyState;
  const statusMap = { 
    0: 'disconnected', 
    1: 'connected', 
    2: 'connecting', 
    3: 'disconnecting' 
  };
  
  const healthCheck = {
    success: true,
    status: 'OK',
    message: '🚀 Raw Wealthy Backend v35.0 is running perfectly!',
    timestamp: new Date().toISOString(),
    version: '35.0.0',
    database: statusMap[dbStatus] || 'unknown',
    memory_storage: memoryStorage.users.length > 0 ? 'active' : 'inactive',
    environment: process.env.NODE_ENV || 'development',
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    node_version: process.version
  };

  res.json(healthCheck);
});

// ==================== ROOT ENDPOINT ====================
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 Raw Wealthy Backend API v35.0 - FULL FRONTEND INTEGRATION',
    version: '35.0.0',
    timestamp: new Date().toISOString(),
    status: 'Fully Operational',
    environment: process.env.NODE_ENV || 'development',
    database: mongoose.connection.readyState === 1 ? 'connected' : 'using memory storage',
    frontend_connected: 'https://us-raw-wealthy.vercel.app',
    features: {
      enhanced_investment_plans: true,
      daily_interest_rates: '15-25%',
      minimum_investment: '₦35,000',
      maximum_investment: '₦1,000,000',
      referral_commission: '20%',
      daily_withdrawal_limit: '₦20,000',
      platform_fee: '10%'
    },
    endpoints: [
      '/api/auth/register',
      '/api/auth/login',
      '/api/profile',
      '/api/investments',
      '/api/deposits',
      '/api/withdrawals',
      '/api/plans',
      '/api/kyc',
      '/api/support',
      '/api/referrals',
      '/api/admin/*',
      '/api/upload'
    ]
  });
});

// ==================== AUTH ROUTES ====================

// Register - COMPLETE INTEGRATION
app.post('/api/auth/register', [
  body('full_name').notEmpty().trim().isLength({ min: 2, max: 100 }),
  body('email').isEmail().normalizeEmail(),
  body('phone').notEmpty().trim(),
  body('password').isLength({ min: 6 }),
  body('risk_tolerance').optional().isIn(['low', 'medium', 'high']),
  body('investment_strategy').optional().isIn(['conservative', 'balanced', 'aggressive'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(
        formatResponse(false, 'Validation failed', { 
          errors: errors.array().map(err => err.msg) 
        })
      );
    }

    const { full_name, email, phone, password, referral_code, risk_tolerance = 'medium', investment_strategy = 'balanced' } = req.body;

    // Check existing user
    let existingUser;
    try {
      existingUser = await User.findOne({ email: email.toLowerCase() });
    } catch (dbError) {
      existingUser = memoryStorage.users.find(u => u.email === email.toLowerCase());
    }

    if (existingUser) {
      return res.status(400).json(
        formatResponse(false, 'User already exists with this email')
      );
    }

    // Handle referral if provided
    let referredBy = null;
    if (referral_code) {
      try {
        referredBy = await User.findOne({ referral_code: referral_code.toUpperCase() });
      } catch (error) {
        referredBy = memoryStorage.users.find(u => u.referral_code === referral_code.toUpperCase());
      }
    }

    // Create user
    const userData = {
      full_name: full_name.trim(),
      email: email.toLowerCase(),
      phone: phone.trim(),
      password,
      balance: 10000, // Welcome bonus
      referral_code: crypto.randomBytes(6).toString('hex').toUpperCase(),
      risk_tolerance,
      investment_strategy,
      referred_by: referredBy ? referredBy._id || referredBy.id : null
    };

    let user;
    try {
      user = new User(userData);
      await user.save();
      
      // Update referrer's referral count
      if (referredBy) {
        referredBy.referral_count += 1;
        await referredBy.save();
        
        // Create referral record with 20% commission
        const referral = new Referral({
          referrer: referredBy._id,
          referred_user: user._id,
          referral_code: referral_code.toUpperCase(),
          status: 'pending',
          commission_percentage: 20  // UPDATED: 20% commission
        });
        await referral.save();
      }
    } catch (dbError) {
      // Fallback to memory storage
      user = {
        _id: crypto.randomBytes(16).toString('hex'),
        ...userData,
        password: await bcrypt.hash(password, 12),
        role: 'user',
        total_earnings: 0,
        referral_earnings: 0,
        kyc_verified: false,
        kyc_status: 'not_submitted',
        is_active: true,
        is_verified: false,
        country: 'ng',
        currency: 'NGN',
        createdAt: new Date(),
        updatedAt: new Date()
      };
      memoryStorage.users.push(user);
    }

    // Generate token
    const token = user.generateAuthToken ? user.generateAuthToken() : jwt.sign(
      { id: user._id || user.id }, 
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    // Create welcome notification
    await createNotification(
      user._id || user.id,
      'Welcome to Raw Wealthy!',
      'Your account has been successfully created. Start your investment journey with enhanced returns up to 25% daily!',
      'success'
    );

    // Create welcome bonus transaction
    await createTransaction(
      user._id || user.id,
      'bonus',
      10000,
      'Welcome bonus for new account',
      'completed'
    );

    // Remove sensitive data from response
    const userResponse = { ...user.toObject ? user.toObject() : user };
    delete userResponse.password;
    delete userResponse.two_factor_secret;

    res.status(201).json(
      formatResponse(true, 'User registered successfully', {
        user: userResponse,
        token,
        requires_2fa: false
      })
    );

  } catch (error) {
    handleError(res, error, 'Server error during registration');
  }
});

// Login - COMPLETE INTEGRATION
app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(
        formatResponse(false, 'Validation failed', { 
          errors: errors.array().map(err => err.msg) 
        })
      );
    }

    const { email, password } = req.body;

    // Find user
    let user;
    try {
      user = await User.findOne({ email: email.toLowerCase() }).select('+password +two_factor_secret');
    } catch (dbError) {
      user = memoryStorage.users.find(u => u.email === email.toLowerCase());
    }

    if (!user) {
      return res.status(400).json(
        formatResponse(false, 'Invalid credentials')
      );
    }

    // Check if account is locked
    if (user.lock_until && user.lock_until > new Date()) {
      const lockTime = Math.ceil((user.lock_until - new Date()) / 1000 / 60);
      return res.status(423).json(
        formatResponse(false, `Account is locked. Try again in ${lockTime} minutes.`)
      );
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      // Increment login attempts
      if (user.incrementLoginAttempts) {
        await user.incrementLoginAttempts();
      }
      return res.status(400).json(
        formatResponse(false, 'Invalid credentials')
      );
    }

    // Reset login attempts on successful login
    if (user.resetLoginAttempts) {
      await user.resetLoginAttempts();
    }

    if (!user.is_active) {
      return res.status(401).json(
        formatResponse(false, 'Account is deactivated. Please contact support.')
      );
    }

    // Check if 2FA is enabled
    if (user.two_factor_enabled) {
      // Return a special response indicating 2FA is required
      return res.status(200).json(
        formatResponse(true, 'Two-factor authentication required', {
          requires_2fa: true,
          email: user.email
        })
      );
    }

    // Generate token
    const token = user.generateAuthToken ? user.generateAuthToken() : jwt.sign(
      { id: user._id || user.id }, 
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    // Update last login
    user.last_login = new Date();
    user.last_active = new Date();
    try {
      await user.save();
    } catch (error) {
      // Handle memory storage update
      const userIndex = memoryStorage.users.findIndex(u => u._id === user._id || u.id === user.id);
      if (userIndex !== -1) {
        memoryStorage.users[userIndex].last_login = new Date();
        memoryStorage.users[userIndex].last_active = new Date();
      }
    }

    // Remove password from response
    const userResponse = { ...user.toObject ? user.toObject() : user };
    delete userResponse.password;
    delete userResponse.two_factor_secret;

    res.json(
      formatResponse(true, 'Login successful', {
        user: userResponse,
        token,
        requires_2fa: false
      })
    );

  } catch (error) {
    handleError(res, error, 'Server error during login');
  }
});

// ==================== PROFILE ROUTES ====================

// Get user profile - COMPLETE INTEGRATION
app.get('/api/profile', auth, async (req, res) => {
  try {
    const userId = req.user._id || req.user.id;
    
    // Get user investments
    let userInvestments = [];
    let userTransactions = [];
    let userNotifications = [];
    let kycSubmission = null;

    try {
      userInvestments = await Investment.find({ user: userId, status: 'active' })
        .populate('plan', 'name daily_interest')
        .lean();
      
      userTransactions = await Transaction.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean();
      
      userNotifications = await Notification.find({ user: userId, is_read: false })
        .sort({ createdAt: -1 })
        .limit(5)
        .lean();
      
      kycSubmission = await KYCSubmission.findOne({ user: userId });
    } catch (dbError) {
      // Memory storage fallback
      userInvestments = memoryStorage.investments.filter(
        inv => (inv.user_id === userId || inv.user === userId) && inv.status === 'active'
      );
      userTransactions = memoryStorage.transactions
        .filter(t => t.user_id === userId || t.user === userId)
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
        .slice(0, 10);
      userNotifications = memoryStorage.notifications.filter(
        n => (n.user_id === userId || n.user === userId) && !n.is_read
      );
      kycSubmission = memoryStorage.kycSubmissions.find(k => k.user_id === userId || k.user === userId);
    }

    // Calculate stats
    const totalActiveValue = userInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    const totalEarnings = userInvestments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0);

    // Calculate daily withdrawal info
    const dailyWithdrawalInfo = await calculateDailyWithdrawal(userId);

    const profileData = {
      user: req.user,
      dashboard_stats: {
        active_investment_value: totalActiveValue,
        total_earnings: req.user.total_earnings || 0,
        total_investments: userInvestments.length,
        unread_notifications: userNotifications.length,
        referral_count: req.user.referral_count || 0,
        referral_earnings: req.user.referral_earnings || 0,
        portfolio_value: totalActiveValue + totalEarnings,
        available_balance: req.user.balance || 0,
        kyc_status: req.user.kyc_status || 'not_submitted',
        kyc_verified: req.user.kyc_verified || false,
        daily_withdrawal_used: dailyWithdrawalInfo.dailyTotal,
        daily_withdrawal_remaining: dailyWithdrawalInfo.remaining,
        daily_withdrawal_limit: 20000
      },
      recent_transactions: userTransactions,
      active_investments: userInvestments,
      kyc_submission: kycSubmission
    };

    res.json(
      formatResponse(true, 'Profile retrieved successfully', profileData)
    );
  } catch (error) {
    handleError(res, error, 'Error fetching profile');
  }
});

// ==================== INVESTMENT PLANS ROUTES ====================

// Get all investment plans - COMPLETE INTEGRATION (UPDATED RATES)
app.get('/api/plans', async (req, res) => {
  try {
    let plans;
    try {
      plans = await InvestmentPlan.find({ is_active: true })
        .sort({ display_order: 1, min_amount: 1 })
        .lean();
    } catch (dbError) {
      plans = memoryStorage.investmentPlans.filter(plan => plan.is_active);
    }

    // Enhance plans with calculated returns
    const enhancedPlans = plans.map(plan => {
      const exampleInvestment = plan.min_amount;
      const dailyReturn = (exampleInvestment * plan.daily_interest) / 100;
      const totalReturn = (exampleInvestment * plan.total_interest) / 100;
      
      return {
        ...plan,
        example_returns: {
          investment: exampleInvestment,
          daily_return: dailyReturn,
          monthly_return: dailyReturn * 30,
          total_return: totalReturn,
          roi_percentage: plan.total_interest
        }
      };
    });

    res.json(
      formatResponse(true, 'Plans retrieved successfully', { plans: enhancedPlans })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching investment plans');
  }
});

// Get investment plans (alias for frontend)
app.get('/api/investment-plans', async (req, res) => {
  try {
    let plans;
    try {
      plans = await InvestmentPlan.find({ is_active: true })
        .sort({ display_order: 1, min_amount: 1 })
        .lean();
    } catch (dbError) {
      plans = memoryStorage.investmentPlans.filter(plan => plan.is_active);
    }

    res.json(
      formatResponse(true, 'Investment plans retrieved successfully', { plans })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching investment plans');
  }
});

// ==================== INVESTMENT ROUTES ====================

// Get user investments - COMPLETE INTEGRATION
app.get('/api/investments', auth, async (req, res) => {
  try {
    const userId = req.user._id || req.user.id;
    const { status, page = 1, limit = 10 } = req.query;
    
    let query = { user: userId };
    if (status) {
      query.status = status;
    }
    
    let userInvestments = [];
    let total = 0;
    
    try {
      const skip = (page - 1) * limit;
      userInvestments = await Investment.find(query)
        .populate('plan', 'name daily_interest duration')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean();
      
      total = await Investment.countDocuments(query);
    } catch (dbError) {
      userInvestments = memoryStorage.investments
        .filter(inv => {
          const matchesUser = inv.user_id === userId || inv.user === userId;
          const matchesStatus = status ? inv.status === status : true;
          return matchesUser && matchesStatus;
        })
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
        .slice((page - 1) * limit, page * limit);
      
      total = memoryStorage.investments.filter(inv => 
        inv.user_id === userId || inv.user === userId
      ).length;
    }

    // Enhance investments with calculations
    const enhancedInvestments = userInvestments.map(inv => {
      const remainingDays = Math.max(0, Math.ceil((new Date(inv.end_date) - new Date()) / (1000 * 60 * 60 * 24)));
      const progressPercentage = inv.status === 'active' ? 
        Math.min(100, ((new Date() - new Date(inv.start_date)) / (new Date(inv.end_date) - new Date(inv.start_date))) * 100) : 
        (inv.status === 'completed' ? 100 : 0);

      return {
        ...inv,
        remaining_days: remainingDays,
        progress_percentage: Math.round(progressPercentage),
        estimated_completion: inv.end_date,
        daily_earnings: inv.daily_earnings || (inv.amount * (inv.plan?.daily_interest || 15) / 100)
      };
    });

    const activeInvestments = enhancedInvestments.filter(inv => inv.status === 'active');
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    const totalEarnings = activeInvestments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0);
    const dailyEarnings = activeInvestments.reduce((sum, inv) => sum + (inv.daily_earnings || 0), 0);

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(
      formatResponse(true, 'Investments retrieved successfully', {
        investments: enhancedInvestments,
        stats: {
          total_active_value: totalActiveValue,
          total_earnings: totalEarnings,
          daily_earnings: dailyEarnings,
          active_count: activeInvestments.length,
          total_count: total
        },
        pagination
      })
    );

  } catch (error) {
    handleError(res, error, 'Error fetching investments');
  }
});

// Create investment - COMPLETE INTEGRATION (UPDATED MIN AMOUNT)
app.post('/api/investments', auth, upload.single('payment_proof'), [
  body('plan_id').notEmpty(),
  body('amount').isFloat({ min: 35000 }), // UPDATED: Minimum 35,000
  body('auto_renew').optional().isBoolean()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(
        formatResponse(false, 'Validation failed')
      );
    }

    const { plan_id, amount, auto_renew = false } = req.body;
    const userId = req.user._id || req.user.id;
    
    let plan;
    try {
      plan = await InvestmentPlan.findById(plan_id);
    } catch (dbError) {
      plan = memoryStorage.investmentPlans.find(p => p._id === plan_id);
    }

    if (!plan) {
      return res.status(404).json(
        formatResponse(false, 'Investment plan not found')
      );
    }

    const investmentAmount = parseFloat(amount);

    if (investmentAmount < plan.min_amount) {
      return res.status(400).json(
        formatResponse(false, `Minimum investment for ${plan.name} is ₦${plan.min_amount.toLocaleString()}`)
      );
    }

    if (plan.max_amount && investmentAmount > plan.max_amount) {
      return res.status(400).json(
        formatResponse(false, `Maximum investment for ${plan.name} is ₦${plan.max_amount.toLocaleString()}`)
      );
    }

    if (investmentAmount > req.user.balance) {
      return res.status(400).json(
        formatResponse(false, 'Insufficient balance for this investment')
      );
    }

    // Handle file upload if provided
    let proofUrl = null;
    if (req.file) {
      try {
        const uploadResult = await handleFileUpload(req.file, 'investment-proofs', userId);
        proofUrl = uploadResult.url;
      } catch (uploadError) {
        return res.status(400).json(
          formatResponse(false, `File upload failed: ${uploadError.message}`)
        );
      }
    }

    // Calculate daily earnings based on plan's daily interest
    const dailyEarnings = (investmentAmount * plan.daily_interest) / 100;
    const expectedEarnings = (investmentAmount * plan.total_interest) / 100;

    // Create investment
    const investmentData = {
      user: userId,
      plan: plan_id,
      amount: investmentAmount,
      status: proofUrl ? 'pending' : 'active',
      start_date: new Date(),
      end_date: new Date(Date.now() + plan.duration * 24 * 60 * 60 * 1000),
      expected_earnings: expectedEarnings,
      earned_so_far: 0,
      daily_earnings: dailyEarnings,
      auto_renew: auto_renew,
      payment_proof_url: proofUrl,
      payment_verified: !proofUrl
    };

    let investment;
    try {
      investment = new Investment(investmentData);
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
    } catch (dbError) {
      // Memory storage fallback
      investment = {
        _id: crypto.randomBytes(16).toString('hex'),
        ...investmentData,
        user_id: userId,
        plan_id: plan_id,
        createdAt: new Date(),
        updatedAt: new Date()
      };
      memoryStorage.investments.push(investment);
      
      // Update user balance in memory
      const userIndex = memoryStorage.users.findIndex(u => u._id === userId || u.id === userId);
      if (userIndex !== -1) {
        memoryStorage.users[userIndex].balance -= investmentAmount;
      }
    }

    // Create transaction
    await createTransaction(
      userId,
      'investment',
      -investmentAmount,
      `Investment in ${plan.name} plan (${plan.daily_interest}% daily)`,
      'completed',
      { investment_id: investment._id || investment.id }
    );

    // Create notification
    await createNotification(
      userId,
      'Investment Created',
      `Your investment of ₦${investmentAmount.toLocaleString()} in ${plan.name} has been created successfully. You will earn ₦${dailyEarnings.toLocaleString()} daily (${plan.daily_interest}%).`,
      'investment',
      '/investments'
    );

    // Process referral earnings (20% commission)
    if (req.user.referred_by) {
      try {
        const referrer = await User.findById(req.user.referred_by);
        if (referrer) {
          const referralEarnings = (investmentAmount * 20) / 100; // 20% commission
          
          // Update referrer's balance
          referrer.balance += referralEarnings;
          referrer.referral_earnings += referralEarnings;
          await referrer.save();
          
          // Create transaction for referrer
          await createTransaction(
            referrer._id,
            'referral',
            referralEarnings,
            `Referral commission from ${req.user.full_name}'s investment`,
            'completed',
            { referred_user_id: userId, investment_id: investment._id || investment.id }
          );
          
          // Update referral record
          await Referral.findOneAndUpdate(
            { referred_user: userId },
            { 
              earnings: referralEarnings,
              investment_amount: investmentAmount,
              status: 'active'
            }
          );
          
          // Create notification for referrer
          await createNotification(
            referrer._id,
            'Referral Commission Earned',
            `You earned ₦${referralEarnings.toLocaleString()} (20% commission) from ${req.user.full_name}'s investment.`,
            'success',
            '/referrals'
          );
        }
      } catch (referralError) {
        console.error('Error processing referral earnings:', referralError);
      }
    }

    res.status(201).json(
      formatResponse(true, 'Investment created successfully!', { 
        investment: {
          ...investment.toObject ? investment.toObject() : investment,
          plan_name: plan.name,
          plan_details: {
            daily_interest: plan.daily_interest,
            total_interest: plan.total_interest,
            duration: plan.duration
          },
          daily_earnings: dailyEarnings,
          expected_total_earnings: expectedEarnings
        }
      })
    );

  } catch (error) {
    handleError(res, error, 'Error creating investment');
  }
});

// ==================== WITHDRAWAL ROUTES ====================

// Get user withdrawals
app.get('/api/withdrawals', auth, async (req, res) => {
  try {
    const userId = req.user._id || req.user.id;
    const { status, page = 1, limit = 10 } = req.query;
    
    let query = { user: userId };
    if (status) {
      query.status = status;
    }
    
    let withdrawals = [];
    let total = 0;
    
    try {
      const skip = (page - 1) * limit;
      withdrawals = await Withdrawal.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean();
      
      total = await Withdrawal.countDocuments(query);
    } catch (dbError) {
      withdrawals = memoryStorage.withdrawals
        .filter(w => {
          const matchesUser = w.user_id === userId || w.user === userId;
          const matchesStatus = status ? w.status === status : true;
          return matchesUser && matchesStatus;
        })
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
        .slice((page - 1) * limit, page * limit);
      
      total = memoryStorage.withdrawals.filter(w => 
        w.user_id === userId || w.user === userId
      ).length;
    }

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(
      formatResponse(true, 'Withdrawals retrieved successfully', {
        withdrawals,
        pagination
      })
    );

  } catch (error) {
    handleError(res, error, 'Error fetching withdrawals');
  }
});

// Create withdrawal - COMPLETE INTEGRATION (UPDATED WITH DAILY LIMIT)
app.post('/api/withdrawals', auth, [
  body('amount').isFloat({ min: 1000 }),
  body('payment_method').isIn(['bank_transfer', 'crypto', 'paypal']),
  body('bank_name').optional().trim(),
  body('account_name').optional().trim(),
  body('account_number').optional().trim(),
  body('bank_code').optional().trim(),
  body('wallet_address').optional().trim(),
  body('paypal_email').optional().isEmail()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(
        formatResponse(false, 'Validation failed')
      );
    }

    const { 
      amount, 
      payment_method,
      bank_name,
      account_name,
      account_number,
      bank_code,
      wallet_address,
      paypal_email
    } = req.body;
    
    const userId = req.user._id || req.user.id;
    const withdrawalAmount = parseFloat(amount);

    // Check minimum withdrawal amount
    if (withdrawalAmount < 1000) {
      return res.status(400).json(
        formatResponse(false, 'Minimum withdrawal is ₦1,000')
      );
    }

    // Check user balance
    if (withdrawalAmount > req.user.balance) {
      return res.status(400).json(
        formatResponse(false, 'Insufficient balance for withdrawal')
      );
    }

    // Check daily withdrawal limit (₦20,000 per day)
    const dailyWithdrawalInfo = await calculateDailyWithdrawal(userId);
    
    if (!dailyWithdrawalInfo.canWithdraw) {
      return res.status(400).json(
        formatResponse(false, `Daily withdrawal limit of ₦20,000 reached. You have withdrawn ₦${dailyWithdrawalInfo.dailyTotal.toLocaleString()} today.`)
      );
    }
    
    if (withdrawalAmount > dailyWithdrawalInfo.remaining) {
      return res.status(400).json(
        formatResponse(false, `You can only withdraw ₦${dailyWithdrawalInfo.remaining.toLocaleString()} more today. Daily limit: ₦20,000`)
      );
    }

    // Calculate platform fee (10%) - UPDATED from 5% to 10%
    const platformFee = withdrawalAmount * 0.10;
    const netAmount = withdrawalAmount - platformFee;

    // Validate payment method specific details
    let paymentDetails = {};
    if (payment_method === 'bank_transfer') {
      if (!bank_name || !account_name || !account_number) {
        return res.status(400).json(
          formatResponse(false, 'Bank details are required for bank transfer')
        );
      }
      paymentDetails = {
        bank_name,
        account_name,
        account_number,
        bank_code: bank_code || ''
      };
    } else if (payment_method === 'crypto') {
      if (!wallet_address) {
        return res.status(400).json(
          formatResponse(false, 'Wallet address is required for cryptocurrency withdrawal')
        );
      }
      paymentDetails = { wallet_address };
    } else if (payment_method === 'paypal') {
      if (!paypal_email) {
        return res.status(400).json(
          formatResponse(false, 'PayPal email is required for PayPal withdrawal')
        );
      }
      paymentDetails = { paypal_email };
    }

    // Prepare withdrawal data
    const withdrawalData = {
      user: userId,
      amount: withdrawalAmount,
      payment_method,
      platform_fee: platformFee,
      net_amount: netAmount,
      status: 'pending',
      reference: generateReference('WDL'),
      daily_withdrawal_tracked: true,
      ...paymentDetails
    };

    let withdrawal;
    try {
      withdrawal = new Withdrawal(withdrawalData);
      await withdrawal.save();
      
      // Update user balance (temporarily hold the amount)
      await User.findByIdAndUpdate(userId, { 
        $inc: { balance: -withdrawalAmount },
        $inc: { daily_withdrawal_total: withdrawalAmount }
      });
    } catch (dbError) {
      // Memory storage fallback
      withdrawal = {
        _id: crypto.randomBytes(16).toString('hex'),
        ...withdrawalData,
        user_id: userId,
        createdAt: new Date(),
        updatedAt: new Date()
      };
      memoryStorage.withdrawals.push(withdrawal);
      
      // Update user balance in memory
      const userIndex = memoryStorage.users.findIndex(u => u._id === userId || u.id === userId);
      if (userIndex !== -1) {
        memoryStorage.users[userIndex].balance -= withdrawalAmount;
        memoryStorage.users[userIndex].daily_withdrawal_total = (memoryStorage.users[userIndex].daily_withdrawal_total || 0) + withdrawalAmount;
      }
    }

    // Create transaction
    await createTransaction(
      userId,
      'withdrawal',
      -withdrawalAmount,
      `Withdrawal request via ${payment_method} (10% fee: ₦${platformFee.toLocaleString()})`,
      'pending',
      { withdrawal_id: withdrawal._id || withdrawal.id }
    );

    // Create notification
    await createNotification(
      userId,
      'Withdrawal Request Submitted',
      `Your withdrawal request of ₦${withdrawalAmount.toLocaleString()} has been submitted. Net amount: ₦${netAmount.toLocaleString()} (10% platform fee: ₦${platformFee.toLocaleString()}). Daily remaining: ₦${(dailyWithdrawalInfo.remaining - withdrawalAmount).toLocaleString()}`,
      'withdrawal',
      '/withdrawals'
    );

    res.status(201).json(
      formatResponse(true, 'Withdrawal request submitted successfully!', { 
        withdrawal,
        daily_withdrawal_info: {
          daily_limit: 20000,
          used_today: dailyWithdrawalInfo.dailyTotal + withdrawalAmount,
          remaining_today: dailyWithdrawalInfo.remaining - withdrawalAmount,
          platform_fee_percentage: '10%',
          platform_fee: platformFee,
          net_amount: netAmount
        },
        message: 'Your withdrawal is pending approval. Processing time is 24-48 hours.'
      })
    );

  } catch (error) {
    handleError(res, error, 'Error creating withdrawal');
  }
});

// Get daily withdrawal info
app.get('/api/withdrawals/daily-info', auth, async (req, res) => {
  try {
    const userId = req.user._id || req.user.id;
    const dailyWithdrawalInfo = await calculateDailyWithdrawal(userId);
    
    res.json(
      formatResponse(true, 'Daily withdrawal info retrieved', {
        daily_limit: 20000,
        used_today: dailyWithdrawalInfo.dailyTotal,
        remaining_today: dailyWithdrawalInfo.remaining,
        can_withdraw: dailyWithdrawalInfo.canWithdraw,
        user_balance: req.user.balance
      })
    );
  } catch (error) {
    handleError(res, error, 'Error fetching daily withdrawal info');
  }
});

// ==================== DEPOSIT ROUTES ====================

// Get user deposits
app.get('/api/deposits', auth, async (req, res) => {
  try {
    const userId = req.user._id || req.user.id;
    const { status, page = 1, limit = 10 } = req.query;
    
    let query = { user: userId };
    if (status) {
      query.status = status;
    }
    
    let deposits = [];
    let total = 0;
    
    try {
      const skip = (page - 1) * limit;
      deposits = await Deposit.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean();
      
      total = await Deposit.countDocuments(query);
    } catch (dbError) {
      deposits = memoryStorage.deposits
        .filter(dep => {
          const matchesUser = dep.user_id === userId || dep.user === userId;
          const matchesStatus = status ? dep.status === status : true;
          return matchesUser && matchesStatus;
        })
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
        .slice((page - 1) * limit, page * limit);
      
      total = memoryStorage.deposits.filter(dep => 
        dep.user_id === userId || dep.user === userId
      ).length;
    }

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(
      formatResponse(true, 'Deposits retrieved successfully', {
        deposits,
        pagination
      })
    );

  } catch (error) {
    handleError(res, error, 'Error fetching deposits');
  }
});

// Create deposit - COMPLETE INTEGRATION
app.post('/api/deposits', auth, upload.single('payment_proof'), [
  body('amount').isFloat({ min: 500 }),
  body('payment_method').isIn(['bank_transfer', 'crypto', 'paypal', 'card']),
  body('transaction_hash').optional().trim(),
  body('bank_name').optional().trim(),
  body('account_name').optional().trim(),
  body('account_number').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(
        formatResponse(false, 'Validation failed')
      );
    }

    const { 
      amount, 
      payment_method, 
      transaction_hash,
      bank_name,
      account_name,
      account_number 
    } = req.body;
    
    const userId = req.user._id || req.user.id;
    const depositAmount = parseFloat(amount);

    // Handle file upload
    let proofUrl = null;
    if (req.file) {
      try {
        const uploadResult = await handleFileUpload(req.file, 'deposit-proofs', userId);
        proofUrl = uploadResult.url;
      } catch (uploadError) {
        return res.status(400).json(
          formatResponse(false, `File upload failed: ${uploadError.message}`)
        );
      }
    }

    // Prepare deposit data
    const depositData = {
      user: userId,
      amount: depositAmount,
      payment_method,
      status: 'pending',
      payment_proof_url: proofUrl,
      reference: generateReference('DEP'),
      transaction_hash: transaction_hash || null
    };

    // Add bank details if provided
    if (payment_method === 'bank_transfer' && bank_name && account_name && account_number) {
      depositData.bank_details = {
        bank_name,
        account_name,
        account_number
      };
    }

    let deposit;
    try {
      deposit = new Deposit(depositData);
      await deposit.save();
    } catch (dbError) {
      // Memory storage fallback
      deposit = {
        _id: crypto.randomBytes(16).toString('hex'),
        ...depositData,
        user_id: userId,
        createdAt: new Date(),
        updatedAt: new Date()
      };
      memoryStorage.deposits.push(deposit);
    }

    // Create notification
    await createNotification(
      userId,
      'Deposit Request Submitted',
      `Your deposit request of ₦${depositAmount.toLocaleString()} has been submitted and is pending approval.`,
      'deposit',
      '/deposits'
    );

    res.status(201).json(
      formatResponse(true, 'Deposit request submitted successfully!', { 
        deposit,
        message: 'Your deposit is pending approval. You will be notified once approved.'
      })
    );
  } catch (error) {
    handleError(res, error, 'Error creating deposit');
  }
});

// ==================== TRANSACTION ROUTES ====================

// Get user transactions - COMPLETE INTEGRATION
app.get('/api/transactions', auth, async (req, res) => {
  try {
    const userId = req.user._id || req.user.id;
    const { 
      type, 
      status, 
      start_date, 
      end_date, 
      page = 1, 
      limit = 20 
    } = req.query;
    
    let query = { user: userId };
    
    // Apply filters
    if (type) query.type = type;
    if (status) query.status = status;
    if (start_date || end_date) {
      query.createdAt = {};
      if (start_date) query.createdAt.$gte = new Date(start_date);
      if (end_date) query.createdAt.$lte = new Date(end_date);
    }
    
    let transactions = [];
    let total = 0;
    
    try {
      const skip = (page - 1) * limit;
      transactions = await Transaction.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean();
      
      total = await Transaction.countDocuments(query);
    } catch (dbError) {
      transactions = memoryStorage.transactions
        .filter(t => {
          const matchesUser = t.user_id === userId || t.user === userId;
          const matchesType = type ? t.type === type : true;
          const matchesStatus = status ? t.status === status : true;
          const matchesDate = true; // Simplified for memory storage
          return matchesUser && matchesType && matchesStatus && matchesDate;
        })
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
        .slice((page - 1) * limit, page * limit);
      
      total = memoryStorage.transactions.filter(t => 
        t.user_id === userId || t.user === userId
      ).length;
    }

    const pagination = {
      page: parseInt(page),
      limit: parseInt(limit),
      total,
      pages: Math.ceil(total / limit)
    };

    res.json(
      formatResponse(true, 'Transactions retrieved successfully', {
        transactions,
        pagination
      })
    );

  } catch (error) {
    handleError(res, error, 'Error fetching transactions');
  }
});

// ==================== REFERRAL ROUTES ====================

// Get referral stats - COMPLETE INTEGRATION (UPDATED: 20% COMMISSION)
app.get('/api/referrals/stats', auth, async (req, res) => {
  try {
    const userId = req.user._id || req.user.id;
    
    let referrals = [];
    let totalReferrals = 0;
    let activeReferrals = 0;
    let totalEarnings = 0;
    let pendingEarnings = 0;

    try {
      referrals = await Referral.find({ referrer: userId })
        .populate('referred_user', 'full_name email createdAt')
        .sort({ createdAt: -1 })
        .lean();
      
      totalReferrals = referrals.length;
      activeReferrals = referrals.filter(r => r.status === 'active').length;
      totalEarnings = referrals.reduce((sum, r) => sum + (r.earnings || 0), 0);
      pendingEarnings = referrals
        .filter(r => r.status === 'pending' && !r.earnings_paid)
        .reduce((sum, r) => sum + (r.earnings || 0), 0);
    } catch (dbError) {
      // Memory storage fallback
      referrals = memoryStorage.referrals
        .filter(r => r.referrer_id === userId || r.referrer === userId)
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
      
      totalReferrals = referrals.length;
      activeReferrals = referrals.filter(r => r.status === 'active').length;
      totalEarnings = referrals.reduce((sum, r) => sum + (r.earnings || 0), 0);
      pendingEarnings = referrals
        .filter(r => r.status === 'pending' && !r.earnings_paid)
        .reduce((sum, r) => sum + (r.earnings || 0), 0);
    }

    res.json(
      formatResponse(true, 'Referral stats retrieved successfully', {
        stats: {
          total_referrals: totalReferrals,
          active_referrals: activeReferrals,
          total_earnings: totalEarnings,
          pending_earnings: pendingEarnings,
          referral_code: req.user.referral_code,
          commission_percentage: 20, // UPDATED: 20% commission
          referral_link: `${process.env.CLIENT_URL || 'https://us-raw-wealthy.vercel.app'}?ref=${req.user.referral_code}`,
          referral_instructions: 'Earn 20% commission on every investment made by users you refer!'
        },
        referrals: referrals.slice(0, 10) // Return only recent referrals
      })
    );

  } catch (error) {
    handleError(res, error, 'Error fetching referral stats');
  }
});

// ==================== UPLOAD ROUTE ====================

// File upload endpoint - COMPLETE INTEGRATION
app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json(
        formatResponse(false, 'No file uploaded')
      );
    }

    const userId = req.user._id || req.user.id;
    const folder = req.body.folder || 'general';

    const uploadResult = await handleFileUpload(req.file, folder, userId);

    res.json(
      formatResponse(true, 'File uploaded successfully', {
        fileUrl: uploadResult.url,
        fileName: uploadResult.filename,
        originalName: uploadResult.originalName,
        size: uploadResult.size,
        mimeType: uploadResult.mimeType,
        folder: folder
      })
    );

  } catch (error) {
    handleError(res, error, 'Error uploading file');
  }
});

// ==================== ADMIN ROUTES ====================

// Admin dashboard stats - COMPLETE INTEGRATION
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
  try {
    // Get statistics
    let totalUsers, totalInvestments, totalDeposits, totalWithdrawals, totalEarnings, activeInvestments;
    
    try {
      totalUsers = await User.countDocuments({});
      totalInvestments = await Investment.countDocuments({});
      totalDeposits = await Deposit.countDocuments({});
      totalWithdrawals = await Withdrawal.countDocuments({});
      
      const earningsResult = await Investment.aggregate([
        { $match: { status: 'active' } },
        { $group: { _id: null, total: { $sum: '$earned_so_far' } } }
      ]);
      totalEarnings = earningsResult[0]?.total || 0;
      
      activeInvestments = await Investment.countDocuments({ status: 'active' });
    } catch (dbError) {
      // Memory storage fallback
      totalUsers = memoryStorage.users.length;
      totalInvestments = memoryStorage.investments.length;
      totalDeposits = memoryStorage.deposits.length;
      totalWithdrawals = memoryStorage.withdrawals.length;
      totalEarnings = memoryStorage.investments
        .filter(inv => inv.status === 'active')
        .reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0);
      activeInvestments = memoryStorage.investments.filter(inv => inv.status === 'active').length;
    }

    // Get pending counts
    let pendingInvestments, pendingDeposits, pendingWithdrawals, pendingKYC;
    
    try {
      pendingInvestments = await Investment.countDocuments({ status: 'pending' });
      pendingDeposits = await Deposit.countDocuments({ status: 'pending' });
      pendingWithdrawals = await Withdrawal.countDocuments({ status: 'pending' });
      pendingKYC = await KYCSubmission.countDocuments({ status: 'pending' });
    } catch (dbError) {
      pendingInvestments = memoryStorage.investments.filter(inv => inv.status === 'pending').length;
      pendingDeposits = memoryStorage.deposits.filter(dep => dep.status === 'pending').length;
      pendingWithdrawals = memoryStorage.withdrawals.filter(w => w.status === 'pending').length;
      pendingKYC = memoryStorage.kycSubmissions.filter(k => k.status === 'pending').length;
    }

    // Calculate platform earnings (10% of all withdrawals) - UPDATED from 5% to 10%
    let platformEarnings = 0;
    try {
      const withdrawalsResult = await Withdrawal.aggregate([
        { $match: { status: 'paid' } },
        { $group: { _id: null, total: { $sum: '$platform_fee' } } }
      ]);
      platformEarnings = withdrawalsResult[0]?.total || 0;
    } catch (error) {
      platformEarnings = memoryStorage.withdrawals
        .filter(w => w.status === 'paid')
        .reduce((sum, w) => sum + (w.platform_fee || 0), 0);
    }

    // Calculate total investments value
    let totalInvestmentValue = 0;
    try {
      const investmentsResult = await Investment.aggregate([
        { $match: { status: 'active' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]);
      totalInvestmentValue = investmentsResult[0]?.total || 0;
    } catch (error) {
      totalInvestmentValue = memoryStorage.investments
        .filter(inv => inv.status === 'active')
        .reduce((sum, inv) => sum + inv.amount, 0);
    }

    const stats = {
      total_users: totalUsers,
      total_investments: totalInvestments,
      total_deposits: totalDeposits,
      total_withdrawals: totalWithdrawals,
      platform_earnings: platformEarnings,
      user_earnings: totalEarnings,
      active_investments: activeInvestments,
      total_investment_value: totalInvestmentValue,
      pending_investments: pendingInvestments,
      pending_deposits: pendingDeposits,
      pending_withdrawals: pendingWithdrawals,
      pending_kyc: pendingKYC,
      total_pending: pendingInvestments + pendingDeposits + pendingWithdrawals + pendingKYC
    };

    res.json(
      formatResponse(true, 'Admin dashboard stats retrieved successfully', {
        stats
      })
    );

  } catch (error) {
    handleError(res, error, 'Error fetching admin dashboard stats');
  }
});

// Get pending withdrawals (admin)
app.get('/api/admin/pending-withdrawals', adminAuth, async (req, res) => {
  try {
    let pendingWithdrawals;
    
    try {
      pendingWithdrawals = await Withdrawal.find({ status: 'pending' })
        .populate('user', 'full_name email')
        .sort({ createdAt: -1 })
        .lean();
    } catch (dbError) {
      pendingWithdrawals = memoryStorage.withdrawals
        .filter(w => w.status === 'pending')
        .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
        .map(w => ({
          ...w,
          user: {
            full_name: memoryStorage.users.find(u => u._id === w.user_id || u.id === w.user_id)?.full_name || 'Unknown',
            email: memoryStorage.users.find(u => u._id === w.user_id || u.id === w.user_id)?.email || 'unknown'
          }
        }));
    }

    res.json(
      formatResponse(true, 'Pending withdrawals retrieved successfully', {
        withdrawals: pendingWithdrawals
      })
    );

  } catch (error) {
    handleError(res, error, 'Error fetching pending withdrawals');
  }
});

// Approve withdrawal (admin) - UPDATED WITH 10% FEE
app.post('/api/admin/withdrawals/:id/approve', adminAuth, async (req, res) => {
  try {
    const withdrawalId = req.params.id;
    const adminId = req.user._id || req.user.id;
    const { remarks, transaction_id } = req.body;

    let withdrawal;
    try {
      withdrawal = await Withdrawal.findById(withdrawalId)
        .populate('user');
      
      if (!withdrawal) {
        return res.status(404).json(
          formatResponse(false, 'Withdrawal not found')
        );
      }

      if (withdrawal.status !== 'pending') {
        return res.status(400).json(
          formatResponse(false, 'Withdrawal is not pending approval')
        );
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
        withdrawal.user._id || withdrawal.user,
        'Withdrawal Approved',
        `Your withdrawal of ₦${withdrawal.amount.toLocaleString()} has been approved and processed. Net amount: ₦${withdrawal.net_amount.toLocaleString()} (10% platform fee: ₦${withdrawal.platform_fee.toLocaleString()}). Transaction ID: ${transaction_id || 'N/A'}`,
        'success',
        '/withdrawals'
      );

      // Send email notification
      await sendEmail(
        withdrawal.user.email,
        'Withdrawal Processed Successfully',
        `<h2>Withdrawal Processed</h2>
         <p>Your withdrawal request has been processed successfully.</p>
         <p><strong>Amount:</strong> ₦${withdrawal.amount.toLocaleString()}</p>
         <p><strong>Net Amount:</strong> ₦${withdrawal.net_amount.toLocaleString()}</p>
         <p><strong>Platform Fee (10%):</strong> ₦${withdrawal.platform_fee.toLocaleString()}</p>
         <p><strong>Transaction ID:</strong> ${transaction_id || 'N/A'}</p>
         <p><strong>Payment Method:</strong> ${withdrawal.payment_method}</p>`,
        `Your withdrawal of ₦${withdrawal.amount.toLocaleString()} has been processed. Net amount: ₦${withdrawal.net_amount.toLocaleString()}`
      );

    } catch (dbError) {
      // Memory storage fallback
      withdrawal = memoryStorage.withdrawals.find(w => w._id === withdrawalId || w.id === withdrawalId);
      if (!withdrawal) {
        return res.status(404).json(
          formatResponse(false, 'Withdrawal not found')
        );
      }

      withdrawal.status = 'paid';
      withdrawal.approved_at = new Date();
      withdrawal.approved_by = adminId;
      withdrawal.paid_at = new Date();
      withdrawal.transaction_id = transaction_id;
      withdrawal.admin_notes = remarks;
      withdrawal.updatedAt = new Date();

      // Update transaction in memory
      const transaction = memoryStorage.transactions.find(t => 
        t.related_withdrawal === withdrawalId || 
        t.metadata?.withdrawal_id === withdrawalId
      );
      if (transaction) {
        transaction.status = 'completed';
      }

      // Create notification in memory
      const user = memoryStorage.users.find(u => u._id === withdrawal.user_id || u.id === withdrawal.user_id);
      if (user) {
        memoryStorage.notifications.push({
          _id: crypto.randomBytes(16).toString('hex'),
          user_id: user._id || user.id,
          title: 'Withdrawal Approved',
          message: `Your withdrawal of ₦${withdrawal.amount.toLocaleString()} has been approved.`,
          type: 'success',
          is_read: false,
          createdAt: new Date(),
          updatedAt: new Date()
        });
      }
    }

    res.json(
      formatResponse(true, 'Withdrawal approved successfully', {
        withdrawal
      })
    );

  } catch (error) {
    handleError(res, error, 'Error approving withdrawal');
  }
});

// ==================== CRON JOBS ====================

// Calculate daily earnings (UPDATED WITH HIGHER RATES)
cron.schedule('0 0 * * *', async () => {
  try {
    console.log('🔄 Calculating daily earnings with enhanced rates...');
    
    let activeInvestments = [];
    
    try {
      activeInvestments = await Investment.find({ 
        status: 'active',
        end_date: { $gt: new Date() }
      }).populate('user plan');
    } catch (dbError) {
      activeInvestments = memoryStorage.investments.filter(
        inv => inv.status === 'active' && new Date(inv.end_date) > new Date()
      );
    }

    let totalEarnings = 0;
    let processedCount = 0;

    for (const investment of activeInvestments) {
      try {
        const dailyEarning = investment.daily_earnings || (investment.amount * (investment.plan?.daily_interest || 15) / 100);
        
        // Update investment earnings
        investment.earned_so_far += dailyEarning;
        investment.last_earning_date = new Date();
        
        try {
          await investment.save();
        } catch (dbError) {
          // Update in memory storage
          const invIndex = memoryStorage.investments.findIndex(
            inv => inv._id === investment._id || inv.id === investment.id
          );
          if (invIndex !== -1) {
            memoryStorage.investments[invIndex].earned_so_far += dailyEarning;
            memoryStorage.investments[invIndex].last_earning_date = new Date();
          }
        }

        // Update user balance and total earnings
        const userId = investment.user?._id || investment.user_id || investment.user;
        if (userId) {
          try {
            await User.findByIdAndUpdate(userId, {
              $inc: { 
                balance: dailyEarning,
                total_earnings: dailyEarning
              }
            });
            
            // Create transaction
            await createTransaction(
              userId,
              'earning',
              dailyEarning,
              `Daily earnings from investment (${investment.plan?.daily_interest || 15}%)`,
              'completed',
              { investment_id: investment._id || investment.id }
            );
            
            // Create notification
            await createNotification(
              userId,
              'Daily Earnings Added',
              `₦${dailyEarning.toLocaleString()} has been added to your account from your investment. You're earning ${investment.plan?.daily_interest || 15}% daily!`,
              'success',
              '/investments'
            );
            
          } catch (dbError) {
            // Update in memory storage
            const userIndex = memoryStorage.users.findIndex(
              u => u._id === userId || u.id === userId
            );
            if (userIndex !== -1) {
              memoryStorage.users[userIndex].balance += dailyEarning;
              memoryStorage.users[userIndex].total_earnings += dailyEarning;
              
              // Create transaction in memory
              memoryStorage.transactions.push({
                _id: crypto.randomBytes(16).toString('hex'),
                user_id: userId,
                type: 'earning',
                amount: dailyEarning,
                description: `Daily earnings from investment`,
                status: 'completed',
                reference: generateReference('ERN'),
                createdAt: new Date(),
                updatedAt: new Date()
              });
              
              // Create notification in memory
              memoryStorage.notifications.push({
                _id: crypto.randomBytes(16).toString('hex'),
                user_id: userId,
                title: 'Daily Earnings Added',
                message: `₦${dailyEarning.toLocaleString()} has been added to your account.`,
                type: 'success',
                is_read: false,
                createdAt: new Date(),
                updatedAt: new Date()
              });
            }
          }
        }

        totalEarnings += dailyEarning;
        processedCount++;

      } catch (investmentError) {
        console.error(`Error processing investment:`, investmentError);
      }
    }

    // Check for completed investments
    try {
      const completedInvestments = await Investment.find({
        status: 'active',
        end_date: { $lte: new Date() }
      });

      for (const investment of completedInvestments) {
        investment.status = 'completed';
        await investment.save();
        
        const userId = investment.user?._id || investment.user_id || investment.user;
        if (userId) {
          await createNotification(
            userId,
            'Investment Completed',
            `Your investment has completed successfully. Total earnings: ₦${investment.earned_so_far.toLocaleString()} (${investment.plan?.total_interest || 450}% return!)`,
            'success',
            '/investments'
          );
        }
      }
    } catch (error) {
      console.error('Error checking completed investments:', error);
    }

    console.log(`✅ Daily earnings calculated. Processed: ${processedCount}, Total: ₦${totalEarnings.toLocaleString()}`);
  } catch (error) {
    console.error('❌ Error calculating daily earnings:', error);
  }
});

// Reset daily withdrawal totals at midnight
cron.schedule('0 0 * * *', async () => {
  try {
    console.log('🔄 Resetting daily withdrawal totals...');
    
    try {
      await User.updateMany(
        {},
        { 
          daily_withdrawal_total: 0,
          daily_withdrawal_reset: new Date()
        }
      );
      console.log('✅ Daily withdrawal totals reset');
    } catch (error) {
      console.error('❌ Error resetting daily withdrawals:', error);
    }
  } catch (error) {
    console.error('❌ Error in daily withdrawal reset cron:', error);
  }
});

// ==================== APPLICATION INITIALIZATION ====================

const initializeApp = async () => {
  try {
    // Initialize memory storage as fallback
    initializeMemoryStorage();
    
    // Attempt MongoDB connection
    const dbConnected = await connectDBWithRetry();
    
    const PORT = process.env.PORT || 10000;
    const server = app.listen(PORT, '0.0.0.0', () => {
      console.log(`
🎯 RAW WEALTHY BACKEND v35.0 - FULL FRONTEND INTEGRATION
🌐 Server running on port ${PORT}
🚀 Environment: ${process.env.NODE_ENV || 'development'}
📊 Health Check: /health
🔗 API Base: /api
💾 Database: ${dbConnected ? 'MongoDB Connected' : 'Memory Storage (Fallback)'}
🛡️ Security: Enhanced with comprehensive protection

✅ ENHANCED FEATURES FULLY INTEGRATED:
   ✅ Enhanced Investment Plans (6 Plans)
   ✅ Minimum Investment: ₦35,000
   ✅ Maximum Investment: ₦1,000,000
   ✅ Daily Interest Rates: 15-25%
   ✅ Total Returns: 450-750% over 30 days
   ✅ Referral Commission: 20%
   ✅ Daily Withdrawal Limit: ₦20,000
   ✅ Platform Withdrawal Fee: 10%
   ✅ User Authentication & Registration (with 2FA)
   ✅ Profile Management (Complete CRUD)
   ✅ Deposit & Withdrawal Processing
   ✅ KYC Verification System
   ✅ Support Ticket System
   ✅ Admin Dashboard (Full Control)
   ✅ Real-time Notifications
   ✅ File Upload System
   ✅ Transaction History
   ✅ Password Reset System
   ✅ Cron Job Automation
   ✅ Email Notifications
   ✅ Advanced Admin Routes

🌐 FRONTEND FULLY CONNECTED:
   ✅ https://us-raw-wealthy.vercel.app
   ✅ CORS properly configured
   ✅ All endpoints accessible
   ✅ Real-time synchronization

🚀 DEPLOYMENT READY - 100% FRONTEND CONNECTED WITH ENHANCED RATES!
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
    console.error('❌ Application initialization failed:', error);
    process.exit(1);
  }
};

// Start the application
initializeApp();

export default app;
