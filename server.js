// server.js - RAW WEALTHY BACKEND v37.0 - ENHANCED EDITION
// COMPLETE MODERNIZATION WITH FULL FRONTEND INTEGRATION

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
import axios from 'axios';

// ES Modules equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Environment configuration
dotenv.config({ path: path.join(__dirname, '.env') });

// ==================== CONFIGURATION ====================
const config = {
  // Server
  port: process.env.PORT || 10000,
  nodeEnv: process.env.NODE_ENV || 'development',
  
  // Database
  mongoURI: process.env.MONGODB_URI || 'mongodb://localhost:27017/rawwealthy',
  
  // Security
  jwtSecret: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production',
  jwtExpiresIn: '30d',
  bcryptRounds: 12,
  
  // Client
  clientURL: process.env.CLIENT_URL || 'http://localhost:3000',
  serverURL: process.env.SERVER_URL || 'http://localhost:10000',
  
  // Business
  minInvestment: 3500,
  minDeposit: 3500,
  minWithdrawal: 3500,
  platformFeePercent: 10,
  referralCommissionPercent: 10,
  welcomeBonus: 100,
  
  // Email
  emailEnabled: false,
  
  // Storage
  uploadDir: path.join(__dirname, 'uploads'),
  maxFileSize: 10 * 1024 * 1024, // 10MB
  allowedMimeTypes: {
    'image/jpeg': 'jpg',
    'image/jpg': 'jpg',
    'image/png': 'png',
    'image/gif': 'gif',
    'image/webp': 'webp',
    'application/pdf': 'pdf'
  }
};

console.log('🚀 Raw Wealthy Backend Initializing...');
console.log('=========================================');
console.log(`Environment: ${config.nodeEnv}`);
console.log(`Port: ${config.port}`);
console.log(`Client URL: ${config.clientURL}`);
console.log(`Server URL: ${config.serverURL}`);
console.log('=========================================\n');

// ==================== EXPRESS SETUP ====================
const app = express();

// Security middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(xss());
app.use(hpp());
app.use(mongoSanitize());
app.use(compression());

// Logging
app.use(morgan(config.nodeEnv === 'production' ? 'combined' : 'dev'));

// CORS configuration
const corsOptions = {
  origin: [
    config.clientURL,
    config.serverURL,
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:3001',
    'https://rawwealthy.com',
    'https://www.rawwealthy.com'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Body parsing
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: { success: false, message: 'Too many requests from this IP' }
});

app.use('/api/', limiter);

// ==================== FILE UPLOAD ====================
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  if (config.allowedMimeTypes[file.mimetype]) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type'), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: config.maxFileSize }
});

// Create upload directory if it doesn't exist
if (!fs.existsSync(config.uploadDir)) {
  fs.mkdirSync(config.uploadDir, { recursive: true });
}

// Serve static files
app.use('/uploads', express.static(config.uploadDir));

// ==================== DATABASE MODELS ====================

// User Schema
const userSchema = new mongoose.Schema({
  full_name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  phone: { type: String, required: true },
  password: { type: String, required: true, select: false },
  role: { type: String, enum: ['user', 'admin', 'super_admin'], default: 'user' },
  balance: { type: Number, default: 0 },
  total_earnings: { type: Number, default: 0 },
  referral_earnings: { type: Number, default: 0 },
  risk_tolerance: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  investment_strategy: { type: String, enum: ['conservative', 'balanced', 'aggressive'], default: 'balanced' },
  country: { type: String, default: 'ng' },
  currency: { type: String, default: 'NGN' },
  referral_code: { type: String, unique: true },
  referred_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  referral_count: { type: Number, default: 0 },
  kyc_verified: { type: Boolean, default: false },
  kyc_status: { type: String, enum: ['pending', 'verified', 'rejected', 'not_submitted'], default: 'not_submitted' },
  kyc_submitted_at: Date,
  kyc_verified_at: Date,
  two_factor_enabled: { type: Boolean, default: false },
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
    verified_at: Date
  },
  wallet_address: String,
  paypal_email: String,
  last_login: Date,
  profile_image: String,
  notifications_enabled: { type: Boolean, default: true },
  email_notifications: { type: Boolean, default: true },
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
      return ret;
    }
  }
});

userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ referral_code: 1 }, { unique: true });

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

// Investment Plan Schema
const investmentPlanSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  description: { type: String, required: true },
  min_amount: { type: Number, required: true },
  max_amount: { type: Number },
  daily_interest: { type: Number, required: true },
  total_interest: { type: Number, required: true },
  duration: { type: Number, required: true },
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
  display_order: { type: Number, default: 0 }
}, { 
  timestamps: true 
});

const InvestmentPlan = mongoose.model('InvestmentPlan', investmentPlanSchema);

// Investment Schema
const investmentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  plan: { type: mongoose.Schema.Types.ObjectId, ref: 'InvestmentPlan', required: true },
  amount: { type: Number, required: true },
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
  approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  transaction_id: String,
  remarks: String
}, { 
  timestamps: true 
});

investmentSchema.index({ user: 1, status: 1 });
investmentSchema.index({ end_date: 1 });

const Investment = mongoose.model('Investment', investmentSchema);

// Deposit Schema
const depositSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
  payment_method: { type: String, enum: ['bank_transfer', 'crypto', 'paypal', 'card'], required: true },
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'cancelled'], default: 'pending' },
  payment_proof_url: String,
  transaction_hash: String,
  reference: { type: String, unique: true },
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
  }
}, { 
  timestamps: true 
});

depositSchema.index({ user: 1, status: 1 });
depositSchema.index({ reference: 1 }, { unique: true });

const Deposit = mongoose.model('Deposit', depositSchema);

// Withdrawal Schema
const withdrawalSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true },
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
  reference: { type: String, unique: true },
  admin_notes: String,
  approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approved_at: Date,
  paid_at: Date,
  transaction_id: String
}, { 
  timestamps: true 
});

withdrawalSchema.index({ user: 1, status: 1 });

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'investment', 'earning', 'referral', 'bonus', 'fee', 'refund'], required: true },
  amount: { type: Number, required: true },
  description: { type: String, required: true },
  reference: { type: String, unique: true },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'completed' },
  balance_before: Number,
  balance_after: Number,
  related_investment: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment' },
  related_deposit: { type: mongoose.Schema.Types.ObjectId, ref: 'Deposit' },
  related_withdrawal: { type: mongoose.Schema.Types.ObjectId, ref: 'Withdrawal' },
  payment_proof_url: String,
  admin_notes: String
}, { 
  timestamps: true 
});

transactionSchema.index({ user: 1, createdAt: -1 });

const Transaction = mongoose.model('Transaction', transactionSchema);

// KYC Submission Schema
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
  notes: String
}, { 
  timestamps: true 
});

const KYCSubmission = mongoose.model('KYCSubmission', kycSubmissionSchema);

// Support Ticket Schema
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
  reply_count: { type: Number, default: 0 }
}, { 
  timestamps: true 
});

supportTicketSchema.index({ user: 1, status: 1 });

const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);

// Referral Schema
const referralSchema = new mongoose.Schema({
  referrer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  referred_user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  referral_code: { type: String, required: true },
  status: { type: String, enum: ['pending', 'active', 'completed', 'expired'], default: 'pending' },
  earnings: { type: Number, default: 0 },
  commission_percentage: { type: Number, default: config.referralCommissionPercent },
  investment_amount: Number,
  earnings_paid: { type: Boolean, default: false },
  paid_at: Date
}, { 
  timestamps: true 
});

referralSchema.index({ referrer: 1, status: 1 });

const Referral = mongoose.model('Referral', referralSchema);

// Notification Schema
const notificationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { type: String, enum: ['info', 'success', 'warning', 'error', 'investment', 'withdrawal', 'deposit', 'kyc', 'referral', 'system'], default: 'info' },
  is_read: { type: Boolean, default: false },
  is_email_sent: { type: Boolean, default: false },
  action_url: String,
  priority: { type: Number, default: 0 }
}, { 
  timestamps: true 
});

notificationSchema.index({ user: 1, is_read: 1 });

const Notification = mongoose.model('Notification', notificationSchema);

// Admin Audit Schema
const adminAuditSchema = new mongoose.Schema({
  admin_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  target_type: { type: String, enum: ['user', 'investment', 'deposit', 'withdrawal', 'kyc', 'transaction', 'plan'] },
  target_id: mongoose.Schema.Types.ObjectId,
  details: mongoose.Schema.Types.Mixed,
  ip_address: String,
  user_agent: String
}, { 
  timestamps: true 
});

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
  
  const statusCode = error.statusCode || 500;
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

const handleFileUpload = async (file, folder = 'general', userId = null) => {
  if (!file) return null;
  
  try {
    const uploadsDir = path.join(config.uploadDir, folder);
    
    if (!fs.existsSync(uploadsDir)) {
      fs.mkdirSync(uploadsDir, { recursive: true });
    }
    
    const timestamp = Date.now();
    const randomStr = crypto.randomBytes(8).toString('hex');
    const userIdPrefix = userId ? `${userId}_` : '';
    const fileExtension = config.allowedMimeTypes[file.mimetype] || 'bin';
    const filename = `${userIdPrefix}${timestamp}_${randomStr}.${fileExtension}`;
    const filepath = path.join(uploadsDir, filename);
    
    await fs.promises.writeFile(filepath, file.buffer);
    
    return {
      url: `${config.serverURL}/uploads/${folder}/${filename}`,
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
      ...metadata
    });
    
    await transaction.save();
    return transaction;
  } catch (error) {
    console.error('Error creating transaction:', error);
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
      user_agent: userAgent
    });
    
    await audit.save();
    return audit;
  } catch (error) {
    console.error('Error creating admin audit:', error);
    return null;
  }
};

// ==================== MIDDLEWARE ====================

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
      return res.status(401).json(formatResponse(false, 'Account is deactivated'));
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
        return res.status(403).json(formatResponse(false, 'Admin privileges required'));
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
    console.log('🔄 Connecting to MongoDB...');
    
    await mongoose.connect(config.mongoURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000
    });
    
    console.log('✅ MongoDB connected successfully');
    
    // Create admin user if it doesn't exist
    await createAdminUser();
    
    // Create default investment plans if none exist
    await createDefaultPlans();
    
    console.log('✅ Database initialization completed');
  } catch (error) {
    console.error('❌ Database initialization error:', error.message);
    process.exit(1);
  }
};

const createAdminUser = async () => {
  try {
    const adminEmail = 'admin@rawwealthy.com';
    const adminPassword = 'Admin123456';
    
    const existingAdmin = await User.findOne({ email: adminEmail });
    if (existingAdmin) {
      console.log('✅ Admin already exists');
      return;
    }
    
    const salt = await bcrypt.genSalt(12);
    const hash = await bcrypt.hash(adminPassword, salt);
    
    const admin = new User({
      full_name: 'Raw Wealthy Admin',
      email: adminEmail,
      phone: '1234567890',
      password: hash,
      role: 'super_admin',
      balance: 1000000,
      kyc_verified: true,
      kyc_status: 'verified',
      is_active: true,
      is_verified: true,
      referral_code: 'ADMIN' + crypto.randomBytes(4).toString('hex').toUpperCase()
    });
    
    await admin.save();
    console.log('✅ Admin user created');
    console.log(`📧 Email: ${adminEmail}`);
    console.log(`🔑 Password: ${adminPassword}`);
    
  } catch (error) {
    console.error('Error creating admin user:', error);
  }
};

const createDefaultPlans = async () => {
  try {
    const count = await InvestmentPlan.countDocuments();
    if (count > 0) {
      console.log(`✅ ${count} investment plans already exist`);
      return;
    }
    
    const defaultPlans = [
      {
        name: 'Cocoa Beans',
        description: 'Invest in premium cocoa beans with stable returns. Perfect for beginners.',
        min_amount: 3500,
        max_amount: 50000,
        daily_interest: 10,
        total_interest: 300,
        duration: 30,
        risk_level: 'low',
        raw_material: 'Cocoa',
        category: 'agriculture',
        is_popular: true,
        features: ['Low Risk', 'Stable Returns', 'Daily Payouts'],
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
        features: ['High Risk', 'Maximum Returns', 'Energy Sector'],
        color: '#dc2626',
        icon: '🛢️',
        display_order: 3
      }
    ];
    
    await InvestmentPlan.insertMany(defaultPlans);
    console.log('✅ Created default investment plans');
  } catch (error) {
    console.error('Error creating default plans:', error);
  }
};

// ==================== ROUTES ====================

// Health check
app.get('/health', async (req, res) => {
  const health = {
    success: true,
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '37.0.0',
    environment: config.nodeEnv,
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  };
  
  res.json(health);
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 Raw Wealthy Backend API v37.0',
    version: '37.0.0',
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
      upload: '/api/upload'
    }
  });
});

// ==================== AUTH ROUTES ====================

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
        errors: errors.array()
      }));
    }

    const { full_name, email, phone, password, referral_code } = req.body;

    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json(formatResponse(false, 'User already exists'));
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
      'Your account has been successfully created.',
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

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json(formatResponse(false, 'Invalid credentials'));
    }

    user.last_login = new Date();
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

    res.json(formatResponse(true, 'Password reset email sent'));
  } catch (error) {
    handleError(res, error, 'Error processing forgot password');
  }
});

// ==================== PROFILE ROUTES ====================

// Get profile
app.get('/api/profile', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    const user = await User.findById(userId).lean();
    
    const [investments, deposits, withdrawals, transactions, notifications, kyc, referrals] = await Promise.all([
      Investment.find({ user: userId })
        .populate('plan', 'name daily_interest duration total_interest')
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
      Notification.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      KYCSubmission.findOne({ user: userId }).lean(),
      Referral.find({ referrer: userId })
        .populate('referred_user', 'full_name email createdAt')
        .sort({ createdAt: -1 })
        .limit(10)
        .lean()
    ]);

    const activeInvestments = investments.filter(inv => inv.status === 'active');
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    
    const dailyInterest = activeInvestments.reduce((sum, inv) => {
      if (inv.plan && inv.plan.daily_interest) {
        return sum + (inv.amount * inv.plan.daily_interest / 100);
      }
      return sum;
    }, 0);
    
    const totalEarnings = investments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0);
    const referralEarnings = referrals.reduce((sum, ref) => sum + (ref.earnings || 0), 0);

    const profileData = {
      user: {
        ...user,
        bank_details: user.bank_details || null
      },
      
      dashboard_stats: {
        active_investment_value: totalActiveValue,
        total_earnings: totalEarnings,
        daily_interest: dailyInterest,
        referral_earnings: referralEarnings,
        total_investments: investments.length,
        active_investments_count: activeInvestments.length,
        total_deposits: deposits.filter(d => d.status === 'approved').length,
        total_withdrawals: withdrawals.filter(w => w.status === 'paid').length,
        referral_count: user.referral_count || 0,
        unread_notifications: notifications.filter(n => !n.is_read).length,
        available_balance: user.balance || 0,
        portfolio_value: (user.balance || 0) + totalEarnings + referralEarnings,
        kyc_status: user.kyc_status || 'not_submitted',
        kyc_verified: user.kyc_verified || false
      },
      
      investment_history: investments,
      transaction_history: transactions,
      deposit_history: deposits,
      withdrawal_history: withdrawals,
      referral_history: referrals,
      kyc_submission: kyc,
      notifications: notifications
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
      'Your profile information has been updated.',
      'info',
      '/profile'
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
      verified: false
    };

    await user.save();

    await createNotification(
      userId,
      'Bank Details Updated',
      'Your bank account details have been updated.',
      'info',
      '/profile'
    );

    res.json(formatResponse(true, 'Bank details updated successfully', {
      bank_details: user.bank_details
    }));
  } catch (error) {
    handleError(res, error, 'Error updating bank details');
  }
});

// ==================== INVESTMENT PLANS ROUTES ====================

// Get all investment plans
app.get('/api/plans', async (req, res) => {
  try {
    const plans = await InvestmentPlan.find({ is_active: true })
      .sort({ display_order: 1, min_amount: 1 })
      .lean();
    
    const enhancedPlans = plans.map(plan => ({
      ...plan,
      roi_percentage: plan.total_interest,
      daily_roi: plan.daily_interest,
      monthly_roi: plan.daily_interest * 30,
      features: plan.features || ['Secure Investment', 'Daily Payouts', '24/7 Support']
    }));
    
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

// ==================== INVESTMENT ROUTES ====================

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

    const activeInvestments = investments.filter(inv => inv.status === 'active');
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    const totalEarnings = activeInvestments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0);
    const dailyEarnings = activeInvestments.reduce((sum, inv) => {
      if (inv.plan && inv.plan.daily_interest) {
        return sum + (inv.amount * inv.plan.daily_interest / 100);
      }
      return sum;
    }, 0);

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
        daily_earnings: dailyEarnings,
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
    
    const plan = await InvestmentPlan.findById(plan_id);
    if (!plan) {
      return res.status(404).json(formatResponse(false, 'Investment plan not found'));
    }

    const investmentAmount = parseFloat(amount);

    if (investmentAmount < plan.min_amount) {
      return res.status(400).json(formatResponse(false, 
        `Minimum investment is ${plan.min_amount}`));
    }

    if (plan.max_amount && investmentAmount > plan.max_amount) {
      return res.status(400).json(formatResponse(false,
        `Maximum investment is ${plan.max_amount}`));
    }

    if (investmentAmount > req.user.balance) {
      return res.status(400).json(formatResponse(false, 'Insufficient balance'));
    }

    let proofUrl = null;
    if (req.file) {
      try {
        const uploadResult = await handleFileUpload(req.file, 'investment-proofs', userId);
        proofUrl = uploadResult.url;
      } catch (uploadError) {
        return res.status(400).json(formatResponse(false, `File upload failed`));
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
      payment_verified: !proofUrl
    });

    await investment.save();

    await User.findByIdAndUpdate(userId, { 
      $inc: { balance: -investmentAmount }
    });

    await InvestmentPlan.findByIdAndUpdate(plan_id, {
      $inc: { 
        investment_count: 1,
        total_invested: investmentAmount
      }
    });

    await createTransaction(
      userId,
      'investment',
      -investmentAmount,
      `Investment in ${plan.name} plan`,
      proofUrl ? 'pending' : 'completed',
      { investment_id: investment._id }
    );

    await createNotification(
      userId,
      'Investment Created',
      `Your investment of ₦${investmentAmount.toLocaleString()} has been created.`,
      'investment',
      '/investments'
    );

    res.status(201).json(formatResponse(true, 'Investment created successfully!', { 
      investment: {
        ...investment.toObject(),
        plan_name: plan.name
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error creating investment');
  }
});

// ==================== DEPOSIT ROUTES ====================

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
        approved_count: deposits.filter(d => d.status === 'approved').length
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

    let proofUrl = null;
    if (req.file) {
      try {
        const uploadResult = await handleFileUpload(req.file, 'deposit-proofs', userId);
        proofUrl = uploadResult.url;
      } catch (uploadError) {
        return res.status(400).json(formatResponse(false, `File upload failed`));
      }
    }

    const deposit = new Deposit({
      user: userId,
      amount: depositAmount,
      payment_method,
      status: 'pending',
      payment_proof_url: proofUrl,
      reference: generateReference('DEP')
    });

    await deposit.save();

    await createNotification(
      userId,
      'Deposit Request Submitted',
      `Your deposit request of ₦${depositAmount.toLocaleString()} has been submitted.`,
      'deposit',
      '/deposits'
    );

    res.status(201).json(formatResponse(true, 'Deposit request submitted successfully!', { 
      deposit
    }));
  } catch (error) {
    handleError(res, error, 'Error creating deposit');
  }
});

// ==================== WITHDRAWAL ROUTES ====================

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

    const totalWithdrawals = withdrawals.filter(w => w.status === 'paid').reduce((sum, w) => sum + w.amount, 0);
    const pendingWithdrawals = withdrawals.filter(w => w.status === 'pending').reduce((sum, w) => sum + w.amount, 0);
    const totalFees = withdrawals.filter(w => w.status === 'paid').reduce((sum, w) => sum + w.platform_fee, 0);

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
        total_fees: totalFees,
        total_count: total
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

    if (withdrawalAmount < config.minWithdrawal) {
      return res.status(400).json(formatResponse(false, 
        `Minimum withdrawal is ${config.minWithdrawal}`));
    }

    if (withdrawalAmount > req.user.balance) {
      return res.status(400).json(formatResponse(false, 'Insufficient balance'));
    }

    const platformFee = withdrawalAmount * (config.platformFeePercent / 100);
    const netAmount = withdrawalAmount - platformFee;

    let paymentDetails = {};
    if (payment_method === 'bank_transfer') {
      if (!req.user.bank_details || !req.user.bank_details.account_number) {
        return res.status(400).json(formatResponse(false, 'Please update your bank details'));
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
        return res.status(400).json(formatResponse(false, 'Please set your wallet address'));
      }
      paymentDetails = { wallet_address: req.user.wallet_address };
    } else if (payment_method === 'paypal') {
      if (!req.user.paypal_email) {
        return res.status(400).json(formatResponse(false, 'Please set your PayPal email'));
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
      ...paymentDetails
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
      { withdrawal_id: withdrawal._id }
    );

    await createNotification(
      userId,
      'Withdrawal Request Submitted',
      `Your withdrawal request of ₦${withdrawalAmount.toLocaleString()} has been submitted.`,
      'withdrawal',
      '/withdrawals'
    );

    res.status(201).json(formatResponse(true, 'Withdrawal request submitted successfully!', { 
      withdrawal
    }));
  } catch (error) {
    handleError(res, error, 'Error creating withdrawal');
  }
});

// ==================== TRANSACTION ROUTES ====================

// Get user transactions
app.get('/api/transactions', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    const { type, status, page = 1, limit = 20 } = req.query;
    
    const query = { user: userId };
    
    if (type) query.type = type;
    if (status) query.status = status;
    
    const skip = (page - 1) * limit;
    
    const [transactions, total] = await Promise.all([
      Transaction.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit))
        .lean(),
      Transaction.countDocuments(query)
    ]);

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

// ==================== KYC ROUTES ====================

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
      return res.status(400).json(formatResponse(false, `File upload failed`));
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

    await User.findByIdAndUpdate(userId, {
      kyc_status: 'pending',
      kyc_submitted_at: new Date()
    });

    await createNotification(
      userId,
      'KYC Submitted',
      'Your KYC documents have been submitted for verification.',
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

// ==================== SUPPORT ROUTES ====================

// Get support tickets
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

// Create support ticket
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
          mime_type: uploadResult.mimeType
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
      status: 'open'
    });

    await supportTicket.save();

    await createNotification(
      userId,
      'Support Ticket Created',
      `Your support ticket #${ticketId} has been created.`,
      'info',
      `/support/ticket/${ticketId}`
    );

    res.status(201).json(formatResponse(true, 'Support ticket created successfully!', {
      ticket: supportTicket
    }));
  } catch (error) {
    handleError(res, error, 'Error creating support ticket');
  }
});

// ==================== REFERRAL ROUTES ====================

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

    const user = await User.findById(userId);
    
    res.json(formatResponse(true, 'Referral stats retrieved successfully', {
      stats: {
        total_referrals: totalReferrals,
        active_referrals: activeReferrals,
        total_earnings: totalEarnings,
        pending_earnings: pendingEarnings,
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

// ==================== NOTIFICATION ROUTES ====================

// Get notifications
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

    const unreadCount = await Notification.countDocuments({ 
      user: userId, 
      is_read: false 
    });

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
    const notification = await Notification.findOneAndUpdate(
      { _id: req.params.id, user: req.user._id },
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
    await Notification.updateMany(
      { user: req.user._id, is_read: false },
      { is_read: true }
    );
    
    res.json(formatResponse(true, 'All notifications marked as read'));
  } catch (error) {
    handleError(res, error, 'Error marking notifications as read');
  }
});

// ==================== UPLOAD ROUTES ====================

// Upload file
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
      mimeType: uploadResult.mimeType
    }));
  } catch (error) {
    handleError(res, error, 'Error uploading file');
  }
});

// ==================== ADMIN ROUTES ====================

// Admin dashboard
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
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
      pendingKYC,
      recentTransactions,
      recentUsers
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
      Transaction.find({})
        .populate('user', 'full_name email')
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      User.find({})
        .select('full_name email phone createdAt last_login')
        .sort({ createdAt: -1 })
        .limit(10)
        .lean()
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
      },
      recent_activity: {
        transactions: recentTransactions,
        users: recentUsers
      }
    };

    res.json(formatResponse(true, 'Admin dashboard stats retrieved successfully', {
      stats
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
      search,
      sort_by = 'createdAt',
      sort_order = 'desc'
    } = req.query;
    
    const query = {};
    
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
        .select('-password')
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
          total_withdrawals: withdrawals
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
      pagination
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching users');
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
      total_amount: pendingWithdrawals.reduce((sum, wdl) => sum + wdl.amount, 0)
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching pending withdrawals');
  }
});

// Get pending KYC
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

// Approve investment
app.post('/api/admin/investments/:id/approve', adminAuth, async (req, res) => {
  try {
    const investmentId = req.params.id;
    const adminId = req.user._id;

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
    
    await investment.save();

    await createNotification(
      investment.user._id,
      'Investment Approved',
      `Your investment of ₦${investment.amount.toLocaleString()} has been approved.`,
      'investment',
      '/investments'
    );

    await createAdminAudit(
      adminId,
      'APPROVE_INVESTMENT',
      'investment',
      investmentId,
      {
        amount: investment.amount,
        plan: investment.plan.name,
        user_id: investment.user._id
      },
      req.ip,
      req.headers['user-agent']
    );

    res.json(formatResponse(true, 'Investment approved successfully', {
      investment
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
      { investment_id: investment._id }
    );

    await createNotification(
      investment.user._id,
      'Investment Rejected',
      `Your investment has been rejected. Reason: ${remarks}`,
      'error',
      '/investments'
    );

    await createAdminAudit(
      adminId,
      'REJECT_INVESTMENT',
      'investment',
      investmentId,
      {
        amount: investment.amount,
        user_id: investment.user._id,
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent']
    );

    res.json(formatResponse(true, 'Investment rejected successfully', {
      investment
    }));
  } catch (error) {
    handleError(res, error, 'Error rejecting investment');
  }
});

// Approve deposit
app.post('/api/admin/deposits/:id/approve', adminAuth, async (req, res) => {
  try {
    const depositId = req.params.id;
    const adminId = req.user._id;

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
      { deposit_id: deposit._id }
    );

    await createNotification(
      deposit.user._id,
      'Deposit Approved',
      `Your deposit of ₦${deposit.amount.toLocaleString()} has been approved.`,
      'success',
      '/deposits'
    );

    await createAdminAudit(
      adminId,
      'APPROVE_DEPOSIT',
      'deposit',
      depositId,
      {
        amount: deposit.amount,
        user_id: deposit.user._id
      },
      req.ip,
      req.headers['user-agent']
    );

    res.json(formatResponse(true, 'Deposit approved successfully', {
      deposit
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
    deposit.admin_notes = remarks;
    
    await deposit.save();

    await createNotification(
      deposit.user._id,
      'Deposit Rejected',
      `Your deposit has been rejected. Reason: ${remarks}`,
      'error',
      '/deposits'
    );

    await createAdminAudit(
      adminId,
      'REJECT_DEPOSIT',
      'deposit',
      depositId,
      {
        amount: deposit.amount,
        user_id: deposit.user._id,
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

// Approve withdrawal
app.post('/api/admin/withdrawals/:id/approve', adminAuth, async (req, res) => {
  try {
    const withdrawalId = req.params.id;
    const adminId = req.user._id;

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
    
    await withdrawal.save();

    await User.findByIdAndUpdate(withdrawal.user._id, {
      $inc: { total_withdrawals: withdrawal.amount },
      last_withdrawal_date: new Date()
    });

    await createNotification(
      withdrawal.user._id,
      'Withdrawal Approved',
      `Your withdrawal of ₦${withdrawal.amount.toLocaleString()} has been approved.`,
      'success',
      '/withdrawals'
    );

    await createAdminAudit(
      adminId,
      'APPROVE_WITHDRAWAL',
      'withdrawal',
      withdrawalId,
      {
        amount: withdrawal.amount,
        user_id: withdrawal.user._id
      },
      req.ip,
      req.headers['user-agent']
    );

    res.json(formatResponse(true, 'Withdrawal approved successfully', {
      withdrawal
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
    withdrawal.admin_notes = remarks;
    
    await withdrawal.save();

    await User.findByIdAndUpdate(withdrawal.user._id, {
      $inc: { balance: withdrawal.amount }
    });

    await createTransaction(
      withdrawal.user._id,
      'refund',
      withdrawal.amount,
      `Refund for rejected withdrawal`,
      'completed',
      { withdrawal_id: withdrawal._id }
    );

    await createNotification(
      withdrawal.user._id,
      'Withdrawal Rejected',
      `Your withdrawal has been rejected. Reason: ${remarks}`,
      'error',
      '/withdrawals'
    );

    await createAdminAudit(
      adminId,
      'REJECT_WITHDRAWAL',
      'withdrawal',
      withdrawalId,
      {
        amount: withdrawal.amount,
        user_id: withdrawal.user._id,
        remarks: remarks
      },
      req.ip,
      req.headers['user-agent']
    );

    res.json(formatResponse(true, 'Withdrawal rejected successfully', {
      withdrawal
    }));
  } catch (error) {
    handleError(res, error, 'Error rejecting withdrawal');
  }
});

// Approve KYC
app.post('/api/admin/kyc/:id/approve', adminAuth, async (req, res) => {
  try {
    const kycId = req.params.id;
    const adminId = req.user._id;

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
    
    await kyc.save();

    await User.findByIdAndUpdate(kyc.user._id, {
      kyc_status: 'verified',
      kyc_verified: true,
      kyc_verified_at: new Date()
    });

    await createNotification(
      kyc.user._id,
      'KYC Approved',
      'Your KYC documents have been verified and approved.',
      'kyc',
      '/profile'
    );

    await createAdminAudit(
      adminId,
      'APPROVE_KYC',
      'kyc',
      kycId,
      {
        user_id: kyc.user._id,
        id_type: kyc.id_type
      },
      req.ip,
      req.headers['user-agent']
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
    const { rejection_reason } = req.body;

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
    
    await kyc.save();

    await User.findByIdAndUpdate(kyc.user._id, {
      kyc_status: 'rejected'
    });

    await createNotification(
      kyc.user._id,
      'KYC Rejected',
      `Your KYC has been rejected. Reason: ${rejection_reason}`,
      'kyc',
      '/kyc'
    );

    await createAdminAudit(
      adminId,
      'REJECT_KYC',
      'kyc',
      kycId,
      {
        user_id: kyc.user._id,
        rejection_reason: rejection_reason
      },
      req.ip,
      req.headers['user-agent']
    );

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
      'system'
    );

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

    await createNotification(
      userId,
      is_active ? 'Account Activated' : 'Account Deactivated',
      is_active 
        ? 'Your account has been activated.'
        : 'Your account has been deactivated.',
      'system'
    );

    await createAdminAudit(
      req.user._id,
      'UPDATE_USER_STATUS',
      'user',
      userId,
      {
        new_status: is_active ? 'active' : 'inactive',
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

// Update user balance
app.put('/api/admin/users/:id/balance', adminAuth, [
  body('amount').isFloat(),
  body('description').notEmpty()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed'));
    }

    const userId = req.params.id;
    const { amount, description } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    const newBalance = user.balance + parseFloat(amount);

    await User.findByIdAndUpdate(userId, {
      $inc: { balance: amount }
    });

    await createTransaction(
      userId,
      amount > 0 ? 'bonus' : 'fee',
      amount,
      description,
      'completed'
    );

    await createNotification(
      userId,
      'Balance Updated',
      `Your balance has been updated by ₦${Math.abs(amount).toLocaleString()}. New balance: ₦${newBalance.toLocaleString()}`,
      amount > 0 ? 'success' : 'warning'
    );

    await createAdminAudit(
      req.user._id,
      'UPDATE_USER_BALANCE',
      'user',
      userId,
      {
        amount: amount,
        description: description,
        old_balance: user.balance,
        new_balance: newBalance,
        user_name: user.full_name
      },
      req.ip,
      req.headers['user-agent']
    );

    res.json(formatResponse(true, 'User balance updated successfully', {
      new_balance: newBalance
    }));
  } catch (error) {
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
    const { verified, remarks } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    if (!user.bank_details) {
      return res.status(400).json(formatResponse(false, 'User has no bank details'));
    }

    user.bank_details.verified = verified;
    user.bank_details.verified_at = verified ? new Date() : null;
    await user.save();

    await createNotification(
      userId,
      verified ? 'Bank Details Verified' : 'Bank Details Unverified',
      verified 
        ? 'Your bank details have been verified. You can now make withdrawals.'
        : 'Your bank details verification has been revoked.',
      verified ? 'success' : 'warning',
      '/profile'
    );

    await createAdminAudit(
      req.user._id,
      verified ? 'VERIFY_BANK_DETAILS' : 'UNVERIFY_BANK_DETAILS',
      'user',
      userId,
      {
        verified: verified,
        remarks: remarks,
        user_name: user.full_name
      },
      req.ip,
      req.headers['user-agent']
    );

    res.json(formatResponse(true, 'Bank details verification updated successfully', {
      bank_details: user.bank_details
    }));
  } catch (error) {
    handleError(res, error, 'Error updating bank details verification');
  }
});

// ==================== CRON JOBS ====================

// Daily earnings calculation
cron.schedule('0 0 * * *', async () => {
  try {
    console.log('🔄 Calculating daily earnings...');
    
    const activeInvestments = await Investment.find({ 
      status: 'active',
      end_date: { $gt: new Date() }
    }).populate('user plan');
    
    for (const investment of activeInvestments) {
      const dailyEarning = (investment.amount * investment.plan.daily_interest) / 100;
      
      investment.earned_so_far += dailyEarning;
      investment.last_earning_date = new Date();
      
      await investment.save();
      
      await User.findByIdAndUpdate(investment.user._id, {
        $inc: { 
          balance: dailyEarning,
          total_earnings: dailyEarning
        }
      });
      
      await createTransaction(
        investment.user._id,
        'earning',
        dailyEarning,
        `Daily earnings from ${investment.plan.name} investment`,
        'completed',
        { investment_id: investment._id }
      );
      
      if (investment.earned_so_far >= investment.expected_earnings) {
        investment.status = 'completed';
        await investment.save();
        
        await createNotification(
          investment.user._id,
          'Investment Completed',
          `Your investment in ${investment.plan.name} has been completed. Total earnings: ₦${investment.earned_so_far.toLocaleString()}`,
          'success',
          '/investments'
        );
      }
    }
    
    console.log(`✅ Daily earnings calculated for ${activeInvestments.length} investments`);
  } catch (error) {
    console.error('❌ Error calculating daily earnings:', error);
  }
});

// ==================== ERROR HANDLING ====================

// 404 handler
app.use((req, res) => {
  res.status(404).json(formatResponse(false, 'Endpoint not found'));
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('🚨 Global error handler:', error);
  
  if (error.name === 'UnauthorizedError') {
    return res.status(401).json(formatResponse(false, 'Invalid token'));
  }
  
  res.status(500).json(formatResponse(false, 
    config.nodeEnv === 'production' 
      ? 'Internal server error' 
      : error.message
  ));
});

// ==================== SERVER START ====================

const startServer = async () => {
  try {
    await initializeDatabase();
    
    app.listen(config.port, () => {
      console.log(`🚀 Server running on port ${config.port}`);
      console.log(`🌐 Environment: ${config.nodeEnv}`);
      console.log(`📁 Upload directory: ${config.uploadDir}`);
      console.log(`🔗 API Base URL: ${config.serverURL}`);
      console.log('=========================================');
      console.log('✅ Raw Wealthy Backend Ready!');
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
};

startServer();

export default app;
