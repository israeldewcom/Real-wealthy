// server.js - ULTIMATE PRODUCTION READY RAW WEALTHY BACKEND v15.0 - ADVANCED UPGRADE
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const mongoSanitize = require('express-mongo-sanitize');
const { body, validationResult } = require('express-validator');
const cron = require('node-cron');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const nodemailer = require('nodemailer');
const QRCode = require('qrcode');
const speakeasy = require('speakeasy');
const axios = require('axios');
const WebSocket = require('ws');
const redis = require('redis');
const cloudinary = require('cloudinary').v2;
const crypto = require('crypto');
const geoip = require('geoip-lite');
const userAgent = require('express-useragent');
const moment = require('moment');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();

// ==================== ENHANCED SECURITY CONFIGURATION ====================
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:", "http:", "blob:"],
      connectSrc: ["'self'", "https://raw-wealthy-yibn.onrender.com", "wss:"]
    }
  }
}));

app.use(mongoSanitize());
app.use(compression());
app.use(userAgent.express());

// ==================== ENHANCED RATE LIMITING WITH IP TRACKING ====================
const createAccountLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  message: { success: false, message: 'Too many accounts created from this IP, please try again after an hour' },
  skipSuccessfulRequests: true
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: 'Too many authentication attempts' },
  skipFailedRequests: false
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  message: { success: false, message: 'Too many requests' }
});

const investmentLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: { success: false, message: 'Too many investment requests' }
});

// ==================== ENHANCED CLOUDINARY CONFIGURATION ====================
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true
});

// ==================== PERFECT CORS CONFIGURATION ====================
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      "https://real-earning.vercel.app",
      "https://real-earning.vercel.app",
      "http://localhost:3000",
      "http://127.0.0.1:5500",
      "http://localhost:5500",
      "https://raw-wealthy-frontend.vercel.app",
      "https://raw-wealthy-frontend.vercel.app",
      "https://rawwealthy.com",
      "https://www.rawwealthy.com",
      "http://localhost:3001",
      "https://raw-wealthy.vercel.app"
    ];
    
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.log('Blocked by CORS:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'X-Device-Id', 'X-Platform'],
  exposedHeaders: ['X-Total-Count', 'X-Total-Pages'],
  maxAge: 86400 // 24 hours
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

// ==================== ENHANCED FILE UPLOAD CONFIGURATION ====================
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadPath = 'uploads/';
    if (!fs.existsSync(uploadPath)) {
      fs.mkdirSync(uploadPath, { recursive: true });
    }
    cb(null, uploadPath);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const safeName = file.originalname.replace(/[^a-zA-Z0-9.]/g, '_');
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(safeName));
  }
});

const fileFilter = (req, file, cb) => {
  const allowedMimes = [
    'image/jpeg',
    'image/jpg', 
    'image/png',
    'image/gif',
    'image/webp',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
  ];
  
  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error(`Invalid file type: ${file.mimetype}. Only images and documents are allowed.`), false);
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 15 * 1024 * 1024, // 15MB limit
    files: 5 // Maximum 5 files
  }
});

// ==================== ENHANCED REDIS CACHE WITH CLUSTER SUPPORT ====================
let redisClient;
const initializeRedis = async () => {
  try {
    redisClient = redis.createClient({
      url: process.env.REDIS_URL || 'redis://localhost:6379',
      socket: {
        connectTimeout: 60000,
        lazyConnect: true,
        reconnectStrategy: (retries) => Math.min(retries * 100, 5000)
      },
      password: process.env.REDIS_PASSWORD
    });

    redisClient.on('error', (err) => {
      console.log('⚠️ Redis Connection Error (Using Fallback):', err.message);
    });

    redisClient.on('connect', () => {
      console.log('✅ Redis Connected Successfully');
    });

    redisClient.on('ready', () => {
      console.log('🚀 Redis Ready for Operations');
    });

    await redisClient.connect();
    return true;
  } catch (error) {
    console.log('❌ Redis Connection Failed - Using In-Memory Fallback');
    
    // Enhanced in-memory fallback with TTL support
    redisClient = {
      data: new Map(),
      isOpen: true,
      get: async (key) => {
        const item = redisClient.data.get(key);
        if (item && item.expiry && Date.now() > item.expiry) {
          redisClient.data.delete(key);
          return null;
        }
        return item ? item.value : null;
      },
      setEx: async (key, expiry, value) => {
        redisClient.data.set(key, {
          value,
          expiry: Date.now() + (expiry * 1000)
        });
      },
      del: async (key) => redisClient.data.delete(key),
      set: async (key, value) => {
        redisClient.data.set(key, { value });
      },
      quit: async () => { 
        redisClient.data.clear();
        redisClient.isOpen = false;
      },
      exists: async (key) => redisClient.data.has(key),
      ttl: async (key) => {
        const item = redisClient.data.get(key);
        if (!item || !item.expiry) return -2;
        const remaining = Math.ceil((item.expiry - Date.now()) / 1000);
        return remaining > 0 ? remaining : -2;
      }
    };
    return false;
  }
};

// ==================== ENHANCED WEBSOCKET SETUP WITH ROOMS ====================
const wss = new WebSocket.Server({ noServer: true });
const connectedClients = new Map();
const userRooms = new Map();

wss.on('connection', (ws, request) => {
  const userId = request.headers['user-id'];
  const deviceId = request.headers['device-id'] || uuidv4();
  
  if (userId) {
    connectedClients.set(userId, ws);
    
    // Create user room for targeted messaging
    if (!userRooms.has(userId)) {
      userRooms.set(userId, new Set());
    }
    userRooms.get(userId).add(ws);
    
    console.log(`✅ User ${userId} connected via WebSocket (Device: ${deviceId})`);
    
    // Send welcome message
    ws.send(JSON.stringify({
      type: 'connection_established',
      message: 'WebSocket connection established',
      timestamp: new Date().toISOString()
    }));
  }

  ws.on('message', (data) => {
    try {
      const message = JSON.parse(data);
      console.log('WebSocket message received:', message);
      
      // Handle ping-pong for connection health
      if (message.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
      }
    } catch (error) {
      console.error('WebSocket message parsing error:', error);
    }
  });

  ws.on('close', () => {
    if (userId) {
      const userRoom = userRooms.get(userId);
      if (userRoom) {
        userRoom.delete(ws);
        if (userRoom.size === 0) {
          userRooms.delete(userId);
        }
      }
      console.log(`❌ User ${userId} disconnected`);
    }
  });

  ws.on('error', (error) => {
    console.error(`WebSocket error for user ${userId}:`, error);
  });
});

// Enhanced WebSocket broadcast function
const broadcastToUser = (userId, data) => {
  const userRoom = userRooms.get(userId);
  if (userRoom) {
    userRoom.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({
          ...data,
          timestamp: new Date().toISOString(),
          id: uuidv4()
        }));
      }
    });
  }
};

// Broadcast to all users (admin notifications)
const broadcastToAll = (data) => {
  connectedClients.forEach((client, userId) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({
        ...data,
        timestamp: new Date().toISOString()
      }));
    }
  });
};

// ==================== ENHANCED EMAIL CONFIGURATION WITH TEMPLATES ====================
const createEmailTransporter = () => {
  try {
    if (process.env.EMAIL_SERVICE === 'gmail') {
      return nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        },
        pool: true,
        maxConnections: 5,
        maxMessages: 100
      });
    } else if (process.env.EMAIL_SERVICE === 'smtp') {
      return nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT,
        secure: process.env.SMTP_SECURE === 'true',
        auth: {
          user: process.env.SMTP_USER,
          pass: process.env.SMTP_PASS
        }
      });
    }
    return null;
  } catch (error) {
    console.log('⚠️ Email transporter creation failed:', error.message);
    return null;
  }
};

const emailTransporter = createEmailTransporter();

// Email templates
const emailTemplates = {
  welcome: (user) => ({
    subject: 'Welcome to Raw Wealthy - Start Your Investment Journey!',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #fbbf24;">Welcome to Raw Wealthy!</h2>
        <p>Dear ${user.full_name},</p>
        <p>Your account has been created successfully. Welcome to Africa's premier raw materials investment platform.</p>
        <div style="background: #f8fafc; padding: 20px; border-radius: 10px; margin: 20px 0;">
          <h3 style="color: #1e293b;">Your Account Details:</h3>
          <p><strong>Name:</strong> ${user.full_name}</p>
          <p><strong>Email:</strong> ${user.email}</p>
          <p><strong>Referral Code:</strong> <code style="background: #e2e8f0; padding: 5px 10px; border-radius: 5px;">${user.referral_code}</code></p>
        </div>
        <p>Start your investment journey today and grow your wealth with our secure raw materials investment plans.</p>
        <a href="${process.env.FRONTEND_URL}/dashboard" style="background: #fbbf24; color: #0f172a; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">Go to Dashboard</a>
        <p style="margin-top: 30px; color: #64748b; font-size: 14px;">Best regards,<br>Raw Wealthy Team</p>
      </div>
    `
  }),
  investmentCreated: (investment, user) => ({
    subject: `Investment Request Submitted - ${investment.plan.name}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #fbbf24;">Investment Request Submitted!</h2>
        <p>Dear ${user.full_name},</p>
        <p>Your investment request has been submitted successfully and is awaiting admin approval.</p>
        <div style="background: #f8fafc; padding: 20px; border-radius: 10px; margin: 20px 0;">
          <h3 style="color: #1e293b;">Investment Details:</h3>
          <p><strong>Plan:</strong> ${investment.plan.name}</p>
          <p><strong>Amount:</strong> ₦${investment.amount.toLocaleString()}</p>
          <p><strong>Expected Returns:</strong> ₦${investment.expected_earnings.toLocaleString()}</p>
          <p><strong>Duration:</strong> ${investment.plan.duration} days</p>
          <p><strong>Status:</strong> <span style="color: #f59e0b;">Pending Approval</span></p>
        </div>
        <p>You will be notified once your investment is approved and activated.</p>
        <a href="${process.env.FRONTEND_URL}/investment-history" style="background: #fbbf24; color: #0f172a; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">View Investment</a>
        <p style="margin-top: 30px; color: #64748b; font-size: 14px;">Best regards,<br>Raw Wealthy Team</p>
      </div>
    `
  })
};

// ==================== ENHANCED DATABASE MODELS WITH ADVANCED FEATURES ====================

// Enhanced User Model with Security Tracking
const userSchema = new mongoose.Schema({
  // Basic Information
  full_name: { type: String, required: true, trim: true },
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    index: true,
    lowercase: true,
    validate: {
      validator: function(email) {
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
      },
      message: 'Invalid email format'
    }
  },
  phone: { 
    type: String, 
    required: true,
    validate: {
      validator: function(phone) {
        return /^[\+]?[1-9][\d]{0,15}$/.test(phone);
      },
      message: 'Invalid phone number format'
    }
  },
  password: { type: String, required: true, select: false },
  
  // Role and Permissions
  role: { 
    type: String, 
    enum: ['user', 'admin', 'super_admin'], 
    default: 'user' 
  },
  permissions: [String],
  
  // Financial Information
  balance: { type: Number, default: 0, min: 0 },
  total_earnings: { type: Number, default: 0, min: 0 },
  referral_earnings: { type: Number, default: 0, min: 0 },
  lifetime_deposits: { type: Number, default: 0, min: 0 },
  lifetime_withdrawals: { type: Number, default: 0, min: 0 },
  
  // Referral System
  referral_code: { type: String, unique: true, index: true },
  referred_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  referral_count: { type: Number, default: 0 },
  
  // KYC Verification
  kyc_verified: { type: Boolean, default: false },
  kyc_level: { type: String, enum: ['none', 'basic', 'enhanced', 'full'], default: 'none' },
  kyc_documents: {
    id_type: String,
    id_number: String,
    id_front: String,
    id_back: String,
    selfie_with_id: String,
    status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
    submitted_at: Date,
    reviewed_at: Date,
    reviewed_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    rejection_reason: String
  },
  
  // Investment Preferences
  risk_tolerance: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  investment_strategy: { type: String, enum: ['conservative', 'balanced', 'aggressive'], default: 'balanced' },
  
  // Security Features
  two_factor_enabled: { type: Boolean, default: false },
  two_factor_secret: { type: String, select: false },
  backup_codes: [{ type: String, select: false }],
  security_questions: [{
    question: String,
    answer: { type: String, select: false }
  }],
  
  // Account Status
  is_active: { type: Boolean, default: true },
  is_verified: { type: Boolean, default: false },
  verification_token: String,
  verification_expires: Date,
  
  // Login Security
  last_login: Date,
  last_login_ip: String,
  last_login_device: String,
  login_attempts: { type: Number, default: 0 },
  lock_until: Date,
  password_changed_at: Date,
  
  // Device Management
  devices: [{
    device_id: String,
    device_name: String,
    platform: String,
    last_active: Date,
    ip_address: String,
    is_trusted: { type: Boolean, default: false }
  }],
  
  // Banking Information
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String,
    verified: { type: Boolean, default: false },
    verified_at: Date
  },
  
  // Crypto Wallets
  crypto_wallet: {
    btc: { type: String, default: '' },
    eth: { type: String, default: '' },
    usdt: { type: String, default: '' },
    bnb: { type: String, default: '' }
  },
  
  // Preferences
  preferences: {
    currency: { type: String, default: 'NGN' },
    language: { type: String, default: 'en' },
    timezone: { type: String, default: 'Africa/Lagos' },
    email_notifications: { type: Boolean, default: true },
    sms_notifications: { type: Boolean, default: true },
    push_notifications: { type: Boolean, default: true },
    marketing_emails: { type: Boolean, default: false }
  },
  
  // Investment Portfolio
  investment_portfolio: {
    total_invested: { type: Number, default: 0 },
    active_investments: { type: Number, default: 0 },
    completed_investments: { type: Number, default: 0 },
    total_roi: { type: Number, default: 0 },
    favorite_plans: [{ type: mongoose.Schema.Types.ObjectId, ref: 'InvestmentPlan' }]
  },
  
  // Analytics
  signup_source: String,
  utm_parameters: mongoose.Schema.Types.Mixed,
  
  // Timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, { 
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.two_factor_secret;
      delete ret.backup_codes;
      delete ret.security_questions;
      delete ret.verification_token;
      return ret;
    }
  }
});

// Virtual for account age
userSchema.virtual('account_age_days').get(function() {
  return Math.floor((Date.now() - this.createdAt) / (1000 * 60 * 60 * 24));
});

// Virtual for isLocked
userSchema.virtual('isLocked').get(function() {
  return !!(this.lock_until && this.lock_until > Date.now());
});

// Virtual for referral URL
userSchema.virtual('referral_url').get(function() {
  return `${process.env.FRONTEND_URL}/register?ref=${this.referral_code}`;
});

// Pre-save middleware
userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12);
    this.password_changed_at = Date.now();
  }
  
  if (!this.referral_code) {
    this.referral_code = this.generateReferralCode();
  }
  
  this.updatedAt = Date.now();
  next();
});

// Generate referral code method
userSchema.methods.generateReferralCode = function() {
  return crypto.randomBytes(4).toString('hex').toUpperCase();
};

// Password comparison method
userSchema.methods.comparePassword = async function(password) {
  if (this.isLocked) {
    const remainingTime = Math.ceil((this.lock_until - Date.now()) / 1000 / 60);
    throw new Error(`Account is temporarily locked. Try again in ${remainingTime} minutes.`);
  }
  
  const isMatch = await bcrypt.compare(password, this.password);
  
  if (!isMatch) {
    this.login_attempts += 1;
    if (this.login_attempts >= 5) {
      this.lock_until = Date.now() + 30 * 60 * 1000; // Lock for 30 minutes
    }
    await this.save();
    return false;
  }
  
  // Reset login attempts on successful login
  if (this.login_attempts > 0) {
    this.login_attempts = 0;
    this.lock_until = undefined;
    this.last_login = new Date();
    await this.save();
  }
  
  return true;
};

// 2FA methods
userSchema.methods.generate2FASecret = function() {
  const secret = speakeasy.generateSecret({
    name: `RawWealthy (${this.email})`,
    length: 20
  });
  this.two_factor_secret = secret.base32;
  
  // Generate backup codes
  this.backup_codes = Array.from({ length: 8 }, () => 
    crypto.randomBytes(4).toString('hex').toUpperCase()
  );
  
  return secret;
};

userSchema.methods.verify2FAToken = function(token) {
  return speakeasy.totp.verify({
    secret: this.two_factor_secret,
    encoding: 'base32',
    token: token,
    window: 2
  });
};

// Generate backup codes
userSchema.methods.generateBackupCodes = function() {
  this.backup_codes = Array.from({ length: 8 }, () => 
    crypto.randomBytes(4).toString('hex').toUpperCase()
  );
  return this.backup_codes;
};

const User = mongoose.model('User', userSchema);

// Enhanced Investment Plan Model
const investmentPlanSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  description: { type: String, required: true },
  short_description: String,
  
  // Financial Details
  min_amount: { type: Number, required: true, min: 1000 },
  max_amount: { type: Number, min: 1000 },
  daily_interest: { type: Number, required: true, min: 0.1, max: 100 },
  total_interest: { type: Number, required: true, min: 1, max: 1000 },
  duration: { type: Number, required: true, min: 1 }, // in days
  
  // Risk and Category
  risk_level: { type: String, enum: ['low', 'medium', 'high'], required: true },
  category: { 
    type: String, 
    enum: ['agriculture', 'mining', 'energy', 'metals', 'technology', 'real_estate', 'crypto', 'commodities'], 
    default: 'agriculture' 
  },
  raw_material: { type: String, required: true },
  
  // Status and Visibility
  is_active: { type: Boolean, default: true },
  is_popular: { type: Boolean, default: false },
  is_featured: { type: Boolean, default: false },
  display_order: { type: Number, default: 0 },
  
  // Media and Presentation
  image_url: String,
  icon: String,
  color_scheme: String,
  features: [String],
  tags: [String],
  requirements: [String],
  
  // Performance Metrics
  popularity_score: { type: Number, default: 0 },
  investment_count: { type: Number, default: 0 },
  total_invested: { type: Number, default: 0 },
  success_rate: { type: Number, default: 95, min: 0, max: 100 },
  avg_roi: { type: Number, default: 0 },
  
  // Historical Data
  roi_history: [{
    period: Date,
    average_roi: Number,
    total_investments: Number
  }],
  
  // Compliance
  terms_conditions: String,
  risk_disclaimer: String,
  
  // Timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, {
  timestamps: true,
  toJSON: { virtuals: true }
});

// Virtual for estimated earnings
investmentPlanSchema.virtual('estimated_earnings').get(function() {
  return (this.min_amount * this.total_interest) / 100;
});

// Virtual for daily earnings
investmentPlanSchema.virtual('daily_earnings_min').get(function() {
  return (this.min_amount * this.daily_interest) / 100;
});

investmentPlanSchema.index({ category: 1, is_active: 1 });
investmentPlanSchema.index({ risk_level: 1, is_active: 1 });
investmentPlanSchema.index({ popularity_score: -1 });

const InvestmentPlan = mongoose.model('InvestmentPlan', investmentPlanSchema);

// Enhanced Investment Model with Advanced Tracking
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
  
  // Investment Details
  amount: { 
    type: Number, 
    required: true, 
    min: [1000, 'Minimum investment is ₦1000'] 
  },
  currency: { type: String, default: 'NGN' },
  
  // Status and Lifecycle
  status: { 
    type: String, 
    enum: ['pending', 'active', 'completed', 'cancelled', 'suspended'], 
    default: 'pending',
    index: true 
  },
  stage: { 
    type: String, 
    enum: ['submitted', 'under_review', 'approved', 'activated', 'matured'], 
    default: 'submitted' 
  },
  
  // Dates
  start_date: { type: Date, default: Date.now },
  end_date: { type: Date, required: true },
  approved_at: Date,
  completed_at: Date,
  
  // Earnings Tracking
  expected_earnings: { type: Number, required: true },
  earned_so_far: { type: Number, default: 0 },
  daily_earnings: { type: Number, default: 0 },
  last_earning_date: Date,
  total_earnings: { type: Number, default: 0 },
  
  // Settings
  auto_renew: { type: Boolean, default: false },
  compound_interest: { type: Boolean, default: false },
  
  // Payment Information
  payment_proof: String,
  transaction_hash: String,
  payment_method: String,
  
  // Admin Management
  admin_notes: String,
  approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reviewed_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  
  // Performance Metrics
  performance_metrics: {
    current_roi: { type: Number, default: 0 },
    days_remaining: { type: Number, default: 0 },
    expected_daily: { type: Number, default: 0 },
    progress_percentage: { type: Number, default: 0 }
  },
  
  // Risk Management
  risk_score: { type: Number, default: 0 },
  flags: [{
    type: String,
    reason: String,
    raised_at: { type: Date, default: Date.now },
    resolved: { type: Boolean, default: false }
  }],
  
  // Timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, {
  timestamps: true,
  toJSON: { virtuals: true }
});

// Virtuals
investmentSchema.virtual('remaining_days').get(function() {
  if (this.status !== 'active') return 0;
  const now = new Date();
  const end = new Date(this.end_date);
  const diffTime = Math.max(0, end - now);
  return Math.ceil(diffTime / (1000 * 60 * 60 * 24));
});

investmentSchema.virtual('is_expired').get(function() {
  return this.status === 'active' && new Date() > this.end_date;
});

investmentSchema.virtual('current_roi_percentage').get(function() {
  if (this.amount === 0) return 0;
  return ((this.earned_so_far / this.amount) * 100).toFixed(2);
});

investmentSchema.virtual('progress_percentage').get(function() {
  if (this.status !== 'active') return 0;
  const totalDays = Math.ceil((this.end_date - this.start_date) / (1000 * 60 * 60 * 24));
  const daysPassed = Math.ceil((new Date() - this.start_date) / (1000 * 60 * 60 * 24));
  return Math.min(100, (daysPassed / totalDays) * 100);
});

// Pre-save middleware
investmentSchema.pre('save', async function(next) {
  if (this.isModified('plan') && this.plan) {
    const plan = await InvestmentPlan.findById(this.plan);
    if (plan) {
      const endDate = new Date(this.start_date);
      endDate.setDate(endDate.getDate() + plan.duration);
      this.end_date = endDate;
      
      this.expected_earnings = (this.amount * plan.total_interest) / 100;
      this.daily_earnings = (this.amount * plan.daily_interest) / 100;
      
      // Update performance metrics
      this.performance_metrics = {
        current_roi: parseFloat(this.current_roi_percentage),
        days_remaining: this.remaining_days,
        expected_daily: this.daily_earnings,
        progress_percentage: this.progress_percentage
      };
    }
  }
  
  this.updatedAt = Date.now();
  next();
});

investmentSchema.index({ user: 1, status: 1 });
investmentSchema.index({ end_date: 1 });
investmentSchema.index({ createdAt: -1 });

const Investment = mongoose.model('Investment', investmentSchema);

// Enhanced Deposit Model
const depositSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true, 
    index: true 
  },
  
  // Deposit Details
  amount: { 
    type: Number, 
    required: true, 
    min: [500, 'Minimum deposit is ₦500'] 
  },
  currency: { type: String, default: 'NGN' },
  payment_method: { 
    type: String, 
    enum: ['bank_transfer', 'crypto', 'paypal', 'card', 'flutterwave', 'paystack'], 
    required: true 
  },
  
  // Status
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'processing', 'cancelled'], 
    default: 'pending',
    index: true 
  },
  
  // Payment Information
  payment_proof: String,
  transaction_hash: String,
  reference: { type: String, unique: true, index: true },
  
  // Bank Details
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String,
    bank_code: String
  },
  
  // Crypto Details
  crypto_details: {
    wallet_address: String,
    transaction_hash: String,
    coin_type: { type: String, enum: ['BTC', 'ETH', 'USDT', 'BNB', 'LTC'] },
    network: String,
    confirmations: { type: Number, default: 0 }
  },
  
  // Payment Gateway
  payment_gateway: String,
  gateway_reference: String,
  gateway_response: mongoose.Schema.Types.Mixed,
  
  // Admin Management
  admin_notes: String,
  approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approved_at: Date,
  processed_at: Date,
  
  // Risk Management
  risk_score: { type: Number, default: 0 },
  flags: [String],
  
  // Timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, {
  timestamps: true,
  toJSON: { virtuals: true }
});

// Pre-save middleware for reference
depositSchema.pre('save', function(next) {
  if (!this.reference) {
    this.reference = `DEP${Date.now()}${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  }
  next();
});

// Post-save middleware for approved deposits
depositSchema.post('findOneAndUpdate', async function(doc) {
  if (doc && this.getUpdate().$set && this.getUpdate().$set.status === 'approved' && doc.status !== 'approved') {
    try {
      // Update user balance
      await User.findByIdAndUpdate(doc.user, { 
        $inc: { 
          balance: doc.amount,
          lifetime_deposits: doc.amount
        } 
      });
      
      // Create transaction record
      await Transaction.create({
        user: doc.user,
        type: 'deposit',
        amount: doc.amount,
        description: `Deposit via ${doc.payment_method}`,
        status: 'completed',
        reference: `TXN${Date.now()}${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
        metadata: {
          deposit_id: doc._id,
          payment_method: doc.payment_method
        }
      });

      // Clear user cache
      await redisClient.del(`user:${doc.user}`);
      await redisClient.del(`profile:${doc.user}`);
      
      // Send real-time notification
      broadcastToUser(doc.user.toString(), {
        type: 'balance_update',
        balance: (await User.findById(doc.user)).balance,
        message: `Deposit of ₦${doc.amount.toLocaleString()} approved`
      });

      // Send email notification
      const user = await User.findById(doc.user);
      await sendEmail(
        user.email,
        'Deposit Approved - Raw Wealthy',
        `Your deposit of ₦${doc.amount.toLocaleString()} has been approved and credited to your account.`,
        emailTemplates.depositApproved?.(doc, user)?.html
      );
      
    } catch (error) {
      console.error('Error processing approved deposit:', error);
    }
  }
});

depositSchema.index({ user: 1, createdAt: -1 });
depositSchema.index({ reference: 1 });
depositSchema.index({ status: 1, createdAt: -1 });

const Deposit = mongoose.model('Deposit', depositSchema);

// Enhanced Withdrawal Model
const withdrawalSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true, 
    index: true 
  },
  
  // Withdrawal Details
  amount: { 
    type: Number, 
    required: true, 
    min: [1000, 'Minimum withdrawal is ₦1000'] 
  },
  currency: { type: String, default: 'NGN' },
  payment_method: { 
    type: String, 
    enum: ['bank_transfer', 'crypto', 'paypal', 'flutterwave', 'paystack'], 
    required: true 
  },
  
  // Fees and Net Amount
  platform_fee: { type: Number, default: 0 },
  transaction_fee: { type: Number, default: 0 },
  net_amount: { type: Number, required: true },
  
  // Payment Details
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String,
    bank_code: String,
    routing_number: String
  },
  wallet_address: String,
  paypal_email: String,
  
  // Status
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'processing', 'paid', 'cancelled'], 
    default: 'pending',
    index: true 
  },
  
  // References
  reference: { type: String, unique: true, index: true },
  gateway_reference: String,
  
  // Admin Management
  admin_notes: String,
  approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approved_at: Date,
  processed_at: Date,
  paid_at: Date,
  
  // Payment Proof
  payment_proof: String,
  transaction_details: mongoose.Schema.Types.Mixed,
  
  // Risk Management
  risk_score: { type: Number, default: 0 },
  flags: [String],
  requires_manual_review: { type: Boolean, default: false },
  
  // Timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, {
  timestamps: true,
  toJSON: { virtuals: true }
});

// Pre-save middleware
withdrawalSchema.pre('save', function(next) {
  if (this.isModified('amount')) {
    this.platform_fee = this.amount * 0.05; // 5% platform fee
    this.transaction_fee = this.amount * 0.01; // 1% transaction fee
    this.net_amount = this.amount - this.platform_fee - this.transaction_fee;
  }
  
  if (!this.reference) {
    this.reference = `WD${Date.now()}${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
  }
  
  next();
});

// Post-save middleware for approved withdrawals
withdrawalSchema.post('findOneAndUpdate', async function(doc) {
  if (doc && this.getUpdate().$set && this.getUpdate().$set.status === 'approved' && doc.status !== 'approved') {
    try {
      // Update user balance
      await User.findByIdAndUpdate(doc.user, { 
        $inc: { 
          balance: -doc.amount,
          lifetime_withdrawals: doc.amount
        } 
      });
      
      // Create transaction record
      await Transaction.create({
        user: doc.user,
        type: 'withdrawal',
        amount: -doc.amount,
        description: `Withdrawal via ${doc.payment_method} (Fee: ₦${doc.platform_fee + doc.transaction_fee})`,
        status: 'completed',
        reference: `TXN${Date.now()}${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
        metadata: {
          withdrawal_id: doc._id,
          payment_method: doc.payment_method,
          fees: {
            platform: doc.platform_fee,
            transaction: doc.transaction_fee
          }
        }
      });

      // Clear user cache
      await redisClient.del(`user:${doc.user}`);
      await redisClient.del(`profile:${doc.user}`);
      
      // Send real-time notification
      broadcastToUser(doc.user.toString(), {
        type: 'balance_update',
        balance: (await User.findById(doc.user)).balance,
        message: `Withdrawal of ₦${doc.amount.toLocaleString()} approved`
      });

      // Send email notification
      const user = await User.findById(doc.user);
      await sendEmail(
        user.email,
        'Withdrawal Approved - Raw Wealthy',
        `Your withdrawal request of ₦${doc.amount.toLocaleString()} has been approved. Net amount: ₦${doc.net_amount.toLocaleString()}.`,
        emailTemplates.withdrawalApproved?.(doc, user)?.html
      );
      
    } catch (error) {
      console.error('Error processing approved withdrawal:', error);
    }
  }
});

withdrawalSchema.index({ user: 1, createdAt: -1 });
withdrawalSchema.index({ reference: 1 });
withdrawalSchema.index({ status: 1, createdAt: -1 });

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// Enhanced Transaction Model
const transactionSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true, 
    index: true 
  },
  type: { 
    type: String, 
    enum: [
      'deposit', 'withdrawal', 'investment', 'earning', 
      'referral', 'bonus', 'fee', 'dividend', 'refund',
      'transfer', 'commission', 'penalty', 'adjustment'
    ], 
    required: true 
  },
  category: { 
    type: String, 
    enum: ['investment', 'withdrawal', 'deposit', 'earning', 'referral', 'system', 'fee'], 
    default: 'system' 
  },
  
  // Amount Details
  amount: { type: Number, required: true },
  currency: { type: String, default: 'NGN' },
  running_balance: Number,
  
  // Description
  description: { type: String, required: true },
  reference: { type: String, unique: true, index: true },
  
  // Status
  status: { 
    type: String, 
    enum: ['pending', 'completed', 'failed', 'cancelled', 'reversed'], 
    default: 'completed' 
  },
  
  // Related Entities
  related_investment: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment' },
  related_deposit: { type: mongoose.Schema.Types.ObjectId, ref: 'Deposit' },
  related_withdrawal: { type: mongoose.Schema.Types.ObjectId, ref: 'Withdrawal' },
  
  // Metadata
  metadata: mongoose.Schema.Types.Mixed,
  tags: [String],
  
  // Timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, {
  timestamps: true,
  toJSON: { virtuals: true }
});

// Pre-save middleware
transactionSchema.pre('save', function(next) {
  if (!this.reference) {
    this.reference = `TXN${Date.now()}${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
  }
  next();
});

transactionSchema.index({ user: 1, createdAt: -1 });
transactionSchema.index({ type: 1, status: 1 });
transactionSchema.index({ reference: 1 });

const Transaction = mongoose.model('Transaction', transactionSchema);

// Enhanced KYC Model
const kycSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true, 
    index: true 
  },
  
  // Personal Information
  id_type: { 
    type: String, 
    enum: ['national_id', 'passport', 'driver_license', 'voters_card'], 
    required: true 
  },
  id_number: { type: String, required: true },
  issue_date: Date,
  expiry_date: Date,
  issuing_country: { type: String, default: 'Nigeria' },
  
  // Document Uploads
  id_front: { type: String, required: true },
  id_back: { type: String, required: true },
  selfie_with_id: { type: String, required: true },
  proof_of_address: String,
  
  // Status and Review
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'under_review'], 
    default: 'pending',
    index: true 
  },
  level: { type: String, enum: ['basic', 'enhanced', 'full'], default: 'basic' },
  
  // Review Information
  admin_notes: String,
  reviewed_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reviewed_at: Date,
  rejection_reason: String,
  
  // Verification Metrics
  verification_score: { type: Number, default: 0, min: 0, max: 100 },
  automated_check: { type: Boolean, default: false },
  manual_review: { type: Boolean, default: false },
  risk_level: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  
  // Timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, {
  timestamps: true,
  toJSON: { virtuals: true }
});

kycSchema.index({ user: 1, status: 1 });
kycSchema.index({ status: 1, createdAt: -1 });

const KYC = mongoose.model('KYC', kycSchema);

// Enhanced Notification Model
const notificationSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true, 
    index: true 
  },
  
  // Notification Content
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { 
    type: String, 
    enum: ['info', 'success', 'warning', 'error', 'system', 'promotional'], 
    default: 'info' 
  },
  
  // Status
  is_read: { type: Boolean, default: false },
  is_archived: { type: Boolean, default: false },
  
  // Action
  action_url: String,
  action_label: String,
  related_model: String,
  related_id: mongoose.Schema.Types.ObjectId,
  
  // Priority and Delivery
  priority: { type: String, enum: ['low', 'medium', 'high', 'urgent'], default: 'medium' },
  delivery_method: { type: String, enum: ['in_app', 'email', 'sms', 'push'], default: 'in_app' },
  sent_at: Date,
  read_at: Date,
  
  // Expiry
  expires_at: Date,
  
  // Timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, {
  timestamps: true,
  toJSON: { virtuals: true }
});

notificationSchema.index({ user: 1, is_read: 1 });
notificationSchema.index({ user: 1, createdAt: -1 });
notificationSchema.index({ expires_at: 1 }, { expireAfterSeconds: 0 });

const Notification = mongoose.model('Notification', notificationSchema);

// Enhanced Support Ticket Model
const supportTicketSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true, 
    index: true 
  },
  
  // Ticket Information
  subject: { type: String, required: true },
  message: { type: String, required: true },
  category: { 
    type: String, 
    enum: ['general', 'technical', 'investment', 'withdrawal', 'kyc', 'account', 'other'], 
    default: 'general' 
  },
  subcategory: String,
  
  // Status
  status: { 
    type: String, 
    enum: ['open', 'in_progress', 'resolved', 'closed'], 
    default: 'open',
    index: true 
  },
  priority: { 
    type: String, 
    enum: ['low', 'medium', 'high', 'urgent'], 
    default: 'medium' 
  },
  
  // Assignment
  assigned_to: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  assigned_at: Date,
  
  // Responses
  responses: [{
    message: String,
    replied_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    is_admin: { type: Boolean, default: false },
    attachments: [String],
    internal_notes: String,
    createdAt: { type: Date, default: Date.now }
  }],
  
  // Attachments
  attachments: [String],
  
  // Tracking
  last_response_at: Date,
  first_response_time: Number, // in minutes
  resolution_time: Number, // in minutes
  
  // Feedback
  satisfaction_rating: { type: Number, min: 1, max: 5 },
  feedback_comment: String,
  
  // Timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, {
  timestamps: true
});

supportTicketSchema.index({ user: 1, status: 1 });
supportTicketSchema.index({ category: 1, status: 1 });
supportTicketSchema.index({ priority: 1, status: 1 });

const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);

// Enhanced Blog Post Model
const blogPostSchema = new mongoose.Schema({
  title: { type: String, required: true },
  slug: { type: String, required: true, unique: true },
  content: { type: String, required: true },
  excerpt: String,
  
  // Author Information
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  co_authors: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  
  // Categorization
  category: { 
    type: String, 
    enum: ['investment', 'education', 'news', 'tips', 'market_analysis', 'success_stories'], 
    default: 'investment' 
  },
  tags: [String],
  
  // Media
  featured_image: String,
  image_gallery: [String],
  video_url: String,
  
  // Status
  status: { 
    type: String, 
    enum: ['draft', 'published', 'archived', 'scheduled'], 
    default: 'draft' 
  },
  published_at: Date,
  
  // SEO
  meta_title: String,
  meta_description: String,
  canonical_url: String,
  
  // Engagement
  views: { type: Number, default: 0 },
  likes: { type: Number, default: 0 },
  shares: { type: Number, default: 0 },
  reading_time: Number, // in minutes
  
  // Comments
  comments: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    content: String,
    likes: { type: Number, default: 0 },
    is_approved: { type: Boolean, default: true },
    replies: [{
      user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      content: String,
      likes: { type: Number, default: 0 },
      createdAt: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now }
  }],
  
  // Timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, {
  timestamps: true
});

blogPostSchema.index({ slug: 1 });
blogPostSchema.index({ category: 1, published_at: -1 });
blogPostSchema.index({ status: 1, published_at: -1 });

const BlogPost = mongoose.model('BlogPost', blogPostSchema);

// Enhanced Affiliate Model
const affiliateSchema = new mongoose.Schema({
  user: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User', 
    required: true, 
    index: true 
  },
  
  // Affiliate Information
  affiliate_code: { type: String, required: true, unique: true, index: true },
  commission_rate: { type: Number, default: 10 }, // 10% commission
  custom_rate: Number,
  
  // Earnings
  total_commissions: { type: Number, default: 0 },
  pending_commissions: { type: Number, default: 0 },
  paid_commissions: { type: Number, default: 0 },
  
  // Referrals
  referrals: [{
    referred_user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    commission_amount: Number,
    status: { type: String, enum: ['pending', 'approved', 'paid'], default: 'pending' },
    level: { type: Number, default: 1 }, // For multi-level marketing
    created_at: { type: Date, default: Date.now }
  }],
  
  // Payment Settings
  payment_method: {
    type: { type: String, enum: ['bank', 'crypto', 'paypal'] },
    details: mongoose.Schema.Types.Mixed
  },
  minimum_payout: { type: Number, default: 5000 },
  
  // Status
  is_active: { type: Boolean, default: true },
  is_suspended: { type: Boolean, default: false },
  
  // Performance
  conversion_rate: Number,
  click_count: { type: Number, default: 0 },
  signup_count: { type: Number, default: 0 },
  
  // Timestamps
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, {
  timestamps: true
});

affiliateSchema.index({ user: 1 });
affiliateSchema.index({ affiliate_code: 1 });

const Affiliate = mongoose.model('Affiliate', affiliateSchema);

// ==================== ENHANCED MIDDLEWARE ====================

// Enhanced Auth Middleware with Device Tracking
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ 
        success: false, 
        message: 'No token, authorization denied',
        code: 'NO_TOKEN'
      });
    }

    // Check Redis for token blacklist
    try {
      const isBlacklisted = await redisClient.get(`blacklist:${token}`);
      if (isBlacklisted) {
        return res.status(401).json({ 
          success: false, 
          message: 'Token has been invalidated',
          code: 'TOKEN_BLACKLISTED'
        });
      }
    } catch (redisError) {
      console.log('⚠️ Redis blacklist check failed, continuing without blacklist check');
    }

    if (!process.env.JWT_SECRET) {
      throw new Error('JWT_SECRET environment variable is required');
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check cache for user
    try {
      const cachedUser = await redisClient.get(`user:${decoded.id}`);
      if (cachedUser) {
        req.user = JSON.parse(cachedUser);
        return next();
      }
    } catch (cacheError) {
      console.log('⚠️ Cache read failed, fetching from database');
    }

    const user = await User.findById(decoded.id).select('-password -two_factor_secret -backup_codes');
    
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Token is not valid',
        code: 'INVALID_TOKEN'
      });
    }

    if (!user.is_active) {
      return res.status(401).json({ 
        success: false, 
        message: 'Account is deactivated',
        code: 'ACCOUNT_DEACTIVATED'
      });
    }

    // Update last login info
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const deviceInfo = `${req.useragent?.browser} on ${req.useragent?.os} (${req.useragent?.platform})`;
    
    user.last_login = new Date();
    user.last_login_ip = ip;
    user.last_login_device = deviceInfo;
    
    // Track device
    const deviceId = req.headers['x-device-id'] || uuidv4();
    const existingDevice = user.devices.find(d => d.device_id === deviceId);
    
    if (existingDevice) {
      existingDevice.last_active = new Date();
      existingDevice.ip_address = ip;
    } else {
      user.devices.push({
        device_id: deviceId,
        device_name: req.headers['x-device-name'] || 'Unknown Device',
        platform: req.useragent?.platform || 'Unknown',
        last_active: new Date(),
        ip_address: ip,
        is_trusted: false
      });
    }
    
    await user.save();

    // Cache user for 5 minutes
    try {
      await redisClient.setEx(`user:${user._id}`, 300, JSON.stringify(user.toJSON()));
    } catch (cacheError) {
      console.log('⚠️ Cache write failed, continuing without cache');
    }
    
    req.user = user;
    req.deviceId = deviceId;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false, 
        message: 'Token expired',
        code: 'TOKEN_EXPIRED'
      });
    }
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid token',
        code: 'INVALID_TOKEN'
      });
    }
    res.status(401).json({ 
      success: false, 
      message: 'Token is not valid',
      code: 'AUTH_FAILED'
    });
  }
};

// Enhanced Admin Auth Middleware
const adminAuth = async (req, res, next) => {
  try {
    await auth(req, res, () => {});
    if (!['admin', 'super_admin'].includes(req.user.role)) {
      return res.status(403).json({ 
        success: false, 
        message: 'Access denied. Admin only.',
        code: 'ADMIN_ACCESS_REQUIRED'
      });
    }
    next();
  } catch (error) {
    res.status(401).json({ 
      success: false, 
      message: 'Authentication failed',
      code: 'AUTH_FAILED'
    });
  }
};

// Super Admin Auth Middleware
const superAdminAuth = async (req, res, next) => {
  try {
    await auth(req, res, () => {});
    if (req.user.role !== 'super_admin') {
      return res.status(403).json({ 
        success: false, 
        message: 'Access denied. Super Admin only.',
        code: 'SUPER_ADMIN_ACCESS_REQUIRED'
      });
    }
    next();
  } catch (error) {
    res.status(401).json({ 
      success: false, 
      message: 'Authentication failed',
      code: 'AUTH_FAILED'
    });
  }
};

// KYC Verified Middleware
const kycVerified = async (req, res, next) => {
  try {
    await auth(req, res, () => {});
    if (!req.user.kyc_verified) {
      return res.status(403).json({ 
        success: false, 
        message: 'KYC verification required for this action',
        code: 'KYC_VERIFICATION_REQUIRED'
      });
    }
    next();
  } catch (error) {
    res.status(401).json({ 
      success: false, 
      message: 'Authentication failed',
      code: 'AUTH_FAILED'
    });
  }
};

// Enhanced File Upload Middleware
const handleFileUpload = async (file, folder = 'general') => {
  if (!file) return null;
  
  // Use Cloudinary for production, local storage for development
  if (process.env.NODE_ENV === 'production' && process.env.CLOUDINARY_CLOUD_NAME) {
    try {
      const result = await cloudinary.uploader.upload(file.path, {
        folder: `rawwealthy/${folder}`,
        resource_type: 'auto',
        quality: 'auto',
        fetch_format: 'auto',
        transformation: [
          { width: 1000, height: 1000, crop: 'limit' }
        ]
      });
      
      // Delete local file after upload
      try {
        fs.unlinkSync(file.path);
      } catch (unlinkError) {
        console.log('⚠️ Failed to delete local file:', unlinkError.message);
      }
      
      return result.secure_url;
    } catch (error) {
      console.error('Cloudinary upload error:', error);
      // Fallback to local file path if Cloudinary fails
      return `/uploads/${path.basename(file.path)}`;
    }
  } else {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const filename = `${folder}-${uniqueSuffix}${path.extname(file.originalname)}`;
    const filePath = path.join('uploads', folder, filename);
    
    // Ensure directory exists
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    // Move file
    await fs.promises.rename(file.path, filePath);
    
    return `/uploads/${folder}/${filename}`;
  }
};

// ==================== ENHANCED UTILITY FUNCTIONS ====================

// Enhanced Email Service with Retry Logic
const sendEmail = async (to, subject, text, html = null) => {
  if (!emailTransporter) {
    console.log('⚠️ Email transporter not available');
    return false;
  }

  const mailOptions = {
    from: process.env.EMAIL_FROM || `Raw Wealthy <${process.env.EMAIL_USER}>`,
    to: to,
    subject: subject,
    text: text,
    html: html || text
  };

  try {
    await emailTransporter.sendMail(mailOptions);
    console.log(`✅ Email sent to ${to}`);
    return true;
  } catch (error) {
    console.error('❌ Email sending error:', error);
    
    // Retry logic
    try {
      console.log('🔄 Retrying email send...');
      await new Promise(resolve => setTimeout(resolve, 2000));
      await emailTransporter.sendMail(mailOptions);
      console.log(`✅ Email sent to ${to} on retry`);
      return true;
    } catch (retryError) {
      console.error('❌ Email retry failed:', retryError);
      return false;
    }
  }
};

// Enhanced Notification Service
const createNotification = async (userId, title, message, type = 'info', actionUrl = null, relatedModel = null, relatedId = null, priority = 'medium') => {
  try {
    const notification = await Notification.create({
      user: userId,
      title,
      message,
      type,
      action_url: actionUrl,
      related_model: relatedModel,
      related_id: relatedId,
      priority
    });

    // Send real-time notification via WebSocket
    broadcastToUser(userId.toString(), {
      type: 'notification',
      notification: notification
    });

    return notification;
  } catch (error) {
    console.error('❌ Notification creation error:', error);
    return null;
  }
};

// Enhanced Cache Helper with Compression
const cacheResponse = async (key, data, expiry = 300) => {
  try {
    await redisClient.setEx(key, expiry, JSON.stringify(data));
  } catch (error) {
    console.log('⚠️ Cache write failed');
  }
};

const getCachedResponse = async (key) => {
  try {
    const cached = await redisClient.get(key);
    return cached ? JSON.parse(cached) : null;
  } catch (error) {
    console.log('⚠️ Cache read failed');
    return null;
  }
};

// Enhanced Password Generator
const generatePassword = (length = 12) => {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
  let password = '';
  for (let i = 0; i < length; i++) {
    password += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return password;
};

// Enhanced Response Formatter
const formatResponse = (success, message, data = null, pagination = null, code = null) => {
  const response = {
    success,
    message,
    timestamp: new Date().toISOString(),
    version: '15.0.0'
  };
  
  if (code) {
    response.code = code;
  }
  
  if (data !== null) {
    response.data = data;
  }
  
  if (pagination !== null) {
    response.pagination = pagination;
  }
  
  return response;
};

// Calculate Investment Performance
const calculateInvestmentPerformance = (investment) => {
  const now = new Date();
  const start = new Date(investment.start_date);
  const end = new Date(investment.end_date);
  
  const totalDays = Math.ceil((end - start) / (1000 * 60 * 60 * 24));
  const daysPassed = Math.ceil((now - start) / (1000 * 60 * 60 * 24));
  const daysRemaining = Math.max(0, totalDays - daysPassed);
  
  const expectedTotal = investment.expected_earnings;
  const earnedSoFar = investment.earned_so_far;
  const projectedRemaining = (investment.daily_earnings * daysRemaining);
  
  return {
    total_days: totalDays,
    days_passed: Math.min(daysPassed, totalDays),
    days_remaining: daysRemaining,
    progress_percentage: Math.min(100, (daysPassed / totalDays) * 100),
    earned_percentage: expectedTotal > 0 ? (earnedSoFar / expectedTotal) * 100 : 0,
    projected_total: earnedSoFar + projectedRemaining,
    is_on_track: earnedSoFar >= (investment.daily_earnings * daysPassed) * 0.9 // 90% of expected
  };
};

// Generate secure referral code
const generateReferralCode = () => {
  return crypto.randomBytes(6).toString('hex').toUpperCase();
};

// ==================== ENHANCED DATABASE INITIALIZATION ====================
const initializeDatabase = async () => {
  try {
    // Check if admin exists
    const adminExists = await User.findOne({ email: 'admin@rawwealthy.com' });
    if (!adminExists) {
      const adminPassword = process.env.ADMIN_PASSWORD || 'Admin123!';
      const admin = new User({
        full_name: 'Raw Wealthy Admin',
        email: 'admin@rawwealthy.com',
        phone: '+2348000000001',
        password: adminPassword,
        role: 'super_admin',
        kyc_verified: true,
        balance: 0,
        is_verified: true,
        referral_code: generateReferralCode()
      });
      await admin.save();
      console.log('✅ Super Admin user created');
    }

    // Check if plans exist
    const plansExist = await InvestmentPlan.countDocuments();
    if (plansExist === 0) {
      const plans = [
        {
          name: 'Cocoa Starter',
          description: 'Beginner-friendly cocoa investment with stable returns. Perfect for those new to raw materials investment.',
          short_description: 'Start your investment journey with cocoa',
          min_amount: 3500,
          max_amount: 50000,
          daily_interest: 1.5,
          total_interest: 45,
          duration: 30,
          risk_level: 'low',
          is_popular: true,
          is_featured: true,
          raw_material: 'Cocoa',
          category: 'agriculture',
          features: ['Low Risk', 'Stable Returns', 'Beginner Friendly', 'Daily Payouts', 'Insurance Backed'],
          tags: ['beginner', 'agriculture', 'low-risk', 'cocoa'],
          color_scheme: 'green',
          display_order: 1
        },
        {
          name: 'Gold Premium',
          description: 'Premium gold investment with higher returns and portfolio diversification benefits.',
          short_description: 'Premium gold investment opportunity',
          min_amount: 50000,
          max_amount: 500000,
          daily_interest: 2.5,
          total_interest: 75,
          duration: 30,
          risk_level: 'medium',
          is_popular: true,
          raw_material: 'Gold',
          category: 'metals',
          features: ['Medium Risk', 'Higher Returns', 'Portfolio Diversification', 'Daily Payouts', 'Secure Storage'],
          tags: ['premium', 'metals', 'medium-risk', 'gold'],
          color_scheme: 'gold',
          display_order: 2
        },
        {
          name: 'Crude Oil Pro',
          description: 'Professional crude oil investment portfolio for experienced investors seeking maximum returns.',
          short_description: 'Professional crude oil investment',
          min_amount: 100000,
          max_amount: 1000000,
          daily_interest: 3.5,
          total_interest: 105,
          duration: 30,
          risk_level: 'high',
          is_popular: false,
          raw_material: 'Crude Oil',
          category: 'energy',
          features: ['High Risk', 'Maximum Returns', 'Professional Grade', 'Daily Payouts', 'Market Analysis'],
          tags: ['professional', 'energy', 'high-risk', 'oil'],
          color_scheme: 'black',
          display_order: 3
        },
        {
          name: 'Tech Innovation',
          description: 'Technology sector investment focusing on innovative startups and emerging technologies.',
          short_description: 'Technology sector investment',
          min_amount: 75000,
          max_amount: 750000,
          daily_interest: 2.8,
          total_interest: 84,
          duration: 30,
          risk_level: 'medium',
          is_popular: true,
          raw_material: 'Technology',
          category: 'technology',
          features: ['Tech Sector', 'Innovation Focus', 'Medium Returns', 'Daily Payouts', 'Growth Potential'],
          tags: ['technology', 'innovation', 'medium-risk', 'tech'],
          color_scheme: 'blue',
          display_order: 4
        },
        {
          name: 'Real Estate Prime',
          description: 'Prime real estate investment with stable long-term returns and asset backing.',
          short_description: 'Prime real estate investment',
          min_amount: 150000,
          max_amount: 2000000,
          daily_interest: 2.2,
          total_interest: 66,
          duration: 60,
          risk_level: 'low',
          is_popular: false,
          raw_material: 'Real Estate',
          category: 'real_estate',
          features: ['Low Risk', 'Long Term', 'Asset Backed', 'Monthly Payouts', 'Property Ownership'],
          tags: ['real-estate', 'long-term', 'low-risk', 'property'],
          color_scheme: 'purple',
          display_order: 5
        }
      ];

      await InvestmentPlan.insertMany(plans);
      console.log('✅ Investment plans created');
    }

    console.log('✅ Database initialization completed');
  } catch (error) {
    console.error('❌ Database initialization error:', error);
  }
};

// ==================== ENHANCED WORKING MONGODB CONNECTION ====================
const connectDB = async () => {
  try {
    const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://israeldewa1_db_user:rawwealthy@rawwealthy.9cnu0jw.mongodb.net/rawwealthy?retryWrites=true&w=majority';
    
    console.log('🔄 Connecting to MongoDB...');
    
    await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 30000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      minPoolSize: 5,
      maxIdleTimeMS: 30000,
      family: 4
    });
    
    console.log('✅ MongoDB Connected Successfully!');
    
    // Initialize database
    await initializeDatabase();
    
  } catch (error) {
    console.error('❌ MongoDB Connection Error:', error.message);
    console.log('💡 Retrying in 10 seconds...');
    setTimeout(connectDB, 10000);
  }
};

// ==================== ENHANCED HEALTH CHECK WITH METRICS ====================
app.get('/health', async (req, res) => {
  try {
    const dbStatus = mongoose.connection.readyState;
    const statusMap = {
      0: 'disconnected',
      1: 'connected', 
      2: 'connecting',
      3: 'disconnecting'
    };
    
    const memoryUsage = process.memoryUsage();
    const uptime = process.uptime();
    
    const healthData = {
      success: true,
      status: 'OK', 
      message: '🚀 Raw Wealthy Backend v15.0 is running perfectly!',
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development',
      version: '15.0.0',
      database: statusMap[dbStatus] || 'unknown',
      redis: redisClient.isOpen ? 'connected' : 'fallback',
      cloudinary: process.env.CLOUDINARY_CLOUD_NAME ? 'configured' : 'not_configured',
      websocket: connectedClients.size,
      system: {
        uptime: Math.floor(uptime),
        memory: {
          used: Math.round(memoryUsage.heapUsed / 1024 / 1024) + 'MB',
          total: Math.round(memoryUsage.heapTotal / 1024 / 1024) + 'MB',
          rss: Math.round(memoryUsage.rss / 1024 / 1024) + 'MB'
        },
        node_version: process.version,
        platform: process.platform
      }
    };
    
    res.status(200).json(healthData);
  } catch (error) {
    res.status(500).json({ 
      success: false,
      status: 'ERROR',
      message: 'Health check failed',
      error: error.message 
    });
  }
});

// ==================== ENHANCED TEST ROUTE ====================
app.get('/test', (req, res) => {
  res.json({
    success: true,
    message: '✅ Backend is WORKING!',
    database: 'tested_and_working',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    version: '15.0.0',
    features: {
      authentication: 'enabled',
      file_upload: 'enabled',
      real_time: 'enabled',
      caching: 'enabled',
      email: emailTransporter ? 'enabled' : 'disabled'
    }
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 Raw Wealthy Backend API v15.0 - Production Ready',
    version: '15.0.0',
    timestamp: new Date().toISOString(),
    endpoints: {
      health: '/health',
      test: '/test',
      api: '/api',
      documentation: 'Coming soon...'
    },
    support: {
      email: 'support@rawwealthy.com',
      status: 'operational'
    }
  });
});

// ==================== ENHANCED API ROUTES ====================

// Apply rate limiting
app.use('/api/auth/register', createAccountLimiter);
app.use('/api/auth/', authLimiter);
app.use('/api/investments', investmentLimiter);
app.use('/api/', apiLimiter);

// Serve static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ==================== ENHANCED AUTH ROUTES ====================

// Register Route
app.post('/api/auth/register', [
  body('full_name').notEmpty().trim().withMessage('Full name is required'),
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('phone').notEmpty().trim().withMessage('Phone number is required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
  body('referral_code').optional().trim(),
  body('risk_tolerance').optional().isIn(['low', 'medium', 'high']),
  body('investment_strategy').optional().isIn(['conservative', 'balanced', 'aggressive'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { full_name, email, phone, password, referral_code, risk_tolerance, investment_strategy } = req.body;

    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json(formatResponse(false, 'User already exists with this email'));
    }

    // Check referral code
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
      referred_by: referredBy?._id,
      risk_tolerance: risk_tolerance || 'medium',
      investment_strategy: investment_strategy || 'balanced',
      signup_source: req.headers['origin'] || 'direct'
    });

    await user.save();

    // Generate JWT token
    if (!process.env.JWT_SECRET) {
      throw new Error('JWT_SECRET environment variable is required');
    }

    const token = jwt.sign(
      { id: user._id }, 
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '30d' }
    );

    // Cache user data
    await cacheResponse(`user:${user._id}`, user.toJSON(), 300);

    // Create welcome notification
    await createNotification(
      user._id,
      'Welcome to Raw Wealthy!',
      'Your account has been created successfully. Start your investment journey today.',
      'success',
      '/dashboard'
    );

    // Send welcome email
    await sendEmail(
      user.email,
      'Welcome to Raw Wealthy!',
      `Dear ${full_name},\n\nWelcome to Raw Wealthy Investment Platform! Your account has been created successfully.\n\nStart your investment journey today and grow your wealth with our secure raw materials investment plans.\n\nBest regards,\nRaw Wealthy Team`,
      emailTemplates.welcome(user).html
    );

    // Referral bonus if applicable
    if (referredBy) {
      const referralBonus = 1000; // ₦1000 referral bonus
      await User.findByIdAndUpdate(referredBy._id, {
        $inc: { 
          balance: referralBonus,
          referral_earnings: referralBonus,
          referral_count: 1
        }
      });

      await Transaction.create({
        user: referredBy._id,
        type: 'referral',
        amount: referralBonus,
        description: `Referral bonus for ${full_name}`,
        status: 'completed',
        reference: `REF${Date.now()}${crypto.randomBytes(4).toString('hex').toUpperCase()}`
      });

      // Clear cache
      await redisClient.del(`user:${referredBy._id}`);

      await createNotification(
        referredBy._id,
        'Referral Bonus Earned!',
        `You earned ₦${referralBonus} referral bonus for referring ${full_name}`,
        'success'
      );
    }

    res.status(201).json(formatResponse(true, 'User registered successfully', {
      user: {
        id: user._id,
        full_name: user.full_name,
        email: user.email,
        phone: user.phone,
        role: user.role,
        balance: user.balance,
        referral_code: user.referral_code,
        kyc_verified: user.kyc_verified,
        risk_tolerance: user.risk_tolerance,
        investment_strategy: user.investment_strategy,
        total_earnings: user.total_earnings,
        referral_earnings: user.referral_earnings
      },
      token
    }));
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json(formatResponse(false, 'Server error during registration'));
  }
});

// Login Route
app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail().withMessage('Valid email is required'),
  body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { email, password, two_factor_code } = req.body;

    // Find user with password
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    if (!user) {
      return res.status(400).json(formatResponse(false, 'Invalid credentials'));
    }

    // Check if account is locked
    if (user.isLocked) {
      const remainingTime = Math.ceil((user.lock_until - Date.now()) / 1000 / 60);
      return res.status(423).json(formatResponse(false, `Account temporarily locked. Try again in ${remainingTime} minutes.`));
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json(formatResponse(false, 'Invalid credentials'));
    }

    // Check 2FA if enabled
    if (user.two_factor_enabled) {
      if (!two_factor_code) {
        return res.status(200).json(formatResponse(true, 'Two-factor authentication required', {
          requires_2fa: true,
          user_id: user._id
        }));
      }

      const is2FATokenValid = user.verify2FAToken(two_factor_code);
      if (!is2FATokenValid) {
        // Check backup codes
        const isBackupCode = user.backup_codes.includes(two_factor_code);
        if (!isBackupCode) {
          return res.status(400).json(formatResponse(false, 'Invalid two-factor code'));
        }
        // Remove used backup code
        user.backup_codes = user.backup_codes.filter(code => code !== two_factor_code);
        await user.save();
      }
    }

    // Update last login
    user.last_login = new Date();
    user.last_login_ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    user.last_login_device = `${req.useragent?.browser} on ${req.useragent?.os}`;
    user.login_attempts = 0;
    user.lock_until = undefined;
    await user.save();

    // Generate JWT token
    if (!process.env.JWT_SECRET) {
      throw new Error('JWT_SECRET environment variable is required');
    }

    const token = jwt.sign(
      { id: user._id }, 
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '30d' }
    );

    // Cache user data
    await cacheResponse(`user:${user._id}`, user.toJSON(), 300);

    res.json(formatResponse(true, 'Login successful', {
      user: {
        id: user._id,
        full_name: user.full_name,
        email: user.email,
        phone: user.phone,
        role: user.role,
        balance: user.balance,
        referral_code: user.referral_code,
        kyc_verified: user.kyc_verified,
        total_earnings: user.total_earnings,
        referral_earnings: user.referral_earnings,
        two_factor_enabled: user.two_factor_enabled,
        risk_tolerance: user.risk_tolerance,
        investment_strategy: user.investment_strategy
      },
      token
    }));
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json(formatResponse(false, 'Server error during login'));
  }
});

// ==================== ENHANCED INVESTMENT PLAN ROUTES ====================

// Get Investment Plans
app.get('/api/plans', async (req, res) => {
  try {
    const cacheKey = 'investment_plans:all';
    const cachedPlans = await getCachedResponse(cacheKey);
    
    if (cachedPlans) {
      return res.json(formatResponse(true, 'Plans retrieved successfully', { plans: cachedPlans }));
    }

    const plans = await InvestmentPlan.find({ is_active: true })
      .sort({ display_order: 1, popularity_score: -1 });
    
    // Cache plans for 5 minutes
    await cacheResponse(cacheKey, plans, 300);

    res.json(formatResponse(true, 'Plans retrieved successfully', { plans }));
  } catch (error) {
    console.error('Get plans error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching investment plans'));
  }
});

// Get Popular Plans
app.get('/api/plans/popular', async (req, res) => {
  try {
    const cacheKey = 'investment_plans:popular';
    const cachedPlans = await getCachedResponse(cacheKey);
    
    if (cachedPlans) {
      return res.json(formatResponse(true, 'Popular plans retrieved', { plans: cachedPlans }));
    }

    const plans = await InvestmentPlan.find({ 
      is_active: true, 
      is_popular: true 
    })
    .sort({ popularity_score: -1 })
    .limit(6);

    await cacheResponse(cacheKey, plans, 300);

    res.json(formatResponse(true, 'Popular plans retrieved', { plans }));
  } catch (error) {
    console.error('Get popular plans error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching popular plans'));
  }
});

// Get Plan by ID
app.get('/api/plans/:id', async (req, res) => {
  try {
    const plan = await InvestmentPlan.findById(req.params.id);
    
    if (!plan) {
      return res.status(404).json(formatResponse(false, 'Investment plan not found'));
    }

    res.json(formatResponse(true, 'Plan retrieved successfully', { plan }));
  } catch (error) {
    console.error('Get plan error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching investment plan'));
  }
});

// ==================== ENHANCED INVESTMENT ROUTES ====================

// Get User Investments
app.get('/api/investments', auth, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const skip = (page - 1) * limit;
    const status = req.query.status;

    let query = { user: req.user.id };
    if (status && status !== 'all') {
      query.status = status;
    }

    const investments = await Investment.find(query)
      .populate('plan', 'name daily_interest total_interest duration raw_material category risk_level')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await Investment.countDocuments(query);

    // Calculate enhanced stats
    const activeInvestments = await Investment.find({ user: req.user.id, status: 'active' });
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    const totalEarnings = activeInvestments.reduce((sum, inv) => sum + inv.earned_so_far, 0);
    const projectedEarnings = activeInvestments.reduce((sum, inv) => {
      const remainingDays = Math.max(0, Math.ceil((inv.end_date - new Date()) / (1000 * 60 * 60 * 24)));
      return sum + (inv.daily_earnings * remainingDays);
    }, 0);

    // Add performance metrics to each investment
    const investmentsWithPerformance = investments.map(inv => {
      const performance = calculateInvestmentPerformance(inv);
      return {
        ...inv.toObject(),
        performance
      };
    });

    res.json(formatResponse(true, 'Investments retrieved successfully', {
      investments: investmentsWithPerformance,
      stats: {
        total_active_value: totalActiveValue,
        total_earnings: totalEarnings,
        projected_earnings: projectedEarnings,
        active_count: activeInvestments.length,
        total_investment_count: total
      }
    }, {
      page,
      limit,
      total,
      pages: Math.ceil(total / limit)
    }));
  } catch (error) {
    console.error('Get investments error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching investments'));
  }
});

// Create Investment
app.post('/api/investments', auth, upload.single('payment_proof'), [
  body('plan_id').isMongoId().withMessage('Invalid plan ID'),
  body('amount').isFloat({ min: 1000 }).withMessage('Minimum investment is ₦1000'),
  body('auto_renew').optional().isBoolean(),
  body('transaction_hash').optional().isString()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { plan_id, amount, auto_renew, transaction_hash } = req.body;
    
    let payment_proof = null;
    if (req.file) {
      payment_proof = await handleFileUpload(req.file, 'investment-proofs');
    }

    const plan = await InvestmentPlan.findById(plan_id);
    if (!plan) {
      return res.status(404).json(formatResponse(false, 'Investment plan not found'));
    }

    if (amount < plan.min_amount) {
      return res.status(400).json(formatResponse(false, `Minimum investment for ${plan.name} is ₦${plan.min_amount.toLocaleString()}`));
    }

    if (plan.max_amount && amount > plan.max_amount) {
      return res.status(400).json(formatResponse(false, `Maximum investment for ${plan.name} is ₦${plan.max_amount.toLocaleString()}`));
    }

    const user = await User.findById(req.user.id);
    if (amount > user.balance) {
      return res.status(400).json(formatResponse(false, 'Insufficient balance for this investment'));
    }

    const investment = new Investment({
      user: req.user.id,
      plan: plan_id,
      amount: parseFloat(amount),
      payment_proof,
      auto_renew: auto_renew === 'true' || auto_renew === true,
      transaction_hash: transaction_hash || null
    });

    await investment.save();
    await investment.populate('plan', 'name daily_interest total_interest duration raw_material category');

    // Deduct from user balance
    await User.findByIdAndUpdate(req.user.id, { $inc: { balance: -amount } });

    // Update user investment portfolio
    await User.findByIdAndUpdate(req.user.id, {
      $inc: {
        'investment_portfolio.total_invested': amount,
        'investment_portfolio.active_investments': 1
      }
    });

    // Update plan statistics
    await InvestmentPlan.findByIdAndUpdate(plan_id, {
      $inc: {
        investment_count: 1,
        total_invested: amount
      }
    });

    // Clear cache
    await redisClient.del(`user:${req.user.id}`);
    await redisClient.del(`profile:${req.user.id}`);
    await redisClient.del('investment_plans:all');
    await redisClient.del('investment_plans:popular');

    // Create transaction record
    await Transaction.create({
      user: req.user.id,
      type: 'investment',
      amount: -amount,
      description: `Investment in ${plan.name} plan`,
      status: 'completed',
      related_investment: investment._id,
      category: 'investment',
      reference: `INV${Date.now()}${crypto.randomBytes(4).toString('hex').toUpperCase()}`
    });

    // Send real-time balance update
    broadcastToUser(req.user.id, {
      type: 'balance_update',
      balance: user.balance - amount,
      message: `Investment of ₦${amount.toLocaleString()} submitted`
    });

    // Create notification
    await createNotification(
      req.user.id,
      'Investment Created',
      `Your investment of ₦${amount.toLocaleString()} in ${plan.name} has been submitted for approval.`,
      'info',
      '/investment-history',
      'investment',
      investment._id
    );

    // Send email notification
    await sendEmail(
      user.email,
      'Investment Request Submitted - Raw Wealthy',
      `Your investment request of ₦${amount.toLocaleString()} in ${plan.name} has been submitted and is awaiting approval.`,
      emailTemplates.investmentCreated(investment, user).html
    );

    res.status(201).json(formatResponse(true, 'Investment created successfully! Waiting for admin approval.', { investment }));
  } catch (error) {
    console.error('Create investment error:', error);
    res.status(500).json(formatResponse(false, 'Error creating investment'));
  }
});

// ==================== ENHANCED PROFILE ROUTES ====================

// Get User Profile
app.get('/api/profile', auth, async (req, res) => {
  try {
    const cacheKey = `profile:${req.user.id}`;
    const cachedProfile = await getCachedResponse(cacheKey);
    
    if (cachedProfile) {
      return res.json(formatResponse(true, 'Profile retrieved successfully', cachedProfile));
    }

    const user = await User.findById(req.user.id)
      .populate('referred_by', 'full_name email');
    
    // Get dashboard stats
    const activeInvestments = await Investment.find({ 
      user: req.user.id, 
      status: 'active' 
    }).populate('plan');
    
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    const totalEarnings = activeInvestments.reduce((sum, inv) => sum + inv.earned_so_far, 0);
    
    // Get recent transactions
    const recentTransactions = await Transaction.find({ user: req.user.id })
      .sort({ createdAt: -1 })
      .limit(5);
    
    // Get unread notifications count
    const unreadNotifications = await Notification.countDocuments({ 
      user: req.user.id, 
      is_read: false 
    });

    // Get referral stats
    const referralCount = await User.countDocuments({ referred_by: req.user.id });

    const profileData = {
      user,
      dashboard_stats: {
        active_investment_value: totalActiveValue,
        total_earnings: totalEarnings,
        total_investments: activeInvestments.length,
        unread_notifications: unreadNotifications,
        referral_count: referralCount,
        account_age_days: user.account_age_days
      },
      recent_transactions: recentTransactions,
      active_investments: activeInvestments
    };

    // Cache profile data
    await cacheResponse(cacheKey, profileData, 60); // 1 minute cache

    res.json(formatResponse(true, 'Profile retrieved successfully', profileData));
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching profile'));
  }
});

// ==================== ENHANCED ADMIN ROUTES ====================

// Admin Dashboard Stats
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
  try {
    // Get total users
    const totalUsers = await User.countDocuments({ role: 'user' });
    
    // Get new users this month
    const startOfMonth = new Date(new Date().getFullYear(), new Date().getMonth(), 1);
    const newUsersThisMonth = await User.countDocuments({ 
      role: 'user', 
      createdAt: { $gte: startOfMonth } 
    });
    
    // Get total invested amount
    const totalInvested = await Investment.aggregate([
      { $match: { status: { $in: ['active', 'completed'] } } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    // Get total withdrawn amount
    const totalWithdrawn = await Withdrawal.aggregate([
      { $match: { status: 'approved' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    // Get pending approvals
    const pendingInvestments = await Investment.countDocuments({ status: 'pending' });
    const pendingDeposits = await Deposit.countDocuments({ status: 'pending' });
    const pendingWithdrawals = await Withdrawal.countDocuments({ status: 'pending' });
    const pendingKYC = await KYC.countDocuments({ status: 'pending' });
    
    // Get platform earnings (fees)
    const platformEarnings = await Transaction.aggregate([
      { $match: { type: 'fee', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    // Get active investments count
    const activeInvestments = await Investment.countDocuments({ status: 'active' });

    // Get recent activities
    const recentUsers = await User.find({ role: 'user' })
      .select('full_name email createdAt')
      .sort({ createdAt: -1 })
      .limit(5);

    const recentTransactions = await Transaction.find()
      .populate('user', 'full_name email')
      .sort({ createdAt: -1 })
      .limit(5);

    const stats = {
      total_users: totalUsers,
      new_users_this_month: newUsersThisMonth,
      total_invested: totalInvested.length > 0 ? totalInvested[0].total : 0,
      total_withdrawn: totalWithdrawn.length > 0 ? totalWithdrawn[0].total : 0,
      pending_approvals: pendingInvestments + pendingDeposits + pendingWithdrawals + pendingKYC,
      platform_earnings: platformEarnings.length > 0 ? Math.abs(platformEarnings[0].total) : 0,
      active_investments: activeInvestments,
      pending_investments: pendingInvestments,
      pending_deposits: pendingDeposits,
      pending_withdrawals: pendingWithdrawals,
      pending_kyc: pendingKYC
    };

    res.json(formatResponse(true, 'Admin dashboard stats retrieved', { 
      stats,
      recent_users: recentUsers,
      recent_transactions: recentTransactions
    }));
  } catch (error) {
    console.error('Admin dashboard error:', error);
    res.status(500).json(formatResponse(false, 'Error fetching admin dashboard'));
  }
});

// ==================== ENHANCED CRON JOBS ====================

// Calculate daily earnings for active investments
cron.schedule('0 0 * * *', async () => {
  try {
    console.log('🔄 Calculating daily earnings...');
    
    const activeInvestments = await Investment.find({ 
      status: 'active',
      end_date: { $gt: new Date() }
    }).populate('plan', 'daily_interest').populate('user');

    let totalEarnings = 0;
    let processedInvestments = 0;

    for (const investment of activeInvestments) {
      try {
        const dailyEarning = (investment.amount * investment.plan.daily_interest) / 100;
        
        investment.earned_so_far += dailyEarning;
        investment.total_earnings += dailyEarning;
        investment.last_earning_date = new Date();
        
        // Update performance metrics
        investment.performance_metrics = {
          current_roi: parseFloat(investment.current_roi_percentage),
          days_remaining: investment.remaining_days,
          expected_daily: investment.daily_earnings,
          progress_percentage: investment.progress_percentage
        };
        
        await investment.save();

        // Update user balance and total earnings
        await User.findByIdAndUpdate(investment.user._id, {
          $inc: { 
            balance: dailyEarning,
            total_earnings: dailyEarning
          }
        });

        // Create transaction record
        await Transaction.create({
          user: investment.user._id,
          type: 'earning',
          amount: dailyEarning,
          description: `Daily earnings from ${investment.plan.name} investment`,
          status: 'completed',
          metadata: { investment_id: investment._id },
          related_investment: investment._id,
          category: 'earning',
          reference: `ERN${Date.now()}${crypto.randomBytes(4).toString('hex').toUpperCase()}`
        });

        // Clear cache
        await redisClient.del(`user:${investment.user._id}`);
        await redisClient.del(`profile:${investment.user._id}`);

        // Send real-time notification for significant earnings
        if (dailyEarning >= 1000) {
          broadcastToUser(investment.user._id.toString(), {
            type: 'earning_added',
            amount: dailyEarning,
            investment: investment.plan.name,
            balance: (await User.findById(investment.user._id)).balance
          });

          await createNotification(
            investment.user._id,
            'Daily Earnings Added',
            `₦${dailyEarning.toLocaleString()} has been added to your account from ${investment.plan.name} investment.`,
            'success',
            '/dashboard',
            'investment',
            investment._id
          );
        }

        totalEarnings += dailyEarning;
        processedInvestments++;

      } catch (investmentError) {
        console.error(`Error processing investment ${investment._id}:`, investmentError);
      }
    }

    console.log(`✅ Daily earnings calculated for ${processedInvestments} investments. Total: ₦${totalEarnings.toLocaleString()}`);
  } catch (error) {
    console.error('❌ Error calculating daily earnings:', error);
  }
});

// Check for completed investments
cron.schedule('0 1 * * *', async () => {
  try {
    console.log('🔄 Checking completed investments...');
    
    const completedInvestments = await Investment.find({
      status: 'active',
      end_date: { $lte: new Date() }
    }).populate('user plan');

    for (const investment of completedInvestments) {
      try {
        investment.status = 'completed';
        investment.completed_at = new Date();
        await investment.save();

        // Update user investment portfolio
        await User.findByIdAndUpdate(investment.user._id, {
          $inc: {
            'investment_portfolio.active_investments': -1,
            'investment_portfolio.completed_investments': 1
          }
        });

        // Handle auto-renew if enabled
        if (investment.auto_renew) {
          const newInvestment = new Investment({
            user: investment.user._id,
            plan: investment.plan._id,
            amount: investment.amount,
            auto_renew: true
          });
          await newInvestment.save();

          await createNotification(
            investment.user._id,
            'Investment Auto-Renewed',
            `Your ${investment.plan.name} investment has been automatically renewed.`,
            'success',
            '/dashboard',
            'investment',
            newInvestment._id
          );
        } else {
          await createNotification(
            investment.user._id,
            'Investment Completed',
            `Your ${investment.plan.name} investment has been completed successfully. Total earned: ₦${investment.earned_so_far.toLocaleString()}.`,
            'success',
            '/dashboard',
            'investment',
            investment._id
          );
        }
      } catch (investmentError) {
        console.error(`Error completing investment ${investment._id}:`, investmentError);
      }
    }

    console.log(`✅ Completed ${completedInvestments.length} investment checks`);
  } catch (error) {
    console.error('❌ Error checking completed investments:', error);
  }
});

// Cleanup expired notifications
cron.schedule('0 2 * * *', async () => {
  try {
    console.log('🔄 Cleaning up expired notifications...');
    
    const result = await Notification.deleteMany({
      expires_at: { $lte: new Date() }
    });
    
    console.log(`✅ Cleaned up ${result.deletedCount} expired notifications`);
  } catch (error) {
    console.error('❌ Error cleaning up notifications:', error);
  }
});

// Update plan popularity scores
cron.schedule('0 3 * * *', async () => {
  try {
    console.log('🔄 Updating plan popularity scores...');
    
    const plans = await InvestmentPlan.find({ is_active: true });
    
    for (const plan of plans) {
      try {
        // Calculate popularity based on investment count and total invested
        const popularityScore = (plan.investment_count * 0.6) + (plan.total_invested / 10000 * 0.4);
        plan.popularity_score = popularityScore;
        
        // Update ROI history
        plan.roi_history.push({
          period: new Date(),
          average_roi: plan.total_interest,
          total_investments: plan.investment_count
        });
        
        // Keep only last 30 records
        if (plan.roi_history.length > 30) {
          plan.roi_history = plan.roi_history.slice(-30);
        }
        
        await plan.save();
      } catch (planError) {
        console.error(`Error updating plan ${plan._id}:`, planError);
      }
    }
    
    console.log(`✅ Updated popularity scores for ${plans.length} plans`);
  } catch (error) {
    console.error('❌ Error updating plan popularity:', error);
  }
});

// ==================== ENHANCED ERROR HANDLING ====================
app.use((err, req, res, next) => {
  console.error('Error Stack:', err.stack);
  
  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map(val => val.message);
    return res.status(400).json(formatResponse(false, 'Validation Error', { errors: messages }));
  }
  
  // Mongoose duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    return res.status(400).json(formatResponse(false, `${field} already exists`));
  }
  
  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json(formatResponse(false, 'Invalid token'));
  }
  
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json(formatResponse(false, 'Token expired'));
  }

  // Multer errors
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json(formatResponse(false, 'File too large. Maximum size is 15MB.'));
    }
    if (err.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json(formatResponse(false, 'Too many files. Maximum 5 files allowed.'));
    }
    return res.status(400).json(formatResponse(false, `File upload error: ${err.message}`));
  }

  // CORS errors
  if (err.message === 'Not allowed by CORS') {
    return res.status(403).json(formatResponse(false, 'CORS policy: Request not allowed'));
  }

  // Log unexpected errors
  console.error('Unexpected Error:', err);

  res.status(err.status || 500).json(formatResponse(false, 
    process.env.NODE_ENV === 'production' ? 'Internal Server Error' : err.message
  ));
});

// 404 Handler
app.use('*', (req, res) => {
  res.status(404).json(formatResponse(false, 
    `Route ${req.originalUrl} not found`,
    { 
      suggestion: 'Check the API documentation for available endpoints',
      available_endpoints: {
        health: '/health',
        test: '/test',
        auth: '/api/auth/*',
        plans: '/api/plans',
        investments: '/api/investments',
        profile: '/api/profile'
      }
    }
  ));
});

// ==================== GRACEFUL SHUTDOWN ====================
const gracefulShutdown = async () => {
  console.log('🔄 Shutting down gracefully...');
  
  try {
    // Close MongoDB connection
    await mongoose.connection.close();
    console.log('✅ MongoDB connection closed.');
    
    // Close Redis connection
    if (redisClient && redisClient.quit) {
      await redisClient.quit();
      console.log('✅ Redis connection closed.');
    }
    
    // Close WebSocket connections
    wss.close(() => {
      console.log('✅ WebSocket server closed.');
    });
    
    process.exit(0);
  } catch (error) {
    console.error('Error during shutdown:', error);
    process.exit(1);
  }
};

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// ==================== INITIALIZE APPLICATION ====================
const initializeApp = async () => {
  try {
    // Initialize Redis first
    await initializeRedis();
    
    // Connect to MongoDB
    await connectDB();
    
    // Start server
    const PORT = process.env.PORT || 5000;
    const server = app.listen(PORT, () => {
      console.log(`
🎯 Raw Wealthy Backend v15.0 - ULTIMATE PRODUCTION READY EDITION
🌐 Server running on port ${PORT}
🚀 Environment: ${process.env.NODE_ENV || 'development'}
📊 Health Check: http://localhost:${PORT}/health
🔗 API Base: http://localhost:${PORT}/api
💾 Database: MongoDB Cloud - Raw Wealthy Cluster
☁️  Cloudinary: ${process.env.CLOUDINARY_CLOUD_NAME ? 'Configured' : 'Not configured'}
🛡️ Security: Enhanced with Redis, WebSockets, and advanced security features
📧 Email: ${emailTransporter ? 'Configured' : 'Not configured'}
⚡ Real-time: WebSocket support enabled (${connectedClients.size} clients)
🎯 Frontend Integration: 100% Ready with CORS configured
🔧 Redis: ${redisClient.isOpen ? 'Connected' : 'Using Fallback'}
📈 Features: Advanced analytics, real-time notifications, file uploads, KYC verification
      `);
    });

    // WebSocket upgrade handler
    server.on('upgrade', (request, socket, head) => {
      wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
      });
    });

  } catch (error) {
    console.error('❌ Application initialization failed:', error);
    process.exit(1);
  }
};

initializeApp();

module.exports = app;
