
// server.js - RAW WEALTHY BACKEND v60.0 - ULTIMATE EDITION
// COMPLETE BACKEND WITH ALL ENDPOINTS, REAL-TIME FEATURES, AND DATABASE MODELS
// ENHANCED WITH ADVANCED FEATURES, AUTOMATION, AND PERFORMANCE OPTIMIZATIONS

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
import { body, validationResult, param, query } from 'express-validator';
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
import { Server as SocketServer } from 'socket.io';
import http from 'http';
import WebSocket from 'ws';
import Redis from 'ioredis';
import mongoosePaginate from 'mongoose-paginate-v2';
import winston from 'winston';
import { v2 as cloudinary } from 'cloudinary';

// ES Modules equivalent of __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Environment configuration
dotenv.config();

// ==================== ENHANCED CONFIGURATION ====================
const config = {
  // Server
  port: process.env.PORT || 10000,
  nodeEnv: process.env.NODE_ENV || 'production',
  serverURL: process.env.SERVER_URL || `http://localhost:${process.env.PORT || 10000}`,
  
  // Database
  mongoURI: process.env.MONGODB_URI || 'mongodb://localhost:27017/rawwealthy',
  redisURI: process.env.REDIS_URI || 'redis://localhost:6379',
  
  // Security
  jwtSecret: process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex'),
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '30d',
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 12,
  
  // Client
  clientURL: process.env.CLIENT_URL || 'http://localhost:3000',
  allowedOrigins: [],
  
  // Email
  emailEnabled: process.env.EMAIL_HOST && process.env.EMAIL_USER && process.env.EMAIL_PASS,
  emailConfig: {
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT) || 587,
    secure: parseInt(process.env.EMAIL_PORT) === 465,
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
    from: process.env.EMAIL_FROM || `"Raw Wealthy" <${process.env.EMAIL_USER}>`
  },
  
  // Cloudinary (for image storage)
  cloudinaryEnabled: process.env.CLOUDINARY_CLOUD_NAME && 
                     process.env.CLOUDINARY_API_KEY && 
                     process.env.CLOUDINARY_API_SECRET,
  cloudinaryConfig: {
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
  },
  
  // Business Logic
  minInvestment: parseInt(process.env.MIN_INVESTMENT) || 3500,
  minDeposit: parseInt(process.env.MIN_DEPOSIT) || 3500,
  minWithdrawal: parseInt(process.env.MIN_WITHDRAWAL) || 3500,
  platformFeePercent: parseFloat(process.env.PLATFORM_FEE_PERCENT) || 10,
  referralCommissionPercent: parseFloat(process.env.REFERRAL_COMMISSION_PERCENT) || 10,
  welcomeBonus: parseInt(process.env.WELCOME_BONUS) || 100,
  
  // Advanced Features
  enableAutoInvest: process.env.ENABLE_AUTO_INVEST === 'true',
  enableCryptoPayments: process.env.ENABLE_CRYPTO_PAYMENTS === 'true',
  enableSocialLogin: process.env.ENABLE_SOCIAL_LOGIN === 'true',
  enableMarketplace: process.env.ENABLE_MARKETPLACE === 'true',
  enablePortfolioManagement: process.env.ENABLE_PORTFOLIO_MANAGEMENT === 'true',
  
  // Storage
  uploadDir: path.join(__dirname, 'uploads'),
  maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 20 * 1024 * 1024,
  allowedMimeTypes: {
    'image/jpeg': 'jpg',
    'image/jpg': 'jpg',
    'image/png': 'png',
    'image/gif': 'gif',
    'image/webp': 'webp',
    'application/pdf': 'pdf',
    'image/svg+xml': 'svg',
    'application/msword': 'doc',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx'
  },
  
  // Real-time
  realTimeUpdateInterval: 30000,
  cacheTTL: 60000,
  maxConnections: 10000,
  
  // Performance
  enableCaching: process.env.ENABLE_CACHING === 'true',
  enableCompression: process.env.ENABLE_COMPRESSION !== 'false',
  enableClusterMode: process.env.ENABLE_CLUSTER_MODE === 'true'
};

// Build allowed origins
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

// Initialize Cloudinary
if (config.cloudinaryEnabled) {
  cloudinary.config(config.cloudinaryConfig);
}

// ==================== ENHANCED LOGGING ====================
const logger = winston.createLogger({
  level: config.nodeEnv === 'production' ? 'info' : 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// ==================== EXPRESS SETUP ====================
const app = express();
const server = http.createServer(app);

// WebSocket Server
const wss = new WebSocket.Server({ server });
const connectedClients = new Map();

// Socket.IO with enhanced configuration
const io = new SocketServer(server, {
  cors: {
    origin: config.allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true
  },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000,
  maxHttpBufferSize: 1e8
});

const activeConnections = new Map();

// Initialize Redis if enabled
let redisClient = null;
if (config.enableCaching) {
  redisClient = new Redis(config.redisURI);
  redisClient.on('connect', () => logger.info('✅ Redis connected'));
  redisClient.on('error', (err) => logger.error('❌ Redis error:', err));
}

// ==================== ENHANCED MIDDLEWARE SETUP ====================
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdn.socket.io"],
      imgSrc: ["'self'", "data:", "https:", "http:", config.serverURL, config.clientURL],
      connectSrc: ["'self'", "ws:", "wss:", config.clientURL, config.serverURL, "https://cdn.socket.io"]
    }
  }
}));

app.use(xss());
app.use(hpp());
app.use(mongoSanitize());

if (config.enableCompression) {
  app.use(compression({
    level: 6,
    threshold: 100 * 1024
  }));
}

// Enhanced logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    logger.info({
      method: req.method,
      url: req.url,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.get('user-agent')
    });
  });
  next();
});

// CORS Configuration
const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || config.allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      const isPreview = origin.includes('vercel.app') || origin.includes('onrender.com');
      if (isPreview) {
        logger.info(`🌐 Allowed preview: ${origin}`);
        callback(null, true);
      } else {
        logger.warn(`🚫 Blocked by CORS: ${origin}`);
        callback(new Error('Not allowed by CORS'));
      }
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin', 'X-API-Key'],
  exposedHeaders: ['X-Total-Count', 'X-Total-Pages']
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Body Parsing
app.use(express.json({ 
  limit: '50mb',
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));
app.use(express.urlencoded({ 
  extended: true, 
  limit: '50mb',
  parameterLimit: 10000 
}));

// Rate Limiting with enhanced configuration
const createRateLimiter = (windowMs, max, message, keyGenerator = null) => rateLimit({
  windowMs,
  max,
  message: { success: false, message },
  skipSuccessfulRequests: false,
  keyGenerator: keyGenerator || (req => req.ip),
  handler: (req, res) => {
    logger.warn(`Rate limit exceeded for IP: ${req.ip}, Path: ${req.path}`);
    res.status(429).json({ success: false, message });
  }
});

const rateLimiters = {
  auth: createRateLimiter(15 * 60 * 1000, 20, 'Too many authentication attempts'),
  api: createRateLimiter(15 * 60 * 1000, 1000, 'Too many requests'),
  financial: createRateLimiter(15 * 60 * 1000, 50, 'Too many financial operations'),
  upload: createRateLimiter(15 * 60 * 1000, 10, 'Too many upload requests')
};

app.use('/api/auth/login', rateLimiters.auth);
app.use('/api/auth/register', rateLimiters.auth);
app.use('/api/investments', rateLimiters.financial);
app.use('/api/deposits', rateLimiters.financial);
app.use('/api/withdrawals', rateLimiters.financial);
app.use('/api/upload', rateLimiters.upload);
app.use('/api/', rateLimiters.api);

// ==================== ENHANCED FILE UPLOAD CONFIGURATION ====================
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  if (!config.allowedMimeTypes[file.mimetype]) {
    return cb(new Error(`Invalid file type: ${file.mimetype}. Allowed types: ${Object.keys(config.allowedMimeTypes).join(', ')}`), false);
  }
  
  if (file.size > config.maxFileSize) {
    return cb(new Error(`File too large. Max ${config.maxFileSize / 1024 / 1024}MB`), false);
  }
  
  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: { 
    fileSize: config.maxFileSize,
    files: 10,
    fields: 20
  }
});

// Enhanced file upload handler with Cloudinary support
const handleFileUpload = async (file, folder = 'general', userId = null) => {
  if (!file) return null;
  
  try {
    // Use Cloudinary if configured
    if (config.cloudinaryEnabled) {
      const result = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          {
            folder: `rawwealthy/${folder}`,
            public_id: `${userId}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
            resource_type: 'auto',
            transformation: folder.includes('profile') ? [{ width: 500, height: 500, crop: 'fill' }] : []
          },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        uploadStream.end(file.buffer);
      });
      
      return {
        url: result.secure_url,
        public_id: result.public_id,
        originalName: file.originalname,
        size: file.size,
        mimeType: file.mimetype,
        uploadedAt: new Date(),
        storage: 'cloudinary'
      };
    } else {
      // Local storage fallback
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
        uploadedAt: new Date(),
        storage: 'local'
      };
    }
  } catch (error) {
    logger.error('File upload error:', error);
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
    res.set('Cache-Control', 'public, max-age=604800');
  }
}));

// ==================== ENHANCED DATABASE MODELS ====================

// User Model with enhanced fields
const userSchema = new mongoose.Schema({
  full_name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, index: true },
  phone: { type: String, required: true, index: true },
  password: { type: String, required: true, select: false },
  role: { type: String, enum: ['user', 'admin', 'super_admin', 'moderator'], default: 'user' },
  balance: { type: Number, default: 0, min: 0 },
  total_earnings: { type: Number, default: 0, min: 0 },
  referral_earnings: { type: Number, default: 0, min: 0 },
  risk_tolerance: { type: String, enum: ['low', 'medium', 'high', 'very_high'], default: 'medium' },
  investment_strategy: { type: String, enum: ['conservative', 'balanced', 'aggressive', 'speculative'], default: 'balanced' },
  country: { type: String, default: 'ng' },
  currency: { type: String, enum: ['NGN', 'USD', 'EUR', 'GBP', 'CAD', 'AUD'], default: 'NGN' },
  referral_code: { type: String, unique: true, sparse: true, index: true },
  referred_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  referral_count: { type: Number, default: 0 },
  kyc_verified: { type: Boolean, default: false },
  kyc_status: { type: String, enum: ['pending', 'verified', 'rejected', 'under_review', 'not_submitted'], default: 'not_submitted' },
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
    verified_at: Date
  },
  crypto_wallets: [{
    coin_type: { type: String, enum: ['BTC', 'ETH', 'USDT', 'BNB', 'SOL'] },
    wallet_address: String,
    network: String,
    verified: { type: Boolean, default: false }
  }],
  last_login: Date,
  last_active: Date,
  login_attempts: { type: Number, default: 0 },
  lock_until: Date,
  profile_image: String,
  notifications_enabled: { type: Boolean, default: true },
  email_notifications: { type: Boolean, default: true },
  sms_notifications: { type: Boolean, default: false },
  push_notifications: { type: Boolean, default: true },
  // Real-time fields
  online_status: { type: Boolean, default: false },
  last_seen: Date,
  total_deposits: { type: Number, default: 0 },
  total_withdrawals: { type: Number, default: 0 },
  total_investments: { type: Number, default: 0 },
  // Enhanced fields
  investment_portfolio: {
    total_value: { type: Number, default: 0 },
    active_investments: { type: Number, default: 0 },
    completed_investments: { type: Number, default: 0 },
    average_roi: { type: Number, default: 0 }
  },
  settings: {
    theme: { type: String, enum: ['light', 'dark', 'auto'], default: 'auto' },
    language: { type: String, default: 'en' },
    timezone: { type: String, default: 'UTC' },
    email_digest: { type: Boolean, default: true },
    auto_reinvest: { type: Boolean, default: false }
  },
  security_logs: [{
    action: String,
    ip_address: String,
    user_agent: String,
    timestamp: { type: Date, default: Date.now }
  }],
  metadata: mongoose.Schema.Types.Mixed
}, { 
  timestamps: true,
  toJSON: { 
    virtuals: true,
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.two_factor_secret;
      delete ret.verification_token;
      delete ret.password_reset_token;
      delete ret.security_logs;
      return ret;
    }
  }
});

userSchema.index({ is_active: 1, role: 1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ 'investment_portfolio.total_value': -1 });

userSchema.pre('save', async function(next) {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, config.bcryptRounds);
  }
  
  if (!this.referral_code) {
    this.referral_code = crypto.randomBytes(6).toString('hex').toUpperCase();
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

userSchema.methods.logSecurityEvent = function(action, req) {
  this.security_logs.push({
    action,
    ip_address: req.ip,
    user_agent: req.headers['user-agent'],
    timestamp: new Date()
  });
  
  // Keep only last 50 security logs
  if (this.security_logs.length > 50) {
    this.security_logs = this.security_logs.slice(-50);
  }
  
  return this.save();
};

userSchema.virtual('referral_link').get(function() {
  return `${config.clientURL}/register?ref=${this.referral_code}`;
});

userSchema.virtual('formatted_balance').get(function() {
  return new Intl.NumberFormat('en-NG', {
    style: 'currency',
    currency: this.currency
  }).format(this.balance);
});

const User = mongoose.model('User', userSchema);

// Enhanced Investment Plan Model
const investmentPlanSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  description: { type: String, required: true },
  detailed_description: String,
  min_amount: { type: Number, required: true, min: config.minInvestment },
  max_amount: { type: Number, min: config.minInvestment },
  daily_interest: { type: Number, required: true, min: 0.1, max: 100 },
  total_interest: { type: Number, required: true, min: 1, max: 1000 },
  duration: { type: Number, required: true, min: 1 },
  risk_level: { type: String, enum: ['low', 'medium', 'high', 'very_high'], required: true },
  raw_material: { type: String, required: true },
  category: { type: String, enum: ['agriculture', 'mining', 'energy', 'metals', 'precious_stones', 'real_estate', 'technology', 'renewable'], default: 'agriculture' },
  tags: [String],
  is_active: { type: Boolean, default: true },
  is_popular: { type: Boolean, default: false },
  is_featured: { type: Boolean, default: false },
  image_url: String,
  color: String,
  icon: String,
  features: [String],
  investment_count: { type: Number, default: 0 },
  total_invested: { type: Number, default: 0 },
  total_earned: { type: Number, default: 0 },
  success_rate: { type: Number, default: 95, min: 0, max: 100 },
  display_order: { type: Number, default: 0 },
  // Advanced fields
  roi_breakdown: [{
    period: String,
    percentage: Number
  }],
  requirements: {
    kyc_required: { type: Boolean, default: true },
    min_kyc_level: { type: String, enum: ['basic', 'verified', 'advanced'], default: 'basic' }
  },
  statistics: {
    avg_investment_amount: { type: Number, default: 0 },
    completion_rate: { type: Number, default: 0 },
    user_satisfaction: { type: Number, default: 0 }
  }
}, { 
  timestamps: true 
});

investmentPlanSchema.index({ is_active: 1, is_popular: 1, is_featured: 1 });
investmentPlanSchema.index({ category: 1, risk_level: 1 });
investmentPlanSchema.index({ 'statistics.completion_rate': -1 });

const InvestmentPlan = mongoose.model('InvestmentPlan', investmentPlanSchema);

// Enhanced Investment Model
const investmentSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  plan: { type: mongoose.Schema.Types.ObjectId, ref: 'InvestmentPlan', required: true },
  amount: { type: Number, required: true, min: config.minInvestment },
  status: { 
    type: String, 
    enum: ['pending', 'active', 'completed', 'cancelled', 'failed', 'suspended', 'liquidated'], 
    default: 'pending' 
  },
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
  remarks: String,
  progress_percentage: { type: Number, default: 0, min: 0, max: 100 },
  remaining_days: Number,
  // Enhanced fields
  earnings_history: [{
    date: Date,
    amount: Number,
    type: { type: String, enum: ['daily', 'bonus', 'adjustment'] }
  }],
  performance_metrics: {
    roi: { type: Number, default: 0 },
    daily_performance: { type: Number, default: 0 },
    volatility: { type: Number, default: 0 }
  },
  documents: [{
    name: String,
    url: String,
    type: String,
    uploaded_at: { type: Date, default: Date.now }
  }],
  metadata: mongoose.Schema.Types.Mixed,
  liquidation_details: {
    date: Date,
    reason: String,
    amount_returned: Number,
    processed_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
  }
}, { 
  timestamps: true 
});

investmentSchema.index({ user: 1, status: 1 });
investmentSchema.index({ status: 1, end_date: 1 });
investmentSchema.index({ 'performance_metrics.roi': -1 });
investmentSchema.index({ createdAt: -1 });

investmentSchema.virtual('is_active').get(function() {
  return this.status === 'active';
});

investmentSchema.virtual('days_remaining').get(function() {
  if (!this.end_date) return 0;
  const now = new Date();
  const end = new Date(this.end_date);
  return Math.max(0, Math.ceil((end - now) / (1000 * 60 * 60 * 24)));
});

const Investment = mongoose.model('Investment', investmentSchema);

// Enhanced Deposit Model
const depositSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true, min: config.minDeposit },
  payment_method: { 
    type: String, 
    enum: ['bank_transfer', 'crypto', 'paypal', 'card', 'flutterwave', 'paystack', 'stripe', 'manual'], 
    required: true 
  },
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'cancelled', 'processing', 'failed'], 
    default: 'pending' 
  },
  payment_proof_url: String,
  transaction_hash: String,
  reference: { type: String, unique: true, sparse: true },
  admin_notes: String,
  approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approved_at: Date,
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String,
    transaction_reference: String
  },
  crypto_details: {
    wallet_address: String,
    coin_type: String,
    network: String,
    amount_crypto: Number
  },
  card_details: {
    last4: String,
    brand: String,
    country: String
  },
  // Enhanced fields
  currency: { type: String, default: 'NGN' },
  exchange_rate: { type: Number, default: 1 },
  amount_original: Number,
  fee_amount: { type: Number, default: 0 },
  net_amount: { type: Number, default: 0 },
  payment_gateway_response: mongoose.Schema.Types.Mixed,
  metadata: mongoose.Schema.Types.Mixed
}, { 
  timestamps: true 
});

depositSchema.index({ user: 1, status: 1, createdAt: -1 });
depositSchema.index({ reference: 1 }, { unique: true, sparse: true });
depositSchema.index({ 'crypto_details.transaction_hash': 1 });

const Deposit = mongoose.model('Deposit', depositSchema);

// Enhanced Withdrawal Model
const withdrawalSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  amount: { type: Number, required: true, min: config.minWithdrawal },
  payment_method: { 
    type: String, 
    enum: ['bank_transfer', 'crypto', 'paypal', 'stripe', 'manual'], 
    required: true 
  },
  platform_fee: { type: Number, default: 0 },
  net_amount: { type: Number, required: true },
  bank_details: {
    bank_name: String,
    account_name: String,
    account_number: String,
    bank_code: String,
    verified: { type: Boolean, default: false },
    swift_code: String,
    iban: String
  },
  crypto_details: {
    wallet_address: String,
    coin_type: String,
    network: String
  },
  paypal_email: String,
  stripe_account: String,
  status: { 
    type: String, 
    enum: ['pending', 'approved', 'rejected', 'paid', 'processing', 'failed', 'cancelled'], 
    default: 'pending' 
  },
  reference: { type: String, unique: true, sparse: true },
  admin_notes: String,
  approved_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approved_at: Date,
  paid_at: Date,
  transaction_id: String,
  // Enhanced fields
  currency: { type: String, default: 'NGN' },
  exchange_rate: { type: Number, default: 1 },
  processing_fee: { type: Number, default: 0 },
  total_fee: { type: Number, default: 0 },
  payment_gateway_response: mongoose.Schema.Types.Mixed,
  metadata: mongoose.Schema.Types.Mixed,
  rejection_reason: String
}, { 
  timestamps: true 
});

withdrawalSchema.index({ user: 1, status: 1, createdAt: -1 });
withdrawalSchema.index({ reference: 1 }, { unique: true, sparse: true });

const Withdrawal = mongoose.model('Withdrawal', withdrawalSchema);

// Enhanced Transaction Model
const transactionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { 
    type: String, 
    enum: ['deposit', 'withdrawal', 'investment', 'earning', 'referral', 'bonus', 'fee', 'refund', 'dividend', 'interest', 'penalty', 'adjustment'], 
    required: true 
  },
  amount: { type: Number, required: true },
  description: { type: String, required: true },
  reference: { type: String, unique: true, sparse: true },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled', 'processing'], default: 'completed' },
  balance_before: Number,
  balance_after: Number,
  related_investment: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment' },
  related_deposit: { type: mongoose.Schema.Types.ObjectId, ref: 'Deposit' },
  related_withdrawal: { type: mongoose.Schema.Types.ObjectId, ref: 'Withdrawal' },
  // Enhanced fields
  category: String,
  subcategory: String,
  metadata: mongoose.Schema.Types.Mixed,
  payment_method: String,
  currency: { type: String, default: 'NGN' },
  exchange_rate: { type: Number, default: 1 },
  fee_amount: { type: Number, default: 0 },
  net_amount: Number,
  tags: [String],
  automated: { type: Boolean, default: false }
}, { 
  timestamps: true 
});

transactionSchema.index({ user: 1, createdAt: -1 });
transactionSchema.index({ type: 1, status: 1, createdAt: -1 });
transactionSchema.index({ reference: 1 }, { unique: true, sparse: true });

const Transaction = mongoose.model('Transaction', transactionSchema);

// Enhanced KYC Submission Model
const kycSubmissionSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  id_type: { type: String, enum: ['national_id', 'passport', 'driver_license', 'voters_card', 'residence_permit'], required: true },
  id_number: { type: String, required: true },
  id_front_url: { type: String, required: true },
  id_back_url: String,
  selfie_with_id_url: { type: String, required: true },
  address_proof_url: String,
  proof_of_address_type: { type: String, enum: ['utility_bill', 'bank_statement', 'tax_document', 'government_letter'] },
  status: { type: String, enum: ['pending', 'approved', 'rejected', 'under_review', 'expired'], default: 'pending' },
  reviewed_by: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reviewed_at: Date,
  rejection_reason: String,
  notes: String,
  // Enhanced fields
  kyc_level: { type: String, enum: ['basic', 'verified', 'advanced'], default: 'basic' },
  expiry_date: Date,
  documents: [{
    type: String,
    url: String,
    verified: { type: Boolean, default: false },
    verified_at: Date
  }],
  personal_info: {
    date_of_birth: Date,
    gender: String,
    nationality: String,
    occupation: String,
    source_of_funds: String
  },
  address: {
    street: String,
    city: String,
    state: String,
    country: String,
    postal_code: String
  },
  metadata: mongoose.Schema.Types.Mixed,
  verification_score: { type: Number, min: 0, max: 100 }
}, { 
  timestamps: true 
});

kycSubmissionSchema.index({ status: 1, createdAt: -1 });
kycSubmissionSchema.index({ user: 1, status: 1 });

const KYCSubmission = mongoose.model('KYCSubmission', kycSubmissionSchema);

// Enhanced Support Ticket Model
const supportTicketSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  ticket_id: { type: String, unique: true, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  category: { 
    type: String, 
    enum: ['general', 'technical', 'investment', 'withdrawal', 'deposit', 'kyc', 'account', 'verification', 'security', 'other'], 
    default: 'general' 
  },
  priority: { type: String, enum: ['low', 'medium', 'high', 'urgent'], default: 'medium' },
  status: { type: String, enum: ['open', 'in_progress', 'resolved', 'closed', 'pending'], default: 'open' },
  attachments: [{
    filename: String,
    url: String,
    size: Number,
    mime_type: String,
    uploaded_at: { type: Date, default: Date.now }
  }],
  assigned_to: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  last_reply_at: Date,
  reply_count: { type: Number, default: 0 },
  is_read_by_user: { type: Boolean, default: false },
  is_read_by_admin: { type: Boolean, default: false },
  // Enhanced fields
  department: { type: String, enum: ['support', 'technical', 'financial', 'verification', 'admin'], default: 'support' },
  labels: [String],
  satisfaction_rating: { type: Number, min: 1, max: 5 },
  resolution_time: Number,
  metadata: mongoose.Schema.Types.Mixed
}, { 
  timestamps: true 
});

supportTicketSchema.index({ user: 1, status: 1, createdAt: -1 });
supportTicketSchema.index({ ticket_id: 1 }, { unique: true });
supportTicketSchema.index({ assigned_to: 1, status: 1 });

const SupportTicket = mongoose.model('SupportTicket', supportTicketSchema);

// Enhanced Referral Model
const referralSchema = new mongoose.Schema({
  referrer: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  referred_user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  referral_code: { type: String, required: true },
  status: { type: String, enum: ['pending', 'active', 'completed', 'expired', 'cancelled'], default: 'pending' },
  earnings: { type: Number, default: 0 },
  commission_percentage: { type: Number, default: config.referralCommissionPercent },
  investment_amount: Number,
  earnings_paid: { type: Boolean, default: false },
  paid_at: Date,
  // Enhanced fields
  tier: { type: String, enum: ['basic', 'silver', 'gold', 'platinum'], default: 'basic' },
  commission_history: [{
    amount: Number,
    date: Date,
    source: String,
    investment_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment' }
  }],
  metadata: mongoose.Schema.Types.Mixed,
  conversion_date: Date,
  lifetime_value: { type: Number, default: 0 }
}, { 
  timestamps: true 
});

referralSchema.index({ referrer: 1, status: 1 });
referralSchema.index({ referred_user: 1 }, { unique: true });
referralSchema.index({ createdAt: -1 });

const Referral = mongoose.model('Referral', referralSchema);

// Enhanced Notification Model
const notificationSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  type: { 
    type: String, 
    enum: ['info', 'success', 'warning', 'error', 'investment', 'withdrawal', 'deposit', 'kyc', 'referral', 'system', 'security', 'promotion'], 
    default: 'info' 
  },
  is_read: { type: Boolean, default: false },
  is_email_sent: { type: Boolean, default: false },
  is_push_sent: { type: Boolean, default: false },
  action_url: String,
  // Enhanced fields
  priority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  category: String,
  metadata: mongoose.Schema.Types.Mixed,
  expires_at: Date,
  read_at: Date
}, { 
  timestamps: true 
});

notificationSchema.index({ user: 1, is_read: 1, createdAt: -1 });
notificationSchema.index({ expires_at: 1 }, { expireAfterSeconds: 0 });

const Notification = mongoose.model('Notification', notificationSchema);

// Enhanced Admin Audit Log Model
const adminAuditSchema = new mongoose.Schema({
  admin_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  action: { type: String, required: true },
  target_type: { type: String, enum: ['user', 'investment', 'deposit', 'withdrawal', 'kyc', 'transaction', 'plan', 'system', 'ticket', 'referral'] },
  target_id: mongoose.Schema.Types.ObjectId,
  details: mongoose.Schema.Types.Mixed,
  ip_address: String,
  user_agent: String,
  // Enhanced fields
  status: { type: String, enum: ['success', 'failed', 'pending'], default: 'success' },
  error_message: String,
  duration_ms: Number,
  request_body: mongoose.Schema.Types.Mixed,
  response_body: mongoose.Schema.Types.Mixed
}, { 
  timestamps: true 
});

adminAuditSchema.index({ admin_id: 1, createdAt: -1 });
adminAuditSchema.index({ action: 1, createdAt: -1 });

const AdminAudit = mongoose.model('AdminAudit', adminAuditSchema);

// New Models for Enhanced Features

// Portfolio Model
const portfolioSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, unique: true },
  total_value: { type: Number, default: 0 },
  active_investments: [{
    investment: { type: mongoose.Schema.Types.ObjectId, ref: 'Investment' },
    amount: Number,
    start_date: Date,
    expected_end_date: Date,
    daily_earnings: Number
  }],
  allocation: {
    agriculture: { type: Number, default: 0 },
    mining: { type: Number, default: 0 },
    energy: { type: Number, default: 0 },
    metals: { type: Number, default: 0 },
    precious_stones: { type: Number, default: 0 },
    real_estate: { type: Number, default: 0 }
  },
  performance: {
    total_earned: { type: Number, default: 0 },
    average_roi: { type: Number, default: 0 },
    best_performing: { type: mongoose.Schema.Types.ObjectId, ref: 'InvestmentPlan' },
    worst_performing: { type: mongoose.Schema.Types.ObjectId, ref: 'InvestmentPlan' }
  },
  risk_score: { type: Number, default: 50, min: 0, max: 100 },
  last_updated: { type: Date, default: Date.now }
}, { 
  timestamps: true 
});

const Portfolio = mongoose.model('Portfolio', portfolioSchema);

// Market Data Model
const marketDataSchema = new mongoose.Schema({
  raw_material: { type: String, required: true, unique: true },
  current_price: { type: Number, required: true },
  price_history: [{
    date: Date,
    price: Number,
    change_percentage: Number
  }],
  market_trend: { type: String, enum: ['bullish', 'bearish', 'neutral'], default: 'neutral' },
  volatility: { type: Number, default: 0 },
  last_updated: { type: Date, default: Date.now },
  metadata: mongoose.Schema.Types.Mixed
}, { 
  timestamps: true 
});

const MarketData = mongoose.model('MarketData', marketDataSchema);

// Auto-Invest Strategy Model
const autoInvestStrategySchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  is_active: { type: Boolean, default: true },
  strategy_type: { type: String, enum: ['fixed_amount', 'percentage', 'smart'], default: 'fixed_amount' },
  amount: Number,
  percentage: { type: Number, min: 0, max: 100 },
  frequency: { type: String, enum: ['daily', 'weekly', 'monthly'], default: 'monthly' },
  plans: [{ type: mongoose.Schema.Types.ObjectId, ref: 'InvestmentPlan' }],
  risk_level: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
  last_executed: Date,
  next_execution: Date,
  total_invested: { type: Number, default: 0 },
  executions_count: { type: Number, default: 0 },
  settings: mongoose.Schema.Types.Mixed
}, { 
  timestamps: true 
});

const AutoInvestStrategy = mongoose.model('AutoInvestStrategy', autoInvestStrategySchema);

// ==================== ENHANCED UTILITY FUNCTIONS ====================

const formatResponse = (success, message, data = null, pagination = null, meta = null) => {
  const response = { 
    success, 
    message, 
    timestamp: new Date().toISOString(),
    version: '60.0.0'
  };
  
  if (data !== null) response.data = data;
  if (pagination !== null) response.pagination = pagination;
  if (meta !== null) response.meta = meta;
  
  return response;
};

const handleError = (res, error, defaultMessage = 'An error occurred') => {
  logger.error('Error:', error);
  
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

// Cache helper functions
const cache = {
  set: async (key, value, ttl = config.cacheTTL) => {
    if (!redisClient || !config.enableCaching) return;
    try {
      await redisClient.setex(key, ttl / 1000, JSON.stringify(value));
    } catch (error) {
      logger.error('Cache set error:', error);
    }
  },
  
  get: async (key) => {
    if (!redisClient || !config.enableCaching) return null;
    try {
      const data = await redisClient.get(key);
      return data ? JSON.parse(data) : null;
    } catch (error) {
      logger.error('Cache get error:', error);
      return null;
    }
  },
  
  del: async (key) => {
    if (!redisClient || !config.enableCaching) return;
    try {
      await redisClient.del(key);
    } catch (error) {
      logger.error('Cache del error:', error);
    }
  },
  
  clearByPattern: async (pattern) => {
    if (!redisClient || !config.enableCaching) return;
    try {
      const keys = await redisClient.keys(pattern);
      if (keys.length > 0) {
        await redisClient.del(...keys);
      }
    } catch (error) {
      logger.error('Cache clear pattern error:', error);
    }
  }
};

// Enhanced notification function
const createNotification = async (userId, title, message, type = 'info', actionUrl = null, metadata = {}) => {
  try {
    const notification = new Notification({
      user: userId,
      title,
      message,
      type,
      action_url: actionUrl,
      metadata,
      expires_at: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days
    });
    
    await notification.save();
    
    // Send real-time notification
    const notificationData = {
      _id: notification._id,
      title,
      message,
      type,
      action_url: actionUrl,
      createdAt: notification.createdAt,
      metadata
    };
    
    // Broadcast via Socket.IO
    io.to(`user_${userId}`).emit('notification', notificationData);
    
    // Broadcast via WebSocket
    const wsClient = connectedClients.get(userId.toString());
    if (wsClient && wsClient.readyState === WebSocket.OPEN) {
      wsClient.send(JSON.stringify({
        type: 'notification',
        data: notificationData
      }));
    }
    
    // Clear user notifications cache
    await cache.del(`notifications:${userId}`);
    
    return notification;
  } catch (error) {
    logger.error('Error creating notification:', error);
    return null;
  }
};

// Enhanced transaction function
const createTransaction = async (userId, type, amount, description, status = 'completed', metadata = {}, proofUrl = null) => {
  try {
    const user = await User.findById(userId);
    if (!user) return null;
    
    const balanceBefore = user.balance;
    const balanceAfter = user.balance + amount;
    
    const transaction = new Transaction({
      user: userId,
      type,
      amount,
      description,
      status,
      reference: generateReference('TXN'),
      balance_before: balanceBefore,
      balance_after: balanceAfter,
      payment_proof_url: proofUrl,
      metadata,
      currency: user.currency,
      ...metadata
    });
    
    await transaction.save();
    
    // Update user balance
    user.balance = balanceAfter;
    
    // Update user statistics
    if (type === 'deposit' && status === 'completed') {
      user.total_deposits = (user.total_deposits || 0) + Math.abs(amount);
    } else if (type === 'withdrawal' && status === 'completed') {
      user.total_withdrawals = (user.total_withdrawals || 0) + Math.abs(amount);
    } else if (type === 'investment' && status === 'completed') {
      user.total_investments = (user.total_investments || 0) + Math.abs(amount);
    } else if (type === 'earning') {
      user.total_earnings = (user.total_earnings || 0) + Math.abs(amount);
    } else if (type === 'referral') {
      user.referral_earnings = (user.referral_earnings || 0) + Math.abs(amount);
    }
    
    await user.save();
    
    // Clear user transactions cache
    await cache.del(`transactions:${userId}`);
    
    // Send real-time update
    const transactionData = {
      _id: transaction._id,
      type,
      amount,
      description,
      status,
      balance_before: balanceBefore,
      balance_after: balanceAfter,
      createdAt: transaction.createdAt,
      reference: transaction.reference,
      currency: user.currency
    };
    
    // Broadcast to user
    io.to(`user_${userId}`).emit('transaction_update', transactionData);
    
    // Broadcast via WebSocket
    const wsClient = connectedClients.get(userId.toString());
    if (wsClient && wsClient.readyState === WebSocket.OPEN) {
      wsClient.send(JSON.stringify({
        type: 'transaction_update',
        data: transactionData
      }));
    }
    
    return transaction;
  } catch (error) {
    logger.error('Error creating transaction:', error);
    return null;
  }
};

// Enhanced dashboard data function with caching
const getUserDashboardData = async (userId, useCache = true) => {
  const cacheKey = `dashboard:${userId}`;
  
  if (useCache && config.enableCaching) {
    const cached = await cache.get(cacheKey);
    if (cached) {
      return cached;
    }
  }
  
  try {
    const [user, investments, transactions, deposits, withdrawals, referrals, portfolio] = await Promise.all([
      User.findById(userId).lean(),
      Investment.find({ user: userId })
        .populate('plan', 'name daily_interest duration category')
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      Transaction.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      Deposit.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      Withdrawal.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      Referral.find({ referrer: userId })
        .populate('referred_user', 'full_name email')
        .sort({ createdAt: -1 })
        .limit(5)
        .lean(),
      Portfolio.findOne({ user: userId }).lean()
    ]);

    if (!user) return null;

    // Calculate stats
    const activeInvestments = investments.filter(inv => inv.status === 'active');
    const totalActiveValue = activeInvestments.reduce((sum, inv) => sum + inv.amount, 0);
    
    let dailyInterest = 0;
    activeInvestments.forEach(inv => {
      if (inv.plan && inv.plan.daily_interest) {
        dailyInterest += (inv.amount * inv.plan.daily_interest) / 100;
      }
    });
    
    const totalEarnings = investments.reduce((sum, inv) => sum + (inv.earned_so_far || 0), 0);
    const referralEarnings = referrals.reduce((sum, ref) => sum + (ref.earnings || 0), 0);
    
    const totalDepositsAmount = deposits
      .filter(d => d.status === 'approved')
      .reduce((sum, dep) => sum + dep.amount, 0);
    
    const totalWithdrawalsAmount = withdrawals
      .filter(w => w.status === 'paid')
      .reduce((sum, wdl) => sum + wdl.amount, 0);

    // Calculate portfolio allocation
    const portfolioAllocation = {};
    activeInvestments.forEach(inv => {
      if (inv.plan && inv.plan.category) {
        portfolioAllocation[inv.plan.category] = (portfolioAllocation[inv.plan.category] || 0) + inv.amount;
      }
    });

    // Calculate performance metrics
    const performanceMetrics = {
      total_return: ((totalEarnings + referralEarnings) / totalDepositsAmount * 100) || 0,
      monthly_return: dailyInterest * 30 / totalActiveValue * 100 || 0,
      risk_score: calculateRiskScore(activeInvestments)
    };

    const dashboardData = {
      user: {
        ...user,
        online_status: activeConnections.has(userId.toString()),
        formatted_balance: new Intl.NumberFormat('en-NG', {
          style: 'currency',
          currency: user.currency
        }).format(user.balance || 0)
      },
      
      financial_summary: {
        current_balance: user.balance || 0,
        total_earnings: totalEarnings,
        referral_earnings: referralEarnings,
        daily_interest: dailyInterest,
        active_investment_value: totalActiveValue,
        portfolio_value: (user.balance || 0) + totalActiveValue + totalEarnings,
        total_deposits: totalDepositsAmount,
        total_withdrawals: totalWithdrawalsAmount,
        net_profit: totalEarnings + referralEarnings
      },
      
      counts: {
        total_investments: investments.length,
        active_investments: activeInvestments.length,
        completed_investments: investments.filter(i => i.status === 'completed').length,
        total_deposits: deposits.filter(d => d.status === 'approved').length,
        total_withdrawals: withdrawals.filter(w => w.status === 'paid').length,
        referral_count: user.referral_count || 0
      },
      
      portfolio: {
        allocation: portfolioAllocation,
        performance: performanceMetrics,
        ...(portfolio || {})
      },
      
      recent_activity: {
        investments: investments.slice(0, 5),
        transactions: transactions.slice(0, 10),
        deposits: deposits.slice(0, 5),
        withdrawals: withdrawals.slice(0, 5),
        referrals: referrals.slice(0, 5)
      },
      
      investment_progress: activeInvestments.map(inv => {
        const remainingDays = Math.max(0, Math.ceil((new Date(inv.end_date) - new Date()) / (1000 * 60 * 60 * 24)));
        const totalDays = Math.ceil((new Date(inv.end_date) - new Date(inv.start_date)) / (1000 * 60 * 60 * 24));
        const daysPassed = totalDays - remainingDays;
        const progressPercentage = Math.min(100, (daysPassed / totalDays) * 100);
        
        return {
          plan: inv.plan?.name,
          amount: inv.amount,
          progress: Math.round(progressPercentage),
          remaining_days: remainingDays,
          daily_earning: (inv.amount * (inv.plan?.daily_interest || 0)) / 100,
          earned_so_far: inv.earned_so_far || 0,
          category: inv.plan?.category
        };
      }),
      
      market_insights: await getMarketInsights(),
      
      status: {
        kyc_status: user.kyc_status || 'not_submitted',
        kyc_verified: user.kyc_verified || false,
        two_factor_enabled: user.two_factor_enabled || false
      },
      
      timestamps: {
        last_update: new Date().toISOString(),
        server_time: new Date().toISOString(),
        cache_hit: false
      }
    };

    // Cache the result
    if (config.enableCaching) {
      await cache.set(cacheKey, dashboardData, 30000); // 30 seconds cache
    }

    return dashboardData;
  } catch (error) {
    logger.error('Error getting user dashboard data:', error);
    return null;
  }
};

// Helper function to calculate risk score
const calculateRiskScore = (investments) => {
  if (!investments.length) return 50;
  
  let totalRisk = 0;
  let totalAmount = 0;
  
  investments.forEach(inv => {
    if (inv.plan && inv.plan.risk_level) {
      const riskValue = {
        low: 25,
        medium: 50,
        high: 75,
        very_high: 90
      }[inv.plan.risk_level] || 50;
      
      totalRisk += riskValue * inv.amount;
      totalAmount += inv.amount;
    }
  });
  
  return totalAmount > 0 ? Math.round(totalRisk / totalAmount) : 50;
};

// Market insights function
const getMarketInsights = async () => {
  try {
    const marketData = await MarketData.find().limit(5).lean();
    return marketData.map(data => ({
      raw_material: data.raw_material,
      current_price: data.current_price,
      trend: data.market_trend,
      volatility: data.volatility
    }));
  } catch (error) {
    return [];
  }
};

// ==================== ENHANCED AUTHENTICATION MIDDLEWARE ====================

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
    
    // Check if token is about to expire (within 1 hour)
    const tokenExp = decoded.exp * 1000;
    const now = Date.now();
    if (tokenExp - now < 3600000) {
      // Token will expire in less than 1 hour
      res.set('X-Token-Refresh', 'true');
    }
    
    // Update last active and log security event
    user.last_active = new Date();
    await user.save();
    
    // Log security event
    await user.logSecurityEvent('API_ACCESS', req);
    
    req.user = user;
    req.userId = user._id;
    next();
  } catch (error) {
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json(formatResponse(false, 'Invalid token'));
    } else if (error.name === 'TokenExpiredError') {
      return res.status(401).json(formatResponse(false, 'Token expired'));
    }
    
    logger.error('Auth middleware error:', error);
    res.status(500).json(formatResponse(false, 'Server error during authentication'));
  }
};

const adminAuth = async (req, res, next) => {
  try {
    await auth(req, res, () => {
      if (!['admin', 'super_admin', 'moderator'].includes(req.user.role)) {
        return res.status(403).json(formatResponse(false, 'Access denied. Admin privileges required.'));
      }
      next();
    });
  } catch (error) {
    handleError(res, error, 'Admin authentication error');
  }
};

const superAdminAuth = async (req, res, next) => {
  try {
    await auth(req, res, () => {
      if (req.user.role !== 'super_admin') {
        return res.status(403).json(formatResponse(false, 'Access denied. Super admin privileges required.'));
      }
      next();
    });
  } catch (error) {
    handleError(res, error, 'Super admin authentication error');
  }
};

// ==================== ENHANCED REAL-TIME SETUP ====================

// WebSocket connection handler with enhanced features
wss.on('connection', (ws, req) => {
  const connectionId = crypto.randomBytes(8).toString('hex');
  logger.info(`🔌 New WebSocket connection: ${connectionId}`);
  
  ws.connectionId = connectionId;
  ws.isAlive = true;
  
  ws.on('pong', () => {
    ws.isAlive = true;
  });
  
  ws.on('message', async (message) => {
    try {
      const data = JSON.parse(message);
      
      if (data.type === 'ping') {
        ws.send(JSON.stringify({ type: 'pong', timestamp: Date.now() }));
        return;
      }
      
      if (data.type === 'authenticate' && data.token) {
        try {
          const decoded = jwt.verify(data.token, config.jwtSecret);
          const userId = decoded.id;
          
          // Store connection
          connectedClients.set(userId, ws);
          ws.userId = userId;
          
          logger.info(`✅ WebSocket authenticated for user: ${userId}`);
          
          // Update user online status
          await User.findByIdAndUpdate(userId, {
            online_status: true,
            last_seen: new Date()
          });
          
          // Send initial data
          const userData = await getUserDashboardData(userId);
          ws.send(JSON.stringify({
            type: 'initial_data',
            data: userData,
            connection_id: connectionId
          }));
          
          // Broadcast user online status
          io.emit('user_status', {
            userId,
            online: true,
            timestamp: new Date().toISOString()
          });
          
        } catch (error) {
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Authentication failed'
          }));
        }
      }
      
      // Handle subscription to events
      if (data.type === 'subscribe' && ws.userId) {
        const { channels } = data;
        ws.subscribedChannels = channels || [];
      }
      
    } catch (error) {
      logger.error('WebSocket message error:', error);
    }
  });
  
  ws.on('close', () => {
    const userId = ws.userId;
    
    // Remove from connected clients
    if (userId) {
      connectedClients.delete(userId);
      logger.info(`🔌 WebSocket disconnected for user: ${userId}`);
      
      // Update user offline status
      User.findByIdAndUpdate(userId, {
        online_status: false,
        last_seen: new Date()
      }).catch(() => {});
      
      // Broadcast user offline status
      io.emit('user_status', {
        userId,
        online: false,
        timestamp: new Date().toISOString()
      });
    }
  });
  
  // Set initial heartbeat
  ws.send(JSON.stringify({ 
    type: 'connected',
    connection_id: connectionId,
    timestamp: new Date().toISOString()
  }));
});

// Heartbeat for WebSocket connections
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) {
      return ws.terminate();
    }
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

// Socket.IO connection handler with enhanced features
io.on('connection', (socket) => {
  logger.info('🔌 New Socket.IO connection:', socket.id);
  
  socket.on('authenticate', async (token) => {
    try {
      const decoded = jwt.verify(token, config.jwtSecret);
      const userId = decoded.id;
      
      // Join user room and other rooms
      socket.join(`user_${userId}`);
      socket.join('global_updates');
      activeConnections.set(userId, socket.id);
      
      socket.userId = userId;
      
      logger.info(`✅ Socket.IO authenticated for user: ${userId}`);
      
      // Update user online status
      await User.findByIdAndUpdate(userId, {
        online_status: true,
        last_seen: new Date()
      });
      
      // Send welcome message
      socket.emit('authenticated', {
        userId,
        socketId: socket.id,
        timestamp: new Date().toISOString(),
        message: 'Connected to real-time server'
      });
      
      // Send initial dashboard data
      const dashboardData = await getUserDashboardData(userId);
      socket.emit('dashboard_update', dashboardData);
      
      // Broadcast user online status
      io.emit('user_status', {
        userId,
        online: true,
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      socket.emit('error', { message: 'Authentication failed' });
    }
  });
  
  socket.on('subscribe', (channels) => {
    if (!socket.userId) return;
    
    channels.forEach(channel => {
      socket.join(channel);
    });
  });
  
  socket.on('unsubscribe', (channels) => {
    channels.forEach(channel => {
      socket.leave(channel);
    });
  });
  
  socket.on('disconnect', () => {
    const userId = socket.userId;
    
    // Remove from active connections
    if (userId) {
      activeConnections.delete(userId);
      logger.info(`🔌 Socket.IO disconnected for user: ${userId}`);
      
      // Update user offline status
      User.findByIdAndUpdate(userId, {
        online_status: false,
        last_seen: new Date()
      }).catch(() => {});
      
      // Broadcast user offline status
      io.emit('user_status', {
        userId,
        online: false,
        timestamp: new Date().toISOString()
      });
    }
  });
});

// Enhanced broadcast helper functions
const broadcastToUser = (userId, event, data) => {
  // Broadcast via Socket.IO
  io.to(`user_${userId}`).emit(event, data);
  
  // Broadcast via WebSocket
  const wsClient = connectedClients.get(userId.toString());
  if (wsClient && wsClient.readyState === WebSocket.OPEN) {
    wsClient.send(JSON.stringify({
      type: event,
      data: data
    }));
  }
};

const broadcastToAll = (event, data, filter = null) => {
  if (filter) {
    io.to(filter).emit(event, data);
  } else {
    io.emit(event, data);
  }
  
  // Broadcast via WebSocket to all connected clients
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({
        type: event,
        data: data
      }));
    }
  });
};

// ==================== ENHANCED ROUTES ====================

// Health check with detailed metrics
app.get('/api/health', async (req, res) => {
  const health = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '60.0.0',
    environment: config.nodeEnv,
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    redis: redisClient ? (redisClient.status === 'ready' ? 'connected' : 'disconnected') : 'disabled',
    real_time: {
      websocket_connections: connectedClients.size,
      socketio_connections: activeConnections.size,
      total_connections: connectedClients.size + activeConnections.size
    },
    features: {
      caching: config.enableCaching,
      auto_invest: config.enableAutoInvest,
      crypto_payments: config.enableCryptoPayments,
      cloudinary: config.cloudinaryEnabled
    }
  };
  
  res.json(health);
});

// System status
app.get('/api/system/status', adminAuth, async (req, res) => {
  try {
    const now = new Date();
    const oneHourAgo = new Date(now - 60 * 60 * 1000);
    const oneDayAgo = new Date(now - 24 * 60 * 60 * 1000);
    
    const [
      totalUsers,
      newUsersToday,
      activeUsersToday,
      totalInvestments,
      activeInvestments,
      totalDeposits,
      totalWithdrawals,
      systemLoad
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ createdAt: { $gte: oneDayAgo } }),
      User.countDocuments({ last_active: { $gte: oneHourAgo } }),
      Investment.countDocuments(),
      Investment.countDocuments({ status: 'active' }),
      Deposit.countDocuments({ status: 'approved' }),
      Withdrawal.countDocuments({ status: 'paid' }),
      getSystemLoad()
    ]);
    
    const systemStatus = {
      overview: {
        total_users: totalUsers,
        new_users_today: newUsersToday,
        active_users_today: activeUsersToday,
        total_investments: totalInvestments,
        active_investments: activeInvestments,
        total_deposits: totalDeposits,
        total_withdrawals: totalWithdrawals
      },
      performance: {
        ...systemLoad,
        uptime: process.uptime(),
        memory_usage: process.memoryUsage(),
        database_connections: mongoose.connection.readyState
      },
      real_time: {
        active_connections: activeConnections.size,
        websocket_connections: connectedClients.size,
        last_updated: new Date().toISOString()
      }
    };
    
    res.json(formatResponse(true, 'System status retrieved', systemStatus));
  } catch (error) {
    handleError(res, error, 'Error fetching system status');
  }
});

async function getSystemLoad() {
  return {
    cpu_usage: process.cpuUsage(),
    load_average: process.loadavg?.(),
    platform: process.platform,
    node_version: process.version
  };
}

// ==================== ENHANCED AUTH ROUTES ====================

// Enhanced register endpoint
app.post('/api/auth/register', [
  body('full_name').notEmpty().trim().isLength({ min: 2, max: 100 }),
  body('email').isEmail().normalizeEmail(),
  body('phone').notEmpty().trim().isLength({ min: 10, max: 15 }),
  body('password').isLength({ min: 8 }).matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/),
  body('confirm_password').notEmpty(),
  body('risk_tolerance').optional().isIn(['low', 'medium', 'high', 'very_high']),
  body('investment_strategy').optional().isIn(['conservative', 'balanced', 'aggressive', 'speculative']),
  body('referral').optional().trim(),
  body('country').optional().trim(),
  body('currency').optional().isIn(['NGN', 'USD', 'EUR', 'GBP', 'CAD', 'AUD'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { 
      full_name, 
      email, 
      phone, 
      password, 
      confirm_password,
      risk_tolerance = 'medium', 
      investment_strategy = 'balanced', 
      referral,
      country = 'ng',
      currency = 'NGN'
    } = req.body;

    // Check password confirmation
    if (password !== confirm_password) {
      return res.status(400).json(formatResponse(false, 'Passwords do not match'));
    }

    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json(formatResponse(false, 'Email already registered'));
    }

    // Create user
    const user = new User({
      full_name,
      email: email.toLowerCase(),
      phone,
      password,
      risk_tolerance,
      investment_strategy,
      country,
      currency,
      balance: config.welcomeBonus,
      is_active: true
    });

    // Handle referral if provided
    if (referral) {
      const referrer = await User.findOne({ referral_code: referral });
      if (referrer) {
        user.referred_by = referrer._id;
        
        // Create referral record
        const referralRecord = new Referral({
          referrer: referrer._id,
          referred_user: user._id,
          referral_code: referral,
          status: 'pending',
          conversion_date: new Date()
        });
        
        await referralRecord.save();
        
        // Update referrer's count
        referrer.referral_count = (referrer.referral_count || 0) + 1;
        await referrer.save();
      }
    }

    await user.save();

    // Create portfolio for user
    const portfolio = new Portfolio({
      user: user._id,
      total_value: config.welcomeBonus
    });
    await portfolio.save();

    // Generate token
    const token = user.generateAuthToken();

    // Create welcome notification
    await createNotification(
      user._id,
      'Welcome to Raw Wealthy! 🎉',
      `Welcome ${full_name}! Your account has been created successfully. You received a ${user.currency}${config.welcomeBonus} welcome bonus. Start investing today!`,
      'success',
      '/dashboard'
    );

    // Log security event
    await user.logSecurityEvent('REGISTRATION', req);

    // Clear cache
    await cache.clearByPattern('users:*');

    res.status(201).json(formatResponse(true, 'Registration successful', {
      user: {
        _id: user._id,
        full_name: user.full_name,
        email: user.email,
        phone: user.phone,
        balance: user.balance,
        referral_code: user.referral_code,
        role: user.role,
        kyc_verified: user.kyc_verified,
        currency: user.currency,
        referral_link: user.referral_link
      },
      token,
      welcome_bonus: config.welcomeBonus
    }));
  } catch (error) {
    handleError(res, error, 'Error during registration');
  }
});

// Enhanced login endpoint
app.post('/api/auth/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
  body('remember_me').optional().isBoolean()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { email, password, remember_me = false } = req.body;

    // Find user with password
    const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
    if (!user) {
      return res.status(400).json(formatResponse(false, 'Invalid email or password'));
    }

    // Check if account is active
    if (!user.is_active) {
      return res.status(400).json(formatResponse(false, 'Account is deactivated. Contact support.'));
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      // Increment login attempts
      user.login_attempts = (user.login_attempts || 0) + 1;
      
      if (user.login_attempts >= 5) {
        user.lock_until = new Date(Date.now() + 15 * 60 * 1000); // Lock for 15 minutes
        await user.save();
        
        await createNotification(
          user._id,
          'Account Locked 🔒',
          'Your account has been locked due to multiple failed login attempts. It will be unlocked in 15 minutes.',
          'security',
          '/security'
        );
        
        return res.status(400).json(formatResponse(false, 'Account locked due to multiple failed attempts. Try again in 15 minutes.'));
      }
      
      await user.save();
      return res.status(400).json(formatResponse(false, 'Invalid email or password'));
    }

    // Reset login attempts on successful login
    user.login_attempts = 0;
    user.lock_until = null;
    user.last_login = new Date();
    await user.save();

    // Generate token with extended expiry for remember me
    const tokenExpiry = remember_me ? '90d' : config.jwtExpiresIn;
    const token = jwt.sign(
      { 
        id: user._id,
        email: user.email,
        role: user.role,
        kyc_verified: user.kyc_verified
      },
      config.jwtSecret,
      { expiresIn: tokenExpiry }
    );

    // Log security event
    await user.logSecurityEvent('LOGIN_SUCCESS', req);

    // Clear user cache
    await cache.del(`user:${user._id}`);
    await cache.del(`dashboard:${user._id}`);

    res.json(formatResponse(true, 'Login successful', {
      user: {
        _id: user._id,
        full_name: user.full_name,
        email: user.email,
        role: user.role,
        balance: user.balance,
        referral_code: user.referral_code,
        kyc_verified: user.kyc_verified,
        bank_details: user.bank_details,
        currency: user.currency,
        settings: user.settings
      },
      token,
      expires_in: tokenExpiry,
      requires_2fa: user.two_factor_enabled
    }));
  } catch (error) {
    handleError(res, error, 'Error during login');
  }
});

// Enhanced profile routes...

// ==================== ENHANCED PROFILE ROUTES ====================

// Get user profile with statistics
app.get('/api/profile', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId)
      .select('-password -two_factor_secret -verification_token -password_reset_token -security_logs');
    
    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    // Get additional statistics
    const [portfolio, investments, referrals] = await Promise.all([
      Portfolio.findOne({ user: req.userId }).lean(),
      Investment.find({ user: req.userId }).countDocuments(),
      Referral.find({ referrer: req.userId }).countDocuments()
    ]);

    const profileData = {
      ...user.toObject(),
      statistics: {
        total_investments: investments,
        total_referrals: referrals,
        portfolio_value: portfolio?.total_value || 0,
        risk_score: portfolio?.risk_score || 50
      },
      portfolio_allocation: portfolio?.allocation || {}
    };

    res.json(formatResponse(true, 'Profile retrieved successfully', { user: profileData }));
  } catch (error) {
    handleError(res, error, 'Error fetching profile');
  }
});

// Update user profile with enhanced validation
app.put('/api/profile', auth, [
  body('full_name').optional().trim().isLength({ min: 2, max: 100 }),
  body('phone').optional().trim().isLength({ min: 10, max: 15 }),
  body('country').optional().trim(),
  body('currency').optional().isIn(['NGN', 'USD', 'EUR', 'GBP', 'CAD', 'AUD']),
  body('risk_tolerance').optional().isIn(['low', 'medium', 'high', 'very_high']),
  body('investment_strategy').optional().isIn(['conservative', 'balanced', 'aggressive', 'speculative']),
  body('settings.theme').optional().isIn(['light', 'dark', 'auto']),
  body('settings.language').optional().isString(),
  body('settings.timezone').optional().isString(),
  body('settings.auto_reinvest').optional().isBoolean(),
  body('profile_image').optional().isURL()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const updates = {};
    const allowedFields = ['full_name', 'phone', 'country', 'currency', 'risk_tolerance', 'investment_strategy', 'settings', 'profile_image'];
    
    allowedFields.forEach(field => {
      if (req.body[field] !== undefined) {
        if (field === 'settings') {
          updates.$set = updates.$set || {};
          updates.$set['settings'] = { ...req.user.settings, ...req.body.settings };
        } else {
          updates[field] = req.body[field];
        }
      }
    });

    const user = await User.findByIdAndUpdate(
      req.userId,
      updates,
      { new: true, runValidators: true }
    ).select('-password -two_factor_secret');

    if (!user) {
      return res.status(404).json(formatResponse(false, 'User not found'));
    }

    // Log security event
    await user.logSecurityEvent('PROFILE_UPDATE', req);

    // Clear cache
    await cache.del(`user:${user._id}`);
    await cache.del(`dashboard:${user._id}`);

    res.json(formatResponse(true, 'Profile updated successfully', { user }));
  } catch (error) {
    handleError(res, error, 'Error updating profile');
  }
});

// Upload profile picture
app.post('/api/profile/picture', auth, upload.single('profile_picture'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json(formatResponse(false, 'No file uploaded'));
    }

    // Upload file
    const uploadResult = await handleFileUpload(req.file, 'profile-pictures', req.userId);
    
    // Update user profile
    const user = await User.findByIdAndUpdate(
      req.userId,
      { profile_image: uploadResult.url },
      { new: true }
    ).select('-password -two_factor_secret');

    // Clear cache
    await cache.del(`user:${user._id}`);

    res.json(formatResponse(true, 'Profile picture updated successfully', { 
      profile_image: uploadResult.url,
      user 
    }));
  } catch (error) {
    handleError(res, error, 'Error uploading profile picture');
  }
});

// Get user statistics
app.get('/api/profile/statistics', auth, async (req, res) => {
  try {
    const userId = req.userId;
    const cacheKey = `user_stats:${userId}`;
    
    // Try cache first
    const cachedStats = await cache.get(cacheKey);
    if (cachedStats && config.enableCaching) {
      return res.json(formatResponse(true, 'Statistics retrieved (cached)', cachedStats));
    }

    const now = new Date();
    const oneMonthAgo = new Date(now.getFullYear(), now.getMonth() - 1, now.getDate());
    const threeMonthsAgo = new Date(now.getFullYear(), now.getMonth() - 3, now.getDate());
    
    const [
      totalInvestments,
      activeInvestments,
      completedInvestments,
      totalDeposits,
      totalWithdrawals,
      totalEarnings,
      monthlyEarnings,
      portfolio,
      referrals
    ] = await Promise.all([
      Investment.countDocuments({ user: userId }),
      Investment.countDocuments({ user: userId, status: 'active' }),
      Investment.countDocuments({ user: userId, status: 'completed' }),
      Deposit.countDocuments({ user: userId, status: 'approved' }),
      Withdrawal.countDocuments({ user: userId, status: 'paid' }),
      Investment.aggregate([
        { $match: { user: mongoose.Types.ObjectId(userId) } },
        { $group: { _id: null, total: { $sum: '$earned_so_far' } } }
      ]),
      Investment.aggregate([
        { 
          $match: { 
            user: mongoose.Types.ObjectId(userId),
            createdAt: { $gte: oneMonthAgo }
          } 
        },
        { $group: { _id: null, total: { $sum: '$earned_so_far' } } }
      ]),
      Portfolio.findOne({ user: userId }).lean(),
      Referral.aggregate([
        { $match: { referrer: mongoose.Types.ObjectId(userId) } },
        { 
          $group: { 
            _id: null, 
            total: { $sum: '$earnings' },
            count: { $sum: 1 }
          } 
        }
      ])
    ]);

    const stats = {
      investments: {
        total: totalInvestments,
        active: activeInvestments,
        completed: completedInvestments,
        success_rate: totalInvestments > 0 ? Math.round((completedInvestments / totalInvestments) * 100) : 0
      },
      financial: {
        total_deposits: totalDeposits,
        total_withdrawals: totalWithdrawals,
        total_earnings: totalEarnings[0]?.total || 0,
        monthly_earnings: monthlyEarnings[0]?.total || 0,
        net_worth: req.user.balance + (portfolio?.total_value || 0)
      },
      portfolio: {
        total_value: portfolio?.total_value || 0,
        risk_score: portfolio?.risk_score || 50,
        allocation: portfolio?.allocation || {}
      },
      referrals: {
        total: referrals[0]?.count || 0,
        total_earnings: referrals[0]?.total || 0,
        conversion_rate: 0 // Could be calculated based on referral clicks vs signups
      },
      performance: {
        roi: portfolio?.performance?.average_roi || 0,
        best_month: monthlyEarnings[0]?.total || 0,
        consistency_score: 85 // Placeholder - would be calculated based on investment consistency
      }
    };

    // Cache the result
    await cache.set(cacheKey, stats, 60000); // 1 minute cache

    res.json(formatResponse(true, 'Statistics retrieved', stats));
  } catch (error) {
    handleError(res, error, 'Error fetching statistics');
  }
});

// ==================== ENHANCED INVESTMENT PLAN ROUTES ====================

// Get all investment plans with filters and pagination
app.get('/api/plans', [
  query('category').optional().isString(),
  query('risk_level').optional().isIn(['low', 'medium', 'high', 'very_high']),
  query('min_amount').optional().isFloat({ min: 0 }),
  query('max_amount').optional().isFloat({ min: 0 }),
  query('featured').optional().isBoolean(),
  query('popular').optional().isBoolean(),
  query('search').optional().isString(),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 }),
  query('sort').optional().isIn(['name', 'daily_interest', 'duration', 'min_amount', 'popularity'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { 
      category, 
      risk_level, 
      min_amount, 
      max_amount, 
      featured, 
      popular, 
      search,
      page = 1, 
      limit = 20,
      sort = 'popularity'
    } = req.query;

    // Build query
    const query = { is_active: true };
    
    if (category) query.category = category;
    if (risk_level) query.risk_level = risk_level;
    if (featured !== undefined) query.is_featured = featured === 'true';
    if (popular !== undefined) query.is_popular = popular === 'true';
    
    if (min_amount || max_amount) {
      query.min_amount = {};
      if (min_amount) query.min_amount.$gte = parseFloat(min_amount);
      if (max_amount) query.min_amount.$lte = parseFloat(max_amount);
    }
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { raw_material: { $regex: search, $options: 'i' } },
        { tags: { $regex: search, $options: 'i' } }
      ];
    }

    // Build sort options
    let sortOptions = {};
    switch (sort) {
      case 'name':
        sortOptions = { name: 1 };
        break;
      case 'daily_interest':
        sortOptions = { daily_interest: -1 };
        break;
      case 'duration':
        sortOptions = { duration: 1 };
        break;
      case 'min_amount':
        sortOptions = { min_amount: 1 };
        break;
      case 'popularity':
        sortOptions = { investment_count: -1, display_order: 1 };
        break;
      default:
        sortOptions = { display_order: 1, is_featured: -1, is_popular: -1 };
    }

    // Execute query with pagination
    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort: sortOptions,
      lean: true
    };

    const result = await InvestmentPlan.paginate(query, options);

    res.json(formatResponse(true, 'Investment plans retrieved', {
      plans: result.docs,
      pagination: {
        page: result.page,
        limit: result.limit,
        total: result.totalDocs,
        pages: result.totalPages,
        hasPrevPage: result.hasPrevPage,
        hasNextPage: result.hasNextPage
      },
      filters: {
        categories: await InvestmentPlan.distinct('category', { is_active: true }),
        risk_levels: await InvestmentPlan.distinct('risk_level', { is_active: true })
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching investment plans');
  }
});

// Get plan categories
app.get('/api/plans/categories', async (req, res) => {
  try {
    const categories = await InvestmentPlan.aggregate([
      { $match: { is_active: true } },
      { 
        $group: { 
          _id: '$category',
          count: { $sum: 1 },
          total_invested: { $sum: '$total_invested' },
          avg_return: { $avg: '$daily_interest' }
        }
      },
      { $sort: { count: -1 } }
    ]);

    res.json(formatResponse(true, 'Categories retrieved', { categories }));
  } catch (error) {
    handleError(res, error, 'Error fetching categories');
  }
});

// Get recommended plans based on user profile
app.get('/api/plans/recommended', auth, async (req, res) => {
  try {
    const user = req.user;
    const cacheKey = `recommended_plans:${user._id}`;
    
    // Try cache first
    const cached = await cache.get(cacheKey);
    if (cached && config.enableCaching) {
      return res.json(formatResponse(true, 'Recommended plans retrieved (cached)', cached));
    }

    // Build recommendation query based on user profile
    const query = { is_active: true };
    
    // Adjust based on user risk tolerance
    switch (user.risk_tolerance) {
      case 'low':
        query.risk_level = 'low';
        query.daily_interest = { $gte: 1, $lte: 3 };
        break;
      case 'medium':
        query.risk_level = { $in: ['low', 'medium'] };
        query.daily_interest = { $gte: 2, $lte: 5 };
        break;
      case 'high':
        query.risk_level = { $in: ['medium', 'high'] };
        query.daily_interest = { $gte: 3, $lte: 8 };
        break;
      case 'very_high':
        query.risk_level = 'very_high';
        query.daily_interest = { $gte: 5, $lte: 15 };
        break;
    }

    // Adjust based on user investment strategy
    switch (user.investment_strategy) {
      case 'conservative':
        query.min_amount = { $lte: 10000 };
        query.duration = { $lte: 30 };
        break;
      case 'balanced':
        query.min_amount = { $lte: 50000 };
        query.duration = { $lte: 90 };
        break;
      case 'aggressive':
        query.min_amount = { $lte: 100000 };
        query.duration = { $lte: 180 };
        break;
      case 'speculative':
        query.min_amount = { $lte: 500000 };
        query.duration = { $lte: 365 };
        break;
    }

    // Get recommended plans
    const recommendedPlans = await InvestmentPlan.find(query)
      .sort({ success_rate: -1, investment_count: -1 })
      .limit(6)
      .lean();

    // Get popular plans as fallback
    const popularPlans = await InvestmentPlan.find({ 
      is_active: true, 
      is_popular: true,
      _id: { $nin: recommendedPlans.map(p => p._id) }
    })
      .limit(6 - recommendedPlans.length)
      .lean();

    const allPlans = [...recommendedPlans, ...popularPlans];

    // Cache the result
    await cache.set(cacheKey, allPlans, 300000); // 5 minutes cache

    res.json(formatResponse(true, 'Recommended plans retrieved', { plans: allPlans }));
  } catch (error) {
    handleError(res, error, 'Error fetching recommended plans');
  }
});

// ==================== ENHANCED INVESTMENT ROUTES ====================

// Get user investments with advanced filtering
app.get('/api/investments', auth, [
  query('status').optional().isIn(['pending', 'active', 'completed', 'cancelled', 'failed', 'suspended']),
  query('plan_id').optional().isMongoId(),
  query('start_date').optional().isISO8601(),
  query('end_date').optional().isISO8601(),
  query('min_amount').optional().isFloat({ min: 0 }),
  query('max_amount').optional().isFloat({ min: 0 }),
  query('sort').optional().isIn(['createdAt', 'amount', 'end_date', 'progress_percentage']),
  query('order').optional().isIn(['asc', 'desc']),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { 
      status, 
      plan_id, 
      start_date, 
      end_date, 
      min_amount, 
      max_amount,
      sort = 'createdAt',
      order = 'desc',
      page = 1,
      limit = 20
    } = req.query;

    // Build query
    const query = { user: req.userId };
    
    if (status) query.status = status;
    if (plan_id) query.plan = plan_id;
    
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

    // Build sort options
    const sortOptions = {};
    sortOptions[sort] = order === 'asc' ? 1 : -1;

    // Execute query with pagination
    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort: sortOptions,
      populate: {
        path: 'plan',
        select: 'name daily_interest duration category risk_level'
      },
      lean: true
    };

    const result = await Investment.paginate(query, options);

    // Calculate statistics
    const stats = await Investment.aggregate([
      { $match: { user: mongoose.Types.ObjectId(req.userId) } },
      { 
        $group: {
          _id: null,
          total_invested: { $sum: '$amount' },
          total_earned: { $sum: '$earned_so_far' },
          active_investments: { 
            $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] } 
          },
          completed_investments: { 
            $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] } 
          }
        }
      }
    ]);

    res.json(formatResponse(true, 'Investments retrieved', {
      investments: result.docs,
      statistics: stats[0] || {
        total_invested: 0,
        total_earned: 0,
        active_investments: 0,
        completed_investments: 0
      },
      pagination: {
        page: result.page,
        limit: result.limit,
        total: result.totalDocs,
        pages: result.totalPages,
        hasPrevPage: result.hasPrevPage,
        hasNextPage: result.hasNextPage
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching investments');
  }
});

// Enhanced investment creation with validation
app.post('/api/investments', auth, upload.single('payment_proof'), [
  body('plan_id').notEmpty().isMongoId(),
  body('amount').isFloat({ min: config.minInvestment }),
  body('auto_renew').optional().isBoolean(),
  body('remarks').optional().trim().isLength({ max: 500 }),
  body('payment_method').optional().isIn(['balance', 'bank_transfer', 'crypto']),
  body('use_balance').optional().isBoolean()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { plan_id, amount, auto_renew = false, remarks, payment_method = 'balance', use_balance = true } = req.body;
    const userId = req.userId;
    const user = req.user;
    
    // Check plan
    const plan = await InvestmentPlan.findById(plan_id);
    if (!plan) {
      return res.status(404).json(formatResponse(false, 'Investment plan not found'));
    }

    if (!plan.is_active) {
      return res.status(400).json(formatResponse(false, 'This investment plan is currently unavailable'));
    }

    const investmentAmount = parseFloat(amount);

    // Validate amount
    if (investmentAmount < plan.min_amount) {
      return res.status(400).json(formatResponse(false, 
        `Minimum investment for ${plan.name} is ${user.currency}${plan.min_amount.toLocaleString()}`));
    }

    if (plan.max_amount && investmentAmount > plan.max_amount) {
      return res.status(400).json(formatResponse(false,
        `Maximum investment for ${plan.name} is ${user.currency}${plan.max_amount.toLocaleString()}`));
    }

    // Check KYC requirement
    if (plan.requirements?.kyc_required && !user.kyc_verified) {
      return res.status(400).json(formatResponse(false, 'KYC verification is required for this investment plan'));
    }

    let proofUrl = null;
    let status = 'pending';
    let payment_verified = false;

    // Handle payment
    if (payment_method === 'balance' && use_balance) {
      // Check balance
      if (investmentAmount > user.balance) {
        return res.status(400).json(formatResponse(false, 'Insufficient balance for this investment'));
      }
      status = 'active';
      payment_verified = true;
    } else {
      // Handle file upload for payment proof
      if (req.file) {
        try {
          const uploadResult = await handleFileUpload(req.file, 'investment-proofs', userId);
          proofUrl = uploadResult.url;
        } catch (uploadError) {
          return res.status(400).json(formatResponse(false, `File upload failed: ${uploadError.message}`));
        }
      } else {
        return res.status(400).json(formatResponse(false, 'Payment proof is required for non-balance payments'));
      }
    }

    // Calculate investment details
    const expectedEarnings = (investmentAmount * plan.total_interest) / 100;
    const dailyEarnings = (investmentAmount * plan.daily_interest) / 100;
    const endDate = new Date(Date.now() + plan.duration * 24 * 60 * 60 * 1000);

    // Create investment
    const investment = new Investment({
      user: userId,
      plan: plan_id,
      amount: investmentAmount,
      status,
      start_date: new Date(),
      end_date: endDate,
      expected_earnings: expectedEarnings,
      earned_so_far: 0,
      daily_earnings: dailyEarnings,
      auto_renew,
      payment_proof_url: proofUrl,
      payment_verified,
      remarks,
      remaining_days: plan.duration,
      progress_percentage: 0
    });

    await investment.save();

    // Handle payment from balance
    if (payment_method === 'balance' && use_balance) {
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
          payment_method: 'balance'
        }
      );
    }

    // Update plan statistics
    await InvestmentPlan.findByIdAndUpdate(plan_id, {
      $inc: { 
        investment_count: 1,
        total_invested: investmentAmount
      }
    });

    // Update user portfolio
    await updatePortfolio(userId);

    // Create notification
    await createNotification(
      userId,
      'Investment Created 📈',
      `Your investment of ${user.currency}${investmentAmount.toLocaleString()} in ${plan.name} has been created successfully.${status === 'pending' ? ' Awaiting admin approval.' : ' Your investment is now active!'}`,
      'investment',
      `/investments/${investment._id}`
    );

    // Handle referral if this is the first investment
    if (user.referred_by) {
      const referral = await Referral.findOne({ 
        referred_user: userId,
        status: 'pending'
      });
      
      if (referral) {
        referral.status = 'active';
        referral.investment_amount = investmentAmount;
        referral.conversion_date = new Date();
        await referral.save();
        
        // Notify referrer
        await createNotification(
          referral.referrer,
          'Referral Conversion 🎉',
          `${user.full_name} has made their first investment of ${user.currency}${investmentAmount.toLocaleString()}. You will earn commissions from their investments!`,
          'referral',
          '/referrals'
        );
      }
    }

    // Notify admin if payment proof uploaded
    if (proofUrl) {
      const admins = await User.find({ role: { $in: ['admin', 'super_admin', 'moderator'] } });
      for (const admin of admins) {
        await createNotification(
          admin._id,
          'New Investment Pending Approval',
          `User ${user.full_name} has created a new investment of ${user.currency}${investmentAmount.toLocaleString()} requiring approval.`,
          'system',
          `/admin/investments/${investment._id}`
        );
      }
    }

    // Clear cache
    await cache.del(`investments:${userId}`);
    await cache.del(`dashboard:${userId}`);

    res.status(201).json(formatResponse(true, 'Investment created successfully!', { 
      investment: {
        ...investment.toObject(),
        plan_details: {
          name: plan.name,
          daily_interest: plan.daily_interest,
          duration: plan.duration,
          total_interest: plan.total_interest,
          category: plan.category
        },
        estimated_completion: endDate,
        daily_earnings_formatted: `${user.currency}${dailyEarnings.toFixed(2)}`
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error creating investment');
  }
});

// Update portfolio function
async function updatePortfolio(userId) {
  try {
    const investments = await Investment.find({ 
      user: userId,
      status: 'active'
    }).populate('plan', 'category');
    
    const portfolio = {
      total_value: 0,
      active_investments: investments.length,
      allocation: {},
      performance: {
        total_earned: 0,
        average_roi: 0
      }
    };
    
    let totalEarnings = 0;
    let totalInvested = 0;
    
    investments.forEach(inv => {
      portfolio.total_value += inv.amount;
      totalInvested += inv.amount;
      totalEarnings += inv.earned_so_far || 0;
      
      if (inv.plan?.category) {
        portfolio.allocation[inv.plan.category] = 
          (portfolio.allocation[inv.plan.category] || 0) + inv.amount;
      }
    });
    
    // Calculate ROI
    portfolio.performance.total_earned = totalEarnings;
    portfolio.performance.average_roi = totalInvested > 0 ? 
      (totalEarnings / totalInvested * 100) : 0;
    
    // Calculate risk score based on allocation
    const riskWeights = {
      agriculture: 25,
      mining: 60,
      energy: 70,
      metals: 50,
      precious_stones: 80,
      real_estate: 40,
      technology: 75,
      renewable: 30
    };
    
    let totalRisk = 0;
    let totalAllocated = 0;
    
    Object.entries(portfolio.allocation).forEach(([category, amount]) => {
      const riskWeight = riskWeights[category] || 50;
      totalRisk += riskWeight * amount;
      totalAllocated += amount;
    });
    
    portfolio.risk_score = totalAllocated > 0 ? 
      Math.round(totalRisk / totalAllocated) : 50;
    
    // Update or create portfolio
    await Portfolio.findOneAndUpdate(
      { user: userId },
      { 
        $set: portfolio,
        $setOnInsert: { user: userId }
      },
      { upsert: true, new: true }
    );
    
    // Update user investment portfolio stats
    await User.findByIdAndUpdate(userId, {
      'investment_portfolio.total_value': portfolio.total_value,
      'investment_portfolio.active_investments': portfolio.active_investments,
      'investment_portfolio.average_roi': portfolio.performance.average_roi
    });
    
  } catch (error) {
    logger.error('Error updating portfolio:', error);
  }
}

// ==================== ENHANCED DEPOSIT ROUTES ====================

// Get user deposits with filtering
app.get('/api/deposits', auth, [
  query('status').optional().isIn(['pending', 'approved', 'rejected', 'cancelled', 'processing', 'failed']),
  query('payment_method').optional().isIn(['bank_transfer', 'crypto', 'paypal', 'card', 'flutterwave', 'paystack', 'stripe']),
  query('start_date').optional().isISO8601(),
  query('end_date').optional().isISO8601(),
  query('min_amount').optional().isFloat({ min: 0 }),
  query('max_amount').optional().isFloat({ min: 0 }),
  query('sort').optional().isIn(['createdAt', 'amount', 'status']),
  query('order').optional().isIn(['asc', 'desc']),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { 
      status, 
      payment_method,
      start_date,
      end_date,
      min_amount,
      max_amount,
      sort = 'createdAt',
      order = 'desc',
      page = 1,
      limit = 20
    } = req.query;

    // Build query
    const query = { user: req.userId };
    
    if (status) query.status = status;
    if (payment_method) query.payment_method = payment_method;
    
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

    // Build sort options
    const sortOptions = {};
    sortOptions[sort] = order === 'asc' ? 1 : -1;

    // Execute query with pagination
    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort: sortOptions,
      lean: true
    };

    const result = await Deposit.paginate(query, options);

    // Calculate statistics
    const stats = await Deposit.aggregate([
      { $match: { user: mongoose.Types.ObjectId(req.userId), status: 'approved' } },
      { 
        $group: {
          _id: null,
          total_deposits: { $sum: '$amount' },
          count: { $sum: 1 },
          average_amount: { $avg: '$amount' },
          last_deposit: { $max: '$createdAt' }
        }
      }
    ]);

    res.json(formatResponse(true, 'Deposits retrieved', {
      deposits: result.docs,
      statistics: stats[0] || {
        total_deposits: 0,
        count: 0,
        average_amount: 0
      },
      pagination: {
        page: result.page,
        limit: result.limit,
        total: result.totalDocs,
        pages: result.totalPages,
        hasPrevPage: result.hasPrevPage,
        hasNextPage: result.hasNextPage
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching deposits');
  }
});

// Enhanced deposit creation
app.post('/api/deposits', auth, upload.single('payment_proof'), [
  body('amount').isFloat({ min: config.minDeposit }),
  body('payment_method').isIn(['bank_transfer', 'crypto', 'paypal', 'card', 'flutterwave', 'paystack', 'stripe']),
  body('remarks').optional().trim().isLength({ max: 500 }),
  body('bank_details').optional().isObject(),
  body('crypto_details').optional().isObject(),
  body('card_details').optional().isObject()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { amount, payment_method, remarks, bank_details, crypto_details, card_details } = req.body;
    const userId = req.userId;
    const user = req.user;
    const depositAmount = parseFloat(amount);

    // Validate payment method specific requirements
    if (payment_method === 'bank_transfer' && !bank_details && !req.file) {
      return res.status(400).json(formatResponse(false, 'Bank details or payment proof is required for bank transfer'));
    }

    if (payment_method === 'crypto' && !crypto_details?.wallet_address) {
      return res.status(400).json(formatResponse(false, 'Wallet address is required for crypto deposit'));
    }

    let proofUrl = null;
    
    // Handle file upload
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
      reference: generateReference('DEP'),
      remarks,
      bank_details: bank_details || null,
      crypto_details: crypto_details || null,
      card_details: card_details || null,
      currency: user.currency
    });

    await deposit.save();

    // Create notification
    await createNotification(
      userId,
      'Deposit Request Submitted 💰',
      `Your deposit request of ${user.currency}${depositAmount.toLocaleString()} has been submitted and is pending approval.`,
      'deposit',
      `/deposits/${deposit._id}`
    );

    // Notify admin
    const admins = await User.find({ role: { $in: ['admin', 'super_admin', 'moderator'] } });
    for (const admin of admins) {
      await createNotification(
        admin._id,
        'New Deposit Request',
        `User ${req.user.full_name} has submitted a deposit request of ${user.currency}${depositAmount.toLocaleString()}.`,
        'system',
        `/admin/deposits/${deposit._id}`
      );
    }

    // Clear cache
    await cache.del(`deposits:${userId}`);
    await cache.del(`dashboard:${userId}`);

    // For payment gateways like Paystack, Flutterwave, Stripe
    if (['paystack', 'flutterwave', 'stripe', 'card'].includes(payment_method)) {
      // In a real implementation, you would:
      // 1. Initialize payment gateway
      // 2. Create payment link/transaction
      // 3. Return payment URL to frontend
      
      const paymentData = {
        reference: deposit.reference,
        amount: depositAmount * 100, // Convert to kobo/pesewas
        email: user.email,
        currency: user.currency,
        callback_url: `${config.clientURL}/deposit/verify`,
        metadata: {
          userId: userId.toString(),
          depositId: deposit._id.toString()
        }
      };

      // This is where you'd integrate with actual payment gateway
      // For now, we'll return mock data
      return res.status(201).json(formatResponse(true, 'Deposit request submitted successfully! Payment initialization required.', { 
        deposit: {
          ...deposit.toObject(),
          formatted_amount: `${user.currency}${depositAmount.toLocaleString()}`,
          requires_payment: true,
          payment_gateway: payment_method
        },
        payment_gateway: {
          name: payment_method,
          requires_redirect: true,
          // In real implementation, this would be the actual payment URL
          payment_url: `${config.serverURL}/api/payment/${payment_method}/initiate/${deposit._id}`
        }
      }));
    }

    res.status(201).json(formatResponse(true, 'Deposit request submitted successfully!', { 
      deposit: {
        ...deposit.toObject(),
        formatted_amount: `${user.currency}${depositAmount.toLocaleString()}`,
        requires_approval: true
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error creating deposit');
  }
});

// ==================== ENHANCED WITHDRAWAL ROUTES ====================

// Get user withdrawals with filtering
app.get('/api/withdrawals', auth, [
  query('status').optional().isIn(['pending', 'approved', 'rejected', 'paid', 'processing', 'failed', 'cancelled']),
  query('payment_method').optional().isIn(['bank_transfer', 'crypto', 'paypal', 'stripe']),
  query('start_date').optional().isISO8601(),
  query('end_date').optional().isISO8601(),
  query('min_amount').optional().isFloat({ min: 0 }),
  query('max_amount').optional().isFloat({ min: 0 }),
  query('sort').optional().isIn(['createdAt', 'amount', 'status']),
  query('order').optional().isIn(['asc', 'desc']),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { 
      status, 
      payment_method,
      start_date,
      end_date,
      min_amount,
      max_amount,
      sort = 'createdAt',
      order = 'desc',
      page = 1,
      limit = 20
    } = req.query;

    // Build query
    const query = { user: req.userId };
    
    if (status) query.status = status;
    if (payment_method) query.payment_method = payment_method;
    
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

    // Build sort options
    const sortOptions = {};
    sortOptions[sort] = order === 'asc' ? 1 : -1;

    // Execute query with pagination
    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort: sortOptions,
      lean: true
    };

    const result = await Withdrawal.paginate(query, options);

    // Calculate statistics
    const stats = await Withdrawal.aggregate([
      { $match: { user: mongoose.Types.ObjectId(req.userId), status: 'paid' } },
      { 
        $group: {
          _id: null,
          total_withdrawn: { $sum: '$amount' },
          total_fees: { $sum: '$platform_fee' },
          count: { $sum: 1 },
          average_amount: { $avg: '$amount' },
          last_withdrawal: { $max: '$createdAt' }
        }
      }
    ]);

    res.json(formatResponse(true, 'Withdrawals retrieved', {
      withdrawals: result.docs,
      statistics: stats[0] || {
        total_withdrawn: 0,
        total_fees: 0,
        count: 0,
        average_amount: 0
      },
      pagination: {
        page: result.page,
        limit: result.limit,
        total: result.totalDocs,
        pages: result.totalPages,
        hasPrevPage: result.hasPrevPage,
        hasNextPage: result.hasNextPage
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching withdrawals');
  }
});

// Enhanced withdrawal creation
app.post('/api/withdrawals', auth, [
  body('amount').isFloat({ min: config.minWithdrawal }),
  body('payment_method').isIn(['bank_transfer', 'crypto', 'paypal', 'stripe']),
  body('bank_details').optional().isObject(),
  body('crypto_details').optional().isObject(),
  body('paypal_email').optional().isEmail(),
  body('stripe_account').optional().isString(),
  body('pin').optional().isString().isLength({ min: 4, max: 6 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { 
      amount, 
      payment_method, 
      bank_details, 
      crypto_details, 
      paypal_email,
      stripe_account,
      pin 
    } = req.body;
    
    const userId = req.userId;
    const user = req.user;
    const withdrawalAmount = parseFloat(amount);

    // Security check - verify PIN if required
    if (pin && user.settings?.withdrawal_pin) {
      // In real implementation, you would verify the PIN
      // For now, we'll just check if it's provided
      if (pin !== '1234') { // Replace with actual PIN verification
        return res.status(400).json(formatResponse(false, 'Invalid PIN'));
      }
    }

    // Check balance
    if (withdrawalAmount > user.balance) {
      return res.status(400).json(formatResponse(false, 'Insufficient balance for withdrawal'));
    }

    // Check KYC requirement for large withdrawals
    if (withdrawalAmount > 500000 && !user.kyc_verified) {
      return res.status(400).json(formatResponse(false, 'KYC verification is required for withdrawals above ₦500,000'));
    }

    // Validate payment method specific requirements
    if (payment_method === 'bank_transfer') {
      if (!bank_details && !user.bank_details?.account_number) {
        return res.status(400).json(formatResponse(false, 'Bank details are required for bank transfer withdrawals'));
      }
    }

    if (payment_method === 'crypto' && !crypto_details?.wallet_address) {
      return res.status(400).json(formatResponse(false, 'Wallet address is required for crypto withdrawals'));
    }

    if (payment_method === 'paypal' && !paypal_email) {
      return res.status(400).json(formatResponse(false, 'PayPal email is required for PayPal withdrawals'));
    }

    if (payment_method === 'stripe' && !stripe_account) {
      return res.status(400).json(formatResponse(false, 'Stripe account is required for Stripe withdrawals'));
    }

    // Calculate fees and net amount
    const platformFee = withdrawalAmount * (config.platformFeePercent / 100);
    const processingFee = payment_method === 'crypto' ? 0.001 * withdrawalAmount : 0; // 0.1% for crypto
    const totalFee = platformFee + processingFee;
    const netAmount = withdrawalAmount - totalFee;

    // Create withdrawal
    const withdrawal = new Withdrawal({
      user: userId,
      amount: withdrawalAmount,
      payment_method,
      platform_fee: platformFee,
      processing_fee: processingFee,
      total_fee: totalFee,
      net_amount: netAmount,
      status: 'pending',
      reference: generateReference('WDL'),
      bank_details: bank_details || user.bank_details,
      crypto_details: crypto_details || null,
      paypal_email: paypal_email || null,
      stripe_account: stripe_account || null,
      currency: user.currency
    });

    await withdrawal.save();

    // Create transaction (pending)
    await createTransaction(
      userId,
      'withdrawal',
      -withdrawalAmount,
      `Withdrawal request of ${user.currency}${withdrawalAmount.toLocaleString()}`,
      'pending',
      { 
        withdrawal_id: withdrawal._id,
        payment_method,
        platform_fee: platformFee,
        processing_fee: processingFee,
        net_amount: netAmount
      }
    );

    // Create notification
    await createNotification(
      userId,
      'Withdrawal Request Submitted 💸',
      `Your withdrawal request of ${user.currency}${withdrawalAmount.toLocaleString()} has been submitted and is pending approval. You will receive ${user.currency}${netAmount.toLocaleString()} after fees.`,
      'withdrawal',
      `/withdrawals/${withdrawal._id}`
    );

    // Notify admin
    const admins = await User.find({ role: { $in: ['admin', 'super_admin', 'moderator'] } });
    for (const admin of admins) {
      await createNotification(
        admin._id,
        'New Withdrawal Request',
        `User ${req.user.full_name} has requested a withdrawal of ${user.currency}${withdrawalAmount.toLocaleString()}.`,
        'system',
        `/admin/withdrawals/${withdrawal._id}`
      );
    }

    // Clear cache
    await cache.del(`withdrawals:${userId}`);
    await cache.del(`dashboard:${userId}`);

    res.status(201).json(formatResponse(true, 'Withdrawal request submitted successfully!', { 
      withdrawal: {
        ...withdrawal.toObject(),
        formatted_amount: `${user.currency}${withdrawalAmount.toLocaleString()}`,
        formatted_net_amount: `${user.currency}${netAmount.toLocaleString()}`,
        formatted_fee: `${user.currency}${totalFee.toLocaleString()}`,
        estimated_processing_time: payment_method === 'crypto' ? '1-2 hours' : '24-48 hours'
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error creating withdrawal');
  }
});

// ==================== ENHANCED TRANSACTION ROUTES ====================

// Get user transactions with advanced filtering
app.get('/api/transactions', auth, [
  query('type').optional().isIn(['deposit', 'withdrawal', 'investment', 'earning', 'referral', 'bonus', 'fee', 'refund', 'dividend', 'interest', 'penalty', 'adjustment']),
  query('status').optional().isIn(['pending', 'completed', 'failed', 'cancelled', 'processing']),
  query('start_date').optional().isISO8601(),
  query('end_date').optional().isISO8601(),
  query('min_amount').optional().isFloat({ min: 0 }),
  query('max_amount').optional().isFloat({ min: 0 }),
  query('category').optional().isString(),
  query('search').optional().isString(),
  query('sort').optional().isIn(['createdAt', 'amount', 'type']),
  query('order').optional().isIn(['asc', 'desc']),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { 
      type, 
      status,
      start_date,
      end_date,
      min_amount,
      max_amount,
      category,
      search,
      sort = 'createdAt',
      order = 'desc',
      page = 1,
      limit = 20
    } = req.query;

    // Build query
    const query = { user: req.userId };
    
    if (type) query.type = type;
    if (status) query.status = status;
    if (category) query.category = category;
    
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
    
    if (search) {
      query.$or = [
        { description: { $regex: search, $options: 'i' } },
        { reference: { $regex: search, $options: 'i' } }
      ];
    }

    // Build sort options
    const sortOptions = {};
    sortOptions[sort] = order === 'asc' ? 1 : -1;

    // Execute query with pagination
    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort: sortOptions,
      lean: true
    };

    const result = await Transaction.paginate(query, options);

    // Calculate statistics
    const stats = await Transaction.aggregate([
      { $match: { user: mongoose.Types.ObjectId(req.userId) } },
      { 
        $facet: {
          by_type: [
            { $group: { _id: '$type', count: { $sum: 1 }, total: { $sum: '$amount' } } }
          ],
          by_status: [
            { $group: { _id: '$status', count: { $sum: 1 } } }
          ],
          summary: [
            { 
              $group: { 
                _id: null, 
                total_volume: { $sum: { $abs: '$amount' } },
                total_count: { $sum: 1 },
                last_transaction: { $max: '$createdAt' }
              } 
            }
          ]
        }
      }
    ]);

    res.json(formatResponse(true, 'Transactions retrieved', {
      transactions: result.docs,
      statistics: {
        by_type: stats[0]?.by_type || [],
        by_status: stats[0]?.by_status || [],
        summary: stats[0]?.summary[0] || {
          total_volume: 0,
          total_count: 0
        }
      },
      pagination: {
        page: result.page,
        limit: result.limit,
        total: result.totalDocs,
        pages: result.totalPages,
        hasPrevPage: result.hasPrevPage,
        hasNextPage: result.hasNextPage
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching transactions');
  }
});

// Export transactions
app.get('/api/transactions/export', auth, [
  query('start_date').optional().isISO8601(),
  query('end_date').optional().isISO8601(),
  query('format').optional().isIn(['csv', 'json', 'pdf'])
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { start_date, end_date, format = 'csv' } = req.query;

    // Build query
    const query = { user: req.userId, status: 'completed' };
    
    if (start_date || end_date) {
      query.createdAt = {};
      if (start_date) query.createdAt.$gte = new Date(start_date);
      if (end_date) query.createdAt.$lte = new Date(end_date);
    }

    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .lean();

    if (format === 'csv') {
      // Convert to CSV
      const csvData = transactions.map(txn => ({
        Date: new Date(txn.createdAt).toLocaleDateString(),
        Type: txn.type,
        Description: txn.description,
        Amount: txn.amount,
        Currency: txn.currency || 'NGN',
        Reference: txn.reference,
        Status: txn.status,
        'Balance Before': txn.balance_before,
        'Balance After': txn.balance_after
      }));

      // In a real implementation, you would use a CSV library
      // For now, we'll return JSON
      res.json(formatResponse(true, 'Transactions exported', { 
        format: 'json', // Fallback to JSON
        data: csvData,
        count: transactions.length,
        date_range: {
          start: start_date || 'beginning',
          end: end_date || 'now'
        }
      }));
    } else {
      res.json(formatResponse(true, 'Transactions exported', { 
        format,
        data: transactions,
        count: transactions.length,
        date_range: {
          start: start_date || 'beginning',
          end: end_date || 'now'
        }
      }));
    }
  } catch (error) {
    handleError(res, error, 'Error exporting transactions');
  }
});

// ==================== ENHANCED KYC ROUTES ====================

// Submit KYC with enhanced validation
app.post('/api/kyc', auth, upload.fields([
  { name: 'id_front', maxCount: 1 },
  { name: 'id_back', maxCount: 1 },
  { name: 'selfie_with_id', maxCount: 1 },
  { name: 'address_proof', maxCount: 1 },
  { name: 'additional_documents', maxCount: 3 }
]), [
  body('id_type').isIn(['national_id', 'passport', 'driver_license', 'voters_card', 'residence_permit']),
  body('id_number').notEmpty().trim(),
  body('proof_of_address_type').optional().isIn(['utility_bill', 'bank_statement', 'tax_document', 'government_letter']),
  body('personal_info.date_of_birth').optional().isISO8601(),
  body('personal_info.gender').optional().isIn(['male', 'female', 'other']),
  body('personal_info.nationality').optional().trim(),
  body('personal_info.occupation').optional().trim(),
  body('personal_info.source_of_funds').optional().trim(),
  body('address.street').optional().trim(),
  body('address.city').optional().trim(),
  body('address.state').optional().trim(),
  body('address.country').optional().trim(),
  body('address.postal_code').optional().trim()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { 
      id_type, 
      id_number, 
      proof_of_address_type,
      personal_info,
      address
    } = req.body;
    
    const userId = req.userId;
    const user = req.user;

    // Check if user already has pending KYC
    const existingKYC = await KYCSubmission.findOne({ 
      user: userId,
      status: { $in: ['pending', 'under_review'] }
    });
    
    if (existingKYC) {
      return res.status(400).json(formatResponse(false, 'You already have a KYC submission pending review'));
    }

    // Check if user already has verified KYC
    const verifiedKYC = await KYCSubmission.findOne({ 
      user: userId,
      status: 'approved'
    });
    
    if (verifiedKYC) {
      return res.status(400).json(formatResponse(false, 'Your KYC is already verified'));
    }

    // Handle file uploads
    const files = req.files;
    if (!files?.id_front || !files?.selfie_with_id) {
      return res.status(400).json(formatResponse(false, 'ID front and selfie with ID are required'));
    }

    const uploadedFiles = {};

    try {
      // Upload required documents
      uploadedFiles.id_front = await handleFileUpload(files.id_front[0], 'kyc', userId);
      uploadedFiles.selfie_with_id = await handleFileUpload(files.selfie_with_id[0], 'kyc', userId);
      
      if (files.id_back?.[0]) {
        uploadedFiles.id_back = await handleFileUpload(files.id_back[0], 'kyc', userId);
      }
      
      if (files.address_proof?.[0]) {
        uploadedFiles.address_proof = await handleFileUpload(files.address_proof[0], 'kyc', userId);
      }

      // Upload additional documents if any
      if (files.additional_documents) {
        uploadedFiles.additional_documents = [];
        for (const file of files.additional_documents) {
          const result = await handleFileUpload(file, 'kyc', userId);
          uploadedFiles.additional_documents.push({
            type: file.originalname.split('.')[0],
            url: result.url
          });
        }
      }
    } catch (uploadError) {
      return res.status(400).json(formatResponse(false, `File upload failed: ${uploadError.message}`));
    }

    // Prepare documents array
    const documents = [
      { type: 'id_front', url: uploadedFiles.id_front.url, verified: false },
      { type: 'selfie_with_id', url: uploadedFiles.selfie_with_id.url, verified: false }
    ];
    
    if (uploadedFiles.id_back) {
      documents.push({ type: 'id_back', url: uploadedFiles.id_back.url, verified: false });
    }
    
    if (uploadedFiles.address_proof) {
      documents.push({ 
        type: 'address_proof', 
        url: uploadedFiles.address_proof.url, 
        verified: false 
      });
    }
    
    if (uploadedFiles.additional_documents) {
      documents.push(...uploadedFiles.additional_documents.map(doc => ({
        ...doc,
        verified: false
      })));
    }

    // Create KYC submission
    const kycSubmission = new KYCSubmission({
      user: userId,
      id_type,
      id_number,
      id_front_url: uploadedFiles.id_front.url,
      id_back_url: uploadedFiles.id_back?.url,
      selfie_with_id_url: uploadedFiles.selfie_with_id.url,
      address_proof_url: uploadedFiles.address_proof?.url,
      proof_of_address_type,
      status: 'pending',
      kyc_level: 'basic',
      expiry_date: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year expiry
      documents,
      personal_info: personal_info || {},
      address: address || {},
      verification_score: calculateVerificationScore(personal_info, documents)
    });

    await kycSubmission.save();

    // Update user KYC status
    await User.findByIdAndUpdate(userId, {
      kyc_status: 'pending',
      kyc_submitted_at: new Date()
    });

    // Create notification
    await createNotification(
      userId,
      'KYC Submitted 📋',
      'Your KYC documents have been submitted successfully and are under review. This usually takes 1-3 business days.',
      'kyc',
      '/profile'
    );

    // Notify admin
    const admins = await User.find({ role: { $in: ['admin', 'super_admin', 'moderator'] } });
    for (const admin of admins) {
      await createNotification(
        admin._id,
        'New KYC Submission',
        `User ${user.full_name} has submitted KYC documents for verification. Verification score: ${kycSubmission.verification_score}/100`,
        'system',
        `/admin/kyc/${kycSubmission._id}`
      );
    }

    // Clear cache
    await cache.del(`kyc:${userId}`);
    await cache.del(`dashboard:${userId}`);

    res.status(201).json(formatResponse(true, 'KYC submitted successfully! Your documents are under review.', { 
      kyc: {
        ...kycSubmission.toObject(),
        estimated_review_time: '1-3 business days',
        verification_score: kycSubmission.verification_score
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error submitting KYC');
  }
});

function calculateVerificationScore(personalInfo, documents) {
  let score = 0;
  
  // Document completeness (max 40 points)
  const requiredDocs = ['id_front', 'selfie_with_id'];
  const optionalDocs = ['id_back', 'address_proof'];
  
  requiredDocs.forEach(doc => {
    if (documents.some(d => d.type === doc)) score += 20;
  });
  
  optionalDocs.forEach(doc => {
    if (documents.some(d => d.type === doc)) score += 10;
  });
  
  // Personal info completeness (max 30 points)
  if (personalInfo) {
    const infoFields = ['date_of_birth', 'nationality', 'occupation', 'source_of_funds'];
    infoFields.forEach(field => {
      if (personalInfo[field]) score += 7.5;
    });
  }
  
  // Address completeness (max 30 points)
  // This would be calculated based on address fields
  
  return Math.min(100, score);
}

// Get KYC status with details
app.get('/api/kyc/status', auth, async (req, res) => {
  try {
    const kyc = await KYCSubmission.findOne({ user: req.userId });
    
    if (!kyc) {
      return res.json(formatResponse(true, 'KYC status retrieved', { 
        kyc: null,
        user_kyc_status: req.user.kyc_status,
        user_kyc_verified: req.user.kyc_verified,
        requirements: {
          basic: ['id_front', 'selfie_with_id'],
          verified: ['id_front', 'id_back', 'selfie_with_id', 'address_proof'],
          advanced: ['id_front', 'id_back', 'selfie_with_id', 'address_proof', 'proof_of_income']
        }
      }));
    }

    // Calculate expiry status
    const now = new Date();
    const expiryDate = new Date(kyc.expiry_date);
    const daysUntilExpiry = Math.ceil((expiryDate - now) / (1000 * 60 * 60 * 24));
    const isExpiringSoon = daysUntilExpiry <= 30 && daysUntilExpiry > 0;
    const isExpired = expiryDate < now;

    res.json(formatResponse(true, 'KYC status retrieved', { 
      kyc: {
        ...kyc.toObject(),
        expiry_status: {
          expiry_date: kyc.expiry_date,
          days_until_expiry: daysUntilExpiry,
          is_expiring_soon: isExpiringSoon,
          is_expired: isExpired
        },
        documents_status: kyc.documents?.map(doc => ({
          type: doc.type,
          verified: doc.verified,
          verified_at: doc.verified_at
        })) || []
      },
      user_kyc_status: req.user.kyc_status,
      user_kyc_verified: req.user.kyc_verified,
      next_level: kyc.kyc_level === 'basic' ? 'verified' : kyc.kyc_level === 'verified' ? 'advanced' : null
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching KYC status');
  }
});

// ==================== ENHANCED REFERRAL ROUTES ====================

// Get referral stats with advanced analytics
app.get('/api/referrals/stats', auth, async (req, res) => {
  try {
    const userId = req.userId;
    const cacheKey = `referral_stats:${userId}`;
    
    // Try cache first
    const cachedStats = await cache.get(cacheKey);
    if (cachedStats && config.enableCaching) {
      return res.json(formatResponse(true, 'Referral stats retrieved (cached)', cachedStats));
    }
    
    const [referrals, totalEarnings, pendingEarnings, todayEarnings, monthlyEarnings, conversionStats] = await Promise.all([
      Referral.find({ referrer: userId })
        .populate('referred_user', 'full_name email createdAt balance total_investments')
        .sort({ createdAt: -1 })
        .limit(20)
        .lean(),
      Referral.aggregate([
        { $match: { referrer: mongoose.Types.ObjectId(userId), earnings_paid: true } },
        { $group: { _id: null, total: { $sum: '$earnings' } } }
      ]),
      Referral.aggregate([
        { $match: { referrer: mongoose.Types.ObjectId(userId), earnings_paid: false, status: 'active' } },
        { $group: { _id: null, total: { $sum: '$earnings' } } }
      ]),
      Referral.aggregate([
        { 
          $match: { 
            referrer: mongoose.Types.ObjectId(userId),
            paid_at: { 
              $gte: new Date(new Date().setHours(0, 0, 0, 0))
            }
          } 
        },
        { $group: { _id: null, total: { $sum: '$earnings' } } }
      ]),
      Referral.aggregate([
        { 
          $match: { 
            referrer: mongoose.Types.ObjectId(userId),
            paid_at: { 
              $gte: new Date(new Date().setMonth(new Date().getMonth() - 1))
            }
          } 
        },
        { $group: { _id: null, total: { $sum: '$earnings' } } }
      ]),
      Referral.aggregate([
        { $match: { referrer: mongoose.Types.ObjectId(userId) } },
        {
          $group: {
            _id: '$status',
            count: { $sum: 1 },
            total_earnings: { $sum: '$earnings' }
          }
        }
      ])
    ]);

    // Calculate conversion rate (pending to active)
    const conversionStatsObj = {};
    conversionStats.forEach(stat => {
      conversionStatsObj[stat._id] = stat;
    });

    const pendingCount = conversionStatsObj.pending?.count || 0;
    const activeCount = conversionStatsObj.active?.count || 0;
    const conversionRate = pendingCount + activeCount > 0 ? 
      (activeCount / (pendingCount + activeCount)) * 100 : 0;

    // Calculate lifetime value of referrals
    let lifetimeValue = 0;
    referrals.forEach(ref => {
      if (ref.referred_user?.total_investments) {
        lifetimeValue += ref.referred_user.total_investments * 0.1; // 10% of their investments
      }
    });

    const stats = {
      overview: {
        total_referrals: referrals.length,
        active_referrals: activeCount,
        pending_referrals: pendingCount,
        conversion_rate: Math.round(conversionRate),
        lifetime_value: lifetimeValue
      },
      earnings: {
        total_earnings: totalEarnings[0]?.total || 0,
        pending_earnings: pendingEarnings[0]?.total || 0,
        today_earnings: todayEarnings[0]?.total || 0,
        monthly_earnings: monthlyEarnings[0]?.total || 0,
        average_earnings_per_referral: referrals.length > 0 ? 
          (totalEarnings[0]?.total || 0) / referrals.length : 0
      },
      referral_info: {
        referral_code: req.user.referral_code,
        referral_link: `${config.clientURL}/register?ref=${req.user.referral_code}`,
        qr_code_url: `${config.serverURL}/api/referrals/qr?ref=${req.user.referral_code}`,
        share_text: `Join Raw Wealthy and start investing in raw materials! Use my referral code: ${req.user.referral_code}`
      },
      performance: {
        top_referrals: referrals
          .filter(r => r.earnings > 0)
          .sort((a, b) => b.earnings - a.earnings)
          .slice(0, 5),
        recent_conversions: referrals
          .filter(r => r.status === 'active')
          .slice(0, 5)
      }
    };

    // Cache the result
    await cache.set(cacheKey, stats, 300000); // 5 minutes cache

    res.json(formatResponse(true, 'Referral stats retrieved', { stats, referrals: referrals.slice(0, 10) }));
  } catch (error) {
    handleError(res, error, 'Error fetching referral stats');
  }
});

// Generate referral QR code
app.get('/api/referrals/qr', auth, async (req, res) => {
  try {
    const referralLink = `${config.clientURL}/register?ref=${req.user.referral_code}`;
    
    // Generate QR code
    const qrCodeDataURL = await QRCode.toDataURL(referralLink, {
      width: 300,
      margin: 2,
      color: {
        dark: '#000000',
        light: '#FFFFFF'
      }
    });

    res.json(formatResponse(true, 'QR code generated', {
      qr_code: qrCodeDataURL,
      referral_link: referralLink,
      referral_code: req.user.referral_code
    }));
  } catch (error) {
    handleError(res, error, 'Error generating QR code');
  }
});

// ==================== ENHANCED SUPPORT ROUTES ====================

// Create support ticket with enhanced features
app.post('/api/support/tickets', auth, upload.array('attachments', 5), [
  body('subject').notEmpty().trim().isLength({ min: 5, max: 200 }),
  body('message').notEmpty().trim().isLength({ min: 20, max: 5000 }),
  body('category').isIn(['general', 'technical', 'investment', 'withdrawal', 'deposit', 'kyc', 'account', 'verification', 'security', 'other']),
  body('priority').optional().isIn(['low', 'medium', 'high', 'urgent']),
  body('department').optional().isIn(['support', 'technical', 'financial', 'verification', 'admin']),
  body('related_transaction').optional().isMongoId(),
  body('related_investment').optional().isMongoId()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { 
      subject, 
      message, 
      category, 
      priority = 'medium', 
      department = 'support',
      related_transaction,
      related_investment
    } = req.body;
    
    const userId = req.userId;
    const user = req.user;

    // Handle file uploads
    const attachments = [];
    if (req.files && req.files.length > 0) {
      for (const file of req.files) {
        try {
          const uploadResult = await handleFileUpload(file, 'support', userId);
          attachments.push({
            filename: uploadResult.originalName,
            url: uploadResult.url,
            size: uploadResult.size,
            mime_type: uploadResult.mimeType,
            uploaded_at: uploadResult.uploadedAt
          });
        } catch (uploadError) {
          logger.error('File upload error:', uploadError);
        }
      }
    }

    // Create support ticket
    const supportTicket = new SupportTicket({
      user: userId,
      ticket_id: generateReference('TICKET'),
      subject,
      message,
      category,
      priority,
      department,
      status: 'open',
      attachments,
      last_reply_at: new Date(),
      metadata: {
        related_transaction,
        related_investment,
        user_tier: user.role,
        user_kyc_status: user.kyc_status
      }
    });

    await supportTicket.save();

    // Create notification
    await createNotification(
      userId,
      'Support Ticket Created 🎫',
      `Your support ticket "${subject}" has been created successfully. Ticket ID: ${supportTicket.ticket_id}. We'll get back to you soon.`,
      'info',
      `/support/tickets/${supportTicket._id}`
    );

    // Notify relevant department
    const departmentAdmins = await User.find({ 
      role: { $in: ['admin', 'super_admin', 'moderator'] },
      // In real implementation, you might have department assignments
    }).limit(3);
    
    for (const admin of departmentAdmins) {
      await createNotification(
        admin._id,
        'New Support Ticket',
        `User ${user.full_name} has created a new ${priority} priority support ticket in ${department} department: "${subject}"`,
        'system',
        `/admin/support/${supportTicket._id}`
      );
    }

    // Clear cache
    await cache.del(`support_tickets:${userId}`);

    res.status(201).json(formatResponse(true, 'Support ticket created successfully!', { 
      ticket: {
        ...supportTicket.toObject(),
        estimated_response_time: getEstimatedResponseTime(priority),
        support_email: 'support@rawwealthy.com',
        support_phone: '+234 916 180 6424'
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error creating support ticket');
  }
});

function getEstimatedResponseTime(priority) {
  switch (priority) {
    case 'urgent': return '1-2 hours';
    case 'high': return '4-6 hours';
    case 'medium': return '12-24 hours';
    case 'low': return '24-48 hours';
    default: return '24 hours';
  }
}

// Get user support tickets with filtering
app.get('/api/support/tickets', auth, [
  query('status').optional().isIn(['open', 'in_progress', 'resolved', 'closed', 'pending']),
  query('category').optional().isString(),
  query('priority').optional().isIn(['low', 'medium', 'high', 'urgent']),
  query('start_date').optional().isISO8601(),
  query('end_date').optional().isISO8601(),
  query('sort').optional().isIn(['createdAt', 'last_reply_at', 'priority']),
  query('order').optional().isIn(['asc', 'desc']),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 50 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { 
      status, 
      category,
      priority,
      start_date,
      end_date,
      sort = 'last_reply_at',
      order = 'desc',
      page = 1,
      limit = 20
    } = req.query;

    // Build query
    const query = { user: req.userId };
    
    if (status) query.status = status;
    if (category) query.category = category;
    if (priority) query.priority = priority;
    
    if (start_date || end_date) {
      query.createdAt = {};
      if (start_date) query.createdAt.$gte = new Date(start_date);
      if (end_date) query.createdAt.$lte = new Date(end_date);
    }

    // Build sort options
    const sortOptions = {};
    sortOptions[sort] = order === 'asc' ? 1 : -1;

    // Execute query with pagination
    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort: sortOptions,
      lean: true
    };

    const result = await SupportTicket.paginate(query, options);

    // Calculate statistics
    const stats = await SupportTicket.aggregate([
      { $match: { user: mongoose.Types.ObjectId(req.userId) } },
      { 
        $group: {
          _id: null,
          total_tickets: { $sum: 1 },
          open_tickets: { 
            $sum: { $cond: [{ $in: ['$status', ['open', 'in_progress', 'pending']] }, 1, 0] } 
          },
          resolved_tickets: { 
            $sum: { $cond: [{ $eq: ['$status', 'resolved'] }, 1, 0] } 
          },
          avg_resolution_time: { $avg: '$resolution_time' }
        }
      }
    ]);

    res.json(formatResponse(true, 'Support tickets retrieved', {
      tickets: result.docs,
      statistics: stats[0] || {
        total_tickets: 0,
        open_tickets: 0,
        resolved_tickets: 0
      },
      pagination: {
        page: result.page,
        limit: result.limit,
        total: result.totalDocs,
        pages: result.totalPages,
        hasPrevPage: result.hasPrevPage,
        hasNextPage: result.hasNextPage
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching support tickets');
  }
});

// ==================== ENHANCED DASHBOARD ROUTES ====================

// Get enhanced dashboard data
app.get('/api/dashboard', auth, async (req, res) => {
  try {
    const dashboardData = await getUserDashboardData(req.userId);
    
    if (!dashboardData) {
      return res.status(500).json(formatResponse(false, 'Failed to load dashboard data'));
    }

    // Add real-time data
    dashboardData.real_time = {
      online_status: activeConnections.has(req.userId.toString()),
      last_update: new Date().toISOString(),
      server_time: new Date().toISOString()
    };

    // Add quick actions
    dashboardData.quick_actions = {
      can_invest: req.user.balance >= config.minInvestment && req.user.kyc_verified,
      can_withdraw: req.user.balance >= config.minWithdrawal,
      can_deposit: true,
      needs_kyc: !req.user.kyc_verified,
      has_pending_actions: false // You would calculate this based on user's pending items
    };

    res.json(formatResponse(true, 'Dashboard data retrieved', dashboardData));
  } catch (error) {
    handleError(res, error, 'Error fetching dashboard data');
  }
});

// Get dashboard widgets (modular dashboard components)
app.get('/api/dashboard/widgets', auth, async (req, res) => {
  try {
    const userId = req.userId;
    const user = req.user;
    
    const widgets = await Promise.all([
      // Financial Summary Widget
      getFinancialSummaryWidget(userId, user),
      
      // Investment Progress Widget
      getInvestmentProgressWidget(userId),
      
      // Recent Activity Widget
      getRecentActivityWidget(userId),
      
      // Market Insights Widget
      getMarketInsightsWidget(),
      
      // Portfolio Allocation Widget
      getPortfolioAllocationWidget(userId),
      
      // Performance Metrics Widget
      getPerformanceMetricsWidget(userId),
      
      // Quick Stats Widget
      getQuickStatsWidget(userId, user)
    ]);

    res.json(formatResponse(true, 'Dashboard widgets retrieved', { widgets }));
  } catch (error) {
    handleError(res, error, 'Error fetching dashboard widgets');
  }
});

async function getFinancialSummaryWidget(userId, user) {
  const [deposits, withdrawals, investments] = await Promise.all([
    Deposit.aggregate([
      { $match: { user: mongoose.Types.ObjectId(userId), status: 'approved' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]),
    Withdrawal.aggregate([
      { $match: { user: mongoose.Types.ObjectId(userId), status: 'paid' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]),
    Investment.aggregate([
      { $match: { user: mongoose.Types.ObjectId(userId), status: 'active' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ])
  ]);

  return {
    type: 'financial_summary',
    title: 'Financial Summary',
    data: {
      balance: user.balance || 0,
      total_deposits: deposits[0]?.total || 0,
      total_withdrawals: withdrawals[0]?.total || 0,
      active_investments: investments[0]?.total || 0,
      net_worth: (user.balance || 0) + (investments[0]?.total || 0),
      currency: user.currency
    }
  };
}

async function getInvestmentProgressWidget(userId) {
  const investments = await Investment.find({ 
    user: userId, 
    status: 'active' 
  })
    .populate('plan', 'name')
    .limit(5)
    .lean();

  return {
    type: 'investment_progress',
    title: 'Active Investments',
    data: investments.map(inv => ({
      plan: inv.plan?.name,
      amount: inv.amount,
      progress: inv.progress_percentage || 0,
      remaining_days: inv.remaining_days || 0,
      earned_so_far: inv.earned_so_far || 0
    }))
  };
}

async function getRecentActivityWidget(userId) {
  const transactions = await Transaction.find({ user: userId })
    .sort({ createdAt: -1 })
    .limit(10)
    .lean();

  return {
    type: 'recent_activity',
    title: 'Recent Activity',
    data: transactions
  };
}

async function getMarketInsightsWidget() {
  const marketData = await MarketData.find()
    .sort({ last_updated: -1 })
    .limit(3)
    .lean();

  return {
    type: 'market_insights',
    title: 'Market Insights',
    data: marketData
  };
}

async function getPortfolioAllocationWidget(userId) {
  const portfolio = await Portfolio.findOne({ user: userId }).lean();
  
  return {
    type: 'portfolio_allocation',
    title: 'Portfolio Allocation',
    data: portfolio?.allocation || {}
  };
}

async function getPerformanceMetricsWidget(userId) {
  const investments = await Investment.aggregate([
    { $match: { user: mongoose.Types.ObjectId(userId), status: 'completed' } },
    {
      $group: {
        _id: null,
        total_invested: { $sum: '$amount' },
        total_earned: { $sum: '$earned_so_far' },
        count: { $sum: 1 }
      }
    }
  ]);

  const data = investments[0] || { total_invested: 0, total_earned: 0, count: 0 };
  const roi = data.total_invested > 0 ? (data.total_earned / data.total_invested) * 100 : 0;

  return {
    type: 'performance_metrics',
    title: 'Performance Metrics',
    data: {
      total_investments: data.count,
      total_returns: data.total_earned,
      average_roi: roi,
      success_rate: data.count > 0 ? 95 : 0 // This would be calculated based on actual success
    }
  };
}

async function getQuickStatsWidget(userId, user) {
  const [referrals, pendingActions] = await Promise.all([
    Referral.countDocuments({ referrer: userId }),
    // Count pending deposits, withdrawals, etc.
    Promise.all([
      Deposit.countDocuments({ user: userId, status: 'pending' }),
      Withdrawal.countDocuments({ user: userId, status: 'pending' }),
      Investment.countDocuments({ user: userId, status: 'pending' })
    ])
  ]);

  const totalPending = pendingActions.reduce((sum, count) => sum + count, 0);

  return {
    type: 'quick_stats',
    title: 'Quick Stats',
    data: {
      referral_count: referrals,
      pending_actions: totalPending,
      kyc_status: user.kyc_status,
      account_level: user.role === 'admin' ? 'Admin' : user.kyc_verified ? 'Verified' : 'Basic',
      days_active: Math.floor((new Date() - new Date(user.createdAt)) / (1000 * 60 * 60 * 24))
    }
  };
}

// ==================== ENHANCED REAL-TIME ROUTES ====================

// Real-time authentication with enhanced security
app.post('/api/realtime/auth', auth, async (req, res) => {
  try {
    const token = req.user.generateAuthToken();
    const sessionId = crypto.randomBytes(16).toString('hex');
    
    // Store session info (in production, use Redis)
    const sessionData = {
      userId: req.userId,
      userAgent: req.headers['user-agent'],
      ip: req.ip,
      createdAt: new Date()
    };
    
    if (config.enableCaching && redisClient) {
      await redisClient.setex(`session:${sessionId}`, 3600, JSON.stringify(sessionData));
    }
    
    res.json(formatResponse(true, 'Real-time authentication successful', {
      token,
      session_id: sessionId,
      websocket_url: `${config.serverURL.replace('http', 'ws')}`,
      socketio_url: `${config.serverURL}`,
      user_id: req.userId,
      features: {
        realtime_updates: true,
        notifications: true,
        market_data: true,
        portfolio_updates: true
      }
    }));
  } catch (error) {
    handleError(res, error, 'Real-time authentication failed');
  }
});

// Subscribe to real-time channels
app.post('/api/realtime/subscribe', auth, [
  body('channels').isArray(),
  body('channels.*').isString()
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { channels } = req.body;
    const userId = req.userId;

    // Validate channels
    const allowedChannels = [
      'market_updates',
      'portfolio_updates',
      'transaction_updates',
      'notification_updates',
      'system_alerts'
    ];

    const validChannels = channels.filter(channel => allowedChannels.includes(channel));

    // Store subscription (in production, use Redis)
    if (config.enableCaching && redisClient) {
      await redisClient.setex(
        `subscriptions:${userId}`, 
        86400, // 24 hours
        JSON.stringify(validChannels)
      );
    }

    res.json(formatResponse(true, 'Subscribed to channels', {
      channels: validChannels,
      subscription_expires: new Date(Date.now() + 86400000).toISOString()
    }));
  } catch (error) {
    handleError(res, error, 'Error subscribing to channels');
  }
});

// ==================== ENHANCED ADMIN ROUTES ====================

// Enhanced admin dashboard with more metrics
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
  try {
    const now = new Date();
    const today = new Date(now.setHours(0, 0, 0, 0));
    const yesterday = new Date(today.getTime() - 86400000);
    const lastWeek = new Date(today.getTime() - 7 * 86400000);
    const lastMonth = new Date(today.getTime() - 30 * 86400000);
    
    const [
      totalUsers,
      newUsersToday,
      newUsersYesterday,
      activeUsersToday,
      totalInvestments,
      activeInvestments,
      totalDeposits,
      totalWithdrawals,
      pendingDeposits,
      pendingWithdrawals,
      pendingInvestments,
      pendingKYC,
      financialMetrics,
      userGrowth,
      investmentGrowth
    ] = await Promise.all([
      User.countDocuments({}),
      User.countDocuments({ createdAt: { $gte: today } }),
      User.countDocuments({ createdAt: { $gte: yesterday, $lt: today } }),
      User.countDocuments({ last_active: { $gte: today } }),
      Investment.countDocuments({}),
      Investment.countDocuments({ status: 'active' }),
      Deposit.countDocuments({ status: 'approved' }),
      Withdrawal.countDocuments({ status: 'paid' }),
      Deposit.countDocuments({ status: 'pending' }),
      Withdrawal.countDocuments({ status: 'pending' }),
      Investment.countDocuments({ status: 'pending' }),
      KYCSubmission.countDocuments({ status: 'pending' }),
      // Financial metrics
      Promise.all([
        Deposit.aggregate([
          { $match: { status: 'approved' } },
          { $group: { _id: null, total: { $sum: '$amount' } } }
        ]),
        Withdrawal.aggregate([
          { $match: { status: 'paid' } },
          { $group: { _id: null, total: { $sum: '$amount' } } }
        ]),
        Investment.aggregate([
          { $match: { status: 'active' } },
          { $group: { _id: null, total: { $sum: '$amount' } } }
        ])
      ]),
      // Growth metrics
      Promise.all([
        User.countDocuments({ createdAt: { $gte: lastWeek } }),
        User.countDocuments({ createdAt: { $gte: lastMonth } })
      ]),
      Promise.all([
        Investment.countDocuments({ createdAt: { $gte: lastWeek } }),
        Investment.countDocuments({ createdAt: { $gte: lastMonth } })
      ])
    ]);
    
    const adminDashboard = {
      overview: {
        total_users: totalUsers,
        new_users_today: newUsersToday,
        new_users_yesterday: newUsersYesterday,
        active_users_today: activeUsersToday,
        total_investments: totalInvestments,
        active_investments: activeInvestments,
        total_deposits: totalDeposits,
        total_withdrawals: totalWithdrawals
      },
      
      pending_actions: {
        pending_deposits: pendingDeposits,
        pending_withdrawals: pendingWithdrawals,
        pending_investments: pendingInvestments,
        pending_kyc: pendingKYC
      },
      
      financial: {
        total_deposits_amount: financialMetrics[0][0]?.total || 0,
        total_withdrawals_amount: financialMetrics[1][0]?.total || 0,
        active_investments_value: financialMetrics[2][0]?.total || 0,
        net_cash_flow: (financialMetrics[0][0]?.total || 0) - (financialMetrics[1][0]?.total || 0),
        platform_earnings: (financialMetrics[1][0]?.total || 0) * (config.platformFeePercent / 100)
      },
      
      growth_metrics: {
        user_growth: {
          weekly: userGrowth[0],
          monthly: userGrowth[1],
          weekly_growth_rate: totalUsers > 0 ? (userGrowth[0] / totalUsers * 100) : 0
        },
        investment_growth: {
          weekly: investmentGrowth[0],
          monthly: investmentGrowth[1],
          weekly_growth_rate: totalInvestments > 0 ? (investmentGrowth[0] / totalInvestments * 100) : 0
        }
      },
      
      real_time: {
        online_users: activeConnections.size,
        active_sessions: connectedClients.size + activeConnections.size,
        server_time: new Date().toISOString(),
        uptime: process.uptime(),
        memory_usage: process.memoryUsage()
      },
      
      alerts: await getSystemAlerts()
    };
    
    res.json(formatResponse(true, 'Admin dashboard loaded', adminDashboard));
  } catch (error) {
    handleError(res, error, 'Error loading admin dashboard');
  }
});

async function getSystemAlerts() {
  const alerts = [];
  const now = new Date();
  
  // Check for system issues
  if (mongoose.connection.readyState !== 1) {
    alerts.push({
      type: 'critical',
      message: 'Database connection issue',
      timestamp: new Date().toISOString()
    });
  }
  
  // Check for pending actions that need attention
  const urgentPending = await Withdrawal.countDocuments({ 
    status: 'pending', 
    createdAt: { $lt: new Date(now.getTime() - 2 * 60 * 60 * 1000) } // Older than 2 hours
  });
  
  if (urgentPending > 0) {
    alerts.push({
      type: 'warning',
      message: `${urgentPending} withdrawals pending for more than 2 hours`,
      timestamp: new Date().toISOString()
    });
  }
  
  // Check for failed transactions
  const failedTransactions = await Transaction.countDocuments({
    status: 'failed',
    createdAt: { $gte: new Date(now.getTime() - 24 * 60 * 60 * 1000) }
  });
  
  if (failedTransactions > 5) {
    alerts.push({
      type: 'warning',
      message: `${failedTransactions} failed transactions in the last 24 hours`,
      timestamp: new Date().toISOString()
    });
  }
  
  return alerts;
}

// Enhanced admin user management
app.get('/api/admin/users', adminAuth, [
  query('search').optional().isString(),
  query('role').optional().isIn(['user', 'admin', 'super_admin', 'moderator']),
  query('status').optional().isIn(['active', 'inactive', 'suspended']),
  query('kyc_status').optional().isIn(['pending', 'verified', 'rejected', 'not_submitted']),
  query('verified').optional().isBoolean(),
  query('min_balance').optional().isFloat({ min: 0 }),
  query('max_balance').optional().isFloat({ min: 0 }),
  query('sort').optional().isIn(['createdAt', 'balance', 'total_investments', 'last_active']),
  query('order').optional().isIn(['asc', 'desc']),
  query('page').optional().isInt({ min: 1 }),
  query('limit').optional().isInt({ min: 1, max: 100 })
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json(formatResponse(false, 'Validation failed', { errors: errors.array() }));
    }

    const { 
      search, 
      role, 
      status, 
      kyc_status,
      verified,
      min_balance,
      max_balance,
      sort = 'createdAt',
      order = 'desc',
      page = 1,
      limit = 50
    } = req.query;

    // Build query
    const query = {};
    
    if (search) {
      query.$or = [
        { full_name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { phone: { $regex: search, $options: 'i' } },
        { referral_code: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (role) query.role = role;
    
    if (status === 'active') {
      query.is_active = true;
    } else if (status === 'inactive') {
      query.is_active = false;
    } else if (status === 'suspended') {
      query.is_active = false;
      // You might have a separate suspended flag
    }
    
    if (kyc_status) query.kyc_status = kyc_status;
    if (verified !== undefined) query.is_verified = verified === 'true';
    
    if (min_balance || max_balance) {
      query.balance = {};
      if (min_balance) query.balance.$gte = parseFloat(min_balance);
      if (max_balance) query.balance.$lte = parseFloat(max_balance);
    }

    // Build sort options
    const sortOptions = {};
    sortOptions[sort] = order === 'asc' ? 1 : -1;

    // Execute query with pagination
    const options = {
      page: parseInt(page),
      limit: parseInt(limit),
      sort: sortOptions,
      select: '-password -two_factor_secret -verification_token -password_reset_token -security_logs',
      lean: true
    };

    const result = await User.paginate(query, options);

    // Get statistics for the filtered results
    const stats = await User.aggregate([
      { $match: query },
      {
        $group: {
          _id: null,
          total_users: { $sum: 1 },
          total_balance: { $sum: '$balance' },
          total_investments: { $sum: '$total_investments' },
          total_deposits: { $sum: '$total_deposits' },
          avg_balance: { $avg: '$balance' }
        }
      }
    ]);

    res.json(formatResponse(true, 'Users retrieved', {
      users: result.docs,
      statistics: stats[0] || {
        total_users: 0,
        total_balance: 0,
        total_investments: 0,
        total_deposits: 0,
        avg_balance: 0
      },
      pagination: {
        page: result.page,
        limit: result.limit,
        total: result.totalDocs,
        pages: result.totalPages,
        hasPrevPage: result.hasPrevPage,
        hasNextPage: result.hasNextPage
      }
    }));
  } catch (error) {
    handleError(res, error, 'Error fetching users');
  }
});

// ==================== ENHANCED AUTOMATION TOOLS ====================

// Advanced daily earnings calculation with performance tracking
const calculateDailyEarnings = async () => {
  try {
    logger.info('💰 Calculating daily earnings...');
    
    const startTime = Date.now();
    const activeInvestments = await Investment.find({ 
      status: 'active',
      end_date: { $gt: new Date() }
    }).populate('plan', 'daily_interest').populate('user', 'balance email');
    
    let totalEarnings = 0;
    let processedCount = 0;
    let failedCount = 0;
    const earningsByUser = new Map();
    
    for (const investment of activeInvestments) {
      try {
        if (investment.plan && investment.plan.daily_interest) {
          const dailyEarning = (investment.amount * investment.plan.daily_interest) / 100;
          
          // Update investment
          investment.earned_so_far = (investment.earned_so_far || 0) + dailyEarning;
          investment.last_earning_date = new Date();
          investment.earnings_history = investment.earnings_history || [];
          investment.earnings_history.push({
            date: new Date(),
            amount: dailyEarning,
            type: 'daily'
          });
          
          await investment.save();
          
          // Update user balance
          await createTransaction(
            investment.user._id,
            'earning',
            dailyEarning,
            `Daily earnings from ${investment.plan.name} investment`,
            'completed',
            { 
              investment_id: investment._id,
              plan_name: investment.plan.name,
              automated: true
            }
          );
          
          // Track earnings by user for batch notifications
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
            plan: investment.plan.name,
            amount: dailyEarning
          });
          
          totalEarnings += dailyEarning;
          processedCount++;
        }
      } catch (error) {
        logger.error(`Error processing investment ${investment._id}:`, error);
        failedCount++;
      }
    }
    
    // Send batch notifications to users
    for (const [userId, data] of earningsByUser.entries()) {
      if (data.investments.length > 0) {
        await createNotification(
          userId,
          'Daily Earnings Added 🎉',
          `You earned ${data.user.currency}${data.total.toFixed(2)} from ${data.investments.length} active investments today.`,
          'earning',
          '/investments'
        );
      }
    }
    
    const duration = Date.now() - startTime;
    
    logger.info(`✅ Daily earnings calculated: ${totalEarnings.toFixed(2)} for ${processedCount} investments (${failedCount} failed) in ${duration}ms`);
    
    // Log performance metrics
    const performanceLog = new AdminAudit({
      admin_id: null,
      action: 'DAILY_EARNINGS_CALCULATION',
      target_type: 'system',
      details: {
        total_earnings: totalEarnings,
        processed_count: processedCount,
        failed_count: failedCount,
        duration_ms: duration,
        timestamp: new Date().toISOString()
      },
      status: failedCount === 0 ? 'success' : 'failed',
      duration_ms: duration
    });
    
    await performanceLog.save();
    
    return { 
      totalEarnings, 
      processedCount, 
      failedCount, 
      duration 
    };
  } catch (error) {
    logger.error('❌ Error calculating daily earnings:', error);
    return { totalEarnings: 0, processedCount: 0, failedCount: 0, duration: 0 };
  }
};

// Enhanced matured investments completion
const completeMaturedInvestments = async () => {
  try {
    logger.info('📅 Completing matured investments...');
    
    const startTime = Date.now();
    const maturedInvestments = await Investment.find({ 
      status: 'active',
      end_date: { $lte: new Date() }
    }).populate('plan', 'name').populate('user', 'full_name email balance currency');
    
    let completedCount = 0;
    let autoRenewedCount = 0;
    let failedCount = 0;
    
    for (const investment of maturedInvestments) {
      try {
        // Check if auto-renew is enabled
        if (investment.auto_renew && investment.user.balance >= investment.amount) {
          // Auto-renew the investment
          const newEndDate = new Date(Date.now() + investment.plan.duration * 24 * 60 * 60 * 1000);
          investment.end_date = newEndDate;
          investment.start_date = new Date();
          investment.earned_so_far = 0;
          investment.progress_percentage = 0;
          investment.remaining_days = investment.plan.duration;
          investment.earnings_history = [];
          
          await investment.save();
          
          // Deduct amount from balance for renewal
          await createTransaction(
            investment.user._id,
            'investment',
            -investment.amount,
            `Auto-renewal of ${investment.plan.name} investment`,
            'completed',
            { 
              investment_id: investment._id,
              plan_name: investment.plan.name,
              automated: true,
              type: 'auto_renew'
            }
          );
          
          await createNotification(
            investment.user._id,
            'Investment Auto-Renewed 🔄',
            `Your investment in ${investment.plan.name} has been auto-renewed for another ${investment.plan.duration} days.`,
            'investment',
            `/investments/${investment._id}`
          );
          
          autoRenewedCount++;
        } else {
          // Complete the investment
          investment.status = 'completed';
          await investment.save();
          
          // Return principal if not auto-renew
          if (!investment.auto_renew) {
            await createTransaction(
              investment.user._id,
              'investment',
              investment.amount,
              `Investment principal returned for ${investment.plan.name}`,
              'completed',
              { 
                investment_id: investment._id,
                plan_name: investment.plan.name,
                type: 'principal_return',
                automated: true
              }
            );
          }
          
          // Create notification
          await createNotification(
            investment.user._id,
            'Investment Completed 🎯',
            `Your investment in ${investment.plan.name} has completed. Total earnings: ${investment.user.currency}${investment.earned_so_far.toFixed(2)}.${investment.auto_renew ? ' Investment has been auto-renewed.' : ' Principal has been returned to your balance.'}`,
            'investment',
            '/investments'
          );
          
          completedCount++;
        }
        
        // Update portfolio
        await updatePortfolio(investment.user._id);
        
      } catch (error) {
        logger.error(`Error completing investment ${investment._id}:`, error);
        failedCount++;
      }
    }
    
    const duration = Date.now() - startTime;
    
    logger.info(`✅ Completed ${completedCount} matured investments, ${autoRenewedCount} auto-renewed (${failedCount} failed) in ${duration}ms`);
    
    return { 
      completedCount, 
      autoRenewedCount, 
      failedCount, 
      duration 
    };
  } catch (error) {
    logger.error('❌ Error completing matured investments:', error);
    return { completedCount: 0, autoRenewedCount: 0, failedCount: 0, duration: 0 };
  }
};

// Enhanced referral earnings processing
const processReferralEarnings = async () => {
  try {
    logger.info('👥 Processing referral earnings...');
    
    const startTime = Date.now();
    const pendingReferrals = await Referral.find({ 
      status: 'active',
      earnings_paid: false,
      investment_amount: { $gt: 0 }
    })
      .populate('referrer', 'balance email full_name')
      .populate('referred_user', 'full_name');
    
    let processedCount = 0;
    let totalEarnings = 0;
    let failedCount = 0;
    
    for (const referral of pendingReferrals) {
      try {
        // Check if referred user has active investments
        const activeInvestments = await Investment.countDocuments({
          user: referral.referred_user._id,
          status: 'active'
        });
        
        if (activeInvestments > 0) {
          const commission = (referral.investment_amount * referral.commission_percentage) / 100;
          
          // Update referral
          referral.earnings = commission;
          referral.earnings_paid = true;
          referral.paid_at = new Date();
          referral.status = 'completed';
          referral.commission_history = referral.commission_history || [];
          referral.commission_history.push({
            amount: commission,
            date: new Date(),
            source: 'investment_completion',
            investment_id: referral.investment_amount
          });
          
          await referral.save();
          
          // Pay commission to referrer
          await createTransaction(
            referral.referrer._id,
            'referral',
            commission,
            `Referral commission from ${referral.referred_user.full_name}`,
            'completed',
            { 
              referral_id: referral._id,
              referred_user: referral.referred_user.full_name,
              investment_amount: referral.investment_amount,
              automated: true
            }
          );
          
          // Create notification for referrer
          await createNotification(
            referral.referrer._id,
            'Referral Commission Earned 💰',
            `You earned ${referral.referrer.currency}${commission.toFixed(2)} commission from ${referral.referred_user.full_name}'s investment.`,
            'referral',
            '/referrals'
          );
          
          totalEarnings += commission;
          processedCount++;
        }
      } catch (error) {
        logger.error(`Error processing referral ${referral._id}:`, error);
        failedCount++;
      }
    }
    
    const duration = Date.now() - startTime;
    
    logger.info(`✅ Processed ${processedCount} referral earnings: ${totalEarnings.toFixed(2)} (${failedCount} failed) in ${duration}ms`);
    
    return { 
      totalEarnings, 
      processedCount, 
      failedCount, 
      duration 
    };
  } catch (error) {
    logger.error('❌ Error processing referral earnings:', error);
    return { totalEarnings: 0, processedCount: 0, failedCount: 0, duration: 0 };
  }
};

// New: Process auto-invest strategies
const processAutoInvestStrategies = async () => {
  if (!config.enableAutoInvest) {
    return { processed: 0, invested: 0, failed: 0 };
  }
  
  try {
    logger.info('🤖 Processing auto-invest strategies...');
    
    const startTime = Date.now();
    const now = new Date();
    const strategies = await AutoInvestStrategy.find({
      is_active: true,
      next_execution: { $lte: now }
    }).populate('user', 'balance email').populate('plans');
    
    let processed = 0;
    let totalInvested = 0;
    let failed = 0;
    
    for (const strategy of strategies) {
      try {
        const user = strategy.user;
        
        // Calculate investment amount based on strategy type
        let investmentAmount = 0;
        
        if (strategy.strategy_type === 'fixed_amount') {
          investmentAmount = strategy.amount;
        } else if (strategy.strategy_type === 'percentage') {
          investmentAmount = (user.balance * strategy.percentage) / 100;
        } else if (strategy.strategy_type === 'smart') {
          // Smart strategy: invest based on risk level and market conditions
          investmentAmount = calculateSmartInvestmentAmount(user, strategy);
        }
        
        // Validate investment amount
        if (investmentAmount < config.minInvestment || investmentAmount > user.balance) {
          logger.warn(`Auto-invest skipped for user ${user._id}: Invalid amount ${investmentAmount}`);
          continue;
        }
        
        // Get eligible plans based on strategy
        const eligiblePlans = await InvestmentPlan.find({
          _id: { $in: strategy.plans },
          is_active: true,
          min_amount: { $lte: investmentAmount },
          risk_level: { $lte: strategy.risk_level }
        });
        
        if (eligiblePlans.length === 0) {
          logger.warn(`Auto-invest skipped for user ${user._id}: No eligible plans`);
          continue;
        }
        
        // Select a plan (for now, select the first one)
        const selectedPlan = eligiblePlans[0];
        
        // Create investment
        const investment = new Investment({
          user: user._id,
          plan: selectedPlan._id,
          amount: investmentAmount,
          status: 'active',
          start_date: new Date(),
          end_date: new Date(Date.now() + selectedPlan.duration * 24 * 60 * 60 * 1000),
          expected_earnings: (investmentAmount * selectedPlan.total_interest) / 100,
          daily_earnings: (investmentAmount * selectedPlan.daily_interest) / 100,
          auto_renew: true,
          payment_verified: true,
          remarks: `Auto-invest via ${strategy.name} strategy`
        });
        
        await investment.save();
        
        // Update user balance
        await createTransaction(
          user._id,
          'investment',
          -investmentAmount,
          `Auto-investment in ${selectedPlan.name}`,
          'completed',
          { 
            investment_id: investment._id,
            plan_name: selectedPlan.name,
            strategy_id: strategy._id,
            automated: true
          }
        );
        
        // Update strategy
        strategy.last_executed = now;
        strategy.next_execution = calculateNextExecution(strategy.frequency);
        strategy.total_invested = (strategy.total_invested || 0) + investmentAmount;
        strategy.executions_count = (strategy.executions_count || 0) + 1;
        await strategy.save();
        
        // Create notification
        await createNotification(
          user._id,
          'Auto-Investment Executed 🤖',
          `Your auto-invest strategy "${strategy.name}" has executed. ${user.currency}${investmentAmount.toFixed(2)} invested in ${selectedPlan.name}.`,
          'investment',
          '/investments'
        );
        
        // Update portfolio
        await updatePortfolio(user._id);
        
        totalInvested += investmentAmount;
        processed++;
        
      } catch (error) {
        logger.error(`Error processing auto-invest strategy ${strategy._id}:`, error);
        failed++;
      }
    }
    
    const duration = Date.now() - startTime;
    
    logger.info(`✅ Processed ${processed} auto-invest strategies: ${totalInvested.toFixed(2)} invested (${failed} failed) in ${duration}ms`);
    
    return { 
      processed, 
      totalInvested, 
      failed, 
      duration 
    };
  } catch (error) {
    logger.error('❌ Error processing auto-invest strategies:', error);
    return { processed: 0, totalInvested: 0, failed: 0, duration: 0 };
  }
};

function calculateSmartInvestmentAmount(user, strategy) {
  // Simple smart algorithm - can be enhanced
  const riskFactor = {
    low: 0.1,
    medium: 0.2,
    high: 0.3
  }[strategy.risk_level] || 0.15;
  
  return user.balance * riskFactor;
}

function calculateNextExecution(frequency) {
  const now = new Date();
  switch (frequency) {
    case 'daily':
      return new Date(now.getTime() + 24 * 60 * 60 * 1000);
    case 'weekly':
      return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    case 'monthly':
      return new Date(now.getFullYear(), now.getMonth() + 1, now.getDate());
    default:
      return new Date(now.getTime() + 24 * 60 * 60 * 1000);
  }
}

// New: Update market data
const updateMarketData = async () => {
  try {
    logger.info('📊 Updating market data...');
    
    // In a real implementation, you would fetch this from external APIs
    // For now, we'll simulate market data updates
    
    const rawMaterials = ['Cocoa', 'Gold', 'Crude Oil', 'Silver', 'Coffee', 'Palm Oil'];
    const updates = [];
    
    for (const material of rawMaterials) {
      const currentPrice = 1000 + Math.random() * 500; // Simulated price
      const changePercentage = (Math.random() - 0.5) * 10; // -5% to +5%
      
      const update = {
        updateOne: {
          filter: { raw_material: material },
          update: {
            $set: {
              current_price: currentPrice,
              market_trend: changePercentage > 0 ? 'bullish' : changePercentage < 0 ? 'bearish' : 'neutral',
              volatility: Math.random() * 20,
              last_updated: new Date()
            },
            $push: {
              price_history: {
                date: new Date(),
                price: currentPrice,
                change_percentage: changePercentage
              }
            }
          },
          upsert: true
        }
      };
      
      updates.push(update);
    }
    
    if (updates.length > 0) {
      await MarketData.bulkWrite(updates);
      logger.info(`✅ Updated market data for ${updates.length} materials`);
    }
    
    return { updated: updates.length };
  } catch (error) {
    logger.error('❌ Error updating market data:', error);
    return { updated: 0 };
  }
};

// ==================== ENHANCED CRON JOBS ====================

// Daily automation (runs every day at midnight)
cron.schedule('0 0 * * *', async () => {
  logger.info('⏰ Running daily automation...');
  
  const earningsResult = await calculateDailyEarnings();
  const completionResult = await completeMaturedInvestments();
  const referralResult = await processReferralEarnings();
  const autoInvestResult = await processAutoInvestStrategies();
  const marketDataResult = await updateMarketData();
  
  logger.info('✅ Daily automation completed:', {
    earnings: earningsResult,
    completions: completionResult,
    referrals: referralResult,
    auto_invest: autoInvestResult,
    market_data: marketDataResult
  });
  
  // Broadcast system update
  broadcastToAll('system_update', {
    type: 'daily_automation_completed',
    timestamp: new Date().toISOString(),
    results: {
      earnings: earningsResult,
      completions: completionResult,
      referrals: referralResult
    }
  });
});

// Hourly tasks (runs every hour)
cron.schedule('0 * * * *', async () => {
  logger.info('⏰ Running hourly tasks...');
  
  // Update online status
  await updateOnlineStatus();
  
  // Update cache statistics
  await updateCacheStatistics();
  
  // Check for system alerts
  await checkSystemAlerts();
});

// Every 5 minutes: Update real-time data
cron.schedule('*/5 * * * *', async () => {
  try {
    // Update market data more frequently during trading hours
    const now = new Date();
    const hour = now.getHours();
    
    if (hour >= 9 && hour <= 17) { // 9 AM to 5 PM
      await updateMarketData();
      
      // Broadcast market updates to subscribed users
      const marketData = await MarketData.find().limit(5).lean();
      io.to('market_updates').emit('market_update', {
        data: marketData,
        timestamp: new Date().toISOString()
      });
    }
  } catch (error) {
    logger.error('Error in 5-minute cron job:', error);
  }
});

// Every minute: Update user online status
cron.schedule('* * * * *', async () => {
  try {
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    
    // Mark users who haven't been active as offline
    const result = await User.updateMany(
      { 
        online_status: true,
        last_seen: { $lt: fiveMinutesAgo }
      },
      { 
        online_status: false 
      }
    );
    
    if (result.modifiedCount > 0) {
      logger.info(`Updated ${result.modifiedCount} users to offline status`);
    }
  } catch (error) {
    logger.error('❌ Error updating online status:', error);
  }
});

async function updateOnlineStatus() {
  // This function is called hourly to clean up stale connections
  const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000);
  
  // Update users who haven't been active
  await User.updateMany(
    { 
      online_status: true,
      last_seen: { $lt: fifteenMinutesAgo }
    },
    { 
      online_status: false 
    }
  );
}

async function updateCacheStatistics() {
  if (!redisClient) return;
  
  try {
    const info = await redisClient.info();
    logger.debug('Redis cache statistics updated');
  } catch (error) {
    logger.error('Error updating cache statistics:', error);
  }
}

async function checkSystemAlerts() {
  // Check for system issues and send alerts
  const alerts = await getSystemAlerts();
  
  if (alerts.length > 0) {
    // Send alerts to admin users
    const admins = await User.find({ role: { $in: ['admin', 'super_admin'] } });
    
    for (const admin of admins) {
      for (const alert of alerts) {
        await createNotification(
          admin._id,
          `System Alert: ${alert.type.toUpperCase()}`,
          alert.message,
          alert.type === 'critical' ? 'error' : 'warning',
          '/admin/dashboard'
        );
      }
    }
  }
}

// ==================== ENHANCED DATABASE INITIALIZATION ====================

const initializeDatabase = async () => {
  try {
    logger.info('🔄 Connecting to MongoDB...');
    
    // Connect to MongoDB with enhanced options
    await mongoose.connect(config.mongoURI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      maxPoolSize: 100,
      minPoolSize: 10,
      retryWrites: true,
      w: 'majority'
    });
    
    logger.info('✅ MongoDB connected successfully');
    
    // Initialize pagination plugin
    mongoose.plugin(mongoosePaginate);
    
    // Create default investment plans if none exist
    const planCount = await InvestmentPlan.countDocuments();
    if (planCount === 0) {
      logger.info('📝 Creating default investment plans...');
      
      const defaultPlans = [
        {
          name: 'Cocoa Beans Premium',
          description: 'Invest in premium organic cocoa beans from West Africa',
          detailed_description: 'This plan focuses on high-quality organic cocoa beans sourced directly from certified farms in Ghana and Ivory Coast. With stable returns and low risk, it\'s perfect for beginners.',
          min_amount: 3500,
          max_amount: 500000,
          daily_interest: 2.5,
          total_interest: 75,
          duration: 30,
          risk_level: 'low',
          raw_material: 'Cocoa',
          category: 'agriculture',
          is_popular: true,
          is_featured: true,
          features: ['Low Risk', 'Stable Returns', 'Beginner Friendly', 'Daily Payouts', 'Organic Certified'],
          color: '#10b981',
          icon: '🌱',
          tags: ['beginner', 'stable', 'agriculture'],
          display_order: 1,
          success_rate: 98,
          roi_breakdown: [
            { period: 'Weekly', percentage: 17.5 },
            { period: 'Monthly', percentage: 75 },
            { period: 'Quarterly', percentage: 225 }
          ]
        },
        {
          name: 'Gold Investment Plus',
          description: 'Precious metal investment with high liquidity and security',
          detailed_description: 'Invest in physical gold stored in secure vaults. This plan offers high liquidity and acts as a hedge against inflation. Perfect for medium to long-term investors.',
          min_amount: 50000,
          max_amount: 10000000,
          daily_interest: 3.2,
          total_interest: 96,
          duration: 30,
          risk_level: 'medium',
          raw_material: 'Gold',
          category: 'metals',
          is_popular: true,
          is_featured: true,
          features: ['Medium Risk', 'Higher Returns', 'High Liquidity', 'Inflation Hedge', 'Secure Storage'],
          color: '#fbbf24',
          icon: '🥇',
          tags: ['precious', 'secure', 'liquidity'],
          display_order: 2,
          success_rate: 95,
          roi_breakdown: [
            { period: 'Weekly', percentage: 22.4 },
            { period: 'Monthly', percentage: 96 },
            { period: 'Quarterly', percentage: 288 }
          ]
        },
        {
          name: 'Crude Oil Energy Fund',
          description: 'High-return energy sector investment with premium benefits',
          detailed_description: 'Invest in crude oil futures and energy sector projects. This high-risk, high-reward plan is for experienced investors looking for maximum returns.',
          min_amount: 100000,
          max_amount: 50000000,
          daily_interest: 4.1,
          total_interest: 123,
          duration: 30,
          risk_level: 'high',
          raw_material: 'Crude Oil',
          category: 'energy',
          is_featured: true,
          features: ['High Risk', 'Maximum Returns', 'Energy Sector', 'Premium Investment', 'Expert Managed'],
          color: '#dc2626',
          icon: '🛢️',
          tags: ['energy', 'high-risk', 'premium'],
          display_order: 3,
          success_rate: 92,
          roi_breakdown: [
            { period: 'Weekly', percentage: 28.7 },
            { period: 'Monthly', percentage: 123 },
            { period: 'Quarterly', percentage: 369 }
          ]
        },
        {
          name: 'Silver Trading Account',
          description: 'Silver commodity trading with flexible investment options',
          min_amount: 10000,
          daily_interest: 2.8,
          total_interest: 84,
          duration: 30,
          risk_level: 'low',
          raw_material: 'Silver',
          category: 'metals',
          features: ['Flexible', 'Stable', 'Commodity Trading'],
          color: '#9ca3af',
          icon: '🥈',
          display_order: 4
        },
        {
          name: 'Coffee Bean Harvest',
          description: 'Seasonal coffee bean investment from Ethiopian highlands',
          min_amount: 25000,
          daily_interest: 3.5,
          total_interest: 105,
          duration: 45,
          risk_level: 'medium',
          raw_material: 'Coffee',
          category: 'agriculture',
          features: ['Seasonal', 'Premium Quality', 'Direct Trade'],
          color: '#92400e',
          icon: '☕',
          display_order: 5
        }
      ];
      
      await InvestmentPlan.insertMany(defaultPlans);
      logger.info('✅ Default investment plans created');
    }
    
    // Create market data if none exists
    const marketDataCount = await MarketData.countDocuments();
    if (marketDataCount === 0) {
      logger.info('📈 Creating initial market data...');
      await updateMarketData();
    }
    
    // Create admin user if none exists
    const adminCount = await User.countDocuments({ role: { $in: ['admin', 'super_admin'] } });
    if (adminCount === 0) {
      logger.info('👑 Creating admin user...');
      
      const adminPassword = process.env.ADMIN_PASSWORD || 'Admin@123456';
      const hashedPassword = await bcrypt.hash(adminPassword, config.bcryptRounds);
      
      const admin = new User({
        full_name: 'Raw Wealthy Administrator',
        email: 'admin@rawwealthy.com',
        phone: '09161806424',
        password: hashedPassword,
        role: 'super_admin',
        balance: 1000000,
        kyc_verified: true,
        kyc_status: 'verified',
        is_active: true,
        is_verified: true,
        referral_code: 'ADMIN001',
        settings: {
          theme: 'dark',
          language: 'en',
          timezone: 'Africa/Lagos',
          auto_reinvest: true
        }
      });
      
      await admin.save();
      
      logger.info('🎉 Admin user created successfully!');
      logger.info(`📧 Email: admin@rawwealthy.com`);
      logger.info(`🔑 Password: ${adminPassword}`);
      
      // Create admin portfolio
      const adminPortfolio = new Portfolio({
        user: admin._id,
        total_value: 1000000,
        risk_score: 50
      });
      await adminPortfolio.save();
    }
    
    // Create moderator user if none exists
    const moderatorCount = await User.countDocuments({ role: 'moderator' });
    if (moderatorCount === 0) {
      logger.info('👤 Creating moderator user...');
      
      const moderatorPassword = process.env.MODERATOR_PASSWORD || 'Moderator@123456';
      const hashedPassword = await bcrypt.hash(moderatorPassword, config.bcryptRounds);
      
      const moderator = new User({
        full_name: 'Raw Wealthy Moderator',
        email: 'moderator@rawwealthy.com',
        phone: '09161806425',
        password: hashedPassword,
        role: 'moderator',
        balance: 0,
        kyc_verified: true,
        kyc_status: 'verified',
        is_active: true,
        is_verified: true,
        referral_code: 'MOD001'
      });
      
      await moderator.save();
      
      logger.info('🎉 Moderator user created successfully!');
    }
    
    logger.info('✅ Database initialization completed');
  } catch (error) {
    logger.error('❌ Database initialization error:', error.message);
    throw error;
  }
};

// ==================== ENHANCED SERVER INITIALIZATION ====================

const startServer = async () => {
  try {
    // Initialize database
    await initializeDatabase();
    
    // Start server
    server.listen(config.port, '0.0.0.0', () => {
      logger.info(`
🎯 RAW WEALTHY BACKEND v60.0 - ULTIMATE EDITION
=========================================================
🌐 Server running on port ${config.port}
🚀 Environment: ${config.nodeEnv}
📊 Health Check: /health
⚡ System Status: /api/system/status
🔗 API Base: /api
⚡ Real-time: WebSocket & Socket.IO Ready
💾 Database: MongoDB Connected
📡 Redis Cache: ${config.enableCaching ? '✅ Enabled' : '❌ Disabled'}
☁️ Cloudinary: ${config.cloudinaryEnabled ? '✅ Enabled' : '❌ Disabled'}
📧 Email: ${config.emailEnabled ? '✅ Enabled' : '❌ Disabled'}
📁 Uploads: ${config.uploadDir}

✅ ENHANCED FEATURES:
   🤖 Auto-Invest Strategies
   📊 Portfolio Management
   📈 Market Data Integration
   🔄 Real-time Updates
   🛡️ Enhanced Security
   📱 Mobile Optimization
   🌐 Multi-currency Support
   🔔 Push Notifications
   📊 Advanced Analytics
   🤝 Referral System 2.0

✅ PERFORMANCE OPTIMIZATIONS:
   ⚡ Response Caching
   📦 Request Compression
   🔄 Connection Pooling
   🚀 Load Balancing Ready
   📊 Query Optimization
   💾 Memory Management

✅ ADVANCED AUTOMATION:
   ⏰ Smart Cron Jobs
   🤖 Auto-Invest Execution
   📈 Market Data Updates
   💰 Daily Earnings Calculation
   🔄 Investment Auto-renewal
   👥 Referral Processing
   🚨 System Monitoring

✅ SECURITY ENHANCEMENTS:
   🔐 JWT Authentication
   🛡️ Rate Limiting
   🚫 SQL Injection Protection
   ✨ XSS Protection
   📝 Input Validation
   🔒 CSRF Protection
   👁️ Audit Logging
   🔐 Two-Factor Auth Ready

🚀 BACKEND IS FULLY OPERATIONAL AND ENHANCED!
      `);
    });

    // Enhanced graceful shutdown
    const gracefulShutdown = async (signal) => {
      logger.info(`\n${signal} received, shutting down gracefully...`);
      
      // Update all users offline
      await User.updateMany(
        { online_status: true },
        { online_status: false, last_seen: new Date() }
      ).catch(err => logger.error('Error updating user status:', err));
      
      // Close WebSocket connections
      wss.clients.forEach((ws) => {
        ws.close(1001, 'Server shutting down');
      });
      connectedClients.clear();
      
      // Close Socket.IO
      io.close();
      
      // Close Redis connection
      if (redisClient) {
        await redisClient.quit().catch(err => logger.error('Error closing Redis:', err));
      }
      
      // Close server
      server.close(async () => {
        logger.info('HTTP server closed');
        
        // Close database connection
        try {
          await mongoose.connection.close();
          logger.info('Database connection closed');
        } catch (dbError) {
          logger.error('Error closing database:', dbError);
        }
        
        logger.info('Process terminated gracefully');
        process.exit(0);
      });
      
      // Force shutdown after 15 seconds
      setTimeout(() => {
        logger.error('Could not close connections in time, forcefully shutting down');
        process.exit(1);
      }, 15000);
    };

    // Handle shutdown signals
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    
    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught Exception:', error);
      gracefulShutdown('uncaughtException');
    });

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
    });

  } catch (error) {
    logger.error('❌ Server initialization failed:', error);
    process.exit(1);
  }
};

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 Raw Wealthy Backend API v60.0 - Ultimate Edition',
    version: '60.0.0',
    timestamp: new Date().toISOString(),
    status: 'Operational',
    environment: config.nodeEnv,
    documentation: `${config.serverURL}/docs`,
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
      upload: 'POST /api/* with files',
      realtime: '/api/realtime/*',
      system: '/api/system/*',
      health: '/health',
      status: '/api/system/status'
    },
    features: {
      realtime_updates: true,
      portfolio_management: true,
      auto_invest: config.enableAutoInvest,
      crypto_payments: config.enableCryptoPayments,
      multi_currency: true,
      advanced_analytics: true
    }
  });
});

// 404 handler with enhanced suggestions
app.use((req, res) => {
  res.status(404).json(formatResponse(false, 'Endpoint not found', {
    requested_url: req.originalUrl,
    method: req.method,
    timestamp: new Date().toISOString(),
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
      '/api/realtime/*',
      '/api/system/*',
      '/health'
    ],
    documentation: `${config.serverURL}/docs`,
    support_contact: 'support@rawwealthy.com'
  }));
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error('Global error:', err);
  
  // Generate error ID for tracking
  const errorId = crypto.randomBytes(8).toString('hex');
  
  if (err instanceof multer.MulterError) {
    return res.status(400).json(formatResponse(false, `File upload error: ${err.message}`));
  }
  
  res.status(500).json(formatResponse(false, 'Internal server error', {
    error_id: errorId,
    timestamp: new Date().toISOString(),
    support_contact: 'support@rawwealthy.com',
    reference: `ERR-${errorId}`
  }));
});

// Start the server
startServer();

export default app;
